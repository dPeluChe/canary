// Package ci correlates GitHub Actions activity with an attack window.
//
// LAYER 4 of 4. See docs/ARCHITECTURE/OVERVIEW.md.
//
// No surveyed tool does this, and it is the question that matters most when a
// registry is compromised: a developer's laptop can be verified clean while a
// CI runner installed the same dependency tree and exfiltrated repository
// secrets, leaving nothing behind locally.
//
// The question this layer answers, per repo:
//
//	Did a workflow install dependencies inside the window,
//	and if so, what secrets were reachable from that job?
//
// A run inside the window is not by itself a compromise. The finding is only
// material when the resolved dependency set contained a malicious version AND
// secrets existed to steal. Reporting the run alone produces alarm without
// information — and the correct outcome of most investigations is a
// documented negative, not a credential rotation. That judgement is deliberately
// NOT made here: this package reports exposure, the verdict layer crosses it.
package ci

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-github/v66/github"
)

// Run is one workflow run within the queried window.
type Run struct {
	ID            int64
	Workflow      string
	Event         string
	Branch        string
	Conclusion    string
	CreatedAt     time.Time
	InstalledDeps bool   // the job ran npm ci / npm install / bun install / pnpm i
	InstallCmd    string // the command observed in the workflow definition
}

// RepoExposure is what a single repo had at risk during the window.
type RepoExposure struct {
	Slug        string
	Runs        []Run
	SecretNames []string // names only; canary never reads secret values
	OrgSecrets  bool     // org-level secrets can be injected without appearing on the repo

	// SecretsUnknown is set when the token could not list secrets. It is not
	// the same as "no secrets": one is an unanswered question, the other is an
	// answer, and a report that conflates them understates the risk.
	SecretsUnknown bool
}

// ErrNoToken means no credential was available. Layer 4 is skipped rather than
// guessed: unauthenticated GitHub cannot list runs for private repos or any
// secrets at all, and a silent empty result would read as "no CI activity".
var ErrNoToken = errors.New("ci: no GitHub token (set GITHUB_TOKEN or GH_TOKEN)")

// ErrRateLimited means GitHub refused further queries. Callers must record it
// as a coverage gap; the repos after it were not checked.
var ErrRateLimited = errors.New("ci: GitHub rate limit reached")

// Client queries the GitHub API. The zero value is not usable; use New.
type Client struct {
	gh *github.Client
}

// New builds a client from an explicit token, falling back to GITHUB_TOKEN and
// then GH_TOKEN.
func New(token string) (*Client, error) {
	if token == "" {
		token = firstNonEmpty(os.Getenv("GITHUB_TOKEN"), os.Getenv("GH_TOKEN"))
	}
	if token == "" {
		return nil, ErrNoToken
	}
	return &Client{gh: github.NewClient(nil).WithAuthToken(token)}, nil
}

// NewWithBaseURL is for tests: it points the client at a local server.
func NewWithBaseURL(base string) (*Client, error) {
	c := github.NewClient(nil)
	parsed, err := c.WithEnterpriseURLs(base, base)
	if err != nil {
		return nil, err
	}
	return &Client{gh: parsed}, nil
}

// Query returns the runs and secret surface for slug between since and until.
//
// Runs are fetched with the API's own created filter rather than by paging
// everything and filtering locally — a busy repo has thousands of runs and the
// window is usually days.
func (c *Client) Query(ctx context.Context, slug string, since, until time.Time) (*RepoExposure, error) {
	owner, repo, ok := splitSlug(slug)
	if !ok {
		return nil, fmt.Errorf("ci: %q is not owner/repo", slug)
	}
	out := &RepoExposure{Slug: slug}

	created := ">=" + since.UTC().Format(time.RFC3339)
	if !until.IsZero() {
		created = since.UTC().Format(time.RFC3339) + ".." + until.UTC().Format(time.RFC3339)
	}

	runs, resp, err := c.gh.Actions.ListRepositoryWorkflowRuns(ctx, owner, repo,
		&github.ListWorkflowRunsOptions{
			Created:     created,
			ListOptions: github.ListOptions{PerPage: 100},
		})
	if err != nil {
		return nil, classify(resp, err)
	}
	for _, r := range runs.WorkflowRuns {
		out.Runs = append(out.Runs, Run{
			ID:         r.GetID(),
			Workflow:   r.GetName(),
			Event:      r.GetEvent(),
			Branch:     r.GetHeadBranch(),
			Conclusion: r.GetConclusion(),
			CreatedAt:  r.GetCreatedAt().Time,
		})
	}

	// Secret NAMES only. canary never reads a value, and the API does not
	// expose one — but saying so explicitly is part of the contract.
	secrets, resp, err := c.gh.Actions.ListRepoSecrets(ctx, owner, repo, &github.ListOptions{PerPage: 100})
	switch {
	case err != nil && isRateLimit(resp, err):
		return nil, ErrRateLimited
	case err != nil:
		out.SecretsUnknown = true
	default:
		for _, s := range secrets.Secrets {
			out.SecretNames = append(out.SecretNames, s.Name)
		}
	}

	orgSecrets, resp, err := c.gh.Actions.ListRepoOrgSecrets(ctx, owner, repo, &github.ListOptions{PerPage: 1})
	if err == nil && orgSecrets.TotalCount > 0 {
		out.OrgSecrets = true
	} else if err != nil && isRateLimit(resp, err) {
		return nil, ErrRateLimited
	}

	return out, nil
}

// installRE matches the package-manager invocations that resolve and execute
// dependency code. `npm ci` is included deliberately: installing strictly from
// a lockfile is safer than `npm install`, but it still executes whatever the
// lockfile pins.
var installRE = regexp.MustCompile(`(?m)\b(npm\s+(ci|install|i)\b|yarn\s+(install|--frozen-lockfile)|pnpm\s+(install|i)\b|bun\s+install\b|pip\s+install\b|poetry\s+install\b|bundle\s+install\b|cargo\s+(build|install)\b|go\s+mod\s+download\b)`)

// MarkInstalls reads each run's workflow definition and records whether it
// installs dependencies, and with what command.
//
// This is what turns "a workflow ran" into "a workflow resolved the dependency
// tree" — the only version of the question worth answering.
func (c *Client) MarkInstalls(ctx context.Context, slug string, exp *RepoExposure) error {
	owner, repo, ok := splitSlug(slug)
	if !ok {
		return fmt.Errorf("ci: %q is not owner/repo", slug)
	}

	cache := map[int64]struct {
		installs bool
		cmd      string
	}{}

	for i := range exp.Runs {
		run, resp, err := c.gh.Actions.GetWorkflowRunByID(ctx, owner, repo, exp.Runs[i].ID)
		if err != nil {
			if isRateLimit(resp, err) {
				return ErrRateLimited
			}
			continue
		}
		wfID := run.GetWorkflowID()
		if hit, done := cache[wfID]; done {
			exp.Runs[i].InstalledDeps, exp.Runs[i].InstallCmd = hit.installs, hit.cmd
			continue
		}

		wf, resp, err := c.gh.Actions.GetWorkflowByID(ctx, owner, repo, wfID)
		if err != nil {
			if isRateLimit(resp, err) {
				return ErrRateLimited
			}
			continue
		}
		body, _, _, err := c.gh.Repositories.GetContents(ctx, owner, repo, wf.GetPath(), nil)
		if err != nil || body == nil {
			continue
		}
		text, err := body.GetContent()
		if err != nil {
			continue
		}

		cmd := installRE.FindString(text)
		entry := struct {
			installs bool
			cmd      string
		}{installs: cmd != "", cmd: strings.TrimSpace(cmd)}
		cache[wfID] = entry
		exp.Runs[i].InstalledDeps, exp.Runs[i].InstallCmd = entry.installs, entry.cmd
	}
	return nil
}

// InstallRuns returns only the runs that resolved dependencies. Those are the
// ones that could have executed a poisoned package.
func (e *RepoExposure) InstallRuns() []Run {
	var out []Run
	for _, r := range e.Runs {
		if r.InstalledDeps {
			out = append(out, r)
		}
	}
	return out
}

// Material reports whether this exposure is worth raising, given whether the
// repo actually resolved a malicious version.
//
// This is the rule the whole layer exists to enforce: a run inside the window
// is not a finding on its own, and neither are secrets on their own. Both plus
// a malicious version is the case that justifies naming a credential.
func (e *RepoExposure) Material(maliciousResolved bool) bool {
	if !maliciousResolved || len(e.InstallRuns()) == 0 {
		return false
	}
	return len(e.SecretNames) > 0 || e.OrgSecrets || e.SecretsUnknown
}

func classify(resp *github.Response, err error) error {
	if isRateLimit(resp, err) {
		return ErrRateLimited
	}
	return fmt.Errorf("ci: %w", err)
}

func isRateLimit(resp *github.Response, err error) bool {
	var rl *github.RateLimitError
	var ab *github.AbuseRateLimitError
	if errors.As(err, &rl) || errors.As(err, &ab) {
		return true
	}
	return resp != nil && resp.StatusCode == http.StatusForbidden && resp.Rate.Remaining == 0
}

func splitSlug(slug string) (owner, repo string, ok bool) {
	owner, repo, ok = strings.Cut(strings.TrimSuffix(slug, "/"), "/")
	return owner, repo, ok && owner != "" && repo != ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
