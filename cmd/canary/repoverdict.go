package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dPeluChe/canary/internal/ci"
	"github.com/dPeluChe/canary/internal/deps"
	"github.com/dPeluChe/canary/internal/discover"
	"github.com/dPeluChe/canary/internal/inventory"
	"github.com/dPeluChe/canary/internal/ioc"
	"github.com/dPeluChe/canary/internal/verdict"
	"github.com/dPeluChe/canary/internal/zizmor"
)

// ownerMap attributes a path to the repo that contains it — the NEAREST one.
//
// A prefix match alone hands a finding inside a nested repo to its parent:
// a real scan reported labs-canary/cmd/canary/scan_test.go under the workspace
// root, because the workspace is itself a git repo. discover already solved
// this for lockfiles by claiming longest-path first; layer 2 did not, and the
// finding pointed at a repo that does not own the file.
type ownerMap struct {
	inv *discover.Result

	// ownerOf caches the nearest repo per sweep finding path, built once per
	// scan. Without it, attributing per repo per finding made the cross
	// quadratic on a 322-repo tree.
	ownerOf map[string]string
}

// build resolves the owning repo for every finding path, once.
func (o *ownerMap) build(findings []ioc.Finding) {
	o.ownerOf = make(map[string]string, len(findings))
	for _, f := range findings {
		o.ownerOf[f.Path] = o.nearest(f.Path)
	}
}

// nearest returns the longest repo path containing p, or "" when none do.
func (o ownerMap) nearest(p string) string {
	best := ""
	for _, r := range o.inv.Repos {
		if len(r.Path) <= len(best) {
			continue
		}
		if strings.HasPrefix(p, r.Path+string(os.PathSeparator)) {
			best = r.Path
		}
	}
	return best
}

// artifactsUnder attributes sweep findings to the repo that owns them, sorted
// by path: the sweep completes concurrently, so without the sort the same tree
// lists its findings in a different order every run and diffing reports — the
// natural way to answer "what changed since yesterday" — is noise.
func artifactsUnder(o ownerMap, sweep *ioc.Result, repoPath string) []string {
	var out []string
	for _, f := range sweep.Findings {
		if o.ownerOf[f.Path] != repoPath {
			continue
		}
		out = append(out, f.Describe(repoPath))
	}
	sort.Strings(out)
	return out
}

// hasIndicator reports whether any finding under repoPath carries a known
// indicator, as opposed to only having moved inside the window. That is the
// line between confirmed and suspected: a hook edited last week is ordinary,
// a hook containing the C2 domain is not.
func hasIndicator(o ownerMap, sweep *ioc.Result, repoPath string) bool {
	for _, f := range sweep.Findings {
		if f.Artifact != "" && o.ownerOf[f.Path] == repoPath {
			return true
		}
	}
	return false
}

// looseEntry covers what belongs to no repository: lockfiles discover found
// outside any repo, and sweep hits under no repo path.
//
// Both were being dropped. discover reports orphans deliberately — un-repo'd
// checkouts, unpacked tarballs, vendored app directories are exactly where an
// incident tree has stragglers — and a malicious version there was neither
// matched nor declared missing.
func looseEntry(o ownerMap, sweep *ioc.Result, matcher *deps.Matcher, familySeen *int, rep *verdict.Report) *verdict.Repo {
	v := verdict.Repo{Name: "(outside any repo)"}

	var arts []string
	for _, f := range sweep.Findings {
		if underAnyRepo(o, f.Path) {
			continue
		}
		arts = append(arts, f.Describe(o.inv.Root))
	}
	sort.Strings(arts)
	v.Artifacts = arts

	var all []deps.Resolved
	checked := 0
	for _, lf := range o.inv.Orphans {
		if !deps.Supported(lf.Kind) {
			rep.AddGap("lockfile kind %q has no extractor yet — those files were not read", lf.Kind)
			continue
		}
		res, err := deps.Extract(lf)
		if err != nil {
			rep.AddGap("%s could not be read: %v", lf.Path, err)
			continue
		}
		all = append(all, res...)
		checked++
	}
	for _, f := range matcher.Match(all) {
		v.MaliciousDeps = append(v.MaliciousDeps, describeFinding(f))
	}
	*familySeen += len(matcher.MatchIgnoringVersions(all))

	if len(v.MaliciousDeps) == 0 && len(v.Artifacts) == 0 && checked == 0 {
		return nil
	}
	switch {
	case len(v.MaliciousDeps) > 0:
		v.Status = verdict.Confirmed
	case len(v.Artifacts) > 0:
		v.Status = verdict.Suspected
	default:
		v.Status = verdict.Clean
	}
	v.Reason = fmt.Sprintf("%d package(s) from %d orphan lockfile(s) outside any git repo", len(all), checked)
	return &v
}

func underAnyRepo(o ownerMap, path string) bool {
	return o.nearest(path) != ""
}

// repoScan carries what one repo's verdict needs, shared across the concurrent
// per-repo loop.
type repoScan struct {
	matcher  *deps.Matcher
	owners   ownerMap
	sweep    *ioc.Result
	window   time.Time
	zizmorOK bool
	ciClient *ci.Client

	rep     *verdict.Report
	builder *inventory.Builder

	scanMu     sync.Mutex
	familySeen int
}

// verdictFor computes one repo's verdict. It is the body of what cmdScan ran
// per repo before the loop went concurrent; the logic is unchanged.
func (rc *repoScan) verdictFor(repo discover.Repo) verdict.Repo {
	v := verdict.Repo{Name: repo.Name, Slug: repo.Slug}
	v.Artifacts = artifactsUnder(rc.owners, rc.sweep, repo.Path)

	var all []deps.Resolved
	checked, skipped := 0, 0
	for _, lf := range repo.Lockfiles {
		if !deps.Supported(lf.Kind) {
			skipped++
			rc.rep.AddGap("lockfile kind %q has no extractor yet — those files were not read", lf.Kind)
			continue
		}
		res, err := deps.Extract(lf)
		if err != nil {
			skipped++
			rc.rep.AddGap("%s could not be read: %v", lf.Rel, err)
			continue
		}
		all = append(all, res...)
		checked++
	}
	rc.scanMu.Lock()
	rc.builder.Add(repo, all, checked, skipped)
	rc.scanMu.Unlock()

	// Layer 1 having nothing to read does NOT end the repo: layers 3 and 4
	// still apply, and a repo with no lockfiles can still ship a
	// dangerous workflow. Skipping here was silently dropping them.
	depsSkipped := checked == 0
	if depsSkipped {
		switch {
		case len(repo.Lockfiles) == 0:
			v.Reason = "no lockfiles"
		default:
			v.Reason = fmt.Sprintf("%d lockfile(s), none readable by this build", skipped)
		}
	}

	for _, f := range rc.matcher.Match(all) {
		v.MaliciousDeps = append(v.MaliciousDeps, describeFinding(f))
	}

	// Self-validation: can the extractor see these families AT ALL? A
	// negative from an extractor never observed matching anything is
	// worthless — this is the manual step from JOURNAL/2608.md.
	visible := rc.matcher.MatchIgnoringVersions(all)
	rc.scanMu.Lock()
	rc.familySeen += len(visible)
	rc.scanMu.Unlock()

	// Evidence outranks the skip. Layer 1 having nothing to read must never
	// hide a layer-2 hit: a repo with a dropped payload and no lockfile is
	// compromised, not unchecked.
	switch {
	case len(v.MaliciousDeps) > 0 || hasIndicator(rc.owners, rc.sweep, repo.Path):
		v.Status = verdict.Confirmed
		v.Reason = fmt.Sprintf("%d package(s) resolved from %d lockfile(s)", len(all), checked)
	case len(v.Artifacts) > 0:
		// Persistence with no known indicator: a location moved inside the
		// window. Real enough to name, not enough to call confirmed.
		v.Status = verdict.Suspected
		v.Reason = fmt.Sprintf("%d package(s) resolved from %d lockfile(s); no malicious version, but a persistence location moved inside the window", len(all), checked)
	case depsSkipped:
		v.Status = verdict.Skipped
	default:
		v.Status = verdict.Clean
		v.Reason = fmt.Sprintf("%d packages from %d lockfile(s), no known-malicious version", len(all), checked)
		if len(visible) > 0 {
			v.Reason += fmt.Sprintf("; %d package(s) of an affected family present at safe versions", len(visible))
		}
	}
	if rc.zizmorOK {
		// zizmor answers "could this workflow be abused", not "were you
		// attacked". That is Suspected at most: it never escalates a repo
		// the forensic layers found clean.
		if hits, zErr := zizmor.Run(context.Background(), repo.Path); zErr != nil {
			rc.rep.AddGap("layer 3 could not audit %s: %v", repo.Name, zErr)
		} else if len(hits) > 0 {
			for _, h := range hits {
				v.Artifacts = append(v.Artifacts, "workflow: "+h.Describe())
			}
			if v.Status == verdict.Clean || v.Status == verdict.Skipped {
				v.Status = verdict.Suspected
				v.Reason = fmt.Sprintf("%s; %d workflow weakness(es) reported by zizmor", v.Reason, len(hits))
			}
		}
	}

	if rc.ciClient != nil && repo.Slug != "" {
		checkCI(rc.ciClient, rc.rep, &v, repo.Slug, rc.window, len(v.MaliciousDeps) > 0)
	}
	return v
}
