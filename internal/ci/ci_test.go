package ci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var window = time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC)

// fakeGitHub serves canned responses. Tests never touch the network, the same
// rule the other layers follow for the filesystem.
func fakeGitHub(t *testing.T, routes map[string]any) *Client {
	t.Helper()
	mux := http.NewServeMux()
	for path, body := range routes {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := NewWithBaseURL(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func workflowFile(body string) map[string]any {
	return map[string]any{
		"type":     "file",
		"encoding": "base64",
		"name":     "ci.yml",
		"path":     ".github/workflows/ci.yml",
		"content":  base64.StdEncoding.EncodeToString([]byte(body)),
	}
}

func TestQueryReturnsRunsAndSecretNames(t *testing.T) {
	c := fakeGitHub(t, map[string]any{
		"/api/v3/repos/acme/app/actions/runs": map[string]any{
			"total_count": 1,
			"workflow_runs": []map[string]any{{
				"id": 42, "name": "build", "event": "push", "head_branch": "main",
				"conclusion": "success", "created_at": "2026-08-04T12:00:00Z",
			}},
		},
		"/api/v3/repos/acme/app/actions/secrets": map[string]any{
			"total_count": 2,
			"secrets": []map[string]any{
				{"name": "NPM_TOKEN"}, {"name": "AWS_ACCESS_KEY_ID"},
			},
		},
		"/api/v3/repos/acme/app/actions/organization-secrets": map[string]any{
			"total_count": 0, "secrets": []map[string]any{},
		},
	})

	exp, err := c.Query(context.Background(), "acme/app", window, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(exp.Runs) != 1 || exp.Runs[0].ID != 42 {
		t.Fatalf("runs: %+v", exp.Runs)
	}
	if len(exp.SecretNames) != 2 || exp.SecretNames[0] != "NPM_TOKEN" {
		t.Errorf("secret names: %v", exp.SecretNames)
	}
	if exp.SecretsUnknown {
		t.Error("secrets were listed, so they are not unknown")
	}
}

// "could not list secrets" and "there are no secrets" are different answers.
// Conflating them understates the risk.
func TestQuerySeparatesUnknownSecretsFromNone(t *testing.T) {
	c := fakeGitHub(t, map[string]any{
		"/api/v3/repos/acme/app/actions/runs": map[string]any{
			"total_count": 0, "workflow_runs": []map[string]any{},
		},
		// secrets endpoint absent -> 404 -> unknown, not empty
	})

	exp, err := c.Query(context.Background(), "acme/app", window, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !exp.SecretsUnknown {
		t.Error("a failed secrets listing must be recorded as unknown")
	}
	if len(exp.SecretNames) != 0 {
		t.Errorf("no names should be invented: %v", exp.SecretNames)
	}
}

// The distinction that makes layer 4 worth anything: a workflow that ran is
// not the same as a workflow that resolved the dependency tree.
func TestMarkInstallsReadsTheWorkflowDefinition(t *testing.T) {
	c := fakeGitHub(t, map[string]any{
		"/api/v3/repos/acme/app/actions/runs": map[string]any{
			"total_count": 2,
			"workflow_runs": []map[string]any{
				{"id": 1, "name": "build", "created_at": "2026-08-04T12:00:00Z"},
				{"id": 2, "name": "lint", "created_at": "2026-08-04T13:00:00Z"},
			},
		},
		"/api/v3/repos/acme/app/actions/secrets": map[string]any{"total_count": 0, "secrets": []map[string]any{}},
		"/api/v3/repos/acme/app/actions/runs/1":  map[string]any{"id": 1, "workflow_id": 100},
		"/api/v3/repos/acme/app/actions/runs/2":  map[string]any{"id": 2, "workflow_id": 200},
		"/api/v3/repos/acme/app/actions/workflows/100": map[string]any{
			"id": 100, "path": ".github/workflows/build.yml",
		},
		"/api/v3/repos/acme/app/actions/workflows/200": map[string]any{
			"id": 200, "path": ".github/workflows/lint.yml",
		},
		"/api/v3/repos/acme/app/contents/.github/workflows/build.yml": workflowFile(
			"jobs:\n  build:\n    steps:\n      - run: npm ci\n      - run: npm test\n"),
		"/api/v3/repos/acme/app/contents/.github/workflows/lint.yml": workflowFile(
			"jobs:\n  lint:\n    steps:\n      - run: echo lint only\n"),
	})

	exp, err := c.Query(context.Background(), "acme/app", window, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.MarkInstalls(context.Background(), "acme/app", exp); err != nil {
		t.Fatal(err)
	}

	installs := exp.InstallRuns()
	if len(installs) != 1 || installs[0].ID != 1 {
		t.Fatalf("only the build workflow installs: %+v", exp.Runs)
	}
	if installs[0].InstallCmd != "npm ci" {
		t.Errorf("the observed command should be reported, got %q", installs[0].InstallCmd)
	}
}

// THE rule of this layer. A run inside the window is not a finding on its own,
// and neither are secrets. Reporting runs alone produces alarm without
// information.
func TestMaterialRequiresAllThreeSignals(t *testing.T) {
	installing := &RepoExposure{
		Runs:        []Run{{ID: 1, InstalledDeps: true}},
		SecretNames: []string{"NPM_TOKEN"},
	}
	cases := []struct {
		name              string
		exp               *RepoExposure
		maliciousResolved bool
		want              bool
	}{
		{"install run + secrets + malicious version", installing, true, true},
		{"install run + secrets, nothing malicious resolved", installing, false, false},
		{"malicious version but no run installed", &RepoExposure{
			Runs: []Run{{ID: 1, InstalledDeps: false}}, SecretNames: []string{"X"}}, true, false},
		{"malicious version, install run, no secrets to steal", &RepoExposure{
			Runs: []Run{{ID: 1, InstalledDeps: true}}}, true, false},
		{"secrets unlistable counts as exposure, not as absence", &RepoExposure{
			Runs: []Run{{ID: 1, InstalledDeps: true}}, SecretsUnknown: true}, true, true},
		{"org secrets can be injected without appearing on the repo", &RepoExposure{
			Runs: []Run{{ID: 1, InstalledDeps: true}}, OrgSecrets: true}, true, true},
	}
	for _, tc := range cases {
		if got := tc.exp.Material(tc.maliciousResolved); got != tc.want {
			t.Errorf("%s: Material = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A rate limit must be distinguishable, so the caller can say which repos were
// never checked instead of reporting them as clean.
func TestQuerySurfacesRateLimit(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Limit", "5000")
		http.Error(w, `{"message":"API rate limit exceeded"}`, http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := NewWithBaseURL(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Query(context.Background(), "acme/app", window, time.Time{}); err != ErrRateLimited {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
}

func TestNewWithoutATokenRefusesRatherThanGuessing(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	if _, err := New(""); err != ErrNoToken {
		t.Fatalf("want ErrNoToken, got %v", err)
	}
}

func TestQueryRejectsABadSlug(t *testing.T) {
	c := fakeGitHub(t, nil)
	if _, err := c.Query(context.Background(), "not-a-slug", window, time.Time{}); err == nil {
		t.Fatal("want an error for a slug without an owner")
	}
}

func TestInstallRegexpCoversTheCommonManagers(t *testing.T) {
	yes := []string{
		"      - run: npm ci\n", "- run: npm install --production",
		"- run: pnpm i --frozen-lockfile", "- run: bun install", "- run: yarn install",
		"- run: pip install -r requirements.txt", "- run: go mod download",
	}
	for _, s := range yes {
		if !installRE.MatchString(s) {
			t.Errorf("should match an install: %q", s)
		}
	}
	no := []string{"- run: npm run build", "- run: echo installing", "- run: npm audit"}
	for _, s := range no {
		if installRE.MatchString(s) {
			t.Errorf("should NOT match: %q", s)
		}
	}
	if got := strings.TrimSpace(installRE.FindString("- run: npm ci --silent")); got != "npm ci" {
		t.Errorf("reported command: got %q", got)
	}
}
