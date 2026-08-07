package zizmor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A workflow with several real weaknesses: a pull_request_target trigger that
// checks out untrusted code, an unpinned action, and template injection.
const vulnerableWorkflow = `name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
      - run: npm ci
`

func repoWithWorkflow(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func requireZizmor(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("zizmor"); err != nil {
		t.Skip("zizmor not installed; the absent path is covered by TestRunWithoutZizmor")
	}
}

// zizmor exits 14 when it finds something, so exit status alone cannot tell
// findings from failure. Parsing its output is the only reliable signal.
func TestRunParsesRealZizmorOutput(t *testing.T) {
	requireZizmor(t)
	root := repoWithWorkflow(t, vulnerableWorkflow)

	found, err := Run(context.Background(), root)
	if err != nil {
		t.Fatalf("a non-zero exit means findings, not failure: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("this workflow has known weaknesses and should produce findings")
	}

	byAudit := map[string]Finding{}
	for _, f := range found {
		byAudit[f.Audit] = f
	}
	for _, want := range []string{"dangerous-triggers", "template-injection"} {
		if _, ok := byAudit[want]; !ok {
			t.Errorf("expected the %s audit to fire, got %v", want, keys(byAudit))
		}
	}

	f := byAudit["template-injection"]
	if f.Severity == "" || f.URL == "" {
		t.Errorf("severity and doc link must survive parsing: %+v", f)
	}
	if !strings.HasSuffix(f.File, "ci.yml") || filepath.IsAbs(f.File) {
		t.Errorf("path should be relative to the repo, got %q", f.File)
	}
	// zizmor rows are 0-indexed; a report that is off by one sends a human to
	// the wrong line.
	if f.Line < 1 {
		t.Errorf("line should be 1-indexed, got %d", f.Line)
	}
}

// A repo with no workflows is a real answer, not a coverage gap.
func TestRunWithNoWorkflowsIsNotAGap(t *testing.T) {
	found, err := Run(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("no workflows should not error: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("nothing to audit: %v", found)
	}
}

// The case that matters most: zizmor absent must be distinguishable, so the
// caller can print a gap instead of an implied pass.
func TestRunWithoutZizmorIsDistinguishable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	if _, err := Available(context.Background()); err != ErrNotInstalled {
		t.Errorf("Available: want ErrNotInstalled, got %v", err)
	}
	_, err := Run(context.Background(), repoWithWorkflow(t, vulnerableWorkflow))
	if err != ErrNotInstalled {
		t.Fatalf("Run: want ErrNotInstalled, got %v", err)
	}
}

func TestDescribeLeadsWithSeverity(t *testing.T) {
	f := Finding{
		Audit: "template-injection", Desc: "code injection via template expansion",
		Severity: "High", Confidence: "High", File: ".github/workflows/ci.yml", Line: 10,
		URL: "https://docs.zizmor.sh/audits/#template-injection",
	}
	got := f.Describe()
	if !strings.HasPrefix(got, "HIGH ") {
		t.Errorf("severity should lead so the worst reads first: %q", got)
	}
	if !strings.Contains(got, "ci.yml:10") || !strings.Contains(got, "docs.zizmor.sh") {
		t.Errorf("location and doc link must be actionable: %q", got)
	}
}

func keys(m map[string]Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
