package ioc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dPeluChe/canary/internal/attack"
)

func aged(t *testing.T, path string, when time.Time) {
	t.Helper()
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

var (
	beforeWindow = windowStart.Add(-120 * 24 * time.Hour)
	insideWindow = windowStart.Add(3 * time.Hour)
)

// The differentiator: an agent hook written during the window is reported even
// though nothing about its content is known to be bad.
func TestPersistenceReportsAHookTouchedInsideTheWindow(t *testing.T) {
	repo := t.TempDir()
	hook := write(t, filepath.Join(repo, ".claude", "hooks", "on-start.sh"), "#!/bin/sh\necho hi\n")
	aged(t, hook, insideWindow)

	res, err := Persistence(repo, RepoTargets, nil, Options{Window: windowStart})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want the hook reported, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if !f.Persistent || !f.InWindow || f.Artifact != "" {
		t.Errorf("mtime-only finding: %+v", f)
	}
	if !strings.Contains(f.Describe(repo), "verify by hand") {
		t.Errorf("an mtime-only hit must ask for a human, got %q", f.Describe(repo))
	}
}

// An untouched file is a strong negative and has to be counted, otherwise a
// clean verdict cannot say what it actually checked.
func TestPersistenceCountsUntouchedTargetsAsEvidence(t *testing.T) {
	repo := t.TempDir()
	old := write(t, filepath.Join(repo, ".vscode", "tasks.json"), `{"version":"2.0.0"}`)
	aged(t, old, beforeWindow)

	res, err := Persistence(repo, RepoTargets, nil, Options{Window: windowStart})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("an old untouched file is not a finding: %+v", res.Findings)
	}
	if res.PersistenceChecked != 1 || res.PersistenceUntouched != 1 {
		t.Errorf("checked=%d untouched=%d, both should be 1", res.PersistenceChecked, res.PersistenceUntouched)
	}
}

// Content is the strong signal: an old mtime does not excuse a known indicator.
func TestPersistenceReportsIndicatorEvenWithAnOldMtime(t *testing.T) {
	repo := t.TempDir()
	p := write(t, filepath.Join(repo, ".vscode", "tasks.json"), "{\"cmd\":\"curl npm-cache.com\"}")
	aged(t, p, beforeWindow)

	atk := []attack.Attack{{ID: "keyv-2026-08", Started: windowStart,
		Artifacts: []attack.Artifact{{Kind: attack.KindDomain, Value: "npm-cache.com"}}}}

	res, err := Persistence(repo, RepoTargets, atk, Options{Window: windowStart})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want the indicator reported, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Artifact != "npm-cache.com" || f.InWindow {
		t.Errorf("want a content hit outside the window: %+v", f)
	}
	if !strings.Contains(f.Describe(repo), "outside the window") {
		t.Errorf("the description must not imply it happened in the window: %q", f.Describe(repo))
	}
}

// git ships *.sample hooks inert. Flagging them would bury the one hook that
// matters under nine that never run.
func TestPersistenceIgnoresGitSampleHooks(t *testing.T) {
	repo := t.TempDir()
	for _, n := range []string{"pre-commit.sample", "pre-push.sample"} {
		p := write(t, filepath.Join(repo, ".git", "hooks", n), "#!/bin/sh\n")
		aged(t, p, insideWindow)
	}
	real := write(t, filepath.Join(repo, ".git", "hooks", "pre-commit"), "#!/bin/sh\ncurl evil\n")
	aged(t, real, insideWindow)

	res, err := Persistence(repo, RepoTargets, nil, Options{Window: windowStart})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("only the real hook should be reported, got %d: %+v", len(res.Findings), res.Findings)
	}
	if filepath.Base(res.Findings[0].Path) != "pre-commit" {
		t.Errorf("wrong hook flagged: %s", res.Findings[0].Path)
	}
}

// The deploy-surface family, which the web-check evaluation added. A service
// worker persists in the visitor's browser, not on this machine.
func TestPersistenceCoversTheDeploySurface(t *testing.T) {
	repo := t.TempDir()
	sw := write(t, filepath.Join(repo, "public", "sw.js"), "self.addEventListener('fetch', e => {})")
	aged(t, sw, insideWindow)

	res, err := Persistence(repo, RepoTargets, nil, Options{Window: windowStart})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want the service worker reported, got %d", len(res.Findings))
	}
	if res.Findings[0].Family != FamilyDeploy {
		t.Errorf("family: got %q, want %q", res.Findings[0].Family, FamilyDeploy)
	}
	if !strings.Contains(res.Findings[0].Note, "survives a redeploy") {
		t.Errorf("the note should say why this one is worse: %q", res.Findings[0].Note)
	}
}

// Home targets are a separate list because they sit outside the scanned tree.
func TestPersistenceHomeTargets(t *testing.T) {
	home := t.TempDir()
	rc := write(t, filepath.Join(home, ".zshrc"), "export PATH=$PATH\n")
	aged(t, rc, insideWindow)
	old := write(t, filepath.Join(home, ".profile"), "\n")
	aged(t, old, beforeWindow)

	res, err := Persistence(home, HomeTargets, nil, Options{Window: windowStart})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || filepath.Base(res.Findings[0].Path) != ".zshrc" {
		t.Fatalf("want only the recently touched profile: %+v", res.Findings)
	}
	if res.PersistenceUntouched != 1 {
		t.Errorf("the untouched profile is evidence and must be counted, got %d", res.PersistenceUntouched)
	}
}

// A target that does not exist is not checked and must not be counted as
// inspected — claiming coverage of a file that is not there is the same lie as
// a silent skip.
func TestPersistenceDoesNotCountAbsentTargets(t *testing.T) {
	res, err := Persistence(t.TempDir(), RepoTargets, nil, Options{Window: windowStart})
	if err != nil {
		t.Fatal(err)
	}
	if res.PersistenceChecked != 0 || len(res.Findings) != 0 {
		t.Errorf("empty repo: checked=%d findings=%d", res.PersistenceChecked, len(res.Findings))
	}
}

func TestResultMergeAccumulates(t *testing.T) {
	a := &Result{Findings: []Finding{{Path: "a"}}, PersistenceChecked: 2, SkippedLarge: 1}
	b := &Result{Findings: []Finding{{Path: "b"}}, PersistenceChecked: 3, PersistenceUntouched: 1}
	a.Merge(b)
	a.Merge(nil)

	if len(a.Findings) != 2 || a.PersistenceChecked != 5 || a.PersistenceUntouched != 1 || a.SkippedLarge != 1 {
		t.Errorf("merge lost data: %+v", a)
	}
}
