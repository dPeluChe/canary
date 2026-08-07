package ioc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dPeluChe/canary/internal/attack"
)

var windowStart = time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC)

func write(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func atkWith(arts ...attack.Artifact) []attack.Attack {
	return []attack.Attack{{ID: "keyv-2026-08", Started: windowStart, Artifacts: arts}}
}

// The whole reason PathScope exists, now end to end through a real walk: the
// same filename under the compromised package is a finding, under a legitimate
// package it is not.
func TestSweepScopesFilenameArtifacts(t *testing.T) {
	root := t.TempDir()
	bad := write(t, filepath.Join(root, "node_modules", "keyv", "General_Category", "Math_Symbol.js"), "x")
	write(t, filepath.Join(root, "node_modules", "regenerate-unicode-properties", "General_Category", "Math_Symbol.js"), "x")

	res, err := Sweep(root, atkWith(attack.Artifact{
		Kind: attack.KindFilename, Value: "Math_Symbol.js", PathScope: "**/node_modules/keyv/**",
	}), Options{Window: windowStart})
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Findings) != 1 {
		t.Fatalf("want exactly the scoped hit, got %d: %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].Path != bad {
		t.Errorf("wrong file flagged: %s", res.Findings[0].Path)
	}
}

// node_modules is pruned by discover and deliberately walked here: installed
// code is where a dropped payload lives.
func TestSweepWalksIntoNodeModules(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "node_modules", "evil", "index.js"),
		"const c2 = 'npm-cache.com';\n")

	res, err := Sweep(root, atkWith(attack.Artifact{Kind: attack.KindDomain, Value: "npm-cache.com"}),
		Options{Window: windowStart})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("a payload inside node_modules must be found, got %d", len(res.Findings))
	}
	if res.Findings[0].Line != 1 || !strings.Contains(res.Findings[0].Excerpt, "npm-cache.com") {
		t.Errorf("line and excerpt should let a human confirm: %+v", res.Findings[0])
	}
}

// Content and mtime are separate signals. An old file with bad content is
// still a finding, but it is not one that happened inside the window.
func TestSweepReportsWindowSeparatelyFromContent(t *testing.T) {
	root := t.TempDir()
	old := write(t, filepath.Join(root, "old.js"), "npm-cache.com")
	recent := write(t, filepath.Join(root, "recent.js"), "npm-cache.com")

	before := windowStart.Add(-90 * 24 * time.Hour)
	if err := os.Chtimes(old, before, before); err != nil {
		t.Fatal(err)
	}
	after := windowStart.Add(2 * time.Hour)
	if err := os.Chtimes(recent, after, after); err != nil {
		t.Fatal(err)
	}

	res, err := Sweep(root, atkWith(attack.Artifact{Kind: attack.KindDomain, Value: "npm-cache.com"}),
		Options{Window: windowStart})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("both files carry the indicator, got %d", len(res.Findings))
	}
	for _, f := range res.Findings {
		want := filepath.Base(f.Path) == "recent.js"
		if f.InWindow != want {
			t.Errorf("%s: InWindow=%v, want %v", filepath.Base(f.Path), f.InWindow, want)
		}
	}
}

// With no window given, nothing can be placed inside one. Reporting everything
// as in-window would be the alarming answer rather than the correct one.
func TestSweepWithoutAWindowClaimsNothingIsInIt(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "x.js"), "npm-cache.com")

	res, err := Sweep(root, atkWith(attack.Artifact{Kind: attack.KindDomain, Value: "npm-cache.com"}), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].InWindow {
		t.Fatalf("no window means no in-window claim: %+v", res.Findings)
	}
}

// A file too big to search is a coverage gap, not a clean file.
func TestSweepCountsWhatItDidNotRead(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "huge.js"), strings.Repeat("a", 5000)+"npm-cache.com")

	res, err := Sweep(root, atkWith(attack.Artifact{Kind: attack.KindDomain, Value: "npm-cache.com"}),
		Options{MaxFileSize: 100, Window: windowStart})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatal("the file was over the limit and should not have been searched")
	}
	if res.SkippedLarge != 1 {
		t.Fatalf("the skip must be counted, got %d", res.SkippedLarge)
	}
	gaps := res.Gaps()
	if len(gaps) != 1 || !strings.Contains(gaps[0], "NOT searched") {
		t.Errorf("the skip must surface as a gap, got %v", gaps)
	}
}

// Binary files are not searched, and that is not a gap — a domain name inside
// a compiled blob is not evidence a human can act on.
func TestSweepSkipsBinaryWithoutCallingItAGap(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "blob.bin"), "\x00\x01\x02npm-cache.com")

	res, err := Sweep(root, atkWith(attack.Artifact{Kind: attack.KindDomain, Value: "npm-cache.com"}),
		Options{Window: windowStart})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.SkippedBinary != 1 {
		t.Fatalf("findings=%d skippedBinary=%d", len(res.Findings), res.SkippedBinary)
	}
	if len(res.Gaps()) != 0 {
		t.Errorf("a skipped binary is not a coverage gap: %v", res.Gaps())
	}
}

// A content artifact with a scope must not cost a read outside that scope.
// This is the difference between reading a few files and reading a tree.
func TestSweepDoesNotReadOutsideAContentScope(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "public", "sw.js"), "npm-cache.com")
	for i := 0; i < 20; i++ {
		write(t, filepath.Join(root, "src", "f"+string(rune('a'+i))+".js"), "harmless")
	}

	res, err := Sweep(root, atkWith(attack.Artifact{
		Kind: attack.KindDomain, Value: "npm-cache.com", PathScope: "public/**",
	}), Options{Window: windowStart})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want the scoped hit, got %d", len(res.Findings))
	}
	if res.FilesRead != 1 {
		t.Errorf("only the scoped file should have been read, read %d of %d walked",
			res.FilesRead, res.FilesScanned)
	}
}

func TestSweepWithNoArtifactsDoesNothing(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "x.js"), "npm-cache.com")

	res, err := Sweep(root, []attack.Attack{{ID: "empty"}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.FilesScanned != 0 {
		t.Errorf("nothing to look for means no walk: %+v", res)
	}
}

// A forensic sweep must not abort on one unreadable directory.
func TestSweepToleratesUnreadablePaths(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "readable", "x.js"), "npm-cache.com")
	locked := filepath.Join(root, "locked")
	if err := os.MkdirAll(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	res, err := Sweep(root, atkWith(attack.Artifact{Kind: attack.KindDomain, Value: "npm-cache.com"}),
		Options{Window: windowStart})
	if err != nil {
		t.Fatalf("the sweep must survive an unreadable directory: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Errorf("the readable half must still be swept, got %d", len(res.Findings))
	}
}
