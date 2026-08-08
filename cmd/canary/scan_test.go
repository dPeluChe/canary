package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests exist because three of the four defects an adversarial audit
// found lived in this file, and none of them could have been caught by the
// package tests: every internal package worked correctly in isolation while
// the assembly dropped evidence on the floor.
//
// What they pin is the orchestration — which status wins, what reaches the
// report, and which exit code comes out.

const attackFile = `{
  "schema": 1,
  "id": "keyv-2026-08",
  "name": "keyv npm compromise",
  "started": "2026-08-04T09:00:00Z",
  "source": "https://example.invalid/keyv",
  "packages": [{"ecosystem": "npm", "name": "keyv", "versions": ["6.0.0"]}],
  "artifacts": [{"kind": "domain", "value": "npm-cache-evil.invalid", "note": "C2"}]
}`

type tree struct {
	root, attacks string
}

func newTree(t *testing.T) *tree {
	t.Helper()
	base := t.TempDir()
	// Never write into the developer's home during a test run.
	t.Setenv("CANARY_DATA_DIR", filepath.Join(base, "data"))
	tr := &tree{root: filepath.Join(base, "tree"), attacks: filepath.Join(base, "attacks")}
	writeFile(t, filepath.Join(tr.attacks, "keyv.json"), attackFile)
	if err := os.MkdirAll(tr.root, 0o755); err != nil {
		t.Fatal(err)
	}
	return tr
}

// repo creates a git repo. lockfile is written verbatim when non-empty.
func (tr *tree) repo(t *testing.T, name, lockName, lockBody string) string {
	t.Helper()
	dir := filepath.Join(tr.root, name)
	writeFile(t, filepath.Join(dir, ".git", "config"), "[core]\n")
	if lockName != "" {
		writeFile(t, filepath.Join(dir, lockName), lockBody)
	}
	return dir
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func lockWith(version string) string {
	return `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/keyv":{"version":"` + version + `"}}}`
}

// run executes cmdScan with stdout captured, returning the text and exit code.
// -home=false keeps the developer's own machine out of a unit test.
func (tr *tree) run(t *testing.T, extra ...string) (string, int) {
	t.Helper()
	args := append([]string{"-dir", tr.attacks, "-home=false"}, extra...)
	args = append(args, tr.root)

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	code := cmdScan(args)

	w.Close()
	os.Stdout = orig
	out, _ := io.ReadAll(r)
	return string(out), code
}

// 1. A malicious version resolved from a lockfile is CONFIRMED and exits 1.
func TestScanConfirmsAMaliciousDependency(t *testing.T) {
	tr := newTree(t)
	tr.repo(t, "infected", "package-lock.json", lockWith("6.0.0"))

	out, code := tr.run(t)
	if code != exitFindings {
		t.Fatalf("exit = %d, want %d\n%s", code, exitFindings, out)
	}
	if !strings.Contains(out, "CONFIRMED") || !strings.Contains(out, "npm/keyv@6.0.0") {
		t.Errorf("the finding must be named:\n%s", out)
	}
}

// 2. THE regression. A repo with no readable lockfile but a known indicator on
// disk is CONFIRMED, not SKIPPED. Layer 1 having nothing to read must never
// hide a layer-2 hit — the evidence was previously kept in memory and withheld.
func TestScanDoesNotLetASkipHideAnOnDiskIndicator(t *testing.T) {
	tr := newTree(t)
	dir := tr.repo(t, "noLockfile", "", "")
	writeFile(t, filepath.Join(dir, "src", "app.js"), `const c2 = "npm-cache-evil.invalid";`)

	out, code := tr.run(t)
	if code != exitFindings {
		t.Fatalf("a repo with a dropped payload must not exit clean: exit=%d\n%s", code, out)
	}
	if strings.Contains(out, "SKIPPED — 1") {
		t.Errorf("the repo was checked and it hit; SKIPPED means not checked:\n%s", out)
	}
	if !strings.Contains(out, "npm-cache-evil.invalid") {
		t.Errorf("the indicator must reach the text report, not only the JSON:\n%s", out)
	}
}

// 3. A lockfile kind with no extractor is SKIPPED with a gap, never CLEAN.
func TestScanSkipsUnsupportedLockfilesAndSaysSo(t *testing.T) {
	tr := newTree(t)
	tr.repo(t, "rustapp", "Cargo.lock", "[[package]]\nname = \"x\"\n")

	out, code := tr.run(t)
	if code != exitClean {
		t.Fatalf("nothing was found, exit should be clean: %d", code)
	}
	if !strings.Contains(out, "SKIPPED") {
		t.Errorf("an unread lockfile is not a clean repo:\n%s", out)
	}
	if !strings.Contains(out, "Cargo.lock") {
		t.Errorf("the gap must name the kind that was not read:\n%s", out)
	}
}

// 4. A genuinely clean repo is CLEAN and exits 0.
func TestScanReportsACleanRepo(t *testing.T) {
	tr := newTree(t)
	tr.repo(t, "safe", "package-lock.json", lockWith("4.5.4"))

	out, code := tr.run(t)
	if code != exitClean {
		t.Fatalf("exit = %d, want clean\n%s", code, out)
	}
	if !strings.Contains(out, "CLEAN") || strings.Contains(out, "CONFIRMED") {
		t.Errorf("a safe version of an affected package is not a finding:\n%s", out)
	}
	// Self-validation: the extractor must be shown to see the family at all.
	if !strings.Contains(out, "affected family present at safe versions") {
		t.Errorf("a clean result must carry the proof that makes it trustworthy:\n%s", out)
	}
}

// 5. An orphan lockfile — outside any git repo — is still scanned. Unpacked
// tarballs and vendored app directories are where an incident tree strays.
func TestScanCoversLockfilesOutsideAnyRepo(t *testing.T) {
	tr := newTree(t)
	tr.repo(t, "somerepo", "package-lock.json", lockWith("4.5.4"))
	writeFile(t, filepath.Join(tr.root, "unpacked", "package-lock.json"), lockWith("6.0.0"))

	out, code := tr.run(t)
	if code != exitFindings {
		t.Fatalf("a malicious version outside a repo must still be found: exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "outside any repo") || !strings.Contains(out, "npm/keyv@6.0.0") {
		t.Errorf("the orphan hit must be named:\n%s", out)
	}
}

// 6. Zero attacks loaded is exit 2, never 0. A scan with nothing to match
// against reports clean for the same reason a scan that never ran does.
func TestScanRefusesToRunWithNoAttacksLoaded(t *testing.T) {
	tr := newTree(t)
	tr.repo(t, "any", "package-lock.json", lockWith("6.0.0"))
	empty := t.TempDir()

	if code := cmdScan([]string{"-dir", empty, "-home=false", tr.root}); code != exitError {
		t.Fatalf("exit = %d, want %d — an empty attack set is not a clean scan", code, exitError)
	}
}

// The gaps are half the output, and machine-readable consumers need them too.
func TestScanJSONCarriesStatusAndGaps(t *testing.T) {
	tr := newTree(t)
	tr.repo(t, "infected", "package-lock.json", lockWith("6.0.0"))

	out, _ := tr.run(t, "-format", "json")
	var rep struct {
		Repos []struct {
			Name          string   `json:"name"`
			Status        string   `json:"status"`
			MaliciousDeps []string `json:"maliciousDeps"`
		} `json:"repos"`
		Gaps []string `json:"gaps"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("json render: %v\n%s", err, out)
	}
	if len(rep.Repos) != 1 || rep.Repos[0].Status != "CONFIRMED" {
		t.Fatalf("repos: %+v", rep.Repos)
	}
	if len(rep.Gaps) == 0 {
		t.Error("a run that skipped layers 3 and 4 must say so in JSON too")
	}
}

// A finding inside a nested repository belongs to that repository, not to its
// parent. discover already claims lockfiles longest-path-first; layer 2 used a
// bare prefix match, so a real scan reported labs-canary/cmd/canary/scan_test.go
// under the workspace root — which is itself a git repo and does not own the
// file. Found by running the binary on a real tree, not by a test or an audit.
func TestArtifactsBelongToTheNearestRepo(t *testing.T) {
	tr := newTree(t)
	outer := tr.repo(t, "outer", "", "")
	inner := filepath.Join(outer, "nested")
	writeFile(t, filepath.Join(inner, ".git", "config"), "[core]\n")
	writeFile(t, filepath.Join(inner, "src", "payload.js"), `fetch("npm-cache-evil.invalid")`)

	out, code := tr.run(t, "-v")
	if code != exitFindings {
		t.Fatalf("the payload must be found: exit=%d\n%s", code, out)
	}

	var current string
	attributed := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "outer" || trimmed == "nested":
			current = trimmed
		case strings.Contains(trimmed, "payload.js") && current != "":
			attributed[current] = trimmed
		}
	}
	if _, wrong := attributed["outer"]; wrong {
		t.Errorf("the parent repo must not claim a nested repo's finding:\n%s", out)
	}
	if _, right := attributed["nested"]; !right {
		t.Errorf("the nested repo must own its own finding:\n%s", out)
	}
}

// -reuse answers one question — does a newly published attack touch the set we
// already resolved — and must therefore touch nothing: no walk, no sweep, no
// network. Walking the tree first would cost what a full scan costs and defeat
// the artifact entirely.
func TestScanReuseMatchesTheStoredInventoryWithoutReadingTheTree(t *testing.T) {
	tr := newTree(t)
	tr.repo(t, "app", "package-lock.json", lockWith("6.0.0"))

	if _, code := tr.run(t); code != exitFindings {
		t.Fatal("the first scan must build the inventory")
	}

	// Delete the tree entirely. A reuse run that still works proves it read
	// nothing but the inventory.
	if err := os.RemoveAll(filepath.Join(tr.root, "app")); err != nil {
		t.Fatal(err)
	}

	out, code := tr.run(t, "-reuse")
	if code != exitFindings {
		t.Fatalf("the stored set still contains the malicious version: exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "npm/keyv@6.0.0") {
		t.Errorf("the finding must come from the inventory:\n%s", out)
	}
	for _, want := range []string{"was NOT re-read", "layers 2, 3 and 4 did NOT run"} {
		if !strings.Contains(out, want) {
			t.Errorf("a fast answer must not imply a full sweep, missing %q:\n%s", want, out)
		}
	}
}

// Without an inventory, -reuse must refuse rather than report an empty tree.
func TestScanReuseWithoutAnInventoryRefuses(t *testing.T) {
	tr := newTree(t)
	tr.repo(t, "app", "package-lock.json", lockWith("6.0.0"))

	if _, code := tr.run(t, "-reuse"); code != exitError {
		t.Fatal("no inventory is a canary failure, not a clean tree")
	}
}

// A full scan must not write into the tree it inspects, inventory included.
func TestInventoryIsNotWrittenIntoTheScannedTree(t *testing.T) {
	tr := newTree(t)
	tr.repo(t, "app", "package-lock.json", lockWith("4.5.4"))

	before := take(t, tr.root)
	if _, code := tr.run(t); code != exitClean {
		t.Fatal("fixture should be clean")
	}
	if changes := diff(t, before, take(t, tr.root)); len(changes) > 0 {
		t.Errorf("the inventory must live in canary's data dir, not the tree:\n  %v", changes)
	}
}

// Material() is false for two reachable reasons — no malicious version
// resolved, or nothing reachable to steal — and they are opposite findings.
// One message covering both told a human "no malicious version resolved" about
// a repo that had one: the report lying about what was checked.
func TestCIReasonNamesTheActualNegative(t *testing.T) {
	nothingMalicious := ciReason(3, false)
	if !strings.Contains(nothingMalicious, "no malicious version resolved") {
		t.Errorf("got %q", nothingMalicious)
	}

	nothingToSteal := ciReason(3, true)
	if strings.Contains(nothingToSteal, "no malicious version resolved") {
		t.Errorf("a repo WITH a malicious version must not be told it had none: %q", nothingToSteal)
	}
	if !strings.Contains(nothingToSteal, "no reachable secrets") {
		t.Errorf("the real reason must be named: %q", nothingToSteal)
	}
	if !strings.Contains(nothingToSteal, "WITH a malicious version resolved") {
		t.Errorf("the reader must still see that a malicious version was present: %q", nothingToSteal)
	}
}
