package corpus

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dPeluChe/canary/internal/attack"
)

func writeManifest(t *testing.T, root, subdir, body string) {
	t.Helper()
	dir := filepath.Join(root, "samples", subdir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The subdirectory names DataDog actually publishes, verified against the
// repository. Upstream mixes separators — ai-skills with a hyphen,
// ide_extensions with an underscore — and a map that guesses one spelling
// fails the whole load, since an unknown subdir is deliberately fatal.
func TestLoadDataDogAcceptsTheRealSubdirNames(t *testing.T) {
	for _, subdir := range []string{"npm", "pypi", "ide_extensions", "ai-skills"} {
		dir := t.TempDir()
		writeManifest(t, dir, subdir, `{"evil": null}`)
		if _, err := LoadDataDog(dir); err != nil {
			t.Errorf("subdir %q published by DataDog was rejected: %v", subdir, err)
		}
	}
}

func TestLoadDataDogIsMalicious(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "npm", `{
	  "keyv": ["6.0.0"],
	  "cacheable-request": ["13.0.20", "13.0.21"],
	  "wholly-bad": null
	}`)
	writeManifest(t, dir, "pypi", `{"badlib": ["1.0.0"]}`)

	c, err := LoadDataDog(dir)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		eco, name, version string
		want               bool
	}{
		{"npm", "keyv", "6.0.0", true},
		{"npm", "keyv", "5.1.0", false},
		{"npm", "cacheable-request", "13.0.21", true},
		{"npm", "cacheable-request", "13.0.19", false},
		{"npm", "wholly-bad", "0.0.1", true},   // null => every version
		{"npm", "wholly-bad", "999.0.0", true}, // null => every version
		{"npm", "not-in-corpus", "1.0.0", false},
		{"PyPI", "badlib", "1.0.0", true},
		// Vendor lists disagree on ecosystem casing; matching must not.
		{"NPM", "keyv", "6.0.0", true},
		{"pypi", "badlib", "1.0.0", true},
	}
	for _, tc := range cases {
		if got := c.IsMalicious(tc.eco, tc.name, tc.version); got != tc.want {
			t.Errorf("IsMalicious(%q,%q,%q) = %v, want %v", tc.eco, tc.name, tc.version, got, tc.want)
		}
	}
}

// A corpus hit and an attack hit must not disagree about the same package.
func TestCorpusMatchingAgreesWithAttackMatching(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "npm", `{"keyv": ["6.0.0"], "wholly-bad": null}`)
	c, err := LoadDataDog(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"keyv", "wholly-bad"} {
		e, ok := c.Lookup("npm", name)
		if !ok {
			t.Fatalf("%s missing", name)
		}
		equivalent := attack.Package{Ecosystem: e.Ecosystem, Name: e.Name, Versions: e.Versions}
		for _, v := range []string{"6.0.0", "5.0.0", "999.0.0"} {
			if got, want := c.IsMalicious("npm", name, v), equivalent.Matches("npm", name, v); got != want {
				t.Errorf("%s@%s: corpus says %v, attack.Package says %v", name, v, got, want)
			}
		}
	}
}

// Two sources flagging the same package must widen coverage, never narrow it.
// A source listing three versions must not replace one that said "all".
func TestAddNeverNarrowsCoverage(t *testing.T) {
	c := &Corpus{entries: map[entryKey]Entry{}, counts: map[string]int{}}

	c.add(Entry{Package: attack.Package{Ecosystem: "npm", Name: "evil"}, Sources: []string{"all-versions-source"}})
	c.add(Entry{Package: attack.Package{Ecosystem: "npm", Name: "evil", Versions: []string{"1.0.0"}}, Sources: []string{"picky-source"}})

	if !c.IsMalicious("npm", "evil", "9.9.9") {
		t.Error("a source listing one version narrowed an all-versions entry")
	}
	if c.Count("npm") != 1 {
		t.Errorf("merged entry counted twice: %d", c.Count("npm"))
	}

	e, _ := c.Lookup("npm", "evil")
	if len(e.Sources) != 2 {
		t.Errorf("provenance should list both sources, got %v", e.Sources)
	}
}

// Provenance is per entry, not per corpus: an entry must not claim sources
// that never flagged it.
func TestProvenanceIsPerEntry(t *testing.T) {
	c := &Corpus{entries: map[entryKey]Entry{}, counts: map[string]int{}}
	c.add(Entry{Package: attack.Package{Ecosystem: "npm", Name: "a"}, Sources: []string{"source-one"}})
	c.add(Entry{Package: attack.Package{Ecosystem: "npm", Name: "b"}, Sources: []string{"source-two"}})

	a, _ := c.Lookup("npm", "a")
	if len(a.Sources) != 1 || a.Sources[0] != "source-one" {
		t.Errorf("entry a should name only source-one, got %v", a.Sources)
	}
}

func TestLoadDataDogCounts(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "npm", `{"a": ["1"], "b": null, "c": ["1","2"]}`)
	writeManifest(t, dir, "pypi", `{"d": ["1"]}`)

	c, err := LoadDataDog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Count("npm") != 3 {
		t.Errorf("Count(npm) = %d, want 3", c.Count("npm"))
	}
	if c.Count("") != 4 {
		t.Errorf("Count(total) = %d, want 4", c.Count(""))
	}
	if ecos := c.Ecosystems(); len(ecos) != 2 || ecos[0] != "PyPI" || ecos[1] != "npm" {
		t.Errorf("Ecosystems() = %v", ecos)
	}
}

// A subdir nobody mapped is a coverage gap, not a clean result.
func TestLoadDataDogRejectsUnknownSubdir(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "npm", `{"a": null}`)
	writeManifest(t, dir, "cargo", `{"b": null}`)

	if _, err := LoadDataDog(dir); err == nil {
		t.Fatal("want an error naming the unmapped subdir, got nil")
	}
}

func TestLoadDataDogEmptyAndMissing(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "npm", `{}`)
	if _, err := LoadDataDog(dir); err == nil {
		t.Error("an empty manifest should not load as a populated corpus")
	}
	if _, err := LoadDataDog(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("a missing directory should error")
	}
}

func TestZeroValueCorpusIsSafe(t *testing.T) {
	var c Corpus
	if c.IsMalicious("npm", "anything", "1.0.0") {
		t.Error("zero-value corpus must not report a hit")
	}
	if _, ok := c.Lookup("npm", "anything"); ok {
		t.Error("zero-value corpus must not resolve a lookup")
	}
	if c.Count("") != 0 {
		t.Error("zero-value corpus must count zero")
	}
}
