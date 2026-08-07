package corpus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeList(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "compromised-packages.txt")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// The trap in this format: a scoped package has two colons and only the last
// one separates the version. Splitting on the first yields "@accordproject"
// at version "concerto-analysis:3.24.1" — an entry that matches nothing while
// the list looks fully loaded.
func TestLoadShaiHuludSplitsScopedNamesOnTheLastColon(t *testing.T) {
	p := writeList(t, `# Shai-Hulud Compromised Packages List
#
02-echo:0.0.7
@accordproject/concerto-analysis:3.24.1
@scope/deep/name:1.0.0
`)
	c, err := LoadShaiHulud(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Count("") != 3 {
		t.Fatalf("want 3 entries, got %d", c.Count(""))
	}
	for _, tc := range []struct{ name, version string }{
		{"02-echo", "0.0.7"},
		{"@accordproject/concerto-analysis", "3.24.1"},
		{"@scope/deep/name", "1.0.0"},
	} {
		if !c.IsMalicious("npm", tc.name, tc.version) {
			t.Errorf("%s@%s should be in the corpus", tc.name, tc.version)
		}
	}
	// The wrong split would have produced this.
	if _, bad := c.Lookup("npm", "@accordproject"); bad {
		t.Error("the scope alone must never become an entry")
	}
}

// A pinned version means only that version. This list is not "all versions".
func TestLoadShaiHuludPinsExactVersions(t *testing.T) {
	c, err := LoadShaiHulud(writeList(t, "keyv:6.0.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsMalicious("npm", "keyv", "6.0.0") {
		t.Error("the listed version must match")
	}
	if c.IsMalicious("npm", "keyv", "4.5.4") {
		t.Error("a safe version must not match a pinned entry")
	}
}

// Entries carry their source, so a report can say one list flagged it rather
// than implying several agreed.
func TestLoadShaiHuludCarriesProvenance(t *testing.T) {
	c, err := LoadShaiHulud(writeList(t, "keyv:6.0.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := c.Lookup("npm", "keyv")
	if len(e.Sources) != 1 || e.Sources[0] != ShaiHuludSource {
		t.Errorf("provenance: %v", e.Sources)
	}
}

// A malformed line is an error, not a skip. Silently dropping entries shrinks
// the set canary matches against while the file looks fully loaded.
func TestLoadShaiHuludRefusesMalformedLines(t *testing.T) {
	for _, body := range []string{"keyv\n", "keyv:\n", ":6.0.0\n"} {
		if _, err := LoadShaiHulud(writeList(t, body)); err == nil {
			t.Errorf("%q should be refused", strings.TrimSpace(body))
		}
	}
	if _, err := LoadShaiHulud(writeList(t, "# only comments\n\n")); err == nil {
		t.Error("a list with no entries must not load as a populated corpus")
	}
}

// Two sources flagging the same package widen coverage, and the merge is the
// one already proven for DataDog.
func TestShaiHuludMergesWithAnotherSource(t *testing.T) {
	c, err := LoadShaiHulud(writeList(t, "keyv:6.0.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	dd := t.TempDir()
	sub := filepath.Join(dd, "samples", "npm")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "manifest.json"), []byte(`{"keyv": ["6.0.1"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	other, err := LoadDataDog(dd)
	if err != nil {
		t.Fatal(err)
	}

	c.Merge(other)
	if !c.IsMalicious("npm", "keyv", "6.0.0") || !c.IsMalicious("npm", "keyv", "6.0.1") {
		t.Error("merging two sources must cover both versions")
	}
}

// Load merges whatever source lists happen to be cached, and records how old
// each one is — the number that lets refreshing stay explicit.
func TestLoadMergesSourcesAndRecordsAge(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "shai-hulud.txt"), []byte("keyv:6.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "samples", "npm")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "manifest.json"), []byte(`{"evil": null}`), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsMalicious("npm", "keyv", "6.0.0") || !c.IsMalicious("npm", "evil", "9.9.9") {
		t.Error("both cached sources must be consulted")
	}
	if len(c.Sources()) != 2 {
		t.Errorf("sources: %v", c.Sources())
	}
	if len(c.Fetched()) != 2 {
		t.Errorf("every source needs an age, got %v", c.Fetched())
	}
}

// A directory with nothing recognisable is an error, not an empty corpus: a
// scan with nothing loaded reports clean exactly like one that never ran.
func TestLoadRefusesADirectoryWithNoSources(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("want an error naming that no source lists were found")
	}
}
