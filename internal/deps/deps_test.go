package deps

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dPeluChe/canary/internal/discover"
)

// Shape of the real project measured during the keyv incident, from
// docs/RESEARCH/SPARK_ANALYSIS.md: 26 packages declared in package.json, 790
// resolved in the lockfile, 80 of those nested. The reference project read the
// manifest and checked 26.
const (
	declaredInManifest = 26
	topLevelEntries    = 710
	nestedEntries      = 80
	wantResolved       = topLevelEntries + nestedEntries
)

// buildFixture writes a package.json / package-lock.json pair whose numbers
// match the shape above. The compromised package is placed ONLY in the
// lockfile, nested, exactly where the real one was.
func buildFixture(t *testing.T) discover.Lockfile {
	t.Helper()
	dir := t.TempDir()

	direct := map[string]string{}
	packages := map[string]any{}

	for i := 0; i < topLevelEntries; i++ {
		name := fmt.Sprintf("pkg-%04d", i)
		packages["node_modules/"+name] = map[string]any{
			"version":  "1.0.0",
			"resolved": "https://registry.npmjs.org/" + name + "/-/" + name + "-1.0.0.tgz",
		}
		if i < declaredInManifest {
			direct[name] = "^1.0.0"
		}
	}

	// Nested entries exist because of version conflicts, so they carry the same
	// name at a different version. spark skipped these on purpose.
	for i := 0; i < nestedEntries; i++ {
		parent := fmt.Sprintf("pkg-%04d", i)
		child := fmt.Sprintf("pkg-%04d", topLevelEntries-1-i)
		packages[fmt.Sprintf("node_modules/%s/node_modules/%s", parent, child)] = map[string]any{
			"version": "2.0.0",
		}
	}

	// The package that mattered: transitive, nested, absent from package.json.
	packages["node_modules/pkg-0003/node_modules/keyv"] = map[string]any{
		"version": "6.0.0",
	}

	packages[""] = map[string]any{
		"name":         "fixture",
		"version":      "1.0.0",
		"dependencies": direct,
	}

	writeJSON(t, filepath.Join(dir, "package.json"), map[string]any{
		"name":         "fixture",
		"version":      "1.0.0",
		"dependencies": direct,
	})
	lockPath := filepath.Join(dir, "package-lock.json")
	writeJSON(t, lockPath, map[string]any{
		"name":            "fixture",
		"version":         "1.0.0",
		"lockfileVersion": 3,
		"requires":        true,
		"packages":        packages,
	})

	return discover.Lockfile{
		Path:      lockPath,
		Rel:       "package-lock.json",
		Kind:      "package-lock.json",
		Ecosystem: "npm",
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// THE test. Extraction must return the resolved set, not the declared set.
// A scanner that answers 26 here answers the wrong question, and would have
// reported clean during a live incident — see docs/RESEARCH/SPARK_ANALYSIS.md.
func TestExtractIsTransitivelyComplete(t *testing.T) {
	lf := buildFixture(t)

	got, err := Extract(lf)
	if err != nil {
		t.Fatal(err)
	}

	// +1 for the planted keyv entry.
	if len(got) != wantResolved+1 {
		t.Fatalf("resolved %d packages, want %d — a manifest-based scanner returns %d",
			len(got), wantResolved+1, declaredInManifest)
	}
	if len(got) <= declaredInManifest*2 {
		t.Fatalf("resolved %d, barely above the %d declared: this reads like manifest parsing",
			len(got), declaredInManifest)
	}
}

// The specific failure that made the reference project useless: the compromised
// package is transitive and nested, so it appears in zero package.json files.
func TestExtractFindsNestedPackageAbsentFromManifest(t *testing.T) {
	lf := buildFixture(t)

	got, err := Extract(lf)
	if err != nil {
		t.Fatal(err)
	}

	manifest, err := os.ReadFile(filepath.Join(filepath.Dir(lf.Path), "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pj struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(manifest, &pj); err != nil {
		t.Fatal(err)
	}
	if _, declared := pj.Dependencies["keyv"]; declared {
		t.Fatal("fixture is wrong: keyv must NOT be declared in package.json")
	}

	for _, r := range got {
		if r.Name == "keyv" && r.Version == "6.0.0" {
			if r.Ecosystem != "npm" {
				t.Errorf("ecosystem: got %q", r.Ecosystem)
			}
			if r.Lockfile != lf.Path {
				t.Errorf("lockfile provenance: got %q", r.Lockfile)
			}
			return
		}
	}
	t.Fatal("keyv@6.0.0 is nested in the lockfile and was not resolved — this is the spark bug")
}

// Nested entries carry a different version of a name that also exists at the
// top level. Collapsing them to one loses the compromised copy.
func TestExtractKeepsNestedVersionsOfTheSameName(t *testing.T) {
	lf := buildFixture(t)

	got, err := Extract(lf)
	if err != nil {
		t.Fatal(err)
	}

	versions := map[string]bool{}
	for _, r := range got {
		if r.Name == "pkg-0709" {
			versions[r.Version] = true
		}
	}
	if !versions["1.0.0"] || !versions["2.0.0"] {
		t.Fatalf("pkg-0709 should appear at both 1.0.0 (top level) and 2.0.0 (nested), got %v", versions)
	}
}

func TestExtractRejectsUnsupportedLockfile(t *testing.T) {
	_, err := Extract(discover.Lockfile{Path: "/nope/Gemfile.lock", Kind: "Gemfile.lock", Ecosystem: "RubyGems"})
	if err == nil {
		t.Fatal("want an error naming the unsupported kind, got nil")
	}
}
