package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dPeluChe/canary/internal/deps"
	"github.com/dPeluChe/canary/internal/discover"
)

func repo(name, path string) discover.Repo {
	return discover.Repo{Name: name, Path: path}
}

func resolved(names ...string) []deps.Resolved {
	var out []deps.Resolved
	for _, n := range names {
		out = append(out, deps.Resolved{Ecosystem: "npm", Name: n, Version: "1.0.0"})
	}
	return out
}

// A real tree resolves the same few thousand packages across hundreds of repos.
// Storing them per repo would multiply the file by an order of magnitude, so
// the package list is deduplicated and repos hold indices.
func TestBuilderStoresEachVersionOnce(t *testing.T) {
	b := NewBuilder("/tree")
	b.Add(repo("a", "/tree/a"), resolved("left-pad", "chalk"), 1, 0)
	b.Add(repo("b", "/tree/b"), resolved("left-pad", "keyv"), 1, 0)

	inv := b.Inventory()
	if len(inv.Packages) != 3 {
		t.Fatalf("left-pad is shared and must be stored once: %+v", inv.Packages)
	}
	if len(inv.Repos) != 2 || len(inv.Repos[0].Packages) != 2 {
		t.Fatalf("repos: %+v", inv.Repos)
	}
}

// Matching a stored inventory must go through exactly the code path a fresh
// scan uses, or the two would drift and a cached answer would differ.
func TestResolvedRebuildsTheSetForMatching(t *testing.T) {
	b := NewBuilder("/tree")
	b.Add(repo("a", "/tree/a"), resolved("keyv", "chalk"), 1, 0)
	inv := b.Inventory()

	got := inv.Resolved(inv.Repos[0])
	if len(got) != 2 {
		t.Fatalf("want 2 resolved, got %d", len(got))
	}
	names := map[string]bool{}
	for _, r := range got {
		names[r.Name] = true
		if r.Ecosystem != "npm" || r.Version != "1.0.0" {
			t.Errorf("round trip lost detail: %+v", r)
		}
	}
	if !names["keyv"] || !names["chalk"] {
		t.Errorf("names: %v", names)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	b := NewBuilder("/tree")
	b.Add(repo("a", "/tree/a"), resolved("keyv"), 1, 0)

	path := filepath.Join(t.TempDir(), "inv.json")
	if err := Save(path, b.Inventory()); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Root != "/tree" || len(got.Repos) != 1 || len(got.Packages) != 1 {
		t.Fatalf("round trip: %+v", got)
	}
	if got.Age() < 0 {
		t.Error("age must be measurable")
	}
}

// A schema it does not recognise is an error. Silently reading a future format
// would produce a smaller resolved set than was scanned — a cleaner tree than
// exists.
func TestLoadRefusesAnUnknownSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inv.json")
	body, _ := json.Marshal(map[string]any{
		"schema": 99, "root": "/tree",
		"repos": []map[string]any{{"name": "a", "path": "/tree/a"}},
	})
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("want a schema error, got %v", err)
	}
}

// An inventory recording no repos is not an empty tree, it is a broken file.
func TestLoadRefusesAnEmptyInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inv.json")
	body, _ := json.Marshal(Inventory{Schema: Schema, Root: "/tree"})
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("an inventory with no repos must not load")
	}
}

// Two trees must not share one inventory, or scanning the second would report
// the first.
func TestPathIsPerTree(t *testing.T) {
	a := Path("/data", "/tree/one")
	b := Path("/data", "/tree/two")
	if a == b {
		t.Fatalf("different trees resolved to the same file: %s", a)
	}
	if a != Path("/data", "/tree/one/") {
		t.Error("a trailing separator must not create a second inventory")
	}
}

// Tests and operators need canary's data out of the developer's home.
func TestDataDirHonoursTheEnvironment(t *testing.T) {
	t.Setenv(EnvDataDir, "/somewhere/else")
	got, err := DataDir()
	if err != nil || got != "/somewhere/else" {
		t.Fatalf("DataDir = %q, %v", got, err)
	}
}
