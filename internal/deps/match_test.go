package deps

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dPeluChe/canary/internal/attack"
	"github.com/dPeluChe/canary/internal/corpus"
)

func keyvAttack() attack.Attack {
	return attack.Attack{
		Schema:  attack.Schema,
		ID:      "keyv-2026-08",
		Name:    "keyv npm compromise",
		Started: time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC),
		Packages: []attack.Package{
			{Ecosystem: "npm", Name: "keyv", Versions: []string{"6.0.0"}},
			{Ecosystem: "npm", Name: "cacheable-request", Versions: []string{"13.0.20"}},
		},
	}
}

func testCorpus(t *testing.T, manifest string) *corpus.Corpus {
	t.Helper()
	dir := t.TempDir()
	sub := filepath.Join(dir, "samples", "npm")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := corpus.LoadDataDog(dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func resolved(pairs ...string) []Resolved {
	var out []Resolved
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, Resolved{
			Ecosystem: "npm", Name: pairs[i], Version: pairs[i+1],
			Lockfile: "/tree/repo/package-lock.json",
		})
	}
	return out
}

// The whole point of layer 1: a transitive package nobody declared, pinned at
// the poisoned version, is reported.
func TestMatchFindsTheMaliciousVersion(t *testing.T) {
	got := Match(
		resolved("left-pad", "1.3.0", "keyv", "6.0.0", "chalk", "5.0.0"),
		[]attack.Attack{keyvAttack()}, nil)

	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %v", len(got), got)
	}
	if got[0].String() != "npm/keyv@6.0.0" {
		t.Errorf("got %s", got[0].String())
	}
	if len(got[0].Attacks) != 1 || got[0].Attacks[0] != "keyv-2026-08" {
		t.Errorf("provenance: got %v", got[0].Attacks)
	}
	if got[0].Lockfile != "/tree/repo/package-lock.json" {
		t.Errorf("lockfile provenance lost: %q", got[0].Lockfile)
	}
}

// A safe version of a compromised package is NOT a finding. This is the case
// the real investigation hit: keyv was present at 4.5.4, not 6.0.0.
func TestMatchIgnoresSafeVersionsOfACompromisedPackage(t *testing.T) {
	got := Match(resolved("keyv", "4.5.4"), []attack.Attack{keyvAttack()}, nil)
	if len(got) != 0 {
		t.Fatalf("keyv@4.5.4 is safe and must not be reported: %v", got)
	}
}

// THE self-validation step. A clean result from an extractor never observed
// matching anything is worthless — the same package at a safe version must
// still be visible when the version test is removed.
func TestMatchIgnoringVersionsProvesTheFamilyIsVisible(t *testing.T) {
	pkgs := resolved("keyv", "4.5.4")

	if got := Match(pkgs, []attack.Attack{keyvAttack()}, nil); len(got) != 0 {
		t.Fatalf("exact match should be clean, got %v", got)
	}

	got := MatchIgnoringVersions(pkgs, []attack.Attack{keyvAttack()}, nil)
	if len(got) != 1 {
		t.Fatalf("self-validation should see keyv at ANY version, got %d — a clean result here means the extractor never saw the family and the negative above proves nothing", len(got))
	}
	if got[0].Version != "4.5.4" {
		t.Errorf("self-validation should report the version actually present, got %q", got[0].Version)
	}
}

// Self-validation finding nothing is the signal that a negative cannot be
// trusted, so it must not be confused with a clean exact match.
func TestMatchIgnoringVersionsIsEmptyWhenTheFamilyIsAbsent(t *testing.T) {
	got := MatchIgnoringVersions(resolved("left-pad", "1.3.0"), []attack.Attack{keyvAttack()}, nil)
	if len(got) != 0 {
		t.Fatalf("no keyv anywhere in the tree, got %v", got)
	}
}

func TestMatchConsultsTheCorpus(t *testing.T) {
	c := testCorpus(t, `{"evil-typosquat": null, "keyv": ["6.0.0"]}`)

	got := Match(resolved("evil-typosquat", "0.0.1"), nil, c)
	if len(got) != 1 {
		t.Fatalf("want 1 corpus finding, got %d", len(got))
	}
	if len(got[0].Sources) != 1 {
		t.Errorf("corpus provenance missing: %v", got[0].Sources)
	}
	if len(got[0].Attacks) != 0 {
		t.Errorf("no attack file flagged it: %v", got[0].Attacks)
	}
}

// A package both an attack file and a corpus call malicious is ONE finding
// carrying both, not two findings that double-count the same risk.
func TestMatchMergesProvenanceForTheSamePackage(t *testing.T) {
	c := testCorpus(t, `{"keyv": ["6.0.0"]}`)

	got := Match(resolved("keyv", "6.0.0"), []attack.Attack{keyvAttack()}, c)
	if len(got) != 1 {
		t.Fatalf("want 1 merged finding, got %d: %v", len(got), got)
	}
	if len(got[0].Attacks) != 1 || len(got[0].Sources) != 1 {
		t.Errorf("both sources should appear: attacks=%v sources=%v", got[0].Attacks, got[0].Sources)
	}
}

// Ecosystem casing varies across vendor lists; a miss here would silently drop
// a real finding.
func TestMatchIsCaseInsensitiveOnEcosystem(t *testing.T) {
	got := Match([]Resolved{{Ecosystem: "NPM", Name: "keyv", Version: "6.0.0"}},
		[]attack.Attack{keyvAttack()}, nil)
	if len(got) != 1 {
		t.Fatalf("ecosystem casing must not lose a finding, got %d", len(got))
	}
}

func TestMatchWithNoSourcesFindsNothing(t *testing.T) {
	if got := Match(resolved("keyv", "6.0.0"), nil, nil); len(got) != 0 {
		t.Fatalf("no sources loaded means nothing can match, got %v", got)
	}
}

// A tree resolves hundreds of thousands of packages; matching must not be
// quadratic over the attack list.
func BenchmarkMatchRealisticTree(b *testing.B) {
	var pkgs []Resolved
	for i := 0; i < 250_000; i++ {
		pkgs = append(pkgs, Resolved{Ecosystem: "npm", Name: "pkg-" + string(rune('a'+i%26)), Version: "1.0.0"})
	}
	atk := keyvAttack()
	for i := 0; i < 446; i++ {
		atk.Packages = append(atk.Packages, attack.Package{Ecosystem: "npm", Name: "bad-" + string(rune('a'+i%26)), Versions: []string{"1.0.0"}})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Match(pkgs, []attack.Attack{atk}, nil)
	}
}
