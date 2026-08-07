package attack

import (
	"strings"
	"testing"
	"time"
)

// These pin the load-time drops an audit predicted and probing confirmed:
// four ways a vendor list and a lockfile spell the same thing differently, each
// producing a CLEAN verdict with the attack loaded. That is the worst output
// this tool can give, and none of it raised an error.

func TestMatchesSurvivesVendorVersionSpellings(t *testing.T) {
	cases := []struct {
		listed, resolved string
		want             bool
		why              string
	}{
		{"6.0.0", "6.0.0", true, "identical"},
		{"v6.0.0", "6.0.0", true, "vendors write a leading v, lockfiles do not"},
		{"6.0.0", "v6.0.0", true, "and the other way round"},
		{"6.0.0", "6.0.0+build.5", true, "semver: build metadata is not part of precedence"},
		{"6.0.0+sha.1", "6.0.0", true, "same, from the list side"},
		{"6.0.0", "6.0.1", false, "a different patch is a different version"},
		{"6.0.0", "16.0.0", false, "the v-strip must not eat a digit"},
		{"6.0.0-rc.1", "6.0.0", false, "a prerelease is NOT the release"},
	}
	for _, tc := range cases {
		p := Package{Ecosystem: "npm", Name: "keyv", Versions: []string{tc.listed}}
		if got := p.Matches("npm", "keyv", tc.resolved); got != tc.want {
			t.Errorf("listed %q vs resolved %q = %v, want %v — %s", tc.listed, tc.resolved, got, tc.want, tc.why)
		}
	}
}

// npm lowercases and PyPI normalizes per PEP 503. Ecosystems that do not
// publish a folding rule are compared verbatim, because folding a Go module
// path would invent matches.
func TestMatchesFoldsNamesOnlyWhereTheRegistryDoes(t *testing.T) {
	cases := []struct {
		eco, listed, resolved string
		want                  bool
	}{
		{"npm", "Keyv", "keyv", true},
		{"npm", "keyv", "KEYV", true},
		{"npm", "keyv", "keyv2", false},
		{"PyPI", "Flask_Login", "flask-login", true},
		{"PyPI", "zope.interface", "zope-interface", true},
		{"PyPI", "a--b", "a-b", true},
		{"PyPI", "flask", "flask-login", false},
		// Go module paths are case-sensitive; folding them would be a false positive.
		{"Go", "github.com/Sirupsen/logrus", "github.com/sirupsen/logrus", false},
	}
	for _, tc := range cases {
		p := Package{Ecosystem: tc.eco, Name: tc.listed, Versions: []string{"1.0.0"}}
		if got := p.Matches(tc.eco, tc.resolved, "1.0.0"); got != tc.want {
			t.Errorf("%s: listed %q vs resolved %q = %v, want %v", tc.eco, tc.listed, tc.resolved, got, tc.want)
		}
	}
}

// A range split on its comma yields entries that match nothing while the file
// looks fully loaded — the silent failure this whole layer is shaped against.
// Resolving ranges is OSV's job, so canary refuses rather than guesses.
func TestFromCSVRefusesAVersionRange(t *testing.T) {
	m := Attack{ID: "x", Name: "x", Started: time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC)}
	for _, cell := range []string{`">=1.0.0, <2.0.0"`, `"^1.2.3"`, `"1.0.0 - 2.0.0"`, `"1.x || 2.x"`} {
		in := "Package,Malicious Versions\nkeyv," + cell + "\n"
		_, err := FromCSV(strings.NewReader(in), "npm", m)
		if err == nil {
			t.Errorf("%s should be refused, not split into entries that match nothing", cell)
			continue
		}
		if !strings.Contains(err.Error(), "RANGE") {
			t.Errorf("the error must say why: %v", err)
		}
	}

	// Exact versions, including a comma-separated list, still load.
	ok := "Package,Malicious Versions\nkeyv,\"6.0.0, 6.0.1\"\n"
	got, err := FromCSV(strings.NewReader(ok), "npm", m)
	if err != nil {
		t.Fatalf("an ordinary multi-version cell must still load: %v", err)
	}
	if len(got.Packages[0].Versions) != 2 {
		t.Errorf("versions: %v", got.Packages[0].Versions)
	}
}

func TestNormalizeVersionLeavesUnknownShapesAlone(t *testing.T) {
	for _, v := range []string{"", "latest", "6", "2026.08.04", "abc123"} {
		if got := NormalizeVersion(v); got != v {
			t.Errorf("NormalizeVersion(%q) = %q — unknown shapes must not be guessed at", v, got)
		}
	}
}
