package ioc

import (
	"path/filepath"
	"testing"
)

// THE test for this file. The published indicator was the bare filename
// Math_Symbol.js. Unscoped it hits a legitimate Unicode data file present in
// hundreds of projects; the real indicator was that name inside the
// compromised package. PathScope is what separates the two, so the matcher
// behind it has to get exactly this pair right.
func TestMatchScopeSeparatesTheMathSymbolCase(t *testing.T) {
	const scope = "**/node_modules/keyv/**"

	malicious := "apps/web/node_modules/keyv/General_Category/Math_Symbol.js"
	if !matchScope(scope, malicious) {
		t.Errorf("the real indicator was missed: %s", malicious)
	}

	legitimate := "apps/web/node_modules/regenerate-unicode-properties/General_Category/Math_Symbol.js"
	if matchScope(scope, legitimate) {
		t.Errorf("false positive on a legitimate Unicode data file: %s", legitimate)
	}
}

func TestMatchScope(t *testing.T) {
	cases := []struct {
		scope, rel string
		want       bool
	}{
		{"", "anything/at/all.js", true}, // empty scope matches anywhere

		// ** spans any number of segments, including zero.
		{"**/node_modules/keyv/**", "node_modules/keyv/index.js", true},
		{"**/node_modules/keyv/**", "a/b/c/node_modules/keyv/lib/x.js", true},
		{"**/node_modules/keyv/**", "node_modules/keyvx/index.js", false},
		{"**/node_modules/keyv/**", "node_modules/other/keyv.js", false},

		// * stays inside one segment and must not cross a separator.
		{"src/*.js", "src/index.js", true},
		{"src/*.js", "src/nested/index.js", false},
		{"src/*/index.js", "src/a/index.js", true},

		{"public/**", "public/assets/sw.js", true},
		{"public/**", "private/assets/sw.js", false},

		// A leading ** must still match a path with no prefix at all.
		{"**/sw.js", "sw.js", true},
		{"**/sw.js", "public/sw.js", true},
		{"**/sw.js", "public/sw.js.map", false},
	}

	for _, tc := range cases {
		if got := matchScope(tc.scope, tc.rel); got != tc.want {
			t.Errorf("matchScope(%q, %q) = %v, want %v", tc.scope, tc.rel, got, tc.want)
		}
	}
}

// Scopes are always written with forward slashes, but the sweep builds paths
// with filepath.Rel, which uses the platform separator. A path assembled the
// way the sweep assembles it must still match.
//
// Note this is NOT a backslash-conversion test: on Unix a backslash is a legal
// filename character and filepath.ToSlash correctly leaves it alone.
func TestMatchScopeAcceptsPlatformSeparators(t *testing.T) {
	native := filepath.Join("apps", "web", "node_modules", "keyv", "x.js")
	if !matchScope("**/node_modules/keyv/**", native) {
		t.Errorf("a natively-joined path should match a slash-written scope: %q", native)
	}
}

// A malformed pattern must not match everything by accident — an unclosed
// bracket that silently matched would turn one bad indicator into a sweep-wide
// false positive.
func TestMatchScopeRejectsBadPattern(t *testing.T) {
	if matchScope("**/[unclosed", "node_modules/keyv/x.js") {
		t.Error("a malformed scope must not match")
	}
}
