package ioc

import (
	"path/filepath"
	"strings"
)

// matchScope reports whether a path relative to the scan root sits under a
// PathScope glob. An empty scope matches anything.
//
// Stdlib filepath.Match does NOT implement `**` — it treats the pattern as
// segment-local, so `**/node_modules/keyv/**` would never match a nested path.
// Getting this wrong is not a cosmetic bug: PathScope is the only thing
// standing between a filename indicator and the Math_Symbol.js false positive
// that motivated the whole field. See docs/ARCHITECTURE/DATA_MODEL.md.
func matchScope(scope, rel string) bool {
	if scope == "" {
		return true
	}
	rel = filepath.ToSlash(rel)
	return matchSegments(splitGlob(scope), strings.Split(rel, "/"))
}

func splitGlob(pattern string) []string {
	return strings.Split(strings.Trim(filepath.ToSlash(pattern), "/"), "/")
}

// matchSegments walks pattern and path segment by segment. `**` consumes zero
// or more segments; every other segment is matched with filepath.Match, which
// keeps `*` and `?` from crossing a separator.
func matchSegments(pattern, name []string) bool {
	if len(pattern) == 0 {
		return len(name) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(name); i++ {
			if matchSegments(pattern[1:], name[i:]) {
				return true
			}
		}
		return false
	}
	if len(name) == 0 {
		return false
	}
	ok, err := filepath.Match(pattern[0], name[0])
	if err != nil || !ok {
		return false
	}
	return matchSegments(pattern[1:], name[1:])
}
