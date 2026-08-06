// Package deps resolves the full dependency set of a lockfile and checks it
// against known-malicious versions.
//
// LAYER 1 of 4. See docs/ARCHITECTURE/OVERVIEW.md.
//
// Two sources, deliberately:
//
//  1. OSV.dev — MAL- advisories from the OpenSSF malicious-packages feed,
//     plus ordinary CVEs. Authoritative, but lags a breaking incident.
//  2. Local campaigns — vendor IoC lists, available within hours.
//
// The hard requirement is TRANSITIVE COMPLETENESS. Supply-chain attacks land
// in transitive dependencies, not direct ones: in the keyv incident the
// compromised packages appeared in zero package.json files and in hundreds of
// lockfiles. A scanner that reads declared dependencies finds nothing.
// See docs/RESEARCH/SPARK_ANALYSIS.md for the worked example.
//
// Extraction is delegated to google/osv-scalibr rather than hand-written
// parsers — it covers the ecosystems and resolves transitives.
//
// STATUS: not implemented.
package deps

import "github.com/dPeluChe/canary/internal/discover"

// Resolved is one package version present in a lockfile, direct or transitive.
type Resolved struct {
	Ecosystem string
	Name      string
	Version   string
	Lockfile  string
	Direct    bool
}

// Extract reads a lockfile and returns every package version it pins,
// including transitive and nested entries.
func Extract(lf discover.Lockfile) ([]Resolved, error) {
	panic("not implemented")
}
