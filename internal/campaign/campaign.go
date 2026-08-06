// Package campaign loads attack campaigns from data files.
//
// A campaign is DATA, never compiled-in code. This is the central design
// decision of canary: when a supply-chain attack breaks, the vendor IoC list
// (Wiz, Socket, Aikido, StepSecurity) is public within hours, while the OSV
// MAL- advisory can take days. Tools that hardcode their package list into
// source need a release per incident. canary loads a file and runs.
//
// STATUS: not implemented. See docs/ARCHITECTURE/DATA_MODEL.md.
package campaign

import "time"

// Campaign is one supply-chain incident and everything known to identify it.
type Campaign struct {
	ID        string    // e.g. "keyv-2026-08"
	Name      string    // human label
	Started   time.Time // attack window start, UTC
	Source    string    // URL of the report this was built from
	Packages  []Package // known-malicious package versions
	Artifacts []Artifact
}

// Package is a package name plus the versions known to be malicious.
// A version NOT in this list is not evidence of safety, only of absence.
type Package struct {
	Ecosystem string
	Name      string
	Versions  []string
}

// Artifact is a filesystem or network indicator: a C2 domain, an embedded
// string, a dropped filename, a user agent.
//
// PathScope matters and is easy to get wrong. During the keyv incident the
// indicator "Math_Symbol.js" produced false positives against
// regenerate-unicode-properties, a legitimate Unicode data package. The real
// indicator was that filename INSIDE the keyv package. An artifact without a
// path scope is a bug report waiting to happen.
type Artifact struct {
	Kind      string // "domain" | "ip" | "string" | "filename" | "useragent"
	Value     string
	PathScope string // glob the match must sit under; empty means anywhere
	Note      string
}

// Load reads every campaign file in dir.
func Load(dir string) ([]Campaign, error) {
	panic("not implemented")
}
