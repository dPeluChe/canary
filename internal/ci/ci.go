// Package ci correlates GitHub Actions activity with an attack window.
//
// LAYER 4 of 4. See docs/ARCHITECTURE/OVERVIEW.md.
//
// No surveyed tool does this, and it is the question that matters most when a
// registry is compromised: a developer's laptop can be verified clean while a
// CI runner installed the same dependency tree and exfiltrated repository
// secrets, leaving nothing behind locally.
//
// The question this layer answers, per repo:
//
//	Did a workflow install dependencies inside the window,
//	and if so, what secrets were reachable from that job?
//
// A run inside the window is not by itself a compromise. The finding is only
// material when the resolved dependency set contained a malicious version AND
// secrets existed to steal. Reporting the run alone produces alarm without
// information — and the correct outcome of most investigations is a
// documented negative, not a credential rotation.
//
// STATUS: not implemented.
package ci

import "time"

// Run is one workflow run within the queried window.
type Run struct {
	ID            int64
	Workflow      string
	Event         string
	Branch        string
	Conclusion    string
	CreatedAt     time.Time
	InstalledDeps bool   // the job ran npm ci / npm install / bun install / pnpm i
	InstallCmd    string // the command observed in the workflow definition
}

// RepoExposure is what a single repo had at risk during the window.
type RepoExposure struct {
	Slug        string
	Runs        []Run
	SecretNames []string // names only; canary never reads secret values
	OrgSecrets  bool     // org-level secrets can be injected without appearing on the repo
}

// Query returns the runs and secret surface for slug between since and until.
func Query(slug string, since, until time.Time) (*RepoExposure, error) {
	panic("not implemented")
}
