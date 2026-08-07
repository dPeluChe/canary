// Package ioc sweeps the filesystem for attack artifacts and for the
// persistence mechanisms modern supply-chain malware installs.
//
// LAYER 2 of 4. See docs/ARCHITECTURE/OVERVIEW.md.
//
// This layer is the reason canary exists. The 2026 npm attacks stopped at
// stealing credentials and started installing persistence in developer
// tooling — Claude Code hooks, VS Code tasks.json, shell profiles, git hooks.
// The surveyed scanners (osv-scanner, shai-hulud-detect, trivy, grype) do not
// look there. See docs/RESEARCH/TOOLING_LANDSCAPE.md.
//
// Unlike the deps layer, this one opts back INTO node_modules: installed code
// is exactly where a dropped payload lives.
//
// STATUS: not implemented.
package ioc

// PersistenceTarget is a location malware is known to write to in order to
// survive a reboot or re-execute on a developer's next action.
//
// Each is checked for two things: known-bad content, and modification inside
// the forensic window. An untouched file with an old mtime is a strong
// negative; content alone is not.
var PersistenceTargets = []string{
	"~/.claude/settings.json",
	"~/.claude/hooks/",
	"<repo>/.claude/settings.json",
	"<repo>/.claude/settings.local.json",
	"<repo>/.vscode/tasks.json",
	"~/.config/git/hooks/",
	"<repo>/.git/hooks/",
	"~/.zshrc",
	"~/.bashrc",
	"~/.profile",
}

// Finding is one artifact match on disk.
type Finding struct {
	Path       string
	Attack     string
	Artifact   string
	Line       int
	Excerpt    string
	Persistent bool // matched a PersistenceTarget rather than ordinary source
}

// Sweep scans root for the artifacts of the given attacks.
func Sweep(root string, attacks []string) ([]Finding, error) {
	panic("not implemented")
}
