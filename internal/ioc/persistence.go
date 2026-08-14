package ioc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dPeluChe/canary/internal/attack"
)

// Families of persistence. They are reported apart because they mean different
// things: one survives on the developer's machine, the other ships to users.
const (
	FamilyDeveloper = "developer machine"
	FamilyDeploy    = "deploy surface"
)

// Target is a location worth inspecting because malware is known to write
// there, not because it is unusual to have one.
type Target struct {
	Rel    string // path relative to the base, or a directory to list when Dir
	Dir    bool
	Family string
	Note   string
}

// RepoTargets are checked inside every discovered repository.
//
// The deploy-surface half exists because a postinstall payload can write into
// a repository, and what it writes is served verbatim on the next deploy. That
// half was missing until it surfaced while evaluating web-check — see
// docs/RESEARCH/TOOLING_LANDSCAPE.md.
var RepoTargets = []Target{
	{Rel: ".claude/settings.json", Family: FamilyDeveloper, Note: "Claude Code settings"},
	{Rel: ".claude/settings.local.json", Family: FamilyDeveloper, Note: "Claude Code local settings"},
	{Rel: ".claude/hooks", Dir: true, Family: FamilyDeveloper, Note: "Claude Code hooks run on the developer's next action"},
	{Rel: ".vscode/tasks.json", Family: FamilyDeveloper, Note: "VS Code tasks can run on folder open"},
	{Rel: ".git/hooks", Dir: true, Family: FamilyDeveloper, Note: "git hooks run on commit, push and checkout"},

	{Rel: "sw.js", Family: FamilyDeploy, Note: "service worker: persists in the visitor's browser and survives a redeploy"},
	{Rel: "service-worker.js", Family: FamilyDeploy, Note: "service worker: persists in the visitor's browser and survives a redeploy"},
	{Rel: "public/sw.js", Family: FamilyDeploy, Note: "service worker: persists in the visitor's browser and survives a redeploy"},
	{Rel: "public/service-worker.js", Family: FamilyDeploy, Note: "service worker: persists in the visitor's browser and survives a redeploy"},
	{Rel: "static/sw.js", Family: FamilyDeploy, Note: "service worker: persists in the visitor's browser and survives a redeploy"},
	{Rel: "index.html", Family: FamilyDeploy, Note: "served HTML: an injected script tag ships to every visitor"},
	{Rel: "public/index.html", Family: FamilyDeploy, Note: "served HTML: an injected script tag ships to every visitor"},
	{Rel: "_headers", Family: FamilyDeploy, Note: "a weakened CSP re-enables what the CSP was blocking"},
	{Rel: "netlify.toml", Family: FamilyDeploy, Note: "a weakened CSP re-enables what the CSP was blocking"},
	{Rel: "vercel.json", Family: FamilyDeploy, Note: "a weakened CSP re-enables what the CSP was blocking"},
	{Rel: "staticwebapp.config.json", Family: FamilyDeploy, Note: "a weakened CSP re-enables what the CSP was blocking"},
	{Rel: "public/.well-known", Dir: true, Family: FamilyDeploy, Note: "deep-link association and security contact"},
	{Rel: ".well-known", Dir: true, Family: FamilyDeploy, Note: "deep-link association and security contact"},
}

// HomeTargets live OUTSIDE the scanned tree. They are checked because agent
// hooks and shell profiles are exactly where the 2026 attacks persisted, but a
// run that reads $HOME while it was asked to scan a project directory has to
// say so — see Result.HomeInspected.
var HomeTargets = []Target{
	{Rel: ".claude/settings.json", Family: FamilyDeveloper, Note: "Claude Code settings"},
	{Rel: ".claude/hooks", Dir: true, Family: FamilyDeveloper, Note: "Claude Code hooks run on the developer's next action"},
	{Rel: ".config/git/hooks", Dir: true, Family: FamilyDeveloper, Note: "global git hooks run in every repository"},
	{Rel: ".zshrc", Family: FamilyDeveloper, Note: "shell profile runs on every new shell"},
	{Rel: ".bashrc", Family: FamilyDeveloper, Note: "shell profile runs on every new shell"},
	{Rel: ".bash_profile", Family: FamilyDeveloper, Note: "shell profile runs on every login shell"},
	{Rel: ".profile", Family: FamilyDeveloper, Note: "shell profile runs on every login shell"},
}

// Persistence inspects known locations under base. It stats exact paths and
// lists a handful of directories rather than walking a tree — these are known
// addresses, and treating them as a search would cost what the artifact sweep
// costs for no extra coverage.
//
// A file here is reported when it carries a known indicator, or when it was
// modified inside the window. Those are different strengths of evidence and
// the caller must not merge them: `~/.zshrc` edited this week is ordinary, a
// `~/.zshrc` containing the C2 domain is not.
func Persistence(base string, targets []Target, attacks []attack.Attack, opt Options) (*Result, error) {
	if opt.MaxFileSize <= 0 {
		opt.MaxFileSize = defaultMaxFileSize
	}

	var indicators []ref
	for _, a := range attacks {
		for _, art := range a.Artifacts {
			if art.Kind != attack.KindFilename {
				indicators = append(indicators, ref{attackID: a.ID, art: art})
			}
		}
	}

	res := &Result{}
	for _, t := range targets {
		for _, path := range expand(base, t) {
			info, err := os.Stat(path)
			if err != nil || info.IsDir() {
				continue
			}
			res.PersistenceChecked++

			mod := info.ModTime()
			in := inWindow(mod, opt.Window)
			hits := scanIndicators(path, info.Size(), indicators, opt)

			if !in && len(hits) == 0 {
				// An untouched file with an old mtime is a strong negative, and
				// counting it is what lets a clean verdict say what it checked.
				res.PersistenceUntouched++
				continue
			}

			if len(hits) == 0 {
				res.Findings = append(res.Findings, Finding{
					Path: path, Target: t.Rel, Family: t.Family, Note: t.Note,
					ModTime: mod, InWindow: true, Persistent: true,
				})
				continue
			}
			for _, h := range hits {
				h.Target, h.Family, h.Note = t.Rel, t.Family, t.Note
				h.ModTime, h.InWindow, h.Persistent = mod, in, true
				res.Findings = append(res.Findings, h)
			}
		}
	}
	return res, nil
}

// expand turns a target into the concrete files to stat. Directory targets are
// listed one level deep; git's own *.sample hooks are excluded because git
// ships them inert and flagging them would bury the one hook that matters.
func expand(base string, t Target) []string {
	full := filepath.Join(base, t.Rel)
	if !t.Dir {
		return []string{full}
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".sample") {
			continue
		}
		out = append(out, filepath.Join(full, e.Name()))
	}
	return out
}

func scanIndicators(path string, size int64, indicators []ref, opt Options) []Finding {
	if len(indicators) == 0 || size > opt.MaxFileSize {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil || isBinary(data) {
		return nil
	}
	var out []Finding
	for _, r := range indicators {
		if line, excerpt, ok := findLine(data, r.pattern); ok {
			out = append(out, Finding{
				Path: path, Attack: r.attackID, Artifact: r.art.Value,
				Kind: r.art.Kind, Line: line, Excerpt: excerpt,
			})
		}
	}
	return out
}

// Describe renders a persistence finding for a report. It states which of the
// two signals fired, because "contains a known indicator" and "was modified in
// the window" are not the same claim.
func (f Finding) Describe(relTo string) string {
	shown := f.Path
	if relTo != "" {
		if rel, err := filepath.Rel(relTo, f.Path); err == nil {
			shown = rel
		}
	}
	family := ""
	if f.Family != "" {
		family = " [" + f.Family + "]"
	}
	switch {
	case f.Artifact != "":
		where := "mtime outside the window"
		if f.InWindow {
			where = "MODIFIED INSIDE THE WINDOW"
		}
		return fmt.Sprintf("%s:%d — %s %q via %s, %s%s",
			shown, f.Line, f.Kind, f.Artifact, f.Attack, where, family)
	default:
		return fmt.Sprintf("%s — modified inside the window (%s), no known indicator: verify by hand%s",
			shown, f.ModTime.UTC().Format(time.RFC3339), family)
	}
}
