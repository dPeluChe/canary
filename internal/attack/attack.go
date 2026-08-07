// Package attack loads known supply-chain attacks from data files.
//
// An attack here is the ATTACKER's, not a scan of ours: one registry
// compromise, described as data. It is never compiled in. When an attack
// breaks, the vendor IoC list (Wiz, Socket, Aikido, StepSecurity) is public
// within hours, while the OSV MAL- advisory can take days. Tools that hardcode
// their package list into source need a release per incident. canary loads a
// file and runs.
//
// The trap this layer guards against is an attack that looks loaded but is
// not. A misspelled key, a file that failed to parse, an empty directory —
// each one silently shrinks the set canary matches against, and the scan still
// reports clean. Load therefore fails loudly instead of returning a partial
// set: an unreadable attack file is a hole in coverage, not one bad path in a
// tree walk.
//
// On-disk format: docs/ARCHITECTURE/DATA_MODEL.md.
package attack

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dPeluChe/canary/internal/datadir"
)

// Schema is the only on-disk schema version canary accepts. Bump it when the
// format changes incompatibly; loading refuses anything else rather than
// guessing at fields it does not understand.
const Schema = 1

// ErrNoAttacks means the directory was readable but held no attack file.
// Callers must surface this as a coverage gap — a scan with zero attacks
// loaded reports clean for exactly the same reason a scan that never ran does.
var ErrNoAttacks = errors.New("no attack files found")

// Artifact kinds. Anything else is rejected at load time.
const (
	KindDomain    = "domain"
	KindIP        = "ip"
	KindString    = "string"
	KindFilename  = "filename"
	KindUserAgent = "useragent"
)

var artifactKinds = map[string]bool{
	KindDomain:    true,
	KindIP:        true,
	KindString:    true,
	KindFilename:  true,
	KindUserAgent: true,
}

// Attack is one supply-chain incident and everything known to identify it.
type Attack struct {
	Schema    int        `json:"schema"`
	ID        string     `json:"id"`      // e.g. "keyv-2026-08"
	Name      string     `json:"name"`    // human label
	Started   time.Time  `json:"started"` // attack window start, RFC3339
	Source    string     `json:"source"`  // URL of the report this was built from
	Note      string     `json:"note,omitempty"`
	Packages  []Package  `json:"packages,omitempty"`
	Artifacts []Artifact `json:"artifacts,omitempty"`

	File string `json:"-"` // path this attack was loaded from
}

// Package is a package name plus the versions known to be malicious.
// A version NOT in this list is not evidence of safety, only of absence.
type Package struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Versions  []string `json:"versions,omitempty"`
}

// Artifact is a filesystem or network indicator: a C2 domain, an embedded
// string, a dropped filename, a user agent.
//
// PathScope matters and is easy to get wrong. During the keyv incident the
// indicator "Math_Symbol.js" produced false positives against
// regenerate-unicode-properties, a legitimate Unicode data package. The real
// indicator was that filename INSIDE the keyv package. An artifact without a
// path scope is a bug report waiting to happen, so a filename artifact without
// one is refused at load time.
type Artifact struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	PathScope string `json:"pathScope,omitempty"` // glob the match must sit under; empty means anywhere
	Note      string `json:"note,omitempty"`
}

// Sources an attack directory can come from, in precedence order.
const (
	SourceFlag    = datadir.SourceFlag
	SourceEnv     = "$" + EnvDir
	SourceRepo    = datadir.SourceRepo + " attacks/"
	SourceDefault = datadir.SourceDefault
)

// EnvDir is the environment variable scripts/fetch-attack.sh writes into.
const EnvDir = "CANARY_ATTACK_DIR"

// ResolveDir picks which directory to load attacks from, and reports which
// source chose it so output can name it. See datadir.Resolve for the
// precedence and for why a missing explicit directory is not fallen through.
func ResolveDir(explicit, workdir string) (dir, source string, err error) {
	return datadir.Resolve(explicit, workdir, EnvDir, "attacks")
}

// Load reads every *.json attack file in dir, non-recursively. Subdirectories are
// skipped: scripts/fetch-attack.sh clones whole upstream repos underneath.
//
// It returns an error rather than a partial set if any file fails to load, and
// ErrNoAttacks if none were found. A missing dir wraps fs.ErrNotExist so the
// caller can turn it into a gap instead of an abort.
func Load(dir string) ([]Attack, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("attack: %w", err)
	}

	var out []Attack
	seen := map[string]string{}

	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		c, err := loadFile(path)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[c.ID]; dup {
			return nil, fmt.Errorf("attack: duplicate id %q in %s and %s", c.ID, prev, path)
		}
		seen[c.ID] = path
		out = append(out, c)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("attack: %s: %w", dir, ErrNoAttacks)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func loadFile(path string) (Attack, error) {
	var c Attack

	f, err := os.Open(path)
	if err != nil {
		return c, fmt.Errorf("attack: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	// A misspelled key would otherwise decode to zero packages and read as clean.
	dec.DisallowUnknownFields()

	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("attack: %s: %w", path, err)
	}
	if dec.More() {
		return c, fmt.Errorf("attack: %s: trailing data after the attack object", path)
	}

	c.File = path
	if err := c.validate(); err != nil {
		return c, fmt.Errorf("attack: %s: %w", path, err)
	}
	return c, nil
}

func (c *Attack) validate() error {
	if c.Schema != Schema {
		return fmt.Errorf("schema %d is not supported, want %d", c.Schema, Schema)
	}
	if c.ID == "" {
		return errors.New("id is required")
	}
	if c.Name == "" {
		return errors.New("name is required")
	}
	if c.Started.IsZero() {
		return errors.New("started is required: layers 2 and 4 have no forensic window without it")
	}
	if len(c.Packages) == 0 && len(c.Artifacts) == 0 {
		return errors.New("attack declares neither packages nor artifacts and can never match")
	}

	for i, p := range c.Packages {
		if p.Ecosystem == "" {
			return fmt.Errorf("packages[%d]: ecosystem is required", i)
		}
		if p.Name == "" {
			return fmt.Errorf("packages[%d]: name is required", i)
		}
		for j, v := range p.Versions {
			if strings.TrimSpace(v) == "" {
				return fmt.Errorf("packages[%d].versions[%d]: empty version", i, j)
			}
		}
	}

	for i, a := range c.Artifacts {
		if !artifactKinds[a.Kind] {
			return fmt.Errorf("artifacts[%d]: unknown kind %q", i, a.Kind)
		}
		if a.Value == "" {
			return fmt.Errorf("artifacts[%d]: value is required", i)
		}
		if a.Kind == KindFilename && a.PathScope == "" {
			return fmt.Errorf("artifacts[%d]: kind %q requires pathScope; %q unscoped is a false-positive generator", i, a.Kind, a.Value)
		}
		if a.PathScope != "" {
			if _, err := filepath.Match(a.PathScope, ""); err != nil {
				return fmt.Errorf("artifacts[%d]: bad pathScope %q: %w", i, a.PathScope, err)
			}
		}
	}

	return nil
}

// VersionLabel renders Versions for display. An empty list matches every
// version, and printing an empty column would hide that.
func (p Package) VersionLabel() string {
	if len(p.Versions) == 0 {
		return "ALL VERSIONS"
	}
	return strings.Join(p.Versions, ", ")
}

// NormalizeVersion makes two spellings of the same version comparable.
//
// A vendor list writes "v6.0.0" where a lockfile stores "6.0.0", and semver
// says build metadata is NOT part of precedence — so "6.0.0" and "6.0.0+build"
// are the same version. Comparing them raw produced a clean verdict with the
// attack loaded, which is the worst output this tool can give.
//
// Deliberately conservative: it does not parse or range-match. Anything beyond
// these two spellings is left alone rather than guessed at.
func NormalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	if i := strings.IndexByte(v, '+'); i > 0 {
		v = v[:i]
	}
	return v
}

// NormalizeName folds a package name the way its own registry does, so a
// vendor's spelling and a lockfile's spelling of the same package compare
// equal.
//
// Only ecosystems whose registry publishes a folding rule are folded: npm
// lowercases, and PyPI normalizes per PEP 503 (lowercase, and runs of - _ .
// collapse to a single -). Everything else is compared verbatim, because Go
// module paths and others are genuinely case-sensitive and folding them would
// invent matches.
func NormalizeName(ecosystem, name string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return strings.ToLower(strings.TrimSpace(name))
	case "pypi":
		var b strings.Builder
		prevSep := false
		for _, r := range strings.ToLower(strings.TrimSpace(name)) {
			if r == '-' || r == '_' || r == '.' {
				if !prevSep {
					b.WriteByte('-')
					prevSep = true
				}
				continue
			}
			prevSep = false
			b.WriteRune(r)
		}
		return b.String()
	default:
		return strings.TrimSpace(name)
	}
}

// Matches reports whether ecosystem/name@version is covered by p.
//
// An empty Versions list means EVERY version matches: a wholly malicious
// package has no safe version, and layer 1's self-validation mode needs the
// same shape.
func (p Package) Matches(ecosystem, name, version string) bool {
	if !strings.EqualFold(p.Ecosystem, ecosystem) {
		return false
	}
	if NormalizeName(p.Ecosystem, p.Name) != NormalizeName(ecosystem, name) {
		return false
	}
	if len(p.Versions) == 0 {
		return true
	}
	want := NormalizeVersion(version)
	for _, v := range p.Versions {
		if NormalizeVersion(v) == want {
			return true
		}
	}
	return false
}
