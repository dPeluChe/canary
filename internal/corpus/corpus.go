// Package corpus loads cumulative malicious-package datasets and answers
// "is this resolved version known malicious" for layer 1.
//
// A corpus is deliberately NOT a set of attack files. An attack file is one
// registry compromise with a forensic window (Attack.Started) that layers 2
// and 4 key off; a corpus spans years and many unrelated incidents and has no
// single window. Forcing a cumulative dataset into one Attack would invent a
// meaningless Started and pollute the window-based layers.
//
// Matching reuses attack.Package so a corpus hit and an attack hit cannot
// disagree about the same package — two sources that compare versions or
// ecosystems differently would produce answers that depend on which list found
// it first.
//
// Every entry carries the sources that flagged it. Provenance is per entry,
// never per corpus: one source is a claim, three agreeing is corroboration,
// and a report that cannot tell them apart cannot be calibrated.
package corpus

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dPeluChe/canary/internal/attack"
	"github.com/dPeluChe/canary/internal/datadir"
)

// Entry is one malicious package from one or more corpus sources.
type Entry struct {
	attack.Package
	Sources []string // every source that flagged this package
}

// Corpus is an offline lookup of known-malicious packages from cumulative
// sources. The zero value is an empty corpus; use a Load function to populate.
type Corpus struct {
	entries map[entryKey]Entry
	counts  map[string]int // per-ecosystem entry count
	sources []string
}

// Ecosystem is folded for the key because attack.Package.Matches compares it
// case-insensitively; keying on the raw string would make lookup stricter than
// matching and lose entries.
type entryKey struct {
	ecosystem, name string
}

// The name is folded exactly as attack.Package.Matches folds it, or a lookup
// would miss an entry that matching would have hit.
func keyFor(ecosystem, name string) entryKey {
	return entryKey{strings.ToLower(ecosystem), attack.NormalizeName(ecosystem, name)}
}

// datadogSubdirToOSV maps a DataDog samples/<subdir> to the OSV ecosystem
// identifier canary uses everywhere else. Upstream is inconsistent about
// separators (ai-skills, ide_extensions), so both spellings are accepted.
//
// A subdir absent from this map is an error, not a skip: a corpus that
// silently drops an ecosystem reads as broader coverage than it has.
var datadogSubdirToOSV = map[string]string{
	"npm":              "npm",
	"pypi":             "PyPI",
	"ide_extensions":   "VSCode Marketplace",
	"ide-extensions":   "VSCode Marketplace",
	"ai_skills":        "AI Skills",
	"ai-skills":        "AI Skills",
	"vscode":           "VSCode Marketplace",
	"vscode_extension": "VSCode Marketplace",
}

// IsMalicious reports whether ecosystem/name@version is in the corpus.
// An entry with no versions matches every version.
func (c *Corpus) IsMalicious(ecosystem, name, version string) bool {
	e, ok := c.Lookup(ecosystem, name)
	if !ok {
		return false
	}
	return e.Matches(ecosystem, name, version)
}

// Lookup returns the entry for ecosystem/name, or false if absent. The
// returned Versions slice is empty when every version matches.
func (c *Corpus) Lookup(ecosystem, name string) (Entry, bool) {
	if c.entries == nil {
		return Entry{}, false
	}
	e, ok := c.entries[keyFor(ecosystem, name)]
	return e, ok
}

// Count returns the number of entries for an ecosystem, or the total when
// ecosystem is empty.
func (c *Corpus) Count(ecosystem string) int {
	if ecosystem == "" {
		n := 0
		for _, ct := range c.counts {
			n += ct
		}
		return n
	}
	return c.counts[ecosystem]
}

// Ecosystems returns the ecosystems present, sorted.
func (c *Corpus) Ecosystems() []string {
	out := make([]string, 0, len(c.counts))
	for eco := range c.counts {
		out = append(out, eco)
	}
	sort.Strings(out)
	return out
}

// Sources returns the source labels this corpus was built from.
func (c *Corpus) Sources() []string {
	return append([]string(nil), c.sources...)
}

// Sources a corpus directory can come from, in precedence order. Mirrors
// attack.ResolveDir so `canary attacks -corpus` resolves its directory the
// same way `canary attacks` does — an inconsistency here would mean the same
// flag means different things depending on whether -corpus is set.
const (
	SourceFlag    = datadir.SourceFlag
	SourceEnv     = "$" + EnvDir
	SourceRepo    = datadir.SourceRepo + " corpus/"
	SourceDefault = datadir.SourceDefault
)

// EnvDir is the environment variable scripts/fetch-attack.sh writes into.
const EnvDir = "CANARY_CORPUS_DIR"

// ResolveDir picks which directory to load a corpus from, and reports which
// source chose it. Same contract as attack.ResolveDir — they share
// datadir.Resolve so a flag cannot behave differently depending on which data
// it points at.
func ResolveDir(explicit, workdir string) (dir, source string, err error) {
	return datadir.Resolve(explicit, workdir, EnvDir, "corpus")
}

// LoadDataDog reads every samples/<subdir>/manifest.json under dir (a cloned
// DataDog malicious-software-packages-dataset). Each manifest is a
// map[name][]versions where a JSON null means "every version is malicious" —
// which is the overwhelming majority of entries, since a typosquat has no safe
// version.
func LoadDataDog(dir string) (*Corpus, error) {
	const source = "DataDog/malicious-software-packages-dataset"

	samples := filepath.Join(dir, "samples")
	entries, err := os.ReadDir(samples)
	if err != nil {
		return nil, fmt.Errorf("corpus: datadog: %w", err)
	}

	c := &Corpus{
		entries: map[entryKey]Entry{},
		counts:  map[string]int{},
		sources: []string{source},
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		eco, ok := datadogSubdirToOSV[e.Name()]
		if !ok {
			return nil, fmt.Errorf("corpus: datadog: unknown ecosystem subdir %q — map it in datadogSubdirToOSV or remove the directory", e.Name())
		}
		if err := c.loadManifest(eco, filepath.Join(samples, e.Name(), "manifest.json"), source); err != nil {
			return nil, err
		}
	}

	if c.Count("") == 0 {
		return nil, fmt.Errorf("corpus: datadog: %s: no entries loaded", dir)
	}
	return c, nil
}

func (c *Corpus) loadManifest(eco, path, source string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("corpus: %w", err)
	}
	defer f.Close()

	var m map[string][]string
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return fmt.Errorf("corpus: %s: %w", path, err)
	}

	for name, vers := range m {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		c.add(Entry{
			Package: attack.Package{Ecosystem: eco, Name: name, Versions: attack.NormalizeVersions(vers)},
			Sources: []string{source},
		})
	}
	return nil
}

// add merges an entry into the corpus. When two sources disagree, coverage
// only ever WIDENS: an empty version list means "every version" and must not
// be narrowed by a source that happens to list a few. Silently trading a
// match-all entry for a match-three entry loses exactly the packages a corpus
// exists to catch.
func (c *Corpus) add(e Entry) {
	key := keyFor(e.Ecosystem, e.Name)
	prev, dup := c.entries[key]
	if !dup {
		c.counts[e.Ecosystem]++
		c.entries[key] = e
		return
	}

	if len(prev.Versions) == 0 || len(e.Versions) == 0 {
		prev.Versions = nil
	} else {
		prev.Versions = attack.NormalizeVersions(append(prev.Versions, e.Versions...))
	}
	for _, s := range e.Sources {
		if !slicesContains(prev.Sources, s) {
			prev.Sources = append(prev.Sources, s)
		}
	}
	c.entries[key] = prev
}

func slicesContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
