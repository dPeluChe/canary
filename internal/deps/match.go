package deps

import (
	"sort"
	"strings"

	"github.com/dPeluChe/canary/internal/attack"
	"github.com/dPeluChe/canary/internal/corpus"
)

// Finding is one resolved package that at least one source calls malicious,
// with every source that said so. Provenance is kept per finding because one
// vendor list saying it and three independent sources saying it are different
// claims, and a report that flattens them cannot be calibrated.
type Finding struct {
	Resolved
	Attacks []string // attack ids that flagged this exact version
	Sources []string // corpus sources that flagged it
}

// String renders the finding as ecosystem/name@version, the form used in
// verdict.Repo.MaliciousDeps.
func (f Finding) String() string {
	return f.Ecosystem + "/" + f.Name + "@" + f.Version
}

// Matcher answers "is this resolved package malicious" against a fixed set of
// attacks and corpus. The index is built once, so a caller that matches per
// repo — a scan — pays for it once instead of once per repo per mode.
// A Matcher is read-only after NewMatcher and safe for concurrent use.
type Matcher struct {
	idx    map[indexKey][]attackRef
	corpus *corpus.Corpus
}

// NewMatcher indexes attacks for repeated matching.
func NewMatcher(attacks []attack.Attack, c *corpus.Corpus) *Matcher {
	return &Matcher{idx: indexAttacks(attacks), corpus: c}
}

// Match reports which resolved packages are known malicious.
//
// This is the offline path: it consults the attack files and corpus already
// loaded, never the network. Absence from them is absence from those lists,
// not evidence of safety — the wording of anything built on this must not
// overstate it.
func Match(resolved []Resolved, attacks []attack.Attack, c *corpus.Corpus) []Finding {
	return NewMatcher(attacks, c).Match(resolved)
}

// MatchIgnoringVersions runs the same cross with the version test removed, to
// prove the extractor can see a package family AT ALL.
//
// This is not a convenience. During the incident that started this project the
// match was re-run without the version filter specifically to check the parser
// could see the affected family before a negative result was trusted — it
// found keyv at safe versions, which is what made "no malicious versions" mean
// something. A negative from an extractor never observed matching anything is
// worthless. See docs/JOURNAL/2608.md.
func MatchIgnoringVersions(resolved []Resolved, attacks []attack.Attack, c *corpus.Corpus) []Finding {
	return NewMatcher(attacks, c).MatchIgnoringVersions(resolved)
}

// Match is the reusable form of the package-level Match.
func (m *Matcher) Match(resolved []Resolved) []Finding { return m.match(resolved, true) }

// MatchIgnoringVersions is the reusable form of the package-level function.
func (m *Matcher) MatchIgnoringVersions(resolved []Resolved) []Finding {
	return m.match(resolved, false)
}

func (m *Matcher) match(resolved []Resolved, checkVersion bool) []Finding {
	byPkg := map[indexKey]*Finding{}
	var order []indexKey

	for _, r := range resolved {
		// Normalize once: the versioned key and the index lookup fold the
		// ecosystem and name identically, so doing it twice per package is
		// the hot loop's only waste.
		base := indexKey{strings.ToLower(r.Ecosystem), attack.NormalizeName(r.Ecosystem, r.Name), ""}
		key := base
		key.version = r.Version
		if !checkVersion {
			key.version = ""
		}

		var hitAttacks, hitSources []string

		for _, ref := range m.idx[base] {
			if !checkVersion || ref.pkg.Matches(r.Ecosystem, r.Name, r.Version) {
				hitAttacks = appendUnique(hitAttacks, ref.attackID)
			}
		}

		if m.corpus != nil {
			if entry, ok := m.corpus.Lookup(r.Ecosystem, r.Name); ok {
				if !checkVersion || entry.Matches(r.Ecosystem, r.Name, r.Version) {
					hitSources = appendUnique(hitSources, entry.Sources...)
				}
			}
		}

		if len(hitAttacks) == 0 && len(hitSources) == 0 {
			continue
		}

		// One finding per package version, even when several lockfiles across
		// the tree resolve it — the lockfile that carried it is on Resolved.
		f, seen := byPkg[key]
		if !seen {
			f = &Finding{Resolved: r}
			byPkg[key] = f
			order = append(order, key)
		}
		f.Attacks = appendUnique(f.Attacks, hitAttacks...)
		f.Sources = appendUnique(f.Sources, hitSources...)
	}

	out := make([]Finding, 0, len(order))
	for _, k := range order {
		f := byPkg[k]
		sort.Strings(f.Attacks)
		sort.Strings(f.Sources)
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}

type indexKey struct {
	ecosystem, name, version string
}

type attackRef struct {
	attackID string
	pkg      attack.Package
}

// indexAttacks builds a name lookup so matching is not quadratic. A real tree
// resolves hundreds of thousands of packages against hundreds of attack
// entries; comparing every pair would be the slowest part of a scan by orders
// of magnitude.
func indexAttacks(attacks []attack.Attack) map[indexKey][]attackRef {
	idx := map[indexKey][]attackRef{}
	for _, a := range attacks {
		for _, p := range a.Packages {
			// The index key must fold exactly as Matches folds, or the lookup
			// short-circuits before the comparison it is meant to accelerate.
			key := indexKey{strings.ToLower(p.Ecosystem), attack.NormalizeName(p.Ecosystem, p.Name), ""}
			idx[key] = append(idx[key], attackRef{attackID: a.ID, pkg: p})
		}
	}
	return idx
}

func appendUnique(dst []string, vals ...string) []string {
	for _, v := range vals {
		if v == "" {
			continue
		}
		found := false
		for _, d := range dst {
			if d == v {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, v)
		}
	}
	return dst
}
