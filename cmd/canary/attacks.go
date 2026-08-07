package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/dPeluChe/canary/internal/attack"
	"github.com/dPeluChe/canary/internal/corpus"
)

// cmdAttacks lists or shows the attack data canary matches against. It
// always prints which directory it read and why that one, because "no attacks
// loaded" and "attacks loaded, nothing matched" are the pair this whole tool
// exists to keep apart.
//
// With -corpus, the same command loads a cumulative dataset (DataDog,
// pypi_malregistry) instead of attack files. A corpus is another source of
// "is this malicious?" — the same question attacks answer — so it lives here
// rather than as a third top-level noun. The positional arg becomes a package
// name to look up, and a hit exits 1 (finding) while a miss exits 0.
func cmdAttacks(args []string) int {
	flags := flag.NewFlagSet("attacks", flag.ExitOnError)
	dir := flags.String("dir", "", "directory (attack files or corpus dataset)")
	asCorpus := flags.Bool("corpus", false, "load a corpus dataset (DataDog/pypi-mal) instead of attack files")
	eco := flags.String("ecosystem", "", "filter corpus lookup to one ecosystem (npm, PyPI, ...)")
	if err := flags.Parse(args); err != nil {
		return exitError
	}

	wd, _ := os.Getwd()

	if *asCorpus {
		return cmdAttacksCorpus(flags, *dir, *eco, wd)
	}

	resolved, source, err := attack.ResolveDir(*dir, wd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}

	attacks, err := attack.Load(resolved)
	if err != nil {
		fmt.Fprintf(os.Stderr, "canary: %s (%s)\n", resolved, source)
		fmt.Fprintln(os.Stderr, "canary:", err)
		if errors.Is(err, attack.ErrNoAttacks) || errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintln(os.Stderr, "        fetch a list with scripts/fetch-attack.sh, or pass -dir")
		}
		return exitError
	}

	// A positional argument is an attack id. There is no list/show subcommand:
	// `canary attacks` already means "show me the attacks".
	if flags.NArg() == 1 {
		return showAttack(attacks, flags.Arg(0))
	}
	if flags.NArg() > 1 {
		fmt.Fprintf(os.Stderr, "canary attacks: one attack id at a time, got %d arguments\n", flags.NArg())
		return exitError
	}

	fmt.Printf("%d attack(s) from %s (%s)\n\n", len(attacks), resolved, source)
	fmt.Printf("%-20s %-12s %8s %10s  %s\n", "ID", "STARTED", "PACKAGES", "ARTIFACTS", "NAME")
	for _, a := range attacks {
		fmt.Printf("%-20s %-12s %8d %10d  %s\n",
			a.ID, a.Started.UTC().Format("2006-01-02"), len(a.Packages), len(a.Artifacts), a.Name)
	}
	return exitClean
}

// cmdAttacksCorpus is the -corpus path of cmdAttacks. It resolves the corpus
// directory the same way attacks resolves its own — an inconsistency here
// would mean -dir means different things depending on whether -corpus is set.
func cmdAttacksCorpus(flags *flag.FlagSet, dir, ecoFilter, wd string) int {
	resolved, source, err := corpus.ResolveDir(dir, wd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}

	c, err := corpus.Load(resolved)
	if err != nil {
		fmt.Fprintf(os.Stderr, "canary: %s (%s)\n", resolved, source)
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}

	// A positional argument is a package name to look up. Exit codes follow
	// the contract: a hit is a FINDING (1), a miss is clean (0). Getting this
	// backwards makes `canary attacks -corpus <pkg> && echo ok` print ok
	// exactly when the package is malicious.
	if flags.NArg() >= 1 {
		name := flags.Arg(0)
		lookups := c.Ecosystems()
		if ecoFilter != "" {
			if !slices.Contains(lookups, ecoFilter) {
				fmt.Fprintf(os.Stderr, "canary: -ecosystem %q is not in this corpus (have: %s)\n",
					ecoFilter, strings.Join(lookups, ", "))
				return exitError
			}
			lookups = []string{ecoFilter}
		}

		hit := false
		for _, e := range lookups {
			entry, ok := c.Lookup(e, name)
			if !ok {
				continue
			}
			hit = true
			fmt.Printf("%-10s %-40s %s\n", e, name, entry.VersionLabel())
			fmt.Printf("%-10s %-40s via %s\n", "", "", strings.Join(entry.Sources, ", "))
		}
		if !hit {
			fmt.Printf("%s: not in this corpus (%d entries across %s)\n",
				name, c.Count(""), strings.Join(c.Ecosystems(), ", "))
			fmt.Println("absence from a list is not evidence of safety, only absence from that list")
			return exitClean
		}
		return exitFindings
	}

	fmt.Printf("%d entries from %s (%s)\n\n", c.Count(""), resolved, source)

	// Age is printed because refreshing is explicit: a list nobody updated in
	// months reports clean just as confidently as a current one.
	fetched := c.Fetched()
	fmt.Printf("%-46s %s\n", "SOURCE", "LAST REFRESHED")
	for _, s := range c.Sources() {
		when, ok := fetched[s]
		if !ok {
			fmt.Printf("%-46s unknown\n", s)
			continue
		}
		age := time.Since(when)
		note := ""
		if age > 7*24*time.Hour {
			note = fmt.Sprintf("  STALE — %d days old, run `canary update`", int(age.Hours()/24))
		}
		fmt.Printf("%-46s %s%s\n", s, when.UTC().Format("2006-01-02"), note)
	}
	fmt.Println()
	fmt.Printf("%-20s %8s\n", "ECOSYSTEM", "ENTRIES")
	for _, e := range c.Ecosystems() {
		fmt.Printf("%-20s %8d\n", e, c.Count(e))
	}
	return exitClean
}

func showAttack(attacks []attack.Attack, id string) int {
	for _, a := range attacks {
		if a.ID != id {
			continue
		}
		fmt.Printf("%s — %s\n", a.ID, a.Name)
		fmt.Printf("window starts  %s\n", a.Started.UTC().Format(time.RFC3339))
		fmt.Printf("source         %s\n", a.Source)
		fmt.Printf("file           %s\n", a.File)
		if a.Note != "" {
			fmt.Printf("note           %s\n", a.Note)
		}

		fmt.Printf("\nPACKAGES (%d)\n", len(a.Packages))
		for _, p := range a.Packages {
			fmt.Printf("  %-12s %-32s %s\n", p.Ecosystem, p.Name, p.VersionLabel())
		}

		fmt.Printf("\nARTIFACTS (%d)\n", len(a.Artifacts))
		for _, art := range a.Artifacts {
			scope := art.PathScope
			if scope == "" {
				scope = "(anywhere)"
			}
			fmt.Printf("  %-10s %-34s under %s\n", art.Kind, art.Value, scope)
			if art.Note != "" {
				fmt.Printf("             %s\n", art.Note)
			}
		}
		return exitClean
	}

	fmt.Fprintf(os.Stderr, "canary: no attack with id %q among %d loaded\n", id, len(attacks))
	return exitError
}

// cmdImport converts a vendor CSV into an attack file on STDOUT. canary
// never writes a file — redirect it yourself. That keeps the read-only
// invariant literal rather than argued about.
func cmdImport(args []string) int {
	flags := flag.NewFlagSet("import", flag.ExitOnError)
	csvPath := flags.String("csv", "", "vendor package list (CSV with Package / Malicious Versions columns)")
	id := flags.String("id", "", "attack id, e.g. keyv-2026-08")
	name := flags.String("name", "", "human label")
	started := flags.String("started", "", "attack window start, RFC3339")
	source := flags.String("source", "", "URL of the report this came from")
	note := flags.String("note", "", "why this attack file exists")
	ecosystem := flags.String("ecosystem", "npm", "OSV ecosystem for every row")
	if err := flags.Parse(args); err != nil {
		return exitError
	}

	if *csvPath == "" || *id == "" || *name == "" || *started == "" {
		fmt.Fprintln(os.Stderr, "canary import: -csv, -id, -name and -started are required")
		fmt.Fprintln(os.Stderr, "  canary import -csv keyv.csv -id keyv-2026-08 \\")
		fmt.Fprintln(os.Stderr, "    -name 'keyv npm compromise' -started 2026-08-04T09:00:00Z \\")
		fmt.Fprintln(os.Stderr, "    -source https://... > attacks/keyv-2026-08.json")
		return exitError
	}

	when, err := time.Parse(time.RFC3339, *started)
	if err != nil {
		fmt.Fprintf(os.Stderr, "canary: -started must be RFC3339: %v\n", err)
		return exitError
	}

	f, err := os.Open(*csvPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}
	defer f.Close()

	built, err := attack.FromCSV(f, *ecosystem, attack.Attack{
		ID: *id, Name: *name, Started: when, Source: *source, Note: *note,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(built); err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}

	fmt.Fprintf(os.Stderr, "canary: %d package(s) from %s — artifacts must be added by hand, the CSV carries none\n",
		len(built.Packages), *csvPath)
	return exitClean
}
