// Command canary is a read-only supply-chain forensics scanner for trees of
// repositories. It never modifies what it inspects.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/dPeluChe/canary/internal/attack"
	"github.com/dPeluChe/canary/internal/corpus"
	"github.com/dPeluChe/canary/internal/discover"
)

const version = "0.0.1-dev"

// Exit codes are part of the contract: CI and cron branch on them.
const (
	exitClean    = 0 // nothing found
	exitFindings = 1 // findings present
	exitError    = 2 // canary itself failed
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitError)
	}

	switch os.Args[1] {
	case "discover":
		os.Exit(cmdDiscover(os.Args[2:]))
	case "attacks":
		os.Exit(cmdAttacks(os.Args[2:]))
	case "import":
		os.Exit(cmdImport(os.Args[2:]))
	case "corpus":
		os.Exit(cmdCorpus(os.Args[2:]))
	case "scan":
		os.Exit(cmdScan(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Println("canary", version)
		os.Exit(exitClean)
	case "help", "--help", "-h":
		usage()
		os.Exit(exitClean)
	default:
		fmt.Fprintf(os.Stderr, "canary: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(exitError)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `canary — read-only supply-chain forensics for trees of repositories

USAGE
  canary <command> [flags] [path]

COMMANDS
  discover <path>    Inventory repos and lockfiles under a path
  attacks            Known attacks canary can match against
  attacks <id>       One attack in full
  import -csv <f>    Convert a vendor CSV to an attack file, on stdout
  corpus <dir>       Load a cumulative malicious-package dataset (DataDog/pypi-mal)
  corpus <dir> <pkg> Look up one package in a loaded corpus
  scan <path>        Run the full sweep and emit a verdict per repo
  version            Print the version

Run "canary <command> -h" for command flags.

No command takes more than two words. Anything longer is a flag.

canary never writes to what it scans. There is no remediation flag by design:
a forensic tool that modifies destroys the evidence it was sent to collect.
`)
}

func cmdDiscover(args []string) int {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	quiet := fs.Bool("quiet", false, "only print the summary")
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}

	res, err := discover.Walk(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}

	if !*quiet {
		for _, r := range res.Repos {
			slug := r.Slug
			if slug == "" {
				slug = "(no github remote)"
			}
			fmt.Printf("%-40s %-34s %d lockfile(s)\n", r.Name, slug, len(r.Lockfiles))
			for _, lf := range r.Lockfiles {
				fmt.Printf("    %-24s %s\n", lf.Ecosystem, lf.Rel)
			}
		}
		for _, lf := range res.Orphans {
			rel, _ := filepath.Rel(res.Root, lf.Path)
			fmt.Printf("%-40s %-34s %s\n", "(outside any repo)", lf.Ecosystem, rel)
		}
	}

	fmt.Printf("\n%d repos · %d lockfiles · %d orphan lockfiles under %s\n",
		len(res.Repos), res.CountLockfiles(), len(res.Orphans), res.Root)
	return exitClean
}

// cmdAttacks lists or shows the attack data files canary matches against. It
// always prints which directory it read and why that one, because "no attacks
// loaded" and "attacks loaded, nothing matched" are the pair this whole tool
// exists to keep apart.
func cmdAttacks(args []string) int {
	flags := flag.NewFlagSet("attacks", flag.ExitOnError)
	dir := flags.String("dir", "", "attack directory (default: $CANARY_ATTACK_DIR, ./attacks, ~/.canary/attacks)")
	if err := flags.Parse(args); err != nil {
		return exitError
	}

	wd, _ := os.Getwd()
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

// cmdCorpus loads a cumulative malicious-package dataset (DataDog or
// pypi_malregistry shape) and either lists its coverage or looks up one
// package. A corpus is NOT a set of attack files: it has no forensic window,
// so it feeds layer 1's matching directly rather than going through Attack.
func cmdCorpus(args []string) int {
	fs := flag.NewFlagSet("corpus", flag.ExitOnError)
	eco := fs.String("ecosystem", "", "filter lookup to one ecosystem (npm, PyPI, ...)")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "canary corpus: <dir> required (a cloned DataDog dataset or pypi_malregistry)")
		return exitError
	}

	c, err := corpus.LoadDataDog(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}

	// A second positional arg is a package name to look up. Exit codes follow
	// the contract: a hit is a FINDING (1), a miss is clean (0). Getting this
	// backwards makes `canary corpus <dir> <pkg> && echo ok` print ok exactly
	// when the package is malicious.
	if fs.NArg() >= 2 {
		name := fs.Arg(1)
		lookups := c.Ecosystems()
		if *eco != "" {
			if !slices.Contains(lookups, *eco) {
				fmt.Fprintf(os.Stderr, "canary: -ecosystem %q is not in this corpus (have: %s)\n",
					*eco, strings.Join(lookups, ", "))
				return exitError
			}
			lookups = []string{*eco}
		}

		hit := false
		for _, e := range lookups {
			entry, ok := c.Lookup(e, name)
			if !ok {
				continue
			}
			hit = true
			vers := entry.VersionLabel()
			fmt.Printf("%-10s %-40s %s\n", e, name, vers)
			fmt.Printf("%-10s %-40s via %s\n", "", "", strings.Join(entry.Sources, ", "))
		}
		if !hit {
			// Not a clean bill of health, and the wording must not imply one.
			fmt.Printf("%s: not in this corpus (%d entries across %s)\n",
				name, c.Count(""), strings.Join(c.Ecosystems(), ", "))
			fmt.Println("absence from a list is not evidence of safety, only absence from that list")
			return exitClean
		}
		return exitFindings
	}

	fmt.Printf("%d entries from %s — sources: %s\n\n",
		c.Count(""), fs.Arg(0), strings.Join(c.Sources(), ", "))
	fmt.Printf("%-20s %8s\n", "ECOSYSTEM", "ENTRIES")
	for _, e := range c.Ecosystems() {
		fmt.Printf("%-20s %8d\n", e, c.Count(e))
	}
	return exitClean
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	since := fs.String("since", "", "forensic window start, RFC3339 (e.g. 2026-08-04T09:00:00Z)")
	offline := fs.Bool("offline", false, "no network: local attack files only")
	format := fs.String("format", "text", "output format: text|json|sarif")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	_, _, _ = since, offline, format

	fmt.Fprintln(os.Stderr, "canary: scan is not implemented yet — see docs/ARCHITECTURE/OVERVIEW.md")
	fmt.Fprintln(os.Stderr, "        the discover layer is done: try `canary discover <path>`")
	return exitError
}
