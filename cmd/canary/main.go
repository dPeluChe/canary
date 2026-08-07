// Command canary is a read-only supply-chain forensics scanner for trees of
// repositories. It never modifies what it inspects.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/dPeluChe/canary/internal/attack"
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
  discover   Inventory repos and lockfiles under a path
  attacks    List or show the known attacks canary can match against
  scan       Run the full sweep and emit a verdict per repo
  version    Print the version

Run "canary <command> -h" for command flags.

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

	sub := "list"
	if flags.NArg() > 0 {
		sub = flags.Arg(0)
	}
	if sub != "list" && sub != "show" {
		fmt.Fprintf(os.Stderr, "canary attacks: unknown subcommand %q (want list or show)\n", sub)
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

	if sub == "show" {
		if flags.NArg() < 2 {
			fmt.Fprintln(os.Stderr, "canary attacks show: needs an attack id")
			return exitError
		}
		return showAttack(attacks, flags.Arg(1))
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
