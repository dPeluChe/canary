// Command canary is a read-only supply-chain forensics scanner for trees of
// repositories. It never modifies what it inspects.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

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
	case "update":
		os.Exit(cmdUpdate(os.Args[2:]))
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
  attacks -corpus    Load a cumulative dataset (DataDog/pypi-mal) instead
  attacks -corpus <pkg>  Look up one package in a loaded corpus
  import -csv <f>    Convert a vendor CSV to an attack file, on stdout
  update             Refresh the redistributable source lists
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
