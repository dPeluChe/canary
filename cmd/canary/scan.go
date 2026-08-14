package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dPeluChe/canary/internal/attack"
	"github.com/dPeluChe/canary/internal/ci"
	"github.com/dPeluChe/canary/internal/corpus"
	"github.com/dPeluChe/canary/internal/deps"
	"github.com/dPeluChe/canary/internal/discover"
	"github.com/dPeluChe/canary/internal/inventory"
	"github.com/dPeluChe/canary/internal/ioc"
	"github.com/dPeluChe/canary/internal/verdict"
	"github.com/dPeluChe/canary/internal/zizmor"
)

// cmdScan is the whole product in one command: inventory a tree, resolve every
// lockfile transitively, and cross the result against every known attack.
//
// Layers 2, 3 and 4 are not implemented, so this reports layer 1 only — and
// says so in the gaps rather than letting the output read as a full sweep.
func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	dir := fs.String("dir", "", "attack directory (default: $CANARY_ATTACK_DIR, ./attacks, ~/.canary/attacks)")
	corpusDir := fs.String("corpus", "", "corpus dataset to consult as well (default: $CANARY_CORPUS_DIR, ./corpus)")
	format := fs.String("format", "text", "output format: text|json|sarif")
	reuse := fs.Bool("reuse", false, "match against the stored inventory instead of re-reading the tree")
	noSave := fs.Bool("no-inventory", false, "do not persist the resolved inventory")
	verbose := fs.Bool("v", false, "list every clean and skipped repo instead of summarising them")
	sweepOn := fs.Bool("sweep", true, "layer 2 artifact sweep; walks node_modules, so it costs minutes on a large tree")
	ciOn := fs.Bool("ci", false, "layer 4: query GitHub Actions runs inside the window (needs GITHUB_TOKEN or GH_TOKEN)")
	homeOn := fs.Bool("home", true, "also inspect persistence targets in $HOME (agent hooks, shell profiles) — outside the scanned tree")
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}
	wd, _ := os.Getwd()

	// Before any work: a scan that runs to completion and then fails to
	// render has done its most expensive work for nothing.
	if *format != "text" && *format != "json" && *format != "sarif" {
		fmt.Fprintf(os.Stderr, "canary: unknown format %q (want text, json or sarif)\n", *format)
		return exitError
	}

	dataDir, dataErr := inventory.DataDir()

	// -reuse answers one question only: does a newly published attack touch the
	// set we already resolved? It must therefore touch NOTHING — no walk, no
	// sweep, no network. Walking the tree first would cost what a full scan
	// costs and defeat the artifact entirely.
	if *reuse {
		if dataErr != nil {
			fmt.Fprintln(os.Stderr, "canary:", dataErr)
			return exitError
		}
		return scanFromInventory(inventory.Path(dataDir, mustAbs(root)), *dir, *corpusDir, *format, *verbose)
	}

	inv, err := discover.Walk(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}

	rep := &verdict.Report{Root: inv.Root, Verbose: *verbose}

	attackDir, attackSrc, err := attack.ResolveDir(*dir, wd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}
	attacks, err := attack.Load(attackDir)
	if err != nil {
		// No attacks is not a clean scan — it is a scan with nothing to match
		// against, and it must not be reported as one.
		fmt.Fprintf(os.Stderr, "canary: %s (%s)\n", attackDir, attackSrc)
		fmt.Fprintln(os.Stderr, "canary:", err)
		fmt.Fprintln(os.Stderr, "        a scan with zero attacks loaded reports clean for the same")
		fmt.Fprintln(os.Stderr, "        reason a scan that never ran does — refusing to run")
		return exitError
	}
	for _, a := range attacks {
		rep.Attacks = append(rep.Attacks, a.ID)
	}

	var c *corpus.Corpus
	corpusPath, _, cErr := corpus.ResolveDir(*corpusDir, wd)
	if cErr == nil {
		if loaded, err := corpus.Load(corpusPath); err == nil {
			c = loaded
			rep.Attacks = append(rep.Attacks, loaded.Sources()...)
		} else if *corpusDir != "" {
			fmt.Fprintln(os.Stderr, "canary:", err)
			return exitError
		} else {
			// The reason matters: a corrupt corpus and an absent one are
			// different problems, and "not consulted" alone hides which.
			rep.AddGap("no corpus dataset loaded (%s): %v — cumulative sources not consulted", corpusPath, err)
		}
	}

	// Layer 2 runs once over the whole tree rather than per repo: it opts back
	// into node_modules, and walking that twice for nested repos would double
	// the most expensive part of a scan.
	window := earliestWindow(attacks)
	sweep := &ioc.Result{}
	switch {
	case !*sweepOn:
		rep.AddGap("layer 2 artifact sweep was disabled with -sweep=false; the tree was NOT searched for artifacts")
	case artifactCount(attacks) == 0:
		rep.AddGap("no attack file carries filesystem artifacts, so the tree was not searched for any")
	default:
		sweep, err = ioc.Sweep(inv.Root, attacks, ioc.Options{Window: window})
		if err != nil {
			fmt.Fprintln(os.Stderr, "canary:", err)
			return exitError
		}
		for _, g := range sweep.Gaps() {
			rep.AddGap("artifact sweep: %s", g)
		}
	}

	for _, repo := range inv.Repos {
		if pr, err := ioc.Persistence(repo.Path, ioc.RepoTargets, attacks, ioc.Options{Window: window}); err == nil {
			sweep.Merge(pr)
		}
	}

	// $HOME is outside the tree the user asked about. Reading it is what finds
	// agent-hook persistence, but a run that goes there has to say so.
	if *homeOn {
		if home, err := os.UserHomeDir(); err == nil {
			hr, hErr := ioc.Persistence(home, ioc.HomeTargets, attacks, ioc.Options{Window: window})
			if hErr == nil {
				rep.AddGap("persistence: %d location(s) in $HOME were inspected — outside the scanned tree, disable with -home=false", hr.PersistenceChecked)
				for _, f := range hr.Findings {
					rep.HomeFindings = append(rep.HomeFindings, f.Describe(home))
				}
				sweep.PersistenceChecked += hr.PersistenceChecked
				sweep.PersistenceUntouched += hr.PersistenceUntouched
			}
		}
	} else {
		rep.AddGap("persistence targets in $HOME were NOT inspected (-home=false); agent hooks and shell profiles are where the 2026 attacks persisted")
	}
	if sweep.FilesScanned > 0 {
		rep.AddGap("artifact sweep walked %d file(s) and read %d; %d skipped as binary",
			sweep.FilesScanned, sweep.FilesRead, sweep.SkippedBinary)
	}
	if sweep.PersistenceChecked > 0 {
		rep.AddGap("persistence: %d known location(s) inspected, %d untouched since the window start",
			sweep.PersistenceChecked, sweep.PersistenceUntouched)
	}
	zizmorOK := true
	if v, zErr := zizmor.Available(context.Background()); zErr != nil {
		zizmorOK = false
		rep.AddGap("layer 3: zizmor is not installed, so workflow files were NOT audited " +
			"(brew install zizmor) — an unasked question, not a clean answer")
	} else {
		rep.AddGap("layer 3 ran %s: it answers whether a workflow COULD be abused, not whether it was", v)
	}
	var ciClient *ci.Client
	if *ciOn {
		ciClient, err = ci.New("")
		if err != nil {
			fmt.Fprintln(os.Stderr, "canary:", err)
			return exitError
		}
	} else {
		rep.AddGap("layer 4 was not run (-ci): CI activity inside the window was NOT checked, " +
			"and a laptop can be clean while a runner installed the same tree")
	}
	rep.AddGap("OSV.dev was not queried; only local attack files and corpus were matched")

	// The inventory is what makes testing a newly published attack cheap: the
	// tree changes slowly, the attack list changes daily.
	invPath := ""
	if dataErr == nil {
		invPath = inventory.Path(dataDir, inv.Root)
	}
	builder := inventory.NewBuilder(inv.Root)
	matcher := deps.NewMatcher(attacks, c)
	owners := ownerMap{inv: inv}
	owners.build(sweep.Findings)

	// Per-repo work runs concurrently: lockfile extraction and zizmor are the
	// CPU- and process-bound halves a sequential loop left on the table. Order
	// is preserved by writing each verdict to its slot, never by append; the
	// shared report gaps are safe because AddGap locks, and the builder and
	// self-validation counter sit behind scanMu.
	rc := &repoScan{
		matcher: matcher, owners: owners, sweep: sweep, window: window,
		zizmorOK: zizmorOK, ciClient: ciClient, rep: rep, builder: builder,
	}
	repoVerdicts := make([]verdict.Repo, len(inv.Repos))
	scanWorkers := runtime.NumCPU()
	if scanWorkers > 8 {
		scanWorkers = 8
	}
	if scanWorkers < 1 {
		scanWorkers = 1
	}
	sema := make(chan struct{}, scanWorkers)
	var wg sync.WaitGroup

	for i, repo := range inv.Repos {
		wg.Add(1)
		sema <- struct{}{}
		go func(i int, repo discover.Repo) {
			defer wg.Done()
			defer func() { <-sema }()
			repoVerdicts[i] = rc.verdictFor(repo)
		}(i, repo)
	}
	wg.Wait()
	rep.Repos = append(rep.Repos, repoVerdicts...)

	if loose := looseEntry(owners, sweep, matcher, &rc.familySeen, rep); loose != nil {
		rep.Repos = append(rep.Repos, *loose)
	}

	if rc.familySeen == 0 {
		rep.AddGap("self-validation found NO package from any loaded attack family anywhere in the tree, " +
			"at any version — the extractor was never observed matching, so a clean result here is unproven")
	}

	if !*noSave && invPath != "" {
		if err := inventory.Save(invPath, builder.Inventory()); err != nil {
			rep.AddGap("the resolved inventory could not be saved: %v — the next run re-reads the tree", err)
		} else {
			rep.AddGap("resolved inventory saved to %s (%d unique package versions); "+
				"`-reuse` matches a new attack against it without re-reading the tree",
				invPath, len(builder.Inventory().Packages))
		}
	}

	out, err := rep.Render(*format)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}
	os.Stdout.Write(out)

	if rep.Findings() {
		return exitFindings
	}
	return exitClean
}

// earliestWindow is the start of the widest window across loaded attacks. A
// file modified after the earliest one is inside SOME window, and narrowing it
// per attack would need a sweep per attack over the same tree.
func earliestWindow(attacks []attack.Attack) time.Time {
	var out time.Time
	for _, a := range attacks {
		if out.IsZero() || a.Started.Before(out) {
			out = a.Started
		}
	}
	return out
}

func artifactCount(attacks []attack.Attack) int {
	n := 0
	for _, a := range attacks {
		n += len(a.Artifacts)
	}
	return n
}

func mustAbs(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

func describeFinding(f deps.Finding) string {
	var via []string
	via = append(via, f.Attacks...)
	via = append(via, f.Sources...)
	return fmt.Sprintf("%s via %s", f.String(), strings.Join(via, ", "))
}
