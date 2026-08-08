package main

import (
	"fmt"
	"os"

	"github.com/dPeluChe/canary/internal/attack"
	"github.com/dPeluChe/canary/internal/corpus"
	"github.com/dPeluChe/canary/internal/deps"
	"github.com/dPeluChe/canary/internal/inventory"
	"github.com/dPeluChe/canary/internal/verdict"
)

// scanFromInventory matches loaded attacks against a previously resolved set,
// reading nothing but the inventory and the attack files.
//
// It is layer 1 only, and says so: the tree was not re-read, so anything
// installed since the inventory was built is invisible, and layers 2 to 4 did
// not run at all. A fast answer that implied a full sweep would be the worst
// kind of speedup.
func scanFromInventory(invPath, attackDir, corpusDir, format string, verbose bool) int {
	stored, err := inventory.Load(invPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		fmt.Fprintln(os.Stderr, "        run a full scan once to build it")
		return exitError
	}

	wd, _ := os.Getwd()
	dir, source, err := attack.ResolveDir(attackDir, wd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}
	attacks, err := attack.Load(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "canary: %s (%s)\n", dir, source)
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}

	var c *corpus.Corpus
	if p, _, cErr := corpus.ResolveDir(corpusDir, wd); cErr == nil {
		if loaded, lErr := corpus.Load(p); lErr == nil {
			c = loaded
		}
	}

	rep := &verdict.Report{Root: stored.Root, Verbose: verbose}
	for _, a := range attacks {
		rep.Attacks = append(rep.Attacks, a.ID)
	}
	days := int(stored.Age().Hours() / 24)
	rep.AddGap("matched a stored inventory built %s (%d day(s) ago): the tree was NOT re-read, "+
		"so anything installed since is invisible", stored.Created.UTC().Format("2006-01-02"), days)
	rep.AddGap("layers 2, 3 and 4 did NOT run: -reuse answers only whether a new attack touches the " +
		"already-resolved package set")
	if days > 7 {
		rep.AddGap("the inventory is %d days old — a tree that resolved clean then is not clean now; "+
			"re-run a full scan", days)
	}

	familySeen := 0
	for _, r := range stored.Repos {
		v := verdict.Repo{Name: r.Name, Slug: r.Slug}
		all := stored.Resolved(r)
		for _, f := range deps.Match(all, attacks, c) {
			v.MaliciousDeps = append(v.MaliciousDeps, describeFinding(f))
		}
		familySeen += len(deps.MatchIgnoringVersions(all, attacks, c))

		if len(v.MaliciousDeps) > 0 {
			v.Status = verdict.Confirmed
			v.Reason = fmt.Sprintf("%d package(s) from the stored inventory", len(all))
		} else {
			v.Status = verdict.Clean
			v.Reason = fmt.Sprintf("%d package(s) from the stored inventory, no known-malicious version", len(all))
		}
		rep.Repos = append(rep.Repos, v)
	}
	if familySeen == 0 {
		rep.AddGap("self-validation found NO package from any loaded attack family in the inventory, " +
			"at any version — the negative is unproven")
	}

	out, err := rep.Render(format)
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
