package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dPeluChe/canary/internal/attack"
	"github.com/dPeluChe/canary/internal/corpus"
	"github.com/dPeluChe/canary/internal/deps"
	"github.com/dPeluChe/canary/internal/discover"
	"github.com/dPeluChe/canary/internal/ioc"
	"github.com/dPeluChe/canary/internal/verdict"
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
	sweepOn := fs.Bool("sweep", true, "layer 2 artifact sweep; walks node_modules, so it costs minutes on a large tree")
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}
	wd, _ := os.Getwd()

	inv, err := discover.Walk(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}

	rep := &verdict.Report{Root: inv.Root}

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
		if loaded, err := corpus.LoadDataDog(corpusPath); err == nil {
			c = loaded
			rep.Attacks = append(rep.Attacks, loaded.Sources()...)
		} else if *corpusDir != "" {
			fmt.Fprintln(os.Stderr, "canary:", err)
			return exitError
		} else {
			rep.AddGap("no corpus dataset loaded (%s) — cumulative sources not consulted", corpusPath)
		}
	}

	// Layer 2 runs once over the whole tree rather than per repo: it opts back
	// into node_modules, and walking that twice for nested repos would double
	// the most expensive part of a scan.
	sweep := &ioc.Result{}
	switch {
	case !*sweepOn:
		rep.AddGap("layer 2 artifact sweep was disabled with -sweep=false; the tree was NOT searched for artifacts")
	case artifactCount(attacks) == 0:
		rep.AddGap("no attack file carries filesystem artifacts, so the tree was not searched for any")
	default:
		sweep, err = ioc.Sweep(inv.Root, attacks, ioc.Options{Window: earliestWindow(attacks)})
		if err != nil {
			fmt.Fprintln(os.Stderr, "canary:", err)
			return exitError
		}
		for _, g := range sweep.Gaps() {
			rep.AddGap("artifact sweep: %s", g)
		}
	}

	rep.AddGap("persistence targets (Claude Code hooks, VS Code tasks.json, shell profiles, git hooks) are not checked yet")
	rep.AddGap("layer 3 (workflow static analysis, delegated to zizmor) is not implemented")
	rep.AddGap("layer 4 (CI runs inside the attack window) is not implemented")
	rep.AddGap("OSV.dev was not queried; only local attack files and corpus were matched")

	familySeen := 0
	for _, repo := range inv.Repos {
		v := verdict.Repo{Name: repo.Name, Slug: repo.Slug}
		v.Artifacts = artifactsUnder(sweep, repo.Path)

		var all []deps.Resolved
		checked, skipped := 0, 0
		for _, lf := range repo.Lockfiles {
			if !deps.Supported(lf.Kind) {
				skipped++
				rep.AddGap("lockfile kind %q has no extractor yet — those files were not read", lf.Kind)
				continue
			}
			res, err := deps.Extract(lf)
			if err != nil {
				skipped++
				rep.AddGap("%s could not be read: %v", lf.Rel, err)
				continue
			}
			all = append(all, res...)
			checked++
		}

		if checked == 0 && len(v.Artifacts) == 0 {
			v.Status = verdict.Skipped
			switch {
			case len(repo.Lockfiles) == 0:
				v.Reason = "no lockfiles"
			default:
				v.Reason = fmt.Sprintf("%d lockfile(s), none readable by this build", skipped)
			}
			rep.Repos = append(rep.Repos, v)
			continue
		}

		for _, f := range deps.Match(all, attacks, c) {
			v.MaliciousDeps = append(v.MaliciousDeps, describeFinding(f))
		}

		// Self-validation: can the extractor see these families AT ALL? A
		// negative from an extractor never observed matching anything is
		// worthless — this is the manual step from JOURNAL/2608.md.
		visible := deps.MatchIgnoringVersions(all, attacks, c)
		familySeen += len(visible)

		if len(v.MaliciousDeps) > 0 || len(v.Artifacts) > 0 {
			v.Status = verdict.Confirmed
			v.Reason = fmt.Sprintf("%d package(s) resolved from %d lockfile(s)", len(all), checked)
		} else {
			v.Status = verdict.Clean
			v.Reason = fmt.Sprintf("%d packages from %d lockfile(s), no known-malicious version", len(all), checked)
			if len(visible) > 0 {
				v.Reason += fmt.Sprintf("; %d package(s) of an affected family present at safe versions", len(visible))
			}
		}
		rep.Repos = append(rep.Repos, v)
	}

	if familySeen == 0 {
		rep.AddGap("self-validation found NO package from any loaded attack family anywhere in the tree, " +
			"at any version — the extractor was never observed matching, so a clean result here is unproven")
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

// artifactsUnder attributes sweep findings to the repo that contains them.
// Findings outside every repo are still in the sweep result; they surface in
// the run summary rather than being dropped.
func artifactsUnder(sweep *ioc.Result, repoPath string) []string {
	var out []string
	prefix := repoPath + string(os.PathSeparator)
	for _, f := range sweep.Findings {
		if !strings.HasPrefix(f.Path, prefix) {
			continue
		}
		rel, err := filepath.Rel(repoPath, f.Path)
		if err != nil {
			rel = f.Path
		}
		when := "mtime outside the window"
		if f.InWindow {
			when = "MODIFIED INSIDE THE WINDOW"
		}
		line := ""
		if f.Line > 0 {
			line = fmt.Sprintf(":%d", f.Line)
		}
		out = append(out, fmt.Sprintf("%s%s — %s %q via %s, %s", rel, line, f.Kind, f.Artifact, f.Attack, when))
	}
	return out
}

func describeFinding(f deps.Finding) string {
	var via []string
	via = append(via, f.Attacks...)
	via = append(via, f.Sources...)
	return fmt.Sprintf("%s via %s", f.String(), strings.Join(via, ", "))
}
