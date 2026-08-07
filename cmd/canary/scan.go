package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dPeluChe/canary/internal/attack"
	"github.com/dPeluChe/canary/internal/ci"
	"github.com/dPeluChe/canary/internal/corpus"
	"github.com/dPeluChe/canary/internal/deps"
	"github.com/dPeluChe/canary/internal/discover"
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

	window := earliestWindow(attacks)
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

		// Layer 1 having nothing to read does NOT end the repo: layers 3 and 4
		// still apply, and a repo with no lockfiles can still ship a
		// dangerous workflow. Skipping here was silently dropping them.
		depsSkipped := checked == 0
		if depsSkipped {
			switch {
			case len(repo.Lockfiles) == 0:
				v.Reason = "no lockfiles"
			default:
				v.Reason = fmt.Sprintf("%d lockfile(s), none readable by this build", skipped)
			}
		}

		for _, f := range deps.Match(all, attacks, c) {
			v.MaliciousDeps = append(v.MaliciousDeps, describeFinding(f))
		}

		// Self-validation: can the extractor see these families AT ALL? A
		// negative from an extractor never observed matching anything is
		// worthless — this is the manual step from JOURNAL/2608.md.
		visible := deps.MatchIgnoringVersions(all, attacks, c)
		familySeen += len(visible)

		switch {
		case depsSkipped:
			v.Status = verdict.Skipped
		case len(v.MaliciousDeps) > 0 || hasIndicator(sweep, repo.Path):
			v.Status = verdict.Confirmed
			v.Reason = fmt.Sprintf("%d package(s) resolved from %d lockfile(s)", len(all), checked)
		case len(v.Artifacts) > 0:
			// Persistence with no known indicator: a location moved inside the
			// window. Real enough to name, not enough to call confirmed.
			v.Status = verdict.Suspected
			v.Reason = fmt.Sprintf("%d package(s) resolved from %d lockfile(s); no malicious version, but a persistence location moved inside the window", len(all), checked)
		default:
			v.Status = verdict.Clean
			v.Reason = fmt.Sprintf("%d packages from %d lockfile(s), no known-malicious version", len(all), checked)
			if len(visible) > 0 {
				v.Reason += fmt.Sprintf("; %d package(s) of an affected family present at safe versions", len(visible))
			}
		}
		if zizmorOK {
			// zizmor answers "could this workflow be abused", not "were you
			// attacked". That is Suspected at most: it never escalates a repo
			// the forensic layers found clean.
			if hits, zErr := zizmor.Run(context.Background(), repo.Path); zErr != nil {
				rep.AddGap("layer 3 could not audit %s: %v", repo.Name, zErr)
			} else if len(hits) > 0 {
				for _, h := range hits {
					v.Artifacts = append(v.Artifacts, "workflow: "+h.Describe())
				}
				if v.Status == verdict.Clean || v.Status == verdict.Skipped {
					v.Status = verdict.Suspected
					v.Reason = fmt.Sprintf("%s; %d workflow weakness(es) reported by zizmor", v.Reason, len(hits))
				}
			}
		}

		if ciClient != nil && repo.Slug != "" {
			checkCI(ciClient, rep, &v, repo.Slug, window, len(v.MaliciousDeps) > 0)
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
		out = append(out, f.Describe(repoPath))
	}
	return out
}

// hasIndicator reports whether any finding under repoPath carries a known
// indicator, as opposed to only having moved inside the window. That is the
// line between confirmed and suspected: a hook edited last week is ordinary,
// a hook containing the C2 domain is not.
func hasIndicator(sweep *ioc.Result, repoPath string) bool {
	prefix := repoPath + string(os.PathSeparator)
	for _, f := range sweep.Findings {
		if f.Artifact != "" && strings.HasPrefix(f.Path, prefix) {
			return true
		}
	}
	return false
}

// checkCI folds layer 4 into a repo verdict.
//
// The rule this enforces is the reason the layer exists: a run inside the
// window is NOT a finding on its own, and neither are secrets. Only all three
// together — a run that installed dependencies, secrets reachable from it, and
// a malicious version actually resolved — justify naming a credential. Runs
// alone produce alarm without information.
func checkCI(c *ci.Client, rep *verdict.Report, v *verdict.Repo, slug string, window time.Time, maliciousResolved bool) {
	exp, err := c.Query(context.Background(), slug, window, time.Time{})
	if err != nil {
		if errors.Is(err, ci.ErrRateLimited) {
			rep.AddGap("layer 4 hit the GitHub rate limit; some repos were NOT checked for CI activity")
		} else {
			rep.AddGap("layer 4 could not query %s: %v", slug, err)
		}
		return
	}
	if err := c.MarkInstalls(context.Background(), slug, exp); err != nil {
		rep.AddGap("layer 4 could not read workflow definitions for %s: %v", slug, err)
	}

	installs := exp.InstallRuns()
	v.CIInWindow = len(installs)
	v.SecretsAtRisk = len(exp.SecretNames)
	if exp.SecretsUnknown {
		rep.AddGap("layer 4 could not list secrets for %s; exposure there is unknown, not absent", slug)
	}
	if len(installs) == 0 {
		return
	}

	if !exp.Material(maliciousResolved) {
		// Recorded, deliberately not escalated. This is the documented negative
		// the original investigation produced, and it is the common case.
		v.Reason += fmt.Sprintf("; %d CI run(s) installed dependencies in the window, but no malicious version resolved", len(installs))
		return
	}

	v.Status = verdict.Confirmed
	names := exp.SecretNames
	if exp.OrgSecrets {
		names = append(names, "(org-level secrets injectable)")
	}
	if exp.SecretsUnknown {
		names = append(names, "(secret list unavailable — exposure unknown)")
	}
	v.Artifacts = append(v.Artifacts, fmt.Sprintf(
		"CI: %d run(s) installed dependencies inside the window (%s) with a malicious version resolved; reachable secrets: %s",
		len(installs), installs[0].InstallCmd, strings.Join(names, ", ")))
}

func describeFinding(f deps.Finding) string {
	var via []string
	via = append(via, f.Attacks...)
	via = append(via, f.Sources...)
	return fmt.Sprintf("%s via %s", f.String(), strings.Join(via, ", "))
}
