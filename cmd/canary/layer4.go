package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dPeluChe/canary/internal/ci"
	"github.com/dPeluChe/canary/internal/verdict"
)

// checkCI folds layer 4 into a repo verdict.
//
// The rule this enforces is the reason the layer exists: a run inside the
// window is NOT a finding on its own, and neither are secrets. Only all three
// together — a run that installed dependencies, secrets reachable from it, and
// a malicious version actually resolved — justify naming a credential. Runs
// alone produce alarm without information.
// ciReason explains why CI activity inside the window was not escalated.
//
// Material() can be false for two reachable reasons — no malicious version
// resolved, or nothing reachable to steal — and they are opposite findings. A
// single message covering both told a human "no malicious version resolved"
// about a repo that had one, which is the report lying about what was checked.
func ciReason(installs int, maliciousResolved bool) string {
	if !maliciousResolved {
		return fmt.Sprintf("; %d CI run(s) installed dependencies in the window, but no malicious version resolved", installs)
	}
	return fmt.Sprintf("; %d CI run(s) installed dependencies in the window WITH a malicious version resolved, but no reachable secrets were found", installs)
}

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
	if exp.SecretsTruncated {
		rep.AddGap("layer 4 hit the secret page ceiling for %s; secrets beyond the first %d were NOT listed", slug, 50*100)
	}
	if exp.RunsTruncated {
		rep.AddGap("layer 4 hit the page ceiling for %s; runs beyond the first %d were NOT examined", slug, 50*100)
	}
	if len(installs) == 0 {
		return
	}

	if !exp.Material(maliciousResolved) {
		// Recorded, deliberately not escalated. This is the documented negative
		// the original investigation produced, and it is the common case — but
		// it has to say WHICH negative, see ciReason.
		v.Reason += ciReason(len(installs), maliciousResolved)
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
