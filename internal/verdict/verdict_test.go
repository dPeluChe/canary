package verdict

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The exit code is the contract CI and cron branch on, so it must agree with
// the printed report. A C2 domain in ~/.zshrc printed under DEVELOPER MACHINE
// while the process exited 0 was the exact disagreement this pins.
func TestFindingsCountsHomeFindings(t *testing.T) {
	r := &Report{
		Repos:        []Repo{{Name: "a", Status: Clean}},
		HomeFindings: []string{`~/.zshrc:1 — domain "npm-cache.com" MODIFIED INSIDE THE WINDOW`},
	}
	if !r.Findings() {
		t.Fatal("an indicator in $HOME must drive a non-zero exit")
	}
}

func TestFindingsPerStatus(t *testing.T) {
	cases := []struct {
		status Status
		want   bool
	}{
		{Confirmed, true},
		{Suspected, true},
		{Clean, false},
		{Skipped, false}, // not checked is not a finding, and not clean either
	}
	for _, tc := range cases {
		r := &Report{Repos: []Repo{{Name: "a", Status: tc.status}}}
		if got := r.Findings(); got != tc.want {
			t.Errorf("%s: Findings = %v, want %v", tc.status, got, tc.want)
		}
	}
	if (&Report{}).Findings() {
		t.Error("an empty report has no findings")
	}
}

// The output contract: CONFIRMED and SUSPECTED never interleave, severity
// first, a clean result is one line per repo, and Skipped is its own section
// rather than folded into clean.
func TestTextHonoursTheOutputContract(t *testing.T) {
	r := &Report{
		Root:    "/tree",
		Attacks: []string{"keyv-2026-08"},
		Repos: []Repo{
			{Name: "cleanrepo", Status: Clean, Reason: "500 packages, no known-malicious version"},
			{Name: "suspect", Status: Suspected, Reason: "a hook moved"},
			{Name: "hit", Status: Confirmed, MaliciousDeps: []string{"npm/keyv@6.0.0"}},
			{Name: "unchecked", Status: Skipped, Reason: "no lockfiles"},
		},
	}
	out := string(mustRender(t, r, "text"))

	iConf := strings.Index(out, "CONFIRMED")
	iSusp := strings.Index(out, "SUSPECTED")
	iClean := strings.Index(out, "CLEAN")
	iSkip := strings.Index(out, "SKIPPED")
	if iConf < 0 || iSusp < 0 || iClean < 0 || iSkip < 0 {
		t.Fatalf("every section must appear:\n%s", out)
	}
	if !(iConf < iSusp && iSusp < iClean && iClean < iSkip) {
		t.Errorf("sections out of order (confirmed, suspected, clean, skipped):\n%s", out)
	}

	// A clean result is one line. A long report concluding "nothing happened"
	// is worse than a short one saying so.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "cleanrepo") && !strings.Contains(line, "no known-malicious") {
			t.Errorf("a clean repo must state what was checked on its one line: %q", line)
		}
	}
}

// Gaps are mandatory output. Silent truncation that reads as complete coverage
// is the worst possible result.
func TestTextAlwaysPrintsGaps(t *testing.T) {
	r := &Report{Root: "/tree", Repos: []Repo{{Name: "a", Status: Clean}}}
	r.AddGap("layer 2 was not run")

	out := string(mustRender(t, r, "text"))
	if !strings.Contains(out, "NOT ESTABLISHED BY THIS RUN") || !strings.Contains(out, "layer 2 was not run") {
		t.Fatalf("gaps must print even on a clean run:\n%s", out)
	}
	if !strings.Contains(out, "not evidence of safety") {
		t.Error("the report must not let absence read as safety")
	}
}

func TestAddGapDedupes(t *testing.T) {
	r := &Report{}
	r.AddGap("lockfile kind %q has no extractor", "Cargo.lock")
	r.AddGap("lockfile kind %q has no extractor", "Cargo.lock")
	r.AddGap("lockfile kind %q has no extractor", "Gemfile.lock")
	if len(r.Gaps) != 2 {
		t.Fatalf("a per-repo gap must not print once per repo, got %v", r.Gaps)
	}
}

// A bare integer status in a machine-readable report is unreadable without the
// source, and downstream tooling would key on it.
func TestStatusMarshalsAsItsName(t *testing.T) {
	b := mustRender(t, &Report{Repos: []Repo{{Name: "a", Status: Confirmed}}}, "json")
	var back struct {
		Repos []struct {
			Status string `json:"status"`
		} `json:"repos"`
	}
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Repos[0].Status != "CONFIRMED" {
		t.Errorf("status: got %q", back.Repos[0].Status)
	}
}

// SARIF must error rather than emit nothing: silently producing an empty
// report is how a scan that never ran reads as a scan that found nothing.
func TestRenderRejectsUnimplementedAndUnknownFormats(t *testing.T) {
	r := &Report{}
	for _, f := range []string{"sarif", "yaml"} {
		if _, err := r.Render(f); err == nil {
			t.Errorf("format %q should error, not return empty output", f)
		}
	}
}

func mustRender(t *testing.T, r *Report, format string) []byte {
	t.Helper()
	b, err := r.Render(format)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A clean result is one line. At a handful of repos that means one each; at
// three hundred it means one total, because a wall of identical CLEAN rows
// buries the sections that need reading. The real run that motivated this
// printed 180 of them.
func TestTextCollapsesCleanAtScale(t *testing.T) {
	r := &Report{Root: "/tree"}
	for i := 0; i < 50; i++ {
		r.Repos = append(r.Repos, Repo{Name: fmt.Sprintf("repo%02d", i), Status: Clean, Reason: "no known-malicious version"})
	}

	out := string(mustRender(t, r, "text"))
	if strings.Contains(out, "repo00") {
		t.Errorf("50 clean repos should collapse to a count:\n%s", out)
	}
	if !strings.Contains(out, "CLEAN — 50 repo(s)") || !strings.Contains(out, "-v to list") {
		t.Errorf("the count and the way to expand it must both be there:\n%s", out)
	}

	r.Verbose = true
	if !strings.Contains(string(mustRender(t, r, "text")), "repo00") {
		t.Error("-v must restore the per-repo detail")
	}
}

// A report whose unordered half changes between identical runs reads as if
// something differed. The collapsed SKIPPED summary iterated a map, so the
// same scan printed its reasons in a different order every time.
func TestTextSkippedSummaryIsDeterministic(t *testing.T) {
	build := func() *Report {
		r := &Report{Root: "/tree"}
		for i := 0; i < 25; i++ {
			reason := "no lockfiles"
			if i%3 == 0 {
				reason = "1 lockfile(s), none readable by this build"
			}
			if i%5 == 0 {
				reason = "2 lockfile(s), none readable by this build"
			}
			r.Repos = append(r.Repos, Repo{Name: fmt.Sprintf("s%02d", i), Status: Skipped, Reason: reason})
		}
		return r
	}
	first := string(mustRender(t, build(), "text"))
	for i := 0; i < 10; i++ {
		if got := string(mustRender(t, build(), "text")); got != first {
			t.Fatalf("the same report must render identically every time:\n%s\n---\n%s", first, got)
		}
	}
}

// Skipped collapses too, but never loses the REASONS: what was not checked and
// why is the half of a report that is easiest to lose and worst to lose.
func TestTextKeepsSkipReasonsWhenCollapsing(t *testing.T) {
	r := &Report{Root: "/tree"}
	for i := 0; i < 22; i++ {
		reason := "no lockfiles"
		if i%2 == 0 {
			reason = "1 lockfile(s), none readable by this build"
		}
		r.Repos = append(r.Repos, Repo{Name: fmt.Sprintf("s%02d", i), Status: Skipped, Reason: reason})
	}

	out := string(mustRender(t, r, "text"))
	if strings.Contains(out, "s00") {
		t.Errorf("names collapse at scale:\n%s", out)
	}
	for _, reason := range []string{"no lockfiles", "none readable by this build"} {
		if !strings.Contains(out, reason) {
			t.Errorf("the reason %q must survive collapsing:\n%s", reason, out)
		}
	}
	if !strings.Contains(out, "SKIPPED — 22 repo(s) NOT checked") {
		t.Errorf("the count must stay explicit:\n%s", out)
	}
}

// Findings never collapse: the whole point is that they are read.
func TestTextNeverCollapsesFindings(t *testing.T) {
	r := &Report{Root: "/tree"}
	for i := 0; i < 40; i++ {
		r.Repos = append(r.Repos, Repo{
			Name: fmt.Sprintf("hit%02d", i), Status: Confirmed,
			MaliciousDeps: []string{"npm/keyv@6.0.0"},
		})
	}
	out := string(mustRender(t, r, "text"))
	for _, name := range []string{"hit00", "hit39"} {
		if !strings.Contains(out, name) {
			t.Errorf("every confirmed repo must be named, %s missing", name)
		}
	}
}
