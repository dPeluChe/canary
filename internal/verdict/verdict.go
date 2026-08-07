// Package verdict merges the layers into one answer per repository and renders it.
//
// The output contract, learned from running this investigation by hand:
//
//   - CONFIRMED and SUSPECTED are separate sections, never interleaved.
//   - A clean result is one line. A long report that concludes "nothing
//     happened" is worse than a short one that says so directly.
//   - Every negative states what was checked, so absence of evidence is
//     distinguishable from absence of checking.
//   - Coverage gaps are printed, not silently dropped. A truncated scan that
//     reads as complete is the worst possible output.
package verdict

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Status is the per-repo conclusion.
type Status int

const (
	Clean     Status = iota // checked, nothing found
	Suspected               // something to verify by hand
	Confirmed               // malicious version or artifact present
	Skipped                 // not checked; Reason says why
)

func (s Status) String() string {
	switch s {
	case Clean:
		return "CLEAN"
	case Suspected:
		return "SUSPECTED"
	case Confirmed:
		return "CONFIRMED"
	default:
		return "SKIPPED"
	}
}

// MarshalJSON renders the status as its name. A bare integer in a report is a
// number nobody can read without the source.
func (s Status) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// Repo is the verdict for one repository.
type Repo struct {
	Name          string   `json:"name"`
	Slug          string   `json:"slug,omitempty"`
	Status        Status   `json:"status"`
	Reason        string   `json:"reason"`
	MaliciousDeps []string `json:"maliciousDeps,omitempty"` // ecosystem/name@version
	Artifacts     []string `json:"artifacts,omitempty"`
	CIInWindow    int      `json:"ciInWindow,omitempty"`
	SecretsAtRisk int      `json:"secretsAtRisk,omitempty"`
}

// Report is a whole run.
type Report struct {
	Root    string   `json:"root"`
	Attacks []string `json:"attacks"`
	Repos   []Repo   `json:"repos"`

	// HomeFindings sit outside every repository — persistence in $HOME belongs
	// to the machine, not to a project, and attributing it to one would be
	// wrong in both directions.
	HomeFindings []string `json:"homeFindings,omitempty"`

	Gaps []string `json:"gaps"` // what this run could NOT establish
}

// Findings reports whether anything was found, which drives the exit code.
//
// HomeFindings count. They are stored apart from Repos because persistence in
// $HOME belongs to the machine rather than a project, and leaving them out of
// this check made the exit code disagree with the printed report: a C2 domain
// in ~/.zshrc printed under DEVELOPER MACHINE while the process exited 0.
func (r *Report) Findings() bool {
	if len(r.HomeFindings) > 0 {
		return true
	}
	for _, repo := range r.Repos {
		if repo.Status == Confirmed || repo.Status == Suspected {
			return true
		}
	}
	return false
}

// AddGap records something this run could not establish. Duplicates are
// dropped so a per-repo gap does not print once per repo.
func (r *Report) AddGap(format string, args ...any) {
	g := fmt.Sprintf(format, args...)
	for _, existing := range r.Gaps {
		if existing == g {
			return
		}
	}
	r.Gaps = append(r.Gaps, g)
}

// Render writes the report in format: "text", "json" or "sarif".
func (r *Report) Render(format string) ([]byte, error) {
	switch format {
	case "text", "":
		return []byte(r.text()), nil
	case "json":
		return json.MarshalIndent(r, "", "  ")
	case "sarif":
		return nil, fmt.Errorf("verdict: sarif is not implemented yet — use text or json")
	default:
		return nil, fmt.Errorf("verdict: unknown format %q (want text, json or sarif)", format)
	}
}

func (r *Report) text() string {
	var b strings.Builder

	byStatus := map[Status][]Repo{}
	for _, repo := range r.Repos {
		byStatus[repo.Status] = append(byStatus[repo.Status], repo)
	}

	// CONFIRMED and SUSPECTED never interleave, and severity comes first.
	for _, s := range []Status{Confirmed, Suspected} {
		repos := byStatus[s]
		if len(repos) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s — %d repo(s)\n\n", s, len(repos))
		for _, repo := range repos {
			fmt.Fprintf(&b, "  %s\n", repo.Name)
			if repo.Slug != "" {
				fmt.Fprintf(&b, "    %s\n", repo.Slug)
			}
			for _, d := range repo.MaliciousDeps {
				fmt.Fprintf(&b, "    %s\n", d)
			}
			for _, a := range repo.Artifacts {
				fmt.Fprintf(&b, "    %s\n", a)
			}
			if repo.Reason != "" {
				fmt.Fprintf(&b, "    %s\n", repo.Reason)
			}
			b.WriteString("\n")
		}
	}

	// A clean result is one line per repo, and it says what was checked.
	if n := len(byStatus[Clean]); n > 0 {
		fmt.Fprintf(&b, "CLEAN — %d repo(s)\n", n)
		for _, repo := range byStatus[Clean] {
			fmt.Fprintf(&b, "  %-40s %s\n", repo.Name, repo.Reason)
		}
		b.WriteString("\n")
	}

	// Skipped is a first-class status: a repo nobody checked is not a clean one.
	if n := len(byStatus[Skipped]); n > 0 {
		fmt.Fprintf(&b, "SKIPPED — %d repo(s) NOT checked\n", n)
		for _, repo := range byStatus[Skipped] {
			fmt.Fprintf(&b, "  %-40s %s\n", repo.Name, repo.Reason)
		}
		b.WriteString("\n")
	}

	if len(r.HomeFindings) > 0 {
		fmt.Fprintf(&b, "DEVELOPER MACHINE — %d persistence location(s) outside any repo\n", len(r.HomeFindings))
		for _, f := range r.HomeFindings {
			fmt.Fprintf(&b, "  %s\n", f)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "%d repo(s) under %s, matched against %d attack source(s): %s\n",
		len(r.Repos), r.Root, len(r.Attacks), strings.Join(r.Attacks, ", "))

	// Mandatory. Silent truncation that reads as complete coverage is the worst
	// possible output, so gaps print even when everything looks clean.
	if len(r.Gaps) > 0 {
		b.WriteString("\nNOT ESTABLISHED BY THIS RUN\n")
		gaps := append([]string(nil), r.Gaps...)
		sort.Strings(gaps)
		for _, g := range gaps {
			fmt.Fprintf(&b, "  - %s\n", g)
		}
		b.WriteString("\nAbsence from the lists above is absence from those lists, not evidence of safety.\n")
	}

	return b.String()
}
