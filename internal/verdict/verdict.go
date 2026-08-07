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
//
// STATUS: not implemented.
package verdict

// Status is the per-repo conclusion.
type Status int

const (
	Clean     Status = iota // checked, nothing found
	Suspected               // something to verify by hand
	Confirmed               // malicious version or artifact present
	Skipped                 // not checked; Reason says why
)

// Repo is the verdict for one repository.
type Repo struct {
	Name          string
	Slug          string
	Status        Status
	Reason        string
	MaliciousDeps []string // ecosystem/name@version
	Artifacts     []string
	CIInWindow    int
	SecretsAtRisk int
}

// Report is a whole run.
type Report struct {
	Root    string
	Attacks []string
	Repos   []Repo
	Gaps    []string // what this run could NOT establish
}

// Render writes the report in format: "text", "json" or "sarif".
func (r *Report) Render(format string) ([]byte, error) {
	panic("not implemented")
}
