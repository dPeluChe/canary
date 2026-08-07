// Package zizmor delegates layer 3 — static analysis of GitHub Actions
// workflow files — to the zizmor binary.
//
// LAYER 3 of 4, and the only layer canary does not implement. zizmor has 23
// audits across 10 weakness classes and is actively maintained; competing with
// it would be wasted effort and would age badly. See
// docs/RESEARCH/TOOLING_LANDSCAPE.md.
//
// The important behaviour here is the absent case. zizmor missing does not
// mean the workflows are fine — it means nobody looked, and that has to reach
// the report as a gap. Layers 1, 2 and 4 answer "were you attacked"; this one
// answers "could you be", and silently dropping it would turn an unasked
// question into an implied clean answer.
package zizmor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrNotInstalled means the binary is not on PATH. Callers must record it as a
// coverage gap rather than treating the empty result as a pass.
var ErrNotInstalled = errors.New("zizmor: not installed (brew install zizmor)")

// Finding is one zizmor audit hit, reduced to what a canary report needs.
type Finding struct {
	Audit      string // zizmor's ident, e.g. "template-injection"
	Desc       string
	Severity   string // Informational | Low | Medium | High | Unknown
	Confidence string
	URL        string
	File       string
	Line       int // 1-indexed; zizmor reports 0-indexed rows
}

// report mirrors the fields canary reads from `zizmor --format json`, verified
// against zizmor 1.29.0. Unknown fields are ignored on purpose: the tool is
// maintained independently and adding keys must not break the delegation.
type report struct {
	Ident          string `json:"ident"`
	Desc           string `json:"desc"`
	URL            string `json:"url"`
	Determinations struct {
		Severity   string `json:"severity"`
		Confidence string `json:"confidence"`
	} `json:"determinations"`
	Locations []struct {
		Symbolic struct {
			Key struct {
				Local struct {
					Path string `json:"verbatim_path"`
				} `json:"Local"`
			} `json:"key"`
		} `json:"symbolic"`
		Concrete struct {
			Location struct {
				StartPoint struct {
					Row int `json:"row"`
				} `json:"start_point"`
			} `json:"location"`
		} `json:"concrete"`
	} `json:"locations"`
}

// Available reports the zizmor version on PATH, or ErrNotInstalled.
func Available(ctx context.Context) (string, error) {
	path, err := exec.LookPath("zizmor")
	if err != nil {
		return "", ErrNotInstalled
	}
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("zizmor: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Run audits the workflows under repoPath.
//
// zizmor exits non-zero when it finds something — 14 in 1.29.0 — so exit status
// alone cannot distinguish findings from failure. Parsing stdout is the only
// reliable signal, and a failure to parse is an error rather than an empty
// result, because an empty result reads as clean.
func Run(ctx context.Context, repoPath string) ([]Finding, error) {
	bin, err := exec.LookPath("zizmor")
	if err != nil {
		return nil, ErrNotInstalled
	}
	wf := filepath.Join(repoPath, ".github", "workflows")
	if fi, statErr := os.Stat(wf); statErr != nil || !fi.IsDir() {
		return nil, nil // no workflows is a real answer, not a gap
	}

	cmd := exec.CommandContext(ctx, bin, "--format", "json", "--no-progress", wf)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	raw := strings.TrimSpace(stdout.String())
	if raw == "" {
		if runErr != nil {
			return nil, fmt.Errorf("zizmor: %w: %s", runErr, firstLine(stderr.String()))
		}
		return nil, nil
	}

	var reports []report
	if err := json.Unmarshal([]byte(raw), &reports); err != nil {
		return nil, fmt.Errorf("zizmor: could not parse output: %w", err)
	}

	var out []Finding
	for _, r := range reports {
		f := Finding{
			Audit: r.Ident, Desc: r.Desc, URL: r.URL,
			Severity: r.Determinations.Severity, Confidence: r.Determinations.Confidence,
		}
		if len(r.Locations) > 0 {
			l := r.Locations[0]
			f.File = l.Symbolic.Key.Local.Path
			if rel, relErr := filepath.Rel(repoPath, f.File); relErr == nil {
				f.File = rel
			}
			f.Line = l.Concrete.Location.StartPoint.Row + 1 // zizmor rows are 0-indexed
		}
		out = append(out, f)
	}
	return out, nil
}

// Describe renders a finding for a canary report, severity first so the worst
// reads first — the ordering the output contract asks for.
func (f Finding) Describe() string {
	where := f.File
	if f.Line > 0 {
		where = fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	return fmt.Sprintf("%s %s — %s (%s confidence) %s",
		strings.ToUpper(f.Severity), where, f.Desc, strings.ToLower(f.Confidence), f.URL)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
