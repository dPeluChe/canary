// Package ioc sweeps the filesystem for attack artifacts and for the
// persistence mechanisms modern supply-chain malware installs.
//
// LAYER 2 of 4. See docs/ARCHITECTURE/OVERVIEW.md.
//
// This layer is the reason canary exists. The 2026 npm attacks stopped at
// stealing credentials and started installing persistence in developer
// tooling — Claude Code hooks, VS Code tasks.json, shell profiles, git hooks.
// The surveyed scanners (osv-scanner, shai-hulud-detect, trivy, grype) do not
// look there. See docs/RESEARCH/TOOLING_LANDSCAPE.md.
//
// Unlike the deps layer, this one opts back INTO node_modules: installed code
// is exactly where a dropped payload lives. That makes the sweep expensive, so
// what it declines to read is counted and reported rather than dropped — a
// sweep that skipped half a tree and said nothing would be worse than no sweep.
package ioc

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dPeluChe/canary/internal/attack"
)

// Finding is one artifact match on disk, or one persistence location that
// carries an indicator or moved inside the window.
type Finding struct {
	Path     string
	Attack   string
	Artifact string
	Kind     string
	Line     int
	Excerpt  string
	ModTime  time.Time
	InWindow bool // modified at or after the attack window start

	// Set for persistence findings only.
	Persistent bool
	Target     string // the target pattern that matched
	Family     string // FamilyDeveloper or FamilyDeploy
	Note       string // why this location is worth inspecting
}

// Result is one sweep, including what it could not read. The skip counters are
// not diagnostics: they are the coverage gaps this run has to declare.
type Result struct {
	Findings []Finding

	FilesScanned      int
	FilesRead         int
	SkippedLarge      int // over MaxFileSize, contents never searched
	SkippedBinary     int // NUL byte near the start, not text
	SkippedUnreadable int // permissions, races, vanished files

	PersistenceChecked   int // known locations that exist and were inspected
	PersistenceUntouched int // inspected, old mtime, no indicator — a strong negative
}

// Merge folds another result into r, so a run can combine the artifact sweep
// with per-repo and home persistence checks.
//
// The same file can be reached by both — a service worker is walked by the
// sweep and inspected as a deploy target — so identical hits are merged rather
// than listed twice. The persistence copy wins: it carries the family and the
// note explaining why that location matters.
func (r *Result) Merge(other *Result) {
	if other == nil {
		return
	}
	seen := map[findingKey]int{}
	for i, f := range r.Findings {
		seen[keyOf(f)] = i
	}
	for _, f := range other.Findings {
		if at, dup := seen[keyOf(f)]; dup {
			if f.Persistent && !r.Findings[at].Persistent {
				r.Findings[at] = f
			}
			continue
		}
		seen[keyOf(f)] = len(r.Findings)
		r.Findings = append(r.Findings, f)
	}
	r.FilesScanned += other.FilesScanned
	r.FilesRead += other.FilesRead
	r.SkippedLarge += other.SkippedLarge
	r.SkippedBinary += other.SkippedBinary
	r.SkippedUnreadable += other.SkippedUnreadable
	r.PersistenceChecked += other.PersistenceChecked
	r.PersistenceUntouched += other.PersistenceUntouched
}

// Gaps renders the skip counters as sentences for verdict.Report.Gaps. It
// returns nothing when the sweep read everything it walked.
func (r *Result) Gaps() []string {
	var out []string
	if r.SkippedLarge > 0 {
		out = append(out, fmt.Sprintf("%d file(s) exceeded the size limit and their contents were NOT searched", r.SkippedLarge))
	}
	if r.SkippedUnreadable > 0 {
		out = append(out, fmt.Sprintf("%d path(s) could not be read and were NOT searched", r.SkippedUnreadable))
	}
	return out
}

// Options bounds the sweep. The defaults exist because this layer walks
// node_modules: without a ceiling, one vendored source map can cost more than
// the rest of a repository.
type Options struct {
	MaxFileSize int64     // skip content search above this; 0 uses the default
	Window      time.Time // attack window start, for the mtime half of the check
	Workers     int       // concurrent content readers; 0 uses NumCPU
}

const defaultMaxFileSize = 2 << 20 // 2 MiB

type ref struct {
	attackID string
	art      attack.Artifact
}

type findingKey struct {
	path, artifact string
	line           int
}

func keyOf(f Finding) findingKey {
	return findingKey{f.Path, f.Artifact, f.Line}
}

// Sweep walks root looking for the artifacts of the given attacks.
//
// Filename artifacts are matched on the path alone and cost nothing. Content
// artifacts (domain, ip, string, useragent) require reading the file, so a
// PathScope on them is not just about false positives — it is the difference
// between reading a handful of files and reading a tree.
func Sweep(root string, attacks []attack.Attack, opt Options) (*Result, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("ioc: %w", err)
	}
	if opt.MaxFileSize <= 0 {
		opt.MaxFileSize = defaultMaxFileSize
	}

	var byPath, byContent []ref
	for _, a := range attacks {
		for _, art := range a.Artifacts {
			r := ref{attackID: a.ID, art: art}
			if art.Kind == attack.KindFilename {
				byPath = append(byPath, r)
			} else {
				byContent = append(byContent, r)
			}
		}
	}
	if len(byPath) == 0 && len(byContent) == 0 {
		return &Result{}, nil
	}

	res := &Result{}
	var mu sync.Mutex

	// Both halves run concurrently: the walk (measured at 56k files/s
	// single-threaded, against trees of millions) and the content reads.
	workers := opt.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	type job struct {
		path       string
		mod        time.Time
		size       int64
		applicable []ref
	}
	jobs := make(chan job, workers*4)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if j.size > opt.MaxFileSize {
					mu.Lock()
					res.SkippedLarge++
					mu.Unlock()
					continue
				}
				data, readErr := os.ReadFile(j.path)
				if readErr != nil {
					mu.Lock()
					res.SkippedUnreadable++
					mu.Unlock()
					continue
				}
				if isBinary(data) {
					mu.Lock()
					res.SkippedBinary++
					mu.Unlock()
					continue
				}
				var found []Finding
				for _, r := range j.applicable {
					if line, excerpt, ok := findLine(data, r.art.Value); ok {
						found = append(found, Finding{
							Path: j.path, Attack: r.attackID, Artifact: r.art.Value,
							Kind: r.art.Kind, Line: line, Excerpt: excerpt,
							ModTime: j.mod, InWindow: inWindow(j.mod, opt.Window),
						})
					}
				}
				mu.Lock()
				res.FilesRead++
				res.Findings = append(res.Findings, found...)
				mu.Unlock()
			}
		}()
	}

	walkConcurrent(abs, workers, func(path string, d fs.DirEntry, err error) {
		if err != nil {
			mu.Lock()
			res.SkippedUnreadable++
			mu.Unlock()
			return // a forensic sweep does not abort on one permission error
		}

		rel, relErr := filepath.Rel(abs, path)
		if relErr != nil {
			rel = path
		}

		info, statErr := d.Info()
		var mod time.Time
		var size int64
		if statErr == nil {
			mod = info.ModTime()
			size = info.Size()
		}

		mu.Lock()
		res.FilesScanned++
		for _, r := range byPath {
			if d.Name() != r.art.Value || !matchScope(r.art.PathScope, rel) {
				continue
			}
			res.Findings = append(res.Findings, Finding{
				Path: path, Attack: r.attackID, Artifact: r.art.Value,
				Kind: r.art.Kind, ModTime: mod, InWindow: inWindow(mod, opt.Window),
			})
		}
		mu.Unlock()

		// Only queue a read if some content artifact could apply to this path.
		// A scoped content artifact therefore costs nothing outside its scope,
		// which is the difference between reading a few files and reading a tree.
		var applicable []ref
		for _, r := range byContent {
			if matchScope(r.art.PathScope, rel) {
				applicable = append(applicable, r)
			}
		}
		if len(applicable) > 0 {
			jobs <- job{path: path, mod: mod, size: size, applicable: applicable}
		}
	})

	close(jobs)
	wg.Wait()

	return res, nil
}

// inWindow reports whether a file was modified at or after the window start.
// A zero window means no window was given, so nothing can be placed inside it —
// reporting everything as in-window would be the alarming answer, not the
// correct one.
func inWindow(mod, start time.Time) bool {
	if start.IsZero() || mod.IsZero() {
		return false
	}
	return !mod.Before(start)
}

// isBinary uses the same heuristic as git: a NUL byte near the start means the
// file is not text, and searching it for a domain name is wasted work.
func isBinary(data []byte) bool {
	if len(data) > 8000 {
		data = data[:8000]
	}
	return bytes.IndexByte(data, 0) >= 0
}

// findLine returns the 1-indexed line carrying value, with a trimmed excerpt.
// Reporting the line and its text is what lets a human confirm a hit without
// canary having to decide whether the surrounding code is malicious.
func findLine(data []byte, value string) (int, string, bool) {
	idx := bytes.Index(data, []byte(value))
	if idx < 0 {
		return 0, "", false
	}
	line := bytes.Count(data[:idx], []byte("\n")) + 1

	start := bytes.LastIndexByte(data[:idx], '\n') + 1
	end := bytes.IndexByte(data[idx:], '\n')
	if end < 0 {
		end = len(data)
	} else {
		end += idx
	}

	excerpt := strings.TrimSpace(string(data[start:end]))
	if len(excerpt) > 200 {
		excerpt = excerpt[:200] + "…"
	}
	return line, excerpt, true
}
