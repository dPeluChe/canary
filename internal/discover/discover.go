// Package discover walks a directory tree and inventories the git repositories
// and dependency lockfiles inside it. It is the entry point for every other
// layer: nothing in canary scans a path that discover did not report.
package discover

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Repo is a git repository found under the scanned root.
type Repo struct {
	Path      string     // absolute path to the repo root
	Name      string     // directory name, for display
	Remote    string     // origin URL, empty if none
	Slug      string     // owner/repo parsed from Remote, empty if not GitHub
	Lockfiles []Lockfile // lockfiles found inside this repo
}

// Lockfile is a dependency manifest that pins resolved versions.
type Lockfile struct {
	Path      string // absolute path
	Rel       string // path relative to its repo root
	Kind      string // file name, e.g. "package-lock.json"
	Ecosystem string // OSV ecosystem name, e.g. "npm"
}

// Result is the full inventory of a scanned tree.
type Result struct {
	Root    string
	Repos   []Repo
	Orphans []Lockfile // lockfiles that live outside any git repo
}

// prunedDirs are never descended into. Build output and installed dependencies
// are not evidence of what a project *declares*; the deps layer reads lockfiles,
// and the ioc layer opts back into node_modules explicitly when it needs to.
var prunedDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"target":       true,
	"dist":         true,
	"build":        true,
	".next":        true,
	".nuxt":        true,
	"vendor":       true,
	"venv":         true,
	".venv":        true,
	"__pycache__":  true,
	".terraform":   true,
	"Pods":         true,
}

// lockfileEcosystems maps a lockfile name to its OSV ecosystem identifier.
var lockfileEcosystems = map[string]string{
	"package-lock.json":   "npm",
	"npm-shrinkwrap.json": "npm",
	"yarn.lock":           "npm",
	"pnpm-lock.yaml":      "npm",
	"bun.lock":            "npm",
	"bun.lockb":           "npm",
	"Cargo.lock":          "crates.io",
	"go.sum":              "Go",
	"requirements.txt":    "PyPI",
	"poetry.lock":         "PyPI",
	"Pipfile.lock":        "PyPI",
	"uv.lock":             "PyPI",
	"Gemfile.lock":        "RubyGems",
	"composer.lock":       "Packagist",
	"pubspec.lock":        "Pub",
	"mix.lock":            "Hex",
}

// Walk inventories root, returning every git repo and lockfile beneath it.
// It never writes, and it tolerates unreadable directories rather than aborting.
func Walk(root string) (*Result, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	res := &Result{Root: abs}
	repoAt := map[string]*Repo{}
	var repoPaths []string
	var loose []Lockfile

	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip, do not abort the sweep
		}

		if d.IsDir() {
			name := d.Name()
			if name == ".git" {
				root := filepath.Dir(path)
				r := &Repo{Path: root, Name: filepath.Base(root)}
				r.Remote = originRemote(root)
				r.Slug = parseSlug(r.Remote)
				repoAt[root] = r
				repoPaths = append(repoPaths, root)
				return filepath.SkipDir
			}
			if prunedDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}

		eco, ok := lockfileEcosystems[d.Name()]
		if !ok {
			return nil
		}
		loose = append(loose, Lockfile{Path: path, Kind: d.Name(), Ecosystem: eco})
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Longest path first so nested repos claim their lockfiles before parents do.
	sort.Slice(repoPaths, func(i, j int) bool {
		return len(repoPaths[i]) > len(repoPaths[j])
	})

	for _, lf := range loose {
		owner := ""
		for _, rp := range repoPaths {
			if strings.HasPrefix(lf.Path, rp+string(os.PathSeparator)) {
				owner = rp
				break
			}
		}
		if owner == "" {
			res.Orphans = append(res.Orphans, lf)
			continue
		}
		rel, _ := filepath.Rel(owner, lf.Path)
		lf.Rel = rel
		repoAt[owner].Lockfiles = append(repoAt[owner].Lockfiles, lf)
	}

	for _, rp := range repoPaths {
		res.Repos = append(res.Repos, *repoAt[rp])
	}
	sort.Slice(res.Repos, func(i, j int) bool { return res.Repos[i].Path < res.Repos[j].Path })

	return res, nil
}

// originRemote reads origin's URL straight from .git/config. Shelling out to
// git for this would cost a process per repo across a tree of hundreds.
func originRemote(repoRoot string) string {
	f, err := os.Open(filepath.Join(repoRoot, ".git", "config"))
	if err != nil {
		return ""
	}
	defer f.Close()

	inOrigin := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inOrigin = line == `[remote "origin"]`
			continue
		}
		if inOrigin && strings.HasPrefix(line, "url") {
			if _, v, ok := strings.Cut(line, "="); ok {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

// parseSlug extracts "owner/repo" from a GitHub remote in either SSH or HTTPS form.
func parseSlug(remote string) string {
	if remote == "" || !strings.Contains(remote, "github.com") {
		return ""
	}
	s := strings.TrimSuffix(remote, ".git")
	if _, after, ok := strings.Cut(s, "github.com:"); ok {
		return after
	}
	if _, after, ok := strings.Cut(s, "github.com/"); ok {
		return after
	}
	return ""
}

// CountLockfiles returns the total number of lockfiles across all repos and orphans.
func (r *Result) CountLockfiles() int {
	n := len(r.Orphans)
	for _, repo := range r.Repos {
		n += len(repo.Lockfiles)
	}
	return n
}
