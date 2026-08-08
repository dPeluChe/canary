package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Invariant 1 says canary never writes, moves, deletes or fixes anything it
// inspects. Until now that was asserted and never demonstrated.
//
// A syscall trace would prove one run on one machine — and on macOS it needs
// SIP disabled or root, so it would be a manual ritual nobody repeats. Hashing
// the whole tree before and after proves every run, on every platform, in CI,
// and keeps proving it when someone adds a layer that writes.

type snapshot map[string]string

// take records every path under root with its size, mode, mtime and content
// hash. Directories are recorded too, so a created or removed one is caught.
func take(t *testing.T, root string) snapshot {
	t.Helper()
	snap := snapshot{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable path is still a path: record that it exists and
			// could not be read, the same on both sides of the comparison.
			if rel, relErr := filepath.Rel(root, path); relErr == nil {
				snap[rel] = "unreadable"
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			snap[rel] = "dir " + info.Mode().String() + " " + info.ModTime().UTC().Format("20060102150405.000000000")
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			snap[rel] = "unreadable-file"
			return nil
		}
		sum := sha256.Sum256(body)
		snap[rel] = "file " + info.Mode().String() +
			" " + info.ModTime().UTC().Format("20060102150405.000000000") +
			" " + hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func diff(t *testing.T, before, after snapshot) []string {
	t.Helper()
	var out []string
	for path, was := range before {
		now, still := after[path]
		switch {
		case !still:
			out = append(out, "DELETED  "+path)
		case now != was:
			out = append(out, "MODIFIED "+path+"\n    before: "+was+"\n    after:  "+now)
		}
	}
	for path := range after {
		if _, existed := before[path]; !existed {
			out = append(out, "CREATED  "+path)
		}
	}
	sort.Strings(out)
	return out
}

// TestScanNeverWritesToTheTreeItInspects exercises every layer against a tree
// that has something for each of them to find — a malicious lockfile, a C2
// domain on disk, persistence locations, a vulnerable workflow — because a
// layer that finds nothing also writes nothing, and would prove less.
func TestScanNeverWritesToTheTreeItInspects(t *testing.T) {
	tr := newTree(t)

	infected := tr.repo(t, "infected", "package-lock.json", lockWith("6.0.0"))
	writeFile(t, filepath.Join(infected, "src", "app.js"), `const c2 = "npm-cache-evil.invalid";`)
	writeFile(t, filepath.Join(infected, ".claude", "hooks", "on-start.sh"), "#!/bin/sh\necho hi\n")
	writeFile(t, filepath.Join(infected, ".vscode", "tasks.json"), `{"version":"2.0.0"}`)
	writeFile(t, filepath.Join(infected, "public", "sw.js"), "self.addEventListener('fetch', () => {})")
	writeFile(t, filepath.Join(infected, ".git", "hooks", "pre-commit"), "#!/bin/sh\n")
	writeFile(t, filepath.Join(infected, ".git", "hooks", "pre-push.sample"), "#!/bin/sh\n")
	writeFile(t, filepath.Join(infected, ".github", "workflows", "ci.yml"),
		"name: ci\non: [pull_request_target]\njobs:\n  build:\n    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n")

	// node_modules is where the sweep opts back in, so it must be covered.
	writeFile(t, filepath.Join(infected, "node_modules", "keyv", "index.js"), `fetch("npm-cache-evil.invalid")`)

	tr.repo(t, "clean", "package-lock.json", lockWith("4.5.4"))
	writeFile(t, filepath.Join(tr.root, "orphan", "package-lock.json"), lockWith("6.0.0"))

	before := take(t, tr.root)
	attacksBefore := take(t, tr.attacks)

	out, code := tr.run(t)
	if code != exitFindings {
		t.Fatalf("the fixture must produce findings, or this proves nothing: exit=%d\n%s", code, out)
	}

	if changes := diff(t, before, take(t, tr.root)); len(changes) > 0 {
		t.Errorf("canary modified the tree it inspected — invariant 1:\n  %v", changes)
	}
	// The attack files are input, not evidence, but they are equally not ours
	// to touch.
	if changes := diff(t, attacksBefore, take(t, tr.attacks)); len(changes) > 0 {
		t.Errorf("canary modified its own attack files:\n  %v", changes)
	}
}

// The read-only guarantee must hold when things go wrong too: an unreadable
// directory, a lockfile that does not parse, a corpus that fails to load.
func TestScanNeverWritesOnTheErrorPaths(t *testing.T) {
	tr := newTree(t)

	broken := tr.repo(t, "brokenlock", "package-lock.json", "{ this is not json")
	writeFile(t, filepath.Join(broken, "public", "sw.js"), "x")
	tr.repo(t, "nolock", "", "")

	locked := filepath.Join(tr.root, "locked")
	if err := os.MkdirAll(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	before := take(t, tr.root)
	if _, code := tr.run(t); code == exitError {
		t.Fatal("the fixture should be scannable, not a canary failure")
	}
	if changes := diff(t, before, take(t, tr.root)); len(changes) > 0 {
		t.Errorf("canary wrote while handling errors:\n  %v", changes)
	}
}

// discover and the attacks listing are read paths too, and cheap to cover.
func TestReadOnlyCommandsNeverWrite(t *testing.T) {
	tr := newTree(t)
	tr.repo(t, "app", "package-lock.json", lockWith("6.0.0"))

	before := take(t, tr.root)
	if code := cmdDiscover([]string{"-quiet", tr.root}); code != exitClean {
		t.Fatalf("discover exit = %d", code)
	}
	if code := cmdAttacks([]string{"-dir", tr.attacks}); code != exitClean {
		t.Fatalf("attacks exit = %d", code)
	}
	if changes := diff(t, before, take(t, tr.root)); len(changes) > 0 {
		t.Errorf("a read command wrote to the tree:\n  %v", changes)
	}
}
