package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func mkRepo(t *testing.T, root, name, remote string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "[core]\n\trepositoryformatversion = 0\n"
	if remote != "" {
		cfg += "[remote \"origin\"]\n\turl = " + remote + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func write(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWalkFindsReposAndLockfiles(t *testing.T) {
	root := t.TempDir()
	a := mkRepo(t, root, "alpha", "https://github.com/dPeluChe/alpha.git")
	mkRepo(t, root, "beta", "git@github.com:dPeluChe/beta.git")

	write(t, filepath.Join(a, "package-lock.json"))
	write(t, filepath.Join(a, "web", "pnpm-lock.yaml"))

	res, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Repos) != 2 {
		t.Fatalf("want 2 repos, got %d", len(res.Repos))
	}
	if res.CountLockfiles() != 2 {
		t.Fatalf("want 2 lockfiles, got %d", res.CountLockfiles())
	}
	if res.Repos[0].Slug != "dPeluChe/alpha" {
		t.Errorf("https slug: got %q", res.Repos[0].Slug)
	}
	if res.Repos[1].Slug != "dPeluChe/beta" {
		t.Errorf("ssh slug: got %q", res.Repos[1].Slug)
	}
}

// A lockfile nested under node_modules is an installed artifact, not a declaration.
func TestWalkPrunesNodeModules(t *testing.T) {
	root := t.TempDir()
	a := mkRepo(t, root, "alpha", "")
	write(t, filepath.Join(a, "package-lock.json"))
	write(t, filepath.Join(a, "node_modules", "keyv", "package-lock.json"))

	res, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.CountLockfiles() != 1 {
		t.Fatalf("want 1 lockfile, got %d", res.CountLockfiles())
	}
}

// Nested repos must claim their own lockfiles instead of leaking them to the parent.
func TestWalkAssignsLockfileToNearestRepo(t *testing.T) {
	root := t.TempDir()
	outer := mkRepo(t, root, "outer", "")
	inner := mkRepo(t, outer, "inner", "")
	write(t, filepath.Join(inner, "Cargo.lock"))

	res, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res.Repos {
		if r.Path == outer && len(r.Lockfiles) != 0 {
			t.Errorf("outer repo claimed %d lockfiles, want 0", len(r.Lockfiles))
		}
		if r.Path == inner && len(r.Lockfiles) != 1 {
			t.Errorf("inner repo claimed %d lockfiles, want 1", len(r.Lockfiles))
		}
	}
}

func TestWalkReportsOrphanLockfiles(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "loose", "package-lock.json"))

	res, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Orphans) != 1 {
		t.Fatalf("want 1 orphan, got %d", len(res.Orphans))
	}
}
