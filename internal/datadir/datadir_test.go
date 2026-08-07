package datadir

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePrecedence(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "things"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CANARY_TEST_DIR", "/from/env")
	if dir, src, _ := Resolve("/from/flag", work, "CANARY_TEST_DIR", "things"); dir != "/from/flag" || src != SourceFlag {
		t.Errorf("flag should win: %q via %q", dir, src)
	}
	if dir, src, _ := Resolve("", work, "CANARY_TEST_DIR", "things"); dir != "/from/env" || src != SourceEnv("CANARY_TEST_DIR") {
		t.Errorf("env should beat repo-local: %q via %q", dir, src)
	}

	t.Setenv("CANARY_TEST_DIR", "")
	if dir, _, _ := Resolve("", work, "CANARY_TEST_DIR", "things"); dir != filepath.Join(work, "things") {
		t.Errorf("repo-local should win when it exists: %q", dir)
	}
	if _, src, _ := Resolve("", t.TempDir(), "CANARY_TEST_DIR", "things"); src != SourceDefault {
		t.Errorf("absent repo-local should fall through to default, got %q", src)
	}
}

// A missing explicit directory must be returned as-is. Falling through would
// read a different list than the one asked for, without saying so.
func TestResolveDoesNotFallThroughOnMissingExplicit(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "things"), 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "nope")

	if dir, src, _ := Resolve(missing, work, "CANARY_TEST_DIR", "things"); dir != missing || src != SourceFlag {
		t.Fatalf("want the missing dir back untouched, got %q via %q", dir, src)
	}
}

// The risk of a shared resolver is a caller wired to the wrong subdirectory or
// variable. Two data sets must not resolve to the same default.
func TestDifferentSubdirsDoNotCollide(t *testing.T) {
	empty := t.TempDir()

	a, _, err := Resolve("", empty, "CANARY_A_DIR", "attacks")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := Resolve("", empty, "CANARY_B_DIR", "corpus")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("attacks and corpus resolved to the same default: %q", a)
	}
	if filepath.Base(a) != "attacks" || filepath.Base(b) != "corpus" {
		t.Errorf("defaults should end in their own subdir: %q, %q", a, b)
	}
}
