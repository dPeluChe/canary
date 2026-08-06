package campaign

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const keyvCampaign = `{
  "schema": 1,
  "id": "keyv-2026-08",
  "name": "keyv / cacheable npm compromise",
  "started": "2026-08-04T09:00:00Z",
  "source": "https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack",
  "packages": [
    {"ecosystem": "npm", "name": "keyv", "versions": ["6.0.0"]},
    {"ecosystem": "npm", "name": "cacheable-request", "versions": ["13.0.20"]}
  ],
  "artifacts": [
    {"kind": "domain", "value": "npm-cache.com", "note": "C2"},
    {"kind": "filename", "value": "Math_Symbol.js", "pathScope": "**/node_modules/keyv/**",
     "note": "unscoped this hits regenerate-unicode-properties"}
  ]
}`

func writeCampaign(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadReadsCampaigns(t *testing.T) {
	dir := t.TempDir()
	writeCampaign(t, dir, "keyv.json", keyvCampaign)
	writeCampaign(t, dir, "aaa.json", strings.Replace(keyvCampaign, `"keyv-2026-08"`, `"axios-2025-11"`, 1))

	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 campaigns, got %d", len(got))
	}
	// Sorted by ID, not by filename, so reports are stable across filesystems.
	if got[0].ID != "axios-2025-11" || got[1].ID != "keyv-2026-08" {
		t.Fatalf("unsorted: %q, %q", got[0].ID, got[1].ID)
	}

	c := got[1]
	if c.Started.UTC().Format("2006-01-02T15:04:05Z") != "2026-08-04T09:00:00Z" {
		t.Errorf("started: got %v", c.Started)
	}
	if len(c.Packages) != 2 || c.Packages[0].Name != "keyv" {
		t.Errorf("packages: got %+v", c.Packages)
	}
	if c.Artifacts[1].PathScope != "**/node_modules/keyv/**" {
		t.Errorf("pathScope: got %q", c.Artifacts[1].PathScope)
	}
	if c.File != filepath.Join(dir, "keyv.json") {
		t.Errorf("provenance: got %q", c.File)
	}
}

// A misspelled key must not decode to an empty list. Silently loading zero
// packages produces a clean verdict for a campaign that was never applied.
func TestLoadRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	writeCampaign(t, dir, "typo.json", strings.Replace(keyvCampaign, `"packages"`, `"package"`, 1))

	if _, err := Load(dir); err == nil {
		t.Fatal("want error for unknown field, got nil")
	}
}

// Invariant 4: a bare filename indicator is a false-positive generator.
// This is the Math_Symbol.js case from the incident that started the project.
func TestLoadRejectsUnscopedFilenameArtifact(t *testing.T) {
	dir := t.TempDir()
	writeCampaign(t, dir, "bad.json", strings.Replace(keyvCampaign,
		`"pathScope": "**/node_modules/keyv/**",`, "", 1))

	_, err := Load(dir)
	if err == nil {
		t.Fatal("want error for unscoped filename artifact, got nil")
	}
	if !strings.Contains(err.Error(), "pathScope") {
		t.Errorf("error should name pathScope: %v", err)
	}
}

// Invariant 5: never return a partial set. Four campaigns loaded out of five
// reads as full coverage and is the worst possible output.
func TestLoadFailsRatherThanReturningPartialSet(t *testing.T) {
	dir := t.TempDir()
	writeCampaign(t, dir, "good.json", keyvCampaign)
	writeCampaign(t, dir, "broken.json", `{"schema": 1, "id": "x"`)

	got, err := Load(dir)
	if err == nil {
		t.Fatalf("want error, got %d campaigns", len(got))
	}
	if got != nil {
		t.Errorf("want nil campaigns on failure, got %d", len(got))
	}
	if !strings.Contains(err.Error(), "broken.json") {
		t.Errorf("error should name the failing file: %v", err)
	}
}

// A scan that loaded no campaigns and a scan that found nothing look identical
// from the outside. The caller needs to tell them apart.
func TestLoadEmptyDirIsNotSuccess(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); !errors.Is(err, ErrNoCampaigns) {
		t.Fatalf("want ErrNoCampaigns, got %v", err)
	}
}

func TestLoadMissingDirIsDistinguishable(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("want fs.ErrNotExist, got %v", err)
	}
}

// fetch-campaign.sh clones upstream repos into subdirectories of the campaign
// dir; walking into them would try to parse every JSON file they ship.
func TestLoadSkipsSubdirsAndOtherFiles(t *testing.T) {
	dir := t.TempDir()
	writeCampaign(t, dir, "keyv.json", keyvCampaign)
	writeCampaign(t, dir, "notes.md", "not a campaign")
	if err := os.MkdirAll(filepath.Join(dir, "wiz"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCampaign(t, dir, filepath.Join("wiz", "package.json"), `{"name":"upstream"}`)

	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 campaign, got %d", len(got))
	}
}

// Two files claiming the same id means one of them silently wins wherever
// campaigns are keyed by id.
func TestLoadRejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	writeCampaign(t, dir, "a.json", keyvCampaign)
	writeCampaign(t, dir, "b.json", keyvCampaign)

	if _, err := Load(dir); err == nil {
		t.Fatal("want error for duplicate id, got nil")
	}
}

func TestLoadRequiresWindowStart(t *testing.T) {
	dir := t.TempDir()
	writeCampaign(t, dir, "nowindow.json",
		strings.Replace(keyvCampaign, `"started": "2026-08-04T09:00:00Z",`, "", 1))

	if _, err := Load(dir); err == nil {
		t.Fatal("want error for missing started, got nil")
	}
}

func TestLoadRejectsUnknownArtifactKind(t *testing.T) {
	dir := t.TempDir()
	writeCampaign(t, dir, "kind.json", strings.Replace(keyvCampaign, `"kind": "domain"`, `"kind": "dns"`, 1))

	if _, err := Load(dir); err == nil {
		t.Fatal("want error for unknown artifact kind, got nil")
	}
}

func TestLoadRejectsUnsupportedSchema(t *testing.T) {
	dir := t.TempDir()
	writeCampaign(t, dir, "future.json", strings.Replace(keyvCampaign, `"schema": 1`, `"schema": 99`, 1))

	if _, err := Load(dir); err == nil {
		t.Fatal("want error for unsupported schema, got nil")
	}
}

func TestPackageMatches(t *testing.T) {
	pinned := Package{Ecosystem: "npm", Name: "keyv", Versions: []string{"6.0.0"}}
	if !pinned.Matches("npm", "keyv", "6.0.0") {
		t.Error("pinned version should match")
	}
	if pinned.Matches("npm", "keyv", "4.5.4") {
		t.Error("safe version should not match")
	}
	if pinned.Matches("PyPI", "keyv", "6.0.0") {
		t.Error("wrong ecosystem should not match")
	}
	// Ecosystem spelling varies across vendor lists ("npm" vs "NPM"); the name does not.
	if !pinned.Matches("NPM", "keyv", "6.0.0") {
		t.Error("ecosystem compare should be case-insensitive")
	}

	// Omitted versions mean the whole package is malicious, at any version.
	all := Package{Ecosystem: "npm", Name: "evil-typosquat"}
	if !all.Matches("npm", "evil-typosquat", "0.0.1") {
		t.Error("empty versions should match every version")
	}
}
