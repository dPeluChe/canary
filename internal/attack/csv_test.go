package attack

import (
	"strings"
	"testing"
	"time"
)

func testMeta() Attack {
	return Attack{
		ID:      "keyv-2026-08",
		Name:    "keyv / cacheable npm compromise",
		Started: time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC),
		Source:  "https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack",
	}
}

// The published shape quotes multi-version cells, so the commas inside them are
// data. Splitting on commas without a CSV reader silently mangles 358 of the
// 446 rows in the real list.
func TestFromCSVKeepsQuotedVersionLists(t *testing.T) {
	in := `Package,Malicious Versions
@adminide-stack/clock-tik-browser,12.0.24
@or-sdk/api-tokens-lambda,"1.4.2, 1.4.3, 1.4.4"
`
	got, err := FromCSV(strings.NewReader(in), "npm", testMeta())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Packages) != 2 {
		t.Fatalf("want 2 packages, got %d", len(got.Packages))
	}
	if len(got.Packages[1].Versions) != 3 {
		t.Fatalf("quoted cell: want 3 versions, got %v", got.Packages[1].Versions)
	}
	if !got.Packages[1].Matches("npm", "@or-sdk/api-tokens-lambda", "1.4.3") {
		t.Error("middle version of a quoted list should match")
	}
}

// Vendors publish the same two columns in different orders.
func TestFromCSVFindsColumnsByHeaderNotPosition(t *testing.T) {
	in := "Malicious Versions,Package\n\"1.0.0, 1.0.1\",evil\n"
	got, err := FromCSV(strings.NewReader(in), "npm", testMeta())
	if err != nil {
		t.Fatal(err)
	}
	if got.Packages[0].Name != "evil" || len(got.Packages[0].Versions) != 2 {
		t.Fatalf("got %+v", got.Packages[0])
	}
}

// A blank versions cell must not become "every version of this package is
// malicious" — that is a claim the vendor did not make.
func TestFromCSVRefusesRowWithoutVersions(t *testing.T) {
	in := "Package,Malicious Versions\nkeyv,\n"
	_, err := FromCSV(strings.NewReader(in), "npm", testMeta())
	if err == nil {
		t.Fatal("want error for a versions-less row, got nil")
	}
	if !strings.Contains(err.Error(), "EVERY version") {
		t.Errorf("error should explain the consequence: %v", err)
	}
}

func TestFromCSVRejectsUnknownHeaders(t *testing.T) {
	in := "pkg,vers\nkeyv,6.0.0\n"
	if _, err := FromCSV(strings.NewReader(in), "npm", testMeta()); err == nil {
		t.Fatal("want error for unrecognized headers, got nil")
	}
}

// Vendors repeat a package across rows when versions land in batches.
func TestFromCSVMergesRepeatedPackages(t *testing.T) {
	in := "Package,Malicious Versions\nkeyv,6.0.0\nkeyv,\"6.0.1, 6.0.0\"\n"
	got, err := FromCSV(strings.NewReader(in), "npm", testMeta())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Packages) != 1 {
		t.Fatalf("want the rows merged into 1 package, got %d", len(got.Packages))
	}
	if v := got.Packages[0].Versions; len(v) != 2 || v[0] != "6.0.0" || v[1] != "6.0.1" {
		t.Fatalf("want deduped and sorted versions, got %v", v)
	}
}

// A successful conversion must never produce something Load would reject.
func TestFromCSVOutputPassesValidation(t *testing.T) {
	in := "Package,Malicious Versions\nkeyv,6.0.0\n"
	got, err := FromCSV(strings.NewReader(in), "npm", testMeta())
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != Schema {
		t.Errorf("schema not stamped: %d", got.Schema)
	}
	if err := got.validate(); err != nil {
		t.Errorf("converter emitted an invalid attack: %v", err)
	}

	incomplete := FromCSVMissingMeta(t, in)
	if incomplete == nil {
		t.Error("want validation to reject metadata-less output")
	}
}

func FromCSVMissingMeta(t *testing.T, in string) error {
	t.Helper()
	_, err := FromCSV(strings.NewReader(in), "npm", Attack{ID: "x"})
	return err
}
