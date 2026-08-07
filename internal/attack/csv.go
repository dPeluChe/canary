package attack

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Header names accepted for the two columns a vendor package list must carry.
// Matching is case-insensitive and ignores surrounding space.
var (
	packageHeaders  = []string{"package", "name", "package name"}
	versionsHeaders = []string{"malicious versions", "versions", "version"}
)

// FromCSV builds an Attack from a vendor package list — the shape Wiz publishes
// during an incident: a "Package" column and a "Malicious Versions" column
// holding a quoted, comma-separated list.
//
// Columns are located by header name rather than position, because vendors
// publish the same data with different column orders.
//
// A row with a package but no versions is an ERROR, not an empty list. Empty
// versions mean "every version of this package is malicious", which is a claim
// no converter should make on a vendor's behalf from a blank cell.
//
// The result is validated before returning, so a successful conversion cannot
// produce a file that Load would later reject.
func FromCSV(r io.Reader, ecosystem string, meta Attack) (Attack, error) {
	if ecosystem == "" {
		return meta, fmt.Errorf("attack: csv: ecosystem is required")
	}

	rd := csv.NewReader(r)
	rd.FieldsPerRecord = -1
	rd.TrimLeadingSpace = true

	header, err := rd.Read()
	if err != nil {
		return meta, fmt.Errorf("attack: csv: reading header: %w", err)
	}

	nameCol, err := findColumn(header, packageHeaders)
	if err != nil {
		return meta, err
	}
	versCol, err := findColumn(header, versionsHeaders)
	if err != nil {
		return meta, err
	}

	byName := map[string]int{}
	line := 1
	for {
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		line++
		if err != nil {
			return meta, fmt.Errorf("attack: csv: line %d: %w", line, err)
		}
		if nameCol >= len(rec) || versCol >= len(rec) {
			return meta, fmt.Errorf("attack: csv: line %d: has %d field(s), need at least %d", line, len(rec), max(nameCol, versCol)+1)
		}

		name := strings.TrimSpace(rec[nameCol])
		if name == "" {
			continue
		}

		if isRange(rec[versCol]) {
			return meta, fmt.Errorf("attack: csv: line %d: %q lists a version RANGE (%q); the format holds exact versions, and splitting a range on its comma produces entries that match nothing. Resolve it to concrete versions first", line, name, strings.TrimSpace(rec[versCol]))
		}
		versions := splitVersions(rec[versCol])
		if len(versions) == 0 {
			return meta, fmt.Errorf("attack: csv: line %d: %q has no versions; an empty list would match EVERY version, so state it deliberately in the file instead", line, name)
		}

		// Vendors repeat a package across rows when versions land in batches.
		if at, seen := byName[name]; seen {
			meta.Packages[at].Versions = NormalizeVersions(append(meta.Packages[at].Versions, versions...))
			continue
		}
		byName[name] = len(meta.Packages)
		meta.Packages = append(meta.Packages, Package{Ecosystem: ecosystem, Name: name, Versions: versions})
	}

	if len(meta.Packages) == 0 {
		return meta, fmt.Errorf("attack: csv: no package rows found")
	}

	meta.Schema = Schema
	if err := meta.validate(); err != nil {
		return meta, fmt.Errorf("attack: csv: %w", err)
	}
	return meta, nil
}

func findColumn(header, accepted []string) (int, error) {
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(h))
		for _, a := range accepted {
			if h == a {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("attack: csv: no column named any of %v (found %v)", accepted, header)
}

// isRange spots a semver range in a cell. Ranges are refused rather than
// parsed: resolving them is OSV's job, and the silent alternative — splitting
// ">=1.0.0, <2.0.0" on its comma — yields two entries that match nothing while
// the attack file looks fully loaded.
func isRange(cell string) bool {
	return strings.ContainsAny(cell, "<>^~") || strings.Contains(cell, "||") ||
		strings.Contains(cell, " - ") || strings.Contains(cell, "*")
}

func splitVersions(cell string) []string {
	var out []string
	for _, v := range strings.Split(cell, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return NormalizeVersions(out)
}

// NormalizeVersions trims, drops blanks, dedupes and sorts a version list.
// Exported because every source adapter needs the same normalization, and two
// sources that normalize differently would disagree about the same package.
func NormalizeVersions(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
