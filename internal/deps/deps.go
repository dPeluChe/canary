// Package deps resolves the full dependency set of a lockfile and checks it
// against known-malicious versions.
//
// LAYER 1 of 4. See docs/ARCHITECTURE/OVERVIEW.md.
//
// Two sources, deliberately:
//
//  1. OSV.dev — MAL- advisories from the OpenSSF malicious-packages feed,
//     plus ordinary CVEs. Authoritative, but lags a breaking incident.
//  2. Local attack files — vendor IoC lists, available within hours.
//
// The hard requirement is TRANSITIVE COMPLETENESS. Supply-chain attacks land
// in transitive dependencies, not direct ones: in the keyv incident the
// compromised packages appeared in zero package.json files and in hundreds of
// lockfiles. A scanner that reads declared dependencies finds nothing.
// See docs/RESEARCH/SPARK_ANALYSIS.md for the worked example.
//
// Extraction is delegated to google/osv-scalibr rather than hand-written
// parsers — it covers the ecosystems and resolves transitives.
package deps

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/bunlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnlock"
	scalibrfs "github.com/google/osv-scalibr/fs"

	"github.com/dPeluChe/canary/internal/discover"
)

// Resolved is one package version present in a lockfile, direct or transitive.
//
// Direct is NOT populated yet: scalibr reports dependency groups (dev,
// optional), not whether the manifest declared the package. It stays false
// rather than guessed. Reporting may say "transitive" only once something
// fills it — and per DATA_MODEL it must never be used to filter, which is the
// bug this whole layer exists to avoid.
type Resolved struct {
	Ecosystem string
	Name      string
	Version   string
	Lockfile  string
	Direct    bool
}

// newExtractor maps a lockfile name to the scalibr extractor that reads it.
// A kind absent from this map is reported as unsupported rather than skipped:
// a lockfile nobody read is a coverage gap, not a clean result.
var newExtractor = map[string]func(*cpb.PluginConfig) (filesystem.Extractor, error){
	"package-lock.json":   packagelockjson.New,
	"npm-shrinkwrap.json": packagelockjson.New,
	"yarn.lock":           yarnlock.New,
	"pnpm-lock.yaml":      pnpmlock.New,
	"bun.lock":            bunlock.New,
}

// Supported reports whether Extract can read this lockfile kind.
func Supported(kind string) bool {
	_, ok := newExtractor[kind]
	return ok
}

// Extract reads a lockfile and returns every package version it pins,
// including transitive and nested entries.
//
// The count it returns is the point of this layer: for a real project it is
// hundreds, where the manifest declares a couple of dozen. Anything that
// returns roughly the manifest's size is answering a different question.
func Extract(lf discover.Lockfile) ([]Resolved, error) {
	factory, ok := newExtractor[lf.Kind]
	if !ok {
		return nil, fmt.Errorf("deps: %s: unsupported lockfile kind %q", lf.Path, lf.Kind)
	}
	ext, err := factory(nil)
	if err != nil {
		return nil, fmt.Errorf("deps: %s: %w", lf.Path, err)
	}

	f, err := os.Open(lf.Path)
	if err != nil {
		return nil, fmt.Errorf("deps: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("deps: %s: %w", lf.Path, err)
	}

	dir := filepath.Dir(lf.Path)
	inv, err := ext.Extract(context.Background(), &filesystem.ScanInput{
		FS:     scalibrfs.DirFS(dir),
		Path:   filepath.Base(lf.Path),
		Root:   dir,
		Info:   info,
		Reader: f,
	})
	if err != nil {
		return nil, fmt.Errorf("deps: %s: %w", lf.Path, err)
	}

	out := make([]Resolved, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		if p == nil || p.Name == "" {
			continue
		}
		out = append(out, Resolved{
			Ecosystem: lf.Ecosystem,
			Name:      p.Name,
			Version:   p.Version,
			Lockfile:  lf.Path,
		})
	}
	return out, nil
}
