// Package datadir resolves where canary reads a data set from, and reports
// which candidate won.
//
// Every source of "is this malicious" — attack files, corpus datasets, and the
// adapters still to come — needs the same precedence and the same refusal to
// fall through. Two resolvers that drift apart mean a flag behaves differently
// depending on which data it points at, which is the sort of surprise a
// forensic tool cannot afford.
package datadir

import (
	"fmt"
	"os"
	"path/filepath"
)

// Sources a directory can come from, in precedence order.
const (
	SourceFlag    = "flag"
	SourceRepo    = "repo-local"
	SourceDefault = "default"
)

// SourceEnv names the environment variable that supplied the directory.
func SourceEnv(envVar string) string { return "$" + envVar }

// Resolve picks a directory: explicit, then $envVar, then <workdir>/<subdir>
// if it exists, then ~/.canary/<subdir>.
//
// An explicit or env value is returned WITHOUT checking that it exists.
// Falling through to another directory because the requested one is missing
// would silently read the wrong list — the caller must see the resulting
// fs.ErrNotExist instead.
func Resolve(explicit, workdir, envVar, subdir string) (dir, source string, err error) {
	if explicit != "" {
		return explicit, SourceFlag, nil
	}
	if v := os.Getenv(envVar); v != "" {
		return v, SourceEnv(envVar), nil
	}
	if workdir != "" {
		local := filepath.Join(workdir, subdir)
		if fi, statErr := os.Stat(local); statErr == nil && fi.IsDir() {
			return local, SourceRepo + " " + subdir + "/", nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", fmt.Errorf("datadir: no directory given and home is unreadable: %w", err)
	}
	return filepath.Join(home, ".canary", subdir), SourceDefault, nil
}
