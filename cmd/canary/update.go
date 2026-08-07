package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dPeluChe/canary/internal/corpus"
)

// source is a redistributable list canary can fetch. Licence is recorded here
// because it is the field that decides whether a list may be cached at all —
// the vendor CSVs have none and stay manual through `canary import`.
type source struct {
	name    string
	url     string
	file    string
	licence string
	verify  func(path string) (int, error)
}

var sources = []source{
	{
		name:    corpus.ShaiHuludSource,
		url:     "https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt",
		file:    "shai-hulud.txt",
		licence: "MIT",
		verify: func(path string) (int, error) {
			c, err := corpus.LoadShaiHulud(path)
			if err != nil {
				return 0, err
			}
			return c.Count(""), nil
		},
	},
}

// cmdUpdate refreshes the local source cache.
//
// Refreshing is explicit and never a side effect of a read command: a network
// call hidden inside `attacks` or `scan` would cost the reproducibility a
// forensic answer depends on — you have to be able to say you scanned against
// exactly this list.
//
// canary writes only here, into its own data directory. That is not a breach
// of the read-only invariant, which is about what canary INSPECTS; a refusal
// to write anywhere near a scanned tree is what keeps it literal.
func cmdUpdate(args []string) int {
	flags := flag.NewFlagSet("update", flag.ExitOnError)
	dir := flags.String("dir", "", "corpus directory (default: $CANARY_CORPUS_DIR, ./corpus, ~/.canary/corpus)")
	timeout := flags.Duration("timeout", 60*time.Second, "per-source download timeout")
	if err := flags.Parse(args); err != nil {
		return exitError
	}

	wd, _ := os.Getwd()
	resolved, src, err := corpus.ResolveDir(*dir, wd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}
	if err := os.MkdirAll(resolved, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		return exitError
	}
	fmt.Printf("updating %s (%s)\n\n", resolved, src)

	failed := 0
	for _, s := range sources {
		n, err := fetchSource(s, resolved, *timeout)
		if err != nil {
			// A source that did not refresh is a coverage gap, not a silent
			// no-op: the cached copy may be months old and still be used.
			fmt.Fprintf(os.Stderr, "  FAILED  %-46s %v\n", s.name, err)
			failed++
			continue
		}
		fmt.Printf("  ok      %-46s %6d entries  (%s)\n", s.name, n, s.licence)
	}

	fmt.Printf("\n%d source(s) refreshed, %d failed\n", len(sources)-failed, failed)
	fmt.Println("vendor incident lists stay manual: no licence to redistribute them — use `canary import`")
	if failed > 0 {
		return exitError
	}
	return exitClean
}

// fetchSource downloads to a temporary file, parses it, and only then replaces
// the cached copy. A truncated download that overwrote a good list would shrink
// the set canary matches against without saying so.
func fetchSource(s source, dir string, timeout time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("http %s", resp.Status)
	}

	tmp, err := os.CreateTemp(dir, ".canary-download-*")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}

	n, err := s.verify(tmpName)
	if err != nil {
		return 0, fmt.Errorf("downloaded but unusable: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, s.file)); err != nil {
		return 0, err
	}
	return n, nil
}
