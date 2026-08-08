package corpus

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/dPeluChe/canary/internal/attack"
)

// ShaiHuludSource is the provenance label carried by every entry from this list.
const ShaiHuludSource = "Cobenian/shai-hulud-detect"

// LoadShaiHulud reads a `name:version` list — the shape
// Cobenian/shai-hulud-detect publishes as compromised-packages.txt, MIT and
// therefore redistributable, unlike the vendor CSVs.
//
// It is a corpus and not an attack file for the same reason DataDog's is: the
// list spans several campaigns from September 2025 onward and has no single
// forensic window, so forcing it into Attack would invent a Started that layers
// 2 and 4 would then key off.
//
// Scoped packages make the split non-obvious: "@scope/name:1.2.3" has two
// colons and only the last one separates the version.
func LoadShaiHulud(path string) (*Corpus, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("corpus: shai-hulud: %w", err)
	}
	defer f.Close()

	c := &Corpus{
		entries: map[entryKey]Entry{},
		counts:  map[string]int{},
		sources: []string{ShaiHuludSource},
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		i := strings.LastIndexByte(text, ':')
		if i <= 0 || i == len(text)-1 {
			return nil, fmt.Errorf("corpus: shai-hulud: %s: line %d: %q is not name:version", path, line, text)
		}
		name, version := strings.TrimSpace(text[:i]), strings.TrimSpace(text[i+1:])
		if name == "" || version == "" {
			return nil, fmt.Errorf("corpus: shai-hulud: %s: line %d: empty name or version in %q", path, line, text)
		}

		// This list is npm-only; every entry the upstream README describes is a
		// compromised npm package.
		c.add(Entry{
			Package: attack.Package{Ecosystem: "npm", Name: name, Versions: []string{version}},
			Sources: []string{ShaiHuludSource},
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("corpus: shai-hulud: %s: %w", path, err)
	}

	if c.Count("") == 0 {
		return nil, fmt.Errorf("corpus: shai-hulud: %s: no entries loaded", path)
	}
	return c, nil
}
