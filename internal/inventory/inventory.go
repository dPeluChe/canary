// Package inventory persists the resolved dependency set of a scanned tree.
//
// Re-resolving 486 lockfiles to test one newly published attack is wasted work:
// the tree changes slowly, the attack list changes daily. With the inventory on
// disk, matching a new attack costs milliseconds and touches nothing.
//
// It is also the artifact `watch` depends on — polling a feed is only cheap
// because the answer does not require walking anything.
//
// WHERE IT IS NOT WRITTEN: docs/TASK_TODO.md originally proposed
// `.canary/inventory.json` inside the scanned tree. That would break invariant
// 1, which says canary never writes to what it inspects, and the read-only test
// in cmd/canary would fail on it. The inventory lives in canary's own data
// directory instead, keyed by the tree it describes.
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dPeluChe/canary/internal/deps"
	"github.com/dPeluChe/canary/internal/discover"
)

// Schema is the on-disk version. A mismatch is refused rather than guessed at.
const Schema = 1

// Package is one resolved version, stored once no matter how many repos pin it.
// A real tree resolves the same few thousand packages across hundreds of repos,
// so storing them per repo would multiply the file by an order of magnitude.
type Package struct {
	Ecosystem string `json:"e"`
	Name      string `json:"n"`
	Version   string `json:"v"`
}

// Repo is one repository and the packages it resolved, as indices into
// Inventory.Packages.
type Repo struct {
	Name      string `json:"name"`
	Slug      string `json:"slug,omitempty"`
	Path      string `json:"path"`
	Lockfiles int    `json:"lockfiles"`
	Skipped   int    `json:"skipped,omitempty"`
	Packages  []int  `json:"pkgs"`
}

// Inventory is a whole tree's resolved set at a point in time.
type Inventory struct {
	Schema   int       `json:"schema"`
	Root     string    `json:"root"`
	Created  time.Time `json:"created"`
	Packages []Package `json:"packages"`
	Repos    []Repo    `json:"repos"`
}

// Age is how long ago the tree was actually read.
func (inv *Inventory) Age() time.Duration { return time.Since(inv.Created) }

// Resolved rebuilds the deps.Resolved set for a repo, so matching a new attack
// against a stored inventory goes through exactly the same code path as
// matching against a fresh scan.
func (inv *Inventory) Resolved(r Repo) []deps.Resolved {
	out := make([]deps.Resolved, 0, len(r.Packages))
	for _, i := range r.Packages {
		if i < 0 || i >= len(inv.Packages) {
			continue
		}
		p := inv.Packages[i]
		out = append(out, deps.Resolved{
			Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version, Lockfile: r.Path,
		})
	}
	return out
}

// Builder accumulates an inventory during a scan, deduplicating as it goes.
type Builder struct {
	inv   Inventory
	index map[Package]int
}

// NewBuilder starts an inventory for root.
func NewBuilder(root string) *Builder {
	return &Builder{
		inv:   Inventory{Schema: Schema, Root: root, Created: time.Now().UTC()},
		index: map[Package]int{},
	}
}

// Add records one repo's resolved set.
func (b *Builder) Add(repo discover.Repo, resolved []deps.Resolved, lockfiles, skipped int) {
	entry := Repo{
		Name: repo.Name, Slug: repo.Slug, Path: repo.Path,
		Lockfiles: lockfiles, Skipped: skipped,
	}
	for _, r := range resolved {
		key := Package{Ecosystem: r.Ecosystem, Name: r.Name, Version: r.Version}
		i, seen := b.index[key]
		if !seen {
			i = len(b.inv.Packages)
			b.index[key] = i
			b.inv.Packages = append(b.inv.Packages, key)
		}
		entry.Packages = append(entry.Packages, i)
	}
	b.inv.Repos = append(b.inv.Repos, entry)
}

// Inventory returns what has been built.
func (b *Builder) Inventory() *Inventory { return &b.inv }

// EnvDataDir overrides where canary keeps its own data. Tests set it so a test
// run never writes into the developer's home, and operators can point it at a
// shared or ephemeral location.
const EnvDataDir = "CANARY_DATA_DIR"

// DataDir is canary's own directory: $CANARY_DATA_DIR, else ~/.canary.
func DataDir() (string, error) {
	if v := os.Getenv(EnvDataDir); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("inventory: no data directory and home is unreadable: %w", err)
	}
	return filepath.Join(home, ".canary"), nil
}

// Path is where the inventory for a tree lives: canary's own data directory,
// keyed by a hash of the tree's absolute path so several trees coexist.
func Path(dataDir, root string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(root)))
	return filepath.Join(dataDir, "inventory", hex.EncodeToString(sum[:8])+".json")
}

// Save writes the inventory, creating the directory if needed. It writes to a
// temporary file and renames, so an interrupted save never leaves a truncated
// inventory that would later load as a smaller tree than was scanned.
func Save(path string, inv *Inventory) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	body, err := json.Marshal(inv)
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".inventory-*")
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return fmt.Errorf("inventory: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	return os.Rename(tmp.Name(), path)
}

// Load reads a stored inventory. A schema it does not recognise is an error:
// silently reading a future format would produce a smaller resolved set than
// was actually scanned, which reads as a cleaner tree than exists.
func Load(path string) (*Inventory, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	var inv Inventory
	if err := json.Unmarshal(body, &inv); err != nil {
		return nil, fmt.Errorf("inventory: %s: %w", path, err)
	}
	if inv.Schema != Schema {
		return nil, fmt.Errorf("inventory: %s: schema %d is not supported, want %d", path, inv.Schema, Schema)
	}
	if len(inv.Repos) == 0 {
		return nil, fmt.Errorf("inventory: %s: no repos recorded", path)
	}
	return &inv, nil
}
