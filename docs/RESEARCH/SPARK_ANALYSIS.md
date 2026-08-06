# The reference project: spark

[dPeluChe/spark](https://github.com/dPeluChe/spark) is the author's existing
Rust TUI for repo management, port scanning, cert checking, tool updating and a
light security audit. ~19,761 LOC, MIT.

canary was going to be built by extracting spark's security modules. That plan
was dropped after analysis, but spark remains the **design reference** — its
UX decisions were right even where its implementation was not.

This doc records both halves: what to copy, and the one bug that must never be
reproduced.

## The fatal bug: spark's dependency audit cannot see supply-chain attacks

`spark audit --deps` parses `package.json` for dependencies, then reads
`package-lock.json` — but **only to correct the versions of packages it already
found in `package.json`** (`src/scanner/dep_scanner/mod.rs:106-117`). Everything
else in the lockfile is parsed and thrown away. It also explicitly skips nested
entries (`parsers.rs:69-71`).

Measured on one real project during the incident:

```
declared in package.json:   26
packages in the lockfile:  790
  of those, nested:         80   ← discarded on purpose
was the compromised package declared?   No — it is transitive
```

**spark would have checked 26 packages and missed the compromised family
entirely.**

This is not a small bug. It is the wrong data model for the job. Supply-chain
attacks target deep transitive dependencies precisely *because* nobody declares
them. Any dependency check that starts from a manifest instead of a resolved
lockfile answers a different question than the one being asked.

Related gaps of the same kind:

- Only `package-lock.json`, `Cargo.lock`, `requirements.txt`. No `yarn.lock`,
  no `pnpm-lock.yaml`, no `bun.lockb` — three formats that were needed
  immediately in practice.
- Only inspects the **root** of each path (`path.join("package.json")`). Real
  lockfiles live in monorepos, `apps/*`, `web/`, `src-tauri/`. A hand scan of
  the same tree found 317 lockfiles; spark's model finds at most one per repo.
- OSV is queried online only. No concept of a *campaign* with loadable IoCs, so
  during the first hours of an incident — when the vendor list exists and the
  advisory does not — it has nothing to match against.

**canary's rule 3 ("transitive completeness or nothing") exists because of this
specific bug.**

## The second lesson: TUI-first is the wrong shape

spark is 19,761 LOC, of which **7,104 are the TUI**. That is what makes it
pleasant to use interactively and awkward to run in CI or cron.

A forensic tool has the opposite priority: exit codes, machine-readable output,
unattended runs. Hence canary's `core → headless CLI → optional TUI viewer`
layering, with the TUI never driving a scan.

## What is worth inheriting

The code does not port to Go, but these decisions do:

| From spark | Why it was right |
|---|---|
| `.sparkauditignore` | Per-repo scan exclusions as a committed file |
| Per-repo tags | Lets you scope a sweep: own repos vs third-party clones |
| `--offline` | A security tool must work without network |
| `-o report.txt` | Report to file, not just stdout |
| ghq-style repo discovery over a tree | The right unit of work — canary's `discover` |
| Severity-ordered output, critical first | Correct default for scanning output |

And the modules that seemed reusable, with their actual fate:

| Module | LOC | Fate |
|---|---|---|
| `scanner/dep_scanner/` | 524 | Discarded — the bug above. OSV-Scalibr replaces it |
| `scanner/repo_manager.rs` + `repo_scanner.rs` | 921 | Rewritten as `internal/discover` |
| `scanner/secret_scanner/` | 869 | Gitleaks replaces it |
| `scanner/history_scanner.rs` | 212 | Gitleaks handles git history |
| `scanner/code_patterns/` | 584 | Patterns are data and port; the engine is rewritten |

## Boundary

spark keeps its role: repo manager, ports, certs, updater, and a light hygiene
`audit`. canary takes the forensic work. **They are separate products and must
not grow a dependency on each other.**
