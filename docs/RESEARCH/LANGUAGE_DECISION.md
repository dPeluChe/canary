# Why Go

Decided August 2026. The initial lean was Rust, on the reasoning that a
reference project already existed in Rust with ~2,600 lines of reusable code.
Research reversed that. The criterion that decided it was **access to libraries
that let the tool keep growing**.

## The deciding factor: OSV-Scalibr

[OSV-Scalibr](https://pkg.go.dev/github.com/google/osv-scalibr) is Google's
software-composition-analysis library — the engine behind `osv-scanner`, and,
per Google, their primary SCA engine internally for live hosts, code repos and
containers.

It is **importable as a Go library**, and it solves precisely the problem the
reference project got wrong:

| Requirement | Hand-written (Rust) | OSV-Scalibr |
|---|---|---|
| Transitive dependencies | write it yourself | native |
| Lockfile formats | 3, hand-parsed | Go, Java, JavaScript, Python, Ruby "and much more", via a plugin system |
| Recursive filesystem scan | write it yourself | built in |
| SBOM (SPDX / CycloneDX) | write it yourself | included |

In Rust that layer is written by hand. In Go it is an import. Since layer 1 is
table stakes that must be *correct* rather than *novel*, buying it outright is
the whole argument.

## The rest of the ecosystem agrees

- **[Syft](https://pkg.go.dev/github.com/anchore/syft/syft)** (Anchore) — importable, dozens of packaging ecosystems
- **[Gitleaks](https://pkg.go.dev/github.com/zricethezav/gitleaks/v8)** — de facto standard for secret detection, importable
- **go-github** — layer 4 talks to the API directly instead of shelling out to `gh`
- **Trivy, Grype, Poutine, osv-scanner** — all Go. The tools canary might one
  day interoperate with are all in the same ecosystem.

On the Rust side, [`rustsec`](https://docs.rs/rustsec/) audits `Cargo.lock`
against the Rust advisory DB — Rust auditing Rust. There is no cross-ecosystem
equivalent. `zizmor` is Rust but ships as a binary, not a library to build on.

Rust has the better **TUI** ecosystem (ratatui). Go has the better **security**
ecosystem. This project is the second kind.

## What Go costs us

The reference project (see SPARK_ANALYSIS.md) has ~2,600 lines that looked
reusable. Module by module, most of it is replaced by something better:

| Module | LOC | Fate in Go |
|---|---|---|
| `dep_scanner` (OSV client) | 524 | Discarded anyway — it had a fatal design bug. OSV-Scalibr replaces it. **Net gain** |
| `secret_scanner` | 869 | Gitleaks replaces it, better maintained. **Net gain** |
| `history_scanner` | 212 | Gitleaks handles git history natively. **Net gain** |
| `code_patterns` | 584 | The *patterns are data* and port to any language. Only the ~300-line engine is rewritten |
| `repo_scanner` + `repo_manager` | 921 | Rewritten as `internal/discover` — the real cost, roughly one to two days |

The genuinely valuable inheritance from the reference project is not its Rust
code. It is the **design**: the ignore-file model, per-repo tagging, `--offline`,
and the shape of the audit output. Those port as decisions.

## TUI

**[Bubbletea](https://github.com/charmbracelet/bubbletea)** — ~38k ★, top 0.1%
of Go projects, in production at Microsoft Azure, AWS, NVIDIA, Cockroach Labs
and Ubuntu. With `bubbles` (components) and `lipgloss` (styling).

It uses the Elm architecture — `Init` / `Update` / `View` over a model — which
is the same shape ratatui pushes you toward, so view designs port conceptually.

**Start on v1 stable. v2 is still a Release Candidate** and a new project should
not carry RC debt in its foundation.

Alternative considered: [tview](https://github.com/rivo/tview) — more
ready-made widgets, less of a framework. Bubbletea wins on ecosystem and
maintenance.

The TUI is a **viewer over a finished report**, never the driver of a scan.
See SPARK_ANALYSIS.md for why.
