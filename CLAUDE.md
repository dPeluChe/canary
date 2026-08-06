# CLAUDE.md — canary

Context for agents working in this repo. Read this before touching code.

## What this is

A read-only supply-chain forensics CLI, in Go, that operates over a **tree of
repositories** rather than a single project. It answers: after a registry
compromise, which of my repos is affected, did CI install the bad version
inside the attack window, and did anything persist on disk?

It is **not** a general SCA tool. `osv-scanner` and `trivy` are better at that
and canary should delegate rather than compete. Read
[docs/RESEARCH/TOOLING_LANDSCAPE.md](docs/RESEARCH/TOOLING_LANDSCAPE.md) before
proposing any feature — the survey of what already exists is the reason this
project has the shape it has.

## Where it came from

canary exists because this investigation was run by hand during a live npm
supply-chain incident in August 2026, and the manual procedure turned out to
have no tool behind it. The full origin story, including which parts were
manual and why, is in [docs/JOURNAL/2608.md](docs/JOURNAL/2608.md).

Three research docs carry the decisions so you do not have to re-derive them:

- [TOOLING_LANDSCAPE.md](docs/RESEARCH/TOOLING_LANDSCAPE.md) — what exists, with sources
- [LANGUAGE_DECISION.md](docs/RESEARCH/LANGUAGE_DECISION.md) — why Go and not Rust
- [SPARK_ANALYSIS.md](docs/RESEARCH/SPARK_ANALYSIS.md) — the reference project and its one fatal bug

If you disagree with a decision, argue with the doc. Do not silently reverse it.

## Architecture

Five packages under `internal/`, one per layer, plus a viewer:

```
discover/   walk a tree → repos + lockfiles        [DONE, tested]
campaign/   load IoC lists as data                 [stub]
deps/       layer 1 — lockfiles → malicious versions  [stub]
ioc/        layer 2 — artifacts + persistence      [stub]
ci/         layer 4 — GitHub Actions × window      [stub]
verdict/    merge → per-repo answer → text/json/sarif  [stub]
tui/        optional viewer over a finished report [stub]
```

Layer 3 (static analysis of workflow files) is **delegated to `zizmor`**, not
reimplemented. It has 23 mature rules; competing with it is wasted effort.

Details: [docs/ARCHITECTURE/OVERVIEW.md](docs/ARCHITECTURE/OVERVIEW.md) ·
[docs/ARCHITECTURE/DATA_MODEL.md](docs/ARCHITECTURE/DATA_MODEL.md)

## Non-negotiable behavior

These are product invariants, not preferences. Do not add a flag that breaks
one because it seems convenient.

1. **Read-only.** No write, move, delete, quarantine or auto-fix — ever. A
   forensic tool that modifies destroys its own evidence.
2. **Campaigns are data files**, never compiled-in constants.
3. **Transitive completeness.** Any dependency check that only reads declared
   dependencies is wrong. This is the specific bug that made the reference
   project useless for this job.
4. **Artifacts carry a path scope.** A bare filename indicator produces false
   positives — see `campaign.Artifact.PathScope` and the `Math_Symbol.js` case
   documented there.
5. **Report coverage gaps explicitly.** Silent truncation that reads as
   complete coverage is the worst possible output.
6. **Never suggest blanket credential rotation.** Only on real evidence, naming
   the credential and the reason.
7. **Headless first.** The TUI views a finished report; it never drives a scan.

## Code rules

Go 1.24. Standard toolchain, no framework beyond what is listed below.

- `gofmt` clean, `go vet` clean, tests pass. That is the bar for every commit.
- **Comments: none by default.** When one is genuinely needed, write a terse
  WHY-only note — never a walkthrough, never a restatement of the code. Max
  ~3 lines. Package-level doc comments explaining a layer's *purpose and its
  trap* are the exception and are wanted.
  - BAD: eight lines narrating what the loop does.
  - GOOD: `// Longest path first so nested repos claim their lockfiles before parents do.`
- Files stay in the 400–500 LOC range. Split by responsibility past that.
- Reuse what is already here before adding a dependency or a helper.
- One pass. Do not refactor passing code that was not part of the task.
- Errors: return them, wrap with context, never `panic` outside a deliberate
  `not implemented` stub.
- Tolerate unreadable paths during a walk — skip and continue. A forensic sweep
  that aborts on one permission error is useless on a real machine.

### Planned dependencies

Add these when the layer that needs them is implemented, not before:

| Package | Layer | Why |
|---|---|---|
| `github.com/google/osv-scalibr` | deps | Google's SCA library. Handles transitives and many ecosystems. **Do not hand-write lockfile parsers.** |
| `github.com/google/go-github` | ci | Actions runs, workflow definitions, secret *names* |
| `github.com/charmbracelet/bubbletea` + `bubbles` + `lipgloss` | tui | v1 stable — v2 is still RC, do not start on it |
| `github.com/spf13/cobra` | cmd | Only once the command surface outgrows stdlib `flag` |

The CLI currently uses stdlib `flag` on purpose: the scaffold builds with zero
network access.

## Testing

`go test ./...`. Tests build fixture trees in `t.TempDir()` — never scan a real
path in a test. The discover tests are the model to follow: each one pins a
behavior that is easy to get wrong (pruning `node_modules`, nested repos
claiming their own lockfiles, orphan lockfiles).

## Conventions

- Docs: root holds only README / CLAUDE / LICENSE. Everything else in `docs/`
  under ARCHITECTURE / RESEARCH / GUIDES / JOURNAL, `UPPERCASE_SNAKE.md`.
- Tasks: `docs/TASK_TODO.md`.
- Journal: `docs/JOURNAL/YYMM.md`. Decisions and their reasons go there.
- **This file carries no history** — no PR numbers, no version numbers, no
  release dates. They rot and cost tokens in every session. State and
  instructions only.

## Scope boundary

canary is deliberately **isolated**. It is not part of any other tooling in the
author's workspace and must not grow dependencies on it. Repo-watching,
status-and-PR dashboards, and release flows belong to other projects. If a
request would couple canary to one of them, say so instead of building it.
