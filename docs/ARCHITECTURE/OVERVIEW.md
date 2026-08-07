# Architecture

## Shape

```
        ┌──────────────────────────────────────────────┐
        │  discover — walk tree → repos + lockfiles    │  DONE
        └───────────────────┬──────────────────────────┘
                            │
     ┌──────────────┬───────┴───────┬──────────────────┐
     ▼              ▼               ▼                  ▼
 ┌────────┐   ┌──────────┐   ┌────────────┐   ┌────────────────┐
 │ deps   │   │   ioc    │   │ workflows  │   │  ci (window)   │
 │ L1     │   │   L2     │   │ L3 →zizmor │   │  L4            │
 └────┬───┘   └────┬─────┘   └─────┬──────┘   └────────┬───────┘
      └────────────┴───────┬───────┴───────────────────┘
                           ▼
                 ┌──────────────────┐
                 │     verdict      │  per repo → text / json / sarif
                 └────────┬─────────┘
                          ▼
                    ┌──────────┐
                    │   tui    │  optional viewer, never drives
                    └──────────┘

        attack — IoC data files, feeds deps + ioc
```

## Layers

### discover — **implemented**

Walks a root, finds git repos (by `.git`), attributes every lockfile to its
nearest enclosing repo, and reports lockfiles outside any repo as orphans.

Reads `origin` from `.git/config` directly rather than shelling out to `git`:
across hundreds of repos that is hundreds of processes.

Prunes `node_modules`, `target`, `dist`, `build`, `.next`, `vendor`, `venv` and
friends — installed and built output is not a declaration. **The `ioc` layer
opts back into `node_modules` deliberately**, because that is exactly where a
dropped payload lives.

Verified against a real tree: 320 repos, 485 lockfiles.

### attack — IoC data

A attack is one incident: its window, its malicious package versions, its
filesystem and network artifacts, and the URL of the report it came from.

Loaded from files. Never compiled in. This is the difference between responding
to an incident in an hour and waiting for a release. See DATA_MODEL.md.

### deps — layer 1

Resolve every package version a lockfile pins — **including transitive and
nested entries** — then check against two sources:

1. **OSV.dev** — `MAL-` advisories plus CVEs. Authoritative, lags an incident.
2. **Local attacks** — vendor lists, available in hours.

Extraction delegates to `google/osv-scalibr`. Do not hand-write parsers; that
is exactly the mistake documented in RESEARCH/SPARK_ANALYSIS.md.

### ioc — layer 2

Sweep the filesystem for attack artifacts (C2 domains, embedded strings,
dropped filenames) and check the persistence targets modern malware writes to:
Claude Code hooks and settings, VS Code `tasks.json`, shell profiles, git hooks.

Each target is checked for **both** known-bad content **and** modification
inside the forensic window. An untouched file with an old mtime is a strong
negative; content alone is not.

Artifacts must carry a path scope — see DATA_MODEL.md for the false-positive
that motivated it.

### workflows — layer 3, delegated

Static analysis of workflow files goes to `zizmor` (23 rules). canary shells
out and folds the result into the verdict rather than reimplementing it.

### ci — layer 4

Per repo with a GitHub remote, for a given window:

1. workflow runs created inside the window
2. whether the job installed dependencies, and with what command
3. secret **names** available to that job (never values), plus whether
   org-level secrets could be injected

A run in the window is not a finding by itself. It becomes material only when
crossed with layer 1: a malicious version actually resolved *and* secrets
existed. Runs alone produce alarm without information.

### verdict

Merges everything into one status per repo — Clean / Suspected / Confirmed /
Skipped — and renders text, JSON or SARIF.

Output contract, from doing this by hand:

- CONFIRMED and SUSPECTED never interleave
- A clean result is one line
- Negatives state what was checked
- **Coverage gaps are printed**, never silently dropped

### tui

Bubbletea viewer over a finished `verdict.Report`. Headless is the product; the
TUI is a convenience.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | clean |
| 1 | findings present |
| 2 | canary itself failed |

Part of the contract — CI and cron branch on them.

## Concurrency

Not yet implemented. When it is: `discover` is sequential and cheap; `deps`,
`ioc` and `ci` fan out per repo. `ci` is network-bound and must respect GitHub
rate limits — bound it separately from the CPU-bound layers.
