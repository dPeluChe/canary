# TASK_TODO

Ordered so each step is provable before the next depends on it.

## Done

- [x] `internal/discover` — tree walk, repo attribution, orphan lockfiles, tests
- [x] Scaffold: module, CLI skeleton, exit-code contract, docs

## Next — campaign loading

- [ ] Define the on-disk campaign format (YAML or JSON — pick one, document it
      in ARCHITECTURE/DATA_MODEL.md)
- [ ] `campaign.Load` + tests
- [ ] `scripts/fetch-campaign.sh` → converter from the Wiz CSV shape to that format
- [ ] `canary campaign list` / `canary campaign show <id>`

## Layer 1 — deps

- [ ] Wire `google/osv-scalibr` for extraction
- [ ] **Prove transitive completeness first**: assert the extractor returns
      hundreds of packages for a lockfile whose manifest declares ~26. This is
      the bug that killed the reference project — pin it with a test before
      building on top
- [ ] Match against loaded campaigns (offline path)
- [ ] Query OSV.dev for `MAL-` + CVE (online path), batched
- [ ] **Self-validation mode**: re-run the match ignoring versions, to prove the
      extractor can see a package family at all. A negative from an unvalidated
      parser is worthless — see JOURNAL/2608.md

## Layer 2 — ioc

- [ ] Artifact sweep with `PathScope` honored
- [ ] Opt back into `node_modules` for this layer only
- [ ] Persistence targets: Claude Code settings + hooks, VS Code `tasks.json`,
      shell profiles, git hooks (global and per repo)
- [ ] Check content **and** mtime against the window; report them separately

## Layer 4 — ci

- [ ] `go-github`: runs in window per repo
- [ ] Parse workflow definitions for the install command
- [ ] Secret **names** per repo; detect org-level secret injection
- [ ] Cross-reference with layer 1 — do not report a run as a finding on its own
- [ ] Handle rate limits and missing-token gracefully → `Skipped` + a `Gap`

## verdict

- [ ] Merge layers into per-repo status
- [ ] Text renderer honoring the output contract (clean = one line)
- [ ] JSON renderer
- [ ] SARIF renderer
- [ ] Exit codes wired
- [ ] **Persist the resolved inventory** to `.canary/inventory.json`, not just
      the verdict. Re-resolving 485 lockfiles to test one new campaign is
      wasted work — and `watch` mode below depends on this artifact existing

## Layer 3 — delegation

- [ ] Shell out to `zizmor` when present; record a `Gap` when absent

## watch mode

Decided in scope. `canary watch` polls the **threat feeds**, not the
filesystem — the asymmetry that makes it cheap is that your tree changes slowly
while the campaign list changes daily. A tree that scanned clean today is not
clean tomorrow, because tomorrow's attack was not published yet.

```
canary watch --interval 6h
  1. poll OSV MAL- / OpenSSF malicious-packages / vendor lists
  2. new campaign? → match against the ALREADY-RESOLVED inventory
  3. hit → alert.  no hit → stay silent
```

Step 2 is milliseconds because it reads `.canary/inventory.json` instead of
re-walking. That artifact is the prerequisite — see the verdict section.

- [ ] Feed pollers with etag/since handling
- [ ] Match new campaigns against the cached inventory
- [ ] Alert sink (stdout / exit code first; anything else later)
- [ ] Staleness guard: refuse to stay silent on an inventory older than N days,
      since a silent watch over a stale inventory is worse than no watch

**Explicitly out of scope**, both are different products:

- *Install-time interception* (wrapping `npm install` to vet before execution).
  Socket's `safe npm` does this; it would couple canary to every package
  manager.
- *Live persistence monitoring* (a daemon watching `~/.claude/hooks/` and
  `tasks.json` for writes). That is an EDR, with a completely different risk
  profile — something resident with access to `$HOME` is not the same kind of
  thing as a binary that runs and exits.

## Later

- [ ] TUI viewer (bubbletea v1)
- [ ] Gitleaks integration for secrets
- [ ] Ignore-file support (spark's `.sparkauditignore` model)
- [ ] Per-repo tags to scope sweeps (own repos vs third-party clones)
- [ ] Concurrency: fan out per repo, bound network layer separately
- [ ] `cobra` once the command surface outgrows stdlib `flag`
- [ ] Release: goreleaser, brew tap, binaries

## Open questions

- Campaign format: YAML (readable, needs a dep) vs JSON (stdlib, noisier)?
- Should campaigns be vendored in-repo at all, or always fetched? Upstream
  vendor lists have unclear licensing — the Wiz IoC repo publishes none.
