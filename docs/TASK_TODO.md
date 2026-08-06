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

## Layer 3 — delegation

- [ ] Shell out to `zizmor` when present; record a `Gap` when absent

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
- Is there a useful `canary watch` mode, or does that belong to a different
  tool entirely? (Leaning: different tool. Keep the scope boundary.)
