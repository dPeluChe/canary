# TASK_TODO

Ordered so each step is provable before the next depends on it.

## Done

- [x] `internal/discover` — tree walk, repo attribution, orphan lockfiles, tests
- [x] Scaffold: module, CLI skeleton, exit-code contract, docs
- [x] On-disk attack format: **JSON, schema 1**, documented in
      ARCHITECTURE/DATA_MODEL.md
- [x] `attack.Load` + tests — all-or-nothing loading, `ErrNoAttacks`,
      unknown keys rejected, unscoped `filename` artifacts refused
- [x] `canary attacks` / `canary attacks <id>`
- [x] Attack dir resolution: `-dir`, `$CANARY_ATTACK_DIR`, repo-local
      `attacks/`, `~/.canary/attacks`. Every run prints which directory it read
      and which source chose it; an explicit dir that is missing errors instead
      of falling through to another one
- [x] `canary import` — converter from the vendor CSV shape. Verified on
      the real Wiz list: 446 packages, round-tripped back through Load
- [x] Wire `google/osv-scalibr` for extraction (npm family: package-lock,
      npm-shrinkwrap, yarn, pnpm, bun.lock). Other kinds return an explicit
      unsupported error, never an empty result
- [x] **Transitive completeness proven**: 791 resolved against 26 declared in
      the fixture, and the test was verified to go red when extraction is
      replaced with spark's manifest-based model. Real lockfiles: 288 from 26
      declared, 956 from 68

## Next — Layer 1, deps

- [ ] Match resolved packages against loaded attacks (offline path)
- [ ] Populate `Resolved.Direct` — scalibr reports dep *groups*, not whether the
      manifest declared it. Reporting only, never filtering
- [ ] Extractors for the non-npm lockfile kinds discover already finds
      (Cargo.lock, go.sum, requirements.txt, poetry.lock, Gemfile.lock, …)
- [ ] Query OSV.dev for `MAL-` + CVE (online path), batched
- [ ] **Self-validation mode**: re-run the match ignoring versions, to prove the
      extractor can see a package family at all. A negative from an unvalidated
      parser is worthless — see JOURNAL/2608.md

## attacks as the multi-source centre

Decided: several sources, not one. Each entry carries **provenance** (which
source called it malicious), and every run prints which sources it reached —
an unreachable source is a gap, never a silence.

- [ ] `canary update` — explicit refresh. Never automatic on a read command:
      a network call as a side effect costs reproducibility, and forensics has
      to be able to say "I scanned against exactly this list"
- [ ] Source adapter: **OSV.dev** `querybatch` (free, authoritative, lags days)
- [ ] Source adapter: **OpenSSF malicious-packages** (Apache, clonable, OSV format)
- [ ] Source adapter: **Cobenian/shai-hulud-detect** (MIT, 5,752 `name:version`,
      actively maintained — correct TOOLING_LANDSCAPE, which implies otherwise)
- [ ] Staleness surfaced in `canary attacks`: age per source, loud when old
- [ ] Vendor CSVs stay manual via `canary import` — no licence to redistribute

Not adapters, deliberately: Socket (service with auth, not a list) and the other
scanners surveyed in TOOLING_LANDSCAPE. Consuming a data source is cheap and
uncoupled; invoking another tool couples canary to its CLI, output format and
failure modes. `zizmor` stays the one exception, because it contributes
*analysis*, not data.

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
      the verdict. Re-resolving 485 lockfiles to test one new attack is
      wasted work — and `watch` mode below depends on this artifact existing

## Layer 3 — delegation

- [ ] Shell out to `zizmor` when present; record a `Gap` when absent

## watch mode

Decided in scope. `canary watch` polls the **threat feeds**, not the
filesystem — the asymmetry that makes it cheap is that your tree changes slowly
while the attack list changes daily. A tree that scanned clean today is not
clean tomorrow, because tomorrow's attack was not published yet.

```
canary watch --interval 6h
  1. poll OSV MAL- / OpenSSF malicious-packages / vendor lists
  2. new attack? → match against the ALREADY-RESOLVED inventory
  3. hit → alert.  no hit → stay silent
```

Step 2 is milliseconds because it reads `.canary/inventory.json` instead of
re-walking. That artifact is the prerequisite — see the verdict section.

- [ ] Feed pollers with etag/since handling
- [ ] Match new attacks against the cached inventory
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

- [ ] TUI viewer (bubbletea v1), `canary view [report.json]` — two screens:
      finished reports, and an attack-catalogue browser (446 packages is an
      unreadable terminal dump). Viewer only: it never drives a scan
- [ ] Gitleaks integration for secrets
- [ ] Ignore-file support (spark's `.sparkauditignore` model)
- [ ] Per-repo tags to scope sweeps (own repos vs third-party clones)
- [ ] Concurrency: fan out per repo, bound network layer separately
- [ ] `cobra` once the command surface outgrows stdlib `flag`
- [ ] Release: goreleaser, brew tap, binaries

## Open questions

- ~~Attack format: YAML vs JSON?~~ **Resolved: JSON.** Rationale in
  ARCHITECTURE/DATA_MODEL.md.
- Should attacks be vendored in-repo at all, or always fetched? Upstream
  vendor lists have unclear licensing — the Wiz IoC repo publishes none.
- Does an attack need a window **end**? `Started` alone means the window runs
  to now, which is the conservative reading and is what layers 2 and 4 will do
  today. A closed window would tighten mtime evidence for an incident already
  contained. Not added unilaterally — it is a DATA_MODEL change.
