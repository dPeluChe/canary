# campaigns/

Attack campaigns as data. Drop a file here and `canary` matches against it —
no rebuild, no release.

## Why this directory exists

When a registry compromise breaks, the vendor IoC list is public within hours.
The OSV `MAL-` advisory can take days. Tools that compile their package list
into source need a release per incident; canary reads this directory.

## Licensing — read before adding a file

**Vendor IoC lists are not automatically redistributable.** The Wiz Research
IoC repository, for example, publishes no LICENSE file, which means default
copyright applies. That is why no vendor CSV is vendored in this repo.

Use `scripts/fetch-campaign.sh` to pull upstream lists into an untracked local
directory. Only commit a campaign file here if its upstream license clearly
permits redistribution, and record the source URL in the file.

## Format

Not finalized — see `docs/TASK_TODO.md`. The shape is defined by
`internal/campaign.Campaign` and documented in
`docs/ARCHITECTURE/DATA_MODEL.md`.

Sketch:

```yaml
id: keyv-2026-08
name: keyv / cacheable npm compromise
started: 2026-08-04T09:00:00Z
source: https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack

packages:
  - ecosystem: npm
    name: keyv
    versions: ["6.0.0"]
  - ecosystem: npm
    name: cacheable-request
    versions: ["13.0.20"]

artifacts:
  - kind: domain
    value: npm-cache.com
    note: C2
  - kind: filename
    value: Math_Symbol.js
    pathScope: "**/node_modules/keyv/**"
    note: >
      MUST be scoped. Unscoped this matches
      regenerate-unicode-properties/General_Category/Math_Symbol.js,
      a legitimate Unicode data file.
```

## Upstream sources

- [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) — OSV format, cross-ecosystem, the canonical feed
- [Wiz Research IoCs](https://github.com/wiz-sec-public/wiz-research-iocs) — fast during incidents, no license
- Socket, Aikido, StepSecurity — vendor advisories, usually blog-first
