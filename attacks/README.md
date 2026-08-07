# attacks/

Attack attacks as data. Drop a file here and `canary` matches against it —
no rebuild, no release.

## Why this directory exists

When a registry compromise breaks, the vendor IoC list is public within hours.
The OSV `MAL-` advisory can take days. Tools that compile their package list
into source need a release per incident; canary reads this directory.

## Licensing — read before adding a file

**Vendor IoC lists are not automatically redistributable.** The Wiz Research
IoC repository, for example, publishes no LICENSE file, which means default
copyright applies. That is why no vendor CSV is vendored in this repo.

Use `scripts/fetch-attack.sh` to pull upstream lists into an untracked local
directory. Only commit an attack file here if its upstream license clearly
permits redistribution, and record the source URL in the file.

## Format

JSON, one attack per `*.json` file. Full spec and the reasoning behind JSON
over YAML: `docs/ARCHITECTURE/DATA_MODEL.md`.

```json
{
  "schema": 1,
  "id": "keyv-2026-08",
  "name": "keyv / cacheable npm compromise",
  "started": "2026-08-04T09:00:00Z",
  "source": "https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack",

  "packages": [
    { "ecosystem": "npm", "name": "keyv", "versions": ["6.0.0"] },
    { "ecosystem": "npm", "name": "cacheable-request", "versions": ["13.0.20"] }
  ],

  "artifacts": [
    { "kind": "domain", "value": "npm-cache.com", "note": "C2" },
    {
      "kind": "filename",
      "value": "Math_Symbol.js",
      "pathScope": "**/node_modules/keyv/**",
      "note": "MUST be scoped. Unscoped this matches regenerate-unicode-properties/General_Category/Math_Symbol.js, a legitimate Unicode data file."
    }
  ]
}
```

Three rules that bite:

- **`kind: filename` without `pathScope` is refused at load time.** That is the
  `Math_Symbol.js` case above, enforced rather than documented.
- **Omitting `versions` means every version of that package matches.** Correct
  for a wholly malicious package; a loud mistake anywhere else.
- **A file that fails to parse fails the whole load.** Attacks are the set
  canary matches against; a partial set produces a clean verdict that is a lie.

Subdirectories are ignored, so `fetch-attack.sh` can clone upstream repos
straight into this directory without their JSON being mistaken for attacks.

## Upstream sources

Incident-shaped (one file per compromise, with a window):

- [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) — OSV format, cross-ecosystem, the canonical feed
- [Wiz Research IoCs](https://github.com/wiz-sec-public/wiz-research-iocs) — fast during incidents, no license
- Socket, Aikido, StepSecurity — vendor advisories, usually blog-first

Corpus-shaped (cumulative, no single window — loaded as a layer-1 lookup, not
attack files; see `internal/corpus` and TOOLING_LANDSCAPE.md):

- [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) — Apache-2.0, 47k npm + 1.8k PyPI (Aug 2026), `manifest.json` per ecosystem
- [lxyeternal/pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) — 9,503 PyPI pkgs, **no license** — fetch locally, never commit
- [Backstabbers-Knife-Collection](https://github.com/dasfreak/Backstabbers-Knife-Collection) — 174 historical ground-truth pkgs (research-use license)
