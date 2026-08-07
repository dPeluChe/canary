# Data model

## Attack

A attack is one supply-chain incident, expressed as data.

```
Attack
  ID        "keyv-2026-08"
  Name      human label
  Started   attack window start, UTC
  Source    URL of the report it was built from
  Packages  []Package
  Artifacts []Artifact

Package
  Ecosystem  "npm"
  Name       "keyv"
  Versions   ["6.0.0"]

Artifact
  Kind       "domain" | "ip" | "string" | "filename" | "useragent"
  Value      the indicator
  PathScope  glob the match must sit under; empty = anywhere
  Note       why this indicator exists
```

### On-disk format: JSON

One attack per `*.json` file, in a directory. `attack.Load(dir)` reads that
directory non-recursively.

```json
{
  "schema": 1,
  "id": "keyv-2026-08",
  "name": "keyv / cacheable npm compromise",
  "started": "2026-08-04T09:00:00Z",
  "source": "https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack",
  "note": "443 packages, maintainer account compromise",

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
      "note": "unscoped this hits regenerate-unicode-properties, a legitimate Unicode data file"
    }
  ]
}
```

**Why JSON and not YAML.** Four reasons, in order of weight:

1. `encoding/json` is stdlib. A YAML library is the single dependency that
   would cost canary its "builds with zero network" property, and the planned
   dependency table in CLAUDE.md deliberately does not list one.
2. The canonical upstream feed (OpenSSF `malicious-packages`) is OSV format,
   which is JSON. The converter's input and its output share a decoder.
3. Attack files are generated, not typed. The list that mattered during the
   originating incident was 443 packages out of a CSV; YAML's authoring
   ergonomics buy little at that size.
4. canary's own dependency surface is part of its argument. A supply-chain
   forensics tool carries fewer third-party parsers than it comfortably could.

JSON's real cost is the lack of comments, which is why `note` is a schema field
on the attack and on every artifact. The *why* of an indicator travels as
data, and survives into the report.

### Field rules, and what each one prevents

| Field | Rule | Failure it prevents |
|---|---|---|
| `schema` | must equal `1` | a future format decoding as a half-empty attack |
| `id`, `name` | required | unattributable findings |
| `started` | required, RFC3339 | layers 2 and 4 have no window without it |
| `packages` / `artifacts` | at least one non-empty | an attack that can never match |
| `versions` | **omitted or empty means every version matches** | a wholly malicious package (typosquat, hijacked publish) has no safe version |
| `pathScope` | **required when `kind` is `filename`** | the `Math_Symbol.js` false positive, below |
| unknown keys | rejected | `"package"` for `"packages"` decoding to zero packages and reporting clean |

Loading is all-or-nothing. One malformed file fails the whole call rather than
returning the others, and an empty directory returns `ErrNoAttacks` instead
of an empty slice. Four attacks loaded out of five, or zero loaded silently,
both read downstream as full coverage — see invariant 5.

`pathScope` globs use `**` and are matched against paths relative to the scan
root. Note that stdlib `filepath.Match` does **not** implement `**`; the ioc
layer needs a matcher that does. Load only smoke-tests the pattern's syntax.

### Why attacks are files

When an attack breaks, the vendor IoC list (Wiz, Socket, Aikido, StepSecurity)
is public within hours. The OSV `MAL-` advisory can take days. A tool that
compiles its package list into source needs a release per incident — at least
one scanner in this space keeps its list in a TypeScript source file.

canary loads a file and runs. During the incident that started this project,
the vendor list was a CSV published the same morning.

### Why `PathScope` is mandatory in practice

The published indicator for one incident was the filename `Math_Symbol.js`.
Matched naively across a tree it hits
`regenerate-unicode-properties/General_Category/Math_Symbol.js` — a legitimate
Unicode data file present in hundreds of projects.

The real indicator was that filename **inside the compromised package's own
directory**. Same string, completely different meaning depending on path.

A bare filename artifact is a false-positive generator. Set `PathScope`.

### Two-source matching, deliberately

| Source | Strength | Weakness |
|---|---|---|
| OSV `MAL-` | authoritative, curated, cross-ecosystem | lags the incident by days |
| Local attack | available in hours | manual, incomplete, goes stale |

Neither alone is sufficient. Both are queried and results merged.

**Absence from both lists is not evidence of safety.** It is evidence of
absence from two lists. The verdict wording must not overstate this.

## Resolved

One package version present in a lockfile.

```
Resolved
  Ecosystem  "npm"
  Name       "keyv"
  Version    "4.5.4"
  Lockfile   path it came from
  Direct     declared in the manifest, vs transitive
```

`Direct` is for reporting only — **never** for filtering. Filtering on it is
precisely the bug documented in RESEARCH/SPARK_ANALYSIS.md.

## Verdict

```
Status  Clean | Suspected | Confirmed | Skipped

Repo
  Name, Slug
  Status, Reason
  MaliciousDeps  ["npm/keyv@6.0.0"]
  Artifacts      ioc matches
  CIInWindow     runs inside the window
  SecretsAtRisk  secret count reachable from those runs

Report
  Root, Attacks
  Repos []Repo
  Gaps  []string   ← what this run could NOT establish
```

`Skipped` is a first-class status, not an error. A repo with no lockfile, no
GitHub remote, or an unreadable path was **not checked**, and saying so is the
difference between a useful report and a misleading one.

`Gaps` carries what the whole run could not establish — no token so layer 4 was
skipped, `--offline` so OSV was not queried, other machines not reachable.
Printing them is mandatory. Silent truncation that reads as full coverage is
the worst possible output.
