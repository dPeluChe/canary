# Data model

## Campaign

A campaign is one supply-chain incident, expressed as data.

```
Campaign
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

### Why campaigns are files

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
| Local campaign | available in hours | manual, incomplete, goes stale |

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
  Root, Campaigns
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
