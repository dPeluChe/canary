# Tooling landscape

Survey done August 2026, while responding to a live npm supply-chain incident.
The question was: **does a tool already do this, and if so, should we just use it?**

Answer: for two of the four layers, yes — use them. For the other two, nothing
exists. That gap is the whole reason canary exists.

Re-read this before proposing a feature. Several obvious ideas are already
solved better elsewhere.

---

## Layer 1 — lockfiles against known-malicious versions

**Mature. Do not compete; delegate or reuse the library.**

### [osv-scanner](https://github.com/google/osv-scanner) — Google, ~10.7k ★

- `osv-scanner scan source -r <dir>` walks a directory tree
- Consumes **`MAL-` advisories** from the [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages)
  feed (~35k reports as of Aug 2025) — *confirmed malicious*, not merely
  *vulnerable*. `npm audit` has no such distinction. This is the single most
  useful data source in the space.
- Offline mode with a downloaded database
- Built on **[OSV-Scalibr](https://pkg.go.dev/github.com/google/osv-scalibr)**,
  which is importable as a Go library — see LANGUAGE_DECISION.md
- **Weakness:** depends on the advisory already being published. During the
  first hours of an incident the vendor IoC list is out and OSV is not.

### [Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect) — ~397 ★, bash, MIT

The closest existing thing to canary's layer 1, and worth reading before
implementing:

- `--bulk` auto-discovers projects under parent directories — the tree case
- Cross-checks manifests *and* lockfiles against 5,699 known-bad versions
  across npm, PyPI, Composer, Crates, Go, Hex, RubyGems
- Also matches malicious file hashes, C2 domains, malicious workflow files
- **Read-only by design** — "the script never modifies, deletes, or quarantines
  anything." Same posture canary takes.
- Package list maintained by PR, citing Socket / StepSecurity / Aikido

**Re-checked August 2026 — it is also a data source, and canary should consume
it.** `compromised-packages.txt` is a plain `name:version` list, 5,752 entries
spanning several campaigns from September 2025, under **MIT**, with commits
within the last day. MIT matters: unlike the vendor CSVs, whose licensing is
unstated, this list can be redistributed and derived from. It is wired as a
source adapter — see TASK_TODO. Note this is a *list*, not a tool canary
invokes; the difference is the whole point of the section below.

### Others worth knowing

- **[safedep/vet](https://github.com/safedep/vet)** — policy as CEL, malware
  detection, free for open source
- **[Socket CLI](https://docs.socket.dev/docs/faq)** — 70+ alert categories,
  free unlimited for open source, `safe npm` install wrapper
- **[Syft](https://pkg.go.dev/github.com/anchore/syft/syft)** — Anchore,
  importable Go library, dozens of packaging ecosystems, SBOM-first
- **Trivy / Grype** — broader (containers, IaC, filesystems); overkill here

### Incident-response scanners: check the numbers first

A wave of single-incident scanners appears after every attack. Most are
abandoned within weeks. Verify before trusting:

- [digi4care/shai-scan](https://github.com/digi4care/shai-scan) — **0 ★, 10 commits.**
  Notable only for being the one tool that mentions *persistence hooks in
  Claude Code and VS Code*. That it is unmaintained says the problem is
  recognized but unserved.
- [Cloudsek-Engineering/shai-hulud-scanner](https://github.com/Cloudsek-Engineering/shai-hulud-scanner)
  — **1 ★**, Python, and ships `--remediate`. A forensic tool that modifies is
  a tool that destroys evidence. Do not model anything on it.
- [mathiscode/codebase-scanner](https://github.com/mathiscode/codebase-scanner) — 44 ★, signature-based, MIT

---

## Layer 2 — filesystem artifacts and persistence

**Essentially unserved. This is canary's first differentiator.**

The 2026 npm attacks moved past credential theft into persistence in developer
tooling: Claude Code hooks, VS Code `tasks.json`, shell profiles, git hooks.

`shai-hulud-detect` covers hashes, C2 domains and workflow files.
`shai-scan` claims agent-hook persistence but is unmaintained. The mainstream
SCA tools do not look at this at all — it is outside their model, which is
"packages", not "what the package did to this machine."

### The false-positive lesson

During the incident that started this project, the published indicator was a
filename. Matching it naively hit
`regenerate-unicode-properties/General_Category/Math_Symbol.js`, a legitimate
Unicode data file. The real indicator was that filename **inside the compromised
package's own directory**.

This is why `attack.Artifact` carries a `PathScope`. A bare filename
indicator is a false-positive generator.

---

## Layer 3 — static analysis of CI workflows

**Mature. Delegate, do not reimplement.**

- **[zizmor](https://docs.zizmor.sh/audits/)** — 23 rules across 10 weakness
  classes, the widest coverage; has autofix. Rust.
- **[poutine](https://github.com/boostsecurityio/poutine)** — 121 known-vulnerable-component rules
- **gato-x** — offensive enumeration

Comparative study: [Unpacking Security Scanners for GitHub Actions Workflows](https://arxiv.org/html/2601.14455v2).

All three answer *"is this workflow insecure?"*. None answer *"did this
workflow run during the attack window?"* — which is layer 4.

---

## Layer 4 — CI activity correlated with the attack window

**Nothing exists. This is canary's main differentiator.**

The question that matters most after a registry compromise:

> A developer's laptop can be verified clean while a CI runner installed the
> same dependency tree and exfiltrated repository secrets, leaving no local
> trace at all.

The closest thing is
**[StepSecurity Harden-Runner](https://docs.stepsecurity.io/workspace/detections)**,
which detects exfiltration in real time — including a process reading the
`Runner.Worker` memory, a signal with very low false-positive rate. But it is
preventive and SaaS: if it was not installed before the attack, it is useless
afterward.

GitHub documents the manual path:
[audit log filtered on `programmatic_access_type`](https://docs.github.com/en/code-security/reference/security-incident-response/investigation-areas),
plus watching for `register_self_hosted_runner` events.

The manual procedure canary automates, per repo:

1. `gh run list` → runs inside the window
2. read the workflow → did the job install dependencies, and with what command
3. `gh secret list` → what was reachable from that job
4. cross-reference with layer 1: was a malicious version actually resolved?

A run inside the window is **not** a finding on its own. It only becomes
material when a malicious version was present *and* secrets existed. Reporting
runs alone produces alarm without information.

---

## Additional consumable lists

Re-checked August 2026. These are consumable *data* sources (lists/feeds),
not tools to invoke — the same distinction as shai-hulud-detect's
`compromised-packages.txt`. Each is a candidate source adapter; none is a
scanner canary would shell out to.

### [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) — ~371 ★, Apache-2.0

The largest redistributable corpus found. Counted directly from the manifests
on 7 Aug 2026: **47,306 npm and 1,833 PyPI packages**, plus IDE extensions and
AI Skills. Human-vetted, mostly surfaced by
[GuardDog](https://github.com/DataDog/guarddog). Verify the count rather than
quoting it — it grows, and an out-of-date figure in a doc reads as precision it
does not have.
Ecosystems: npm, PyPI, IDE extensions, AI Skills. Each ecosystem subdir ships a
`manifest.json` — a `map[name][]versions` where `null` means "every version is
malicious", which is 99% of PyPI entries (1,816 of 1,833): a typosquat has no
safe version. Apache-2.0 means it can be redistributed and derived from, unlike
the vendor CSVs.

Note the subdirectory names are inconsistent upstream — `ai-skills` with a
hyphen, `ide_extensions` with an underscore. `internal/corpus` accepts both,
and has a test pinning the real names: an unmapped subdir is deliberately
fatal, so guessing one spelling fails the entire load.

**It is a cumulative corpus, not an incident.** Forcing it into the on-disk
`Attack` format would break the one-incident-one-window model: layers 2 and 4
key off `Started`, and a years-spanning corpus has no single forensic window.
It belongs as a **corpus source** for layer 1 (an offline `IsMalicious`
lookup alongside the OSV.dev online path), not as a converted attack file.
See `internal/corpus`.

### [lxyeternal/pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) — ~129 ★, **NO LICENSE**

**10,823 versions of 9,503 malicious PyPI packages**, from the ASE 2023 paper
"An Empirical Study of Malicious Code In PyPI Ecosystem" (Guo et al., extended
in USENIX Security 26). Heavy on typosquats. PyPI-only. Same
corpus-not-incident caveat as DataDog.

**Licensing checked 7 Aug 2026: there is no LICENSE file and the README does
not state a licence.** An earlier draft of this section called it CC0; that was
wrong. Default copyright applies, exactly as with the Wiz IoC repository — see
`attacks/README.md`. It may be fetched and used locally, never vendored into
this repo or redistributed.

### [Backstabbers-Knife-Collection](https://github.com/dasfreak/Backstabbers-Knife-Collection) — academic, npm/PyPI/RubyGems

174 malicious packages from real-world attacks, Nov 2015 – Nov 2019, manually
collected and analyzed (Ohm et al., DIMVA 2020). Small and historical, but the
ground-truth baseline every detection paper since has measured against. Useful
as a **self-validation fixture**: a scanner that misses these is wrong, full
stop. License is research-use; verify before redistributing.

### [Safeguard threat feed](https://safeguard.sh/threat-feed) — free, multi-format

A public feed of high-severity supply-chain CVEs, malicious-package alerts
(npm, PyPI, Maven, NuGet, crates.io), and exploit-availability changes. Ships
as RSS, JSON, and **STIX 2.1** indicator bundles — the STIX form is the one a
SIEM/TIP would ingest. 90-day rolling window, <5 min lag from upstream. A
candidate for the `watch` mode poller (TASK_TODO), not a one-shot fetch.

### GitHub Advisory Database — malware, 8 ecosystems

Not a separate feed: GitHub ingests OpenSSF malicious-packages into its
Advisory Database and now flags malware across **npm, PyPI, Maven, RubyGems,
NuGet, Go, crates.io, PHP Composer** ([GitHub Blog](https://github.blog/security/supply-chain-security/how-we-took-malware-advisories-beyond-npm/)).
Worth noting because it widens the OSV `MAL-` surface beyond npm for any tool
that already queries OSV.dev — canary's planned OSV adapter inherits this for
free. [PyRank](https://pyrank.org/advisories/) is a daily-refreshed catalogue
over the same OSV data (~10k PyPI advisories), useful as a browsing UI.

### Incident-specific forks worth tracking

The shai-hulud-detect family keeps forking per incident. Apply the rule from
"Incident-response scanners: check the numbers first" above before trusting any
of them — it exists precisely for this category.

- [otaviomarcal/npm-supply-chain-detector](https://github.com/otaviomarcal/npm-supply-chain-detector)
  — fork tracking Sept 2025 → Aug 2026 campaigns (chalk/debug, axios takeover,
  keyv/cacheable, SANDWORM_MODE), 5,100+ malicious versions, MIT.
  **0 ★ as of 7 Aug 2026.** By this document's own standard that is not a
  source to depend on: an unreviewed fork is one maintainer's judgement with
  nobody checking it. Listed for awareness, deliberately NOT wired as an
  adapter. If its extra versions matter, the correct move is to get them
  upstreamed into shai-hulud-detect, which is reviewed by PR.
- [Securest8/npm-incident-response](https://github.com/Securest8/npm-incident-response)
  — keyv/cacheable-specific, but documents the **persistence vectors**
  (`.claude/settings.json` `SessionStart`, `.vscode/tasks.json` `folderOpen`)
  that layer 2 must sweep. Read for the IoC shape, do not model the tool.

### What is NOT a list

[homeofe/supply-chain-guard](https://github.com/homeofe/supply-chain-guard)
and [safedep/vet](https://github.com/safedep/vet) are scanners (350+ and
policy-CEL rules respectively), not consumable data. They belong in the
"others worth knowing" tier of layer 1, not in the source-adapter list.
Consuming a data source is cheap and uncoupled; invoking a scanner couples
canary to its CLI and failure modes. `zizmor` stays the one exception because
it contributes *analysis*, not data.

---

## Vendor advisories as a data source

Vendors publish per-incident advisories, not consumable feeds:

- [Vercel — npm supply chain attack response, Sep 2025](https://vercel.com/blog/critical-npm-supply-chain-attack-response-september-8-2025)
- [Vercel — s1ngularity / Nx](https://vercel.com/changelog/s1ngularity-supply-chain-attack-in-nx-packages)
- [Vercel — axios compromise](https://vercel.com/changelog/axios-package-compromise-and-remediation-steps)

What they *do* is more interesting than what they publish: block egress to C2
hostnames from build infrastructure, refuse the affected packages in new
builds, purge build caches of affected projects. Platform-level control, not
consumable from outside.

The consumable feed is OSV `MAL-`. Vendors — Wiz, Socket, Aikido,
StepSecurity — are upstream of it, which is exactly the lag canary's campaign
files are designed to cover.

---

## Not verified

**Reddit.** Direct fetches of reddit.com were blocked from the research
environment, and `site:reddit.com` searches returned aggregator pages rather
than threads. There is **no verified community sentiment** in this document —
everything above comes from repos, vendor blogs and documentation. If community
consensus matters for a decision, it still needs to be gathered.
