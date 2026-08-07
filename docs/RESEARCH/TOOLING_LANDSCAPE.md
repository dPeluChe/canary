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
