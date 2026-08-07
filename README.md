# canary

Read-only supply-chain forensics for **trees of repositories**.

You have a folder with 80 repos in it. A registry gets compromised at 09:00 UTC.
Which of your projects is affected, which CI runner installed the bad version,
and did anything persist? `canary` answers that in one pass.

> **Status: early scaffold.** `discover` and the attack data layer work. The
> four scanning layers are designed and stubbed. See
> [docs/TASK_TODO.md](docs/TASK_TODO.md).

```
canary discover ~/code            # inventory: repos + lockfiles
canary attacks list               # known attacks canary can match against
canary attacks show keyv-2026-08  # one attack in full
canary attacks import -csv keyv.csv -id keyv-2026-08 \
  -name 'keyv npm compromise' -started 2026-08-04T09:00:00Z \
  > attacks/keyv-2026-08.json     # vendor CSV → attack file, on stdout
canary scan ~/code --since 2026-08-04T09:00:00Z
```

An *attack* is the attacker's, not yours: one registry compromise expressed as
a data file — its window, the package versions it poisoned, and the traces it
leaves on disk. You run scans **against** them. New attacks are published
constantly, which is why they are files you drop in rather than constants
compiled into a release.

## Why this exists

There are good tools for pieces of this. There is nothing that does the whole
thing over a tree of repos and hands you a verdict per repo.

| Layer | What it answers | Prior art |
|---|---|---|
| 1. **deps** | Does any lockfile pin a known-malicious version? | `osv-scanner`, `shai-hulud-detect` do this well |
| 2. **ioc** | Are the attack's artifacts on disk? Did anything install persistence? | **almost nobody** |
| 3. **workflows** | Are the CI workflows themselves insecure? | `zizmor` does this well — canary delegates |
| 4. **ci window** | Did a runner install deps during the attack window, with secrets in reach? | **nobody** |

Layers 2 and 4 are the reason for the project. Layer 1 is table stakes that has
to be correct anyway. Layer 3 is someone else's solved problem.

Full survey with sources: [docs/RESEARCH/TOOLING_LANDSCAPE.md](docs/RESEARCH/TOOLING_LANDSCAPE.md).

## Design rules

These are not style preferences. Each one comes from a specific failure
observed while doing this investigation by hand.

**Read-only. Always.** There is no `--fix`, no `--remediate`, no quarantine.
A forensic tool that modifies destroys the evidence it was sent to collect.
At least one scanner in this space ships `--remediate`; that is a good reason
not to run it.

**Attacks are data, not code.** When an attack breaks, the vendor IoC list is
public in hours while the OSV `MAL-` advisory can take days. Tools that compile
their package list into source need a release per incident. `canary` loads a
file.

**Transitive completeness or nothing.** Supply-chain attacks land in transitive
dependencies. A scanner that reads declared dependencies from a manifest finds
zero. See [docs/RESEARCH/SPARK_ANALYSIS.md](docs/RESEARCH/SPARK_ANALYSIS.md) for
a worked example of exactly this bug in a real tool.

**Headless first, TUI second.** The core is a library, the CLI has exit codes
and JSON/SARIF, and the TUI is an optional viewer over a finished report. It
never drives a scan.

**A clean result is one line.** A long report concluding "nothing happened" is
worse than a short one that says so. Negatives state what was checked, so
absence of evidence is distinguishable from absence of checking. Coverage gaps
are printed, never silently dropped.

**Never recommend blanket credential rotation.** Only on real evidence, naming
the specific credential and why. Rotating everything "just in case" costs hours
and burns trust.

## Install

Not published yet.

```
go build -o canary ./cmd/canary
```

## License

MIT
