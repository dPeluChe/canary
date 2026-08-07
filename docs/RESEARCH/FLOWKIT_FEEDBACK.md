# flowkit / lefthook — field report

Running notes from using flowkit inside canary. Written to be handed to the
flowkit dev, so every entry is reproducible and says what was expected, what
happened, and what would fix it.

This doc lives here only because canary is where the observations happened. It
is **not** a dependency: nothing in canary's code or build reads it, and the
scope boundary in CLAUDE.md still holds.

Environment: flowkit 0.1.32 (fe1cc5c) · lefthook 2.1.10 · gitleaks 8.30.1 ·
macOS · Go repo, solo → team mode.

Severity: **S1** silently weakens a guarantee · **S2** costs real time or
produces a wrong belief · **S3** friction.

---

## S1 — `lefthook-local.yml` alone is inert, and nothing says so

**The one that matters.** After `flowkit hooks --team`, the repo held both
`lefthook.yml` (from solo mode) and `lefthook-local.yml`, byte-identical.
Deleting the apparent duplicate looked like cleanup.

```
$ rm lefthook.yml && flowkit hooks --verify
x jobs: pre-commit resolves 0 jobs -- only personal overlay present
x canary: shape(s) passed the effective pre-commit hook UNSEEN:
    dpat aws postgres-uri sentry-dsn iteris-token generic-high-entropy
```

All six central secret rules went from *blocked* to *unseen* while the hooks
still looked installed. Lefthook merges an overlay onto a base; with no base
there is nothing to merge onto.

The failure mode is the dangerous kind: `git status` clean, hooks present,
commits succeeding, zero secret scanning.

**Fix, in order of value:**

1. `flowkit hooks --team` should end by stating that `lefthook.yml` is the
   **base and must be committed**, and offer to `git add` it. Today it writes
   the overlay and leaves the base untracked, which is the one configuration
   where a fresh clone gets no hooks at all.
2. `flowkit unhook` and any cleanup path should refuse to remove
   `lefthook.yml` while `lefthook-local.yml` exists, or remove both.
3. The verify message is already excellent — it names the exact cause. Worth
   surfacing the same sentence *preemptively* in `--team` output.

## S1 — `--team` detects the unportable agent import but does not move it

`flowkit hooks --team` printed:

```
-> committed CLAUDE.md already imports FLOW_CLAUDE.md -- consider moving that
   line to CLAUDE.local.md (machine-local path, not portable)
```

…and then did nothing. The whole point of `--team` is portability, and this is
the single most unportable thing in the repo: `@~/.agents/skills/FLOW_CLAUDE.md`
resolves on one machine, so every other contributor gets a broken import in
every agent session.

Detecting it and leaving it is the worst of the three options — the operator
now has a warning they must act on manually, in a command whose job was exactly
that.

**Fix:** in `--team`, move the line to `CLAUDE.local.md` and add it to
`.git/info/exclude` (both of which flowkit already knows how to do). If moving
a committed file's content is considered too invasive, make it a prompt, not a
note. Doing it by hand took three steps that the tool could not get wrong.

## S2 — `flowkit about` reports "untracked" as a neutral fact

```
hooks mode:      lefthook.yml (untracked)
```

Read cold, that is a mode label. It is actually a statement that a fresh clone
of this repo has **no hooks**. Same for the `.gitleaks-baseline.json` left
untracked and *not* excluded in solo mode — permanent `git status` noise, and
one distracted `git add -A` from being committed.

**Fix:** `about` should qualify it — `lefthook.yml (untracked — a fresh clone
gets no hooks; commit it or run flowkit hooks --team)`. Solo mode should also
add its own artifacts to `.git/info/exclude`, the way team mode already does
for the baseline.

## S2 — `hooks --verify` fails identically for "not wired" and "cache cold"

First run in this repo reported FAILED. The repo *was* wired; lefthook simply
had not fetched the remotes cache yet. Running any lefthook command populated
it and verify passed with no configuration change.

The reported failure sent me looking for a wiring problem that did not exist.

**Fix:** distinguish the two. If the config references remotes but the cache is
absent, say so and name the command that populates it, rather than reporting
the same FAILED as an unwired repo.

## S2 — the suggested Go lint command is a false green

`about` suggests `lint: go vet ./...`, and the ship-config template comments
suggest the same. That silently drops formatting, which for Go is normally part
of the same bar.

Worse, the obvious fix is a trap: **`gofmt -l` exits 0 even when it lists
unformatted files.** `gofmt -l . && go vet ./...` looks like a formatting gate
and enforces nothing.

What actually works, now in canary's ship config:

```yaml
lint: gofmt -l . | (! grep .) && go vet ./...
```

Verified in both directions with a planted misformat and a planted `vet` error.

**Fix:** ship the safe form as the suggested Go default. A stack template that
suggests a false green is worse than suggesting nothing, because it gets pasted
and trusted. Worth auditing the other stacks' suggestions for the same shape.

## S2 — docs-only pushes skip lint, including the push that defines lint

`pre-push` skips `lint`/`typecheck` when every pushed file is `.md`. Sensible
by default — but the PR that fills the `## ship config` block is *by definition*
a docs-only push, so the gate a repo just declared never runs against itself.
The commands went in unvalidated; I had to exercise them by hand.

**Fix:** run the gate anyway when the diff touches `CLAUDE.md`'s ship config
block. That is the one `.md` change that is not docs.

## S3 — the `core.hooksPath` banner prints on every commit and push

A global `core.hooksPath` produces ~15 lines of lefthook banner on **every**
commit and push:

```
core.hooksPath is set globally to '/Users/peluche/.config/git/hooks'
Custom hooks paths are not supported by default.
  ...
Skipping hook sync:
```

Meanwhile `flowkit hooks --verify` passes end-to-end and the hooks demonstrably
work — a planted `vet` error blocked a real push. So the banner is telling the
operator that something is broken, on every single operation, while it is not.

`flowkit hooks` separately reports `chain wrapper(s) missing for: pre-commit
pre-push`. That may well be the real gap, but the two messages disagree in
tone, and the loud one is the wrong one.

**Fix:** if verify passes, suppress or collapse the banner. If the chain
wrappers genuinely need to exist, `flowkit hooks` should offer to write them —
it is the only actionable form of this message and it currently ends in "add
them and re-run".

## S3 — `git-guard` blocks `-D` but the suggested alternative cannot finish the job

```
[git-guard] blocked: git branch -D
Use 'git branch -d' so unmerged work is never dropped silently.
```

Correct guard, and it fired on a genuinely throwaway probe branch. But `-d`
refuses unmerged branches by design, so the suggested command cannot delete
what was blocked. The only documented escape is `FLOWKIT_GIT_GUARD=off`, which
is a bigger hammer than the situation needs.

What worked, and stays honest — make the branch genuinely merged first:

```sh
git branch -f <throwaway> <branch-it-should-match>
git branch -d <throwaway>
```

**Fix:** put that two-liner in the guard's message. As written, the guidance
dead-ends and pushes the operator toward the bypass — the opposite of what the
guard wants.

## Note for `/ship`: never `--delete-branch` on a stacked PR

Not a flowkit bug — GitHub semantics — but it will bite any automation that
merges PRs.

Merging a base PR with `gh pr merge --delete-branch` while another PR targets
that branch **closes the child PR**, and a closed PR cannot be retargeted.
Recovery is: re-push the deleted branch, reopen the child, retarget to `main`,
merge, then delete.

If `/ship` ever merges automatically, it should check for open PRs targeting
the head branch before passing `--delete-branch`.

---

## What is genuinely good, and should not change

**The verify canary is the best thing in the toolkit.** Planting a real secret
per central rule and asserting the hook blocks it is the only check that can
tell "scanning and finding nothing" apart from "not scanning". It is what
caught the S1 above; a file-existence check would have reported everything
fine. Consider running it automatically after any `hooks` invocation, not only
on `--verify`.

**`lint-health --canary` follows the same principle** for lint coverage. The
idea deserves to spread further — a green gate nobody has seen go red is not
evidence.

**The ship-config-in-CLAUDE.md indirection works.** One block, parsed by both
the hook and the skill, no duplicated command lists. Its parser survived a
value containing a pipe and `&&` without quoting games.

**`git-guard` and the commit-msg attribution stripper** both fired correctly
and unobtrusively. Authorship staying human is the right default.
