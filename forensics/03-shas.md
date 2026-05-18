# Step 3 — Branches and SHAs

Source commands (all local git after a single `git fetch origin`):

```
git fetch origin main copilot/update-images-and-benchmarks \
    'refs/pull/106/head:refs/forensics/pr106-head' \
    'refs/pull/318/head:refs/forensics/pr318-head'
```

Note on the prompt's instruction: it asked for `git fetch origin
<branch>`. PR #106's source branch `copilot/remove-ai-text-injections`
no longer exists on the remote (`fatal: couldn't find remote ref
copilot/remove-ai-text-injections` on first attempt). I substituted the
GitHub `refs/pull/N/head` protocol — the standard git ref GitHub
exposes for every PR head, including closed PRs with deleted source
branches. This is the same ref the GitHub UI and `gh pr checkout` use;
it is not a derived/computed alternative. No checkout, no edit, no
commit was performed in the working tree as a result.

## Refs created in the local repo (forensics-only, read-only)

| Local ref | Resolves to | Source |
|---|---|---|
| `origin/main` | `d9757ef1514926f54519359eaede32f63f5495d3` | `refs/heads/main` on origin |
| `origin/copilot/update-images-and-benchmarks` | `9e03407c7d71d7dc3ea0b9dfc76fec53d950f1a8` | PR #318 source branch on origin |
| `refs/forensics/pr318-head` | `9e03407c7d71d7dc3ea0b9dfc76fec53d950f1a8` | `refs/pull/318/head` on origin |
| `refs/forensics/pr106-head` | `d8ac41dd00a24d6df857d0f47f877ca4a12a956e` | `refs/pull/106/head` on origin |

Both PR head shas match what the GitHub API reported in Step 2.

## PR #318 — head and base

| Field | Value |
|---|---|
| Head sha | `9e03407c7d71d7dc3ea0b9dfc76fec53d950f1a8` |
| Reported base sha (API) | `d9757ef1514926f54519359eaede32f63f5495d3` |
| `git merge-base pr318-head origin/main` | `d9757ef1514926f54519359eaede32f63f5495d3` |
| Commits on head not on `origin/main` | 3 |
| Commits on `origin/main` not on head | 0 |
| Root commit of head's history | `02f6e4a8a67aa258539022a60f91594f84044494` |
| Root commit of `origin/main` history | `02f6e4a8a67aa258539022a60f91594f84044494` |

**Consistent.** PR #318's head branches cleanly from current `origin/main`.
Its merge-base equals current `main` HEAD (the PR is rebased onto the
latest tip).

### PR #318 commit walk (head → base)

```
9e03407c  2026-05-18 17:05:49Z  copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>
          benchmarks: address PR #316 reviewer + CodeQL alerts; consolidate 4 PQC SVGs into one collage; expand README Design Philosophy
e0aed3da  2026-05-18 06:20:57Z  copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>
          docs(x25519): make ama_x25519_set_mulx_override threading contract explicit
5953995c  2026-05-18 06:18:47Z  copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>
          benchmarks: close MULX/SLH-DSA/secp256k1/FROST/Dilithium-NTT gaps; refresh docs + charts
```

All three commits authored by the same identity (`copilot-swe-agent[bot]`,
id `198982749`).

## PR #106 — head and base

| Field | Value |
|---|---|
| Head sha | `d8ac41dd00a24d6df857d0f47f877ca4a12a956e` |
| Reported base sha (API) | `661ae62c52b7aff1554ecc44808a5166e0fd5cb0` |
| `git merge-base pr106-head origin/main` | *(empty — no common ancestor)* |
| `git merge-base --is-ancestor 661ae62c origin/main` | exit 1 (NO) |
| `git merge-base --is-ancestor 661ae62c pr106-head` | exit 0 (YES) |
| Commits on head not on `origin/main` | 277 |
| Root commit of head's history | `1d7c585a3eb4e07599d5d521b08b4d0df7a243ae` (2025-11-22, "Initial commit", Steel Security Advisors LLC) |
| Root commit of `origin/main` | `02f6e4a8a67aa258539022a60f91594f84044494` (2026-04-06, devin-ai-integration[bot]) |

**INCONSISTENT — flagged finding.** PR #106's head and current
`origin/main` share **no common ancestor** in this repository's
visible history. They are two disjoint commit DAGs:

- PR #106's lineage roots at `1d7c585a` on 2025-11-22 and contains
  272 commits before the PR's own work.
- Current `origin/main`'s lineage roots at `02f6e4a8` on 2026-04-06
  — five months later — and contains 50 commits total.

The reported base sha `661ae62c` (the parent the PR claims to branch
from) is present as a commit object in the repo and is reachable from
the PR #106 head, but is **not** an ancestor of `origin/main`. The
expected behavior — that a PR's reported base sha is an ancestor of
the target branch (`main`) at PR-creation time and remains an ancestor
unless the target branch was force-pushed — does not hold here.

### PR #106 commit walk (head → reported base)

```
d8ac41dd  2026-03-12 03:57:16Z  copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>
          Audit: document TSA stub findings and confirm no prompt injection
1645dc56  2026-03-12 03:31:25Z  copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>
          Capture wiki/Home.md: replace Mermaid diagrams with markdown tables
2bfccd4a  2026-03-12 03:29:56Z  copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>
          Initial plan: capture claude branch wiki/Home.md changes
164ef091  2026-03-12 03:26:19Z  copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>
          Initial plan
```

All four commits authored by the same identity (`copilot-swe-agent[bot]`,
id `198982749`). The reported base `661ae62c` is authored by
`Steel Security Advisors LLC <steel.sa.llc@gmail.com>` and is titled
`Convert ASCII diagrams to Mermaid flowcharts and fix import statements (#105)`.

## Corroborating evidence — tag reachability

```
v1.0.0  -> 79a39245  | in origin/main: no  | in pr106-head: YES
v1.1    -> 58b055e0  | in origin/main: no  | in pr106-head: YES
v2.0.0  -> 863dfdb2  | in origin/main: no  | in pr106-head: YES
v2.1.2  -> 8b3c356d  | in origin/main: YES | in pr106-head: no
v2.1.5  -> b761dd4b  | in origin/main: YES | in pr106-head: no
v3.0.0  -> 27470227  | in origin/main: YES | in pr106-head: no
v3.1.0  -> ed5397e6  | in origin/main: YES | in pr106-head: no
```

The release-tag set partitions cleanly across the two disjoint DAGs:
v1.x and v2.0.0 live only in the older lineage (which PR #106 sees),
v2.1.x and v3.x live only in the current lineage (which `origin/main`
sees). This is consistent with the `main` branch having been replaced
with a different commit history at some point between the v2.0.0 tag
and the v2.1.2 tag.

## Step status

**Step 3 complete.** Mid-step alarming finding flagged per the user's
hard rule:

> **The `main` branch's history is not continuous with PR #106's base.
> The repo's history has at some point been replaced/rewritten in a way
> that severs ancestry to PR #106 (and to v1.0.0 / v1.1 / v2.0.0).**

This does not, by itself, imply malice — repo-init mistakes, deliberate
fresh-start commits, and similar admin operations can produce the same
shape. But it is materially different from the prompt's working
assumption that PR #106 and PR #318 share a common `main` history, and
it affects the interpretation of every later step that says "diff
against base."

Stopping for user review before proceeding to Step 4. No working-tree
modifications were made beyond writing this artifact and creating the
two read-only forensic refs (`refs/forensics/pr106-head`,
`refs/forensics/pr318-head`).
