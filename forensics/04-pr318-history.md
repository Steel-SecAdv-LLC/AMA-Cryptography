# Step 4 — PR #318 Commit History and Force-Push Surface

## Substitution note

The prompt called for:
- `gh api repos/:owner/:repo/pulls/318/commits`
- `gh api repos/:owner/:repo/issues/318/events`

The MCP server exposes `pull_request_read`/`issue_read`/`list_commits`/
`get_commit` but **not** the GitHub Issues Events / PR Timeline
endpoints. There is no `events`/`timeline` method on `issue_read` or
`pull_request_read`. So:

- "commits" → satisfied by `git log` on `refs/forensics/pr318-head`,
  with each commit cross-verified via `mcp__github__get_commit` (which
  returns GitHub-side committer/author records alongside the raw
  commit object).
- "events" / force-push detection → **partial gap**, documented below.

## All commits on PR #318 (head → base)

Three commits, walked in newest-first order:

### Commit `9e03407c7d71d7dc3ea0b9dfc76fec53d950f1a8`

| Field | Value |
|---|---|
| Tree | `e3870bd7360c94ce40621698cd452a9bf0cb9072` |
| Parent | `e0aed3da60d273c69c06e298949b77ebe5fee3e2` |
| Subject | `benchmarks: address PR #316 reviewer + CodeQL alerts; consolidate 4 PQC SVGs into one collage; expand README Design Philosophy` |
| Author name / email | `copilot-swe-agent[bot]` / `198982749+Copilot@users.noreply.github.com` |
| Author date | `2026-05-18T17:05:49Z` |
| Committer name / email | `GitHub` / `noreply@github.com` |
| Committer date | `2026-05-18T17:05:49Z` |
| GPG `%G?` status | `E` (signature present, cannot verify — public key not in local keyring) |
| GPG `%GK` key id | `B5690EEEBB952194` |
| Trailers | `Agent-Logs-Url: https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/sessions/d6d39aab-220d-486f-bd08-214e447ffbf5`  /  `Co-authored-by: Steel-SecAdv-LLC <222707050+Steel-SecAdv-LLC@users.noreply.github.com>` |

GitHub-side cross-check (`get_commit`):
- `author.login=Copilot`, `author.id=198982749`, app `copilot-swe-agent`.
- `committer.login=web-flow`, `committer.id=19864447` (this is the
  fixed GitHub identity used when a commit is created through the
  GitHub API rather than a normal git push).

### Commit `e0aed3da60d273c69c06e298949b77ebe5fee3e2`

| Field | Value |
|---|---|
| Tree | `1e23e1742333730ddfda47f3dea81cf99d930be3` |
| Parent | `5953995c109eac55f6d7650a696bbf1cb29648ad` |
| Subject | `docs(x25519): make ama_x25519_set_mulx_override threading contract explicit` |
| Author name / email | `copilot-swe-agent[bot]` / `198982749+Copilot@users.noreply.github.com` |
| Author date | `2026-05-18T06:20:57Z` |
| Committer name / email | `GitHub` / `noreply@github.com` |
| Committer date | `2026-05-18T06:20:57Z` |
| GPG `%G?` status | `E` |
| GPG `%GK` key id | `B5690EEEBB952194` |
| Trailers | `Agent-Logs-Url: https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/sessions/0d309f9a-76c4-4445-af1f-385aa355572f`  /  `Co-authored-by: Steel-SecAdv-LLC <222707050+Steel-SecAdv-LLC@users.noreply.github.com>` |

GitHub side: same `Copilot`/`web-flow` pair as above.

### Commit `5953995c109eac55f6d7650a696bbf1cb29648ad`

| Field | Value |
|---|---|
| Tree | `a39455deb6e8516def2ab5eb67428718d5b14556` |
| Parent | `d9757ef1514926f54519359eaede32f63f5495d3` (= current `origin/main` HEAD) |
| Subject | `benchmarks: close MULX/SLH-DSA/secp256k1/FROST/Dilithium-NTT gaps; refresh docs + charts` |
| Author name / email | `copilot-swe-agent[bot]` / `198982749+Copilot@users.noreply.github.com` |
| Author date | `2026-05-18T06:18:47Z` |
| Committer name / email | `GitHub` / `noreply@github.com` |
| Committer date | `2026-05-18T06:18:47Z` |
| GPG `%G?` status | `E` |
| GPG `%GK` key id | `B5690EEEBB952194` |
| Trailers | `Agent-Logs-Url: https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/sessions/0d309f9a-76c4-4445-af1f-385aa355572f`  /  `Co-authored-by: Steel-SecAdv-LLC <222707050+Steel-SecAdv-LLC@users.noreply.github.com>` |

GitHub side: same `Copilot`/`web-flow` pair as above.

## Identity inventory

Every identity that appears in any author/committer/trailer slot across
the three PR #318 commits:

| Role | Name | Email | GitHub login | GitHub id | Notes |
|---|---|---|---|---|---|
| author × 3 | `copilot-swe-agent[bot]` | `198982749+Copilot@users.noreply.github.com` | `Copilot` | `198982749` | GitHub App "Copilot coding agent" (`copilot-swe-agent`). Same id is used by every Copilot coding-agent commit on every repo — id sharing across both PRs is the expected default, not anomalous. |
| committer × 3 | `GitHub` | `noreply@github.com` | `web-flow` | `19864447` | GitHub's fixed "commit via API/UI" identity. Indicates the commit was created server-side (e.g., via the GitHub API or web flow), not pushed from a local git client. |
| co-author trailer × 3 | `Steel-SecAdv-LLC` | `222707050+Steel-SecAdv-LLC@users.noreply.github.com` | (user account) | `222707050` | The repo owner. Trailer is text and is not authenticated; it does not imply the named user touched the commit object. |

No third identity appears. **No non-Copilot, non-web-flow, non-owner
email observed in any of the three commits.**

## Commit signatures

All three commits carry a GPG signature mapped to key id
`B5690EEEBB952194`. The local keyring does not contain this public key
so `%G?` reports `E` ("cannot verify"). This key id is GitHub's
documented web-flow signing key (used to sign every commit that GitHub
creates server-side via the API / web UI). Verification status here is
unknown from this environment — to confirm the signatures actually
chain to GitHub's published web-flow key, the key needs to be imported
into the keyring. No attempt to do that was made in this read-only
investigation.

## Co-occurring `Agent-Logs-Url` sessions

Two distinct Copilot agent session UUIDs appear in the trailers:

- `0d309f9a-76c4-4445-af1f-385aa355572f` — commits `5953995c`
  (06:18:47Z) and `e0aed3da` (06:20:57Z), both on 2026-05-18.
- `d6d39aab-220d-486f-bd08-214e447ffbf5` — commit `9e03407c`
  (17:05:49Z) on 2026-05-18.

In other words, PR #318's three commits were produced across **two
different Copilot agent sessions**. The earlier session's two commits
match the cherry-pick claim in PR #318's body ("Takes over #316 by
cherry-picking its two commits (`5953995`, `e0aed3d`)"). The later
session is the one whose PR description contains the
"⚠️ Note on prompt-injection during this session" block (it is the
session that authored the PR description / the head commit).

Note: the cherry-pick claim in the PR body is literally a no-op cherry-
pick — the two earlier commit shas are *identical* in PR #316 and
PR #318 (verifiable later in Step 8/9 once PR #316's branch is fetched).
Identical shas mean the commit objects were not re-created; the branch
either fast-forwarded or was reused.

## Force-push / branch-rewrite surface — gap noted

The prompt asked for `gh api repos/.../issues/318/events`, which is
the Issues Events / Timeline endpoint where GitHub records events of
type `head_ref_force_pushed`, `base_ref_changed`,
`head_ref_deleted`, etc. **The MCP server does not expose this
endpoint.** This is a real gap; I cannot, from inside this sandbox,
enumerate force-push events on PR #318's head branch via API.

Indirect evidence collected:

1. PR #318 reports `commits=3` in the API; locally `git rev-list --count
   origin/main..pr318-head` is also 3. No discrepancy in commit count.
2. All 3 commit objects were verified to exist on GitHub side via
   `mcp__github__get_commit`. None are orphaned.
3. The PR's `get_comments` returned `[]` — there is no automated
   GitHub "Copilot force-pushed the branch" notice in the conversation
   thread. (GitHub usually does *not* post these as issue comments —
   they live in the timeline — so absence here is not informative.)
4. PR #318 has 3 check runs on the head commit, all `copilot` /
   `copilot-pull-request-reviewer`, all started within minutes of PR
   creation (17:13–17:30 UTC). The check_runs endpoint only returns
   checks for the current head commit, so it does not reveal whether
   prior heads existed.

**Conclusion of force-push surface:** indeterminate from MCP alone.
If the user has access to `https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/pull/318` and can read the timeline directly, that gap can be closed independently.

## Additional finding surfaced incidentally

When fetching PR #318's review comments to look for timeline activity,
the `copilot-pull-request-reviewer` bot's 5 inline comments referenced
the following files:

- `src/c/ama_x25519.c` (line 346)
- `src/c/ama_dilithium.c` (referenced in review summary)
- `include/ama_cryptography.h` (referenced in review summary)
- `pyproject.toml` (line 278)
- `docs/BENCHMARK_HISTORY.md` (referenced in review summary)
- `benchmarks/benchmark_c_raw.c` (lines 42, 959)
- `benchmarks/generate_charts.py` (line 467)
- and several `benchmarks/charts/*.svg`

`src/c/ama_x25519.c`, `src/c/ama_dilithium.c`, `include/ama_cryptography.h`,
`pyproject.toml`, and `docs/BENCHMARK_HISTORY.md` are not listed in the
user's stated PR-#318 scope. These will be examined formally in Step 6
(scope check).
