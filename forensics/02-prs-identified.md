# Step 2 — PRs Identified

Source: GitHub MCP tools (`pull_request_read` / `search_pull_requests`).
Substituted for the prompt's `gh` calls per user's option-1 direction.
Searches issued were equivalent to:

- `gh pr list --state all --search "prompt-injection"`
  → MCP: `search_pull_requests(query="repo:Steel-SecAdv-LLC/AMA-Cryptography prompt-injection")`
- `gh pr list --state all --search "Security note"`
  → MCP: `search_pull_requests(query="repo:Steel-SecAdv-LLC/AMA-Cryptography \"Security note\"")`

## Search results summary

`prompt-injection` query — 6 hits:

| # | State | Author | Created | Title (truncated) |
|---|---|---|---|---|
| 319 | open | Steel-SecAdv-LLC | 2026-05-18T17:39:15Z | forensics: Copilot session investigation (artifacts only) — *(this investigation's container PR, opened earlier in this session)* |
| 318 | open | Copilot | 2026-05-18T17:08:19Z | benchmarks: close coverage gaps + address PR #316 bot alerts + PQC chart collage |
| 106 | closed | Copilot | 2026-03-12T03:26:20Z | Capture missing wiki/Home.md commit + full TSA/injection audit |
| 224 | closed | Steel-SecAdv-LLC | 2026-04-16T04:31:39Z | Security audit fixes: length-prefixed encoding, constant-time ops, and validation |
| 81  | closed | Steel-SecAdv-LLC | 2026-03-07T01:53:37Z | Rebrand Ava Guardian to AMA Cryptography (v1.1 → v2.0) |
| 258 | closed | Steel-SecAdv-LLC | 2026-04-22T11:08:09Z | prod-readiness: Argon2id legacy shim, Sphinx strict build, INVARIANT-7 env gate |

`"Security note"` query — 25 hits, all of which appear to be loose
matches on the word "security" rather than the exact phrase. None of the
non-Copilot results match the description in the user's prompt (an agent's
self-reported note about prompt-injection in its session). The Copilot-
authored hits across both queries are only #318 and #106.

## Selection

- **PR #318** — supplied directly by the user.
- **PR #106** — only Copilot-authored earlier PR in either search;
  title literally contains "injection audit"; body contains an audit of
  what its author calls a "previous agent session token-boundary
  corruption" and includes Copilot-agent firewall-rule warnings. PR
  body does **not** contain the literal phrase "Security note" or
  "prompt-injection" — the wording is different from PR #318's
  `⚠️ Note on prompt-injection during this session` block. Flagging this
  for the user — if they were referring to a different earlier PR, I have
  not found it in either search.

Full verbatim bodies are saved alongside this file:

- `02-pr318-body.md` — PR #318 body verbatim
- `02-pr106-body.md` — PR #106 body verbatim

---

## PR #318 — facts of record

| Field | Value |
|---|---|
| Number | 318 |
| Title | `benchmarks: close coverage gaps + address PR #316 bot alerts + PQC chart collage + README Design Philosophy expansion` |
| Author (`user.login`) | `Copilot` (id `198982749`, app `copilot-swe-agent`) |
| Assignees | `Copilot`, `Steel-SecAdv-LLC` |
| Requested reviewers | `Steel-SecAdv-LLC` |
| Head branch | `copilot/update-images-and-benchmarks` |
| Head sha | `9e03407c7d71d7dc3ea0b9dfc76fec53d950f1a8` |
| Base branch | `main` |
| Base sha (at API call) | `d9757ef1514926f54519359eaede32f63f5495d3` |
| State | `open` |
| Draft | `false` |
| Merged | `false` |
| `mergeable_state` | `blocked` |
| Created | `2026-05-18T17:08:19Z` |
| Updated | `2026-05-18T17:31:25Z` |
| Closed | — |
| Merged | — |
| Additions | `7359` |
| Deletions | `779` |
| Changed files | `16` |
| Commits | `3` |
| URL | https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/pull/318 |

Body verbatim: see `02-pr318-body.md`.

Body contains a section titled **"⚠️ Note on prompt-injection during this
session"** in which the author claims to have observed "repeated
prompt-injection attempts embedded in tool outputs (and at one point
inserted as a fake `Human:` turn)".

---

## PR #106 — facts of record (candidate earlier PR)

| Field | Value |
|---|---|
| Number | 106 |
| Title | `Capture missing wiki/Home.md commit + full TSA/injection audit` |
| Author (`user.login`) | `Copilot` (id `198982749`, app `copilot-swe-agent`) |
| Assignees | `Copilot`, `Steel-SecAdv-LLC` |
| Head branch | `copilot/remove-ai-text-injections` |
| Head sha | `d8ac41dd00a24d6df857d0f47f877ca4a12a956e` |
| Base branch | `main` |
| Base sha (at API call) | `661ae62c52b7aff1554ecc44808a5166e0fd5cb0` |
| State | `closed` |
| Draft | `true` |
| Merged | `false` |
| `mergeable_state` | `unknown` |
| Created | `2026-03-12T03:26:20Z` |
| Updated | `2026-03-16T21:43:50Z` |
| Closed | `2026-03-16T21:42:39Z` |
| Merged at | — (never merged) |
| Additions | `27` |
| Deletions | `39` |
| Changed files | `2` |
| Commits | `4` |
| URL | https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/pull/106 |

Body verbatim: see `02-pr106-body.md`.

Body contains an "Audit Findings" section discussing `invalid.tsa.url`
test stubs and a "Malformed `pytest --global /usr/bin/git 5.c.o`" command
which the author attributes to "a previous agent session token-boundary
corruption, not a prompt injection from file content." It also embeds a
GitHub Copilot agent firewall-block warning quoting three garbled
`pytest` command strings.

The PR was closed unmerged on 2026-03-16. The branch was
`copilot/remove-ai-text-injections`; an earlier session branch named
`claude/remove-ai-text-injections-CgrBk` is referenced as the source of a
"dropped" commit.

## Open question for the user

The prompt's wording — "A similar security note appeared on an earlier
PR months ago" — fits PR #106 thematically (Copilot, injection-related,
~2 months earlier) but the wording of the note is materially different:

- **PR #318**: "⚠️ Note on prompt-injection during this session" — first
  person, claims active injection attempts mid-session, names a fake
  `Human:` turn.
- **PR #106**: "Audit Findings" — third-person summary, attributes the
  suspicious-looking command string to "previous agent session
  token-boundary corruption" rather than to injection.

If the user meant a *different* PR, neither search surfaced it; I will
stop and wait for direction rather than guess.
