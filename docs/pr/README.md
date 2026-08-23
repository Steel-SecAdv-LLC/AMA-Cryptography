# `docs/pr/` — the PR #394 description, as a file

`pr-394-description.md` is the exact text the GitHub description of PR #394
should carry. Apply it with:

    gh pr edit 394 --body-file docs/pr/pr-394-description.md

Check the size first — GitHub rejects a description over 65,536 characters and
this one is within a hundred of it:

    python3 -c "print(len(open('docs/pr/pr-394-description.md',encoding='utf-8').read()))"

## Why it lives here

GitHub's PR description is written through a single whole-document parameter —
there is no patch API — and this one is 65,521 characters against GitHub's
65,536-character hard limit, with **15 characters of headroom**. Three things
follow, and all three are the reason the text is version-controlled rather than
edited in place:

1. **A whole-document rewrite is all-or-nothing.** A truncated or drifted write
   destroys the description; there is nothing to diff against afterwards unless
   the intended text exists somewhere. Now it does.
2. **The next person to add a sentence breaks it.** Fifteen characters is not
   one. A description at its ceiling cannot absorb a correction, which is part
   of how the counts in it went stale — and it is why the corrections below are
   phrased to be no longer than the claims they replace. Anything further added
   here has to displace something.
3. **It can be reviewed.** A description is a claim about the change; keeping it
   in the tree puts it under the same review and the same gates as the code.

## What this revision corrects, and against what

Every figure below was re-measured at `c694bc5` before it was written.

| Claim as it stood | Measured | Command |
|---|---|---|
| "Breaking Changes: **four**" and "All eight are tabulated in `CHANGELOG.md`" | **ten** breaking, **twelve** behavioural, twenty-two rows | the glance table in `CHANGELOG.md`, parsed |
| Ed25519 batch-verify R-canonicality undeclared | declared as glance-table row 14 | `CHANGELOG.md` |
| "covering all 55 commits" (twice) | the branch carries **233** | `git rev-list --count origin/main..HEAD` |
| the static test-function, file and executing counts, as of an earlier pass | **4,542 functions / 189 files / 6,125 executing** | `tools/update_docs.py --counts`; `python3 -m pytest tests/ -q` |
| the Python-suite line, as of `6c40102` | **6,125 passed / 49 skipped / 0 failed** at `c694bc5` | `python3 -m pytest tests/ -q` |
| C suite / MSan / TSan "63/63" | **67/67** (69/69 on the fe51 backend build) | `ctest --output-on-failure` |
| "`mypy --strict` clean, 234 files" (twice) | **303 files** | `MYPYPATH=. python3 -m mypy --strict --explicit-package-bases <CI scope>` |
| "documented counts (62)" | **66** | `tools/check_documented_counts.py` |
| "Re-run the platform lanes at `6c40102`" | at `c694bc5` | `git rev-parse HEAD` |

The breaking-change enumeration is no longer duplicated in the description. Two
records disagreeing about how many changes a release makes is worse than either
record being wrong on its own, so `CHANGELOG.md`'s glance table is the single
list — each row with its migration — and the description indexes it.
