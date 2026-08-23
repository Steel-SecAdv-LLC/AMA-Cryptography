# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""``docs/pr/pr-394-description.md`` must fit in a GitHub PR description.

The file exists to be applied with ``gh pr edit 394 --body-file``. GitHub
rejects a pull-request body over 65,536 characters, and a PR description is
written through a single whole-document parameter — there is no patch API — so
an over-length file does not degrade, it fails the whole write. Discovering
that at the moment someone is trying to correct the description is the worst
possible time, which is the same objection this tree makes to any check that
runs later than the thing it protects.

The limit is the *character* count of the decoded text, not its UTF-8 byte
length: the description carries ``§``, ``→``, ``×``, em dashes and an emoji,
so the two differ by a few hundred and only one of them is what GitHub counts.

This is deliberately not a "keep it under N% of the limit" rule. The file is at
the ceiling today — see ``docs/pr/README.md`` — and a rule the tree already
violates is one somebody switches off. What the test does instead is report the
headroom on every failure, so the person over the line knows exactly how much
to reclaim, and assert that the headroom is a number rather than a surprise.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PR_BODY = REPO_ROOT / "docs" / "pr" / "pr-394-description.md"

#: https://docs.github.com/en/rest/pulls/pulls — bodies are capped at 65,536
#: characters. Named rather than inlined so the failure message can quote it.
GITHUB_BODY_LIMIT = 65_536


def test_the_description_file_exists() -> None:
    """A missing file would make every other assertion here vacuously true."""
    assert PR_BODY.is_file(), f"{PR_BODY} is missing; docs/pr/README.md explains what it is for"


def test_the_description_fits_a_github_pull_request_body() -> None:
    text = PR_BODY.read_text(encoding="utf-8")
    headroom = GITHUB_BODY_LIMIT - len(text)
    assert len(text) <= GITHUB_BODY_LIMIT, (
        f"{PR_BODY.relative_to(REPO_ROOT)} is {len(text):,} characters, "
        f"{-headroom:,} over GitHub's {GITHUB_BODY_LIMIT:,}-character limit for a "
        f"pull-request body. `gh pr edit --body-file` would reject it outright — "
        f"a PR description is written as one whole document, so there is no "
        f"partial write. Reclaim at least {-headroom:,} characters."
    )


def test_the_headroom_is_reported_so_the_ceiling_is_never_a_surprise() -> None:
    """The file is AT the ceiling; the number belongs where someone will see it.

    ``docs/pr/README.md`` states the headroom, and it is checked here rather
    than left to be re-measured by hand — a stated figure nothing verifies is
    the defect class the description itself was corrected for.
    """
    readme = (REPO_ROOT / "docs" / "pr" / "README.md").read_text(encoding="utf-8")
    headroom = GITHUB_BODY_LIMIT - len(PR_BODY.read_text(encoding="utf-8"))
    # An exact, greppable line, NOT a bare substring search for the number.
    # The first version of this assertion looked for `str(headroom)` anywhere in
    # the README, and with a headroom of 5 it matched "65,536", "5.0.0" and a
    # date — it passed whatever the README said, which is the defect class this
    # whole file was written to close.
    marker = f"PR-DESCRIPTION-HEADROOM: {headroom} characters"
    assert marker in readme, (
        f"docs/pr/README.md does not carry the line {marker!r}. The description "
        f"is {len(PR_BODY.read_text(encoding='utf-8')):,} characters, so that is "
        f"the headroom; update the README or the figure a reader trusts is stale."
    )
