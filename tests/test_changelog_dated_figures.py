#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The CHANGELOG labels its dated figures, and its long form stays recoverable.

PR #394's readiness audit executed 1,815 statements extracted from the
repository's documents and found 139 whose figure no longer held at the
release head — every one of them a count, line number or measurement inside
a dated CHANGELOG pass entry, superseded by later passes.  Such entries are a
record; the [5.0.0] section says so in one place, ahead of the entries it
qualifies, and names the files that do carry the current numbers.

On 2026-09-24 the unreleased material was condensed into a digest, and the
dated pass journals left the file.  They were not deleted from the record: the
[5.0.0] section names the commit that last holds them, so
``git show <sha>:CHANGELOG.md`` recovers every one.  This module pins both
halves of that:

* the label precedes everything it qualifies — the digest's own subsections,
  and any pass entry, should one ever be written into the file again (the
  first pass heading is found rather than named, so a later one is covered);
* the label names where the current numbers live, and names the commit that
  holds the long form — and that commit really does hold it.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CHANGELOG = REPO / "CHANGELOG.md"
LABEL = "**Dated figures are dated.**"
PASS_HEADING = "### Maintenance pass, "
LONG_FORM_RE = re.compile(r"`git show ([0-9a-f]{7,40}):CHANGELOG\.md`")


def _release_section(text: str, version: str) -> str:
    start = re.search(rf"^## \[{re.escape(version)}\]", text, re.M)
    assert start, f"no [{version}] section in CHANGELOG.md"
    rest = text[start.end() :]
    following = re.search(r"^## \[", rest, re.M)
    return rest[: following.start()] if following else rest


def _qualifier(section: str) -> str:
    """The text from the label to the first subsection it qualifies."""
    label = section.index(LABEL)
    first_sub = re.search(r"^### ", section[label:], re.M)
    assert first_sub, "the label qualifies nothing: no subsection follows it"
    return section[label : label + first_sub.start()]


def _prose(markdown: str) -> str:
    """Blockquote markers dropped and whitespace collapsed, so a phrase is
    found wherever the paragraph happens to wrap."""
    lines = (re.sub(r"^\s*>\s?", "", line) for line in markdown.splitlines())
    return " ".join(" ".join(lines).split())


def test_the_label_precedes_everything_it_qualifies() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    section = _release_section(text, "5.0.0")
    label = section.index(LABEL)
    first_sub = re.search(r"^### ", section, re.M)
    assert first_sub and label < first_sub.start(), (
        "a subsection was added above the label, so the entries it qualifies "
        "are no longer all below it"
    )
    if PASS_HEADING in text:
        assert text.index(LABEL) < text.index(PASS_HEADING), (
            "a pass entry was added above the label, so the entries it "
            "qualifies are no longer all below it"
        )


def test_the_label_says_what_is_current_and_what_is_a_record() -> None:
    qualifier = _prose(_qualifier(_release_section(CHANGELOG.read_text(encoding="utf-8"), "5.0.0")))
    assert "no gate reads a pass entry as a current property" in qualifier
    assert "docs/METRICS_REPORT.md" in qualifier, (
        "the label must name where the current numbers actually live, or a "
        "reader is told the entries are stale with nowhere to go instead"
    )


def _long_form_sha() -> str:
    section = _release_section(CHANGELOG.read_text(encoding="utf-8"), "5.0.0")
    head = section[: section.index(LABEL) + len(_qualifier(section))]
    match = LONG_FORM_RE.search(head)
    assert match, (
        "the [5.0.0] section must name the commit holding the long-form "
        "journal as `git show <sha>:CHANGELOG.md`, ahead of the digest"
    )
    return match.group(1)


def test_the_long_form_commit_is_named_ahead_of_the_digest() -> None:
    assert re.fullmatch(r"[0-9a-f]{7,40}", _long_form_sha())


@pytest.mark.requires_git_history
def test_the_named_commit_holds_the_long_form() -> None:
    """The pointer must lead somewhere: the named commit's CHANGELOG carries the
    dated pass journals and their label.  A shallow checkout lacks the object,
    which is a skip here and a failure under ``AMA_CI_REQUIRE_HISTORY``."""
    sha = _long_form_sha()
    try:
        old = subprocess.run(
            ["git", "show", f"{sha}:CHANGELOG.md"],
            cwd=REPO,
            capture_output=True,
            check=True,
        ).stdout.decode("utf-8")
    except (OSError, subprocess.CalledProcessError):
        pytest.skip(f"commit {sha} is not available in this checkout (shallow clone)")
    assert PASS_HEADING in old, f"{sha}:CHANGELOG.md carries no pass journal"
    assert LABEL in old
    assert old.index(LABEL) < old.index(PASS_HEADING)
