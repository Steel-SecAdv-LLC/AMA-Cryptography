#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The dated pass entries are labelled as dated.

PR #394's readiness audit executed 1,815 statements extracted from the
repository's documents and found 139 whose figure no longer held at the
release head — every one of them a count, line number or measurement inside
a dated CHANGELOG pass entry, superseded by later passes.  Such entries are a
record; a label says so in one place, ahead of the first dated entry, and
names the files that do carry the current numbers.  This test keeps that label
in place and ahead of the entries it qualifies — including entries added after
it, which is why the first pass heading is found rather than named.

The 5.0.0 pass entries and their label moved, verbatim, from the CHANGELOG's
``[5.0.0]`` section to ``docs/changelog/5.0.0-development-journal.md``, so the
property is pinned there, where the entries now are.  The CHANGELOG's 5.0.0
section must keep pointing at the journal, or a reader of the release notes
cannot find the record the label describes.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
JOURNAL = REPO_ROOT / "docs" / "changelog" / "5.0.0-development-journal.md"
LABEL = "**Dated figures are dated.**"
FIRST_PASS = "### Maintenance pass, "


def test_the_dated_figures_label_precedes_the_first_pass_entry() -> None:
    text = JOURNAL.read_text(encoding="utf-8")
    label = text.index(LABEL)
    first_pass = text.index(FIRST_PASS)
    assert label < first_pass, (
        "a pass entry was added above the label, so the entries it qualifies "
        "are no longer all below it"
    )
    qualifier = text[label:first_pass]
    assert "no gate reads a pass entry as a current property" in qualifier
    assert "docs/METRICS_REPORT.md" in qualifier, (
        "the label must name where the current numbers actually live, or a "
        "reader is told the entries are stale with nowhere to go instead"
    )


def test_the_release_notes_point_at_the_journal() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    start = text.index("\n## [5.0.0] - ")
    section = text[start : text.index("\n## [", start + 1)]
    assert "](docs/changelog/5.0.0-development-journal.md)" in section, (
        "the 5.0.0 release notes no longer link the development journal that "
        "holds the dated entries"
    )
