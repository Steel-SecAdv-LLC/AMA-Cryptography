#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The CHANGELOG's dated pass entries are labelled as dated.

PR #394's readiness audit executed 1,815 statements extracted from the
repository's documents and found 139 whose figure no longer held at the
release head — every one of them a count, line number or measurement inside
a dated CHANGELOG pass entry, superseded by later passes.  Such entries are a
record; the [5.0.0] section says so in one place, ahead of the first dated
entry, and names the files that do carry the current numbers.  This test
keeps that label in place and ahead of the entries it qualifies — including
entries added after it, which is why the first pass heading is found rather
than named.
"""

from __future__ import annotations

from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
LABEL = "**Dated figures are dated.**"
FIRST_PASS = "### Maintenance pass, "


def test_the_dated_figures_label_precedes_the_first_pass_entry() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
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
