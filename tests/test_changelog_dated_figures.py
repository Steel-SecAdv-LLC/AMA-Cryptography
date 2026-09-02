#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The CHANGELOG's dated pass entries are labelled as dated.

PR #394's readiness audit executed 1,815 statements extracted from the
repository's documents and found 139 whose figure no longer held at the
release head — every one of them a count, line number or measurement inside
a dated CHANGELOG pass entry, superseded by later passes.  Such entries are a
record; the [5.0.0] section now says so in one place, ahead of the first
dated entry, and names the ledger that lists the superseded figures.  This
test keeps that label in place and ahead of the entries it qualifies.
"""

from __future__ import annotations

from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"


def test_the_dated_figures_label_precedes_the_first_pass_entry() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    label = text.index("**Dated figures are dated.**")
    first_pass = text.index("### Maintenance pass, sixteenth")
    assert label < first_pass
    assert "docs/audit/PR394_CLAIMS.yaml" in text[label:first_pass]
    assert "no gate reads a pass entry as a current property" in text[label:first_pass]
