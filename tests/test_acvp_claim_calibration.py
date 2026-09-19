#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The README's ACVP headline names its denominator.

"1,215 / 1,215" is true of the vectors the harness runs and silent about the
5,789 it skips.  PR #394's readiness audit re-ran the harness (ledger
F-ACVP-01: 1,215 tested, 1,215 pass, 4,667 AFT-filtered skips) and found the
skip accounting stated only in docs/compliance/ACVP_SELF_ATTESTATION.md.  The
README sentence now carries the same totals; this test keeps the two in step.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
ATTESTATION = REPO_ROOT / "docs" / "compliance" / "ACVP_SELF_ATTESTATION.md"


def _skip_totals(text: str) -> tuple[str, str, str]:
    total = re.search(r"\*\*([0-9,]+) vectors were skipped total\*\*", text)
    aft = re.search(r"\*\*([0-9,]+) AFT-filtered skips\*\*", text)
    non_aft = re.search(r"\*\*([0-9,]+) non-AFT skips\*\*", text)
    assert total and aft and non_aft, "the attestation no longer states its skip accounting"
    return total.group(1), aft.group(1), non_aft.group(1)


def test_the_readme_states_the_attestations_skip_totals() -> None:
    total, aft, non_aft = _skip_totals(ATTESTATION.read_text(encoding="utf-8"))
    readme = README.read_text(encoding="utf-8")
    line = next(
        line for line in readme.splitlines() if "NIST ACVP vector validation (1,215" in line
    )
    assert f"skips {total} further vectors" in line
    assert f"({aft} filtered inside AFT groups" in line
    assert f"{non_aft} non-AFT" in line
    assert "ACVP_SELF_ATTESTATION.md" in line


def test_the_skip_totals_add_up() -> None:
    total, aft, non_aft = (
        int(v.replace(",", "")) for v in _skip_totals(ATTESTATION.read_text(encoding="utf-8"))
    )
    assert aft + non_aft == total
