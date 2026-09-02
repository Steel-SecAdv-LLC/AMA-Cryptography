#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The README's stated 3R detection efficacy is the measured one.

PR #394's readiness audit measured ``ResonanceTimingMonitor`` against a
trailing-window z-score on real ML-DSA-65 sign timings
(docs/audit/sweeps/r3_efficacy.py -> docs/audit/PR394_3R_EFFICACY.tsv) and
found the monitor below the trivial baseline on isolated outliers.  The
README now states those numbers.  This test pins the README to the table so
the numbers cannot drift apart: a re-measurement that changes the table
must change the prose, and prose edited without a measurement fails here.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TABLE = REPO_ROOT / "docs" / "audit" / "PR394_3R_EFFICACY.tsv"
README = REPO_ROOT / "README.md"


def _rows() -> dict[tuple[str, str, str], list[str]]:
    out: dict[tuple[str, str, str], list[str]] = {}
    for line in TABLE.read_text(encoding="utf-8").splitlines()[1:]:
        if not line or line.startswith("#"):
            continue
        family, parameter, detector, *rest = line.split("\t")
        out[(family, parameter, detector)] = rest
    return out


def _pct(value: str) -> int:
    return round(float(value) * 100)


def test_the_readme_states_the_measured_point_anomaly_rates() -> None:
    rows = _rows()
    section = README.read_text(encoding="utf-8")
    start = section.index("Measured detection efficacy")
    prose = section[start : start + 2000]
    r3_10, base_10 = rows[("point", "x10.0", "3R")], rows[("point", "x10.0", "baseline")]
    r3_15, base_15 = rows[("point", "x1.5", "3R")], rows[("point", "x1.5", "baseline")]
    assert f"{_pct(r3_10[0])}% of the time (baseline: {_pct(base_10[0])}%)" in prose
    fpr_r3, fpr_base = float(r3_10[1]) * 100, float(base_10[1]) * 100
    assert f"false-positive rate of {fpr_r3:.1f}% (baseline: {fpr_base:.1f}%)" in prose
    assert f"at 1.5x, {_pct(r3_15[0])}% (baseline: {_pct(base_15[0])}%)" in prose


def test_the_readme_states_the_measured_step_delays() -> None:
    rows = _rows()
    prose = README.read_text(encoding="utf-8")
    r3_10, base_10 = rows[("step", "+10%", "3R")], rows[("step", "+10%", "baseline")]
    r3_5, base_5 = rows[("step", "+5%", "3R")], rows[("step", "+5%", "baseline")]
    assert f"3R after {r3_10[2]} samples and the baseline after {base_10[2]}" in prose
    assert f"at +5%, 3R needed {r3_5[2]} samples to the baseline's {base_5[2]}" in prose


def test_the_table_is_the_measurement_not_a_placeholder() -> None:
    text = TABLE.read_text(encoding="utf-8")
    assert re.search(r"^# benign_n=4000 median_ms=[0-9.]+ mad_ms=[0-9.]+ seed=394$", text, re.M)
    assert len(_rows()) == 26
