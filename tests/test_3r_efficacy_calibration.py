#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The README's stated 3R detection efficacy is the measured one.

``benchmarks/r3_efficacy_eval.py`` measures ``ResonanceTimingMonitor``
against a trailing-window z-score on real ML-DSA-65 sign timings and writes
``benchmarks/r3_efficacy.tsv``; the monitor came out below the trivial
baseline on isolated outliers.  The README states those numbers.  This test
pins the README to the table so the numbers cannot drift apart: a
re-measurement that changes the table must change the prose, and prose
edited without a measurement fails here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import benchmarks.r3_efficacy_eval as ev

REPO_ROOT = Path(__file__).resolve().parent.parent
TABLE = REPO_ROOT / "benchmarks" / "r3_efficacy.tsv"
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


def _detection(row: list[str]) -> str:
    """How the README words one step row: its delay, or that nothing fired."""
    return f"after {row[2]} samples" if row[0] == "1" else "not at all"


def test_the_readme_states_the_measured_step_delays() -> None:
    rows = _rows()
    prose = README.read_text(encoding="utf-8")
    r3_10, base_10 = rows[("step", "+10%", "3R")], rows[("step", "+10%", "baseline")]
    r3_5, base_5 = rows[("step", "+5%", "3R")], rows[("step", "+5%", "baseline")]
    assert (
        f"+10% was detected by 3R {_detection(r3_10)} and by the baseline "
        f"{_detection(base_10)}" in prose
    )
    assert f"at +5%, by 3R {_detection(r3_5)} and by the baseline {_detection(base_5)}" in prose


def test_the_table_is_the_measurement_not_a_placeholder() -> None:
    text = TABLE.read_text(encoding="utf-8")
    assert re.search(r"^# benign_n=4000 median_ms=[0-9.]+ mad_ms=[0-9.]+ seed=394$", text, re.M)
    assert len(_rows()) == 26
    # The paired step metric writes this column; a table without it was
    # produced by the unpaired metric, which credited ordinary false alarms.
    assert text.splitlines()[0].split("\t")[-1] == "step_excess_alarm_rate"


# --------------------------------------------------------------------------
# The step metric credits only alarms the shift caused
# --------------------------------------------------------------------------
#
# ``step_metrics`` used to count ANY alarm after the shift as a detection and
# report the first as the delay.  At the measured clean-trace false-positive
# rates (1.8% and 3.2%) such an alarm is near-certain with no shift at all, so
# every step row read ``detected=1`` and the delays were those of ordinary
# false alarms -- the committed table showed the baseline at exactly 47 samples
# for +5%, +10% and +30%.  The metric is now paired against the same detector
# run over the unshifted trace.  These tests drive it with alarm vectors, not
# timings, so they are deterministic.

_N = 4000
_MID = _N // 2


def _alarms(indices: set[int]) -> list[bool]:
    return [i in indices for i in range(_N)]


def test_an_alarm_the_clean_trace_also_raises_is_not_a_detection() -> None:
    """The exact shape of the defect: a benign alarm after the shift.

    The detector here ignores the shift entirely -- it alarms at the same
    indices on both traces, as any input-independent detector does -- so no
    shift was detected, whatever fires after the midpoint.
    """
    benign = _alarms({150, 900, _MID + 47, _MID + 300, _N - 1})
    detected, delay, _, excess = ev.step_metrics(benign, benign, _MID)
    assert not detected, "an alarm the unshifted trace raises too is not caused by the shift"
    assert delay == -1
    assert excess == 0.0


def test_the_delay_is_to_the_first_alarm_the_shift_caused() -> None:
    clean = _alarms({900, _MID + 3})
    shifted = _alarms({900, _MID + 3, _MID + 25, _MID + 26})
    detected, delay, fpr, excess = ev.step_metrics(shifted, clean, _MID)
    assert detected
    assert delay == 25, "the benign alarm at +3 is not the detection; the first caused one is"
    assert fpr == 1 / (_MID - 100)
    assert excess == 2 / (_N - _MID)


def test_mismatched_runs_are_refused() -> None:
    with pytest.raises(ValueError):
        ev.step_metrics(_alarms(set()), [False] * (_N - 1), _MID)
