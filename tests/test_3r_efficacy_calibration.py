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
import subprocess
from pathlib import Path
from typing import Callable

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
    if row[0] != "1":
        return "not at all"
    unit = "sample" if row[2] == "1" else "samples"
    return f"after {row[2]} {unit}"


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


def test_detectors_score_identical_injected_traces() -> None:
    """PIN (review finding, 2026-10-07): the head-to-head columns are
    paired — the injection runs exactly once per repeat and every detector
    scores that same trace.  The first committed form put the detector
    loop outermost around a shared RNG, so 3R consumed one set of
    injection placements and the baseline the next.  Mutation: with the
    injection moved back inside the detector loop, the injection count
    doubles and the per-detector traces diverge, failing both assertions."""
    injections: list[list[float]] = []
    base = [0.1] * 300

    def inject(trace: list[float]) -> tuple[list[float], set[int]]:
        t = list(trace)
        slot = 100 + len(injections)
        t[slot] = 9.9
        injections.append(t)
        return t, {slot}

    seen: dict[str, list[list[float]]] = {"a": [], "b": []}

    def detector(name: str) -> Callable[[list[float]], list[bool]]:
        def run(trace: list[float]) -> list[bool]:
            seen[name].append(list(trace))
            return [v > 1.0 for v in trace]

        return run

    out = ev.paired_rates(base, inject, (("a", detector("a")), ("b", detector("b"))), 4)
    assert len(injections) == 4, "one injection per repeat, shared by every detector"
    assert seen["a"] == seen["b"], "both detectors must score the identical traces"
    assert out["a"] == out["b"] == (1.0, 0.0)


class _GitShim:
    """A ``subprocess`` stand-in for ``_provenance_lines``'s two git calls."""

    # The function's except clause resolves this through the patched name.
    CalledProcessError = subprocess.CalledProcessError

    def __init__(self, status: str, fail: bool = False) -> None:
        self._status = status
        self._fail = fail

    def run(self, cmd: list[str], **kwargs: object) -> object:
        if self._fail:
            raise OSError("no git in the measuring environment")
        out = "abc123def456" if "rev-parse" in cmd else self._status

        class _Done:
            stdout = out + "\n"

        return _Done()


def _attested(mapped: bool) -> dict[str, object]:
    return {
        "native_backend": {
            "path": "/opt/lib/libama_core.so",
            "preload_digest_hex": "ab" * 32,
            "preload_digest_is_of_mapped_bytes": mapped,
        }
    }


def test_provenance_records_clean_dirty_and_gitless_states(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN (review finding, 2026-10-07): the commit field distinguishes the
    three worktree states a regeneration can run from.  Without the dirty
    marker, rows measured from edited code publish under the clean commit's
    name; without the except arm, a gitless environment crashes the
    measurement instead of recording that the commit is unestablishable."""
    monkeypatch.setattr("ama_cryptography._self_test.module_attestation", lambda: _attested(True))
    monkeypatch.setattr(
        "benchmarks.benchmark_runner._native_build_configuration", lambda: "cmake -DX=1"
    )
    monkeypatch.setattr(ev, "subprocess", _GitShim(status=""))
    assert "commit=abc123def456 " in ev._provenance_lines(7)
    monkeypatch.setattr(ev, "subprocess", _GitShim(status=" M monitoring.py"))
    assert "commit=abc123def456+dirty-worktree " in ev._provenance_lines(7)
    monkeypatch.setattr(ev, "subprocess", _GitShim(status="", fail=True))
    assert "commit=unrecorded (no git in the measuring environment)" in ev._provenance_lines(7)


def test_an_unpublishable_trailer_refuses_the_regeneration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN (review finding on f0582cf, mutation-earned): the fallback
    branches used to let main() write the table with artifact and build
    'unrecorded' — a published figure without its build flags, which
    AGENTS.md section 8 item 7 forbids.  The write site now refuses any
    trailer whose artifact or build line cannot pin what ran, while a
    fully pinned trailer passes.  Mutation: removing the refusal call
    from main's write path fails exactly this test's refusal case."""
    monkeypatch.setattr(ev, "subprocess", _GitShim(status=""))
    monkeypatch.setattr(
        "benchmarks.benchmark_runner._native_build_configuration",
        lambda: "cmake -DAMA_USE_NATIVE_PQC=ON (from build/python-cmake)",
    )
    monkeypatch.setattr("ama_cryptography._self_test.module_attestation", lambda: _attested(True))
    ev._refuse_unpublishable_provenance(ev._provenance_lines(7))  # pinned: no raise
    monkeypatch.setattr("ama_cryptography._self_test.module_attestation", lambda: _attested(False))
    with pytest.raises(SystemExit, match="cannot pin what ran"):
        ev._refuse_unpublishable_provenance(ev._provenance_lines(7))
    monkeypatch.setattr("ama_cryptography._self_test.module_attestation", lambda: _attested(True))
    monkeypatch.setattr(
        "benchmarks.benchmark_runner._native_build_configuration",
        lambda: "not recorded: no build tree digest-matches the measured object",
    )
    with pytest.raises(SystemExit, match="cannot pin what ran"):
        ev._refuse_unpublishable_provenance(ev._provenance_lines(7))


def test_the_write_path_itself_refuses_an_unpublishable_trailer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """PIN (mutation-earned): the refusal is wired into the one write
    path, not just available beside it — _write_table with an
    unpublishable trailer raises and leaves no file, and with a pinned
    trailer writes body + trailer.  Mutation: dropping the refusal call
    inside _write_table fails exactly the no-file assertion."""
    out = tmp_path / "r3_efficacy.tsv"
    with pytest.raises(SystemExit, match="cannot pin what ran"):
        ev._write_table(out, "row\n", "# artifact: unrecorded (no attestation)\n")
    assert not out.exists()
    ev._write_table(out, "row\n", "# artifact: libama.so sha3_256=ab\n# build: cmake\n")
    assert out.read_text(encoding="utf-8").startswith("row\n# artifact: libama.so")


def test_provenance_pins_the_artifact_only_for_mapped_digests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN (review finding, 2026-10-07): the artifact and build lines claim
    the measured object only when the attestation's digest is of the mapped
    bytes.  An unmapped digest, or a missing attestation, must say
    'unrecorded' AND must not reach the build-tree attribution at all — a
    claim derived from an unpinned artifact would outrun the evidence."""
    monkeypatch.setattr(ev, "subprocess", _GitShim(status=""))
    calls: list[str] = []

    def build_configuration() -> str:
        calls.append("called")
        return "cmake -DAMA_USE_NATIVE_PQC=ON (from build/python-cmake)"

    monkeypatch.setattr(
        "benchmarks.benchmark_runner._native_build_configuration", build_configuration
    )
    monkeypatch.setattr("ama_cryptography._self_test.module_attestation", lambda: _attested(True))
    mapped = ev._provenance_lines(7)
    assert f"# artifact: libama_core.so sha3_256={'ab' * 32}" in mapped
    assert "# build: cmake -DAMA_USE_NATIVE_PQC=ON (from build/python-cmake)" in mapped
    assert calls == ["called"]
    monkeypatch.setattr("ama_cryptography._self_test.module_attestation", lambda: _attested(False))
    unmapped = ev._provenance_lines(7)
    assert "# artifact: unrecorded (preload digest is not of the mapped bytes" in unmapped
    assert "# build: unrecorded (no pinned artifact to attribute a build tree to)" in unmapped
    monkeypatch.setattr("ama_cryptography._self_test.module_attestation", lambda: {})
    missing = ev._provenance_lines(7)
    assert "# artifact: unrecorded (no native-backend attestation" in missing
    assert "# build: unrecorded (no pinned artifact to attribute a build tree to)" in missing
    assert calls == ["called"], "an unpinned artifact must never reach build attribution"
