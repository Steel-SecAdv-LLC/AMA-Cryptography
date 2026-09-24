# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The per-package pattern check is O(1) and detects exactly what it did.

Through 5.0.0 ``AmaCryptographyMonitor.record_package_signing`` ran the full
``RecursionPatternMonitor.analyze_patterns`` on every monitored package: a
copy of the history, every inter-package interval and a two-pass mean and
standard deviation at three scales plus the code counts, rebuilt from scratch
each call -- 5.0-5.2 ms per package at the default 10,000-entry history,
657-742% of a 0.69-0.76 ms package (``benchmarks/validation_suite.py
--only-3r``).  It now reads exact running moments that ``record_package``
maintains in O(1).

These tests pin the change from four directions:

* **Same detections.**  ``_reference_analysis`` below is the 5.0.0
  ``analyze_patterns`` / ``_recursive_extract`` body, copied verbatim apart
  from taking the history as an argument.  Over seeded workloads that slide
  the window many times, trigger both anomaly types at both frequency
  severities, and change ``max_depth`` mid-run (``MONITORING.md`` documents
  doing so), the new monitor reports the same anomalies -- type, severity,
  observed values exactly; z-scores and expected values to 1e-9 relative,
  because the exact moments are rounded once where the two-pass form rounds
  ``n`` times -- and bit-identical ``features``.
* **No drift.**  After tens of thousands of slides over values spanning
  eighteen orders of magnitude, the running sums equal sums built fresh from
  the retained window, as integers.
* **O(1).**  The per-package path must not iterate the history at all.
* **Input.**  A value that cannot enter the exact sums is refused before
  anything is recorded, and the monitor keeps agreeing with the reference.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Iterator
from typing import Any

import pytest

from ama_cryptography.monitoring import (
    AmaCryptographyMonitor,
    RecursionPatternMonitor,
    _ExactWindowMoments,
    _mean,
    _std,
)

# --------------------------------------------------------------------------
# The 5.0.0 algorithm, verbatim, as the oracle.
# --------------------------------------------------------------------------


def _reference_extract(data: list[float], depth: int, max_depth: int) -> dict[str, Any]:
    if depth >= max_depth or len(data) < 2:
        return {}

    features = {
        f"level_{depth}_mean": _mean(data),
        f"level_{depth}_std": _std(data),
        f"level_{depth}_range": max(data) - min(data),
        f"level_{depth}_samples": len(data),
    }

    if len(data) >= 4:
        downsampled = data[::2]
        deeper_features = _reference_extract(downsampled, depth + 1, max_depth)
        features.update(deeper_features)

    return features


def _reference_analysis(history: list[dict[str, Any]], max_depth: int) -> dict[str, Any]:
    if len(history) < 10:
        return {"status": "insufficient_data"}

    timestamps = [p["timestamp"] for p in history]
    intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

    features = _reference_extract(intervals, 0, max_depth)

    anomalies = []

    if "level_0_mean" in features and "level_0_std" in features:
        recent_interval = intervals[-1] if len(intervals) > 0 else 0
        if features["level_0_std"] > 0:
            z_score = abs(recent_interval - features["level_0_mean"]) / features["level_0_std"]

            if z_score > 3.0:
                anomalies.append(
                    {
                        "type": "unusual_frequency",
                        "z_score": float(z_score),
                        "severity": "warning" if z_score < 5.0 else "critical",
                        "details": {
                            "expected_interval_sec": features["level_0_mean"],
                            "observed_interval_sec": recent_interval,
                        },
                    }
                )

    code_counts = [float(p.get("code_count", 0)) for p in history]
    if len(code_counts) > 10:
        mean_count = _mean(code_counts)
        std_count = _std(code_counts)
        recent_count = code_counts[-1]

        if std_count > 0:
            z_score = abs(recent_count - mean_count) / std_count
            if z_score > 3.0:
                anomalies.append(
                    {
                        "type": "unusual_package_size",
                        "z_score": float(z_score),
                        "severity": "info",
                        "details": {
                            "expected_codes": mean_count,
                            "observed_codes": recent_count,
                        },
                    }
                )

    return {
        "status": "analyzed",
        "features": features,
        "anomalies": anomalies,
        "total_packages": len(history),
    }


# --------------------------------------------------------------------------
# Workloads
# --------------------------------------------------------------------------


class _Stream:
    """SplitMix64: a seeded, reproducible stream for test workloads.

    Local rather than ``random.Random`` so the workloads are pinned by this
    file alone -- the same draws on every Python version -- and nothing here
    looks like, or needs excusing as, a PRNG used for secrets.
    """

    def __init__(self, seed: int) -> None:
        self._state = seed & 0xFFFFFFFFFFFFFFFF

    def bits64(self) -> int:
        self._state = (self._state + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = self._state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
        return z ^ (z >> 31)

    def random(self) -> float:
        return (self.bits64() >> 11) / float(1 << 53)

    def uniform(self, lo: float, hi: float) -> float:
        return lo + (hi - lo) * self.random()

    def randint(self, lo: int, hi: int) -> int:
        return lo + self.bits64() % (hi - lo + 1)

    def gauss(self, mu: float, sigma: float) -> float:
        u1 = 1.0 - self.random()  # (0, 1]
        u2 = self.random()
        return mu + sigma * math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)


def _workload(seed: int, count: int, base: float) -> Iterator[dict[str, Any]]:
    """Package metadata with explicit timestamps: steady signing, bursts,
    droughts, and occasional outsized packages -- enough of each that both
    anomaly types fire, and the frequency check at both severities."""
    rng = _Stream(seed)
    ts = base
    for _ in range(count):
        roll = rng.random()
        if roll < 0.03:
            ts += rng.uniform(0.5, 3.0)  # drought
        elif roll < 0.06:
            ts += rng.uniform(1e-6, 1e-4)  # burst
        else:
            ts += abs(rng.gauss(0.01, 0.002))
        code_count = 7 if rng.random() < 0.95 else rng.randint(1, 400)
        yield {
            "timestamp": ts,
            "author": f"a{rng.randint(0, 3)}",
            "code_count": code_count,
            "content_hash": f"{rng.bits64():016x}",
        }


def _assert_same_anomalies(got: list[dict[str, Any]], want: list[dict[str, Any]]) -> None:
    assert [(a["type"], a["severity"]) for a in got] == [(a["type"], a["severity"]) for a in want]
    for g, w in zip(got, want):
        assert g["z_score"] == pytest.approx(w["z_score"], rel=1e-9)
        assert set(g["details"]) == set(w["details"])
        for key in ("observed_interval_sec", "observed_codes"):
            if key in w["details"]:
                assert g["details"][key] == w["details"][key]
        for key in ("expected_interval_sec", "expected_codes"):
            if key in w["details"]:
                assert g["details"][key] == pytest.approx(w["details"][key], rel=1e-9)


def _fresh_moments(values: list[float]) -> _ExactWindowMoments:
    moments = _ExactWindowMoments()
    for v in values:
        moments.add(v)
    return moments


def _window_intervals(history: deque[dict[str, Any]]) -> list[float]:
    ts = [float(p["timestamp"]) for p in history]
    return [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]


# --------------------------------------------------------------------------
# Same detections
# --------------------------------------------------------------------------


class TestAgreesWithTheFullHistoryAnalyzer:
    @pytest.mark.parametrize(
        "max_history,max_depth,depth_after_half,base,seed",
        [
            (10, 3, 3, 1.7e9, 1),
            (11, 1, 0, 1.7e9, 2),
            (16, 3, 5, 0.0, 3),
            (37, 0, 3, 1.7e9, 4),
            (64, 5, 2, 1.7e9, 5),
            (200, 3, 3, 1.7e9, 6),
        ],
    )
    def test_every_window_matches_the_reference(
        self,
        max_history: int,
        max_depth: int,
        depth_after_half: int,
        base: float,
        seed: int,
    ) -> None:
        monitor = RecursionPatternMonitor(max_depth=max_depth, max_history=max_history)
        count = 4 * max_history + 150
        seen: dict[str, int] = {}
        for i, meta in enumerate(_workload(seed, count, base)):
            if i == count // 2:
                # MONITORING.md: `monitor.patterns.max_depth = 4` after
                # construction.  The per-package check reads it live.
                monitor.max_depth = depth_after_half
            monitor.record_package(meta)
            want = _reference_analysis(list(monitor.package_history), monitor.max_depth)

            got = monitor.analyze_patterns()
            assert got.keys() == want.keys()
            assert got["status"] == want["status"]
            if want["status"] == "analyzed":
                # The features path is the unchanged algorithm: bit-identical.
                assert got["features"] == want["features"]
                assert got["total_packages"] == want["total_packages"]
                _assert_same_anomalies(got["anomalies"], want["anomalies"])
                for a in want["anomalies"]:
                    key = f"{a['type']}:{a['severity']}"
                    seen[key] = seen.get(key, 0) + 1
            # The per-package check is the report's anomaly list.
            _assert_same_anomalies(monitor.detect_anomalies(), want.get("anomalies", []))

        # The workload must actually exercise detection, or agreement proves
        # nothing.  Not in the 10- and 11-package windows: one value among n
        # can sit at most sqrt(n - 1) population standard deviations from the
        # mean, so 9 intervals cap z at 2.83 and 10 code counts at 3.0 -- a
        # z > 3.0 anomaly is unreachable there, and those two cases pin
        # agreement in the no-detection regime.  (max_depth 0 disables the
        # frequency check for the first half of the (37, 0, ...) case; the
        # second half re-enables it.)
        if max_history >= 16:
            assert seen.get("unusual_package_size:info", 0) > 0
            assert (
                seen.get("unusual_frequency:warning", 0) + seen.get("unusual_frequency:critical", 0)
                > 0
            )

    def test_both_frequency_severities_are_covered(self) -> None:
        """The parametrised cases, pooled, raise warning AND critical."""
        severities: set[str] = set()
        for seed in range(1, 7):
            monitor = RecursionPatternMonitor(max_history=200)
            for meta in _workload(seed, 600, 1.7e9):
                monitor.record_package(meta)
                severities.update(
                    a["severity"]
                    for a in monitor.detect_anomalies()
                    if a["type"] == "unusual_frequency"
                )
        assert severities == {"warning", "critical"}

    def test_record_package_signing_raises_the_reference_alerts(self) -> None:
        """End to end through the public monitor: the alerts a monitored
        package raises are the reference analyzer's anomalies for the window
        that package completed."""
        monitor = AmaCryptographyMonitor(enabled=True, detect_volume_spikes=False)
        monitor.patterns = RecursionPatternMonitor(max_history=50)
        expected: list[dict[str, Any]] = []
        shadow: deque[dict[str, Any]] = deque(maxlen=50)
        for meta in _workload(11, 400, 1.7e9):
            monitor.record_package_signing(meta)
            shadow.append(dict(meta))
            want = _reference_analysis(list(shadow), 3)
            expected.extend(want.get("anomalies", []))
        got = [a["anomaly"] for a in monitor.alerts if a["type"] == "pattern"]
        assert 0 < len(expected) < monitor.alert_retention
        _assert_same_anomalies(got, expected)


# --------------------------------------------------------------------------
# No drift
# --------------------------------------------------------------------------


class TestExactMomentsDoNotDrift:
    def test_running_sums_equal_fresh_sums_after_many_slides(self) -> None:
        rng = _Stream(20260924)
        monitor = RecursionPatternMonitor(max_history=16)
        ts = 0.0
        for _ in range(30_000):
            # Non-monotone timestamps (wall clocks step backwards) and values
            # across eighteen orders of magnitude: the regime in which a float
            # running sum loses the small terms outright.
            ts += (1.0 if rng.random() < 0.5 else -1.0) * 10.0 ** rng.uniform(-9, 9)
            monitor.record_package({"timestamp": ts, "code_count": 10.0 ** rng.uniform(-9, 9)})

        history = monitor.package_history
        fresh_intervals = _fresh_moments(_window_intervals(history))
        fresh_counts = _fresh_moments([float(p["code_count"]) for p in history])
        for running, fresh in (
            (monitor._interval_moments, fresh_intervals),
            (monitor._code_count_moments, fresh_counts),
        ):
            assert running.count == fresh.count
            assert running._sum == fresh._sum
            assert running._sum_sq == fresh._sum_sq

    def test_moments_are_the_correctly_rounded_mean_and_std(self) -> None:
        """RANGE: the exact moments against math.fsum on a known window."""
        values = [0.1, 0.2, 0.3, 1e-12, 12345.678, -3.5]
        m = _fresh_moments(values)
        assert m.mean() == math.fsum(values) / len(values)
        mu = math.fsum(values) / len(values)
        var = math.fsum((v - mu) ** 2 for v in values) / len(values)
        assert m.std() == pytest.approx(math.sqrt(var), rel=1e-12)
        assert _fresh_moments([2.5] * 9).std() == 0.0
        assert _fresh_moments([2.5]).std() == 0.0


# --------------------------------------------------------------------------
# O(1)
# --------------------------------------------------------------------------


class _NoIterationHistory(deque[dict[str, Any]]):
    """A history that fails the moment anything walks it."""

    def __iter__(self) -> Iterator[dict[str, Any]]:
        raise AssertionError("the per-package pattern path iterated the history")


class TestPerPackagePathIsConstantTime:
    def test_record_package_signing_never_walks_the_history(self) -> None:
        monitor = AmaCryptographyMonitor(enabled=True)
        patterns = monitor.patterns
        for meta in _workload(7, 300, 1.7e9):
            monitor.record_package_signing(meta)
        # deque(iterable) iterates the argument, not the new instance.
        patterns.package_history = _NoIterationHistory(
            patterns.package_history, maxlen=patterns.package_history.maxlen
        )
        for meta in _workload(8, 300, 1.8e9):
            monitor.record_package_signing(meta)
        assert len(patterns.package_history) == 600

    def test_the_report_still_walks_it(self) -> None:
        """Control: the guard above can fire -- the on-demand report is the
        O(n) path, and it trips the same history."""
        patterns = RecursionPatternMonitor()
        for meta in _workload(9, 20, 1.7e9):
            patterns.record_package(meta)
        patterns.package_history = _NoIterationHistory(
            patterns.package_history, maxlen=patterns.package_history.maxlen
        )
        with pytest.raises(AssertionError, match="iterated the history"):
            patterns.analyze_patterns()


# --------------------------------------------------------------------------
# Input
# --------------------------------------------------------------------------


class TestMetadataThatCannotEnterTheSums:
    @pytest.mark.parametrize(
        "bad",
        [
            {"code_count": float("nan")},
            {"code_count": float("inf")},
            {"code_count": "seven"},
            {"code_count": 10**400},
            {"timestamp": float("nan")},
            {"timestamp": float("-inf")},
            {"timestamp": "1700000000"},
            {"timestamp": True},
            {"timestamp": None},
        ],
    )
    def test_is_refused_before_anything_is_recorded(self, bad: dict[str, Any]) -> None:
        monitor = RecursionPatternMonitor(max_history=12)
        workload = list(_workload(21, 40, 1.7e9))
        for meta in workload[:30]:
            monitor.record_package(meta)
        before = list(monitor.package_history)

        with pytest.raises(ValueError, match="package metadata"):
            monitor.record_package({**workload[30], **bad})

        assert list(monitor.package_history) == before
        # State stayed consistent: the next packages still agree with the
        # reference over the same window.
        for meta in workload[31:]:
            monitor.record_package(meta)
            want = _reference_analysis(list(monitor.package_history), monitor.max_depth)
            _assert_same_anomalies(monitor.detect_anomalies(), want["anomalies"])
            assert monitor.analyze_patterns()["features"] == want["features"]

    @pytest.mark.parametrize(
        "ok,expected_count",
        [({"code_count": "7"}, 7.0), ({"code_count": True}, 1.0), ({}, 0.0)],
    )
    def test_code_count_keeps_its_float_conversion(
        self, ok: dict[str, Any], expected_count: float
    ) -> None:
        """code_count has always gone through float(); that stays accepted."""
        monitor = RecursionPatternMonitor()
        monitor.record_package({"timestamp": 5, **ok})
        assert monitor._code_count_moments.mean() == expected_count

    def test_an_int_timestamp_is_a_real_number(self) -> None:
        monitor = RecursionPatternMonitor()
        for i in range(12):
            monitor.record_package({"timestamp": 1_700_000_000 + i, "code_count": 7})
        assert monitor.analyze_patterns()["status"] == "analyzed"


def test_a_zero_history_monitor_records_nothing() -> None:
    monitor = RecursionPatternMonitor(max_history=0)
    for meta in _workload(3, 30, 1.7e9):
        monitor.record_package(meta)
    assert len(monitor.package_history) == 0
    assert monitor.detect_anomalies() == []
    assert monitor.analyze_patterns() == {"status": "insufficient_data"}


# --------------------------------------------------------------------------
# The demo's summary states the library's real default
# --------------------------------------------------------------------------


def test_the_monitor_demo_states_the_constructor_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``tools/monitoring/ama_cryptography_monitor_demo.py`` printed
    that monitoring was off by default, at zero cost, beside a constructor that
    defaults to ``enabled=True``.  The line is now derived; this pins it to
    the signature in both directions."""
    import importlib.util
    import inspect
    from pathlib import Path

    path = (
        Path(__file__).resolve().parent.parent / "tools/monitoring/ama_cryptography_monitor_demo.py"
    )
    spec = importlib.util.spec_from_file_location("_monitor_demo_under_test", path)
    assert spec is not None and spec.loader is not None
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)

    default = inspect.signature(AmaCryptographyMonitor.__init__).parameters["enabled"].default
    assert default is True
    line = demo.default_state_line()
    assert line.startswith("Enabled by default")
    assert "Disabled" not in line

    # And it follows the signature rather than restating it.
    def off_by_default(self: Any, enabled: bool = False) -> None:
        pass

    monkeypatch.setattr(demo.AmaCryptographyMonitor, "__init__", off_by_default)
    assert demo.default_state_line().startswith("Off unless requested")
