# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the 5.0.0 timing-detector contract — every axis the 8d72b8c
measurement found broken, in the direction that fails on regression.

The pre-5.0.0 rule had four measured defects (benchmarks/
detector_baseline_eval.py, commit 8d72b8c): the z-score was computed against
statistics that had already absorbed the observation (mathematically capped
below sqrt((1-alpha)/alpha) = 3.0, so every threshold_sigma >= 3.0 and the
'critical' severity were unreachable); it was OR'd with a fixed
Gaussian-calibrated MAD threshold that false-alarmed on 12.5% of clean
heavy-tailed traffic; the per-operation profiles were keyed partly to names
no production call site emits; and a sustained regime change was absorbed by
the trailing window (17.6% recall).  Each test below fails if its defect
returns.
"""

from __future__ import annotations

import math
import random
from collections import deque
from pathlib import Path
from typing import ClassVar, cast

import pytest

from ama_cryptography.monitoring import ResonanceTimingMonitor, TimingAnomaly


def _tight_baseline(monitor: ResonanceTimingMonitor, n: int = 50) -> None:
    """Alternating 9.9 / 10.1: median 10.0, MAD 0.1, robust sigma 0.14826."""
    for value in [9.9, 10.1] * (n // 2):
        monitor.record_timing("op", value)


class TestOrderOfUpdate:
    def test_four_sigma_spike_alarms_at_three_sigma_floor(self) -> None:
        """The regression pin on the update-before-test defect.

        A ~4-robust-sigma spike on a tight baseline must alarm at the 3.0
        floor.  Under the pre-5.0.0 rule this exact case could NOT alarm:
        the EWMA update ran first, so the achievable deviation was capped
        strictly below 3.0 at the default alpha=0.1.
        """
        monitor = ResonanceTimingMonitor(threshold_sigma=3.0)
        _tight_baseline(monitor)
        anomaly = monitor.record_timing("op", 10.0 + 4.0 * 0.14826)
        assert anomaly is not None
        assert anomaly.kind == "point"
        assert anomaly.deviation_sigma == pytest.approx(4.0, abs=0.2)


class TestBudgetAndSigmaAreLive:
    def test_smaller_alarm_budget_means_fewer_alarms(self) -> None:
        """8d72b8c: sigma 2/3/5 all produced exactly 497 alarms.  The
        calibrated budget is the knob that now governs heavy-tailed data,
        and it must be monotone."""

        def alarms(budget: float) -> int:
            monitor = ResonanceTimingMonitor(
                anomaly_profiles={"op": {"threshold_sigma": 3.0, "alarm_budget": budget}}
            )
            rng = random.Random(11)  # noqa: S311 -- test stream, not key material (TDC-001)
            count = 0
            for _ in range(4000):
                if monitor.record_timing("op", rng.lognormvariate(-3.9, 0.22)):
                    count += 1
            return count

        loose, tight = alarms(0.05), alarms(0.002)
        assert loose > tight, (loose, tight)

    def test_larger_sigma_floor_means_fewer_alarms(self) -> None:
        """On near-normal data with ~4-sigma spikes, floors 3.0 and 5.0 must
        produce strictly different alarm counts (a 4-sigma spike clears one
        and not the other)."""

        def alarms(sigma: float) -> int:
            monitor = ResonanceTimingMonitor(
                anomaly_profiles={"op": {"threshold_sigma": sigma, "alarm_budget": 0.002}}
            )
            rng = random.Random(7)  # noqa: S311 -- test stream, not key material (TDC-001)
            count = 0
            for _ in range(2000):
                x = 10.0 + 0.1483 * rng.gauss(0, 1)
                if rng.random() < 0.02:
                    x = 10.0 + 0.1483 * 4.0
                if monitor.record_timing("op", x):
                    count += 1
            return count

        assert alarms(3.0) > alarms(5.0)


class TestCalibration:
    def test_threshold_activates_only_with_enough_scores(self) -> None:
        monitor = ResonanceTimingMonitor()
        rng = random.Random(3)  # noqa: S311 -- test stream, not key material (TDC-001)
        for _ in range(60):  # 30 post-warmup scores < the 100 required
            monitor.record_timing("op", rng.lognormvariate(-3.9, 0.22))
        assert monitor._calibrated_score_threshold("op", 0.01) is None
        for _ in range(200):
            monitor.record_timing("op", rng.lognormvariate(-3.9, 0.22))
        threshold = monitor._calibrated_score_threshold("op", 0.01)
        assert threshold is not None and threshold > 0.0

    def test_calibration_survives_score_history_saturation(self) -> None:
        """The recompute cadence must outlive the bounded score history.

        _score_history is a deque(maxlen=4096).  The recompute test used to
        be `len(history) - cached_len < 32` — and len() freezes at maxlen
        once the deque saturates, so after ~4,126 recorded operations of one
        name the cached quantile threshold silently never recomputed again
        for the life of the process.  Measured on the shipped default: a
        post-saturation regime change left the cache frozen at 3.4 while the
        live 99% quantile was 15.8, and the point-alarm rate ran at 10.6%
        against the declared 1% budget — permanently.  The cadence now runs
        on a monotone ingest counter; this drives a monitor well past
        saturation, changes the regime, and requires the calibrated
        threshold to follow.  Fails against the len()-cadence form.
        """
        monitor = ResonanceTimingMonitor()
        rng = random.Random(11)  # noqa: S311 -- test stream, not key material (TDC-001)
        maxlen = monitor._SCORE_HISTORY_LEN
        interval = monitor._THRESHOLD_RECOMPUTE_INTERVAL

        # Saturate the history and settle the cache in the low regime.
        for _ in range(maxlen + 4 * interval):
            monitor.record_timing("op", rng.lognormvariate(-3.9, 0.22))
        low_threshold = monitor._calibrated_score_threshold("op", 0.01)
        assert low_threshold is not None
        assert len(monitor._score_history["op"]) == maxlen, "history must be saturated"

        # New regime: two orders of magnitude slower.  Enough samples to
        # cross several recompute intervals and dominate the window tail.
        for _ in range(maxlen // 2):
            monitor.record_timing("op", rng.lognormvariate(0.7, 0.22))
        high_threshold = monitor._calibrated_score_threshold("op", 0.01)
        assert high_threshold is not None
        assert high_threshold > low_threshold * 2, (
            f"calibrated threshold froze across deque saturation: "
            f"low={low_threshold} high={high_threshold} — the recompute "
            f"cadence is reading the bounded window's len() again"
        )

    def test_contamination_at_the_budget_rate_cannot_capture_the_threshold(self) -> None:
        """PIN (mutation-earned 2026-10-06): the contamination guard in
        ``_calibrated_score_threshold``.

        Anomalies arriving at the alarm-budget rate place ~budget of the
        score history at their own score level, so the raw ``(1 - b)`` order
        statistic lands inside the anomaly cluster and the threshold
        converges onto the anomalies (measured unguarded on this stream:
        threshold ~49 against an anomaly score level of ~60 by 4,000
        samples, still climbing, with asymptotic recall tending to ~50% —
        the loss ``benchmarks/r3_efficacy.tsv`` recorded against the trivial
        baseline).  The guard caps the threshold at ``_TAIL_GUARD_RATIO``
        times a contamination-immune lower order statistic; this drives a
        long contaminated stream and requires the threshold to stay with
        the clean bulk and the recall to stay high.  Fails against the
        unguarded order statistic.
        """
        monitor = ResonanceTimingMonitor()
        rng = random.Random(394)  # noqa: S311 -- test stream, not key material (TDC-001)
        inject = random.Random(777)  # noqa: S311 -- test stream, not key material (TDC-001)
        n = 12000
        trace = [0.1236 * math.exp(0.0337 * rng.gauss(0.0, 1.0)) for _ in range(n)]
        injected = set(inject.sample(range(100, n), n // 100))
        alarms = []
        for i, x in enumerate(trace):
            value = x * 3.0 if i in injected else x
            alarms.append(monitor.record_timing("op", value) is not None)
        recall = sum(1 for i in injected if alarms[i]) / len(injected)
        # Read the OPERATIONAL cache — the threshold the alarms above were
        # actually judged against — rather than calling the method with a
        # literal budget: the cache is computed under the monitor's own
        # profile budget, and a literal that drifted from it would make this
        # assertion measure a threshold no decision used.
        threshold = monitor._calibrated_threshold["op"][1]
        assert threshold is not None
        # The x3 anomaly cluster scores ~60 robust sigmas on this trace
        # shape; the clean q95 is ~2 and the guard ratio 4, so a guarded
        # threshold stays an order of magnitude below the cluster.  The
        # unguarded mutant crosses 15 long before the stream ends.
        assert threshold < 15.0, f"threshold {threshold} was captured by the contamination"
        assert recall >= 0.90, f"recall {recall} — the threshold absorbed the anomalies"

    def test_a_quantized_bulk_does_not_collapse_the_guarded_threshold(self) -> None:
        """Degenerate-scale behaviour of the contamination guard, pinned.

        On a coarse-timer or strongly bimodal operation most samples equal
        the trailing median, so most robust scores are exactly 0 and the
        guard's lower order statistic is 0.  A cap of ``4 * 0`` would
        collapse the bar to the sigma floor and alarm on every legitimate
        slow-path sample; the guard must instead stand aside and let the raw
        ``(1 - b)`` quantile govern.  This drives a 98%-constant /
        2%-slow-path stream — the slow path must stay UNDER the 5% guard
        fraction, or the guard statistic itself lands in the slow cluster
        and the zero branch is never reached (the first version of this test
        used 10% and measured as constraining nothing: the always-cap mutant
        passed it) — and requires the threshold to sit at the quantile of
        the real score distribution, not at zero.
        """
        monitor = ResonanceTimingMonitor()
        rng = random.Random(1201)  # noqa: S311 -- test stream, not key material (TDC-001)
        for i in range(2000):
            value = 0.1000 if i % 50 else 0.1000 * (1.5 + rng.random())
            monitor.record_timing("op", value)
        threshold = monitor._calibrated_score_threshold("op", 0.01)
        assert threshold is not None
        # The slow-path scores are hundreds of robust sigmas (MAD of the
        # bulk is ~0, floored by the EWMA scale); a collapsed cap would
        # report ~0 here and the sigma floor would govern every decision.
        assert threshold > monitor.threshold, (
            f"guarded threshold {threshold} collapsed below the sigma floor "
            f"on a quantized bulk — the zero-guard branch is gone"
        )

    def test_an_oversized_alarm_budget_keeps_the_guard_rank_in_the_tail(self) -> None:
        """RANGE: ``guard_tail`` is clamped at the median for budgets > 0.1.

        An uncapped ``5 * budget`` crosses 1.0 at budgets above 0.2, which
        would send the guard rank to the window minimum and cap the
        threshold at four times the smallest score ever observed.
        """
        monitor = ResonanceTimingMonitor()
        rng = random.Random(77)  # noqa: S311 -- test stream, not key material (TDC-001)
        for _ in range(600):
            monitor.record_timing("op", rng.lognormvariate(-3.9, 0.22))
        generous = monitor._calibrated_score_threshold("op", 0.30)
        # No cache eviction: the budget is part of the cache key, so the
        # second call must recompute on its own (the eviction this test used
        # to perform was hiding exactly the stale-budget bug the key fixes —
        # review finding, 2026-10-06).
        strict = monitor._calibrated_score_threshold("op", 0.01)
        assert generous is not None and strict is not None
        assert 0.0 < generous <= strict, (
            f"budget 0.30 produced threshold {generous} vs {strict} at 0.01 — "
            f"the guard rank left the tail"
        )

    def test_uncalibrated_severity_is_capped_at_warning(self) -> None:
        """Criticality claims a measured tail; before calibration a gross
        outlier alarms at 'warning' only."""
        monitor = ResonanceTimingMonitor(threshold_sigma=3.0)
        _tight_baseline(monitor)  # 50 samples: warmed up, NOT calibrated
        anomaly = monitor.record_timing("op", 50.0)
        assert anomaly is not None
        assert anomaly.severity == "warning"

    def test_calibrated_criticality_is_reachable(self) -> None:
        """Unreachable before 5.0.0 (z capped below 3.0 < the 5.0 critical
        bar); now 'critical' at twice the operating threshold."""
        monitor = ResonanceTimingMonitor(threshold_sigma=3.0)
        _tight_baseline(monitor, n=200)  # calibrated
        anomaly = monitor.record_timing("op", 50.0)
        assert anomaly is not None
        assert anomaly.severity == "critical"


class TestSplitLineResonance:
    """The split-line (Siegel top-ordinates) channel of detect_resonance.

    PIN test_the_channel_sums_exactly_two_ordinates — fails when the
    channel is reduced to the single largest ordinate (j = 1, Fisher's
    statistic again); earned by mutation after the first candidate pin
    (the two-tone detection comparison) was measured NOT to kill that
    mutant — under j = 1 the measured null bar lands at 8.32, below
    Fisher's conservative analytic 8.76, so the comparison's margin came
    from bar softness, not from the second ordinate.  The two-tone test
    below therefore claims the measured capability, not the mechanism.
    The first (rejected) harmonic-comb form of this channel is recorded
    in ``detect_resonance``'s comment block."""

    @staticmethod
    def _detect(series: list[float]) -> dict[str, object]:
        monitor = ResonanceTimingMonitor()
        for value in series:
            monitor.record_timing("op", value)
        return monitor.detect_resonance("op")

    def test_the_channel_sums_exactly_two_ordinates(self) -> None:
        """PIN: ``multiline_ratio`` is the top-2 sum over the mean, strictly
        above the top-1 ratio on any spectrum whose second ordinate is
        positive — reduced to j = 1 the field collapses onto
        ``resonance_ratio`` and both assertions fail."""
        rng = random.Random(42000)  # noqa: S311 -- test stream, not key material (TDC-001)
        series = [0.1 + 0.004 * rng.gauss(0.0, 1.0) for _ in range(100)]
        out = self._detect(series)
        assert out["multiline_ordinates"] == 2
        multiline = cast(float, out["multiline_ratio"])
        single = cast(float, out["resonance_ratio"])
        assert multiline > single + 0.5, out

    def test_two_tone_energy_is_caught_where_the_single_bin_test_misses(self) -> None:
        """Measured capability on two equal tones (not the mechanism pin —
        see the class docstring)."""
        fisher_hits = multiline_hits = 0
        for seed in range(40):
            rng = random.Random(42000 + seed)  # noqa: S311 -- test stream, not keys (TDC-001)
            series = [
                0.1
                + 0.0022 * math.sin(2.0 * math.pi * i / 7.111)
                + 0.0022 * math.sin(2.0 * math.pi * i / 11.3)
                + 0.004 * rng.gauss(0.0, 1.0)
                for i in range(100)
            ]
            out = self._detect(series)
            fisher_hits += bool(out["has_resonance"])
            multiline_hits += bool(out["has_multiline_resonance"])
        # Measured on these exact seeds: Fisher 14/40, split-line 22/40.
        # Deterministic arithmetic, so the floors cannot flake.
        assert multiline_hits >= fisher_hits + 5, (fisher_hits, multiline_hits)
        assert multiline_hits >= 16

    def test_clean_streams_stay_inside_the_budget_order(self) -> None:
        rng = random.Random(31)  # noqa: S311 -- test stream, not key material (TDC-001)
        flags = 0
        n = 150
        for _ in range(n):
            series = [0.1 + 0.004 * rng.gauss(0.0, 1.0) for _ in range(100)]
            flags += bool(self._detect(series)["has_multiline_resonance"])
        # Budget 1%; the padded real pipeline measures ~1.2%, so 4% here
        # (6 of 150) is the generous deterministic ceiling.
        assert flags <= 6, flags

    def test_the_null_bar_is_deterministic_and_cached(self) -> None:
        """An OFF-TABLE size, so the derivation and its cache actually run:
        m = 64 is pinned and returned before the cache is ever read, so the
        earlier form of this test passed with the cache broken (review
        finding, 2026-10-07)."""
        key = (24, 2)
        assert 24 not in ResonanceTimingMonitor._MULTILINE_THRESHOLDS
        ResonanceTimingMonitor._MULTILINE_THRESHOLD_CACHE.pop(key, None)
        first = ResonanceTimingMonitor._multiline_threshold(24)
        assert key in ResonanceTimingMonitor._MULTILINE_THRESHOLD_CACHE
        again = ResonanceTimingMonitor._multiline_threshold(24)
        assert first == again
        # Between the pinned neighbours (16: 8.80, 32: 11.14).
        assert 8.8 < first < 11.2, first
        ResonanceTimingMonitor._MULTILINE_THRESHOLD_CACHE.pop(key, None)

    def test_the_threshold_follows_the_configured_ordinates(self) -> None:
        """PIN (review finding, 2026-10-07): the null simulation derives the
        retained top values from ``MULTILINE_ORDINATES`` — a subclass that
        configures j = 3 gets a bar measured for the top-3 sum, strictly
        above the j = 2 bar, instead of the shipped table's.  Mutation:
        hard-coding the top two back (or returning the pinned table
        regardless of j) fails exactly this test."""

        class ThreeLine(ResonanceTimingMonitor):
            MULTILINE_ORDINATES: ClassVar[int] = 3

        try:
            three = ThreeLine._multiline_threshold(32)
            two = ResonanceTimingMonitor._MULTILINE_THRESHOLDS[32]
            assert three > two, (three, two)
        finally:
            ResonanceTimingMonitor._MULTILINE_THRESHOLD_CACHE.pop((32, 3), None)

    def test_the_pinned_table_matches_a_fresh_derivation(self) -> None:
        """PIN: the pinned thresholds and the derivation procedure cannot
        drift apart — one size is re-derived from scratch and compared to
        its table entry exactly (same seed, same arithmetic, so equality is
        byte-level).  A corrupted or stale table entry fails here."""
        m = 32
        table_value = ResonanceTimingMonitor._MULTILINE_THRESHOLDS[m]
        pinned = dict(ResonanceTimingMonitor._MULTILINE_THRESHOLDS)
        try:
            ResonanceTimingMonitor._MULTILINE_THRESHOLDS.clear()
            ResonanceTimingMonitor._MULTILINE_THRESHOLD_CACHE.pop((m, 2), None)
            fresh = ResonanceTimingMonitor._multiline_threshold(m)
        finally:
            ResonanceTimingMonitor._MULTILINE_THRESHOLDS.update(pinned)
            ResonanceTimingMonitor._MULTILINE_THRESHOLD_CACHE.pop((m, 2), None)
        assert fresh == table_value, (fresh, table_value)

    def test_an_oversized_window_stays_on_the_pinned_table(self) -> None:
        """PIN (review finding, 2026-10-07): the analysis window is capped
        at ``_MAX_RESONANCE_SAMPLES``, so a monitor constructed with any
        ``window_size`` stays on the pinned null-bar table.  Uncapped,
        16,385 samples pad to 32,768 and scan m = 16,384 — off the table,
        into the 65.5-million-draw synchronous null simulation (measured
        15.1 s) plus a 32,768-point pure-Python FFT.  Mutation: with the
        ``min(...)`` cap removed from ``detect_resonance``, the
        ``scanned_bins`` assertion fails (after paying exactly the latency
        this cap exists to refuse).

        History is injected directly: the pin is on ``detect_resonance``'s
        window, and 16,385 ``record_timing`` calls at window_size=20,000
        cost ~23 s of windowed-MAD work that buys the pin nothing.
        """
        cap = ResonanceTimingMonitor._MAX_RESONANCE_SAMPLES
        table = ResonanceTimingMonitor._MULTILINE_THRESHOLDS
        assert cap == 2 * max(table)
        monitor = ResonanceTimingMonitor(window_size=20000, max_history=20000)
        rng = random.Random(777)  # noqa: S311 -- test stream, not key material (TDC-001)
        samples = [0.1 + 0.004 * rng.gauss(0.0, 1.0) for _ in range(cap + 1)]
        with monitor._lock:
            history = monitor.timing_history.setdefault("op", deque(maxlen=monitor.max_history))
            history.extend(samples)
        cache_before = set(ResonanceTimingMonitor._MULTILINE_THRESHOLD_CACHE)
        out = monitor.detect_resonance("op")
        assert out["scanned_bins"] == cap // 2, out["scanned_bins"]
        assert out["multiline_threshold"] == table[cap // 2]
        # The pinned bar answered; no size was simulated for this report.
        assert set(ResonanceTimingMonitor._MULTILINE_THRESHOLD_CACHE) == cache_before

    def test_a_multiline_only_verdict_reaches_report_and_posture(self) -> None:
        """PIN (review finding): get_security_report admitted an analysis
        only on has_resonance, so the exact case the split-line channel
        exists for — its flag true, Fisher's false — never reached the
        report or the posture evaluation.  Driven end to end on a
        deterministic multiline-only verdict."""
        from ama_cryptography.adaptive_posture import PostureEvaluator
        from ama_cryptography.monitoring import AmaCryptographyMonitor

        monitor = AmaCryptographyMonitor()
        rng = random.Random(42013)  # noqa: S311 -- test stream, not key material (TDC-001)
        found = None
        for seed in range(60):
            rng = random.Random(42000 + seed)  # noqa: S311 -- test stream, not keys (TDC-001)
            series = [
                0.1
                + 0.0022 * math.sin(2.0 * math.pi * i / 7.111)
                + 0.0022 * math.sin(2.0 * math.pi * i / 11.3)
                + 0.004 * rng.gauss(0.0, 1.0)
                for i in range(100)
            ]
            probe = ResonanceTimingMonitor()
            for v in series:
                probe.record_timing("op", v)
            out = probe.detect_resonance("op")
            if out["has_multiline_resonance"] and not out["has_resonance"]:
                found = series
                break
        assert found is not None, "no multiline-only seed in range — scenario invalid"
        for v in found:
            monitor.timing.record_timing("op", v)
        report = monitor.get_security_report()
        analysis = report.get("resonance_analysis", {})
        assert "op" in analysis, "multiline-only verdict dropped at report admission"
        score = PostureEvaluator()._score_resonance(analysis)
        assert score > 0.0, "multiline-only verdict reached the report but scored 0"

    def test_posture_scores_the_multiline_excess(self) -> None:
        from ama_cryptography.adaptive_posture import PostureEvaluator

        ev = PostureEvaluator()
        quiet = ev._score_resonance(
            {
                "op": {
                    "resonance_ratio": 1.0,
                    "threshold_ratio": 8.76,
                    "multiline_ratio": 2.0,
                    "multiline_threshold": 12.78,
                }
            }
        )
        loud = ev._score_resonance(
            {
                "op": {
                    "resonance_ratio": 1.0,
                    "threshold_ratio": 8.76,
                    "multiline_ratio": 26.0,
                    "multiline_threshold": 12.78,
                }
            }
        )
        assert quiet == 0.0
        assert loud > 0.4


class TestSustainedShift:
    def _run_shift(
        self, magnitude: float, monitor: ResonanceTimingMonitor
    ) -> list[tuple[int, TimingAnomaly]]:
        rng = random.Random(13)  # noqa: S311 -- test stream, not key material (TDC-001)
        events: list[tuple[int, TimingAnomaly]] = []
        for i in range(2000):
            x = rng.lognormvariate(-3.9, 0.22) * (magnitude if i >= 1000 else 1.0)
            anomaly = monitor.record_timing("op", x)
            if anomaly is not None and anomaly.kind == "shift":
                events.append((i, anomaly))
        return events

    def test_upward_shift_raises_prompt_edge_triggered_events(self) -> None:
        """8d72b8c flagged 17.6% of a 30% regime change; the sign CUSUM must
        alert within the re-baseline horizon — and as a bounded number of
        events, not per-sample noise."""
        monitor = ResonanceTimingMonitor()
        events = self._run_shift(1.3, monitor)
        onset_events = [i for i, _ in events if i >= 1000]
        assert onset_events, "a 30% sustained shift produced no shift event"
        assert onset_events[0] - 1000 <= 300, f"detection delay {onset_events[0] - 1000}"
        # Edge-triggered: one warning plus at most one escalation per
        # episode, and re-baselining bounds episodes — a 1000-sample shifted
        # regime must produce a handful of events, not hundreds.
        assert len(onset_events) <= 8, f"{len(onset_events)} events — per-sample regression?"

    def test_downward_shift_is_also_detected(self) -> None:
        monitor = ResonanceTimingMonitor()
        events = self._run_shift(0.77, monitor)
        assert any(i >= 1000 for i, _ in events)

    def test_regime_state_covers_shift_then_rebaselines(self) -> None:
        monitor = ResonanceTimingMonitor()
        rng = random.Random(17)  # noqa: S311 -- test stream, not key material (TDC-001)
        in_shift_flags: list[bool] = []
        for i in range(2000):
            x = rng.lognormvariate(-3.9, 0.22) * (1.3 if i >= 1000 else 1.0)
            monitor.record_timing("op", x)
            state = monitor.get_shift_state("op")
            in_shift_flags.append(bool(state is not None and state["in_shift"]))
        # The regime is covered from detection until re-baselining...
        covered = sum(in_shift_flags[1000:1300])
        assert covered >= 180, f"only {covered}/300 pre-re-baseline samples covered"
        # ...and after re-baselining the shifted level is the new normal.
        assert not any(in_shift_flags[1600:]), "re-baseline did not adopt the new regime"

    def test_drifting_stream_shorter_than_the_lock_raises_nothing(self) -> None:
        """Pre-lock, a moving reference must raise no shift event at all.

        Before the reference locks at ``_CUSUM_LOCK_SAMPLES`` the CUSUM is
        scored against the *trailing* median, which only keeps E[sign] ~ 0 on
        a stationary stream.  Against a systematic drift the median lags,
        every sample lands on the same side, and the accumulator climbs ~k per
        sample straight through h and 2h — so a short, entirely benign stream
        produced a **'critical'**.  That is what failed
        ``test_scheduled_key_rotation_raises_no_critical_anomaly`` on
        ubuntu-24.04-arm: key registration walks a dict that grows as the
        schedule advances, which is exactly such a drift.

        Reverting the pre-lock guard makes this fail with a 'warning' at
        sample ~50 and a 'critical' at ~69.
        """
        rng = random.Random(7)  # noqa: S311 -- test stream, not key material (TDC-001)
        monitor = ResonanceTimingMonitor(window_size=64)
        events: list[TimingAnomaly] = []
        n = ResonanceTimingMonitor._CUSUM_LOCK_SAMPLES // 2  # far below the lock
        for i in range(n):
            x = 0.0016 - i * 4e-6 + rng.uniform(-2e-7, 2e-7)
            anomaly = monitor.record_timing("key_register", x)
            if anomaly is not None and anomaly.kind == "shift":
                events.append(anomaly)

        state = monitor.get_shift_state("key_register")
        assert state is not None and not state["locked"], (
            "scenario is only meaningful while the reference is unlocked; "
            f"locked={state['locked'] if state else None} after {n} samples"
        )
        assert events == [], f"pre-lock drift raised shift event(s): {events}"
        # And the accumulators carry no evidence to escalate from later.
        assert state["gp"] == 0.0 and state["gn"] == 0.0

    def test_constant_stream_never_alarms(self) -> None:
        monitor = ResonanceTimingMonitor()
        for _ in range(1500):
            assert monitor.record_timing("op", 0.005) is None

    def test_get_shift_state_contract(self) -> None:
        monitor = ResonanceTimingMonitor()
        assert monitor.get_shift_state("op") is None
        for _ in range(60):
            monitor.record_timing("op", 1.0)
        state = monitor.get_shift_state("op")
        assert state is not None
        assert {"mu0", "sigma0", "gp", "gn", "locked", "in_shift"} <= set(state)
        state["gp"] = 999.0  # a snapshot copy — mutating it must not leak in
        inner = monitor.get_shift_state("op")
        assert inner is not None and inner["gp"] != 999.0


class TestProfilesMatchProduction:
    #: The instrumentation calls whose first argument names an operation.
    _EMITTERS = frozenset({"monitor_crypto_operation", "record_timing"})

    @classmethod
    def _emitted_operation_names(cls) -> tuple[set[str], list[str]]:
        """``(names, unresolvable sites)`` over every shipped module, by AST.

        A call whose operation name is not a string literal cannot be checked
        against the profiles, so it is reported -- except inside
        ``monitoring.py``'s own ``monitor_crypto_operation``, the wrapper that
        forwards its caller's ``operation`` to ``record_timing`` and is
        covered by the callers' literals.
        """
        import ast

        package = Path(__file__).resolve().parent.parent / "ama_cryptography"
        names: set[str] = set()
        unresolvable: list[str] = []

        def visit(node: ast.AST, path: Path, function: str | None) -> None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function = node.name
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in cls._EMITTERS
                and node.args
            ):
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    names.add(first.value)
                elif not (path.name == "monitoring.py" and function == "monitor_crypto_operation"):
                    unresolvable.append(f"{path.name}:{node.lineno}")
            for child in ast.iter_child_nodes(node):
                visit(child, path, function)

        for path in sorted(package.rglob("*.py")):
            visit(ast.parse(path.read_text(encoding="utf-8")), path, None)
        return names, unresolvable

    def test_emitted_operation_names_are_profiled(self) -> None:
        """8d72b8c profiled aes_gcm_encrypt/decrypt -- names no production
        call site emits -- while crypto_api's actual names fell to the
        global default.  Every name the in-tree instrumentation emits must
        have an explicit profile.

        The names are read from the source, not typed here: the first
        revision listed nine by hand and missed three that legacy_compat
        emits (``sha3_256_hash``, ``hmac_auth``, ``hmac_verify``), so deleting
        any of their profiles left this green.
        """
        emitted, unresolvable = self._emitted_operation_names()
        assert unresolvable == [], (
            "an instrumentation call names its operation with a non-literal, so "
            f"its profile cannot be checked: {unresolvable}"
        )
        assert len(emitted) >= 12, sorted(emitted)
        missing = sorted(emitted - set(ResonanceTimingMonitor.DEFAULT_ANOMALY_PROFILES))
        assert missing == [], f"emitted operation names with no anomaly profile: {missing}"

    def test_every_profile_declares_a_budget(self) -> None:
        for name, profile in ResonanceTimingMonitor.DEFAULT_ANOMALY_PROFILES.items():
            assert 0.0 < profile["alarm_budget"] <= 0.05, name

    def test_wrapper_forwards_input_size(self) -> None:
        """The pre-5.0.0 AmaCryptographyMonitor wrapper dropped input_size,
        making every normalize_by_size profile dead configuration."""
        from ama_cryptography.monitoring import AmaCryptographyMonitor

        wrapper = AmaCryptographyMonitor(enabled=True)
        # 2 ms over 1000 bytes with a size-normalizing profile records
        # 0.002 ms/byte, not 2 ms.
        wrapper.timing.anomaly_profiles["norm_op"] = {
            "threshold_sigma": 3.0,
            "alarm_budget": 0.01,
            "normalize_by_size": True,
        }
        for _ in range(40):
            wrapper.monitor_crypto_operation("norm_op", 2.0, input_size=1000)
        stats = wrapper.timing.baseline_stats["norm_op"]
        assert stats["mean"] == pytest.approx(0.002, rel=0.01)


class TestEvalHarnessGateLogic:
    """The evaluation harness is itself load-bearing (CI gates on it), so
    its pure gate logic gets the same negative-direction coverage."""

    # One import style for this module throughout the class: the monkeypatch
    # test below needs the module object itself, and mixing `import x` with
    # `from x import y` for the same module is what CodeQL alert 623 flagged.

    def test_tie_band_is_derived_from_seed_spread(self) -> None:
        import benchmarks.detector_baseline_eval as ev

        assert ev.tie_band([0.5, 0.5, 0.5]) == pytest.approx(0.01)  # floor
        spread = [0.40, 0.50, 0.60]
        assert ev.tie_band(spread) == pytest.approx(0.2, abs=0.001)  # 2 x stdev

    def test_flags_at_budget_selects_top_scores_in_eval_region(self) -> None:
        import benchmarks.detector_baseline_eval as ev

        scores = [0.0] * (ev.EVAL_START + 10)
        scores[ev.EVAL_START + 3] = 9.0
        scores[ev.EVAL_START + 7] = 8.0
        scores[ev.EVAL_START - 1] = 99.0  # outside the eval region: never chosen
        flags = ev.flags_at_budget(scores, 2)
        assert flags[ev.EVAL_START + 3] and flags[ev.EVAL_START + 7]
        assert not flags[ev.EVAL_START - 1]
        assert sum(flags) == 2

    def test_sigma_floor_gate_fails_on_an_inert_detector(self) -> None:
        """Feed the gate a monitor whose sigma is forced inert (the 8d72b8c
        shape) and assert the gate actually goes red — a gate that cannot
        fail is the defect class this PR exists to remove."""
        import benchmarks.detector_baseline_eval as ev

        original = ev.run_shipped
        try:

            def inert(  # type: ignore[no-untyped-def]  # mirror signature (TDC-002)
                values, *, threshold_sigma=3.0, alarm_budget=0.01
            ):
                run = original(values, threshold_sigma=3.0, alarm_budget=alarm_budget)
                return run  # ignores the sigma argument — inert by construction

            ev.run_shipped = inert
            assert ev.gate_sigma_floor_live().passed is False
        finally:
            ev.run_shipped = original

    def test_gates_are_deterministic(self) -> None:
        """Two runs of the gate suite must agree exactly.

        The gates used to run on live wall-clock timings, which made their
        verdicts a property of the host: the shift gate failed 7 runs in 30
        with nothing wrong, because a CPU frequency change is a genuine regime
        change that the detector correctly reacts to and the gate could not
        tell from the injected one.  A gate whose result depends on the host
        cannot distinguish a detector regression from a busy runner.
        """
        import benchmarks.detector_baseline_eval as ev

        first = {g.name: (g.passed, g.detail) for g in ev.run_gates(1200)}
        second = {g.name: (g.passed, g.detail) for g in ev.run_gates(1200)}
        assert first == second, "gate results differ between runs on identical input"

    def test_synthetic_gate_base_has_no_regime_change(self) -> None:
        """The stream the gates run on must contain no shift for the detector
        to find — otherwise 'zero false shift events' would be measuring the
        stream's quirks rather than the detector's restraint."""
        import benchmarks.detector_baseline_eval as ev

        base = ev.synthetic_base(2000, ev.GATE_BASE_SEED)
        first_half = sorted(base[: len(base) // 2])
        second_half = sorted(base[len(base) // 2 :])
        median_first = first_half[len(first_half) // 2]
        median_second = second_half[len(second_half) // 2]
        assert (
            abs(median_second - median_first) / median_first < 0.05
        ), "the gate base drifted between halves; a gate stream must be stationary"

    def test_sigma_gate_counts_in_the_calibrated_regime(self) -> None:
        """The sigma gate must not draw its separation from the warmup window.

        Calibration for budget b activates only after max(100, 1/b) scores.
        Counting from before that point measured the uncalibrated posture,
        where sigma is the only threshold and separation is guaranteed whether
        or not it survives calibration — so a detector that ignored sigma the
        moment calibration went live still passed.
        """
        import benchmarks.detector_baseline_eval as ev

        activation = max(100, int(1 / ev._SIGMA_GATE_BUDGET))
        assert ev._SIGMA_GATE_START > activation, (
            f"the sigma gate counts from {ev._SIGMA_GATE_START}, at or before "
            f"calibration activates ({activation}) — its separation would come "
            f"from the uncalibrated warmup"
        )


class TestThePairwiseBarDoesNotDependOnArrivalOrder:
    """A pair's bar is a property of the pair, not of who recorded last.

    ``_update_timing_ratios`` took ``alarm_budget`` from the operation
    currently being recorded.  For a pair that is an arbitrary choice between
    two, and the per-pair threshold cache was keyed on the pair alone, so the
    first budget to compute a bar owned it for a whole recompute interval.

    Measured before the fix, on a pair of a ``{"alarm_budget": 0.002}`` and a
    ``0.05`` operation after 4,000 records each: the bar is 7.868 when computed
    under 0.002 and 5.011 under 0.05, and the 5.011 was served to the 0.002
    caller — 36% too low for the operation that asked for the tighter budget.
    """

    PROFILES: ClassVar[dict[str, dict[str, float]]] = {
        "strict": {"threshold_sigma": 3.0, "alarm_budget": 0.002},
        "loose": {"threshold_sigma": 3.0, "alarm_budget": 0.05},
    }
    PAIR: ClassVar[tuple[str, str]] = ("loose", "strict")

    @staticmethod
    def _samples(seed: int = 7, records: int = 4000) -> list[tuple[str, float]]:
        """The warm-up stream as explicit (operation, value) pairs.

        Materialised rather than drawn inline so a test can re-interleave the
        SAME values: reordering an inline RNG loop would also reassign which
        draws each operation receives, and the comparison would no longer
        isolate arrival order.

        Drawn from a private generator, like every other stream in this file.
        This one used to call ``random.seed(seed)``, which reseeds the
        interpreter-wide generator: every later test in the process that drew
        from ``random`` got a stream fixed by whichever of these tests ran
        last, so their behaviour depended on test order.  ``random.Random(n)``
        and ``random.seed(n)`` seed the same algorithm identically, so the
        values — and the figures measured from them above — are unchanged.
        """
        rng = random.Random(seed)  # noqa: S311 -- test stream, not key material (TDC-001)
        out: list[tuple[str, float]] = []
        for _ in range(records):
            for op, mu in (("strict", 10.0), ("loose", 25.0)):
                out.append((op, rng.lognormvariate(math.log(mu), 0.25)))
        return out

    def test_the_sample_stream_leaves_the_global_generator_alone(self) -> None:
        """Materialising the stream must not reseed ``random`` for the process."""
        before = random.getstate()
        self._samples(records=8)
        assert random.getstate() == before, (
            "_samples() reseeded the interpreter-wide generator; later tests "
            "that draw from `random` would see a stream fixed by this one"
        )

    @staticmethod
    def _warmed_from(
        profiles: dict[str, dict[str, float]], samples: list[tuple[str, float]]
    ) -> ResonanceTimingMonitor:
        from ama_cryptography.monitoring import ResonanceTimingMonitor

        monitor = ResonanceTimingMonitor(window_size=64, anomaly_profiles=profiles)
        for op, value in samples:
            monitor.record_timing(op, value)
        return monitor

    @classmethod
    def _warmed(
        cls, profiles: dict[str, dict[str, float]], seed: int = 7, records: int = 4000
    ) -> ResonanceTimingMonitor:
        return cls._warmed_from(profiles, cls._samples(seed, records))

    def test_the_pair_budget_is_the_stricter_of_the_two(self) -> None:
        monitor = self._warmed(self.PROFILES)
        assert monitor._pair_alarm_budget(self.PAIR) == 0.002
        assert monitor._pair_alarm_budget((self.PAIR[1], self.PAIR[0])) == 0.002

    def test_an_unprofiled_operation_contributes_the_default(self) -> None:
        monitor = self._warmed({"strict": self.PROFILES["strict"]})
        assert monitor._pair_alarm_budget(self.PAIR) == 0.002
        assert monitor._pair_alarm_budget(("loose", "loose")) == monitor.DEFAULT_ALARM_BUDGET

    def test_a_different_budget_is_not_served_from_the_cache(self) -> None:
        """The cache is keyed on the budget, not only on the pair."""
        monitor = self._warmed(self.PROFILES)
        loose_bar = monitor._calibrated_ratio_threshold(self.PAIR, 0.05)
        strict_bar = monitor._calibrated_ratio_threshold(self.PAIR, 0.002)
        assert loose_bar is not None and strict_bar is not None
        assert strict_bar > loose_bar, (
            f"a 0.002 budget produced a bar of {strict_bar} that is not stricter "
            f"than the 0.05 budget's {loose_bar}; the cached value was reused"
        )

    def test_the_recording_path_actually_uses_the_pair_budget(self) -> None:
        """End to end, through ``record_timing`` — not the helper directly.

        The tests above call ``_pair_alarm_budget`` and
        ``_calibrated_ratio_threshold`` themselves, so all of them pass even if
        ``_update_timing_ratios`` never consults the pair budget at all.
        Measured: replacing the call site with a fixed
        ``DEFAULT_ALARM_BUDGET`` left every other test in this class green.

        The observable is the cached entry the recording path writes:
        ``_ratio_threshold[pair]`` is ``(ingest count, budget, threshold)``, so
        the budget the live path used is recorded there.
        """
        monitor = self._warmed(self.PROFILES)
        cached = monitor._ratio_threshold.get(self.PAIR)
        assert cached is not None, (
            "the recording path never computed a bar for this pair; the test " "has no subject"
        )
        _total, budget_used, _threshold = cached
        assert budget_used == 0.002, (
            f"the live path computed this pair's bar under a budget of "
            f"{budget_used}, not the pair's stricter 0.002; a per-operation "
            f"budget the caller asked for is not reaching the pairs it is in"
        )

    def test_the_live_budget_is_the_same_whichever_side_records_last(self) -> None:
        """The order property: the live path's budget does not follow the recorder.

        Two monitors ingest the SAME (operation, value) pairs; only the
        interleaving differs — every per-iteration pair is swapped, so the
        operation that records last flips from ``loose`` to ``strict`` while
        each operation's own sample stream is identical.  The observable is
        the recording path's cached ``(count, budget, bar)`` triple, for the
        same reason ``test_the_recording_path_actually_uses_the_pair_budget``
        reads it: a direct ``_calibrated_ratio_threshold`` call supplies the
        budget itself, so it cannot see an order-dependent budget at all.
        The first revision of this test compared direct calls on two monitors
        built by the same seeded loop — bit-identical constructions — and
        stayed green with the arrival-order fix reverted.

        Only ``(count, budget)`` is compared across the two orders.  The bar
        itself is a quantile over the pair's deviation history, and each
        deviation is computed against the windows as they stood at that
        instant, so its numeric value legitimately depends on interleaving —
        measured here: 7.868 with loose recording last against 7.027 with
        strict last, both under the pair's 0.002 budget.  What the
        arrival-order fix guarantees, and what reverting it breaks, is the
        budget: taken from whichever operation is recording, the two orders
        cache 0.05 and 0.002 respectively and this assertion fails.
        """
        samples = self._samples()
        swapped = [s for i in range(0, len(samples), 2) for s in (samples[i + 1], samples[i])]
        assert swapped != samples and sorted(swapped) == sorted(samples)
        assert samples[-1][0] != swapped[-1][0], "the swap did not flip the last recorder"

        forward = self._warmed_from(self.PROFILES, samples)
        backward = self._warmed_from(self.PROFILES, swapped)

        fwd = forward._ratio_threshold.get(self.PAIR)
        bwd = backward._ratio_threshold.get(self.PAIR)
        assert (
            fwd is not None and bwd is not None
        ), "the recording path never computed a bar for this pair; the test has no subject"
        assert fwd[2] is not None and bwd[2] is not None
        assert fwd[:2] == bwd[:2], (
            f"the live path's (count, budget) depends on which side recorded "
            f"last: {fwd[:2]} when loose records last, {bwd[:2]} when strict "
            f"does; the bar is being computed under the recorder's own budget "
            f"rather than the pair's"
        )
