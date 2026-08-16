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

import random

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
    def test_emitted_operation_names_are_profiled(self) -> None:
        """8d72b8c profiled aes_gcm_encrypt/decrypt — names no production
        call site emits — while crypto_api's actual names fell to the
        global default.  Every name the in-tree instrumentation emits must
        have an explicit profile."""
        emitted_by_crypto_api = {"sign", "verify", "encrypt", "decrypt", "sphincs_sign"}
        emitted_by_legacy_compat = {
            "ed25519_sign",
            "ed25519_verify",
            "dilithium_sign",
            "dilithium_verify",
        }
        profiled = set(ResonanceTimingMonitor.DEFAULT_ANOMALY_PROFILES)
        assert emitted_by_crypto_api <= profiled
        assert emitted_by_legacy_compat <= profiled

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

            def inert(values, *, threshold_sigma=3.0, alarm_budget=0.01):  # type: ignore[no-untyped-def]  # mirrors run_shipped for monkeypatch (TDC-002)
                run = original(values, threshold_sigma=3.0, alarm_budget=alarm_budget)
                return run  # ignores the sigma argument — inert by construction

            ev.run_shipped = inert
            assert ev.gate_sigma_floor_live().passed is False
        finally:
            ev.run_shipped = original
