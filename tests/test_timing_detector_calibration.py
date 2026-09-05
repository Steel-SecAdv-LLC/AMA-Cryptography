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
from typing import ClassVar

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
        """
        import math
        import random

        random.seed(seed)
        out: list[tuple[str, float]] = []
        for _ in range(records):
            for op, mu in (("strict", 10.0), ("loose", 25.0)):
                out.append((op, random.lognormvariate(math.log(mu), 0.25)))
        return out

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
