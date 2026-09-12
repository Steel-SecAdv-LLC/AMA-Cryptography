# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The four properties ``PostureEvaluator`` claims and did not have.

``MONITORING.md`` promises that "with no new anomalies the level decays
geometrically", and the comment on the accumulator repeats it.  The
accumulator rewrite that made the composite score bounded — ``max(score,
acc * decay)`` instead of the unbounded ``acc * decay + score`` — was correct
and is kept.  What it did not survive contact with is the rest of the
evaluator, in four places, each pinned here:

1. **Decay is real.**  ``_score_lyapunov_stability`` appended to a deque that
   nothing ever drained, and ran on EVERY evaluation.  Once its derivative
   went positive the baseline froze (the deliberate anti-"boiling frog"
   guard), so it returned the same non-zero instability forever with zero new
   alerts — a permanent ``0.15 * instability`` floor under the composite, and
   ``max(...)`` cannot decay below its own floor.  Saturated, that floor is
   exactly the ELEVATED threshold.

2. **A sustained stream still escalates.**  Consecutive-evaluation counters
   were keyed to the EXACT candidate level and zeroed on any other, so the
   sawtooth the peak-hold accumulator produces — peak on an alert-bearing
   cycle, 5% decay on the quiet ones — never filled any counter.

3. **A tie is not a drop.**  The shared cursor used a strict ``>``, so an
   alert whose timestamp equalled the cursor was scored by nothing.

4. **An un-timestamped alert is scored once.**  It was treated as
   unconditionally new, so its deviation was re-appended on every cycle.

Every test below is written to FAIL against the code as it stood; the commit
message records the four mutations and their transcripts.
"""

from __future__ import annotations

from typing import Any

from ama_cryptography.adaptive_posture import PostureEvaluator, ThreatLevel


class _FakeAnomaly:
    def __init__(self, severity: str, deviation: float) -> None:
        self.severity = severity
        self.deviation_sigma = deviation


def _timing_alert(
    timestamp: float | None, severity: str = "critical", deviation: float = 10.0
) -> dict[str, Any]:
    alert: dict[str, Any] = {
        "type": "timing",
        "anomaly": _FakeAnomaly(severity, deviation),
    }
    if timestamp is not None:
        alert["timestamp"] = timestamp
    return alert


def _report(alerts: list[dict[str, Any]], total_alerts: int = 50) -> dict[str, Any]:
    return {
        "status": "ok",
        "recent_alerts": alerts,
        "resonance_analysis": {},
        "total_alerts": total_alerts,
    }


class TestQuietPeriodsActuallyDecay:
    """Property 1: no new anomalies means the level comes back down."""

    def test_level_returns_to_nominal_after_a_burst(self) -> None:
        evaluator = PostureEvaluator()

        # A burst large enough to fill the Lyapunov history (>= 5 deviations)
        # and to drive its derivative positive: rising magnitudes, so V grows
        # against the baseline established on the first qualifying cycle.
        window: list[dict[str, Any]] = []
        clock = 1.0
        for magnitude in (2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0):
            window.append(_timing_alert(clock, deviation=magnitude))
            clock += 1.0
            evaluator.evaluate(_report(list(window)))

        escalated = evaluator._accumulated_score
        assert escalated > 0.0, "the burst produced no score at all"

        # Now go quiet: the SAME window, no new alerts.  Nothing may keep
        # asserting instability from state the monitor is no longer reporting.
        for _ in range(200):
            evaluator.evaluate(_report(list(window)))

        assert evaluator._accumulated_score < evaluator.elevated_threshold - (
            evaluator.hysteresis_band
        ), (
            "the accumulated score did not decay below the de-escalation "
            f"boundary after 200 quiet evaluations (got "
            f"{evaluator._accumulated_score!r}, peak was {escalated!r})"
        )
        assert evaluator._current_level is ThreatLevel.NOMINAL

    def test_the_lyapunov_term_stops_scoring_a_quiet_system(self) -> None:
        evaluator = PostureEvaluator()
        window = [_timing_alert(float(i), deviation=2.0 ** (i + 1)) for i in range(1, 9)]
        for _ in range(3):
            evaluator.evaluate(_report(list(window)))

        # After enough quiet cycles the retained deviation history is gone,
        # so there is nothing left to derive an instability signal from.
        for _ in range(60):
            evaluator.evaluate(_report(list(window)))
        assert len(evaluator._timing_deviation_history) == 0
        assert evaluator._lyapunov_baseline is None


class TestSustainedStreamsEscalate:
    """Property 2: a signal that keeps arriving still reaches its level."""

    def test_a_sawtooth_stream_just_over_the_threshold_escalates(self) -> None:
        """The exact shape the peak-hold accumulator produces.

        One critical timing alert of 3.6 sigma scores 0.45 * 0.36 = 0.162,
        just over the 0.15 ELEVATED threshold.  Two quiet evaluations decay the
        hold to 0.162 * 0.95 = 0.1539 and then 0.1462 — under the threshold —
        so the candidate cycles ELEVATED, ELEVATED, NOMINAL forever.  Counting
        consecutive evaluations at the EXACT candidate level tops out at two
        and resets, so this stream never escalated, while the unbounded
        accumulator it replaced climbed past the threshold and stayed.

        3.6 sigma is not a contrived value: the weights are 0.45 / 0.25 / 0.15
        / 0.15 and the raw score is bounded by 1.0, so a peak that only just
        clears a threshold is the normal case for a low-and-slow signal.
        """
        evaluator = PostureEvaluator()
        window: list[dict[str, Any]] = []
        clock = 1.0
        levels: list[ThreatLevel] = []
        peak = 0.0

        for _ in range(12):
            window.append(_timing_alert(clock, severity="critical", deviation=3.6))
            clock += 1.0
            for _quiet in range(3):
                levels.append(evaluator.evaluate(_report(list(window))).threat_level)
                peak = max(peak, evaluator._accumulated_score)

        # Non-vacuity: the signal really does clear the threshold, so a failure
        # below is the counter's fault and not the score's.
        assert peak >= evaluator.elevated_threshold, (
            f"the constructed stream peaked at {peak!r}, under the "
            f"{evaluator.elevated_threshold!r} threshold it is meant to clear"
        )
        assert any(level is not ThreatLevel.NOMINAL for level in levels), (
            "a sustained anomaly stream that repeatedly clears the ELEVATED "
            "threshold never left NOMINAL: "
            f"{[lvl.name for lvl in levels]}"
        )


class TestAlertCursorBoundaries:
    """Properties 3 and 4: ties are scored, un-timestamped alerts once."""

    def test_alerts_tying_the_cursor_are_still_scored(self) -> None:
        evaluator = PostureEvaluator()
        first = _timing_alert(100.0, deviation=5.0)
        tied = _timing_alert(100.0, deviation=5.0)

        evaluator.evaluate(_report([first]))
        assert len(evaluator._timing_deviation_history) == 1

        # `tied` carries exactly the cursor timestamp.  A strict `>` drops it.
        evaluator.evaluate(_report([first, tied]))
        assert (
            len(evaluator._timing_deviation_history) == 2
        ), "an alert whose timestamp equals the cursor was never scored"

        # And it is not scored twice on the next pass.  The history AGES on a
        # quiet cycle (that is property 1), so the assertion is that it does
        # not GROW, not that it stays put.
        for _ in range(5):
            evaluator.evaluate(_report([first, tied]))
            assert (
                len(evaluator._timing_deviation_history) <= 2
            ), "an alert already past the cursor was scored again"

    def test_an_untimestamped_alert_is_scored_exactly_once(self) -> None:
        evaluator = PostureEvaluator()
        window = [_timing_alert(None, deviation=7.0)]

        evaluator.evaluate(_report(list(window)))
        assert len(evaluator._timing_deviation_history) == 1

        # Treated as unconditionally new, this grew the deque by one entry per
        # cycle until it held 50 copies of one stale deviation — enough on its
        # own to manufacture a Lyapunov instability signal from a single alert.
        high_water = 1
        for _ in range(60):
            evaluator.evaluate(_report(list(window)))
            high_water = max(high_water, len(evaluator._timing_deviation_history))
        assert high_water == 1, (
            "an alert with no timestamp was re-scored on later evaluations "
            f"(deviation history reached {high_water} entries from one alert)"
        )
