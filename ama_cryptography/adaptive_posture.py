#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography - Adaptive Cryptographic Posture System
============================================================

Consumes 3R monitor output to dynamically evaluate system security posture
and trigger appropriate cryptographic responses: algorithm switching and
key rotation via existing infrastructure.

Architecture:
    3R Monitor → PostureEvaluator → CryptoPostureController → crypto_api.py
                                                            → key_management.py

No new cryptographic logic is introduced. This module orchestrates existing
primitives (multi-algorithm API, BIP32 key derivation, key rotation manager)
based on real-time anomaly signals from the 3R monitoring system.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Version: 5.0.0
"""

import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum, auto
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from ama_cryptography.equations import lyapunov_function

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """
    System-wide threat assessment derived from 3R monitor signals.

    Each level maps to a concrete cryptographic response:
        NOMINAL  → No action, standard operations
        ELEVATED → Increase monitoring frequency, prepare rotation
        HIGH     → Rotate keys, switch to stronger algorithms
        CRITICAL → Immediate key rotation + algorithm upgrade + alert
    """

    NOMINAL = auto()
    ELEVATED = auto()
    HIGH = auto()
    CRITICAL = auto()


class PostureAction(Enum):
    """Actions the posture system can trigger."""

    NONE = auto()
    INCREASE_MONITORING = auto()
    ROTATE_KEYS = auto()
    SWITCH_ALGORITHM = auto()
    ROTATE_AND_SWITCH = auto()


@dataclass
class PostureEvaluation:
    """
    Result of a posture evaluation cycle.

    Attributes:
        threat_level: Current assessed threat level
        action: Recommended action
        confidence: Evaluation confidence (0.0–1.0)
        signals: Contributing anomaly signals
        timestamp: Evaluation time
    """

    threat_level: ThreatLevel
    action: PostureAction
    confidence: float
    signals: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)


@dataclass
class PendingAction:
    """
    A destructive posture action awaiting confirmation.

    When confirmation_mode is enabled on CryptoPostureController,
    actions like ROTATE_KEYS, SWITCH_ALGORITHM, and ROTATE_AND_SWITCH
    are queued as PendingActions instead of executing immediately.

    Attributes:
        action_id: Unique identifier for this pending action
        action: The posture action to execute
        reason: Why this action was triggered
        timestamp: When the action was queued
        confirmed: Whether the action has been confirmed
    """

    action_id: str
    action: PostureAction
    reason: str
    timestamp: float
    confirmed: bool = False


class PostureEvaluator:
    """
    Evaluates cryptographic security posture from 3R monitor output.

    Consumes timing anomalies, pattern anomalies, resonance analysis, and
    Lyapunov stability signals from AmaCryptographyMonitor to derive a threat
    level and recommended action. Thresholds are configurable for different
    deployment contexts.

    The evaluator uses a weighted scoring model:

    - Timing anomalies (45%) — severity-weighted scores
    - Pattern anomalies (25%) — z-score magnitude
    - Resonance detection (15%) — resonance ratio
    - Lyapunov stability (15%) — double-helix engine divergence detection

    Threshold calibration:

    Thresholds are set at statistically meaningful sigma levels
    mapped to the [0, 1] composite score range using a Gaussian CDF
    survival function approximation::

        ELEVATED  = 1 - Phi(3)  ≈ 0.0013  → 0.15  (3-sigma anomaly)
        HIGH      = 1 - Phi(5)  ≈ 2.9e-7  → 0.45  (5-sigma anomaly)
        CRITICAL  = 1 - Phi(7)  ≈ 1.3e-12 → 0.80  (7-sigma anomaly)

    These values represent the probability that a score this high arises
    from normal operational variance. The mapping to [0,1] accounts for
    the weighted composite score compression from four signal sources.
    """

    # Calibrated thresholds: 3σ, 5σ, 7σ mapped to composite score space.
    # Derivation: run benchmark suite with monitor enabled, measure the
    # composite score distribution under normal operation, then set
    # thresholds where P(score > threshold | normal) matches the target
    # false-positive rates: 1-in-750 (ELEVATED), 1-in-3.5M (HIGH),
    # 1-in-780B (CRITICAL).  The values below were calibrated against
    # the AMA benchmark suite (benchmarks/benchmark_suite.py) timing distributions.
    DEFAULT_ELEVATED_THRESHOLD = 0.15  # 3-sigma: mild concern
    DEFAULT_HIGH_THRESHOLD = 0.45  # 5-sigma: probable attack
    DEFAULT_CRITICAL_THRESHOLD = 0.80  # 7-sigma: active side-channel

    def __init__(
        self,
        elevated_threshold: float = DEFAULT_ELEVATED_THRESHOLD,
        high_threshold: float = DEFAULT_HIGH_THRESHOLD,
        critical_threshold: float = DEFAULT_CRITICAL_THRESHOLD,
        decay_rate: float = 0.95,
        evaluation_window: int = 100,
        escalation_count: int = 3,
        hysteresis_band: float = 0.05,
    ) -> None:
        """
        Args:
            elevated_threshold: Score threshold for ELEVATED level
            high_threshold: Score threshold for HIGH level
            critical_threshold: Score threshold for CRITICAL level
            decay_rate: Exponential decay factor for historical scores (0 < r < 1)
            evaluation_window: Number of recent alerts to consider
            escalation_count: Consecutive evaluations required to escalate threat level
            hysteresis_band: Score must drop below (threshold - band) to de-escalate
        """
        self.elevated_threshold = elevated_threshold
        self.high_threshold = high_threshold
        self.critical_threshold = critical_threshold
        self.decay_rate = decay_rate
        self.evaluation_window = evaluation_window
        self.escalation_count = escalation_count
        self.hysteresis_band = hysteresis_band
        self._accumulated_score: float = 0.0
        self._evaluation_count: int = 0
        # Hysteresis state: track consecutive evaluations at each candidate level
        self._consecutive_counts: Dict[ThreatLevel, int] = dict.fromkeys(ThreatLevel, 0)
        self._current_level: ThreatLevel = ThreatLevel.NOMINAL
        # Lyapunov stability tracking — rolling window of timing deviations
        self._timing_deviation_history: Deque[float] = deque(maxlen=50)
        self._lyapunov_baseline: Optional[float] = None
        # Track the timestamp of the last processed alert so we don't
        # re-append deviations from the monitor's sliding window.
        # Using timestamps instead of positional index because the
        # window slides (old alerts drop off the front), which would
        # invalidate a count-based offset.
        self._last_processed_alert_ts: float = -1.0
        #: How many alerts bearing exactly ``_last_processed_alert_ts`` have
        #: already been scored.  Without it the cursor's strict ``>`` dropped
        #: every alert that TIED the cursor, and a tie is routine: monitoring
        #: stamps with ``time.time()``, whose granularity is ~15.6 ms on
        #: Windows and whose float64 ULP at the current epoch is ~238 ns.
        #: Before the three scorers shared one cursor, a tied alert was still
        #: scored by two of them; afterwards it was scored by nothing.
        self._scored_at_cursor_ts: int = 0

    def evaluate(self, monitor_report: Dict[str, Any]) -> PostureEvaluation:
        """
        Evaluate security posture from a 3R monitor security report.

        Args:
            monitor_report: Output of AmaCryptographyMonitor.get_security_report()

        Returns:
            PostureEvaluation with threat level and recommended action
        """
        if monitor_report.get("status") == "monitoring_disabled":
            return PostureEvaluation(
                threat_level=ThreatLevel.NOMINAL,
                action=PostureAction.NONE,
                confidence=0.0,
                signals={"reason": "monitoring_disabled"},
            )

        signals: Dict[str, Any] = {}

        # `recent_alerts` is a SLIDING window (monitoring.get_security_report
        # returns `self.alerts[-10:]`), not a queue this evaluator drains.  The
        # same alert is therefore present on every call until ten newer ones
        # push it out — so scoring the window as given re-counts each alert up
        # to ten times, and the raw score stays pinned at its peak long after
        # the anomaly is over.
        #
        # `_score_lyapunov_stability` already de-duplicated by timestamp; the
        # other two scorers did not, and the accumulator below then compounded
        # the repetition.  Measured on one stale critical alert with no further
        # activity: raw_score pinned at 0.4500 forever, effective_score 0.45 ->
        # 4.83 by the fifteenth cycle against a CRITICAL threshold of 0.80,
        # reaching CRITICAL / ROTATE_AND_SWITCH at cycle 4 and never leaving.
        # MONITORING.md's "Exponential decay prevents stale anomalies from
        # driving permanent escalation" was exactly what did not happen.
        #
        # The cursor is advanced ONCE per evaluation, after every scorer has
        # seen the new alerts — sharing `_score_lyapunov_stability`'s cursor
        # without that would let whichever scorer ran first consume the alerts
        # and leave the others with nothing.
        # Score from the FULL retained alert list when the monitor provides it
        # (``scorable_alerts``), falling back to the last-10 display window.
        # An attacker who floods >=10 non-scored-type alerts (volume_spike,
        # note_artifact, ...) after a genuine timing/pattern critical could
        # otherwise push that critical out of the 10-entry ``recent_alerts``
        # window before the next poll and suppress escalation.  The cursor
        # filter below still scores each alert exactly once, so widening the
        # input cannot double-count.  (2026-08 v5 audit, item 15 — alert-window
        # suppression.)
        scorable = monitor_report.get("scorable_alerts")
        source_alerts = (
            scorable if scorable is not None else monitor_report.get("recent_alerts", [])
        )
        new_alerts = self._alerts_not_yet_scored(source_alerts)
        timing_alerts = [a for a in new_alerts if a.get("type") == "timing"]
        pattern_alerts = [a for a in new_alerts if a.get("type") == "pattern"]

        timing_score = self._score_timing_alerts(timing_alerts)
        pattern_score = self._score_pattern_alerts(pattern_alerts)
        resonance_score = self._score_resonance(monitor_report.get("resonance_analysis", {}))
        lyapunov_score = self._score_lyapunov_stability(timing_alerts)
        self._advance_alert_cursor(new_alerts)

        score = (
            timing_score * 0.45
            + pattern_score * 0.25
            + resonance_score * 0.15
            + lyapunov_score * 0.15
        )
        signals["timing_score"] = timing_score
        signals["pattern_score"] = pattern_score
        signals["resonance_score"] = resonance_score
        signals["lyapunov_score"] = lyapunov_score
        signals["raw_score"] = score
        signals["timing_alert_count"] = len(timing_alerts)
        signals["pattern_alert_count"] = len(pattern_alerts)

        # Decaying peak-hold, NOT a decaying sum.
        #
        # `acc = acc * decay + score` is a geometric series: for a constant
        # per-cycle score it converges to `score / (1 - decay)`, a gain of 20x
        # at the default decay of 0.95, and it is unbounded above.  The
        # thresholds it is compared against are documented — in this class's
        # own docstring — as per-evaluation probabilities in [0, 1]
        # ("ELEVATED = 1 - Phi(3)", "CRITICAL ... 1-in-780B"), and the table
        # tops out at 0.80.  A steady per-cycle score of only 0.04 therefore
        # reached "7-sigma, active side-channel" in the limit, and any sustained
        # signal pinned the level at CRITICAL with an effective_score that kept
        # climbing past 1.0 with nothing left to mean.
        #
        # max(score, acc * decay) keeps every property the old form was chosen
        # for and none of the ones it did not intend:
        #   * bounded in [0, 1], so the calibrated thresholds are comparable to
        #     the quantity they are compared against;
        #   * a genuine 7-sigma composite reaches CRITICAL on the evaluation
        #     that observes it, rather than after four cycles of summation;
        #   * with no new anomalies the level decays geometrically, which is
        #     what MONITORING.md promises;
        #   * `decay_rate=1.0` still means "no decay" (a running maximum), the
        #     behaviour the scenario tests use for determinism.
        self._accumulated_score = max(score, self._accumulated_score * self.decay_rate)
        self._evaluation_count += 1
        effective_score = self._accumulated_score
        signals["effective_score"] = effective_score

        # Determine threat level
        threat_level, action = self._classify(effective_score)

        # Confidence is based on sample count (need baseline before high confidence)
        total_alerts = monitor_report.get("total_alerts", 0)
        confidence = min(1.0, total_alerts / 50.0) if total_alerts > 0 else 0.0

        return PostureEvaluation(
            threat_level=threat_level,
            action=action,
            confidence=confidence,
            signals=signals,
        )

    def _alerts_not_yet_scored(self, alerts: List[Dict]) -> List[Dict]:
        """The alerts in the sliding window this evaluator has not scored yet.

        An alert with no ``timestamp`` is placed at 0.0, which the cursor —
        initialised to -1.0 — is behind exactly once.  It is therefore scored
        on the first evaluation that sees it and skipped thereafter.  Treating
        it as unconditionally new, which this did, meant
        ``_score_lyapunov_stability`` re-appended the same deviation to
        ``_timing_deviation_history`` on EVERY evaluation, growing the deque
        by one entry per cycle until it held 50 copies of one stale deviation
        and manufactured a Lyapunov instability signal out of a single alert.
        Every alert the monitor emits carries a timestamp — each
        ``self.alerts.append`` in ``monitoring.py`` sets
        ``"timestamp": time.time()`` — but the hand-built shape is not
        hypothetical: ``tests/test_adaptive_posture_scenarios.py`` emitted it,
        so the whole scenario suite ran on the always-new path and pinned none
        of the de-duplication this cursor exists to provide.

        Alerts that TIE the cursor are counted rather than compared.  A strict
        ``>`` dropped them permanently, and ties happen whenever two alerts
        land in the same clock tick.  ``_scored_at_cursor_ts`` records how many
        of the tied alerts have already been scored; the window preserves
        arrival order and only ever drops from the front, so counting them off
        in order is exact while the window still holds them, and fails towards
        skipping (never towards double-counting) if it no longer does.
        """
        # Backward-clock-step guard (2026-08 v5 audit, item 15): the monitor
        # stamps alerts with the wall clock (monitoring.time.time()).  If it
        # steps back, every freshly-created alert carries a timestamp below this
        # forward-only cursor and is silently dropped from scoring — the
        # adaptive defense goes blind under a still-detected attack.  When every
        # incoming alert predates the cursor, the clock regressed: re-baseline
        # so the new alerts are scored (re-scoring at most the retained window).
        incoming = [
            float(a["timestamp"]) for a in alerts if isinstance(a.get("timestamp"), (int, float))
        ]
        if incoming and max(incoming) < self._last_processed_alert_ts:
            self._last_processed_alert_ts = -1.0
            self._scored_at_cursor_ts = 0

        fresh: List[Dict] = []
        tie_index = 0
        for a in alerts:
            ts = a.get("timestamp")
            ts_value = float(ts) if isinstance(ts, (int, float)) else 0.0
            if ts_value > self._last_processed_alert_ts:
                fresh.append(a)
            elif ts_value == self._last_processed_alert_ts:
                if tie_index >= self._scored_at_cursor_ts:
                    fresh.append(a)
                tie_index += 1
        return fresh

    def _advance_alert_cursor(self, scored: List[Dict]) -> None:
        """Move the cursor past everything the scorers just saw.

        Called once per evaluation, after all three scorers have run.  The
        cursor only ever moves forward, so an out-of-order timestamp cannot
        rewind it and cause a re-score.

        Also maintains ``_scored_at_cursor_ts``, the number of alerts bearing
        exactly the cursor timestamp that have been scored: when the cursor
        advances it is reset to the count at the new timestamp, and when the
        newest alert merely ties the existing cursor it is incremented.  An
        alert with no timestamp is placed at 0.0, the same value the filter
        gives it, so the pair stays consistent and it is consumed once.
        """
        if not scored:
            return
        timestamps: List[float] = []
        for alert in scored:
            raw = alert.get("timestamp")
            timestamps.append(float(raw) if isinstance(raw, (int, float)) else 0.0)
        newest = max(timestamps)
        at_newest = sum(1 for ts in timestamps if ts == newest)
        if newest > self._last_processed_alert_ts:
            self._last_processed_alert_ts = newest
            self._scored_at_cursor_ts = at_newest
        elif newest == self._last_processed_alert_ts:
            self._scored_at_cursor_ts += at_newest

    def _score_timing_alerts(self, alerts: List[Dict]) -> float:
        """Score timing alerts by severity."""
        if not alerts:
            return 0.0
        score = 0.0
        for alert in alerts[-self.evaluation_window :]:
            anomaly = alert.get("anomaly")
            if anomaly is None:
                continue
            # TimingAnomaly is a dataclass with .severity and .deviation_sigma
            severity = getattr(anomaly, "severity", "")
            deviation = getattr(anomaly, "deviation_sigma", 0.0)
            if severity == "critical":
                score += min(1.0, deviation / 10.0)
            elif severity == "warning":
                score += min(0.5, deviation / 10.0)
        return min(1.0, score / max(1, len(alerts)))

    def _score_pattern_alerts(self, alerts: List[Dict]) -> float:
        """Score pattern alerts by z-score magnitude."""
        if not alerts:
            return 0.0
        score = 0.0
        for alert in alerts[-self.evaluation_window :]:
            anomaly = alert.get("anomaly", {})
            z_score = anomaly.get("z_score", 0.0)
            severity = anomaly.get("severity", "info")
            if severity == "critical":
                score += min(1.0, z_score / 10.0)
            elif severity == "warning":
                score += min(0.5, z_score / 10.0)
            else:
                score += min(0.2, z_score / 10.0)
        return min(1.0, score / max(1, len(alerts)))

    #: Width of the resonance ramp, as a multiple of the detection threshold.
    #: The score is 0 at the threshold and 1.0 at (1 + this) times it, which
    #: reproduces the original "3.0 is threshold, 10.0 is alarming" ramp
    #: exactly when the threshold is 3.0.
    _RESONANCE_RAMP = 7.0 / 3.0

    #: Threshold assumed for an analysis dict that does not carry one.
    #: :meth:`ResonanceTimingMonitor.detect_resonance` reports
    #: ``threshold_ratio`` since 5.0.0; a hand-built report (a test fixture, a
    #: replayed record from an older build) may not, and 3.0 is the bar that
    #: was hard-coded here before the detector derived its own.
    _RESONANCE_DEFAULT_THRESHOLD = 3.0

    def _score_resonance(self, resonance_data: Dict[str, Any]) -> float:
        """Score resonance analysis results.

        Normalised against the threshold the DETECTOR used, not against a
        constant.  ``detect_resonance`` derives its bar from the number of
        periodogram ordinates it searched (Fisher's g-test, ln(m / alpha)), so
        a fixed 3.0 here scored an ordinary noise maximum at m = 64 — ratio
        ~4.16 — as 0.17 of the way to "active side-channel" while the detector
        itself had correctly declined to flag it.  Scoring against the reported
        threshold keeps the two consistent by construction: 0 at the bar the
        detector actually applied, 1.0 at 3.33x it.
        """
        if not resonance_data:
            return 0.0
        scores = []
        for analysis in resonance_data.values():
            if not isinstance(analysis, dict):
                continue
            ratio = float(analysis.get("resonance_ratio", 0.0))
            threshold = float(analysis.get("threshold_ratio", self._RESONANCE_DEFAULT_THRESHOLD))
            if threshold <= 0.0:
                threshold = self._RESONANCE_DEFAULT_THRESHOLD
            scores.append(
                min(1.0, max(0.0, (ratio - threshold) / (threshold * self._RESONANCE_RAMP)))
            )
        return max(scores, default=0.0)

    def _score_lyapunov_stability(self, timing_alerts: List[Dict]) -> float:
        """Score timing distribution stability using Lyapunov analysis.

        Uses the double-helix engine's Lyapunov function to detect when
        timing distributions diverge from stable basins, indicating
        potential side-channel attack or environmental degradation.

        The timing deviation history is treated as a state vector; the
        Lyapunov function V(x) = ||x - x*||^2 measures distance from
        equilibrium. If V_dot > 0 (instability), the score increases.
        """
        # Collect deviation magnitudes from NEW timing alerts only.
        # timing_alerts comes from the monitor's recent_alerts sliding
        # window (last ~10 alerts).  The window slides — old alerts
        # drop off the front — so a positional index would become
        # stale.  Instead we compare each alert's timestamp against
        # the last one we processed.
        # `timing_alerts` has ALREADY been filtered to the not-yet-scored set
        # by `_alerts_not_yet_scored`, and the cursor is advanced once by
        # `_advance_alert_cursor` after every scorer has run.  This function
        # used to do both jobs itself, which is why it was the only scorer that
        # did not double-count — and why moving the filter up had to take the
        # cursor advance with it: three scorers sharing one cursor, each
        # advancing it, means the first to run consumes the alerts and the
        # other two see an empty list.
        appended = 0
        for alert in timing_alerts:
            anomaly = alert.get("anomaly")
            if anomaly is not None:
                deviation = getattr(anomaly, "deviation_sigma", 0.0)
                self._timing_deviation_history.append(deviation)
                appended += 1

        if appended == 0:
            # No new deviations this cycle: age the retained state instead of
            # re-asserting instability from it.
            #
            # This deque was append-only and drained by nothing but reset().
            # The scorer runs on EVERY evaluation, so once V_dot went positive
            # the baseline froze (the deliberate "boiling frog" guard below)
            # and `instability` returned the SAME non-zero value forever, with
            # zero new alerts.  That put a permanent floor of
            # 0.15 * instability under the composite score, and
            # `max(score, acc * decay)` cannot decay below its own floor.  With
            # instability saturated at 1.0 the floor is exactly 0.15 — the
            # ELEVATED threshold — while de-escalation needs score < 0.15 -
            # 0.05, so the evaluator was pinned at ELEVATED for the process
            # lifetime.  It is the precise failure the accumulator rewrite was
            # made to remove, moved one term to the left, and it falsified both
            # the comment on the accumulator and MONITORING.md's "with no new
            # anomalies the level decays geometrically".
            #
            # Dropping the oldest sample per quiet cycle means the state
            # reflects recent evidence and nothing else: after as many quiet
            # evaluations as the deque is long, there is no evidence left, and
            # clearing the baseline there lets the next burst re-baseline
            # rather than measure itself against a stale one.
            if self._timing_deviation_history:
                self._timing_deviation_history.popleft()
            if not self._timing_deviation_history:
                self._lyapunov_baseline = None
            return 0.0

        if len(self._timing_deviation_history) < 5:
            return 0.0

        # Build state vector from recent deviation history
        from ama_cryptography._numeric import Vec, zeros

        n = len(self._timing_deviation_history)
        state = Vec(list(self._timing_deviation_history))
        # Target state: zero deviations (stable cryptographic timing)
        target = zeros(n)

        # Compute Lyapunov value V(x) = ||x - x*||^2, normalized by
        # dimension so the score is the mean squared deviation.  Without
        # this normalization the value would grow as the deque fills from
        # 5 to 50 elements, producing false instability signals.
        V = lyapunov_function(state, target) / n

        # Establish baseline on first evaluation with enough data
        if self._lyapunov_baseline is None:
            self._lyapunov_baseline = V
            return 0.0

        # Compute derivative proxy: V_dot ~ V_current - V_previous
        V_dot = V - self._lyapunov_baseline

        # If Lyapunov derivative is positive, system is diverging (unstable)
        if V_dot > 0:
            # Normalize: V growing indicates instability
            instability = min(1.0, V / max(self._lyapunov_baseline * 10.0, 1e-6))
        else:
            # System is stable or converging — low score
            instability = 0.0

        # Update baseline with exponential moving average, but only when
        # the system is stable.  Updating during instability would cause the
        # baseline to track the attack, making the score converge to zero
        # ("boiling frog" problem).
        if V_dot <= 0:
            self._lyapunov_baseline = self._lyapunov_baseline * 0.9 + V * 0.1

        return instability

    def _classify(self, score: float) -> tuple:
        """
        Classify threat level from effective score with hysteresis.

        Escalation requires N consecutive evaluations above a threshold.
        De-escalation requires the score to drop below (threshold - hysteresis_band).
        This prevents oscillation and reduces false-positive-driven actions.
        """
        # Determine raw candidate level from score
        if score >= self.critical_threshold:
            candidate = ThreatLevel.CRITICAL
        elif score >= self.high_threshold:
            candidate = ThreatLevel.HIGH
        elif score >= self.elevated_threshold:
            candidate = ThreatLevel.ELEVATED
        else:
            candidate = ThreatLevel.NOMINAL

        # Level ordering for comparison
        level_order = {
            ThreatLevel.NOMINAL: 0,
            ThreatLevel.ELEVATED: 1,
            ThreatLevel.HIGH: 2,
            ThreatLevel.CRITICAL: 3,
        }
        thresholds = {
            ThreatLevel.ELEVATED: self.elevated_threshold,
            ThreatLevel.HIGH: self.high_threshold,
            ThreatLevel.CRITICAL: self.critical_threshold,
        }

        # Update consecutive counts, with the hysteresis band applied on the
        # ESCALATION side as well as the de-escalation side.
        #
        # This counted evaluations at the EXACT candidate level and zeroed
        # every other level.  Under the old unbounded accumulator
        # (acc = acc*decay + score) any sustained signal climbed steadily and
        # parked inside one band for many cycles, so the counter filled.  The
        # bounded peak-hold (acc = max(score, acc*decay)) makes the effective
        # score a SAWTOOTH instead: it jumps to the peak on an alert-bearing
        # cycle and decays 5% on the quiet ones in between.  A peak between a
        # threshold T and T/0.95^2 — about 10.8% above it, which is where a
        # low-and-slow signal naturally sits, not a contrived value — makes the
        # candidate alternate between that level and the one below on every
        # cycle.  No level ever reached escalation_count consecutive hits, and
        # a sustained anomaly stream that origin/main escalated to CRITICAL sat
        # at NOMINAL for as long as it ran.
        #
        # A level that has already been touched keeps accumulating evidence
        # while the score stays within hysteresis_band below its threshold —
        # the same band, in the same direction, that de-escalation already
        # required.  A level that has NOT been touched still needs the score to
        # reach the threshold outright, so this cannot escalate on a signal
        # that never crossed it.  A score that falls more than the band below
        # resets the counter, as before.
        for level in ThreatLevel:
            if level is ThreatLevel.NOMINAL:
                # Never an escalation target; kept in the mapping so the
                # summary and reset() see a full, consistent table.
                self._consecutive_counts[level] = (
                    self._consecutive_counts.get(level, 0) + 1
                    if candidate is ThreatLevel.NOMINAL
                    else 0
                )
                continue
            already_counting = self._consecutive_counts.get(level, 0) > 0
            floor = thresholds[level] - (self.hysteresis_band if already_counting else 0.0)
            if score >= floor:
                self._consecutive_counts[level] = self._consecutive_counts.get(level, 0) + 1
            else:
                self._consecutive_counts[level] = 0

        current_ord = level_order[self._current_level]
        candidate_ord = level_order[candidate]

        if candidate_ord > current_ord:
            # Escalation: require N consecutive evaluations.  Take the HIGHEST
            # level above the current one whose counter is satisfied — with
            # at-or-above counting, several can be.
            for level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.ELEVATED):
                if (
                    level_order[level] > current_ord
                    and self._consecutive_counts[level] >= self.escalation_count
                ):
                    self._current_level = level
                    break
        elif candidate_ord < current_ord:
            # De-escalation: require score below (threshold - hysteresis_band)
            current_threshold = thresholds.get(self._current_level, 0.0)
            if score < current_threshold - self.hysteresis_band:
                self._current_level = candidate
        # else: same level, no change needed

        # Map current level to action
        action_map = {
            ThreatLevel.NOMINAL: PostureAction.NONE,
            ThreatLevel.ELEVATED: PostureAction.INCREASE_MONITORING,
            ThreatLevel.HIGH: PostureAction.ROTATE_KEYS,
            ThreatLevel.CRITICAL: PostureAction.ROTATE_AND_SWITCH,
        }
        return self._current_level, action_map[self._current_level]

    def reset(self) -> None:
        """Reset accumulated score state."""
        self._accumulated_score = 0.0
        self._evaluation_count = 0
        self._consecutive_counts = dict.fromkeys(ThreatLevel, 0)
        self._current_level = ThreatLevel.NOMINAL
        self._timing_deviation_history.clear()
        self._lyapunov_baseline = None
        self._last_processed_alert_ts = -1.0
        self._scored_at_cursor_ts = 0


class CryptoPostureController:
    """
    Sits between application code and the cryptographic API to enforce
    posture-driven policy. Triggers key rotation and algorithm switching
    through existing infrastructure.

    Integration points:
        - Key rotation: Uses KeyRotationManager from key_management.py
        - HD derivation: Uses HDKeyDerivation from key_management.py
        - Algorithm selection: Maps AlgorithmType from crypto_api.py
        - Monitoring: Reads AmaCryptographyMonitor from ama_cryptography.monitor

    Usage:
        >>> from ama_cryptography.monitor import AmaCryptographyMonitor
        >>> monitor = AmaCryptographyMonitor(enabled=True)
        >>> controller = CryptoPostureController(monitor=monitor)
        >>> # ... application performs crypto operations ...
        >>> evaluation = controller.evaluate_and_respond()
        >>> if evaluation.action != PostureAction.NONE:
        ...     logger.warning(f"Posture action: {evaluation.action}")
    """

    # Algorithm preference ordering: higher index = stronger, WITHIN a family.
    # Keys correspond to AlgorithmType enum names in crypto_api.py.
    #
    # Strength is only meaningful between algorithms that do the same job.  A
    # single flat ladder over every AlgorithmType is not merely imprecise, it
    # is unsafe: `_trigger_algorithm_switch` upgrades to the next entry above
    # the current one, so a flat table containing both families would answer a
    # posture escalation on KYBER_1024 (a KEM) by switching to ML_DSA_65 (a
    # signature scheme).  The caller's key agreement would then be performed by
    # something that cannot perform key agreement — a functional break dressed
    # as hardening, and precisely the "selector maps input onto a real choice
    # it does not mean" failure INVARIANT-35 forbids.
    #
    # So the ladders are per family, and every comparison the controller makes
    # is scoped to the family it was constructed for.  KYBER_1024 and
    # HYBRID_KEM are ranked here — the open question this resolves — but on
    # their own ladder: the hybrid is stronger because it composes X25519 with
    # ML-KEM-1024 and survives the failure of either.
    ALGORITHM_FAMILIES: Dict[str, Dict[str, int]] = {
        "signature": {
            "ED25519": 0,
            "ML_DSA_65": 1,
            "SPHINCS_256F": 2,
            "HYBRID_SIG": 3,
        },
        "kem": {
            "KYBER_1024": 0,
            "HYBRID_KEM": 1,
        },
    }

    # Flat name -> strength view, retained because it is public API and read by
    # callers and tests.  Strengths are family-local: comparing across families
    # through this mapping is meaningless, which is why the controller never
    # does — it uses `_family_strength` throughout.  AlgorithmType members that
    # rank in no family (AES_256_GCM, an AEAD with no alternative to escalate
    # to) are deliberately absent and are rejected at construction.
    ALGORITHM_STRENGTH: Dict[str, int] = {
        name: strength
        for ladder in ALGORITHM_FAMILIES.values()
        for name, strength in ladder.items()
    }

    #: How many consecutive ATTEMPTED-and-FAILED rotations are tried before
    #: the controller stops attempting automatically.  Six, because the
    #: backoff ladder below doubles from ``rotation_cooldown / 32`` and
    #: reaches exactly ``rotation_cooldown`` on the sixth failure: at the
    #: default 300 s the rungs are 9.4 s, 18.8 s, 37.5 s, 75 s, 150 s, 300 s.
    #:
    #: FIVE of those six are ever waited on, not six.  The cap guard in
    #: ``_trigger_rotation`` runs BEFORE the backoff guard, so reaching streak
    #: 6 IS the suspension and the 300 s armed by the sixth failure is never
    #: served.  The window actually spent retrying is
    #: 9.375 + 18.75 + 37.5 + 75 + 150 = 290.625 s — 4 min 51 s at the default
    #: cooldown, not the "roughly ten minutes" this note used to claim from
    #: summing all six rungs.
    MAX_CONSECUTIVE_ROTATION_FAILURES: int = 6

    @classmethod
    def family_of(cls, algorithm: str) -> Optional[str]:
        """The ladder ``algorithm`` belongs to, or None if it ranks in none."""
        for family, ladder in cls.ALGORITHM_FAMILIES.items():
            if algorithm in ladder:
                return family
        return None

    def __init__(
        self,
        monitor: Any = None,
        evaluator: Optional[PostureEvaluator] = None,
        rotation_manager: Any = None,
        hd_derivation: Any = None,
        current_algorithm: str = "ML_DSA_65",
        rotation_cooldown: float = 300.0,
        on_rotation: Optional[Callable[[], None]] = None,
        on_algorithm_switch: Optional[Callable[[str], None]] = None,
        max_history: int = 1000,
        confirmation_mode: bool = False,
        grace_period: float = 300.0,
    ) -> None:
        """
        Args:
            monitor: AmaCryptographyMonitor instance
            evaluator: PostureEvaluator (created with defaults if None)
            rotation_manager: KeyRotationManager from key_management.py
            hd_derivation: HDKeyDerivation from key_management.py
            current_algorithm: Initial algorithm identifier
            rotation_cooldown: Minimum seconds between rotation triggers
            on_rotation: Callback invoked when key rotation is triggered
            on_algorithm_switch: Callback invoked when algorithm is switched
            max_history: Maximum number of evaluations to retain in history
            confirmation_mode: If True, destructive actions require explicit confirmation
            grace_period: Seconds before auto-executing unconfirmed actions (fail-safe)
        """
        self.monitor = monitor
        self.evaluator = evaluator or PostureEvaluator()
        self.rotation_manager = rotation_manager
        self.hd_derivation = hd_derivation
        # INVARIANT-35: a selector must never resolve weaker than it was asked,
        # and no selector may map unknown input onto a real choice.  Every
        # strength lookup below used to be `ALGORITHM_STRENGTH.get(name, 0)`, so
        # an unrecognised name silently scored 0 — the WEAKEST rung.  A
        # controller constructed with a real AlgorithmType the table did not
        # list would therefore be "upgraded" on the first CRITICAL evaluation
        # and the swap logged as hardening, while the downgrade detector —
        # seeded from the same 0 — could not see it.  Reject at the boundary
        # instead, so the defaults below are unreachable by construction rather
        # than load-bearing.
        #
        # KYBER_1024 and HYBRID_KEM now rank, on the KEM ladder; what is
        # rejected is a name that ranks in no family at all.
        family = self.family_of(current_algorithm)
        if family is None:
            ranked = ", ".join(
                f"{fam}: {sorted(ladder, key=ladder.__getitem__)}"
                for fam, ladder in self.ALGORITHM_FAMILIES.items()
            )
            raise ValueError(
                f"unrankable algorithm {current_algorithm!r}: the posture "
                f"controller escalates within a family of interchangeable "
                f"algorithms, and this name belongs to none of them ({ranked}). "
                f"AES_256_GCM is the expected case — an AEAD with no stronger "
                f"alternative to escalate to. Ranking it anyway would let a "
                f"posture escalation substitute an algorithm that does a "
                f"different job (INVARIANT-35)."
            )
        self._algorithm_family: str = family
        self._ladder: Dict[str, int] = self.ALGORITHM_FAMILIES[family]
        self.current_algorithm = current_algorithm
        self.rotation_cooldown = rotation_cooldown
        self.on_rotation = on_rotation
        self.on_algorithm_switch = on_algorithm_switch
        self.confirmation_mode = confirmation_mode
        self.grace_period = grace_period

        self._last_rotation_time: float = 0.0
        #: Consecutive rotations that were ATTEMPTED and FAILED.  Reset to 0
        #: by any rotation that succeeds, and by reset().  See
        #: _trigger_rotation for why a failure needs its own counter rather
        #: than sharing ``_last_rotation_time``.
        self._rotation_failure_streak: int = 0
        #: Earliest time a retry after a failed rotation may be attempted —
        #: the exponential backoff window.  Distinct from
        #: ``_last_rotation_time``, which throttles SUCCESSFUL rotations.
        self._rotation_retry_not_before: float = 0.0
        #: Throttles algorithm switches independently of rotations — see
        #: _execute_action for why one timer could not serve both.
        self._last_switch_time: float = 0.0
        self._rotation_count: int = 0
        self._switch_count: int = 0
        self._history: Deque[PostureEvaluation] = deque(maxlen=max_history)
        # Pre-sorted (ascending strength) for _trigger_algorithm_switch; avoids
        # repeated sort on every posture-triggered algorithm upgrade.
        # Scoped to this controller's family, so an escalation can never leave
        # it: the ladder it walks contains only interchangeable algorithms.
        self._sorted_algorithms: List[Tuple[str, int]] = sorted(
            self._ladder.items(), key=lambda x: x[1]
        )
        # Priority 5: Algorithm downgrade detection
        self._highest_algorithm_reached: int = self._family_strength(current_algorithm)
        # Priority 12: Pending actions for confirmation gate
        self._pending_actions: List[PendingAction] = []

    UNRANKED_STRENGTH = -1
    """Strength of a name absent from this controller's ladder.

    Below the weakest ranked rung, deliberately: ``current_algorithm`` is a
    public attribute, so a caller can assign a name from another family (or a
    typo) after construction.  ``.get(name, 0)`` scored that identically to the
    weakest *real* algorithm, which is the silent-downgrade shape INVARIANT-35
    exists to forbid — the detector could not distinguish "dropped to ED25519"
    from "dropped to something I cannot rank at all".  A negative rung makes
    the second case strictly worse than the first, so it always trips the
    downgrade alarm.
    """

    def _family_strength(self, algorithm: str) -> int:
        """Strength of ``algorithm`` on THIS controller's ladder.

        Never consults another family's ladder: a KEM's rung and a signature
        scheme's rung are not comparable quantities, and treating them as
        comparable is how a cross-family switch would look like an upgrade.
        """
        return self._ladder.get(algorithm, self.UNRANKED_STRENGTH)

    def evaluate_and_respond(self) -> PostureEvaluation:
        """
        Run one evaluation cycle: read monitor, assess posture, act.

        Returns:
            PostureEvaluation describing the assessment and any actions taken
        """
        if self.monitor is None:
            return PostureEvaluation(
                threat_level=ThreatLevel.NOMINAL,
                action=PostureAction.NONE,
                confidence=0.0,
                signals={"reason": "no_monitor"},
            )

        report = self.monitor.get_security_report()
        evaluation = self.evaluator.evaluate(report)
        self._history.append(evaluation)

        # Priority 5: Algorithm downgrade detection
        current_strength = self._family_strength(self.current_algorithm)
        if current_strength > self._highest_algorithm_reached:
            self._highest_algorithm_reached = current_strength
        if current_strength < self._highest_algorithm_reached:
            highest_name = next(
                (k for k, v in self._ladder.items() if v == self._highest_algorithm_reached),
                "unknown",
            )
            logger.critical(
                "Algorithm downgrade detected: %s (strength %d) -> %s (strength %d)",
                highest_name,
                self._highest_algorithm_reached,
                self.current_algorithm,
                current_strength,
            )

        # Auto-execute expired pending actions (fail-safe)
        self._process_expired_pending_actions()

        # Enforce cooldown
        now = time.time()
        # A backward wall-clock step (NTP step via chronyd/ntpd -g, a manual
        # date set, a VM snapshot restore, or a container clock adjustment)
        # makes ``now < self._last_rotation_time`` — a NEGATIVE delta that reads
        # as "still in cooldown" indefinitely and silently mutes protective
        # rotations for the whole step.  Detect the regression and re-anchor the
        # arm-time so the cooldown counts real elapsed seconds from here; the
        # worst case becomes one extra cooldown of delay, never a permanent
        # wedge.  (2026-08 v5 audit, item 15 — clock-step deaf-and-dumb wedge.)
        if now < self._last_rotation_time:
            self._last_rotation_time = now
        cooldown_active = (now - self._last_rotation_time) < self.rotation_cooldown

        destructive_actions = {
            PostureAction.ROTATE_KEYS,
            PostureAction.SWITCH_ALGORITHM,
            PostureAction.ROTATE_AND_SWITCH,
        }

        if evaluation.action in destructive_actions and not cooldown_active:
            if self.confirmation_mode:
                # Cap pending actions — prevent unbounded queue growth
                _MAX_PENDING = 10
                if len(self._pending_actions) >= _MAX_PENDING:
                    logger.warning(
                        "Pending action queue full (%d). Dropping new %s action.",
                        _MAX_PENDING,
                        evaluation.action.name,
                    )
                else:
                    # Queue action for confirmation instead of immediate execution
                    pending = PendingAction(
                        action_id=str(uuid.uuid4()),
                        action=evaluation.action,
                        reason=f"Threat level: {evaluation.threat_level.name}, "
                        f"confidence: {evaluation.confidence:.2f}",
                        timestamp=now,
                    )
                    self._pending_actions.append(pending)
                    # Update cooldown so repeated evaluations don't bypass it
                    self._last_rotation_time = now
                    logger.info(
                        "Action %s queued for confirmation (id=%s, grace_period=%.0fs)",
                        evaluation.action.name,
                        pending.action_id,
                        self.grace_period,
                    )
            else:
                # Immediate execution (default behavior)
                self._execute_action(evaluation.action)

        return evaluation

    def _execute_action(self, action: PostureAction) -> bool:
        """Execute a posture action immediately.

        Returns False when the action's rotation half was SUPPRESSED by the
        failure cap or the retry backoff and nothing else in the action ran —
        i.e. when nothing happened.  Callers that report an execution to a
        human (``confirm_action``) or that consume a queued action
        (``_process_expired_pending_actions``) must not treat a suppressed
        rotation as done.

        The two effects an action can have are throttled independently, by
        ``_last_rotation_time`` and ``_last_switch_time``, because they have
        opposite failure modes and one timer cannot serve both:

        * A rotation that was attempted and FAILED (the KMS unreachable,
          ``on_rotation`` raising) must stay retryable, so arming is delegated
          to :meth:`_trigger_rotation`, which arms only when a rotation
          actually happened or there was no mechanism to attempt.  Arming
          unconditionally here, and *before* the attempt, silently defeated
          that and made the whole attempted/succeeded distinction dead code.
        * An algorithm switch must never run back-to-back, so
          :meth:`_trigger_algorithm_switch_if_due` arms its own window whether
          or not anything else in the action succeeded.

        Sharing one timer meant ``ROTATE_AND_SWITCH`` had to pick which
        property to break, and it broke the second: a failing rotation left the
        timer unarmed, the switch rode along un-throttled, and every evaluation
        cycle climbed another rung of the ladder and fired the switch callback
        again — the exact condition the ``SWITCH_ALGORITHM`` branch armed the
        timer to prevent.

        Splitting them also means a switch no longer postpones a due rotation.
        That coupling was incidental to the shared timer, and losing it removes
        a case where escalating the algorithm suppressed the retry of a
        rotation the same threat had demanded.
        """
        if action == PostureAction.ROTATE_AND_SWITCH:
            # arms the rotation throttle iff it succeeded
            rotated = self._trigger_rotation()
            self._trigger_algorithm_switch_if_due()
            # False when the rotation half was suppressed: the action names two
            # effects and only one of them was attempted.  The switch half has
            # its own due-window, so a caller that re-tries this action later
            # does not switch twice.
            return rotated
        if action == PostureAction.ROTATE_KEYS:
            return self._trigger_rotation()  # arms the throttle iff it succeeded
        if action == PostureAction.SWITCH_ALGORITHM:
            # False when the cooldown suppressed the switch: confirm_action
            # keeps the pending action instead of popping it and telling the
            # operator a switch ran that never did — mirroring the rotation
            # half above.
            return self._trigger_algorithm_switch_if_due()
        return True

    def _process_expired_pending_actions(self) -> None:
        """Auto-execute pending actions that have exceeded the grace period.

        Respects ``rotation_cooldown`` between auto-executed actions so that
        multiple simultaneously-expired actions do not bypass throttling.
        """
        now = time.time()
        # Same backward-clock-step guard as evaluate_and_respond: a step makes
        # ``now < pa.timestamp`` (the action was queued at a higher clock), so
        # ``now - pa.timestamp`` is negative and the grace period never elapses
        # — the queued protective action would never auto-execute.  Re-anchor
        # the queue time on a detected regression so the grace period counts
        # forward.  (2026-08 v5 audit, item 15.)
        if now < self._last_rotation_time:
            self._last_rotation_time = now
        still_pending = []
        for pa in self._pending_actions:
            if pa.confirmed:
                continue
            if now < pa.timestamp:
                pa.timestamp = now
            if (now - pa.timestamp) >= self.grace_period:
                # Respect cooldown between auto-executed actions
                if (now - self._last_rotation_time) < self.rotation_cooldown:
                    still_pending.append(pa)
                    continue
                logger.warning(
                    "Auto-executing pending action %s (id=%s) after grace period expiry",
                    pa.action.name,
                    pa.action_id,
                )
                if not self._execute_action(pa.action):
                    # Same reason as confirm_action: a suppressed rotation did
                    # not happen, so the action is not done and must not be
                    # dropped from the queue.
                    logger.warning(
                        "Pending action %s (id=%s) was SUPPRESSED, not executed; "
                        "it stays queued.",
                        pa.action.name,
                        pa.action_id,
                    )
                    still_pending.append(pa)
            else:
                still_pending.append(pa)
        self._pending_actions = still_pending

    def confirm_action(self, action_id: str) -> bool:
        """
        Confirm and execute a pending action.

        The confirmed action is removed from _pending_actions immediately
        after execution to prevent stale entries from accumulating.

        Args:
            action_id: The ID of the pending action to confirm

        Returns:
            True if action was found and executed, False otherwise
        """
        for i, pa in enumerate(self._pending_actions):
            if pa.action_id == action_id and not pa.confirmed:
                if not self._execute_action(pa.action):
                    # SUPPRESSED, not executed.  This used to set
                    # pa.confirmed, pop the action, log "Confirmed and executed
                    # action" and return True — consuming an explicit human
                    # confirmation for a rotation that never ran, with no way
                    # for the operator to tell.  The action stays pending and
                    # unconfirmed so a later call can carry it out once the
                    # backoff elapses, or so reset() can clear a suspension.
                    logger.warning(
                        "Confirmed action %s (id=%s) was SUPPRESSED, not executed: "
                        "the rotation throttle/backoff (after %d consecutive "
                        "failures) or the algorithm-switch cooldown declined it. "
                        "The action remains pending. See "
                        "get_posture_summary()['rotation_suspended']; a suspended "
                        "controller resumes only on reset().",
                        pa.action.name,
                        action_id,
                        self._rotation_failure_streak,
                    )
                    return False
                pa.confirmed = True
                self._pending_actions.pop(i)
                logger.info("Confirmed and executed action %s (id=%s)", pa.action.name, action_id)
                return True
        return False

    def reject_action(self, action_id: str) -> bool:
        """
        Reject and cancel a pending action.

        Args:
            action_id: The ID of the pending action to reject

        Returns:
            True if action was found and cancelled, False if not found
        """
        original_len = len(self._pending_actions)
        self._pending_actions = [pa for pa in self._pending_actions if pa.action_id != action_id]
        found = len(self._pending_actions) < original_len
        if found:
            logger.info("Rejected pending action (id=%s)", action_id)
        else:
            logger.warning("Attempted to reject unknown action (id=%s)", action_id)
        return found

    def acknowledge_downgrade(self, reason: str) -> None:
        """
        Explicitly acknowledge and allow an algorithm downgrade.

        Resets _highest_algorithm_reached to current algorithm strength,
        allowing de-escalation. The reason is logged for audit.

        Args:
            reason: Human-readable justification for the downgrade
        """
        old_highest = self._highest_algorithm_reached
        self._highest_algorithm_reached = self._family_strength(self.current_algorithm)
        logger.info(
            "Algorithm downgrade acknowledged: strength %d -> %d, reason: %s",
            old_highest,
            self._highest_algorithm_reached,
            reason,
        )

    def _rotation_retry_delay(self, streak: int) -> float:
        """Backoff before retrying after ``streak`` consecutive failures.

        Doubles per failure and lands exactly on ``rotation_cooldown`` at
        ``MAX_CONSECUTIVE_ROTATION_FAILURES``, so the ladder is derived from
        the throttle the caller already configured rather than from a second
        knob nobody asked for.  Clamped at ``rotation_cooldown`` so a caller
        who raises the cap cannot produce a delay longer than the cooldown a
        SUCCESSFUL rotation would impose.
        """
        cap = max(1, self.MAX_CONSECUTIVE_ROTATION_FAILURES)
        exponent = min(max(streak, 1), cap) - 1
        return float(self.rotation_cooldown) * (2.0**exponent) / (2.0 ** (cap - 1))

    def _trigger_rotation(self) -> bool:
        """Trigger key rotation through existing infrastructure.

        Returns True when an attempt was MADE (whether it then succeeded or
        failed) or when there was no mechanism to attempt, and False when the
        call was SUPPRESSED by the cap or the backoff guard.  The return value
        exists because ``confirm_action`` reported True and logged "Confirmed
        and executed action" for a suppressed rotation, popping the operator's
        pending action for an execution that did not happen; the guards had no
        way to say so.

        Failed rotations are throttled by their own exponential backoff and
        capped, which is a different thing from the ``rotation_cooldown``
        window a SUCCESSFUL rotation arms.

        Both are needed, and the reason is a measurement.  Arming
        ``_last_rotation_time`` unconditionally in ``_execute_action`` — which
        is what this class did before — made the whole attempted/succeeded
        distinction dead code and suppressed every retry of a rotation that
        had never happened.  Deleting that line fixed the dead code and
        removed the only throttle a FAILING rotation had: over 20 evaluation
        cycles at sustained CRITICAL, a raising ``on_rotation`` callback was
        invoked 20 times, ``_rotation_count`` reached 20, the cooldown was
        never armed, and with a caller-supplied KMS-backed manager whose
        ``initiate_rotation`` raises, 20 fresh ``posture-rotation-N`` keys
        were registered — one per cycle, unbounded in the evaluation rate.
        (The same run with a rotation that succeeds: 1 invocation, cooldown
        armed.)

        So: retryable, but not free.  Each consecutive failure doubles the
        wait (see ``_rotation_retry_delay``), and after
        ``MAX_CONSECUTIVE_ROTATION_FAILURES`` the controller stops attempting
        and says so at CRITICAL.  Continuing to hammer a rotation mechanism
        that has failed six times with growing backoff does not rotate
        anything; it burns key identifiers and derivation indices, floods the
        callback, and buries the operator's evidence.

        A rotation that SUCCEEDS clears the streak, so a mechanism that comes
        back resumes immediately — WHILE THE CONTROLLER IS STILL ATTEMPTING.
        Once the cap is reached there is no next success to have: the guard
        below returns before ``get_active_key`` or ``on_rotation`` is touched,
        and the streak is only cleared downstream of it.  ``reset()`` is
        therefore the sole exit from the suspended state, which is what the
        CRITICAL log says and what this docstring used to imply otherwise.

        ``get_posture_summary()`` reports ``rotation_failure_streak`` and
        ``rotation_suspended`` so the stopped state is readable rather than
        silent.
        """
        now = time.time()

        if self._rotation_failure_streak >= self.MAX_CONSECUTIVE_ROTATION_FAILURES:
            # Logged at DEBUG, not WARNING: the CRITICAL below fires once when
            # the cap is reached, and repeating it every evaluation would bury
            # it under its own copies.  The state is on get_posture_summary().
            logger.debug(
                "Posture rotation suspended after %d consecutive failures; "
                "not attempting. Fix the rotation mechanism and call reset().",
                self._rotation_failure_streak,
            )
            return False

        # Backward-clock-step guard (2026-08 v5 audit, item 15): the retry
        # backoff never exceeds rotation_cooldown (it doubles from
        # rotation_cooldown/32 and caps at rotation_cooldown on the sixth
        # failure), so a remaining backoff larger than that is impossible under
        # a monotonic clock and means the wall clock stepped back, leaving a
        # stale future deadline.  Clear it rather than suppress retries for the
        # step's duration.
        if self._rotation_retry_not_before - now > self.rotation_cooldown:
            self._rotation_retry_not_before = now
        if self._rotation_failure_streak and now < self._rotation_retry_not_before:
            logger.info(
                "Posture rotation retry suppressed: %.0fs of the %.0fs backoff "
                "after %d consecutive failure(s) remain",
                self._rotation_retry_not_before - now,
                self._rotation_retry_delay(self._rotation_failure_streak),
                self._rotation_failure_streak,
            )
            return False

        # AFTER the two guards: a suppressed attempt must not burn a key
        # identifier or an HD derivation index.  Those are minted from this
        # counter, and incrementing it per suppressed cycle would reintroduce
        # the unbounded growth by another route.
        self._rotation_count += 1

        derivation_path: Optional[str] = None
        # ``attempted`` = a rotation mechanism was actually invoked;
        # ``succeeded`` = a mechanism that ACTUALLY ROTATES KEYS completed
        # without raising.  These gate whether the cooldown timer is armed
        # (see the end of the method).
        #
        # The key-rotating mechanism (``rotation_manager``) is tracked
        # SEPARATELY from the ``on_rotation`` notifier.  ``on_rotation`` is
        # documented as a callback ("invoked when key rotation is triggered"),
        # not a rotation mechanism, so a notifier that returns normally must NOT
        # mark the rotation successful when the KMS-backed rotation was
        # attempted and failed — otherwise a healthy notifier over a broken KMS
        # reports success, arms the cooldown, clears the failure streak, and the
        # MAX_CONSECUTIVE_ROTATION_FAILURES cap never trips on an unmitigated
        # threat (2026-08 v5 audit, item 15 — rotation success accounting).
        attempted = False
        succeeded = False
        manager_attempted = False
        manager_succeeded = False

        if self.rotation_manager is not None:
            # Guarded like every other rotation_manager call in this flow.
            # get_active_key was the one unguarded fetch: the shipped
            # KeyRotationManager's is a bare attribute read that cannot
            # raise, but the manager is caller-suppliable precisely so a
            # remote KMS can back it, and this module's own contract (and
            # the comment below) names "the KMS is unreachable" as a
            # failure the posture flow must survive.  A raising fetch is an
            # attempted-and-failed rotation: the cooldown stays unarmed and
            # the next evaluation retries, exactly as a failed register/
            # initiate does.
            try:
                active_key = self.rotation_manager.get_active_key()
            except Exception as e:
                logger.warning("Posture key rotation failed: could not read the active key: %s", e)
                active_key = None
                manager_attempted = True
            if active_key is not None:
                manager_attempted = True
                new_key_id = f"posture-rotation-{self._rotation_count}"

                # Derive new key material via BIP32 if HD derivation is available
                if self.hd_derivation is not None:
                    derivation_path = f"m/44'/0'/{self._rotation_count}'/0/0"
                    try:
                        self.hd_derivation.derive_path(derivation_path)
                    except Exception as e:
                        logger.warning("HD derivation failed during posture rotation: %s", e)
                        derivation_path = None

                try:
                    self.rotation_manager.register_key(
                        new_key_id,
                        purpose="signing",
                        derivation_path=derivation_path,
                        expires_in=timedelta(days=30),
                    )
                    self.rotation_manager.initiate_rotation(active_key, new_key_id)
                    logger.info("Posture-triggered key rotation: %s -> %s", active_key, new_key_id)
                    manager_succeeded = True
                except Exception as e:
                    logger.warning("Posture key rotation failed: %s", e)

        attempted = manager_attempted
        succeeded = manager_succeeded

        if self.on_rotation is not None:
            attempted = True
            try:
                self.on_rotation()
                # The notifier can only CONFIRM success when the key-rotating
                # mechanism did not fail.  If a rotation_manager was attempted
                # and failed, the notifier does not rescue it (the KMS failure
                # dominates, so the streak/backoff still accrues); if no
                # rotation_manager is configured, the callback is the only
                # mechanism and its success stands — preserving the
                # callback-only deployment.
                if not (manager_attempted and not manager_succeeded):
                    succeeded = True
            except Exception as e:
                logger.warning("Rotation callback failed: %s", e)

        # Arm the cooldown only when a rotation actually happened, or when there
        # was no mechanism to attempt (a no-op trigger — preserves prior
        # behaviour).  A rotation that was *attempted and failed* (e.g. the KMS
        # is unreachable) must NOT arm the cooldown: otherwise the posture
        # engine "believes it acted", suppressing every retry for the full
        # cooldown window while the threat that demanded rotation persists.
        #
        # A failed attempt instead arms the backoff, which is the same idea at
        # a shorter and growing horizon: retryable, but not once per
        # evaluation cycle.  The two are mutually exclusive by construction —
        # a rotation either happened or it did not.
        if succeeded or not attempted:
            self._last_rotation_time = time.time()
            self._rotation_failure_streak = 0
            self._rotation_retry_not_before = 0.0
            return True

        self._rotation_failure_streak += 1
        self._rotation_retry_not_before = time.time() + self._rotation_retry_delay(
            self._rotation_failure_streak
        )
        if self._rotation_failure_streak >= self.MAX_CONSECUTIVE_ROTATION_FAILURES:
            logger.critical(
                "Posture key rotation has failed %d consecutive times; the "
                "controller will stop attempting it. The threat that demanded "
                "rotation is NOT addressed. Repair the rotation mechanism and "
                "call reset() to resume.",
                self._rotation_failure_streak,
            )
        else:
            logger.warning(
                "Posture key rotation failed (%d consecutive); next attempt in " "%.0fs",
                self._rotation_failure_streak,
                self._rotation_retry_delay(self._rotation_failure_streak),
            )
        # Attempted and failed is still ATTEMPTED: the caller asked for a
        # rotation and one was tried.  Only the two guards above suppress.
        return True

    def _trigger_algorithm_switch_if_due(self) -> bool:
        """Switch algorithms unless the switch throttle is still cooling down.

        Returns ``True`` when a switch attempt was allowed through, ``False``
        when the cooldown suppressed it — so a caller consuming a pending
        ``SWITCH_ALGORITHM`` action can tell "executed" from "skipped at
        DEBUG level".  ``confirm_action`` used to pop the operator's pending
        switch and log "Confirmed and executed action" for a switch this
        method silently declined: the same consumed-confirmation defect the
        rotation half already had fixed.

        Arms ``_last_switch_time`` on every switch attempt that is allowed
        through — not only on ones that changed the algorithm — so a controller
        already at the top of its ladder cannot spin the callback either.
        """
        now = time.time()
        # Backward-clock-step guard (2026-08 v5 audit, item 15): re-anchor a
        # switch-time that a clock regression left in the future, so the switch
        # cooldown cannot wedge on a negative delta.
        if now < self._last_switch_time:
            self._last_switch_time = now
        if (now - self._last_switch_time) < self.rotation_cooldown:
            logger.debug(
                "Algorithm switch suppressed: %.0fs of the %.0fs switch cooldown remain",
                self.rotation_cooldown - (now - self._last_switch_time),
                self.rotation_cooldown,
            )
            return False
        self._last_switch_time = now
        self._trigger_algorithm_switch()
        return True

    def _trigger_algorithm_switch(self) -> None:
        """Switch to a stronger algorithm.

        Refuses to act on an UNRANKABLE current algorithm.  ``UNRANKED_STRENGTH
        = -1`` exists because ``current_algorithm`` is a public attribute and a
        caller can assign a name from another family (or a typo) after
        construction, where -1 always trips the downgrade alarm.  It did — and
        then this method used the same -1 as the bar to beat, so
        ``strength > -1`` matched the FIRST entry of the ascending ladder and
        the controller "escalated" to its WEAKEST rung.  On the signature
        ladder that is ED25519, a classical scheme, selected in response to a
        detected threat, logged as an upgrade and handed to
        ``on_algorithm_switch``.  The pre-branch code, ``ALGORITHM_STRENGTH.get(
        name, 0)``, resolved the same input to the rung above 0 — so the
        unrankable-name handling made the selection strictly weaker than what
        it replaced, which is the INVARIANT-35 downgrade it was added to
        prevent.

        There is no defined "next rung above" a name that is not on the ladder,
        so there is nothing to switch to.  The controller stays where it is and
        says so at CRITICAL: an unrankable ``current_algorithm`` means the
        posture machinery is operating on a value it cannot reason about, and
        that is an operator-visible fault, not a routine skip.
        """
        current_strength = self._family_strength(self.current_algorithm)
        if current_strength == self.UNRANKED_STRENGTH:
            logger.critical(
                "Posture escalation refused: current_algorithm %r is not on the "
                "%s strength ladder, so there is no next rung above it. The "
                "controller is unchanged. Assign a name from ALGORITHM_FAMILIES.",
                self.current_algorithm,
                self._algorithm_family,
            )
            return
        # Use pre-sorted list (ascending strength) cached at init time
        new_algorithm = self.current_algorithm
        for alg, strength in self._sorted_algorithms:
            if strength > current_strength:
                new_algorithm = alg
                break

        if new_algorithm != self.current_algorithm:
            old = self.current_algorithm
            self.current_algorithm = new_algorithm
            self._switch_count += 1
            logger.info("Posture-triggered algorithm switch: %s -> %s", old, new_algorithm)

            if self.on_algorithm_switch is not None:
                try:
                    self.on_algorithm_switch(new_algorithm)
                except Exception as e:
                    logger.warning("Algorithm switch callback failed: %s", e)

    def get_posture_summary(self) -> Dict[str, Any]:
        """
        Get summary of posture controller state.

        Returns:
            Dict with current state, history stats, and action counts
        """
        recent: List[PostureEvaluation] = list(self._history)[-10:] if self._history else []
        return {
            "current_algorithm": self.current_algorithm,
            "current_threat_level": (
                recent[-1].threat_level.name if recent else ThreatLevel.NOMINAL.name
            ),
            "rotation_count": self._rotation_count,
            # A controller that has stopped attempting rotation while the
            # threat that demanded it persists is the most important thing an
            # operator can know about this object, and until these two keys
            # existed there was no way to read it off the public surface.
            "rotation_failure_streak": self._rotation_failure_streak,
            "rotation_suspended": (
                self._rotation_failure_streak >= self.MAX_CONSECUTIVE_ROTATION_FAILURES
            ),
            "switch_count": self._switch_count,
            "evaluation_count": len(self._history),
            "highest_algorithm_reached": self._highest_algorithm_reached,
            "confirmation_mode": self.confirmation_mode,
            "pending_actions": [
                {
                    "action_id": pa.action_id,
                    "action": pa.action.name,
                    "reason": pa.reason,
                    "timestamp": pa.timestamp,
                    "confirmed": pa.confirmed,
                }
                for pa in self._pending_actions
            ],
            "recent_evaluations": [
                {
                    "threat_level": e.threat_level.name,
                    "action": e.action.name,
                    "confidence": e.confidence,
                    "timestamp": e.timestamp,
                }
                for e in recent
            ],
        }

    def reset(self) -> None:
        """Reset controller state."""
        self.evaluator.reset()
        self._last_rotation_time = 0.0
        self._rotation_failure_streak = 0
        self._rotation_retry_not_before = 0.0
        self._last_switch_time = 0.0
        self._rotation_count = 0
        self._switch_count = 0
        self._history.clear()
        self._highest_algorithm_reached = self._family_strength(self.current_algorithm)
        self._pending_actions.clear()
