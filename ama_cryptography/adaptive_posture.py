#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

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
Version: 2.2.0
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
    # the AMA benchmark suite (benchmark_suite.py) timing distributions.
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

        # Score timing anomalies
        recent_alerts = monitor_report.get("recent_alerts", [])
        timing_alerts = [a for a in recent_alerts if a.get("type") == "timing"]
        pattern_alerts = [a for a in recent_alerts if a.get("type") == "pattern"]

        timing_score = self._score_timing_alerts(timing_alerts)
        pattern_score = self._score_pattern_alerts(pattern_alerts)
        resonance_score = self._score_resonance(monitor_report.get("resonance_analysis", {}))
        lyapunov_score = self._score_lyapunov_stability(timing_alerts)

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

        # Apply exponential decay to accumulated score
        self._accumulated_score = self._accumulated_score * self.decay_rate + score
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

    def _score_resonance(self, resonance_data: Dict[str, Any]) -> float:
        """Score resonance analysis results."""
        if not resonance_data:
            return 0.0
        max_ratio = max(
            (analysis.get("resonance_ratio", 0.0) for analysis in resonance_data.values()),
            default=0.0,
        )
        # Normalize: ratio of 3.0 is threshold, 10.0 is alarming
        return min(1.0, max(0.0, (max_ratio - 3.0) / 7.0))

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
        for alert in timing_alerts:
            ts = alert.get("timestamp", 0.0)
            if ts <= self._last_processed_alert_ts:
                continue
            anomaly = alert.get("anomaly")
            if anomaly is not None:
                deviation = getattr(anomaly, "deviation_sigma", 0.0)
                self._timing_deviation_history.append(deviation)
            self._last_processed_alert_ts = ts

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

        # Update consecutive counts
        for level in ThreatLevel:
            if level == candidate:
                self._consecutive_counts[level] = self._consecutive_counts.get(level, 0) + 1
            else:
                self._consecutive_counts[level] = 0

        # Level ordering for comparison
        level_order = {
            ThreatLevel.NOMINAL: 0,
            ThreatLevel.ELEVATED: 1,
            ThreatLevel.HIGH: 2,
            ThreatLevel.CRITICAL: 3,
        }

        current_ord = level_order[self._current_level]
        candidate_ord = level_order[candidate]

        if candidate_ord > current_ord:
            # Escalation: require N consecutive evaluations
            if self._consecutive_counts[candidate] >= self.escalation_count:
                self._current_level = candidate
        elif candidate_ord < current_ord:
            # De-escalation: require score below (threshold - hysteresis_band)
            thresholds = {
                ThreatLevel.ELEVATED: self.elevated_threshold,
                ThreatLevel.HIGH: self.high_threshold,
                ThreatLevel.CRITICAL: self.critical_threshold,
            }
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

    # Algorithm preference ordering: higher index = stronger.
    # Keys correspond to AlgorithmType enum names in crypto_api.py.
    ALGORITHM_STRENGTH = {
        "ED25519": 0,
        "ML_DSA_65": 1,
        "SPHINCS_256F": 2,
        "HYBRID_SIG": 3,
    }

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
        self.current_algorithm = current_algorithm
        self.rotation_cooldown = rotation_cooldown
        self.on_rotation = on_rotation
        self.on_algorithm_switch = on_algorithm_switch
        self.confirmation_mode = confirmation_mode
        self.grace_period = grace_period

        self._last_rotation_time: float = 0.0
        self._rotation_count: int = 0
        self._switch_count: int = 0
        self._history: Deque[PostureEvaluation] = deque(maxlen=max_history)
        # Pre-sorted (ascending strength) for _trigger_algorithm_switch; avoids
        # repeated sort on every posture-triggered algorithm upgrade.
        self._sorted_algorithms: List[Tuple[str, int]] = sorted(
            self.ALGORITHM_STRENGTH.items(), key=lambda x: x[1]
        )
        # Priority 5: Algorithm downgrade detection
        self._highest_algorithm_reached: int = self.ALGORITHM_STRENGTH.get(current_algorithm, 0)
        # Priority 12: Pending actions for confirmation gate
        self._pending_actions: List[PendingAction] = []

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
        current_strength = self.ALGORITHM_STRENGTH.get(self.current_algorithm, 0)
        if current_strength > self._highest_algorithm_reached:
            self._highest_algorithm_reached = current_strength
        if current_strength < self._highest_algorithm_reached:
            highest_name = next(
                (
                    k
                    for k, v in self.ALGORITHM_STRENGTH.items()
                    if v == self._highest_algorithm_reached
                ),
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

    def _execute_action(self, action: PostureAction) -> None:
        """Execute a posture action immediately.

        Updates ``_last_rotation_time`` so the cooldown window applies
        consistently regardless of whether the action was queued via
        confirmation mode or executed immediately.
        """
        self._last_rotation_time = time.time()
        if action == PostureAction.ROTATE_AND_SWITCH:
            self._trigger_rotation()
            self._trigger_algorithm_switch()
        elif action == PostureAction.ROTATE_KEYS:
            self._trigger_rotation()
        elif action == PostureAction.SWITCH_ALGORITHM:
            self._trigger_algorithm_switch()

    def _process_expired_pending_actions(self) -> None:
        """Auto-execute pending actions that have exceeded the grace period.

        Respects ``rotation_cooldown`` between auto-executed actions so that
        multiple simultaneously-expired actions do not bypass throttling.
        """
        now = time.time()
        still_pending = []
        for pa in self._pending_actions:
            if pa.confirmed:
                continue
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
                self._execute_action(pa.action)
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
                pa.confirmed = True
                self._execute_action(pa.action)
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
        self._highest_algorithm_reached = self.ALGORITHM_STRENGTH.get(self.current_algorithm, 0)
        logger.info(
            "Algorithm downgrade acknowledged: strength %d -> %d, reason: %s",
            old_highest,
            self._highest_algorithm_reached,
            reason,
        )

    def _trigger_rotation(self) -> None:
        """Trigger key rotation through existing infrastructure."""
        self._last_rotation_time = time.time()
        self._rotation_count += 1

        derivation_path: Optional[str] = None

        if self.rotation_manager is not None:
            active_key = self.rotation_manager.get_active_key()
            if active_key is not None:
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
                    logger.info("Posture-triggered key rotation: %s → %s", active_key, new_key_id)
                except Exception as e:
                    logger.warning("Posture key rotation failed: %s", e)

        if self.on_rotation is not None:
            try:
                self.on_rotation()
            except Exception as e:
                logger.warning("Rotation callback failed: %s", e)

    def _trigger_algorithm_switch(self) -> None:
        """Switch to a stronger algorithm."""
        current_strength = self.ALGORITHM_STRENGTH.get(self.current_algorithm, 0)
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
            logger.info("Posture-triggered algorithm switch: %s → %s", old, new_algorithm)

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
        self._rotation_count = 0
        self._switch_count = 0
        self._history.clear()
        self._highest_algorithm_reached = self.ALGORITHM_STRENGTH.get(self.current_algorithm, 0)
        self._pending_actions.clear()
