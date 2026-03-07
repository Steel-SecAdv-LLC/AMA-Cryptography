#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
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
Version: 2.0
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional

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


class PostureEvaluator:
    """
    Evaluates cryptographic security posture from 3R monitor output.

    Consumes timing anomalies, pattern anomalies, and resonance analysis
    from AmaCryptographyMonitor to derive a threat level and recommended
    action. Thresholds are configurable for different deployment contexts.

    The evaluator uses a weighted scoring model:
        - Timing anomalies (critical/warning) contribute severity-weighted scores
        - Pattern anomalies contribute based on z-score magnitude
        - Resonance detection contributes based on resonance ratio
        - Scores are normalized against configurable thresholds
    """

    def __init__(
        self,
        elevated_threshold: float = 0.3,
        high_threshold: float = 0.6,
        critical_threshold: float = 0.85,
        decay_rate: float = 0.95,
        evaluation_window: int = 100,
    ) -> None:
        """
        Args:
            elevated_threshold: Score threshold for ELEVATED level
            high_threshold: Score threshold for HIGH level
            critical_threshold: Score threshold for CRITICAL level
            decay_rate: Exponential decay factor for historical scores (0 < r < 1)
            evaluation_window: Number of recent alerts to consider
        """
        self.elevated_threshold = elevated_threshold
        self.high_threshold = high_threshold
        self.critical_threshold = critical_threshold
        self.decay_rate = decay_rate
        self.evaluation_window = evaluation_window
        self._accumulated_score: float = 0.0
        self._evaluation_count: int = 0

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
        score = 0.0

        # Score timing anomalies
        recent_alerts = monitor_report.get("recent_alerts", [])
        timing_alerts = [a for a in recent_alerts if a.get("type") == "timing"]
        pattern_alerts = [a for a in recent_alerts if a.get("type") == "pattern"]

        timing_score = self._score_timing_alerts(timing_alerts)
        pattern_score = self._score_pattern_alerts(pattern_alerts)
        resonance_score = self._score_resonance(monitor_report.get("resonance_analysis", {}))

        score = timing_score * 0.5 + pattern_score * 0.3 + resonance_score * 0.2
        signals["timing_score"] = timing_score
        signals["pattern_score"] = pattern_score
        signals["resonance_score"] = resonance_score
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
            severity = getattr(anomaly, "severity", alert.get("anomaly", {}).get("severity", ""))
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
        max_ratio = 0.0
        for _op, analysis in resonance_data.items():
            ratio = analysis.get("resonance_ratio", 0.0)
            if ratio > max_ratio:
                max_ratio = ratio
        # Normalize: ratio of 3.0 is threshold, 10.0 is alarming
        return min(1.0, max(0.0, (max_ratio - 3.0) / 7.0))

    def _classify(self, score: float) -> tuple:
        """Classify threat level from effective score."""
        if score >= self.critical_threshold:
            return ThreatLevel.CRITICAL, PostureAction.ROTATE_AND_SWITCH
        elif score >= self.high_threshold:
            return ThreatLevel.HIGH, PostureAction.ROTATE_KEYS
        elif score >= self.elevated_threshold:
            return ThreatLevel.ELEVATED, PostureAction.INCREASE_MONITORING
        return ThreatLevel.NOMINAL, PostureAction.NONE

    def reset(self) -> None:
        """Reset accumulated score state."""
        self._accumulated_score = 0.0
        self._evaluation_count = 0


class CryptoPostureController:
    """
    Sits between application code and the cryptographic API to enforce
    posture-driven policy. Triggers key rotation and algorithm switching
    through existing infrastructure.

    Integration points:
        - Key rotation: Uses KeyRotationManager from key_management.py
        - HD derivation: Uses HDKeyDerivation from key_management.py
        - Algorithm selection: Maps AlgorithmType from crypto_api.py
        - Monitoring: Reads AmaCryptographyMonitor from ama_cryptography_monitor.py

    Usage:
        >>> from ama_cryptography_monitor import AmaCryptographyMonitor
        >>> monitor = AmaCryptographyMonitor(enabled=True)
        >>> controller = CryptoPostureController(monitor=monitor)
        >>> # ... application performs crypto operations ...
        >>> evaluation = controller.evaluate_and_respond()
        >>> if evaluation.action != PostureAction.NONE:
        ...     logger.warning(f"Posture action: {evaluation.action}")
    """

    # Algorithm preference ordering: higher index = stronger
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
        """
        self.monitor = monitor
        self.evaluator = evaluator or PostureEvaluator()
        self.rotation_manager = rotation_manager
        self.hd_derivation = hd_derivation
        self.current_algorithm = current_algorithm
        self.rotation_cooldown = rotation_cooldown
        self.on_rotation = on_rotation
        self.on_algorithm_switch = on_algorithm_switch

        self._last_rotation_time: float = 0.0
        self._rotation_count: int = 0
        self._switch_count: int = 0
        self._history: List[PostureEvaluation] = []

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

        # Enforce cooldown
        now = time.time()
        cooldown_active = (now - self._last_rotation_time) < self.rotation_cooldown

        if evaluation.action == PostureAction.ROTATE_AND_SWITCH and not cooldown_active:
            self._trigger_rotation()
            self._trigger_algorithm_switch()
        elif evaluation.action == PostureAction.ROTATE_KEYS and not cooldown_active:
            self._trigger_rotation()
        elif evaluation.action == PostureAction.SWITCH_ALGORITHM and not cooldown_active:
            self._trigger_algorithm_switch()

        return evaluation

    def _trigger_rotation(self) -> None:
        """Trigger key rotation through existing infrastructure."""
        self._last_rotation_time = time.time()
        self._rotation_count += 1

        if self.rotation_manager is not None:
            active_key = self.rotation_manager.get_active_key()
            if active_key is not None:
                new_key_id = f"posture-rotation-{self._rotation_count}"
                # Derive new key via BIP32 if HD derivation is available
                if self.hd_derivation is not None:
                    try:
                        path = f"m/44'/0'/{self._rotation_count}'/0/0"
                        _derived_key, _chain = self.hd_derivation.derive_path(path)
                    except (ValueError, Exception) as e:
                        logger.warning("HD derivation failed during posture rotation: %s", e)

                try:
                    self.rotation_manager.register_key(
                        new_key_id,
                        purpose="signing",
                        expires_in=timedelta(days=30),
                    )
                    self.rotation_manager.initiate_rotation(active_key, new_key_id)
                    logger.info(
                        "Posture-triggered key rotation: %s → %s", active_key, new_key_id
                    )
                except (ValueError, Exception) as e:
                    logger.warning("Posture key rotation failed: %s", e)

        if self.on_rotation is not None:
            try:
                self.on_rotation()
            except Exception as e:
                logger.warning("Rotation callback failed: %s", e)

    def _trigger_algorithm_switch(self) -> None:
        """Switch to a stronger algorithm."""
        current_strength = self.ALGORITHM_STRENGTH.get(self.current_algorithm, 0)
        # Find next stronger algorithm
        candidates = sorted(
            self.ALGORITHM_STRENGTH.items(), key=lambda x: x[1]
        )
        new_algorithm = self.current_algorithm
        for alg, strength in candidates:
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
        recent = self._history[-10:] if self._history else []
        return {
            "current_algorithm": self.current_algorithm,
            "current_threat_level": (
                recent[-1].threat_level.name if recent else ThreatLevel.NOMINAL.name
            ),
            "rotation_count": self._rotation_count,
            "switch_count": self._switch_count,
            "evaluation_count": len(self._history),
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
