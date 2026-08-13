#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for the Adaptive Cryptographic Posture System.

Validates:
    - PostureEvaluator threat classification thresholds
    - Exponential decay of accumulated scores
    - CryptoPostureController rotation/switch callbacks
    - Cooldown enforcement
    - Algorithm strength ordering and upgrade logic
    - Monitor-disabled and no-monitor edge cases
"""

from typing import Any
from unittest.mock import MagicMock

import pytest

from ama_cryptography.adaptive_posture import (
    CryptoPostureController,
    PostureAction,
    PostureEvaluation,
    PostureEvaluator,
    ThreatLevel,
)

# ---------------------------------------------------------------------------
# PostureEvaluator tests
# ---------------------------------------------------------------------------


class TestPostureEvaluator:
    """Tests for PostureEvaluator threat classification."""

    def test_nominal_on_empty_report(self) -> None:
        """Empty report with no alerts should yield NOMINAL."""
        evaluator = PostureEvaluator()
        report = {"recent_alerts": [], "total_alerts": 0}
        result = evaluator.evaluate(report)
        assert result.threat_level == ThreatLevel.NOMINAL
        assert result.action == PostureAction.NONE

    def test_monitoring_disabled(self) -> None:
        """Disabled monitoring should yield NOMINAL with zero confidence."""
        evaluator = PostureEvaluator()
        report = {"status": "monitoring_disabled"}
        result = evaluator.evaluate(report)
        assert result.threat_level == ThreatLevel.NOMINAL
        assert result.action == PostureAction.NONE
        assert result.confidence == 0.0
        assert result.signals["reason"] == "monitoring_disabled"

    def test_elevated_threshold(self) -> None:
        """Score crossing elevated threshold triggers INCREASE_MONITORING."""
        # escalation_count=1 to test threshold behavior without hysteresis delay
        evaluator = PostureEvaluator(
            elevated_threshold=0.1,
            high_threshold=0.5,
            critical_threshold=0.9,
            escalation_count=1,
        )
        # Feed enough timing anomalies to cross elevated but not high
        anomaly = MagicMock()
        anomaly.severity = "warning"
        anomaly.deviation_sigma = 3.0
        alerts = [{"type": "timing", "anomaly": anomaly}]
        report = {"recent_alerts": alerts, "total_alerts": 10}
        result = evaluator.evaluate(report)
        assert result.threat_level in (ThreatLevel.ELEVATED, ThreatLevel.HIGH)
        assert result.action in (
            PostureAction.INCREASE_MONITORING,
            PostureAction.ROTATE_KEYS,
        )

    def test_critical_threshold(self) -> None:
        """High severity alerts should eventually reach CRITICAL."""
        evaluator = PostureEvaluator(
            elevated_threshold=0.1, high_threshold=0.3, critical_threshold=0.5
        )
        anomaly = MagicMock()
        anomaly.severity = "critical"
        anomaly.deviation_sigma = 10.0
        alerts = [{"type": "timing", "anomaly": anomaly} for _ in range(5)]
        report = {"recent_alerts": alerts, "total_alerts": 50}
        # Feed multiple rounds to accumulate score past critical
        for _ in range(5):
            result = evaluator.evaluate(report)
        assert result.threat_level == ThreatLevel.CRITICAL
        assert result.action == PostureAction.ROTATE_AND_SWITCH

    def test_decay_reduces_score(self) -> None:
        """Accumulated score should decay when fed clean reports."""
        evaluator = PostureEvaluator(decay_rate=0.5)
        # First: inject a score
        anomaly = MagicMock()
        anomaly.severity = "critical"
        anomaly.deviation_sigma = 8.0
        report_hot = {
            "recent_alerts": [{"type": "timing", "anomaly": anomaly}],
            "total_alerts": 10,
        }
        evaluator.evaluate(report_hot)
        score_after_hot = evaluator._accumulated_score

        # Then: feed empty reports and watch score decay
        report_clean = {"recent_alerts": [], "total_alerts": 10}
        for _ in range(10):
            evaluator.evaluate(report_clean)
        assert evaluator._accumulated_score < score_after_hot * 0.1

    def test_reset_clears_state(self) -> None:
        """Reset should zero accumulated score and evaluation count."""
        evaluator = PostureEvaluator()
        evaluator._accumulated_score = 5.0
        evaluator._evaluation_count = 42
        evaluator.reset()
        assert evaluator._accumulated_score == 0.0
        assert evaluator._evaluation_count == 0

    def test_confidence_scales_with_alert_count(self) -> None:
        """Confidence should scale from 0 to 1 based on total_alerts."""
        evaluator = PostureEvaluator()
        report_low = {"recent_alerts": [], "total_alerts": 5}
        result_low = evaluator.evaluate(report_low)
        assert result_low.confidence == pytest.approx(5.0 / 50.0)

        evaluator.reset()
        report_high = {"recent_alerts": [], "total_alerts": 100}
        result_high = evaluator.evaluate(report_high)
        assert result_high.confidence == 1.0

    def test_pattern_alerts_contribute_to_score(self) -> None:
        """Pattern alerts with high z-scores should raise the score."""
        evaluator = PostureEvaluator(elevated_threshold=0.01)
        alerts = [
            {
                "type": "pattern",
                "anomaly": {"z_score": 8.0, "severity": "critical"},
            }
        ]
        report = {"recent_alerts": alerts, "total_alerts": 10}
        result = evaluator.evaluate(report)
        assert result.signals["pattern_score"] > 0

    def test_resonance_scoring(self) -> None:
        """Resonance ratios above 3.0 should contribute score."""
        evaluator = PostureEvaluator()
        report = {
            "recent_alerts": [],
            "total_alerts": 10,
            "resonance_analysis": {"op1": {"resonance_ratio": 8.0}},
        }
        result = evaluator.evaluate(report)
        assert result.signals["resonance_score"] > 0

    def test_resonance_below_threshold(self) -> None:
        """Resonance ratio below 3.0 should contribute zero."""
        evaluator = PostureEvaluator()
        report = {
            "recent_alerts": [],
            "total_alerts": 10,
            "resonance_analysis": {"op1": {"resonance_ratio": 2.0}},
        }
        result = evaluator.evaluate(report)
        assert result.signals["resonance_score"] == 0.0


# ---------------------------------------------------------------------------
# CryptoPostureController tests
# ---------------------------------------------------------------------------


class TestCryptoPostureController:
    """Tests for CryptoPostureController rotation and switching."""

    def _make_monitor(self, report: Any) -> Any:
        """Create a mock monitor returning the given report."""
        monitor = MagicMock()
        monitor.get_security_report.return_value = report
        return monitor

    def test_no_monitor_returns_nominal(self) -> None:
        """Controller with no monitor should return NOMINAL."""
        controller = CryptoPostureController(monitor=None)
        result = controller.evaluate_and_respond()
        assert result.threat_level == ThreatLevel.NOMINAL
        assert result.signals["reason"] == "no_monitor"

    def test_rotation_callback_triggered(self) -> None:
        """Rotation callback should fire when action is ROTATE_KEYS."""
        on_rotation = MagicMock()
        # Force a CRITICAL evaluation by pre-loading the evaluator
        # escalation_count=1 to bypass hysteresis for this test
        evaluator = PostureEvaluator(critical_threshold=0.01, escalation_count=1)
        anomaly = MagicMock()
        anomaly.severity = "critical"
        anomaly.deviation_sigma = 10.0
        report = {
            "recent_alerts": [{"type": "timing", "anomaly": anomaly}],
            "total_alerts": 50,
        }
        monitor = self._make_monitor(report)
        controller = CryptoPostureController(
            monitor=monitor,
            evaluator=evaluator,
            on_rotation=on_rotation,
            rotation_cooldown=0,
        )
        controller.evaluate_and_respond()
        on_rotation.assert_called_once()

    def test_algorithm_switch_callback_triggered(self) -> None:
        """Algorithm switch callback should fire on ROTATE_AND_SWITCH."""
        on_switch = MagicMock()
        on_rotation = MagicMock()
        # escalation_count=1 to bypass hysteresis for this test
        evaluator = PostureEvaluator(critical_threshold=0.01, escalation_count=1)
        anomaly = MagicMock()
        anomaly.severity = "critical"
        anomaly.deviation_sigma = 10.0
        report = {
            "recent_alerts": [{"type": "timing", "anomaly": anomaly}],
            "total_alerts": 50,
        }
        monitor = self._make_monitor(report)
        controller = CryptoPostureController(
            monitor=monitor,
            evaluator=evaluator,
            current_algorithm="ED25519",
            on_rotation=on_rotation,
            on_algorithm_switch=on_switch,
            rotation_cooldown=0,
        )
        controller.evaluate_and_respond()
        on_switch.assert_called_with("ML_DSA_65")

    def test_algorithm_upgrade_ordering(self) -> None:
        """Algorithm should upgrade to next stronger, not skip levels."""
        controller = CryptoPostureController(current_algorithm="ED25519")
        controller._trigger_algorithm_switch()
        assert controller.current_algorithm == "ML_DSA_65"
        controller._trigger_algorithm_switch()
        assert controller.current_algorithm == "SPHINCS_256F"
        controller._trigger_algorithm_switch()
        assert controller.current_algorithm == "HYBRID_SIG"

    def test_no_upgrade_at_max_strength(self) -> None:
        """Already at strongest algorithm should not change."""
        controller = CryptoPostureController(current_algorithm="HYBRID_SIG")
        controller._trigger_algorithm_switch()
        assert controller.current_algorithm == "HYBRID_SIG"
        assert controller._switch_count == 0

    def test_cooldown_prevents_rapid_rotation(self) -> None:
        """Rotation within cooldown window should be suppressed."""
        on_rotation = MagicMock()
        evaluator = PostureEvaluator(critical_threshold=0.01, escalation_count=1)
        anomaly = MagicMock()
        anomaly.severity = "critical"
        anomaly.deviation_sigma = 10.0
        report = {
            "recent_alerts": [{"type": "timing", "anomaly": anomaly}],
            "total_alerts": 50,
        }
        monitor = self._make_monitor(report)
        controller = CryptoPostureController(
            monitor=monitor,
            evaluator=evaluator,
            on_rotation=on_rotation,
            rotation_cooldown=9999,
        )
        controller.evaluate_and_respond()
        call_count_first = on_rotation.call_count
        # Second evaluation should be suppressed by cooldown
        controller.evaluate_and_respond()
        assert on_rotation.call_count == call_count_first

    def test_rotation_manager_integration(self) -> None:
        """Rotation manager should receive register_key and initiate_rotation."""
        rotation_mgr = MagicMock()
        rotation_mgr.get_active_key.return_value = "key-001"
        controller = CryptoPostureController(rotation_manager=rotation_mgr, rotation_cooldown=0)
        controller._trigger_rotation()
        rotation_mgr.register_key.assert_called_once()
        rotation_mgr.initiate_rotation.assert_called_once_with("key-001", "posture-rotation-1")

    def test_hd_derivation_used_when_available(self) -> None:
        """HD derivation should be called during rotation if available."""
        rotation_mgr = MagicMock()
        rotation_mgr.get_active_key.return_value = "key-001"
        hd = MagicMock()
        controller = CryptoPostureController(
            rotation_manager=rotation_mgr,
            hd_derivation=hd,
            rotation_cooldown=0,
        )
        controller._trigger_rotation()
        hd.derive_path.assert_called_once()

    def test_history_bounded(self) -> None:
        """History should not grow beyond max_history."""
        monitor = self._make_monitor({"recent_alerts": [], "total_alerts": 0})
        controller = CryptoPostureController(monitor=monitor, max_history=5)
        for _ in range(20):
            controller.evaluate_and_respond()
        assert len(controller._history) <= 5

    def test_posture_summary(self) -> None:
        """get_posture_summary should return expected keys."""
        controller = CryptoPostureController()
        summary = controller.get_posture_summary()
        assert "current_algorithm" in summary
        assert "current_threat_level" in summary
        assert "rotation_count" in summary
        assert "switch_count" in summary
        assert "evaluation_count" in summary
        assert "recent_evaluations" in summary

    def test_reset_clears_all(self) -> None:
        """Reset should zero all counters and clear history."""
        controller = CryptoPostureController()
        controller._rotation_count = 5
        controller._switch_count = 3
        controller._history.append(
            PostureEvaluation(
                threat_level=ThreatLevel.HIGH,
                action=PostureAction.ROTATE_KEYS,
                confidence=0.8,
                signals={},
            )
        )
        controller.reset()
        assert controller._rotation_count == 0
        assert controller._switch_count == 0
        assert len(controller._history) == 0

    def test_callback_exception_does_not_crash(self) -> None:
        """Exceptions in callbacks should be caught, not propagated."""
        on_rotation = MagicMock(side_effect=RuntimeError("boom"))
        controller = CryptoPostureController(on_rotation=on_rotation, rotation_cooldown=0)
        # Should not raise
        controller._trigger_rotation()

    def test_rotation_manager_exception_does_not_crash(self) -> None:
        """Exceptions from rotation_manager should be caught."""
        rotation_mgr = MagicMock()
        rotation_mgr.get_active_key.return_value = "key-001"
        rotation_mgr.register_key.side_effect = RuntimeError("storage error")
        controller = CryptoPostureController(rotation_manager=rotation_mgr, rotation_cooldown=0)
        # Should not raise
        controller._trigger_rotation()

    def test_failed_rotation_does_not_arm_the_cooldown(self) -> None:
        """A rotation that was attempted and FAILED must remain retryable.

        ``_trigger_rotation`` arms ``_last_rotation_time`` only when a rotation
        actually happened, precisely so a transient backend failure does not
        suppress every retry for the full cooldown window while the threat that
        demanded the rotation persists.  ``_execute_action`` used to arm it
        unconditionally, and *before* the attempt, which made that condition
        dead code: this pins the behaviour it protects.
        """
        on_rotation = MagicMock(side_effect=RuntimeError("KMS unreachable"))
        controller = CryptoPostureController(on_rotation=on_rotation, rotation_cooldown=300)
        controller._last_rotation_time = 0.0

        controller._execute_action(PostureAction.ROTATE_KEYS)

        assert on_rotation.call_count == 1
        assert controller._last_rotation_time == 0.0, (
            "a failed rotation must not arm the cooldown — otherwise the engine "
            "believes it acted and suppresses retries while the threat persists"
        )

        # The retry is therefore free to run rather than being throttled out.
        controller._execute_action(PostureAction.ROTATE_KEYS)
        assert on_rotation.call_count == 2

    def test_successful_rotation_arms_the_cooldown(self) -> None:
        """The converse: a rotation that succeeded does throttle the next one."""
        controller = CryptoPostureController(on_rotation=MagicMock(), rotation_cooldown=300)
        controller._last_rotation_time = 0.0

        controller._execute_action(PostureAction.ROTATE_KEYS)

        assert controller._last_rotation_time > 0.0

    def test_algorithm_switch_arms_the_cooldown(self) -> None:
        """A non-rotating action still consumes the throttle window."""
        controller = CryptoPostureController(
            on_algorithm_switch=MagicMock(), rotation_cooldown=300
        )
        controller._last_rotation_time = 0.0

        controller._execute_action(PostureAction.SWITCH_ALGORITHM)

        assert controller._last_rotation_time > 0.0

    def test_unknown_algorithm_is_rejected(self) -> None:
        """INVARIANT-35: an unrankable algorithm name must not resolve to a rung.

        Every strength lookup is ``ALGORITHM_STRENGTH.get(name, 0)``, so an
        unrecognised name silently scored as the WEAKEST algorithm — and a
        controller constructed with a real ``AlgorithmType`` this table does not
        list (KYBER_1024, HYBRID_KEM) would be "upgraded" to ML_DSA_65 on the
        first CRITICAL evaluation, logged as hardening, with the downgrade
        detector blinded by the same default.
        """
        with pytest.raises(ValueError, match="unknown algorithm"):
            CryptoPostureController(current_algorithm="HYBRID_KEM")
        with pytest.raises(ValueError, match="unknown algorithm"):
            CryptoPostureController(current_algorithm="ML_DSA_87")

        # Every name the table does rank is still accepted.
        for name in CryptoPostureController.ALGORITHM_STRENGTH:
            CryptoPostureController(current_algorithm=name)
