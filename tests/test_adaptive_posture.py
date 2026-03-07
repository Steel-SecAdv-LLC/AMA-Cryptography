#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

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

    def test_nominal_on_empty_report(self):
        """Empty report with no alerts should yield NOMINAL."""
        evaluator = PostureEvaluator()
        report = {"recent_alerts": [], "total_alerts": 0}
        result = evaluator.evaluate(report)
        assert result.threat_level == ThreatLevel.NOMINAL
        assert result.action == PostureAction.NONE

    def test_monitoring_disabled(self):
        """Disabled monitoring should yield NOMINAL with zero confidence."""
        evaluator = PostureEvaluator()
        report = {"status": "monitoring_disabled"}
        result = evaluator.evaluate(report)
        assert result.threat_level == ThreatLevel.NOMINAL
        assert result.action == PostureAction.NONE
        assert result.confidence == 0.0
        assert result.signals["reason"] == "monitoring_disabled"

    def test_elevated_threshold(self):
        """Score crossing elevated threshold triggers INCREASE_MONITORING."""
        evaluator = PostureEvaluator(
            elevated_threshold=0.1, high_threshold=0.5, critical_threshold=0.9
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

    def test_critical_threshold(self):
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

    def test_decay_reduces_score(self):
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

    def test_reset_clears_state(self):
        """Reset should zero accumulated score and evaluation count."""
        evaluator = PostureEvaluator()
        evaluator._accumulated_score = 5.0
        evaluator._evaluation_count = 42
        evaluator.reset()
        assert evaluator._accumulated_score == 0.0
        assert evaluator._evaluation_count == 0

    def test_confidence_scales_with_alert_count(self):
        """Confidence should scale from 0 to 1 based on total_alerts."""
        evaluator = PostureEvaluator()
        report_low = {"recent_alerts": [], "total_alerts": 5}
        result_low = evaluator.evaluate(report_low)
        assert result_low.confidence == pytest.approx(5.0 / 50.0)

        evaluator.reset()
        report_high = {"recent_alerts": [], "total_alerts": 100}
        result_high = evaluator.evaluate(report_high)
        assert result_high.confidence == 1.0

    def test_pattern_alerts_contribute_to_score(self):
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

    def test_resonance_scoring(self):
        """Resonance ratios above 3.0 should contribute score."""
        evaluator = PostureEvaluator()
        report = {
            "recent_alerts": [],
            "total_alerts": 10,
            "resonance_analysis": {"op1": {"resonance_ratio": 8.0}},
        }
        result = evaluator.evaluate(report)
        assert result.signals["resonance_score"] > 0

    def test_resonance_below_threshold(self):
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

    def _make_monitor(self, report):
        """Create a mock monitor returning the given report."""
        monitor = MagicMock()
        monitor.get_security_report.return_value = report
        return monitor

    def test_no_monitor_returns_nominal(self):
        """Controller with no monitor should return NOMINAL."""
        controller = CryptoPostureController(monitor=None)
        result = controller.evaluate_and_respond()
        assert result.threat_level == ThreatLevel.NOMINAL
        assert result.signals["reason"] == "no_monitor"

    def test_rotation_callback_triggered(self):
        """Rotation callback should fire when action is ROTATE_KEYS."""
        on_rotation = MagicMock()
        # Force a CRITICAL evaluation by pre-loading the evaluator
        evaluator = PostureEvaluator(critical_threshold=0.01)
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
        on_rotation.assert_called()

    def test_algorithm_switch_callback_triggered(self):
        """Algorithm switch callback should fire on ROTATE_AND_SWITCH."""
        on_switch = MagicMock()
        on_rotation = MagicMock()
        evaluator = PostureEvaluator(critical_threshold=0.01)
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

    def test_algorithm_upgrade_ordering(self):
        """Algorithm should upgrade to next stronger, not skip levels."""
        controller = CryptoPostureController(current_algorithm="ED25519")
        controller._trigger_algorithm_switch()
        assert controller.current_algorithm == "ML_DSA_65"
        controller._trigger_algorithm_switch()
        assert controller.current_algorithm == "SPHINCS_256F"
        controller._trigger_algorithm_switch()
        assert controller.current_algorithm == "HYBRID_SIG"

    def test_no_upgrade_at_max_strength(self):
        """Already at strongest algorithm should not change."""
        controller = CryptoPostureController(current_algorithm="HYBRID_SIG")
        controller._trigger_algorithm_switch()
        assert controller.current_algorithm == "HYBRID_SIG"
        assert controller._switch_count == 0

    def test_cooldown_prevents_rapid_rotation(self):
        """Rotation within cooldown window should be suppressed."""
        on_rotation = MagicMock()
        evaluator = PostureEvaluator(critical_threshold=0.01)
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

    def test_rotation_manager_integration(self):
        """Rotation manager should receive register_key and initiate_rotation."""
        rotation_mgr = MagicMock()
        rotation_mgr.get_active_key.return_value = "key-001"
        controller = CryptoPostureController(rotation_manager=rotation_mgr, rotation_cooldown=0)
        controller._trigger_rotation()
        rotation_mgr.register_key.assert_called_once()
        rotation_mgr.initiate_rotation.assert_called_once_with("key-001", "posture-rotation-1")

    def test_hd_derivation_used_when_available(self):
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

    def test_history_bounded(self):
        """History should not grow beyond _max_history."""
        monitor = self._make_monitor({"recent_alerts": [], "total_alerts": 0})
        controller = CryptoPostureController(monitor=monitor)
        controller._max_history = 5
        for _ in range(20):
            controller.evaluate_and_respond()
        assert len(controller._history) <= 5

    def test_posture_summary(self):
        """get_posture_summary should return expected keys."""
        controller = CryptoPostureController()
        summary = controller.get_posture_summary()
        assert "current_algorithm" in summary
        assert "current_threat_level" in summary
        assert "rotation_count" in summary
        assert "switch_count" in summary
        assert "evaluation_count" in summary
        assert "recent_evaluations" in summary

    def test_reset_clears_all(self):
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

    def test_callback_exception_does_not_crash(self):
        """Exceptions in callbacks should be caught, not propagated."""
        on_rotation = MagicMock(side_effect=RuntimeError("boom"))
        controller = CryptoPostureController(on_rotation=on_rotation, rotation_cooldown=0)
        # Should not raise
        controller._trigger_rotation()

    def test_rotation_manager_exception_does_not_crash(self):
        """Exceptions from rotation_manager should be caught."""
        rotation_mgr = MagicMock()
        rotation_mgr.get_active_key.return_value = "key-001"
        rotation_mgr.register_key.side_effect = RuntimeError("storage error")
        controller = CryptoPostureController(rotation_manager=rotation_mgr, rotation_cooldown=0)
        # Should not raise
        controller._trigger_rotation()
