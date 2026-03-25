#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Scenario tests for the adaptive cryptographic posture system.

Covers ThreatLevel enum values, PostureEvaluator initialization,
threat level escalation and de-escalation, multiple anomaly signals,
threshold-based escalation, default threat level, and score decay.
"""

import pytest

from ama_cryptography.adaptive_posture import (
    PostureAction,
    PostureEvaluation,
    PostureEvaluator,
    ThreatLevel,
)


# ---- helpers ----------------------------------------------------------------

def _make_report(
    timing_alerts=None,
    pattern_alerts=None,
    resonance_analysis=None,
    total_alerts=50,
    status="ok",
):
    """Build a minimal monitor report dict."""
    alerts = []
    if timing_alerts:
        alerts.extend(timing_alerts)
    if pattern_alerts:
        alerts.extend(pattern_alerts)
    return {
        "status": status,
        "recent_alerts": alerts,
        "resonance_analysis": resonance_analysis or {},
        "total_alerts": total_alerts,
    }


def _timing_alert(severity="critical", deviation=10.0):
    """Create a fake timing alert entry."""

    class _FakeAnomaly:
        def __init__(self, sev, dev):
            self.severity = sev
            self.deviation_sigma = dev

    return {"type": "timing", "anomaly": _FakeAnomaly(severity, deviation)}


def _pattern_alert(severity="critical", z_score=10.0):
    """Create a fake pattern alert entry."""
    return {
        "type": "pattern",
        "anomaly": {"severity": severity, "z_score": z_score},
    }


# ---- tests ------------------------------------------------------------------


class TestThreatLevelEnum:
    """Tests for the ThreatLevel enum."""

    def test_enum_has_four_values(self) -> None:
        """ThreatLevel must have exactly NOMINAL, ELEVATED, HIGH, CRITICAL."""
        names = {e.name for e in ThreatLevel}
        assert names == {"NOMINAL", "ELEVATED", "HIGH", "CRITICAL"}

    def test_enum_values_are_unique(self) -> None:
        """Each ThreatLevel value must be distinct."""
        values = [e.value for e in ThreatLevel]
        assert len(values) == len(set(values))


class TestPostureEvaluatorInit:
    """Tests for PostureEvaluator initialization and defaults."""

    def test_default_initialization(self) -> None:
        """PostureEvaluator() should succeed with sensible defaults."""
        ev = PostureEvaluator()
        assert ev.elevated_threshold == 0.3
        assert ev.high_threshold == 0.6
        assert ev.critical_threshold == 0.85
        assert ev.decay_rate == 0.95

    def test_default_threat_level_is_nominal(self) -> None:
        """A freshly created evaluator must report NOMINAL."""
        ev = PostureEvaluator()
        result = ev.evaluate(_make_report())
        assert result.threat_level == ThreatLevel.NOMINAL

    def test_custom_thresholds(self) -> None:
        """Custom thresholds should be stored correctly."""
        ev = PostureEvaluator(
            elevated_threshold=0.1,
            high_threshold=0.4,
            critical_threshold=0.7,
        )
        assert ev.elevated_threshold == 0.1
        assert ev.high_threshold == 0.4
        assert ev.critical_threshold == 0.7


class TestEscalation:
    """Tests for threat level escalation behaviour."""

    def test_escalation_requires_consecutive_evaluations(self) -> None:
        """The threat level should not escalate on a single high-score
        evaluation; it requires escalation_count consecutive hits."""
        ev = PostureEvaluator(
            elevated_threshold=0.1,
            high_threshold=0.3,
            critical_threshold=0.5,
            escalation_count=3,
            decay_rate=1.0,  # disable decay for determinism
        )
        # One high-scoring evaluation is not enough
        report = _make_report(
            timing_alerts=[_timing_alert("critical", 20.0)] * 5
        )
        result = ev.evaluate(report)
        # Should still be NOMINAL after a single evaluation
        assert result.threat_level == ThreatLevel.NOMINAL

    def test_escalation_sequence_to_elevated(self) -> None:
        """After enough consecutive high-score evaluations the level must
        escalate to at least ELEVATED."""
        ev = PostureEvaluator(
            elevated_threshold=0.1,
            high_threshold=0.5,
            critical_threshold=0.8,
            escalation_count=2,
            decay_rate=1.0,
        )
        report = _make_report(
            timing_alerts=[_timing_alert("critical", 10.0)] * 3,
        )
        # Push multiple evaluations to accumulate score
        for _ in range(5):
            result = ev.evaluate(report)

        assert result.threat_level.value >= ThreatLevel.ELEVATED.value

    def test_threshold_based_escalation(self) -> None:
        """Scores above the critical threshold (with enough consecutive
        evaluations) should eventually reach CRITICAL."""
        ev = PostureEvaluator(
            elevated_threshold=0.05,
            high_threshold=0.15,
            critical_threshold=0.3,
            escalation_count=2,
            decay_rate=1.0,
        )
        report = _make_report(
            timing_alerts=[_timing_alert("critical", 20.0)] * 10,
            pattern_alerts=[_pattern_alert("critical", 20.0)] * 10,
        )
        for _ in range(10):
            result = ev.evaluate(report)

        assert result.threat_level == ThreatLevel.CRITICAL


class TestDeescalation:
    """Tests for threat level de-escalation behaviour."""

    def test_deescalation_on_clean_reports(self) -> None:
        """After escalation, feeding many clean (zero-score) reports should
        eventually de-escalate the threat level back to NOMINAL."""
        ev = PostureEvaluator(
            elevated_threshold=0.1,
            high_threshold=0.4,
            critical_threshold=0.7,
            escalation_count=2,
            decay_rate=0.5,  # aggressive decay
            hysteresis_band=0.0,
        )
        # Escalate first
        hot_report = _make_report(
            timing_alerts=[_timing_alert("critical", 20.0)] * 10,
        )
        for _ in range(10):
            ev.evaluate(hot_report)

        # Now feed clean reports
        clean_report = _make_report()
        for _ in range(50):
            result = ev.evaluate(clean_report)

        assert result.threat_level == ThreatLevel.NOMINAL


class TestMultipleSignals:
    """Tests combining multiple anomaly signal types."""

    def test_multiple_anomaly_signals_combine(self) -> None:
        """Timing + pattern + resonance signals should all contribute to
        the effective score."""
        ev = PostureEvaluator(decay_rate=1.0)
        report = _make_report(
            timing_alerts=[_timing_alert("critical", 8.0)] * 3,
            pattern_alerts=[_pattern_alert("warning", 6.0)] * 3,
            resonance_analysis={
                "op1": {"resonance_ratio": 8.0},
            },
        )
        result = ev.evaluate(report)
        signals = result.signals
        assert signals["timing_score"] > 0
        assert signals["pattern_score"] > 0
        assert signals["resonance_score"] > 0


class TestDecayBehaviour:
    """Tests for exponential score decay over time."""

    def test_decay_reduces_accumulated_score(self) -> None:
        """With decay_rate < 1 and no new anomalies, the accumulated score
        must decrease across evaluations."""
        ev = PostureEvaluator(decay_rate=0.5)
        hot_report = _make_report(
            timing_alerts=[_timing_alert("critical", 10.0)] * 5,
        )
        ev.evaluate(hot_report)
        score_after_hot = ev._accumulated_score

        # Feed clean reports and verify decay
        clean = _make_report()
        for _ in range(5):
            ev.evaluate(clean)

        assert ev._accumulated_score < score_after_hot

    def test_decay_rate_one_preserves_score(self) -> None:
        """With decay_rate=1.0 and zero-score reports, the accumulated
        score should never decrease (no decay applied)."""
        ev = PostureEvaluator(decay_rate=1.0)
        hot_report = _make_report(
            timing_alerts=[_timing_alert("critical", 10.0)] * 5,
        )
        ev.evaluate(hot_report)
        score = ev._accumulated_score

        clean = _make_report()
        ev.evaluate(clean)
        # Score should stay the same (decay_rate=1.0 means multiply by 1)
        assert ev._accumulated_score == pytest.approx(score, abs=1e-12)
