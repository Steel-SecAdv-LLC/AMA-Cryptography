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

import math
from pathlib import Path
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

REPO_ROOT = Path(__file__).resolve().parent.parent

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
        """A composite that really is above the threshold reaches CRITICAL.

        This test used to feed the SAME five alerts five times and rely on the
        accumulator summing them past the bar — "Feed multiple rounds to
        accumulate score past critical".  That is the defect, not the feature:
        ``recent_alerts`` is a sliding window the evaluator does not drain, so
        re-serving it is what a monitor does on every cycle with no new
        activity, and treating that as escalation pinned clean deployments at
        CRITICAL.  A single stale alert drove effective_score from 0.45 to 4.83
        over fifteen cycles against a threshold of 0.80.

        What CRITICAL is documented to mean is a 7-sigma composite in one
        evaluation, so that is what this now builds: saturated timing AND
        pattern AND resonance signals, giving a raw composite above the bar on
        the evaluation that observes it.
        """
        evaluator = PostureEvaluator(
            elevated_threshold=0.1, high_threshold=0.3, critical_threshold=0.5
        )
        anomaly = MagicMock()
        anomaly.severity = "critical"
        anomaly.deviation_sigma = 10.0
        report: dict[str, Any] = {
            "recent_alerts": [
                {"type": "timing", "timestamp": 1000.0 + i, "anomaly": anomaly} for i in range(5)
            ]
            + [
                {
                    "type": "pattern",
                    "timestamp": 1010.0 + i,
                    "anomaly": {"z_score": 12.0, "severity": "critical"},
                }
                for i in range(5)
            ],
            "resonance_analysis": {"sign": {"resonance_ratio": 10.0}},
            "total_alerts": 50,
        }
        # Escalation deliberately requires `escalation_count` consecutive
        # evaluations above the bar (default 3), so the composite is sustained
        # with NEW alerts each cycle — a continuing attack, which is what the
        # control is for.  Re-serving the same alerts would not do it, and must
        # not: that is the neighbouring regression test.
        base_alerts: list[dict[str, Any]] = list(report["recent_alerts"])
        for round_index in range(evaluator.escalation_count):
            fresh: dict[str, Any] = {
                "recent_alerts": [
                    {
                        "type": alert["type"],
                        "timestamp": alert["timestamp"] + 100.0 * round_index,
                        "anomaly": alert["anomaly"],
                    }
                    for alert in base_alerts
                ],
                "resonance_analysis": report["resonance_analysis"],
                "total_alerts": report["total_alerts"],
            }
            result = evaluator.evaluate(fresh)
            assert result.signals["raw_score"] > 0.5, result.signals
        assert result.threat_level == ThreatLevel.CRITICAL
        assert result.action == PostureAction.ROTATE_AND_SWITCH

    def test_a_stale_alert_cannot_hold_the_posture_at_critical(self) -> None:
        """The regression: re-serving one alert must not escalate at all.

        ``get_security_report()`` returns ``self.alerts[-10:]``.  With no new
        activity the same alert is present on every cycle, and both the timing
        and pattern scorers re-scored it every time while the accumulator
        compounded the repetition.  Measured before the fix: raw_score pinned at
        0.4500 and effective_score climbing 0.45 -> 4.83 over fifteen cycles,
        CRITICAL from cycle 4 onward with ROTATE_AND_SWITCH — on one alert and
        no further activity.
        """
        evaluator = PostureEvaluator()
        anomaly = MagicMock()
        anomaly.severity = "critical"
        anomaly.deviation_sigma = 269.8
        report = {
            "recent_alerts": [{"type": "timing", "timestamp": 1000.0, "anomaly": anomaly}],
            "resonance_analysis": {},
            "total_alerts": 1,
        }

        first = evaluator.evaluate(report)
        assert first.signals["raw_score"] > 0.0, "the alert must be scored once"

        # How long decay needs, derived rather than guessed: the effective
        # score falls by `decay_rate` per cycle from `first`, and the level
        # returns to NOMINAL once it is below `elevated_threshold`.  The
        # de-escalation path also needs the score under
        # (threshold - hysteresis_band), and `escalation_count` cycles are
        # spent on the way up, so allow for both.
        span = math.log(evaluator.elevated_threshold / first.signals["effective_score"])
        cycles = math.ceil(span / math.log(evaluator.decay_rate)) + evaluator.escalation_count + 5

        levels = []
        for _ in range(cycles):
            result = evaluator.evaluate(report)
            levels.append(result.threat_level)
            assert result.signals["raw_score"] == 0.0, (
                "an alert already scored was scored again: " f"{result.signals}"
            )
            assert result.signals["effective_score"] <= first.signals["effective_score"], (
                "the effective score rose with no new anomaly: " f"{result.signals}"
            )
            assert result.signals["effective_score"] <= 1.0, (
                "effective_score left the [0, 1] range its thresholds are "
                f"calibrated in: {result.signals}"
            )
        assert ThreatLevel.CRITICAL not in levels, levels
        assert levels[-1] == ThreatLevel.NOMINAL, levels[-5:]

    def test_the_effective_score_stays_inside_the_threshold_range(self) -> None:
        """`effective_score` must be comparable to the calibrated thresholds.

        The thresholds are documented as per-evaluation probabilities in
        [0, 1] (``ELEVATED = 1 - Phi(3)``, ``CRITICAL ... 1-in-780B``).  The
        old ``acc = acc * decay + score`` is a geometric series with a 20x gain
        at the default decay, so a sustained score of 0.04 reached "7-sigma" in
        the limit and the reported figure kept climbing past 1.0.
        """
        evaluator = PostureEvaluator()
        anomaly = MagicMock()
        anomaly.severity = "critical"
        anomaly.deviation_sigma = 100.0
        for i in range(50):
            report = {
                "recent_alerts": [{"type": "timing", "timestamp": 1000.0 + i, "anomaly": anomaly}],
                "resonance_analysis": {},
                "total_alerts": 50,
            }
            result = evaluator.evaluate(report)
            assert 0.0 <= result.signals["effective_score"] <= 1.0, result.signals

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

    def test_raising_get_active_key_is_caught_and_counts_as_attempted(self) -> None:
        """The one rotation_manager call that was unguarded, guarded.

        register_key / initiate_rotation / on_rotation failures were each
        caught, but get_active_key — the FIRST call of the flow — raised
        straight through _trigger_rotation and out of a whole
        evaluate_and_respond cycle.  The shipped KeyRotationManager's
        implementation is a bare attribute read that cannot raise, but the
        manager is caller-suppliable precisely so a remote KMS can back it,
        and this module's own contract names "the KMS is unreachable" as a
        failure the flow must survive.  A raising fetch must not crash, and
        it counts as attempted-and-FAILED so the cooldown stays unarmed and
        the next evaluation retries.
        """
        rotation_mgr = MagicMock()
        rotation_mgr.get_active_key.side_effect = ConnectionError("KMS unreachable")
        controller = CryptoPostureController(rotation_manager=rotation_mgr, rotation_cooldown=300)
        controller._last_rotation_time = 0.0

        # Must not raise.
        controller._trigger_rotation()

        assert rotation_mgr.get_active_key.call_count == 1
        rotation_mgr.register_key.assert_not_called()
        assert controller._last_rotation_time == 0.0, (
            "a rotation that failed at the active-key fetch must not arm the "
            "cooldown — the threat that demanded it is still standing"
        )

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
        """A non-rotating action still consumes its own throttle window.

        The switch throttle is separate from the rotation one: a rotation that
        failed must stay retryable, while a switch must never run back-to-back,
        and a single timer cannot deliver both.  The property asserted here is
        the one that matters — a second immediate switch does not execute.
        """
        on_switch = MagicMock()
        controller = CryptoPostureController(on_algorithm_switch=on_switch, rotation_cooldown=300)
        controller._last_switch_time = 0.0

        controller._execute_action(PostureAction.SWITCH_ALGORITHM)

        assert controller._last_switch_time > 0.0
        assert on_switch.call_count == 1

        controller._execute_action(PostureAction.SWITCH_ALGORITHM)
        assert on_switch.call_count == 1, "a second switch inside the window must be suppressed"

    def test_failed_rotation_does_not_unthrottle_the_paired_switch(self) -> None:
        """ROTATE_AND_SWITCH must not turn a failing rotation into a switch spin.

        ``_trigger_rotation`` deliberately leaves the rotation throttle unarmed
        when the rotation was attempted and failed, so the retry is not
        suppressed.  While the two effects shared one timer, that left the
        paired algorithm switch un-throttled as well: every evaluation cycle
        climbed another rung of the ladder and fired the switch callback again,
        with the KMS still unreachable.  The rotation stays retryable; the
        switch does not ride along.
        """
        on_rotation = MagicMock(side_effect=RuntimeError("KMS unreachable"))
        on_switch = MagicMock()
        controller = CryptoPostureController(
            on_rotation=on_rotation,
            on_algorithm_switch=on_switch,
            rotation_cooldown=300,
        )
        controller._last_rotation_time = 0.0
        controller._last_switch_time = 0.0

        controller._execute_action(PostureAction.ROTATE_AND_SWITCH)
        controller._execute_action(PostureAction.ROTATE_AND_SWITCH)
        controller._execute_action(PostureAction.ROTATE_AND_SWITCH)

        assert on_rotation.call_count == 3, "a failed rotation must remain retryable"
        assert on_switch.call_count == 1, (
            "the paired switch must obey its own cooldown even though the "
            "rotation failed and left the rotation throttle unarmed"
        )
        assert controller._last_rotation_time == 0.0

    def test_unrankable_algorithm_is_rejected(self) -> None:
        """INVARIANT-35: an unrankable algorithm name must not resolve to a rung.

        Every strength lookup was ``ALGORITHM_STRENGTH.get(name, 0)``, so an
        unrecognised name silently scored as the WEAKEST algorithm — and a
        controller constructed with a name the table did not list would be
        "upgraded" on the first CRITICAL evaluation, logged as hardening, with
        the downgrade detector blinded by the same default.

        What is rejected is now a name that ranks in NO family.  KYBER_1024 and
        HYBRID_KEM rank on the KEM ladder; AES_256_GCM ranks nowhere, because
        there is no stronger AEAD to escalate to.
        """
        with pytest.raises(ValueError, match="unrankable algorithm"):
            CryptoPostureController(current_algorithm="ML_DSA_87")
        with pytest.raises(ValueError, match="unrankable algorithm"):
            CryptoPostureController(current_algorithm="AES_256_GCM")
        with pytest.raises(ValueError, match="unrankable algorithm"):
            CryptoPostureController(current_algorithm="")

        # Every name the ladders do rank is accepted.
        for name in CryptoPostureController.ALGORITHM_STRENGTH:
            CryptoPostureController(current_algorithm=name)


class TestAlgorithmFamilies:
    """Escalation is scoped to a family of interchangeable algorithms.

    A single flat strength ladder over every ``AlgorithmType`` would make
    ``_trigger_algorithm_switch`` answer a posture escalation on a KEM by
    switching to a signature scheme — the caller's key agreement performed by
    something that cannot do key agreement.  These pin the family scoping and
    the ranking of the two KEM names.
    """

    def test_every_kem_algorithm_type_is_rankable(self) -> None:
        """The two KEM ``AlgorithmType`` names reach the controller and rank."""
        for name in ("KYBER_1024", "HYBRID_KEM"):
            controller = CryptoPostureController(current_algorithm=name)
            assert controller.family_of(name) == "kem"
            assert controller.current_algorithm == name

    def test_hybrid_kem_outranks_kyber(self) -> None:
        """X25519 + ML-KEM-1024 survives the failure of either component."""
        ladder = CryptoPostureController.ALGORITHM_FAMILIES["kem"]
        assert ladder["HYBRID_KEM"] > ladder["KYBER_1024"]

    def test_signature_family_ordering_is_unchanged(self) -> None:
        ladder = CryptoPostureController.ALGORITHM_FAMILIES["signature"]
        assert ladder == {"ED25519": 0, "ML_DSA_65": 1, "SPHINCS_256F": 2, "HYBRID_SIG": 3}

    def test_families_are_disjoint(self) -> None:
        seen: set[str] = set()
        for ladder in CryptoPostureController.ALGORITHM_FAMILIES.values():
            assert not (seen & set(ladder)), "an algorithm ranks in two families"
            seen |= set(ladder)
        # The flat view must not silently drop a name to a collision.
        assert set(CryptoPostureController.ALGORITHM_STRENGTH) == seen

    def test_switch_never_leaves_the_family(self) -> None:
        """The escalation ladder contains only same-family algorithms.

        Driven through the real escalation path, not by inspecting the table:
        a KEM controller pushed to its ceiling must never be holding a
        signature-scheme name.
        """
        for family, ladder in CryptoPostureController.ALGORITHM_FAMILIES.items():
            for name in ladder:
                controller = CryptoPostureController(current_algorithm=name)
                for _ in range(len(CryptoPostureController.ALGORITHM_STRENGTH) + 2):
                    controller._trigger_algorithm_switch()
                    assert controller.current_algorithm in ladder, (
                        f"escalation from {name} left the {family} family: "
                        f"now {controller.current_algorithm}"
                    )
                # It settles at the family ceiling, not at the global one.
                ceiling = max(ladder, key=ladder.__getitem__)
                assert controller.current_algorithm == ceiling

    def test_kem_escalation_reaches_hybrid_kem(self) -> None:
        controller = CryptoPostureController(current_algorithm="KYBER_1024")
        controller._trigger_algorithm_switch()
        assert controller.current_algorithm == "HYBRID_KEM"
        assert controller._switch_count == 1

    def test_cross_family_assignment_trips_the_downgrade_alarm(self) -> None:
        """A name from another family scores below the weakest ranked rung.

        ``current_algorithm`` is public, so a caller can assign across
        families.  ``.get(name, 0)`` scored that exactly like the weakest real
        algorithm; it must instead be strictly worse, so the alarm fires.
        """
        controller = CryptoPostureController(current_algorithm="HYBRID_SIG")
        assert controller._family_strength("HYBRID_SIG") == 3
        # A KEM name is not on the signature ladder at any rung.
        assert (
            controller._family_strength("HYBRID_KEM") == CryptoPostureController.UNRANKED_STRENGTH
        )
        assert controller._family_strength("HYBRID_KEM") < controller._family_strength("ED25519")

    def test_downgrade_detection_fires_for_an_unranked_name(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        monitor = MagicMock()
        monitor.get_security_report.return_value = {"recent_alerts": [], "total_alerts": 0}
        controller = CryptoPostureController(monitor=monitor, current_algorithm="HYBRID_SIG")
        controller.evaluate_and_respond()
        controller.current_algorithm = "KYBER_1024"  # wrong family, unrankable here
        with caplog.at_level(logging.CRITICAL, logger="ama_cryptography.adaptive_posture"):
            controller.evaluate_and_respond()
        assert any(
            "Algorithm downgrade detected" in record.message for record in caplog.records
        ), "an unrankable current_algorithm must trip the downgrade alarm"


class TestMonitoringDocMatchesTheCode:
    """MONITORING.md's posture section must state what the code does.

    It documented a three-signal 50/30/20 weighting (the code has four signals
    at 45/25/15/15), a score table of 0.0-0.3 / 0.3-0.6 / 0.6-0.8 / 0.8-1.0
    (the constants are 0.15 / 0.45 / 0.80), an ``evaluator.evaluate()`` that
    takes no argument, and a ``controller.respond()`` that does not exist.
    Every one of those is a reader acting on a number or a call that is not
    there, which is the INVARIANT-16 failure mode.
    """

    @staticmethod
    def _doc() -> str:
        return (REPO_ROOT / "MONITORING.md").read_text(encoding="utf-8")

    def test_the_documented_thresholds_are_the_constants(self) -> None:
        doc = self._doc()
        for value in (
            PostureEvaluator.DEFAULT_ELEVATED_THRESHOLD,
            PostureEvaluator.DEFAULT_HIGH_THRESHOLD,
            PostureEvaluator.DEFAULT_CRITICAL_THRESHOLD,
        ):
            rendered = f"{value:.2f}"
            assert rendered in doc, f"MONITORING.md does not state the threshold {rendered}"

    def test_the_documented_weights_are_the_weights(self) -> None:
        """Read the weights out of ``evaluate``'s source and require each one."""
        import inspect
        import re as _re

        source = inspect.getsource(PostureEvaluator.evaluate)
        weights = sorted(
            {float(m) for m in _re.findall(r"_score \* (0\.\d+)", source)}, reverse=True
        )
        assert weights, "no signal weights found in PostureEvaluator.evaluate"
        doc = self._doc()
        for weight in weights:
            percent = f"{round(weight * 100)}%"
            assert percent in doc, f"MONITORING.md does not state the {percent} signal weight"

    def test_the_documented_api_calls_exist(self) -> None:
        import inspect

        doc = self._doc()
        assert "evaluator.evaluate(monitor.get_security_report())" in doc
        assert "controller.evaluate_and_respond()" in doc
        assert "controller.respond()" not in doc, "MONITORING.md calls a method that does not exist"
        # And the signatures the snippet implies really are those signatures.
        assert list(inspect.signature(PostureEvaluator.evaluate).parameters) == [
            "self",
            "monitor_report",
        ]
        assert list(inspect.signature(CryptoPostureController.evaluate_and_respond).parameters) == [
            "self"
        ]
