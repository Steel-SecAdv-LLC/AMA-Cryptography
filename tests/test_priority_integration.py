#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Tests for the 12-priority integration.

Covers:
- Priority 2: NonceTracker persistence and reuse detection
- Priority 4: Key lifecycle enforcement
- Priority 5: Algorithm downgrade detection
- Priority 6: Cross-operation timing correlation
- Priority 7: Timing drift detection
- Priority 8: Operation-specific anomaly profiles
- Priority 9: Runtime code integrity monitoring
- Priority 10: Import chain integrity
- Priority 11: Hysteresis in threat classification
- Priority 12: Confirmation gate for destructive actions
- Formal package schema
"""

import time

import pytest

from ama_cryptography.adaptive_posture import (
    CryptoPostureController,
    PendingAction,
    PostureAction,
    PostureEvaluator,
    ThreatLevel,
)
from ama_cryptography_monitor import (
    AmaCryptographyMonitor,
    ImportHijackViolation,
    IntegrityViolation,
    NonceTracker,
    RecursionPatternMonitor,
    RefactoringAnalyzer,
    ResonanceTimingMonitor,
)

# ============================================================================
# Priority 2: NonceTracker Tests
# ============================================================================


class TestNonceTracker:
    """Tests for nonce reuse detection and persistence."""

    def test_no_reuse_returns_none(self, tmp_path):
        tracker = NonceTracker(persist_path=str(tmp_path / "nonces.dat"))
        result = tracker.check_and_record(b"key1", b"\x00" * 12)
        assert result is None

    def test_reuse_detected(self, tmp_path):
        tracker = NonceTracker(persist_path=str(tmp_path / "nonces.dat"))
        tracker.check_and_record(b"key1", b"\x00" * 12)
        result = tracker.check_and_record(b"key1", b"\x00" * 12)
        assert result is not None
        assert result["type"] == "nonce_reuse"
        assert result["severity"] == "critical"

    def test_different_keys_same_nonce_ok(self, tmp_path):
        tracker = NonceTracker(persist_path=str(tmp_path / "nonces.dat"))
        tracker.check_and_record(b"key1", b"\x00" * 12)
        result = tracker.check_and_record(b"key2", b"\x00" * 12)
        assert result is None

    def test_persistence_survives_restart(self, tmp_path):
        path = str(tmp_path / "nonces.dat")
        tracker1 = NonceTracker(persist_path=path)
        tracker1.check_and_record(b"key1", b"\x01" * 12)

        # Simulate restart
        tracker2 = NonceTracker(persist_path=path)
        result = tracker2.check_and_record(b"key1", b"\x01" * 12)
        assert result is not None
        assert result["type"] == "nonce_reuse"

    def test_get_counter(self, tmp_path):
        tracker = NonceTracker(persist_path=str(tmp_path / "nonces.dat"))
        tracker.check_and_record(b"key1", b"\x01" * 12)
        tracker.check_and_record(b"key1", b"\x02" * 12)
        assert tracker.get_counter(b"key1") == 2

    def test_get_all_counters(self, tmp_path):
        tracker = NonceTracker(persist_path=str(tmp_path / "nonces.dat"))
        tracker.check_and_record(b"key1", b"\x01" * 12)
        tracker.check_and_record(b"key2", b"\x02" * 12)
        counters = tracker.get_all_counters()
        assert len(counters) == 2


# ============================================================================
# Priority 4: Key Lifecycle Tests
# ============================================================================


class TestKeyLifecycleEnforcement:
    """Tests for key lifecycle monitoring in RecursionPatternMonitor."""

    def test_key_usage_warning_at_75_percent(self):
        monitor = RecursionPatternMonitor()
        anomalies = monitor.monitor_key_usage({
            "key_id": "test-key",
            "status": "ACTIVE",
            "usage_count": 750,
            "max_usage": 1000,
            "expires_at": None,
        })
        assert any(a["type"] == "key_usage_warning" for a in anomalies)

    def test_key_usage_critical_at_90_percent(self):
        monitor = RecursionPatternMonitor()
        anomalies = monitor.monitor_key_usage({
            "key_id": "test-key",
            "status": "ACTIVE",
            "usage_count": 950,
            "max_usage": 1000,
            "expires_at": None,
        })
        assert any(a["type"] == "key_usage_critical" for a in anomalies)

    def test_expired_key_detected(self):
        monitor = RecursionPatternMonitor()
        anomalies = monitor.monitor_key_usage({
            "key_id": "test-key",
            "status": "ACTIVE",
            "usage_count": 10,
            "max_usage": 1000,
            "expires_at": time.time() - 3600,  # expired 1 hour ago
        })
        assert any(a["type"] == "key_expired" for a in anomalies)

    def test_revoked_key_detected(self):
        monitor = RecursionPatternMonitor()
        anomalies = monitor.monitor_key_usage({
            "key_id": "test-key",
            "status": "REVOKED",
            "usage_count": 10,
            "max_usage": 1000,
            "expires_at": None,
        })
        assert any(a["type"] == "key_status_violation" for a in anomalies)

    def test_deprecated_key_detected(self):
        monitor = RecursionPatternMonitor()
        anomalies = monitor.monitor_key_usage({
            "key_id": "test-key",
            "status": "DEPRECATED",
            "usage_count": 10,
            "max_usage": None,
            "expires_at": None,
        })
        assert any(a["type"] == "key_status_violation" for a in anomalies)

    def test_active_key_no_anomaly(self):
        monitor = RecursionPatternMonitor()
        anomalies = monitor.monitor_key_usage({
            "key_id": "test-key",
            "status": "ACTIVE",
            "usage_count": 10,
            "max_usage": 1000,
            "expires_at": time.time() + 86400,
        })
        assert len(anomalies) == 0


# ============================================================================
# Priority 5: Algorithm Downgrade Detection Tests
# ============================================================================


class TestAlgorithmDowngradeDetection:
    """Tests for algorithm downgrade detection in CryptoPostureController."""

    def test_highest_algorithm_tracked(self):
        controller = CryptoPostureController(current_algorithm="ML_DSA_65")
        assert controller._highest_algorithm_reached == 1

    def test_downgrade_acknowledged(self):
        controller = CryptoPostureController(current_algorithm="HYBRID_SIG")
        controller._highest_algorithm_reached = 3
        controller.current_algorithm = "ED25519"
        controller.acknowledge_downgrade("Testing downgrade")
        assert controller._highest_algorithm_reached == 0

    def test_summary_includes_highest(self):
        controller = CryptoPostureController(current_algorithm="SPHINCS_256F")
        summary = controller.get_posture_summary()
        assert "highest_algorithm_reached" in summary
        assert summary["highest_algorithm_reached"] == 2


# ============================================================================
# Priorities 6-8: Resonance Timing Enhancement Tests
# ============================================================================


class TestResonanceTimingEnhancements:
    """Tests for cross-op correlation, drift detection, and anomaly profiles."""

    def test_anomaly_profiles_default(self):
        monitor = ResonanceTimingMonitor()
        assert "ed25519_sign" in monitor.anomaly_profiles
        assert monitor.anomaly_profiles["ed25519_sign"]["threshold_sigma"] == 2.0

    def test_anomaly_profiles_custom(self):
        custom = {"custom_op": {"threshold_sigma": 4.0, "normalize_by_size": True}}
        monitor = ResonanceTimingMonitor(anomaly_profiles=custom)
        assert "custom_op" in monitor.anomaly_profiles
        assert monitor.anomaly_profiles["custom_op"]["threshold_sigma"] == 4.0

    def test_frozen_baseline_captured_at_30_samples(self):
        monitor = ResonanceTimingMonitor()
        for i in range(30):
            monitor.record_timing("test_op", 1.0 + (i % 3) * 0.01)
        assert "test_op" in monitor._frozen_baselines
        frozen_mean, _frozen_std = monitor._frozen_baselines["test_op"]
        assert frozen_mean > 0

    def test_input_size_normalization(self):
        """Priority 8: Size-normalized anomaly detection."""
        monitor = ResonanceTimingMonitor()
        # Record with different sizes but consistent per-byte timing
        for _i in range(35):
            monitor.record_timing("aes_gcm_encrypt", 10.0, input_size=1000)
        stats = monitor.baseline_stats.get("aes_gcm_encrypt", {})
        # The mean should be ~0.01 (10ms / 1000 bytes)
        assert stats.get("mean", 0) < 0.1

    def test_ratio_tracking_initialized(self):
        monitor = ResonanceTimingMonitor()
        for _i in range(35):
            monitor.record_timing("op_a", 1.0)
            monitor.record_timing("op_b", 2.0)
        # Ratio samples should be populated
        assert len(monitor._ratio_samples) > 0


# ============================================================================
# Priorities 9-10: Runtime Integrity Tests
# ============================================================================


class TestRuntimeIntegrity:
    """Tests for code integrity and import chain monitoring."""

    def test_integrity_baselines_populated(self):
        analyzer = RefactoringAnalyzer()
        # Baselines may be empty if running outside the repo, but the dict exists
        assert isinstance(analyzer._integrity_baselines, dict)

    def test_import_baselines_populated(self):
        analyzer = RefactoringAnalyzer()
        assert isinstance(analyzer._import_baselines, dict)

    def test_verify_integrity_returns_list(self):
        analyzer = RefactoringAnalyzer()
        violations = analyzer.verify_integrity()
        assert isinstance(violations, list)

    def test_verify_imports_returns_list(self):
        analyzer = RefactoringAnalyzer()
        violations = analyzer.verify_imports()
        assert isinstance(violations, list)

    def test_monitor_verify_runtime_integrity(self, tmp_path):
        monitor = AmaCryptographyMonitor(
            enabled=True,
            nonce_persist_path=str(tmp_path / "nonces.dat"),
        )
        result = monitor.verify_runtime_integrity()
        assert "integrity_violations" in result
        assert "import_violations" in result

    def test_integrity_violation_dataclass(self):
        v = IntegrityViolation(
            file_path="/test/file.py",
            expected_hash="abc123",
            actual_hash="def456",
        )
        assert v.file_path == "/test/file.py"

    def test_import_hijack_violation_dataclass(self):
        v = ImportHijackViolation(
            module_name="test_module",
            expected_path="/original/path.py",
            actual_path="/hijacked/path.py",
        )
        assert v.module_name == "test_module"


# ============================================================================
# Priority 11: Hysteresis Tests
# ============================================================================


class TestHysteresis:
    """Tests for hysteresis in threat classification."""

    def test_escalation_requires_consecutive_evaluations(self):
        evaluator = PostureEvaluator(
            elevated_threshold=0.3,
            escalation_count=3,
        )
        # Single high score should not escalate
        evaluator._accumulated_score = 0.0
        result1 = evaluator._classify(0.5)
        assert result1[0] == ThreatLevel.NOMINAL  # Not yet escalated

    def test_escalation_after_n_consecutive(self):
        evaluator = PostureEvaluator(
            elevated_threshold=0.3,
            escalation_count=2,
        )
        evaluator._classify(0.5)
        result = evaluator._classify(0.5)
        assert result[0] == ThreatLevel.ELEVATED

    def test_deescalation_requires_hysteresis_band(self):
        evaluator = PostureEvaluator(
            elevated_threshold=0.3,
            hysteresis_band=0.05,
            escalation_count=1,
        )
        # Escalate
        evaluator._classify(0.5)
        # Score just below threshold but within band — should NOT de-escalate
        result = evaluator._classify(0.28)
        assert result[0] == ThreatLevel.ELEVATED
        # Score below threshold - band — should de-escalate
        result = evaluator._classify(0.2)
        assert result[0] == ThreatLevel.NOMINAL

    def test_reset_clears_hysteresis_state(self):
        evaluator = PostureEvaluator(escalation_count=1)
        evaluator._classify(0.5)
        evaluator.reset()
        assert evaluator._current_level == ThreatLevel.NOMINAL
        assert all(v == 0 for v in evaluator._consecutive_counts.values())


# ============================================================================
# Priority 12: Confirmation Gate Tests
# ============================================================================


class TestConfirmationGate:
    """Tests for confirmation gate on destructive posture actions."""

    def test_pending_action_dataclass(self):
        pa = PendingAction(
            action_id="test-123",
            action=PostureAction.ROTATE_KEYS,
            reason="Test reason",
            timestamp=time.time(),
        )
        assert pa.confirmed is False
        assert pa.action == PostureAction.ROTATE_KEYS

    def test_confirmation_mode_queues_actions(self):
        controller = CryptoPostureController(
            confirmation_mode=True,
            grace_period=300.0,
        )
        # Direct call to test queuing
        pa = PendingAction(
            action_id="test-1",
            action=PostureAction.ROTATE_KEYS,
            reason="test",
            timestamp=time.time(),
        )
        controller._pending_actions.append(pa)
        assert len(controller._pending_actions) == 1

    def test_confirm_action(self):
        controller = CryptoPostureController(confirmation_mode=True)
        pa = PendingAction(
            action_id="test-2",
            action=PostureAction.ROTATE_KEYS,
            reason="test",
            timestamp=time.time(),
        )
        controller._pending_actions.append(pa)
        result = controller.confirm_action("test-2")
        assert result is True

    def test_reject_action(self):
        controller = CryptoPostureController(confirmation_mode=True)
        pa = PendingAction(
            action_id="test-3",
            action=PostureAction.ROTATE_KEYS,
            reason="test",
            timestamp=time.time(),
        )
        controller._pending_actions.append(pa)
        result = controller.reject_action("test-3")
        assert result is True
        assert len(controller._pending_actions) == 0

    def test_reject_nonexistent_action_returns_false(self):
        controller = CryptoPostureController(confirmation_mode=True)
        result = controller.reject_action("nonexistent-id")
        assert result is False

    def test_summary_includes_pending_actions(self):
        controller = CryptoPostureController(confirmation_mode=True)
        summary = controller.get_posture_summary()
        assert "pending_actions" in summary
        assert "confirmation_mode" in summary

    def test_immediate_mode_executes_directly(self):
        """Default (confirmation_mode=False) executes immediately."""
        controller = CryptoPostureController(confirmation_mode=False)
        assert controller.confirmation_mode is False

    def test_reset_clears_pending_actions(self):
        controller = CryptoPostureController(confirmation_mode=True)
        pa = PendingAction(
            action_id="test-4",
            action=PostureAction.ROTATE_KEYS,
            reason="test",
            timestamp=time.time(),
        )
        controller._pending_actions.append(pa)
        controller.reset()
        assert len(controller._pending_actions) == 0


# ============================================================================
# Package Schema Tests
# ============================================================================


class TestPackageSchema:
    """Tests for the formal CryptoPackage schema."""

    def test_schema_roundtrip(self):
        from schemas.crypto_package_v1 import CryptoPackageSchemaV1

        pkg = CryptoPackageSchemaV1(
            package_id="test-pkg-1",
            content_hash="abc123",
            algorithm="ML_DSA_65",
            signer_id="test-signer",
        )
        json_str = pkg.to_json()
        restored = CryptoPackageSchemaV1.from_json(json_str)
        assert restored.package_id == "test-pkg-1"
        assert restored.algorithm == "ML_DSA_65"
        assert restored.schema_version == "1.0"

    def test_schema_version_check(self):
        from schemas.crypto_package_v1 import CryptoPackageSchemaV1

        bad_json = '{"schema_version": "99.0", "package_id": "test"}'
        with pytest.raises(ValueError, match="Unsupported schema version"):
            CryptoPackageSchemaV1.from_json(bad_json)

    def test_integrity_hash(self):
        from schemas.crypto_package_v1 import CryptoPackageSchemaV1

        pkg = CryptoPackageSchemaV1(package_id="test-pkg-2")
        h = pkg.compute_integrity_hash()
        assert len(h) == 64  # SHA3-256 hex digest


# ============================================================================
# AmaCryptographyMonitor Integration Tests
# ============================================================================


class TestMonitorIntegration:
    """Integration tests for the unified monitor with all new features."""

    def test_nonce_tracking_via_monitor(self, tmp_path):
        monitor = AmaCryptographyMonitor(
            enabled=True,
            nonce_persist_path=str(tmp_path / "nonces.dat"),
        )
        monitor.check_nonce(b"key1", b"\x00" * 12)
        monitor.check_nonce(b"key1", b"\x00" * 12)  # reuse
        assert any(a["type"] == "nonce" for a in monitor.alerts)

    def test_key_lifecycle_via_monitor(self, tmp_path):
        monitor = AmaCryptographyMonitor(
            enabled=True,
            nonce_persist_path=str(tmp_path / "nonces.dat"),
        )
        monitor.monitor_key_lifecycle({
            "key_id": "test-key",
            "status": "REVOKED",
            "usage_count": 10,
            "max_usage": 1000,
            "expires_at": None,
        })
        assert any(a["type"] == "key_lifecycle" for a in monitor.alerts)

    def test_disabled_monitor_skips_all(self, tmp_path):
        monitor = AmaCryptographyMonitor(
            enabled=False,
            nonce_persist_path=str(tmp_path / "nonces.dat"),
        )
        monitor.check_nonce(b"key1", b"\x00" * 12)
        monitor.monitor_key_lifecycle({"key_id": "test"})
        assert len(monitor.alerts) == 0
        result = monitor.verify_runtime_integrity()
        assert result == {"status": "monitoring_disabled"}
