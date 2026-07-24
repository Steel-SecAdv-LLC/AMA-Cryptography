#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Regression coverage for two fail-open defects closed in the refinement pass.

* **Adaptive posture cooldown (`adaptive_posture.py`)** — a key rotation that is
  *attempted and fails* must not arm the rotation cooldown, or the posture
  engine suppresses every retry for the full cooldown window while the threat
  persists.  A rotation that *succeeds* must arm it.
* **Runtime integrity baseline (`monitoring.py`)** — when the startup baseline
  could not be established, ``verify_integrity`` must report a violation
  (fail-closed) rather than an empty list that reads as "verified clean".
"""

from __future__ import annotations

from unittest.mock import MagicMock

from ama_cryptography.adaptive_posture import CryptoPostureController
from ama_cryptography.monitoring import RefactoringAnalyzer


class TestRotationCooldownFailOpen:
    def test_failed_rotation_does_not_arm_cooldown(self) -> None:
        rotation_mgr = MagicMock()
        rotation_mgr.get_active_key.return_value = "key-001"
        rotation_mgr.initiate_rotation.side_effect = RuntimeError("KMS unavailable")
        controller = CryptoPostureController(rotation_manager=rotation_mgr, rotation_cooldown=9999)

        controller._trigger_rotation()  # must not raise, must not arm cooldown

        # Cooldown never armed → a retry is permitted immediately.
        assert controller._last_rotation_time == 0.0

    def test_successful_rotation_arms_cooldown(self) -> None:
        rotation_mgr = MagicMock()
        rotation_mgr.get_active_key.return_value = "key-001"
        controller = CryptoPostureController(rotation_manager=rotation_mgr, rotation_cooldown=9999)

        controller._trigger_rotation()

        assert controller._last_rotation_time > 0.0

    def test_no_mechanism_is_a_noop_that_still_arms(self) -> None:
        # With neither a rotation manager nor a callback there is nothing to
        # fail, so the trigger is a no-op that legitimately arms the cooldown
        # (preserves prior behaviour / prevents trigger spam).
        controller = CryptoPostureController(rotation_cooldown=9999)
        controller._trigger_rotation()
        assert controller._last_rotation_time > 0.0


class TestIntegrityBaselineFailClosed:
    def test_unavailable_baseline_reports_violation(self) -> None:
        analyzer = RefactoringAnalyzer()
        # Simulate a failed/partial startup baseline.
        analyzer._integrity_baseline_ready = False

        violations = analyzer.verify_integrity()

        assert len(violations) == 1
        assert violations[0].actual_hash == "BASELINE_UNAVAILABLE"

    def test_ready_baseline_is_clean_in_repo(self) -> None:
        # In the repo/installed layout the baseline is established, so a fresh
        # analyzer verifies clean (no unexpected violation).
        analyzer = RefactoringAnalyzer()
        assert analyzer._integrity_baseline_ready is True
        assert analyzer.verify_integrity() == []
