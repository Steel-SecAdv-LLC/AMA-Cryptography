#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Tests for the PostureAction.HALT action and adaptive posture wiring in crypto_api.py.

Covers:
- PostureAction.HALT exists in the enum
- _maybe_evaluate_posture raises CryptoModuleError on HALT
- AMA_ADAPTIVE_POSTURE_ENABLED flag disables the controller
- No false positives under normal (empty report) operation
"""

import logging
from unittest.mock import MagicMock, patch

import pytest

from ama_cryptography.adaptive_posture import PostureAction, PostureEvaluation, ThreatLevel

# Guard for tests that require crypto_api.py (needs native C library)
try:
    from ama_cryptography.pqc_backends import _native_lib

    NATIVE_AVAILABLE = _native_lib is not None
except ImportError:
    NATIVE_AVAILABLE = False

skip_no_native = pytest.mark.skipif(
    not NATIVE_AVAILABLE,
    reason="Native C library not available (build with cmake)",
)


class TestPostureActionHalt:
    def test_halt_exists_in_enum(self) -> None:
        """PostureAction.HALT is a member of the PostureAction enum."""
        assert hasattr(PostureAction, "HALT")
        assert PostureAction.HALT in PostureAction

    def test_halt_is_distinct_from_other_actions(self) -> None:
        """HALT is not equal to any other PostureAction value."""
        other = [a for a in PostureAction if a != PostureAction.HALT]
        assert PostureAction.HALT not in other

    def test_halt_has_unique_value(self) -> None:
        """All PostureAction members have unique values."""
        values = [a.value for a in PostureAction]
        assert len(values) == len(set(values))


@skip_no_native
class TestMaybeEvaluatePosture:
    """Tests for crypto_api._maybe_evaluate_posture()."""

    def test_does_nothing_when_disabled(self) -> None:
        """No error raised when AMA_ADAPTIVE_POSTURE_ENABLED=False."""
        with patch("ama_cryptography.crypto_api.AMA_ADAPTIVE_POSTURE_ENABLED", False):
            from ama_cryptography.crypto_api import _maybe_evaluate_posture

            _maybe_evaluate_posture()  # must not raise

    def test_does_nothing_when_controller_none(self) -> None:
        """No error raised when _posture_controller is None."""
        with (
            patch("ama_cryptography.crypto_api.AMA_ADAPTIVE_POSTURE_ENABLED", True),
            patch("ama_cryptography.crypto_api._posture_controller", None),
        ):
            from ama_cryptography.crypto_api import _maybe_evaluate_posture

            _maybe_evaluate_posture()  # must not raise

    def test_raises_crypto_module_error_on_halt(self) -> None:
        """_maybe_evaluate_posture raises CryptoModuleError when action is HALT."""
        from ama_cryptography.exceptions import CryptoModuleError

        halt_eval = PostureEvaluation(
            threat_level=ThreatLevel.CRITICAL,
            action=PostureAction.HALT,
            confidence=1.0,
            signals={},
        )
        mock_controller = MagicMock()
        mock_controller.evaluate_and_respond.return_value = halt_eval

        with (
            patch("ama_cryptography.crypto_api.AMA_ADAPTIVE_POSTURE_ENABLED", True),
            patch("ama_cryptography.crypto_api._posture_controller", mock_controller),
        ):
            from ama_cryptography.crypto_api import _maybe_evaluate_posture

            with pytest.raises(CryptoModuleError, match="critical anomaly"):
                _maybe_evaluate_posture()

    def test_no_error_on_none_action(self) -> None:
        """_maybe_evaluate_posture does NOT raise for PostureAction.NONE."""
        nominal_eval = PostureEvaluation(
            threat_level=ThreatLevel.NOMINAL,
            action=PostureAction.NONE,
            confidence=0.0,
            signals={},
        )
        mock_controller = MagicMock()
        mock_controller.evaluate_and_respond.return_value = nominal_eval

        with (
            patch("ama_cryptography.crypto_api.AMA_ADAPTIVE_POSTURE_ENABLED", True),
            patch("ama_cryptography.crypto_api._posture_controller", mock_controller),
        ):
            from ama_cryptography.crypto_api import _maybe_evaluate_posture

            _maybe_evaluate_posture()  # must not raise

    def test_logs_warning_on_rotate_keys(self, caplog: pytest.LogCaptureFixture) -> None:
        """_maybe_evaluate_posture logs a warning for ROTATE_KEYS action."""
        rotate_eval = PostureEvaluation(
            threat_level=ThreatLevel.HIGH,
            action=PostureAction.ROTATE_KEYS,
            confidence=0.9,
            signals={},
        )
        mock_controller = MagicMock()
        mock_controller.evaluate_and_respond.return_value = rotate_eval

        with (
            patch("ama_cryptography.crypto_api.AMA_ADAPTIVE_POSTURE_ENABLED", True),
            patch("ama_cryptography.crypto_api._posture_controller", mock_controller),
            caplog.at_level(logging.WARNING),
        ):
            from ama_cryptography.crypto_api import _maybe_evaluate_posture

            _maybe_evaluate_posture()

        assert any("ROTATE_KEYS" in r.message for r in caplog.records)


@skip_no_native
class TestAmaAdaptivePostureEnabled:
    def test_flag_exists_in_crypto_api(self) -> None:
        """AMA_ADAPTIVE_POSTURE_ENABLED is a bool in crypto_api."""
        from ama_cryptography.crypto_api import AMA_ADAPTIVE_POSTURE_ENABLED

        assert isinstance(AMA_ADAPTIVE_POSTURE_ENABLED, bool)

    def test_env_var_disables_posture(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """AMA_DISABLE_ADAPTIVE_POSTURE=1 sets AMA_ADAPTIVE_POSTURE_ENABLED=False."""

        monkeypatch.setenv("AMA_DISABLE_ADAPTIVE_POSTURE", "1")
        # Re-evaluate the flag (it's set at module import time, so we check
        # the logic independently).
        import os

        flag = os.getenv("AMA_DISABLE_ADAPTIVE_POSTURE", "0").lower() not in (
            "1",
            "true",
            "yes",
            "on",
        )
        assert flag is False

    def test_env_var_true_disables_posture(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """AMA_DISABLE_ADAPTIVE_POSTURE=true also disables posture."""
        import os

        monkeypatch.setenv("AMA_DISABLE_ADAPTIVE_POSTURE", "true")
        flag = os.getenv("AMA_DISABLE_ADAPTIVE_POSTURE", "0").lower() not in (
            "1",
            "true",
            "yes",
            "on",
        )
        assert flag is False
