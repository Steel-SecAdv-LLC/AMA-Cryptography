#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Tests for ama_cryptography.__init__.py exports.

Verifies that all new public symbols added by the integration work are
accessible via `import ama_cryptography` or `from ama_cryptography import ...`.

This test does NOT require the native C library for most assertions —
it only checks that the names exist in __all__ and are importable.
"""


class TestInitAllContents:
    """Verify __all__ contains expected integration symbols."""

    def _get_all(self):
        import ama_cryptography

        return ama_cryptography.__all__

    # --- Secure Channel ---
    def test_secure_channel_provider_in_all(self):
        assert "SecureChannelProvider" in self._get_all()

    def test_secure_session_in_all(self):
        assert "SecureSession" in self._get_all()

    def test_secure_channel_initiator_in_all(self):
        assert "SecureChannelInitiator" in self._get_all()

    def test_secure_channel_responder_in_all(self):
        assert "SecureChannelResponder" in self._get_all()

    def test_channel_error_in_all(self):
        assert "ChannelError" in self._get_all()

    def test_handshake_error_in_all(self):
        assert "HandshakeError" in self._get_all()

    def test_replay_error_in_all(self):
        assert "ReplayError" in self._get_all()

    # --- Session Management ---
    def test_session_store_in_all(self):
        assert "SessionStore" in self._get_all()

    def test_session_state_in_all(self):
        assert "SessionState" in self._get_all()

    def test_replay_window_in_all(self):
        assert "ReplayWindow" in self._get_all()

    def test_replay_detected_error_in_all(self):
        assert "ReplayDetectedError" in self._get_all()

    # --- Adaptive Posture ---
    def test_crypto_posture_controller_in_all(self):
        assert "CryptoPostureController" in self._get_all()

    def test_posture_evaluator_in_all(self):
        assert "PostureEvaluator" in self._get_all()

    def test_posture_action_in_all(self):
        assert "PostureAction" in self._get_all()

    def test_threat_level_in_all(self):
        assert "ThreatLevel" in self._get_all()

    # --- FROST ---
    def test_frost_provider_in_all(self):
        assert "FROSTProvider" in self._get_all()

    # --- HSM ---
    def test_hsm_available_in_all(self):
        assert "HSM_AVAILABLE" in self._get_all()

    def test_hsm_key_storage_in_all(self):
        assert "HSMKeyStorage" in self._get_all()

    def test_ama_hsm_unavailable_error_in_all(self):
        assert "AmaHSMUnavailableError" in self._get_all()

    # --- Key Management ---
    def test_hd_key_derivation_in_all(self):
        assert "HDKeyDerivation" in self._get_all()

    def test_key_rotation_manager_in_all(self):
        assert "KeyRotationManager" in self._get_all()

    # --- RFC 3161 ---
    def test_rfc3161_available_in_all(self):
        assert "RFC3161_AVAILABLE" in self._get_all()

    # --- Adaptive posture env flag ---
    def test_ama_adaptive_posture_enabled_in_all(self):
        assert "AMA_ADAPTIVE_POSTURE_ENABLED" in self._get_all()


class TestInitImports:
    """Verify actual importability of key new symbols."""

    def test_import_session_store(self):
        from ama_cryptography import SessionStore

        assert SessionStore is not None

    def test_import_session_state(self):
        from ama_cryptography import SessionState

        assert SessionState is not None

    def test_import_replay_window(self):
        from ama_cryptography import ReplayWindow

        assert ReplayWindow is not None

    def test_import_crypto_posture_controller(self):
        from ama_cryptography import CryptoPostureController

        assert CryptoPostureController is not None

    def test_import_posture_action(self):
        from ama_cryptography import PostureAction

        assert PostureAction is not None

    def test_import_posture_action_halt(self):
        from ama_cryptography import PostureAction

        assert hasattr(PostureAction, "HALT")

    def test_import_hsm_available(self):
        from ama_cryptography import HSM_AVAILABLE

        assert isinstance(HSM_AVAILABLE, bool)

    def test_import_ama_hsm_unavailable_error(self):
        from ama_cryptography import AmaHSMUnavailableError

        assert issubclass(AmaHSMUnavailableError, RuntimeError)

    def test_import_rfc3161_available(self):
        from ama_cryptography import RFC3161_AVAILABLE

        assert isinstance(RFC3161_AVAILABLE, bool)

    def test_import_secure_session(self):
        from ama_cryptography import SecureSession

        assert SecureSession is not None

    def test_import_replay_error(self):
        from ama_cryptography import ReplayError

        assert ReplayError is not None

    def test_import_replay_detected_error(self):
        from ama_cryptography import ReplayDetectedError

        assert ReplayDetectedError is not None


class TestSecureChannelDocstring:
    """Verify the docstring update in secure_channel.py (task A)."""

    def test_docstring_no_experimental(self):
        """The phrase 'should be treated as experimental' must not appear."""
        import ama_cryptography.secure_channel as sc

        assert "experimental" not in (sc.__doc__ or "")

    def test_docstring_contains_required_text(self):
        """Docstring mentions formal security review and Noise Protocol Framework."""
        import ama_cryptography.secure_channel as ama_sc

        # Normalise whitespace so newline-split phrases match.
        doc = " ".join((ama_sc.__doc__ or "").split())
        assert "formal security review" in doc
        assert "Noise Protocol Framework" in doc

    def test_docstring_mentions_ml_kem(self):
        """Docstring mentions ML-KEM-1024."""
        import ama_cryptography.secure_channel as ama_sc

        doc = ama_sc.__doc__ or ""
        assert "ML-KEM-1024" in doc


class TestRfc3161Comment:
    """Verify the INVARIANT-1 clarifying comment in rfc3161_timestamp.py."""

    def test_comment_exists_in_source(self):
        """rfc3161_timestamp.py source contains the INVARIANT-1 comment."""
        import inspect

        import ama_cryptography.rfc3161_timestamp as ts

        src = inspect.getsource(ts)
        assert "NOT violate INVARIANT-1" in src or "not violate INVARIANT-1" in src.lower()
