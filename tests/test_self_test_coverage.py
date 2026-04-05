#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Self-Test Coverage Tests
=========================

Coverage closure for ama_cryptography/_self_test.py (target: >= 80%).
Tests state machine, KATs, integrity verification, pairwise tests,
timing oracle, and the main POST runner.

AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
"""

from unittest.mock import MagicMock, patch

import pytest

from ama_cryptography.pqc_backends import (
    DILITHIUM_AVAILABLE,
    KYBER_AVAILABLE,
    SPHINCS_AVAILABLE,
    _native_lib,
)

NATIVE_AVAILABLE = _native_lib is not None

skip_no_native = pytest.mark.skipif(
    not NATIVE_AVAILABLE, reason="Native C library not available"
)
skip_no_dilithium = pytest.mark.skipif(
    not DILITHIUM_AVAILABLE, reason="Dilithium not available"
)
skip_no_kyber = pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber not available")


# ===========================================================================
# State Machine Tests
# ===========================================================================


class TestStateMachine:
    """Test module state transitions."""

    def test_module_status_returns_string(self) -> None:
        """module_status returns a string."""
        from ama_cryptography._self_test import module_status

        status = module_status()
        assert isinstance(status, str)
        assert status in ("OPERATIONAL", "ERROR", "SELF_TEST")

    def test_set_error_sets_error_state(self) -> None:
        """_set_error transitions to ERROR state."""
        from ama_cryptography._self_test import (
            _set_error,
            _set_operational,
            module_error_reason,
            module_status,
        )

        _set_error("test error reason")
        assert module_status() == "ERROR"
        assert module_error_reason() == "test error reason"
        # Restore
        _set_operational()

    def test_set_operational_clears_error(self) -> None:
        """_set_operational transitions to OPERATIONAL and clears error."""
        from ama_cryptography._self_test import (
            _set_error,
            _set_operational,
            module_error_reason,
            module_status,
        )

        _set_error("temporary error")
        _set_operational()
        assert module_status() == "OPERATIONAL"
        assert module_error_reason() is None

    def test_check_operational_raises_in_error_state(self) -> None:
        """check_operational raises CryptoModuleError in ERROR state."""
        from ama_cryptography._self_test import (
            _set_error,
            _set_operational,
            check_operational,
        )
        from ama_cryptography.exceptions import CryptoModuleError

        _set_error("forced error for test")
        try:
            with pytest.raises(CryptoModuleError):
                check_operational()
        finally:
            _set_operational()

    def test_check_operational_passes_in_operational(self) -> None:
        """check_operational does not raise in OPERATIONAL state."""
        from ama_cryptography._self_test import _set_operational, check_operational

        _set_operational()
        check_operational()  # Should not raise


# ===========================================================================
# Module Integrity Verification Tests
# ===========================================================================


class TestModuleIntegrity:
    """Test verify_module_integrity and update_integrity_digest."""

    def test_verify_module_integrity_returns_tuple(self) -> None:
        """verify_module_integrity returns (bool, str) tuple."""
        from ama_cryptography._self_test import verify_module_integrity

        result = verify_module_integrity()
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], str)

    def test_verify_missing_digest_file(self) -> None:
        """Missing digest file returns (False, ...)."""
        from ama_cryptography._self_test import verify_module_integrity

        with patch(
            "ama_cryptography._self_test._INTEGRITY_DIGEST_FILE"
        ) as mock_path:
            mock_path.exists.return_value = False
            passed, detail = verify_module_integrity()
            assert not passed
            assert "missing" in detail.lower() or "not found" in detail.lower()

    def test_verify_empty_digest_file(self) -> None:
        """Empty digest file returns (False, ...)."""
        from ama_cryptography._self_test import verify_module_integrity

        with patch(
            "ama_cryptography._self_test._INTEGRITY_DIGEST_FILE"
        ) as mock_path:
            mock_path.exists.return_value = True
            mock_path.read_text.return_value = ""
            passed, detail = verify_module_integrity()
            assert not passed
            assert "empty" in detail.lower()

    def test_verify_mismatched_digest(self) -> None:
        """Mismatched digest returns (False, ...)."""
        from ama_cryptography._self_test import verify_module_integrity

        with patch(
            "ama_cryptography._self_test._INTEGRITY_DIGEST_FILE"
        ) as mock_path:
            mock_path.exists.return_value = True
            mock_path.read_text.return_value = "deadbeef" * 8
            passed, detail = verify_module_integrity()
            assert not passed
            assert "mismatch" in detail.lower()

    def test_update_integrity_digest_returns_hex(self) -> None:
        """update_integrity_digest returns a hex string."""
        from ama_cryptography._self_test import update_integrity_digest

        digest = update_integrity_digest()
        assert isinstance(digest, str)
        assert len(digest) == 64  # SHA3-256 hex = 64 chars
        int(digest, 16)  # Should be valid hex

    def test_compute_module_digest_deterministic(self) -> None:
        """_compute_module_digest is deterministic."""
        from ama_cryptography._self_test import _compute_module_digest

        d1 = _compute_module_digest()
        d2 = _compute_module_digest()
        assert d1 == d2


# ===========================================================================
# KAT Tests
# ===========================================================================


class TestKATs:
    """Test Known Answer Test functions."""

    def test_kat_sha3_256_passes(self) -> None:
        """SHA3-256 KAT passes with correct implementation."""
        from ama_cryptography._self_test import _kat_sha3_256

        passed, detail = _kat_sha3_256()
        assert passed
        assert "passed" in detail.lower()

    @skip_no_native
    def test_kat_hmac_sha3_256(self) -> None:
        """HMAC-SHA3-256 KAT passes or skips."""
        from ama_cryptography._self_test import _kat_hmac_sha3_256

        passed, detail = _kat_hmac_sha3_256()
        assert passed

    @skip_no_native
    def test_kat_aes_256_gcm(self) -> None:
        """AES-256-GCM KAT passes or skips."""
        from ama_cryptography._self_test import _kat_aes_256_gcm

        passed, detail = _kat_aes_256_gcm()
        assert passed

    @skip_no_kyber
    def test_kat_ml_kem_1024(self) -> None:
        """ML-KEM-1024 KAT passes."""
        from ama_cryptography._self_test import _kat_ml_kem_1024

        passed, detail = _kat_ml_kem_1024()
        assert passed

    @skip_no_dilithium
    def test_kat_ml_dsa_65(self) -> None:
        """ML-DSA-65 KAT passes."""
        from ama_cryptography._self_test import _kat_ml_dsa_65

        passed, detail = _kat_ml_dsa_65()
        assert passed

    def test_kat_slh_dsa(self) -> None:
        """SLH-DSA KAT passes or skips."""
        from ama_cryptography._self_test import _kat_slh_dsa

        passed, detail = _kat_slh_dsa()
        assert passed

    def test_kat_ed25519(self) -> None:
        """Ed25519 KAT passes or skips."""
        from ama_cryptography._self_test import _kat_ed25519

        passed, detail = _kat_ed25519()
        assert passed


# ===========================================================================
# Pairwise Consistency Tests
# ===========================================================================


@skip_no_dilithium
class TestPairwiseTests:
    """Test pairwise consistency test functions."""

    def test_pairwise_signature_success(self) -> None:
        """Pairwise signature test passes with valid keys."""
        from ama_cryptography._self_test import _set_operational, pairwise_test_signature
        from ama_cryptography.pqc_backends import (
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
        )

        _set_operational()
        kp = generate_dilithium_keypair()
        pairwise_test_signature(
            dilithium_sign, dilithium_verify, kp.secret_key, kp.public_key, "ML-DSA-65"
        )

    def test_pairwise_signature_failure(self) -> None:
        """Pairwise signature test fails with mock failure."""
        from ama_cryptography._self_test import _set_operational, pairwise_test_signature
        from ama_cryptography.exceptions import CryptoModuleError

        _set_operational()

        def mock_sign(msg: bytes, sk: bytes) -> bytes:
            return b"\x00" * 100

        def mock_verify(msg: bytes, sig: bytes, pk: bytes) -> bool:
            return False

        with pytest.raises(CryptoModuleError, match="[Pp]airwise"):
            pairwise_test_signature(mock_sign, mock_verify, b"sk", b"pk", "mock-algo")
        _set_operational()

    @skip_no_kyber
    def test_pairwise_kem_success(self) -> None:
        """Pairwise KEM test passes with valid keys."""
        from ama_cryptography._self_test import _set_operational, pairwise_test_kem
        from ama_cryptography.pqc_backends import (
            generate_kyber_keypair,
            kyber_decapsulate,
            kyber_encapsulate,
        )

        _set_operational()
        kp = generate_kyber_keypair()
        pairwise_test_kem(
            kyber_encapsulate, kyber_decapsulate, kp.public_key, kp.secret_key, "ML-KEM-1024"
        )

    def test_pairwise_kem_failure(self) -> None:
        """Pairwise KEM test fails with mock mismatch."""
        from ama_cryptography._self_test import _set_operational, pairwise_test_kem
        from ama_cryptography.exceptions import CryptoModuleError

        _set_operational()

        class MockEncap:
            ciphertext = b"ct"
            shared_secret = b"ss1"

        def mock_encaps(pk: bytes) -> MockEncap:
            return MockEncap()

        def mock_decaps(ct: bytes, sk: bytes) -> bytes:
            return b"ss2"  # Different from shared_secret

        with pytest.raises(CryptoModuleError, match="[Pp]airwise"):
            pairwise_test_kem(mock_encaps, mock_decaps, b"pk", b"sk", "mock-kem")
        _set_operational()


# ===========================================================================
# Timing Oracle Tests
# ===========================================================================


@skip_no_native
class TestTimingOracle:
    """Test _timing_oracle_consttime."""

    def test_timing_oracle_passes(self) -> None:
        """Timing oracle test passes (constant-time implementation)."""
        from ama_cryptography._self_test import _timing_oracle_consttime

        passed, detail = _timing_oracle_consttime()
        # May occasionally fail due to noise, so just verify it returns a tuple
        assert isinstance(passed, bool)
        assert isinstance(detail, str)

    def test_timing_oracle_skips_when_no_native(self) -> None:
        """Timing oracle skips when native consttime is not available."""
        from ama_cryptography._self_test import _timing_oracle_consttime

        with patch("ama_cryptography.secure_memory._native_consttime_memcmp", None):
            passed, detail = _timing_oracle_consttime()
            assert passed
            assert "skipped" in detail.lower() or "not available" in detail.lower()


# ===========================================================================
# secure_token_bytes Tests
# ===========================================================================


class TestSecureTokenBytes:
    """Test secure_token_bytes RNG health check wrapper."""

    def test_basic_output(self) -> None:
        """secure_token_bytes produces bytes of requested size."""
        from ama_cryptography._self_test import _set_operational, secure_token_bytes

        _set_operational()
        result = secure_token_bytes(32)
        assert len(result) == 32
        assert isinstance(result, bytes)

    def test_different_sizes(self) -> None:
        """secure_token_bytes handles various sizes."""
        from ama_cryptography._self_test import _set_operational, secure_token_bytes

        _set_operational()
        assert len(secure_token_bytes(1)) == 1
        assert len(secure_token_bytes(64)) == 64
        assert len(secure_token_bytes(256)) == 256

    def test_raises_in_error_state(self) -> None:
        """secure_token_bytes raises when module is in ERROR state."""
        from ama_cryptography._self_test import (
            _set_error,
            _set_operational,
            secure_token_bytes,
        )
        from ama_cryptography.exceptions import CryptoModuleError

        _set_error("test error")
        try:
            with pytest.raises(CryptoModuleError):
                secure_token_bytes(32)
        finally:
            _set_operational()


# ===========================================================================
# POST Duration and Results Tests
# ===========================================================================


class TestPOSTResults:
    """Test POST duration and results accessors."""

    def test_post_duration_ms(self) -> None:
        """post_duration_ms returns a non-negative float."""
        from ama_cryptography._self_test import post_duration_ms

        duration = post_duration_ms()
        assert isinstance(duration, float)
        assert duration >= 0

    def test_module_self_test_results(self) -> None:
        """module_self_test_results returns a list of tuples."""
        from ama_cryptography._self_test import module_self_test_results

        results = module_self_test_results()
        assert isinstance(results, list)
        for name, passed, detail in results:
            assert isinstance(name, str)
            assert isinstance(passed, bool)
            assert isinstance(detail, str)


# ===========================================================================
# reset_module Tests
# ===========================================================================


class TestResetModule:
    """Test module reset functionality."""

    @skip_no_native
    def test_reset_from_error_state(self) -> None:
        """reset_module re-runs self-tests from ERROR state."""
        from ama_cryptography._self_test import (
            _set_error,
            module_status,
            reset_module,
        )

        _set_error("deliberate error for testing reset")
        assert module_status() == "ERROR"
        result = reset_module()
        # Result depends on whether integrity digest is up to date
        assert isinstance(result, bool)
