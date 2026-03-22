#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
FIPS 140-3 Self-Test and Module Integrity Tests
================================================

Tests for the FIPS 140-3 power-on self-test infrastructure:
- Error state machine transitions
- KAT execution and validation
- Module integrity verification
- Continuous RNG health check
- Pairwise consistency test helpers
- Integrity CLI (update/verify/show)

Run with:  pytest tests/test_fips140_self_test.py -v -m fips
"""

import sys
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.fips


# ============================================================================
# Module State Machine
# ============================================================================


class TestModuleStateMachine:
    """Test FIPS 140-3 error state machine transitions."""

    def test_module_is_operational_after_import(self) -> None:
        """Module should be OPERATIONAL after successful import."""
        from ama_cryptography._self_test import module_status

        assert module_status() == "OPERATIONAL"

    def test_module_error_reason_is_none_when_operational(self) -> None:
        from ama_cryptography._self_test import module_error_reason

        assert module_error_reason() is None

    def test_check_operational_does_not_raise_when_operational(self) -> None:
        # Smoke test: verifies no exception raised when OPERATIONAL
        from ama_cryptography._self_test import check_operational, module_status

        check_operational()
        assert module_status() == "OPERATIONAL"

    def test_set_error_transitions_to_error_state(self) -> None:
        from ama_cryptography._self_test import (
            _set_error,
            _set_operational,
            module_error_reason,
            module_status,
        )

        try:
            _set_error("test failure reason")
            assert module_status() == "ERROR"
            assert module_error_reason() == "test failure reason"
        finally:
            _set_operational()

    def test_check_operational_raises_in_error_state(self) -> None:
        from ama_cryptography._self_test import (
            _set_error,
            _set_operational,
            check_operational,
        )
        from ama_cryptography.exceptions import CryptoModuleError

        try:
            _set_error("forced error")
            with pytest.raises(CryptoModuleError, match="forced error"):
                check_operational()
        finally:
            _set_operational()

    def test_reset_module_recovers_from_error(self) -> None:
        from ama_cryptography._self_test import (
            _set_error,
            module_status,
            reset_module,
        )

        _set_error("transient failure")
        assert module_status() == "ERROR"
        result = reset_module()
        assert result is True
        assert module_status() == "OPERATIONAL"

    def test_module_status_exported_from_package(self) -> None:
        """Public API should be accessible from ama_cryptography."""
        from ama_cryptography import (
            CryptoModuleError,
            check_operational,
            module_error_reason,
            module_status,
            post_duration_ms,
            reset_module,
            secure_token_bytes,
        )

        assert callable(module_status)
        assert callable(module_error_reason)
        assert callable(reset_module)
        assert callable(check_operational)
        assert issubclass(CryptoModuleError, Exception)
        assert callable(secure_token_bytes)
        assert callable(post_duration_ms)


# ============================================================================
# Power-On Self-Tests
# ============================================================================


class TestPowerOnSelfTests:
    """Test KAT execution and POST behavior."""

    def test_post_completed_successfully(self) -> None:
        from ama_cryptography._self_test import module_status

        assert module_status() == "OPERATIONAL"

    def test_post_duration_is_under_budget(self) -> None:
        from ama_cryptography._self_test import post_duration_ms

        duration = post_duration_ms()
        assert duration > 0, "POST duration should be positive"
        assert duration < 500, f"POST took {duration:.1f}ms, exceeding 500ms budget"

    def test_all_kats_passed(self) -> None:
        from ama_cryptography._self_test import module_self_test_results

        results = module_self_test_results()
        assert len(results) > 0, "No self-test results recorded"
        for name, passed, detail in results:
            assert passed, f"KAT {name} failed: {detail}"

    def test_expected_kat_names_present(self) -> None:
        from ama_cryptography._self_test import module_self_test_results

        results = module_self_test_results()
        names = {name for name, _, _ in results}
        expected = {"integrity", "SHA3-256", "AES-256-GCM", "RNG"}
        # These are always expected; PQC tests may be skipped if unavailable
        for name in expected:
            assert name in names, f"Missing KAT: {name}"

    def test_run_self_tests_is_idempotent(self) -> None:
        from ama_cryptography._self_test import _run_self_tests, module_status

        result = _run_self_tests()
        assert result is True
        assert module_status() == "OPERATIONAL"

    def test_individual_kat_sha3_256(self) -> None:
        from ama_cryptography._self_test import _kat_sha3_256

        passed, detail = _kat_sha3_256()
        assert passed, detail

    def test_individual_kat_hmac_sha3_256(self) -> None:
        from ama_cryptography._self_test import _kat_hmac_sha3_256

        passed, detail = _kat_hmac_sha3_256()
        assert passed, detail

    def test_individual_kat_aes_256_gcm(self) -> None:
        from ama_cryptography._self_test import _kat_aes_256_gcm

        passed, detail = _kat_aes_256_gcm()
        assert passed, detail

    def test_individual_kat_ml_kem_1024(self) -> None:
        from ama_cryptography._self_test import _kat_ml_kem_1024

        passed, detail = _kat_ml_kem_1024()
        assert passed, detail

    def test_individual_kat_ml_dsa_65(self) -> None:
        from ama_cryptography._self_test import _kat_ml_dsa_65

        passed, detail = _kat_ml_dsa_65()
        assert passed, detail

    def test_individual_kat_slh_dsa(self) -> None:
        from ama_cryptography._self_test import _kat_slh_dsa

        passed, detail = _kat_slh_dsa()
        assert passed, detail

    def test_individual_kat_ed25519(self) -> None:
        from ama_cryptography._self_test import _kat_ed25519

        passed, detail = _kat_ed25519()
        assert passed, detail


# ============================================================================
# Continuous RNG Health Check
# ============================================================================


class TestContinuousRNG:
    """Test the continuous RNG health check wrapper."""

    def test_secure_token_bytes_returns_correct_length(self) -> None:
        from ama_cryptography._self_test import secure_token_bytes

        for n in (16, 32, 64):
            result = secure_token_bytes(n)
            assert len(result) == n

    def test_secure_token_bytes_returns_different_outputs(self) -> None:
        from ama_cryptography._self_test import secure_token_bytes

        a = secure_token_bytes(32)
        b = secure_token_bytes(32)
        assert a != b

    def test_secure_token_bytes_raises_in_error_state(self) -> None:
        from ama_cryptography._self_test import (
            _set_error,
            _set_operational,
            secure_token_bytes,
        )
        from ama_cryptography.exceptions import CryptoModuleError

        try:
            _set_error("test error")
            with pytest.raises(CryptoModuleError):
                secure_token_bytes(32)
        finally:
            _set_operational()

    def test_identical_rng_output_triggers_error(self) -> None:
        """If secrets.token_bytes returns identical consecutive values, error state."""
        from ama_cryptography._self_test import (
            _set_operational,
            module_status,
            secure_token_bytes,
        )
        from ama_cryptography.exceptions import CryptoModuleError

        fixed = b"\xaa" * 32
        try:
            with patch("ama_cryptography._self_test.secrets.token_bytes", return_value=fixed):
                # First call sets _previous_rng_output
                secure_token_bytes(32)
                # Second call should detect duplicate
                with pytest.raises(CryptoModuleError, match="Continuous RNG"):
                    secure_token_bytes(32)
            assert module_status() == "ERROR"
        finally:
            _set_operational()


# ============================================================================
# Module Integrity Verification
# ============================================================================


class TestModuleIntegrity:
    """Test SHA3-256 module integrity verification."""

    def test_compute_digest_returns_hex_string(self) -> None:
        from ama_cryptography._self_test import _compute_module_digest

        digest = _compute_module_digest()
        assert len(digest) == 64  # SHA3-256 hex
        assert all(c in "0123456789abcdef" for c in digest)

    def test_compute_digest_is_deterministic(self) -> None:
        from ama_cryptography._self_test import _compute_module_digest

        assert _compute_module_digest() == _compute_module_digest()

    def test_verify_module_integrity_passes(self) -> None:
        from ama_cryptography._self_test import verify_module_integrity

        passed, detail = verify_module_integrity()
        assert passed is True
        assert detail == "Module integrity verified"

    def test_integrity_cli_verify(self) -> None:
        """Test `python -m ama_cryptography.integrity --verify` succeeds."""
        import subprocess

        result = subprocess.run(
            [sys.executable, "-m", "ama_cryptography.integrity", "--verify"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "OK" in result.stdout

    def test_integrity_cli_show(self) -> None:
        """Test `python -m ama_cryptography.integrity --show` outputs a hex digest."""
        import subprocess

        result = subprocess.run(
            [sys.executable, "-m", "ama_cryptography.integrity", "--show"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        digest = result.stdout.strip()
        assert len(digest) == 64


# ============================================================================
# Pairwise Consistency Tests
# ============================================================================


class TestPairwiseConsistency:
    """Test the pairwise consistency test helpers."""

    def test_pairwise_signature_passes_for_valid_keypair(self) -> None:
        from ama_cryptography._self_test import pairwise_test_signature
        from ama_cryptography.pqc_backends import (
            DILITHIUM_AVAILABLE,
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
        )

        if not DILITHIUM_AVAILABLE:
            pytest.skip("Dilithium not available")

        kp = generate_dilithium_keypair()
        # Should not raise
        pairwise_test_signature(
            dilithium_sign,
            dilithium_verify,
            kp.secret_key,
            kp.public_key,
            "ML-DSA-65",
        )

    def test_pairwise_kem_passes_for_valid_keypair(self) -> None:
        from ama_cryptography._self_test import pairwise_test_kem
        from ama_cryptography.pqc_backends import (
            KYBER_AVAILABLE,
            generate_kyber_keypair,
            kyber_decapsulate,
            kyber_encapsulate,
        )

        if not KYBER_AVAILABLE:
            pytest.skip("Kyber not available")

        kp = generate_kyber_keypair()
        # Should not raise
        pairwise_test_kem(
            kyber_encapsulate,
            kyber_decapsulate,
            kp.public_key,
            kp.secret_key,
            "ML-KEM-1024",
        )

    def test_pairwise_signature_fails_with_wrong_key(self) -> None:
        from ama_cryptography._self_test import (
            _set_operational,
            pairwise_test_signature,
        )
        from ama_cryptography.exceptions import CryptoModuleError
        from ama_cryptography.pqc_backends import (
            DILITHIUM_AVAILABLE,
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
        )

        if not DILITHIUM_AVAILABLE:
            pytest.skip("Dilithium not available")

        kp1 = generate_dilithium_keypair()
        kp2 = generate_dilithium_keypair()

        try:
            with pytest.raises(CryptoModuleError, match="Pairwise test failed"):
                pairwise_test_signature(
                    dilithium_sign,
                    dilithium_verify,
                    kp1.secret_key,
                    kp2.public_key,  # mismatched
                    "ML-DSA-65",
                )
        finally:
            _set_operational()


# ============================================================================
# CryptoModuleError Exception
# ============================================================================


class TestCryptoModuleError:
    """Test the CryptoModuleError exception class."""

    def test_is_runtime_error(self) -> None:
        from ama_cryptography.exceptions import CryptoModuleError

        assert issubclass(CryptoModuleError, RuntimeError)

    def test_can_be_raised_and_caught(self) -> None:
        from ama_cryptography.exceptions import CryptoModuleError

        with pytest.raises(CryptoModuleError, match="test message"):
            raise CryptoModuleError("test message")

    def test_importable_from_package(self) -> None:
        from ama_cryptography import CryptoModuleError  # noqa: F401
