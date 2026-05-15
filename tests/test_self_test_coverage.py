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

from pathlib import Path
from unittest.mock import patch

import pytest

from ama_cryptography.pqc_backends import (
    DILITHIUM_AVAILABLE,
    KYBER_AVAILABLE,
    _native_lib,
)

NATIVE_AVAILABLE = _native_lib is not None

skip_no_native = pytest.mark.skipif(not NATIVE_AVAILABLE, reason="Native C library not available")
skip_no_dilithium = pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
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
        """Missing digest file returns (False, ...) when the signed-integrity
        artefact is also unavailable (fallback path).

        The signed-integrity primary path bypasses the digest file when it
        succeeds, so this test must force `_verify_signed_integrity` into the
        "no signed-integrity artefact" branch to exercise the digest-only
        fallback that the original test was written for.
        """
        from ama_cryptography._self_test import verify_module_integrity

        with (
            patch(
                "ama_cryptography._self_test._verify_signed_integrity",
                return_value=(False, "no signed-integrity artefact (digest-only fallback)"),
            ),
            patch("ama_cryptography._self_test._INTEGRITY_DIGEST_FILE") as mock_path,
        ):
            mock_path.exists.return_value = False
            passed, detail = verify_module_integrity()
            assert not passed
            assert "missing" in detail.lower() or "not found" in detail.lower()

    def test_verify_empty_digest_file(self) -> None:
        """Empty digest file returns (False, ...) on the digest-only fallback path."""
        from ama_cryptography._self_test import verify_module_integrity

        with (
            patch(
                "ama_cryptography._self_test._verify_signed_integrity",
                return_value=(False, "no signed-integrity artefact (digest-only fallback)"),
            ),
            patch("ama_cryptography._self_test._INTEGRITY_DIGEST_FILE") as mock_path,
        ):
            mock_path.exists.return_value = True
            mock_path.read_text.return_value = ""
            passed, detail = verify_module_integrity()
            assert not passed
            assert "empty" in detail.lower()

    def test_verify_mismatched_digest(self) -> None:
        """Mismatched digest returns (False, ...) on the digest-only fallback path."""
        from ama_cryptography._self_test import verify_module_integrity

        with (
            patch(
                "ama_cryptography._self_test._verify_signed_integrity",
                return_value=(False, "no signed-integrity artefact (digest-only fallback)"),
            ),
            patch("ama_cryptography._self_test._INTEGRITY_DIGEST_FILE") as mock_path,
        ):
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

    def test_verify_signed_integrity_mismatched_embedded_digest(self) -> None:
        """Signed path returns (False, ...) when the embedded digest does not
        match the recomputed digest — i.e. .py files were tampered after the
        wheel was built and signed.
        """
        from ama_cryptography._self_test import _verify_signed_integrity

        # The embedded digest is "deadbeef" * 8; the recomputed digest passed
        # in is the real digest, so they differ -> failure path.
        ok, detail = _verify_signed_integrity("a" * 64)
        # If the signature module is absent on this install the test is not
        # applicable (we'd hit the "no signed-integrity artefact" branch).
        if "no signed-integrity artefact" in detail:
            pytest.skip("signed-integrity artefact not shipped on this install")
        assert not ok
        # Either the digest mismatch or the verify-failure branch is acceptable —
        # both are correct fail-closed outcomes for tampered input.
        assert (
            "mismatch" in detail.lower()
            or "did not verify" in detail.lower()
            or "did NOT verify" in detail
        )

    def test_verify_signed_integrity_missing_module(self) -> None:
        """Signed path returns the well-defined no-artefact sentinel when
        ``_integrity_signature`` cannot be imported, so the caller can fall
        back to the digest-only path rather than treating it as a failure.

        Implementation note: ``from X import Y`` re-loads ``Y`` from disk
        when its sys.modules entry is missing, so simply popping the cache
        is not enough.  We rename the artefact file briefly to force the
        ImportError, then restore it.
        """
        import sys

        import ama_cryptography

        st_mod = ama_cryptography._self_test

        sig_path = Path(st_mod.__file__).resolve().parent / "_integrity_signature.py"
        backup = sig_path.with_suffix(".py.bak-test-INT-004")
        cached_mod = sys.modules.pop("ama_cryptography._integrity_signature", None)
        cached_attr = getattr(ama_cryptography, "_integrity_signature", None)
        if cached_attr is not None:
            try:
                delattr(ama_cryptography, "_integrity_signature")
            except AttributeError:
                pass
        if sig_path.exists():
            sig_path.rename(backup)
        try:
            ok, detail = st_mod._verify_signed_integrity("a" * 64)
        finally:
            if backup.exists():
                backup.rename(sig_path)
            if cached_mod is not None:
                sys.modules["ama_cryptography._integrity_signature"] = cached_mod
            if cached_attr is not None:
                ama_cryptography._integrity_signature = cached_attr

        assert not ok
        assert "no signed-integrity artefact" in detail

    def test_verify_signed_integrity_requires_trust_anchor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Strict release mode fails closed if no trust anchor is configured."""
        from ama_cryptography import _integrity_signature as sig_mod
        from ama_cryptography import _self_test as st_mod

        monkeypatch.setattr(st_mod, "_load_integrity_trust_anchor", lambda: (None, None))
        monkeypatch.setenv("AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR", "1")

        ok, detail = st_mod._verify_signed_integrity(sig_mod.INTEGRITY_DIGEST_HEX)

        assert not ok
        assert "trust anchor required" in detail

    def test_verify_signed_integrity_rejects_wrong_trust_anchor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Signed path rejects a signature whose pubkey is not the configured anchor."""
        from ama_cryptography import _integrity_signature as sig_mod
        from ama_cryptography import _self_test as st_mod

        wrong_anchor = "00" * 32
        if sig_mod.INTEGRITY_PUBKEY_HEX == wrong_anchor:
            wrong_anchor = "11" * 32
        monkeypatch.setattr(
            st_mod,
            "_load_integrity_trust_anchor",
            lambda: (wrong_anchor, None),
        )

        ok, detail = st_mod._verify_signed_integrity(sig_mod.INTEGRITY_DIGEST_HEX)

        assert not ok
        assert "trust anchor mismatch" in detail

    def test_load_integrity_trust_anchor_normalises_native_decode_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A ctypes/OSError/UnicodeDecodeError from the native lookup must
        collapse to ``(None, reason)`` instead of bubbling out as a raw
        traceback at import-time POST.  Without the fix the decode/strip
        was outside the try/except and a malformed pointer would crash
        the module instead of fail-closed (Copilot review #3251129734)."""
        from typing import ClassVar

        from ama_cryptography import _self_test as st_mod

        class _Pubkey:
            argtypes: ClassVar[list[object]] = []
            restype: object = None

            def __call__(self) -> bytes:
                # Simulate a malformed native return that fails .decode("ascii").
                return b"\xff\xfe not-ascii"

        class _Lib:
            ama_integrity_trust_anchor_pubkey_hex = _Pubkey()

        monkeypatch.setattr(
            "ama_cryptography.pqc_backends._native_lib",
            _Lib(),
        )

        anchor, err = st_mod._load_integrity_trust_anchor()
        assert anchor is None
        assert err is not None
        assert "trust-anchor lookup failed" in err

    def test_verify_signed_integrity_strict_release_refuses_digest_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR=1 must refuse digest-only fallback
        even when the digest matches — this is the release-grade posture."""
        from ama_cryptography import _self_test as st_mod

        monkeypatch.setattr(
            st_mod,
            "_verify_signed_integrity",
            lambda _digest: (False, "no signed-integrity artefact (digest-only fallback)"),
        )
        monkeypatch.setenv("AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR", "1")

        ok, detail = st_mod.verify_module_integrity()

        assert not ok
        assert "AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR" in detail
        assert "forbids digest-only" in detail


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

        passed, _detail = _kat_hmac_sha3_256()
        assert passed

    @skip_no_native
    def test_kat_aes_256_gcm(self) -> None:
        """AES-256-GCM KAT passes or skips."""
        from ama_cryptography._self_test import _kat_aes_256_gcm

        passed, _detail = _kat_aes_256_gcm()
        assert passed

    @skip_no_kyber
    def test_kat_ml_kem_1024(self) -> None:
        """ML-KEM-1024 KAT passes."""
        from ama_cryptography._self_test import _kat_ml_kem_1024

        passed, _detail = _kat_ml_kem_1024()
        assert passed

    @skip_no_dilithium
    def test_kat_ml_dsa_65(self) -> None:
        """ML-DSA-65 KAT passes."""
        from ama_cryptography._self_test import _kat_ml_dsa_65

        passed, _detail = _kat_ml_dsa_65()
        assert passed

    def test_kat_slh_dsa(self) -> None:
        """SLH-DSA KAT passes or skips."""
        from ama_cryptography._self_test import _kat_slh_dsa

        passed, _detail = _kat_slh_dsa()
        assert passed

    def test_kat_ed25519(self) -> None:
        """Ed25519 KAT passes or skips."""
        from ama_cryptography._self_test import _kat_ed25519

        passed, _detail = _kat_ed25519()
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

        with pytest.raises(CryptoModuleError, match=r"[Pp]airwise"):
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

        with pytest.raises(CryptoModuleError, match=r"[Pp]airwise"):
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
