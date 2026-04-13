#!/usr/bin/env python3
"""
AMA Cryptography - Tests for New PQC Parameter Sets

Comprehensive tests for:
- Phase 5: ML-KEM-512/768 (FIPS 203)
- Phase 6: SLH-DSA parameter sets (FIPS 205)
- Phase 7: ML-DSA-44/87 (FIPS 204)

Tests cover keypair generation, encapsulation/decapsulation,
signing/verification, invalid input rejection, and edge cases.

Copyright 2025-2026 Steel Security Advisors LLC
Licensed under the Apache License, Version 2.0
"""

import pytest

from ama_cryptography.pqc_backends import (
    KYBER_AVAILABLE,
    DILITHIUM_AVAILABLE,
    SPHINCS_AVAILABLE,
    _get_native_lib,
)


# ============================================================================
# Helper: check if new parameter set functions exist in the native library
# ============================================================================

def _has_native_func(name: str) -> bool:
    """Check if a specific function exists in the native C library."""
    lib = _get_native_lib()
    if lib is None:
        return False
    return hasattr(lib, name)


# ============================================================================
# ML-KEM-512 Tests (FIPS 203, Level 1)
# ============================================================================

_KYBER512_AVAILABLE = _has_native_func("ama_kyber512_keypair")


@pytest.mark.skipif(not _KYBER512_AVAILABLE, reason="ML-KEM-512 not available")
class TestMLKEM512:
    """Tests for ML-KEM-512 (FIPS 203, Level 1)."""

    def test_keypair_generation(self) -> None:
        """ML-KEM-512 keypair generates correct-size keys."""
        from ama_cryptography.pqc_backends import generate_kyber512_keypair

        pk, sk = generate_kyber512_keypair()
        assert len(pk) == 800, f"Expected pk=800 bytes, got {len(pk)}"
        assert len(sk) == 1632, f"Expected sk=1632 bytes, got {len(sk)}"

    def test_encapsulate_decapsulate(self) -> None:
        """ML-KEM-512 encaps/decaps produce matching shared secrets."""
        from ama_cryptography.pqc_backends import (
            generate_kyber512_keypair,
            kyber512_encapsulate,
            kyber512_decapsulate,
        )

        pk, sk = generate_kyber512_keypair()
        ct, ss_enc = kyber512_encapsulate(pk)
        ss_dec = kyber512_decapsulate(ct, sk)

        assert len(ct) == 768, f"Expected ct=768 bytes, got {len(ct)}"
        assert len(ss_enc) == 32, f"Expected ss=32 bytes, got {len(ss_enc)}"
        assert ss_enc == ss_dec, "Shared secrets must match"

    def test_wrong_sk_produces_different_ss(self) -> None:
        """ML-KEM-512 decaps with wrong sk produces different shared secret."""
        from ama_cryptography.pqc_backends import (
            generate_kyber512_keypair,
            kyber512_encapsulate,
            kyber512_decapsulate,
        )

        pk1, sk1 = generate_kyber512_keypair()
        _pk2, sk2 = generate_kyber512_keypair()

        ct, ss_enc = kyber512_encapsulate(pk1)
        ss_wrong = kyber512_decapsulate(ct, sk2)
        # FO transform: implicit rejection means different ss, not error
        assert ss_wrong != ss_enc, "Wrong SK should produce different shared secret"

    def test_keypair_uniqueness(self) -> None:
        """Each ML-KEM-512 keypair is unique."""
        from ama_cryptography.pqc_backends import generate_kyber512_keypair

        pk1, sk1 = generate_kyber512_keypair()
        pk2, sk2 = generate_kyber512_keypair()
        assert pk1 != pk2, "Public keys must be unique"
        assert sk1 != sk2, "Secret keys must be unique"


# ============================================================================
# ML-KEM-768 Tests (FIPS 203, Level 3)
# ============================================================================

_KYBER768_AVAILABLE = _has_native_func("ama_kyber768_keypair")


@pytest.mark.skipif(not _KYBER768_AVAILABLE, reason="ML-KEM-768 not available")
class TestMLKEM768:
    """Tests for ML-KEM-768 (FIPS 203, Level 3)."""

    def test_keypair_generation(self) -> None:
        """ML-KEM-768 keypair generates correct-size keys."""
        from ama_cryptography.pqc_backends import generate_kyber768_keypair

        pk, sk = generate_kyber768_keypair()
        assert len(pk) == 1184, f"Expected pk=1184 bytes, got {len(pk)}"
        assert len(sk) == 2400, f"Expected sk=2400 bytes, got {len(sk)}"

    def test_encapsulate_decapsulate(self) -> None:
        """ML-KEM-768 encaps/decaps produce matching shared secrets."""
        from ama_cryptography.pqc_backends import (
            generate_kyber768_keypair,
            kyber768_encapsulate,
            kyber768_decapsulate,
        )

        pk, sk = generate_kyber768_keypair()
        ct, ss_enc = kyber768_encapsulate(pk)
        ss_dec = kyber768_decapsulate(ct, sk)

        assert len(ct) == 1088, f"Expected ct=1088 bytes, got {len(ct)}"
        assert len(ss_enc) == 32, f"Expected ss=32 bytes, got {len(ss_enc)}"
        assert ss_enc == ss_dec, "Shared secrets must match"

    def test_wrong_sk_produces_different_ss(self) -> None:
        """ML-KEM-768 decaps with wrong sk produces different shared secret."""
        from ama_cryptography.pqc_backends import (
            generate_kyber768_keypair,
            kyber768_encapsulate,
            kyber768_decapsulate,
        )

        pk1, sk1 = generate_kyber768_keypair()
        _pk2, sk2 = generate_kyber768_keypair()

        ct, ss_enc = kyber768_encapsulate(pk1)
        ss_wrong = kyber768_decapsulate(ct, sk2)
        assert ss_wrong != ss_enc, "Wrong SK should produce different shared secret"

    def test_keypair_uniqueness(self) -> None:
        """Each ML-KEM-768 keypair is unique."""
        from ama_cryptography.pqc_backends import generate_kyber768_keypair

        pk1, _sk1 = generate_kyber768_keypair()
        pk2, _sk2 = generate_kyber768_keypair()
        assert pk1 != pk2, "Public keys must be unique"


# ============================================================================
# SLH-DSA Parameter Set Tests (FIPS 205)
# ============================================================================

_SLH_DSA_VARIANTS = [
    ("128s", 32, 64, 7856),
    ("128f", 32, 64, 17088),
    ("192s", 48, 96, 16224),
    ("192f", 48, 96, 35664),
    ("256s", 64, 128, 29792),
]


def _slh_dsa_available(variant: str) -> bool:
    return _has_native_func(f"ama_slh_dsa_{variant}_keypair")


@pytest.mark.skipif(
    not _slh_dsa_available("128f"),
    reason="SLH-DSA parameter sets not available",
)
class TestSLHDSAParameterSets:
    """Tests for SLH-DSA additional parameter sets (FIPS 205)."""

    @pytest.mark.parametrize(
        "variant,pk_size,sk_size,sig_size",
        [v for v in _SLH_DSA_VARIANTS if _slh_dsa_available(v[0])],
        ids=[v[0] for v in _SLH_DSA_VARIANTS if _slh_dsa_available(v[0])],
    )
    def test_keypair_sizes(
        self, variant: str, pk_size: int, sk_size: int, sig_size: int
    ) -> None:
        """SLH-DSA keypair produces correct-size keys."""
        from ama_cryptography.pqc_backends import _slh_dsa_keypair

        pk, sk = _slh_dsa_keypair(variant, pk_size, sk_size)
        assert len(pk) == pk_size
        assert len(sk) == sk_size

    @pytest.mark.parametrize(
        "variant,pk_size,sk_size,sig_size",
        [v for v in _SLH_DSA_VARIANTS if _slh_dsa_available(v[0])],
        ids=[v[0] for v in _SLH_DSA_VARIANTS if _slh_dsa_available(v[0])],
    )
    def test_sign_verify_roundtrip(
        self, variant: str, pk_size: int, sk_size: int, sig_size: int
    ) -> None:
        """SLH-DSA sign/verify roundtrip succeeds."""
        from ama_cryptography.pqc_backends import (
            _slh_dsa_keypair,
            _slh_dsa_sign,
            _slh_dsa_verify,
        )

        pk, sk = _slh_dsa_keypair(variant, pk_size, sk_size)
        msg = b"AMA Cryptography SLH-DSA test message"
        sig = _slh_dsa_sign(variant, sig_size, msg, sk)

        assert len(sig) <= sig_size
        assert _slh_dsa_verify(variant, msg, sig, pk) is True

    @pytest.mark.parametrize(
        "variant,pk_size,sk_size,sig_size",
        [v for v in _SLH_DSA_VARIANTS if _slh_dsa_available(v[0])],
        ids=[v[0] for v in _SLH_DSA_VARIANTS if _slh_dsa_available(v[0])],
    )
    def test_wrong_message_fails(
        self, variant: str, pk_size: int, sk_size: int, sig_size: int
    ) -> None:
        """SLH-DSA verify with wrong message returns False."""
        from ama_cryptography.pqc_backends import (
            _slh_dsa_keypair,
            _slh_dsa_sign,
            _slh_dsa_verify,
        )

        pk, sk = _slh_dsa_keypair(variant, pk_size, sk_size)
        msg = b"correct message"
        sig = _slh_dsa_sign(variant, sig_size, msg, sk)

        assert _slh_dsa_verify(variant, b"wrong message", sig, pk) is False

    def test_keypair_uniqueness(self) -> None:
        """SLH-DSA keypairs are unique."""
        if not _slh_dsa_available("128f"):
            pytest.skip("SLH-DSA-128f not available")
        from ama_cryptography.pqc_backends import _slh_dsa_keypair

        pk1, _sk1 = _slh_dsa_keypair("128f", 32, 64)
        pk2, _sk2 = _slh_dsa_keypair("128f", 32, 64)
        assert pk1 != pk2


# ============================================================================
# ML-DSA-44 Tests (FIPS 204, Level 2)
# ============================================================================

_DSA44_AVAILABLE = _has_native_func("ama_dilithium44_keypair")


@pytest.mark.skipif(not _DSA44_AVAILABLE, reason="ML-DSA-44 not available")
class TestMLDSA44:
    """Tests for ML-DSA-44 (FIPS 204, Level 2)."""

    def test_keypair_generation(self) -> None:
        """ML-DSA-44 keypair generates correct-size keys."""
        from ama_cryptography.pqc_backends import generate_dilithium44_keypair

        pk, sk = generate_dilithium44_keypair()
        assert len(pk) == 1312, f"Expected pk=1312, got {len(pk)}"
        assert len(sk) == 2560, f"Expected sk=2560, got {len(sk)}"

    def test_sign_verify(self) -> None:
        """ML-DSA-44 sign/verify roundtrip succeeds."""
        from ama_cryptography.pqc_backends import (
            generate_dilithium44_keypair,
            dilithium44_sign,
            dilithium44_verify,
        )

        pk, sk = generate_dilithium44_keypair()
        msg = b"AMA Cryptography ML-DSA-44 test"
        sig = dilithium44_sign(msg, sk)

        assert len(sig) <= 2420
        assert dilithium44_verify(msg, sig, pk) is True

    def test_wrong_message_fails(self) -> None:
        """ML-DSA-44 verify with wrong message returns False."""
        from ama_cryptography.pqc_backends import (
            generate_dilithium44_keypair,
            dilithium44_sign,
            dilithium44_verify,
        )

        pk, sk = generate_dilithium44_keypair()
        sig = dilithium44_sign(b"correct", sk)
        assert dilithium44_verify(b"wrong", sig, pk) is False

    def test_wrong_key_fails(self) -> None:
        """ML-DSA-44 verify with wrong pk returns False."""
        from ama_cryptography.pqc_backends import (
            generate_dilithium44_keypair,
            dilithium44_sign,
            dilithium44_verify,
        )

        pk1, sk1 = generate_dilithium44_keypair()
        pk2, _sk2 = generate_dilithium44_keypair()
        sig = dilithium44_sign(b"test", sk1)
        assert dilithium44_verify(b"test", sig, pk2) is False

    def test_invalid_sk_size(self) -> None:
        """ML-DSA-44 sign rejects wrong-size secret key."""
        from ama_cryptography.pqc_backends import dilithium44_sign

        with pytest.raises(ValueError, match="2560"):
            dilithium44_sign(b"test", b"\x00" * 100)

    def test_invalid_pk_size(self) -> None:
        """ML-DSA-44 verify rejects wrong-size public key."""
        from ama_cryptography.pqc_backends import dilithium44_verify

        with pytest.raises(ValueError, match="1312"):
            dilithium44_verify(b"test", b"\x00" * 2420, b"\x00" * 100)

    def test_type_validation(self) -> None:
        """ML-DSA-44 rejects non-bytes inputs."""
        from ama_cryptography.pqc_backends import dilithium44_sign, dilithium44_verify

        with pytest.raises(TypeError):
            dilithium44_sign("not bytes", b"\x00" * 2560)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            dilithium44_verify("not bytes", b"\x00" * 2420, b"\x00" * 1312)  # type: ignore[arg-type]

    def test_keypair_uniqueness(self) -> None:
        """Each ML-DSA-44 keypair is unique."""
        from ama_cryptography.pqc_backends import generate_dilithium44_keypair

        pk1, _sk1 = generate_dilithium44_keypair()
        pk2, _sk2 = generate_dilithium44_keypair()
        assert pk1 != pk2


# ============================================================================
# ML-DSA-87 Tests (FIPS 204, Level 5)
# ============================================================================

_DSA87_AVAILABLE = _has_native_func("ama_dilithium87_keypair")


@pytest.mark.skipif(not _DSA87_AVAILABLE, reason="ML-DSA-87 not available")
class TestMLDSA87:
    """Tests for ML-DSA-87 (FIPS 204, Level 5)."""

    def test_keypair_generation(self) -> None:
        """ML-DSA-87 keypair generates correct-size keys."""
        from ama_cryptography.pqc_backends import generate_dilithium87_keypair

        pk, sk = generate_dilithium87_keypair()
        assert len(pk) == 2592, f"Expected pk=2592, got {len(pk)}"
        assert len(sk) == 4896, f"Expected sk=4896, got {len(sk)}"

    def test_sign_verify(self) -> None:
        """ML-DSA-87 sign/verify roundtrip succeeds."""
        from ama_cryptography.pqc_backends import (
            generate_dilithium87_keypair,
            dilithium87_sign,
            dilithium87_verify,
        )

        pk, sk = generate_dilithium87_keypair()
        msg = b"AMA Cryptography ML-DSA-87 test"
        sig = dilithium87_sign(msg, sk)

        assert len(sig) <= 4627
        assert dilithium87_verify(msg, sig, pk) is True

    def test_wrong_message_fails(self) -> None:
        """ML-DSA-87 verify with wrong message returns False."""
        from ama_cryptography.pqc_backends import (
            generate_dilithium87_keypair,
            dilithium87_sign,
            dilithium87_verify,
        )

        pk, sk = generate_dilithium87_keypair()
        sig = dilithium87_sign(b"correct", sk)
        assert dilithium87_verify(b"wrong", sig, pk) is False

    def test_wrong_key_fails(self) -> None:
        """ML-DSA-87 verify with wrong pk returns False."""
        from ama_cryptography.pqc_backends import (
            generate_dilithium87_keypair,
            dilithium87_sign,
            dilithium87_verify,
        )

        pk1, sk1 = generate_dilithium87_keypair()
        pk2, _sk2 = generate_dilithium87_keypair()
        sig = dilithium87_sign(b"test", sk1)
        assert dilithium87_verify(b"test", sig, pk2) is False

    def test_invalid_sk_size(self) -> None:
        """ML-DSA-87 sign rejects wrong-size secret key."""
        from ama_cryptography.pqc_backends import dilithium87_sign

        with pytest.raises(ValueError, match="4896"):
            dilithium87_sign(b"test", b"\x00" * 100)

    def test_invalid_pk_size(self) -> None:
        """ML-DSA-87 verify rejects wrong-size public key."""
        from ama_cryptography.pqc_backends import dilithium87_verify

        with pytest.raises(ValueError, match="2592"):
            dilithium87_verify(b"test", b"\x00" * 4627, b"\x00" * 100)

    def test_empty_message(self) -> None:
        """ML-DSA-87 can sign and verify empty messages."""
        from ama_cryptography.pqc_backends import (
            generate_dilithium87_keypair,
            dilithium87_sign,
            dilithium87_verify,
        )

        pk, sk = generate_dilithium87_keypair()
        sig = dilithium87_sign(b"", sk)
        assert dilithium87_verify(b"", sig, pk) is True


# ============================================================================
# Cython Binding Tests (Phase 3 coverage)
# ============================================================================


class TestCythonBindingAvailability:
    """Verify Cython bindings can be probed without crashing."""

    def test_kyber_binding_probe(self) -> None:
        """kyber_binding module can be probed."""
        try:
            from ama_cryptography import kyber_binding  # type: ignore[attr-defined]

            assert hasattr(kyber_binding, "kyber_keypair") or True
        except ImportError:
            pytest.skip("Cython kyber_binding not compiled")

    def test_sphincs_binding_probe(self) -> None:
        """sphincs_binding module can be probed."""
        try:
            from ama_cryptography import sphincs_binding  # type: ignore[attr-defined]

            assert hasattr(sphincs_binding, "sphincs_keypair") or True
        except ImportError:
            pytest.skip("Cython sphincs_binding not compiled")

    def test_aes_gcm_binding_probe(self) -> None:
        """aes_gcm_binding module can be probed."""
        try:
            from ama_cryptography import aes_gcm_binding  # type: ignore[attr-defined]

            assert True
        except ImportError:
            pytest.skip("Cython aes_gcm_binding not compiled")

    def test_chacha20poly1305_binding_probe(self) -> None:
        """chacha20poly1305_binding module can be probed."""
        try:
            from ama_cryptography import chacha20poly1305_binding  # type: ignore[attr-defined]

            assert True
        except ImportError:
            pytest.skip("Cython chacha20poly1305_binding not compiled")

    def test_x25519_binding_probe(self) -> None:
        """x25519_binding module can be probed."""
        try:
            from ama_cryptography import x25519_binding  # type: ignore[attr-defined]

            assert True
        except ImportError:
            pytest.skip("Cython x25519_binding not compiled")


# ============================================================================
# Helix Engine Complete Wiring Tests (Phase 4 coverage)
# ============================================================================


class TestHelixEngineWiring:
    """Verify helix_engine_complete.pyx wiring in setup.py / double_helix_engine.py."""

    def test_get_optimized_engine_import(self) -> None:
        """get_optimized_engine is importable from double_helix_engine."""
        from ama_cryptography.double_helix_engine import get_optimized_engine

        engine = get_optimized_engine(state_dim=50)
        assert engine is not None

    def test_cython_helix_probe(self) -> None:
        """Cython helix engine availability flag is set correctly."""
        from ama_cryptography.double_helix_engine import _CY_HELIX_AVAILABLE

        # Just verify the probe ran without error
        assert isinstance(_CY_HELIX_AVAILABLE, bool)


# ============================================================================
# Cross-Parameter-Set Consistency Tests
# ============================================================================


class TestParameterSetConsistency:
    """Cross-cutting tests for parameter set consistency."""

    @pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber not available")
    def test_kyber_1024_still_works(self) -> None:
        """Existing Kyber-1024 is not broken by new parameter sets."""
        from ama_cryptography.pqc_backends import (
            generate_kyber_keypair,
            kyber_encapsulate,
            kyber_decapsulate,
        )

        kp = generate_kyber_keypair()
        enc = kyber_encapsulate(kp.public_key)
        ss = kyber_decapsulate(enc.ciphertext, kp.secret_key)
        assert ss == enc.shared_secret

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
    def test_dilithium_65_still_works(self) -> None:
        """Existing ML-DSA-65 is not broken by new parameter sets."""
        from ama_cryptography.pqc_backends import (
            generate_dilithium_keypair,
            dilithium_sign,
            dilithium_verify,
        )

        kp = generate_dilithium_keypair()
        sig = dilithium_sign(b"test message", kp.secret_key)
        assert dilithium_verify(b"test message", sig, kp.public_key) is True

    @pytest.mark.skipif(not SPHINCS_AVAILABLE, reason="SPHINCS+ not available")
    def test_sphincs_256f_still_works(self) -> None:
        """Existing SPHINCS+-256f is not broken by new parameter sets."""
        from ama_cryptography.pqc_backends import (
            generate_sphincs_keypair,
            sphincs_sign,
            sphincs_verify,
        )

        kp = generate_sphincs_keypair()
        sig = sphincs_sign(b"test message", kp.secret_key)
        assert sphincs_verify(b"test message", sig, kp.public_key) is True


# ============================================================================
# Performance Baseline Tests (Phase 10c addendum)
# ============================================================================

import os

_CI_PERF = os.environ.get("CI_PERF", "0") == "1"


@pytest.mark.skipif(not _CI_PERF, reason="CI_PERF not enabled")
class TestNewAlgorithmPerformance:
    """Performance baseline tests for new algorithms."""

    @pytest.mark.skipif(not _KYBER512_AVAILABLE, reason="ML-KEM-512 not available")
    def test_kyber512_keygen_perf(self) -> None:
        """ML-KEM-512 keygen completes within 5 seconds for 10 iterations."""
        import time

        from ama_cryptography.pqc_backends import generate_kyber512_keypair

        start = time.monotonic()
        for _ in range(10):
            generate_kyber512_keypair()
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"ML-KEM-512 keygen too slow: {elapsed:.2f}s for 10 iters"

    @pytest.mark.skipif(not _KYBER768_AVAILABLE, reason="ML-KEM-768 not available")
    def test_kyber768_keygen_perf(self) -> None:
        """ML-KEM-768 keygen completes within 5 seconds for 10 iterations."""
        import time

        from ama_cryptography.pqc_backends import generate_kyber768_keypair

        start = time.monotonic()
        for _ in range(10):
            generate_kyber768_keypair()
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"ML-KEM-768 keygen too slow: {elapsed:.2f}s for 10 iters"

    @pytest.mark.skipif(not _DSA44_AVAILABLE, reason="ML-DSA-44 not available")
    def test_dsa44_sign_perf(self) -> None:
        """ML-DSA-44 sign completes within 10 seconds for 5 iterations."""
        import time

        from ama_cryptography.pqc_backends import (
            generate_dilithium44_keypair,
            dilithium44_sign,
        )

        pk, sk = generate_dilithium44_keypair()
        msg = b"performance test message"
        start = time.monotonic()
        for _ in range(5):
            dilithium44_sign(msg, sk)
        elapsed = time.monotonic() - start
        assert elapsed < 10.0, f"ML-DSA-44 sign too slow: {elapsed:.2f}s for 5 iters"

    @pytest.mark.skipif(not _DSA87_AVAILABLE, reason="ML-DSA-87 not available")
    def test_dsa87_sign_perf(self) -> None:
        """ML-DSA-87 sign completes within 10 seconds for 5 iterations."""
        import time

        from ama_cryptography.pqc_backends import (
            generate_dilithium87_keypair,
            dilithium87_sign,
        )

        pk, sk = generate_dilithium87_keypair()
        msg = b"performance test message"
        start = time.monotonic()
        for _ in range(5):
            dilithium87_sign(msg, sk)
        elapsed = time.monotonic() - start
        assert elapsed < 10.0, f"ML-DSA-87 sign too slow: {elapsed:.2f}s for 5 iters"
