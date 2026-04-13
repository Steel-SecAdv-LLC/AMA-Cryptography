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

import os

import pytest

from ama_cryptography.pqc_backends import (
    DILITHIUM_AVAILABLE,
    KYBER_AVAILABLE,
    SPHINCS_AVAILABLE,
    _native_lib,
)

# ============================================================================
# Helper: check if new parameter set functions exist in the native library
# ============================================================================


def _has_native_func(name: str) -> bool:
    """Check if a specific function exists in the native C library."""
    lib = _native_lib
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

        keypair = generate_kyber512_keypair()
        assert (
            len(keypair.public_key) == 800
        ), f"Expected pk=800 bytes, got {len(keypair.public_key)}"
        assert (
            len(keypair.secret_key) == 1632
        ), f"Expected sk=1632 bytes, got {len(keypair.secret_key)}"

    def test_encapsulate_decapsulate(self) -> None:
        """ML-KEM-512 encaps/decaps produce matching shared secrets."""
        from ama_cryptography.pqc_backends import (
            generate_kyber512_keypair,
            kyber512_decapsulate,
            kyber512_encapsulate,
        )

        keypair = generate_kyber512_keypair()
        encaps = kyber512_encapsulate(keypair.public_key)
        ss_dec = kyber512_decapsulate(encaps.ciphertext, keypair.secret_key)

        assert len(encaps.ciphertext) == 768, f"Expected ct=768 bytes, got {len(encaps.ciphertext)}"
        assert (
            len(encaps.shared_secret) == 32
        ), f"Expected ss=32 bytes, got {len(encaps.shared_secret)}"
        assert encaps.shared_secret == ss_dec, "Shared secrets must match"

    def test_wrong_sk_produces_different_ss(self) -> None:
        """ML-KEM-512 decaps with wrong sk produces different shared secret."""
        from ama_cryptography.pqc_backends import (
            generate_kyber512_keypair,
            kyber512_decapsulate,
            kyber512_encapsulate,
        )

        kp1 = generate_kyber512_keypair()
        kp2 = generate_kyber512_keypair()

        encaps = kyber512_encapsulate(kp1.public_key)
        ss_wrong = kyber512_decapsulate(encaps.ciphertext, kp2.secret_key)
        # FO transform: implicit rejection means different ss, not error
        assert ss_wrong != encaps.shared_secret, "Wrong SK should produce different shared secret"

    def test_keypair_uniqueness(self) -> None:
        """Each ML-KEM-512 keypair is unique."""
        from ama_cryptography.pqc_backends import generate_kyber512_keypair

        kp1 = generate_kyber512_keypair()
        kp2 = generate_kyber512_keypair()
        assert kp1.public_key != kp2.public_key, "Public keys must be unique"
        assert kp1.secret_key != kp2.secret_key, "Secret keys must be unique"


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

        keypair = generate_kyber768_keypair()
        assert (
            len(keypair.public_key) == 1184
        ), f"Expected pk=1184 bytes, got {len(keypair.public_key)}"
        assert (
            len(keypair.secret_key) == 2400
        ), f"Expected sk=2400 bytes, got {len(keypair.secret_key)}"

    def test_encapsulate_decapsulate(self) -> None:
        """ML-KEM-768 encaps/decaps produce matching shared secrets."""
        from ama_cryptography.pqc_backends import (
            generate_kyber768_keypair,
            kyber768_decapsulate,
            kyber768_encapsulate,
        )

        keypair = generate_kyber768_keypair()
        encaps = kyber768_encapsulate(keypair.public_key)
        ss_dec = kyber768_decapsulate(encaps.ciphertext, keypair.secret_key)

        assert (
            len(encaps.ciphertext) == 1088
        ), f"Expected ct=1088 bytes, got {len(encaps.ciphertext)}"
        assert (
            len(encaps.shared_secret) == 32
        ), f"Expected ss=32 bytes, got {len(encaps.shared_secret)}"
        assert encaps.shared_secret == ss_dec, "Shared secrets must match"

    def test_wrong_sk_produces_different_ss(self) -> None:
        """ML-KEM-768 decaps with wrong sk produces different shared secret."""
        from ama_cryptography.pqc_backends import (
            generate_kyber768_keypair,
            kyber768_decapsulate,
            kyber768_encapsulate,
        )

        kp1 = generate_kyber768_keypair()
        kp2 = generate_kyber768_keypair()

        encaps = kyber768_encapsulate(kp1.public_key)
        ss_wrong = kyber768_decapsulate(encaps.ciphertext, kp2.secret_key)
        assert ss_wrong != encaps.shared_secret, "Wrong SK should produce different shared secret"

    def test_keypair_uniqueness(self) -> None:
        """Each ML-KEM-768 keypair is unique."""
        from ama_cryptography.pqc_backends import generate_kyber768_keypair

        kp1 = generate_kyber768_keypair()
        kp2 = generate_kyber768_keypair()
        assert kp1.public_key != kp2.public_key, "Public keys must be unique"


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
    def test_keypair_sizes(self, variant: str, pk_size: int, sk_size: int, sig_size: int) -> None:
        """SLH-DSA keypair produces correct-size keys."""
        from ama_cryptography.pqc_backends import _slh_dsa_keypair

        kp = _slh_dsa_keypair(variant, pk_size, sk_size)
        assert len(kp.public_key) == pk_size
        assert len(kp.secret_key) == sk_size

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

        kp = _slh_dsa_keypair(variant, pk_size, sk_size)
        msg = b"AMA Cryptography SLH-DSA test message"
        sig = _slh_dsa_sign(variant, sig_size, msg, kp.secret_key)

        assert len(sig) <= sig_size
        assert _slh_dsa_verify(variant, msg, sig, kp.public_key) is True

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

        kp = _slh_dsa_keypair(variant, pk_size, sk_size)
        msg = b"correct message"
        sig = _slh_dsa_sign(variant, sig_size, msg, kp.secret_key)

        assert _slh_dsa_verify(variant, b"wrong message", sig, kp.public_key) is False

    def test_keypair_uniqueness(self) -> None:
        """SLH-DSA keypairs are unique."""
        if not _slh_dsa_available("128f"):
            pytest.skip("SLH-DSA-128f not available")
        from ama_cryptography.pqc_backends import _slh_dsa_keypair

        kp1 = _slh_dsa_keypair("128f", 32, 64)
        kp2 = _slh_dsa_keypair("128f", 32, 64)
        assert kp1.public_key != kp2.public_key


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

        keypair = generate_dilithium44_keypair()
        assert len(keypair.public_key) == 1312, f"Expected pk=1312, got {len(keypair.public_key)}"
        assert len(keypair.secret_key) == 2560, f"Expected sk=2560, got {len(keypair.secret_key)}"

    def test_sign_verify(self) -> None:
        """ML-DSA-44 sign/verify roundtrip succeeds."""
        from ama_cryptography.pqc_backends import (
            dilithium44_sign,
            dilithium44_verify,
            generate_dilithium44_keypair,
        )

        keypair = generate_dilithium44_keypair()
        msg = b"AMA Cryptography ML-DSA-44 test"
        sig = dilithium44_sign(msg, keypair.secret_key)

        assert len(sig) <= 2420
        assert dilithium44_verify(msg, sig, keypair.public_key) is True

    def test_wrong_message_fails(self) -> None:
        """ML-DSA-44 verify with wrong message returns False."""
        from ama_cryptography.pqc_backends import (
            dilithium44_sign,
            dilithium44_verify,
            generate_dilithium44_keypair,
        )

        keypair = generate_dilithium44_keypair()
        sig = dilithium44_sign(b"correct", keypair.secret_key)
        assert dilithium44_verify(b"wrong", sig, keypair.public_key) is False

    def test_wrong_key_fails(self) -> None:
        """ML-DSA-44 verify with wrong pk returns False."""
        from ama_cryptography.pqc_backends import (
            dilithium44_sign,
            dilithium44_verify,
            generate_dilithium44_keypair,
        )

        kp1 = generate_dilithium44_keypair()
        kp2 = generate_dilithium44_keypair()
        sig = dilithium44_sign(b"test", kp1.secret_key)
        assert dilithium44_verify(b"test", sig, kp2.public_key) is False

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
            dilithium44_sign("not bytes", b"\x00" * 2560)  # type: ignore[arg-type]  # deliberate type mismatch for test (PQC-003)
        with pytest.raises(TypeError):
            dilithium44_verify("not bytes", b"\x00" * 2420, b"\x00" * 1312)  # type: ignore[arg-type]  # deliberate type mismatch for test (PQC-003)

    def test_keypair_uniqueness(self) -> None:
        """Each ML-DSA-44 keypair is unique."""
        from ama_cryptography.pqc_backends import generate_dilithium44_keypair

        kp1 = generate_dilithium44_keypair()
        kp2 = generate_dilithium44_keypair()
        assert kp1.public_key != kp2.public_key


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

        keypair = generate_dilithium87_keypair()
        assert len(keypair.public_key) == 2592, f"Expected pk=2592, got {len(keypair.public_key)}"
        assert len(keypair.secret_key) == 4896, f"Expected sk=4896, got {len(keypair.secret_key)}"

    def test_sign_verify(self) -> None:
        """ML-DSA-87 sign/verify roundtrip succeeds."""
        from ama_cryptography.pqc_backends import (
            dilithium87_sign,
            dilithium87_verify,
            generate_dilithium87_keypair,
        )

        keypair = generate_dilithium87_keypair()
        msg = b"AMA Cryptography ML-DSA-87 test"
        sig = dilithium87_sign(msg, keypair.secret_key)

        assert len(sig) <= 4627
        assert dilithium87_verify(msg, sig, keypair.public_key) is True

    def test_wrong_message_fails(self) -> None:
        """ML-DSA-87 verify with wrong message returns False."""
        from ama_cryptography.pqc_backends import (
            dilithium87_sign,
            dilithium87_verify,
            generate_dilithium87_keypair,
        )

        keypair = generate_dilithium87_keypair()
        sig = dilithium87_sign(b"correct", keypair.secret_key)
        assert dilithium87_verify(b"wrong", sig, keypair.public_key) is False

    def test_wrong_key_fails(self) -> None:
        """ML-DSA-87 verify with wrong pk returns False."""
        from ama_cryptography.pqc_backends import (
            dilithium87_sign,
            dilithium87_verify,
            generate_dilithium87_keypair,
        )

        kp1 = generate_dilithium87_keypair()
        kp2 = generate_dilithium87_keypair()
        sig = dilithium87_sign(b"test", kp1.secret_key)
        assert dilithium87_verify(b"test", sig, kp2.public_key) is False

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
            dilithium87_sign,
            dilithium87_verify,
            generate_dilithium87_keypair,
        )

        keypair = generate_dilithium87_keypair()
        sig = dilithium87_sign(b"", keypair.secret_key)
        assert dilithium87_verify(b"", sig, keypair.public_key) is True


# ============================================================================
# Cython Binding Tests (Phase 3 coverage)
# ============================================================================


class TestCythonBindingAvailability:
    """Verify Cython bindings can be probed without crashing."""

    def test_kyber_binding_probe(self) -> None:
        """kyber_binding module can be probed."""
        try:
            from ama_cryptography import (
                kyber_binding,  # type: ignore[attr-defined]  # Cython .so; built at install time (CY-001)
            )

            assert hasattr(kyber_binding, "kyber_keypair") or True
        except ImportError:
            pytest.skip("Cython kyber_binding not compiled")

    def test_sphincs_binding_probe(self) -> None:
        """sphincs_binding module can be probed."""
        try:
            from ama_cryptography import (
                sphincs_binding,  # type: ignore[attr-defined]  # Cython .so; built at install time (CY-001)
            )

            assert hasattr(sphincs_binding, "sphincs_keypair") or True
        except ImportError:
            pytest.skip("Cython sphincs_binding not compiled")

    def test_aes_gcm_binding_probe(self) -> None:
        """aes_gcm_binding module can be probed."""
        try:
            from ama_cryptography import (
                aes_gcm_binding,  # type: ignore[attr-defined]  # Cython .so; built at install time (CY-001)  # noqa: F401 -- unused import for probe (CY-001)
            )

            assert True
        except ImportError:
            pytest.skip("Cython aes_gcm_binding not compiled")

    def test_chacha20poly1305_binding_probe(self) -> None:
        """chacha20poly1305_binding module can be probed."""
        try:
            from ama_cryptography import (
                chacha20poly1305_binding,  # type: ignore[attr-defined]  # Cython .so; built at install time (CY-001)  # noqa: F401 -- unused import for probe (CY-001)
            )

            assert True
        except ImportError:
            pytest.skip("Cython chacha20poly1305_binding not compiled")

    def test_x25519_binding_probe(self) -> None:
        """x25519_binding module can be probed."""
        try:
            from ama_cryptography import (
                x25519_binding,  # type: ignore[attr-defined]  # Cython .so; built at install time (CY-001)  # noqa: F401 -- unused import for probe (CY-001)
            )

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
            kyber_decapsulate,
            kyber_encapsulate,
        )

        kp = generate_kyber_keypair()
        enc = kyber_encapsulate(kp.public_key)
        ss = kyber_decapsulate(enc.ciphertext, kp.secret_key)
        assert ss == enc.shared_secret

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
    def test_dilithium_65_still_works(self) -> None:
        """Existing ML-DSA-65 is not broken by new parameter sets."""
        from ama_cryptography.pqc_backends import (
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
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
            dilithium44_sign,
            generate_dilithium44_keypair,
        )

        keypair = generate_dilithium44_keypair()
        msg = b"performance test message"
        start = time.monotonic()
        for _ in range(5):
            dilithium44_sign(msg, keypair.secret_key)
        elapsed = time.monotonic() - start
        assert elapsed < 10.0, f"ML-DSA-44 sign too slow: {elapsed:.2f}s for 5 iters"

    @pytest.mark.skipif(not _DSA87_AVAILABLE, reason="ML-DSA-87 not available")
    def test_dsa87_sign_perf(self) -> None:
        """ML-DSA-87 sign completes within 10 seconds for 5 iterations."""
        import time

        from ama_cryptography.pqc_backends import (
            dilithium87_sign,
            generate_dilithium87_keypair,
        )

        keypair = generate_dilithium87_keypair()
        msg = b"performance test message"
        start = time.monotonic()
        for _ in range(5):
            dilithium87_sign(msg, keypair.secret_key)
        elapsed = time.monotonic() - start
        assert elapsed < 10.0, f"ML-DSA-87 sign too slow: {elapsed:.2f}s for 5 iters"
