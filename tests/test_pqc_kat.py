#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
NIST Known Answer Tests (KAT) for Post-Quantum Cryptography.

Validates AMA Cryptography's PQC implementations against NIST FIPS 203/204/205 specifications.
These tests verify correct key sizes, signature sizes, and round-trip functionality
to ensure cryptographic compliance.

Standards:
- NIST FIPS 203 (ML-KEM / Kyber)
- NIST FIPS 204 (ML-DSA / Dilithium)
- NIST FIPS 205 (SLH-DSA / SPHINCS+)

References:
- https://csrc.nist.gov/pubs/fips/203/final
- https://csrc.nist.gov/pubs/fips/204/final
- https://csrc.nist.gov/pubs/fips/205/final
"""

import json
import secrets
from pathlib import Path
from typing import Any, ClassVar

import pytest

# =============================================================================
# NIST FIPS 204 (ML-DSA / Dilithium) Constants
# =============================================================================


class MLDSA65Spec:
    """NIST FIPS 204 ML-DSA-65 (Dilithium3) specification constants."""

    # Security level: NIST Level 3 (~192-bit quantum security)
    SECURITY_LEVEL = 3

    # Key sizes (bytes) per NIST FIPS 204 Table 1
    PUBLIC_KEY_BYTES = 1952
    SECRET_KEY_BYTES = 4032
    SIGNATURE_BYTES = 3309

    # Ring parameters
    N = 256  # Polynomial degree
    Q = 8380417  # Modulus
    K = 6  # Matrix rows
    L = 5  # Matrix columns

    # Sampling parameters
    ETA = 4
    TAU = 49
    GAMMA1 = 2**19
    GAMMA2 = (Q - 1) // 32


class MLDSA44Spec:
    """NIST FIPS 204 ML-DSA-44 (Dilithium2) specification constants."""

    SECURITY_LEVEL = 2
    PUBLIC_KEY_BYTES = 1312
    SECRET_KEY_BYTES = 2560
    SIGNATURE_BYTES = 2420

    N = 256
    Q = 8380417
    K = 4
    L = 4
    ETA = 2


class MLDSA87Spec:
    """NIST FIPS 204 ML-DSA-87 (Dilithium5) specification constants."""

    SECURITY_LEVEL = 5
    PUBLIC_KEY_BYTES = 2592
    SECRET_KEY_BYTES = 4896
    SIGNATURE_BYTES = 4627

    N = 256
    Q = 8380417
    K = 8
    L = 7
    ETA = 2


# =============================================================================
# NIST FIPS 203 (ML-KEM / Kyber) Constants
# =============================================================================


class MLKEM1024Spec:
    """NIST FIPS 203 ML-KEM-1024 (Kyber-1024) specification constants."""

    # Security level: NIST Level 5 (~256-bit classical, ~128-bit quantum)
    SECURITY_LEVEL = 5

    # Key sizes (bytes) per NIST FIPS 203 Table 2
    PUBLIC_KEY_BYTES = 1568
    SECRET_KEY_BYTES = 3168
    CIPHERTEXT_BYTES = 1568
    SHARED_SECRET_BYTES = 32

    # Ring parameters
    N = 256  # Polynomial degree
    Q = 3329  # Modulus
    K = 4  # Module rank

    # Compression parameters
    DU = 11
    DV = 5
    ETA1 = 2
    ETA2 = 2


class MLKEM768Spec:
    """NIST FIPS 203 ML-KEM-768 (Kyber-768) specification constants."""

    SECURITY_LEVEL = 3
    PUBLIC_KEY_BYTES = 1184
    SECRET_KEY_BYTES = 2400
    CIPHERTEXT_BYTES = 1088
    SHARED_SECRET_BYTES = 32

    N = 256
    Q = 3329
    K = 3
    DU = 10
    DV = 4
    ETA1 = 2
    ETA2 = 2


class MLKEM512Spec:
    """NIST FIPS 203 ML-KEM-512 (Kyber-512) specification constants."""

    SECURITY_LEVEL = 1
    PUBLIC_KEY_BYTES = 800
    SECRET_KEY_BYTES = 1632
    CIPHERTEXT_BYTES = 768
    SHARED_SECRET_BYTES = 32

    N = 256
    Q = 3329
    K = 2
    DU = 10
    DV = 4
    ETA1 = 3
    ETA2 = 2


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def dilithium_provider() -> Any:
    """Get Dilithium provider if available."""
    from ama_cryptography.pqc_backends import DILITHIUM_AVAILABLE

    if not DILITHIUM_AVAILABLE:
        pytest.skip("Dilithium backend not available (install oqs package)")

    from ama_cryptography.pqc_backends import DilithiumProvider

    return DilithiumProvider()


@pytest.fixture
def kyber_provider() -> Any:
    """Get Kyber provider if available."""
    from ama_cryptography.pqc_backends import KYBER_AVAILABLE

    if not KYBER_AVAILABLE:
        pytest.skip("Kyber backend not available (install oqs package)")

    from ama_cryptography.pqc_backends import KyberProvider

    return KyberProvider()


# =============================================================================
# ML-DSA (Dilithium) KAT Tests
# =============================================================================


class TestMLDSA65KAT:
    """Known Answer Tests for ML-DSA-65 (Dilithium3)."""

    def test_public_key_size(self, dilithium_provider: Any) -> None:
        """Public key size matches NIST FIPS 204 specification."""
        keypair = dilithium_provider.generate_keypair()
        assert len(keypair.public_key) == MLDSA65Spec.PUBLIC_KEY_BYTES, (
            f"Public key size mismatch: expected {MLDSA65Spec.PUBLIC_KEY_BYTES}, "
            f"got {len(keypair.public_key)}"
        )

    def test_secret_key_size(self, dilithium_provider: Any) -> None:
        """Secret key size matches NIST FIPS 204 specification."""
        keypair = dilithium_provider.generate_keypair()
        assert len(keypair.secret_key) == MLDSA65Spec.SECRET_KEY_BYTES, (
            f"Secret key size mismatch: expected {MLDSA65Spec.SECRET_KEY_BYTES}, "
            f"got {len(keypair.secret_key)}"
        )

    def test_signature_size(self, dilithium_provider: Any) -> None:
        """Signature size matches NIST FIPS 204 specification."""
        keypair = dilithium_provider.generate_keypair()
        message = b"NIST FIPS 204 KAT test message"
        signature = dilithium_provider.sign(message, keypair.secret_key)

        assert len(signature) == MLDSA65Spec.SIGNATURE_BYTES, (
            f"Signature size mismatch: expected {MLDSA65Spec.SIGNATURE_BYTES}, "
            f"got {len(signature)}"
        )

    def test_sign_verify_roundtrip(self, dilithium_provider: Any) -> None:
        """Sign/verify round-trip produces valid signature."""
        keypair = dilithium_provider.generate_keypair()
        message = b"Round-trip test message for ML-DSA-65"

        signature = dilithium_provider.sign(message, keypair.secret_key)
        is_valid = dilithium_provider.verify(message, signature, keypair.public_key)

        assert is_valid, "Valid signature should verify successfully"

    def test_invalid_signature_fails(self, dilithium_provider: Any) -> None:
        """Modified signature fails verification."""
        keypair = dilithium_provider.generate_keypair()
        message = b"Test message"

        signature = bytearray(dilithium_provider.sign(message, keypair.secret_key))
        # Flip a bit in the signature
        signature[0] ^= 0x01

        is_valid = dilithium_provider.verify(message, bytes(signature), keypair.public_key)
        assert not is_valid, "Modified signature should fail verification"

    def test_wrong_message_fails(self, dilithium_provider: Any) -> None:
        """Signature on different message fails verification."""
        keypair = dilithium_provider.generate_keypair()
        message1 = b"Original message"
        message2 = b"Different message"

        signature = dilithium_provider.sign(message1, keypair.secret_key)
        is_valid = dilithium_provider.verify(message2, signature, keypair.public_key)

        assert not is_valid, "Signature should not verify for different message"

    def test_wrong_public_key_fails(self, dilithium_provider: Any) -> None:
        """Signature fails verification with wrong public key."""
        keypair1 = dilithium_provider.generate_keypair()
        keypair2 = dilithium_provider.generate_keypair()
        message = b"Test message"

        signature = dilithium_provider.sign(message, keypair1.secret_key)
        is_valid = dilithium_provider.verify(message, signature, keypair2.public_key)

        assert not is_valid, "Signature should not verify with different public key"

    def test_signature_consistency(self, dilithium_provider: Any) -> None:
        """ML-DSA-65 signatures are valid regardless of randomization mode.

        Note: FIPS 204 allows both deterministic and randomized signing.
        The native implementation uses deterministic signing per FIPS 204.
        This test verifies that multiple signatures from the same key are all valid.
        """
        keypair = dilithium_provider.generate_keypair()
        message = b"Consistency test"

        sig1 = dilithium_provider.sign(message, keypair.secret_key)
        sig2 = dilithium_provider.sign(message, keypair.secret_key)

        # Both signatures should verify correctly
        assert dilithium_provider.verify(
            message, sig1, keypair.public_key
        ), "First signature should verify"
        assert dilithium_provider.verify(
            message, sig2, keypair.public_key
        ), "Second signature should verify"

    def test_empty_message(self, dilithium_provider: Any) -> None:
        """Can sign and verify empty message."""
        keypair = dilithium_provider.generate_keypair()
        message = b""

        signature = dilithium_provider.sign(message, keypair.secret_key)
        is_valid = dilithium_provider.verify(message, signature, keypair.public_key)

        assert is_valid, "Empty message signature should verify"

    def test_large_message(self, dilithium_provider: Any) -> None:
        """Can sign and verify large message."""
        keypair = dilithium_provider.generate_keypair()
        message = secrets.token_bytes(1024 * 1024)  # 1 MB

        signature = dilithium_provider.sign(message, keypair.secret_key)
        is_valid = dilithium_provider.verify(message, signature, keypair.public_key)

        assert is_valid, "Large message signature should verify"

    def test_entropy_in_keys(self, dilithium_provider: Any) -> None:
        """Generated keys have sufficient entropy."""
        keypair = dilithium_provider.generate_keypair()

        # Count unique bytes in public key
        unique_bytes = len(set(keypair.public_key))

        # Should have good entropy (at least 200 unique byte values for 1952 bytes)
        assert (
            unique_bytes >= 200
        ), f"Public key lacks entropy: only {unique_bytes} unique byte values"


# =============================================================================
# ML-KEM (Kyber) KAT Tests
# =============================================================================


class TestMLKEM1024KAT:
    """Known Answer Tests for ML-KEM-1024 (Kyber-1024)."""

    def test_public_key_size(self, kyber_provider: Any) -> None:
        """Public key size matches NIST FIPS 203 specification."""
        keypair = kyber_provider.generate_keypair()
        assert len(keypair.public_key) == MLKEM1024Spec.PUBLIC_KEY_BYTES, (
            f"Public key size mismatch: expected {MLKEM1024Spec.PUBLIC_KEY_BYTES}, "
            f"got {len(keypair.public_key)}"
        )

    def test_secret_key_size(self, kyber_provider: Any) -> None:
        """Secret key size matches NIST FIPS 203 specification."""
        keypair = kyber_provider.generate_keypair()
        assert len(keypair.secret_key) == MLKEM1024Spec.SECRET_KEY_BYTES, (
            f"Secret key size mismatch: expected {MLKEM1024Spec.SECRET_KEY_BYTES}, "
            f"got {len(keypair.secret_key)}"
        )

    def test_ciphertext_size(self, kyber_provider: Any) -> None:
        """Ciphertext size matches NIST FIPS 203 specification."""
        keypair = kyber_provider.generate_keypair()
        ciphertext, _ = kyber_provider.encapsulate(keypair.public_key)

        assert len(ciphertext) == MLKEM1024Spec.CIPHERTEXT_BYTES, (
            f"Ciphertext size mismatch: expected {MLKEM1024Spec.CIPHERTEXT_BYTES}, "
            f"got {len(ciphertext)}"
        )

    def test_shared_secret_size(self, kyber_provider: Any) -> None:
        """Shared secret size matches NIST FIPS 203 specification."""
        keypair = kyber_provider.generate_keypair()
        _, shared_secret = kyber_provider.encapsulate(keypair.public_key)

        assert len(shared_secret) == MLKEM1024Spec.SHARED_SECRET_BYTES, (
            f"Shared secret size mismatch: expected {MLKEM1024Spec.SHARED_SECRET_BYTES}, "
            f"got {len(shared_secret)}"
        )

    def test_encapsulate_decapsulate_roundtrip(self, kyber_provider: Any) -> None:
        """Encapsulate/decapsulate round-trip produces matching shared secrets."""
        keypair = kyber_provider.generate_keypair()

        ciphertext, shared_secret_enc = kyber_provider.encapsulate(keypair.public_key)
        shared_secret_dec = kyber_provider.decapsulate(ciphertext, keypair.secret_key)

        assert (
            shared_secret_enc == shared_secret_dec
        ), "Encapsulated and decapsulated shared secrets must match"

    def test_different_keypairs_different_secrets(self, kyber_provider: Any) -> None:
        """Different keypairs produce different shared secrets."""
        keypair1 = kyber_provider.generate_keypair()
        keypair2 = kyber_provider.generate_keypair()

        _, secret1 = kyber_provider.encapsulate(keypair1.public_key)
        _, secret2 = kyber_provider.encapsulate(keypair2.public_key)

        # With overwhelming probability, secrets should differ
        assert secret1 != secret2, "Different keypairs should produce different secrets"

    def test_encapsulation_randomness(self, kyber_provider: Any) -> None:
        """Multiple encapsulations produce different ciphertexts."""
        keypair = kyber_provider.generate_keypair()

        ct1, _ = kyber_provider.encapsulate(keypair.public_key)
        ct2, _ = kyber_provider.encapsulate(keypair.public_key)

        # Encapsulation should be randomized
        assert ct1 != ct2, "Multiple encapsulations should produce different ciphertexts"

    def test_wrong_secret_key_implicit_rejection(self, kyber_provider: Any) -> None:
        """Decapsulation with wrong secret key uses implicit rejection."""
        keypair1 = kyber_provider.generate_keypair()
        keypair2 = kyber_provider.generate_keypair()

        ciphertext, shared_secret_enc = kyber_provider.encapsulate(keypair1.public_key)

        # Decapsulate with wrong key - should use implicit rejection
        shared_secret_wrong = kyber_provider.decapsulate(ciphertext, keypair2.secret_key)

        # Should NOT match (implicit rejection returns random-looking secret)
        assert (
            shared_secret_enc != shared_secret_wrong
        ), "Decapsulation with wrong key should not produce matching secret"

    def test_entropy_in_shared_secret(self, kyber_provider: Any) -> None:
        """Shared secret has good entropy distribution."""
        keypair = kyber_provider.generate_keypair()
        _, shared_secret = kyber_provider.encapsulate(keypair.public_key)

        # For 32 bytes, expect at least 20 unique values
        unique_bytes = len(set(shared_secret))
        assert (
            unique_bytes >= 20
        ), f"Shared secret lacks entropy: only {unique_bytes} unique byte values"


# =============================================================================
# Cross-Algorithm Tests
# =============================================================================


class TestMLKEM512KAT:
    """Known Answer Tests for ML-KEM-512 (Kyber-512) per NIST FIPS 203."""

    @pytest.fixture(autouse=True)
    def _check_available(self) -> None:
        from ama_cryptography.pqc_backends import _has_native_func  # type: ignore[attr-defined]

        if not _has_native_func("ama_kyber512_keypair"):  # type: ignore[operator]
            pytest.skip("ML-KEM-512 not available in native library")

    def test_public_key_size(self) -> None:
        """Public key size matches NIST FIPS 203 ML-KEM-512 specification."""
        from ama_cryptography.pqc_backends import generate_kyber512_keypair

        pk, _sk = generate_kyber512_keypair()
        assert len(pk) == MLKEM512Spec.PUBLIC_KEY_BYTES

    def test_secret_key_size(self) -> None:
        """Secret key size matches NIST FIPS 203 ML-KEM-512 specification."""
        from ama_cryptography.pqc_backends import generate_kyber512_keypair

        _pk, sk = generate_kyber512_keypair()
        assert len(sk) == MLKEM512Spec.SECRET_KEY_BYTES

    def test_ciphertext_size(self) -> None:
        """Ciphertext size matches NIST FIPS 203 ML-KEM-512 specification."""
        from ama_cryptography.pqc_backends import (
            generate_kyber512_keypair,
            kyber512_encapsulate,
        )

        pk, _sk = generate_kyber512_keypair()
        ct, _ss = kyber512_encapsulate(pk)
        assert len(ct) == MLKEM512Spec.CIPHERTEXT_BYTES

    def test_shared_secret_size(self) -> None:
        """Shared secret size matches NIST FIPS 203 specification (32 bytes)."""
        from ama_cryptography.pqc_backends import (
            generate_kyber512_keypair,
            kyber512_encapsulate,
        )

        pk, _sk = generate_kyber512_keypair()
        _ct, ss = kyber512_encapsulate(pk)
        assert len(ss) == MLKEM512Spec.SHARED_SECRET_BYTES

    def test_encapsulate_decapsulate_roundtrip(self) -> None:
        """ML-KEM-512 encaps/decaps round-trip produces matching shared secrets."""
        from ama_cryptography.pqc_backends import (
            generate_kyber512_keypair,
            kyber512_decapsulate,
            kyber512_encapsulate,
        )

        pk, sk = generate_kyber512_keypair()
        ct, ss_enc = kyber512_encapsulate(pk)
        ss_dec = kyber512_decapsulate(ct, sk)
        assert ss_enc == ss_dec, "Shared secrets must match"

    def test_wrong_sk_implicit_rejection(self) -> None:
        """Decaps with wrong sk uses implicit rejection (different shared secret)."""
        from ama_cryptography.pqc_backends import (
            generate_kyber512_keypair,
            kyber512_decapsulate,
            kyber512_encapsulate,
        )

        pk1, _sk1 = generate_kyber512_keypair()
        _pk2, sk2 = generate_kyber512_keypair()
        ct, ss_enc = kyber512_encapsulate(pk1)
        ss_wrong = kyber512_decapsulate(ct, sk2)
        assert ss_enc != ss_wrong

    def test_encapsulation_randomness(self) -> None:
        """Multiple encapsulations produce different ciphertexts."""
        from ama_cryptography.pqc_backends import (
            generate_kyber512_keypair,
            kyber512_encapsulate,
        )

        pk, _sk = generate_kyber512_keypair()
        ct1, _ = kyber512_encapsulate(pk)
        ct2, _ = kyber512_encapsulate(pk)
        assert ct1 != ct2

    def test_kat_vector_sizes(self) -> None:
        """Validate ML-KEM-512 KAT vector sizes match FIPS 203."""
        from tests.test_nist_kat import (
            ML_KEM_DIR,
            kyber_kat_available,
            load_kyber_kat_vectors,
        )

        if not kyber_kat_available("kyber512"):
            pytest.skip("Kyber-512 KAT vectors not available")
        vectors = load_kyber_kat_vectors(ML_KEM_DIR / "kyber512.rsp", max_vectors=5)
        assert len(vectors) > 0
        for v in vectors:
            assert len(v.pk) == MLKEM512Spec.PUBLIC_KEY_BYTES
            assert len(v.sk) == MLKEM512Spec.SECRET_KEY_BYTES
            assert len(v.ct) == MLKEM512Spec.CIPHERTEXT_BYTES
            assert len(v.ss) == MLKEM512Spec.SHARED_SECRET_BYTES


class TestMLKEM768KAT:
    """Known Answer Tests for ML-KEM-768 (Kyber-768) per NIST FIPS 203."""

    @pytest.fixture(autouse=True)
    def _check_available(self) -> None:
        from ama_cryptography.pqc_backends import _has_native_func  # type: ignore[attr-defined]

        if not _has_native_func("ama_kyber768_keypair"):  # type: ignore[operator]
            pytest.skip("ML-KEM-768 not available in native library")

    def test_public_key_size(self) -> None:
        """Public key size matches NIST FIPS 203 ML-KEM-768 specification."""
        from ama_cryptography.pqc_backends import generate_kyber768_keypair

        pk, _sk = generate_kyber768_keypair()
        assert len(pk) == MLKEM768Spec.PUBLIC_KEY_BYTES

    def test_secret_key_size(self) -> None:
        """Secret key size matches NIST FIPS 203 ML-KEM-768 specification."""
        from ama_cryptography.pqc_backends import generate_kyber768_keypair

        _pk, sk = generate_kyber768_keypair()
        assert len(sk) == MLKEM768Spec.SECRET_KEY_BYTES

    def test_ciphertext_size(self) -> None:
        """Ciphertext size matches NIST FIPS 203 ML-KEM-768 specification."""
        from ama_cryptography.pqc_backends import (
            generate_kyber768_keypair,
            kyber768_encapsulate,
        )

        pk, _sk = generate_kyber768_keypair()
        ct, _ss = kyber768_encapsulate(pk)
        assert len(ct) == MLKEM768Spec.CIPHERTEXT_BYTES

    def test_shared_secret_size(self) -> None:
        """Shared secret size matches NIST FIPS 203 specification (32 bytes)."""
        from ama_cryptography.pqc_backends import (
            generate_kyber768_keypair,
            kyber768_encapsulate,
        )

        pk, _sk = generate_kyber768_keypair()
        _ct, ss = kyber768_encapsulate(pk)
        assert len(ss) == MLKEM768Spec.SHARED_SECRET_BYTES

    def test_encapsulate_decapsulate_roundtrip(self) -> None:
        """ML-KEM-768 encaps/decaps round-trip produces matching shared secrets."""
        from ama_cryptography.pqc_backends import (
            generate_kyber768_keypair,
            kyber768_decapsulate,
            kyber768_encapsulate,
        )

        pk, sk = generate_kyber768_keypair()
        ct, ss_enc = kyber768_encapsulate(pk)
        ss_dec = kyber768_decapsulate(ct, sk)
        assert ss_enc == ss_dec, "Shared secrets must match"

    def test_wrong_sk_implicit_rejection(self) -> None:
        """Decaps with wrong sk uses implicit rejection (different shared secret)."""
        from ama_cryptography.pqc_backends import (
            generate_kyber768_keypair,
            kyber768_decapsulate,
            kyber768_encapsulate,
        )

        pk1, _sk1 = generate_kyber768_keypair()
        _pk2, sk2 = generate_kyber768_keypair()
        ct, ss_enc = kyber768_encapsulate(pk1)
        ss_wrong = kyber768_decapsulate(ct, sk2)
        assert ss_enc != ss_wrong

    def test_encapsulation_randomness(self) -> None:
        """Multiple encapsulations produce different ciphertexts."""
        from ama_cryptography.pqc_backends import (
            generate_kyber768_keypair,
            kyber768_encapsulate,
        )

        pk, _sk = generate_kyber768_keypair()
        ct1, _ = kyber768_encapsulate(pk)
        ct2, _ = kyber768_encapsulate(pk)
        assert ct1 != ct2

    def test_kat_vector_sizes(self) -> None:
        """Validate ML-KEM-768 KAT vector sizes match FIPS 203."""
        from tests.test_nist_kat import (
            ML_KEM_DIR,
            kyber_kat_available,
            load_kyber_kat_vectors,
        )

        if not kyber_kat_available("kyber768"):
            pytest.skip("Kyber-768 KAT vectors not available")
        vectors = load_kyber_kat_vectors(ML_KEM_DIR / "kyber768.rsp", max_vectors=5)
        assert len(vectors) > 0
        for v in vectors:
            assert len(v.pk) == MLKEM768Spec.PUBLIC_KEY_BYTES
            assert len(v.sk) == MLKEM768Spec.SECRET_KEY_BYTES
            assert len(v.ct) == MLKEM768Spec.CIPHERTEXT_BYTES
            assert len(v.ss) == MLKEM768Spec.SHARED_SECRET_BYTES


class TestMLDSA44KAT:
    """Known Answer Tests for ML-DSA-44 (Dilithium2) per NIST FIPS 204."""

    @pytest.fixture(autouse=True)
    def _check_available(self) -> None:
        from ama_cryptography.pqc_backends import _has_native_func  # type: ignore[attr-defined]

        if not _has_native_func("ama_dilithium44_keypair"):  # type: ignore[operator]
            pytest.skip("ML-DSA-44 not available in native library")

    def test_public_key_size(self) -> None:
        """Public key size matches NIST FIPS 204 ML-DSA-44 specification."""
        from ama_cryptography.pqc_backends import generate_dilithium44_keypair

        pk, _sk = generate_dilithium44_keypair()
        assert len(pk) == MLDSA44Spec.PUBLIC_KEY_BYTES

    def test_secret_key_size(self) -> None:
        """Secret key size matches NIST FIPS 204 ML-DSA-44 specification."""
        from ama_cryptography.pqc_backends import generate_dilithium44_keypair

        _pk, sk = generate_dilithium44_keypair()
        assert len(sk) == MLDSA44Spec.SECRET_KEY_BYTES

    def test_signature_size(self) -> None:
        """Signature size matches NIST FIPS 204 ML-DSA-44 specification."""
        from ama_cryptography.pqc_backends import (
            dilithium44_sign,
            generate_dilithium44_keypair,
        )

        _pk, sk = generate_dilithium44_keypair()
        sig = dilithium44_sign(b"FIPS 204 KAT test", sk)
        assert len(sig) == MLDSA44Spec.SIGNATURE_BYTES

    def test_sign_verify_roundtrip(self) -> None:
        """ML-DSA-44 sign/verify round-trip succeeds."""
        from ama_cryptography.pqc_backends import (
            dilithium44_sign,
            dilithium44_verify,
            generate_dilithium44_keypair,
        )

        pk, sk = generate_dilithium44_keypair()
        msg = b"ML-DSA-44 roundtrip test"
        sig = dilithium44_sign(msg, sk)
        assert dilithium44_verify(msg, sig, pk)

    def test_invalid_signature_fails(self) -> None:
        """Tampered ML-DSA-44 signature fails verification."""
        from ama_cryptography.pqc_backends import (
            dilithium44_sign,
            dilithium44_verify,
            generate_dilithium44_keypair,
        )

        pk, sk = generate_dilithium44_keypair()
        sig = bytearray(dilithium44_sign(b"test", sk))
        sig[0] ^= 0xFF
        assert not dilithium44_verify(b"test", bytes(sig), pk)

    def test_wrong_message_fails(self) -> None:
        """ML-DSA-44 verification with wrong message fails."""
        from ama_cryptography.pqc_backends import (
            dilithium44_sign,
            dilithium44_verify,
            generate_dilithium44_keypair,
        )

        pk, sk = generate_dilithium44_keypair()
        sig = dilithium44_sign(b"original", sk)
        assert not dilithium44_verify(b"modified", sig, pk)

    def test_wrong_pk_fails(self) -> None:
        """ML-DSA-44 verification with wrong public key fails."""
        from ama_cryptography.pqc_backends import (
            dilithium44_sign,
            dilithium44_verify,
            generate_dilithium44_keypair,
        )

        _pk1, sk1 = generate_dilithium44_keypair()
        pk2, _sk2 = generate_dilithium44_keypair()
        sig = dilithium44_sign(b"test", sk1)
        assert not dilithium44_verify(b"test", sig, pk2)

    def test_kat_vector_sizes(self) -> None:
        """Validate ML-DSA-44 KAT vector sizes match FIPS 204."""
        from tests.test_nist_kat import (
            ML_DSA_DIR,
            dilithium_kat_available,
            load_dilithium_kat_vectors,
        )

        if not dilithium_kat_available("dilithium2"):
            pytest.skip("Dilithium2 (ML-DSA-44) KAT vectors not available")
        vectors = load_dilithium_kat_vectors(ML_DSA_DIR / "dilithium2.rsp", max_vectors=5)
        assert len(vectors) > 0
        for v in vectors:
            assert len(v.pk) == MLDSA44Spec.PUBLIC_KEY_BYTES


class TestMLDSA87KAT:
    """Known Answer Tests for ML-DSA-87 (Dilithium5) per NIST FIPS 204."""

    @pytest.fixture(autouse=True)
    def _check_available(self) -> None:
        from ama_cryptography.pqc_backends import _has_native_func  # type: ignore[attr-defined]

        if not _has_native_func("ama_dilithium87_keypair"):  # type: ignore[operator]
            pytest.skip("ML-DSA-87 not available in native library")

    def test_public_key_size(self) -> None:
        """Public key size matches NIST FIPS 204 ML-DSA-87 specification."""
        from ama_cryptography.pqc_backends import generate_dilithium87_keypair

        pk, _sk = generate_dilithium87_keypair()
        assert len(pk) == MLDSA87Spec.PUBLIC_KEY_BYTES

    def test_secret_key_size(self) -> None:
        """Secret key size matches NIST FIPS 204 ML-DSA-87 specification."""
        from ama_cryptography.pqc_backends import generate_dilithium87_keypair

        _pk, sk = generate_dilithium87_keypair()
        assert len(sk) == MLDSA87Spec.SECRET_KEY_BYTES

    def test_signature_size(self) -> None:
        """Signature size matches NIST FIPS 204 ML-DSA-87 specification."""
        from ama_cryptography.pqc_backends import (
            dilithium87_sign,
            generate_dilithium87_keypair,
        )

        _pk, sk = generate_dilithium87_keypair()
        sig = dilithium87_sign(b"FIPS 204 KAT test", sk)
        assert len(sig) == MLDSA87Spec.SIGNATURE_BYTES

    def test_sign_verify_roundtrip(self) -> None:
        """ML-DSA-87 sign/verify round-trip succeeds."""
        from ama_cryptography.pqc_backends import (
            dilithium87_sign,
            dilithium87_verify,
            generate_dilithium87_keypair,
        )

        pk, sk = generate_dilithium87_keypair()
        msg = b"ML-DSA-87 roundtrip test"
        sig = dilithium87_sign(msg, sk)
        assert dilithium87_verify(msg, sig, pk)

    def test_invalid_signature_fails(self) -> None:
        """Tampered ML-DSA-87 signature fails verification."""
        from ama_cryptography.pqc_backends import (
            dilithium87_sign,
            dilithium87_verify,
            generate_dilithium87_keypair,
        )

        pk, sk = generate_dilithium87_keypair()
        sig = bytearray(dilithium87_sign(b"test", sk))
        sig[0] ^= 0xFF
        assert not dilithium87_verify(b"test", bytes(sig), pk)

    def test_wrong_message_fails(self) -> None:
        """ML-DSA-87 verification with wrong message fails."""
        from ama_cryptography.pqc_backends import (
            dilithium87_sign,
            dilithium87_verify,
            generate_dilithium87_keypair,
        )

        pk, sk = generate_dilithium87_keypair()
        sig = dilithium87_sign(b"original", sk)
        assert not dilithium87_verify(b"modified", sig, pk)

    def test_wrong_pk_fails(self) -> None:
        """ML-DSA-87 verification with wrong public key fails."""
        from ama_cryptography.pqc_backends import (
            dilithium87_sign,
            dilithium87_verify,
            generate_dilithium87_keypair,
        )

        _pk1, sk1 = generate_dilithium87_keypair()
        pk2, _sk2 = generate_dilithium87_keypair()
        sig = dilithium87_sign(b"test", sk1)
        assert not dilithium87_verify(b"test", sig, pk2)

    def test_kat_vector_sizes(self) -> None:
        """Validate ML-DSA-87 KAT vector sizes match FIPS 204."""
        from tests.test_nist_kat import (
            ML_DSA_DIR,
            dilithium_kat_available,
            load_dilithium_kat_vectors,
        )

        if not dilithium_kat_available("dilithium5"):
            pytest.skip("Dilithium5 (ML-DSA-87) KAT vectors not available")
        vectors = load_dilithium_kat_vectors(ML_DSA_DIR / "dilithium5.rsp", max_vectors=5)
        assert len(vectors) > 0
        for v in vectors:
            assert len(v.pk) == MLDSA87Spec.PUBLIC_KEY_BYTES


class TestSLHDSAAllVariantsKAT:
    """NIST KAT tests for all 6 SLH-DSA parameter sets per FIPS 205."""

    SLH_VARIANTS: ClassVar[list[tuple[str, int, int, int]]] = [
        ("128s", 32, 64, 7856),
        ("128f", 32, 64, 17088),
        ("192s", 48, 96, 16224),
        ("192f", 48, 96, 35664),
        ("256s", 64, 128, 29792),
        ("256f", 64, 128, 49856),
    ]

    @pytest.fixture(autouse=True)
    def _check_sphincs(self) -> None:
        from ama_cryptography.pqc_backends import SPHINCS_AVAILABLE

        if not SPHINCS_AVAILABLE:
            pytest.skip("SPHINCS+ backend not available")

    @pytest.mark.parametrize(
        "variant,n,sk_bytes,sig_bytes",
        SLH_VARIANTS,
        ids=[v[0] for v in SLH_VARIANTS],
    )
    def test_key_sizes(self, variant: str, n: int, sk_bytes: int, sig_bytes: int) -> None:
        """All SLH-DSA variants produce correct key sizes per FIPS 205."""
        import importlib

        mod = importlib.import_module("ama_cryptography.pqc_backends")
        keygen_fn = getattr(mod, f"generate_slh_dsa_{variant}_keypair", None)
        if keygen_fn is None:
            pytest.skip(f"SLH-DSA-{variant} keygen not available")
        kp = keygen_fn()
        assert len(kp.public_key) == 2 * n, f"SLH-DSA-{variant} pk should be {2 * n} bytes"
        assert len(kp.secret_key) == 2 * 2 * n, f"SLH-DSA-{variant} sk should be {4 * n} bytes"

    @pytest.mark.parametrize(
        "variant,n,sk_bytes,sig_bytes",
        SLH_VARIANTS,
        ids=[v[0] for v in SLH_VARIANTS],
    )
    def test_sign_verify_roundtrip(
        self, variant: str, n: int, sk_bytes: int, sig_bytes: int
    ) -> None:
        """All SLH-DSA variants sign/verify round-trip succeeds."""
        import importlib

        mod = importlib.import_module("ama_cryptography.pqc_backends")
        keygen_fn = getattr(mod, f"generate_slh_dsa_{variant}_keypair", None)
        sign_fn = getattr(mod, f"slh_dsa_{variant}_sign", None)
        verify_fn = getattr(mod, f"slh_dsa_{variant}_verify", None)
        if not all([keygen_fn, sign_fn, verify_fn]):
            pytest.skip(f"SLH-DSA-{variant} not fully available")
        kp = keygen_fn()
        msg = f"FIPS 205 SLH-DSA-{variant} test".encode()
        sig = sign_fn(msg, kp.secret_key)
        assert verify_fn(msg, sig, kp.public_key)

    @pytest.mark.parametrize(
        "variant,n,sk_bytes,sig_bytes",
        SLH_VARIANTS,
        ids=[v[0] for v in SLH_VARIANTS],
    )
    def test_wrong_message_fails(self, variant: str, n: int, sk_bytes: int, sig_bytes: int) -> None:
        """All SLH-DSA variants reject wrong message."""
        import importlib

        mod = importlib.import_module("ama_cryptography.pqc_backends")
        keygen_fn = getattr(mod, f"generate_slh_dsa_{variant}_keypair", None)
        sign_fn = getattr(mod, f"slh_dsa_{variant}_sign", None)
        verify_fn = getattr(mod, f"slh_dsa_{variant}_verify", None)
        if not all([keygen_fn, sign_fn, verify_fn]):
            pytest.skip(f"SLH-DSA-{variant} not fully available")
        kp = keygen_fn()
        sig = sign_fn(b"original", kp.secret_key)
        assert not verify_fn(b"modified", sig, kp.public_key)

    def test_acvp_sigver_all_variants(self) -> None:
        """Validate all SLH-DSA parameter sets against ACVP vectors."""
        vectors_path = Path(__file__).parent / "kat" / "fips205" / "SLH-DSA-sigVer-FIPS205.json"
        if not vectors_path.exists():
            pytest.skip("ACVP SLH-DSA vectors not available")

        import importlib

        mod = importlib.import_module("ama_cryptography.pqc_backends")

        with open(vectors_path) as f:
            data = json.load(f)

        tested_variants: set[str] = set()
        for group in data["testGroups"]:
            param_set = group.get("parameterSet", "")
            if group.get("signatureInterface") != "internal":
                continue

            # Map ACVP param set name to our function names
            # e.g. "SLH-DSA-SHA2-128s" -> "128s"
            variant = param_set.replace("SLH-DSA-SHA2-", "").replace("SLH-DSA-SHAKE-", "")
            variant = variant.lower().rstrip("-simple")
            verify_fn = getattr(mod, f"slh_dsa_{variant}_verify", None)
            if verify_fn is None:
                verify_fn = getattr(mod, "sphincs_verify", None)
            if verify_fn is None:
                continue

            for tc in group["tests"][:3]:  # Test first 3 per group for speed
                pk = bytes.fromhex(tc["pk"])
                sig = bytes.fromhex(tc["signature"])
                msg = bytes.fromhex(tc["message"])
                expected = tc["testPassed"]
                result = verify_fn(msg, sig, pk)
                assert (
                    result == expected
                ), f"ACVP {param_set} tcId={tc['tcId']}: expected {expected}, got {result}"
                tested_variants.add(param_set)

        # We should have tested at least the default variant
        assert len(tested_variants) > 0, "No SLH-DSA ACVP vectors were tested"


class TestPQCInteroperability:
    """Tests for PQC algorithm interoperability and consistency."""

    def test_dilithium_kyber_independent(
        self,
        dilithium_provider: Any,
        kyber_provider: Any,
    ) -> None:
        """Dilithium and Kyber operations are independent."""
        # Generate both keypairs
        dil_keypair = dilithium_provider.generate_keypair()
        kyber_keypair = kyber_provider.generate_keypair()

        # Sign a message
        message = b"Interoperability test"
        signature = dilithium_provider.sign(message, dil_keypair.secret_key)

        # Encapsulate a secret
        ciphertext, shared_secret = kyber_provider.encapsulate(kyber_keypair.public_key)

        # Both should work independently
        assert dilithium_provider.verify(message, signature, dil_keypair.public_key)
        assert kyber_provider.decapsulate(ciphertext, kyber_keypair.secret_key) == shared_secret


# =============================================================================
# Stress Tests
# =============================================================================


class TestPQCStress:
    """Stress tests for PQC operations."""

    @pytest.mark.parametrize("iterations", [10])
    def test_dilithium_repeated_operations(self, dilithium_provider: Any, iterations: Any) -> None:
        """Repeated Dilithium operations remain consistent."""
        keypair = dilithium_provider.generate_keypair()

        for i in range(iterations):
            message = f"Iteration {i}".encode()
            signature = dilithium_provider.sign(message, keypair.secret_key)
            assert dilithium_provider.verify(message, signature, keypair.public_key)

    @pytest.mark.parametrize("iterations", [10])
    def test_kyber_repeated_operations(self, kyber_provider: Any, iterations: Any) -> None:
        """Repeated Kyber operations remain consistent."""
        keypair = kyber_provider.generate_keypair()

        for _ in range(iterations):
            ct, ss_enc = kyber_provider.encapsulate(keypair.public_key)
            ss_dec = kyber_provider.decapsulate(ct, keypair.secret_key)
            assert ss_enc == ss_dec


# =============================================================================
# NIST FIPS 205 (SLH-DSA / SPHINCS+) Constants
# =============================================================================


class SLHDSA_SHA2_256f_Spec:
    """SLH-DSA-SHA2-256f-simple parameter set per NIST FIPS 205."""

    PUBLIC_KEY_BYTES = 64
    SECRET_KEY_BYTES = 128
    SIGNATURE_BYTES = 49856
    N = 32
    H = 68
    D = 17


# =============================================================================
# SLH-DSA Test Fixtures
# =============================================================================


@pytest.fixture
def sphincs_provider() -> Any:
    """Get SPHINCS+ provider if available."""
    from ama_cryptography.pqc_backends import SPHINCS_AVAILABLE

    if not SPHINCS_AVAILABLE:
        pytest.skip("SPHINCS+ backend not available")

    from ama_cryptography.pqc_backends import (
        generate_sphincs_keypair,
        sphincs_sign,
        sphincs_verify,
    )

    class SphincsProvider:
        def generate_keypair(self) -> Any:
            return generate_sphincs_keypair()

        def sign(self, message: bytes, secret_key: bytes) -> bytes:
            return sphincs_sign(message, secret_key)

        def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
            return sphincs_verify(message, signature, public_key)

    return SphincsProvider()


# =============================================================================
# SLH-DSA (SPHINCS+) KAT Tests — NIST FIPS 205
# =============================================================================


class TestSLHDSA_SHA2_256f_KAT:
    """Known Answer Tests for SLH-DSA-SHA2-256f (SPHINCS+)."""

    def test_public_key_size(self, sphincs_provider: Any) -> None:
        """Public key size matches NIST FIPS 205 specification."""
        kp = sphincs_provider.generate_keypair()
        assert len(kp.public_key) == SLHDSA_SHA2_256f_Spec.PUBLIC_KEY_BYTES

    def test_secret_key_size(self, sphincs_provider: Any) -> None:
        """Secret key size matches NIST FIPS 205 specification."""
        kp = sphincs_provider.generate_keypair()
        assert len(kp.secret_key) == SLHDSA_SHA2_256f_Spec.SECRET_KEY_BYTES

    def test_signature_size(self, sphincs_provider: Any) -> None:
        """Signature size matches NIST FIPS 205 specification."""
        kp = sphincs_provider.generate_keypair()
        sig = sphincs_provider.sign(b"test message", kp.secret_key)
        assert len(sig) == SLHDSA_SHA2_256f_Spec.SIGNATURE_BYTES

    def test_sign_verify_roundtrip(self, sphincs_provider: Any) -> None:
        """Sign/verify roundtrip succeeds."""
        kp = sphincs_provider.generate_keypair()
        msg = b"FIPS 205 roundtrip test"
        sig = sphincs_provider.sign(msg, kp.secret_key)
        assert sphincs_provider.verify(msg, sig, kp.public_key)

    def test_invalid_signature_fails(self, sphincs_provider: Any) -> None:
        """Tampered signature fails verification."""
        kp = sphincs_provider.generate_keypair()
        msg = b"tamper test"
        sig = sphincs_provider.sign(msg, kp.secret_key)
        tampered = bytearray(sig)
        tampered[0] ^= 0xFF
        assert not sphincs_provider.verify(msg, bytes(tampered), kp.public_key)

    def test_wrong_message_fails(self, sphincs_provider: Any) -> None:
        """Verification with wrong message fails."""
        kp = sphincs_provider.generate_keypair()
        sig = sphincs_provider.sign(b"original", kp.secret_key)
        assert not sphincs_provider.verify(b"modified", sig, kp.public_key)

    def test_acvp_sigver_internal_vectors(self, sphincs_provider: Any) -> None:
        """Validate against NIST ACVP SLH-DSA-sigVer-FIPS205 internal vectors."""
        vectors_path = Path(__file__).parent / "kat" / "fips205" / "SLH-DSA-sigVer-FIPS205.json"
        if not vectors_path.exists():
            pytest.skip("ACVP SLH-DSA vectors not available")

        with open(vectors_path) as f:
            data = json.load(f)

        tested = 0
        for group in data["testGroups"]:
            if group.get("parameterSet") != "SLH-DSA-SHA2-256f":
                continue
            if group.get("signatureInterface") != "internal":
                continue

            for tc in group["tests"]:
                pk = bytes.fromhex(tc["pk"])
                sig = bytes.fromhex(tc["signature"])
                msg = bytes.fromhex(tc["message"])
                expected = tc["testPassed"]

                result = sphincs_provider.verify(msg, sig, pk)
                assert (
                    result == expected
                ), f"ACVP tcId={tc['tcId']}: expected {expected}, got {result}"
                tested += 1

        assert tested > 0, "No SLH-DSA-SHA2-256f internal vectors found"

    def test_acvp_sigver_external_pure_vectors(self, sphincs_provider: Any) -> None:
        """Validate against NIST ACVP SLH-DSA-sigVer-FIPS205 external pure vectors."""
        from ama_cryptography.pqc_backends import sphincs_verify_ctx

        vectors_path = Path(__file__).parent / "kat" / "fips205" / "SLH-DSA-sigVer-FIPS205.json"
        if not vectors_path.exists():
            pytest.skip("ACVP SLH-DSA vectors not available")

        with open(vectors_path) as f:
            data = json.load(f)

        tested = 0
        for group in data["testGroups"]:
            if group.get("parameterSet") != "SLH-DSA-SHA2-256f":
                continue
            if group.get("signatureInterface") != "external":
                continue
            if group.get("preHash") != "pure":
                continue

            for tc in group["tests"]:
                pk = bytes.fromhex(tc["pk"])
                sig = bytes.fromhex(tc["signature"])
                msg = bytes.fromhex(tc["message"])
                ctx = bytes.fromhex(tc.get("context", ""))
                expected = tc["testPassed"]

                result = sphincs_verify_ctx(msg, sig, pk, ctx)
                assert (
                    result == expected
                ), f"ACVP tcId={tc['tcId']}: expected {expected}, got {result}"
                tested += 1

        assert tested > 0, "No SLH-DSA-SHA2-256f external pure vectors found"
