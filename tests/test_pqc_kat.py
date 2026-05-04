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
from typing import Any

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

    def test_random_encaps_decaps_50_trials(self, kyber_provider: Any) -> None:
        """50 randomized encaps/decaps round-trips beyond ACVP vectors.

        Under one fixed keypair: every round-trip must produce matching
        shared secrets, each encaps must produce a distinct ciphertext
        (collision probability ≪ 2^-100), and each run must produce a
        distinct 32-byte shared secret.  Catches caching/aliasing
        regressions anywhere in the encaps path.
        """
        keypair = kyber_provider.generate_keypair()
        seen_cts: set[bytes] = set()
        seen_secrets: set[bytes] = set()
        for trial in range(50):
            ciphertext, ss_enc = kyber_provider.encapsulate(keypair.public_key)
            ss_dec = kyber_provider.decapsulate(ciphertext, keypair.secret_key)
            assert (
                ss_enc == ss_dec
            ), f"trial {trial}: encaps/decaps shared secrets diverged in kyber_cpapke_enc"
            seen_cts.add(bytes(ciphertext))
            seen_secrets.add(bytes(ss_enc))

        # 50 randomized encaps under one pk should yield 50 distinct
        # ciphertexts (collision probability ≪ 2^-100) and 50 distinct
        # 32-byte secrets.
        assert len(seen_cts) == 50, (
            f"Only {len(seen_cts)} distinct ciphertexts across 50 encaps — "
            "encapsulation randomness is degraded"
        )
        assert len(seen_secrets) == 50, (
            f"Only {len(seen_secrets)} distinct shared secrets across 50 "
            "encaps — KDF output is degenerate"
        )

    def test_random_keypair_encaps_decaps_25_trials(self, kyber_provider: Any) -> None:
        """25 fresh keypairs, each with its own encaps/decaps round-trip.

        Exercises kyber_keypair_generate (including its sample+NTT
        pipelining) against an independent seed every iteration.
        Companion to the 50-trial single-keypair test, which instead
        stresses encapsulation under a fixed key.
        """
        for trial in range(25):
            kp = kyber_provider.generate_keypair()
            ct, ss_enc = kyber_provider.encapsulate(kp.public_key)
            ss_dec = kyber_provider.decapsulate(ct, kp.secret_key)
            assert (
                ss_enc == ss_dec
            ), f"keypair-trial {trial}: round-trip mismatch in kyber_keypair_generate"


# =============================================================================
# Cross-Algorithm Tests
# =============================================================================


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


# ============================================================================
# SLH-DSA-SHAKE-128s — NIST ACVP byte-exact KAT (FIPS 205, NIST L1)
# ============================================================================


class TestSLHDSA_SHAKE_128s_ACVP:
    """Byte-exact NIST ACVP sigGen vectors for SLH-DSA-SHAKE-128s.

    Vectors live at ``tests/kat/fips205/SLH-DSA-SHAKE-128s-sigGen-FIPS205.json``;
    each entry carries everything needed to reproduce the signature
    (sk, message, context, expected signature, and for hedged vectors
    also additionalRandomness). The test asserts byte equality —
    "FIPS-aligned but doesn't pass FIPS KATs" is not a contract this
    suite is willing to ship.
    """

    VECTORS_PATH = (
        Path(__file__).parent / "kat" / "fips205" / "SLH-DSA-SHAKE-128s-sigGen-FIPS205.json"
    )

    @pytest.fixture(scope="class")
    def vectors(self) -> list[dict[str, Any]]:
        if not self.VECTORS_PATH.exists():
            pytest.skip(f"NIST ACVP SLH-DSA-SHAKE-128s vectors not present at {self.VECTORS_PATH}")
        with open(self.VECTORS_PATH) as f:
            data = json.load(f)
        vectors: list[dict[str, Any]] = data["vectors"]
        if not vectors:
            pytest.skip("No SLH-DSA-SHAKE-128s vectors in JSON")
        return vectors

    def test_size_constants(self) -> None:
        from ama_cryptography.pqc_backends import (
            SLHDSA_SHAKE_128S_PUBLIC_KEY_BYTES,
            SLHDSA_SHAKE_128S_SECRET_KEY_BYTES,
            SLHDSA_SHAKE_128S_SIGNATURE_BYTES,
        )

        assert SLHDSA_SHAKE_128S_PUBLIC_KEY_BYTES == 32
        assert SLHDSA_SHAKE_128S_SECRET_KEY_BYTES == 64
        assert SLHDSA_SHAKE_128S_SIGNATURE_BYTES == 7856

    def test_round_trip(self) -> None:
        """SHAKE-128s keygen → sign → verify holds, negatives reject."""
        from ama_cryptography.pqc_backends import (
            generate_slhdsa_keypair,
            slhdsa_sign,
            slhdsa_verify,
        )

        kp = generate_slhdsa_keypair("SHAKE-128s")
        assert len(kp.public_key) == 32 and len(kp.secret_key) == 64
        sig = slhdsa_sign(b"hello SHAKE-128s", kp.secret_key, b"")
        assert len(sig) == 7856
        assert slhdsa_verify(b"hello SHAKE-128s", sig, kp.public_key, b"")
        # wrong message
        assert not slhdsa_verify(b"different", sig, kp.public_key, b"")
        # wrong context
        assert not slhdsa_verify(b"hello SHAKE-128s", sig, kp.public_key, b"x")
        # wrong public key
        kp2 = generate_slhdsa_keypair("SHAKE-128s")
        assert not slhdsa_verify(b"hello SHAKE-128s", sig, kp2.public_key, b"")

    def test_round_trip_with_context(self) -> None:
        """SHAKE-128s sign/verify with a non-empty context (FIPS 205 §10.2)."""
        from ama_cryptography.pqc_backends import (
            generate_slhdsa_keypair,
            slhdsa_sign,
            slhdsa_verify,
        )

        kp = generate_slhdsa_keypair("SHAKE-128s")
        ctx = b"FINDOMEGAYOU/v1"
        sig = slhdsa_sign(b"hi", kp.secret_key, ctx)
        assert slhdsa_verify(b"hi", sig, kp.public_key, ctx)
        assert not slhdsa_verify(b"hi", sig, kp.public_key, b"")

    def test_ctx_too_long_rejected(self) -> None:
        from ama_cryptography.pqc_backends import generate_slhdsa_keypair, slhdsa_sign

        kp = generate_slhdsa_keypair("SHAKE-128s")
        with pytest.raises(ValueError):
            slhdsa_sign(b"x", kp.secret_key, b"\x00" * 256)

    def test_acvp_siggen_byte_exact(self, vectors: list[dict[str, Any]]) -> None:
        """All 14 NIST ACVP SHAKE-128s sigGen vectors match byte-for-byte.

        This is the contract: sign(M, sk, ctx[, addrnd]) produces exactly
        the bytes NIST published. Mercury's tcIds {214, 215, 216} are
        covered as a subset of the deterministic external/pure set.
        """
        from ama_cryptography.pqc_backends import (
            slhdsa_sign_deterministic,
            slhdsa_sign_internal,
        )

        det_count = hedged_count = 0
        for v in vectors:
            sk = bytes.fromhex(v["sk"])
            msg = bytes.fromhex(v["message"])
            ctx = bytes.fromhex(v.get("context", ""))
            expected = bytes.fromhex(v["signature"])
            assert len(expected) == 7856, f"tc{v['tcId']}: expected sig is not 7856 B"

            if v.get("deterministic"):
                produced = slhdsa_sign_deterministic(msg, sk, ctx, param_set="SHAKE-128s")
                det_count += 1
            else:
                # Hedged: NIST provides additionalRandomness; replay it via the
                # internal interface after applying the §10.2 context wrapper
                # (matching the exact M' the public sign() would build).
                addrnd = bytes.fromhex(v["additionalRandomness"])
                wrapped = b"\x00" + bytes([len(ctx)]) + ctx + msg
                produced = slhdsa_sign_internal(wrapped, sk, addrnd, param_set="SHAKE-128s")
                hedged_count += 1

            assert produced == expected, (
                f"SLH-DSA-SHAKE-128s sigGen tc{v['tcId']}: "
                "AMA signature differs from NIST reference."
            )

        # Both modes must be exercised so a regression in either path is caught.
        assert det_count >= 1, "no deterministic vectors exercised"
        assert hedged_count >= 1, "no hedged vectors exercised"

    def test_acvp_siggen_verify_round_trip(self, vectors: list[dict[str, Any]]) -> None:
        """Each NIST signature also verifies under our verifier (sanity)."""
        from ama_cryptography.pqc_backends import slhdsa_verify

        for v in vectors:
            sk = bytes.fromhex(v["sk"])
            pk = sk[32:]  # PK.seed || PK.root for n=16 (FIPS 205 §10.1)
            msg = bytes.fromhex(v["message"])
            ctx = bytes.fromhex(v.get("context", ""))
            sig = bytes.fromhex(v["signature"])
            assert slhdsa_verify(
                msg, sig, pk, ctx, param_set="SHAKE-128s"
            ), f"NIST sig tc{v['tcId']} did not verify under AMA verifier"
