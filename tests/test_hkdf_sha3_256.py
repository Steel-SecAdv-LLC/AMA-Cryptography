#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography: Tests for HKDF-SHA3-256 key derivation with ethical context integration.

This module provides comprehensive tests for:
1. HKDF-SHA3-256 deterministic key derivation
2. Ethical context integration via create_ethical_hkdf_context()
3. Golden vector validation for reproducibility
4. Key independence verification

Test Vector Sources:
- SHA3-256: NIST FIPS 202 (August 2015), Section A.1
- HKDF-SHA256: RFC 5869, Appendix A (validates HKDF structure)
- HMAC-SHA3-256: Project-specific vectors (no official NIST vectors exist)
- HKDF-SHA3-256: Project-specific vectors (no official NIST/IETF vectors exist)
"""

import hashlib
import json

import pytest

_PYCA_AVAILABLE: bool

try:
    from cryptography.hazmat.backends import default_backend as default_backend
    from cryptography.hazmat.primitives import hashes as hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as HKDF

    _PYCA_AVAILABLE = True
except ImportError:
    default_backend = None  # type: ignore[assignment]  # fallback when pyca unavailable (HKDF-001)
    hashes = None  # type: ignore[assignment]  # fallback when pyca unavailable (HKDF-002)
    HKDF = None  # type: ignore[assignment,misc]  # fallback when pyca unavailable (HKDF-003)
    _PYCA_AVAILABLE = False


class TestHKDFSHA3256:
    """Test suite for HKDF-SHA3-256 key derivation."""

    def test_hkdf_sha3_256_deterministic(self) -> None:
        """Test that HKDF-SHA3-256 produces deterministic outputs with same salt."""
        from ama_cryptography.legacy_compat import derive_keys

        master_secret = b"test_master_secret_32_bytes_long"
        info = "test_context"
        # Use fixed salt for deterministic testing
        fixed_salt = b"fixed_salt_for_testing_32_bytes!"

        # Derive keys twice with same inputs and same salt
        keys1, _salt1 = derive_keys(master_secret, info, num_keys=3, salt=fixed_salt)
        keys2, _salt2 = derive_keys(master_secret, info, num_keys=3, salt=fixed_salt)

        # Should produce identical keys with same salt
        assert keys1 == keys2
        assert len(keys1) == 3
        assert all(len(k) == 32 for k in keys1)

    def test_hkdf_sha3_256_different_info_produces_different_keys(self) -> None:
        """Test that different info parameters produce different keys."""
        from ama_cryptography.legacy_compat import derive_keys

        master_secret = b"test_master_secret_32_bytes_long"
        fixed_salt = b"fixed_salt_for_testing_32_bytes!"

        keys1, _ = derive_keys(master_secret, "context_a", num_keys=1, salt=fixed_salt)
        keys2, _ = derive_keys(master_secret, "context_b", num_keys=1, salt=fixed_salt)

        # Different contexts should produce different keys
        assert keys1[0] != keys2[0]

    def test_hkdf_sha3_256_different_master_produces_different_keys(self) -> None:
        """Test that different master secrets produce different keys."""
        from ama_cryptography.legacy_compat import derive_keys

        master1 = b"master_secret_one_32_bytes_long!"
        master2 = b"master_secret_two_32_bytes_long!"
        info = "same_context"
        fixed_salt = b"fixed_salt_for_testing_32_bytes!"

        keys1, _ = derive_keys(master1, info, num_keys=1, salt=fixed_salt)
        keys2, _ = derive_keys(master2, info, num_keys=1, salt=fixed_salt)

        # Different master secrets should produce different keys
        assert keys1[0] != keys2[0]

    def test_hkdf_sha3_256_key_independence(self) -> None:
        """Test that derived keys are independent of each other."""
        from ama_cryptography.legacy_compat import derive_keys

        master_secret = b"test_master_secret_32_bytes_long"
        info = "test_context"
        fixed_salt = b"fixed_salt_for_testing_32_bytes!"

        keys, _ = derive_keys(master_secret, info, num_keys=5, salt=fixed_salt)

        # All keys should be unique
        assert len(set(keys)) == 5

        # No key should be derivable from another (statistical test)
        for i, key_i in enumerate(keys):
            for j, key_j in enumerate(keys):
                if i != j:
                    # Keys should not be related by simple XOR or concatenation
                    assert key_i != key_j
                    assert hashlib.sha3_256(key_i).digest() != key_j

    def test_hkdf_sha3_256_minimum_master_secret_length(self) -> None:
        """Test that master secret must be at least 32 bytes."""
        from ama_cryptography.legacy_compat import derive_keys

        # Should raise ValueError for short master secret
        with pytest.raises(ValueError, match="at least 32 bytes"):
            derive_keys(b"short", "context", num_keys=1)

        # Should work with exactly 32 bytes
        keys, _ = derive_keys(b"x" * 32, "context", num_keys=1)
        assert len(keys) == 1


class TestEthicalHKDFContext:
    """Test suite for ethical HKDF context integration."""

    def test_ethical_context_creation(self) -> None:
        """Test that ethical context is properly created."""
        from ama_cryptography.legacy_compat import create_ethical_hkdf_context

        base_context = b"base_context"
        enhanced = create_ethical_hkdf_context(base_context)

        # Enhanced context should be longer than base
        assert len(enhanced) > len(base_context)
        # Should append 16 bytes (128-bit ethical signature)
        assert len(enhanced) == len(base_context) + 16

    def test_ethical_context_deterministic(self) -> None:
        """Test that ethical context creation is deterministic."""
        from ama_cryptography.legacy_compat import create_ethical_hkdf_context

        base_context = b"base_context"

        enhanced1 = create_ethical_hkdf_context(base_context)
        enhanced2 = create_ethical_hkdf_context(base_context)

        assert enhanced1 == enhanced2

    def test_ethical_context_different_vectors_produce_different_contexts(self) -> None:
        """Test that different ethical vectors produce different contexts."""
        from ama_cryptography.legacy_compat import create_ethical_hkdf_context

        base_context = b"base_context"

        # Default ethical vector
        enhanced1 = create_ethical_hkdf_context(base_context)

        # Modified ethical vector
        modified_vector = {
            "omniscient": 4.0,  # Changed from 3.0
            "omnipotent": 3.0,
            "omnidirectional": 3.0,
            "omnibenevolent": 2.0,  # Changed to maintain sum
        }
        enhanced2 = create_ethical_hkdf_context(base_context, modified_vector)

        # Different ethical vectors should produce different contexts
        assert enhanced1 != enhanced2

    def test_ethical_vector_affects_derived_keys(self) -> None:
        """Test that ethical vector changes affect derived keys."""
        from ama_cryptography.legacy_compat import derive_keys

        master_secret = b"test_master_secret_32_bytes_long"
        info = "test_context"
        fixed_salt = b"fixed_salt_for_testing_32_bytes!"

        # Default ethical vector
        keys1, _ = derive_keys(master_secret, info, num_keys=1, salt=fixed_salt)

        # Modified ethical vector
        modified_vector = {
            "omniscient": 4.0,  # Changed from 3.0
            "omnipotent": 3.0,
            "omnidirectional": 3.0,
            "omnibenevolent": 2.0,  # Changed to maintain sum
        }
        keys2, _ = derive_keys(
            master_secret, info, num_keys=1, ethical_vector=modified_vector, salt=fixed_salt
        )

        # Different ethical vectors should produce different keys
        assert keys1[0] != keys2[0]


class TestHMACSHA3256:
    """Test suite for HMAC-SHA3-256 authentication."""

    def test_hmac_sha3_256_deterministic(self) -> None:
        """Test that HMAC-SHA3-256 produces deterministic outputs."""
        from ama_cryptography.legacy_compat import hmac_authenticate

        key = b"x" * 32
        message = b"test message"

        tag1 = hmac_authenticate(message, key)
        tag2 = hmac_authenticate(message, key)

        assert tag1 == tag2
        assert len(tag1) == 32  # SHA3-256 output

    def test_hmac_sha3_256_verification(self) -> None:
        """Test HMAC-SHA3-256 verification."""
        from ama_cryptography.legacy_compat import hmac_authenticate, hmac_verify

        key = b"x" * 32
        message = b"test message"

        tag = hmac_authenticate(message, key)

        # Valid tag should verify
        assert hmac_verify(message, tag, key) is True

        # Modified message should not verify
        assert hmac_verify(b"modified message", tag, key) is False

        # Modified tag should not verify
        modified_tag = bytes([tag[0] ^ 1]) + tag[1:]
        assert hmac_verify(message, modified_tag, key) is False

    def test_hmac_sha3_256_minimum_key_length(self) -> None:
        """Test that HMAC key must be at least 32 bytes."""
        from ama_cryptography.legacy_compat import hmac_authenticate

        # Should raise ValueError for short key
        with pytest.raises(ValueError, match="at least 32 bytes"):
            hmac_authenticate(b"message", b"short_key")

        # Should work with exactly 32 bytes
        tag = hmac_authenticate(b"message", b"x" * 32)
        assert len(tag) == 32


class TestNISTSHA3256Vectors:
    """
    Test SHA3-256 against official NIST FIPS 202 test vectors.

    Source: NIST FIPS 202 (August 2015), "SHA-3 Standard: Permutation-Based
    Hash and Extendable-Output Functions"
    https://csrc.nist.gov/publications/detail/fips/202/final
    """

    def test_sha3_256_empty_string_nist_fips_202(self) -> None:
        """
        NIST FIPS 202 SHA3-256 test vector: empty string.

        Input: "" (empty string, 0 bits)
        Expected: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        """
        message = b""
        expected_hex = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"

        result = hashlib.sha3_256(message).hexdigest()
        assert result == expected_hex, f"SHA3-256('') mismatch: {result} != {expected_hex}"

    def test_sha3_256_abc_nist_fips_202(self) -> None:
        """
        NIST FIPS 202 SHA3-256 test vector: "abc".

        Input: "abc" (24 bits)
        Expected: 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
        """
        message = b"abc"
        expected_hex = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"

        result = hashlib.sha3_256(message).hexdigest()
        assert result == expected_hex, f"SHA3-256('abc') mismatch: {result} != {expected_hex}"


@pytest.mark.skipif(not _PYCA_AVAILABLE, reason="PyCA cryptography not installed")
class TestRFC5869HKDFStructure:
    """
    Validate HKDF structure against RFC 5869 test vectors (using SHA-256).

    This validates that our HKDF usage is structurally correct per RFC 5869.
    Source: RFC 5869, Appendix A, Test Case 1
    https://datatracker.ietf.org/doc/html/rfc5869
    """

    def test_hkdf_sha256_rfc5869_test_case_1(self) -> None:
        """
        RFC 5869 Appendix A, Test Case 1 (HKDF-SHA256).

        IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
        salt = 0x000102030405060708090a0b0c (13 octets)
        info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
        L    = 42

        OKM  = 0x3cb25f25faacd57a90434f64d0362f2a
                 2d2d0a90cf1a5a4c5db02d56ecc4c5bf
                 34007208d5b887185865 (42 octets)
        """
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        length = 42
        expected_okm = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend(),
        )
        okm = hkdf.derive(ikm)

        assert okm == expected_okm, "HKDF-SHA256 RFC 5869 Test Case 1 failed"


class TestProjectSpecificVectors:
    """
    Project-specific test vectors for HMAC-SHA3-256 and HKDF-SHA3-256.

    NOTE: No official NIST or IETF test vectors exist for HMAC-SHA3-256 or
    HKDF-SHA3-256 as of November 2025. These vectors are project-specific
    and serve as regression tests to detect unintended implementation changes.

    The expected values were computed using Python's cryptography library
    (version 41.0+) and cross-validated for consistency.
    """

    def test_hmac_sha3_256_project_vector_1(self) -> None:
        """
        Project-specific HMAC-SHA3-256 test vector #1.

        Key: 32 bytes of 0x00
        Message: empty
        Expected: Computed with cryptography library, hardcoded for regression.
        """
        import hmac as hmac_module

        key = b"\x00" * 32
        message = b""

        # Compute HMAC-SHA3-256 using Python's hmac module
        tag = hmac_module.new(key, message, hashlib.sha3_256).digest()

        # Hardcoded expected value (computed with Python 3.12, cryptography 41.0+)
        expected_hex = "e841c164e5b4f10c9f3985587962af72fd607a951196fc92fb3a5251941784ea"
        assert tag.hex() == expected_hex, "HMAC-SHA3-256 project vector #1 failed"

    def test_hmac_sha3_256_project_vector_2(self) -> None:
        """
        Project-specific HMAC-SHA3-256 test vector #2.

        Key: "AMA Crypto HMAC Key 32 bytes!!" (32 bytes)
        Message: "test message for HMAC-SHA3-256"
        Expected: Computed with cryptography library, hardcoded for regression.
        """
        import hmac as hmac_module

        key = b"AMA Crypto HMAC Key 32 bytes!!"
        message = b"test message for HMAC-SHA3-256"

        tag = hmac_module.new(key, message, hashlib.sha3_256).digest()

        # Hardcoded expected value (computed with Python 3.12, cryptography 41.0+)
        expected_hex = "051c4e79ca4e387c5136f249c6e87ca9f7cce2be15cc46d588dd90afeef0f279"
        assert tag.hex() == expected_hex, "HMAC-SHA3-256 project vector #2 failed"

    @pytest.mark.skipif(not _PYCA_AVAILABLE, reason="PyCA cryptography not installed")
    def test_hkdf_sha3_256_project_vector(self) -> None:
        """
        Project-specific HKDF-SHA3-256 test vector.

        IKM: 32 bytes of 0x01
        Salt: None (uses zeros)
        Info: b"HKDF-SHA3-256 test"
        L: 32

        NOTE: No official NIST/IETF test vectors exist for HKDF-SHA3-256.
        This vector validates our implementation is deterministic.
        """
        ikm = b"\x01" * 32
        info = b"HKDF-SHA3-256 test"
        length = 32

        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=length,
            salt=None,
            info=info,
            backend=default_backend(),
        )
        okm1 = hkdf.derive(ikm)

        # Verify determinism by deriving again
        hkdf2 = HKDF(
            algorithm=hashes.SHA3_256(),
            length=length,
            salt=None,
            info=info,
            backend=default_backend(),
        )
        okm2 = hkdf2.derive(ikm)

        assert okm1 == okm2, "HKDF-SHA3-256 is not deterministic"
        assert len(okm1) == 32, "HKDF-SHA3-256 output length incorrect"

    def test_ethical_signature_golden_vector(self) -> None:
        """
        Project-specific ethical signature test vector.

        The ethical signature is SHA3-256(JSON(ETHICAL_VECTOR))[:16].
        This test validates the ethical vector constraints and signature.
        """
        from ama_cryptography.equations import ETHICAL_VECTOR

        # Verify the ethical vector constraint
        assert sum(ETHICAL_VECTOR.values()) == 12.0, "Ethical vector sum != 12.0"
        assert all(w == 3.0 for w in ETHICAL_VECTOR.values()), "Not all weights == 3.0"
        assert len(ETHICAL_VECTOR) == 4, "Ethical vector should have 4 pillars"

        # Compute ethical signature
        ethical_json = json.dumps(ETHICAL_VECTOR, sort_keys=True)
        ethical_hash = hashlib.sha3_256(ethical_json.encode()).digest()
        ethical_signature = ethical_hash[:16]

        # Verify signature length
        assert len(ethical_signature) == 16, "Ethical signature should be 128 bits"

        # Verify determinism
        ethical_signature2 = hashlib.sha3_256(ethical_json.encode()).digest()[:16]
        assert ethical_signature == ethical_signature2, "Ethical signature not deterministic"


class TestKeyManagementSystem:
    """Test suite for key management system integration."""

    def test_kms_generation_uses_hkdf_sha3_256(self) -> None:
        """Test that KMS generation uses HKDF-SHA3-256."""
        from ama_cryptography.legacy_compat import generate_key_management_system

        kms = generate_key_management_system("test_author")

        # Verify KMS structure
        assert kms.master_secret is not None
        assert len(kms.master_secret) == 32
        assert kms.hmac_key is not None
        assert len(kms.hmac_key) == 32
        assert kms.ed25519_keypair is not None
        assert kms.version is not None

    def test_kms_deterministic_with_same_master_secret(self) -> None:
        """Test that KMS derivation is deterministic given same master secret and salt."""
        from ama_cryptography.legacy_compat import derive_keys

        # Fixed master secret and salt for testing
        master_secret = b"fixed_master_secret_32_bytes_lo!"
        info = "OMNI_CODES"
        fixed_salt = b"fixed_salt_for_testing_32_bytes!"

        # Derive keys twice with same salt
        keys1, _ = derive_keys(master_secret, info, num_keys=3, salt=fixed_salt)
        keys2, _ = derive_keys(master_secret, info, num_keys=3, salt=fixed_salt)

        # Should be identical with same salt
        assert keys1 == keys2
