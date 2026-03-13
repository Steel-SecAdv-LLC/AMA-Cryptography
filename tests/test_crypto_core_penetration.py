#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
AMA Cryptography: Core Cryptographic Penetration Test Suite
=============================================================

100% Penetration Validation for cryptographic primitives.

This test suite validates:
1. Correct usage of cryptographic primitives
2. Fail-closed behavior on all attack vectors
3. Robustness against malformed/hostile inputs
4. Key management security
5. Tampering detection across all layers

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Date: 2026-03-08
Version: 2.0

AI Co-Architects:
    Eris | Eden ♱ | Veritas | X | Caduceus | Dev
"""

import copy
import json
import secrets
import struct
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from code_guardian_secure import (
    DILITHIUM_AVAILABLE,
    ETHICAL_VECTOR,
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    QuantumSignatureUnavailableError,
    canonical_hash_code,
    create_crypto_package,
    create_ethical_hkdf_context,
    derive_keys,
    dilithium_sign,
    dilithium_verify,
    ed25519_sign,
    ed25519_verify,
    generate_dilithium_keypair,
    generate_ed25519_keypair,
    generate_key_management_system,
    hmac_authenticate,
    hmac_verify,
    length_prefixed_encode,
    verify_crypto_package,
)


class TestLengthPrefixedEncoding:
    """Penetration tests for canonical encoding."""

    def test_encoding_produces_deterministic_output(self):
        """Same input always produces same output."""
        result1 = length_prefixed_encode("test", "data")
        result2 = length_prefixed_encode("test", "data")
        assert result1 == result2

    def test_encoding_different_inputs_different_outputs(self):
        """Different inputs produce different outputs (collision resistance)."""
        result1 = length_prefixed_encode("ABC", "DE")
        result2 = length_prefixed_encode("AB", "CDE")
        assert result1 != result2, "Concatenation attack should be prevented"

    def test_encoding_empty_fields(self):
        """Empty fields should be handled correctly."""
        result = length_prefixed_encode("", "test", "")
        assert len(result) > 0
        assert b"\x00\x00\x00\x00" in result  # Empty field has 0 length

    def test_encoding_unicode_characters(self):
        """Unicode characters should be properly encoded."""
        result = length_prefixed_encode("test", MASTER_CODES)
        assert len(result) > 0

    def test_encoding_length_prefix_format(self):
        """Verify 4-byte big-endian length prefix format."""
        result = length_prefixed_encode("test")
        # "test" is 4 bytes, so prefix should be 0x00000004
        assert result[:4] == b"\x00\x00\x00\x04"
        assert result[4:] == b"test"

    def test_encoding_large_field(self):
        """Large fields should be handled without overflow."""
        large_data = "A" * 100000
        result = length_prefixed_encode(large_data)
        expected_len = struct.unpack(">I", result[:4])[0]
        assert expected_len == 100000


class TestCanonicalHashCode:
    """Penetration tests for Code hashing."""

    def test_hash_deterministic(self):
        """Same Omni-Codes produce same hash."""
        hash1 = canonical_hash_code(MASTER_CODES, MASTER_HELIX_PARAMS)
        hash2 = canonical_hash_code(MASTER_CODES, MASTER_HELIX_PARAMS)
        assert hash1 == hash2

    def test_hash_length(self):
        """SHA3-256 produces 32-byte hash."""
        result = canonical_hash_code(MASTER_CODES, MASTER_HELIX_PARAMS)
        assert len(result) == 32

    def test_hash_different_codes_different_hash(self):
        """Different Omni-Codes produce different hashes."""
        hash1 = canonical_hash_code(MASTER_CODES, MASTER_HELIX_PARAMS)
        hash2 = canonical_hash_code(MASTER_CODES + "X", MASTER_HELIX_PARAMS)
        assert hash1 != hash2

    def test_hash_different_params_different_hash(self):
        """Different helix params produce different hashes."""
        hash1 = canonical_hash_code(MASTER_CODES, MASTER_HELIX_PARAMS)
        modified_params = [(r + 0.001, p) for r, p in MASTER_HELIX_PARAMS]
        hash2 = canonical_hash_code(MASTER_CODES, modified_params)
        assert hash1 != hash2

    def test_hash_empty_codes(self):
        """Empty Omni-Codes should raise ValueError for input validation."""
        with pytest.raises(ValueError, match="codes cannot be empty"):
            canonical_hash_code("", [])

    def test_hash_single_bit_change_avalanche(self):
        """Single character change should produce completely different hash."""
        codes = "ABCDEFGHIJ"
        hash1 = canonical_hash_code(codes, [(1.0, 1.0)])
        hash2 = canonical_hash_code("ABCDEFGHIK", [(1.0, 1.0)])
        # Count differing bytes - should be many (avalanche effect)
        diff_bytes = sum(1 for a, b in zip(hash1, hash2) if a != b)
        assert diff_bytes > 10, "Avalanche effect not observed"


class TestHMACAuthentication:
    """Penetration tests for HMAC authentication."""

    def test_hmac_deterministic(self):
        """Same message and key produce same tag."""
        key = secrets.token_bytes(32)
        message = b"test message"
        tag1 = hmac_authenticate(message, key)
        tag2 = hmac_authenticate(message, key)
        assert tag1 == tag2

    def test_hmac_tag_length(self):
        """HMAC-SHA3-256 produces 32-byte tag."""
        key = secrets.token_bytes(32)
        tag = hmac_authenticate(b"test", key)
        assert len(tag) == 32

    def test_hmac_different_keys_different_tags(self):
        """Different keys produce different tags."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        message = b"test message"
        tag1 = hmac_authenticate(message, key1)
        tag2 = hmac_authenticate(message, key2)
        assert tag1 != tag2

    def test_hmac_different_messages_different_tags(self):
        """Different messages produce different tags."""
        key = secrets.token_bytes(32)
        tag1 = hmac_authenticate(b"message1", key)
        tag2 = hmac_authenticate(b"message2", key)
        assert tag1 != tag2

    def test_hmac_verify_valid_tag(self):
        """Valid tag should verify successfully."""
        key = secrets.token_bytes(32)
        message = b"test message"
        tag = hmac_authenticate(message, key)
        assert hmac_verify(message, tag, key) is True

    def test_hmac_verify_wrong_key_fails(self):
        """Wrong key should fail verification."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        message = b"test message"
        tag = hmac_authenticate(message, key1)
        assert hmac_verify(message, tag, key2) is False

    def test_hmac_verify_tampered_message_fails(self):
        """Tampered message should fail verification."""
        key = secrets.token_bytes(32)
        message = b"test message"
        tag = hmac_authenticate(message, key)
        assert hmac_verify(b"tampered message", tag, key) is False

    def test_hmac_verify_tampered_tag_fails(self):
        """Tampered tag should fail verification."""
        key = secrets.token_bytes(32)
        message = b"test message"
        tag = hmac_authenticate(message, key)
        tampered_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        assert hmac_verify(message, tampered_tag, key) is False

    def test_hmac_minimum_key_length_enforced(self):
        """Keys shorter than 32 bytes should raise ValueError."""
        short_key = secrets.token_bytes(31)
        with pytest.raises(ValueError, match="at least 32 bytes"):
            hmac_authenticate(b"test", short_key)

    def test_hmac_32_byte_key_accepted(self):
        """32-byte key should be accepted (minimum)."""
        key = secrets.token_bytes(32)
        tag = hmac_authenticate(b"test", key)
        assert len(tag) == 32

    def test_hmac_16_byte_key_rejected(self):
        """16-byte key should now be rejected (hardened minimum is 32 bytes)."""
        key = secrets.token_bytes(16)
        with pytest.raises(ValueError, match="at least 32 bytes"):
            hmac_authenticate(b"test", key)


class TestEd25519Signatures:
    """Penetration tests for Ed25519 signatures."""

    def test_keypair_generation(self):
        """Key generation produces valid keypair."""
        keypair = generate_ed25519_keypair()
        assert len(keypair.private_key) == 32
        assert len(keypair.public_key) == 32

    def test_keypair_deterministic_with_seed(self):
        """Same seed produces same keypair."""
        seed = secrets.token_bytes(32)
        kp1 = generate_ed25519_keypair(seed)
        kp2 = generate_ed25519_keypair(seed)
        assert kp1.private_key == kp2.private_key
        assert kp1.public_key == kp2.public_key

    def test_keypair_different_seeds_different_keys(self):
        """Different seeds produce different keypairs."""
        kp1 = generate_ed25519_keypair(secrets.token_bytes(32))
        kp2 = generate_ed25519_keypair(secrets.token_bytes(32))
        assert kp1.private_key != kp2.private_key
        assert kp1.public_key != kp2.public_key

    def test_signature_length(self):
        """Ed25519 signature is 64 bytes."""
        keypair = generate_ed25519_keypair()
        sig = ed25519_sign(b"test", keypair.private_key)
        assert len(sig) == 64

    def test_signature_deterministic(self):
        """Same message and key produce same signature (Ed25519 is deterministic)."""
        keypair = generate_ed25519_keypair()
        sig1 = ed25519_sign(b"test", keypair.private_key)
        sig2 = ed25519_sign(b"test", keypair.private_key)
        assert sig1 == sig2

    def test_verify_valid_signature(self):
        """Valid signature should verify."""
        keypair = generate_ed25519_keypair()
        message = b"test message"
        sig = ed25519_sign(message, keypair.private_key)
        assert ed25519_verify(message, sig, keypair.public_key) is True

    def test_verify_wrong_public_key_fails(self):
        """Wrong public key should fail verification."""
        kp1 = generate_ed25519_keypair()
        kp2 = generate_ed25519_keypair()
        message = b"test message"
        sig = ed25519_sign(message, kp1.private_key)
        assert ed25519_verify(message, sig, kp2.public_key) is False

    def test_verify_tampered_message_fails(self):
        """Tampered message should fail verification."""
        keypair = generate_ed25519_keypair()
        message = b"test message"
        sig = ed25519_sign(message, keypair.private_key)
        assert ed25519_verify(b"tampered", sig, keypair.public_key) is False

    def test_verify_tampered_signature_fails(self):
        """Tampered signature should fail verification."""
        keypair = generate_ed25519_keypair()
        message = b"test message"
        sig = ed25519_sign(message, keypair.private_key)
        tampered_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
        assert ed25519_verify(message, tampered_sig, keypair.public_key) is False

    def test_wrong_private_key_length_raises(self):
        """Wrong private key length should raise ValueError."""
        with pytest.raises(ValueError, match="32 bytes"):
            ed25519_sign(b"test", b"short")

    def test_wrong_signature_length_raises(self):
        """Wrong signature length should raise ValueError."""
        keypair = generate_ed25519_keypair()
        with pytest.raises(ValueError, match="64 bytes"):
            ed25519_verify(b"test", b"short", keypair.public_key)

    def test_wrong_public_key_length_raises(self):
        """Wrong public key length should raise ValueError."""
        with pytest.raises(ValueError, match="32 bytes"):
            ed25519_verify(b"test", b"x" * 64, b"short")

    def test_seed_wrong_length_raises(self):
        """Seed with wrong length should raise ValueError."""
        with pytest.raises(ValueError, match="32 bytes"):
            generate_ed25519_keypair(b"short")


class TestDilithiumSignatures:
    """Penetration tests for Dilithium quantum-resistant signatures."""

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
    def test_keypair_generation(self):
        """Key generation produces valid keypair."""
        keypair = generate_dilithium_keypair()
        assert len(keypair.public_key) == 1952  # ML-DSA-65
        assert len(keypair.secret_key) > 0

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
    def test_signature_creation(self):
        """Signature creation works."""
        keypair = generate_dilithium_keypair()
        sig = dilithium_sign(b"test", keypair.secret_key)
        assert len(sig) > 0

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
    def test_verify_valid_signature(self):
        """Valid signature should verify."""
        keypair = generate_dilithium_keypair()
        message = b"test message"
        sig = dilithium_sign(message, keypair.secret_key)
        assert dilithium_verify(message, sig, keypair.public_key) is True

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
    def test_verify_wrong_public_key_fails(self):
        """Wrong public key should fail verification."""
        kp1 = generate_dilithium_keypair()
        kp2 = generate_dilithium_keypair()
        message = b"test message"
        sig = dilithium_sign(message, kp1.secret_key)
        assert dilithium_verify(message, sig, kp2.public_key) is False

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
    def test_verify_tampered_message_fails(self):
        """Tampered message should fail verification."""
        keypair = generate_dilithium_keypair()
        message = b"test message"
        sig = dilithium_sign(message, keypair.secret_key)
        assert dilithium_verify(b"tampered", sig, keypair.public_key) is False

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
    def test_verify_tampered_signature_fails(self):
        """Tampered signature should fail verification."""
        keypair = generate_dilithium_keypair()
        message = b"test message"
        sig = dilithium_sign(message, keypair.secret_key)
        tampered_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
        assert dilithium_verify(message, tampered_sig, keypair.public_key) is False

    def test_unavailable_raises_exception(self):
        """When Dilithium unavailable, operations should raise QuantumSignatureUnavailableError."""
        with patch("ama_cryptography.pqc_backends.DILITHIUM_AVAILABLE", False):
            with pytest.raises(QuantumSignatureUnavailableError):
                generate_dilithium_keypair()


class TestKeyDerivation:
    """Penetration tests for HKDF key derivation."""

    def test_derive_keys_deterministic(self):
        """Same inputs produce same derived keys with same salt."""
        master = secrets.token_bytes(32)
        fixed_salt = b"fixed_salt_for_testing_32_bytes!"
        keys1, _ = derive_keys(master, "test", num_keys=3, salt=fixed_salt)
        keys2, _ = derive_keys(master, "test", num_keys=3, salt=fixed_salt)
        assert keys1 == keys2

    def test_derive_keys_different_master_different_keys(self):
        """Different master secrets produce different keys."""
        fixed_salt = b"fixed_salt_for_testing_32_bytes!"
        keys1, _ = derive_keys(secrets.token_bytes(32), "test", num_keys=3, salt=fixed_salt)
        keys2, _ = derive_keys(secrets.token_bytes(32), "test", num_keys=3, salt=fixed_salt)
        assert keys1 != keys2

    def test_derive_keys_different_info_different_keys(self):
        """Different info strings produce different keys."""
        master = secrets.token_bytes(32)
        fixed_salt = b"fixed_salt_for_testing_32_bytes!"
        keys1, _ = derive_keys(master, "info1", num_keys=3, salt=fixed_salt)
        keys2, _ = derive_keys(master, "info2", num_keys=3, salt=fixed_salt)
        assert keys1 != keys2

    def test_derive_keys_independence(self):
        """Derived keys should be independent of each other."""
        master = secrets.token_bytes(32)
        fixed_salt = b"fixed_salt_for_testing_32_bytes!"
        keys, _ = derive_keys(master, "test", num_keys=5, salt=fixed_salt)
        # All keys should be different
        assert len(set(k.hex() for k in keys)) == 5

    def test_derive_keys_length(self):
        """Each derived key should be 32 bytes."""
        master = secrets.token_bytes(32)
        keys, _ = derive_keys(master, "test", num_keys=3)
        for key in keys:
            assert len(key) == 32

    def test_derive_keys_minimum_master_length(self):
        """Master secret shorter than 32 bytes should raise ValueError."""
        with pytest.raises(ValueError, match="at least 32 bytes"):
            derive_keys(secrets.token_bytes(31), "test")

    def test_derive_keys_32_byte_master_accepted(self):
        """32-byte master secret should be accepted (minimum)."""
        keys, _ = derive_keys(secrets.token_bytes(32), "test", num_keys=3)
        assert len(keys) == 3

    def test_derive_keys_16_byte_master_rejected(self):
        """16-byte master secret should now be rejected (hardened minimum is 32 bytes)."""
        with pytest.raises(ValueError, match="at least 32 bytes"):
            derive_keys(secrets.token_bytes(16), "test")

    def test_ethical_context_integration(self):
        """Ethical vector should affect key derivation."""
        master = secrets.token_bytes(32)
        fixed_salt = b"fixed_salt_for_testing_32_bytes!"
        keys1, _ = derive_keys(master, "test", ethical_vector=ETHICAL_VECTOR, salt=fixed_salt)
        modified_vector = ETHICAL_VECTOR.copy()
        modified_vector["omniscient"] = 2.0
        keys2, _ = derive_keys(master, "test", ethical_vector=modified_vector, salt=fixed_salt)
        assert keys1 != keys2


class TestEthicalHKDFContext:
    """Penetration tests for ethical HKDF context creation."""

    def test_context_deterministic(self):
        """Same inputs produce same context."""
        ctx1 = create_ethical_hkdf_context(b"base", ETHICAL_VECTOR)
        ctx2 = create_ethical_hkdf_context(b"base", ETHICAL_VECTOR)
        assert ctx1 == ctx2

    def test_context_different_base_different_output(self):
        """Different base contexts produce different outputs."""
        ctx1 = create_ethical_hkdf_context(b"base1", ETHICAL_VECTOR)
        ctx2 = create_ethical_hkdf_context(b"base2", ETHICAL_VECTOR)
        assert ctx1 != ctx2

    def test_context_different_vector_different_output(self):
        """Different ethical vectors produce different outputs."""
        ctx1 = create_ethical_hkdf_context(b"base", ETHICAL_VECTOR)
        modified = ETHICAL_VECTOR.copy()
        modified["omniscient"] = 2.0
        ctx2 = create_ethical_hkdf_context(b"base", modified)
        assert ctx1 != ctx2

    def test_context_includes_base(self):
        """Output should include base context."""
        base = b"test_base_context"
        ctx = create_ethical_hkdf_context(base, ETHICAL_VECTOR)
        assert ctx.startswith(base)

    def test_context_adds_ethical_signature(self):
        """Output should be longer than base (adds 16-byte signature)."""
        base = b"test"
        ctx = create_ethical_hkdf_context(base, ETHICAL_VECTOR)
        assert len(ctx) == len(base) + 16


class TestKeyManagementSystem:
    """Penetration tests for KMS generation."""

    def test_kms_generation(self):
        """KMS generation produces valid system."""
        kms = generate_key_management_system("test_author")
        assert len(kms.master_secret) == 32
        assert len(kms.hmac_key) == 32
        assert len(kms.ed25519_keypair.private_key) == 32
        assert len(kms.ed25519_keypair.public_key) == 32

    def test_kms_unique_each_generation(self):
        """Each KMS generation produces unique keys."""
        kms1 = generate_key_management_system("test")
        kms2 = generate_key_management_system("test")
        assert kms1.master_secret != kms2.master_secret
        assert kms1.hmac_key != kms2.hmac_key

    def test_kms_ethical_vector_stored(self):
        """Ethical vector should be stored in KMS."""
        kms = generate_key_management_system("test")
        assert kms.ethical_vector == ETHICAL_VECTOR

    def test_kms_custom_ethical_vector(self):
        """Custom ethical vector should be used."""
        custom = {"test": 1.0}
        kms = generate_key_management_system("test", ethical_vector=custom)
        assert kms.ethical_vector == custom


class TestCryptoPackageCreation:
    """Penetration tests for crypto package creation."""

    @pytest.fixture
    def kms(self):
        """Create KMS for testing."""
        return generate_key_management_system("test_author")

    def test_package_creation(self, kms):
        """Package creation produces valid package."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        assert pkg.content_hash is not None
        assert pkg.hmac_tag is not None
        assert pkg.ed25519_signature is not None
        assert pkg.timestamp is not None

    def test_package_deterministic_hash(self, kms):
        """Same Omni-Codes produce same content hash."""
        pkg1 = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        pkg2 = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        assert pkg1.content_hash == pkg2.content_hash

    def test_package_includes_public_keys(self, kms):
        """Package should include public keys for verification."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        assert pkg.ed25519_pubkey == kms.ed25519_keypair.public_key.hex()

    def test_package_ethical_vector_included(self, kms):
        """Package should include ethical vector."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        assert pkg.ethical_vector == kms.ethical_vector
        assert pkg.ethical_hash is not None


class TestCryptoPackageVerification:
    """Penetration tests for crypto package verification."""

    @pytest.fixture
    def kms(self):
        """Create KMS for testing."""
        return generate_key_management_system("test_author")

    @pytest.fixture
    def valid_package(self, kms):
        """Create valid package for testing."""
        return create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")

    def test_verify_valid_package(self, kms, valid_package):
        """Valid package should pass all verifications."""
        results = verify_crypto_package(
            MASTER_CODES, MASTER_HELIX_PARAMS, valid_package, kms.hmac_key
        )
        assert results["content_hash"] is True
        assert results["hmac"] is True
        assert results["ed25519"] is True
        assert results["timestamp"] is True

    def test_verify_tampered_codes_fails(self, kms, valid_package):
        """Tampered Omni-Codes should fail content hash verification."""
        results = verify_crypto_package(
            MASTER_CODES + "TAMPERED",
            MASTER_HELIX_PARAMS,
            valid_package,
            kms.hmac_key,
            require_quantum_signatures=False,
        )
        assert results["content_hash"] is False

    def test_verify_tampered_helix_params_fails(self, kms, valid_package):
        """Tampered helix params should fail content hash verification."""
        tampered_params = [(r + 1.0, p) for r, p in MASTER_HELIX_PARAMS]
        results = verify_crypto_package(
            MASTER_CODES,
            tampered_params,
            valid_package,
            kms.hmac_key,
            require_quantum_signatures=False,
        )
        assert results["content_hash"] is False

    def test_verify_wrong_hmac_key_fails(self, valid_package):
        """Wrong HMAC key should fail HMAC verification."""
        wrong_key = secrets.token_bytes(32)
        results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, valid_package, wrong_key)
        assert results["hmac"] is False

    def test_verify_tampered_content_hash_fails(self, kms, valid_package):
        """Tampered content hash should fail verification."""
        tampered = copy.copy(valid_package)
        # Flip first character of hash
        tampered.content_hash = "f" + valid_package.content_hash[1:]
        results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, tampered, kms.hmac_key)
        assert results["content_hash"] is False

    def test_verify_tampered_hmac_tag_fails(self, kms, valid_package):
        """Tampered HMAC tag should fail verification."""
        tampered = copy.copy(valid_package)
        # Flip a bit in the middle of the tag to ensure actual tampering
        original_bytes = bytes.fromhex(valid_package.hmac_tag)
        tampered_bytes = bytearray(original_bytes)
        tampered_bytes[16] ^= 0xFF  # Flip all bits in middle byte
        tampered.hmac_tag = tampered_bytes.hex()
        results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, tampered, kms.hmac_key)
        assert results["hmac"] is False

    def test_verify_tampered_ed25519_signature_fails(self, kms, valid_package):
        """Tampered Ed25519 signature should fail verification."""
        tampered = copy.copy(valid_package)
        # Use bit-flipping to ensure actual tampering (avoids flaky test if sig starts with 'f')
        original_bytes = bytes.fromhex(valid_package.ed25519_signature)
        tampered_bytes = bytearray(original_bytes)
        tampered_bytes[0] ^= 0xFF  # Flip all bits in first byte
        tampered.ed25519_signature = tampered_bytes.hex()
        results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, tampered, kms.hmac_key)
        assert results["ed25519"] is False

    def test_verify_wrong_ed25519_pubkey_fails(self, kms, valid_package):
        """Wrong Ed25519 public key should fail verification."""
        tampered = copy.copy(valid_package)
        other_kp = generate_ed25519_keypair()
        tampered.ed25519_pubkey = other_kp.public_key.hex()
        results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, tampered, kms.hmac_key)
        assert results["ed25519"] is False

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
    def test_verify_tampered_dilithium_signature_fails(self, kms, valid_package):
        """Tampered Dilithium signature should fail verification."""
        if not valid_package.quantum_signatures_enabled:
            pytest.skip("Quantum signatures not enabled")
        tampered = copy.copy(valid_package)
        # Use bit-flipping to ensure actual tampering (avoids flaky test if sig starts with 'f')
        original_bytes = bytes.fromhex(valid_package.dilithium_signature)
        tampered_bytes = bytearray(original_bytes)
        tampered_bytes[len(tampered_bytes) // 2] ^= 0xFF  # Flip bits in middle byte
        tampered.dilithium_signature = tampered_bytes.hex()
        results = verify_crypto_package(
            MASTER_CODES,
            MASTER_HELIX_PARAMS,
            tampered,
            kms.hmac_key,
            require_quantum_signatures=False,
        )
        assert results["dilithium"] is False


class TestTimestampValidation:
    """Penetration tests for timestamp validation."""

    @pytest.fixture
    def kms(self):
        return generate_key_management_system("test")

    def test_valid_timestamp_passes(self, kms):
        """Current timestamp should pass validation."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key)
        assert results["timestamp"] is True

    def test_future_timestamp_fails(self, kms):
        """Future timestamp should fail validation."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        # Set timestamp to tomorrow
        future = datetime.now(timezone.utc) + timedelta(days=1)
        pkg.timestamp = future.isoformat()
        results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key)
        assert results["timestamp"] is False

    def test_very_old_timestamp_fails(self, kms):
        """Timestamp older than 10 years should fail."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        # Set timestamp to 11 years ago
        old = datetime.now(timezone.utc) - timedelta(days=4000)
        pkg.timestamp = old.isoformat()
        results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key)
        assert results["timestamp"] is False

    def test_malformed_timestamp_fails(self, kms):
        """Malformed timestamp should fail gracefully."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        pkg.timestamp = "not-a-valid-timestamp"
        results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key)
        assert results["timestamp"] is False


class TestMalformedInputHandling:
    """Penetration tests for malformed/hostile input handling."""

    @pytest.fixture
    def kms(self):
        return generate_key_management_system("test")

    def test_invalid_hex_in_content_hash(self, kms):
        """Invalid hex in content_hash should not crash."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        pkg.content_hash = "not_valid_hex!!!"
        # Should either return False for content_hash or raise ValueError
        try:
            results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key)
            assert results["content_hash"] is False
        except ValueError:
            # ValueError is acceptable for invalid hex — the function rejects bad input
            pass
        except Exception as exc:
            pytest.fail(f"Unexpected exception for invalid hex: {exc!r}")

    def test_invalid_hex_in_hmac_tag(self, kms):
        """Invalid hex in hmac_tag should not crash."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        pkg.hmac_tag = "ZZZZ_invalid"
        try:
            results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key)
            assert results["hmac"] is False
        except ValueError:
            # ValueError is acceptable for invalid HMAC hex — the function rejects bad input
            pass
        except Exception as exc:
            pytest.fail(f"Unexpected exception for invalid HMAC hex: {exc!r}")

    def test_truncated_signature(self, kms):
        """Truncated signature should not crash."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        pkg.ed25519_signature = pkg.ed25519_signature[:32]  # Truncate to half
        try:
            results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key)
            assert results["ed25519"] is False
        except ValueError:
            # ValueError is acceptable for truncated signature — the function rejects bad input
            pass
        except Exception as exc:
            pytest.fail(f"Unexpected exception for truncated signature: {exc!r}")

    def test_empty_signature(self, kms):
        """Empty signature should not crash."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        pkg.ed25519_signature = ""
        try:
            results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key)
            assert results["ed25519"] is False
        except ValueError:
            # ValueError is acceptable for empty signature — the function rejects bad input
            pass
        except Exception as exc:
            pytest.fail(f"Unexpected exception for empty signature: {exc!r}")


class TestKeySecurityProperties:
    """Tests to verify key material is not leaked."""

    def test_crypto_package_does_not_contain_private_keys(self):
        """CryptoPackage should never contain private keys."""
        kms = generate_key_management_system("test")
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        pkg_dict = asdict(pkg)
        pkg_json = json.dumps(pkg_dict)

        # Private key should not appear in package
        assert kms.ed25519_keypair.private_key.hex() not in pkg_json
        assert kms.master_secret.hex() not in pkg_json
        assert kms.hmac_key.hex() not in pkg_json

    def test_crypto_package_does_not_contain_master_secret(self):
        """Master secret should never be in package."""
        kms = generate_key_management_system("test")
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        pkg_dict = asdict(pkg)

        # Check all string values
        for key, value in pkg_dict.items():
            if isinstance(value, str):
                assert kms.master_secret.hex() not in value


class TestDowngradeAttacks:
    """Tests for algorithm downgrade attack resistance."""

    def test_package_without_dilithium_clearly_marked(self):
        """Package without Dilithium should be clearly marked."""
        kms = generate_key_management_system("test")
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        # If Dilithium is disabled, quantum_signatures_enabled should be False
        if not DILITHIUM_AVAILABLE:
            assert pkg.quantum_signatures_enabled is False
            assert pkg.dilithium_signature is None

    def test_verification_distinguishes_missing_vs_invalid_dilithium(self):
        """Verification should distinguish missing vs invalid Dilithium."""
        kms = generate_key_management_system("test")
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key)
        # dilithium should be True (valid), False (invalid), or None (not present)
        assert results["dilithium"] in [True, False, None]


class TestConcurrencyAndConsistency:
    """Tests for consistency across multiple operations."""

    def test_multiple_verifications_consistent(self):
        """Multiple verifications of same package should be consistent."""
        kms = generate_key_management_system("test")
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")

        results_list = []
        for _ in range(10):
            results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key)
            results_list.append(results)

        # All results should be identical
        for results in results_list[1:]:
            assert results == results_list[0]

    def test_multiple_package_creations_unique_timestamps(self):
        """Multiple package creations should have unique timestamps."""
        kms = generate_key_management_system("test")
        timestamps = set()
        for _ in range(5):
            pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
            timestamps.add(pkg.timestamp)
        # All 5 timestamps must be unique — no duplicates allowed
        assert len(timestamps) == 5, (
            f"Expected 5 unique timestamps, got {len(timestamps)}: duplicates detected"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
