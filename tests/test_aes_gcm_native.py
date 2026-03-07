#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AES-256-GCM Native C Backend Tests
===================================

Comprehensive test suite for the native AES-256-GCM implementation.
Tests encrypt/decrypt, authentication, edge cases, and interop with PyCA.

AI Co-Architects: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

import secrets

import pytest

# Check if native library is available
try:
    from ama_cryptography.pqc_backends import (
        _AES_GCM_NATIVE_AVAILABLE,
        _native_lib,
    )

    NATIVE_AVAILABLE = _native_lib is not None and _AES_GCM_NATIVE_AVAILABLE
except ImportError:
    NATIVE_AVAILABLE = False

skip_no_native = pytest.mark.skipif(
    not NATIVE_AVAILABLE,
    reason="Native AES-256-GCM library not available (build with cmake)",
)


# ============================================================================
# NIST SP 800-38D TEST VECTORS
# ============================================================================

# Test Case 16 from NIST SP 800-38D (AES-256, 96-bit IV)
NIST_KEY_16 = bytes.fromhex("feffe9928665731c6d6a8f9467308308" "feffe9928665731c6d6a8f9467308308")
NIST_NONCE_16 = bytes.fromhex("cafebabefacedbaddecaf888")
NIST_PT_16 = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b391aafd255"
)
NIST_AAD_16 = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeef" "abaddad2")
NIST_CT_16 = bytes.fromhex(
    "522dc1f099567d07f47f37a32a84427d"
    "643a8cdcbfe5c0c97598a2bd2555d1aa"
    "8cb08e48590dbb3da7b08b1056828838"
    "c5f61e6393ba7a0abcc9f662898015ad"
)
NIST_TAG_16 = bytes.fromhex("2df7cd675b4f09163b41ebf980a7f638")


@skip_no_native
class TestAESGCMNativeBasic:
    """Basic AES-256-GCM encrypt/decrypt tests."""

    def test_encrypt_decrypt_roundtrip(self):
        """Basic encrypt then decrypt roundtrip."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Hello, AES-256-GCM!"

        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext)
        pt = native_aes256_gcm_decrypt(key, nonce, ct, tag)

        assert pt == plaintext

    def test_encrypt_decrypt_with_aad(self):
        """Encrypt/decrypt with additional authenticated data."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Secret data"
        aad = b"authenticated but not encrypted"

        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, aad)
        pt = native_aes256_gcm_decrypt(key, nonce, ct, tag, aad)

        assert pt == plaintext

    def test_wrong_key_fails(self):
        """Decryption with wrong key must fail authentication."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        ct, tag = native_aes256_gcm_encrypt(key1, nonce, b"secret")
        with pytest.raises(ValueError, match="tag verification failed"):
            native_aes256_gcm_decrypt(key2, nonce, ct, tag)

    def test_wrong_nonce_fails(self):
        """Decryption with wrong nonce must fail authentication."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = secrets.token_bytes(32)
        nonce1 = secrets.token_bytes(12)
        nonce2 = secrets.token_bytes(12)

        ct, tag = native_aes256_gcm_encrypt(key, nonce1, b"secret")
        with pytest.raises(ValueError, match="tag verification failed"):
            native_aes256_gcm_decrypt(key, nonce2, ct, tag)

    def test_tampered_ciphertext_fails(self):
        """Tampered ciphertext must fail authentication."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        ct, tag = native_aes256_gcm_encrypt(key, nonce, b"secret data here")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(ValueError, match="tag verification failed"):
            native_aes256_gcm_decrypt(key, nonce, bytes(tampered), tag)

    def test_tampered_tag_fails(self):
        """Tampered tag must fail authentication."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        ct, tag = native_aes256_gcm_encrypt(key, nonce, b"secret data")
        tampered_tag = bytearray(tag)
        tampered_tag[0] ^= 0x01
        with pytest.raises(ValueError, match="tag verification failed"):
            native_aes256_gcm_decrypt(key, nonce, ct, bytes(tampered_tag))

    def test_wrong_aad_fails(self):
        """Decryption with wrong AAD must fail authentication."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        ct, tag = native_aes256_gcm_encrypt(key, nonce, b"data", b"correct aad")
        with pytest.raises(ValueError, match="tag verification failed"):
            native_aes256_gcm_decrypt(key, nonce, ct, tag, b"wrong aad")


@skip_no_native
class TestAESGCMNativeEdgeCases:
    """Edge case tests for AES-256-GCM."""

    def test_empty_plaintext(self):
        """Empty plaintext should work (AAD-only authentication)."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        ct, tag = native_aes256_gcm_encrypt(key, nonce, b"", b"metadata")
        assert ct == b""
        assert len(tag) == 16
        pt = native_aes256_gcm_decrypt(key, nonce, ct, tag, b"metadata")
        assert pt == b""

    def test_single_byte_plaintext(self):
        """Single byte plaintext."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        ct, tag = native_aes256_gcm_encrypt(key, nonce, b"\x42")
        assert len(ct) == 1
        pt = native_aes256_gcm_decrypt(key, nonce, ct, tag)
        assert pt == b"\x42"

    def test_non_block_aligned_plaintext(self):
        """Plaintext not aligned to 16-byte AES block boundary."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        for length in [1, 7, 15, 17, 31, 33, 100, 255]:
            plaintext = secrets.token_bytes(length)
            ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext)
            assert len(ct) == length
            pt = native_aes256_gcm_decrypt(key, nonce, ct, tag)
            assert pt == plaintext

    def test_large_plaintext(self):
        """1 MB plaintext."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = secrets.token_bytes(1024 * 1024)

        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext)
        pt = native_aes256_gcm_decrypt(key, nonce, ct, tag)
        assert pt == plaintext

    def test_deterministic_encryption(self):
        """Same key+nonce+plaintext must produce same ciphertext."""
        from ama_cryptography.pqc_backends import native_aes256_gcm_encrypt

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"deterministic test"

        ct1, tag1 = native_aes256_gcm_encrypt(key, nonce, plaintext)
        ct2, tag2 = native_aes256_gcm_encrypt(key, nonce, plaintext)

        assert ct1 == ct2
        assert tag1 == tag2


@skip_no_native
class TestAESGCMInputValidation:
    """Input validation tests."""

    def test_wrong_key_length(self):
        """Key must be exactly 32 bytes."""
        from ama_cryptography.pqc_backends import native_aes256_gcm_encrypt

        with pytest.raises(ValueError, match="32 bytes"):
            native_aes256_gcm_encrypt(b"short", b"\x00" * 12, b"data")

    def test_wrong_nonce_length(self):
        """Nonce must be exactly 12 bytes."""
        from ama_cryptography.pqc_backends import native_aes256_gcm_encrypt

        with pytest.raises(ValueError, match="12 bytes"):
            native_aes256_gcm_encrypt(b"\x00" * 32, b"short", b"data")

    def test_wrong_tag_length(self):
        """Tag must be exactly 16 bytes."""
        from ama_cryptography.pqc_backends import native_aes256_gcm_decrypt

        with pytest.raises(ValueError, match="16 bytes"):
            native_aes256_gcm_decrypt(b"\x00" * 32, b"\x00" * 12, b"ct", b"short")


@skip_no_native
class TestAESGCMNISTVectors:
    """NIST SP 800-38D test vectors."""

    def test_nist_case_16(self):
        """NIST SP 800-38D Test Case 16 (AES-256, 96-bit IV, AAD)."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        ct, tag = native_aes256_gcm_encrypt(NIST_KEY_16, NIST_NONCE_16, NIST_PT_16, NIST_AAD_16)

        assert (
            ct == NIST_CT_16
        ), f"Ciphertext mismatch:\n  got:    {ct.hex()}\n  expect: {NIST_CT_16.hex()}"
        assert (
            tag == NIST_TAG_16
        ), f"Tag mismatch:\n  got:    {tag.hex()}\n  expect: {NIST_TAG_16.hex()}"

        # Verify decryption
        pt = native_aes256_gcm_decrypt(
            NIST_KEY_16, NIST_NONCE_16, NIST_CT_16, NIST_TAG_16, NIST_AAD_16
        )
        assert pt == NIST_PT_16


@skip_no_native
class TestAESGCMInterop:
    """Interop tests between native and PyCA cryptography."""

    def test_native_encrypt_pyca_decrypt(self):
        """Native-encrypted data must be decryptable by PyCA cryptography."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            pytest.skip("PyCA cryptography not installed")

        from ama_cryptography.pqc_backends import native_aes256_gcm_encrypt

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"cross-implementation test data"
        aad = b"authenticated context"

        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, aad)

        aesgcm = AESGCM(key)
        pt = aesgcm.decrypt(nonce, ct + tag, aad)
        assert pt == plaintext

    def test_pyca_encrypt_native_decrypt(self):
        """PyCA-encrypted data must be decryptable by native backend."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            pytest.skip("PyCA cryptography not installed")

        from ama_cryptography.pqc_backends import native_aes256_gcm_decrypt

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"reverse interop test"
        aad = b"metadata"

        aesgcm = AESGCM(key)
        combined = aesgcm.encrypt(nonce, plaintext, aad)
        ct = combined[:-16]
        tag = combined[-16:]

        pt = native_aes256_gcm_decrypt(key, nonce, ct, tag, aad)
        assert pt == plaintext


@skip_no_native
class TestAESGCMProvider:
    """Tests for AESGCMProvider in crypto_api.py."""

    def test_provider_encrypt_decrypt(self):
        """AESGCMProvider encrypt/decrypt roundtrip."""
        from ama_cryptography.crypto_api import AESGCMProvider, CryptoBackend

        provider = AESGCMProvider(backend=CryptoBackend.C_LIBRARY)
        key = secrets.token_bytes(32)
        plaintext = b"provider integration test"

        result = provider.encrypt(plaintext, key)
        assert result["backend"] == "native_c"

        pt = provider.decrypt(result["ciphertext"], key, result["nonce"], result["tag"])
        assert pt == plaintext

    def test_provider_with_aad(self):
        """AESGCMProvider with additional authenticated data."""
        from ama_cryptography.crypto_api import AESGCMProvider, CryptoBackend

        provider = AESGCMProvider(backend=CryptoBackend.C_LIBRARY)
        key = secrets.token_bytes(32)
        plaintext = b"aad test data"
        aad = b"header info"

        result = provider.encrypt(plaintext, key, aad=aad)
        pt = provider.decrypt(result["ciphertext"], key, result["nonce"], result["tag"], aad=aad)
        assert pt == plaintext

    def test_provider_auto_generates_nonce(self):
        """Provider auto-generates unique nonces when not specified."""
        from ama_cryptography.crypto_api import AESGCMProvider, CryptoBackend

        provider = AESGCMProvider(backend=CryptoBackend.C_LIBRARY)
        key = secrets.token_bytes(32)

        r1 = provider.encrypt(b"data1", key)
        r2 = provider.encrypt(b"data1", key)
        assert r1["nonce"] != r2["nonce"]  # Different nonces
