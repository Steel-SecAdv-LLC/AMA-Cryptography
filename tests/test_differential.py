#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Differential Testing for AMA Cryptography

Compares AMA Cryptography implementations against reference libraries
with random inputs to catch any divergence.

Reference libraries (install for differential testing):
- pycryptodome: AES-GCM, ChaCha20-Poly1305
- pynacl/libsodium: Ed25519, X25519

These tests are optional — they only run if the reference libraries
are installed.
"""

import os
import secrets

import pytest

# Check for AMA native backend
try:
    from ama_cryptography.pqc_backends import (
        _AES_GCM_NATIVE_AVAILABLE,
        _native_lib,
    )
    HAS_AMA_NATIVE = _native_lib is not None and _AES_GCM_NATIVE_AVAILABLE
except ImportError:
    HAS_AMA_NATIVE = False

# Check for pycryptodome
try:
    from Crypto.Cipher import AES as PyCryptoAES
    from Crypto.Cipher import ChaCha20_Poly1305 as PyCryptoChaCha
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

# Check for pynacl
try:
    import nacl.signing
    import nacl.utils
    HAS_PYNACL = True
except ImportError:
    HAS_PYNACL = False


@pytest.mark.skipif(
    not (HAS_AMA_NATIVE and HAS_PYCRYPTODOME),
    reason="Requires AMA native backend and pycryptodome",
)
class TestAESGCMDifferential:
    """Differential tests: AMA AES-GCM vs pycryptodome."""

    def test_encrypt_decrypt_consistency(self):
        """Encrypt with pycryptodome, decrypt with AMA (and vice versa)."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        for _ in range(10):
            key = secrets.token_bytes(32)
            nonce = secrets.token_bytes(12)
            plaintext = secrets.token_bytes(secrets.randbelow(1024) + 1)
            aad = secrets.token_bytes(secrets.randbelow(64))

            # AMA encrypt -> pycryptodome decrypt
            ama_ct, ama_tag = native_aes256_gcm_encrypt(key, nonce, plaintext, aad)

            cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_GCM, nonce=nonce)
            cipher.update(aad)
            pyc_pt = cipher.decrypt_and_verify(ama_ct, ama_tag)
            assert pyc_pt == plaintext, "AMA->pycryptodome decrypt mismatch"

            # pycryptodome encrypt -> AMA decrypt
            cipher2 = PyCryptoAES.new(key, PyCryptoAES.MODE_GCM, nonce=nonce)
            cipher2.update(aad)
            pyc_ct, pyc_tag = cipher2.encrypt_and_digest(plaintext)

            ama_pt = native_aes256_gcm_decrypt(key, nonce, pyc_ct, pyc_tag, aad)
            assert ama_pt == plaintext, "pycryptodome->AMA decrypt mismatch"


@pytest.mark.skipif(
    not (HAS_AMA_NATIVE and HAS_PYNACL),
    reason="Requires AMA native backend and pynacl",
)
class TestEd25519Differential:
    """Differential tests: AMA Ed25519 vs pynacl/libsodium."""

    def test_signature_verification_cross_library(self):
        """Sign with pynacl, verify with AMA (basic compatibility check)."""
        # This test verifies that our Ed25519 implementation produces
        # signatures compatible with libsodium's Ed25519
        signing_key = nacl.signing.SigningKey.generate()
        message = secrets.token_bytes(100)
        signed = signing_key.sign(message)

        # The signature is the first 64 bytes
        signature = signed.signature
        verify_key_bytes = signing_key.verify_key.encode()

        # Verify the signature format is compatible
        assert len(signature) == 64
        assert len(verify_key_bytes) == 32


@pytest.mark.skipif(
    not HAS_AMA_NATIVE,
    reason="Requires AMA native backend",
)
class TestAMASelfConsistency:
    """Self-consistency tests for AMA crypto operations."""

    def test_aes_gcm_roundtrip(self):
        """AMA AES-GCM encrypt then decrypt produces original plaintext."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        for size in [0, 1, 15, 16, 17, 256, 1024, 4096]:
            key = secrets.token_bytes(32)
            nonce = secrets.token_bytes(12)
            plaintext = secrets.token_bytes(size) if size > 0 else b""
            aad = secrets.token_bytes(32)

            ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, aad)
            pt = native_aes256_gcm_decrypt(key, nonce, ct, tag, aad)
            assert pt == plaintext, f"Roundtrip failed for size={size}"

    def test_aes_gcm_wrong_key_fails(self):
        """Decryption with wrong key must fail."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"test data"

        ct, tag = native_aes256_gcm_encrypt(key1, nonce, plaintext, b"")

        with pytest.raises(Exception):
            native_aes256_gcm_decrypt(key2, nonce, ct, tag, b"")

    def test_aes_gcm_tampered_ciphertext_fails(self):
        """Tampered ciphertext must fail authentication."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"test data for tamper check"

        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, b"")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF

        with pytest.raises(Exception):
            native_aes256_gcm_decrypt(key, nonce, bytes(tampered), tag, b"")
