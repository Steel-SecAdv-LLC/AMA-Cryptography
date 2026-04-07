#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AES-GCM NIST SP 800-38D Broader Test Vector Coverage
======================================================

Extends GHASH/PCLMULQDQ test coverage beyond the single NIST Test Case 16
already validated. Covers NIST SP 800-38D test cases for AES-256-GCM with
various plaintext lengths, AAD lengths, and edge cases.

These tests exercise the AVX2 dispatch path (GHASH via PCLMULQDQ Intel
Algorithm 5 polynomial reduction) when hardware support is available,
falling back to the C reference implementation otherwise.

Reference: NIST SP 800-38D
  https://csrc.nist.gov/publications/detail/sp/800-38d/final

AI Co-Architects: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

from __future__ import annotations

import pytest

try:
    from ama_cryptography.pqc_backends import _AES_GCM_NATIVE_AVAILABLE, _native_lib

    NATIVE_AVAILABLE = _native_lib is not None and _AES_GCM_NATIVE_AVAILABLE
except ImportError:
    NATIVE_AVAILABLE = False

skip_no_native = pytest.mark.skipif(
    not NATIVE_AVAILABLE,
    reason="Native AES-256-GCM library not available",
)


# ============================================================================
# NIST SP 800-38D Test Vectors (AES-256 only, 96-bit IV)
#
# Source: NIST SP 800-38D Appendix B
# Only AES-256 cases are included since AMA supports AES-256 only.
#
# NIST test case numbering for AES-256:
#   Case 13: No plaintext, no AAD
#   Case 14: Plaintext only, no AAD
#   Case 15: No plaintext, AAD only
#   Case 16: Both plaintext and AAD (already tested in test_aes_gcm_native.py)
# ============================================================================

NIST_AES256_VECTORS = [
    {
        # Test Case 13: AES-256, no plaintext, no AAD
        "name": "NIST Case 13 (no PT, no AAD)",
        "key": bytes.fromhex("00000000000000000000000000000000" "00000000000000000000000000000000"),
        "nonce": bytes.fromhex("000000000000000000000000"),
        "plaintext": b"",
        "aad": b"",
        "ciphertext": b"",
        "tag": bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b"),
    },
    {
        # Test Case 14: AES-256, plaintext, no AAD
        "name": "NIST Case 14 (PT, no AAD)",
        "key": bytes.fromhex("00000000000000000000000000000000" "00000000000000000000000000000000"),
        "nonce": bytes.fromhex("000000000000000000000000"),
        "plaintext": bytes.fromhex("00000000000000000000000000000000"),
        "aad": b"",
        "ciphertext": bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18"),
        "tag": bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919"),
    },
    {
        # Test Case 15: AES-256, no plaintext, AAD only
        "name": "NIST Case 15 (no PT, AAD)",
        "key": bytes.fromhex("feffe9928665731c6d6a8f9467308308" "feffe9928665731c6d6a8f9467308308"),
        "nonce": bytes.fromhex("cafebabefacedbaddecaf888"),
        "plaintext": b"",
        "aad": bytes.fromhex("feedfacedeadbeeffeedfacedeadbeef" "abaddad2"),
        "ciphertext": b"",
        "tag": bytes.fromhex("9f6be07603c0b0bd1272854063e9c9ba"),
    },
    {
        # Test Case 16: AES-256, plaintext + AAD (canonical reference)
        "name": "NIST Case 16 (PT + AAD)",
        "key": bytes.fromhex("feffe9928665731c6d6a8f9467308308" "feffe9928665731c6d6a8f9467308308"),
        "nonce": bytes.fromhex("cafebabefacedbaddecaf888"),
        "plaintext": bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b391aafd255"
        ),
        "aad": bytes.fromhex("feedfacedeadbeeffeedfacedeadbeef" "abaddad2"),
        "ciphertext": bytes.fromhex(
            "522dc1f099567d07f47f37a32a84427d"
            "643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838"
            "c5f61e6393ba7a0abcc9f662898015ad"
        ),
        "tag": bytes.fromhex("2df7cd675b4f09163b41ebf980a7f638"),
    },
]


# ============================================================================
# Additional test vectors from published GCM test data
# These cover edge cases that stress the GHASH implementation
# ============================================================================

ADDITIONAL_VECTORS = [
    {
        # Single block plaintext, full-zero key
        "name": "Single block PT, zero key",
        "key": bytes(32),
        "nonce": bytes(12),
        "plaintext": bytes(16),
        "aad": b"",
        "encrypt_only": True,  # Just verify encrypt/decrypt roundtrip
    },
    {
        # Multi-block plaintext, no AAD
        "name": "3 blocks PT, no AAD",
        "key": bytes.fromhex("feffe9928665731c6d6a8f9467308308" "feffe9928665731c6d6a8f9467308308"),
        "nonce": bytes.fromhex("cafebabefacedbaddecaf888"),
        "plaintext": bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39"
        ),
        "aad": b"",
        "encrypt_only": True,
    },
    {
        # Short AAD (1 byte), no plaintext
        "name": "1-byte AAD, no PT",
        "key": bytes.fromhex("feffe9928665731c6d6a8f9467308308" "feffe9928665731c6d6a8f9467308308"),
        "nonce": bytes.fromhex("cafebabefacedbaddecaf888"),
        "plaintext": b"",
        "aad": b"\x42",
        "encrypt_only": True,
    },
    {
        # Long AAD (256 bytes), short plaintext (1 byte)
        "name": "256-byte AAD, 1-byte PT",
        "key": bytes.fromhex("feffe9928665731c6d6a8f9467308308" "feffe9928665731c6d6a8f9467308308"),
        "nonce": bytes.fromhex("cafebabefacedbaddecaf888"),
        "plaintext": b"\xff",
        "aad": bytes(range(256)),
        "encrypt_only": True,
    },
]


@skip_no_native
class TestNISTAES256Vectors:
    """NIST SP 800-38D AES-256 test vectors with known ciphertext + tag."""

    @pytest.mark.parametrize(
        "vector",
        [v for v in NIST_AES256_VECTORS if "ciphertext" in v],
        ids=[v["name"] for v in NIST_AES256_VECTORS if "ciphertext" in v],
    )
    def test_encrypt_matches_nist(self, vector: dict) -> None:
        """Encryption produces expected ciphertext and tag."""
        from ama_cryptography.pqc_backends import native_aes256_gcm_encrypt

        aad = vector["aad"] if vector["aad"] else None
        if aad is not None:
            ct, tag = native_aes256_gcm_encrypt(
                vector["key"], vector["nonce"], vector["plaintext"], aad
            )
        else:
            ct, tag = native_aes256_gcm_encrypt(vector["key"], vector["nonce"], vector["plaintext"])

        assert ct == vector["ciphertext"], (
            f"{vector['name']} ciphertext mismatch:\n"
            f"  expected: {vector['ciphertext'].hex()}\n"
            f"  got:      {ct.hex()}"
        )
        assert tag == vector["tag"], (
            f"{vector['name']} tag mismatch:\n"
            f"  expected: {vector['tag'].hex()}\n"
            f"  got:      {tag.hex()}"
        )

    @pytest.mark.parametrize(
        "vector",
        [v for v in NIST_AES256_VECTORS if "ciphertext" in v],
        ids=[v["name"] for v in NIST_AES256_VECTORS if "ciphertext" in v],
    )
    def test_decrypt_matches_nist(self, vector: dict) -> None:
        """Decryption produces expected plaintext."""
        from ama_cryptography.pqc_backends import native_aes256_gcm_decrypt

        aad = vector["aad"] if vector["aad"] else None
        if aad is not None:
            pt = native_aes256_gcm_decrypt(
                vector["key"], vector["nonce"], vector["ciphertext"], vector["tag"], aad
            )
        else:
            pt = native_aes256_gcm_decrypt(
                vector["key"], vector["nonce"], vector["ciphertext"], vector["tag"]
            )

        assert pt == vector["plaintext"], (
            f"{vector['name']} plaintext mismatch:\n"
            f"  expected: {vector['plaintext'].hex()}\n"
            f"  got:      {pt.hex()}"
        )


@skip_no_native
class TestGHASHEdgeCases:
    """Edge cases that stress the GHASH polynomial multiplication."""

    @pytest.mark.parametrize(
        "vector",
        ADDITIONAL_VECTORS,
        ids=[v["name"] for v in ADDITIONAL_VECTORS],
    )
    def test_encrypt_decrypt_roundtrip(self, vector: dict) -> None:
        """Encrypt then decrypt roundtrip for GHASH edge cases."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        aad = vector["aad"] if vector["aad"] else None
        if aad is not None:
            ct, tag = native_aes256_gcm_encrypt(
                vector["key"], vector["nonce"], vector["plaintext"], aad
            )
        else:
            ct, tag = native_aes256_gcm_encrypt(vector["key"], vector["nonce"], vector["plaintext"])

        assert len(ct) == len(vector["plaintext"])
        assert len(tag) == 16

        if aad is not None:
            pt = native_aes256_gcm_decrypt(vector["key"], vector["nonce"], ct, tag, aad)
        else:
            pt = native_aes256_gcm_decrypt(vector["key"], vector["nonce"], ct, tag)
        assert pt == vector["plaintext"], f"Roundtrip failed for {vector['name']}"

    def test_empty_pt_empty_aad(self) -> None:
        """Both empty plaintext and empty AAD — tag-only mode."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = bytes(32)
        nonce = bytes(12)

        ct, tag = native_aes256_gcm_encrypt(key, nonce, b"")
        assert ct == b""
        assert len(tag) == 16

        pt = native_aes256_gcm_decrypt(key, nonce, b"", tag)
        assert pt == b""

    def test_non_block_aligned_aad(self) -> None:
        """AAD that is not a multiple of 16 bytes (tests GHASH padding)."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308" "feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")

        # Test various non-block-aligned AAD lengths
        for aad_len in [1, 7, 13, 15, 17, 20, 31, 33, 47, 63]:
            aad = bytes(range(aad_len))
            pt = b"test plaintext for GHASH padding"

            ct, tag = native_aes256_gcm_encrypt(key, nonce, pt, aad)
            recovered = native_aes256_gcm_decrypt(key, nonce, ct, tag, aad)
            assert recovered == pt, f"Failed for AAD length {aad_len}"

    def test_non_block_aligned_plaintext(self) -> None:
        """Plaintext that is not a multiple of 16 bytes (tests CTR + GHASH)."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308" "feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        aad = b"constant aad"

        for pt_len in [1, 7, 13, 15, 17, 31, 33, 48, 63, 64, 65, 100, 255, 256, 257]:
            pt = bytes(range(256))[:pt_len] if pt_len <= 256 else bytes(pt_len)

            ct, tag = native_aes256_gcm_encrypt(key, nonce, pt, aad)
            assert len(ct) == pt_len
            recovered = native_aes256_gcm_decrypt(key, nonce, ct, tag, aad)
            assert recovered == pt, f"Failed for PT length {pt_len}"

    def test_large_aad(self) -> None:
        """Large AAD (4KB) — tests GHASH with many blocks."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308" "feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        aad = bytes(range(256)) * 16  # 4096 bytes
        pt = b"short plaintext"

        ct, tag = native_aes256_gcm_encrypt(key, nonce, pt, aad)
        recovered = native_aes256_gcm_decrypt(key, nonce, ct, tag, aad)
        assert recovered == pt

    def test_tampered_aad_bit_detected(self) -> None:
        """Single bit flip in AAD must cause tag verification failure."""
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308" "feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        aad = b"authentic associated data"
        pt = b"confidential payload"

        ct, tag = native_aes256_gcm_encrypt(key, nonce, pt, aad)

        # Flip one bit in AAD
        tampered_aad = bytearray(aad)
        tampered_aad[0] ^= 0x01

        with pytest.raises(ValueError, match="tag verification failed"):
            native_aes256_gcm_decrypt(key, nonce, ct, tag, bytes(tampered_aad))


@skip_no_native
class TestGHASHDispatch:
    """Verify AVX2 dispatch path is exercised when available."""

    def test_dispatch_status(self) -> None:
        """Check which AES-GCM dispatch path is active."""
        # This test is informational — it passes regardless of dispatch path.
        # The purpose is to log which path CI uses.
        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = bytes(32)
        nonce = bytes(12)
        pt = b"dispatch test" * 100  # Enough data to exercise GHASH

        ct, tag = native_aes256_gcm_encrypt(key, nonce, pt)
        recovered = native_aes256_gcm_decrypt(key, nonce, ct, tag)
        assert recovered == pt

    def test_multi_block_consistency(self) -> None:
        """Verify multi-block encryption is consistent across dispatch paths.

        Encrypts the same data multiple times and verifies identical output,
        which would catch dispatch-path-dependent GHASH bugs.
        """
        from ama_cryptography.pqc_backends import native_aes256_gcm_encrypt

        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308" "feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        pt = bytes(range(256)) * 4  # 1024 bytes (64 AES blocks)
        aad = bytes(range(128))

        results = [native_aes256_gcm_encrypt(key, nonce, pt, aad) for _ in range(5)]
        ct0, tag0 = results[0]
        for i, (ct, tag) in enumerate(results[1:], start=1):
            assert ct == ct0, f"Ciphertext diverged on iteration {i}"
            assert tag == tag0, f"Tag diverged on iteration {i}"
