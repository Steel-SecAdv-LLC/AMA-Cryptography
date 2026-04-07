#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Ed25519 Batch Verification Tests
=================================

Comprehensive tests for ama_ed25519_batch_verify() covering:
- Correctness with all-valid batches
- Mixed valid/invalid signature detection
- Edge cases (empty, single, max size, over max)
- RFC 8032 Section 7.1 test vectors through batch path
- Both ctypes and Cython code paths

AI Co-Architects: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

from __future__ import annotations

import pytest

from ama_cryptography.pqc_backends import _native_lib

# Skip entire module if native library is not built
pytestmark = pytest.mark.skipif(
    _native_lib is None,
    reason="Native C library not built — skipping batch verify tests",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_signed_entry(seed: bytes, message: bytes) -> tuple[bytes, bytes, bytes]:
    """Generate a (message, signature, public_key) tuple for batch verify."""
    from ama_cryptography.pqc_backends import native_ed25519_keypair_from_seed, native_ed25519_sign

    pk, sk = native_ed25519_keypair_from_seed(seed)
    sig = native_ed25519_sign(message, sk)
    return (message, sig, pk)


def _generate_random_entry(index: int) -> tuple[bytes, bytes, bytes]:
    """Generate a signed entry using a deterministic seed derived from index."""
    seed = (index.to_bytes(4, "little") * 8)[:32]
    message = f"batch test message {index}".encode()
    return _generate_signed_entry(seed, message)


# ---------------------------------------------------------------------------
# RFC 8032 Section 7.1 test vectors
# ---------------------------------------------------------------------------

RFC8032_VECTORS = [
    {
        "name": "TEST 1 (empty message)",
        "secret_key_seed": bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc4" "4449c5697b326919703bac031cae7f60"
        ),
        "public_key": bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a" "0ee172f3daa62325af021a68f707511a"
        ),
        "message": b"",
        "signature": bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b"
        ),
    },
    {
        "name": "TEST 2 (single byte 0x72)",
        "secret_key_seed": bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f" "5b8a319f35aba624da8cf6ed4fb8a6fb"
        ),
        "public_key": bytes.fromhex(
            "3d4017c3e843895a92b70aa74d1b7ebc" "9c982ccf2ec4968cc0cd55f12af4660c"
        ),
        "message": bytes.fromhex("72"),
        "signature": bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540"
            "a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c"
            "387b2eaeb4302aeeb00d291612bb0c00"
        ),
    },
    {
        "name": "TEST 3 (two-byte message)",
        "secret_key_seed": bytes.fromhex(
            "c5aa8df43f9f837bedb7442f31dcb7b1" "66d38535076f094b85ce3a2e0b4458f7"
        ),
        "public_key": bytes.fromhex(
            "fc51cd8e6218a1a38da47ed00230f058" "0816ed13ba3303ac5deb911548908025"
        ),
        "message": bytes.fromhex("af82"),
        "signature": bytes.fromhex(
            "6291d657deec24024827e69c3abe01a3"
            "0ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc659"
            "4a7c15e9716ed28dc027beceea1ec40a"
        ),
    },
]


# ---------------------------------------------------------------------------
# 3a. Correctness — batch of valid signatures
# ---------------------------------------------------------------------------


class TestBatchVerifyAllValid:
    """Batch verification of all-valid signature sets."""

    def test_batch_verify_all_valid_10(self) -> None:
        """Generate 10 key pairs, sign 10 messages, batch verify — all True."""
        from ama_cryptography.pqc_backends import native_ed25519_batch_verify

        entries = [_generate_random_entry(i) for i in range(10)]
        results = native_ed25519_batch_verify(entries)

        assert len(results) == 10
        assert all(results), f"Expected all True, got {results}"

    def test_batch_verify_all_valid_via_provider(self) -> None:
        """Batch verify through Ed25519Provider.batch_verify()."""
        from ama_cryptography.crypto_api import CryptoBackend, Ed25519Provider

        provider = Ed25519Provider(backend=CryptoBackend.C_LIBRARY)
        entries = [_generate_random_entry(i) for i in range(5)]
        results = provider.batch_verify(entries)

        assert len(results) == 5
        assert all(results)

    def test_batch_verify_all_valid_via_convenience(self) -> None:
        """Batch verify through batch_verify_ed25519() convenience function."""
        from ama_cryptography.crypto_api import batch_verify_ed25519

        entries = [_generate_random_entry(i) for i in range(5)]
        results = batch_verify_ed25519(entries)

        assert len(results) == 5
        assert all(results)


# ---------------------------------------------------------------------------
# 3b. Mixed valid/invalid signatures
# ---------------------------------------------------------------------------


class TestBatchVerifyMixed:
    """Batch verification with mix of valid and invalid signatures."""

    def test_batch_verify_mixed(self) -> None:
        """Mix valid and invalid sigs, verify per-entry results are correct."""
        from ama_cryptography.pqc_backends import native_ed25519_batch_verify

        entries = [_generate_random_entry(i) for i in range(5)]

        # Corrupt signatures at indices 1 and 3
        msg1, sig1, pk1 = entries[1]
        corrupted_sig1 = bytearray(sig1)
        corrupted_sig1[0] ^= 0xFF
        entries[1] = (msg1, bytes(corrupted_sig1), pk1)

        msg3, sig3, pk3 = entries[3]
        corrupted_sig3 = bytearray(sig3)
        corrupted_sig3[10] ^= 0xFF
        entries[3] = (msg3, bytes(corrupted_sig3), pk3)

        results = native_ed25519_batch_verify(entries)

        assert len(results) == 5
        assert results[0] is True, "Entry 0 should be valid"
        assert results[1] is False, "Entry 1 should be invalid (corrupted sig)"
        assert results[2] is True, "Entry 2 should be valid"
        assert results[3] is False, "Entry 3 should be invalid (corrupted sig)"
        assert results[4] is True, "Entry 4 should be valid"

    def test_batch_verify_all_invalid(self) -> None:
        """All-invalid batch returns all False."""
        from ama_cryptography.pqc_backends import native_ed25519_batch_verify

        entries = [_generate_random_entry(i) for i in range(3)]

        # Corrupt all signatures
        corrupted = []
        for msg, sig, pk in entries:
            bad_sig = bytearray(sig)
            bad_sig[0] ^= 0xFF
            corrupted.append((msg, bytes(bad_sig), pk))

        results = native_ed25519_batch_verify(corrupted)

        assert len(results) == 3
        assert not any(results), f"Expected all False, got {results}"

    def test_batch_verify_wrong_pubkey(self) -> None:
        """Wrong public key should result in False for that entry."""
        from ama_cryptography.pqc_backends import (
            native_ed25519_batch_verify,
            native_ed25519_keypair,
        )

        entries = [_generate_random_entry(i) for i in range(3)]

        # Replace public key at index 1 with a different key
        wrong_pk, _ = native_ed25519_keypair()
        msg1, sig1, _pk1 = entries[1]
        entries[1] = (msg1, sig1, wrong_pk)

        results = native_ed25519_batch_verify(entries)

        assert results[0] is True
        assert results[1] is False, "Wrong public key should fail"
        assert results[2] is True


# ---------------------------------------------------------------------------
# 3c. Edge cases
# ---------------------------------------------------------------------------


class TestBatchVerifyEdgeCases:
    """Edge case tests for batch verification."""

    def test_batch_verify_empty(self) -> None:
        """Empty batch should return empty list."""
        from ama_cryptography.pqc_backends import native_ed25519_batch_verify

        results = native_ed25519_batch_verify([])
        assert results == []

    def test_batch_verify_single(self) -> None:
        """Single entry batch should work correctly."""
        from ama_cryptography.pqc_backends import native_ed25519_batch_verify

        entry = _generate_random_entry(42)
        results = native_ed25519_batch_verify([entry])

        assert len(results) == 1
        assert results[0] is True

    def test_batch_verify_single_invalid(self) -> None:
        """Single invalid entry should return [False]."""
        from ama_cryptography.pqc_backends import native_ed25519_batch_verify

        msg, sig, pk = _generate_random_entry(42)
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0xFF

        results = native_ed25519_batch_verify([(msg, bytes(bad_sig), pk)])

        assert len(results) == 1
        assert results[0] is False

    def test_batch_verify_max_size(self) -> None:
        """64 entries (max batch size for donna) should work."""
        from ama_cryptography.pqc_backends import native_ed25519_batch_verify

        entries = [_generate_random_entry(i) for i in range(64)]
        results = native_ed25519_batch_verify(entries)

        assert len(results) == 64
        assert all(results), "All 64 valid entries should verify"

    def test_batch_verify_over_max_handled(self) -> None:
        """65+ entries should be handled gracefully (donna processes in chunks)."""
        from ama_cryptography.pqc_backends import native_ed25519_batch_verify

        # donna internally processes in chunks of max_batch_size (64),
        # so 65+ entries should still work via multiple batches
        entries = [_generate_random_entry(i) for i in range(65)]
        results = native_ed25519_batch_verify(entries)

        assert len(results) == 65
        assert all(results), "All 65 valid entries should verify"

    def test_batch_verify_invalid_signature_length(self) -> None:
        """Entry with wrong signature length raises ValueError."""
        from ama_cryptography.pqc_backends import native_ed25519_batch_verify

        seed = bytes(32)
        from ama_cryptography.pqc_backends import native_ed25519_keypair_from_seed

        pk, _sk = native_ed25519_keypair_from_seed(seed)

        with pytest.raises(ValueError, match="64 bytes"):
            native_ed25519_batch_verify([(b"msg", b"short_sig", pk)])

    def test_batch_verify_invalid_pubkey_length(self) -> None:
        """Entry with wrong public key length raises ValueError."""
        from ama_cryptography.pqc_backends import native_ed25519_batch_verify

        with pytest.raises(ValueError, match="32 bytes"):
            native_ed25519_batch_verify([(b"msg", b"\x00" * 64, b"short_pk")])


# ---------------------------------------------------------------------------
# 3d. RFC 8032 test vectors through batch path
# ---------------------------------------------------------------------------


class TestBatchVerifyRFC8032:
    """Verify RFC 8032 Section 7.1 test vectors through batch verify path."""

    def test_rfc8032_vectors_batch(self) -> None:
        """All RFC 8032 vectors should pass through batch verify."""
        from ama_cryptography.pqc_backends import native_ed25519_batch_verify

        entries = []
        for vec in RFC8032_VECTORS:
            entries.append((vec["message"], vec["signature"], vec["public_key"]))

        results = native_ed25519_batch_verify(entries)

        assert len(results) == len(RFC8032_VECTORS)
        for i, (result, vec) in enumerate(zip(results, RFC8032_VECTORS)):
            assert result is True, f"RFC 8032 {vec['name']} failed batch verify at index {i}"

    def test_rfc8032_keygen_batch(self) -> None:
        """RFC 8032 vectors: keygen + sign + batch verify roundtrip."""
        from ama_cryptography.pqc_backends import (
            native_ed25519_batch_verify,
            native_ed25519_keypair_from_seed,
            native_ed25519_sign,
        )

        entries = []
        for vec in RFC8032_VECTORS:
            pk, sk = native_ed25519_keypair_from_seed(vec["secret_key_seed"])  # type: ignore[arg-type]  # dict value is bytes but typed as object (TV-001)
            assert pk == vec["public_key"], f"Keygen mismatch for {vec['name']}"

            sig = native_ed25519_sign(vec["message"], sk)  # type: ignore[arg-type]  # dict value is bytes but typed as object (TV-001)
            assert sig == vec["signature"], f"Sign mismatch for {vec['name']}"

            entries.append((vec["message"], sig, pk))

        results = native_ed25519_batch_verify(entries)
        assert all(results), "All RFC 8032 vectors should batch-verify"

    def test_rfc8032_mixed_with_invalid(self) -> None:
        """RFC 8032 vectors mixed with one corrupted entry."""
        from ama_cryptography.pqc_backends import native_ed25519_batch_verify

        entries = []
        for vec in RFC8032_VECTORS:
            entries.append((vec["message"], vec["signature"], vec["public_key"]))

        # Corrupt the second entry's signature
        msg1, sig1, pk1 = entries[1]
        bad_sig = bytearray(sig1)  # type: ignore[arg-type]  # sig1 is bytes from dict but typed as object (TV-001)
        bad_sig[0] ^= 0xFF
        entries[1] = (msg1, bytes(bad_sig), pk1)

        results = native_ed25519_batch_verify(entries)

        assert results[0] is True, "RFC 8032 TEST 1 should pass"
        assert results[1] is False, "Corrupted TEST 2 should fail"
        assert results[2] is True, "RFC 8032 TEST 3 should pass"


# ---------------------------------------------------------------------------
# 3e. Test both ctypes and Cython paths
# ---------------------------------------------------------------------------


class TestBatchVerifyCtypes:
    """Explicitly test the ctypes batch verify path."""

    def test_ctypes_path(self) -> None:
        """Verify ctypes batch_verify works directly."""
        from ama_cryptography.pqc_backends import native_ed25519_batch_verify

        entries = [_generate_random_entry(i) for i in range(5)]
        results = native_ed25519_batch_verify(entries)

        assert len(results) == 5
        assert all(results)


# NOTE: Cython batch verify tests live in tests/test_ed25519_batch_verify_cython.py
# to avoid the module-level pytestmark skip (which triggers CI backend enforcement).
