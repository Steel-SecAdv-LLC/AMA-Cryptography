#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Ed25519 Comb Table Constants Verification
==========================================

Verifies the comb table precomputed constants (added for Item 4 — larger
basepoint precomputed tables) against RFC 8032 test vectors.

The comb table provides ~3-4x faster keygen/sign by precomputing
multiples of 2^(32*t) * B for t in [0..7]. This test ensures the
lazy-initialized table produces correct results by validating:
- Keygen: seed → expected public key (RFC 8032 vectors)
- Sign: seed + message → expected signature (RFC 8032 vectors)
- Verify: signature validates against public key

AI Co-Architects: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

from __future__ import annotations

from typing import Any

import pytest

from ama_cryptography.pqc_backends import _native_lib

# Skip entire module if native library is not built
pytestmark = pytest.mark.skipif(
    _native_lib is None,
    reason="Native C library not built — skipping comb table tests",
)


# RFC 8032 Section 7.1 test vectors (canonical reference)
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


class TestCombTableKeygen:
    """Verify comb table produces correct public keys from RFC 8032 seeds."""

    @pytest.mark.parametrize(
        "vector",
        RFC8032_VECTORS,
        ids=[str(v["name"]) for v in RFC8032_VECTORS],
    )
    def test_keygen_matches_rfc8032(self, vector: dict[str, Any]) -> None:
        """Comb table basepoint multiplication: seed → correct public key."""
        from ama_cryptography.pqc_backends import native_ed25519_keypair_from_seed

        pk, sk = native_ed25519_keypair_from_seed(vector["secret_key_seed"])

        assert pk == vector["public_key"], (
            f"Public key mismatch for {vector['name']}:\n"
            f"  expected: {vector['public_key'].hex()}\n"
            f"  got:      {pk.hex()}"
        )
        # Verify sk = seed || pk (AMA convention)
        assert sk[:32] == vector["secret_key_seed"]
        assert sk[32:] == pk

    def test_keygen_deterministic(self) -> None:
        """Same seed always produces the same keypair (comb table is stable)."""
        from ama_cryptography.pqc_backends import native_ed25519_keypair_from_seed

        seed = bytes(range(32))
        results = [native_ed25519_keypair_from_seed(seed) for _ in range(10)]

        pk0, sk0 = results[0]
        for i, (pk, sk) in enumerate(results[1:], start=1):
            assert pk == pk0, f"Public key diverged on iteration {i}"
            assert sk == sk0, f"Secret key diverged on iteration {i}"


class TestCombTableSign:
    """Verify comb table produces correct signatures from RFC 8032 vectors."""

    @pytest.mark.parametrize(
        "vector",
        RFC8032_VECTORS,
        ids=[str(v["name"]) for v in RFC8032_VECTORS],
    )
    def test_sign_matches_rfc8032(self, vector: dict[str, Any]) -> None:
        """Comb table path produces byte-identical signatures to RFC 8032."""
        from ama_cryptography.pqc_backends import (
            native_ed25519_keypair_from_seed,
            native_ed25519_sign,
        )

        _pk, sk = native_ed25519_keypair_from_seed(vector["secret_key_seed"])
        sig = native_ed25519_sign(vector["message"], sk)

        assert sig == vector["signature"], (
            f"Signature mismatch for {vector['name']}:\n"
            f"  expected: {vector['signature'].hex()}\n"
            f"  got:      {sig.hex()}"
        )


class TestCombTableVerify:
    """Verify comb table-based signatures pass verification."""

    @pytest.mark.parametrize(
        "vector",
        RFC8032_VECTORS,
        ids=[str(v["name"]) for v in RFC8032_VECTORS],
    )
    def test_verify_rfc8032(self, vector: dict[str, Any]) -> None:
        """RFC 8032 signatures verify against their public keys."""
        from ama_cryptography.pqc_backends import native_ed25519_verify

        assert native_ed25519_verify(
            vector["signature"], vector["message"], vector["public_key"]
        ), f"Verification failed for {vector['name']}"

    def test_sign_then_verify_roundtrip(self) -> None:
        """Full keygen → sign → verify roundtrip through comb table path."""
        from ama_cryptography.pqc_backends import (
            native_ed25519_keypair_from_seed,
            native_ed25519_sign,
            native_ed25519_verify,
        )

        # Use multiple different seeds to exercise the comb table thoroughly
        for i in range(20):
            seed = (i.to_bytes(4, "little") * 8)[:32]
            message = f"comb table roundtrip test {i}".encode()

            pk, sk = native_ed25519_keypair_from_seed(seed)
            sig = native_ed25519_sign(message, sk)
            assert native_ed25519_verify(sig, message, pk), f"Roundtrip failed for seed index {i}"

    def test_cross_validate_multiple_seeds(self) -> None:
        """Cross-validate comb table output across many seeds.

        Ensures the comb table handles the full scalar space correctly,
        not just the few scalars in RFC 8032 vectors.
        """
        import hashlib

        from ama_cryptography.pqc_backends import (
            native_ed25519_keypair_from_seed,
            native_ed25519_sign,
            native_ed25519_verify,
        )

        # Generate 50 different seeds via SHAKE256 for thorough coverage
        for i in range(50):
            h = hashlib.shake_256(f"comb-test-{i}".encode())
            seed = h.digest(32)
            message = f"msg-{i}".encode()

            pk, sk = native_ed25519_keypair_from_seed(seed)
            sig = native_ed25519_sign(message, sk)
            assert native_ed25519_verify(
                sig, message, pk
            ), f"Cross-validation failed for index {i}, seed={seed.hex()[:16]}..."
