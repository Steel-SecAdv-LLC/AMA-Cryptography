#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Ed25519 native C backend interop tests.

This is the most critical test file for the dependency-removal PR.
It proves that the native C Ed25519 implementation produces signatures
that are byte-identical to PyCA cryptography, and vice versa.

Tests:
- Native sign -> PyCA verify (and vice versa)
- Deterministic signatures (same seed+message -> identical bytes)
- Key format conversion (32-byte seed <-> 64-byte native key)
- RFC 8032 Section 7.1 test vectors (both backends)
"""

from __future__ import annotations

from typing import Any

import pytest

from ama_cryptography.pqc_backends import (
    ED25519_PUBLIC_KEY_BYTES,
    ED25519_SECRET_KEY_BYTES,
    ED25519_SIGNATURE_BYTES,
    _native_lib,
)

# Skip entire module if native library is not built
pytestmark = pytest.mark.skipif(
    _native_lib is None,
    reason="Native C library not built — skipping Ed25519 native tests",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pyca_available() -> bool:
    """Check if PyCA cryptography is installed and functional."""
    try:
        from cryptography.hazmat.primitives.asymmetric import (
            ed25519,
        )  # noqa: F401 — import probe for availability check (TE-001)
    except Exception:
        return False
    return True


def _native_sign_and_verify(seed: bytes, message: bytes) -> tuple[Any, ...]:
    """Sign with native C backend. Returns (pk, sk, signature)."""
    from ama_cryptography.pqc_backends import native_ed25519_keypair_from_seed, native_ed25519_sign

    pk, sk = native_ed25519_keypair_from_seed(seed)
    sig = native_ed25519_sign(message, sk)
    return pk, sk, sig


def _pyca_sign(seed: bytes, message: bytes) -> tuple[Any, ...]:
    """Sign with PyCA. Returns (pk_bytes, sig_bytes)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key()

    pk_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sig_bytes = private_key.sign(message)
    return pk_bytes, sig_bytes


def _pyca_verify(signature: bytes, message: bytes, pk_bytes: bytes) -> bool:
    """Verify with PyCA. Returns True if valid."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519

    pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes)
    try:
        pub_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Native-only tests (always run when native lib is built)
# ---------------------------------------------------------------------------


class TestNativeEd25519:
    """Tests for the native C Ed25519 implementation (no PyCA required)."""

    def test_keypair_generation(self) -> None:
        """Native keypair generation produces correct key sizes."""
        from ama_cryptography.pqc_backends import native_ed25519_keypair

        pk, sk = native_ed25519_keypair()
        assert len(pk) == ED25519_PUBLIC_KEY_BYTES
        assert len(sk) == ED25519_SECRET_KEY_BYTES
        # public key should be embedded in sk[32:64]
        assert sk[32:] == pk

    def test_deterministic_keypair(self) -> None:
        """Same seed produces identical keypair."""
        from ama_cryptography.pqc_backends import native_ed25519_keypair_from_seed

        seed = bytes(range(32))
        pk1, sk1 = native_ed25519_keypair_from_seed(seed)
        pk2, sk2 = native_ed25519_keypair_from_seed(seed)
        assert pk1 == pk2
        assert sk1 == sk2

    def test_sign_verify_roundtrip(self) -> None:
        """Native sign -> native verify succeeds."""
        from ama_cryptography.pqc_backends import native_ed25519_verify

        seed = bytes(range(32))
        message = b"test message for native roundtrip"
        pk, _sk, sig = _native_sign_and_verify(seed, message)

        assert len(sig) == ED25519_SIGNATURE_BYTES
        assert native_ed25519_verify(sig, message, pk)

    def test_verify_rejects_tampered_message(self) -> None:
        """Native verify rejects tampered message."""
        from ama_cryptography.pqc_backends import native_ed25519_verify

        seed = bytes(range(32))
        message = b"original message"
        pk, _, sig = _native_sign_and_verify(seed, message)

        assert not native_ed25519_verify(sig, b"tampered message", pk)

    def test_verify_rejects_wrong_key(self) -> None:
        """Native verify rejects signature made with different key."""
        from ama_cryptography.pqc_backends import native_ed25519_keypair, native_ed25519_verify

        seed = bytes(range(32))
        message = b"test message"
        _, _, sig = _native_sign_and_verify(seed, message)

        # Generate a different key
        other_pk, _ = native_ed25519_keypair()
        assert not native_ed25519_verify(sig, message, other_pk)

    def test_deterministic_signatures(self) -> None:
        """Same seed + message -> identical signature bytes."""
        from ama_cryptography.pqc_backends import (
            native_ed25519_keypair_from_seed,
            native_ed25519_sign,
        )

        seed = bytes(range(32))
        message = b"deterministic test"

        _, sk = native_ed25519_keypair_from_seed(seed)
        sig1 = native_ed25519_sign(message, sk)
        sig2 = native_ed25519_sign(message, sk)
        assert sig1 == sig2

    def test_empty_message(self) -> None:
        """Signing and verifying an empty message works."""
        from ama_cryptography.pqc_backends import native_ed25519_verify

        seed = bytes(range(32))
        pk, _, sig = _native_sign_and_verify(seed, b"")
        assert native_ed25519_verify(sig, b"", pk)

    def test_invalid_seed_length(self) -> None:
        """Seed of wrong length raises ValueError."""
        from ama_cryptography.pqc_backends import native_ed25519_keypair_from_seed

        with pytest.raises(ValueError, match="32 bytes"):
            native_ed25519_keypair_from_seed(b"too short")

    def test_invalid_sk_length_for_sign(self) -> None:
        """Secret key of wrong length raises ValueError."""
        from ama_cryptography.pqc_backends import native_ed25519_sign

        with pytest.raises(ValueError, match="64 bytes"):
            native_ed25519_sign(b"message", b"too short")


# ---------------------------------------------------------------------------
# Interop tests (require both native and PyCA)
# ---------------------------------------------------------------------------


requires_pyca = pytest.mark.skipif(
    not _pyca_available(),
    reason="PyCA cryptography not installed — skipping interop tests",
)


@requires_pyca
class TestEd25519Interop:
    """Cross-implementation interop tests: native C <-> PyCA cryptography."""

    def test_sign_native_verify_pyca(self) -> None:
        """Native C signatures verify with PyCA cryptography."""
        seed = bytes(range(32))
        message = b"native sign, pyca verify"

        pk, _, sig = _native_sign_and_verify(seed, message)
        assert _pyca_verify(sig, message, pk)

    def test_sign_pyca_verify_native(self) -> None:
        """PyCA signatures verify with native C implementation."""
        from ama_cryptography.pqc_backends import native_ed25519_verify

        seed = bytes(range(32))
        message = b"pyca sign, native verify"

        pk_bytes, sig = _pyca_sign(seed, message)
        assert native_ed25519_verify(sig, message, pk_bytes)

    def test_deterministic_signatures_cross_impl(self) -> None:
        """Same seed + message -> identical signature bytes in both implementations."""
        seed = bytes(range(32))
        message = b"cross-implementation deterministic test"

        _, _, native_sig = _native_sign_and_verify(seed, message)
        _, pyca_sig = _pyca_sign(seed, message)

        assert native_sig == pyca_sig, (
            f"Signature mismatch:\n" f"  native: {native_sig.hex()}\n" f"  pyca:   {pyca_sig.hex()}"
        )

    def test_key_format_compatibility(self) -> None:
        """32-byte seed -> 64-byte native key conversion is lossless."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from ama_cryptography.pqc_backends import native_ed25519_keypair_from_seed

        seed = bytes(range(32))

        # Native: seed -> (pk, sk=seed||pk)
        native_pk, native_sk = native_ed25519_keypair_from_seed(seed)

        # PyCA: seed -> pk
        pyca_private = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        pyca_pk = pyca_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        assert native_pk == pyca_pk, "Public keys must be identical from same seed"
        assert native_sk[:32] == seed, "Native SK first 32 bytes must be the seed"
        assert native_sk[32:] == native_pk, "Native SK last 32 bytes must be the public key"

    def test_multiple_messages(self) -> None:
        """Interop holds for various message sizes."""
        from ama_cryptography.pqc_backends import native_ed25519_verify

        seed = bytes(range(32))

        messages = [
            b"",
            b"a",
            b"Hello, World!",
            bytes(range(256)),
            b"\x00" * 1000,
            bytes(range(255)) * 10,  # 2550 bytes
        ]

        for msg in messages:
            # Native sign -> PyCA verify
            pk, _, native_sig = _native_sign_and_verify(seed, msg)
            assert _pyca_verify(
                native_sig, msg, pk
            ), f"PyCA failed to verify native sig for {len(msg)}-byte msg"

            # PyCA sign -> native verify
            _, pyca_sig = _pyca_sign(seed, msg)
            assert native_ed25519_verify(
                pyca_sig, msg, pk
            ), f"Native failed to verify PyCA sig for {len(msg)}-byte msg"


# ---------------------------------------------------------------------------
# RFC 8032 Section 7.1 test vectors
# ---------------------------------------------------------------------------

# Test vectors from RFC 8032, Section 7.1
# https://www.rfc-editor.org/rfc/rfc8032#section-7.1
RFC8032_VECTORS = [
    {
        # TEST 1 — empty message
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
        # TEST 2 — single byte 0x72
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
        # TEST 3 — two-byte message
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
# Note: RFC 8032 Section 7.1 also defines TEST 1024 (1023-byte message).
# Large message coverage is handled by test_multiple_messages() interop tests
# which cross-validate native C against PyCA for messages up to 2550 bytes.


class TestRFC8032Vectors:
    """RFC 8032 Section 7.1 test vector validation."""

    @pytest.mark.parametrize(
        "vector",
        RFC8032_VECTORS,
        ids=[str(v["name"]) for v in RFC8032_VECTORS],
    )
    def test_rfc8032_native(self, vector: Any) -> None:
        """RFC 8032 vectors pass with native C implementation."""
        from ama_cryptography.pqc_backends import (
            native_ed25519_keypair_from_seed,
            native_ed25519_sign,
            native_ed25519_verify,
        )

        seed = vector["secret_key_seed"]
        expected_pk = vector["public_key"]
        message = vector["message"]
        expected_sig = vector["signature"]

        # Verify keypair derivation
        pk, sk = native_ed25519_keypair_from_seed(seed)
        assert pk == expected_pk, (
            f"Public key mismatch for {vector['name']}:\n"
            f"  expected: {expected_pk.hex()}\n"
            f"  got:      {pk.hex()}"
        )

        # Verify signature generation
        sig = native_ed25519_sign(message, sk)
        assert sig == expected_sig, (
            f"Signature mismatch for {vector['name']}:\n"
            f"  expected: {expected_sig.hex()}\n"
            f"  got:      {sig.hex()}"
        )

        # Verify signature verification
        assert native_ed25519_verify(sig, message, pk)

    @requires_pyca
    @pytest.mark.parametrize(
        "vector",
        RFC8032_VECTORS[:3],
        ids=[str(v["name"]) for v in RFC8032_VECTORS[:3]],
    )
    def test_rfc8032_pyca(self, vector: Any) -> None:
        """RFC 8032 vectors pass with PyCA cryptography."""
        seed = vector["secret_key_seed"]
        expected_pk = vector["public_key"]
        message = vector["message"]
        expected_sig = vector["signature"]

        pk_bytes, sig = _pyca_sign(seed, message)
        assert pk_bytes == expected_pk
        assert sig == expected_sig
        assert _pyca_verify(sig, message, pk_bytes)


# ---------------------------------------------------------------------------
# Provider-level integration tests
# ---------------------------------------------------------------------------


class TestEd25519ProviderNative:
    """Tests for Ed25519Provider with native backend."""

    def test_provider_generates_valid_keypair(self) -> None:
        """Ed25519Provider.generate_keypair() works with native backend."""
        from ama_cryptography.crypto_api import CryptoBackend, Ed25519Provider

        provider = Ed25519Provider(backend=CryptoBackend.C_LIBRARY)
        keypair = provider.generate_keypair()

        assert len(keypair.public_key) == 32
        assert len(keypair.secret_key) == 32  # 32-byte seed returned

    def test_provider_sign_verify_roundtrip(self) -> None:
        """Ed25519Provider sign/verify roundtrip works."""
        from ama_cryptography.crypto_api import CryptoBackend, Ed25519Provider

        provider = Ed25519Provider(backend=CryptoBackend.C_LIBRARY)
        keypair = provider.generate_keypair()

        message = b"provider integration test"
        sig = provider.sign(message, keypair.secret_key)

        assert provider.verify(message, sig.signature, keypair.public_key)
        assert not provider.verify(b"wrong message", sig.signature, keypair.public_key)
