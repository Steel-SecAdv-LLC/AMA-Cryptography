#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Tests for new cryptographic primitives:
- FALCON-512 (FN-DSA, FIPS 206 draft)
- FROST threshold Ed25519 (RFC 9591)
- SPAKE2 PAKE (RFC 9382)
"""

import ctypes
import os
from typing import Any

import pytest

# Determine if the native C library is available
try:
                from ama_cryptography.pqc_backends import (
                    FALCON_AVAILABLE,
                    FALCON_PUBLIC_KEY_BYTES,
                    FALCON_SECRET_KEY_BYTES,
                    FALCON_SIGNATURE_MAX_BYTES,
                    FROST_AVAILABLE,
                    FROST_COMMITMENT_BYTES,
                    FROST_NONCE_BYTES,
                    FROST_SHARE_BYTES,
                    FROST_SIG_SHARE_BYTES,
                    SPAKE2_AVAILABLE,
                    SPAKE2_CONFIRM_BYTES,
                    SPAKE2_KEY_BYTES,
                    SPAKE2_MSG_BYTES,
                    _native_lib,
                    falcon512_complete_keypair,
                    falcon512_sign,
                    falcon512_verify,
                )

except ImportError:
    FALCON_AVAILABLE = False
    FROST_AVAILABLE = False
    SPAKE2_AVAILABLE = False

skip_no_falcon = pytest.mark.skipif(
    not FALCON_AVAILABLE,
    reason="FALCON-512 not available in native library",
)
skip_no_frost = pytest.mark.skipif(
    not FROST_AVAILABLE,
    reason="FROST not available in native library",
)
skip_no_spake2 = pytest.mark.skipif(
    not SPAKE2_AVAILABLE,
    reason=(
        "SPAKE2 not built on Windows (requires __uint128_t)"
        if os.name == "nt"
        else "SPAKE2 not available in native library"
    ),
)


# ===========================================================================
# FALCON-512 (FN-DSA) TESTS
# ===========================================================================


@skip_no_falcon
class TestFalcon512:
    """FALCON-512 digital signature tests (FIPS 206 draft)."""

    def test_keypair_generation(self) -> None:
        """Generate FALCON-512 keypair with complete NTRU basis."""
        pk = ctypes.create_string_buffer(FALCON_PUBLIC_KEY_BYTES)
        sk = ctypes.create_string_buffer(FALCON_SECRET_KEY_BYTES)
        rc = falcon512_complete_keypair(pk, sk)
        assert rc == 0, f"Keypair generation failed: {rc}"
        # Public key should be non-zero
        assert pk.raw != b"\x00" * FALCON_PUBLIC_KEY_BYTES
        # Secret key should be non-zero
        assert sk.raw != b"\x00" * FALCON_SECRET_KEY_BYTES

    def test_sign_verify_roundtrip(self) -> None:
        """Sign a message and verify the signature."""
        pk = ctypes.create_string_buffer(FALCON_PUBLIC_KEY_BYTES)
        sk = ctypes.create_string_buffer(FALCON_SECRET_KEY_BYTES)
        rc = falcon512_complete_keypair(pk, sk)
        assert rc == 0

        message = b"FALCON-512 test message for FIPS 206 draft compliance"
        sig = ctypes.create_string_buffer(FALCON_SIGNATURE_MAX_BYTES)
        sig_len = ctypes.c_size_t(0)

        rc = falcon512_sign(sig, sig_len, message, len(message), sk)
        assert rc == 0, f"Signing failed: {rc}"
        assert sig_len.value > 0
        assert sig_len.value <= FALCON_SIGNATURE_MAX_BYTES

        rc = falcon512_verify(message, len(message), sig, sig_len.value, pk)
        assert rc == 0, f"Verification failed: {rc}"

    def test_verify_wrong_message_fails(self) -> None:
        """Verification fails with wrong message."""
        pk = ctypes.create_string_buffer(FALCON_PUBLIC_KEY_BYTES)
        sk = ctypes.create_string_buffer(FALCON_SECRET_KEY_BYTES)
        falcon512_complete_keypair(pk, sk)

        message = b"Original message"
        sig = ctypes.create_string_buffer(FALCON_SIGNATURE_MAX_BYTES)
        sig_len = ctypes.c_size_t(0)
        falcon512_sign(sig, sig_len, message, len(message), sk)

        wrong_message = b"Tampered message"
        rc = falcon512_verify(wrong_message, len(wrong_message), sig, sig_len.value, pk)
        assert rc != 0, "Verification should fail with wrong message"

    def test_verify_wrong_key_fails(self) -> None:
        """Verification fails with wrong public key."""
        pk1 = ctypes.create_string_buffer(FALCON_PUBLIC_KEY_BYTES)
        sk1 = ctypes.create_string_buffer(FALCON_SECRET_KEY_BYTES)
        falcon512_complete_keypair(pk1, sk1)

        pk2 = ctypes.create_string_buffer(FALCON_PUBLIC_KEY_BYTES)
        sk2 = ctypes.create_string_buffer(FALCON_SECRET_KEY_BYTES)
        falcon512_complete_keypair(pk2, sk2)

        message = b"Message signed with key 1"
        sig = ctypes.create_string_buffer(FALCON_SIGNATURE_MAX_BYTES)
        sig_len = ctypes.c_size_t(0)
        falcon512_sign(sig, sig_len, message, len(message), sk1)

        rc = falcon512_verify(message, len(message), sig, sig_len.value, pk2)
        assert rc != 0, "Verification should fail with wrong key"

    def test_sign_empty_message(self) -> None:
        """Sign and verify an empty message."""
        pk = ctypes.create_string_buffer(FALCON_PUBLIC_KEY_BYTES)
        sk = ctypes.create_string_buffer(FALCON_SECRET_KEY_BYTES)
        falcon512_complete_keypair(pk, sk)

        message = b""
        sig = ctypes.create_string_buffer(FALCON_SIGNATURE_MAX_BYTES)
        sig_len = ctypes.c_size_t(0)
        rc = falcon512_sign(sig, sig_len, message, 0, sk)
        assert rc == 0

        rc = falcon512_verify(message, 0, sig, sig_len.value, pk)
        assert rc == 0

    def test_multiple_signatures_unique(self) -> None:
        """Each signature should be unique (randomized nonce)."""
        pk = ctypes.create_string_buffer(FALCON_PUBLIC_KEY_BYTES)
        sk = ctypes.create_string_buffer(FALCON_SECRET_KEY_BYTES)
        falcon512_complete_keypair(pk, sk)

        message = b"Same message, different signatures"
        sig1 = ctypes.create_string_buffer(FALCON_SIGNATURE_MAX_BYTES)
        sig2 = ctypes.create_string_buffer(FALCON_SIGNATURE_MAX_BYTES)
        sig_len1 = ctypes.c_size_t(0)
        sig_len2 = ctypes.c_size_t(0)

        falcon512_sign(sig1, sig_len1, message, len(message), sk)
        falcon512_sign(sig2, sig_len2, message, len(message), sk)

        assert sig1.raw[: sig_len1.value] != sig2.raw[: sig_len2.value]

    def test_null_params_rejected(self) -> None:
        """NULL parameters should be rejected."""
        rc = _native_lib.ama_falcon512_keypair(None, None)
        assert rc != 0


# ===========================================================================
# FROST THRESHOLD ED25519 TESTS
# ===========================================================================


@skip_no_frost
class TestFrostThreshold:
    """FROST threshold Ed25519 signature tests (RFC 9591)."""

    def test_keygen_2_of_3(self) -> None:
        """Generate 2-of-3 threshold key shares."""
        group_pk = ctypes.create_string_buffer(32)
        shares = ctypes.create_string_buffer(3 * FROST_SHARE_BYTES)

        rc = _native_lib.ama_frost_keygen_trusted_dealer(
            ctypes.c_uint8(2), ctypes.c_uint8(3), group_pk, shares, None
        )
        assert rc == 0, f"Keygen failed: {rc}"
        assert group_pk.raw != b"\x00" * 32

    def test_keygen_invalid_threshold(self) -> None:
        """Threshold < 2 or > n should fail."""
        group_pk = ctypes.create_string_buffer(32)
        shares = ctypes.create_string_buffer(3 * FROST_SHARE_BYTES)

        # threshold = 1 (too low)
        rc = _native_lib.ama_frost_keygen_trusted_dealer(
            ctypes.c_uint8(1), ctypes.c_uint8(3), group_pk, shares, None
        )
        assert rc != 0

        # threshold > num_participants
        rc = _native_lib.ama_frost_keygen_trusted_dealer(
            ctypes.c_uint8(4), ctypes.c_uint8(3), group_pk, shares, None
        )
        assert rc != 0

    def test_round1_commit(self) -> None:
        """Generate nonce commitments."""
        group_pk = ctypes.create_string_buffer(32)
        shares = ctypes.create_string_buffer(3 * FROST_SHARE_BYTES)
        _native_lib.ama_frost_keygen_trusted_dealer(
            ctypes.c_uint8(2), ctypes.c_uint8(3), group_pk, shares, None
        )

        nonce = ctypes.create_string_buffer(FROST_NONCE_BYTES)
        commitment = ctypes.create_string_buffer(FROST_COMMITMENT_BYTES)

        rc = _native_lib.ama_frost_round1_commit(nonce, commitment, shares)
        assert rc == 0
        assert nonce.raw != b"\x00" * FROST_NONCE_BYTES
        assert commitment.raw != b"\x00" * FROST_COMMITMENT_BYTES

    def test_full_2_of_3_signing(self) -> None:
        """Full 2-of-3 threshold signing protocol."""
        # Key generation
        group_pk = ctypes.create_string_buffer(32)
        shares = ctypes.create_string_buffer(3 * FROST_SHARE_BYTES)
        rc = _native_lib.ama_frost_keygen_trusted_dealer(
            ctypes.c_uint8(2), ctypes.c_uint8(3), group_pk, shares, None
        )
        assert rc == 0

        # Signers: participants 1 and 2 (indices 1, 2)
        signer_indices = bytes([1, 2])
        num_signers = 2

        # Round 1: generate commitments for both signers
        nonce1 = ctypes.create_string_buffer(FROST_NONCE_BYTES)
        commit1 = ctypes.create_string_buffer(FROST_COMMITMENT_BYTES)
        rc = _native_lib.ama_frost_round1_commit(
            nonce1, commit1, ctypes.c_char_p(shares.raw[0:FROST_SHARE_BYTES])
        )
        assert rc == 0

        nonce2 = ctypes.create_string_buffer(FROST_NONCE_BYTES)
        commit2 = ctypes.create_string_buffer(FROST_COMMITMENT_BYTES)
        rc = _native_lib.ama_frost_round1_commit(
            nonce2, commit2, ctypes.c_char_p(shares.raw[FROST_SHARE_BYTES : 2 * FROST_SHARE_BYTES])
        )
        assert rc == 0

        # Collect all commitments
        all_commitments = commit1.raw + commit2.raw

        message = b"FROST threshold signature test message"

        # Round 2: generate signature shares
        sig_share1 = ctypes.create_string_buffer(FROST_SIG_SHARE_BYTES)
        rc = _native_lib.ama_frost_round2_sign(
            sig_share1,
            message,
            len(message),
            ctypes.c_char_p(shares.raw[0:FROST_SHARE_BYTES]),
            ctypes.c_uint8(1),
            nonce1,
            all_commitments,
            signer_indices,
            ctypes.c_uint8(num_signers),
            group_pk,
        )
        assert rc == 0

        sig_share2 = ctypes.create_string_buffer(FROST_SIG_SHARE_BYTES)
        rc = _native_lib.ama_frost_round2_sign(
            sig_share2,
            message,
            len(message),
            ctypes.c_char_p(shares.raw[FROST_SHARE_BYTES : 2 * FROST_SHARE_BYTES]),
            ctypes.c_uint8(2),
            nonce2,
            all_commitments,
            signer_indices,
            ctypes.c_uint8(num_signers),
            group_pk,
        )
        assert rc == 0

        # Aggregate signature
        all_shares = sig_share1.raw + sig_share2.raw
        signature = ctypes.create_string_buffer(64)
        rc = _native_lib.ama_frost_aggregate(
            signature,
            all_shares,
            all_commitments,
            signer_indices,
            ctypes.c_uint8(num_signers),
            message,
            len(message),
            group_pk,
        )
        assert rc == 0
        assert signature.raw != b"\x00" * 64

    def test_keygen_with_provided_secret(self) -> None:
        """Keygen with a provided secret key."""
        secret = os.urandom(32)
        group_pk = ctypes.create_string_buffer(32)
        shares = ctypes.create_string_buffer(5 * FROST_SHARE_BYTES)

        rc = _native_lib.ama_frost_keygen_trusted_dealer(
            ctypes.c_uint8(3),
            ctypes.c_uint8(5),
            group_pk,
            shares,
            secret,
        )
        assert rc == 0


# ===========================================================================
# SPAKE2 PAKE TESTS
# ===========================================================================


@skip_no_spake2
class TestSpake2:
    """SPAKE2 password-authenticated key exchange tests (RFC 9382)."""

    def _run_spake2_handshake(
        self,
        password: bytes,
        id_a: bytes = b"client",
        id_b: bytes = b"server",
    ) -> "tuple[Any, Any, Any, Any, Any, Any]":
        """Run a complete SPAKE2 handshake, return (key_a, key_b)."""
        # Create client and server contexts
        ctx_a = _native_lib.ama_spake2_new()
        ctx_b = _native_lib.ama_spake2_new()
        assert ctx_a is not None
        assert ctx_b is not None

        try:
            # Initialize both sides with same password
            rc = _native_lib.ama_spake2_init(
                ctx_a,
                0,
                id_a,
                len(id_a),
                id_b,
                len(id_b),
                password,
                len(password),
            )
            assert rc == 0, f"Client init failed: {rc}"

            rc = _native_lib.ama_spake2_init(
                ctx_b,
                1,
                id_a,
                len(id_a),
                id_b,
                len(id_b),
                password,
                len(password),
            )
            assert rc == 0, f"Server init failed: {rc}"

            # Generate messages
            msg_a = ctypes.create_string_buffer(SPAKE2_MSG_BYTES)
            msg_a_len = ctypes.c_size_t(0)
            rc = _native_lib.ama_spake2_generate_msg(ctx_a, msg_a, ctypes.byref(msg_a_len))
            assert rc == 0

            msg_b = ctypes.create_string_buffer(SPAKE2_MSG_BYTES)
            msg_b_len = ctypes.c_size_t(0)
            rc = _native_lib.ama_spake2_generate_msg(ctx_b, msg_b, ctypes.byref(msg_b_len))
            assert rc == 0

            # Process peer messages
            key_a = ctypes.create_string_buffer(SPAKE2_KEY_BYTES)
            confirm_a = ctypes.create_string_buffer(SPAKE2_CONFIRM_BYTES)
            expect_a = ctypes.create_string_buffer(SPAKE2_CONFIRM_BYTES)
            rc = _native_lib.ama_spake2_process_msg(
                ctx_a,
                msg_b,
                SPAKE2_MSG_BYTES,
                key_a,
                confirm_a,
                expect_a,
            )
            assert rc == 0

            key_b = ctypes.create_string_buffer(SPAKE2_KEY_BYTES)
            confirm_b = ctypes.create_string_buffer(SPAKE2_CONFIRM_BYTES)
            expect_b = ctypes.create_string_buffer(SPAKE2_CONFIRM_BYTES)
            rc = _native_lib.ama_spake2_process_msg(
                ctx_b,
                msg_a,
                SPAKE2_MSG_BYTES,
                key_b,
                confirm_b,
                expect_b,
            )
            assert rc == 0

            return key_a.raw, key_b.raw, ctx_a, ctx_b, confirm_a, confirm_b
        except Exception:
            _native_lib.ama_spake2_free(ctx_a)
            _native_lib.ama_spake2_free(ctx_b)
            raise

    def test_matching_passwords_derive_same_key(self) -> None:
        """Both parties derive the same shared key with matching passwords."""
        key_a, key_b, ctx_a, ctx_b, _, _ = self._run_spake2_handshake(
            b"correct-horse-battery-staple"
        )
        try:
            assert key_a == key_b, "Shared keys should match"
            assert key_a != b"\x00" * SPAKE2_KEY_BYTES
        finally:
            _native_lib.ama_spake2_free(ctx_a)
            _native_lib.ama_spake2_free(ctx_b)

    def test_different_passwords_derive_different_keys(self) -> None:
        """Different passwords produce different shared keys."""
        key_a1, _, ctx_a1, ctx_b1, _, _ = self._run_spake2_handshake(b"password1")
        key_a2, _, ctx_a2, ctx_b2, _, _ = self._run_spake2_handshake(b"password2")
        try:
            assert key_a1 != key_a2, "Different passwords should give different keys"
        finally:
            _native_lib.ama_spake2_free(ctx_a1)
            _native_lib.ama_spake2_free(ctx_b1)
            _native_lib.ama_spake2_free(ctx_a2)
            _native_lib.ama_spake2_free(ctx_b2)

    def test_confirmation_verification(self) -> None:
        """Confirmation MACs verify correctly."""
        _key_a, _key_b, ctx_a, ctx_b, confirm_a, confirm_b = self._run_spake2_handshake(
            b"test-password"
        )
        try:
            # Client verifies server's confirmation
            rc = _native_lib.ama_spake2_verify_confirm(ctx_a, confirm_b, SPAKE2_CONFIRM_BYTES)
            assert rc == 0, "Client should verify server's confirmation"

            # Server verifies client's confirmation
            rc = _native_lib.ama_spake2_verify_confirm(ctx_b, confirm_a, SPAKE2_CONFIRM_BYTES)
            assert rc == 0, "Server should verify client's confirmation"
        finally:
            _native_lib.ama_spake2_free(ctx_a)
            _native_lib.ama_spake2_free(ctx_b)

    def test_wrong_confirmation_rejected(self) -> None:
        """Wrong confirmation MAC is rejected."""
        _, _, ctx_a, ctx_b, _, confirm_b = self._run_spake2_handshake(b"test-password")
        try:
            # Tamper with confirmation
            bad_confirm = bytearray(confirm_b.raw)
            bad_confirm[0] ^= 0xFF
            rc = _native_lib.ama_spake2_verify_confirm(
                ctx_a, bytes(bad_confirm), SPAKE2_CONFIRM_BYTES
            )
            assert rc != 0, "Tampered confirmation should be rejected"
        finally:
            _native_lib.ama_spake2_free(ctx_a)
            _native_lib.ama_spake2_free(ctx_b)

    def test_empty_identities(self) -> None:
        """SPAKE2 works with empty identities."""
        key_a, key_b, ctx_a, ctx_b, _, _ = self._run_spake2_handshake(
            b"password",
            id_a=b"",
            id_b=b"",
        )
        try:
            assert key_a == key_b
        finally:
            _native_lib.ama_spake2_free(ctx_a)
            _native_lib.ama_spake2_free(ctx_b)

    def test_context_cleanup(self) -> None:
        """ama_spake2_free is NULL-safe."""
        _native_lib.ama_spake2_free(None)  # Should not crash

    def test_invalid_role_rejected(self) -> None:
        """Invalid role (not 0 or 1) is rejected."""
        ctx = _native_lib.ama_spake2_new()
        assert ctx is not None
        try:
            rc = _native_lib.ama_spake2_init(ctx, 2, b"a", 1, b"b", 1, b"pw", 2)
            assert rc != 0
        finally:
            _native_lib.ama_spake2_free(ctx)
