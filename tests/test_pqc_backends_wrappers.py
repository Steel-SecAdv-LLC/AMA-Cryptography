#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Coverage closure for the native wrapper functions in
``ama_cryptography.pqc_backends`` (X25519, Argon2id, ChaCha20-Poly1305,
secp256k1, deterministic keygen, FROST).

The happy path for each primitive is tested in other suites; this file
concentrates on input validation branches (length / range / error return
codes) that are easy to exercise without needing additional fixtures but
were previously uncovered.
"""

from __future__ import annotations

import warnings

import pytest

from ama_cryptography import pqc_backends as pq

skip_no_native = pytest.mark.skipif(pq._native_lib is None, reason="Native C library not built")


# ---------------------------------------------------------------------------
# X25519 validation branches
# ---------------------------------------------------------------------------


@skip_no_native
@pytest.mark.skipif(not pq._X25519_NATIVE_AVAILABLE, reason="X25519 backend not built")
class TestX25519Validation:
    def test_keypair_generates_32_bytes(self) -> None:
        pk, sk = pq.native_x25519_keypair()
        assert len(pk) == 32 and len(sk) == 32

    def test_key_exchange_wrong_sk_length(self) -> None:
        _pk_other, _sk_other = pq.native_x25519_keypair()
        with pytest.raises(ValueError, match="32 bytes"):
            pq.native_x25519_key_exchange(b"\x00" * 16, _pk_other)

    def test_key_exchange_wrong_pk_length(self) -> None:
        _pk, sk = pq.native_x25519_keypair()
        with pytest.raises(ValueError, match="32 bytes"):
            pq.native_x25519_key_exchange(bytes(sk), b"\x00" * 16)

    def test_round_trip(self) -> None:
        alice_pk, alice_sk = pq.native_x25519_keypair()
        bob_pk, bob_sk = pq.native_x25519_keypair()
        ss_ab = pq.native_x25519_key_exchange(bytes(alice_sk), bob_pk)
        ss_ba = pq.native_x25519_key_exchange(bytes(bob_sk), alice_pk)
        assert ss_ab == ss_ba
        assert len(ss_ab) == 32


@skip_no_native
@pytest.mark.skipif(not pq._X25519_NATIVE_AVAILABLE, reason="X25519 backend not built")
class TestX25519Batch:
    """Coverage for ``native_x25519_scalarmult_batch`` (additive batch API)."""

    def test_empty_batch_returns_empty_list(self) -> None:
        # count==0 short-circuits in C and Python — must not touch the
        # native lib (still safe with native_lib loaded; just a no-op).
        assert pq.native_x25519_scalarmult_batch([], []) == []

    def test_length_mismatch_raises(self) -> None:
        pk, sk = pq.native_x25519_keypair()
        with pytest.raises(ValueError, match="batch length mismatch"):
            pq.native_x25519_scalarmult_batch([bytes(sk), bytes(sk)], [bytes(pk)])

    def test_wrong_scalar_size_raises(self) -> None:
        pk, _sk = pq.native_x25519_keypair()
        # 16-byte scalar but pk is 32 — caught by per-element validation
        # (not a post-join blob length check, which mixed-size elements
        # could slip past, e.g. 16+48 == 2*32).
        with pytest.raises(ValueError, match=r"scalar at index 0 must be 32 bytes"):
            pq.native_x25519_scalarmult_batch([b"\x00" * 16], [bytes(pk)])

    def test_wrong_point_size_raises(self) -> None:
        _pk, sk = pq.native_x25519_keypair()
        with pytest.raises(ValueError, match=r"point at index 0 must be 32 bytes"):
            pq.native_x25519_scalarmult_batch([bytes(sk)], [b"\x00" * 16])

    def test_mixed_size_elements_raises(self) -> None:
        # 16-byte + 48-byte scalars sum to 64 == 2*32 — would slip past a
        # post-join blob-length check.  Per-element validation catches the
        # first short element by index.  Regression-pinned per Copilot
        # review on PR #273.
        pk, _sk = pq.native_x25519_keypair()
        with pytest.raises(ValueError, match=r"scalar at index 0 must be 32 bytes"):
            pq.native_x25519_scalarmult_batch([b"\x00" * 16, b"\x11" * 48], [bytes(pk), bytes(pk)])

    def test_non_bytes_scalar_raises(self) -> None:
        # `int` (or any non-bytes-like) scalar should fail the per-element
        # type check rather than producing a cryptic ctypes error.
        pk, _sk = pq.native_x25519_keypair()
        with pytest.raises(ValueError, match=r"scalar at index 0 must be bytes-like"):
            pq.native_x25519_scalarmult_batch(
                [12345],  # type: ignore[list-item]  # int stand-in for non-bytes-like — exercises per-element type rejection (XB-001)
                [bytes(pk)],
            )

    def test_batch_matches_sequential(self) -> None:
        # Build 7 independent (sk, peer_pk) pairs — 7 isn't a multiple of
        # 4, so this exercises both the SIMD prefix (when AVX2 is opted
        # in) and the scalar tail.
        scalars: list[bytes] = []
        points: list[bytes] = []
        expected: list[bytes] = []
        for _ in range(7):
            _our_pk, our_sk = pq.native_x25519_keypair()
            their_pk, _their_sk = pq.native_x25519_keypair()
            scalars.append(bytes(our_sk))
            points.append(bytes(their_pk))
            expected.append(pq.native_x25519_key_exchange(bytes(our_sk), bytes(their_pk)))
        got = pq.native_x25519_scalarmult_batch(scalars, points)
        assert got == expected, "batch must be byte-identical to sequential single-shot"

    def test_low_order_rejection(self) -> None:
        # u=0 is the canonical low-order point; the batch must surface
        # AMA_ERROR_CRYPTO as RuntimeError without returning partial output.
        _pk, sk = pq.native_x25519_keypair()
        with pytest.raises(RuntimeError, match="batch scalar-mult failed"):
            pq.native_x25519_scalarmult_batch([bytes(sk)], [b"\x00" * 32])


# ---------------------------------------------------------------------------
# Argon2id validation branches
# ---------------------------------------------------------------------------


@skip_no_native
@pytest.mark.skipif(not pq._ARGON2_NATIVE_AVAILABLE, reason="Argon2id backend not built")
class TestArgon2idValidation:
    _GOOD_SALT = b"0" * 16

    def test_basic_derivation(self) -> None:
        out = pq.native_argon2id(b"hunter2", self._GOOD_SALT, t_cost=1, m_cost=8, parallelism=1)
        assert isinstance(out, bytes) and len(out) == 32

    def test_salt_too_short(self) -> None:
        with pytest.raises(ValueError, match="salt"):
            pq.native_argon2id(b"pw", b"short", t_cost=1, m_cost=8, parallelism=1)

    def test_output_too_short(self) -> None:
        with pytest.raises(ValueError, match="out_len"):
            pq.native_argon2id(b"pw", self._GOOD_SALT, out_len=2)

    def test_output_too_large_rejected_before_allocation(self) -> None:
        # out_len above the application-sane cap
        # (``_ARGON2ID_MAX_TAG_LEN`` = 1024 bytes, 32× the default tag)
        # must be rejected before ``ctypes.create_string_buffer(
        # out_len)`` is called, so a caller-controlled length cannot
        # become a memory-exhaustion / DoS vector on a memory-
        # constrained host.  Mirrors the cap on the C-side
        # ``ama_argon2id_core`` / ``ama_argon2id_legacy_verify`` (see
        # ``AMA_ARGON2ID_MAX_TAG_LEN`` in ``include/ama_cryptography.h``
        # — PR #258 review thread r31xxxxxxxx).
        with pytest.raises(ValueError, match="out_len"):
            pq.native_argon2id(b"pw", self._GOOD_SALT, out_len=2**32)
        # Just-above-cap value is also rejected (defense in depth:
        # confirms the boundary is at 1024 not UINT32_MAX).
        with pytest.raises(ValueError, match="out_len"):
            pq.native_argon2id(b"pw", self._GOOD_SALT, out_len=pq._ARGON2ID_MAX_TAG_LEN + 1)

    def test_t_cost_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="t_cost"):
            pq.native_argon2id(b"pw", self._GOOD_SALT, t_cost=0)

    def test_parallelism_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="parallelism"):
            pq.native_argon2id(b"pw", self._GOOD_SALT, parallelism=0)

    def test_m_cost_too_small(self) -> None:
        # m_cost must be >= 8 * parallelism; use parallelism=2 so 8 is too small.
        with pytest.raises(ValueError, match="m_cost"):
            pq.native_argon2id(b"pw", self._GOOD_SALT, m_cost=1, parallelism=2)


# ---------------------------------------------------------------------------
# Argon2id pre-shim legacy verify shim (audit 3a).
#
# The shim is only exposed by native libraries that link the
# ``ama_argon2id_legacy_verify`` symbol.  Libraries built without it must
# raise ``RuntimeError`` at call time rather than silently dispatching to
# the fixed derivation — the wrapper detects this with ``hasattr`` on
# ``_native_lib`` and refuses.  Feature-based gating (not version-string
# gating) is used throughout so the tests stay accurate across version
# bumps.
# ---------------------------------------------------------------------------


@skip_no_native
@pytest.mark.skipif(not pq._ARGON2_NATIVE_AVAILABLE, reason="Argon2id backend not built")
@pytest.mark.skipif(
    # The tests in this class exercise both halves of the legacy shim:
    # ``native_argon2id_legacy`` (derivation, used by ``_legacy_tag`` to
    # produce reference tags) and ``native_argon2id_legacy_verify``
    # (constant-time compare).  Skip the whole class unless the native
    # library exports *both* symbols — a build that exports only one
    # would make ``_legacy_tag`` raise ``RuntimeError`` and the suite
    # fail with an error that looks like a test bug rather than a
    # missing-feature skip.
    pq._native_lib is None
    or not hasattr(pq._native_lib, "ama_argon2id_legacy_verify")
    or not hasattr(pq._native_lib, "ama_argon2id_legacy"),
    reason=(
        "Native library does not export both ama_argon2id_legacy and "
        "ama_argon2id_legacy_verify (rebuild required)"
    ),
)
class TestArgon2idLegacyVerify:
    _SALT = b"legacy-migration"
    _PW = b"hunter2"
    _T = 1
    _M = 16
    _P = 1
    _OUT_LEN = 32

    def _legacy_tag(self) -> bytes:
        """Derive a legacy (pre-2.1.5) tag via the public wrapper.

        We exercise ``native_argon2id_legacy`` because ``native_argon2id``
        is always the spec-compliant path — a tag derived by it would not
        verify through the legacy shim (by design).  The wrapper is
        contracted to emit a ``SecurityWarning`` every call; migration
        tooling (and these tests) suppress it explicitly.  A dedicated
        test below asserts the warning IS raised when left unsuppressed.
        """
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", pq.SecurityWarning)
            return pq.native_argon2id_legacy(
                self._PW,
                self._SALT,
                t_cost=self._T,
                m_cost=self._M,
                parallelism=self._P,
                out_len=self._OUT_LEN,
            )

    def test_verify_accepts_legacy_tag(self) -> None:
        tag = self._legacy_tag()
        assert (
            pq.native_argon2id_legacy_verify(
                self._PW,
                self._SALT,
                tag,
                t_cost=self._T,
                m_cost=self._M,
                parallelism=self._P,
            )
            is True
        )

    def test_verify_rejects_bit_flip(self) -> None:
        tag = bytearray(self._legacy_tag())
        tag[0] ^= 0x01
        assert (
            pq.native_argon2id_legacy_verify(
                self._PW,
                self._SALT,
                bytes(tag),
                t_cost=self._T,
                m_cost=self._M,
                parallelism=self._P,
            )
            is False
        )

    def test_verify_rejects_rfc_tag(self) -> None:
        """A tag produced by the RFC-compliant derivation sits in a
        different bit-space and must not verify through the legacy path."""
        rfc_tag = pq.native_argon2id(
            self._PW,
            self._SALT,
            t_cost=self._T,
            m_cost=self._M,
            parallelism=self._P,
            out_len=self._OUT_LEN,
        )
        assert (
            pq.native_argon2id_legacy_verify(
                self._PW,
                self._SALT,
                rfc_tag,
                t_cost=self._T,
                m_cost=self._M,
                parallelism=self._P,
            )
            is False
        )

    def test_short_tag_rejected(self) -> None:
        with pytest.raises(ValueError, match="expected_tag"):
            pq.native_argon2id_legacy_verify(
                self._PW,
                self._SALT,
                b"xxx",
                t_cost=self._T,
                m_cost=self._M,
                parallelism=self._P,
            )

    def test_short_salt_rejected(self) -> None:
        with pytest.raises(ValueError, match="salt"):
            pq.native_argon2id_legacy_verify(
                self._PW,
                b"short",
                b"x" * 32,
                t_cost=self._T,
                m_cost=self._M,
                parallelism=self._P,
            )

    def test_legacy_derive_emits_security_warning(self) -> None:
        """``native_argon2id_legacy`` must emit a SecurityWarning every call.

        The derivation reproduces the pre-2.1.5 blake2b_long bug on
        purpose; a runtime warning makes accidental use in a production
        path loud rather than silent. Fires once per call (not once
        per process) so call-site auditing catches every invocation.
        """
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            pq.native_argon2id_legacy(
                self._PW,
                self._SALT,
                t_cost=self._T,
                m_cost=self._M,
                parallelism=self._P,
                out_len=self._OUT_LEN,
            )
        security_warnings = [w for w in caught if issubclass(w.category, pq.SecurityWarning)]
        assert len(security_warnings) == 1, "expected exactly one SecurityWarning"
        message = str(security_warnings[0].message)
        assert "native_argon2id_legacy" in message
        assert "migration" in message.lower() or "pre-2.1.5" in message

    def test_legacy_verify_does_not_emit_security_warning(self) -> None:
        """``native_argon2id_legacy_verify`` is the intended migration path
        and must stay quiet — a warning on every verify call during a
        rotation would drown the operator in noise. The footgun live
        entirely on the derivation side.
        """
        # Produce a tag via the raw derivation (warning suppressed inside
        # ``_legacy_tag``) so we can test the verify call in isolation.
        tag = self._legacy_tag()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            pq.native_argon2id_legacy_verify(
                self._PW,
                self._SALT,
                tag,
                t_cost=self._T,
                m_cost=self._M,
                parallelism=self._P,
            )
        security_warnings = [w for w in caught if issubclass(w.category, pq.SecurityWarning)]
        assert (
            security_warnings == []
        ), f"_verify must stay silent; saw {[str(w.message) for w in security_warnings]}"


# ---------------------------------------------------------------------------
# ChaCha20-Poly1305 validation branches
# ---------------------------------------------------------------------------


@skip_no_native
@pytest.mark.skipif(
    not pq._CHACHA20_POLY1305_NATIVE_AVAILABLE,
    reason="ChaCha20-Poly1305 backend not built",
)
class TestChaCha20Poly1305Validation:
    _KEY = b"\x01" * 32
    _NONCE = b"\x02" * 12

    def test_round_trip(self) -> None:
        ct, tag = pq.native_chacha20poly1305_encrypt(self._KEY, self._NONCE, b"hello", b"aad")
        assert len(ct) == 5 and len(tag) == 16
        pt = pq.native_chacha20poly1305_decrypt(self._KEY, self._NONCE, ct, tag, b"aad")
        assert pt == b"hello"

    def test_round_trip_empty_plaintext(self) -> None:
        ct, tag = pq.native_chacha20poly1305_encrypt(self._KEY, self._NONCE, b"", b"")
        assert ct == b"" and len(tag) == 16
        pt = pq.native_chacha20poly1305_decrypt(self._KEY, self._NONCE, ct, tag, b"")
        assert pt == b""

    def test_encrypt_wrong_key(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            pq.native_chacha20poly1305_encrypt(b"\x00" * 16, self._NONCE, b"x")

    def test_encrypt_wrong_nonce(self) -> None:
        with pytest.raises(ValueError, match="12 bytes"):
            pq.native_chacha20poly1305_encrypt(self._KEY, b"\x00" * 8, b"x")

    def test_decrypt_wrong_key(self) -> None:
        ct, tag = pq.native_chacha20poly1305_encrypt(self._KEY, self._NONCE, b"x")
        with pytest.raises(ValueError, match="32 bytes"):
            pq.native_chacha20poly1305_decrypt(b"\x00" * 16, self._NONCE, ct, tag)

    def test_decrypt_wrong_nonce(self) -> None:
        ct, tag = pq.native_chacha20poly1305_encrypt(self._KEY, self._NONCE, b"x")
        with pytest.raises(ValueError, match="12 bytes"):
            pq.native_chacha20poly1305_decrypt(self._KEY, b"\x00" * 8, ct, tag)

    def test_decrypt_wrong_tag_length(self) -> None:
        ct, _tag = pq.native_chacha20poly1305_encrypt(self._KEY, self._NONCE, b"x")
        with pytest.raises(ValueError, match="tag"):
            pq.native_chacha20poly1305_decrypt(self._KEY, self._NONCE, ct, b"\x00" * 8)

    def test_decrypt_bad_tag_raises_runtime(self) -> None:
        ct, _tag = pq.native_chacha20poly1305_encrypt(self._KEY, self._NONCE, b"x")
        with pytest.raises(RuntimeError):
            pq.native_chacha20poly1305_decrypt(self._KEY, self._NONCE, ct, b"\x00" * 16)


# ---------------------------------------------------------------------------
# secp256k1 validation branches
# ---------------------------------------------------------------------------


@skip_no_native
@pytest.mark.skipif(not pq._SECP256K1_NATIVE_AVAILABLE, reason="secp256k1 backend not built")
class TestSecp256k1Validation:
    def test_wrong_privkey_length(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            pq.native_secp256k1_pubkey_from_privkey(b"\x01" * 16)

    def test_zero_privkey_raises(self) -> None:
        # All-zero private key is invalid for secp256k1
        with pytest.raises(RuntimeError):
            pq.native_secp256k1_pubkey_from_privkey(b"\x00" * 32)


# ---------------------------------------------------------------------------
# Deterministic keygen validation branches
# ---------------------------------------------------------------------------


@skip_no_native
@pytest.mark.skipif(
    not pq._DETERMINISTIC_KEYGEN_AVAILABLE,
    reason="Deterministic keygen backend not built",
)
class TestDeterministicKeygenValidation:
    def test_kyber_wrong_d_length(self) -> None:
        with pytest.raises(ValueError, match="seed d"):
            pq.native_kyber_keypair_from_seed(b"\x00" * 16, b"\x00" * 32)

    def test_kyber_wrong_z_length(self) -> None:
        with pytest.raises(ValueError, match="seed z"):
            pq.native_kyber_keypair_from_seed(b"\x00" * 32, b"\x00" * 16)

    def test_kyber_round_trip_deterministic(self) -> None:
        d = b"\x01" * 32
        z = b"\x02" * 32
        pk1, sk1 = pq.native_kyber_keypair_from_seed(d, z)
        pk2, sk2 = pq.native_kyber_keypair_from_seed(d, z)
        assert pk1 == pk2 and sk1 == sk2

    def test_dilithium_wrong_xi_length(self) -> None:
        with pytest.raises(ValueError, match="seed xi"):
            pq.native_dilithium_keypair_from_seed(b"\x00" * 16)

    def test_dilithium_round_trip_deterministic(self) -> None:
        xi = b"\x03" * 32
        pk1, sk1 = pq.native_dilithium_keypair_from_seed(xi)
        pk2, sk2 = pq.native_dilithium_keypair_from_seed(xi)
        assert pk1 == pk2 and sk1 == sk2


# ---------------------------------------------------------------------------
# FROST validation branches
# ---------------------------------------------------------------------------


@skip_no_native
@pytest.mark.skipif(not pq._FROST_AVAILABLE, reason="FROST backend not built")
class TestFrostValidation:
    def test_keygen_threshold_too_small(self) -> None:
        with pytest.raises(ValueError, match="threshold"):
            pq.frost_keygen_trusted_dealer(threshold=1, num_participants=3)

    def test_keygen_num_participants_too_small(self) -> None:
        with pytest.raises(ValueError, match="threshold"):
            pq.frost_keygen_trusted_dealer(threshold=3, num_participants=2)

    def test_keygen_num_participants_too_large(self) -> None:
        with pytest.raises(ValueError, match="255"):
            pq.frost_keygen_trusted_dealer(threshold=2, num_participants=256)

    def test_keygen_secret_key_wrong_length(self) -> None:
        with pytest.raises(ValueError, match="secret_key"):
            pq.frost_keygen_trusted_dealer(threshold=2, num_participants=3, secret_key=b"\x00" * 16)

    def test_round1_commit_wrong_share_length(self) -> None:
        with pytest.raises(ValueError, match="participant_share"):
            pq.frost_round1_commit(b"\x00" * 16)

    def test_round2_num_signers_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="num_signers"):
            pq.frost_round2_sign(
                message=b"m",
                participant_share=b"\x00" * pq.FROST_SHARE_BYTES,
                participant_index=1,
                nonce_pair=b"\x00" * pq.FROST_NONCE_BYTES,
                commitments=b"",
                signer_indices=b"",
                num_signers=1,
                group_public_key=b"\x00" * 32,
            )

    def test_round2_participant_index_zero(self) -> None:
        with pytest.raises(ValueError, match="participant_index"):
            pq.frost_round2_sign(
                message=b"m",
                participant_share=b"\x00" * pq.FROST_SHARE_BYTES,
                participant_index=0,
                nonce_pair=b"\x00" * pq.FROST_NONCE_BYTES,
                commitments=b"\x00" * (2 * pq.FROST_COMMITMENT_BYTES),
                signer_indices=b"\x01\x02",
                num_signers=2,
                group_public_key=b"\x00" * 32,
            )

    def test_aggregate_num_signers_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="num_signers"):
            pq.frost_aggregate(
                sig_shares=b"",
                commitments=b"",
                signer_indices=b"",
                num_signers=1,
                message=b"m",
                group_public_key=b"\x00" * 32,
            )

    def test_aggregate_duplicate_signer_indices(self) -> None:
        with pytest.raises(ValueError, match="unique"):
            pq.frost_aggregate(
                sig_shares=b"\x00" * (2 * pq.FROST_SIG_SHARE_BYTES),
                commitments=b"\x00" * (2 * pq.FROST_COMMITMENT_BYTES),
                signer_indices=b"\x01\x01",
                num_signers=2,
                message=b"m",
                group_public_key=b"\x00" * 32,
            )

    def test_aggregate_zero_signer_index(self) -> None:
        with pytest.raises(ValueError, match="1-based"):
            pq.frost_aggregate(
                sig_shares=b"\x00" * (2 * pq.FROST_SIG_SHARE_BYTES),
                commitments=b"\x00" * (2 * pq.FROST_COMMITMENT_BYTES),
                signer_indices=b"\x00\x01",
                num_signers=2,
                message=b"m",
                group_public_key=b"\x00" * 32,
            )


# ---------------------------------------------------------------------------
# hmac_sha3_256 dispatcher branches
# ---------------------------------------------------------------------------


class TestHmacSha3256Dispatcher:
    @pytest.mark.skipif(not pq.HMAC_SHA3_256_AVAILABLE, reason="HMAC-SHA3-256 backend unavailable")
    def test_basic_output(self) -> None:
        out = pq.hmac_sha3_256(b"\x01" * 32, b"msg")
        assert len(out) == 32

    def test_raises_without_backend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pq, "HMAC_SHA3_256_AVAILABLE", False)
        with pytest.raises(RuntimeError, match="backend not available"):
            pq.hmac_sha3_256(b"k" * 32, b"msg")
