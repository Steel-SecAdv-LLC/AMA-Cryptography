#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
FROST Threshold Ed25519 Signing Tests (RFC 9591-STYLE, not interoperable)
=========================================================================

Comprehensive test suite for the FROST threshold signature implementation.
Tests keygen, 2-round signing protocol, aggregation, and Ed25519 verification.

INVARIANT-49 is pinned here on the Python surface, and again in
``tests/c/test_frost.c`` at the C boundary.  Two properties, both of which
the 2026-09 audit demonstrated were absent:

* ``TestFROSTNonceSingleUse`` — a nonce pair is single-use and the LIBRARY is
  what consumes it.  The audit called round 2 three times with one nonce pair
  over three different messages, solved the resulting 3x3 linear system mod
  l, and recovered the hiding nonce, the binding nonce and the participant's
  long-term secret share.  ``test_attack_three_signings_under_one_nonce``
  runs that attack and asserts it no longer completes.
* ``TestFROSTShareVerification`` — aggregation verifies every share against
  the RFC 9591 section 5.3 relation and names the offending participant.
  Before the fix, one flipped bit in one share gave ``rc=0`` from aggregate
  and ``-4`` from ``ed25519_verify`` afterwards, with no attribution.

AI Co-Architects: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

from __future__ import annotations

from typing import Any

import pytest

from ama_cryptography.pqc_backends import FROST_AVAILABLE

skip_no_frost = pytest.mark.skipif(
    not FROST_AVAILABLE,
    reason="FROST native library not available (build with cmake -DAMA_USE_NATIVE_PQC=ON)",
)


@skip_no_frost
class TestFROSTKeygen:
    """Tests for FROST trusted dealer key generation."""

    def test_keygen_basic(self) -> None:
        """2-of-3 keygen produces correct output sizes."""
        from ama_cryptography.pqc_backends import (
            FROST_SHARE_BYTES,
            frost_keygen_trusted_dealer,
        )

        gpk, shares = frost_keygen_trusted_dealer(threshold=2, num_participants=3)
        assert len(gpk) == 32
        assert len(shares) == 3
        for share in shares:
            assert len(share) == FROST_SHARE_BYTES

    def test_keygen_with_secret_key(self) -> None:
        """Keygen with a pre-supplied 32-byte secret key."""
        import secrets

        from ama_cryptography.pqc_backends import frost_keygen_trusted_dealer

        sk = secrets.token_bytes(32)
        gpk, shares = frost_keygen_trusted_dealer(threshold=2, num_participants=3, secret_key=sk)
        assert len(gpk) == 32
        assert len(shares) == 3

    def test_keygen_deterministic_with_same_secret(self) -> None:
        """Same secret key produces the same group public key."""
        from ama_cryptography.pqc_backends import frost_keygen_trusted_dealer

        sk = b"\x01" * 32
        gpk1, _ = frost_keygen_trusted_dealer(threshold=2, num_participants=3, secret_key=sk)
        gpk2, _ = frost_keygen_trusted_dealer(threshold=2, num_participants=3, secret_key=sk)
        assert gpk1 == gpk2

    def test_keygen_invalid_threshold(self) -> None:
        """Threshold < 2 raises ValueError."""
        from ama_cryptography.pqc_backends import frost_keygen_trusted_dealer

        with pytest.raises(ValueError, match="threshold"):
            frost_keygen_trusted_dealer(threshold=1, num_participants=3)

    def test_keygen_threshold_exceeds_participants(self) -> None:
        """threshold > num_participants raises ValueError."""
        from ama_cryptography.pqc_backends import frost_keygen_trusted_dealer

        with pytest.raises(ValueError, match="threshold"):
            frost_keygen_trusted_dealer(threshold=4, num_participants=3)

    def test_keygen_bad_secret_key_length(self) -> None:
        """Non-32-byte secret key raises ValueError."""
        from ama_cryptography.pqc_backends import frost_keygen_trusted_dealer

        with pytest.raises(ValueError, match="32 bytes"):
            frost_keygen_trusted_dealer(threshold=2, num_participants=3, secret_key=b"\x00" * 16)


@skip_no_frost
class TestFROSTSigning:
    """Tests for the FROST 2-round signing protocol."""

    def _do_frost_sign(
        self, message: bytes, threshold: int = 2, num_participants: int = 3
    ) -> tuple[bytes, bytes, bytes]:
        """Helper: run full FROST signing and return (signature, gpk, message)."""
        from ama_cryptography.pqc_backends import (
            frost_aggregate,
            frost_keygen_trusted_dealer,
            frost_round1_commit,
            frost_round2_sign,
        )

        gpk, shares = frost_keygen_trusted_dealer(
            threshold=threshold, num_participants=num_participants
        )

        # Select first `threshold` participants as signers (1-based indices)
        signer_indices = bytes(range(1, threshold + 1))

        # Round 1: each signer generates nonce commitment
        nonces = []
        commitments = []
        for i in range(threshold):
            nonce, commit = frost_round1_commit(shares[i])
            nonces.append(nonce)
            commitments.append(commit)

        all_commitments = b"".join(commitments)

        # Round 2: each signer produces signature share.  INVARIANT-49: each
        # nonce pair is consumed by the call, so each is used exactly once.
        sig_shares = []
        for i in range(threshold):
            sig_share = frost_round2_sign(
                message=message,
                participant_share=shares[i],
                participant_index=i + 1,
                nonce_pair=nonces[i],
                commitments=all_commitments,
                signer_indices=signer_indices,
                num_signers=threshold,
                group_public_key=gpk,
            )
            sig_shares.append(sig_share)

        all_sig_shares = b"".join(sig_shares)

        # Aggregate.  INVARIANT-49: share verification needs each signer's
        # PUBLIC key share — bytes [32, 64) of its dealt share.
        signature = frost_aggregate(
            sig_shares=all_sig_shares,
            commitments=all_commitments,
            signer_public_shares=b"".join(shares[i][32:64] for i in range(threshold)),
            signer_indices=signer_indices,
            num_signers=threshold,
            message=message,
            group_public_key=gpk,
        )

        return signature, gpk, message

    def test_sign_and_aggregate_basic(self) -> None:
        """Basic 2-of-3 FROST signing produces a 64-byte signature."""
        sig, _gpk, _msg = self._do_frost_sign(b"hello FROST")
        assert len(sig) == 64

    def test_sign_ed25519_verify(self) -> None:
        """FROST signature verifies with native Ed25519 verify."""
        from ama_cryptography.pqc_backends import native_ed25519_verify

        sig, gpk, msg = self._do_frost_sign(b"FROST Ed25519 verification test")
        result = native_ed25519_verify(sig, msg, gpk)
        assert result is True, f"Ed25519 verification failed (result={result})"

    def test_sign_empty_message(self) -> None:
        """FROST signing works with an empty message."""
        from ama_cryptography.pqc_backends import native_ed25519_verify

        sig, gpk, msg = self._do_frost_sign(b"")
        assert len(sig) == 64
        result = native_ed25519_verify(sig, msg, gpk)
        assert result is True

    def test_sign_large_message(self) -> None:
        """FROST signing works with a large message."""
        from ama_cryptography.pqc_backends import native_ed25519_verify

        msg = b"A" * 10000
        sig, gpk, _ = self._do_frost_sign(msg)
        assert len(sig) == 64
        result = native_ed25519_verify(sig, msg, gpk)
        assert result is True


@skip_no_frost
class TestFROSTConsistency:
    """Tests for FROST consistency and correctness properties."""

    def test_different_messages_produce_different_signatures(self) -> None:
        """Same key shares, different messages produce different signatures."""
        from ama_cryptography.pqc_backends import (
            frost_aggregate,
            frost_keygen_trusted_dealer,
            frost_round1_commit,
            frost_round2_sign,
        )

        gpk, shares = frost_keygen_trusted_dealer(threshold=2, num_participants=3)
        signer_indices = bytes([1, 2])

        sigs = []
        for msg in [b"message A", b"message B"]:
            nonces = []
            commitments = []
            for i in range(2):
                nonce, commit = frost_round1_commit(shares[i])
                nonces.append(nonce)
                commitments.append(commit)
            all_commitments = b"".join(commitments)

            sig_shares = []
            for i in range(2):
                sig_share = frost_round2_sign(
                    message=msg,
                    participant_share=shares[i],
                    participant_index=i + 1,
                    nonce_pair=nonces[i],
                    commitments=all_commitments,
                    signer_indices=signer_indices,
                    num_signers=2,
                    group_public_key=gpk,
                )
                sig_shares.append(sig_share)

            sig = frost_aggregate(
                sig_shares=b"".join(sig_shares),
                commitments=all_commitments,
                signer_public_shares=shares[0][32:64] + shares[1][32:64],
                signer_indices=signer_indices,
                num_signers=2,
                message=msg,
                group_public_key=gpk,
            )
            sigs.append(sig)

        assert sigs[0] != sigs[1]

    def test_3_of_5_threshold(self) -> None:
        """3-of-5 FROST signing with Ed25519 verification."""
        from ama_cryptography.pqc_backends import (
            frost_aggregate,
            frost_keygen_trusted_dealer,
            frost_round1_commit,
            frost_round2_sign,
            native_ed25519_verify,
        )

        gpk, shares = frost_keygen_trusted_dealer(threshold=3, num_participants=5)
        signer_indices = bytes([1, 3, 5])  # non-contiguous signers
        msg = b"3-of-5 threshold test"

        nonces = []
        commitments = []
        selected_shares = [shares[0], shares[2], shares[4]]
        for share in selected_shares:
            nonce, commit = frost_round1_commit(share)
            nonces.append(nonce)
            commitments.append(commit)

        all_commitments = b"".join(commitments)

        sig_shares = []
        for i, (share, idx) in enumerate(zip(selected_shares, [1, 3, 5])):
            sig_share = frost_round2_sign(
                message=msg,
                participant_share=share,
                participant_index=idx,
                nonce_pair=nonces[i],
                commitments=all_commitments,
                signer_indices=signer_indices,
                num_signers=3,
                group_public_key=gpk,
            )
            sig_shares.append(sig_share)

        sig = frost_aggregate(
            sig_shares=b"".join(sig_shares),
            commitments=all_commitments,
            signer_public_shares=b"".join(s[32:64] for s in selected_shares),
            signer_indices=signer_indices,
            num_signers=3,
            message=msg,
            group_public_key=gpk,
        )

        assert len(sig) == 64
        result = native_ed25519_verify(sig, msg, gpk)
        assert result is True


@skip_no_frost
class TestFROSTEdgeCases:
    """Edge case tests for FROST input validation."""

    def test_round1_bad_share_length(self) -> None:
        """round1_commit rejects wrong share length."""
        from ama_cryptography.pqc_backends import frost_round1_commit

        with pytest.raises(ValueError, match="64 bytes"):
            frost_round1_commit(b"\x00" * 32)

    def test_round2_bad_commitment_length(self) -> None:
        """round2_sign rejects mismatched commitments length."""
        from ama_cryptography.pqc_backends import (
            frost_keygen_trusted_dealer,
            frost_round1_commit,
            frost_round2_sign,
        )

        gpk, shares = frost_keygen_trusted_dealer(threshold=2, num_participants=3)
        nonce, _ = frost_round1_commit(shares[0])

        with pytest.raises(ValueError, match="commitments"):
            frost_round2_sign(
                message=b"test",
                participant_share=shares[0],
                participant_index=1,
                nonce_pair=nonce,
                commitments=b"\x00" * 32,  # wrong length
                signer_indices=bytes([1, 2]),
                num_signers=2,
                group_public_key=gpk,
            )

    def test_aggregate_duplicate_signer_indices(self) -> None:
        """frost_aggregate rejects duplicate signer indices."""
        from ama_cryptography.pqc_backends import frost_aggregate

        with pytest.raises(ValueError, match="unique"):
            frost_aggregate(
                sig_shares=b"\x00" * 64,
                commitments=b"\x00" * 128,
                signer_public_shares=b"\x00" * 64,
                signer_indices=bytes([1, 1]),
                num_signers=2,
                message=b"test",
                group_public_key=b"\x00" * 32,
            )

    def test_aggregate_zero_signer_index(self) -> None:
        """frost_aggregate rejects 0-based signer indices."""
        from ama_cryptography.pqc_backends import frost_aggregate

        with pytest.raises(ValueError, match="1-based"):
            frost_aggregate(
                sig_shares=b"\x00" * 64,
                commitments=b"\x00" * 128,
                signer_public_shares=b"\x00" * 64,
                signer_indices=bytes([0, 1]),
                num_signers=2,
                message=b"test",
                group_public_key=b"\x00" * 32,
            )

    def test_aggregate_bad_public_shares_length(self) -> None:
        """frost_aggregate rejects a mis-sized signer_public_shares buffer."""
        from ama_cryptography.pqc_backends import frost_aggregate

        with pytest.raises(ValueError, match="signer_public_shares"):
            frost_aggregate(
                sig_shares=b"\x00" * 64,
                commitments=b"\x00" * 128,
                signer_public_shares=b"\x00" * 32,  # one short
                signer_indices=bytes([1, 2]),
                num_signers=2,
                message=b"test",
                group_public_key=b"\x00" * 32,
            )


def _ceremony(
    threshold: int = 2, num_participants: int = 3, message: bytes = b"ceremony"
) -> dict[str, Any]:
    """Run keygen + round 1 and return everything a round 2 / aggregate needs.

    Deliberately stops BEFORE round 2 so each test below decides how many
    times, and with which buffers, round 2 is called — that is the property
    under test in ``TestFROSTNonceSingleUse``.
    """
    from ama_cryptography.pqc_backends import (
        frost_keygen_trusted_dealer,
        frost_round1_commit,
    )

    gpk, shares = frost_keygen_trusted_dealer(
        threshold=threshold, num_participants=num_participants
    )
    signer_indices = bytes(range(1, threshold + 1))
    nonces = []
    commitment_list = []
    for i in range(threshold):
        nonce, commitment = frost_round1_commit(shares[i])
        nonces.append(nonce)
        commitment_list.append(commitment)
    return {
        "gpk": gpk,
        "shares": shares,
        "signer_indices": signer_indices,
        "nonces": nonces,
        "commitments": b"".join(commitment_list),
        "public_shares": b"".join(shares[i][32:64] for i in range(threshold)),
        "threshold": threshold,
        "message": message,
    }


def _sign_one(ctx: dict[str, Any], i: int, message: bytes) -> bytes:
    """Round 2 for signer ``i`` of a ``_ceremony`` context."""
    from ama_cryptography.pqc_backends import frost_round2_sign

    return frost_round2_sign(
        message=message,
        participant_share=ctx["shares"][i],
        participant_index=i + 1,
        nonce_pair=ctx["nonces"][i],
        commitments=ctx["commitments"],
        signer_indices=ctx["signer_indices"],
        num_signers=ctx["threshold"],
        group_public_key=ctx["gpk"],
    )


@skip_no_frost
class TestFROSTNonceSingleUse:
    """INVARIANT-49 part 1 — the nonce pair is single-use and library-consumed.

    Audit finding A-4.  ``ama_frost_round2_sign`` used to take the nonce pair
    as ``const uint8_t *``, hold no state, and neither consume nor zeroize it,
    so repeated calls over different messages each returned success.  These
    tests pin every element of the fix at the Python boundary.
    """

    def test_round1_returns_a_writable_buffer(self) -> None:
        """The nonce pair must be writable — round 2 zeroizes it in place."""
        from ama_cryptography.pqc_backends import (
            FROST_NONCE_BYTES,
            frost_keygen_trusted_dealer,
            frost_round1_commit,
        )

        _gpk, shares = frost_keygen_trusted_dealer(threshold=2, num_participants=3)
        nonce, commitment = frost_round1_commit(shares[0])
        assert isinstance(nonce, bytearray), "nonce_pair must be mutable to be consumable"
        assert len(nonce) == FROST_NONCE_BYTES
        assert len(commitment) == 64
        assert nonce != bytearray(FROST_NONCE_BYTES), "a fresh nonce pair is not all-zero"

    def test_nonce_is_zeroed_after_successful_round2(self) -> None:
        ctx = _ceremony()
        nonce = ctx["nonces"][0]
        assert any(nonce), "precondition: the nonce pair starts non-zero"

        sig_share = _sign_one(ctx, 0, ctx["message"])
        assert len(sig_share) == 32
        assert not any(nonce), "nonce pair must be zeroed after a SUCCESSFUL round 2"

    def test_nonce_is_zeroed_after_failed_round2(self) -> None:
        """The contract is "consumed whatever the outcome", not "unless it failed"."""
        from ama_cryptography.pqc_backends import frost_round2_sign

        ctx = _ceremony()
        nonce = ctx["nonces"][0]
        assert any(nonce)

        with pytest.raises(ValueError, match="commitments"):
            frost_round2_sign(
                message=ctx["message"],
                participant_share=ctx["shares"][0],
                participant_index=1,
                nonce_pair=nonce,
                commitments=b"\x00" * 32,  # wrong length: refused before the C call
                signer_indices=ctx["signer_indices"],
                num_signers=2,
                group_public_key=ctx["gpk"],
            )
        assert not any(nonce), "nonce pair must be zeroed after a FAILED round 2"

    def test_nonce_is_zeroed_when_the_native_call_refuses(self) -> None:
        """The other failure path: refused inside C, not by the Python checks.

        A duplicate signer index passes every length check this wrapper makes
        and is rejected by ``validate_signer_indices`` in the C entry point,
        so this exercises the ``consume:`` label rather than the wrapper's
        ``finally``.
        """
        from ama_cryptography.pqc_backends import frost_round2_sign

        ctx = _ceremony()
        nonce = ctx["nonces"][0]
        assert any(nonce)

        with pytest.raises(RuntimeError, match="round2"):
            frost_round2_sign(
                message=ctx["message"],
                participant_share=ctx["shares"][0],
                participant_index=1,
                nonce_pair=nonce,
                commitments=ctx["commitments"],
                signer_indices=bytes([1, 1]),  # duplicate: refused in C
                num_signers=2,
                group_public_key=ctx["gpk"],
            )
        assert not any(nonce), "nonce pair must be zeroed after a native refusal"

    def test_second_round2_with_same_nonce_is_refused(self) -> None:
        ctx = _ceremony()
        _sign_one(ctx, 0, b"message A")
        with pytest.raises(RuntimeError, match="round2"):
            _sign_one(ctx, 0, b"message B")

    def test_all_zero_nonce_pair_is_refused(self) -> None:
        """Asserted without a prior round 2, so the entry check is pinned itself."""
        from ama_cryptography.pqc_backends import FROST_NONCE_BYTES

        ctx = _ceremony()
        ctx["nonces"][0] = bytearray(FROST_NONCE_BYTES)
        with pytest.raises(RuntimeError, match="round2"):
            _sign_one(ctx, 0, ctx["message"])

    def test_immutable_nonce_pair_is_a_type_error(self) -> None:
        """``bytes`` is refused rather than silently copied.

        Copying into a scratch buffer would leave the caller's copy alive and
        reusable, which is precisely the reuse the contract exists to make
        impossible; and writing through a pointer into an immutable ``bytes``
        is undefined behaviour in CPython.  Neither is an acceptable
        fallback, so it is an error.
        """
        ctx = _ceremony()
        ctx["nonces"][0] = bytes(ctx["nonces"][0])
        with pytest.raises(TypeError, match="writable"):
            _sign_one(ctx, 0, ctx["message"])

    def test_attack_three_signings_under_one_nonce(self) -> None:
        """THE ATTACK (audit A-4), asserted to be blocked.

        Three partial signatures over three messages under one nonce pair are
        three independent linear equations in (d, e, lambda*s) mod l; the
        audit solved that system and recovered all three unknowns, the third
        being the participant's long-term secret share.  Only the first
        signing may now succeed, so the system is never obtainable.
        """
        ctx = _ceremony()
        outcomes: list[str] = []
        harvested: list[bytes] = []
        for msg in (b"message A", b"message B", b"message C"):
            try:
                harvested.append(_sign_one(ctx, 0, msg))
                outcomes.append("ok")
            except RuntimeError:
                outcomes.append("refused")

        assert outcomes == ["ok", "refused", "refused"], (
            "signings 2 and 3 under one nonce pair must be refused — otherwise the "
            f"audit's 3x3 recovery of the secret share is reachable again (got {outcomes})"
        )
        assert len(harvested) == 1, (
            "an attacker must be able to harvest at most ONE partial signature per "
            "nonce pair; two already halve the unknowns, three solve the system"
        )


@skip_no_frost
class TestFROSTShareVerification:
    """INVARIANT-49 part 2 — aggregation verifies and attributes (audit A-5)."""

    def _signed(self, threshold: int = 2) -> dict[str, Any]:
        ctx = _ceremony(threshold=threshold)
        ctx["sig_shares"] = [_sign_one(ctx, i, ctx["message"]) for i in range(threshold)]
        return ctx

    def _aggregate(
        self, ctx: dict[str, Any], sig_shares: bytes, public_shares: bytes | None = None
    ) -> bytes:
        from ama_cryptography.pqc_backends import frost_aggregate

        return frost_aggregate(
            sig_shares=sig_shares,
            commitments=ctx["commitments"],
            signer_public_shares=(ctx["public_shares"] if public_shares is None else public_shares),
            signer_indices=ctx["signer_indices"],
            num_signers=ctx["threshold"],
            message=ctx["message"],
            group_public_key=ctx["gpk"],
        )

    def test_honest_ceremony_still_succeeds_end_to_end(self) -> None:
        from ama_cryptography.pqc_backends import native_ed25519_verify

        ctx = self._signed()
        sig = self._aggregate(ctx, b"".join(ctx["sig_shares"]))
        assert len(sig) == 64
        assert native_ed25519_verify(sig, ctx["message"], ctx["gpk"]) is True

    def test_verify_share_accepts_honest_shares(self) -> None:
        from ama_cryptography.pqc_backends import frost_verify_share

        ctx = self._signed()
        for i in range(ctx["threshold"]):
            assert (
                frost_verify_share(
                    sig_share=ctx["sig_shares"][i],
                    participant_index=i + 1,
                    participant_public_share=ctx["shares"][i][32:64],
                    commitments=ctx["commitments"],
                    signer_indices=ctx["signer_indices"],
                    num_signers=ctx["threshold"],
                    message=ctx["message"],
                    group_public_key=ctx["gpk"],
                )
                is True
            )

    def test_verify_share_rejects_a_corrupted_share(self) -> None:
        from ama_cryptography.pqc_backends import frost_verify_share

        ctx = self._signed()
        corrupt = bytearray(ctx["sig_shares"][0])
        corrupt[0] ^= 0x01
        assert (
            frost_verify_share(
                sig_share=bytes(corrupt),
                participant_index=1,
                participant_public_share=ctx["shares"][0][32:64],
                commitments=ctx["commitments"],
                signer_indices=ctx["signer_indices"],
                num_signers=ctx["threshold"],
                message=ctx["message"],
                group_public_key=ctx["gpk"],
            )
            is False
        )

    @pytest.mark.parametrize("culprit", [1, 2])
    def test_aggregate_rejects_and_attributes_a_corrupted_share(self, culprit: int) -> None:
        """The exact input that used to return rc=0 and an invalid signature."""
        from ama_cryptography.pqc_backends import FrostShareRejected

        ctx = self._signed()
        shares = [bytearray(s) for s in ctx["sig_shares"]]
        shares[culprit - 1][0] ^= 0x01
        with pytest.raises(FrostShareRejected) as excinfo:
            self._aggregate(ctx, b"".join(bytes(s) for s in shares))
        assert excinfo.value.participant_index == culprit
        assert str(culprit) in str(excinfo.value)

    def test_aggregate_rejects_mismatched_public_shares(self) -> None:
        """Verification is against PK_i, so the wrong PK_i is a rejection."""
        from ama_cryptography.pqc_backends import FrostShareRejected

        ctx = self._signed()
        swapped = ctx["shares"][1][32:64] + ctx["shares"][0][32:64]
        with pytest.raises(FrostShareRejected) as excinfo:
            self._aggregate(ctx, b"".join(ctx["sig_shares"]), public_shares=swapped)
        assert excinfo.value.participant_index == 1

    def test_attribution_with_three_signers(self) -> None:
        """Attribution must name the third signer, not a constant that matches 1 or 2."""
        from ama_cryptography.pqc_backends import FrostShareRejected

        ctx = self._signed(threshold=3)
        shares = [bytearray(s) for s in ctx["sig_shares"]]
        shares[2][31] ^= 0x01  # third signer == participant index 3
        with pytest.raises(FrostShareRejected) as excinfo:
            self._aggregate(ctx, b"".join(bytes(s) for s in shares))
        assert excinfo.value.participant_index == 3

    def test_rejection_is_a_runtime_error_subclass(self) -> None:
        """Callers written against the old ``RuntimeError`` contract still work."""
        from ama_cryptography.pqc_backends import FrostShareRejected

        assert issubclass(FrostShareRejected, RuntimeError)
