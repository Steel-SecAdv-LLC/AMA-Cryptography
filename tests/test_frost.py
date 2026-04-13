#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
FROST Threshold Ed25519 Signing Tests (RFC 9591)
==================================================

Comprehensive test suite for the FROST threshold signature implementation.
Tests keygen, 2-round signing protocol, aggregation, and Ed25519 verification.

AI Co-Architects: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

from __future__ import annotations

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

        # Round 2: each signer produces signature share
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

        # Aggregate
        signature = frost_aggregate(
            sig_shares=all_sig_shares,
            commitments=all_commitments,
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
                signer_indices=bytes([0, 1]),
                num_signers=2,
                message=b"test",
                group_public_key=b"\x00" * 32,
            )
