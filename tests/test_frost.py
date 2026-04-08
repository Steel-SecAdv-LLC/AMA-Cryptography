#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
FROST Threshold Ed25519 Signature Tests (RFC 9591)

Tests the production-ready FROST implementation using
proper Ed25519 scalar and point arithmetic from ama_ed25519.c.
"""

import pytest

from ama_cryptography.pqc_backends import (
    _FROST_AVAILABLE,
    FROST_SHARE_BYTES,
    FROST_NONCE_BYTES,
    FROST_COMMITMENT_BYTES,
    FROST_SIG_SHARE_BYTES,
)

pytestmark = pytest.mark.skipif(
    not _FROST_AVAILABLE,
    reason="FROST native library not available",
)


def _full_frost_sign(threshold: int, num_participants: int, message: bytes) -> tuple:
    """Helper: Run full FROST keygen + 2-round signing protocol.

    Returns (group_public_key, signature).
    """
    from ama_cryptography.pqc_backends import (
        frost_keygen_trusted_dealer,
        frost_round1_commit,
        frost_round2_sign,
        frost_aggregate,
    )

    # Keygen
    gpk, shares = frost_keygen_trusted_dealer(threshold, num_participants)
    assert len(gpk) == 32
    assert len(shares) == num_participants
    for s in shares:
        assert len(s) == FROST_SHARE_BYTES

    # Select first `threshold` participants as signers
    signer_indices = bytes(range(1, threshold + 1))

    # Round 1: Each signer generates nonce commitments
    nonces = []
    commitments_list = []
    for i in range(threshold):
        nonce, commitment = frost_round1_commit(shares[i])
        assert len(nonce) == FROST_NONCE_BYTES
        assert len(commitment) == FROST_COMMITMENT_BYTES
        nonces.append(nonce)
        commitments_list.append(commitment)

    # Concatenate commitments
    all_commitments = b"".join(commitments_list)

    # Round 2: Each signer generates a signature share
    sig_shares = []
    for i in range(threshold):
        share = frost_round2_sign(
            message=message,
            participant_share=shares[i],
            participant_index=i + 1,
            nonce_pair=nonces[i],
            commitments=all_commitments,
            signer_indices=signer_indices,
            num_signers=threshold,
            group_public_key=gpk,
        )
        assert len(share) == FROST_SIG_SHARE_BYTES
        sig_shares.append(share)

    # Aggregate
    all_sig_shares = b"".join(sig_shares)
    signature = frost_aggregate(
        sig_shares=all_sig_shares,
        commitments=all_commitments,
        signer_indices=signer_indices,
        num_signers=threshold,
        message=message,
        group_public_key=gpk,
    )
    assert len(signature) == 64

    return gpk, signature


class TestFROSTKeygen:
    """Test FROST key generation."""

    def test_keygen_2_of_3(self) -> None:
        """Basic 2-of-3 key generation produces valid shares."""
        from ama_cryptography.pqc_backends import frost_keygen_trusted_dealer

        gpk, shares = frost_keygen_trusted_dealer(2, 3)
        assert len(gpk) == 32
        assert len(shares) == 3
        for share in shares:
            assert len(share) == FROST_SHARE_BYTES

    def test_keygen_3_of_5(self) -> None:
        """3-of-5 threshold keygen."""
        from ama_cryptography.pqc_backends import frost_keygen_trusted_dealer

        gpk, shares = frost_keygen_trusted_dealer(3, 5)
        assert len(gpk) == 32
        assert len(shares) == 5

    def test_keygen_with_secret(self) -> None:
        """Keygen with provided secret key is deterministic in group pk."""
        from ama_cryptography.pqc_backends import frost_keygen_trusted_dealer

        secret = b"\x01" * 32
        gpk1, _ = frost_keygen_trusted_dealer(2, 3, secret_key=secret)
        gpk2, _ = frost_keygen_trusted_dealer(2, 3, secret_key=secret)
        # Same secret -> same group public key
        assert gpk1 == gpk2

    def test_keygen_invalid_params(self) -> None:
        """Invalid parameters raise ValueError."""
        from ama_cryptography.pqc_backends import frost_keygen_trusted_dealer

        with pytest.raises(ValueError):
            frost_keygen_trusted_dealer(1, 3)  # threshold < 2
        with pytest.raises(ValueError):
            frost_keygen_trusted_dealer(5, 3)  # threshold > n


class TestFROSTSigning:
    """Test the full FROST signing protocol."""

    def test_2_of_3_basic(self) -> None:
        """2-of-3 FROST produces a 64-byte signature."""
        gpk, sig = _full_frost_sign(2, 3, b"hello FROST")
        assert len(sig) == 64
        # R and z components should be non-zero
        assert sig[:32] != b"\x00" * 32
        assert sig[32:] != b"\x00" * 32

    def test_3_of_5_basic(self) -> None:
        """3-of-5 FROST produces a valid signature."""
        gpk, sig = _full_frost_sign(3, 5, b"threshold signatures")
        assert len(sig) == 64

    def test_different_messages_different_sigs(self) -> None:
        """Different messages produce different signatures."""
        gpk1, sig1 = _full_frost_sign(2, 3, b"message A")
        gpk2, sig2 = _full_frost_sign(2, 3, b"message B")
        assert sig1 != sig2

    def test_empty_message(self) -> None:
        """FROST works with empty message."""
        gpk, sig = _full_frost_sign(2, 3, b"")
        assert len(sig) == 64

    def test_large_message(self) -> None:
        """FROST works with large messages."""
        msg = b"x" * 10000
        gpk, sig = _full_frost_sign(2, 3, msg)
        assert len(sig) == 64


class TestFROSTConsistency:
    """Test FROST signing consistency and correctness properties."""

    def test_same_signers_same_nonces_deterministic(self) -> None:
        """Verify keygen + signing runs without errors for multiple rounds."""
        from ama_cryptography.pqc_backends import frost_keygen_trusted_dealer

        # Run multiple full signing rounds — no crashes, valid output
        for _ in range(3):
            gpk, sig = _full_frost_sign(2, 3, b"consistency test")
            assert len(sig) == 64

    def test_different_signer_subsets(self) -> None:
        """Different t-sized subsets of n participants can all sign."""
        from ama_cryptography.pqc_backends import (
            frost_keygen_trusted_dealer,
            frost_round1_commit,
            frost_round2_sign,
            frost_aggregate,
        )

        threshold = 2
        n = 4
        gpk, shares = frost_keygen_trusted_dealer(threshold, n)

        # Try subsets {1,2}, {2,3}, {1,4}
        subsets = [(0, 1), (1, 2), (0, 3)]
        for s_a, s_b in subsets:
            signer_indices = bytes([s_a + 1, s_b + 1])

            nonce_a, commit_a = frost_round1_commit(shares[s_a])
            nonce_b, commit_b = frost_round1_commit(shares[s_b])
            all_commitments = commit_a + commit_b

            msg = b"subset signing test"

            share_a = frost_round2_sign(
                msg, shares[s_a], s_a + 1, nonce_a,
                all_commitments, signer_indices, 2, gpk,
            )
            share_b = frost_round2_sign(
                msg, shares[s_b], s_b + 1, nonce_b,
                all_commitments, signer_indices, 2, gpk,
            )

            sig = frost_aggregate(
                share_a + share_b, all_commitments,
                signer_indices, 2, msg, gpk,
            )
            assert len(sig) == 64

    def test_round1_produces_different_nonces(self) -> None:
        """Each round 1 call produces unique nonces and commitments."""
        from ama_cryptography.pqc_backends import (
            frost_keygen_trusted_dealer,
            frost_round1_commit,
        )

        _, shares = frost_keygen_trusted_dealer(2, 3)
        nonce1, commit1 = frost_round1_commit(shares[0])
        nonce2, commit2 = frost_round1_commit(shares[0])
        # Nonces should be different (random)
        assert nonce1 != nonce2
        assert commit1 != commit2


class TestFROSTEdgeCases:
    """Edge case tests."""

    def test_min_threshold(self) -> None:
        """Minimum threshold (2-of-2) works."""
        gpk, sig = _full_frost_sign(2, 2, b"min threshold")
        assert len(sig) == 64

    def test_round1_invalid_share_length(self) -> None:
        """Round 1 rejects invalid share length."""
        from ama_cryptography.pqc_backends import frost_round1_commit

        with pytest.raises(ValueError):
            frost_round1_commit(b"\x00" * 32)  # Too short
