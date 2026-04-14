#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Tests for FROSTProvider — high-level FROST threshold signing wrapper.

Covers:
- 2-of-3 threshold signing round-trip
- 3-of-5 threshold signing round-trip
- verify() delegates to Ed25519 and accepts FROST signatures
- Error cases: unavailable FROST, invalid params
- Provider instantiation guard
"""

import pytest

from ama_cryptography.pqc_backends import FROST_AVAILABLE

skip_no_frost = pytest.mark.skipif(
    not FROST_AVAILABLE,
    reason="FROST native library not available",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _do_frost_signing(threshold: int, num_participants: int, signer_count: int):
    """Run a complete FROST signing session and return (signature, gpk, message)."""
    from ama_cryptography.crypto_api import FROSTProvider

    provider = FROSTProvider()
    msg = b"AMA FROST threshold signing test"

    gpk, shares = provider.keygen(threshold, num_participants)
    assert len(gpk) == 32
    assert len(shares) == num_participants

    # Select which participants sign (1-based)
    signer_indices_list = list(range(1, signer_count + 1))
    signer_indices = bytes(signer_indices_list)

    # Round 1: each signer commits
    nonces = []
    commits = []
    for idx in signer_indices_list:
        nonce, commit = provider.round1_commit(shares[idx - 1])
        nonces.append(nonce)
        commits.append(commit)

    all_commits = b"".join(commits)

    # Round 2: each signer produces a share
    sig_shares = []
    for i, idx in enumerate(signer_indices_list):
        share = provider.round2_sign(
            msg,
            shares[idx - 1],
            idx,
            nonces[i],
            all_commits,
            signer_indices,
            gpk,
        )
        sig_shares.append(share)

    # Aggregate
    signature = provider.aggregate(sig_shares, commits, signer_indices, msg, gpk)
    assert len(signature) == 64
    return signature, gpk, msg


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@skip_no_frost
class TestFROSTProvider:
    def test_instantiation(self):
        """FROSTProvider can be instantiated when FROST is available."""
        from ama_cryptography.crypto_api import FROSTProvider

        provider = FROSTProvider()
        assert provider is not None

    def test_2_of_3_round_trip(self):
        """2-of-3 threshold: signing with 2 participants produces valid signature."""
        sig, gpk, msg = _do_frost_signing(threshold=2, num_participants=3, signer_count=2)
        from ama_cryptography.crypto_api import FROSTProvider

        provider = FROSTProvider()
        assert provider.verify(msg, sig, gpk)

    def test_3_of_5_round_trip(self):
        """3-of-5 threshold: signing with exactly 3 participants produces valid signature."""
        sig, gpk, msg = _do_frost_signing(threshold=3, num_participants=5, signer_count=3)
        from ama_cryptography.crypto_api import FROSTProvider

        provider = FROSTProvider()
        assert provider.verify(msg, sig, gpk)

    def test_all_participants_sign(self):
        """Threshold = n: all participants must sign."""
        sig, gpk, msg = _do_frost_signing(threshold=3, num_participants=3, signer_count=3)
        from ama_cryptography.crypto_api import FROSTProvider

        provider = FROSTProvider()
        assert provider.verify(msg, sig, gpk)

    def test_verify_rejects_wrong_message(self):
        """verify() returns False for a signature over a different message."""
        sig, gpk, _msg = _do_frost_signing(threshold=2, num_participants=3, signer_count=2)
        from ama_cryptography.crypto_api import FROSTProvider

        provider = FROSTProvider()
        wrong_msg = b"Not the signed message"
        assert not provider.verify(wrong_msg, sig, gpk)

    def test_verify_rejects_wrong_key(self):
        """verify() returns False when group public key doesn't match."""
        import secrets

        sig, _gpk, msg = _do_frost_signing(threshold=2, num_participants=3, signer_count=2)
        from ama_cryptography.crypto_api import FROSTProvider

        provider = FROSTProvider()
        wrong_gpk = secrets.token_bytes(32)
        assert not provider.verify(msg, sig, wrong_gpk)

    def test_keygen_invalid_threshold(self):
        """threshold < 2 raises ValueError."""
        from ama_cryptography.crypto_api import FROSTProvider

        provider = FROSTProvider()
        with pytest.raises(ValueError):
            provider.keygen(threshold=1, num_participants=3)

    def test_keygen_threshold_exceeds_participants(self):
        """threshold > num_participants raises ValueError."""
        from ama_cryptography.crypto_api import FROSTProvider

        provider = FROSTProvider()
        with pytest.raises(ValueError):
            provider.keygen(threshold=5, num_participants=3)

    def test_keygen_with_secret_key(self):
        """Providing a 32-byte secret produces valid keypair."""
        import secrets

        from ama_cryptography.crypto_api import FROSTProvider

        provider = FROSTProvider()
        sk = secrets.token_bytes(32)
        gpk, shares = provider.keygen(threshold=2, num_participants=3, secret_key=sk)
        assert len(gpk) == 32
        assert len(shares) == 3

    def test_keygen_deterministic(self):
        """Same secret key → same group public key."""
        from ama_cryptography.crypto_api import FROSTProvider

        provider = FROSTProvider()
        sk = b"\x42" * 32
        gpk1, _ = provider.keygen(2, 3, secret_key=sk)
        gpk2, _ = provider.keygen(2, 3, secret_key=sk)
        assert gpk1 == gpk2

    def test_frost_aggregate_signature_is_standard_ed25519(self):
        """FROST aggregate signature is 64 bytes (standard Ed25519 format)."""
        sig, gpk, msg = _do_frost_signing(threshold=2, num_participants=3, signer_count=2)
        assert len(sig) == 64  # R (32 bytes) || s (32 bytes)


@pytest.mark.skipif(
    FROST_AVAILABLE,
    reason="FROST IS available — testing unavailability path requires no FROST",
)
class TestFROSTProviderUnavailable:
    def test_instantiation_raises_when_unavailable(self):
        """FROSTProvider raises RuntimeError when FROST backend is missing."""
        from ama_cryptography.crypto_api import FROSTProvider

        with pytest.raises(RuntimeError, match="FROST"):
            FROSTProvider()
