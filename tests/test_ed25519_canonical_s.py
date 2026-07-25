#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Ed25519 canonical-S enforcement (RFC 8032 §5.1.7) — INVARIANT-26.

RFC 8032 §5.1.7 requires a verifier to decode the second half of a signature
as an integer ``S`` in the range ``0 <= S < L`` and to reject the signature if
that decoding fails.  ``L`` is the order of the base point::

    L = 2**252 + 27742317777372353535851937790883648493

Neither of this project's two Ed25519 backends enforced that range, and
Wycheproof ``eddsa_verify_schema_v1`` found it:

    tc63  "checking malleability"                  SignatureMalleability
    tc85  "Signature with S just above the bound"  InvalidKtv

Both must be rejected; both verified as VALID.

* The vendored **ed25519-donna** path (the x86-64 default) tested only
  ``RS[63] & 224`` — i.e. it rejected ``S >= 2**253``.  ``L`` sits just above
  ``2**252``, so the whole band ``L <= S < 2**253`` slipped through, and that
  band is exactly where ``S + L`` lands for most signatures.
* The portable **fe51** path (``ama_ed25519.c``) performed no range check at
  all, and its scalar-multiply reduces mod ``L`` internally, so ``S`` and
  ``S + L`` produced the identical point.

The consequence is signature malleability: given any valid ``(R, S)``, anyone
can emit ``(R, S + L)`` — a different 64-byte string that also verifies —
without touching the private key.  Systems that treat signature bytes as an
identity (dedup caches, replay windows, content addressing, transaction ids)
see two distinct "signatures" for one authenticated message.

These tests construct the malleable form directly from a freshly generated
signature rather than replaying a fixed vector, so they keep working if the
key generator, the hash, or the backend changes.  The Wycheproof corpus is run
separately; this file is the targeted regression pin.
"""

from __future__ import annotations

import pytest

from ama_cryptography import crypto_api

#: Order of the Ed25519 base point (RFC 8032 §5.1).
L = 2**252 + 27742317777372353535851937790883648493

MESSAGE = b"canonical-S regression pin"


def _split(signature: bytes) -> tuple[bytes, int]:
    """Return ``(R_bytes, S_int)`` for a 64-byte Ed25519 signature."""
    assert len(signature) == 64
    return signature[:32], int.from_bytes(signature[32:], "little")


def _join(r: bytes, s: int) -> bytes:
    """Rebuild a 64-byte signature from ``R`` and an integer ``S``."""
    return r + s.to_bytes(32, "little")


@pytest.fixture(scope="module")
def signed() -> tuple[crypto_api.Ed25519Provider, bytes, bytes]:
    """A provider plus one genuine (public_key, signature) pair."""
    provider = crypto_api.Ed25519Provider()
    keypair = provider.generate_keypair()
    signature = provider.sign(MESSAGE, keypair.secret_key).signature
    return provider, keypair.public_key, signature


class TestCanonicalSEnforcement:
    def test_honest_signature_still_verifies(
        self, signed: tuple[crypto_api.Ed25519Provider, bytes, bytes]
    ) -> None:
        """The fix must not reject legitimate signatures."""
        provider, public_key, signature = signed
        assert provider.verify(MESSAGE, signature, public_key) is True

    def test_s_plus_l_is_rejected(
        self, signed: tuple[crypto_api.Ed25519Provider, bytes, bytes]
    ) -> None:
        """The malleable twin (R, S + L) must NOT verify.

        This is the exact defect Wycheproof tc63 reports.  ``S + L`` satisfies
        the group equation because the scalar is reduced mod ``L`` downstream,
        so only an explicit range check can reject it.
        """
        provider, public_key, signature = signed
        r, s = _split(signature)
        malleable_s = s + L
        # Guard the premise: if S + L overflowed 32 bytes this vector would be
        # rejected for a different reason and prove nothing.
        assert malleable_s < 2**256, "S + L must still fit in 32 bytes"

        forged = _join(r, malleable_s)
        assert forged != signature, "the malleable form must be a distinct byte string"
        assert provider.verify(MESSAGE, forged, public_key) is False

    @pytest.mark.parametrize("s_value", [L, L + 1, 2**256 - 1], ids=["L", "L+1", "max"])
    def test_out_of_range_s_is_rejected(
        self, signed: tuple[crypto_api.Ed25519Provider, bytes, bytes], s_value: int
    ) -> None:
        """Out-of-range S values must not verify.

        HONESTY NOTE — these are boundary documentation, **not** regression
        pins.  Measured against a deliberately unpatched build, all three of
        these already returned False before the fix, because an arbitrary S
        also has to satisfy the group equation and these do not.  Only
        ``test_s_plus_l_is_rejected`` above changes behaviour with the patch,
        and it is the assertion that actually guards the defect.

        Wycheproof tc85 ("S just above the bound") *is* a true positive for
        the range check, because its S both exceeds L and satisfies the group
        equation.  Constructing such a value here would mean reimplementing
        signing, so that case is left to the Wycheproof corpus, which is run
        as its own gate.  These cases remain worth asserting: they would catch
        a future check written with the bound in the wrong place, or one that
        rejected only some out-of-range encodings.
        """
        provider, public_key, signature = signed
        r, _ = _split(signature)
        assert provider.verify(MESSAGE, _join(r, s_value), public_key) is False


class TestBatchAgreesWithSingle:
    """Batch verification must accept exactly what single verification does.

    donna's batch routine calls its own ``ed25519_sign_open`` internally rather
    than ``ama_ed25519_verify``, so the canonical check had to be applied in
    the batch wrapper as well.  Before that second patch, batch verification
    accepted the malleable signatures that single verification rejected — two
    APIs documented to agree, disagreeing on which signatures are valid.
    """

    def test_batch_rejects_what_single_rejects(
        self, signed: tuple[crypto_api.Ed25519Provider, bytes, bytes]
    ) -> None:
        provider, public_key, signature = signed
        r, s = _split(signature)
        forged = _join(r, s + L)

        entries = [
            (MESSAGE, signature, public_key),
            (MESSAGE, forged, public_key),
        ]
        batch = crypto_api.Ed25519Provider.batch_verify(entries)

        assert len(batch) == 2
        assert bool(batch[0]) is provider.verify(MESSAGE, signature, public_key)
        assert bool(batch[1]) is provider.verify(MESSAGE, forged, public_key)
        assert bool(batch[0]) is True
        assert bool(batch[1]) is False

    def test_batch_of_only_malleable_signatures_reports_all_invalid(
        self, signed: tuple[crypto_api.Ed25519Provider, bytes, bytes]
    ) -> None:
        """A batch containing no valid entry must not report success."""
        _, public_key, signature = signed
        r, s = _split(signature)
        forged = _join(r, s + L)
        batch = crypto_api.Ed25519Provider.batch_verify([(MESSAGE, forged, public_key)] * 3)
        assert not any(bool(x) for x in batch)
