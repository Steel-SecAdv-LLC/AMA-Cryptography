#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
The signer derives its own public half (2026-09 audit, B-2)
===========================================================

``ama_ed25519_sign`` takes a 64-byte secret key laid out as ``seed || A``.  It
recomputes the scalar ``a`` and the nonce PRF key from ``seed``, but used to
take ``A`` verbatim from bytes 32..63 and feed it to ``H(R || A || M)``
without ever checking ``A == [a]B``.

That is a private-key recovery hazard, not a hygiene issue.  ``r`` is a
function of the seed and the message alone, so two signatures over ONE message
under two different ``A`` halves share ``R``, and::

    s1 - s2 = (h1 - h2) * a  (mod L)

hands over the private scalar.  It is the classic "Taming the many EdDSAs"
fault attack, and the reachable version of it here needs no fault injection at
all: a caller that stores the halves separately, reassembles a key from a
corrupted record, or copies 32 bytes from the wrong buffer produces exactly
this input, and the header documented the layout in detail while saying
nothing about the requirement.

The signer now derives ``A`` and refuses a key whose stored half disagrees.
Every test below is an inequality or a refusal rather than a pinned value:
pinning a signature would also pass if signing started returning a constant.
"""

from __future__ import annotations

import pytest

import ama_cryptography.pqc_backends as pb

pytestmark = pytest.mark.skipif(
    not pb._ED25519_NATIVE_AVAILABLE,
    reason="native Ed25519 backend not available in this build",
)

MESSAGE = b"fault-attack probe"


def _keypair() -> tuple[bytes, bytes]:
    public_key, secret_key = pb.native_ed25519_keypair()
    return bytes(public_key), bytes(secret_key)


def _with_corrupted_public_half(secret_key: bytes, bit: int = 0) -> bytes:
    """The same key with one bit flipped in bytes 32..63.

    One bit, not a random replacement: the point is that this is what a
    storage fault or an off-by-one copy produces, not what an attacker has to
    construct.
    """
    corrupted = bytearray(secret_key)
    corrupted[32 + (bit // 8)] ^= 1 << (bit % 8)
    return bytes(corrupted)


class TestTheSignerRefusesAnInconsistentKey:
    def test_a_well_formed_key_still_signs_and_verifies(self) -> None:
        """The positive control.

        Without it every refusal below would also pass against a signer that
        had simply been made to fail for all inputs.
        """
        public_key, secret_key = _keypair()
        signature = pb.native_ed25519_sign(MESSAGE, secret_key)
        assert pb.native_ed25519_verify(signature, MESSAGE, public_key) is True

    @pytest.mark.parametrize("bit", [0, 1, 7, 128, 255])
    def test_a_single_flipped_bit_in_the_public_half_is_refused(self, bit: int) -> None:
        _public_key, secret_key = _keypair()
        with pytest.raises(RuntimeError):
            pb.native_ed25519_sign(MESSAGE, _with_corrupted_public_half(secret_key, bit))

    def test_a_public_half_from_a_different_key_is_refused(self) -> None:
        """The shape a caller reaches by pairing the wrong two records."""
        _pk_a, sk_a = _keypair()
        pk_b, _sk_b = _keypair()
        with pytest.raises(RuntimeError):
            pb.native_ed25519_sign(MESSAGE, sk_a[:32] + pk_b)

    def test_an_all_zero_public_half_is_refused(self) -> None:
        _public_key, secret_key = _keypair()
        with pytest.raises(RuntimeError):
            pb.native_ed25519_sign(MESSAGE, secret_key[:32] + bytes(32))

    def test_the_two_signatures_the_attack_needs_cannot_both_exist(self) -> None:
        """The attack itself, stated as the thing that must not happen.

        Given signatures over the same message under two different ``A``
        halves, ``s1 - s2 = (h1 - h2) * a mod L`` recovers the scalar — but
        only if the second signature exists at all.  It does not.
        """
        _public_key, secret_key = _keypair()
        first = pb.native_ed25519_sign(MESSAGE, secret_key)
        with pytest.raises(RuntimeError):
            pb.native_ed25519_sign(MESSAGE, _with_corrupted_public_half(secret_key))
        # And the genuine signature is unaffected by the refused attempt.
        assert first == pb.native_ed25519_sign(MESSAGE, secret_key)
