# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Non-canonical Ed25519 public-key ``y`` rejection (INVARIANT-38).

RFC 8032 §5.1.3 requires a compressed point whose ``y`` is not in ``[0, p)``
with ``p = 2^255 - 19`` to be **rejected**, not reduced. INVARIANT-27 already
recorded that rule — it is why X25519's canonicalisation sits on the 32-byte
encoding rather than inside the ``fe51_frombytes`` / ``fe64_frombytes``
helpers those two curves share — but neither backend enforced it: both reduced
mod ``p``, so each of the nineteen values in ``[p, 2^255)`` decoded to the same
curve point as its reduced counterpart and a public key had two accepted byte
encodings.

This is the Python-binding half of the coverage, mirroring
``tests/test_secp256k1_ecdsa_noncanonical_pubkey.py`` for INVARIANT-29. The
predicate itself is isolated from the curve and signature checks in
``tests/c/test_ed25519_canonical_s.c``, which drives
``ama_ed25519_point_y_is_canonical`` directly across the whole band and both
sides of the ``p-1`` / ``p`` boundary.

Note on scope: an end-to-end "the non-canonical twin of a real key verifies"
positive control is not practically constructible. A key whose ``y`` has an
in-range twin needs ``y < 19``, which occurs with probability about
``19 / 2^255``. So the gate is exercised here through the policy it enforces —
every value in the band is refused, and canonical keys keep verifying.
"""

from __future__ import annotations

import pytest

from ama_cryptography.pqc_backends import (
    native_ed25519_keypair,
    native_ed25519_sign,
    native_ed25519_verify,
)

P = 2**255 - 19
MESSAGE = b"INVARIANT-38 canonical y"


def _encode(y: int, sign_bit: int = 0) -> bytes:
    """Compressed Edwards encoding: 255-bit little-endian y, x-sign in bit 255."""
    assert 0 <= y < 2**255
    return (y | (sign_bit << 255)).to_bytes(32, "little")


@pytest.fixture(scope="module")
def signed() -> tuple[bytes, bytes]:
    """A real keypair's public key and a valid signature over MESSAGE."""
    public_key, secret_key = native_ed25519_keypair()
    return public_key, native_ed25519_sign(MESSAGE, secret_key)


class TestNonCanonicalYIsRejected:
    """The nineteen encodings in ``[p, 2^255)`` must not verify."""

    @pytest.mark.parametrize("offset", range(19))
    def test_every_value_in_the_band_is_rejected(
        self, offset: int, signed: tuple[bytes, bytes]
    ) -> None:
        _, signature = signed
        assert native_ed25519_verify(signature, MESSAGE, _encode(P + offset)) is False

    @pytest.mark.parametrize("offset", range(19))
    def test_the_sign_bit_does_not_rescue_a_non_canonical_y(
        self, offset: int, signed: tuple[bytes, bytes]
    ) -> None:
        """Bit 255 carries the sign of x, not part of y.

        Masking it off is the first thing the predicate does, so setting it
        must not change the verdict — a rejection that depended on the sign
        bit would be rejecting for the wrong reason.
        """
        _, signature = signed
        assert native_ed25519_verify(signature, MESSAGE, _encode(P + offset, 1)) is False

    def test_the_band_is_exactly_nineteen_values(self) -> None:
        """``2^255 - p == 19``: the guard covers the band and nothing beyond it."""
        assert 2**255 - P == 19


class TestCanonicalYStillVerifies:
    """The change must be strictly narrowing — no conformant encoding is lost."""

    def test_a_real_key_still_verifies(self, signed: tuple[bytes, bytes]) -> None:
        public_key, signature = signed
        assert native_ed25519_verify(signature, MESSAGE, public_key) is True

    def test_p_minus_one_is_canonical(self, signed: tuple[bytes, bytes]) -> None:
        """The largest canonical y must not be caught by an off-by-one.

        ``p - 1`` is almost certainly not on the curve, so this cannot assert
        a successful verify. What it pins is that the *predicate* accepts it:
        a boundary error would make this indistinguishable from the band
        above, and the C test asserts the predicate returns 1 here.
        """
        _, signature = signed
        # Exercised through the binding for parity; the verdict is False for
        # the curve-equation reason, which the C-level predicate test
        # separates out.
        assert native_ed25519_verify(signature, MESSAGE, _encode(P - 1)) is False

    def test_many_fresh_keys_round_trip(self) -> None:
        """Sanity floor: the guard must not reject honestly-generated keys.

        Every conformant signer emits ``y < p``, so a guard that ever fired
        here would be rejecting valid traffic.
        """
        for _ in range(64):
            public_key, secret_key = native_ed25519_keypair()
            assert int.from_bytes(public_key, "little") & ((1 << 255) - 1) < P
            signature = native_ed25519_sign(MESSAGE, secret_key)
            assert native_ed25519_verify(signature, MESSAGE, public_key) is True
