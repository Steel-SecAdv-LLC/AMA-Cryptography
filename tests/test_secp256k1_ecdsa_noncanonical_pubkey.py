# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Non-canonical ECDSA public-key coordinate rejection (INVARIANT-29).

Wycheproof's secp256k1 ECDSA corpus is verify-only and ships no out-of-field
public-key vectors, so this coverage is generated here. ``ama_secp256k1_ecdsa_
verify`` must reject a public key whose ``Qx`` or ``Qy`` coordinate is ``>= p``
rather than silently reducing it modulo ``p`` before the curve-membership check
— the same input-canonicalization stance the ``r, s ∈ [1, n-1]`` range check
takes, and the policy analogue of the X25519 non-canonical-``u`` decision (there
resolved toward *reduction*; here, for a signature public key, toward
*rejection*, so a signature cannot verify under a second, non-canonical encoding
of the same key).

Note on scope: an end-to-end "reduces to a valid, verifying point" positive
control is *not constructible* for the *verify* path on secp256k1. The
non-canonical band ``[p, 2^256)`` holds only ``2^32 + 977`` values, whose
reduced images lie in ``[0, 2^32 + 977)``; producing a *valid* signature for a
public key with such a tiny x-coordinate would require solving the ECDLP or
forging ECDSA. So the gate is exercised here through the policy it enforces
(out-of-field coordinates are rejected) and isolated from the curve/signature
checks by the direct predicate test in ``tests/c/test_secp256k1.c`` (Test 10,
the AMA_TESTING_MODE export).

That limit belongs to verify, not to the curve. ``ama_secp256k1_pubkey_
decompress`` needs no signature, so the same tiny x *is* usable there, and
``TestDecompressRejectsASecondEncodingOfARealPoint`` at the foot of this module
carries the paired accept/reject case the verify path has to do without.
"""

from __future__ import annotations

import pytest

from ama_cryptography.pqc_backends import _native_lib

pytestmark = pytest.mark.skipif(
    _native_lib is None,
    reason="Native C library not built — skipping secp256k1 ECDSA tests",
)

# secp256k1 field prime p = 2^256 - 2^32 - 977.
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# A valid private key in [1, n-1] and a fixed 32-byte digest.
_PRIV = bytes.fromhex("0123456789abcdeffedcba98765432100f1e2d3c4b5a69788796a5b4c3d2e1f0")
_DIGEST = bytes(range(1, 33))

# Non-canonical coordinate encodings (each is >= p) and the max canonical one.
_OUT_OF_FIELD = {
    "p": _P,
    "p_plus_1": _P + 1,
    "two_pow_256_minus_1": (1 << 256) - 1,
}
_P_MINUS_1 = _P - 1


def _uncompressed_pubkey(privkey: bytes) -> bytes:
    """Derive the 64-byte uncompressed (X||Y) public key for ``privkey``.

    The native export is 33-byte SEC1 compressed; recover Y from X via the curve
    equation (secp256k1's p ≡ 3 mod 4, so the square root is one exponentiation)
    and pick the parity the compression prefix encodes.
    """
    from ama_cryptography.pqc_backends import native_secp256k1_pubkey_from_privkey

    compressed = native_secp256k1_pubkey_from_privkey(privkey)
    prefix, x_bytes = compressed[0], compressed[1:]
    x = int.from_bytes(x_bytes, "big")
    y = pow((pow(x, 3, _P) + 7) % _P, (_P + 1) // 4, _P)
    if (y & 1) != (prefix & 1):
        y = _P - y
    return x_bytes + y.to_bytes(32, "big")


def _valid_triple() -> tuple[bytes, bytes, bytes]:
    from ama_cryptography.pqc_backends import native_secp256k1_ecdsa_sign

    pubkey = _uncompressed_pubkey(_PRIV)
    signature = native_secp256k1_ecdsa_sign(_DIGEST, _PRIV)
    return signature, _DIGEST, pubkey


def _with_coordinate(pubkey: bytes, which: str, value: int) -> bytes:
    coord = value.to_bytes(32, "big") if value < (1 << 256) else (b"\xff" * 32)
    if which == "x":
        return coord + pubkey[32:]
    return pubkey[:32] + coord


class TestNonCanonicalPubkeyRejected:
    def test_valid_triple_verifies(self) -> None:
        """Positive control: the canonical key + a real signature verify."""
        from ama_cryptography.pqc_backends import native_secp256k1_ecdsa_verify

        signature, digest, pubkey = _valid_triple()
        assert native_secp256k1_ecdsa_verify(signature, digest, pubkey) is True

    @pytest.mark.parametrize("coord", ["x", "y"])
    @pytest.mark.parametrize("name", sorted(_OUT_OF_FIELD))
    def test_out_of_field_coordinate_is_rejected(self, coord: str, name: str) -> None:
        """A coordinate >= p is rejected (False), not silently reduced."""
        from ama_cryptography.pqc_backends import native_secp256k1_ecdsa_verify

        signature, digest, pubkey = _valid_triple()
        bad = _with_coordinate(pubkey, coord, _OUT_OF_FIELD[name])
        assert bad != pubkey
        assert native_secp256k1_ecdsa_verify(signature, digest, bad) is False

    def test_p_minus_one_is_canonical_but_still_not_the_key(self) -> None:
        """Non-vacuity: p-1 is a *canonical* coordinate (it passes the [0, p)
        gate), yet it is not this key's coordinate, so the end-to-end verify
        still returns False — via the curve/signature checks, not the gate. The
        gate itself is isolated in tests/c/test_secp256k1.c."""
        from ama_cryptography.pqc_backends import native_secp256k1_ecdsa_verify

        signature, digest, pubkey = _valid_triple()
        assert _P_MINUS_1 < _P  # canonical by definition
        bad = _with_coordinate(pubkey, "x", _P_MINUS_1)
        assert native_secp256k1_ecdsa_verify(signature, digest, bad) is False


# The lowest x on secp256k1: 1**3 + 7 = 8, and 8 is a quadratic residue mod p.
# It is what makes the class below constructible where the verify path above
# is not: the non-canonical band is [p, 2**256), only 2**32 + 977 wide, so
# ``x + p`` fits in 32 octets exactly when ``x`` is smaller than that — which
# an x of 1 comfortably is.
_LOW_X = 1
_LOW_Y = pow((pow(_LOW_X, 3, _P) + 7) % _P, (_P + 1) // 4, _P)


class TestDecompressRejectsASecondEncodingOfARealPoint:
    """``ama_secp256k1_pubkey_decompress`` rejects ``x >= p``, never reduces it.

    This is the paired accept/reject case the verify path cannot have, and it
    matters because decompress is the entry point ``ama_cryptography.
    key_formats`` uses to import the compressed public keys that SPKI, COSE and
    the Bitcoin/Ethereum ecosystems actually carry — so it parses attacker-
    supplied octets, and the header promises of it that "a value >= p is
    rejected, never reduced".

    Nothing held that promise to account. Measured against a build with the
    ``secp256k1_fe_bytes_canonical`` call in ``ama_secp256k1_pubkey_decompress``
    deleted, 591 Python tests and the whole ``test_secp256k1`` C suite passed
    while decompress accepted ``x = p + 1`` and returned a 64-octet key whose
    X half was the non-canonical encoding. Test 10 of the C suite does isolate
    the ``[0, p)`` predicate, but calls it directly, so it cannot notice a
    caller that stops consulting it.
    """

    def test_the_canonical_encoding_decompresses(self) -> None:
        """Positive control: without this the rejection below proves nothing."""
        from ama_cryptography.pqc_backends import native_secp256k1_pubkey_decompress

        prefix = bytes([0x02 + (_LOW_Y & 1)])
        out = native_secp256k1_pubkey_decompress(prefix + _LOW_X.to_bytes(32, "big"))
        assert out == _LOW_X.to_bytes(32, "big") + _LOW_Y.to_bytes(32, "big")

    def test_the_non_canonical_twin_is_refused(self) -> None:
        """``x + p`` names the same point and must still be refused.

        The two cases differ in exactly one respect — whether the x octets are
        the canonical representative — so only the canonicality rule can
        separate them. A build that reduced first would decompress both.
        """
        from ama_cryptography.pqc_backends import native_secp256k1_pubkey_decompress

        prefix = bytes([0x02 + (_LOW_Y & 1)])
        second = _LOW_X + _P
        assert second < (1 << 256), "x + p must fit in 32 octets or this is not a twin"
        with pytest.raises(ValueError):
            native_secp256k1_pubkey_decompress(prefix + second.to_bytes(32, "big"))
