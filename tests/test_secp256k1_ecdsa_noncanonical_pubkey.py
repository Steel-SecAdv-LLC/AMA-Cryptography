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
control is *not constructible* for secp256k1. The non-canonical band ``[p,
2^256)`` holds only ``2^32 + 977`` values, whose reduced images lie in ``[0,
2^32 + 977)``; producing a *valid* signature for a public key with such a tiny
x-coordinate would require solving the ECDLP or forging ECDSA. So the gate is
exercised here through the policy it enforces (out-of-field coordinates are
rejected) and isolated from the curve/signature checks by the direct
predicate test in ``tests/c/test_secp256k1.c`` (Test 10, the AMA_TESTING_MODE
export).
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
