# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Regression pins for X25519 non-canonical u-coordinate handling (INVARIANT-27).

RFC 7748 §5 `decodeUCoordinate` masks bit 255 of a received u-coordinate
and stops there, so a decoded value can land anywhere in [0, 2^255). Since
p = 2^255 - 19, nineteen of those values — [p, 2^255) — are representable
but not canonical: each denotes a field element that has a smaller
encoding too. The RFC then does arithmetic mod p, so the element such an
encoding names is unambiguously `u mod p`.

All three field paths in `src/c/ama_x25519.c` masked the top bit and never
reduced, so a u in that band was consumed unreduced and produced a shared
secret that no other implementation computes. Wycheproof x25519 **tc88** is
exactly this case: its u is `p + 3`.

The RFC does not *require* the reduction — Wycheproof scores the case
`acceptable` — so this is an interoperability decision, taken in favour of
reducing. The failure mode of not reducing is bad out of proportion to how
rare it is: two peers holding the same public key derive different shared
secrets and the handshake fails with nothing to point at.

These tests pin the decision so it cannot be reverted by accident. The
second group pins the *other* X25519 policy the corpus exercises: an
all-zero shared secret is rejected rather than returned (RFC 7748 §6.1).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ama_cryptography.pqc_backends import native_x25519_key_exchange

P = 2**255 - 19
REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS = REPO_ROOT / "wycheproof_vectors" / "vectors" / "x25519_test.json"


def _flags(tc: dict[str, object]) -> list[str]:
    raw = tc.get("flags") or []
    assert isinstance(raw, list)
    return [str(f) for f in raw]


def _vectors() -> dict[int, dict[str, object]]:
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    return {int(t["tcId"]): t for g in data["testGroups"] for t in g["tests"]}


@pytest.fixture(scope="module")
def vectors() -> dict[int, dict[str, object]]:
    return _vectors()


# ---------------------------------------------------------------------------
# The decision: reduce mod p
# ---------------------------------------------------------------------------
def test_wycheproof_tc88_matches_the_reduced_interpretation(
    vectors: dict[int, dict[str, object]],
) -> None:
    """tc88's u-coordinate is p + 3. The shared secret must be the one
    for u = 3 — which is what every reference implementation (ref10,
    curve25519-donna, libsodium) computes."""
    tc = vectors[88]
    public = bytes.fromhex(str(tc["public"]))
    private = bytes.fromhex(str(tc["private"]))
    expected = bytes.fromhex(str(tc["shared"]))

    u = int.from_bytes(public, "little") & ((1 << 255) - 1)
    assert u == P + 3, "tc88 changed shape; this test is pinned to u = p + 3"

    assert native_x25519_key_exchange(private, public) == expected


def test_non_canonical_and_canonical_encodings_agree(vectors: dict[int, dict[str, object]]) -> None:
    """The general property, not just tc88: a u in [p, 2^255) must give
    the same shared secret as its reduced form."""
    tc = vectors[88]
    private = bytes.fromhex(str(tc["private"]))
    public = bytes.fromhex(str(tc["public"]))

    reduced = ((int.from_bytes(public, "little") & ((1 << 255) - 1)) % P).to_bytes(32, "little")
    assert reduced != public, "the two encodings must genuinely differ"
    assert native_x25519_key_exchange(private, public) == native_x25519_key_exchange(
        private, reduced
    )


@pytest.mark.parametrize("offset", [0, 1, 2, 3, 7, 18])
def test_every_value_in_the_non_canonical_band_reduces(offset: int) -> None:
    """There are exactly 19 non-canonical values, p .. p+18. Each must
    behave as its reduced form. Sampled across the band."""
    private = bytes.fromhex("c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475")
    raw = (P + offset).to_bytes(32, "little")
    reduced = (offset % P).to_bytes(32, "little")

    try:
        via_reduced = native_x25519_key_exchange(private, reduced)
    except RuntimeError:
        # u = 0 and u = 1 are low-order points; the contributory check
        # rejects both encodings, which is itself the agreement we want.
        with pytest.raises(RuntimeError):
            native_x25519_key_exchange(private, raw)
        return

    assert native_x25519_key_exchange(private, raw) == via_reduced


def test_high_bit_is_still_masked() -> None:
    """RFC 7748 §5 requires bit 255 to be ignored. Setting it must not
    change the result."""
    private = bytes.fromhex("c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475")
    public = bytearray(
        bytes.fromhex("504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829")
    )
    plain = native_x25519_key_exchange(private, bytes(public))
    public[31] |= 0x80
    assert native_x25519_key_exchange(private, bytes(public)) == plain


# ---------------------------------------------------------------------------
# The other X25519 policy the corpus exercises
# ---------------------------------------------------------------------------
def test_low_order_public_keys_are_rejected_not_zeroed(
    vectors: dict[int, dict[str, object]],
) -> None:
    """RFC 7748 §6.1 permits rejecting an all-zero shared secret; this
    library does, rather than returning 32 bytes that look usable and
    carry no contribution from our private key. Wycheproof scores these
    `acceptable` because returning the zeros is also permitted — the
    stricter behaviour is the one committed to here, and
    wycheproof_vectors/run_wycheproof.py pins the count at 31."""
    zero_shared = [tc for tc in vectors.values() if "ZeroSharedSecret" in _flags(tc)]
    assert len(zero_shared) == 31, "corpus changed; update the policy count in the runner too"

    for tc in zero_shared:
        with pytest.raises(RuntimeError):
            native_x25519_key_exchange(
                bytes.fromhex(str(tc["private"])), bytes.fromhex(str(tc["public"]))
            )


def test_normal_exchange_still_agrees_both_ways() -> None:
    """A guard against the canonicalization breaking the ordinary path:
    two parties must still derive the same secret."""
    from ama_cryptography.pqc_backends import native_x25519_keypair

    pub_a, sec_a = native_x25519_keypair()
    pub_b, sec_b = native_x25519_keypair()
    assert native_x25519_key_exchange(sec_a, pub_b) == native_x25519_key_exchange(sec_b, pub_a)
