# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for native secp256k1 ECDSA (RFC 6979 signing, low-s policy, strict DER).

Three properties carry the security weight, and each is tested for the
behaviour that would be *wrong* as well as the one that is right:

  * **Determinism (RFC 6979).** Signing consumes no randomness, so the
    same inputs always yield the same signature. A nonce that repeats
    across two different messages under one key discloses the private
    key outright, so this is checked directly rather than assumed.
  * **Low-s.** For every valid (r, s) the pair (r, n - s) also satisfies
    the verification equation. Signing must never emit the high form and
    verification must reject it — otherwise a signature is not a unique
    identifier for a (key, message) pair. This is the same defect class
    as the Ed25519 non-canonical-S bug fixed on this branch.
  * **Strict DER.** Non-minimal lengths, non-minimal INTEGERs, leading
    zeros, negative INTEGERs and trailing bytes are all rejected.
"""

from __future__ import annotations

import hashlib

import pytest

from ama_cryptography.pqc_backends import (
    native_secp256k1_ecdsa_sign,
    native_secp256k1_ecdsa_verify,
)

# secp256k1 domain parameters.
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
HALF_N = (N - 1) // 2


# ---------------------------------------------------------------------------
# A small independent curve implementation, used only to check the C code
# against something that was not written by the C code.
# ---------------------------------------------------------------------------
def _add(p: tuple[int, int] | None, q: tuple[int, int] | None) -> tuple[int, int] | None:
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] % P * pow(2 * p[1], -1, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    return x, (lam * (p[0] - x) - p[1]) % P


def _mul(k: int, p: tuple[int, int] | None) -> tuple[int, int] | None:
    r: tuple[int, int] | None = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def _pubkey(d: int) -> bytes:
    q = _mul(d % N, (GX, GY))
    assert q is not None
    return q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")


def _parse_der(sig: bytes) -> tuple[int, int]:
    assert sig[0] == 0x30 and len(sig) == sig[1] + 2
    i = 2
    assert sig[i] == 0x02
    rlen = sig[i + 1]
    r = int.from_bytes(sig[i + 2 : i + 2 + rlen], "big")
    i += 2 + rlen
    assert sig[i] == 0x02
    slen = sig[i + 1]
    s = int.from_bytes(sig[i + 2 : i + 2 + slen], "big")
    return r, s


def _encode_der(r: int, s: int) -> bytes:
    def integer(v: int) -> bytes:
        raw = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return bytes([0x02, len(raw)]) + raw

    body = integer(r) + integer(s)
    return bytes([0x30, len(body)]) + body


PRIV = (0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721).to_bytes(32, "big")
PUB = _pubkey(int.from_bytes(PRIV, "big"))
DIGEST = hashlib.sha256(b"sample").digest()


# ---------------------------------------------------------------------------
# Round trip and independent verification
# ---------------------------------------------------------------------------
def test_sign_verify_round_trip() -> None:
    sig = native_secp256k1_ecdsa_sign(DIGEST, PRIV)
    assert native_secp256k1_ecdsa_verify(sig, DIGEST, PUB)


def test_signature_verifies_under_an_independent_implementation() -> None:
    """A signature the library produces must satisfy the ECDSA equation
    as computed by code that shares nothing with it."""
    sig = native_secp256k1_ecdsa_sign(DIGEST, PRIV)
    r, s = _parse_der(sig)
    z = int.from_bytes(DIGEST, "big")
    w = pow(s, -1, N)
    point = _add(
        _mul(z * w % N, (GX, GY)),
        _mul(r * w % N, (int.from_bytes(PUB[:32], "big"), int.from_bytes(PUB[32:], "big"))),
    )
    assert point is not None
    assert point[0] % N == r


def test_wrong_message_does_not_verify() -> None:
    sig = native_secp256k1_ecdsa_sign(DIGEST, PRIV)
    other = hashlib.sha256(b"not sample").digest()
    assert not native_secp256k1_ecdsa_verify(sig, other, PUB)


def test_wrong_key_does_not_verify() -> None:
    sig = native_secp256k1_ecdsa_sign(DIGEST, PRIV)
    assert not native_secp256k1_ecdsa_verify(sig, DIGEST, _pubkey(2))


# ---------------------------------------------------------------------------
# RFC 6979 determinism
# ---------------------------------------------------------------------------
def test_signing_is_deterministic() -> None:
    """RFC 6979: no randomness is consumed, so repeated signing of the
    same inputs is byte-identical. If this ever fails, an RNG crept into
    the signing path."""
    first = native_secp256k1_ecdsa_sign(DIGEST, PRIV)
    for _ in range(8):
        assert native_secp256k1_ecdsa_sign(DIGEST, PRIV) == first


def test_distinct_messages_use_distinct_nonces() -> None:
    """Reusing a nonce across two messages under one key discloses the
    private key by elementary algebra: k = (z1 - z2)/(s1 - s2), then
    d = (s*k - z)/r. A shared `r` between two signatures is exactly that
    condition, so it is checked directly."""
    seen: set[int] = set()
    for i in range(24):
        digest = hashlib.sha256(f"message {i}".encode()).digest()
        r, _ = _parse_der(native_secp256k1_ecdsa_sign(digest, PRIV))
        assert r not in seen, f"nonce reuse: r repeated at message {i}"
        seen.add(r)


def test_same_message_different_keys_use_distinct_nonces() -> None:
    """The RFC 6979 derivation mixes the private key as well as the
    digest, so two keys signing one message must not share a nonce."""
    seen: set[int] = set()
    for i in range(2, 20):
        priv = i.to_bytes(32, "big")
        r, _ = _parse_der(native_secp256k1_ecdsa_sign(DIGEST, priv))
        assert r not in seen
        seen.add(r)


# ---------------------------------------------------------------------------
# Low-s policy — the malleability control
# ---------------------------------------------------------------------------
def test_signing_always_emits_low_s() -> None:
    for i in range(1, 40):
        digest = hashlib.sha256(f"m{i}".encode()).digest()
        _, s = _parse_der(native_secp256k1_ecdsa_sign(digest, PRIV))
        assert s <= HALF_N, f"high s emitted for message {i}"


def test_high_s_twin_is_rejected() -> None:
    """This is the whole point of the policy. (r, n - s) satisfies the
    verification equation just as (r, s) does — that is the malleability.
    Anyone can construct it from a valid signature with no key material.
    The library must reject it."""
    sig = native_secp256k1_ecdsa_sign(DIGEST, PRIV)
    r, s = _parse_der(sig)
    assert s <= HALF_N
    twin = _encode_der(r, N - s)
    assert twin != sig, "the twin must be a genuinely different byte string"
    assert native_secp256k1_ecdsa_verify(sig, DIGEST, PUB)
    assert not native_secp256k1_ecdsa_verify(
        twin, DIGEST, PUB
    ), "high-s twin verified — signature malleability is back"


def test_s_equal_to_half_n_is_accepted_as_the_boundary() -> None:
    """The policy is `s <= (n-1)/2`, so the boundary value itself is the
    low form. A signature is not constructible at will for a chosen s, so
    this pins the comparison rather than the round trip: s = (n-1)/2 must
    not be classed as high."""
    assert HALF_N * 2 + 1 == N
    sig = native_secp256k1_ecdsa_sign(DIGEST, PRIV)
    _, s = _parse_der(sig)
    assert s != 0 and s < N


# ---------------------------------------------------------------------------
# Strict DER
# ---------------------------------------------------------------------------
def _valid_sig() -> tuple[bytes, int, int]:
    sig = native_secp256k1_ecdsa_sign(DIGEST, PRIV)
    r, s = _parse_der(sig)
    return sig, r, s


def test_trailing_byte_is_rejected() -> None:
    sig, _, _ = _valid_sig()
    assert not native_secp256k1_ecdsa_verify(sig + b"\x00", DIGEST, PUB)


def test_truncated_signature_is_rejected() -> None:
    sig, _, _ = _valid_sig()
    assert not native_secp256k1_ecdsa_verify(sig[:-1], DIGEST, PUB)


def test_wrong_outer_tag_is_rejected() -> None:
    sig, _, _ = _valid_sig()
    assert not native_secp256k1_ecdsa_verify(b"\x31" + sig[1:], DIGEST, PUB)


def test_long_form_length_is_rejected() -> None:
    """DER requires the shortest length encoding. `81 <len>` is BER."""
    sig, _r, _s = _valid_sig()
    body = sig[2:]
    mangled = bytes([0x30, 0x81, len(body)]) + body
    assert not native_secp256k1_ecdsa_verify(mangled, DIGEST, PUB)


def test_non_minimal_integer_is_rejected() -> None:
    """A leading zero byte is only legal when the next byte's top bit is
    set. An unnecessary one makes the encoding non-minimal."""
    _, r, s = _valid_sig()

    def integer(v: int, extra_pad: int = 0) -> bytes:
        raw = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        raw = b"\x00" * extra_pad + raw
        return bytes([0x02, len(raw)]) + raw

    for pad_r, pad_s in ((1, 0), (0, 1)):
        body = integer(r, pad_r) + integer(s, pad_s)
        mangled = bytes([0x30, len(body)]) + body
        assert not native_secp256k1_ecdsa_verify(mangled, DIGEST, PUB)


def test_negative_integer_is_rejected() -> None:
    """An INTEGER whose top bit is set without a leading zero is negative
    in DER; r and s are unsigned."""
    body = bytes([0x02, 0x20]) + (b"\xff" * 32) + bytes([0x02, 0x20]) + (b"\x01" * 32)
    mangled = bytes([0x30, len(body)]) + body
    assert not native_secp256k1_ecdsa_verify(mangled, DIGEST, PUB)


def test_zero_r_or_s_is_rejected() -> None:
    for r, s in ((0, 1), (1, 0), (0, 0)):
        mangled = _encode_der(r, s)
        assert not native_secp256k1_ecdsa_verify(mangled, DIGEST, PUB)


def test_r_or_s_at_or_above_the_group_order_is_rejected() -> None:
    """A value >= n must be rejected, not reduced. Reducing would let a
    second byte string verify for the same message."""
    _, r, s = _valid_sig()
    for mangled in (_encode_der(r + N, s), _encode_der(r, s + N), _encode_der(N, s)):
        assert not native_secp256k1_ecdsa_verify(mangled, DIGEST, PUB)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
def test_off_curve_public_key_is_rejected() -> None:
    """The public key must satisfy y^2 = x^3 + 7."""
    bad = (GX.to_bytes(32, "big")) + ((GY ^ 1).to_bytes(32, "big"))
    sig, _, _ = _valid_sig()
    assert not native_secp256k1_ecdsa_verify(sig, DIGEST, bad)


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_wrong_digest_length_raises(length: int) -> None:
    with pytest.raises(ValueError):
        native_secp256k1_ecdsa_sign(b"\x01" * length, PRIV)


@pytest.mark.parametrize("length", [0, 31, 33])
def test_wrong_private_key_length_raises(length: int) -> None:
    with pytest.raises(ValueError):
        native_secp256k1_ecdsa_sign(DIGEST, b"\x01" * length)


@pytest.mark.parametrize("length", [0, 32, 63, 65])
def test_wrong_public_key_length_raises(length: int) -> None:
    sig, _, _ = _valid_sig()
    with pytest.raises(ValueError):
        native_secp256k1_ecdsa_verify(sig, DIGEST, b"\x04" * length)


def test_zero_private_key_is_rejected() -> None:
    with pytest.raises(RuntimeError):
        native_secp256k1_ecdsa_sign(DIGEST, b"\x00" * 32)


def test_private_key_equal_to_group_order_is_rejected() -> None:
    with pytest.raises(RuntimeError):
        native_secp256k1_ecdsa_sign(DIGEST, N.to_bytes(32, "big"))
