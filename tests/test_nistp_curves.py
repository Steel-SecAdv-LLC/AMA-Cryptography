#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
NIST prime curves — P-256 / P-384 / P-521 (ECDSA + ECDH).
=========================================================

The adversarial coverage for these curves lives in the vendored Wycheproof
corpus (1530 vectors across the three suites, run by
``wycheproof_vectors/run_wycheproof.py`` on every PR). This module covers what
that corpus cannot:

* **Independent-reference agreement.** A pure-Python ECDSA/ECDH reference is
  built from the SP 800-186 curve parameters using nothing but ``int``
  arithmetic, and the C implementation is required to agree with it
  byte-for-byte — including the RFC 6979 nonce, which is re-derived here from
  the RFC's own HMAC_DRBG construction. Wycheproof only checks *verification*;
  this is what pins *signing*.
* **Policy.** Signing always emits low-``s``; verification accepts either
  representative by default and rejects the high twin under
  ``require_low_s``. That split is INVARIANT-34 and is the reason these curves
  interoperate at all.
* **Negative space.** Non-canonical coordinates, off-curve points, the
  identity, out-of-range scalars, wrong digest widths, malformed DER, and
  cross-curve confusion.
* **ECDH validation.** A peer key that is off-curve or non-canonical must be
  rejected *before* the private scalar touches it — the invalid-curve defence.

The reference implementation is deliberately the slowest, most obvious code
that could work. Agreeing with it is evidence about the C implementation
precisely because the two share no structure.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import ama_cryptography.pqc_backends as pb  # noqa: E402 -- import follows the repo-root sys.path insert above (NISTP-001)

pytestmark = pytest.mark.skipif(
    not pb._NISTP_NATIVE_AVAILABLE, reason="native NIST prime-curve backend not built"
)


# ---------------------------------------------------------------------------
# SP 800-186 curve parameters, typed out independently of the C table
# ---------------------------------------------------------------------------
CURVES: dict[str, dict] = {
    "P-256": {
        "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        "gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        "gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        "nbytes": 32,
        "hash": "sha256",
    },
    "P-384": {
        "p": int(
            "fffffffffffffffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffeffffffff0000000000000000ffffffff", 16
        ),
        "n": int(
            "ffffffffffffffffffffffffffffffffffffffffffffffffc"
            "7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16
        ),
        "b": int(
            "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120"
            "314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16
        ),
        "gx": int(
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b985"
            "9f741e082542a385502f25dbf55296c3a545e3872760ab7", 16
        ),
        "gy": int(
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce"
            "9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16
        ),
        "nbytes": 48,
        "hash": "sha384",
    },
    "P-521": {
        "p": (1 << 521) - 1,
        "n": int(
            "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            "fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138"
            "6409",
            16,
        ),
        "b": int(
            "51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109"
            "e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f"
            "00",
            16,
        ),
        "gx": int(
            "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3d"
            "baa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd"
            "66",
            16,
        ),
        "gy": int(
            "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e"
            "662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd1"
            "6650",
            16,
        ),
        "nbytes": 66,
        "hash": "sha512",
    },
}
CURVE_NAMES = tuple(CURVES)


# ---------------------------------------------------------------------------
# Pure-Python reference: affine short Weierstrass with a = -3
# ---------------------------------------------------------------------------
def _add(pt_a, pt_b, p):
    if pt_a is None:
        return pt_b
    if pt_b is None:
        return pt_a
    (x1, y1), (x2, y2) = pt_a, pt_b
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if pt_a == pt_b:
        lam = (3 * x1 * x1 - 3) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)


def _mul(k, pt, p):
    acc = None
    for bit in bin(k)[2:]:
        acc = _add(acc, acc, p)
        if bit == "1":
            acc = _add(acc, pt, p)
    return acc


def _bits2int(octets: bytes, qlen: int) -> int:
    value = int.from_bytes(octets, "big")
    blen = len(octets) * 8
    return value >> (blen - qlen) if blen > qlen else value


def _rfc6979_k(x: int, digest: bytes, n: int, qlen: int, hashname: str, nbytes: int) -> int:
    """RFC 6979 §3.2 HMAC_DRBG, written straight from the RFC."""
    hlen = hashlib.new(hashname).digest_size

    def prf(key: bytes, msg: bytes) -> bytes:
        return hmac.new(key, msg, hashname).digest()

    x_oct = x.to_bytes(nbytes, "big")
    h_oct = (_bits2int(digest, qlen) % n).to_bytes(nbytes, "big")
    V = b"\x01" * hlen
    K = b"\x00" * hlen
    K = prf(K, V + b"\x00" + x_oct + h_oct)
    V = prf(K, V)
    K = prf(K, V + b"\x01" + x_oct + h_oct)
    V = prf(K, V)
    while True:
        T = b""
        while len(T) * 8 < qlen:
            V = prf(K, V)
            T += V
        k = _bits2int(T, qlen)
        if 1 <= k < n:
            return k
        K = prf(K, V + b"\x00")
        V = prf(K, V)


def _ref_sign(name: str, digest: bytes, d: int) -> tuple[int, int]:
    c = CURVES[name]
    p, n, nb = c["p"], c["n"], c["nbytes"]
    qlen = n.bit_length()
    k = _rfc6979_k(d, digest, n, qlen, c["hash"], nb)
    point = _mul(k, (c["gx"], c["gy"]), p)
    r = point[0] % n
    e = _bits2int(digest, qlen) % n
    s = pow(k, -1, n) * (e + r * d) % n
    if s > (n - 1) // 2:  # AMA always emits the low representative
        s = n - s
    return r, s


def _pub(name: str, d: int) -> bytes:
    c = CURVES[name]
    pt = _mul(d, (c["gx"], c["gy"]), c["p"])
    return pt[0].to_bytes(c["nbytes"], "big") + pt[1].to_bytes(c["nbytes"], "big")


def _digest(name: str, msg: bytes) -> bytes:
    return hashlib.new(CURVES[name]["hash"], msg).digest()


# ---------------------------------------------------------------------------
# Curve parameter sanity — the table above must describe real curves
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", CURVE_NAMES)
def test_generator_is_on_the_curve(name: str) -> None:
    c = CURVES[name]
    lhs = c["gy"] * c["gy"] % c["p"]
    rhs = (pow(c["gx"], 3, c["p"]) - 3 * c["gx"] + c["b"]) % c["p"]
    assert lhs == rhs
    assert _mul(c["n"], (c["gx"], c["gy"]), c["p"]) is None, "n*G must be the identity"


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_metadata_matches_the_curve(name: str) -> None:
    assert pb.nistp_field_bytes(name) == CURVES[name]["nbytes"]


# ---------------------------------------------------------------------------
# Public-key derivation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", CURVE_NAMES)
def test_pubkey_matches_reference(name: str) -> None:
    """Boundary scalars plus random ones, against the affine reference."""
    n = CURVES[name]["n"]
    nb = CURVES[name]["nbytes"]
    scalars = [1, 2, n - 1, n - 2] + [secrets.randbelow(n - 1) + 1 for _ in range(3)]
    for d in scalars:
        got = pb.native_nistp_pubkey_from_privkey(name, d.to_bytes(nb, "big"))
        assert got == _pub(name, d), f"{name}: derivation diverged at d={d:x}"


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_out_of_range_private_keys_rejected(name: str) -> None:
    n, nb = CURVES[name]["n"], CURVES[name]["nbytes"]
    for bad in (0, n, n + 1, (1 << (nb * 8)) - 1):
        if bad.bit_length() > nb * 8:
            continue
        with pytest.raises(RuntimeError):
            pb.native_nistp_pubkey_from_privkey(name, bad.to_bytes(nb, "big"))
    with pytest.raises(ValueError):
        pb.native_nistp_pubkey_from_privkey(name, b"\x01" * (nb - 1))


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_keypair_generation_is_valid_and_varied(name: str) -> None:
    seen = set()
    for _ in range(4):
        priv, pub = pb.native_nistp_keypair(name)
        assert len(priv) == CURVES[name]["nbytes"]
        assert len(pub) == 2 * CURVES[name]["nbytes"]
        assert 1 <= int.from_bytes(priv, "big") < CURVES[name]["n"]
        assert pb.native_nistp_pubkey_validate(name, pub)
        assert pb.native_nistp_pubkey_from_privkey(name, priv) == pub
        seen.add(priv)
    assert len(seen) == 4, "keygen returned a repeated private key"


# ---------------------------------------------------------------------------
# ECDSA against the RFC 6979 reference
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", CURVE_NAMES)
def test_ecdsa_matches_rfc6979_reference(name: str) -> None:
    nb = CURVES[name]["nbytes"]
    n = CURVES[name]["n"]
    for i in range(3):
        d = secrets.randbelow(n - 1) + 1
        priv = d.to_bytes(nb, "big")
        digest = _digest(name, b"ama-nistp-%s-%d" % (name.encode(), i))
        raw = pb.native_nistp_ecdsa_sign(name, digest, priv, raw=True)
        r_got = int.from_bytes(raw[:nb], "big")
        s_got = int.from_bytes(raw[nb:], "big")
        assert (r_got, s_got) == _ref_sign(name, digest, d), (
            f"{name}: signature diverged from the RFC 6979 reference"
        )


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_ecdsa_is_deterministic(name: str) -> None:
    priv, pub = pb.native_nistp_keypair(name)
    digest = _digest(name, b"determinism")
    first = pb.native_nistp_ecdsa_sign(name, digest, priv)
    assert first == pb.native_nistp_ecdsa_sign(name, digest, priv)
    assert pb.native_nistp_ecdsa_verify(name, first, digest, pub)


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_nonce_does_not_repeat_across_messages_or_keys(name: str) -> None:
    """Distinct (key, digest) pairs must yield distinct r.

    A repeated ``r`` across two messages under one key leaks the private key
    outright, so this is the single most destructive ECDSA failure mode.
    """
    nb = CURVES[name]["nbytes"]
    priv_a, _ = pb.native_nistp_keypair(name)
    priv_b, _ = pb.native_nistp_keypair(name)
    rs = set()
    for priv in (priv_a, priv_b):
        for msg in (b"m0", b"m1", b"m2"):
            raw = pb.native_nistp_ecdsa_sign(name, _digest(name, msg), priv, raw=True)
            rs.add(raw[:nb])
    assert len(rs) == 6, "an RFC 6979 nonce repeated across messages or keys"


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_hedged_signing_differs_but_verifies(name: str) -> None:
    priv, pub = pb.native_nistp_keypair(name)
    digest = _digest(name, b"hedged")
    det = pb.native_nistp_ecdsa_sign(name, digest, priv)
    h1 = pb.native_nistp_ecdsa_sign(name, digest, priv, hedged=True)
    h2 = pb.native_nistp_ecdsa_sign(name, digest, priv, hedged=True)
    assert h1 != det and h1 != h2, "hedged signing produced a deterministic signature"
    assert pb.native_nistp_ecdsa_verify(name, h1, digest, pub)
    assert pb.native_nistp_ecdsa_verify(name, h2, digest, pub)
    with pytest.raises(ValueError):
        pb.native_nistp_ecdsa_sign(name, digest, priv, raw=True, hedged=True)


@pytest.mark.parametrize("name", CURVE_NAMES)
@pytest.mark.parametrize("digest_len", [32, 48, 64])
def test_every_supported_digest_width_works(name: str, digest_len: int) -> None:
    """FIPS 186-5 truncation makes any of the three widths well defined."""
    priv, pub = pb.native_nistp_keypair(name)
    digest = secrets.token_bytes(digest_len)
    sig = pb.native_nistp_ecdsa_sign(name, digest, priv)
    assert pb.native_nistp_ecdsa_verify(name, sig, digest, pub)


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_unsupported_digest_widths_rejected(name: str) -> None:
    priv, pub = pb.native_nistp_keypair(name)
    for bad in (0, 20, 31, 33, 65):
        with pytest.raises(ValueError):
            pb.native_nistp_ecdsa_sign(name, b"\x00" * bad, priv)
        with pytest.raises(ValueError):
            pb.native_nistp_ecdsa_verify(name, b"\x30\x06\x02\x01\x01\x02\x01\x01",
                                         b"\x00" * bad, pub)


# ---------------------------------------------------------------------------
# INVARIANT-34: low-s on signing, X9.62 by default on verification
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", CURVE_NAMES)
def test_signing_always_emits_low_s(name: str) -> None:
    nb, n = CURVES[name]["nbytes"], CURVES[name]["n"]
    for i in range(6):
        priv, _ = pb.native_nistp_keypair(name)
        raw = pb.native_nistp_ecdsa_sign(name, _digest(name, b"low-s-%d" % i), priv, raw=True)
        s = int.from_bytes(raw[nb:], "big")
        assert s <= (n - 1) // 2, f"{name}: signer emitted a high s"


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_high_s_twin_accepted_by_default_rejected_when_strict(name: str) -> None:
    """The malleability twin verifies under X9.62 and not under the strict flag.

    Accepting it by default is what makes these curves usable against TLS,
    X.509, JWS and WebAuthn signers; the strict mode is there for callers who
    own both ends. Both directions are asserted so neither can silently drift.
    """
    nb, n = CURVES[name]["nbytes"], CURVES[name]["n"]
    priv, pub = pb.native_nistp_keypair(name)
    digest = _digest(name, b"malleability")
    raw = pb.native_nistp_ecdsa_sign(name, digest, priv, raw=True)
    r = raw[:nb]
    s = int.from_bytes(raw[nb:], "big")
    twin = r + (n - s).to_bytes(nb, "big")

    assert pb.native_nistp_ecdsa_verify(name, raw, digest, pub, raw=True)
    assert pb.native_nistp_ecdsa_verify(name, twin, digest, pub, raw=True)
    assert pb.native_nistp_ecdsa_verify(name, raw, digest, pub, raw=True, require_low_s=True)
    assert not pb.native_nistp_ecdsa_verify(
        name, twin, digest, pub, raw=True, require_low_s=True
    )


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_out_of_range_signature_components_rejected(name: str) -> None:
    """``r`` or ``s`` >= n must be rejected, never reduced into range."""
    nb, n = CURVES[name]["nbytes"], CURVES[name]["n"]
    priv, pub = pb.native_nistp_keypair(name)
    digest = _digest(name, b"range")
    raw = pb.native_nistp_ecdsa_sign(name, digest, priv, raw=True)
    r = int.from_bytes(raw[:nb], "big")
    s = int.from_bytes(raw[nb:], "big")

    for bad_r, bad_s in ((r + n, s), (r, s + n), (0, s), (r, 0)):
        if bad_r.bit_length() > nb * 8 or bad_s.bit_length() > nb * 8:
            continue
        forged = bad_r.to_bytes(nb, "big") + bad_s.to_bytes(nb, "big")
        assert not pb.native_nistp_ecdsa_verify(name, forged, digest, pub, raw=True)


# ---------------------------------------------------------------------------
# Signature encodings
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", CURVE_NAMES)
def test_der_and_raw_are_the_same_signature(name: str) -> None:
    priv, pub = pb.native_nistp_keypair(name)
    digest = _digest(name, b"encodings")
    der = pb.native_nistp_ecdsa_sign(name, digest, priv)
    raw = pb.native_nistp_ecdsa_sign(name, digest, priv, raw=True)

    assert len(raw) == 2 * CURVES[name]["nbytes"]
    assert pb.native_nistp_sig_der_to_raw(name, der) == raw
    assert pb.native_nistp_sig_raw_to_der(name, raw) == der
    assert pb.native_nistp_ecdsa_verify(name, der, digest, pub)
    assert pb.native_nistp_ecdsa_verify(name, raw, digest, pub, raw=True)


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_der_is_minimal_and_strictly_parsed(name: str) -> None:
    """Only minimal DER is accepted — the encoding-malleability control."""
    priv, pub = pb.native_nistp_keypair(name)
    digest = _digest(name, b"strict der")
    der = bytearray(pb.native_nistp_ecdsa_sign(name, digest, priv))

    # A trailing byte must not be ignored.
    assert not pb.native_nistp_ecdsa_verify(name, bytes(der) + b"\x00", digest, pub)
    # A truncated signature must not parse.
    assert not pb.native_nistp_ecdsa_verify(name, bytes(der[:-1]), digest, pub)
    # A wrong outer tag must not parse.
    wrong_tag = bytearray(der)
    wrong_tag[0] = 0x31
    assert not pb.native_nistp_ecdsa_verify(name, bytes(wrong_tag), digest, pub)
    # An empty signature must not parse.
    assert not pb.native_nistp_ecdsa_verify(name, b"", digest, pub)

    for bad in (b"", b"\x30", bytes(der) + b"\x00", bytes(der[:4])):
        with pytest.raises(ValueError):
            pb.native_nistp_sig_der_to_raw(name, bad)


def test_p521_der_uses_long_form_length_when_needed() -> None:
    """A P-521 body exceeds 127 octets, so DER must use the long form.

    This is the case the secp256k1 parser cannot express, and getting it wrong
    produces signatures no other implementation reads.
    """
    priv, pub = pb.native_nistp_keypair("P-521")
    der = pb.native_nistp_ecdsa_sign("P-521", _digest("P-521", b"long form"), priv)
    assert der[0] == 0x30
    assert der[1] == 0x81, "P-521 SEQUENCE length must use the one-octet long form"
    assert der[2] >= 0x80, "long form must not be used for a short length"
    assert len(der) == 3 + der[2]
    assert pb.native_nistp_ecdsa_verify("P-521", der, _digest("P-521", b"long form"), pub)


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_raw_conversion_rejects_bad_lengths(name: str) -> None:
    nb = CURVES[name]["nbytes"]
    with pytest.raises(ValueError):
        pb.native_nistp_sig_raw_to_der(name, b"\x01" * (2 * nb - 1))
    with pytest.raises(ValueError):
        pb.native_nistp_sig_raw_to_der(name, b"\x00" * (2 * nb))  # r = s = 0


# ---------------------------------------------------------------------------
# Public-key validation (INVARIANT-29 analogue)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", CURVE_NAMES)
def test_non_canonical_and_off_curve_keys_rejected(name: str) -> None:
    c = CURVES[name]
    nb, p = c["nbytes"], c["p"]
    _priv, pub = pb.native_nistp_keypair(name)
    x, y = pub[:nb], pub[nb:]

    assert pb.native_nistp_pubkey_validate(name, pub)

    # A coordinate >= p is a second encoding of a reduced point: rejected,
    # never reduced.
    for bad in (p, p + 1, (1 << (nb * 8)) - 1):
        if bad.bit_length() > nb * 8:
            continue
        assert not pb.native_nistp_pubkey_validate(name, bad.to_bytes(nb, "big") + y)
        assert not pb.native_nistp_pubkey_validate(name, x + bad.to_bytes(nb, "big"))

    # Off the curve.
    flipped = bytearray(pub)
    flipped[-1] ^= 0x01
    assert not pb.native_nistp_pubkey_validate(name, bytes(flipped))

    # The all-zero encoding is the identity and is not a usable public key.
    assert not pb.native_nistp_pubkey_validate(name, b"\x00" * (2 * nb))

    # Wrong length.
    assert not pb.native_nistp_pubkey_validate(name, pub[:-1])


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_verification_rejects_invalid_public_keys(name: str) -> None:
    nb = CURVES[name]["nbytes"]
    priv, pub = pb.native_nistp_keypair(name)
    digest = _digest(name, b"bad key")
    sig = pb.native_nistp_ecdsa_sign(name, digest, priv)

    flipped = bytearray(pub)
    flipped[-1] ^= 0x01
    assert not pb.native_nistp_ecdsa_verify(name, sig, digest, bytes(flipped))
    assert not pb.native_nistp_ecdsa_verify(name, sig, digest, b"\x00" * (2 * nb))


# ---------------------------------------------------------------------------
# SEC 1 point encoding
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", CURVE_NAMES)
def test_sec1_encoding_roundtrips(name: str) -> None:
    nb = CURVES[name]["nbytes"]
    for _ in range(3):
        _, pub = pb.native_nistp_keypair(name)
        uncompressed = pb.native_nistp_point_encode(name, pub)
        compressed = pb.native_nistp_point_encode(name, pub, compressed=True)

        assert uncompressed[0] == 0x04 and len(uncompressed) == 2 * nb + 1
        assert compressed[0] in (0x02, 0x03) and len(compressed) == nb + 1
        assert compressed[0] == 0x02 + (pub[-1] & 1)

        assert pb.native_nistp_point_decode(name, uncompressed) == pub
        assert pb.native_nistp_point_decode(name, compressed) == pub


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_sec1_decoding_rejects_malformed_points(name: str) -> None:
    c = CURVES[name]
    nb, p = c["nbytes"], c["p"]
    _, pub = pb.native_nistp_keypair(name)
    compressed = pb.native_nistp_point_encode(name, pub, compressed=True)

    bad_inputs = [
        b"",
        b"\x04",
        b"\x00" + compressed[1:],           # unknown prefix
        b"\x05" + compressed[1:],           # unknown prefix
        compressed[:-1],                    # truncated
        compressed + b"\x00",               # over-long
        bytes([compressed[0]]) + p.to_bytes(nb, "big"),  # non-canonical x
    ]
    for bad in bad_inputs:
        with pytest.raises(ValueError):
            pb.native_nistp_point_decode(name, bad)


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_decompression_rejects_x_not_on_curve(name: str) -> None:
    """An x whose x^3 - 3x + b is a non-residue must be rejected outright."""
    c = CURVES[name]
    nb, p, b = c["nbytes"], c["p"], c["b"]
    found = 0
    for x in range(2, 400):
        rhs = (pow(x, 3, p) - 3 * x + b) % p
        if pow(rhs, (p - 1) // 2, p) == 1:
            continue  # x IS on the curve; not a negative case
        with pytest.raises(ValueError):
            pb.native_nistp_point_decode(name, b"\x02" + x.to_bytes(nb, "big"))
        found += 1
        if found == 3:
            break
    assert found == 3, "could not find enough off-curve x values to test"


# ---------------------------------------------------------------------------
# ECDH
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", CURVE_NAMES)
def test_ecdh_agrees_and_matches_reference(name: str) -> None:
    c = CURVES[name]
    nb, p, n = c["nbytes"], c["p"], c["n"]
    for _ in range(2):
        priv_a, pub_a = pb.native_nistp_keypair(name)
        priv_b, pub_b = pb.native_nistp_keypair(name)
        z_ab = pb.native_nistp_ecdh(name, priv_a, pub_b)
        z_ba = pb.native_nistp_ecdh(name, priv_b, pub_a)
        assert z_ab == z_ba
        assert len(z_ab) == nb

        da = int.from_bytes(priv_a, "big")
        db = int.from_bytes(priv_b, "big")
        expected = _mul(da * db % n, (c["gx"], c["gy"]), p)
        assert z_ab == expected[0].to_bytes(nb, "big")


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_ecdh_rejects_invalid_peer_keys(name: str) -> None:
    """Invalid-curve defence: the peer key is validated before use.

    Without this check a peer that offers a point on a smooth-order curve
    recovers the private scalar from a handful of exchanges, so the rejection
    is load-bearing rather than hygiene.
    """
    c = CURVES[name]
    nb, p = c["nbytes"], c["p"]
    priv, _ = pb.native_nistp_keypair(name)
    _, peer = pb.native_nistp_keypair(name)

    off_curve = bytearray(peer)
    off_curve[-1] ^= 0x01
    with pytest.raises(RuntimeError):
        pb.native_nistp_ecdh(name, priv, bytes(off_curve))

    with pytest.raises(RuntimeError):
        pb.native_nistp_ecdh(name, priv, b"\x00" * (2 * nb))  # identity

    non_canonical = p.to_bytes(nb, "big") + peer[nb:]
    with pytest.raises(RuntimeError):
        pb.native_nistp_ecdh(name, priv, non_canonical)

    with pytest.raises(ValueError):
        pb.native_nistp_ecdh(name, priv, peer[:-1])
    with pytest.raises(ValueError):
        pb.native_nistp_ecdh(name, priv[:-1], peer)


@pytest.mark.parametrize("name", CURVE_NAMES)
def test_ecdh_rejects_out_of_range_private_scalar(name: str) -> None:
    n, nb = CURVES[name]["n"], CURVES[name]["nbytes"]
    _, peer = pb.native_nistp_keypair(name)
    for bad in (0, n):
        with pytest.raises(RuntimeError):
            pb.native_nistp_ecdh(name, bad.to_bytes(nb, "big"), peer)


# ---------------------------------------------------------------------------
# Cross-curve confusion
# ---------------------------------------------------------------------------
def test_keys_and_signatures_do_not_cross_curves() -> None:
    """A P-256 key must not be usable as a P-384 key, and vice versa."""
    priv256, pub256 = pb.native_nistp_keypair("P-256")
    _priv384, pub384 = pb.native_nistp_keypair("P-384")
    digest = hashlib.sha256(b"cross").digest()

    sig256 = pb.native_nistp_ecdsa_sign("P-256", digest, priv256)
    # Wrong-length key for the curve is a caller error.
    with pytest.raises(ValueError):
        pb.native_nistp_ecdsa_verify("P-384", sig256, digest, pub256)
    with pytest.raises(ValueError):
        pb.native_nistp_ecdsa_sign("P-384", digest, priv256)
    # Right length, wrong curve: must simply not verify.
    mangled = pub256[:32] + pub256[32:][::-1]
    assert not pb.native_nistp_ecdsa_verify("P-256", sig256, digest, mangled)
    with pytest.raises(ValueError):
        pb.native_nistp_ecdh("P-256", priv256, pub384)


def test_unknown_curve_names_are_rejected() -> None:
    for bad in ("P-192", "secp256k1", "Ed25519", 3, -1, True, "", None):
        with pytest.raises((ValueError, TypeError)):
            pb.native_nistp_keypair(bad)  # type: ignore[arg-type]  # deliberately wrong type/value — this test asserts the curve-selector boundary check fires (NISTP-002)


def test_curve_aliases_resolve() -> None:
    assert pb._nistp_curve_id("secp256r1") == pb.NISTP_CURVE_P256
    assert pb._nistp_curve_id("prime256v1") == pb.NISTP_CURVE_P256
    assert pb._nistp_curve_id("secp384r1") == pb.NISTP_CURVE_P384
    assert pb._nistp_curve_id("secp521r1") == pb.NISTP_CURVE_P521
    assert pb._nistp_curve_id(pb.NISTP_CURVE_P521) == pb.NISTP_CURVE_P521
