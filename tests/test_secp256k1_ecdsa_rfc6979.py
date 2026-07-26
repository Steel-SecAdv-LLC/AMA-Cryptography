# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""RFC 6979 conformance for native secp256k1 ECDSA — external anchors + differential.

The 476 Wycheproof ECDSA vectors are *verify*-only: they exercise the parser
and the verification equation, not the deterministic-nonce signing path.  The
property tests in ``test_secp256k1_ecdsa.py`` check determinism, distinctness
and low-s, but none pins the *value* of a signature to an outside authority —
so a nonce derivation that is deterministic but non-conformant would pass all
of them while producing signatures no other implementation reproduces.

This module closes that gap by anchoring the signing path to three independent
authorities and then differentially testing every branch:

  1. **RFC 6979 Appendix A.2.5** (NIST P-256, SHA-256, "sample").  The reference
     HMAC_DRBG below reproduces the RFC's own published ``k`` exactly, proving
     the DRBG is spec-correct rather than merely self-consistent.
  2. **trezor-crypto** secp256k1 deterministic ``k`` vectors (test_check.c),
     an independent implementation deployed in hardware wallets.
  3. **trezor-crypto** secp256k1 signature vectors — full ``(r, s)`` — one of
     which signs a digest **>= n**.  That case is the regression guard for a
     real bug found here: RFC 6979 §2.3.4 ``bits2octets`` reduces the message
     mod n before it enters the DRBG (libsecp256k1 does this too — its nonce
     function feeds ``msgmod32``), and the C omitted the reduction, so for any
     digest >= n it diverged from RFC 6979, libsecp256k1 and trezor alike.
     Unreachable by hashing (~2**-128) but reachable through the raw-digest
     API.  Fixed in ``ama_secp256k1.c``; this vector fails against the
     unreduced code and passes against the fix.

The reference implementation shares no code with the C.
"""

from __future__ import annotations

import hashlib
import hmac

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
G = (GX, GY)
HALF_N = (N - 1) // 2


# ---------------------------------------------------------------------------
# Independent curve arithmetic (affine, variable time — this is a test oracle,
# not production code).
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
        lam = (q[1] - p[1]) * pow((q[0] - p[0]) % P, -1, P) % P
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


# ---------------------------------------------------------------------------
# RFC 6979 §3.2 HMAC-SHA256, generic over the group order q, spec-correct
# (bits2octets reduces mod q — §2.3.4).
# ---------------------------------------------------------------------------
def _bits2int(b: bytes, qlen: int) -> int:
    z = int.from_bytes(b, "big")
    shift = len(b) * 8 - qlen
    return z >> shift if shift > 0 else z


def rfc6979_k(q: int, x: int, h1: bytes) -> int:
    qlen = q.bit_length()
    rlen = (qlen + 7) // 8
    x_o = x.to_bytes(rlen, "big")
    h_o = (_bits2int(h1, qlen) % q).to_bytes(rlen, "big")  # bits2octets: reduce mod q
    V = b"\x01" * 32
    K = b"\x00" * 32

    def mac(key: bytes, msg: bytes) -> bytes:
        return hmac.new(key, msg, hashlib.sha256).digest()

    K = mac(K, V + b"\x00" + x_o + h_o)
    V = mac(K, V)
    K = mac(K, V + b"\x01" + x_o + h_o)
    V = mac(K, V)
    while True:
        T = b""
        while len(T) * 8 < qlen:
            V = mac(K, V)
            T += V
        k = _bits2int(T, qlen)
        if 1 <= k <= q - 1:
            return k
        K = mac(K, V + b"\x00")
        V = mac(K, V)


def _der(r: int, s: int) -> bytes:
    def integer(v: int) -> bytes:
        raw = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return bytes([0x02, len(raw)]) + raw

    body = integer(r) + integer(s)
    return bytes([0x30, len(body)]) + body


def _der_parse(sig: bytes) -> tuple[int, int]:
    assert sig[0] == 0x30 and len(sig) == sig[1] + 2
    i = 2
    assert sig[i] == 0x02
    rlen = sig[i + 1]
    r = int.from_bytes(sig[i + 2 : i + 2 + rlen], "big")
    i += 2 + rlen
    assert sig[i] == 0x02
    slen = sig[i + 1]
    return r, int.from_bytes(sig[i + 2 : i + 2 + slen], "big")


def ref_sign(digest: bytes, priv: bytes) -> bytes:
    d = int.from_bytes(priv, "big")
    assert 1 <= d <= N - 1
    z = int.from_bytes(digest, "big") % N
    while True:
        k = rfc6979_k(N, d, digest)
        point = _mul(k, G)
        assert point is not None
        r = point[0] % N
        if r == 0:
            continue
        s = pow(k, -1, N) * (z + r * d) % N
        if s == 0:
            continue
        if s > HALF_N:
            s = N - s  # low-s
        return _der(r, s)


def ref_pubkey(priv: bytes) -> bytes:
    q = _mul(int.from_bytes(priv, "big"), G)
    assert q is not None
    return q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")


# ---------------------------------------------------------------------------
# External authoritative vectors.
# ---------------------------------------------------------------------------
# RFC 6979 Appendix A.2.5 (NIST P-256), SHA-256, message "sample".
_P256_Q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_A25_X = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
_A25_K = 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60

# trezor-crypto secp256k1 deterministic-k vectors (crypto/tests/test_check.c,
# test_rfc6979): (privkey_hex, message_ascii, expected_k_hex).  The message is
# hashed with SHA-256 before RFC 6979, per that test's `test_deterministic`.
_TREZOR_K = [
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        b"Satoshi Nakamoto",
        "8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15",
    ),
    (
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        b"Satoshi Nakamoto",
        "33a19b60e25fb6f4435af53a3d42d493644827367e6453928554f43e49aa6f90",
    ),
    (
        "f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181",
        b"Alan Turing",
        "525a82b70e67874398067543fd84c83d30c175fdc45fdeee082fe13b1d7cfdf1",
    ),
    (
        "e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2",
        b"There is a computer disease that anybody who works with computers knows "
        b"about. It's a very serious disease and it interferes completely with "
        b"the work. The trouble with computers is that you 'play' with them!",
        "1f4b84c23a86a221d233f2521be018d9318639d5b8bbd6374a8a59232d16ad3d",
    ),
]

# trezor-crypto secp256k1 deterministic ECDSA signature vectors
# (test_ecdsa_sign_digest_deterministic_helper): (privkey_hex, digest_hex,
# raw_sig_hex = r||s, 64 bytes).  The first digest is >= n — the regression
# guard for the bits2octets mod-n reduction.
_TREZOR_SIG = [
    (
        "312155017c70a204106e034520e0cdf17b3e54516e2ece38e38e38e38e38e38e",
        "ffffffffffffffffffffffffffffffff20202020202020202020202020202020",
        "e3d70248ea2fc771fc8d5e62d76b9cfd5402c96990333549eaadce1ae9f737eb"
        "5cfbdc7d1e0ec18cc9b57bbb18f0a57dc929ec3c4dfac9073c581705015f6a8a",
    ),
    (
        "312155017c70a204106e034520e0cdf17b3e54516e2ece38e38e38e38e38e38e",
        "2020202020202020202020202020202020202020202020202020202020202020",
        "40666188895430715552a7e4c6b53851f37a93030fb94e043850921242db78e8"
        "75aa2ac9fd7e5a19402973e60e64382cdc29a09ebf6cb37e92f23be5b9251aee",
    ),
]


def test_reference_drbg_reproduces_rfc6979_appendix_a25() -> None:
    """The reference HMAC_DRBG reproduces RFC 6979's own published k for the
    P-256 "sample" case — so it is anchored to the RFC, not just to itself."""
    k = rfc6979_k(_P256_Q, _A25_X, hashlib.sha256(b"sample").digest())
    assert k == _A25_K


@pytest.mark.parametrize(("priv_hex", "msg", "k_hex"), _TREZOR_K)
def test_reference_drbg_matches_trezor_secp256k1_k(priv_hex: str, msg: bytes, k_hex: str) -> None:
    """The reference DRBG matches trezor-crypto's secp256k1 k on inputs where
    the group order actually matters (e.g. private key n-1), tying it to a
    second independent implementation before it is used to judge the C."""
    k = rfc6979_k(N, int(priv_hex, 16), hashlib.sha256(msg).digest())
    assert k == int(k_hex, 16)


@pytest.mark.parametrize(("priv_hex", "digest_hex", "sig_hex"), _TREZOR_SIG)
def test_native_matches_trezor_signature_vectors(
    priv_hex: str, digest_hex: str, sig_hex: str
) -> None:
    """AMA must reproduce trezor-crypto's exact (r, s). The first vector's
    digest is >= n; it fails against a build that does not reduce the digest
    mod n before RFC 6979 (the bug this file guards), and passes against the
    fix. Both trezor vectors are already low-s."""
    priv = bytes.fromhex(priv_hex)
    digest = bytes.fromhex(digest_hex)
    raw = bytes.fromhex(sig_hex)
    tr_r = int.from_bytes(raw[:32], "big")
    tr_s = int.from_bytes(raw[32:], "big")
    tr_s = tr_s if tr_s <= HALF_N else N - tr_s

    r, s = _der_parse(native_secp256k1_ecdsa_sign(digest, priv))
    assert (r, s) == (tr_r, tr_s)


def test_native_matches_reference_across_random_inputs() -> None:
    """Byte-for-byte agreement between the C and the spec-anchored reference
    over many deterministic pseudo-random (key, message) pairs, both signing
    and cross-verifying. Any divergence in RFC 6979, the scalar arithmetic,
    low-s normalization or DER encoding surfaces as a mismatch."""
    for i in range(200):
        d = int.from_bytes(hashlib.sha256(f"k{i}".encode()).digest(), "big") % (N - 1) + 1
        priv = d.to_bytes(32, "big")
        digest = hashlib.sha256(f"m{i}".encode()).digest()
        native = native_secp256k1_ecdsa_sign(digest, priv)
        assert native == ref_sign(digest, priv), f"sign mismatch at {i}"
        assert native_secp256k1_ecdsa_verify(native, digest, ref_pubkey(priv))


def test_native_reduces_out_of_range_digest_like_the_reference() -> None:
    """Direct coverage of the fix: digests >= n must be reduced mod n before
    RFC 6979, so the C still matches the reference (and thus libsecp256k1 /
    trezor) rather than diverging. `0xff*32` and `n` and `n+1 (mod 2^256)`
    are all >= n."""
    priv = (0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF).to_bytes(32, "big")
    pub = ref_pubkey(priv)
    for big in (b"\xff" * 32, N.to_bytes(32, "big"), ((N + 1) % (2**256)).to_bytes(32, "big")):
        assert int.from_bytes(big, "big") >= N
        native = native_secp256k1_ecdsa_sign(big, priv)
        assert native == ref_sign(big, priv)
        assert native_secp256k1_ecdsa_verify(native, big, pub)
