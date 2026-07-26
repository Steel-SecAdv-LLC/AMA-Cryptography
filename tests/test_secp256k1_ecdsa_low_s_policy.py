# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Caller-selectable low-s policy for ECDSA verification.

``ama_secp256k1_ecdsa_verify`` is strict by default: it rejects the high-``s``
malleability twin ``(r, n - s)``. That is the right default when you control the
signer (Mercury Agent / FINDΩYOU), because it makes a signature a unique
identifier for its (key, message). But X9.62 permits either representative, so a
library that must verify conformant third-party signatures needs an opt-out.

These tests pin the contract: the default rejects a high-``s`` signature, the
``allow_high_s=True`` opt-in accepts the *same* signature, and the relaxation is
surgical — it changes only the low-``s`` decision, never the range or
canonical-public-key checks.
"""

from __future__ import annotations

import pytest

from ama_cryptography.pqc_backends import _native_lib

pytestmark = pytest.mark.skipif(
    _native_lib is None,
    reason="Native C library not built — skipping secp256k1 ECDSA tests",
)

# secp256k1 field prime p and group order n.
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_PRIV = bytes.fromhex("0123456789abcdeffedcba98765432100f1e2d3c4b5a69788796a5b4c3d2e1f0")
_DIGEST = bytes(range(1, 33))

# (pubkey, low_s_sig, r, low_s) — the shared module fixture's shape.
_Fixtures = tuple[bytes, bytes, int, int]


def _uncompressed_pubkey(privkey: bytes) -> bytes:
    from ama_cryptography.pqc_backends import native_secp256k1_pubkey_from_privkey

    compressed = native_secp256k1_pubkey_from_privkey(privkey)
    prefix, x_bytes = compressed[0], compressed[1:]
    x = int.from_bytes(x_bytes, "big")
    y = pow((pow(x, 3, _P) + 7) % _P, (_P + 1) // 4, _P)
    if (y & 1) != (prefix & 1):
        y = _P - y
    return x_bytes + y.to_bytes(32, "big")


def _der_int(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:  # keep the INTEGER positive (minimal DER)
        raw = b"\x00" + raw
    return b"\x02" + bytes([len(raw)]) + raw


def _der_sig(r: int, s: int) -> bytes:
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def _parse_der(sig: bytes) -> tuple[int, int]:
    assert sig[0] == 0x30
    i = 2
    assert sig[i] == 0x02
    rlen = sig[i + 1]
    r = int.from_bytes(sig[i + 2 : i + 2 + rlen], "big")
    i += 2 + rlen
    assert sig[i] == 0x02
    slen = sig[i + 1]
    s = int.from_bytes(sig[i + 2 : i + 2 + slen], "big")
    return r, s


@pytest.fixture(scope="module")
def fixtures() -> tuple[bytes, bytes, int, int]:
    """Return (pubkey, low_s_sig, r, low_s)."""
    from ama_cryptography.pqc_backends import native_secp256k1_ecdsa_sign

    pubkey = _uncompressed_pubkey(_PRIV)
    low_sig = native_secp256k1_ecdsa_sign(_DIGEST, _PRIV)
    r, s = _parse_der(low_sig)
    assert s <= _N // 2, "signing must emit the canonical low-s representative"
    return pubkey, low_sig, r, s


class TestLowSPolicy:
    def test_low_s_signature_verifies_in_both_modes(self, fixtures: _Fixtures) -> None:
        from ama_cryptography.pqc_backends import native_secp256k1_ecdsa_verify

        pubkey, low_sig, _r, _s = fixtures
        assert native_secp256k1_ecdsa_verify(low_sig, _DIGEST, pubkey) is True
        assert native_secp256k1_ecdsa_verify(low_sig, _DIGEST, pubkey, allow_high_s=True) is True

    def test_high_s_twin_rejected_by_default(self, fixtures: _Fixtures) -> None:
        """The default policy rejects (r, n - s) — the malleability twin."""
        from ama_cryptography.pqc_backends import native_secp256k1_ecdsa_verify

        pubkey, _low_sig, r, s = fixtures
        high_sig = _der_sig(r, _N - s)
        assert (_N - s) > _N // 2, "the twin must actually be high-s"
        assert native_secp256k1_ecdsa_verify(high_sig, _DIGEST, pubkey) is False

    def test_high_s_twin_accepted_with_opt_in(self, fixtures: _Fixtures) -> None:
        """allow_high_s=True accepts the same conformant X9.62 twin."""
        from ama_cryptography.pqc_backends import native_secp256k1_ecdsa_verify

        pubkey, _low_sig, r, s = fixtures
        high_sig = _der_sig(r, _N - s)
        assert native_secp256k1_ecdsa_verify(high_sig, _DIGEST, pubkey, allow_high_s=True) is True

    def test_opt_in_does_not_relax_range_or_canonical_checks(self, fixtures: _Fixtures) -> None:
        """The opt-in changes only the low-s decision: an out-of-range s (>= n)
        and an out-of-field public key are still rejected in lenient mode."""
        from ama_cryptography.pqc_backends import native_secp256k1_ecdsa_verify

        pubkey, low_sig, r, _s = fixtures
        # s = n is out of [1, n-1] — rejected regardless of allow_high_s.
        out_of_range = _der_sig(r, _N)
        assert (
            native_secp256k1_ecdsa_verify(out_of_range, _DIGEST, pubkey, allow_high_s=True) is False
        )
        # A non-canonical Qx (= p) is rejected even in lenient mode.
        bad_pub = _P.to_bytes(32, "big") + pubkey[32:]
        assert native_secp256k1_ecdsa_verify(low_sig, _DIGEST, bad_pub, allow_high_s=True) is False
