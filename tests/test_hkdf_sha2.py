#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for the native HKDF-SHA-256/384/512 (RFC 5869) bindings.

Test-vector sources:
  * HKDF-SHA-256: RFC 5869 Appendix A.1 / A.2 / A.3 — OFFICIAL IETF vectors,
    pinned below. These validate the exact wire output of the production
    C implementation (ama_hkdf_sha256), not a project-generated golden value.
  * HKDF-SHA-384 / -512: RFC 5869 defines no vectors for these hashes, so they
    are cross-checked against an INDEPENDENT hmac+hashlib HKDF reference
    (fully derivable from RFC 5869 §2) across a length/salt/info sweep.

The reference implementation intentionally does NOT reuse the AMA code path so
a shared bug cannot mask a divergence.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Callable, ClassVar

import pytest

from ama_cryptography.pqc_backends import (
    _HKDF_SHA2_NATIVE_AVAILABLE,
    native_hkdf_sha256,
    native_hkdf_sha384,
    native_hkdf_sha512,
)

skip_no_native = pytest.mark.skipif(
    not _HKDF_SHA2_NATIVE_AVAILABLE,
    reason="HKDF-SHA-2 native backend not available",
)


def _hkdf_reference(
    hashmod: Callable[..., Any], salt: bytes, ikm: bytes, info: bytes, length: int
) -> bytes:
    """Independent RFC 5869 HKDF over an arbitrary hashlib hash."""
    hlen = hashmod().digest_size
    if not salt:
        salt = b"\x00" * hlen
    prk = hmac.new(salt, ikm, hashmod).digest()
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashmod).digest()
        okm += t
        counter += 1
    return okm[:length]


@skip_no_native
class TestHkdfSha256Rfc5869:
    """RFC 5869 Appendix A official HKDF-SHA-256 KAT vectors."""

    def test_rfc5869_a1(self) -> None:
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        expected = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )
        assert native_hkdf_sha256(ikm, 42, salt, info) == expected

    def test_rfc5869_a2_long(self) -> None:
        ikm = bytes(range(0x50))
        salt = bytes(range(0x60, 0x60 + 0x50))
        info = bytes(range(0xB0, 0xB0 + 0x50))
        expected = bytes.fromhex(
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87"
        )
        assert native_hkdf_sha256(ikm, 82, salt, info) == expected

    def test_rfc5869_a3_zero_salt_info(self) -> None:
        ikm = bytes.fromhex("0b" * 22)
        expected = bytes.fromhex(
            "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8"
        )
        # None salt and None info must behave as zero-length per RFC 5869 §2.2/§2.3
        assert native_hkdf_sha256(ikm, 42, None, b"") == expected


@skip_no_native
class TestHkdfSha2Differential:
    """Byte-identity to an independent hmac+hashlib HKDF reference."""

    CASES: ClassVar[list[tuple[Callable[..., bytes], Callable[..., Any], int]]] = [
        (native_hkdf_sha256, hashlib.sha256, 32),
        (native_hkdf_sha384, hashlib.sha384, 48),
        (native_hkdf_sha512, hashlib.sha512, 64),
    ]

    def test_matches_reference_sweep(self) -> None:
        ikm = b"input keying material \x00\x01\x02\xff"
        for native_fn, hashmod, hlen in self.CASES:
            for length in (1, hlen - 1, hlen, hlen + 1, 200, 1000, 255 * hlen):
                for salt in (None, b"", b"salt-value", b"s" * 200):
                    for info in (b"", b"context", b"i" * 400):
                        got = native_fn(ikm, length, salt, info)
                        ref = _hkdf_reference(hashmod, salt or b"", ikm, info, length)
                        assert got == ref, (
                            f"{native_fn.__name__} L={length} "
                            f"salt={salt!r} info_len={len(info)}"
                        )

    def test_length_bounds(self) -> None:
        for native_fn, _hashmod, hlen in self.CASES:
            with pytest.raises(ValueError):
                native_fn(b"ikm", 0)
            with pytest.raises(ValueError):
                native_fn(b"ikm", 255 * hlen + 1)
            # exactly at the maximum is allowed
            assert len(native_fn(b"ikm", 255 * hlen)) == 255 * hlen

    def test_salt_none_equals_zero_salt(self) -> None:
        # RFC 5869 §2.2: absent salt == HashLen zero bytes.
        for native_fn, _hashmod, hlen in self.CASES:
            a = native_fn(b"ikm", 64, None, b"info")
            b = native_fn(b"ikm", 64, b"\x00" * hlen, b"info")
            assert a == b
