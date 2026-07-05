#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Tests for the public quick_hmac / quick_hkdf dispatchers (crypto_api) and the
pqc_backends.__all__ surface that external consumers (e.g. Mercury) import.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Callable

import pytest

from ama_cryptography import pqc_backends
from ama_cryptography.crypto_api import quick_hkdf, quick_hmac

skip_no_native = pytest.mark.skipif(
    not pqc_backends._HMAC_SHA256_NATIVE_AVAILABLE,
    reason="native HMAC backend not available",
)


def test_pqc_backends_all_symbols_resolve() -> None:
    """Every name advertised in pqc_backends.__all__ must actually exist."""
    missing = [name for name in pqc_backends.__all__ if not hasattr(pqc_backends, name)]
    assert missing == [], f"pqc_backends.__all__ advertises missing names: {missing}"


def test_public_hmac_hkdf_names_exported() -> None:
    """The native HMAC/HKDF surface is discoverable via __all__ (no reaching
    into private module internals)."""
    for name in (
        "native_hmac_sha256",
        "native_hmac_sha384",
        "native_hmac_sha512",
        "native_hmac_sha3_256",
        "native_hkdf_sha256",
        "native_hkdf_sha384",
        "native_hkdf_sha512",
        "native_sha3_512",
        "native_shake256",
    ):
        assert name in pqc_backends.__all__


@skip_no_native
class TestQuickHmac:
    def test_matches_stdlib(self) -> None:
        for algo, hmod in (
            ("sha256", hashlib.sha256),
            ("sha384", hashlib.sha384),
            ("sha512", hashlib.sha512),
        ):
            for key, msg in ((b"", b""), (b"key", b"message"), (b"k" * 200, b"m" * 500)):
                assert quick_hmac(key, msg, algo) == hmac.new(key, msg, hmod).digest()

    def test_sha3_256_shape(self) -> None:
        assert len(quick_hmac(b"key", b"msg", "sha3-256")) == 32

    def test_default_algorithm_is_sha256(self) -> None:
        assert quick_hmac(b"key", b"msg") == hmac.new(b"key", b"msg", hashlib.sha256).digest()

    def test_unsupported_algorithm_raises(self) -> None:
        with pytest.raises(ValueError):
            quick_hmac(b"k", b"m", "md5")


@skip_no_native
class TestQuickHkdf:
    @staticmethod
    def _ref(hmod: Callable[..., Any], salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
        if not salt:
            salt = b"\x00" * hmod().digest_size
        prk = hmac.new(salt, ikm, hmod).digest()
        t = b""
        okm = b""
        i = 1
        while len(okm) < length:
            t = hmac.new(prk, t + info + bytes([i]), hmod).digest()
            okm += t
            i += 1
        return okm[:length]

    def test_matches_reference(self) -> None:
        for algo, hmod in (
            ("sha256", hashlib.sha256),
            ("sha384", hashlib.sha384),
            ("sha512", hashlib.sha512),
        ):
            got = quick_hkdf(b"ikm-value", 40, b"salt", b"context", algo)
            assert got == self._ref(hmod, b"salt", b"ikm-value", b"context", 40)

    def test_sha3_256_default_hkdf(self) -> None:
        assert len(quick_hkdf(b"ikm", 64, algorithm="sha3-256")) == 64

    def test_unsupported_algorithm_raises(self) -> None:
        with pytest.raises(ValueError):
            quick_hkdf(b"ikm", 32, algorithm="md5")
