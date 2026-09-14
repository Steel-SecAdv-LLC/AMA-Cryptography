#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
KAT and contract pins for the SHA-512/384, SHA3-384 and PBKDF2 native exports.

These five symbols close the INVARIANT-1 sweep: the SHA-512 core always
existed in-tree (internal/ama_sha2.h) but was never surfaced to Python, so
callers needing SHA-384/512 or PBKDF2 reached for stdlib hashlib — whose
constructors resolve to OpenSSL in every CPython build that links it,
``hashlib.sha3_256 is _hashlib.openssl_sha3_256`` included.  The KATs here
are the primary correctness pins (FIPS 180-4 / FIPS 202 canonical vectors,
the RFC 7914 §11 PBKDF2-HMAC-SHA256 vectors, the official BIP39 vector);
the hashlib differentials are the comparator cross-check, which is the one
role stdlib hashlib retains in this repository — test-side comparison,
never production computation.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from ama_cryptography import pqc_backends as pb

pytestmark = pytest.mark.skipif(
    not (pb._SHA2_EXT_NATIVE_AVAILABLE and pb._PBKDF2_NATIVE_AVAILABLE),
    reason="SHA-2-ext / PBKDF2 native backend not built in this tree",
)


class TestSha2ExtKats:
    def test_sha512_fips_180_4_abc(self) -> None:
        assert pb.native_sha512(b"abc") == bytes.fromhex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )

    def test_sha512_fips_180_4_empty(self) -> None:
        assert pb.native_sha512(b"") == bytes.fromhex(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )

    def test_sha384_fips_180_4_abc(self) -> None:
        assert pb.native_sha384(b"abc") == bytes.fromhex(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7"
        )

    def test_sha3_384_fips_202_abc(self) -> None:
        assert pb.native_sha3_384(b"abc") == bytes.fromhex(
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
            "98d88cea927ac7f539f1edf228376d25"
        )

    def test_sha3_384_fips_202_empty(self) -> None:
        assert pb.native_sha3_384(b"") == bytes.fromhex(
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
            "c3713831264adb47fb6bd1e058d5f004"
        )

    @pytest.mark.parametrize(
        "n", [0, 1, 47, 48, 63, 64, 103, 104, 111, 112, 127, 128, 129, 255, 1000, 4096]
    )
    def test_differential_against_hashlib_at_block_boundaries(self, n: int) -> None:
        """Every rate/block boundary of all three functions (64/104/128)."""
        data = (bytes(range(256)) * 17)[:n]
        assert pb.native_sha512(data) == hashlib.sha512(data).digest()
        assert pb.native_sha384(data) == hashlib.sha384(data).digest()
        assert pb.native_sha3_384(data) == hashlib.sha3_384(data).digest()


class TestPbkdf2Kats:
    def test_rfc7914_pbkdf2_sha256_vector_1(self) -> None:
        assert pb.native_pbkdf2_hmac_sha256(b"passwd", b"salt", 1, 64) == bytes.fromhex(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        )

    def test_rfc7914_pbkdf2_sha256_vector_2(self) -> None:
        assert pb.native_pbkdf2_hmac_sha256(b"Password", b"NaCl", 80000, 64) == bytes.fromhex(
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
            "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
        )

    def test_bip39_official_vector(self) -> None:
        """Trezor reference vector: 'abandon x11 about' + passphrase TREZOR."""
        mnemonic = ("abandon " * 11 + "about").encode()
        assert pb.native_pbkdf2_hmac_sha512(mnemonic, b"mnemonicTREZOR", 2048, 64) == bytes.fromhex(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
            "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        )

    @pytest.mark.parametrize(
        ("pw_len", "salt_len", "iterations", "dk_len"),
        [
            (0, 4, 1, 32),  # empty password
            (5, 0, 2, 31),  # empty salt, sub-digest output
            (64, 17, 3, 33),  # password exactly one SHA-256 block; multi-block output
            (65, 8, 10, 96),  # password over the SHA-256 block -> RFC 2104 pre-hash
            (129, 20, 7, 65),  # password over the SHA-512 block -> pre-hash on both
            (1, 1, 1, 1),  # minimum everything
        ],
    )
    def test_differential_against_hashlib(
        self, pw_len: int, salt_len: int, iterations: int, dk_len: int
    ) -> None:
        rng_data = bytes(range(256)) * 2
        pw, salt = rng_data[:pw_len], rng_data[100 : 100 + salt_len]
        assert pb.native_pbkdf2_hmac_sha256(pw, salt, iterations, dk_len) == hashlib.pbkdf2_hmac(
            "sha256", pw, salt, iterations, dk_len
        )
        assert pb.native_pbkdf2_hmac_sha512(pw, salt, iterations, dk_len) == hashlib.pbkdf2_hmac(
            "sha512", pw, salt, iterations, dk_len
        )

    def test_random_differential(self) -> None:
        """Randomized cross-check — 20 shapes drawn fresh each run."""
        for _ in range(20):
            pw = os.urandom(os.urandom(1)[0])
            salt = os.urandom(os.urandom(1)[0] % 64)
            it = 1 + os.urandom(1)[0] % 16
            dk = 1 + os.urandom(1)[0] % 96
            assert pb.native_pbkdf2_hmac_sha256(pw, salt, it, dk) == hashlib.pbkdf2_hmac(
                "sha256", pw, salt, it, dk
            )
            assert pb.native_pbkdf2_hmac_sha512(pw, salt, it, dk) == hashlib.pbkdf2_hmac(
                "sha512", pw, salt, it, dk
            )


class TestContracts:
    """Parameter validation is a contract, not a courtesy."""

    def test_zero_iterations_rejected(self) -> None:
        with pytest.raises(ValueError, match="iterations"):
            pb.native_pbkdf2_hmac_sha256(b"p", b"s", 0, 32)

    def test_oversized_iterations_rejected(self) -> None:
        with pytest.raises(ValueError, match="iterations"):
            pb.native_pbkdf2_hmac_sha512(b"p", b"s", 2**32, 32)

    def test_zero_output_rejected(self) -> None:
        with pytest.raises(ValueError, match="output length"):
            pb.native_pbkdf2_hmac_sha256(b"p", b"s", 1, 0)

    def test_the_c_kernel_itself_rejects_zero_iterations(self) -> None:
        """The Python guard must not be the only wall (defense in depth)."""
        import ctypes

        assert pb._native_lib is not None
        out = ctypes.create_string_buffer(32)
        rc = pb._native_lib.ama_pbkdf2_hmac_sha256(b"p", 1, b"s", 1, 0, out, 32)
        assert rc != 0
