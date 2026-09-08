# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The C AMA_ALG_HYBRID and the Python HybridSignatureProvider are one format.

Both sign Ed25519 over ``0x00 || len(domain) || domain || M`` and ML-DSA-65
with the domain as FIPS 204 context, with the same domain string.  This pins
the string at source level and verifies signatures across the two
implementations in both directions.
"""

from __future__ import annotations

import ctypes
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from ama_cryptography import pqc_backends as pb
from ama_cryptography.crypto_api import HYBRID_SIG_DOMAIN, HybridSignatureProvider

REPO = Path(__file__).resolve().parent.parent
HEADER = REPO / "include" / "ama_cryptography.h"

pytestmark = pytest.mark.skipif(
    not pb.DILITHIUM_AVAILABLE or pb._native_lib is None, reason="native ML-DSA backend unavailable"
)

ALG_HYBRID = 4
PK, SK, SIG = 32 + 1952, 64 + 4032, 64 + 3309


def test_c_header_and_python_agree_on_the_domain_string() -> None:
    text = HEADER.read_text(encoding="utf-8")
    m = re.search(r'#define AMA_HYBRID_SIG_DOMAIN "([^"]+)"', text)
    assert m, "AMA_HYBRID_SIG_DOMAIN missing from the public header"
    assert m.group(1).encode("ascii") == HYBRID_SIG_DOMAIN


def _lib() -> ctypes.CDLL:
    lib = pb._native_lib
    lib.ama_context_init.argtypes = [ctypes.c_int]
    lib.ama_context_init.restype = ctypes.c_void_p
    lib.ama_context_free.argtypes = [ctypes.c_void_p]
    lib.ama_context_free.restype = None
    lib.ama_keypair_generate.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    lib.ama_keypair_generate.restype = ctypes.c_int
    lib.ama_sign.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.ama_sign.restype = ctypes.c_int
    lib.ama_verify.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    lib.ama_verify.restype = ctypes.c_int
    loaded: ctypes.CDLL = lib
    return loaded


@pytest.fixture(scope="module")
def c_ctx() -> Iterator[tuple[ctypes.CDLL, int]]:
    lib = _lib()
    ctx = lib.ama_context_init(ALG_HYBRID)
    assert ctx
    yield lib, ctx
    lib.ama_context_free(ctx)


def _c_keypair(lib: ctypes.CDLL, ctx: int) -> tuple[bytes, bytes]:
    pk = ctypes.create_string_buffer(PK)
    sk = ctypes.create_string_buffer(SK)
    assert lib.ama_keypair_generate(ctx, pk, PK, sk, SK) == 0
    return pk.raw, sk.raw


def _c_sign(lib: ctypes.CDLL, ctx: int, message: bytes, sk: bytes) -> bytes:
    sig = ctypes.create_string_buffer(SIG)
    n = ctypes.c_size_t(SIG)
    assert lib.ama_sign(ctx, message, len(message), sk, len(sk), sig, ctypes.byref(n)) == 0
    assert n.value == SIG
    return sig.raw


def _c_verify(lib: ctypes.CDLL, ctx: int, message: bytes, sig: bytes, pk: bytes) -> bool:
    rc: int = lib.ama_verify(ctx, message, len(message), sig, len(sig), pk, len(pk))
    return rc == 0


MESSAGE = b"cross-implementation hybrid signature"


def test_c_signature_verifies_in_python(c_ctx: tuple[ctypes.CDLL, int]) -> None:
    lib, ctx = c_ctx
    pk, sk = _c_keypair(lib, ctx)
    sig = _c_sign(lib, ctx, MESSAGE, sk)
    provider = HybridSignatureProvider()
    assert provider.verify(MESSAGE, sig, pk, parallel=False)
    assert not provider.verify(MESSAGE + b"!", sig, pk, parallel=False)


def test_python_signature_verifies_in_c(c_ctx: tuple[ctypes.CDLL, int]) -> None:
    lib, ctx = c_ctx
    provider = HybridSignatureProvider()
    keys = provider.generate_keypair()
    # The Python keypair carries the 32-byte Ed25519 seed; the C layout wants
    # the 64-byte expanded key (seed || public key), which the Python provider
    # also accepts (see its sign docstring).
    ed_seed = bytes(keys.secret_key[:32])
    _, ed_full = pb.native_ed25519_keypair_from_seed(ed_seed)
    c_sk = ed_full + bytes(keys.secret_key[32:])
    sig = provider.sign(MESSAGE, keys.secret_key).signature
    assert _c_verify(lib, ctx, MESSAGE, sig, keys.public_key)
    assert not _c_verify(lib, ctx, MESSAGE + b"!", sig, keys.public_key)
    # And the C signer with the converted key produces the identical bytes
    # (both components are deterministic).
    assert _c_sign(lib, ctx, MESSAGE, c_sk) == sig
