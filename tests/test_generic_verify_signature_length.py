# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""``ama_verify`` must hold every algorithm to an exact signature length.

The generic entry point exists to give uniform semantics across algorithms.
Its Ed25519 branch checked ``signature_len < 64`` where HYBRID checks
``!= 200``, ML-DSA-65 ``!= P->sig_bytes`` and SLH-DSA ``!= p->sig_bytes``, so
any buffer of 64 or more bytes whose first 64 were a valid signature verified:
a signed blob with arbitrary bytes appended was a valid Ed25519 signature
through this API and through :class:`AmaContext`, which passes the caller's
length straight down.  Measured before the fix against the built library: a
65-byte and an 80-byte signature verified with rc 0, where ML-DSA-65 returned
``AMA_ERROR_VERIFY_FAILED`` for a single trailing byte.

Sixteen algorithm/length cases below pin the exact-length contract for every
signing algorithm the context API exposes -- Ed25519, ML-DSA-65, the hybrid
and SLH-DSA-SHAKE-256f -- so a `<` cannot come back on any branch.  SLH-DSA
was missing from an earlier revision that already made this claim; its
branch delegates the length check to ``ama_sphincs_verify``, which a
regression there would have left untested.
"""

from __future__ import annotations

import ctypes
import functools

import pytest

from ama_cryptography import pqc_backends as pb

pytestmark = pytest.mark.skipif(
    not getattr(pb, "_CONTEXT_API_AVAILABLE", False),
    reason="native context API not available in this build",
)

AMA_SUCCESS = 0
AMA_ERROR_VERIFY_FAILED = -4

_ALGORITHMS = [
    ("ed25519", pb.AmaContext.ALG_ED25519),
    ("ml-dsa-65", pb.AmaContext.ALG_ML_DSA_65),
    ("hybrid", pb.AmaContext.ALG_HYBRID),
    ("sphincs-256f", pb.AmaContext.ALG_SPHINCS_256F),
]


@functools.cache
def _signed(alg: int) -> tuple[bytes, bytes, bytes]:
    """A message, a genuine signature of exactly the algorithm's length, and
    the public key, produced through the same context API the check uses.

    Cached per algorithm: the checks below only read it, and SLH-DSA signing
    is the slow one."""
    message = b"length is part of the signature"
    with pb.AmaContext(alg) as ctx:
        pk_size, sk_size = pb.AmaContext._KEY_SIZES[alg]
        pk = ctypes.create_string_buffer(pk_size)
        sk = ctypes.create_string_buffer(sk_size)
        assert ctx.keypair_generate(pk, pk_size, sk, sk_size) == AMA_SUCCESS
        sig_size = pb.AmaContext._SIG_SIZES[alg]
        sig = ctypes.create_string_buffer(sig_size)
        sig_len = ctypes.c_size_t(sig_size)
        assert ctx.sign(message, sk.raw, sig, ctypes.pointer(sig_len)) == AMA_SUCCESS
        return message, sig.raw[: sig_len.value], pk.raw


@pytest.mark.parametrize(("name", "alg"), _ALGORITHMS)
def test_the_exact_length_verifies(name: str, alg: int) -> None:
    message, signature, public_key = _signed(alg)
    with pb.AmaContext(alg) as ctx:
        assert ctx.verify_rc(message, signature, public_key) == AMA_SUCCESS, name


@pytest.mark.parametrize(("name", "alg"), _ALGORITHMS)
@pytest.mark.parametrize("extra", [1, 16])
def test_trailing_bytes_are_not_a_signature(name: str, alg: int, extra: int) -> None:
    """The case Ed25519 got wrong: a valid signature followed by garbage."""
    message, signature, public_key = _signed(alg)
    padded = signature + bytes([0xAA]) * extra
    with pb.AmaContext(alg) as ctx:
        assert ctx.verify_rc(message, padded, public_key) == AMA_ERROR_VERIFY_FAILED, (
            f"{name}: a {len(padded)}-byte buffer verified as a " f"{len(signature)}-byte signature"
        )


@pytest.mark.parametrize(("name", "alg"), _ALGORITHMS)
def test_a_truncated_signature_is_not_a_signature(name: str, alg: int) -> None:
    message, signature, public_key = _signed(alg)
    with pb.AmaContext(alg) as ctx:
        assert ctx.verify_rc(message, signature[:-1], public_key) == AMA_ERROR_VERIFY_FAILED, name
