# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""ML-DSA-65: which FIPS 204 interface each entry point implements.

Two interfaces ship, and each is pinned here.

* **External / pure** (Algorithm 2, ``M' = 0x00 || len(ctx) || ctx || M``):
  ``dilithium_sign`` / ``dilithium_verify`` — the flagship API, empty
  context — and ``native_ml_dsa_sign(ctx=...)``, whose default is also the
  empty context.
* **Hedged external** (Algorithm 2 with fresh ``rnd``):
  ``native_ml_dsa_sign_hedged``.

The **internal** interface (Algorithm 7, ``mu = H(tr || M)``) does NOT ship
(INVARIANT-50).  It did, as ``ama_ml_dsa_sign`` / ``ama_ml_dsa_verify``, and
under one key it was a signing oracle for external signatures on
attacker-chosen ``(ctx, M)`` pairs.  It now exists only in the C testing
archive; ``tests/c/test_ml_dsa_context_separation.c`` pins the wrapper
equivalence against it.

Until the twenty-third maintenance pass ``dilithium_sign`` was the INTERNAL
interface, so its output was rejected by every other ML-DSA-65
implementation.  The first test below is what pins the fix.
"""

from __future__ import annotations

import pytest

from ama_cryptography import pqc_backends as pb

pytestmark = pytest.mark.skipif(not pb.DILITHIUM_AVAILABLE, reason="ML-DSA backend unavailable")

MESSAGE = b"which FIPS 204 interface am I?"


@pytest.fixture(scope="module")
def keys() -> tuple[bytes, bytes]:
    return pb.native_ml_dsa_keypair(65)


def test_flagship_api_is_the_external_interface_with_an_empty_context(
    keys: tuple[bytes, bytes],
) -> None:
    pk, sk = keys
    sig = pb.dilithium_sign(MESSAGE, sk)
    # Same bytes as the explicit empty-context external call, and the default.
    assert sig == pb.native_ml_dsa_sign(65, MESSAGE, sk, ctx=b"")
    assert sig == pb.native_ml_dsa_sign(65, MESSAGE, sk)
    assert pb.dilithium_verify(MESSAGE, sig, pk)
    assert pb.native_ml_dsa_verify(65, MESSAGE, sig, pk, ctx=b"")


@pytest.mark.parametrize(
    "symbol",
    [
        "ama_ml_dsa_sign",
        "ama_ml_dsa_verify",
        "ama_ml_dsa_sign_internal",
        "ama_ml_dsa_verify_internal",
    ],
)
def test_the_internal_interface_is_not_in_the_shipped_library(symbol: str) -> None:
    """Absent by construction, under both its old public name and its test name."""
    assert pb._native_lib is not None
    assert not hasattr(pb._native_lib, symbol), f"{symbol} is exported"


def test_no_shipped_entry_point_signs_the_raw_wrapper_as_a_context_signature(
    keys: tuple[bytes, bytes],
) -> None:
    """The oracle INVARIANT-50 closes, measured the way it was found.

    Signing the bytes ``0x00 || 0x01 || "x" || M`` must never yield a valid
    signature on ``(M, ctx="x")``.  Through the old raw entry point it did.
    """
    pk, sk = keys
    forged_input = b"\x00\x01x" + MESSAGE
    for sig in (
        pb.native_ml_dsa_sign(65, forged_input, sk),
        pb.dilithium_sign(forged_input, sk),
        pb.native_ml_dsa_sign_hedged(65, forged_input, sk),
    ):
        assert not pb.native_ml_dsa_verify(65, MESSAGE, sig, pk, ctx=b"x")


def test_a_non_empty_context_is_a_different_domain(keys: tuple[bytes, bytes]) -> None:
    pk, sk = keys
    sig = pb.native_ml_dsa_sign(65, MESSAGE, sk, ctx=b"ama")
    assert pb.native_ml_dsa_verify(65, MESSAGE, sig, pk, ctx=b"ama")
    assert not pb.native_ml_dsa_verify(65, MESSAGE, sig, pk, ctx=b"")
    assert not pb.dilithium_verify(MESSAGE, sig, pk)


def test_default_signing_is_deterministic(keys: tuple[bytes, bytes]) -> None:
    _, sk = keys
    assert pb.dilithium_sign(MESSAGE, sk) == pb.dilithium_sign(MESSAGE, sk)


class TestHedged:
    """FIPS 204 Algorithm 2 with a fresh ``rnd``; the variant PROVENANCE.md
    used to claim was already shipped."""

    def test_hedged_signatures_differ_but_both_verify(self, keys: tuple[bytes, bytes]) -> None:
        pk, sk = keys
        a = pb.native_ml_dsa_sign_hedged(65, MESSAGE, sk)
        b = pb.native_ml_dsa_sign_hedged(65, MESSAGE, sk)
        assert a != b, "hedged signing must not be reproducible"
        assert pb.native_ml_dsa_verify(65, MESSAGE, a, pk, ctx=b"")
        assert pb.native_ml_dsa_verify(65, MESSAGE, b, pk, ctx=b"")
        # Verifiable by the flagship verifier too: rnd is not transmitted.
        assert pb.dilithium_verify(MESSAGE, a, pk)

    def test_hedged_differs_from_the_deterministic_signature(
        self, keys: tuple[bytes, bytes]
    ) -> None:
        _, sk = keys
        assert pb.native_ml_dsa_sign_hedged(65, MESSAGE, sk) != pb.native_ml_dsa_sign(
            65, MESSAGE, sk, ctx=b""
        )

    def test_hedged_honours_the_context(self, keys: tuple[bytes, bytes]) -> None:
        pk, sk = keys
        sig = pb.native_ml_dsa_sign_hedged(65, MESSAGE, sk, ctx=b"ama")
        assert pb.native_ml_dsa_verify(65, MESSAGE, sig, pk, ctx=b"ama")
        assert not pb.native_ml_dsa_verify(65, MESSAGE, sig, pk, ctx=b"")

    def test_hedged_rejects_an_oversized_context(self, keys: tuple[bytes, bytes]) -> None:
        _, sk = keys
        with pytest.raises(ValueError, match="at most 255"):
            pb.native_ml_dsa_sign_hedged(65, MESSAGE, sk, ctx=b"x" * 256)

    @pytest.mark.parametrize("ps", [44, 65, 87])
    def test_hedged_works_for_every_parameter_set(self, ps: int) -> None:
        pk, sk = pb.native_ml_dsa_keypair(ps)
        sig = pb.native_ml_dsa_sign_hedged(ps, MESSAGE, sk)
        assert pb.native_ml_dsa_verify(ps, MESSAGE, sig, pk, ctx=b"")
