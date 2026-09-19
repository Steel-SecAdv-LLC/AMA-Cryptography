# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""ML-DSA-65: which FIPS 204 interface each entry point implements.

Three interfaces coexist and are easy to confuse; each is pinned here.

* **Internal** (Algorithm 7, ``mu = H(tr || M)``): ``native_ml_dsa_sign``
  with ``ctx=None``.  FIPS 204 Sec 5.2 restricts it to testing and to
  protocols supplying their own domain separation; the ACVP
  internal-interface vectors replay through it.
* **External / pure** (Algorithm 2, ``M' = 0x00 || len(ctx) || ctx || M``):
  ``dilithium_sign`` / ``dilithium_verify`` — the flagship API, empty
  context — and ``native_ml_dsa_sign(ctx=...)`` for a non-empty one.
* **Hedged external** (Algorithm 2 with fresh ``rnd``):
  ``native_ml_dsa_sign_hedged``.

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
    # Same bytes as the explicit empty-context external call ...
    assert sig == pb.native_ml_dsa_sign(65, MESSAGE, sk, ctx=b"")
    # ... and NOT the internal interface it used to be.
    assert sig != pb.native_ml_dsa_sign(65, MESSAGE, sk)
    assert pb.dilithium_verify(MESSAGE, sig, pk)
    assert pb.native_ml_dsa_verify(65, MESSAGE, sig, pk, ctx=b"")


def test_internal_interface_signature_does_not_verify_as_external(
    keys: tuple[bytes, bytes],
) -> None:
    pk, sk = keys
    internal = pb.native_ml_dsa_sign(65, MESSAGE, sk)
    assert pb.native_ml_dsa_verify(65, MESSAGE, internal, pk)  # as internal
    assert not pb.dilithium_verify(MESSAGE, internal, pk)  # not as external
    assert not pb.native_ml_dsa_verify(65, MESSAGE, internal, pk, ctx=b"")


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
