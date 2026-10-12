#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""ML-KEM seed expansion borrows a bytearray seed instead of copying it."""

from __future__ import annotations

from typing import Any

import pytest

from ama_cryptography import key_formats as kf
from ama_cryptography import pqc_backends as pb

_ALG = kf.ALGORITHMS["ML-KEM-768"]


def _seed() -> bytes:
    return bytes((0x5A + i) & 0xFF for i in range(_ALG.pq_seed_bytes))


def test_expand_matches_reference_for_bytes_and_bytearray() -> None:
    """PIN: a bytes and a bytearray seed expand to the reference key (d/z split, bytes branch)."""
    seed = _seed()
    ref_pk, ref_sk = pb.native_ml_kem_keypair_from_seed(_ALG.pq_set, seed[:32], seed[32:])
    for form in (seed, bytearray(seed)):
        secret, public = kf._expand_pq_seed(_ALG, form)
        assert (public, secret) == (ref_pk, ref_sk)


def test_expand_views_alias_the_callers_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIN: the halves handed to the backend are views of the caller's own seed.

    A copy behind a memoryview has the same type and output; only the identity
    of ``.obj`` and a later write showing through tell it from an alias.
    """
    seen: list[tuple[type, object]] = []
    real = pb.native_ml_kem_keypair_from_seed

    def spy(ps: Any, d: Any, z: Any) -> Any:
        seen.extend([(type(d), d.obj), (type(z), z.obj)])
        return real(ps, d, z)

    monkeypatch.setattr(pb, "native_ml_kem_keypair_from_seed", spy)
    seed = bytearray(_seed())
    kf._expand_pq_seed(_ALG, seed)
    assert [t for t, _ in seen] == [memoryview, memoryview]
    assert seen[0][1] is seed and seen[1][1] is seed
    # The views were released on return; re-view the seed the same way and
    # confirm a write is seen through it (an aliasing view, not a copy).
    with memoryview(seed) as whole, whole[:32] as d2:
        seed[0] ^= 0xFF
        assert d2[0] == seed[0]


def test_seed_views_released_even_when_backend_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIN: the views are released even when the backend raises.

    The held exception keeps the frame alive, so an unreleased ``d`` or ``z``
    would still export the seed and the resize below would raise BufferError.
    """

    def boom(ps: Any, d: Any, z: Any) -> Any:
        raise RuntimeError("backend failed")

    monkeypatch.setattr(pb, "native_ml_kem_keypair_from_seed", boom)
    seed = bytearray(_seed())
    with pytest.raises(RuntimeError) as held:
        kf._expand_pq_seed(_ALG, seed)
    assert held.value.__traceback__ is not None
    seed[:] = bytes(len(seed))
    assert not any(seed)
    seed.append(0)  # BufferError if a view is still exported


def test_ml_dsa_expand_passes_a_bytearray_seed_through_without_a_copy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN: the ML-DSA branch hands the caller's own seed object to the backend."""
    alg = kf.ALGORITHMS["ML-DSA-65"]
    seen: list[object] = []
    real = pb.native_ml_dsa_keypair_from_seed

    def spy(ps: Any, seed: Any) -> Any:
        seen.append(seed)
        return real(ps, seed)

    monkeypatch.setattr(pb, "native_ml_dsa_keypair_from_seed", spy)
    raw = bytes((0x21 + i) & 0xFF for i in range(alg.pq_seed_bytes))
    ref_pk, ref_sk = real(alg.pq_set, raw)
    mutable = bytearray(raw)
    secret, public = kf._expand_pq_seed(alg, mutable)
    assert (public, secret) == (ref_pk, ref_sk)
    assert len(seen) == 1 and seen[0] is mutable
    secret, public = kf._expand_pq_seed(alg, raw)
    assert (public, secret) == (ref_pk, ref_sk)
    assert len(seen) == 2 and seen[1] is raw
