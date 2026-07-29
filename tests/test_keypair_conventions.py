#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Every keypair function must return ``(public, secret)`` — in that order.
=======================================================================

This is an API-shape gate, and it exists because the shape has already gone
wrong once. ``native_nistp_keypair`` was written returning
``(private_key, public_key)`` while every other keypair function in the library
returns ``(public_key, secret_key)``. In a codebase where both appear:

.. code-block:: python

    pub, priv = native_x25519_keypair()
    pub, priv = native_nistp_keypair("P-256")   # actually (priv, pub)

the second line lands a private key in the variable the caller is about to
publish. Nothing in the type system, the linter or any behavioural test
notices: both values are 32-or-more opaque bytes, and the code runs.

Docstrings are not enough — the inconsistent function had a docstring stating
its (wrong) order accurately. So this module asserts the property *behaviourally*
for every keypair function it can discover: it takes the first element and
proves it is the public key, by deriving the public key from the second element
and requiring them to match.

Discovery is by naming convention rather than a hand-written list, so a new
``*_keypair`` function that does not appear here fails
``test_every_keypair_function_is_covered`` instead of going unchecked.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import ama_cryptography.pqc_backends as pb  # noqa: E402 -- import follows the repo-root sys.path insert above (KPC-001)

X25519_BASEPOINT = bytes([9]) + b"\x00" * 31


def _derive_x25519(secret: bytes) -> bytes:
    return pb.native_x25519_key_exchange(secret, X25519_BASEPOINT)


def _derive_ed25519(secret: bytes) -> bytes:
    # RFC 8032 expanded form: sk = seed || pk, so the public key is its tail.
    # Re-deriving from the seed proves the tail is not merely *some* 32 bytes.
    public, _ = pb.native_ed25519_keypair_from_seed(secret[:32])
    assert public == secret[32:], "Ed25519 secret key tail is not its public key"
    derived: bytes = public
    return derived


def _derive_nistp(secret: bytes, curve: Any) -> bytes:
    public: bytes = pb.native_nistp_pubkey_from_privkey(curve, secret)
    return public


# Each entry: a zero-argument constructor, and a way to recompute the public
# key from the secret. If the constructor's first element is not what the
# derivation produces, the ordering is wrong.
KEYPAIRS: dict[str, tuple[Callable[[], tuple[Any, ...]], Callable[[bytes], bytes]]] = {
    "native_x25519_keypair": (pb.native_x25519_keypair, _derive_x25519),
    "native_ed25519_keypair": (pb.native_ed25519_keypair, _derive_ed25519),
    "native_nistp_keypair/P-256": (
        lambda: pb.native_nistp_keypair("P-256"),
        lambda sk: _derive_nistp(sk, "P-256"),
    ),
    "native_nistp_keypair/P-384": (
        lambda: pb.native_nistp_keypair("P-384"),
        lambda sk: _derive_nistp(sk, "P-384"),
    ),
    "native_nistp_keypair/P-521": (
        lambda: pb.native_nistp_keypair("P-521"),
        lambda sk: _derive_nistp(sk, "P-521"),
    ),
}


@pytest.mark.skipif(pb._native_lib is None, reason="native library not built")
@pytest.mark.parametrize("name", sorted(KEYPAIRS))
def test_keypair_returns_public_first(name: str) -> None:
    """The first element must be the public key, proven by re-derivation."""
    make, derive = KEYPAIRS[name]
    first, second = make()
    assert derive(second) == first, (
        f"{name} returned (secret, public); every keypair function in this "
        "library returns (public, secret)"
    )


@pytest.mark.skipif(pb._native_lib is None, reason="native library not built")
@pytest.mark.parametrize("name", sorted(KEYPAIRS))
def test_swapped_unpacking_is_detectable(name: str) -> None:
    """The two elements must not be interchangeable.

    If a keypair's public and secret halves were the same width *and* either
    could be used as either, the ordering gate above would be vacuous. This
    asserts they are genuinely distinguishable — so the previous test is
    testing something.
    """
    make, derive = KEYPAIRS[name]
    first, second = make()
    assert first != second
    # Deriving from the *public* half must not reproduce the public half.
    # A refusal is an even stronger form of "distinguishable" than a wrong
    # answer, so both outcomes satisfy the property; silently returning the
    # input unchanged is the only failure.
    try:
        derived = derive(first)
    except (ValueError, RuntimeError, AssertionError):
        return
    assert derived != first


@pytest.mark.skipif(pb._native_lib is None, reason="native library not built")
def test_ml_kem_and_ml_dsa_return_public_first() -> None:
    """The PQC keypairs, whose halves differ in length.

    Length alone is the distinguisher here, and it is a real one: swapping the
    return values would produce a public key of secret-key length, which every
    downstream length check rejects. Asserted per parameter set so a mis-wired
    row cannot hide behind a correct one.
    """
    for ps in pb.ML_KEM_PARAM_SETS:
        pk, sk = pb.native_ml_kem_keypair(ps)
        sizes = pb.ML_KEM_SIZES[ps]
        assert len(pk) == sizes["public_key"], f"ML-KEM-{ps} returned secret first"
        assert len(sk) == sizes["secret_key"]
        # The public key must be usable as one, and the secret must not be.
        pb.native_ml_kem_encapsulate(ps, pk)
        with pytest.raises(ValueError):
            pb.native_ml_kem_encapsulate(ps, sk)

    for ps in pb.ML_DSA_PARAM_SETS:
        pk, sk = pb.native_ml_dsa_keypair(ps)
        sizes = pb.ML_DSA_SIZES[ps]
        assert len(pk) == sizes["public_key"], f"ML-DSA-{ps} returned secret first"
        assert len(sk) == sizes["secret_key"]
        sig = pb.native_ml_dsa_sign(ps, b"m", sk)
        assert pb.native_ml_dsa_verify(ps, b"m", sig, pk)
        # Signing with the public key must fail rather than produce something.
        with pytest.raises(ValueError):
            pb.native_ml_dsa_sign(ps, b"m", pk)


def test_every_keypair_function_is_covered() -> None:
    """A new ``*_keypair`` function must be added here, not silently skipped."""
    discovered = {
        name
        for name in dir(pb)
        if name.endswith("_keypair") and not name.startswith("_") and callable(getattr(pb, name))
    }
    covered = {name.split("/")[0] for name in KEYPAIRS}
    covered |= {"native_ml_kem_keypair", "native_ml_dsa_keypair"}
    # ``generate_*_keypair`` return dataclasses with named fields rather than
    # tuples, so they cannot be unpacked in the wrong order by construction.
    dataclass_returning = {name for name in discovered if name.startswith("generate_")}
    # ``*_from_seed`` variants are covered transitively: they share the return
    # statement of the function they mirror.
    seeded = {name for name in discovered if name.endswith("_from_seed")}

    uncovered = discovered - covered - dataclass_returning - seeded
    assert (
        not uncovered
    ), f"keypair function(s) with an unasserted return order: {sorted(uncovered)}"


def test_dataclass_keypairs_use_named_fields() -> None:
    """The ``generate_*`` surface must stay unpackable-by-name.

    These are immune to the ordering hazard precisely because they are not
    tuples. That immunity is a property worth pinning: turning one back into a
    bare tuple would reintroduce the failure this module exists for.
    """
    for name in ("generate_kyber_keypair", "generate_dilithium_keypair"):
        fn = getattr(pb, name, None)
        if fn is None:
            continue
        kp = fn()
        assert hasattr(kp, "public_key"), f"{name} lost its named public_key field"
        assert hasattr(kp, "secret_key"), f"{name} lost its named secret_key field"
        assert not isinstance(kp, tuple), f"{name} degraded to a bare tuple"
