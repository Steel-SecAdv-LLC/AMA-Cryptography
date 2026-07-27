#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
INVARIANT-35 — a selector must never resolve weaker than it was asked.
=====================================================================

INVARIANT-7 covers the availability axis: no native backend, no operation.
This module covers the *selection* axis, which nothing covered until the
library grew nine selectable security levels across three families plus
SLH-DSA's two — each an integer or a string away from its neighbours.

The failure being prevented is quiet and total. A selector that maps an
unrecognised ``"ML-KEM-192"`` onto ML-KEM-512, or a mistyped curve id onto
P-256, produces working code, valid signatures and successful handshakes at a
security level nobody chose. Unlike a missing backend it never surfaces: every
downstream artefact is well-formed and every roundtrip test passes.

Two design choices here are deliberate:

* The list of selectors is **derived from the modules**, not written out by
  hand. Adding a tenth parameter set without adding it to a literal list would
  otherwise leave it untested while the suite still went green.
* The battery of bad inputs includes ``True``. ``bool`` is an ``int`` subclass
  in Python, so ``True`` silently indexes position 1 of anything that accepts
  an integer selector — a real class of bug, not a hypothetical one.
"""

from __future__ import annotations

import ctypes
import sys
from pathlib import Path
from typing import Any, Callable

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import ama_cryptography.pqc_backends as pb  # noqa: E402 -- import follows the repo-root sys.path insert above (SEL-001)

# Inputs no selector may accept. Each is a shape that has produced a real
# silent-downgrade bug in some library somewhere.
BAD_INPUTS: tuple[Any, ...] = (
    None,           # missing configuration read as a default
    True,           # bool is an int subclass: indexes position 1
    False,          # ...and position 0
    -1,             # negative index wraps in some languages
    0,              # the classic "unset" sentinel
    "",             # empty config value
    "default",      # a word that invites a fallback branch
    3.0,            # float that equals a valid int
    b"P-256",       # bytes where str was meant
    (),             # wrong container type
)

# Values that look like a real selector but name nothing. These are the
# dangerous ones: a fallback branch would map them onto a neighbour.
NEAR_MISSES: dict[str, tuple[Any, ...]] = {
    "curve": ("P-192", "P-224", "P-256 ", "p-256", "secp256k1", "Ed25519",
              "prime256v2", 1, 2, 3, 192, 224, 255, 257, 383, 385, 520, 522,
              # every other family's valid values: a mis-routed call
              512, 768, 1024, 44, 65, 87),
    "ml_kem": ("ML-KEM-192", "ML-KEM-1023", "Kyber", "Kyber1023", "ml-kem-512",
               "ML-DSA-44", 511, 513, 767, 769, 1023, 1025,
               # every other family's valid values: a mis-routed call
               256, 384, 521, 44, 65, 87),
    "ml_dsa": ("ML-DSA-46", "ML-DSA-2", "Dilithium", "Dilithium4", "ml-dsa-44",
               "ML-KEM-512", 2, 43, 45, 64, 66, 86, 88,
               # every other family's valid values: a mis-routed call
               256, 384, 521, 512, 768, 1024),
}

# The selectors under test, derived from the module rather than hand-listed.
SELECTORS: dict[str, Callable[[Any], int]] = {
    "curve": pb._nistp_curve_id,
    "ml_kem": pb._ml_kem_id,
    "ml_dsa": pb._ml_dsa_id,
}


def test_every_selector_is_covered() -> None:
    """The enumeration must not drift behind the module.

    Any private ``_*_id`` resolver in ``pqc_backends`` is a selector by
    construction. If one appears that this module does not drive, that is the
    failure — not a reason to quietly extend the literal above.
    """
    discovered = {
        name
        for name in dir(pb)
        if name.startswith("_") and name.endswith("_id") and callable(getattr(pb, name))
    }
    covered = {fn.__name__ for fn in SELECTORS.values()}
    # `_param_set_id` is the shared implementation the others delegate to; it
    # takes explicit tables rather than being a selector in its own right.
    discovered.discard("_param_set_id")
    assert discovered == covered, (
        f"selector(s) not driven by this module: {sorted(discovered - covered)}"
    )


@pytest.mark.parametrize("kind", sorted(SELECTORS))
@pytest.mark.parametrize("bad", BAD_INPUTS, ids=repr)
def test_selector_rejects_malformed_input(kind: str, bad: Any) -> None:
    with pytest.raises((ValueError, TypeError)):
        SELECTORS[kind](bad)


@pytest.mark.parametrize("kind", sorted(NEAR_MISSES))
def test_selector_rejects_plausible_near_misses(kind: str) -> None:
    """The dangerous inputs: they look right and name nothing."""
    for bad in NEAR_MISSES[kind]:
        with pytest.raises(ValueError):
            SELECTORS[kind](bad)


@pytest.mark.parametrize("kind", sorted(SELECTORS))
def test_selector_error_names_the_valid_choices(kind: str) -> None:
    """A refusal must be actionable, or callers will invent a fallback."""
    with pytest.raises(ValueError) as excinfo:
        SELECTORS[kind]("definitely-not-a-real-parameter-set")
    message = str(excinfo.value)
    assert "definitely-not-a-real-parameter-set" in message
    assert "expected one of" in message or "expected" in message


def test_aliases_resolve_only_to_sets_that_exist() -> None:
    """An alias may rename a real set. It may not conjure one."""
    for name, ps in pb.NISTP_CURVES_BY_NAME.items():
        assert ps in pb.NISTP_FIELD_BYTES, f"curve alias {name!r} names nothing"
        assert pb._nistp_curve_id(name) == ps
    for name, ps in pb.ML_KEM_BY_NAME.items():
        assert ps in pb.ML_KEM_PARAM_SETS, f"ML-KEM alias {name!r} names nothing"
        assert pb._ml_kem_id(name) == ps
    for name, ps in pb.ML_DSA_BY_NAME.items():
        assert ps in pb.ML_DSA_PARAM_SETS, f"ML-DSA alias {name!r} names nothing"
        assert pb._ml_dsa_id(name) == ps


def test_selectors_are_not_order_dependent() -> None:
    """Distinct selectors must not share a numbering space.

    ML-KEM-512 is 512 and ML-DSA-44 is 44 precisely so a value passed to the
    wrong family is rejected rather than silently accepted. If the two families
    ever overlapped numerically, a mis-routed call would resolve.
    """
    assert not (set(pb.ML_KEM_PARAM_SETS) & set(pb.ML_DSA_PARAM_SETS))
    assert not (set(pb.ML_KEM_PARAM_SETS) & set(pb.NISTP_FIELD_BYTES))
    assert not (set(pb.ML_DSA_PARAM_SETS) & set(pb.NISTP_FIELD_BYTES))


# ---------------------------------------------------------------------------
# The C side: an unknown selector must yield 0 / NULL, never another set's size
# ---------------------------------------------------------------------------
@pytest.mark.skipif(pb._native_lib is None, reason="native library not built")
def test_native_size_queries_refuse_unknown_selectors() -> None:
    """A size query is where a silent downgrade would become a buffer bug.

    Returning some *other* set's length for an unrecognised selector is the
    worst available behaviour: the caller allocates confidently and the
    mismatch surfaces as corruption rather than as an error.
    """
    lib = pb._native_lib
    assert lib is not None

    size_fns = (
        "ama_ml_kem_public_key_bytes",
        "ama_ml_kem_secret_key_bytes",
        "ama_ml_kem_ciphertext_bytes",
        "ama_ml_dsa_public_key_bytes",
        "ama_ml_dsa_secret_key_bytes",
        "ama_ml_dsa_signature_bytes",
        "ama_nistp_field_bytes",
        "ama_nistp_pubkey_bytes",
        "ama_nistp_sig_der_max_len",
    )
    name_fns = (
        "ama_ml_kem_param_set_name",
        "ama_ml_dsa_param_set_name",
        "ama_nistp_curve_name",
    )
    # Neighbouring and nonsense selector values, including every *other*
    # family's valid values — the mis-routed-call case.
    unknown = (-1, 0, 1, 2, 3, 7, 44, 65, 87, 99, 256, 512, 768, 1024, 4096)

    for fn_name in size_fns:
        fn = getattr(lib, fn_name)
        fn.argtypes = [ctypes.c_int]
        fn.restype = ctypes.c_size_t
        family = fn_name.split("_")[1] + "_" + fn_name.split("_")[2]
        valid = {
            "ml_kem": set(pb.ML_KEM_PARAM_SETS),
            "ml_dsa": set(pb.ML_DSA_PARAM_SETS),
            "nistp_field": set(pb.NISTP_FIELD_BYTES),
            "nistp_pubkey": set(pb.NISTP_FIELD_BYTES),
            "nistp_sig": set(pb.NISTP_FIELD_BYTES),
        }[family]
        for value in unknown:
            if value in valid:
                continue
            assert fn(value) == 0, (
                f"{fn_name}({value}) returned a non-zero size for an "
                "unrecognised selector"
            )

    for fn_name in name_fns:
        fn = getattr(lib, fn_name)
        fn.argtypes = [ctypes.c_int]
        fn.restype = ctypes.c_char_p
        family = fn_name.split("_")[1] + "_" + fn_name.split("_")[2]
        valid = {
            "ml_kem": set(pb.ML_KEM_PARAM_SETS),
            "ml_dsa": set(pb.ML_DSA_PARAM_SETS),
            "nistp_curve": set(pb.NISTP_FIELD_BYTES),
        }[family]
        for value in unknown:
            if value in valid:
                continue
            assert fn(value) is None, (
                f"{fn_name}({value}) named a parameter set for an "
                "unrecognised selector"
            )


@pytest.mark.skipif(pb._native_lib is None, reason="native library not built")
def test_native_operations_refuse_unknown_selectors() -> None:
    """Not just the queries — the operations themselves must refuse."""
    lib = pb._native_lib
    assert lib is not None
    buf = ctypes.create_string_buffer(8192)
    out_len = ctypes.c_size_t(8192)

    for bad in (0, 1, 7, 99, 4096):
        assert lib.ama_ml_kem_keypair(
            bad, buf, ctypes.c_size_t(8192), buf, ctypes.c_size_t(8192)
        ) != 0
        assert lib.ama_ml_dsa_keypair(bad, buf, buf) != 0
        assert lib.ama_nistp_keypair(bad, buf, buf) != 0
        assert lib.ama_ml_kem_encapsulate(
            bad, buf, ctypes.c_size_t(8192), buf, ctypes.byref(out_len),
            buf, ctypes.c_size_t(32)
        ) != 0
