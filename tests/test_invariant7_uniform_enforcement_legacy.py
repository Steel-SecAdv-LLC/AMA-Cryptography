# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""INVARIANT-7 uniform call-time enforcement regression test — legacy_compat.

Context
-------
Companion to ``test_invariant7_uniform_enforcement.py``, which covers
:mod:`ama_cryptography.crypto_api`.  This module locks the same
guarantee on :mod:`ama_cryptography.legacy_compat`: under the Sphinx
docs-build gate (``AMA_SPHINX_BUILD=1``) the import-time guard stands
down, so every public cryptographic entry point on ``legacy_compat``
must invoke :func:`ama_cryptography.legacy_compat._enforce_invariant7_lc`
at its top — otherwise a missing native library leaks a downstream
``AttributeError`` / opaque FFI error instead of the canonical
INVARIANT-7 ``RuntimeError``.

The list below pins every ``_enforce_invariant7_lc()`` call site in
``legacy_compat.py`` (14 as of this PR, covering Dilithium, Ed25519,
HMAC-SHA3-256, RFC3161 verify, HKDF context / derive, KMS
generation, and legacy package create / verify).

How to add a new entry point
----------------------------
When you add a new public crypto function to ``legacy_compat.py``:
  1. Add ``_enforce_invariant7_lc()`` as the first statement of the
     function body.
  2. Append an entry to :data:`_ENFORCED_ENTRY_POINTS` below.
If you skip step 1, step 2's test will fail loudly.
"""

from __future__ import annotations

from typing import Any, Callable
from unittest.mock import patch

import pytest

from ama_cryptography import pqc_backends as pq

pytestmark = pytest.mark.skipif(
    pq._native_lib is None,
    reason="Native library unavailable; legacy_compat refuses to import without it.",
)


class _InvariantSentinelError(Exception):
    """Raised by the patched ``_enforce_invariant7_lc`` so the test can
    detect that the enforcer was invoked without caring about the
    downstream error path."""


def _raise_sentinel() -> None:
    raise _InvariantSentinelError("INVARIANT-7 enforcer was invoked (expected)")


def _make_entries() -> list[tuple[str, Callable[[], Any]]]:
    """Return (label, zero-arg callable) for every public crypto entry
    point on ``legacy_compat`` that must invoke ``_enforce_invariant7_lc``.

    Argument values never matter — the sentinel-raising patch fires
    before any argument is inspected.
    """
    from ama_cryptography import legacy_compat as lc

    dummy_bytes = b"x" * 32
    dummy_tag = b"y" * 32
    dummy_key = b"k" * 32
    dummy_sig = b"s" * 64
    dummy_pub = b"p" * 32

    entries: list[tuple[str, Callable[[], Any]]] = [
        ("generate_dilithium_keypair", lc.generate_dilithium_keypair),
        ("dilithium_sign", lambda: lc.dilithium_sign(dummy_bytes, dummy_bytes)),
        (
            "dilithium_verify",
            lambda: lc.dilithium_verify(dummy_bytes, dummy_sig, dummy_pub),
        ),
        ("hmac_authenticate", lambda: lc.hmac_authenticate(dummy_bytes, dummy_key)),
        ("hmac_verify", lambda: lc.hmac_verify(dummy_bytes, dummy_tag, dummy_key)),
        ("generate_ed25519_keypair", lambda: lc.generate_ed25519_keypair()),
        ("ed25519_sign", lambda: lc.ed25519_sign(dummy_bytes, dummy_bytes)),
        (
            "ed25519_verify",
            lambda: lc.ed25519_verify(dummy_bytes, dummy_sig, dummy_pub),
        ),
        (
            "verify_rfc3161_timestamp",
            lambda: lc.verify_rfc3161_timestamp(dummy_bytes, dummy_bytes),
        ),
        (
            "create_ethical_hkdf_context",
            lambda: lc.create_ethical_hkdf_context(dummy_bytes),
        ),
        ("derive_keys", lambda: lc.derive_keys(dummy_bytes, dummy_bytes)),
        (
            "generate_key_management_system",
            lambda: lc.generate_key_management_system(),
        ),
        ("create_crypto_package", lambda: lc.create_crypto_package(dummy_bytes)),
        (
            "verify_crypto_package",
            lambda: lc.verify_crypto_package(dummy_bytes, object()),
        ),
    ]
    return entries


# Lazy construction: ``legacy_compat`` imports are legal in this process
# because ``pytestmark`` already gated on ``_native_lib is not None``.
_ENFORCED_ENTRY_POINTS: list[tuple[str, Callable[[], Any]]] = (
    _make_entries() if pq._native_lib is not None else []
)


@pytest.mark.parametrize(
    "label,call",
    _ENFORCED_ENTRY_POINTS,
    ids=[label for label, _ in _ENFORCED_ENTRY_POINTS],
)
def test_entry_point_invokes_enforce_invariant7_lc(label: str, call: Callable[[], Any]) -> None:
    """Every public crypto entry point on ``legacy_compat`` must call
    ``_enforce_invariant7_lc`` BEFORE any other work."""
    with patch(
        "ama_cryptography.legacy_compat._enforce_invariant7_lc",
        side_effect=_raise_sentinel,
    ):
        with pytest.raises(_InvariantSentinelError):
            call()


def test_entry_point_list_is_non_trivial() -> None:
    """Guard against the test silently collecting zero entries (vacuous
    pass) or against a refactor that removes entry points without
    updating the table above."""
    assert len(_ENFORCED_ENTRY_POINTS) >= 14, (
        f"Expected at least 14 enforced legacy_compat entry points, got "
        f"{len(_ENFORCED_ENTRY_POINTS)}. Check the labels collected."
    )


def test_key_management_hmac_sha512_invokes_enforce_invariant7_km() -> None:
    """Locks the single INVARIANT-7 choke point on ``key_management``:
    every HD-derivation / HMAC-SHA-512 consumer goes through
    ``_hmac_sha512``, and ``_hmac_sha512`` must invoke
    ``_enforce_invariant7_km`` before any FFI descent."""
    from ama_cryptography import key_management as km

    with patch(
        "ama_cryptography.key_management._enforce_invariant7_km",
        side_effect=_raise_sentinel,
    ):
        with pytest.raises(_InvariantSentinelError):
            km._hmac_sha512(b"k" * 32, b"m" * 32)


def test_call_site_count_matches_source() -> None:
    """Regression guard: the number of ``_enforce_invariant7_lc()`` call
    sites in ``legacy_compat.py`` must match the entry-point table
    above.  A mismatch means either a new entry point was added without
    a regression-guard row (coverage gap) or a row was added without a
    corresponding call site (false entry)."""
    import inspect

    from ama_cryptography import legacy_compat as lc

    source = inspect.getsource(lc)
    # Only indented call sites — the unindented ``def _enforce_invariant7_lc()``
    # line is excluded, and the ``from ...`` imports (if any) would also be
    # filtered out because they don't carry parentheses.  Matches any
    # indentation depth (top-level defs use 4, nested would use 8, etc.).
    call_sites = sum(
        1 for line in source.splitlines() if line.lstrip().startswith("_enforce_invariant7_lc()")
    )
    assert call_sites == len(_ENFORCED_ENTRY_POINTS), (
        f"Mismatch: legacy_compat.py has {call_sites} call sites of "
        f"_enforce_invariant7_lc() but the regression-guard table has "
        f"{len(_ENFORCED_ENTRY_POINTS)} entries. Add/remove entries to "
        "match the module source."
    )
