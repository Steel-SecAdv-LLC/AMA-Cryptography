# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""INVARIANT-7 uniform call-time enforcement regression test.

Context
-------
PR #258 moved the INVARIANT-7 fail-closed guarantee from import-time to
call-time under an explicit env-var gate (``AMA_SPHINX_BUILD=1`` /
``SPHINX_BUILD=1`` with strict truthy parsing). The follow-up to #258
completes the call-time half of the promise: every concrete public
cryptographic entry point in :mod:`ama_cryptography.crypto_api` invokes
:func:`ama_cryptography.crypto_api._enforce_invariant7` at its top,
before any other work, so that a missing native library is surfaced
with the INVARIANT-7-specific ``RuntimeError`` rather than leaking a
downstream ``AttributeError`` / ``TypeError`` / opaque FFI error.

What this test does
-------------------
For each entry point in :data:`_ENFORCED_ENTRY_POINTS`, it patches
``crypto_api._enforce_invariant7`` to raise a sentinel exception and
invokes the method. If the method does NOT invoke the enforcer first,
the sentinel is never raised and the test fails — catching any future
refactor that adds a new crypto entry point without the guard.

Why a sentinel instead of patching ``_native_lib``: the sentinel pins
the invocation order. ``_enforce_invariant7`` must be the FIRST call
(before parameter validation, before any FFI descent); the sentinel
proves that. Patching ``_native_lib`` only proves the downstream FFI
would fail, not that the enforcer is the thing catching it.

How to add a new entry point
----------------------------
When you add a new public crypto method to ``crypto_api.py``:
  1. Add ``_enforce_invariant7()`` as the first statement of the
     method body.
  2. Append an entry to :data:`_ENFORCED_ENTRY_POINTS` below.
If you skip step 1, step 2's test will fail loudly.
"""

from __future__ import annotations

import logging
from typing import Any, Callable
from unittest.mock import patch

import pytest

from ama_cryptography import pqc_backends as pq

_logger = logging.getLogger(__name__)

# Construction of provider instances requires the native library (each
# provider's ``__init__`` raises if the backend is missing). We skip the
# whole module in environments without the native lib rather than mock
# every __init__.
pytestmark = pytest.mark.skipif(
    pq._native_lib is None,
    reason="Native library unavailable; provider instantiation needs it.",
)


class _InvariantSentinelError(Exception):
    """Raised by the patched ``_enforce_invariant7`` so the test can
    detect that the enforcer was invoked without caring about the
    downstream error path."""


def _raise_sentinel() -> None:
    raise _InvariantSentinelError("INVARIANT-7 enforcer was invoked (expected)")


def _make_entries() -> list[tuple[str, Callable[[], Any]]]:
    """Return a list of (label, zero-arg callable) for every concrete
    crypto entry point that must invoke ``_enforce_invariant7``.

    Each callable takes no arguments; it closes over pre-instantiated
    provider objects and dummy argument values. The actual argument
    values never matter — the test expects the sentinel to fire BEFORE
    any argument is inspected.
    """
    from ama_cryptography.crypto_api import (
        AESGCMProvider,
        AlgorithmType,
        AmaCryptography,
        Ed25519Provider,
        HybridKEMProvider,
        HybridSignatureProvider,
        KeypairCache,
        KyberProvider,
        MLDSAProvider,
        SphincsProvider,
        batch_verify_ed25519,
        create_crypto_package,
        quick_hash,
        quick_kem,
        quick_sign,
        quick_verify,
        verify_crypto_package,
    )

    entries: list[tuple[str, Callable[[], Any]]] = []
    dummy_bytes = b"x" * 32

    # Providers whose __init__ may raise if their specific backend is
    # absent. Each try/except is narrow: we only skip the entries for
    # backends that aren't built, not the whole module.
    try:
        mldsa = MLDSAProvider()
        entries += [
            ("MLDSAProvider.generate_keypair", mldsa.generate_keypair),
            ("MLDSAProvider.sign", lambda: mldsa.sign(dummy_bytes, dummy_bytes)),
            ("MLDSAProvider.verify", lambda: mldsa.verify(dummy_bytes, dummy_bytes, dummy_bytes)),
        ]
    except Exception as _exc:
        _logger.debug("optional backend unavailable: %s", _exc)

    try:
        ed = Ed25519Provider()
        entries += [
            ("Ed25519Provider.generate_keypair", ed.generate_keypair),
            ("Ed25519Provider.sign", lambda: ed.sign(dummy_bytes, dummy_bytes)),
            ("Ed25519Provider.verify", lambda: ed.verify(dummy_bytes, dummy_bytes, dummy_bytes)),
            ("Ed25519Provider.batch_verify", lambda: Ed25519Provider.batch_verify([])),
        ]
    except Exception as _exc:
        _logger.debug("optional backend unavailable: %s", _exc)

    entries.append(("batch_verify_ed25519", lambda: batch_verify_ed25519([])))

    try:
        kyber = KyberProvider()
        entries += [
            ("KyberProvider.generate_keypair", kyber.generate_keypair),
            ("KyberProvider.encapsulate", lambda: kyber.encapsulate(dummy_bytes)),
            ("KyberProvider.decapsulate", lambda: kyber.decapsulate(dummy_bytes, dummy_bytes)),
        ]
    except Exception as _exc:
        _logger.debug("optional backend unavailable: %s", _exc)

    try:
        sphincs = SphincsProvider()
        entries += [
            ("SphincsProvider.generate_keypair", sphincs.generate_keypair),
            ("SphincsProvider.sign", lambda: sphincs.sign(dummy_bytes, dummy_bytes)),
            (
                "SphincsProvider.verify",
                lambda: sphincs.verify(dummy_bytes, dummy_bytes, dummy_bytes),
            ),
        ]
    except Exception as _exc:
        _logger.debug("optional backend unavailable: %s", _exc)

    try:
        aes = AESGCMProvider()
        entries += [
            ("AESGCMProvider.encrypt", lambda: aes.encrypt(dummy_bytes, dummy_bytes * 1)),
            (
                "AESGCMProvider.decrypt",
                lambda: aes.decrypt(dummy_bytes, dummy_bytes, dummy_bytes, dummy_bytes),
            ),
        ]
    except Exception as _exc:
        _logger.debug("optional backend unavailable: %s", _exc)

    try:
        hkem = HybridKEMProvider()
        entries += [
            ("HybridKEMProvider.generate_keypair", hkem.generate_keypair),
            ("HybridKEMProvider.encapsulate", lambda: hkem.encapsulate(dummy_bytes)),
            ("HybridKEMProvider.decapsulate", lambda: hkem.decapsulate(dummy_bytes, dummy_bytes)),
        ]
    except Exception as _exc:
        _logger.debug("optional backend unavailable: %s", _exc)

    try:
        hsig = HybridSignatureProvider()
        entries += [
            ("HybridSignatureProvider.generate_keypair", hsig.generate_keypair),
            ("HybridSignatureProvider.sign", lambda: hsig.sign(dummy_bytes, dummy_bytes)),
            (
                "HybridSignatureProvider.verify",
                lambda: hsig.verify(dummy_bytes, dummy_bytes, dummy_bytes),
            ),
        ]
    except Exception as _exc:
        _logger.debug("optional backend unavailable: %s", _exc)

    # Facade. Uses Ed25519 because it has the shortest init path.
    try:
        ama = AmaCryptography(algorithm=AlgorithmType.ED25519)
        entries += [
            ("AmaCryptography.generate_keypair", ama.generate_keypair),
            ("AmaCryptography.sign", lambda: ama.sign(dummy_bytes, dummy_bytes)),
            ("AmaCryptography.verify", lambda: ama.verify(dummy_bytes, dummy_bytes, dummy_bytes)),
        ]
    except Exception as _exc:
        _logger.debug("optional backend unavailable: %s", _exc)

    try:
        ama_kem = AmaCryptography(algorithm=AlgorithmType.KYBER_1024)
        entries += [
            ("AmaCryptography.encapsulate", lambda: ama_kem.encapsulate(dummy_bytes)),
            ("AmaCryptography.decapsulate", lambda: ama_kem.decapsulate(dummy_bytes, dummy_bytes)),
        ]
    except Exception as _exc:
        _logger.debug("optional backend unavailable: %s", _exc)

    # Top-level convenience helpers.
    entries += [
        ("quick_hash", lambda: quick_hash(dummy_bytes)),
        ("quick_sign", lambda: quick_sign(dummy_bytes)),
        ("quick_verify", lambda: quick_verify(dummy_bytes, dummy_bytes, dummy_bytes)),
        ("quick_kem", lambda: quick_kem()),
    ]

    # create_crypto_package / verify_crypto_package — top-level crypto
    # compositions that must also be guarded.  The sentinel-raising
    # ``_enforce_invariant7`` patch fires before either argument is
    # inspected, so a dummy that doesn't structurally match
    # ``CryptoPackageResult`` never reaches the function body; a
    # ``typing.cast`` keeps ``mypy --strict`` happy without a runtime
    # dependency on constructing a real ``CryptoPackageResult``.
    from typing import cast

    from ama_cryptography.crypto_api import CryptoPackageResult

    _dummy_result = cast(CryptoPackageResult, object())
    entries += [
        ("create_crypto_package", lambda: create_crypto_package(dummy_bytes)),
        (
            "verify_crypto_package",
            lambda: verify_crypto_package(dummy_bytes, _dummy_result),
        ),
    ]

    # KeypairCache.get_or_generate delegates into AmaCryptography; its
    # guard is the one pinned here.
    try:
        kc = KeypairCache()
        entries.append(("KeypairCache.get_or_generate", kc.get_or_generate))
    except Exception as _exc:
        _logger.debug("optional backend unavailable: %s", _exc)

    return entries


# Build the list lazily only when the native lib is present; on a
# docs-only / no-native box ``import ama_cryptography.crypto_api`` raises
# at the INVARIANT-7 import guard (by design), so eager construction
# would explode before ``pytestmark`` could skip collection.
_ENFORCED_ENTRY_POINTS: list[tuple[str, Callable[[], Any]]] = (
    _make_entries() if pq._native_lib is not None else []
)


@pytest.mark.parametrize(
    "label,call",
    _ENFORCED_ENTRY_POINTS,
    ids=[label for label, _ in _ENFORCED_ENTRY_POINTS],
)
def test_entry_point_invokes_enforce_invariant7(label: str, call: Callable[[], Any]) -> None:
    """Every concrete crypto entry point must call ``_enforce_invariant7``
    BEFORE any other work."""
    with patch("ama_cryptography.crypto_api._enforce_invariant7", side_effect=_raise_sentinel):
        with pytest.raises(_InvariantSentinelError):
            call()


def test_entry_point_list_is_non_trivial() -> None:
    """Guard against the test silently collecting zero entries (which
    would pass the parametrized test vacuously)."""
    assert len(_ENFORCED_ENTRY_POINTS) >= 15, (
        f"Expected at least 15 enforced entry points, got "
        f"{len(_ENFORCED_ENTRY_POINTS)}. If a backend is missing this may "
        "still be acceptable — check the labels collected."
    )
