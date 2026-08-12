#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
FIPS 140-3 module state machine — the error-state leaf (§4.9.2)
===============================================================

The single source of truth for the module's FIPS state (``SELF_TEST`` /
``OPERATIONAL`` / ``ERROR``), the two output-inhibition guards, and the
health-tested CSPRNG draw.

Why this is its own module
--------------------------
Every layer of the library must be able to ask "may cryptographic output
leave this module?" — ``pqc_backends`` and the Cython bindings on the native
surface, ``secure_memory`` on the RNG surface, ``session`` / ``ascon`` /
``key_formats`` / ``agent_binding`` / ``hybrid_combiner`` above them, and
``crypto_api`` at the top.  When these guards lived in ``_self_test`` (the
POST orchestrator), every one of those modules had to import the orchestrator,
while the orchestrator's Known Answer Tests import ``pqc_backends`` to test
the primitives — an import cycle that forced call-time imports
(``session.py``'s mid-file import block, ``secure_memory``'s import inside
``secure_random_bytes``) and was flagged by static analysis on every one of
its edges.

This module is a *leaf*: it imports the standard library and
``ama_cryptography.exceptions`` and nothing else, so anything may import it —
at the top of the file, in any order — and no cycle can form through it.
``_self_test`` keeps orchestrating POST (stages, KATs, results, attestation)
and re-exports these names for backward compatibility, but the state itself
lives here.

The raw state variables are deliberately NOT re-exported by ``_self_test``:
code that rebinds ``_MODULE_STATE`` directly must do so on this module, where
the guards actually read it.  A rebind on a re-exported copy would diverge
from the state the guards enforce and turn a test into a no-op — so the stale
spelling fails loudly (``AttributeError``) instead of passing silently.
"""

import logging
import secrets
import threading
from typing import Dict, Optional

from ama_cryptography.exceptions import CryptoModuleError

logger = logging.getLogger(__name__)

# ============================================================================
# ERROR STATE MACHINE (FIPS 140-3 Section 4.9.2)
# ============================================================================

_MODULE_STATE = "SELF_TEST"  # OPERATIONAL | ERROR | SELF_TEST
_ERROR_REASON: Optional[str] = None

# Identity of the thread currently executing POST, or None.
#
# The error-state guard below has to let POST's own Known Answer Tests call the
# very primitives it is guarding — a KAT that could not invoke ama_sha3_256
# would test nothing.  Widening the guard to "allow anything while the module
# is in SELF_TEST" would do that, but it would also open the whole native
# surface to every *other* thread for the duration of a ``reset_module()``
# call, which is exactly the window an operator triggers after a failure.  So
# the allowance is pinned to the one thread that is actually running the
# self-tests; every other thread continues to see the module as not-yet-usable.
_SELF_TEST_THREAD: Optional[int] = None


def module_status() -> str:
    """Return current module state: OPERATIONAL, ERROR, or SELF_TEST."""
    return _MODULE_STATE


def module_error_reason() -> Optional[str]:
    """Return the reason for ERROR state, or None if not in ERROR."""
    return _ERROR_REASON


def _set_error(reason: str) -> None:
    global _MODULE_STATE, _ERROR_REASON
    _MODULE_STATE = "ERROR"
    _ERROR_REASON = reason
    logger.critical("FIPS 140-3 POST FAILURE: %s", reason)


def _set_operational() -> None:
    global _MODULE_STATE, _ERROR_REASON
    _MODULE_STATE = "OPERATIONAL"
    _ERROR_REASON = None


def _begin_self_test() -> None:
    """Enter SELF_TEST and pin the guard's allowance to the calling thread.

    Called by ``_self_test._run_self_tests`` under its POST lock at the start
    of every run; the transition lives here because the state lives here.
    """
    global _MODULE_STATE, _ERROR_REASON, _SELF_TEST_THREAD
    _MODULE_STATE = "SELF_TEST"
    _ERROR_REASON = None
    _SELF_TEST_THREAD = threading.get_ident()


def _clear_self_test_thread() -> None:
    """Drop the POST thread's self-test allowance.

    ``_run_self_tests`` calls this in a ``finally`` so the allowance cannot
    outlive the run by ANY exit path — leaving it set would keep
    ``check_crypto_permitted`` permissive on that thread for the rest of the
    process's life.
    """
    global _SELF_TEST_THREAD
    _SELF_TEST_THREAD = None


def check_operational() -> None:
    """Raise CryptoModuleError if module is not OPERATIONAL.

    The error message explicitly labels downstream failures as POST-lockout
    symptoms so CI logs do not present a cascade of "Module in error state"
    failures as N independent bugs — they are all consequences of a single
    POST failure whose root cause is in ``_ERROR_REASON``.  Operators
    triaging a failed CI run should look at the FIRST ``CryptoModuleError``
    (which carries the POST root-cause string) and ignore subsequent ones.
    """
    if _MODULE_STATE != "OPERATIONAL":
        root_cause = _ERROR_REASON or _MODULE_STATE
        raise CryptoModuleError(
            f"Module locked out by FIPS POST failure (downstream symptom — "
            f"root cause: {root_cause})"
        )


def check_crypto_permitted() -> None:
    """Refuse cryptographic output while the module is in the FIPS ERROR state.

    FIPS 140-3 §4.9.2 requires a module whose self-tests failed to enter an
    error state in which *all* cryptographic output is inhibited.  Until this
    guard existed the requirement was met only by the high-level
    ``crypto_api`` surface: every one of the native entry points in
    ``pqc_backends`` — key generation, signing, KEM encapsulation, AEAD, HMAC,
    KDF — called straight through to the C library with no state check, so a
    module that had announced ``FIPS 140-3 POST FAILURE`` at import went on
    signing and generating keys for any caller who reached past
    ``crypto_api``.  The error state inhibited nothing that mattered.

    This is deliberately a *weaker* precondition than :func:`check_operational`:

    * ``OPERATIONAL``  — permitted; the ordinary case, and one interned-string
      comparison so the guard is free on the hot path.
    * ``SELF_TEST``    — permitted **only on the thread running POST**, whose
      Known Answer Tests must be able to call the primitives under test.
    * ``ERROR``        — refused, always.

    ``crypto_api`` keeps calling :func:`check_operational` (strict
    ``OPERATIONAL``): a public API entered while POST is still running is a
    caller bug, whereas the native layer is legitimately re-entered from
    inside POST.

    Raises:
        CryptoModuleError: when the module is in ERROR, or when a thread other
            than the POST thread reaches a native primitive mid-self-test.
    """
    if _MODULE_STATE == "OPERATIONAL":
        return
    if _MODULE_STATE == "SELF_TEST" and _SELF_TEST_THREAD == threading.get_ident():
        return
    if _MODULE_STATE == "ERROR":
        raise CryptoModuleError(
            f"Cryptographic operation refused: module is in the FIPS 140-3 "
            f"error state (root cause: {_ERROR_REASON}).  All cryptographic "
            f"output is inhibited until the fault is corrected and "
            f"reset_module() re-runs the power-on self-tests."
        )
    raise CryptoModuleError(
        "Cryptographic operation refused: power-on self-tests have not "
        "completed on this thread (module state: SELF_TEST)."
    )


# ============================================================================
# CONTINUOUS RNG TEST (FIPS 140-3 Section 4.9.2)
# ============================================================================

_RNG_HEALTH_SIZE = 32  # Fixed size for continuous health comparison

# Mutable container for continuous RNG health state (FIPS 140-3 Section 4.9.2).
# Using a dict avoids the ``global`` keyword, which silences CodeQL's
# "unused global variable" false-positive while preserving identical semantics.
# ``_self_test._run_rng_stage`` seeds ``previous`` at POST time through this
# shared reference.
_rng_state: Dict[str, Optional[bytes]] = {"previous": None}


def secure_token_bytes(n: int = 32) -> bytes:
    """
    Wrapper around secrets.token_bytes with continuous RNG health test.

    Draws a single buffer of max(n, 32) bytes, uses the first 32 bytes for
    the health comparison, and returns the first n bytes to the caller.
    This avoids a second RNG call and ensures the health check covers
    the same entropy that the caller receives.

    Gated on :func:`check_crypto_permitted` rather than
    :func:`check_operational`: the stricter form refuses while POST is running,
    which would prevent the self-tests themselves from drawing entropy and left
    this function unusable from exactly the paths that most need a
    health-tested draw.
    """
    check_crypto_permitted()
    draw_size = max(n, _RNG_HEALTH_SIZE)
    buf = secrets.token_bytes(draw_size)
    health_sample = buf[:_RNG_HEALTH_SIZE]
    if _rng_state["previous"] is not None and health_sample == _rng_state["previous"]:
        _set_error("Continuous RNG test failed: consecutive identical outputs")
        raise CryptoModuleError("Module in error state: Continuous RNG test failed")
    _rng_state["previous"] = health_sample
    return buf[:n]
