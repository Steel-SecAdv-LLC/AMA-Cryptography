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
from typing import Any, Callable, Dict, Optional

from ama_cryptography.exceptions import CryptoModuleError, NativeBackendUnavailableError

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

    Raises:
        ValueError: if ``n`` is negative.  Without this, ``buf[:n]`` with a
            negative ``n`` silently returns a truncated buffer (32 - \\|n\\|
            bytes) instead of failing — and a caller that computed a length
            wrong would get key material shorter than it asked for.
        CryptoModuleError: if the module is in the FIPS error state, or the
            continuous RNG health test fails.
    """
    if n < 0:
        raise ValueError("n must be non-negative")
    check_crypto_permitted()
    draw_size = max(n, _RNG_HEALTH_SIZE)
    buf = secrets.token_bytes(draw_size)
    health_sample = buf[:_RNG_HEALTH_SIZE]
    if _rng_state["previous"] is not None and health_sample == _rng_state["previous"]:
        _set_error("Continuous RNG test failed: consecutive identical outputs")
        raise CryptoModuleError("Module in error state: Continuous RNG test failed")
    _rng_state["previous"] = health_sample
    return buf[:n]


# ============================================================================
# PAIRWISE CONSISTENCY TESTS (FIPS 140-3 Section 4.9.2)
# ============================================================================
#
# These live in the leaf so ``pqc_backends`` — whose keygen entry points run
# them on every keypair — can import them without re-creating the
# pqc_backends → _self_test → pqc_backends cycle this module exists to break.
# They deliberately import no cryptography: the primitive under test arrives
# as a callable, and the helpers' only dependencies are the error-state
# machinery above.  ``_self_test`` re-exports them, so the historical
# ``from ama_cryptography._self_test import pairwise_test_signature`` spelling
# keeps working.
#
# Exception discipline (shared by all three helpers): the ERROR state is
# reserved for a test that RAN and FAILED.  Two exception classes reaching a
# helper mean the test could not run at all and must pass through unchanged:
#
# * ``CryptoModuleError`` — the callable re-entered ``check_crypto_permitted``
#   and was refused because another thread moved the module into SELF_TEST or
#   ERROR mid-flight.  Converting that refusal into ``_set_error`` would let a
#   concurrent ``reset_module()`` brick the module with a fabricated
#   "pairwise test failed" root cause, racing POST's own state transitions.
# * ``NativeBackendUnavailableError`` — a counterpart operation is not built.
#   An availability gap is a refusal to release the keypair, not evidence
#   against it.
#
# Everything else (a verify that returns False, a wrong shared secret, a
# nonzero return code, an unexpected crash inside the primitive) is the test
# running and failing, and enters ERROR.


def pairwise_test_signature(
    sign_fn: Callable[..., Any],
    verify_fn: Callable[..., Any],
    secret_key: Any,
    public_key: Any,
    algo_name: str,
) -> None:
    """Sign a test message and verify — raise on failure.

    The FIPS 140-3 pairwise consistency test for a signature keypair: a
    keypair whose halves do not correspond signs something the matching
    public key rejects, and this catches it at generation time instead of at
    first use.  A failure is a conditional self-test failure, so the module
    enters the ERROR state (§4.9.2), not merely the caller's exception
    handler.

    ``sign_fn(message, secret_key)`` must return the signature (raw ``bytes``
    or an object carrying it in ``.signature``);
    ``verify_fn(message, signature, public_key)`` must return truthy for a
    valid signature.
    """
    test_msg = b"FIPS 140-3 pairwise consistency test"
    try:
        sig = sign_fn(test_msg, secret_key)
        if isinstance(sig, bytes):
            valid = verify_fn(test_msg, sig, public_key)
        else:
            # Signature object with .signature attribute
            valid = verify_fn(test_msg, sig.signature, public_key)
        if not valid:
            raise ValueError("Verification returned False")
    except (CryptoModuleError, NativeBackendUnavailableError):
        # Could-not-run, not ran-and-failed — see the discipline note above.
        raise
    except Exception as exc:
        _set_error(f"Pairwise consistency test failed for {algo_name}: {exc}")
        raise CryptoModuleError(
            f"Module in error state: Pairwise test failed for {algo_name}"
        ) from exc


def pairwise_test_kem(
    encaps_fn: Callable[..., Any],
    decaps_fn: Callable[..., Any],
    public_key: Any,
    secret_key: Any,
    algo_name: str,
) -> None:
    """Encapsulate + decapsulate roundtrip test — raise on failure.

    The FIPS 140-3 pairwise consistency test for a KEM keypair.  A failure
    puts the module in the ERROR state, as for the signature form.

    ``encaps_fn(public_key)`` may return either an object carrying
    ``.ciphertext`` / ``.shared_secret`` (the high-level ``kyber_encapsulate``
    shape) or a plain ``(ciphertext, shared_secret)`` tuple (the
    ``native_ml_kem_encapsulate`` shape); ``decaps_fn(ciphertext,
    secret_key)`` must return the shared secret.  The equality check is an
    ordinary comparison: both values are secrets this process derived
    milliseconds ago from its own keypair, so there is no attacker-supplied
    operand for a timing difference to leak anything about.
    """
    try:
        encap = encaps_fn(public_key)
        # Dispatch on the named attributes FIRST: a result class converted to
        # a NamedTuple would satisfy isinstance(…, tuple) and silently switch
        # to positional unpacking, which breaks the moment its field order
        # changes.  The names are the contract; the bare tuple is the
        # fallback for the native functions that return one.
        if hasattr(encap, "ciphertext"):
            ciphertext, shared_secret = encap.ciphertext, encap.shared_secret
        else:
            ciphertext, shared_secret = encap
        ss = decaps_fn(ciphertext, secret_key)
        if ss != shared_secret:
            raise ValueError("Shared secrets do not match")
    except (CryptoModuleError, NativeBackendUnavailableError):
        # Could-not-run, not ran-and-failed — see the discipline note above.
        raise
    except Exception as exc:
        _set_error(f"Pairwise consistency test failed for {algo_name}: {exc}")
        raise CryptoModuleError(
            f"Module in error state: Pairwise test failed for {algo_name}"
        ) from exc


def pairwise_test_agreement(
    agree_fn: Callable[..., Any],
    ephemeral_keypair: Any,
    secret_key: Any,
    public_key: Any,
    algo_name: str,
) -> None:
    """Diffie-Hellman roundtrip test for a key-agreement keypair.

    The owner assurance of pair-wise consistency from NIST SP 800-56A rev. 3
    §5.6.2.1.4, in its strong form: agree with a fresh ephemeral peer from
    both sides and require ``agree_fn(secret_key, eph_public) ==
    agree_fn(eph_secret, public_key)``.  An earlier revision recomputed the
    public key from the private scalar and compared — but that re-runs the
    same scalar-multiplication kernel on the same input, so it caught
    transient faults between the two computations and nothing systematic.
    The roundtrip exercises the kernel on two DIFFERENT scalar/point pairs
    and demands the group law hold across them: a keypair whose halves do
    not correspond, or a kernel that is self-consistently wrong on one
    input, no longer satisfies it.  A failure puts the module in the ERROR
    state, as for the signature and KEM forms.

    ``agree_fn(own_secret, peer_public)`` must return the shared secret.
    ``ephemeral_keypair`` is ``(eph_public, eph_secret)``, generated by the
    CALLER without re-entering its own keygen path (which would recurse into
    this test): draw a scalar from ``secure_token_bytes`` and derive its
    public half directly.  The equality check is an ordinary comparison —
    both values are secrets this process derived from its own fresh keys, so
    there is no attacker-supplied operand for a timing difference to leak
    anything about.
    """
    try:
        eph_public, eph_secret = ephemeral_keypair
        ours = agree_fn(secret_key, eph_public)
        theirs = agree_fn(eph_secret, public_key)
        if ours != theirs:
            raise ValueError("DH roundtrip disagreed: the keypair halves do not correspond")
    except (CryptoModuleError, NativeBackendUnavailableError):
        # Could-not-run, not ran-and-failed — see the discipline note above.
        raise
    except Exception as exc:
        _set_error(f"Pairwise consistency test failed for {algo_name}: {exc}")
        raise CryptoModuleError(
            f"Module in error state: Pairwise test failed for {algo_name}"
        ) from exc
