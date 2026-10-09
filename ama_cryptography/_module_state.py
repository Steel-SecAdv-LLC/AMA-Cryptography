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

import ctypes
import logging
import sys
import threading
from typing import Any, Callable, Dict, Optional, Protocol, Tuple, Union, cast, runtime_checkable

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

# Incremented by every ``_set_error``, so an ERROR can be told apart from the
# one before it even when the two carry the same reason string.  POST compares
# it across its run: a failure another thread reports while POST is running
# (a pairwise test or the continuous RNG test on a draw that began before POST
# did) changes it, and POST then refuses to declare the module OPERATIONAL
# over the top of that failure.
_ERROR_SEQUENCE = 0

# Makes each transition below atomic with respect to the others.  Without it,
# POST's final "SELF_TEST -> OPERATIONAL" was a blind write: an ERROR another
# thread entered between POST's last stage and that write was overwritten,
# and the module reported OPERATIONAL with no reason after a failed
# conditional self-test.  Reentrant so a transition may be taken from code
# that already holds it.
_STATE_LOCK = threading.RLock()

# Serialises POST runs and the reads that must see one run whole.  POST
# (``_self_test._run_self_tests``) holds it for the entire run, and
# ``module_attestation`` / ``last_failure`` take it so they never report a
# half-populated result table as a finished one.  It lives in this leaf, not
# in the orchestrator, because ``check_crypto_permitted`` below reads it.
_POST_LOCK = threading.RLock()


@runtime_checkable
class _OwnershipQueryableLock(Protocol):
    """A lock that can say whether the calling thread holds it."""

    def _is_owned(self) -> bool:
        """True when the calling thread holds the lock.

        A docstring rather than ``...``: a Protocol body is a type, never run,
        and the ellipsis is an expression statement with no effect, which is
        what CodeQL's "Statement has no effect" rule reports (the same answer
        ``_self_test._Absorbing`` gives it).
        """


def _lock_ownership_query(lock: object) -> Callable[[], bool]:
    """Return ``lock``'s "does the calling thread hold me?" method.

    The standard library's reentrant lock answers through ``_is_owned``, which
    ``threading.Condition`` binds from the lock it wraps in the same way.  A
    lock without it cannot support the check ``check_crypto_permitted`` makes,
    and the module refuses to load rather than run without that check.
    """
    if isinstance(lock, _OwnershipQueryableLock):
        return lock._is_owned
    raise ImportError(
        f"{type(lock).__name__} cannot report which thread holds it; the FIPS "
        f"self-test allowance cannot be confined to the thread running POST"
    )


#: True when the calling thread holds ``_POST_LOCK``.
_POST_LOCK_IS_OWNED = _lock_ownership_query(_POST_LOCK)


def module_status() -> str:
    """Return current module state: OPERATIONAL, ERROR, or SELF_TEST."""
    return _MODULE_STATE


def module_error_reason() -> Optional[str]:
    """Return the reason for ERROR state, or None if not in ERROR."""
    return _ERROR_REASON


def _state_snapshot() -> Tuple[str, Optional[str], int]:
    """Return ``(state, error_reason, error_sequence)`` read as one.

    ``module_status()`` and ``module_error_reason()`` are two reads; a
    ``_set_error`` from another thread can land between them and pair the new
    state with the old reason.  Callers that report both use this.
    """
    with _STATE_LOCK:
        return _MODULE_STATE, _ERROR_REASON, _ERROR_SEQUENCE


def _set_error(reason: str) -> int:
    """Enter ERROR with ``reason``; return the error sequence this call assigned."""
    global _MODULE_STATE, _ERROR_REASON, _ERROR_SEQUENCE
    with _STATE_LOCK:
        _MODULE_STATE = "ERROR"
        _ERROR_REASON = reason
        _ERROR_SEQUENCE += 1
        sequence = _ERROR_SEQUENCE
    logger.critical("FIPS 140-3 POST FAILURE: %s", reason)
    return sequence


def _set_operational() -> None:
    global _MODULE_STATE, _ERROR_REASON
    with _STATE_LOCK:
        _MODULE_STATE = "OPERATIONAL"
        _ERROR_REASON = None


def _begin_self_test() -> Tuple[str, Optional[str], int]:
    """Enter SELF_TEST and pin the guard's allowance to the calling thread.

    Called by ``_self_test._run_self_tests`` under ``_POST_LOCK`` at the start
    of every run; the transition lives here because the state lives here.

    Returns the ``(state, error_reason, error_sequence)`` this transition
    replaced, read in the same critical section, so an ERROR that arrived
    after the caller last looked is handed to it instead of being erased
    unseen.  POST records such an ERROR in ``last_failure()`` and passes the
    sequence to :func:`_finish_self_test`.
    """
    global _MODULE_STATE, _ERROR_REASON, _SELF_TEST_THREAD
    with _STATE_LOCK:
        previous = (_MODULE_STATE, _ERROR_REASON, _ERROR_SEQUENCE)
        _MODULE_STATE = "SELF_TEST"
        _ERROR_REASON = None
        _SELF_TEST_THREAD = threading.get_ident()
        return previous


def _finish_self_test(expected_sequence: int) -> bool:
    """Leave SELF_TEST for OPERATIONAL unless an ERROR arrived meanwhile.

    A compare-and-set: the module becomes OPERATIONAL only if it is still in
    SELF_TEST and no ``_set_error`` has run since ``expected_sequence`` was
    read.  Returns False, changing nothing, when either has happened; the
    ERROR another thread entered stands.
    """
    global _MODULE_STATE, _ERROR_REASON
    with _STATE_LOCK:
        if _MODULE_STATE != "SELF_TEST" or _ERROR_SEQUENCE != expected_sequence:
            return False
        _MODULE_STATE = "OPERATIONAL"
        _ERROR_REASON = None
        return True


def _clear_self_test_thread() -> None:
    """Drop the POST thread's self-test allowance.

    ``_run_self_tests`` calls this in a ``finally`` so the allowance cannot
    outlive the run by ANY exit path — leaving it set would keep
    ``check_crypto_permitted`` permissive on that thread for the rest of the
    process's life.
    """
    global _SELF_TEST_THREAD
    with _STATE_LOCK:
        _SELF_TEST_THREAD = None


def _exception_text(exc: BaseException) -> str:
    """``str(exc)`` for a failure reason, even when ``str(exc)`` itself raises.

    Every ERROR transition below is taken inside an ``except`` block that
    formats the exception it caught.  An exception whose ``__str__`` raises
    turned that formatting into a second exception, which escaped before
    ``_set_error`` ran: the test had failed, and the module stayed in the
    state it was in.
    """
    try:
        return str(exc)
    except Exception as text_exc:
        return f"<str() of {type(exc).__name__} raised {type(text_exc).__name__}>"


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
      Known Answer Tests must be able to call the primitives under test.  The
      thread must be the one POST pinned AND must hold ``_POST_LOCK``: the pin
      is dropped in a ``finally`` that a second interrupt can skip, whereas
      the lock is released by the ``with`` statement that holds it, so a
      pin that outlives its run no longer grants anything.
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
    # Otherwise the state, the pin and the lock are decided as one, under the
    # lock every transition takes, so another thread's ``_set_error`` lands
    # wholly before the decision (and this call is refused) or wholly after
    # it.  After it is the window every caller of a guard has, OPERATIONAL
    # callers included -- the check precedes the operation -- and what bounds
    # it is that the next call on this thread is refused
    # (``test_the_post_thread_is_refused_once_another_thread_enters_error``)
    # and that ``_finish_self_test`` refuses to leave SELF_TEST for
    # OPERATIONAL.  The fast path above takes no lock: one read of one global,
    # so the guard stays free on the hot path.  A state that became
    # OPERATIONAL after that read is permitted here, not refused as stale.
    with _STATE_LOCK:
        state = _MODULE_STATE
        if state == "OPERATIONAL" or (
            state == "SELF_TEST"
            and _SELF_TEST_THREAD == threading.get_ident()
            and _POST_LOCK_IS_OWNED()
        ):
            return
        reason = _ERROR_REASON
    if state == "ERROR":
        raise CryptoModuleError(
            f"Cryptographic operation refused: module is in the FIPS 140-3 "
            f"error state (root cause: {reason}).  All cryptographic "
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

# Serializes the continuous RNG test's compare-and-store.
#
# The test is a read-compare-write on shared state, and without a lock it is a
# check-then-act race: with a stuck DRBG returning V, two threads can both read
# the same stale ``previous`` (!= V), both compare their identical V against
# it, both pass, and both store V.  Two consecutive identical CSPRNG outputs —
# the one fault §4.9.2 requires this control to detect — would be issued as key
# material with the control silently satisfied, and it would happen precisely
# when the module is busiest.  The interleaving also loses updates in the
# benign case, so the values being compared are not reliably consecutive.
_rng_lock = threading.Lock()

# Mutable container for continuous RNG health state (FIPS 140-3 Section 4.9.2).
# Using a dict avoids the ``global`` keyword, which silences CodeQL's
# "unused global variable" false-positive while preserving identical semantics.
# ``_self_test._run_rng_stage`` seeds ``previous`` at POST time through this
# shared reference.
_rng_state: Dict[str, Optional[bytes]] = {"previous": None}


#: The SHA-256 kernel used for the continuous-RNG health digest.
#:
#: Injected by ``pqc_backends`` at ITS import time rather than imported from
#: here, because the dependency runs the wrong way for an import: this module
#: is the leaf that ``pqc_backends`` imports at module scope, so importing
#: ``pqc_backends`` back out of it — even function-locally — is a genuine
#: import cycle (CodeQL "Cyclic import").  The previous form deferred the
#: import to call time to keep the cycle from biting at import; that worked,
#: but it left a real cycle in the graph and an alert that could only be
#: argued down rather than closed.
#:
#: Injection removes the edge entirely.  ``hashlib`` is deliberately NOT a
#: fallback: on a libcrypto build its constructors are OpenSSL, and the health
#: sample IS potential key material (for ``n == 32`` it is byte-for-byte the
#: buffer handed to the caller), so falling back would hand every RNG draw's
#: health window to an unauthorized vendor — the INVARIANT-1 violation this
#: whole path exists to remove.  Absent a registered kernel we fail closed.
_health_digest: Optional[Callable[[bytes], bytes]] = None


def register_health_digest(digest: Callable[[bytes], bytes]) -> None:
    """Install the SHA-256 kernel the continuous RNG test hashes with.

    Called once by ``ama_cryptography.pqc_backends`` at its own import time,
    after ``native_sha256`` is defined.  Idempotent and last-write-wins; the
    only caller is that module.
    """
    global _health_digest
    _health_digest = digest


#: The native CSPRNG fill, injected by ``pqc_backends`` at its import time for
#: the same reason as the health digest above: this module is the leaf
#: ``pqc_backends`` imports, so it cannot import back.  It writes into the
#: buffer it is given and nowhere else.
_entropy_fill: Optional[Callable[[Any], None]] = None


def register_entropy_source(fill: Callable[[Any], None]) -> None:
    """Install the native CSPRNG fill every draw goes through.

    Called once by ``ama_cryptography.pqc_backends`` at its own import time
    with ``_native_random_fill``.  Idempotent and last-write-wins.
    """
    global _entropy_fill
    _entropy_fill = fill


def _resolve_native(
    name: str, registered: Optional[Callable[..., Any]], role: str
) -> Callable[..., Any]:
    """The registered kernel, or the same one re-resolved through sys.modules.

    Recovery, not a fallback to another vendor.  Injection alone made this
    state unrecoverable: a kernel is registered once, while ``pqc_backends``
    executes its module body, so anything that re-runs THIS module's body
    while ``pqc_backends`` stays cached (importlib.reload, IPython autoreload,
    a test popping the module, a second module identity on a vendored path)
    left it None for good -- and ``reset_module()`` cannot repair that, its
    POST re-import being a no-op against the cached module.  A ``sys.modules``
    lookup heals it without an import statement, so no edge is added to the
    import graph.

    Absent both, refuse.  The stdlib alternatives are OpenSSL on a libcrypto
    build (``hashlib``) or hand back immutable copies of key material
    (``secrets``), and this path exists to avoid both (INVARIANT-1,
    INVARIANT-6).  Deliberately NOT ``_set_error``: this module reserves the
    error state for a test that ran and failed, and a missing kernel means the
    continuous test never ran.  Latching a permanent, process-wide error for
    an initialisation-ordering fault would inhibit even verify-only paths that
    draw no randomness.
    """
    if registered is not None:
        return registered
    module = sys.modules.get("ama_cryptography.pqc_backends")
    resolved = getattr(module, name, None) if module is not None else None
    if resolved is None:
        raise CryptoModuleError(
            f"Continuous RNG test unavailable: no {role} is registered and "
            f"ama_cryptography.pqc_backends.{name} could not be resolved. "
            "No random bytes were issued."
        )
    return cast(Callable[..., Any], resolved)


def entropy_source() -> Callable[[Any], None]:
    """The native CSPRNG fill every draw goes through, POST's included.

    One seam: ``secure_random_fill`` and the POST RNG stage both resolve the
    source here, so the startup test examines exactly the source the library
    draws from, and a test that substitutes a source substitutes it for both.

    Raises:
        CryptoModuleError: no source is registered or resolvable.
    """
    return _resolve_native("_native_random_fill", _entropy_fill, "entropy source")


def _zero(view: memoryview) -> None:
    view[:] = bytes(view.nbytes)


def _scrub(*values: Any) -> None:
    """Zero every ``bytearray`` given; anything else is immutable and skipped.

    For the shared secrets a pairwise test computes only to compare them: the
    test is their sole holder, so they are zeroed rather than freed intact.
    """
    for value in values:
        if isinstance(value, bytearray):
            _zero(memoryview(value))


def secure_random_fill(buf: Union[bytearray, memoryview]) -> None:
    """Fill ``buf`` in place with health-tested output from the native CSPRNG.

    The one draw every secret in the library comes from.  The output is
    written by the C side straight into ``buf`` -- no ``bytes`` copy of it is
    ever made -- so a caller holding key material in a ``bytearray`` can wipe
    every copy that exists (INVARIANT-6).  ``secrets.token_bytes`` cannot
    offer that: its result is immutable.

    The FIPS 140-3 §4.9.2 continuous health test runs over every draw, on a
    32-byte window: the first 32 bytes of ``buf`` when it is at least that
    long, otherwise a separate 32-byte draw from which ``buf`` is filled.  The
    window is hashed in place by this module's own SHA-256 (never ``hashlib``,
    which is OpenSSL on a libcrypto build -- INVARIANT-1), and only the digest
    is retained, so module state never pins live key material.

    Gated on :func:`check_crypto_permitted` rather than
    :func:`check_operational` so POST itself can draw.

    Any failure -- the source, the digest, the health test -- zeroes ``buf``
    before the exception propagates, so a partial or rejected draw never
    reaches the caller.

    Raises:
        TypeError: ``buf`` is read-only or not a flat run of bytes.
        CryptoModuleError: the module is in the error state, the native
            CSPRNG or digest kernel is unavailable, the operating system's
            source failed, or the continuous health test failed.
    """
    view = memoryview(buf)
    if view.readonly or not view.c_contiguous:
        raise TypeError("secure_random_fill needs a writable, contiguous buffer")
    view = view.cast("B")
    n = view.nbytes
    scratch: Optional[bytearray] = None
    try:
        # Inside the guard: an error-state refusal, a missing entropy source
        # or a missing digest kernel would otherwise raise with the caller's
        # buffer still holding whatever it held before (PR #415 review).
        check_crypto_permitted()
        fill = entropy_source()
        digest_fn = _resolve_native("native_sha256", _health_digest, "health-digest kernel")
        if n >= _RNG_HEALTH_SIZE:
            # A bytearray goes to the source as itself, which borrows it
            # without the cast view; ``view`` stays for the zeroing below.
            whole = type(buf) is bytearray
            fill(buf if whole else view)
            window = buf if whole and n == _RNG_HEALTH_SIZE else view[:_RNG_HEALTH_SIZE]
        else:
            scratch = bytearray(_RNG_HEALTH_SIZE)
            fill(scratch)
            window = memoryview(scratch)
        health_digest = digest_fn(window)
        # Compare-and-store atomically: see the _rng_lock rationale above.
        with _rng_lock:
            if _rng_state["previous"] is not None and health_digest == _rng_state["previous"]:
                _set_error("Continuous RNG test failed: consecutive identical outputs")
                raise CryptoModuleError("Module in error state: Continuous RNG test failed")
            _rng_state["previous"] = health_digest
        if scratch is not None:
            view[:] = memoryview(scratch)[:n]
    except BaseException:
        _zero(view)
        raise
    finally:
        if scratch is not None:
            _zero(memoryview(scratch))


def secure_token_bytearray(n: int = 32) -> bytearray:
    """``n`` health-tested random bytes in a fresh, wipeable ``bytearray``.

    The form every secret draw uses: the caller owns the only copy and can
    scrub it.  See :func:`secure_random_fill`.

    Raises:
        ValueError: ``n`` is negative.
        CryptoModuleError: as :func:`secure_random_fill`.
    """
    if n < 0:
        raise ValueError("n must be non-negative")
    out = bytearray(n)
    secure_random_fill(out)
    return out


def secure_token_bytes(n: int = 32) -> bytes:
    """``n`` health-tested random bytes as ``bytes``, for non-secret uses.

    Nonces, salts and identifiers are public, and an immutable result is what
    their callers want.  A SECRET drawn here would leave an unwipeable copy:
    draw secrets with :func:`secure_token_bytearray` or
    :func:`secure_random_fill`.  The draw itself goes through the same native
    source and health test, and the working buffer is zeroed after the copy.

    Raises:
        ValueError: if ``n`` is negative.  ``buf[:n]`` with a negative ``n``
            would otherwise return a truncated buffer, and a caller that
            computed a length wrong would get fewer bytes than it asked for.
        CryptoModuleError: as :func:`secure_random_fill`.
    """
    work = secure_token_bytearray(n)
    try:
        return bytes(work)
    finally:
        _zero(memoryview(work))


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


#: The native constant-time comparison (``secure_memory.constant_time_compare``),
#: injected by the package ``__init__`` before POST, for the reason the entropy
#: source is: ``secure_memory`` imports this module, so importing it back --
#: even inside a function -- is an import cycle (CodeQL py/cyclic-import on
#: PR #415).  ``_secret_material`` compares through it too, for the same reason.
_secret_comparator: Optional[Callable[[Any, Any], bool]] = None


def register_secret_comparator(compare: Callable[[Any, Any], bool]) -> None:
    """Install the constant-time comparison every secret equality uses.

    Called once by the package ``__init__``, before POST, with
    ``secure_memory.constant_time_compare``.  Idempotent and last-write-wins.
    """
    global _secret_comparator
    _secret_comparator = compare


def secrets_match(a: Any, b: Any) -> bool:
    """Constant-time equality of two secret byte strings (INVARIANT-12).

    The registered comparison, or, if this module's body was re-run after it
    was registered (see :func:`_resolve_native`), the same one found through
    ``sys.modules`` -- a lookup, not an import.  Absent both it
    raises :class:`NativeBackendUnavailableError`, a could-not-run: nothing
    was compared, and no ``==`` stands in for it.
    """
    compare = _secret_comparator
    if compare is None:
        module = sys.modules.get("ama_cryptography.secure_memory")
        compare = getattr(module, "constant_time_compare", None) if module is not None else None
    if compare is None:
        raise NativeBackendUnavailableError(
            "No constant-time comparison is registered: "
            "ama_cryptography.secure_memory has not been imported.  Nothing was compared."
        )
    return bool(compare(a, b))


class _KeyReleasedOnlyIfConsistent:
    """Zero a freshly minted secret key when its pairwise test does not pass.

    Every keygen hands its new key to one of the helpers below before
    returning it.  If the test raises -- it ran and failed, or it could not
    run -- the keypair is not released, so nothing may go on holding the
    secret half: it is zeroed in place before the exception propagates
    (INVARIANT-6, every exit path; INVARIANT-41).  Until 2026-10-08 such a key
    was dropped intact at all twenty call sites; this is the one place they
    share.  A ``bytearray``, a writable ``memoryview`` or a ctypes buffer is
    zeroed, and so is each one in a list or tuple; ``bytes`` cannot be, and
    is left to its holder.
    """

    __slots__ = ("_key",)

    def __init__(self, key: Any) -> None:
        self._key = key

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if exc_type is None:
            return
        _zero_released_key(self._key)


def _zero_released_key(key: Any) -> None:
    """Zero ``key`` in place, or each element of a list or tuple of them (a
    FROST dealer's shares are a list: PR #415 review)."""
    if isinstance(key, bytearray):
        _zero(memoryview(key))
    elif isinstance(key, memoryview) and not key.readonly:
        _zero(key.cast("B"))
    elif isinstance(key, ctypes.Array):
        ctypes.memset(key, 0, ctypes.sizeof(key))
    elif isinstance(key, (list, tuple)):
        for item in key:
            _zero_released_key(item)


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
    with _KeyReleasedOnlyIfConsistent(secret_key):
        test_msg = b"FIPS 140-3 pairwise consistency test"
        try:
            sig = sign_fn(test_msg, secret_key)
            if isinstance(sig, (bytes, bytearray)):
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
            _set_error(f"Pairwise consistency test failed for {algo_name}: {_exception_text(exc)}")
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
    secret_key)`` must return the shared secret.  The two are compared in
    constant time (INVARIANT-12): both are secrets, and no exemption exists
    for a comparison whose operands this process derived itself.
    """
    with _KeyReleasedOnlyIfConsistent(secret_key):
        shared_secret: Any = None
        ss: Any = None
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
            # Constant-time: both are secrets, and INVARIANT-12 covers every
            # secret-dependent comparison (``!=`` exits at the first
            # differing byte; PR #415 review).
            if not secrets_match(ss, shared_secret):
                raise ValueError("Shared secrets do not match")
        except (CryptoModuleError, NativeBackendUnavailableError):
            # Could-not-run, not ran-and-failed — see the discipline note above.
            raise
        except Exception as exc:
            _set_error(f"Pairwise consistency test failed for {algo_name}: {_exception_text(exc)}")
            raise CryptoModuleError(
                f"Module in error state: Pairwise test failed for {algo_name}"
            ) from exc
        finally:
            # Both shared secrets exist only to be compared (the container's, in
            # the object form, dies with ``encap`` when this returns).
            _scrub(ss, shared_secret)


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
    public half directly.  The two shared secrets are compared in constant
    time, as in :func:`pairwise_test_kem`.
    """
    with _KeyReleasedOnlyIfConsistent(secret_key):
        ours: Any = None
        theirs: Any = None
        try:
            eph_public, eph_secret = ephemeral_keypair
            ours = agree_fn(secret_key, eph_public)
            theirs = agree_fn(eph_secret, public_key)
            if not secrets_match(ours, theirs):
                raise ValueError("DH roundtrip disagreed: the keypair halves do not correspond")
        except (CryptoModuleError, NativeBackendUnavailableError):
            # Could-not-run, not ran-and-failed — see the discipline note above.
            raise
        except Exception as exc:
            _set_error(f"Pairwise consistency test failed for {algo_name}: {_exception_text(exc)}")
            raise CryptoModuleError(
                f"Module in error state: Pairwise test failed for {algo_name}"
            ) from exc
        finally:
            _scrub(ours, theirs)
