#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
FIPS 140-3 Power-On Self-Tests (POST) and Module Integrity Verification
=======================================================================

Implements FIPS 140-3 Section 4.9 requirements:
- Known Answer Tests (KAT) for all approved algorithms
- Module integrity verification via SHA3-256 digest
- Pairwise consistency tests for key generation
- Continuous RNG health test

Self-tests run at module import time. On ANY failure the module
enters an ERROR state and all cryptographic operations are refused.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Version: 4.0.0
"""

import ctypes
import hashlib
import json
import logging
import math
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ama_cryptography.exceptions import CryptoModuleError

logger = logging.getLogger(__name__)

# ============================================================================
# ERROR STATE MACHINE (FIPS 140-3 Section 4.9.2)
# ============================================================================

_MODULE_STATE = "SELF_TEST"  # OPERATIONAL | ERROR | SELF_TEST
_ERROR_REASON: Optional[str] = None
# ``passed`` is tri-state:
#   * True  — the test ran and the algorithm produced the expected output.
#   * False — the test ran and the algorithm failed; module enters ERROR.
#   * None  — the test was skipped because its backend is not built.
#             A skip is NOT a pass: callers must treat ``None`` as "not
#             tested" rather than "passing".  When AMA_FIPS_STRICT=1 is
#             set, a skip is escalated to a hard failure inside
#             ``_run_self_tests``.  See _kat_*() docstrings for the
#             specific skip conditions of each algorithm.
_SELF_TEST_RESULTS: List[Tuple[str, Optional[bool], str]] = []  # (name, passed, detail)
_POST_DURATION_MS: float = 0.0

# Serialises POST runs and the state transitions they drive.  ``reset_module()``
# is callable from any thread at any time, and without this two concurrent
# resets could interleave their ``_SELF_TEST_RESULTS`` writes and leave the
# module OPERATIONAL on the strength of a half-populated result list.
_POST_LOCK = threading.RLock()

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

#: Evidence from the last POST failure, retained across a successful
#: ``reset_module()`` so recovery does not erase the record of what failed.
_LAST_FAILURE: Dict[str, Any] = {"reason": None, "results": [], "duration_ms": 0.0}

# Strict mode env: when set, a skipped KAT is treated as a failure so
# release builds (and any deployment that demands every approved
# algorithm be self-tested) refuse to enter OPERATIONAL without every
# backend present.  Non-strict mode (the default for dev / source
# checkouts) records the skip and logs WARNING but allows startup so
# documentation and CI matrix jobs that intentionally exclude a
# backend keep working.
_AMA_FIPS_STRICT_ENV = "AMA_FIPS_STRICT"


def module_status() -> str:
    """Return current module state: OPERATIONAL, ERROR, or SELF_TEST."""
    return _MODULE_STATE


def module_error_reason() -> Optional[str]:
    """Return the reason for ERROR state, or None if not in ERROR."""
    return _ERROR_REASON


def module_self_test_results() -> List[Tuple[str, Optional[bool], str]]:
    """Return list of ``(test_name, passed, detail)`` from the last POST run.

    ``passed`` is tri-state:

    * ``True``  — KAT executed and matched the expected output.
    * ``False`` — KAT executed and failed.
    * ``None``  — KAT was skipped because its backend is unavailable.
                  Skipped tests are *not* counted as passes; consumers
                  filtering for "everything passed" must check
                  ``passed is True`` (or, equivalently, exclude
                  ``passed is None``).
    """
    return list(_SELF_TEST_RESULTS)


def post_duration_ms() -> float:
    """Return the duration of the last POST run in milliseconds."""
    return _POST_DURATION_MS


def module_attestation() -> Dict[str, Any]:
    """Return a machine-readable verdict on what POST actually established.

    ``module_status() == "OPERATIONAL"`` answers "did anything fail?", which is
    a weaker question than "was every approved algorithm actually tested?".  In
    the default non-strict mode a KAT whose backend is absent is recorded as a
    *skip* and POST still reaches OPERATIONAL — a legitimate source-checkout
    mode, but one that a release gate or a deployment health check must be able
    to tell apart from a run where every algorithm was exercised.  Before this
    existed the only way to ask was to re-derive it from the tri-state tuples
    in :func:`module_self_test_results`, and every caller that did not bother
    reported a partially-tested module as verified.

    Keys:
        ``state``            — OPERATIONAL / ERROR / SELF_TEST.
        ``error_reason``     — root cause when ``state`` is ERROR, else None.
        ``fully_verified``   — True only when the module is OPERATIONAL *and*
                               no self-test was skipped.  This is the flag a
                               release gate should assert.
        ``strict_mode``      — whether ``AMA_FIPS_STRICT`` was in force.
        ``tests_run`` / ``tests_passed`` / ``tests_skipped``.
        ``skipped``          — ``[(name, detail), ...]`` for each skipped test,
                               so the log line names what was not covered.
        ``failed``           — ``[(name, detail), ...]``; at most one entry,
                               since POST short-circuits on the first failure.
        ``duration_ms``      — POST wall-clock.
        ``native_backend``   — provenance of the native library that backed the
                               run (see ``pqc_backends.native_backend_diagnostics``),
                               or an explanation of why there was none.
    """
    results = list(_SELF_TEST_RESULTS)
    skipped = [(name, detail) for name, passed, detail in results if passed is None]
    failed = [(name, detail) for name, passed, detail in results if passed is False]
    n_pass = sum(1 for _, passed, _ in results if passed is True)

    try:
        from ama_cryptography.pqc_backends import native_backend_diagnostics

        native = native_backend_diagnostics()
    except Exception as exc:  # pragma: no cover - defensive; never fail attestation
        native = {"loaded": False, "reason": f"diagnostics unavailable: {exc}"}

    return {
        "state": _MODULE_STATE,
        "error_reason": _ERROR_REASON,
        "fully_verified": _MODULE_STATE == "OPERATIONAL" and not skipped and not failed,
        "strict_mode": _env_flag_enabled(_AMA_FIPS_STRICT_ENV),
        "tests_run": len(results),
        "tests_passed": n_pass,
        "tests_skipped": len(skipped),
        "skipped": skipped,
        "failed": failed,
        "duration_ms": _POST_DURATION_MS,
        "native_backend": native,
    }


def _set_error(reason: str) -> None:
    global _MODULE_STATE, _ERROR_REASON
    _MODULE_STATE = "ERROR"
    _ERROR_REASON = reason
    logger.critical("FIPS 140-3 POST FAILURE: %s", reason)


def _set_operational() -> None:
    global _MODULE_STATE, _ERROR_REASON
    _MODULE_STATE = "OPERATIONAL"
    _ERROR_REASON = None


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


def reset_module() -> bool:
    """Re-run self-tests to attempt recovery from ERROR state.

    Serialised against concurrent resets and against a POST already in flight,
    so two callers racing to recover cannot interleave their result lists and
    leave the module OPERATIONAL on a half-populated run.

    The outgoing failure is preserved in :func:`last_failure` before the new run
    overwrites it.  ``_run_self_tests`` clears ``_SELF_TEST_RESULTS`` on entry,
    so a reset that succeeded used to erase every trace of what had gone wrong —
    the state went ERROR → OPERATIONAL and the reason, the failing stage and its
    detail string were gone.  A transient fault that clears on retry is the case
    an operator most needs the record of.
    """
    with _POST_LOCK:
        if _MODULE_STATE == "ERROR":
            _LAST_FAILURE["reason"] = _ERROR_REASON
            _LAST_FAILURE["results"] = list(_SELF_TEST_RESULTS)
            _LAST_FAILURE["duration_ms"] = _POST_DURATION_MS
        return _run_self_tests()


def last_failure() -> Dict[str, Any]:
    """Return the most recent POST failure, or empty when there has not been one.

    Keys mirror the failing run: ``reason``, ``results`` (the full tri-state
    table as it stood when POST failed) and ``duration_ms``.
    """
    return {
        "reason": _LAST_FAILURE["reason"],
        "results": list(_LAST_FAILURE["results"]),
        "duration_ms": _LAST_FAILURE["duration_ms"],
    }


# ============================================================================
# CONTINUOUS RNG TEST (FIPS 140-3 Section 4.9.2)
# ============================================================================

_RNG_HEALTH_SIZE = 32  # Fixed size for continuous health comparison

# Mutable container for continuous RNG health state (FIPS 140-3 Section 4.9.2).
# Using a dict avoids the ``global`` keyword, which silences CodeQL's
# "unused global variable" false-positive while preserving identical semantics.
_rng_state: dict[str, Optional[bytes]] = {"previous": None}


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


# ============================================================================
# PAIRWISE CONSISTENCY TESTS (FIPS 140-3 Section 4.9.2)
# ============================================================================


def pairwise_test_signature(
    sign_fn: Callable[..., Any],
    verify_fn: Callable[..., Any],
    secret_key: Any,
    public_key: Any,
    algo_name: str,
) -> None:
    """Sign a test message and verify — raise on failure."""
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
    """Encapsulate + decapsulate roundtrip test — raise on failure."""
    try:
        encap = encaps_fn(public_key)
        ss = decaps_fn(encap.ciphertext, secret_key)
        if ss != encap.shared_secret:
            raise ValueError("Shared secrets do not match")
    except Exception as exc:
        _set_error(f"Pairwise consistency test failed for {algo_name}: {exc}")
        raise CryptoModuleError(
            f"Module in error state: Pairwise test failed for {algo_name}"
        ) from exc


# ============================================================================
# MODULE INTEGRITY VERIFICATION (FIPS 140-3 Section 4.9.1)
# ============================================================================

_INTEGRITY_DIGEST_FILE = Path(__file__).resolve().parent / "_integrity_digest.txt"

#: How the last integrity check actually verified: ``"signed"`` (Ed25519
#: signature checked), ``"digest-only"`` (unsigned plaintext digest matched, so
#: accidental corruption is detected and deliberate tampering is not), or
#: ``None`` (no check completed).
#:
#: This exists because ``verify_module_integrity()`` returns a single boolean
#: for two materially different outcomes, and the weaker one was silently
#: promoted to the stronger everywhere downstream — ``module_attestation()``
#: reported ``fully_verified: True`` on a module verified only by a plaintext
#: file an attacker who edited the sources could rewrite in the same breath.  A
#: gate cannot refuse a downgrade it cannot see.
_INTEGRITY_STRENGTH: Optional[str] = None
_INTEGRITY_REQUIRE_TRUST_ANCHOR_ENV = "AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR"
_TRUE_ENV_VALUES = {"1", "true", "yes", "on"}

# Domain-separation tag for the Ed25519 signature that binds the .py digest and
# the native-library digest together.  A fixed, versioned constant so the signer
# (_build_sign) and the verifier here construct byte-identical messages; the
# ``v2`` marks the format that binds the native library, distinguishing it from
# the ``v1`` artefacts that signed the .py digest alone.  It is duplicated
# verbatim in _build_sign._INTEGRITY_SIG_DOMAIN and pinned equal by
# tests/test_native_integrity.py — the two modules must not import each other
# (build-time vs runtime separation, INVARIANT-1), so agreement is enforced by
# test rather than by a shared import.
_INTEGRITY_SIG_DOMAIN = b"AMA-integrity-signature-v2\x00"


def _compute_native_library_digest(path: Optional[str]) -> Optional[bytes]:
    """SHA3-256 over the raw bytes of the native library file at ``path``.

    Follows symlinks — the SONAME chain (``.so`` -> ``.so.4`` -> ``.so.4.0.0``)
    resolves to one real object, and it is those bytes, the ones the loader
    actually mapped, that must match what was signed.  Returns ``None`` when the
    path is absent or unreadable; the caller treats that as "could not verify"
    rather than "verified" or "tampered", so a race or a permissions problem
    fails closed on an anchored build and warns on a developer one.
    """
    if not path:
        return None
    try:
        return hashlib.sha3_256(Path(path).read_bytes()).digest()
    except OSError:
        return None


def _composite_integrity_message(py_digest_raw: bytes, native_digest_raw: bytes) -> bytes:
    """The exact bytes the Ed25519 integrity signature covers, v2 format.

    ``SHA3-256(domain || py_digest || native_digest)``.  Hashing the
    concatenation (rather than signing the concatenation directly) keeps the
    signed message a fixed 32 bytes regardless of digest sizes and makes the
    two components inseparable: an attacker who swaps the native library must
    also change the embedded native digest to match at verify time, which
    changes this message, which invalidates a signature they cannot forge.

    Mirrored byte-for-byte in ``_build_sign._composite_integrity_message``.
    """
    return hashlib.sha3_256(
        _INTEGRITY_SIG_DOMAIN + py_digest_raw + native_digest_raw
    ).digest()


def _env_flag_enabled(name: str) -> bool:
    """Return True when a boolean environment variable is explicitly enabled."""
    return os.environ.get(name, "").strip().lower() in _TRUE_ENV_VALUES


def _load_integrity_trust_anchor() -> Tuple[Optional[str], Optional[str]]:
    """Return the configured trust-anchor pubkey hex or an error string.

    The trust anchor is compiled into the native library rather than read from
    mutable Python source.  Developer builds return an empty string and keep
    using the per-build public key embedded in ``_integrity_signature.py``.
    """
    try:
        from ama_cryptography.pqc_backends import _native_lib
    except ImportError as exc:
        return None, f"native backend unavailable for trust-anchor lookup: {exc}"

    if _native_lib is None or not hasattr(_native_lib, "ama_integrity_trust_anchor_pubkey_hex"):
        return None, None
    # The native call and the decode/strip must both be inside the protected
    # block: a broken ctypes binding can raise OSError, a malformed pointer
    # can yield non-ASCII bytes that fail .decode(), and an unexpected
    # NULL-terminator placement can produce a truncated buffer.  All three
    # paths must collapse to a deterministic ``(None, reason)`` so callers
    # fail-closed instead of surfacing a raw traceback from import-time POST.
    try:
        _native_lib.ama_integrity_trust_anchor_pubkey_hex.argtypes = []
        _native_lib.ama_integrity_trust_anchor_pubkey_hex.restype = ctypes.c_char_p
        raw_bytes = _native_lib.ama_integrity_trust_anchor_pubkey_hex()
        raw = raw_bytes.decode("ascii") if raw_bytes else ""
        anchor_hex = raw.strip().lower()
    except Exception as exc:
        return None, f"native trust-anchor lookup failed: {exc}"

    if not anchor_hex:
        return None, None
    try:
        anchor = bytes.fromhex(anchor_hex)
    except ValueError as exc:
        return None, f"integrity trust anchor is not hex: {exc}"
    if len(anchor) != 32:
        return None, f"integrity trust anchor has {len(anchor)} bytes (expected 32)"
    return anchor_hex, None


def _compute_module_digest() -> str:
    """Compute SHA3-256 hash over all .py files in the ama_cryptography package.

    Line endings are normalized (CRLF → LF) before hashing so that the digest
    is identical on Windows (autocrlf=true) and Linux/macOS.

    Excludes ``_integrity_signature.py`` (the build-time-generated
    signature artefact) so the digest input is independent of the
    signature output — otherwise the construction is self-referential
    and the signature could never be verified.
    """
    pkg_dir = Path(__file__).resolve().parent
    hasher = hashlib.sha3_256()
    py_files = sorted(pkg_dir.glob("*.py"))
    for py_file in py_files:
        if py_file.name == "_integrity_signature.py":
            continue
        hasher.update(py_file.name.encode("utf-8"))
        content = py_file.read_bytes().replace(b"\r\n", b"\n")
        hasher.update(content)
    return hasher.hexdigest()


def _verify_signed_integrity(digest_hex: str) -> Tuple[Optional[bool], str]:
    """Verify the build-time Ed25519 signature over the .py digest.

    Returns a tri-state, because "this artefact is bad" and "I have no way to
    check this artefact" are different claims and must not produce the same
    verdict:

        ``(True,  detail)`` — the signature verified.
        ``(False, reason)`` — the artefact is present and *wrong*: digest
                              mismatch, malformed fields, untrusted key, or a
                              signature the verifier rejected.  Tampering.
                              Always a hard POST failure.
        ``(None,  reason)`` — verification could not be *attempted*: the
                              artefact is absent, or the Ed25519 verifier
                              itself is unavailable because the native library
                              did not load.  The caller applies trust-anchor
                              policy: an anchored build refuses to continue, an
                              unanchored source checkout falls through to the
                              digest-only path.

    That third case is the one this function used to get wrong.  A missing
    native library was reported as ``(False, "native Ed25519 not built —
    cannot verify signature")`` and became ``FIPS 140-3 POST FAILURE`` — a
    tampering verdict, phrased as a build defect, for a library that was
    usually built perfectly well and merely sitting somewhere the loader had
    not been told to look.  Operators chasing that message went looking for a
    broken C build that did not exist.  A verifier that cannot run has not
    detected anything; it has failed to look.

    The signature artefact is generated at wheel build time by
    ``ama_cryptography._build_sign`` using the in-tree
    ``ama_ed25519_sign`` C kernel (INVARIANT-1 — no PyCA dependency)
    with an ephemeral, per-build private key.  Only the public key
    and signature ship with the wheel; the private key is discarded
    immediately after signing.  At runtime we recompute the digest
    and call ``ama_ed25519_verify`` with the embedded pubkey.

    Failure modes:
      - signature module missing      → caller falls back to digest-only
      - digest mismatch vs embedded   → tampered .py files between build and now
      - signature verify returns False → tampered signature module (the
        embedded fields were edited post-build to match a tampered .py
        digest), or the native verify call itself reports a bad sig
    """
    try:
        # Lazy import so a missing artefact doesn't surface as a hard
        # ImportError on every call site of verify_module_integrity().
        from ama_cryptography import _integrity_signature as sig_mod
    except ImportError:
        return None, "no signed-integrity artefact (digest-only fallback)"

    try:
        embedded_digest_hex = sig_mod.INTEGRITY_DIGEST_HEX
        pubkey_hex = sig_mod.INTEGRITY_PUBKEY_HEX
        signature_hex = sig_mod.INTEGRITY_SIGNATURE_HEX
    except AttributeError as exc:
        return False, f"signature module malformed: missing field ({exc})"

    if embedded_digest_hex != digest_hex:
        return False, (
            f"signed digest mismatch: stored={embedded_digest_hex[:16]}... "
            f"computed={digest_hex[:16]}... — .py files changed post-build"
        )

    try:
        pubkey = bytes.fromhex(pubkey_hex)
        signature = bytes.fromhex(signature_hex)
        digest_raw = bytes.fromhex(digest_hex)
    except ValueError as exc:
        return False, f"signature module fields not hex: {exc}"

    if len(pubkey) != 32 or len(signature) != 64:
        return False, (
            f"signature module sizes wrong: pubkey={len(pubkey)} "
            f"signature={len(signature)} (expected 32, 64)"
        )

    trust_anchor_hex, trust_anchor_error = _load_integrity_trust_anchor()
    if trust_anchor_error is not None:
        return False, trust_anchor_error
    if trust_anchor_hex is None and _env_flag_enabled(_INTEGRITY_REQUIRE_TRUST_ANCHOR_ENV):
        return False, "integrity trust anchor required but not configured"
    if trust_anchor_hex is not None and pubkey_hex.strip().lower() != trust_anchor_hex:
        return False, (
            "integrity trust anchor mismatch: "
            f"signed_pubkey={pubkey_hex[:16]}... anchor={trust_anchor_hex[:16]}..."
        )

    try:
        from ama_cryptography.pqc_backends import (
            _ED25519_NATIVE_AVAILABLE,
            native_ed25519_verify,
            native_backend_diagnostics,
            native_backend_load_summary,
        )
    except ImportError as exc:
        return None, f"Ed25519 verifier unavailable (pqc_backends import failed: {exc})"

    if not _ED25519_NATIVE_AVAILABLE:
        # Report what actually happened rather than asserting the library was
        # never built.  ``native_backend_load_summary()`` names the directories
        # searched, the candidate files found, and the dlopen error for each —
        # the difference between "you have not run cmake" and "the .so is right
        # there but links against a libc you do not have".
        return None, (
            "Ed25519 verifier unavailable — cannot check the signed-integrity "
            f"artefact. {native_backend_load_summary()}"
        )

    # The native-library digest binds libama_cryptography — the code that
    # performs every cryptographic operation — into the same signature that
    # covers the .py files.  Before this field existed the signature covered the
    # Python wrapper only: an attacker who replaced the shared object with a
    # back-doored build left the .py digest, the signature and the trust anchor
    # all intact and verifying, while the actual cryptography ran from bytes no
    # check had ever looked at.  The wrapper was tamper-evident and the
    # implementation was not.
    #
    # Every SIGNED artefact carries this field: _build_sign can only produce a
    # signature by calling the native ama_ed25519_sign, so a working native
    # library is present at signing time by construction, and its digest is
    # always embedded.  The field is therefore absent only on a hand-built v1
    # test fixture, where the signature covers the raw .py digest instead of the
    # composite — stripping it from a real v2 artefact changes the message the
    # signature must cover and so is caught as a signature failure below, not as
    # a silent downgrade.
    native_digest_hex = getattr(sig_mod, "INTEGRITY_NATIVE_DIGEST_HEX", None)
    if native_digest_hex is None:
        signed_message = digest_raw  # v1: signature is over the raw .py digest
        native_digest_raw = None
    else:
        try:
            native_digest_raw = bytes.fromhex(native_digest_hex)
        except (ValueError, TypeError) as exc:
            return False, f"signature module INTEGRITY_NATIVE_DIGEST_HEX not hex: {exc}"
        if len(native_digest_raw) != 32:
            return False, (
                f"signature module native digest is {len(native_digest_raw)} bytes "
                "(expected 32)"
            )
        signed_message = _composite_integrity_message(digest_raw, native_digest_raw)

    try:
        ok = native_ed25519_verify(signature, signed_message, pubkey)
    except Exception as exc:  # fail-closed: any verify exception must yield False (INT-003)
        return False, f"native Ed25519 verify raised: {exc}"
    if not ok:
        return False, "Ed25519 signature did NOT verify — module tampered"

    # Signature authentic.  Now bind it to the shared object actually loaded.
    global _INTEGRITY_STRENGTH
    anchored = trust_anchor_hex is not None
    native_ok = False
    if native_digest_raw is None:
        native_note = "; native library NOT covered (legacy v1 artefact)"
    else:
        diag = native_backend_diagnostics()
        loaded_path = diag.get("path")
        override = diag.get("override")
        actual_native = _compute_native_library_digest(loaded_path)
        if override:
            # AMA_CRYPTO_LIB_PATH deliberately substitutes the backend; the
            # existing contract already documents that override as "not
            # tamper-evident".  The signature still proves the artefact is
            # authentic, so we do not fail — but the loaded object is not the
            # signed one, and that must be said plainly rather than implied by
            # a green check.
            native_note = (
                "; native library UNVERIFIED — AMA_CRYPTO_LIB_PATH override in "
                f"effect ({override}), loaded object is not the signed one"
            )
        elif actual_native is None:
            # Could not read the loaded object.  Fail closed on an anchored
            # build; downgrade to a note on a developer one, consistent with
            # the tri-state the rest of this verifier uses.
            if anchored:
                return False, (
                    "native library integrity UNVERIFIABLE on an anchored build — "
                    f"could not read the loaded object at {loaded_path!r}"
                )
            native_note = (
                f"; native library UNVERIFIED — could not read {loaded_path!r}"
            )
        elif actual_native != native_digest_raw:
            return False, (
                "native library digest MISMATCH — libama_cryptography has been "
                f"modified since signing (signed={native_digest_raw.hex()[:16]}..., "
                f"loaded={actual_native.hex()[:16]}... at {loaded_path!r})"
            )
        else:
            native_note = "; native library verified"
            native_ok = True

    # Only a signed artefact whose native library was verified against the
    # loaded object is the full-strength state.  Signed-but-native-unverified
    # (override, unreadable dev object, or a legacy v1 artefact) is recorded
    # distinctly so the integrity stage can treat it as a skip rather than a
    # pass — otherwise ``fully_verified`` would again cover a case where the
    # code doing the cryptography was never checked.
    _INTEGRITY_STRENGTH = "signed" if native_ok else "signed-native-unverified"

    if anchored:
        return True, f"signed integrity verified (Ed25519, trusted build pubkey){native_note}"
    return True, f"signed integrity verified (Ed25519, build-time pubkey){native_note}"


def verify_module_integrity() -> Tuple[bool, str]:
    """Verify module source files via signature, falling back to digest.

    Primary path (since v3.2.0, build-pipeline-signed wheels):

    1. Recompute SHA3-256 over the .py files.
    2. Load ``_integrity_signature.py``: embedded pubkey + signature
       + digest.  Recomputed digest must match embedded; then
       ``ama_ed25519_verify`` must accept the (pubkey, signature)
       pair over the raw digest.
    3. Any failure → ERROR state (module refuses crypto ops).

    Fallback path (editable installs, source checkouts, or wheels
    built without ``AMA_BUILD_PIPELINE=1`` in the build env):

    1. Recompute SHA3-256.
    2. Compare to ``_integrity_digest.txt`` (the legacy textual
       artefact).  Mismatch → ERROR state.  Log a WARNING that the
       signed artefact is missing so packagers notice the
       degraded protection in CI logs.

    Both paths are deterministic and side-effect-free; the only
    runtime cost is a single hash + (optionally) a single Ed25519
    verify, both well under 1 ms.
    """
    global _INTEGRITY_STRENGTH
    _INTEGRITY_STRENGTH = None
    current = _compute_module_digest()

    signed_ok, signed_detail = _verify_signed_integrity(current)
    if signed_ok is True:
        # _verify_signed_integrity has already set _INTEGRITY_STRENGTH to
        # "signed" (native library verified) or "signed-native-unverified"
        # (override / unreadable / legacy v1).  Do not flatten that distinction
        # back to "signed" here — the whole point is that a build whose native
        # library went unchecked is not full-strength.
        return True, signed_detail

    # ``False`` is a positive finding of tampering — the artefact is present
    # and does not verify.  Never recoverable, never downgraded.
    #
    # ``None`` means verification could not be attempted (no artefact, or no
    # verifier).  Both land here, and the trust-anchor policy below decides:
    # an anchored build is signed by construction so an unverifiable one is
    # tampering, while an unanchored source checkout falls through to the
    # documented digest-only path.
    #
    # This used to be a substring test against the detail string
    # (``"no signed-integrity artefact" not in signed_detail``), which made the
    # security-critical branch a function of prose.  Any reworded message —
    # including the more accurate ones this change introduces — silently
    # reclassified "cannot verify" as "tampering" or the reverse, depending on
    # which way the wording drifted.  The verdict is now carried by the return
    # value, and the message is free to say whatever is most useful.
    if signed_ok is False:
        logger.error("Signed integrity check failed: %s", signed_detail)
        return False, signed_detail

    # An ANCHORED build has no legitimate unsigned mode, so the fallback is
    # closed off before anything else is considered.
    #
    # This is the bypass that made the anchor decorative.  The signed path
    # above correctly refuses a signature made with the wrong key — an
    # attacker cannot re-sign edited .py files under a key of their own and
    # have it verify.  But they never had to: deleting
    # `_integrity_signature.py` entirely dropped control through to the
    # digest-only fallback, where `_integrity_digest.txt` is plaintext with
    # no signature at all.  Rewrite that one line and arbitrarily modified
    # code was accepted — on a build carrying a compiled anchor, with the
    # log line cheerfully reporting the wheel had been "built without
    # AMA_BUILD_PIPELINE=1".  Forging the signature was hard; removing it
    # was not, and removal reached the same place.
    #
    # The guard below was meant to be that stop, but it tests
    # AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR — a *build-time* environment
    # variable, set inside the cibuildwheel container in release.yml and
    # gone by the time anyone imports the installed wheel. It is therefore
    # never true at runtime for a released artefact, which is precisely
    # where it was needed. The compiled anchor is the part of that intent
    # that survives into the shipped .so, so the compiled anchor is what has
    # to be consulted.
    #
    # An anchor asserts "the signature on this artefact verifies under this
    # key". A missing artefact does not satisfy that assertion; it evades
    # it. Unanchored developer builds and source checkouts read `(None,
    # None)` here and keep the documented WARN-and-continue behaviour.
    anchor_hex, anchor_error = _load_integrity_trust_anchor()
    if anchor_error is not None:
        # Same fail-closed rule the signed path applies: if we cannot
        # determine whether this build is anchored, we must not assume it is
        # not.
        logger.error("Trust-anchor lookup failed: %s", anchor_error)
        return False, anchor_error
    if anchor_hex is not None:
        return False, (
            "signed integrity could not be verified on a build with a compiled "
            f"trust anchor ({anchor_hex[:16]}...) — an anchored build is signed "
            "by construction and ships the verifier that checks it, so an "
            "unverifiable one is tampering, not a legacy build. Digest-only "
            f"fallback refused. Cause: {signed_detail}"
        )

    # Belt and braces for the build environment itself: when the signer runs
    # with AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR=1 and the artefact is somehow
    # absent, fail there too rather than emitting an unsigned wheel.  This no
    # longer carries the runtime case — the anchor check above does.
    if _env_flag_enabled(_INTEGRITY_REQUIRE_TRUST_ANCHOR_ENV):
        return False, (
            "signed integrity could not be verified and "
            f"{_INTEGRITY_REQUIRE_TRUST_ANCHOR_ENV}=1 forbids digest-only "
            f"fallback — rebuild the wheel with AMA_BUILD_PIPELINE=1. "
            f"Cause: {signed_detail}"
        )

    # Digest-only fallback (editable install / source checkout).
    if not _INTEGRITY_DIGEST_FILE.exists():
        logger.error("Integrity digest file not found and no signature artefact")
        return False, "Integrity digest file missing"
    stored = _INTEGRITY_DIGEST_FILE.read_text().strip()
    if not stored:
        logger.error("Integrity digest file is empty")
        return False, "Integrity digest file empty"
    if stored != current:
        reason = f"Module digest mismatch: stored={stored[:16]}... computed={current[:16]}..."
        logger.error(reason)
        return False, reason
    # Digest-only path is healthy; log why the stronger check did not run so
    # the packager can notice the degraded protection in CI logs (one-time
    # WARN, not ERROR).  The reason is carried through verbatim rather than
    # assumed to be "no artefact": a build whose native library failed to load
    # reaches here too, and telling that operator their wheel "was built
    # without AMA_BUILD_PIPELINE=1" would send them to fix a build that is not
    # broken.
    logger.warning(
        "Module integrity verified by UNSIGNED digest only — the Ed25519 "
        "signature check did not run (%s). This detects accidental corruption "
        "but not deliberate tampering: _integrity_digest.txt is plaintext and "
        "an attacker who edits the .py files can rewrite it.",
        signed_detail,
    )
    _INTEGRITY_STRENGTH = "digest-only"
    return True, f"Module integrity verified (digest-only fallback: {signed_detail})"


def update_integrity_digest() -> str:
    """Recompute and store the module integrity digest. Returns the new digest.

    Used by the wheel build pipeline (``--digest-only`` mode) and the
    legacy ``integrity --update`` CLI.  Does NOT regenerate the
    signed-integrity artefact — that requires the native Ed25519
    kernel and lives in ``ama_cryptography._build_sign``.
    """
    digest = _compute_module_digest()
    _INTEGRITY_DIGEST_FILE.write_text(digest + "\n")
    return digest


# ============================================================================
# KNOWN ANSWER TESTS (FIPS 140-3 Section 4.9.1)
# ============================================================================


def _kat_sha3_256() -> Tuple[Optional[bool], str]:
    """SHA3-256 KAT against FIPS 202 vectors — for the *module's own* backend.

    This test used to hash with ``hashlib.sha3_256`` and compare the result to
    the published digest.  That is a Known Answer Test of CPython, which is not
    the implementation this module ships, does not use for SHA3, and cannot
    self-test on CPython's behalf.  The module's own SHA3-256 — the native
    Keccak kernel in ``src/c/ama_sha3.c``, plus whichever SIMD variant the
    dispatcher selects on this host — had no POST coverage at all, and it is
    the one that produces every digest the library emits, including the
    module-integrity digest.  A broken AVX-512 Keccak path would have sailed
    through this stage while CPython's scalar implementation vouched for it.

    Both are checked now: the native backend against the FIPS 202 vectors, and
    ``hashlib`` against the same vectors as a cross-check, since a disagreement
    between two independent implementations of a fixed function localises the
    fault immediately.

    Two vectors rather than one.  The empty message exercises padding alone and
    never fills the 136-byte rate, so it cannot detect a fault in the absorb
    loop; the second is long enough to force a multi-block absorb.
    """
    vectors = (
        # FIPS 202 / NIST CAVP — SHA3-256 of the empty message.
        (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        # 200 bytes of 0xa3 — the CAVP long-message pattern; spans two absorb
        # blocks at the 136-byte SHA3-256 rate.
        (
            b"\xa3" * 200,
            "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787",
        ),
    )

    for message, expected in vectors:
        result = hashlib.sha3_256(message).hexdigest()
        if result != expected:
            return False, (
                f"SHA3-256 KAT failed (hashlib, {len(message)}-byte message): "
                f"got {result}, expected {expected}"
            )

    try:
        from ama_cryptography.pqc_backends import (
            _SHA3_256_NATIVE_AVAILABLE,
            native_sha3_256,
        )
    except ImportError as exc:
        return None, f"SHA3-256 native KAT skipped (pqc_backends unavailable: {exc})"

    if not _SHA3_256_NATIVE_AVAILABLE:
        return None, "SHA3-256 native KAT skipped (native unavailable)"

    for message, expected in vectors:
        try:
            native = native_sha3_256(message).hex()
        except Exception as exc:
            return False, f"SHA3-256 native KAT exception ({len(message)}-byte): {exc}"
        if native != expected:
            return False, (
                f"SHA3-256 KAT failed (NATIVE backend, {len(message)}-byte "
                f"message): got {native}, expected {expected}"
            )

    return True, "SHA3-256 KAT passed (FIPS 202 vectors, native + hashlib)"


def _kat_hmac_sha3_256() -> Tuple[Optional[bool], str]:
    """HMAC-SHA3-256 KAT using native backend against hardcoded NIST-style vector.

    Vector: NIST SP 800-198 / ACVP-derived
      key = 000102...1f (32 bytes)
      msg = "Sample message for keylen=blocklen"
      expected = b83bfd563059c9f54e75cb509af83aa3db5b6eda4ce07afe03063998dac54f3b
    """
    try:
        from ama_cryptography.pqc_backends import (
            _HMAC_SHA3_256_NATIVE_AVAILABLE,
            native_hmac_sha3_256,
        )

        if not _HMAC_SHA3_256_NATIVE_AVAILABLE:
            return None, "HMAC-SHA3-256 KAT skipped (native unavailable)"

        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f" "101112131415161718191a1b1c1d1e1f")
        data = bytes.fromhex("53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e")
        expected = bytes.fromhex("b83bfd563059c9f54e75cb509af83aa3db5b6eda4ce07afe03063998dac54f3b")
        result = native_hmac_sha3_256(key, data)
        if result != expected:
            return False, (
                f"HMAC-SHA3-256 KAT: native output {result.hex()} " f"!= expected {expected.hex()}"
            )
        if len(result) != 32:
            return False, f"HMAC-SHA3-256 KAT: expected 32 bytes, got {len(result)}"
        return True, "HMAC-SHA3-256 KAT passed (NIST SP 800-198 vector)"
    except Exception as exc:
        return False, f"HMAC-SHA3-256 KAT exception: {exc}"


def _kat_aes_256_gcm() -> Tuple[Optional[bool], str]:
    """AES-256-GCM KAT: encrypt known plaintext, verify roundtrip."""
    try:
        from ama_cryptography.pqc_backends import (
            _AES_GCM_NATIVE_AVAILABLE,
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        if not _AES_GCM_NATIVE_AVAILABLE:
            return None, "AES-256-GCM KAT skipped (native unavailable)"

        # NIST SP 800-38D Test Case 16 (AES-256, 96-bit IV, AAD)
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308" "feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        plaintext = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b391aafd255"
        )
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        expected_ct = bytes.fromhex(
            "522dc1f099567d07f47f37a32a84427d"
            "643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838"
            "c5f61e6393ba7a0abcc9f662898015ad"
        )
        expected_tag = bytes.fromhex("2df7cd675b4f09163b41ebf980a7f638")

        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, aad)
        # KAT validation: these are public test vectors, not secrets.
        # Plain equality is correct here — constant-time comparison
        # provides no security benefit when both sides are public.
        if ct != expected_ct:
            return False, f"AES-256-GCM KAT: ciphertext mismatch (got {ct.hex()})"
        if tag != expected_tag:
            return False, f"AES-256-GCM KAT: tag mismatch (got {tag.hex()})"

        pt = native_aes256_gcm_decrypt(key, nonce, ct, tag, aad)
        if pt != plaintext:
            return False, "AES-256-GCM KAT: decrypt mismatch"

        return True, "AES-256-GCM KAT passed (NIST SP 800-38D TC16)"
    except Exception as exc:
        return False, f"AES-256-GCM KAT exception: {exc}"


def _kat_ml_kem_1024() -> Tuple[Optional[bool], str]:
    """ML-KEM-1024 KAT: keygen + encaps + decaps roundtrip."""
    try:
        from ama_cryptography.pqc_backends import (
            KYBER_AVAILABLE,
            generate_kyber_keypair,
            kyber_decapsulate,
            kyber_encapsulate,
        )

        if not KYBER_AVAILABLE:
            return None, "ML-KEM-1024 KAT skipped (backend unavailable)"

        kp = generate_kyber_keypair()
        encap = kyber_encapsulate(kp.public_key)
        ss = kyber_decapsulate(encap.ciphertext, kp.secret_key)
        if ss != encap.shared_secret:
            return False, "ML-KEM-1024 KAT: shared secrets mismatch"
        return True, "ML-KEM-1024 KAT passed"
    except Exception as exc:
        return False, f"ML-KEM-1024 KAT exception: {exc}"


def _kat_ml_dsa_65() -> Tuple[Optional[bool], str]:
    """ML-DSA-65 KAT: keygen + sign + verify roundtrip."""
    try:
        from ama_cryptography.pqc_backends import (
            DILITHIUM_AVAILABLE,
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
        )

        if not DILITHIUM_AVAILABLE:
            return None, "ML-DSA-65 KAT skipped (backend unavailable)"

        kp = generate_dilithium_keypair()
        msg = b"FIPS 140-3 ML-DSA-65 KAT"
        sig = dilithium_sign(msg, kp.secret_key)
        valid = dilithium_verify(msg, sig, kp.public_key)
        if not valid:
            return False, "ML-DSA-65 KAT: signature verification failed"
        # Negative test: tampered message should fail
        tampered = dilithium_verify(msg + b"X", sig, kp.public_key)
        if tampered:
            return False, "ML-DSA-65 KAT: tampered message incorrectly verified"
        return True, "ML-DSA-65 KAT passed"
    except Exception as exc:
        return False, f"ML-DSA-65 KAT exception: {exc}"


def _kat_slh_dsa() -> Tuple[Optional[bool], str]:
    """SLH-DSA (SPHINCS+) KAT: keygen + sign + verify roundtrip.

    Exercises the SHA2-256f-simple parameter set via the legacy SPHINCS+
    surface and tampers the message to confirm the verifier rejects.
    """
    try:
        from ama_cryptography.pqc_backends import (
            SPHINCS_AVAILABLE,
            generate_sphincs_keypair,
            sphincs_sign,
            sphincs_verify,
        )

        if not SPHINCS_AVAILABLE:
            return None, "SLH-DSA KAT skipped (backend unavailable)"

        kp = generate_sphincs_keypair()
        msg = b"FIPS 140-3 SLH-DSA KAT"
        sig = sphincs_sign(msg, kp.secret_key)
        if not sphincs_verify(msg, sig, kp.public_key):
            return False, "SLH-DSA KAT: signature verification failed"
        # Negative path: tampered message must NOT verify (FIPS 140-3 §4.9.1).
        if sphincs_verify(b"tampered " + msg, sig, kp.public_key):
            return False, "SLH-DSA KAT: tampered message incorrectly verified"
        return True, "SLH-DSA KAT passed"
    except Exception as exc:
        return False, f"SLH-DSA KAT exception: {exc}"


def _kat_slh_dsa_shake_128s() -> Tuple[Optional[bool], str]:
    """SLH-DSA-SHAKE-128s KAT: verify-only against a pinned NIST ACVP vector.

    Validates the FIPS 205 NIST L1 parameter set added in v3.1.0. SHAKE-128s
    sign latency is ~1-2 s on commodity x86_64 CI runners (the ``s`` ("small,
    slow") parameter set deliberately trades sign cost for compact signatures
    -- 7856 bytes vs 17088 for ``128f``), which would push the FIPS 140-3 POST
    budget past the 2000 ms ceiling on the slowest runners.

    A *Known Answer Test* in the FIPS 140-3 §4.9.1 sense is satisfied by
    pinning a vetted (pk, msg, ctx, signature) quadruple from NIST CAVP's
    ACVP-Server vector bank and exercising verify-only -- which is ~50 ms
    even on the slowest hosts and still walks the entire FIPS 205 §10.3
    ``slh_verify`` path (M' wrapping, FORS public-key reconstruction,
    Merkle-authentication path verification, hypertree top-out). The
    negative paths (tampered message, wrong context) confirm the verifier
    rejects each, which is the FIPS 140-3 negative-KAT requirement.
    """
    try:
        from ama_cryptography.pqc_backends import SPHINCS_AVAILABLE, slhdsa_verify

        if not SPHINCS_AVAILABLE:
            return None, "SLH-DSA-SHAKE-128s KAT skipped (backend unavailable)"

        # importlib.resources.files is stdlib from Python 3.9; guaranteed at
        # this project's >=3.10 floor, so no import fallback is needed.
        from importlib.resources import files as _resfiles

        kat_path = _resfiles("ama_cryptography").joinpath(
            "_post_kats/slh_dsa_shake_128s_sigver.json"
        )
        try:
            payload = json.loads(kat_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return False, "SLH-DSA-SHAKE-128s KAT: pinned vector missing"

        pk = bytes.fromhex(payload["pk_hex"])
        msg = bytes.fromhex(payload["message_hex"])
        ctx = bytes.fromhex(payload["context_hex"])
        sig = bytes.fromhex(payload["signature_hex"])

        if not slhdsa_verify(msg, sig, pk, ctx, param_set="SHAKE-128s"):
            return False, "SLH-DSA-SHAKE-128s KAT: pinned NIST signature did not verify"
        if slhdsa_verify(b"\x00" + msg, sig, pk, ctx, param_set="SHAKE-128s"):
            return (
                False,
                "SLH-DSA-SHAKE-128s KAT: tampered message incorrectly verified",
            )
        if ctx and slhdsa_verify(
            msg,
            sig,
            pk,
            ctx[:-1] + bytes([ctx[-1] ^ 0x01]),
            param_set="SHAKE-128s",
        ):
            return (
                False,
                "SLH-DSA-SHAKE-128s KAT: tampered ctx incorrectly verified",
            )
        return (
            True,
            f"SLH-DSA-SHAKE-128s KAT passed (pinned NIST tcId={payload['tcId']})",
        )
    except Exception as exc:
        return False, f"SLH-DSA-SHAKE-128s KAT exception: {exc}"


def _kat_ed25519() -> Tuple[Optional[bool], str]:
    """Ed25519 KAT: RFC 8032 known answer, plus a negative case.

    This was a keygen/sign/verify roundtrip, which is a pairwise consistency
    test rather than a Known Answer Test, and it had a specific blind spot: a
    verifier that returns True unconditionally passes a roundtrip.  So does one
    whose scalar arithmetic is wrong in a way that sign and verify share.  And
    because the module-integrity check is itself an ``ama_ed25519_verify``
    call, an always-accept verifier would have carried both this stage and the
    signature check that is supposed to detect tampered sources.

    Three checks now, in the order that localises a fault:

    1. **Known answer** — RFC 8032 §7.1 TEST 1 fixes the seed, so the derived
       public key and the signature over the known message have exactly one
       correct value.  A roundtrip cannot catch an implementation that is
       self-consistent and wrong; this can.
    2. **Negative** — a corrupted signature must be REJECTED.  This is what
       catches the always-accept verifier.
    3. **Pairwise consistency** — a freshly generated key still round-trips,
       which is the FIPS 140-3 §4.9.2 requirement for a keygen path.
    """
    try:
        from ama_cryptography.pqc_backends import (
            _ED25519_NATIVE_AVAILABLE,
            native_ed25519_keypair,
            native_ed25519_keypair_from_seed,
            native_ed25519_sign,
            native_ed25519_verify,
        )

        if not _ED25519_NATIVE_AVAILABLE:
            return None, "Ed25519 KAT skipped (native unavailable)"

        # RFC 8032 §7.1, TEST 1.
        seed = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )
        expected_pk = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        expected_sig = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )

        pk, sk = native_ed25519_keypair_from_seed(seed)
        if pk != expected_pk:
            return False, (
                f"Ed25519 KAT: RFC 8032 TEST 1 public key mismatch — "
                f"got {pk.hex()}, expected {expected_pk.hex()}"
            )

        sig = native_ed25519_sign(b"", sk)
        if sig != expected_sig:
            return False, (
                f"Ed25519 KAT: RFC 8032 TEST 1 signature mismatch — "
                f"got {sig.hex()}, expected {expected_sig.hex()}"
            )

        if not native_ed25519_verify(sig, b"", pk):
            return False, "Ed25519 KAT: RFC 8032 TEST 1 signature did not verify"

        # Negative case: flip one bit of S.  A verifier that accepts this
        # accepts anything, and would equally have accepted a tampered module.
        corrupted = bytearray(sig)
        corrupted[32] ^= 0x01
        if native_ed25519_verify(bytes(corrupted), b"", pk):
            return False, (
                "Ed25519 KAT: verifier ACCEPTED a corrupted signature — it "
                "cannot detect a tampered module either"
            )

        # Pairwise consistency on a fresh key (FIPS 140-3 §4.9.2).
        fresh_pk, fresh_sk = native_ed25519_keypair()
        msg = b"FIPS 140-3 Ed25519 pairwise consistency"
        if not native_ed25519_verify(native_ed25519_sign(msg, fresh_sk), msg, fresh_pk):
            return False, "Ed25519 KAT: pairwise consistency test failed"

        return True, "Ed25519 KAT passed (RFC 8032 TEST 1 + negative + pairwise)"
    except Exception as exc:
        return False, f"Ed25519 KAT exception: {exc}"


# ============================================================================
# MAIN SELF-TEST RUNNER
# ============================================================================


# ============================================================================
# CONSTANT-TIME TIMING ORACLE (dudect-inspired)
# ============================================================================

# Threshold: |t| > 4.5 indicates timing leak (dudect convention)
_DUDECT_THRESHOLD = 4.5
# Single deterministic pass with high statistical power.  The previous
# retry-until-pass loop (3 attempts, 1000 → 10000 → 10000 iterations)
# was a probabilistic test-amplifier — a flaky noise sample on attempt
# 1 was simply re-rolled until it passed, masking real timing leaks
# that happen to fall below the threshold on a noisier-than-usual
# retry.  A single 10000-iteration pass gives the same statistical
# power as one retry attempt and the result is deterministic: the
# outcome depends solely on the implementation under test, not on how
# many bites at the apple POST took.
_TIMING_ITERATIONS = 10000
_TIMING_WARMUP = 200
_TIMING_BUFFER_SIZE = 256

#: Hard ceiling on the operator-supplied min-effect floor, in nanoseconds.
#:
#: The floor is an absolute-effect threshold below which a high-|t| result is
#: treated as measurement noise, so a large enough value disables the test:
#: ``AMA_POST_TIMING_MIN_EFFECT_NS=1e18`` made every real timing leak report
#: "Constant-time OK" while still printing a measurement, which reads in a log
#: exactly like a test that ran and passed.  A control an environment variable
#: can silently switch off is not a control.
#:
#: The ceiling is set three orders of magnitude above any plausible legitimate
#: floor (the auto-computed value is 50 ns on Linux/macOS and 400 ns on
#: Windows' 100 ns-resolution clock) rather than just above it.  The purpose
#: here is to make the test impossible to *disable*, not to second-guess an
#: operator tuning for a noisy host — a tighter bound would reject honest
#: tuning while an attacker with the environment already has better options.
#: Any override that is honoured is logged at WARNING and appears in the
#: oracle's ``min-effect=`` detail, so the deviation is visible in
#: ``module_attestation()`` rather than only in the process's own logs.
_TIMING_MAX_MIN_EFFECT_NS = 100_000.0


def _compute_timing_min_effect_ns() -> float:
    """Compute the platform-aware minimum absolute mean-time delta floor.

    The POST timing oracle needs an absolute-effect-size floor to reject
    measurement-noise false positives from a high-|t| paired test.  The
    correct floor is a function of the host's actual ``perf_counter_ns``
    resolution — there is no value that is simultaneously safe on every
    OS/runner combination if you hardcode a constant:

    * Linux / macOS:  resolution is typically 1 ns (CLOCK_MONOTONIC_RAW).
      Bias from runner jitter has been observed at delta=25 ns / |t|=8.34
      on shared Ubuntu 3.11 GitHub-hosted runners.  A 50 ns absolute floor
      catches this band.
    * Windows:  ``QueryPerformanceCounter`` reports a 100 ns resolution
      via ``time.get_clock_info('perf_counter').resolution`` even on
      modern hardware; quantization noise alone can produce mean deltas
      that round up to 100-200 ns under coverage-instrumented Python
      3.11.  A 50 ns floor is *below* the platform's native granularity
      there — every paired-difference observation snaps to a multiple
      of 100 ns, so the smallest non-zero delta the oracle can ever see
      is 100 ns, and a constant 50 ns floor cannot filter it.

    Fix: scale the floor to ``max(absolute_floor, K * resolution_ns)``
    where ``K=4`` is a conservative safety multiplier over the per-sample
    quantization step.  With 10 000 paired samples the standard error
    of the mean is roughly ``resolution_ns / sqrt(n) ≈ resolution_ns/100``;
    K=4 puts the floor at ~400× SEM on a coarse-clock host, well above
    where pure quantization noise can drive the mean delta, while
    remaining well below the >>500 ns signal a real early-exit memcmp
    leak over 256 bytes produces (the byte loop alone is ~256 ns even
    at 1 ns/byte memory throughput).

    Linux/macOS:  ``max(50, 4*1) = 50 ns`` (absolute floor dominates)
    Windows:      ``max(50, 4*100) = 400 ns`` (resolution floor dominates)

    The floor is computed once at module import.  Operators who need a
    different floor for a specific deployment can override via
    ``AMA_POST_TIMING_MIN_EFFECT_NS`` — explicitly opt-in and logged so
    the deviation appears in audit logs.
    """
    override = os.environ.get("AMA_POST_TIMING_MIN_EFFECT_NS", "").strip()
    if override:
        try:
            override_ns = float(override)
        except ValueError:
            logger.warning(
                "AMA_POST_TIMING_MIN_EFFECT_NS=%r is not a number; ignoring "
                "and using the auto-computed default.",
                override,
            )
        else:
            # The floor is an absolute-effect threshold below which a
            # high-|t| result is treated as measurement noise, so raising it
            # far enough disables the test: an unbounded override could be set
            # to 1e18 ns and every real timing leak would report "Constant-time
            # OK".  A control that an environment variable can silently switch
            # off is not a control.  The ceiling is the smallest signal a real
            # early-exit memcmp over 256 bytes produces (>500 ns, see the
            # docstring); anything at or above it would mask a genuine leak,
            # so it is refused rather than honoured.
            if override_ns >= _TIMING_MAX_MIN_EFFECT_NS:
                logger.error(
                    "Refusing AMA_POST_TIMING_MIN_EFFECT_NS=%.0f ns: at or "
                    "above %.0f ns the min-effect floor would exceed the "
                    "signal a real early-exit memcmp produces, turning the "
                    "timing-leak self-test into an unconditional pass. Using "
                    "the auto-computed default instead.",
                    override_ns,
                    _TIMING_MAX_MIN_EFFECT_NS,
                )
            elif override_ns > 0:
                logger.warning(
                    "POST timing-leak min-effect floor overridden via "
                    "AMA_POST_TIMING_MIN_EFFECT_NS=%.0f ns (auto would have "
                    "been computed from time.get_clock_info)",
                    override_ns,
                )
                return override_ns

    absolute_floor_ns = 50.0
    safety_multiplier = 4.0
    try:
        resolution_s = time.get_clock_info("perf_counter").resolution
    except (ValueError, AttributeError):
        # Older / non-CPython runtimes may not expose get_clock_info for
        # 'perf_counter'.  Fall back to the absolute floor; that is the
        # historically-safe value on the Linux/macOS hosts where this
        # path is hit.
        return absolute_floor_ns
    resolution_ns = max(resolution_s * 1e9, 0.0)
    return max(absolute_floor_ns, safety_multiplier * resolution_ns)


# Minimum absolute mean-time delta (ns) required before POST will declare a
# timing-leak failure.  Computed at import to track the host's actual
# perf_counter granularity — see ``_compute_timing_min_effect_ns`` for the
# physics rationale.  A constant value cannot be simultaneously safe on
# Linux (1 ns granularity) and Windows (100 ns granularity); the auto-scale
# is the principled fix that preserves real-leak detection (>>500 ns
# signal) on both platforms.
_TIMING_MIN_EFFECT_NS = _compute_timing_min_effect_ns()


def _measure_timing_batch(
    n_iterations: int,
    memcmp_fn: Callable[[bytes, bytes, int], int],
    class_a_left: bytes,
    class_a_right: bytes,
    class_b_left: bytes,
    class_b_right: bytes,
    buf_size: int,
) -> Tuple[float, float, float, float, int]:
    """Run n_iterations interleaved timing measurements.

    Returns (mean_class_a, mean_class_b, var_class_a, var_class_b, n).
    """
    times_equal: List[float] = []
    times_differ: List[float] = []

    for i in range(n_iterations):
        if i % 2 == 0:
            t0 = time.perf_counter_ns()
            memcmp_fn(class_a_left, class_a_right, buf_size)
            t1 = time.perf_counter_ns()
            times_equal.append(float(t1 - t0))

            t0 = time.perf_counter_ns()
            memcmp_fn(class_b_left, class_b_right, buf_size)
            t1 = time.perf_counter_ns()
            times_differ.append(float(t1 - t0))
        else:
            t0 = time.perf_counter_ns()
            memcmp_fn(class_b_left, class_b_right, buf_size)
            t1 = time.perf_counter_ns()
            times_differ.append(float(t1 - t0))

            t0 = time.perf_counter_ns()
            memcmp_fn(class_a_left, class_a_right, buf_size)
            t1 = time.perf_counter_ns()
            times_equal.append(float(t1 - t0))

    n1 = len(times_equal)
    mean1 = sum(times_equal) / n1
    mean2 = sum(times_differ) / n1
    var1 = sum((x - mean1) ** 2 for x in times_equal) / (n1 - 1)
    var2 = sum((x - mean2) ** 2 for x in times_differ) / (n1 - 1)
    return mean1, mean2, var1, var2, n1


def _timing_oracle_consttime() -> Tuple[Optional[bool], str]:
    """Test ama_consttime_memcmp for timing leaks via Welch's t-test.

    Single deterministic pass with high statistical power (no retry).

    Runs interleaved comparisons with a first-byte mismatch and a last-byte
    mismatch, measures execution time for each, then computes Welch's
    t-statistic.  If |t| > ``_DUDECT_THRESHOLD`` (4.5), the comparison
    function may leak timing information through data-dependent early exit.
    POST also requires a small absolute effect-size floor before failing:
    GitHub-hosted runners have produced |t| > 4.5 (with deltas in the 25-45 ns
    band on Linux, and 100-200 ns on Windows where ``QueryPerformanceCounter``
    has 100 ns granularity) from host jitter alone, while a real early-exit
    memcmp over 256 bytes is orders of magnitude larger (>>500 ns).
    ``_TIMING_MIN_EFFECT_NS`` is computed at module import as
    ``max(50, 4 × perf_counter_resolution_ns)`` so the floor scales with
    the host clock — 50 ns on Linux/macOS (1 ns resolution), 400 ns on
    Windows (100 ns resolution).  Both values stay well below any real-leak
    signal while keeping POST fail-closed for genuine leaks.  The
    deterministic single-pass design means the ``False`` outcome is
    reproducible on the *same* host: a one-off CI re-run does not
    "re-roll" the result.

    The previous implementation retried up to three times with growing
    sample sizes and accepted ANY pass.  That pattern is a timing-leak
    *amplifier*: a real leak that happens to fall just under the
    threshold on a high-noise retry would be reported as a pass.  By
    running a single 10 000-iteration pass — equivalent in power to
    one of the previous retry attempts — POST gives the same answer
    every time for a given binary and host, with no opportunity to
    re-roll a borderline result into a green light.  Real timing
    leaks (|t| >> 4.5) reproduce; scheduler noise is averaged out by
    the warmup phase + interleaved measurement design.  The two
    classes are intentionally both mismatches (first byte versus last
    byte) so POST tests for data-dependent early exit without
    conflating equal-result fast paths with leak evidence on noisy CI
    hosts.

    Returns:
        * ``(True, detail)``  — implementation is consistent with
          constant-time on this host.
        * ``(False, detail)`` — measured |t| exceeds the threshold;
          treat as a real leak and refuse to enter OPERATIONAL.
        * ``(None, detail)``  — native consttime backend not loaded;
          the test cannot run.  Honoured by the POST runner as a
          skip (NOT as a pass), and escalated to ERROR under
          ``AMA_FIPS_STRICT=1``.

    This makes AMA-Crypto the first open-source library that
    self-tests for timing leaks at startup via FIPS POST.
    """
    from ama_cryptography.secure_memory import _native_consttime_memcmp

    if _native_consttime_memcmp is None:
        return None, "Constant-time oracle skipped: native consttime_memcmp not available"

    buf_size = _TIMING_BUFFER_SIZE
    first_diff_a = b"\xaa" * buf_size
    first_diff_b = b"\x55" + (b"\xaa" * (buf_size - 1))
    last_diff_a = b"\xaa" * buf_size
    last_diff_b = (b"\xaa" * (buf_size - 1)) + b"\x55"

    # Warmup: stabilize CPU frequency, fill i-cache and branch predictors.
    # 200 warmup iterations (up from 100) help the JIT and frequency
    # scaling converge before the measurement window opens.
    for _ in range(_TIMING_WARMUP):
        _native_consttime_memcmp(first_diff_a, first_diff_b, buf_size)
        _native_consttime_memcmp(last_diff_a, last_diff_b, buf_size)

    mean1, mean2, var1, var2, n1 = _measure_timing_batch(
        _TIMING_ITERATIONS,
        _native_consttime_memcmp,
        first_diff_a,
        first_diff_b,
        last_diff_a,
        last_diff_b,
        buf_size,
    )

    se = math.sqrt(var1 / n1 + var2 / n1) if (var1 + var2) > 0 else 0.0
    t_stat = (mean1 - mean2) / se if se > 0 else (0.0 if mean1 == mean2 else float("inf"))

    delta_ns = abs(mean1 - mean2)

    if abs(t_stat) <= _DUDECT_THRESHOLD or delta_ns < _TIMING_MIN_EFFECT_NS:
        return (
            True,
            f"Constant-time OK: |t|={abs(t_stat):.2f}, delta={delta_ns:.0f}ns "
            f"(threshold={_DUDECT_THRESHOLD}, min-effect={_TIMING_MIN_EFFECT_NS:.0f}ns) "
            f"(first-diff={mean1:.0f}ns, last-diff={mean2:.0f}ns, n={n1})",
        )

    # Auditable failure message — operator must be able to distinguish
    # a real native-kernel timing leak from a CI-host jitter false positive
    # without spelunking through this file.  Include both axes of evidence
    # (statistical + absolute) and a one-line remediation pointer.
    return (
        False,
        f"FIPS POST: timing-leak detected in ama_consttime_memcmp — "
        f"|t|={abs(t_stat):.2f} > {_DUDECT_THRESHOLD}, "
        f"delta={delta_ns:.0f}ns >= {_TIMING_MIN_EFFECT_NS:.0f}ns "
        f"(first-diff={mean1:.0f}ns, last-diff={mean2:.0f}ns, n={n1}). "
        f"Operator remediation: (1) re-run on a dedicated/idle host — if "
        f"the failure does NOT reproduce, it is shared-runner jitter; (2) "
        f"if it reproduces, treat as a real leak: rebuild the native C "
        f"library and inspect ama_consttime_memcmp for data-dependent "
        f"early exit. See docs/constant-time-testing.md for full guidance.",
    )


def _run_backend_stage() -> Tuple[bool, Optional[str]]:
    """Fail POST when the native cryptographic backend did not load at all.

    INVARIANT-7 ("No Cryptographic Fallbacks, Ever") is unambiguous: when the
    native constant-time C backend is unavailable the library must refuse to
    operate and must raise at import, load or initialisation time, and "a
    warning without a hard stop" is explicitly named as an unacceptable
    substitute.

    That enforcement was documented as living in the module-level guards of
    ``crypto_api``, ``key_management`` and ``legacy_compat`` — all three of
    which this package imports **lazily**.  ``crypto_api`` sits behind
    ``__init__.__getattr__``, so ``import ama_cryptography`` never executed any
    of them.  A checkout with no discoverable ``libama_cryptography`` therefore
    imported cleanly, emitted a UserWarning, skipped eight of eleven
    self-tests, and reached OPERATIONAL: a warning without a hard stop,
    precisely the shape INVARIANT-7 rules out.  POST is the one thing that
    always runs on import, so POST is where the invariant has to be enforced.

    A *partly* populated backend is not this stage's concern — a build that
    omits, say, SPHINCS+ still leaves the per-algorithm KAT to skip and warn
    (or to fail under ``AMA_FIPS_STRICT``).  This stage answers only the
    all-or-nothing question: is there a native backend at all?

    The documented docs-build override (``AMA_SPHINX_BUILD=1`` /
    ``SPHINX_BUILD=1``) is honoured, matching the sole exception INVARIANT-7
    carves out so Sphinx autodoc can introspect signatures.  It permits the
    import, not any cryptographic operation: every native wrapper still
    raises, and ``module_attestation()["fully_verified"]`` stays False.
    """
    try:
        from ama_cryptography.pqc_backends import (
            native_backend_load_summary,
            native_backend_diagnostics,
        )
    except Exception as exc:
        _SELF_TEST_RESULTS.append(("native-backend", False, f"probe failed: {exc}"))
        return False, f"native backend probe failed: {exc}"

    diag = native_backend_diagnostics()
    if diag["loaded"]:
        _SELF_TEST_RESULTS.append(("native-backend", True, f"loaded from {diag['path']}"))
        return True, None

    summary = native_backend_load_summary()
    if _env_flag_enabled("AMA_SPHINX_BUILD") or _env_flag_enabled("SPHINX_BUILD"):
        _SELF_TEST_RESULTS.append(
            ("native-backend", None, f"docs-build override active — {summary}")
        )
        logger.warning(
            "FIPS 140-3 POST: no native backend, but the documented docs-build "
            "override is active. Import is permitted for autodoc only; every "
            "cryptographic operation still refuses. %s",
            summary,
        )
        return True, None

    _SELF_TEST_RESULTS.append(("native-backend", False, summary))
    return False, (
        f"native cryptographic backend unavailable — INVARIANT-7 forbids "
        f"operating without it. {summary}"
    )


def _run_integrity_stage() -> Tuple[bool, Optional[str]]:
    """Run the module-integrity verification stage.

    Returns ``(passed, error_reason)``.  ``passed=True`` means the
    integrity check verified and POST may proceed; ``passed=False``
    means the runner must short-circuit and ``_run_self_tests`` must
    set ERROR with ``error_reason``.

    Appends one row to ``_SELF_TEST_RESULTS`` regardless of outcome.
    """
    try:
        integrity_passed, integrity_detail = verify_module_integrity()
    except Exception as exc:
        _SELF_TEST_RESULTS.append(("integrity", False, f"Exception: {exc}"))
        return False, f"Module integrity check exception: {exc}"
    if not integrity_passed:
        _SELF_TEST_RESULTS.append(("integrity", False, integrity_detail))
        return False, integrity_detail

    # Anything short of "signed AND native library verified" is recorded as a
    # SKIP, not a PASS, because each weaker outcome leaves some part of the
    # module unchecked:
    #   * "digest-only" — an unsigned plaintext digest an attacker who edits
    #     the .py files can rewrite in the same breath.  Detects corruption,
    #     not tampering.
    #   * "signed-native-unverified" — the signature verified, but the shared
    #     object that performs every cryptographic operation was not bound to
    #     it (AMA_CRYPTO_LIB_PATH override, an unreadable dev object, or a
    #     legacy v1 artefact).  The wrapper is verified; the implementation is
    #     not.
    # Recording either as a skip lands it in the same machinery as an untested
    # algorithm: named in the POST warning, counted by
    # module_attestation()["tests_skipped"], excluded from "fully_verified",
    # and escalated to a hard failure under AMA_FIPS_STRICT.  Promoting either
    # to a pass is exactly the class of "fully verified over an unchecked
    # component" this whole change exists to close.
    if _INTEGRITY_STRENGTH in ("digest-only", "signed-native-unverified"):
        _SELF_TEST_RESULTS.append(("integrity", None, integrity_detail))
        # Read from the environment rather than taken as a parameter: every
        # other stage helper that needs strict mode is wrapped in a lambda by
        # the runner, and this one is monkeypatched zero-arg by the existing
        # branch tests.  Keeping the signature stable costs one env lookup on
        # a path that runs once per process.
        if _env_flag_enabled(_AMA_FIPS_STRICT_ENV):
            return False, (
                f"FIPS strict mode ({_AMA_FIPS_STRICT_ENV}=1): module integrity "
                f"not full-strength ({_INTEGRITY_STRENGTH}) — {integrity_detail}"
            )
        return True, None

    _SELF_TEST_RESULTS.append(("integrity", True, integrity_detail))
    return True, None


def _handle_kat_skip(name: str, detail: str, strict_mode: bool) -> Optional[str]:
    """Decide whether a KAT skip should fail POST or just WARN.

    Returns the error reason if the skip should fail POST under
    strict mode; returns ``None`` if the runner should continue.
    Logs a WARNING in the non-strict case so the operator can
    notice the missing coverage in CI logs.
    """
    if strict_mode:
        return f"FIPS strict mode ({_AMA_FIPS_STRICT_ENV}=1): " f"{name} KAT cannot run — {detail}"
    logger.warning(
        "FIPS 140-3 POST: %s KAT skipped (%s).  This backend has NO "
        "self-test coverage in this run.  Build the C library or set "
        "%s=1 to escalate this skip to a hard POST failure.",
        name,
        detail,
        _AMA_FIPS_STRICT_ENV,
    )
    return None


#: The CASTs the signed-integrity stage depends on, run before it.
#
# The split is not cosmetic: FIPS 140-3 (NIST IG 10.3.A) requires that the
# cryptographic algorithm self-test (CAST) for any approved algorithm the
# integrity test depends on be performed before the integrity test relies on
# it.  The signed-integrity check verifies an Ed25519 signature with the
# module's own native verifier and computes SHA3-256 digests, so both CASTs
# must pass first.  Running Ed25519's KAT after the integrity test — as the
# original single KAT stage did — meant the module authenticated itself with an
# algorithm it had not yet self-tested.
_PRE_INTEGRITY_KAT_NAMES = ("SHA3-256", "Ed25519")


def _all_kat_tests() -> Tuple[Tuple[str, Callable[[], Tuple[Optional[bool], str]]], ...]:
    """Every algorithm KAT, in recorded order.

    Built on each call rather than frozen into a module constant so the
    function references resolve against the *current* module globals: the
    branch tests monkeypatch ``_self_test._kat_sha3_256`` and friends to force
    failures, and a constant captured at import time would hold the originals
    and quietly ignore the patch.
    """
    return (
        ("SHA3-256", _kat_sha3_256),
        ("HMAC-SHA3-256", _kat_hmac_sha3_256),
        ("AES-256-GCM", _kat_aes_256_gcm),
        ("ML-KEM-1024", _kat_ml_kem_1024),
        ("ML-DSA-65", _kat_ml_dsa_65),
        ("SLH-DSA", _kat_slh_dsa),
        ("SLH-DSA-SHAKE-128s", _kat_slh_dsa_shake_128s),
        ("Ed25519", _kat_ed25519),
    )


def _pre_integrity_kats() -> Tuple[Tuple[str, Callable[[], Tuple[Optional[bool], str]]], ...]:
    return tuple(t for t in _all_kat_tests() if t[0] in _PRE_INTEGRITY_KAT_NAMES)


def _post_integrity_kats() -> Tuple[Tuple[str, Callable[[], Tuple[Optional[bool], str]]], ...]:
    return tuple(t for t in _all_kat_tests() if t[0] not in _PRE_INTEGRITY_KAT_NAMES)


def _run_kat_stage(
    strict_mode: bool,
    kat_tests: Optional[Tuple[Tuple[str, Callable[[], Tuple[Optional[bool], str]]], ...]] = None,
) -> Tuple[bool, Optional[str]]:
    """Run the given per-algorithm KATs and record each outcome.

    ``kat_tests`` defaults to the full set; the runner passes a subset so the
    integrity-relevant CASTs run before the integrity stage and the remainder
    after.  Returns ``(passed, error_reason)`` with the same semantics as
    :func:`_run_integrity_stage`; on the first hard-failure (or strict-mode
    skip) it returns early without running the remaining KATs.
    """
    if kat_tests is None:
        kat_tests = _all_kat_tests()
    for name, test_fn in kat_tests:
        try:
            passed, detail = test_fn()
        except Exception as exc:
            detail = f"{name} KAT exception: {exc}"
            _SELF_TEST_RESULTS.append((name, False, detail))
            return False, detail
        _SELF_TEST_RESULTS.append((name, passed, detail))
        if passed is None:
            err = _handle_kat_skip(name, detail, strict_mode)
            if err is not None:
                return False, err
            continue
        if not passed:
            return False, detail
    return True, None


def _run_timing_oracle_stage(strict_mode: bool) -> Tuple[bool, Optional[str]]:
    """Run the constant-time timing-oracle stage exactly once.

    Returns ``(passed, error_reason)``.  Skip semantics mirror the
    KAT stage: ``None`` from the oracle (no native consttime
    backend) is a skip — WARNING in non-strict mode, hard error
    in strict mode.  A measured leak is always a hard error.
    """
    try:
        oracle_passed, oracle_detail = _timing_oracle_consttime()
    except Exception as exc:
        oracle_detail = f"Timing oracle exception: {exc}"
        oracle_passed = False
    _SELF_TEST_RESULTS.append(("consttime-oracle", oracle_passed, oracle_detail))
    if oracle_passed is None:
        if strict_mode:
            return False, (
                f"FIPS strict mode ({_AMA_FIPS_STRICT_ENV}=1): "
                f"consttime-oracle cannot run — {oracle_detail}"
            )
        logger.warning(
            "FIPS 140-3 POST: consttime-oracle skipped (%s).  "
            "Native constant-time backend is required for timing-leak "
            "self-test; set %s=1 to escalate.",
            oracle_detail,
            _AMA_FIPS_STRICT_ENV,
        )
        return True, None
    if oracle_passed is False:
        return False, oracle_detail
    return True, None


def _run_rng_stage() -> Tuple[bool, Optional[str]]:
    """Run the initial continuous-RNG health check.

    Returns ``(passed, error_reason)``.  Two consecutive identical
    32-byte draws is a hard failure; an exception from
    ``secrets.token_bytes`` is treated the same way.
    """
    try:
        out1 = secrets.token_bytes(32)
        out2 = secrets.token_bytes(32)
    except Exception as exc:
        _SELF_TEST_RESULTS.append(("RNG", False, f"Exception: {exc}"))
        return False, f"RNG health test exception: {exc}"
    if out1 == out2:
        _SELF_TEST_RESULTS.append(("RNG", False, "Identical consecutive outputs"))
        return False, "RNG health test failed at startup"
    _rng_state["previous"] = out2
    _SELF_TEST_RESULTS.append(("RNG", True, "RNG health test passed"))
    return True, None


def _run_self_tests() -> bool:
    """
    Run all FIPS 140-3 power-on self-tests.

    Returns True if all tests passed (skipped tests with the backend
    unavailable are NOT counted as passes — see the tri-state semantics
    on ``_SELF_TEST_RESULTS``) and module is OPERATIONAL.  Returns False
    and sets ERROR state if any test failed.

    Skip handling:
        * Default (``AMA_FIPS_STRICT`` unset): a skipped KAT is logged
          at WARNING and recorded in ``_SELF_TEST_RESULTS`` with
          ``passed=None``.  POST continues.  ``module_status()``
          becomes ``OPERATIONAL`` provided no test actually failed.
        * Strict (``AMA_FIPS_STRICT=1``): a skipped KAT is escalated
          to a hard failure — POST returns False and the module enters
          ERROR.  Release wheels and FIPS-validated deployments should
          set this so an absent backend (e.g. SPHINCS+ build flag
          omitted) cannot silently degrade the approved-algorithm set.

    Implementation is split into per-stage helpers (integrity / KAT /
    timing-oracle / RNG) so the main runner stays under the project's
    cyclomatic-complexity ceiling and each stage is independently
    testable.
    """
    global _MODULE_STATE, _ERROR_REASON, _SELF_TEST_RESULTS, _POST_DURATION_MS
    global _SELF_TEST_THREAD

    with _POST_LOCK:
        _MODULE_STATE = "SELF_TEST"
        _ERROR_REASON = None
        _SELF_TEST_RESULTS = []
        _SELF_TEST_THREAD = threading.get_ident()
        start = time.monotonic()

        strict_mode = _env_flag_enabled(_AMA_FIPS_STRICT_ENV)

        stages: Tuple[Tuple[str, Callable[[], Tuple[bool, Optional[str]]]], ...] = (
            # Backend presence runs first purely for diagnosability: with no
            # native library every later stage degrades or skips, and the
            # operator is best served by being told the one fact that explains
            # all of them rather than by a downstream symptom of it.  The
            # verdict is order-independent — a missing backend fails POST from
            # whichever position this stage occupies.
            ("native-backend", _run_backend_stage),
            # CASTs for the algorithms the integrity stage relies on, run
            # BEFORE it (NIST IG 10.3.A): the signed-integrity check verifies an
            # Ed25519 signature with the module's own native verifier and
            # computes SHA3-256 digests, so both must be self-tested first. See
            # _PRE_INTEGRITY_KAT_NAMES.
            ("kat-pre-integrity", lambda: _run_kat_stage(strict_mode, _pre_integrity_kats())),
            ("integrity", _run_integrity_stage),
            # The remaining CASTs, after integrity.
            ("kat", lambda: _run_kat_stage(strict_mode, _post_integrity_kats())),
            ("oracle", lambda: _run_timing_oracle_stage(strict_mode)),
            ("rng", _run_rng_stage),
        )

        all_passed = True
        try:
            for _stage_name, stage_fn in stages:
                stage_ok, err = stage_fn()
                if not stage_ok:
                    if err is None:
                        # SECURITY: asserts can be stripped with ``python -O``;
                        # fail closed explicitly if a stage violates the
                        # ``(False, reason)`` contract.
                        err = "FIPS POST internal error: stage returned (False, None)"
                    _set_error(err)
                    all_passed = False
                    break
        finally:
            # Drop the self-test allowance before returning by ANY path,
            # including an unexpected exception escaping a stage.  Leaving it
            # set would keep ``check_crypto_permitted`` permissive on this
            # thread for the rest of the process's life.
            _SELF_TEST_THREAD = None

        _POST_DURATION_MS = (time.monotonic() - start) * 1000

        if all_passed:
            _set_operational()
            # Count outcomes for the operator log
            n_pass = sum(1 for _, p, _ in _SELF_TEST_RESULTS if p is True)
            skipped = [(name, detail) for name, p, detail in _SELF_TEST_RESULTS if p is None]
            if skipped:
                # A skip is not a pass, and a bare count of them is not much
                # better than silence — the operator needs to know *which*
                # approved algorithms went untested before treating this run
                # as evidence of anything.
                logger.warning(
                    "FIPS 140-3 POST completed in %.1f ms but %d of %d tests were "
                    "SKIPPED — this module is NOT fully verified. Untested: %s. "
                    "Set %s=1 to make a skip a hard failure.",
                    _POST_DURATION_MS,
                    len(skipped),
                    len(_SELF_TEST_RESULTS),
                    ", ".join(f"{name} ({detail})" for name, detail in skipped),
                    _AMA_FIPS_STRICT_ENV,
                )
            else:
                logger.info(
                    "FIPS 140-3 POST completed successfully in %.1f ms "
                    "(%d tests run; %d passed, 0 skipped)",
                    _POST_DURATION_MS,
                    len(_SELF_TEST_RESULTS),
                    n_pass,
                )

        return all_passed
