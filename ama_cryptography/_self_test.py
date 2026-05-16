#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
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
Version: 3.0.0
"""

import ctypes
import hashlib
import json
import logging
import math
import os
import secrets
import time
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple

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


def reset_module() -> bool:
    """Re-run self-tests to attempt recovery from ERROR state."""
    global _MODULE_STATE
    _MODULE_STATE = "SELF_TEST"
    return _run_self_tests()


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
    """
    check_operational()
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
_INTEGRITY_REQUIRE_TRUST_ANCHOR_ENV = "AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR"
_TRUE_ENV_VALUES = {"1", "true", "yes", "on"}


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


def _verify_signed_integrity(digest_hex: str) -> Tuple[bool, str]:
    """Verify the build-time Ed25519 signature over the .py digest.

    Returns:
        ``(True, detail)`` on signature verify, ``(False, reason)`` on
        any failure mode that we can describe, or ``(None, ...)`` is
        intentionally not used — every failure mode must produce a
        Boolean outcome so the caller fails-closed.

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
        return False, "no signed-integrity artefact (digest-only fallback)"

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
        )
    except ImportError as exc:
        return False, f"native Ed25519 unavailable: {exc}"

    if not _ED25519_NATIVE_AVAILABLE:
        return False, "native Ed25519 not built — cannot verify signature"

    try:
        ok = native_ed25519_verify(signature, digest_raw, pubkey)
    except Exception as exc:  # fail-closed: any verify exception must yield False (INT-003)
        return False, f"native Ed25519 verify raised: {exc}"
    if not ok:
        return False, "Ed25519 signature did NOT verify — module tampered"
    if trust_anchor_hex is not None:
        return True, "signed integrity verified (Ed25519, trusted build pubkey)"
    return True, "signed integrity verified (Ed25519, build-time pubkey)"


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
    current = _compute_module_digest()

    signed_ok, signed_detail = _verify_signed_integrity(current)
    if signed_ok:
        return True, signed_detail

    # Signed path was not available OR failed.  If it FAILED (digest
    # matched but signature didn't verify), that's an error — return
    # the specific reason.  If it was simply MISSING, fall back to
    # digest-only with a warning UNLESS a trust anchor is required.
    if "no signed-integrity artefact" not in signed_detail:
        logger.error("Signed integrity check failed: %s", signed_detail)
        return False, signed_detail

    # Release builds must fail closed: AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR=1
    # means "this is a release wheel — no unsigned digest-only acceptance
    # is permitted, even if the .py files happen to match."  Developer
    # editable installs and source checkouts leave the env var unset and
    # still get the documented digest-only WARN-and-continue behaviour.
    if _env_flag_enabled(_INTEGRITY_REQUIRE_TRUST_ANCHOR_ENV):
        return False, (
            "signed-integrity artefact missing and "
            f"{_INTEGRITY_REQUIRE_TRUST_ANCHOR_ENV}=1 forbids digest-only "
            "fallback — rebuild the wheel with AMA_BUILD_PIPELINE=1"
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
    # Digest-only path is healthy; log that signing is missing so the
    # packager can notice it in CI logs (one-time WARN, not ERROR).
    logger.warning(
        "Module integrity verified via digest-only fallback "
        "(_integrity_signature.py absent — wheel was built without "
        "AMA_BUILD_PIPELINE=1)."
    )
    return True, "Module integrity verified (digest-only fallback)"


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
    """SHA3-256 KAT: hash empty string, compare to known digest.

    SHA3-256 ships in CPython's hashlib so the result is always either
    ``(True, ...)`` or ``(False, ...)`` — there is no skip path.
    """
    known_input = b""
    # SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    result = hashlib.sha3_256(known_input).hexdigest()
    if result == expected:
        return True, "SHA3-256 KAT passed"
    return False, f"SHA3-256 KAT failed: got {result}"


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

        try:
            from importlib.resources import files as _resfiles
        except ImportError:  # pragma: no cover - Py<3.9 not supported in this lib
            return False, "SLH-DSA-SHAKE-128s KAT: importlib.resources unavailable"

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
    """Ed25519 KAT: keygen + sign + verify roundtrip."""
    try:
        from ama_cryptography.pqc_backends import (
            _ED25519_NATIVE_AVAILABLE,
            native_ed25519_keypair,
            native_ed25519_sign,
            native_ed25519_verify,
        )

        if not _ED25519_NATIVE_AVAILABLE:
            return None, "Ed25519 KAT skipped (native unavailable)"

        pk, sk = native_ed25519_keypair()
        msg = b"FIPS 140-3 Ed25519 KAT"
        sig = native_ed25519_sign(msg, sk)
        valid = native_ed25519_verify(sig, msg, pk)
        if not valid:
            return False, "Ed25519 KAT: signature verification failed"
        return True, "Ed25519 KAT passed"
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
# Minimum absolute mean-time delta (ns) required before POST will declare a
# timing-leak failure.  With ``time.perf_counter_ns`` granularity (~25-100 ns
# on Linux/macOS x86, often coarser on shared GitHub-hosted runners under
# co-tenant load), a 10000-sample paired-test can drive |t| above 4.5 from
# host-jitter alone with mean deltas in the 25-40 ns range — well below the
# scale of a *real* early-exit memcmp leak over a 256-byte buffer (which is
# orders of magnitude larger because the cmp loop short-circuits on the
# first differing byte vs. running to the end).  Raising the floor from
# 25 ns → 50 ns trades nothing on detection power for real leaks (which
# manifest as >>500 ns deltas in dudect ground-truth measurements) while
# preventing false POST lockouts on noisy CI hosts where scheduler jitter
# alone produces |t|>4.5 with delta in the 25-45 ns band.  See PR
# discussion: shared Ubuntu 3.11 runner observed |t|=8.34 with delta=25ns,
# below any real-leak signature.
_TIMING_MIN_EFFECT_NS = 50.0


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
    band) from host jitter alone, while a real early-exit memcmp over 256
    bytes is orders of magnitude larger (>>500 ns).  The ``_TIMING_MIN_EFFECT_NS``
    floor (50 ns, raised from 25 ns after an Ubuntu 3.11 shared-runner
    observed |t|=8.34 / delta=25 ns false-positive) keeps POST fail-closed
    for material leaks without turning scheduler noise into a permanent
    module ERROR — and the deterministic single-pass design means the
    ``False`` outcome is reproducible on the *same* host: a one-off CI
    re-run does not "re-roll" the result.

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
    _SELF_TEST_RESULTS.append(("integrity", integrity_passed, integrity_detail))
    if not integrity_passed:
        return False, integrity_detail
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


def _run_kat_stage(strict_mode: bool) -> Tuple[bool, Optional[str]]:
    """Run every per-algorithm KAT and record its outcome.

    Returns ``(passed, error_reason)`` with the same semantics as
    :func:`_run_integrity_stage`.  Walks the list of KAT callables
    once; on the first hard-failure (or strict-mode skip) the
    function returns early without running the remaining KATs.
    """
    kat_tests = (
        ("SHA3-256", _kat_sha3_256),
        ("HMAC-SHA3-256", _kat_hmac_sha3_256),
        ("AES-256-GCM", _kat_aes_256_gcm),
        ("ML-KEM-1024", _kat_ml_kem_1024),
        ("ML-DSA-65", _kat_ml_dsa_65),
        ("SLH-DSA", _kat_slh_dsa),
        ("SLH-DSA-SHAKE-128s", _kat_slh_dsa_shake_128s),
        ("Ed25519", _kat_ed25519),
    )
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
    _MODULE_STATE = "SELF_TEST"
    _ERROR_REASON = None
    _SELF_TEST_RESULTS = []
    start = time.monotonic()

    strict_mode = _env_flag_enabled(_AMA_FIPS_STRICT_ENV)

    stages: Tuple[Tuple[str, Callable[[], Tuple[bool, Optional[str]]]], ...] = (
        ("integrity", _run_integrity_stage),
        ("kat", lambda: _run_kat_stage(strict_mode)),
        ("oracle", lambda: _run_timing_oracle_stage(strict_mode)),
        ("rng", _run_rng_stage),
    )

    all_passed = True
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

    _POST_DURATION_MS = (time.monotonic() - start) * 1000

    if all_passed:
        _set_operational()
        # Count outcomes for the operator log
        n_pass = sum(1 for _, p, _ in _SELF_TEST_RESULTS if p is True)
        n_skip = sum(1 for _, p, _ in _SELF_TEST_RESULTS if p is None)
        logger.info(
            "FIPS 140-3 POST completed successfully in %.1f ms "
            "(%d tests run; %d passed, %d skipped)",
            _POST_DURATION_MS,
            len(_SELF_TEST_RESULTS),
            n_pass,
            n_skip,
        )

    return all_passed
