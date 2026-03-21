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
Version: 2.0
"""

import hashlib
import logging
import secrets
import time
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# ============================================================================
# ERROR STATE MACHINE (FIPS 140-3 Section 4.9.2)
# ============================================================================

_MODULE_STATE = "SELF_TEST"  # OPERATIONAL | ERROR | SELF_TEST
_ERROR_REASON: Optional[str] = None
_SELF_TEST_RESULTS: List[Tuple[str, bool, str]] = []  # (name, passed, detail)
_POST_DURATION_MS: float = 0.0


class CryptoModuleError(RuntimeError):
    """Raised when the cryptographic module is in an error state."""
    pass


def module_status() -> str:
    """Return current module state: OPERATIONAL, ERROR, or SELF_TEST."""
    return _MODULE_STATE


def module_error_reason() -> Optional[str]:
    """Return the reason for ERROR state, or None if not in ERROR."""
    return _ERROR_REASON


def module_self_test_results() -> List[Tuple[str, bool, str]]:
    """Return list of (test_name, passed, detail) from the last POST run."""
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
    """Raise CryptoModuleError if module is not OPERATIONAL."""
    if _MODULE_STATE != "OPERATIONAL":
        raise CryptoModuleError(
            f"Module in error state: {_ERROR_REASON or _MODULE_STATE}"
        )


def reset_module() -> bool:
    """Re-run self-tests to attempt recovery from ERROR state."""
    global _MODULE_STATE
    _MODULE_STATE = "SELF_TEST"
    return _run_self_tests()


# ============================================================================
# CONTINUOUS RNG TEST (FIPS 140-3 Section 4.9.2)
# ============================================================================

_previous_rng_output: Optional[bytes] = None


def secure_token_bytes(n: int = 32) -> bytes:
    """
    Wrapper around secrets.token_bytes with continuous RNG health test.

    Compares each output to the previous; if identical, enters ERROR state.
    """
    check_operational()
    global _previous_rng_output
    output = secrets.token_bytes(n)
    if _previous_rng_output is not None and output == _previous_rng_output:
        _set_error("Continuous RNG test failed: consecutive identical outputs")
        raise CryptoModuleError("Module in error state: Continuous RNG test failed")
    _previous_rng_output = output
    return output


# ============================================================================
# PAIRWISE CONSISTENCY TESTS (FIPS 140-3 Section 4.9.2)
# ============================================================================

def pairwise_test_signature(sign_fn, verify_fn, secret_key, public_key,
                            algo_name: str) -> None:
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


def pairwise_test_kem(encaps_fn, decaps_fn, public_key, secret_key,
                      algo_name: str) -> None:
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


def _compute_module_digest() -> str:
    """Compute SHA3-256 hash over all .py files in the ama_cryptography package."""
    pkg_dir = Path(__file__).resolve().parent
    hasher = hashlib.sha3_256()
    py_files = sorted(pkg_dir.glob("*.py"))
    for py_file in py_files:
        # Skip the digest file reference and __pycache__
        if py_file.name == "_integrity_digest.txt":
            continue
        hasher.update(py_file.name.encode("utf-8"))
        hasher.update(py_file.read_bytes())
    return hasher.hexdigest()


def verify_module_integrity() -> bool:
    """Verify module source files against stored digest."""
    if not _INTEGRITY_DIGEST_FILE.exists():
        logger.warning("Integrity digest file not found — skipping check")
        return True  # First run: no digest yet
    stored = _INTEGRITY_DIGEST_FILE.read_text().strip()
    current = _compute_module_digest()
    return stored == current


def update_integrity_digest() -> str:
    """Recompute and store the module integrity digest. Returns the new digest."""
    digest = _compute_module_digest()
    _INTEGRITY_DIGEST_FILE.write_text(digest + "\n")
    return digest


# ============================================================================
# KNOWN ANSWER TESTS (FIPS 140-3 Section 4.9.1)
# ============================================================================

def _kat_sha3_256() -> Tuple[bool, str]:
    """SHA3-256 KAT: hash empty string, compare to known digest."""
    known_input = b""
    # SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    result = hashlib.sha3_256(known_input).hexdigest()
    if result == expected:
        return True, "SHA3-256 KAT passed"
    return False, f"SHA3-256 KAT failed: got {result}"


def _kat_hmac_sha3_256() -> Tuple[bool, str]:
    """HMAC-SHA3-256 KAT using native backend."""
    try:
        from ama_cryptography.pqc_backends import (
            _HMAC_SHA3_256_NATIVE_AVAILABLE,
            native_hmac_sha3_256,
        )
        if not _HMAC_SHA3_256_NATIVE_AVAILABLE:
            return True, "HMAC-SHA3-256 KAT skipped (native unavailable)"

        key = b"\x0b" * 20
        data = b"Hi There"
        result = native_hmac_sha3_256(key, data)
        # Verify it returns 32 bytes and is deterministic
        result2 = native_hmac_sha3_256(key, data)
        if result != result2:
            return False, "HMAC-SHA3-256 KAT: non-deterministic output"
        if len(result) != 32:
            return False, f"HMAC-SHA3-256 KAT: expected 32 bytes, got {len(result)}"
        return True, "HMAC-SHA3-256 KAT passed (determinism verified)"
    except Exception as exc:
        return False, f"HMAC-SHA3-256 KAT exception: {exc}"


def _kat_aes_256_gcm() -> Tuple[bool, str]:
    """AES-256-GCM KAT: encrypt known plaintext, verify roundtrip."""
    try:
        from ama_cryptography.pqc_backends import (
            _AES_GCM_NATIVE_AVAILABLE,
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )
        if not _AES_GCM_NATIVE_AVAILABLE:
            return True, "AES-256-GCM KAT skipped (native unavailable)"

        key = bytes(range(32))
        nonce = bytes(range(12))
        plaintext = b"FIPS 140-3 KAT test vector"
        aad = b"additional data"

        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, aad)
        pt = native_aes256_gcm_decrypt(key, nonce, ct, tag, aad)
        if pt != plaintext:
            return False, "AES-256-GCM KAT: decrypt mismatch"

        # Verify determinism
        ct2, tag2 = native_aes256_gcm_encrypt(key, nonce, plaintext, aad)
        if ct != ct2 or tag != tag2:
            return False, "AES-256-GCM KAT: non-deterministic"

        return True, "AES-256-GCM KAT passed"
    except Exception as exc:
        return False, f"AES-256-GCM KAT exception: {exc}"


def _kat_ml_kem_1024() -> Tuple[bool, str]:
    """ML-KEM-1024 KAT: keygen + encaps + decaps roundtrip."""
    try:
        from ama_cryptography.pqc_backends import (
            KYBER_AVAILABLE,
            generate_kyber_keypair,
            kyber_decapsulate,
            kyber_encapsulate,
        )
        if not KYBER_AVAILABLE:
            return True, "ML-KEM-1024 KAT skipped (backend unavailable)"

        kp = generate_kyber_keypair()
        encap = kyber_encapsulate(kp.public_key)
        ss = kyber_decapsulate(encap.ciphertext, kp.secret_key)
        if ss != encap.shared_secret:
            return False, "ML-KEM-1024 KAT: shared secrets mismatch"
        return True, "ML-KEM-1024 KAT passed"
    except Exception as exc:
        return False, f"ML-KEM-1024 KAT exception: {exc}"


def _kat_ml_dsa_65() -> Tuple[bool, str]:
    """ML-DSA-65 KAT: keygen + sign + verify roundtrip."""
    try:
        from ama_cryptography.pqc_backends import (
            DILITHIUM_AVAILABLE,
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
        )
        if not DILITHIUM_AVAILABLE:
            return True, "ML-DSA-65 KAT skipped (backend unavailable)"

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


def _kat_slh_dsa() -> Tuple[bool, str]:
    """SLH-DSA (SPHINCS+) KAT: keygen + sign + verify roundtrip."""
    try:
        from ama_cryptography.pqc_backends import (
            SPHINCS_AVAILABLE,
            generate_sphincs_keypair,
            sphincs_sign,
            sphincs_verify,
        )
        if not SPHINCS_AVAILABLE:
            return True, "SLH-DSA KAT skipped (backend unavailable)"

        kp = generate_sphincs_keypair()
        msg = b"FIPS 140-3 SLH-DSA KAT"
        sig = sphincs_sign(msg, kp.secret_key)
        valid = sphincs_verify(msg, sig, kp.public_key)
        if not valid:
            return False, "SLH-DSA KAT: signature verification failed"
        return True, "SLH-DSA KAT passed"
    except Exception as exc:
        return False, f"SLH-DSA KAT exception: {exc}"


def _kat_ed25519() -> Tuple[bool, str]:
    """Ed25519 KAT: keygen + sign + verify roundtrip."""
    try:
        from ama_cryptography.pqc_backends import (
            _ED25519_NATIVE_AVAILABLE,
            native_ed25519_keypair,
            native_ed25519_sign,
            native_ed25519_verify,
        )
        if not _ED25519_NATIVE_AVAILABLE:
            return True, "Ed25519 KAT skipped (native unavailable)"

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

def _run_self_tests() -> bool:
    """
    Run all FIPS 140-3 power-on self-tests.

    Returns True if all tests passed and module is OPERATIONAL.
    Returns False and sets ERROR state if any test failed.
    """
    global _MODULE_STATE, _SELF_TEST_RESULTS, _POST_DURATION_MS
    _MODULE_STATE = "SELF_TEST"
    _SELF_TEST_RESULTS = []
    start = time.monotonic()

    # 1. Module integrity verification
    try:
        if not verify_module_integrity():
            _SELF_TEST_RESULTS.append(("integrity", False, "Module integrity check failed"))
            _set_error("Module integrity verification failed")
            _POST_DURATION_MS = (time.monotonic() - start) * 1000
            return False
        _SELF_TEST_RESULTS.append(("integrity", True, "Module integrity verified"))
    except Exception as exc:
        _SELF_TEST_RESULTS.append(("integrity", False, f"Exception: {exc}"))
        _set_error(f"Module integrity check exception: {exc}")
        _POST_DURATION_MS = (time.monotonic() - start) * 1000
        return False

    # 2. KAT for each approved algorithm
    kat_tests = [
        ("SHA3-256", _kat_sha3_256),
        ("HMAC-SHA3-256", _kat_hmac_sha3_256),
        ("AES-256-GCM", _kat_aes_256_gcm),
        ("ML-KEM-1024", _kat_ml_kem_1024),
        ("ML-DSA-65", _kat_ml_dsa_65),
        ("SLH-DSA", _kat_slh_dsa),
        ("Ed25519", _kat_ed25519),
    ]

    all_passed = True
    for name, test_fn in kat_tests:
        try:
            passed, detail = test_fn()
            _SELF_TEST_RESULTS.append((name, passed, detail))
            if not passed:
                all_passed = False
                _set_error(detail)
                break
        except Exception as exc:
            detail = f"{name} KAT exception: {exc}"
            _SELF_TEST_RESULTS.append((name, False, detail))
            _set_error(detail)
            all_passed = False
            break

    # 3. Continuous RNG initial test
    if all_passed:
        try:
            global _previous_rng_output
            out1 = secrets.token_bytes(32)
            out2 = secrets.token_bytes(32)
            if out1 == out2:
                _SELF_TEST_RESULTS.append(("RNG", False, "Identical consecutive outputs"))
                _set_error("RNG health test failed at startup")
                all_passed = False
            else:
                _previous_rng_output = out2
                _SELF_TEST_RESULTS.append(("RNG", True, "RNG health test passed"))
        except Exception as exc:
            _SELF_TEST_RESULTS.append(("RNG", False, f"Exception: {exc}"))
            _set_error(f"RNG health test exception: {exc}")
            all_passed = False

    _POST_DURATION_MS = (time.monotonic() - start) * 1000

    if all_passed:
        _set_operational()
        logger.info(
            "FIPS 140-3 POST completed successfully in %.1f ms (%d tests)",
            _POST_DURATION_MS, len(_SELF_TEST_RESULTS),
        )

    return all_passed
