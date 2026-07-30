#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography - Post-Quantum Cryptography Backends
==========================================================

Centralized PQC backend detection and implementation.
Single source of truth for all post-quantum cryptographic operations.

Supported Algorithms:
- ML-DSA-65 (CRYSTALS-Dilithium): Digital signatures (NIST FIPS 204)
- Kyber-1024 (ML-KEM): Key encapsulation mechanism (NIST FIPS 203)
- SPHINCS+-SHA2-256f: Hash-based signatures (NIST FIPS 205)

This module provides quantum-resistant implementations via native C backend.
All implementations pass NIST KAT (Known Answer Test) validation.

Standards:
- NIST FIPS 203: ML-KEM (Kyber)
- NIST FIPS 204: ML-DSA (CRYSTALS-Dilithium)
- NIST FIPS 205: SLH-DSA (SPHINCS+)

AI Co-Architects: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

import contextlib
import ctypes
import logging
import os
import platform
import warnings
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional, Union, cast

from ama_cryptography._finalizer_health import record_finalizer_error
from ama_cryptography.exceptions import (
    NativeBackendUnavailableError,
    PQCUnavailableError,
    QuantumSignatureUnavailableError,
    SecurityWarning,
)

__all__ = [
    "NativeBackendUnavailableError",
    "PQCUnavailableError",
    "QuantumSignatureUnavailableError",
    "KyberUnavailableError",
    "SphincsUnavailableError",
    "SecurityWarning",
    # Context-based API
    "AmaContext",
    # FROST threshold Ed25519 (RFC 9591)
    "FROST_AVAILABLE",
    "FROST_BACKEND",
    "FROST_SHARE_BYTES",
    "FROST_NONCE_BYTES",
    "FROST_COMMITMENT_BYTES",
    "FROST_SIG_SHARE_BYTES",
    # Native HMAC (RFC 2104 / FIPS 198-1) — direct-consumer surface (Mercury)
    "native_hmac_sha256",
    "native_hmac_sha256_2",
    "native_hmac_sha384",
    "native_hmac_sha512",
    "native_hmac_sha3_256",
    "hmac_sha3_256",
    # Native HKDF (RFC 5869)
    "native_hkdf",
    "native_hkdf_sha256",
    "native_hkdf_sha384",
    "native_hkdf_sha512",
    # Native FIPS 202 hashes / XOFs
    "native_sha3_256",
    "native_sha3_512",
    "native_shake128",
    "native_shake256",
    # Native FIPS 180-4 hash (raw one-shot SHA-256)
    "native_sha256",
]


class PQCStatus(Enum):
    """PQC backend availability status"""

    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


class KyberUnavailableError(PQCUnavailableError):
    """Raised when Kyber-1024 KEM is requested but not available."""

    pass


class SphincsUnavailableError(PQCUnavailableError):
    """Raised when SPHINCS+-256f is requested but not available."""

    pass


# Environment variable to require constant-time backends
# Set AMA_REQUIRE_CONSTANT_TIME=true to refuse non-constant-time backends
AMA_REQUIRE_CONSTANT_TIME = os.getenv("AMA_REQUIRE_CONSTANT_TIME", "").lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# Backend detection — native C library only
_DILITHIUM_AVAILABLE = False
_KYBER_AVAILABLE = False
_SPHINCS_AVAILABLE = False
_DILITHIUM_BACKEND: Optional[str] = None
_KYBER_BACKEND: Optional[str] = None
_SPHINCS_BACKEND: Optional[str] = None

# ============================================================================
# NATIVE C BACKEND DETECTION
# ============================================================================
# Load the native AMA Cryptography shared library which provides ML-DSA-65,
# Kyber-1024, and SPHINCS+-256f via pure C (FIPS 203/204/205 compliant).

_native_lib: Any = None

_BufferInput = Union[bytes, bytearray, memoryview]


@contextlib.contextmanager
def _c_buffer_view(data: _BufferInput) -> Iterator[Any]:
    """Yield a ctypes buffer view without copying writable key material.

    SECURITY: ``ctypes.c_char_p`` accepts immutable ``bytes`` directly but
    rejects ``bytearray``.  For mutable buffers we borrow the exporter with
    ``from_buffer`` so session keys stay in their wipeable bytearray storage
    instead of being materialised as transient heap copies.
    """
    if isinstance(data, bytes):
        yield data
        return
    view = memoryview(data)
    if view.readonly:
        # Read-only memoryviews may not expose a writable buffer for
        # ``from_buffer``; converting to bytes is limited to non-wipeable
        # public inputs and never used by SecureSession key storage.
        try:
            yield view.tobytes()
        finally:
            view.release()
        return
    try:
        if view.ndim != 1 or view.itemsize != 1:
            raise TypeError("buffer must be a one-dimensional byte buffer")
        yield (ctypes.c_char * view.nbytes).from_buffer(view)
    finally:
        view.release()


def _get_lib_names() -> list:
    """Return platform-specific library names."""
    system = platform.system()
    if system == "Darwin":
        return ["libama_cryptography.dylib", "libama_cryptography.so"]
    elif system == "Windows":
        return ["ama_cryptography.dll", "libama_cryptography.dll"]
    return ["libama_cryptography.so"]


def _get_search_dirs() -> list:
    """Build the list of directories to search for the native library."""
    search_dirs: list = []

    # D-1 (2026-04-27 audit): the installed wheel ships
    # libama_cryptography.so* alongside the Python module itself (set up by
    # CMakeBuild._copy_native_library_into_package in setup.py).  Search the
    # module's own directory FIRST so a `pip install`ed package never
    # depends on LD_LIBRARY_PATH or a leftover ./build/ tree.
    module_dir = Path(__file__).resolve().parent
    search_dirs.append(module_dir)

    # In-tree development tree builds (build/, build/python-cmake/, etc.)
    pkg_dir = module_dir.parent
    build_dirs = [
        "build/lib",
        "build/python-cmake/lib",  # D-3: setup.py's isolated CMake build dir
        "build",
        "build/bin",  # MSVC puts DLLs in runtime output dir
        "build/bin/Release",
        "build/bin/Debug",
        "build/Release",  # MSVC multi-config output
        "build/Debug",
        "build/lib/Release",
        "build/lib/Debug",
        "cmake-build-release/lib",
        "cmake-build-release",
        "cmake-build-debug/lib",
        "cmake-build-debug",
    ]
    for build_dir in build_dirs:
        search_dirs.append(pkg_dir / build_dir)

    # System paths (Unix only)
    if platform.system() != "Windows":
        search_dirs.extend([Path("/usr/local/lib"), Path("/usr/lib")])

    # LD_LIBRARY_PATH / DYLD_LIBRARY_PATH / PATH (Windows)
    env_vars = ["LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"]
    if platform.system() == "Windows":
        env_vars.append("PATH")
    for var in env_vars:
        env_path = os.getenv(var, "")
        for p in env_path.split(os.pathsep):
            if p:
                search_dirs.append(Path(p))

    return search_dirs


def _try_load_library(lib_path: Path) -> Optional[ctypes.CDLL]:
    """Try to load a shared library from the given path. Returns None on failure."""
    try:
        if platform.system() == "Windows":
            # On Windows with Python 3.8+, DLL search paths are restricted.
            # Use winmode=0 to search the DLL's directory and PATH.
            return ctypes.CDLL(str(lib_path), winmode=0)
        return ctypes.CDLL(str(lib_path))
    except OSError:
        return None


def _find_native_library() -> Optional[ctypes.CDLL]:
    """Locate and load the native ama_cryptography shared library."""
    lib_names = _get_lib_names()
    search_dirs = _get_search_dirs()

    # AMA_CRYPTO_LIB_PATH override
    override = os.getenv("AMA_CRYPTO_LIB_PATH")
    if override:
        override_path = Path(override)
        if override_path.is_file():
            lib = _try_load_library(override_path)
            if lib is not None:
                return lib
        elif override_path.is_dir():
            search_dirs.insert(0, override_path)

    for search_dir in search_dirs:
        for lib_name in lib_names:
            lib_path = search_dir / lib_name
            if lib_path.is_file():
                lib = _try_load_library(lib_path)
                if lib is not None:
                    return lib

    return None


def _setup_native_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes function signatures for the native library. Returns True on success."""
    try:
        # ML-DSA-65 (Dilithium)
        lib.ama_dilithium_keypair.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.ama_dilithium_keypair.restype = ctypes.c_int

        lib.ama_dilithium_sign.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]
        lib.ama_dilithium_sign.restype = ctypes.c_int

        lib.ama_dilithium_verify.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]
        lib.ama_dilithium_verify.restype = ctypes.c_int

        lib.ama_dilithium_verify_ctx.argtypes = [
            ctypes.c_char_p,  # message
            ctypes.c_size_t,  # message_len
            ctypes.c_char_p,  # ctx
            ctypes.c_size_t,  # ctx_len
            ctypes.c_char_p,  # signature
            ctypes.c_size_t,  # signature_len
            ctypes.c_char_p,  # public_key
        ]
        lib.ama_dilithium_verify_ctx.restype = ctypes.c_int

        lib.ama_dilithium_sign_ctx.argtypes = [
            ctypes.c_char_p,  # signature (out)
            ctypes.POINTER(ctypes.c_size_t),  # signature_len (in/out)
            ctypes.c_char_p,  # message
            ctypes.c_size_t,  # message_len
            ctypes.c_char_p,  # ctx
            ctypes.c_size_t,  # ctx_len
            ctypes.c_char_p,  # secret_key
        ]
        lib.ama_dilithium_sign_ctx.restype = ctypes.c_int

        # Kyber-1024
        lib.ama_kyber_keypair.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.ama_kyber_keypair.restype = ctypes.c_int

        lib.ama_kyber_encapsulate.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.ama_kyber_encapsulate.restype = ctypes.c_int

        lib.ama_kyber_decapsulate.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.ama_kyber_decapsulate.restype = ctypes.c_int

        # SPHINCS+-256f
        lib.ama_sphincs_keypair.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.ama_sphincs_keypair.restype = ctypes.c_int

        lib.ama_sphincs_sign.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]
        lib.ama_sphincs_sign.restype = ctypes.c_int

        lib.ama_sphincs_verify.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]
        lib.ama_sphincs_verify.restype = ctypes.c_int

        lib.ama_sphincs_verify_ctx.argtypes = [
            ctypes.c_char_p,  # message
            ctypes.c_size_t,  # message_len
            ctypes.c_char_p,  # ctx
            ctypes.c_size_t,  # ctx_len
            ctypes.c_char_p,  # signature
            ctypes.c_size_t,  # signature_len
            ctypes.c_char_p,  # public_key
        ]
        lib.ama_sphincs_verify_ctx.restype = ctypes.c_int

        # SLH-DSA (FIPS 205) — parameter-driven public API.
        # Param set selector: 0 = AMA_SLHDSA_SHA2_256F, 1 = AMA_SLHDSA_SHAKE_128S.
        lib.ama_slhdsa_keygen.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        lib.ama_slhdsa_keygen.restype = ctypes.c_int

        lib.ama_slhdsa_keygen_from_seed.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # sk_seed
            ctypes.c_char_p,  # sk_prf
            ctypes.c_char_p,  # pk_seed
            ctypes.c_char_p,  # pk
            ctypes.c_char_p,  # sk
        ]
        lib.ama_slhdsa_keygen_from_seed.restype = ctypes.c_int

        lib.ama_slhdsa_sign.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]
        lib.ama_slhdsa_sign.restype = ctypes.c_int

        lib.ama_slhdsa_verify.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]
        lib.ama_slhdsa_verify.restype = ctypes.c_int

        lib.ama_slhdsa_sign_deterministic.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]
        lib.ama_slhdsa_sign_deterministic.restype = ctypes.c_int

        lib.ama_slhdsa_sign_internal.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,  # addrnd (n bytes)
            ctypes.c_char_p,
        ]
        lib.ama_slhdsa_sign_internal.restype = ctypes.c_int

        return True
    except AttributeError:
        # Library found but missing expected symbols — not built with AMA_USE_NATIVE_PQC
        return False


# Ed25519 native availability (separate from PQC to avoid breaking PQC on older libs)
_ED25519_NATIVE_AVAILABLE = False


class _Ed25519BatchEntry(ctypes.Structure):
    """ctypes mirror of ama_ed25519_batch_entry from ama_cryptography.h."""

    _fields_ = [
        ("message", ctypes.c_char_p),
        ("message_len", ctypes.c_size_t),
        ("signature", ctypes.c_char_p),
        ("public_key", ctypes.c_char_p),
    ]


def _setup_ed25519_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for Ed25519 functions. Separate from PQC setup."""
    try:
        lib.ama_ed25519_keypair.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.ama_ed25519_keypair.restype = ctypes.c_int

        lib.ama_ed25519_sign.argtypes = [
            ctypes.c_char_p,  # signature[64]
            ctypes.c_char_p,  # message
            ctypes.c_size_t,  # message_len
            ctypes.c_char_p,  # secret_key[64]
        ]
        lib.ama_ed25519_sign.restype = ctypes.c_int

        lib.ama_ed25519_verify.argtypes = [
            ctypes.c_char_p,  # signature[64]
            ctypes.c_char_p,  # message
            ctypes.c_size_t,  # message_len
            ctypes.c_char_p,  # public_key[32]
        ]
        lib.ama_ed25519_verify.restype = ctypes.c_int

    except AttributeError:
        return False

    # Batch verify is optional (may be unavailable on some platforms)
    try:
        lib.ama_ed25519_batch_verify.argtypes = [
            ctypes.POINTER(_Ed25519BatchEntry),  # entries
            ctypes.c_size_t,  # count
            ctypes.POINTER(ctypes.c_int),  # results
        ]
        lib.ama_ed25519_batch_verify.restype = ctypes.c_int
    except AttributeError:
        pass  # batch verify unavailable; single-verify still works

    return True


# AES-256-GCM native availability (separate from PQC)
_AES_GCM_NATIVE_AVAILABLE = False


def _setup_aes_gcm_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for AES-256-GCM functions. Separate from PQC setup."""
    try:
        lib.ama_aes256_gcm_encrypt.argtypes = [
            ctypes.c_void_p,  # key[32]
            ctypes.c_void_p,  # nonce[12]
            ctypes.c_void_p,  # plaintext
            ctypes.c_size_t,  # pt_len
            ctypes.c_void_p,  # aad
            ctypes.c_size_t,  # aad_len
            ctypes.c_void_p,  # ciphertext
            ctypes.c_void_p,  # tag[16]
        ]
        lib.ama_aes256_gcm_encrypt.restype = ctypes.c_int

        lib.ama_aes256_gcm_decrypt.argtypes = [
            ctypes.c_void_p,  # key[32]
            ctypes.c_void_p,  # nonce[12]
            ctypes.c_void_p,  # ciphertext
            ctypes.c_size_t,  # ct_len
            ctypes.c_void_p,  # aad
            ctypes.c_size_t,  # aad_len
            ctypes.c_void_p,  # tag[16]
            ctypes.c_void_p,  # plaintext
        ]
        lib.ama_aes256_gcm_decrypt.restype = ctypes.c_int

        return True
    except AttributeError:
        return False


# HKDF native availability
_HKDF_NATIVE_AVAILABLE = False

# HKDF-SHA-2 (RFC 5869) native availability — the SHA-256/384/512 PRF variants
# that interoperate with TLS 1.3 / HPKE / non-AMA stacks (the default ama_hkdf
# uses HMAC-SHA3-256).  Mirrors the _HKDF/_HMAC flags; fail-closed.
_HKDF_SHA2_NATIVE_AVAILABLE = False


def _setup_hkdf_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for HKDF functions. Separate from PQC setup."""
    try:
        lib.ama_hkdf.argtypes = [
            ctypes.c_void_p,  # salt
            ctypes.c_size_t,  # salt_len
            ctypes.c_void_p,  # ikm
            ctypes.c_size_t,  # ikm_len
            ctypes.c_void_p,  # info
            ctypes.c_size_t,  # info_len
            ctypes.c_void_p,  # okm
            ctypes.c_size_t,  # okm_len
        ]
        lib.ama_hkdf.restype = ctypes.c_int

        return True
    except AttributeError:
        return False


def _setup_hkdf_sha2_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for the HKDF-SHA-256/384/512 (RFC 5869) variants."""
    try:
        for name in ("ama_hkdf_sha256", "ama_hkdf_sha384", "ama_hkdf_sha512"):
            fn = getattr(lib, name)
            fn.argtypes = [
                ctypes.c_void_p,  # salt
                ctypes.c_size_t,  # salt_len
                ctypes.c_void_p,  # ikm
                ctypes.c_size_t,  # ikm_len
                ctypes.c_void_p,  # info
                ctypes.c_size_t,  # info_len
                ctypes.c_void_p,  # okm
                ctypes.c_size_t,  # okm_len
            ]
            fn.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


# SHA3-256 native availability (raw hash, not HMAC)
_SHA3_256_NATIVE_AVAILABLE = False

# SHA3-512 + SHAKE128/256 native availability (raw hash / XOF, FIPS 202).
# These C symbols existed but were never surfaced to Python, forcing callers
# (crypto_api.hash_message, rfc3161_timestamp) onto stdlib hashlib.  Fail-closed.
_SHA3_EXT_NATIVE_AVAILABLE = False


def _setup_sha3_256_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for raw SHA3-256 hash (FIPS 202)."""
    try:
        lib.ama_sha3_256.argtypes = [
            ctypes.c_char_p,  # input
            ctypes.c_size_t,  # input_len
            ctypes.c_char_p,  # output (32 bytes)
        ]
        lib.ama_sha3_256.restype = ctypes.c_int

        return True
    except AttributeError:
        return False


# SHA-256 one-shot native availability (raw hash, FIPS 180-4).  Surfaces the
# ama_sha256(out, in, inlen) C symbol so crypto_api key_id derivation keeps
# byte-identical SHA-256 semantics without stdlib hashlib (INVARIANT-1/7).
_SHA256_NATIVE_AVAILABLE = False


def _setup_sha256_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for raw one-shot SHA-256 (FIPS 180-4).

    NOTE the argument order differs from ama_sha3_256(input, input_len,
    output): the C symbol is ``void ama_sha256(uint8_t *out, const uint8_t
    *in, size_t inlen)`` — OUTPUT FIRST, void return — so restype is None,
    matching the ama_hmac_sha256 void-return pattern rather than the SHA3
    rc-checked one.
    """
    try:
        lib.ama_sha256.argtypes = [
            ctypes.c_char_p,  # out (32 bytes)
            ctypes.c_char_p,  # in
            ctypes.c_size_t,  # inlen
        ]
        lib.ama_sha256.restype = None
        return True
    except AttributeError:
        return False


def _setup_sha3_ext_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for SHA3-512 and SHAKE128/256 (FIPS 202)."""
    try:
        lib.ama_sha3_512.argtypes = [
            ctypes.c_char_p,  # input
            ctypes.c_size_t,  # input_len
            ctypes.c_char_p,  # output (64 bytes)
        ]
        lib.ama_sha3_512.restype = ctypes.c_int
        for name in ("ama_shake128", "ama_shake256"):
            fn = getattr(lib, name)
            fn.argtypes = [
                ctypes.c_char_p,  # input
                ctypes.c_size_t,  # input_len
                ctypes.c_char_p,  # output
                ctypes.c_size_t,  # output_len
            ]
            fn.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


# HMAC-SHA3-256 native availability (independent of HKDF)
_HMAC_SHA3_256_NATIVE_AVAILABLE = False

# HMAC-SHA-512 native availability (for BIP32 key derivation)
_HMAC_SHA512_NATIVE_AVAILABLE = False

# HMAC-SHA-384 native availability — RFC 2104 / FIPS 198-1.  Surfaces the
# self-contained `ama_hmac_sha384` C symbol (validated against RFC 4231
# test cases 1-7) to Python so consumers that need HMAC-SHA-384 (e.g. JWS
# HS384 signers, TLS PRF variants) don't fall back to stdlib
# `hmac.new(..., 'sha384')` — which would violate INVARIANT-1 ("zero
# external crypto dependencies").  Mirrors the _256/_512 flags exactly.
_HMAC_SHA384_NATIVE_AVAILABLE = False

# HMAC-SHA-256 native availability — FIPS 198-1.  Surfaces the
# ACVP-validated `ama_hmac_sha256` C symbol (150/150 vectors per
# docs/compliance/ACVP_SELF_ATTESTATION.md) to Python so downstream
# consumers (JWT HS256 signers, TLS 1.3 PRF, future HKDF-SHA-256, ...)
# don't have to fall back to stdlib `hmac.new(..., 'sha256')` — which
# would violate INVARIANT-1 ("zero external crypto dependencies") for
# every consumer that imports AMA — and don't have to maintain a
# parallel Mercury-/Omni-side ctypes shim against the same C symbol.
# v3.2.0 closes the inventory gap.
_HMAC_SHA256_NATIVE_AVAILABLE = False


def _setup_hmac_sha512_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for HMAC-SHA-512."""
    try:
        lib.ama_hmac_sha512.argtypes = [
            ctypes.c_char_p,  # key
            ctypes.c_size_t,  # key_len
            ctypes.c_char_p,  # msg
            ctypes.c_size_t,  # msg_len
            ctypes.c_char_p,  # out (64 bytes)
        ]
        lib.ama_hmac_sha512.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


def _setup_hmac_sha384_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for HMAC-SHA-384 (RFC 2104 / FIPS 198-1).

    Single-segment signer only (no `_2` fast-path — HS384, like HS512,
    has no default hot-path caller that would justify one).  Mirrors the
    SHA-512 binding's `restype = c_int` rc-checked contract exactly.
    """
    try:
        lib.ama_hmac_sha384.argtypes = [
            ctypes.c_char_p,  # key
            ctypes.c_size_t,  # key_len
            ctypes.c_char_p,  # msg
            ctypes.c_size_t,  # msg_len
            ctypes.c_char_p,  # out (48 bytes)
        ]
        lib.ama_hmac_sha384.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


def _setup_hmac_sha256_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for HMAC-SHA-256 (FIPS 198-1).

    Two callable entry points are wired:
      * `ama_hmac_sha256(key, key_len, data, data_len, out[32])` —
        the canonical one-shot signer.
      * `ama_hmac_sha256_2(key, key_len, data1, data1_len, data2,
        data2_len, out[32])` — two-segment variant exposed by
        `src/c/ama_hmac_sha256.h`; lets callers avoid concatenating
        when the upstream serializer already provides the message in
        two pieces (matches the existing SPHINCS+ `spx_prf_msg` use).

    Both C functions return `void` (the only failure mode at the C
    level would be invalid pointers, which the wrapper has already
    validated by the time ctypes marshalling completes), so
    `restype = None` here.  Mirrors the SHA-512 / SHA3-256 pattern
    above with the void-return adjustment.
    """
    try:
        lib.ama_hmac_sha256.argtypes = [
            ctypes.c_char_p,  # key
            ctypes.c_size_t,  # key_len
            ctypes.c_char_p,  # data
            ctypes.c_size_t,  # data_len
            ctypes.c_char_p,  # out (32 bytes)
        ]
        lib.ama_hmac_sha256.restype = None
        lib.ama_hmac_sha256_2.argtypes = [
            ctypes.c_char_p,  # key
            ctypes.c_size_t,  # key_len
            ctypes.c_char_p,  # data1
            ctypes.c_size_t,  # data1_len
            ctypes.c_char_p,  # data2
            ctypes.c_size_t,  # data2_len
            ctypes.c_char_p,  # out (32 bytes)
        ]
        lib.ama_hmac_sha256_2.restype = None
        return True
    except AttributeError:
        return False


def _setup_hmac_sha3_256_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for HMAC-SHA3-256. Independent from HKDF setup."""
    try:
        lib.ama_hmac_sha3_256.argtypes = [
            ctypes.c_char_p,  # key
            ctypes.c_size_t,  # key_len
            ctypes.c_char_p,  # msg
            ctypes.c_size_t,  # msg_len
            ctypes.c_char_p,  # out (32 bytes)
        ]
        lib.ama_hmac_sha3_256.restype = ctypes.c_int

        return True
    except AttributeError:
        return False


# secp256k1 native availability
_SECP256K1_NATIVE_AVAILABLE = False


def _setup_secp256k1_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for secp256k1 functions."""
    try:
        lib.ama_secp256k1_pubkey_from_privkey.argtypes = [
            ctypes.c_char_p,  # privkey[32]
            ctypes.c_char_p,  # compressed_pubkey[33]
        ]
        lib.ama_secp256k1_pubkey_from_privkey.restype = ctypes.c_int

        lib.ama_secp256k1_ecdsa_sign.argtypes = [
            ctypes.c_char_p,  # signature (out, >= 72 bytes)
            ctypes.POINTER(ctypes.c_size_t),  # signature_len (out)
            ctypes.c_char_p,  # message[32] (digest)
            ctypes.c_char_p,  # private_key[32]
        ]
        lib.ama_secp256k1_ecdsa_sign.restype = ctypes.c_int

        lib.ama_secp256k1_ecdsa_verify.argtypes = [
            ctypes.c_char_p,  # signature (DER)
            ctypes.c_size_t,  # signature_len
            ctypes.c_char_p,  # message[32] (digest)
            ctypes.c_char_p,  # public_key[64] (X||Y, no 0x04 prefix)
        ]
        lib.ama_secp256k1_ecdsa_verify.restype = ctypes.c_int

        lib.ama_secp256k1_ecdsa_verify_ex.argtypes = [
            ctypes.c_char_p,  # signature (DER)
            ctypes.c_size_t,  # signature_len
            ctypes.c_char_p,  # message[32] (digest)
            ctypes.c_char_p,  # public_key[64] (X||Y, no 0x04 prefix)
            ctypes.c_uint32,  # flags (AMA_SECP256K1_ECDSA_*)
        ]
        lib.ama_secp256k1_ecdsa_verify_ex.restype = ctypes.c_int

        lib.ama_secp256k1_pubkey_decompress.argtypes = [
            ctypes.c_char_p,  # compressed[33]
            ctypes.c_char_p,  # uncompressed[64] (out, X||Y, no prefix)
        ]
        lib.ama_secp256k1_pubkey_decompress.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


# ECDSA verification policy flags (mirror include/ama_cryptography.h).
# Error codes from include/ama_cryptography.h, for the cases where a wrapper
# has to tell "you passed something invalid" apart from "the operation failed".
AMA_ERROR_INVALID_PARAM = -1

AMA_SECP256K1_ECDSA_VERIFY_STRICT = 0
AMA_SECP256K1_ECDSA_ALLOW_HIGH_S = 1


# ============================================================================
# ML-KEM / ML-DSA PARAMETER SETS (FIPS 203 / FIPS 204)
#
# AMA shipped ML-KEM-1024 and ML-DSA-65 only. Both C implementations are now
# parameter-driven, and these bindings expose every set. The pre-existing
# `generate_kyber_keypair` / `dilithium_sign` wrappers further down are
# untouched and still mean ML-KEM-1024 / ML-DSA-65 exactly as before.
# ============================================================================

_ML_KEM_NATIVE_AVAILABLE = False
_ML_DSA_NATIVE_AVAILABLE = False

# Selectors — must match ama_ml_kem_param_set_t / ama_ml_dsa_param_set_t.
ML_KEM_512 = 512
ML_KEM_768 = 768
ML_KEM_1024 = 1024
ML_DSA_44 = 44
ML_DSA_65 = 65
ML_DSA_87 = 87

ML_KEM_PARAM_SETS: tuple = (ML_KEM_512, ML_KEM_768, ML_KEM_1024)
ML_DSA_PARAM_SETS: tuple = (ML_DSA_44, ML_DSA_65, ML_DSA_87)

# Accepted spellings, so callers arriving from an OID, a JWK ``alg`` or a
# config file do not have to normalise first. An unrecognised name raises
# rather than defaulting — silently selecting the wrong security level is the
# worst failure mode a parameter-set API can have.
ML_KEM_BY_NAME: dict = {
    "ML-KEM-512": ML_KEM_512,
    "ML-KEM-768": ML_KEM_768,
    "ML-KEM-1024": ML_KEM_1024,
    "Kyber512": ML_KEM_512,
    "Kyber768": ML_KEM_768,
    "Kyber1024": ML_KEM_1024,
}
ML_DSA_BY_NAME: dict = {
    "ML-DSA-44": ML_DSA_44,
    "ML-DSA-65": ML_DSA_65,
    "ML-DSA-87": ML_DSA_87,
    "Dilithium2": ML_DSA_44,
    "Dilithium3": ML_DSA_65,
    "Dilithium5": ML_DSA_87,
}


def _sizes(**fields: int) -> dict[str, int]:
    """One row of the size tables below.

    Keyword arguments rather than a dict literal on purpose. Bandit's B105
    heuristic reads ``{"secret_key": 1632}`` as a hardcoded credential named
    ``secret_key`` — six false positives on a table of FIPS byte lengths, and
    six inline Bandit suppression markers (each of which INVARIANT-13 requires
    to carry a justification and a tracking ID) would not fit beside the rows
    without breaking them apart. The returned mapping is identical either way,
    so ``ML_KEM_SIZES[ML_KEM_512]["secret_key"]`` still reads as it always has.
    """
    return fields


# FIPS 203 Table 3 / FIPS 204 Table 2. Mirrored here so a caller can size a
# buffer without a native call; the values are cross-checked against the
# library's own size queries by tests/test_pqc_param_sets.py, so drift between
# this table and the C parameter block fails a test rather than truncating a key.
ML_KEM_SIZES: dict = {
    ML_KEM_512: _sizes(public_key=800, secret_key=1632, ciphertext=768),
    ML_KEM_768: _sizes(public_key=1184, secret_key=2400, ciphertext=1088),
    ML_KEM_1024: _sizes(public_key=1568, secret_key=3168, ciphertext=1568),
}
ML_DSA_SIZES: dict = {
    ML_DSA_44: _sizes(public_key=1312, secret_key=2560, signature=2420),
    ML_DSA_65: _sizes(public_key=1952, secret_key=4032, signature=3309),
    ML_DSA_87: _sizes(public_key=2592, secret_key=4896, signature=4627),
}

ML_KEM_SHARED_SECRET_BYTES = 32


def _setup_ml_kem_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for the parameter-driven ML-KEM entry points."""
    try:
        for name in (
            "ama_ml_kem_public_key_bytes",
            "ama_ml_kem_secret_key_bytes",
            "ama_ml_kem_ciphertext_bytes",
        ):
            fn = getattr(lib, name)
            fn.argtypes = [ctypes.c_int]
            fn.restype = ctypes.c_size_t

        lib.ama_ml_kem_param_set_name.argtypes = [ctypes.c_int]
        lib.ama_ml_kem_param_set_name.restype = ctypes.c_char_p

        lib.ama_ml_kem_keypair.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.ama_ml_kem_keypair.restype = ctypes.c_int

        lib.ama_ml_kem_keypair_from_seed.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # d[32]
            ctypes.c_char_p,  # z[32]
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.ama_ml_kem_keypair_from_seed.restype = ctypes.c_int

        lib.ama_ml_kem_pubkey_from_privkey.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # sk
            ctypes.c_size_t,
            ctypes.c_char_p,  # pk (out)
            ctypes.c_size_t,
        ]
        lib.ama_ml_kem_pubkey_from_privkey.restype = ctypes.c_int

        lib.ama_ml_kem_privkey_check.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.ama_ml_kem_privkey_check.restype = ctypes.c_int

        lib.ama_ml_kem_pubkey_check.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.ama_ml_kem_pubkey_check.restype = ctypes.c_int

        lib.ama_ml_kem_encapsulate.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.ama_ml_kem_encapsulate.restype = ctypes.c_int

        lib.ama_ml_kem_decapsulate.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.ama_ml_kem_decapsulate.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


def _setup_ml_dsa_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for the parameter-driven ML-DSA entry points."""
    try:
        for name in (
            "ama_ml_dsa_public_key_bytes",
            "ama_ml_dsa_secret_key_bytes",
            "ama_ml_dsa_signature_bytes",
        ):
            fn = getattr(lib, name)
            fn.argtypes = [ctypes.c_int]
            fn.restype = ctypes.c_size_t

        lib.ama_ml_dsa_param_set_name.argtypes = [ctypes.c_int]
        lib.ama_ml_dsa_param_set_name.restype = ctypes.c_char_p

        lib.ama_ml_dsa_keypair.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
        lib.ama_ml_dsa_keypair.restype = ctypes.c_int

        lib.ama_ml_dsa_keypair_from_seed.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # xi[32]
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        lib.ama_ml_dsa_keypair_from_seed.restype = ctypes.c_int

        lib.ama_ml_dsa_pubkey_from_privkey.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # secret_key
            ctypes.c_char_p,  # public_key (out)
        ]
        lib.ama_ml_dsa_pubkey_from_privkey.restype = ctypes.c_int

        lib.ama_ml_dsa_privkey_check.argtypes = [ctypes.c_int, ctypes.c_char_p]
        lib.ama_ml_dsa_privkey_check.restype = ctypes.c_int

        lib.ama_ml_dsa_sign.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]
        lib.ama_ml_dsa_sign.restype = ctypes.c_int

        lib.ama_ml_dsa_verify.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]
        lib.ama_ml_dsa_verify.restype = ctypes.c_int

        lib.ama_ml_dsa_sign_ctx.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]
        lib.ama_ml_dsa_sign_ctx.restype = ctypes.c_int

        lib.ama_ml_dsa_verify_ctx.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]
        lib.ama_ml_dsa_verify_ctx.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


# ============================================================================
# NIST PRIME CURVES — P-256 / P-384 / P-521
# ============================================================================

# Native availability for the NIST prime curves (src/c/ama_nistp.c).
_NISTP_NATIVE_AVAILABLE = False

# Curve selectors — must match ama_nist_curve_t in include/ama_cryptography.h.
#
# The curve bit-sizes, not a dense 0..2 index: 0 is what an uninitialised or
# forgotten field holds, and a dense index would make that silently mean
# "P-256" (INVARIANT-35). These also do not collide with the ML-KEM or ML-DSA
# selector values, so a call routed to the wrong family is refused.
NISTP_CURVE_P256 = 256
NISTP_CURVE_P384 = 384
NISTP_CURVE_P521 = 521

# Canonical name -> selector.  The aliases are the names these curves actually
# travel under in the ecosystems this support exists for: SEC 1 / OpenSSL
# ("secp256r1", "prime256v1"), JOSE RFC 7518 §6.2.1.1 ("P-256"), and COSE
# RFC 9053 §7.1 (numeric, handled in ama_cryptography.key_formats).
NISTP_CURVES_BY_NAME: dict = {
    "P-256": NISTP_CURVE_P256,
    "P-384": NISTP_CURVE_P384,
    "P-521": NISTP_CURVE_P521,
    "secp256r1": NISTP_CURVE_P256,
    "secp384r1": NISTP_CURVE_P384,
    "secp521r1": NISTP_CURVE_P521,
    "prime256v1": NISTP_CURVE_P256,
}

# Field/scalar octet widths, indexed by selector.
NISTP_FIELD_BYTES: dict = {
    NISTP_CURVE_P256: 32,
    NISTP_CURVE_P384: 48,
    NISTP_CURVE_P521: 66,
}

# The hash each curve is paired with by FIPS 186-5 / RFC 5480 practice.
NISTP_DEFAULT_HASH: dict = {
    NISTP_CURVE_P256: "sha256",
    NISTP_CURVE_P384: "sha384",
    NISTP_CURVE_P521: "sha512",
}

# ECDSA policy flags (mirror include/ama_cryptography.h).
#
# Low-`s` is a property of the sign/verify *pair*. Setting the signing flag
# without the matching verification flag buys nothing — the high twin of the
# resulting signature still verifies — and costs RFC 6979 conformance. See
# INVARIANT-34.
AMA_NISTP_ECDSA_SIGN_DEFAULT = 0
AMA_NISTP_ECDSA_SIGN_LOW_S = 1
AMA_NISTP_ECDSA_SIGN_HEDGED = 2

AMA_NISTP_ECDSA_VERIFY_DEFAULT = 0
AMA_NISTP_ECDSA_REQUIRE_LOW_S = 1

# Longest DER signature across the supported curves (P-521, long-form length).
NISTP_MAX_SIG_LEN = 141


def _setup_nistp_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for the NIST prime-curve functions."""
    try:
        lib.ama_nistp_field_bytes.argtypes = [ctypes.c_int]
        lib.ama_nistp_field_bytes.restype = ctypes.c_size_t

        lib.ama_nistp_pubkey_bytes.argtypes = [ctypes.c_int]
        lib.ama_nistp_pubkey_bytes.restype = ctypes.c_size_t

        lib.ama_nistp_sig_der_max_len.argtypes = [ctypes.c_int]
        lib.ama_nistp_sig_der_max_len.restype = ctypes.c_size_t

        lib.ama_nistp_curve_name.argtypes = [ctypes.c_int]
        lib.ama_nistp_curve_name.restype = ctypes.c_char_p

        lib.ama_nistp_keypair.argtypes = [
            ctypes.c_int,  # curve
            ctypes.c_char_p,  # private_key (out)
            ctypes.c_char_p,  # public_key (out)
        ]
        lib.ama_nistp_keypair.restype = ctypes.c_int

        lib.ama_nistp_pubkey_from_privkey.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # private_key
            ctypes.c_char_p,  # public_key (out)
        ]
        lib.ama_nistp_pubkey_from_privkey.restype = ctypes.c_int

        lib.ama_nistp_pubkey_validate.argtypes = [ctypes.c_int, ctypes.c_char_p]
        lib.ama_nistp_pubkey_validate.restype = ctypes.c_int

        lib.ama_nistp_point_encode.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # public_key (X||Y)
            ctypes.c_int,  # compressed
            ctypes.c_char_p,  # out
            ctypes.POINTER(ctypes.c_size_t),  # out_len
        ]
        lib.ama_nistp_point_encode.restype = ctypes.c_int

        lib.ama_nistp_point_decode.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # in (SEC 1 prefixed)
            ctypes.c_size_t,  # in_len
            ctypes.c_char_p,  # public_key (out, X||Y)
        ]
        lib.ama_nistp_point_decode.restype = ctypes.c_int

        lib.ama_nistp_ecdh.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # private_key
            ctypes.c_char_p,  # peer_public_key (X||Y)
            ctypes.c_char_p,  # shared_secret (out)
        ]
        lib.ama_nistp_ecdh.restype = ctypes.c_int

        lib.ama_nistp_ecdsa_sign.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # digest
            ctypes.c_size_t,  # digest_len
            ctypes.c_char_p,  # private_key
            ctypes.c_char_p,  # signature (out, DER)
            ctypes.POINTER(ctypes.c_size_t),  # signature_len (out)
        ]
        lib.ama_nistp_ecdsa_sign.restype = ctypes.c_int

        lib.ama_nistp_ecdsa_sign_hedged.argtypes = lib.ama_nistp_ecdsa_sign.argtypes
        lib.ama_nistp_ecdsa_sign_hedged.restype = ctypes.c_int

        lib.ama_nistp_ecdsa_sign_ex.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # digest
            ctypes.c_size_t,  # digest_len
            ctypes.c_char_p,  # private_key
            ctypes.c_char_p,  # signature (out, DER)
            ctypes.POINTER(ctypes.c_size_t),  # signature_len (out)
            ctypes.c_uint32,  # flags (AMA_NISTP_ECDSA_SIGN_*)
        ]
        lib.ama_nistp_ecdsa_sign_ex.restype = ctypes.c_int

        lib.ama_nistp_ecdsa_sign_raw.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # digest
            ctypes.c_size_t,  # digest_len
            ctypes.c_char_p,  # private_key
            ctypes.c_char_p,  # signature (out, r||s)
        ]
        lib.ama_nistp_ecdsa_sign_raw.restype = ctypes.c_int

        lib.ama_nistp_ecdsa_sign_raw_ex.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # digest
            ctypes.c_size_t,  # digest_len
            ctypes.c_char_p,  # private_key
            ctypes.c_char_p,  # signature (out, r||s)
            ctypes.c_uint32,  # flags (AMA_NISTP_ECDSA_SIGN_*)
        ]
        lib.ama_nistp_ecdsa_sign_raw_ex.restype = ctypes.c_int

        lib.ama_nistp_ecdsa_verify_ex.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # digest
            ctypes.c_size_t,  # digest_len
            ctypes.c_char_p,  # public_key
            ctypes.c_char_p,  # signature (DER)
            ctypes.c_size_t,  # signature_len
            ctypes.c_uint32,  # flags
        ]
        lib.ama_nistp_ecdsa_verify_ex.restype = ctypes.c_int

        lib.ama_nistp_ecdsa_verify_raw_ex.argtypes = lib.ama_nistp_ecdsa_verify_ex.argtypes
        lib.ama_nistp_ecdsa_verify_raw_ex.restype = ctypes.c_int

        lib.ama_nistp_sig_der_to_raw.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # der
            ctypes.c_size_t,  # der_len
            ctypes.c_char_p,  # raw (out)
            ctypes.POINTER(ctypes.c_size_t),  # raw_len (out)
        ]
        lib.ama_nistp_sig_der_to_raw.restype = ctypes.c_int

        lib.ama_nistp_sig_raw_to_der.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,  # raw
            ctypes.c_size_t,  # raw_len
            ctypes.c_char_p,  # der (out)
            ctypes.POINTER(ctypes.c_size_t),  # der_len (out)
        ]
        lib.ama_nistp_sig_raw_to_der.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


# ============================================================================
# HSS / LMS — RFC 8554 (verification only; see the wrapper section below)
# ============================================================================

# Native availability for the HSS/LMS verifier (src/c/ama_lms.c).
_LMS_NATIVE_AVAILABLE = False

# Transcribed from include/ama_cryptography.h; the identical spelling is what
# lets tools/check_version_consistency.py check the transcription rather than
# trust it.
AMA_LMS_PUBKEY_LEN = 56
AMA_HSS_PUBKEY_LEN = 60
AMA_HSS_MAX_LEVELS = 8

# RFC 8554 IANA registry. Named rather than numeric at the call site because a
# selector that resolves to a neighbour is the failure INVARIANT-35 exists to
# prevent, and a bare `4` next to a bare `5` in two different registries is
# exactly how that happens.
AMA_LMOTS_SHA256_N32_W1 = 1
AMA_LMOTS_SHA256_N32_W2 = 2
AMA_LMOTS_SHA256_N32_W4 = 3
AMA_LMOTS_SHA256_N32_W8 = 4

AMA_LMS_SHA256_M32_H5 = 5
AMA_LMS_SHA256_M32_H10 = 6
AMA_LMS_SHA256_M32_H15 = 7
AMA_LMS_SHA256_M32_H20 = 8
AMA_LMS_SHA256_M32_H25 = 9

#: Winternitz width by LM-OTS typecode (RFC 8554 Table 1).
LMOTS_WINTERNITZ_W: dict = {
    AMA_LMOTS_SHA256_N32_W1: 1,
    AMA_LMOTS_SHA256_N32_W2: 2,
    AMA_LMOTS_SHA256_N32_W4: 4,
    AMA_LMOTS_SHA256_N32_W8: 8,
}

#: Tree height by LMS typecode (RFC 8554 Table 2).
LMS_TREE_HEIGHT: dict = {
    AMA_LMS_SHA256_M32_H5: 5,
    AMA_LMS_SHA256_M32_H10: 10,
    AMA_LMS_SHA256_M32_H15: 15,
    AMA_LMS_SHA256_M32_H20: 20,
    AMA_LMS_SHA256_M32_H25: 25,
}


def _setup_lms_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for the HSS/LMS verification functions."""
    try:
        lib.ama_lms_signing_available.argtypes = []
        lib.ama_lms_signing_available.restype = ctypes.c_int

        lib.ama_lms_pubkey_params.argtypes = [
            ctypes.c_char_p,  # pubkey
            ctypes.c_size_t,  # pubkey_len
            ctypes.POINTER(ctypes.c_uint32),  # lms_type (out)
            ctypes.POINTER(ctypes.c_uint32),  # lmots_type (out)
            ctypes.POINTER(ctypes.c_uint32),  # h (out)
            ctypes.POINTER(ctypes.c_uint32),  # w (out)
        ]
        lib.ama_lms_pubkey_params.restype = ctypes.c_int

        lib.ama_lms_signature_length.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        lib.ama_lms_signature_length.restype = ctypes.c_size_t

        lib.ama_lms_verify.argtypes = [
            ctypes.c_char_p,  # message
            ctypes.c_size_t,  # message_len
            ctypes.c_char_p,  # signature
            ctypes.c_size_t,  # signature_len
            ctypes.c_char_p,  # pubkey
            ctypes.c_size_t,  # pubkey_len
        ]
        lib.ama_lms_verify.restype = ctypes.c_int

        lib.ama_hss_pubkey_levels.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        lib.ama_hss_pubkey_levels.restype = ctypes.c_int

        lib.ama_hss_verify.argtypes = lib.ama_lms_verify.argtypes
        lib.ama_hss_verify.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


# X25519 native availability
_X25519_NATIVE_AVAILABLE = False


def _setup_x25519_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for X25519 functions."""
    try:
        lib.ama_x25519_keypair.argtypes = [
            ctypes.c_char_p,  # public_key[32]
            ctypes.c_char_p,  # secret_key[32]
        ]
        lib.ama_x25519_keypair.restype = ctypes.c_int

        lib.ama_x25519_key_exchange.argtypes = [
            ctypes.c_char_p,  # shared_secret[32]
            ctypes.c_char_p,  # our_secret_key[32]
            ctypes.c_char_p,  # their_public_key[32]
        ]
        lib.ama_x25519_key_exchange.restype = ctypes.c_int

        # Batched X25519: out[count][32], scalars[count][32], points[count][32].
        # ctypes treats fixed-shape `uint8_t (*)[32]` as opaque void* at this
        # layer; the Python wrapper packs a `bytes` blob of length count*32
        # for each parameter and `ctypes.c_char_p` carries the pointer.
        # `hasattr` guard so a pre-batch-API native build still exposes the
        # core keypair / key-exchange path — without this, `AttributeError`
        # would propagate to the except clause and disable ALL of X25519
        # rather than just the additive batch wrapper.  Same pattern as
        # the Argon2id legacy-shim guard below.
        if hasattr(lib, "ama_x25519_scalarmult_batch"):
            lib.ama_x25519_scalarmult_batch.argtypes = [
                ctypes.c_char_p,  # out      (count × 32 bytes)
                ctypes.c_char_p,  # scalars  (count × 32 bytes)
                ctypes.c_char_p,  # points   (count × 32 bytes)
                ctypes.c_size_t,  # count
            ]
            lib.ama_x25519_scalarmult_batch.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


# Argon2id native availability
_ARGON2_NATIVE_AVAILABLE = False

# Application-sane ceiling on Argon2id output/tag length.  RFC 9106 §3.2
# permits out_len up to 2^32-1, but every real deployment uses 16–64
# bytes; 1024 is 32× the default tag length and leaves ample headroom
# while bounding worst-case CPU + memory in
# ``ama_argon2id_legacy_verify``'s ``calloc(tag_len, 1)`` path.  Kept in
# sync with ``AMA_ARGON2ID_MAX_TAG_LEN`` in ``include/ama_cryptography.h``.
_ARGON2ID_MAX_TAG_LEN = 1024


def _setup_argon2_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for Argon2id functions."""
    try:
        lib.ama_argon2id.argtypes = [
            ctypes.c_char_p,  # password
            ctypes.c_size_t,  # pwd_len
            ctypes.c_char_p,  # salt
            ctypes.c_size_t,  # salt_len
            ctypes.c_uint32,  # t_cost
            ctypes.c_uint32,  # m_cost
            ctypes.c_uint32,  # parallelism
            ctypes.c_char_p,  # output
            ctypes.c_size_t,  # out_len
        ]
        lib.ama_argon2id.restype = ctypes.c_int
        # Legacy-verify shim (CHANGELOG [3.0.0] § BREAKING). Optional —
        # absence just means the legacy migration path is unavailable.
        if hasattr(lib, "ama_argon2id_legacy"):
            lib.ama_argon2id_legacy.argtypes = lib.ama_argon2id.argtypes
            lib.ama_argon2id_legacy.restype = ctypes.c_int
        if hasattr(lib, "ama_argon2id_legacy_verify"):
            lib.ama_argon2id_legacy_verify.argtypes = [
                ctypes.c_char_p,  # password
                ctypes.c_size_t,  # pwd_len
                ctypes.c_char_p,  # salt
                ctypes.c_size_t,  # salt_len
                ctypes.c_uint32,  # t_cost
                ctypes.c_uint32,  # m_cost
                ctypes.c_uint32,  # parallelism
                ctypes.c_char_p,  # expected_tag
                ctypes.c_size_t,  # tag_len
            ]
            lib.ama_argon2id_legacy_verify.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


# ChaCha20-Poly1305 native availability
_CHACHA20_POLY1305_NATIVE_AVAILABLE = False


def _setup_chacha20poly1305_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for ChaCha20-Poly1305 functions."""
    try:
        lib.ama_chacha20poly1305_encrypt.argtypes = [
            ctypes.c_char_p,  # key[32]
            ctypes.c_char_p,  # nonce[12]
            ctypes.c_char_p,  # plaintext
            ctypes.c_size_t,  # pt_len
            ctypes.c_char_p,  # aad
            ctypes.c_size_t,  # aad_len
            ctypes.c_char_p,  # ciphertext
            ctypes.c_char_p,  # tag[16]
        ]
        lib.ama_chacha20poly1305_encrypt.restype = ctypes.c_int

        lib.ama_chacha20poly1305_decrypt.argtypes = [
            ctypes.c_char_p,  # key[32]
            ctypes.c_char_p,  # nonce[12]
            ctypes.c_char_p,  # ciphertext
            ctypes.c_size_t,  # ct_len
            ctypes.c_char_p,  # aad
            ctypes.c_size_t,  # aad_len
            ctypes.c_char_p,  # tag[16]
            ctypes.c_char_p,  # plaintext
        ]
        lib.ama_chacha20poly1305_decrypt.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


# Deterministic keygen native availability
_DETERMINISTIC_KEYGEN_AVAILABLE = False


def _setup_deterministic_keygen_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for deterministic keygen functions."""
    try:
        lib.ama_kyber_keypair_from_seed.argtypes = [
            ctypes.c_char_p,  # d[32]
            ctypes.c_char_p,  # z[32]
            ctypes.c_char_p,  # pk
            ctypes.c_char_p,  # sk
        ]
        lib.ama_kyber_keypair_from_seed.restype = ctypes.c_int

        lib.ama_dilithium_keypair_from_seed.argtypes = [
            ctypes.c_char_p,  # xi[32]
            ctypes.c_char_p,  # public_key
            ctypes.c_char_p,  # secret_key
        ]
        lib.ama_dilithium_keypair_from_seed.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


# FROST threshold Ed25519 (RFC 9591) availability
_FROST_AVAILABLE = False
_FROST_BACKEND: Optional[str] = None
FROST_SHARE_BYTES = 64  # 32 secret + 32 public
FROST_NONCE_BYTES = 64  # 32 hiding + 32 binding
FROST_COMMITMENT_BYTES = 64  # 32 hiding_point + 32 binding_point
FROST_SIG_SHARE_BYTES = 32


def _setup_frost_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for FROST threshold Ed25519 functions."""
    try:
        lib.ama_frost_keygen_trusted_dealer.argtypes = [
            ctypes.c_uint8,  # threshold
            ctypes.c_uint8,  # num_participants
            ctypes.c_char_p,  # group_public_key
            ctypes.c_char_p,  # participant_shares
            ctypes.c_char_p,  # secret_key (nullable)
        ]
        lib.ama_frost_keygen_trusted_dealer.restype = ctypes.c_int

        lib.ama_frost_round1_commit.argtypes = [
            ctypes.c_char_p,  # nonce_pair
            ctypes.c_char_p,  # commitment
            ctypes.c_char_p,  # participant_share
        ]
        lib.ama_frost_round1_commit.restype = ctypes.c_int

        lib.ama_frost_round2_sign.argtypes = [
            ctypes.c_char_p,  # sig_share
            ctypes.c_char_p,  # message
            ctypes.c_size_t,  # message_len
            ctypes.c_char_p,  # participant_share
            ctypes.c_uint8,  # participant_index
            ctypes.c_char_p,  # nonce_pair
            ctypes.c_char_p,  # commitments
            ctypes.c_char_p,  # signer_indices
            ctypes.c_uint8,  # num_signers
            ctypes.c_char_p,  # group_public_key
        ]
        lib.ama_frost_round2_sign.restype = ctypes.c_int

        lib.ama_frost_aggregate.argtypes = [
            ctypes.c_char_p,  # signature
            ctypes.c_char_p,  # sig_shares
            ctypes.c_char_p,  # commitments
            ctypes.c_char_p,  # signer_indices
            ctypes.c_uint8,  # num_signers
            ctypes.c_char_p,  # message
            ctypes.c_size_t,  # message_len
            ctypes.c_char_p,  # group_public_key
        ]
        lib.ama_frost_aggregate.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


# Context-based API availability (ama_context_init / ama_context_free etc.)
_CONTEXT_API_AVAILABLE = False


def _setup_context_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for the opaque-context C API (ama_context_init et al.)."""
    try:
        # ama_context_t* ama_context_init(ama_algorithm_t algorithm)
        lib.ama_context_init.argtypes = [ctypes.c_int]
        lib.ama_context_init.restype = ctypes.c_void_p

        # void ama_context_free(ama_context_t* ctx)
        lib.ama_context_free.argtypes = [ctypes.c_void_p]
        lib.ama_context_free.restype = None

        # ama_error_t ama_keypair_generate(ctx, pubkey, pubkey_len, seckey, seckey_len)
        lib.ama_keypair_generate.argtypes = [
            ctypes.c_void_p,  # ctx
            ctypes.c_char_p,  # public_key
            ctypes.c_size_t,  # public_key_len
            ctypes.c_char_p,  # secret_key
            ctypes.c_size_t,  # secret_key_len
        ]
        lib.ama_keypair_generate.restype = ctypes.c_int

        # ama_error_t ama_sign(ctx, msg, msg_len, sk, sk_len, sig, sig_len*)
        lib.ama_sign.argtypes = [
            ctypes.c_void_p,  # ctx
            ctypes.c_char_p,  # message
            ctypes.c_size_t,  # message_len
            ctypes.c_char_p,  # secret_key
            ctypes.c_size_t,  # secret_key_len
            ctypes.c_char_p,  # signature
            ctypes.POINTER(ctypes.c_size_t),  # signature_len (in/out)
        ]
        lib.ama_sign.restype = ctypes.c_int

        # ama_error_t ama_verify(ctx, msg, msg_len, sig, sig_len, pk, pk_len)
        lib.ama_verify.argtypes = [
            ctypes.c_void_p,  # ctx
            ctypes.c_char_p,  # message
            ctypes.c_size_t,  # message_len
            ctypes.c_char_p,  # signature
            ctypes.c_size_t,  # signature_len
            ctypes.c_char_p,  # public_key
            ctypes.c_size_t,  # public_key_len
        ]
        lib.ama_verify.restype = ctypes.c_int

        # ama_error_t ama_kem_encapsulate(ctx, pk, pk_len, ct, ct_len*, ss, ss_len)
        lib.ama_kem_encapsulate.argtypes = [
            ctypes.c_void_p,  # ctx
            ctypes.c_char_p,  # public_key
            ctypes.c_size_t,  # public_key_len
            ctypes.c_char_p,  # ciphertext
            ctypes.POINTER(ctypes.c_size_t),  # ciphertext_len (in/out)
            ctypes.c_char_p,  # shared_secret
            ctypes.c_size_t,  # shared_secret_len
        ]
        lib.ama_kem_encapsulate.restype = ctypes.c_int

        # ama_error_t ama_kem_decapsulate(ctx, ct, ct_len, sk, sk_len, ss, ss_len)
        lib.ama_kem_decapsulate.argtypes = [
            ctypes.c_void_p,  # ctx
            ctypes.c_char_p,  # ciphertext
            ctypes.c_size_t,  # ciphertext_len
            ctypes.c_char_p,  # secret_key
            ctypes.c_size_t,  # secret_key_len
            ctypes.c_char_p,  # shared_secret
            ctypes.c_size_t,  # shared_secret_len
        ]
        lib.ama_kem_decapsulate.restype = ctypes.c_int

        return True
    except AttributeError:
        return False


_native_lib = _find_native_library()
if _native_lib is not None:
    if _setup_native_ctypes(_native_lib):
        _DILITHIUM_AVAILABLE = True
        _DILITHIUM_BACKEND = "native"
        _KYBER_AVAILABLE = True
        _KYBER_BACKEND = "native"
        _SPHINCS_AVAILABLE = True
        _SPHINCS_BACKEND = "native"
    _ED25519_NATIVE_AVAILABLE = _setup_ed25519_ctypes(_native_lib)
    _AES_GCM_NATIVE_AVAILABLE = _setup_aes_gcm_ctypes(_native_lib)
    _HKDF_NATIVE_AVAILABLE = _setup_hkdf_ctypes(_native_lib)
    _HKDF_SHA2_NATIVE_AVAILABLE = _setup_hkdf_sha2_ctypes(_native_lib)
    _SHA3_256_NATIVE_AVAILABLE = _setup_sha3_256_ctypes(_native_lib)
    _SHA256_NATIVE_AVAILABLE = _setup_sha256_ctypes(_native_lib)
    _SHA3_EXT_NATIVE_AVAILABLE = _setup_sha3_ext_ctypes(_native_lib)
    _HMAC_SHA3_256_NATIVE_AVAILABLE = _setup_hmac_sha3_256_ctypes(_native_lib)
    _HMAC_SHA512_NATIVE_AVAILABLE = _setup_hmac_sha512_ctypes(_native_lib)
    _HMAC_SHA384_NATIVE_AVAILABLE = _setup_hmac_sha384_ctypes(_native_lib)
    _HMAC_SHA256_NATIVE_AVAILABLE = _setup_hmac_sha256_ctypes(_native_lib)
    _SECP256K1_NATIVE_AVAILABLE = _setup_secp256k1_ctypes(_native_lib)
    _NISTP_NATIVE_AVAILABLE = _setup_nistp_ctypes(_native_lib)
    _LMS_NATIVE_AVAILABLE = _setup_lms_ctypes(_native_lib)
    _ML_KEM_NATIVE_AVAILABLE = _setup_ml_kem_ctypes(_native_lib)
    _ML_DSA_NATIVE_AVAILABLE = _setup_ml_dsa_ctypes(_native_lib)
    _X25519_NATIVE_AVAILABLE = _setup_x25519_ctypes(_native_lib)
    _ARGON2_NATIVE_AVAILABLE = _setup_argon2_ctypes(_native_lib)
    _CHACHA20_POLY1305_NATIVE_AVAILABLE = _setup_chacha20poly1305_ctypes(_native_lib)
    _DETERMINISTIC_KEYGEN_AVAILABLE = _setup_deterministic_keygen_ctypes(_native_lib)
    _FROST_AVAILABLE = _setup_frost_ctypes(_native_lib)
    if _FROST_AVAILABLE:
        _FROST_BACKEND = "native"
    _CONTEXT_API_AVAILABLE = _setup_context_ctypes(_native_lib)


# Public API for checking availability
DILITHIUM_AVAILABLE: bool = _DILITHIUM_AVAILABLE
DILITHIUM_BACKEND: Optional[str] = _DILITHIUM_BACKEND
KYBER_AVAILABLE: bool = _KYBER_AVAILABLE
KYBER_BACKEND: Optional[str] = _KYBER_BACKEND
SPHINCS_AVAILABLE: bool = _SPHINCS_AVAILABLE
SPHINCS_BACKEND: Optional[str] = _SPHINCS_BACKEND

# SHA3-256 (raw hash) native availability — consumed by get_pqc_backend_info()
# and exported for downstream callers that need to check native SHA3 support.
SHA3_256_NATIVE_AVAILABLE: bool = _SHA3_256_NATIVE_AVAILABLE

# HMAC-SHA3-256 availability — determined at import time.
# Cython binding is probed later (after function definitions), so we
# expose ctypes availability now and patch after the Cython probe.
HMAC_SHA3_256_AVAILABLE: bool = _HMAC_SHA3_256_NATIVE_AVAILABLE
HMAC_SHA3_256_BACKEND: Optional[str] = "native" if _HMAC_SHA3_256_NATIVE_AVAILABLE else None

# Public mirrors for the families added alongside the parameter-set work. Every
# pre-existing family has one; without these the only way to ask "is the
# NIST-P backend present?" was to read a module-private underscore name or to
# call a function and catch — which is asking by side effect.
ML_KEM_NATIVE_AVAILABLE: bool = _ML_KEM_NATIVE_AVAILABLE
ML_DSA_NATIVE_AVAILABLE: bool = _ML_DSA_NATIVE_AVAILABLE
NISTP_NATIVE_AVAILABLE: bool = _NISTP_NATIVE_AVAILABLE
LMS_NATIVE_AVAILABLE: bool = _LMS_NATIVE_AVAILABLE
SECP256K1_NATIVE_AVAILABLE: bool = _SECP256K1_NATIVE_AVAILABLE

# =============================================================================
# SECURITY WARNINGS AND CONSTANT-TIME ENFORCEMENT
# =============================================================================

# Installation instruction (must be defined before constant-time enforcement)
_INSTALL_HINT = (
    "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
)

# Deprecation warning for AMA_REQUIRE_CONSTANT_TIME (superseded by INVARIANT-7 revised)
if os.environ.get("AMA_REQUIRE_CONSTANT_TIME"):
    logging.getLogger(__name__).warning(
        "AMA_REQUIRE_CONSTANT_TIME is set but no longer needed: "
        "INVARIANT-7 (revised) enforces native-only operation unconditionally. "
        "This env var has no effect and should be removed from your configuration."
    )

# Enforce constant-time requirement if AMA_REQUIRE_CONSTANT_TIME is set
if AMA_REQUIRE_CONSTANT_TIME:
    if not _DILITHIUM_AVAILABLE:
        raise PQCUnavailableError(
            "PQC_UNAVAILABLE: AMA_REQUIRE_CONSTANT_TIME is set but no "
            "constant-time PQC backend is available. " + _INSTALL_HINT
        )

# Key sizes per NIST FIPS 203/204/205 specifications
# ML-DSA-65 (Dilithium3)
DILITHIUM_PUBLIC_KEY_BYTES = 1952
DILITHIUM_SECRET_KEY_BYTES = 4032
DILITHIUM_SIGNATURE_BYTES = 3309

# Kyber-1024
KYBER_PUBLIC_KEY_BYTES = 1568
KYBER_SECRET_KEY_BYTES = 3168
KYBER_CIPHERTEXT_BYTES = 1568
KYBER_SHARED_SECRET_BYTES = 32

# SPHINCS+-SHA2-256f-simple (legacy aliases for SLH-DSA-SHA2-256f-simple)
SPHINCS_PUBLIC_KEY_BYTES = 64
SPHINCS_SECRET_KEY_BYTES = 128
SPHINCS_SIGNATURE_BYTES = 49856

# SLH-DSA (FIPS 205) — parameter set sizes.
SLHDSA_SHA2_256F_PUBLIC_KEY_BYTES = 64
SLHDSA_SHA2_256F_SECRET_KEY_BYTES = 128
SLHDSA_SHA2_256F_SIGNATURE_BYTES = 49856

SLHDSA_SHAKE_128S_PUBLIC_KEY_BYTES = 32
SLHDSA_SHAKE_128S_SECRET_KEY_BYTES = 64
SLHDSA_SHAKE_128S_SIGNATURE_BYTES = 7856

# Param set selector values must match ama_slhdsa_param_set_t in the header.
_AMA_SLHDSA_SHA2_256F = 0
_AMA_SLHDSA_SHAKE_128S = 1

_SLHDSA_PARAM_SETS = {
    "SHA2-256f": (
        _AMA_SLHDSA_SHA2_256F,
        SLHDSA_SHA2_256F_PUBLIC_KEY_BYTES,
        SLHDSA_SHA2_256F_SECRET_KEY_BYTES,
        SLHDSA_SHA2_256F_SIGNATURE_BYTES,
        32,  # n
    ),
    "SHAKE-128s": (
        _AMA_SLHDSA_SHAKE_128S,
        SLHDSA_SHAKE_128S_PUBLIC_KEY_BYTES,
        SLHDSA_SHAKE_128S_SECRET_KEY_BYTES,
        SLHDSA_SHAKE_128S_SIGNATURE_BYTES,
        16,  # n
    ),
}

# Ed25519 (RFC 8032)
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SECRET_KEY_BYTES = 64
ED25519_SIGNATURE_BYTES = 64

# AES-256-GCM (NIST SP 800-38D)
AES256_KEY_BYTES = 32
AES256_GCM_NONCE_BYTES = 12
AES256_GCM_TAG_BYTES = 16

# secp256k1 (BIP32)
SECP256K1_PRIVKEY_BYTES = 32
SECP256K1_PUBKEY_BYTES = 33

# X25519 (RFC 7748)
X25519_KEY_BYTES = 32

# ChaCha20-Poly1305 (RFC 8439)
POLY1305_TAG_BYTES = 16

# ============================================================================
# ERROR MESSAGE CONSTANTS
# ============================================================================

# Unknown backend state error messages (should never occur in normal operation)
_DILITHIUM_UNKNOWN_STATE = "PQC_UNAVAILABLE: Unknown backend state"
_KYBER_UNKNOWN_STATE = "KYBER_UNAVAILABLE: Unknown backend state"
_SPHINCS_UNKNOWN_STATE = "SPHINCS_UNAVAILABLE: Unknown backend state"

# Backend unavailable error messages
_DILITHIUM_UNAVAILABLE_MSG = f"PQC_UNAVAILABLE: Dilithium backend not available. {_INSTALL_HINT}"
_KYBER_UNAVAILABLE_MSG = f"KYBER_UNAVAILABLE: Kyber-1024 backend not available. {_INSTALL_HINT}"
_SPHINCS_UNAVAILABLE_MSG = (
    f"SPHINCS_UNAVAILABLE: SPHINCS+-256f backend not available. {_INSTALL_HINT}"
)


class AmaContext:
    """
    Python wrapper around the opaque ``ama_context_t`` C context.

    Provides a context-manager interface so the underlying C context is always
    freed (and key material scrubbed) when the ``with`` block exits — even on
    exceptions.

    Algorithm constants (``ama_algorithm_t`` enum values from the C header):

    - ``AmaContext.ALG_ML_DSA_65`` = 0
    - ``AmaContext.ALG_KYBER_1024`` = 1
    - ``AmaContext.ALG_SPHINCS_256F`` = 2
    - ``AmaContext.ALG_ED25519`` = 3
    - ``AmaContext.ALG_HYBRID`` = 4

    Example::

        with AmaContext(AmaContext.ALG_ML_DSA_65) as ctx:
            rc = ctx.keypair_generate(pub_buf, len(pub_buf), sec_buf, len(sec_buf))
    """

    # ama_algorithm_t enum values
    ALG_ML_DSA_65 = 0
    ALG_KYBER_1024 = 1
    ALG_SPHINCS_256F = 2
    ALG_ED25519 = 3
    ALG_HYBRID = 4

    def __init__(self, algorithm: int) -> None:
        if not _CONTEXT_API_AVAILABLE or _native_lib is None:
            raise PQCUnavailableError(
                "Context-based C API is not available. "
                "Build native C library with AMA_USE_NATIVE_PQC=ON."
            )
        self._ctx = _native_lib.ama_context_init(algorithm)
        if not self._ctx:
            raise RuntimeError(
                f"ama_context_init failed for algorithm={algorithm}. "
                "Ensure the native library is built correctly."
            )

    # ------------------------------------------------------------------
    # Context-manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "AmaContext":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        """Free the underlying C context and scrub key material."""
        # Atomic swap: prevents double-free if close() is called more than once.
        ctx, self._ctx = self._ctx, None
        if ctx is not None and _native_lib is not None:
            _native_lib.ama_context_free(ctx)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception as exc:  # — INVARIANT-3/9: __del__ must not raise (FIN-AMA-001)
            record_finalizer_error("AmaContext", f"close() failed: {exc}")

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def keypair_generate(
        self,
        public_key: ctypes.Array,
        public_key_len: int,
        secret_key: ctypes.Array,
        secret_key_len: int,
    ) -> int:
        """Call ``ama_keypair_generate``. Returns ``AMA_SUCCESS`` (0) on success."""
        self._require_open()
        return int(
            _native_lib.ama_keypair_generate(
                self._ctx, public_key, public_key_len, secret_key, secret_key_len
            )
        )

    # ------------------------------------------------------------------
    # Signature operations
    # ------------------------------------------------------------------

    def sign(
        self,
        message: bytes,
        secret_key: bytes,
        signature: ctypes.Array,
        signature_len: "ctypes._Pointer[ctypes.c_size_t]",
    ) -> int:
        """Call ``ama_sign``. Returns ``AMA_SUCCESS`` (0) on success."""
        self._require_open()
        return int(
            _native_lib.ama_sign(
                self._ctx,
                message,
                len(message),
                secret_key,
                len(secret_key),
                signature,
                signature_len,
            )
        )

    def verify(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes,
    ) -> int:
        """
        Call ``ama_verify``.

        Returns ``AMA_SUCCESS`` (0) if the signature is valid,
        ``AMA_ERROR_VERIFY_FAILED`` (-4) if it is not.
        """
        self._require_open()
        return int(
            _native_lib.ama_verify(
                self._ctx,
                message,
                len(message),
                signature,
                len(signature),
                public_key,
                len(public_key),
            )
        )

    # ------------------------------------------------------------------
    # KEM operations (Kyber-1024 context)
    # ------------------------------------------------------------------

    def kem_encapsulate(
        self,
        public_key: bytes,
        ciphertext: ctypes.Array,
        ciphertext_len: "ctypes._Pointer[ctypes.c_size_t]",
        shared_secret: ctypes.Array,
        shared_secret_len: int,
    ) -> int:
        """Call ``ama_kem_encapsulate``. Returns ``AMA_SUCCESS`` (0) on success."""
        self._require_open()
        return int(
            _native_lib.ama_kem_encapsulate(
                self._ctx,
                public_key,
                len(public_key),
                ciphertext,
                ciphertext_len,
                shared_secret,
                shared_secret_len,
            )
        )

    def kem_decapsulate(
        self,
        ciphertext: bytes,
        secret_key: bytes,
        shared_secret: ctypes.Array,
        shared_secret_len: int,
    ) -> int:
        """Call ``ama_kem_decapsulate``. Returns ``AMA_SUCCESS`` (0) on success."""
        self._require_open()
        return int(
            _native_lib.ama_kem_decapsulate(
                self._ctx,
                ciphertext,
                len(ciphertext),
                secret_key,
                len(secret_key),
                shared_secret,
                shared_secret_len,
            )
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_open(self) -> None:
        if self._ctx is None:
            raise RuntimeError("AmaContext has already been closed.")


def get_pqc_status() -> PQCStatus:
    """
    Get current PQC backend status.

    Returns:
        PQCStatus.AVAILABLE if any PQC backend is available
        PQCStatus.UNAVAILABLE otherwise
    """
    if DILITHIUM_AVAILABLE or KYBER_AVAILABLE or SPHINCS_AVAILABLE:
        return PQCStatus.AVAILABLE
    return PQCStatus.UNAVAILABLE


def get_pqc_backend_info() -> dict:
    """
    Get detailed information about PQC backend availability.

    Returns:
        Dictionary with backend status and details for all algorithms
    """
    return {
        "status": get_pqc_status().value,
        "dilithium_available": DILITHIUM_AVAILABLE,
        "dilithium_backend": DILITHIUM_BACKEND,
        "kyber_available": KYBER_AVAILABLE,
        "kyber_backend": KYBER_BACKEND,
        "sphincs_available": SPHINCS_AVAILABLE,
        "sphincs_backend": SPHINCS_BACKEND,
        "algorithms": {
            "ML-DSA-65": {
                "available": DILITHIUM_AVAILABLE,
                "backend": DILITHIUM_BACKEND,
                "security_level": 3 if DILITHIUM_AVAILABLE else None,
                "key_sizes": (
                    {
                        "public_key": DILITHIUM_PUBLIC_KEY_BYTES,
                        "secret_key": DILITHIUM_SECRET_KEY_BYTES,
                        "signature": DILITHIUM_SIGNATURE_BYTES,
                    }
                    if DILITHIUM_AVAILABLE
                    else None
                ),
            },
            "Kyber-1024": {
                "available": KYBER_AVAILABLE,
                "backend": KYBER_BACKEND,
                "security_level": 5 if KYBER_AVAILABLE else None,
                "key_sizes": (
                    {
                        "public_key": KYBER_PUBLIC_KEY_BYTES,
                        "secret_key": KYBER_SECRET_KEY_BYTES,
                        "ciphertext": KYBER_CIPHERTEXT_BYTES,
                        "shared_secret": KYBER_SHARED_SECRET_BYTES,
                    }
                    if KYBER_AVAILABLE
                    else None
                ),
            },
            "SPHINCS+-256f": {
                "available": SPHINCS_AVAILABLE,
                "backend": SPHINCS_BACKEND,
                "security_level": 5 if SPHINCS_AVAILABLE else None,
                "key_sizes": (
                    {
                        "public_key": SPHINCS_PUBLIC_KEY_BYTES,
                        "secret_key": SPHINCS_SECRET_KEY_BYTES,
                        "signature": SPHINCS_SIGNATURE_BYTES,
                    }
                    if SPHINCS_AVAILABLE
                    else None
                ),
            },
        },
        # Everything below is driven off the registry tables rather than
        # written out, so a new parameter set cannot be added without appearing
        # here. `get_pqc_backend_info` is documented as covering "all
        # algorithms" and enumerated exactly three of them, which meant it
        # reported none of the six PQ parameter sets this branch reaches, none
        # of the three NIST prime curves, and not HSS/LMS.
        "parameter_sets": {
            "ml_kem": {
                f"ML-KEM-{pid}": {
                    "available": ML_KEM_NATIVE_AVAILABLE,
                    "backend": "native" if ML_KEM_NATIVE_AVAILABLE else None,
                    "key_sizes": dict(sizes) if ML_KEM_NATIVE_AVAILABLE else None,
                }
                for pid, sizes in sorted(ML_KEM_SIZES.items())
            },
            "ml_dsa": {
                f"ML-DSA-{pid}": {
                    "available": ML_DSA_NATIVE_AVAILABLE,
                    "backend": "native" if ML_DSA_NATIVE_AVAILABLE else None,
                    "key_sizes": dict(sizes) if ML_DSA_NATIVE_AVAILABLE else None,
                }
                for pid, sizes in sorted(ML_DSA_SIZES.items())
            },
            "nist_prime_curves": {
                f"P-{cid}": {
                    "available": NISTP_NATIVE_AVAILABLE,
                    "backend": "native" if NISTP_NATIVE_AVAILABLE else None,
                    "field_bytes": nb,
                    "default_hash": NISTP_DEFAULT_HASH[cid],
                }
                for cid, nb in sorted(NISTP_FIELD_BYTES.items())
            },
        },
        "HSS-LMS": {
            "available": LMS_NATIVE_AVAILABLE,
            "backend": "native" if LMS_NATIVE_AVAILABLE else None,
            # Stated here rather than left to be discovered: LMS is stateful,
            # and AMA implements only the half that holds no state.
            "operations": ["verify"] if LMS_NATIVE_AVAILABLE else [],
            "description": "RFC 8554 HSS/LMS verification (signing not implemented)",
        },
        "secp256k1": {
            "available": SECP256K1_NATIVE_AVAILABLE,
            "backend": "native" if SECP256K1_NATIVE_AVAILABLE else None,
            "description": "SEC 2 secp256k1 ECDSA, low-`s` by default (INVARIANT-28)",
        },
        "SHA3-256": {
            "available": SHA3_256_NATIVE_AVAILABLE,
            "backend": "native" if SHA3_256_NATIVE_AVAILABLE else None,
            "description": "FIPS 202 SHA3-256 (Keccak-f[1600])",
        },
        "HMAC-SHA3-256": {
            "available": HMAC_SHA3_256_AVAILABLE,
            "backend": HMAC_SHA3_256_BACKEND,
            "description": "RFC 2104 HMAC with SHA3-256 (136-byte block)",
        },
        # Legacy field for backward compatibility
        "backend": DILITHIUM_BACKEND,
        "algorithm": "ML-DSA-65" if DILITHIUM_AVAILABLE else None,
        "security_level": 3 if DILITHIUM_AVAILABLE else None,
    }


def _secure_memzero(buf: bytearray) -> None:
    """Zero a bytearray in-place without importing secure_memory (avoids cyclic import)."""
    for i in range(len(buf)):
        buf[i] = 0


@dataclass
class DilithiumKeyPair:
    """
    CRYSTALS-Dilithium post-quantum key pair (ML-DSA-65, Level 3).

    Key Sizes (NIST FIPS spec):
        - Secret key: 4032 bytes
        - Public key: 1952 bytes
        - Signature: 3309 bytes

    Security: 192-bit quantum security (NIST Security Level 3)
    Standard: NIST FIPS 204 (ML-DSA)

    INVARIANT-6: secret_key is stored as mutable bytearray and securely
    zeroed via wipe() / __del__.
    """

    secret_key: Union[bytes, bytearray] = field(repr=False)  # 4032 bytes for ML-DSA-65
    public_key: bytes  # 1952 bytes for ML-DSA-65

    def __post_init__(self) -> None:
        if isinstance(self.secret_key, bytes):
            object.__setattr__(self, "secret_key", bytearray(self.secret_key))

    def wipe(self) -> None:
        """Securely zero secret key material."""
        if isinstance(self.secret_key, bytearray) and len(self.secret_key) > 0:
            _secure_memzero(self.secret_key)

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception as exc:  # — INVARIANT-3/9: __del__ must not raise (FIN-001)
            # INVARIANT-3 addendum: silence is never the only outcome.
            record_finalizer_error("DilithiumKeyPair", f"wipe() failed: {exc}")


@dataclass
class KyberKeyPair:
    """
    CRYSTALS-Kyber post-quantum key pair (Kyber-1024, Level 5).

    Key Sizes (NIST FIPS spec):
        - Secret key: 3168 bytes
        - Public key: 1568 bytes
        - Ciphertext: 1568 bytes
        - Shared secret: 32 bytes

    Security: 256-bit classical / 128-bit quantum security (NIST Security Level 5)
    Standard: NIST FIPS 203 (ML-KEM)

    INVARIANT-6: secret_key is stored as mutable bytearray and securely
    zeroed via wipe() / __del__.
    """

    secret_key: Union[bytes, bytearray] = field(repr=False)  # 3168 bytes for Kyber-1024
    public_key: bytes  # 1568 bytes for Kyber-1024

    def __post_init__(self) -> None:
        if isinstance(self.secret_key, bytes):
            object.__setattr__(self, "secret_key", bytearray(self.secret_key))

    def wipe(self) -> None:
        """Securely zero secret key material."""
        if isinstance(self.secret_key, bytearray) and len(self.secret_key) > 0:
            _secure_memzero(self.secret_key)

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception as exc:  # — INVARIANT-3/9: __del__ must not raise (FIN-002)
            # INVARIANT-3 addendum: silence is never the only outcome.
            record_finalizer_error("KyberKeyPair", f"wipe() failed: {exc}")


@dataclass
class KyberEncapsulation:
    """
    Kyber-1024 key encapsulation result.

    Contains the ciphertext and shared secret from encapsulation.
    """

    ciphertext: bytes  # 1568 bytes
    shared_secret: bytes  # 32 bytes


@dataclass
class SphincsKeyPair:
    """
    SPHINCS+-SHA2-256f-simple post-quantum key pair (Level 5).

    Key Sizes (NIST FIPS spec):
        - Secret key: 128 bytes
        - Public key: 64 bytes
        - Signature: 49856 bytes

    Security: 256-bit classical / 128-bit quantum security (NIST Security Level 5)
    Standard: NIST FIPS 205 (SLH-DSA)

    Note: SPHINCS+ signatures are large (~49KB) but provide stateless
    hash-based security with no risk of key reuse vulnerabilities.

    INVARIANT-6: secret_key is stored as mutable bytearray and securely
    zeroed via wipe() / __del__.
    """

    secret_key: Union[bytes, bytearray] = field(repr=False)  # 128 bytes for SPHINCS+-256f
    public_key: bytes  # 64 bytes for SPHINCS+-256f

    def __post_init__(self) -> None:
        if isinstance(self.secret_key, bytes):
            object.__setattr__(self, "secret_key", bytearray(self.secret_key))

    def wipe(self) -> None:
        """Securely zero secret key material."""
        if isinstance(self.secret_key, bytearray) and len(self.secret_key) > 0:
            _secure_memzero(self.secret_key)

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception as exc:  # — INVARIANT-3/9: __del__ must not raise (FIN-003)
            # INVARIANT-3 addendum: silence is never the only outcome.
            record_finalizer_error("SphincsKeyPair", f"wipe() failed: {exc}")


def generate_dilithium_keypair() -> DilithiumKeyPair:
    """
    Generate CRYSTALS-Dilithium key pair (Level 3).

    Returns:
        DilithiumKeyPair with ML-DSA-65 keys

    Raises:
        QuantumSignatureUnavailableError: If no Dilithium backend is available
    """
    if not DILITHIUM_AVAILABLE:
        raise QuantumSignatureUnavailableError(_DILITHIUM_UNAVAILABLE_MSG)

    if DILITHIUM_BACKEND == "native" and _native_lib is not None:
        pk_buf = ctypes.create_string_buffer(DILITHIUM_PUBLIC_KEY_BYTES)
        sk_buf = ctypes.create_string_buffer(DILITHIUM_SECRET_KEY_BYTES)
        rc = _native_lib.ama_dilithium_keypair(pk_buf, sk_buf)
        if rc != 0:
            ctypes.memset(sk_buf, 0, DILITHIUM_SECRET_KEY_BYTES)
            raise QuantumSignatureUnavailableError(
                f"Native dilithium_keypair failed with error code {rc}"
            )
        result = DilithiumKeyPair(secret_key=bytearray(sk_buf), public_key=bytes(pk_buf))
        ctypes.memset(sk_buf, 0, DILITHIUM_SECRET_KEY_BYTES)
        return result

    raise QuantumSignatureUnavailableError(_DILITHIUM_UNKNOWN_STATE)


def dilithium_sign(message: bytes, secret_key: Union[bytes, bytearray]) -> bytes:
    """
    Sign message with CRYSTALS-Dilithium (ML-DSA-65).

    Args:
        message: Data to sign
        secret_key: Dilithium secret key (4032 bytes)

    Returns:
        Dilithium signature (3309 bytes)

    Raises:
        QuantumSignatureUnavailableError: If no Dilithium backend is available
    """
    if not DILITHIUM_AVAILABLE:
        raise QuantumSignatureUnavailableError(_DILITHIUM_UNAVAILABLE_MSG)

    if len(secret_key) != DILITHIUM_SECRET_KEY_BYTES:
        raise ValueError(
            f"Invalid secret key length: expected {DILITHIUM_SECRET_KEY_BYTES}, "
            f"got {len(secret_key)}"
        )

    # Primary path: Cython binding (zero marshaling overhead)
    if _cy_dilithium_sign_fn is not None:
        result: bytes = _cy_dilithium_sign_fn(message, bytes(secret_key))
        return result

    if DILITHIUM_BACKEND == "native" and _native_lib is not None:
        sig_buf = ctypes.create_string_buffer(DILITHIUM_SIGNATURE_BYTES)
        sig_len = ctypes.c_size_t(DILITHIUM_SIGNATURE_BYTES)
        # INVARIANT-6: use mutable ctypes buffer to avoid non-wipeable bytes() copy
        sk_buf = ctypes.create_string_buffer(bytes(secret_key), len(secret_key))
        try:
            rc = _native_lib.ama_dilithium_sign(
                sig_buf,
                ctypes.byref(sig_len),
                message,
                ctypes.c_size_t(len(message)),
                sk_buf,
            )
            if rc != 0:
                raise QuantumSignatureUnavailableError(
                    f"Native dilithium_sign failed with error code {rc}"
                )
            return bytes(sig_buf[: sig_len.value])  # type: ignore[arg-type]  # ctypes buffer slice not typed as bytes-compatible (PQC-001)
        finally:
            ctypes.memset(sk_buf, 0, len(secret_key))

    raise QuantumSignatureUnavailableError(_DILITHIUM_UNKNOWN_STATE)


def dilithium_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify CRYSTALS-Dilithium signature.

    Args:
        message: Original data
        signature: Dilithium signature
        public_key: Dilithium public key (1952 bytes)

    Returns:
        True if signature is valid, False otherwise

    Raises:
        QuantumSignatureUnavailableError: If no Dilithium backend is available
    """
    if not DILITHIUM_AVAILABLE:
        raise QuantumSignatureUnavailableError(_DILITHIUM_UNAVAILABLE_MSG)

    if len(public_key) != DILITHIUM_PUBLIC_KEY_BYTES:
        raise ValueError(
            f"Invalid public key length: expected {DILITHIUM_PUBLIC_KEY_BYTES}, "
            f"got {len(public_key)}"
        )

    # Primary path: Cython binding (zero marshaling overhead)
    if _cy_dilithium_verify_fn is not None:
        valid: bool = _cy_dilithium_verify_fn(signature, message, public_key)
        return valid

    if DILITHIUM_BACKEND == "native" and _native_lib is not None:
        rc = _native_lib.ama_dilithium_verify(
            message,
            ctypes.c_size_t(len(message)),
            signature,
            ctypes.c_size_t(len(signature)),
            public_key,
        )
        return bool(rc == 0)

    raise QuantumSignatureUnavailableError(_DILITHIUM_UNKNOWN_STATE)


def dilithium_verify_ctx(message: bytes, signature: bytes, public_key: bytes, ctx: bytes) -> bool:
    """
    Verify ML-DSA-65 signature with context (FIPS 204 external/pure).

    Applies M' = 0x00 || len(ctx) || ctx || M domain separation.

    Args:
        message: Raw message
        signature: Signature (3309 bytes)
        public_key: Public key (1952 bytes)
        ctx: Context string (0–255 bytes)

    Returns:
        True if signature is valid, False otherwise

    Raises:
        QuantumSignatureUnavailableError: If no Dilithium backend is available
        ValueError: If ctx exceeds 255 bytes
    """
    if len(ctx) > 255:
        raise ValueError(f"Context must be at most 255 bytes, got {len(ctx)}")
    if not DILITHIUM_AVAILABLE:
        raise QuantumSignatureUnavailableError(_DILITHIUM_UNAVAILABLE_MSG)
    if len(public_key) != DILITHIUM_PUBLIC_KEY_BYTES:
        raise ValueError(
            f"Invalid public key length: expected {DILITHIUM_PUBLIC_KEY_BYTES}, "
            f"got {len(public_key)}"
        )
    if DILITHIUM_BACKEND == "native" and _native_lib is not None:
        rc = _native_lib.ama_dilithium_verify_ctx(
            message,
            ctypes.c_size_t(len(message)),
            ctx,
            ctypes.c_size_t(len(ctx)),
            signature,
            ctypes.c_size_t(len(signature)),
            public_key,
        )
        return bool(rc == 0)
    raise QuantumSignatureUnavailableError(_DILITHIUM_UNKNOWN_STATE)


def dilithium_sign_ctx(message: bytes, secret_key: Union[bytes, bytearray], ctx: bytes) -> bytes:
    """
    ML-DSA-65 sign with FIPS 204 §5.2 binding context (external/pure).

    Applies the domain-separation wrapper M' = 0x00 || len(ctx) || ctx || M
    defined in FIPS 204 §5.2 (lines 5–6) before invoking the internal
    signing algorithm. This is the symmetric counterpart of
    :func:`dilithium_verify_ctx`: a signature produced here verifies
    against the same context, and only against the same context.

    Args:
        message: Raw message to sign (arbitrary length)
        secret_key: ML-DSA-65 secret key (4032 bytes)
        ctx: Context string (0–255 bytes, per FIPS 204 §5.2 line 4)

    Returns:
        ML-DSA-65 signature (3309 bytes)

    Raises:
        QuantumSignatureUnavailableError: If no Dilithium backend is available
        ValueError: If ``ctx`` exceeds 255 bytes or ``secret_key`` length is wrong

    Standards:
        NIST FIPS 204 §5.2 (ML-DSA.Sign).
    """
    if len(ctx) > 255:
        raise ValueError(f"Context must be at most 255 bytes, got {len(ctx)}")
    if not DILITHIUM_AVAILABLE:
        raise QuantumSignatureUnavailableError(_DILITHIUM_UNAVAILABLE_MSG)
    if len(secret_key) != DILITHIUM_SECRET_KEY_BYTES:
        raise ValueError(
            f"Invalid secret key length: expected {DILITHIUM_SECRET_KEY_BYTES}, "
            f"got {len(secret_key)}"
        )

    if DILITHIUM_BACKEND == "native" and _native_lib is not None:
        sig_buf = ctypes.create_string_buffer(DILITHIUM_SIGNATURE_BYTES)
        sig_len = ctypes.c_size_t(DILITHIUM_SIGNATURE_BYTES)
        # INVARIANT-6: use mutable ctypes buffer to avoid non-wipeable bytes() copy
        sk_buf = ctypes.create_string_buffer(bytes(secret_key), len(secret_key))
        try:
            rc = _native_lib.ama_dilithium_sign_ctx(
                sig_buf,
                ctypes.byref(sig_len),
                message,
                ctypes.c_size_t(len(message)),
                ctx,
                ctypes.c_size_t(len(ctx)),
                sk_buf,
            )
            if rc != 0:
                raise QuantumSignatureUnavailableError(
                    f"Native dilithium_sign_ctx failed with error code {rc}"
                )
            return bytes(sig_buf[: sig_len.value])  # type: ignore[arg-type]  # ctypes buffer slice not typed as bytes-compatible (PQC-001)
        finally:
            ctypes.memset(sk_buf, 0, len(secret_key))

    raise QuantumSignatureUnavailableError(_DILITHIUM_UNKNOWN_STATE)


# ============================================================================
# KYBER-1024 (ML-KEM) KEY ENCAPSULATION MECHANISM
# ============================================================================


def generate_kyber_keypair() -> KyberKeyPair:
    """
    Generate CRYSTALS-Kyber key pair (Kyber-1024, Level 5).

    Kyber-1024 provides IND-CCA2 secure key encapsulation based on the
    Module-LWE (Learning With Errors) problem.

    Returns:
        KyberKeyPair with Kyber-1024 keys

    Raises:
        KyberUnavailableError: If Kyber backend is not available

    Example:
        >>> keypair = generate_kyber_keypair()
        >>> len(keypair.public_key)
        1568
        >>> len(keypair.secret_key)
        3168
    """
    if not KYBER_AVAILABLE:
        raise KyberUnavailableError(_KYBER_UNAVAILABLE_MSG)

    if KYBER_BACKEND == "native" and _native_lib is not None:
        pk_buf = ctypes.create_string_buffer(KYBER_PUBLIC_KEY_BYTES)
        sk_buf = ctypes.create_string_buffer(KYBER_SECRET_KEY_BYTES)
        rc = _native_lib.ama_kyber_keypair(
            pk_buf,
            ctypes.c_size_t(KYBER_PUBLIC_KEY_BYTES),
            sk_buf,
            ctypes.c_size_t(KYBER_SECRET_KEY_BYTES),
        )
        if rc != 0:
            ctypes.memset(sk_buf, 0, KYBER_SECRET_KEY_BYTES)
            raise KyberUnavailableError(f"Native kyber_keypair failed with error code {rc}")
        result = KyberKeyPair(secret_key=bytearray(sk_buf), public_key=bytes(pk_buf))
        ctypes.memset(sk_buf, 0, KYBER_SECRET_KEY_BYTES)
        return result

    raise KyberUnavailableError(_KYBER_UNKNOWN_STATE)


def kyber_encapsulate(public_key: bytes) -> KyberEncapsulation:
    """
    Encapsulate a shared secret using Kyber-1024.

    Generates a random shared secret and encapsulates it using the
    recipient's public key. Only the holder of the corresponding
    secret key can decapsulate to recover the shared secret.

    Args:
        public_key: Kyber-1024 public key (1568 bytes)

    Returns:
        KyberEncapsulation with ciphertext and shared secret

    Raises:
        KyberUnavailableError: If Kyber backend is not available
        ValueError: If public_key has incorrect length

    Example:
        >>> keypair = generate_kyber_keypair()
        >>> encap = kyber_encapsulate(keypair.public_key)
        >>> len(encap.ciphertext)
        1568
        >>> len(encap.shared_secret)
        32
    """
    if not KYBER_AVAILABLE:
        raise KyberUnavailableError(_KYBER_UNAVAILABLE_MSG)

    if len(public_key) != KYBER_PUBLIC_KEY_BYTES:
        raise ValueError(
            f"Invalid public key length: expected {KYBER_PUBLIC_KEY_BYTES}, "
            f"got {len(public_key)}"
        )

    if KYBER_BACKEND == "native" and _native_lib is not None:
        ct_buf = ctypes.create_string_buffer(KYBER_CIPHERTEXT_BYTES)
        ct_len = ctypes.c_size_t(KYBER_CIPHERTEXT_BYTES)
        ss_buf = ctypes.create_string_buffer(KYBER_SHARED_SECRET_BYTES)
        rc = _native_lib.ama_kyber_encapsulate(
            public_key,
            ctypes.c_size_t(len(public_key)),
            ct_buf,
            ctypes.byref(ct_len),
            ss_buf,
            ctypes.c_size_t(KYBER_SHARED_SECRET_BYTES),
        )
        if rc != 0:
            raise KyberUnavailableError(f"Native kyber_encapsulate failed with error code {rc}")
        return KyberEncapsulation(
            ciphertext=bytes(ct_buf[: ct_len.value]),  # type: ignore[arg-type]  # ctypes buffer slice not typed as bytes-compatible (PQC-002)
            shared_secret=bytes(ss_buf),
        )

    raise KyberUnavailableError(_KYBER_UNKNOWN_STATE)


def kyber_decapsulate(ciphertext: bytes, secret_key: Union[bytes, bytearray]) -> bytes:
    """
    Decapsulate a shared secret using Kyber-1024.

    Recovers the shared secret from the ciphertext using the secret key.
    This operation is IND-CCA2 secure with implicit rejection.

    Args:
        ciphertext: Kyber-1024 ciphertext (1568 bytes)
        secret_key: Kyber-1024 secret key (3168 bytes)

    Returns:
        Shared secret (32 bytes)

    Raises:
        KyberUnavailableError: If Kyber backend is not available
        ValueError: If ciphertext or secret_key has incorrect length

    Example:
        >>> keypair = generate_kyber_keypair()
        >>> encap = kyber_encapsulate(keypair.public_key)
        >>> shared_secret = kyber_decapsulate(encap.ciphertext, keypair.secret_key)
        >>> shared_secret == encap.shared_secret
        True
    """
    if not KYBER_AVAILABLE:
        raise KyberUnavailableError(_KYBER_UNAVAILABLE_MSG)

    if len(ciphertext) != KYBER_CIPHERTEXT_BYTES:
        raise ValueError(
            f"Invalid ciphertext length: expected {KYBER_CIPHERTEXT_BYTES}, "
            f"got {len(ciphertext)}"
        )

    if len(secret_key) != KYBER_SECRET_KEY_BYTES:
        raise ValueError(
            f"Invalid secret key length: expected {KYBER_SECRET_KEY_BYTES}, "
            f"got {len(secret_key)}"
        )

    if KYBER_BACKEND == "native" and _native_lib is not None:
        ss_buf = ctypes.create_string_buffer(KYBER_SHARED_SECRET_BYTES)
        # INVARIANT-6: use mutable ctypes buffer to avoid non-wipeable bytes() copy
        sk_buf = ctypes.create_string_buffer(bytes(secret_key), len(secret_key))
        try:
            rc = _native_lib.ama_kyber_decapsulate(
                ciphertext,
                ctypes.c_size_t(len(ciphertext)),
                sk_buf,
                ctypes.c_size_t(len(secret_key)),
                ss_buf,
                ctypes.c_size_t(KYBER_SHARED_SECRET_BYTES),
            )
            if rc != 0:
                raise KyberUnavailableError(f"Native kyber_decapsulate failed with error code {rc}")
            return bytes(ss_buf)
        finally:
            ctypes.memset(sk_buf, 0, len(secret_key))

    raise KyberUnavailableError(_KYBER_UNKNOWN_STATE)


# ============================================================================
# SPHINCS+-SHA2-256f-simple HASH-BASED SIGNATURES
# ============================================================================


def generate_sphincs_keypair() -> SphincsKeyPair:
    """
    Generate SPHINCS+-SHA2-256f-simple key pair (Level 5).

    SPHINCS+ provides stateless hash-based signatures with no risk of
    key reuse vulnerabilities. The 'f' variant is optimized for fast
    signing at the cost of larger signatures.

    Returns:
        SphincsKeyPair with SPHINCS+-256f keys

    Raises:
        SphincsUnavailableError: If SPHINCS+ backend is not available

    Example:
        >>> keypair = generate_sphincs_keypair()
        >>> len(keypair.public_key)
        64
        >>> len(keypair.secret_key)
        128
    """
    if not SPHINCS_AVAILABLE:
        raise SphincsUnavailableError(_SPHINCS_UNAVAILABLE_MSG)

    if SPHINCS_BACKEND == "native" and _native_lib is not None:
        pk_buf = ctypes.create_string_buffer(SPHINCS_PUBLIC_KEY_BYTES)
        sk_buf = ctypes.create_string_buffer(SPHINCS_SECRET_KEY_BYTES)
        rc = _native_lib.ama_sphincs_keypair(pk_buf, sk_buf)
        if rc != 0:
            ctypes.memset(sk_buf, 0, SPHINCS_SECRET_KEY_BYTES)
            raise SphincsUnavailableError(f"Native sphincs_keypair failed with error code {rc}")
        result = SphincsKeyPair(secret_key=bytearray(sk_buf), public_key=bytes(pk_buf))
        ctypes.memset(sk_buf, 0, SPHINCS_SECRET_KEY_BYTES)
        return result

    raise SphincsUnavailableError(_SPHINCS_UNKNOWN_STATE)


def sphincs_sign(message: bytes, secret_key: Union[bytes, bytearray]) -> bytes:
    """
    Sign message with SPHINCS+-SHA2-256f-simple.

    SPHINCS+ signatures are large (~49KB) but provide strong security
    guarantees based only on hash function security assumptions.

    Args:
        message: Data to sign (arbitrary length)
        secret_key: SPHINCS+-256f secret key (128 bytes)

    Returns:
        SPHINCS+ signature (49856 bytes)

    Raises:
        SphincsUnavailableError: If SPHINCS+ backend is not available
        ValueError: If secret_key has incorrect length

    Example:
        >>> keypair = generate_sphincs_keypair()
        >>> signature = sphincs_sign(b"Hello, World!", keypair.secret_key)
        >>> len(signature)
        49856
    """
    if not SPHINCS_AVAILABLE:
        raise SphincsUnavailableError(_SPHINCS_UNAVAILABLE_MSG)

    if len(secret_key) != SPHINCS_SECRET_KEY_BYTES:
        raise ValueError(
            f"Invalid secret key length: expected {SPHINCS_SECRET_KEY_BYTES}, "
            f"got {len(secret_key)}"
        )

    if SPHINCS_BACKEND == "native" and _native_lib is not None:
        sig_buf = ctypes.create_string_buffer(SPHINCS_SIGNATURE_BYTES)
        sig_len = ctypes.c_size_t(SPHINCS_SIGNATURE_BYTES)
        # INVARIANT-6: use mutable ctypes buffer to avoid non-wipeable bytes() copy
        sk_buf = ctypes.create_string_buffer(bytes(secret_key), len(secret_key))
        try:
            rc = _native_lib.ama_sphincs_sign(
                sig_buf,
                ctypes.byref(sig_len),
                message,
                ctypes.c_size_t(len(message)),
                sk_buf,
            )
            if rc != 0:
                raise SphincsUnavailableError(f"Native sphincs_sign failed with error code {rc}")
            return bytes(sig_buf[: sig_len.value])  # type: ignore[arg-type]  # ctypes buffer slice not typed as bytes-compatible (PQC-003)
        finally:
            ctypes.memset(sk_buf, 0, len(secret_key))

    raise SphincsUnavailableError(_SPHINCS_UNKNOWN_STATE)


def sphincs_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify SPHINCS+-SHA2-256f-simple signature.

    Args:
        message: Original data
        signature: SPHINCS+ signature (49856 bytes)
        public_key: SPHINCS+-256f public key (64 bytes)

    Returns:
        True if signature is valid, False otherwise

    Raises:
        SphincsUnavailableError: If SPHINCS+ backend is not available
        ValueError: If public_key has incorrect length

    Example:
        >>> keypair = generate_sphincs_keypair()
        >>> signature = sphincs_sign(b"Hello, World!", keypair.secret_key)
        >>> sphincs_verify(b"Hello, World!", signature, keypair.public_key)
        True
        >>> sphincs_verify(b"Tampered!", signature, keypair.public_key)
        False
    """
    if not SPHINCS_AVAILABLE:
        raise SphincsUnavailableError(_SPHINCS_UNAVAILABLE_MSG)

    if len(public_key) != SPHINCS_PUBLIC_KEY_BYTES:
        raise ValueError(
            f"Invalid public key length: expected {SPHINCS_PUBLIC_KEY_BYTES}, "
            f"got {len(public_key)}"
        )

    if SPHINCS_BACKEND == "native" and _native_lib is not None:
        rc = _native_lib.ama_sphincs_verify(
            message,
            ctypes.c_size_t(len(message)),
            signature,
            ctypes.c_size_t(len(signature)),
            public_key,
        )
        return bool(rc == 0)

    raise SphincsUnavailableError(_SPHINCS_UNKNOWN_STATE)


def sphincs_verify_ctx(message: bytes, signature: bytes, public_key: bytes, ctx: bytes) -> bool:
    """
    Verify SLH-DSA-SHA2-256f signature with context (FIPS 205 external/pure).

    Applies M' = 0x00 || len(ctx) || ctx || M domain separation.

    Args:
        message: Raw message
        signature: Signature (49856 bytes)
        public_key: Public key (64 bytes)
        ctx: Context string (0–255 bytes)

    Returns:
        True if signature is valid, False otherwise

    Raises:
        SphincsUnavailableError: If SPHINCS+ backend is not available
        ValueError: If ctx exceeds 255 bytes
    """
    if len(ctx) > 255:
        raise ValueError(f"Context must be at most 255 bytes, got {len(ctx)}")
    if not SPHINCS_AVAILABLE:
        raise SphincsUnavailableError(_SPHINCS_UNAVAILABLE_MSG)
    if len(public_key) != SPHINCS_PUBLIC_KEY_BYTES:
        raise ValueError(
            f"Invalid public key length: expected {SPHINCS_PUBLIC_KEY_BYTES}, "
            f"got {len(public_key)}"
        )
    if SPHINCS_BACKEND == "native" and _native_lib is not None:
        rc = _native_lib.ama_sphincs_verify_ctx(
            message,
            ctypes.c_size_t(len(message)),
            ctx,
            ctypes.c_size_t(len(ctx)),
            signature,
            ctypes.c_size_t(len(signature)),
            public_key,
        )
        return bool(rc == 0)
    raise SphincsUnavailableError(_SPHINCS_UNKNOWN_STATE)


# ============================================================================
# SLH-DSA (FIPS 205) — parameter-driven Python API
# ============================================================================


@dataclass
class SlhDsaKeyPair:
    """
    SLH-DSA (FIPS 205) post-quantum key pair, parameter-driven.

    Supports two NIST-standardized parameter sets:

    - ``"SHA2-256f"`` — NIST L5; pk=64, sk=128, sig=49856.
    - ``"SHAKE-128s"`` — NIST L1; pk=32, sk=64,  sig=7856.

    INVARIANT-6: secret_key is stored as a mutable bytearray so it can be
    securely zeroed via :meth:`wipe` / :meth:`__del__`.
    """

    public_key: bytes
    secret_key: Union[bytes, bytearray] = field(repr=False)
    param_set: str = "SHAKE-128s"

    def __post_init__(self) -> None:
        if isinstance(self.secret_key, bytes):
            object.__setattr__(self, "secret_key", bytearray(self.secret_key))
        if self.param_set not in _SLHDSA_PARAM_SETS:
            raise ValueError(
                f"Unsupported SLH-DSA parameter set: {self.param_set!r}. "
                f"Supported: {sorted(_SLHDSA_PARAM_SETS)}"
            )
        _, pk_len, sk_len, _, _ = _SLHDSA_PARAM_SETS[self.param_set]
        if len(self.public_key) != pk_len:
            raise ValueError(
                f"SLH-DSA-{self.param_set}: invalid public key length "
                f"(expected {pk_len}, got {len(self.public_key)})"
            )
        if len(self.secret_key) != sk_len:
            raise ValueError(
                f"SLH-DSA-{self.param_set}: invalid secret key length "
                f"(expected {sk_len}, got {len(self.secret_key)})"
            )

    def wipe(self) -> None:
        """Securely zero the secret key in place (INVARIANT-6)."""
        if isinstance(self.secret_key, bytearray):
            for i in range(len(self.secret_key)):
                self.secret_key[i] = 0

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception as exc:  # — INVARIANT-3/9: __del__ must not raise (FIN-004)
            # INVARIANT-3 addendum: silence is never the only outcome.
            record_finalizer_error("SlhDsaKeyPair", f"wipe() failed: {exc}")


def _slhdsa_resolve(param_set: str) -> tuple:
    """Look up (enum_id, pk_len, sk_len, sig_len, n) or raise ValueError."""
    try:
        return _SLHDSA_PARAM_SETS[param_set]
    except KeyError as exc:
        raise ValueError(
            f"Unsupported SLH-DSA parameter set: {param_set!r}. "
            f"Supported: {sorted(_SLHDSA_PARAM_SETS)}"
        ) from exc


def generate_slhdsa_keypair(param_set: str = "SHAKE-128s") -> SlhDsaKeyPair:
    """Generate an SLH-DSA keypair.

    Args:
        param_set: One of ``"SHA2-256f"`` or ``"SHAKE-128s"``.

    Returns:
        SlhDsaKeyPair with platform-RNG-sourced key material.

    Raises:
        SphincsUnavailableError: If the native SLH-DSA backend is not built.
        ValueError: On unsupported param_set.
        RuntimeError: On native key generation failure.
    """
    enum_id, pk_len, sk_len, _, _ = _slhdsa_resolve(param_set)
    if not SPHINCS_AVAILABLE or _native_lib is None:
        raise SphincsUnavailableError(_SPHINCS_UNAVAILABLE_MSG)
    pk_buf = ctypes.create_string_buffer(pk_len)
    sk_buf = ctypes.create_string_buffer(sk_len)
    try:
        rc = _native_lib.ama_slhdsa_keygen(ctypes.c_int(enum_id), pk_buf, sk_buf)
        if rc != 0:
            raise RuntimeError(f"ama_slhdsa_keygen({param_set}) failed: rc={rc}")
        # INVARIANT-6: copy SK into a wipeable bytearray, then immediately
        # zero the ctypes scratch buffer so the only live copy of the secret
        # key is the one the SlhDsaKeyPair (or its caller) owns.
        return SlhDsaKeyPair(
            public_key=bytes(pk_buf.raw[:pk_len]),
            secret_key=bytearray(sk_buf.raw[:sk_len]),
            param_set=param_set,
        )
    finally:
        ctypes.memset(sk_buf, 0, sk_len)


def generate_slhdsa_keypair_from_seed(
    sk_seed: Union[bytes, bytearray],
    sk_prf: Union[bytes, bytearray],
    pk_seed: Union[bytes, bytearray],
    param_set: str = "SHAKE-128s",
) -> SlhDsaKeyPair:
    """Deterministically derive an SLH-DSA keypair from FIPS 205 §10.1 seeds.

    Mirrors the C-level :c:func:`ama_slhdsa_keygen_from_seed` entry point.
    All three seed inputs must be exactly ``n`` bytes long
    (``n = 16`` for SHAKE-128s, ``n = 32`` for SHA2-256f). The resulting
    secret key layout is ``SK.seed || SK.prf || PK.seed || PK.root`` and
    the public key is ``PK.seed || PK.root``.

    Raises:
        SphincsUnavailableError: If the native SLH-DSA backend is not built.
        ValueError: On unsupported ``param_set`` or wrong seed length.
        RuntimeError: On native key generation failure.
    """
    enum_id, pk_len, sk_len, _, n = _slhdsa_resolve(param_set)
    if not SPHINCS_AVAILABLE or _native_lib is None:
        raise SphincsUnavailableError(_SPHINCS_UNAVAILABLE_MSG)
    for label, seed in (("sk_seed", sk_seed), ("sk_prf", sk_prf), ("pk_seed", pk_seed)):
        if len(seed) != n:
            raise ValueError(f"SLH-DSA-{param_set}: {label} must be {n} bytes, got {len(seed)}")
    pk_buf = ctypes.create_string_buffer(pk_len)
    sk_buf = ctypes.create_string_buffer(sk_len)
    # INVARIANT-6: keep all secret-bearing scratch buffers in mutable
    # ctypes storage so they can be wiped before this function returns.
    sk_seed_buf = ctypes.create_string_buffer(bytes(sk_seed), n)
    sk_prf_buf = ctypes.create_string_buffer(bytes(sk_prf), n)
    pk_seed_buf = ctypes.create_string_buffer(bytes(pk_seed), n)
    try:
        rc = _native_lib.ama_slhdsa_keygen_from_seed(
            ctypes.c_int(enum_id),
            sk_seed_buf,
            sk_prf_buf,
            pk_seed_buf,
            pk_buf,
            sk_buf,
        )
        if rc != 0:
            raise RuntimeError(f"ama_slhdsa_keygen_from_seed({param_set}) failed: rc={rc}")
        return SlhDsaKeyPair(
            public_key=bytes(pk_buf.raw[:pk_len]),
            secret_key=bytearray(sk_buf.raw[:sk_len]),
            param_set=param_set,
        )
    finally:
        ctypes.memset(sk_buf, 0, sk_len)
        ctypes.memset(sk_seed_buf, 0, n)
        ctypes.memset(sk_prf_buf, 0, n)
        ctypes.memset(pk_seed_buf, 0, n)


def slhdsa_sign(
    message: bytes,
    secret_key: Union[bytes, bytearray],
    ctx: bytes = b"",
    param_set: str = "SHAKE-128s",
) -> bytes:
    """Sign a message with SLH-DSA using the FIPS 205 §10.2 context wrapper.

    The signature is produced via the hedged variant (fresh ``addrnd``).
    For byte-exact NIST ACVP deterministic test vectors, use
    :func:`slhdsa_sign_deterministic`.

    Raises:
        ValueError: If ``len(ctx) > 255`` or ``secret_key`` is the wrong length.
        SphincsUnavailableError: If the native backend is not built.
        RuntimeError: On native signing failure.
    """
    if len(ctx) > 255:
        raise ValueError(f"Context must be at most 255 bytes, got {len(ctx)}")
    enum_id, _, sk_len, sig_len, _ = _slhdsa_resolve(param_set)
    if not SPHINCS_AVAILABLE or _native_lib is None:
        raise SphincsUnavailableError(_SPHINCS_UNAVAILABLE_MSG)
    if len(secret_key) != sk_len:
        raise ValueError(
            f"SLH-DSA-{param_set}: invalid secret key length "
            f"(expected {sk_len}, got {len(secret_key)})"
        )
    sig_buf = ctypes.create_string_buffer(sig_len)
    sig_buf_len = ctypes.c_size_t(sig_len)
    # INVARIANT-6: route the secret key through a mutable ctypes buffer so it
    # can be zeroed on the way out — ``bytes(secret_key)`` would otherwise
    # leave an immutable, non-wipeable copy on the Python heap.
    sk_buf = ctypes.create_string_buffer(bytes(secret_key), sk_len)
    try:
        rc = _native_lib.ama_slhdsa_sign(
            ctypes.c_int(enum_id),
            sig_buf,
            ctypes.byref(sig_buf_len),
            message,
            ctypes.c_size_t(len(message)),
            ctx if ctx else None,
            ctypes.c_size_t(len(ctx)),
            sk_buf,
        )
        if rc != 0:
            raise RuntimeError(f"ama_slhdsa_sign({param_set}) failed: rc={rc}")
        return bytes(sig_buf.raw[: sig_buf_len.value])
    finally:
        ctypes.memset(sk_buf, 0, sk_len)


def slhdsa_verify(
    message: bytes,
    signature: bytes,
    public_key: bytes,
    ctx: bytes = b"",
    param_set: str = "SHAKE-128s",
) -> bool:
    """Verify an SLH-DSA signature with FIPS 205 §10.2 context wrapper.

    Returns ``True`` iff the signature is valid; returns ``False`` for any
    cryptographic verification failure (wrong message, wrong context, wrong
    public key, malformed signature length, …).
    """
    if len(ctx) > 255:
        raise ValueError(f"Context must be at most 255 bytes, got {len(ctx)}")
    enum_id, pk_len, _, _, _ = _slhdsa_resolve(param_set)
    if not SPHINCS_AVAILABLE or _native_lib is None:
        raise SphincsUnavailableError(_SPHINCS_UNAVAILABLE_MSG)
    if len(public_key) != pk_len:
        raise ValueError(
            f"SLH-DSA-{param_set}: invalid public key length "
            f"(expected {pk_len}, got {len(public_key)})"
        )
    rc = _native_lib.ama_slhdsa_verify(
        ctypes.c_int(enum_id),
        signature,
        ctypes.c_size_t(len(signature)),
        message,
        ctypes.c_size_t(len(message)),
        ctx if ctx else None,
        ctypes.c_size_t(len(ctx)),
        public_key,
    )
    return bool(rc == 0)


def slhdsa_sign_deterministic(
    message: bytes,
    secret_key: Union[bytes, bytearray],
    ctx: bytes = b"",
    param_set: str = "SHAKE-128s",
) -> bytes:
    """Deterministic SLH-DSA sign (FIPS 205 §10.2 with ``addrnd = PK.seed``).

    Exposed for byte-exact NIST ACVP KAT validation against the deterministic
    sigGen vectors. **Production code should call** :func:`slhdsa_sign`
    (hedged) **for forward-secrecy under fault attacks.**
    """
    if len(ctx) > 255:
        raise ValueError(f"Context must be at most 255 bytes, got {len(ctx)}")
    enum_id, _, sk_len, sig_len, _ = _slhdsa_resolve(param_set)
    if not SPHINCS_AVAILABLE or _native_lib is None:
        raise SphincsUnavailableError(_SPHINCS_UNAVAILABLE_MSG)
    if len(secret_key) != sk_len:
        raise ValueError(
            f"SLH-DSA-{param_set}: invalid secret key length "
            f"(expected {sk_len}, got {len(secret_key)})"
        )
    sig_buf = ctypes.create_string_buffer(sig_len)
    sig_buf_len = ctypes.c_size_t(sig_len)
    # INVARIANT-6: see slhdsa_sign — wipe the ctypes scratch SK on exit.
    sk_buf = ctypes.create_string_buffer(bytes(secret_key), sk_len)
    try:
        rc = _native_lib.ama_slhdsa_sign_deterministic(
            ctypes.c_int(enum_id),
            sig_buf,
            ctypes.byref(sig_buf_len),
            message,
            ctypes.c_size_t(len(message)),
            ctx if ctx else None,
            ctypes.c_size_t(len(ctx)),
            sk_buf,
        )
        if rc != 0:
            raise RuntimeError(f"ama_slhdsa_sign_deterministic({param_set}) failed: rc={rc}")
        return bytes(sig_buf.raw[: sig_buf_len.value])
    finally:
        ctypes.memset(sk_buf, 0, sk_len)


def slhdsa_sign_internal(
    message: bytes,
    secret_key: Union[bytes, bytearray],
    addrnd: bytes,
    param_set: str = "SHAKE-128s",
) -> bytes:
    """SLH-DSA "internal interface" sign with explicit ``addrnd``.

    Skips the FIPS 205 §10.2 context wrapper and signs ``message`` directly.
    Exposed for ACVP ``signatureInterface == "internal"`` KAT validation.
    """
    enum_id, _, sk_len, sig_len, n = _slhdsa_resolve(param_set)
    if not SPHINCS_AVAILABLE or _native_lib is None:
        raise SphincsUnavailableError(_SPHINCS_UNAVAILABLE_MSG)
    if len(secret_key) != sk_len:
        raise ValueError(
            f"SLH-DSA-{param_set}: invalid secret key length "
            f"(expected {sk_len}, got {len(secret_key)})"
        )
    if len(addrnd) != n:
        raise ValueError(f"SLH-DSA-{param_set}: addrnd must be {n} bytes, got {len(addrnd)}")
    sig_buf = ctypes.create_string_buffer(sig_len)
    sig_buf_len = ctypes.c_size_t(sig_len)
    # INVARIANT-6: route both SK and addrnd through wipeable ctypes scratch
    # storage. ``addrnd`` is randomness bound into the signature and —
    # depending on caller policy — may be derived from secret material
    # (e.g. PRF over SK), so we treat it as sensitive even though it is
    # ultimately revealed via the resulting signature.
    sk_buf = ctypes.create_string_buffer(bytes(secret_key), sk_len)
    addrnd_buf = ctypes.create_string_buffer(bytes(addrnd), n)
    try:
        rc = _native_lib.ama_slhdsa_sign_internal(
            ctypes.c_int(enum_id),
            sig_buf,
            ctypes.byref(sig_buf_len),
            message,
            ctypes.c_size_t(len(message)),
            addrnd_buf,
            sk_buf,
        )
        if rc != 0:
            raise RuntimeError(f"ama_slhdsa_sign_internal({param_set}) failed: rc={rc}")
        return bytes(sig_buf.raw[: sig_buf_len.value])
    finally:
        ctypes.memset(sk_buf, 0, sk_len)
        ctypes.memset(addrnd_buf, 0, n)


# ============================================================================
# ED25519 NATIVE C BACKEND (RFC 8032)
# ============================================================================


def native_ed25519_keypair() -> tuple:
    """
    Generate Ed25519 keypair using native C backend.

    Returns:
        (public_key, secret_key) — 32-byte pk, 64-byte sk (seed || pk)

    Raises:
        RuntimeError: If native library is not available or keypair generation fails
    """
    import secrets as _secrets

    if _native_lib is None or not _ED25519_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "Ed25519 native backend not available. " + _INSTALL_HINT
        )

    pk_buf = ctypes.create_string_buffer(ED25519_PUBLIC_KEY_BYTES)
    sk_buf = ctypes.create_string_buffer(ED25519_SECRET_KEY_BYTES)

    # Seed the first 32 bytes — the C function expects caller-provided entropy
    seed = _secrets.token_bytes(32)
    ctypes.memmove(sk_buf, seed, 32)

    rc = _native_lib.ama_ed25519_keypair(pk_buf, sk_buf)
    if rc != 0:
        raise RuntimeError(f"Ed25519 keypair generation failed (rc={rc})")

    return bytes(pk_buf), bytes(sk_buf)


def native_ed25519_keypair_from_seed(seed: bytes) -> tuple:
    """
    Generate Ed25519 keypair from a specific 32-byte seed.

    This is the deterministic variant used for interop testing and
    key format conversion (32-byte seed -> 64-byte native key).

    Args:
        seed: Exactly 32 bytes of seed material

    Returns:
        (public_key, secret_key) — 32-byte pk, 64-byte sk (seed || pk)

    Raises:
        ValueError: If seed is not exactly 32 bytes
        RuntimeError: If native library is not available
    """
    if len(seed) != 32:
        raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(seed)}")

    if _native_lib is None or not _ED25519_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "Ed25519 native backend not available. " + _INSTALL_HINT
        )

    pk_buf = ctypes.create_string_buffer(ED25519_PUBLIC_KEY_BYTES)
    sk_buf = ctypes.create_string_buffer(ED25519_SECRET_KEY_BYTES)

    # Load seed into first 32 bytes of sk_buf
    ctypes.memmove(sk_buf, seed, 32)

    rc = _native_lib.ama_ed25519_keypair(pk_buf, sk_buf)
    if rc != 0:
        raise RuntimeError(f"Ed25519 keypair generation failed (rc={rc})")

    return bytes(pk_buf), bytes(sk_buf)


def native_ed25519_sign(message: bytes, secret_key: Union[bytes, bytearray]) -> bytes:
    """
    Sign message with Ed25519 using native C backend.

    Primary path: Cython binding (zero marshaling overhead).
    Fallback: ctypes binding.

    Args:
        message: Data to sign (arbitrary length)
        secret_key: 64-byte secret key (seed || public_key)

    Returns:
        64-byte Ed25519 signature

    Raises:
        RuntimeError: If native library is not available or signing fails
        ValueError: If secret_key has incorrect length
    """
    if len(secret_key) != ED25519_SECRET_KEY_BYTES:
        raise ValueError(
            f"Ed25519 secret key must be {ED25519_SECRET_KEY_BYTES} bytes, "
            f"got {len(secret_key)}"
        )

    if _cy_ed25519_sign_fn is not None:
        sig_result: bytes = _cy_ed25519_sign_fn(message, bytes(secret_key))
        return sig_result

    if _native_lib is None or not _ED25519_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "Ed25519 native backend not available. " + _INSTALL_HINT
        )

    sig_buf = ctypes.create_string_buffer(ED25519_SIGNATURE_BYTES)
    # INVARIANT-6: use mutable ctypes buffer to avoid non-wipeable bytes() copy
    sk_buf = ctypes.create_string_buffer(bytes(secret_key), len(secret_key))
    try:
        rc = _native_lib.ama_ed25519_sign(sig_buf, message, ctypes.c_size_t(len(message)), sk_buf)
        if rc != 0:
            raise RuntimeError(f"Ed25519 signing failed (rc={rc})")
        return bytes(sig_buf)
    finally:
        ctypes.memset(sk_buf, 0, len(secret_key))


def _probe_cython_ed25519() -> "tuple[Any, Any]":
    """Detect Cython Ed25519 bindings at module load time."""
    try:
        from ama_cryptography.ed25519_binding import (  # type: ignore[import-not-found]  # optional Cython .so, cmake -DAMA_USE_NATIVE_PQC=ON (PQC-004)
            cy_ed25519_sign,
            cy_ed25519_verify,
        )

        return cy_ed25519_sign, cy_ed25519_verify
    except (ImportError, AttributeError):
        return None, None


def _probe_cython_dilithium() -> "tuple[Any, Any]":
    """Detect Cython Dilithium bindings at module load time."""
    try:
        from ama_cryptography.dilithium_binding import (  # type: ignore[import-not-found]  # optional Cython .so, cmake -DAMA_USE_NATIVE_PQC=ON (PQC-005)
            cy_dilithium_sign,
            cy_dilithium_verify,
        )

        return cy_dilithium_sign, cy_dilithium_verify
    except (ImportError, AttributeError):
        return None, None


def _probe_cython_hkdf() -> "Any":
    """Detect Cython HKDF binding at module load time."""
    try:
        from ama_cryptography.hkdf_binding import (  # type: ignore[import-not-found]  # optional Cython .so, cmake -DAMA_USE_NATIVE_PQC=ON (PQC-006)
            cy_hkdf,
        )

        return cy_hkdf
    except (ImportError, AttributeError):
        return None


_cy_ed25519_sign_fn, _cy_ed25519_verify_fn = _probe_cython_ed25519()
_cy_dilithium_sign_fn, _cy_dilithium_verify_fn = _probe_cython_dilithium()
_cy_hkdf_fn = _probe_cython_hkdf()


def native_ed25519_verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """
    Verify Ed25519 signature using native C backend.

    Primary path: Cython binding (zero marshaling overhead).
    Fallback: ctypes binding.

    Args:
        signature: 64-byte Ed25519 signature
        message: Original data that was signed
        public_key: 32-byte Ed25519 public key

    Returns:
        True if signature is valid, False otherwise

    Raises:
        RuntimeError: If native library is not available
        ValueError: If signature or public_key has incorrect length
    """
    if len(signature) != ED25519_SIGNATURE_BYTES:
        raise ValueError(
            f"Ed25519 signature must be {ED25519_SIGNATURE_BYTES} bytes, " f"got {len(signature)}"
        )
    if len(public_key) != ED25519_PUBLIC_KEY_BYTES:
        raise ValueError(
            f"Ed25519 public key must be {ED25519_PUBLIC_KEY_BYTES} bytes, "
            f"got {len(public_key)}"
        )

    if _cy_ed25519_verify_fn is not None:
        verify_result: bool = _cy_ed25519_verify_fn(signature, message, public_key)
        return verify_result

    if _native_lib is None or not _ED25519_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "Ed25519 native backend not available. " + _INSTALL_HINT
        )

    rc: int = _native_lib.ama_ed25519_verify(
        signature, message, ctypes.c_size_t(len(message)), public_key
    )
    return rc == 0


def native_ed25519_batch_verify(
    entries: list,
) -> list:
    """
    Batch verify multiple Ed25519 signatures using native C backend.

    This is intentionally non-constant-time (vartime) because verification
    scalars are public. This is safe and documented in the donna header.

    Args:
        entries: List of (message, signature, public_key) tuples.
            - message: bytes — data that was signed
            - signature: 64-byte Ed25519 signature
            - public_key: 32-byte Ed25519 public key

    Returns:
        List of bools — True if corresponding signature is valid, False otherwise.

    Raises:
        RuntimeError: If native library is not available
        ValueError: If any entry has invalid lengths
    """
    if _native_lib is None or not _ED25519_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "Ed25519 native backend not available. " + _INSTALL_HINT
        )

    count = len(entries)
    if count == 0:
        return []

    # Check if batch verify C function is available; fall back to single verify
    has_batch = hasattr(_native_lib, "ama_ed25519_batch_verify") and (
        getattr(_native_lib.ama_ed25519_batch_verify, "argtypes", None) is not None
    )

    # Validate all entries first
    for i, (_msg, sig, pk) in enumerate(entries):
        if len(sig) != ED25519_SIGNATURE_BYTES:
            raise ValueError(
                f"Entry {i}: Ed25519 signature must be {ED25519_SIGNATURE_BYTES} bytes, "
                f"got {len(sig)}"
            )
        if len(pk) != ED25519_PUBLIC_KEY_BYTES:
            raise ValueError(
                f"Entry {i}: Ed25519 public key must be {ED25519_PUBLIC_KEY_BYTES} bytes, "
                f"got {len(pk)}"
            )

    if has_batch:
        # Use native batch verify
        EntryArray = _Ed25519BatchEntry * count
        c_entries = EntryArray()
        for i, (msg, sig, pk) in enumerate(entries):
            c_entries[i].message = msg
            c_entries[i].message_len = len(msg)
            c_entries[i].signature = sig
            c_entries[i].public_key = pk

        results_arr = (ctypes.c_int * count)()
        rc = _native_lib.ama_ed25519_batch_verify(c_entries, ctypes.c_size_t(count), results_arr)
        # 0=AMA_SUCCESS (all valid), -4=AMA_ERROR_VERIFY_FAILED (some invalid, results populated)
        if rc != 0 and rc != -4:
            raise RuntimeError(f"Ed25519 batch verify failed (rc={rc})")
        return [bool(results_arr[i]) for i in range(count)]

    # Fallback: verify each signature individually
    out: list[bool] = []
    for msg, sig, pk in entries:
        verify_rc: int = _native_lib.ama_ed25519_verify(sig, msg, len(msg), pk)
        out.append(verify_rc == 0)
    return out


# ============================================================================
# AES-256-GCM NATIVE C BACKEND (NIST SP 800-38D)
# ============================================================================


def native_aes256_gcm_encrypt(
    key: _BufferInput,
    nonce: _BufferInput,
    plaintext: _BufferInput,
    aad: _BufferInput = b"",
) -> tuple[bytes, bytes]:
    """
    AES-256-GCM authenticated encryption using native C backend.

    Args:
        key: 32-byte AES-256 key
        nonce: 12-byte nonce (IV)
        plaintext: Data to encrypt
        aad: Additional authenticated data (default: empty)

    Returns:
        (ciphertext, tag) — ciphertext same length as plaintext, 16-byte tag

    Raises:
        RuntimeError: If native library is not available
        ValueError: If key or nonce has incorrect length
    """
    if _native_lib is None or not _AES_GCM_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "AES-256-GCM native backend not available. " + _INSTALL_HINT
        )

    if len(key) != AES256_KEY_BYTES:
        raise ValueError(f"AES-256 key must be {AES256_KEY_BYTES} bytes, got {len(key)}")
    if len(nonce) != AES256_GCM_NONCE_BYTES:
        raise ValueError(
            f"AES-256-GCM nonce must be {AES256_GCM_NONCE_BYTES} bytes, " f"got {len(nonce)}"
        )

    ct_buf = ctypes.create_string_buffer(len(plaintext))
    tag_buf = ctypes.create_string_buffer(AES256_GCM_TAG_BYTES)

    # SECURITY: borrow bytearray-backed key material directly through the
    # buffer protocol; do not call bytes(key), which leaves an immutable
    # transient copy outside the secure wipe path.
    with (
        _c_buffer_view(key) as key_buf,
        _c_buffer_view(nonce) as nonce_buf,
        _c_buffer_view(plaintext) as pt_buf,
        _c_buffer_view(aad) as aad_buf,
    ):
        rc = _native_lib.ama_aes256_gcm_encrypt(
            key_buf,
            nonce_buf,
            pt_buf if len(plaintext) > 0 else None,
            ctypes.c_size_t(len(plaintext)),
            aad_buf if len(aad) > 0 else None,
            ctypes.c_size_t(len(aad)),
            ct_buf,
            tag_buf,
        )
    if rc != 0:
        raise RuntimeError(f"AES-256-GCM encryption failed (rc={rc})")

    return bytes(ct_buf), bytes(tag_buf)


def native_aes256_gcm_decrypt(
    key: _BufferInput,
    nonce: _BufferInput,
    ciphertext: _BufferInput,
    tag: _BufferInput,
    aad: _BufferInput = b"",
) -> bytes:
    """
    AES-256-GCM authenticated decryption using native C backend.

    Args:
        key: 32-byte AES-256 key
        nonce: 12-byte nonce (IV)
        ciphertext: Data to decrypt
        tag: 16-byte authentication tag
        aad: Additional authenticated data (default: empty)

    Returns:
        Decrypted plaintext

    Raises:
        RuntimeError: If native library is not available
        ValueError: If key, nonce, or tag has incorrect length, or if
            authentication tag verification fails
    """
    if _native_lib is None or not _AES_GCM_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "AES-256-GCM native backend not available. " + _INSTALL_HINT
        )

    if len(key) != AES256_KEY_BYTES:
        raise ValueError(f"AES-256 key must be {AES256_KEY_BYTES} bytes, got {len(key)}")
    if len(nonce) != AES256_GCM_NONCE_BYTES:
        raise ValueError(
            f"AES-256-GCM nonce must be {AES256_GCM_NONCE_BYTES} bytes, " f"got {len(nonce)}"
        )
    if len(tag) != AES256_GCM_TAG_BYTES:
        raise ValueError(
            f"AES-256-GCM tag must be {AES256_GCM_TAG_BYTES} bytes, " f"got {len(tag)}"
        )

    pt_buf = ctypes.create_string_buffer(len(ciphertext))

    # SECURITY: borrow bytearray-backed key material directly through the
    # buffer protocol; authentication failure never observes a copied key.
    with (
        _c_buffer_view(key) as key_buf,
        _c_buffer_view(nonce) as nonce_buf,
        _c_buffer_view(ciphertext) as ct_buf,
        _c_buffer_view(aad) as aad_buf,
        _c_buffer_view(tag) as tag_buf,
    ):
        rc = _native_lib.ama_aes256_gcm_decrypt(
            key_buf,
            nonce_buf,
            ct_buf if len(ciphertext) > 0 else None,
            ctypes.c_size_t(len(ciphertext)),
            aad_buf if len(aad) > 0 else None,
            ctypes.c_size_t(len(aad)),
            tag_buf,
            pt_buf,
        )
    if rc != 0:
        raise ValueError("AES-256-GCM authentication tag verification failed")

    return bytes(pt_buf)


# ============================================================================
# HKDF NATIVE C BACKEND (RFC 5869)
# ============================================================================


def native_hkdf(
    ikm: _BufferInput,
    length: int,
    salt: "Optional[_BufferInput]" = None,
    info: _BufferInput = b"",
) -> bytes:
    """
    HKDF key derivation using native C backend (HMAC-SHA3-256).

    Primary path: Cython binding (zero marshaling overhead).
    Fallback: ctypes binding.

    Args:
        ikm: Input key material
        length: Desired output length in bytes (max 8160 = 255*32)
        salt: Optional salt (None uses zero-length salt per RFC 5869)
        info: Context/application-specific info

    Returns:
        Derived key material of requested length

    Raises:
        RuntimeError: If native library is not available
        ValueError: If length exceeds maximum
    """
    if length > 8160:
        raise ValueError(f"HKDF output length must be <= 8160, got {length}")
    if length <= 0:
        raise ValueError(f"HKDF output length must be > 0, got {length}")

    # Primary path: Cython binding for immutable bytes.  Writable key
    # buffers intentionally use the ctypes path below so the native C
    # kernel reads the caller-owned bytearray directly and no Python
    # bytes(key) copy survives outside secure_memzero.
    if (
        _cy_hkdf_fn is not None
        and isinstance(ikm, bytes)
        and (salt is None or isinstance(salt, bytes))
        and isinstance(info, bytes)
    ):
        hkdf_result: bytes = _cy_hkdf_fn(ikm, length, salt=salt, info=info if info else None)
        return hkdf_result

    if _native_lib is None or not _HKDF_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError("HKDF native backend not available. " + _INSTALL_HINT)

    okm_buf = ctypes.create_string_buffer(length)

    salt_len = len(salt) if salt else 0
    info_len = len(info)
    # SECURITY: rekey derives from live bytearray key storage via a
    # borrowed ctypes view.  This removes the previous bytes(self.key)
    # transient heap copy while preserving the native HKDF implementation.
    with (
        _c_buffer_view(ikm) as ikm_buf,
        _c_buffer_view(salt or b"") as salt_buf,
        _c_buffer_view(info) as info_buf,
    ):
        rc = _native_lib.ama_hkdf(
            salt_buf if salt_len > 0 else None,
            ctypes.c_size_t(salt_len),
            ikm_buf if len(ikm) > 0 else None,
            ctypes.c_size_t(len(ikm)),
            info_buf if info_len > 0 else None,
            ctypes.c_size_t(info_len),
            okm_buf,
            ctypes.c_size_t(length),
        )
    if rc != 0:
        raise RuntimeError(f"HKDF derivation failed (rc={rc})")

    return bytes(okm_buf)


def _native_hkdf_sha2(
    fn_name: str,
    digest_size: int,
    ikm: _BufferInput,
    length: int,
    salt: "Optional[_BufferInput]",
    info: _BufferInput,
) -> bytes:
    """Shared body for the HKDF-SHA-256/384/512 (RFC 5869) bindings."""
    max_len = 255 * digest_size
    if length <= 0:
        raise ValueError(f"HKDF output length must be > 0, got {length}")
    if length > max_len:
        raise ValueError(f"HKDF output length must be <= {max_len}, got {length}")
    if _native_lib is None or not _HKDF_SHA2_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "HKDF-SHA-2 native backend not available. " + _INSTALL_HINT
        )

    okm_buf = ctypes.create_string_buffer(length)
    salt_len = len(salt) if salt else 0
    ikm_len = len(ikm)
    info_len = len(info)
    # Borrow stable pointers via the buffer protocol (mirrors native_hkdf).
    # Immutable bytes are passed through; writable bytearray / memoryview key
    # material is read in place through a c_char view rather than coerced via
    # the c_void_p argtype — the latter rejects bytearray outright (TypeError)
    # and never exposes the wipeable buffer to the native kernel directly.
    with (
        _c_buffer_view(ikm) as ikm_buf,
        _c_buffer_view(salt if salt is not None else b"") as salt_buf,
        _c_buffer_view(info) as info_buf,
    ):
        rc = getattr(_native_lib, fn_name)(
            salt_buf if salt_len > 0 else None,
            ctypes.c_size_t(salt_len),
            ikm_buf if ikm_len > 0 else None,
            ctypes.c_size_t(ikm_len),
            info_buf if info_len > 0 else None,
            ctypes.c_size_t(info_len),
            okm_buf,
            ctypes.c_size_t(length),
        )
    if rc != 0:
        raise RuntimeError(f"{fn_name} failed (rc={rc})")
    return bytes(okm_buf)


def native_hkdf_sha256(
    ikm: _BufferInput,
    length: int,
    salt: "Optional[_BufferInput]" = None,
    info: _BufferInput = b"",
) -> bytes:
    """
    HKDF-SHA-256 (RFC 5869) via native C implementation (ama_hkdf_sha256).

    The canonical interoperable KDF: TLS 1.3 (RFC 8446), HPKE (RFC 9180), and
    most non-AMA stacks derive keys with HKDF-SHA-256.  Output is byte-identical
    to a stdlib hmac+hashlib HKDF reference and validated against the RFC 5869
    Appendix A.1-A.3 test vectors.  INVARIANT-1 compliant.

    Args:
        ikm: Input key material.
        length: Desired output length in bytes (max 255*32 = 8160).
        salt: Optional salt (None/empty -> 32 zero bytes per RFC 5869 §2.2).
        info: Optional context/application info.

    Returns:
        `length` bytes of output key material.

    Raises:
        RuntimeError: native backend unavailable.
        ValueError: length out of range.
    """
    return _native_hkdf_sha2("ama_hkdf_sha256", 32, ikm, length, salt, info)


def native_hkdf_sha384(
    ikm: _BufferInput,
    length: int,
    salt: "Optional[_BufferInput]" = None,
    info: _BufferInput = b"",
) -> bytes:
    """
    HKDF-SHA-384 (RFC 5869) via native C implementation (ama_hkdf_sha384).

    Output is byte-identical to a stdlib hmac+hashlib HKDF reference.
    INVARIANT-1 compliant.  Max output length 255*48 = 12240 bytes.
    """
    return _native_hkdf_sha2("ama_hkdf_sha384", 48, ikm, length, salt, info)


def native_hkdf_sha512(
    ikm: _BufferInput,
    length: int,
    salt: "Optional[_BufferInput]" = None,
    info: _BufferInput = b"",
) -> bytes:
    """
    HKDF-SHA-512 (RFC 5869) via native C implementation (ama_hkdf_sha512).

    Output is byte-identical to a stdlib hmac+hashlib HKDF reference.
    INVARIANT-1 compliant.  Max output length 255*64 = 16320 bytes.
    """
    return _native_hkdf_sha2("ama_hkdf_sha512", 64, ikm, length, salt, info)


# ============================================================================
# SHA3-256 NATIVE C BACKEND (FIPS 202)
# ============================================================================


def _probe_cython_sha3() -> "Optional[Callable[[bytes], bytes]]":
    """Detect Cython SHA3-256 binding at module load time."""
    try:
        from ama_cryptography.sha3_binding import cy_sha3_256

        return cy_sha3_256
    except (ImportError, AttributeError):
        return None


_cy_sha3_fn = _probe_cython_sha3()


def native_sha3_256(data: bytes) -> bytes:
    """
    SHA3-256 via native C implementation (ama_sha3_256).

    INVARIANT-1 compliant — zero external crypto dependencies.
    FIPS 202 compliant — Keccak-f[1600] sponge, rate 136, capacity 64.
    Uses Cython binding when available for zero call overhead,
    otherwise falls back to ctypes.

    Args:
        data: Input bytes to hash

    Returns:
        32-byte SHA3-256 digest

    Raises:
        RuntimeError: If native library is not available
    """
    if _cy_sha3_fn is not None:
        try:
            return _cy_sha3_fn(data)
        except Exception:
            raise
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except BaseException as exc:
            raise RuntimeError(f"Cython SHA3-256 panic: {exc}") from exc

    if _native_lib is None or not _SHA3_256_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "SHA3-256 native backend not available. " + _INSTALL_HINT
        )

    out_buf = ctypes.create_string_buffer(32)

    rc = _native_lib.ama_sha3_256(
        data,
        ctypes.c_size_t(len(data)),
        out_buf,
    )
    if rc != 0:
        raise RuntimeError(f"SHA3-256 failed (rc={rc})")

    return bytes(out_buf)


def native_sha256(data: bytes) -> bytes:
    """SHA-256 (FIPS 180-4) via native C implementation (ama_sha256).

    Byte-identical to ``hashlib.sha256(data).digest()``.  INVARIANT-1
    compliant (zero external crypto dependencies); fail-closed per
    INVARIANT-7 (no stdlib fallback).

    Args:
        data: Input bytes to hash.

    Returns:
        32-byte SHA-256 digest.

    Raises:
        RuntimeError: If the native library / ama_sha256 symbol is unavailable.
    """
    if _native_lib is None or not _SHA256_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "SHA-256 native backend not available. " + _INSTALL_HINT
        )

    out_buf = ctypes.create_string_buffer(32)
    # C signature is OUTPUT-FIRST: ama_sha256(out, in, inlen).  Do NOT reorder
    # to match ama_sha3_256(in, len, out) — that would corrupt memory.
    _native_lib.ama_sha256(out_buf, data, ctypes.c_size_t(len(data)))
    return bytes(out_buf)


def native_sha3_512(data: bytes) -> bytes:
    """
    SHA3-512 via native C implementation (ama_sha3_512).

    FIPS 202 compliant.  INVARIANT-1 compliant — lets callers stop falling
    back to stdlib `hashlib.sha3_512` for a primitive the native core already
    provides.  Byte-identical to `hashlib.sha3_512(data).digest()`.

    Args:
        data: Input bytes to hash.

    Returns:
        64-byte SHA3-512 digest.

    Raises:
        RuntimeError: If the native backend is not available.
    """
    if _native_lib is None or not _SHA3_EXT_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "SHA3-512 native backend not available. " + _INSTALL_HINT
        )

    out_buf = ctypes.create_string_buffer(64)
    rc = _native_lib.ama_sha3_512(data, ctypes.c_size_t(len(data)), out_buf)
    if rc != 0:
        raise RuntimeError(f"SHA3-512 failed (rc={rc})")
    return bytes(out_buf)


def _native_shake(fn_name: str, data: bytes, length: int) -> bytes:
    """Shared body for the SHAKE128/256 one-shot XOF bindings."""
    if length < 0:
        raise ValueError(f"SHAKE output length must be >= 0, got {length}")
    if _native_lib is None or not _SHA3_EXT_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError("SHAKE native backend not available. " + _INSTALL_HINT)
    # Zero-length squeeze matches hashlib.shake_*.digest(0) == b"".  The C
    # kernel rejects a NULL output pointer, so short-circuit here.
    if length == 0:
        return b""
    out_buf = ctypes.create_string_buffer(length)
    rc = getattr(_native_lib, fn_name)(
        data,
        ctypes.c_size_t(len(data)),
        out_buf,
        ctypes.c_size_t(length),
    )
    if rc != 0:
        raise RuntimeError(f"{fn_name} failed (rc={rc})")
    return bytes(out_buf.raw[:length])


def native_shake128(data: bytes, length: int) -> bytes:
    """
    SHAKE128 XOF via native C implementation (ama_shake128).

    FIPS 202 compliant.  Byte-identical to
    `hashlib.shake_128(data).digest(length)`.  INVARIANT-1 compliant.

    Args:
        data: Input bytes to absorb.
        length: Desired output length in bytes.

    Returns:
        `length` bytes of XOF output.
    """
    return _native_shake("ama_shake128", data, length)


def native_shake256(data: bytes, length: int) -> bytes:
    """
    SHAKE256 XOF via native C implementation (ama_shake256).

    FIPS 202 compliant.  Byte-identical to
    `hashlib.shake_256(data).digest(length)`.  INVARIANT-1 compliant.

    Args:
        data: Input bytes to absorb.
        length: Desired output length in bytes.

    Returns:
        `length` bytes of XOF output.
    """
    return _native_shake("ama_shake256", data, length)


# ============================================================================
# HMAC-SHA3-256 NATIVE C BACKEND (RFC 2104)
# ============================================================================


def native_hmac_sha3_256(key: bytes, msg: bytes) -> bytes:
    """
    HMAC-SHA3-256 via native C implementation (ama_hmac_sha3_256).

    INVARIANT-1 compliant — zero external crypto dependencies.
    RFC 2104 compliant — 136-byte block size for SHA3-256 (Keccak rate).

    Args:
        key: HMAC key (any length; keys >136 bytes are hashed first)
        msg: Message to authenticate

    Returns:
        32-byte HMAC-SHA3-256 tag

    Raises:
        RuntimeError: If native library is not available
    """
    if _native_lib is None or not _HMAC_SHA3_256_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "HMAC-SHA3-256 native backend not available. " + _INSTALL_HINT
        )

    out_buf = ctypes.create_string_buffer(32)

    rc = _native_lib.ama_hmac_sha3_256(
        key,
        ctypes.c_size_t(len(key)),
        msg,
        ctypes.c_size_t(len(msg)),
        out_buf,
    )
    if rc != 0:
        raise RuntimeError(f"HMAC-SHA3-256 failed (rc={rc})")

    return bytes(out_buf)


def native_hmac_sha512(key: bytes, msg: bytes) -> bytes:
    """
    HMAC-SHA-512 via native C implementation (ama_hmac_sha512).

    Used for BIP32 key derivation in key_management.py.
    INVARIANT-1 compliant — zero external crypto dependencies.

    Args:
        key: HMAC key (any length; keys >128 bytes are hashed first)
        msg: Message to authenticate

    Returns:
        64-byte HMAC-SHA-512 tag

    Raises:
        RuntimeError: If native library is not available
    """
    if _native_lib is None or not _HMAC_SHA512_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "HMAC-SHA-512 native backend not available. " + _INSTALL_HINT
        )

    out_buf = ctypes.create_string_buffer(64)

    rc = _native_lib.ama_hmac_sha512(
        key,
        ctypes.c_size_t(len(key)),
        msg,
        ctypes.c_size_t(len(msg)),
        out_buf,
    )
    if rc != 0:
        raise RuntimeError(f"HMAC-SHA-512 failed (rc={rc})")

    return bytes(out_buf)


def native_hmac_sha384(key: bytes, msg: bytes) -> bytes:
    """
    HMAC-SHA-384 via native C implementation (ama_hmac_sha384).

    Standards: RFC 2104 (HMAC), FIPS 198-1 (HMAC), FIPS 180-4 (SHA-384).
    The C kernel is validated against RFC 4231 test cases 1-7.  Same
    one-shot, rc-checked contract as the existing `native_hmac_sha512`
    binding — the underlying C kernel internally hashes oversized keys
    per RFC 2104 Section 2 (SHA-384's block size is 128 bytes, so the
    key-prep threshold is 128, not 64), so callers do NOT need to
    pre-hash; pass the key verbatim.

    INVARIANT-1 compliant — zero external crypto dependencies.

    Args:
        key: HMAC key (any length; keys > 128 bytes are SHA-384 hashed
             first per RFC 2104 Section 2).  Pass raw bytes; do NOT pre-hash.
        msg: Message to authenticate.

    Returns:
        48-byte HMAC-SHA-384 tag, byte-identical to
        `hmac.new(key, msg, hashlib.sha384).digest()`.

    Raises:
        RuntimeError: If the native library is not loaded or the
                      ama_hmac_sha384 symbol was not bound at module init.
    """
    if _native_lib is None or not _HMAC_SHA384_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "HMAC-SHA-384 native backend not available. " + _INSTALL_HINT
        )

    out_buf = ctypes.create_string_buffer(48)

    rc = _native_lib.ama_hmac_sha384(
        key,
        ctypes.c_size_t(len(key)),
        msg,
        ctypes.c_size_t(len(msg)),
        out_buf,
    )
    if rc != 0:
        raise RuntimeError(f"HMAC-SHA-384 failed (rc={rc})")

    return bytes(out_buf)


def native_hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """
    HMAC-SHA-256 via native C implementation (ama_hmac_sha256).

    Standards: RFC 2104 (HMAC), FIPS 198-1 (HMAC), FIPS 180-4 (SHA-256).
    The C implementation is ACVP-validated against 150/150 NIST CAVP
    vectors (docs/compliance/ACVP_SELF_ATTESTATION.md).  Same one-shot
    contract as the existing `native_hmac_sha512` / `native_hmac_sha3_256`
    bindings — the underlying C kernel internally hashes oversized keys
    per RFC 2104 §2 ("Definition of HMAC") so callers do NOT need to
    pre-hash; pass the key verbatim.

    Intended consumers — every Python code path that today reaches for
    `hmac.new(key, msg, 'sha256').digest()` and would otherwise violate
    INVARIANT-1 ("zero external crypto dependencies") by routing
    through stdlib hashlib.  Concrete v3.2.0 adopters:

      * JWT HS256 signers (wire-defined as HMAC-SHA-256 by RFC 7518
        §3.2; cannot substitute SHA-512 or SHA3-256 and remain RFC 7519
        round-trippable).  Bound consumer: `omni-mercury-engine`'s
        `security/native_jwt.py` `_sign` path — see Mercury PR thread
        in the v3.2.0 release notes.
      * Future TLS 1.2 / 1.3 PRF callers, BIP32 derivation variants
        that prefer SHA-256, S/MIME / IPsec integrity tags.

    Args:
        key: HMAC key (any length; keys >64 bytes are SHA-256 hashed
             first per RFC 2104 §2).  Pass raw bytes; do NOT pre-hash.
        msg: Message to authenticate.

    Returns:
        32-byte HMAC-SHA-256 tag.

    Raises:
        RuntimeError: If the native library is not loaded or the
                      ama_hmac_sha256 symbol was not bound at module
                      init (older AMA build without the v3.2.0 wiring).
    """
    if _native_lib is None or not _HMAC_SHA256_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "HMAC-SHA-256 native backend not available. " + _INSTALL_HINT
        )

    out_buf = ctypes.create_string_buffer(32)

    # ama_hmac_sha256 returns void at the C level (no failure path that
    # isn't a programmer error — invalid pointer / negative length /
    # etc., all caught before the call by ctypes marshalling), so no
    # rc check.  Matches the signature ama_hmac_sha256.h declares.
    _native_lib.ama_hmac_sha256(
        key,
        ctypes.c_size_t(len(key)),
        msg,
        ctypes.c_size_t(len(msg)),
        out_buf,
    )

    return bytes(out_buf)


def native_hmac_sha256_2(key: bytes, msg1: bytes, msg2: bytes) -> bytes:
    """
    HMAC-SHA-256 with two concatenated message segments
    (ama_hmac_sha256_2).

    Equivalent to `native_hmac_sha256(key, msg1 + msg2)` but avoids
    materialising the concatenation in Python.  Useful when the caller
    already has the message in two pieces (e.g., JWT signing input is
    `b64(header) || '.' || b64(payload)` — the separator is a fixed
    single byte the caller would otherwise have to concat in).

    Args:
        key: HMAC key (any length; keys >64 bytes are SHA-256 hashed
             first per RFC 2104 §2).
        msg1: First message segment.
        msg2: Second message segment.

    Returns:
        32-byte HMAC-SHA-256 tag identical to `native_hmac_sha256(key,
        msg1 + msg2)`.

    Raises:
        RuntimeError: If the native library is not loaded or the
                      ama_hmac_sha256_2 symbol was not bound.
    """
    if _native_lib is None or not _HMAC_SHA256_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "HMAC-SHA-256 native backend not available. " + _INSTALL_HINT
        )

    out_buf = ctypes.create_string_buffer(32)

    _native_lib.ama_hmac_sha256_2(
        key,
        ctypes.c_size_t(len(key)),
        msg1,
        ctypes.c_size_t(len(msg1)),
        msg2,
        ctypes.c_size_t(len(msg2)),
        out_buf,
    )

    return bytes(out_buf)


def _probe_cython_hmac() -> "Optional[Callable[[bytes, bytes], bytes]]":
    """Detect Cython HMAC-SHA3-256 binding at module load time."""
    try:
        from ama_cryptography.hmac_binding import cy_hmac_sha3_256

        return cast(Callable[[bytes, bytes], bytes], cy_hmac_sha3_256)
    except (ImportError, AttributeError):
        return None


_cy_hmac_fn = _probe_cython_hmac()

# Patch public availability constants now that Cython probe is complete.
if _cy_hmac_fn is not None:
    HMAC_SHA3_256_AVAILABLE = True
    HMAC_SHA3_256_BACKEND = "cython"
elif _HMAC_SHA3_256_NATIVE_AVAILABLE:
    HMAC_SHA3_256_AVAILABLE = True
    HMAC_SHA3_256_BACKEND = "native"
else:
    HMAC_SHA3_256_AVAILABLE = False
    HMAC_SHA3_256_BACKEND = None

    warnings.warn(
        "HMAC-SHA3-256 native backend not available. "
        "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON "
        "&& cmake --build build  — or install the Cython extension.",
        UserWarning,
        stacklevel=1,
    )


def hmac_sha3_256(key: bytes, msg: bytes) -> bytes:
    """
    HMAC-SHA3-256 via AMA native C implementation.

    Primary path: Cython binding (zero marshaling overhead).
    Fallback: ctypes binding (available if Cython extension not built).

    INVARIANT-1 compliant — zero external crypto dependencies.
    RFC 2104 compliant — 136-byte block size for SHA3-256.

    Raises:
        RuntimeError: If no HMAC-SHA3-256 backend is available (neither
            Cython extension nor native C library found).
    """
    if not HMAC_SHA3_256_AVAILABLE:
        raise NativeBackendUnavailableError("HMAC-SHA3-256 backend not available. " + _INSTALL_HINT)
    if _cy_hmac_fn is not None:
        try:
            return _cy_hmac_fn(key, msg)
        except Exception:
            raise
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except BaseException as exc:
            raise RuntimeError(f"Cython HMAC-SHA3-256 panic: {exc}") from exc
    return native_hmac_sha3_256(key, msg)


# ============================================================================
# PROVIDER WRAPPER CLASSES FOR KAT TESTS
# ============================================================================


@dataclass
class _DilithiumKATKeyPair:
    """Internal keypair structure for KAT test compatibility."""

    public_key: bytes
    secret_key: Union[bytes, bytearray]


class DilithiumProvider:
    """
    Provider wrapper for Dilithium (ML-DSA-65) operations.

    This class provides a consistent interface for NIST KAT tests,
    wrapping the underlying function-based API.

    Example:
        >>> provider = DilithiumProvider()
        >>> keypair = provider.generate_keypair()
        >>> signature = provider.sign(b"message", keypair.secret_key)
        >>> provider.verify(b"message", signature, keypair.public_key)
        True
    """

    def generate_keypair(self) -> _DilithiumKATKeyPair:
        """
        Generate a new Dilithium keypair.

        Returns:
            _DilithiumKATKeyPair with public_key and secret_key attributes
        """
        kp = generate_dilithium_keypair()
        # Copy secret_key to detach from DilithiumKeyPair's bytearray;
        # DilithiumKeyPair.__del__ wipes its own copy on scope exit.
        return _DilithiumKATKeyPair(public_key=kp.public_key, secret_key=bytearray(kp.secret_key))

    def sign(self, message: bytes, secret_key: Union[bytes, bytearray]) -> bytes:
        """
        Sign a message with Dilithium.

        Args:
            message: Data to sign
            secret_key: Dilithium secret key

        Returns:
            Dilithium signature
        """
        return dilithium_sign(message, secret_key)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a Dilithium signature.

        Args:
            message: Original data
            signature: Dilithium signature
            public_key: Dilithium public key

        Returns:
            True if valid, False otherwise
        """
        return dilithium_verify(message, signature, public_key)


@dataclass
class _KyberKATKeyPair:
    """Internal keypair structure for KAT test compatibility."""

    public_key: bytes
    secret_key: Union[bytes, bytearray]


class KyberProvider:
    """
    Provider wrapper for Kyber (ML-KEM-1024) operations.

    This class provides a consistent interface for NIST KAT tests,
    wrapping the underlying function-based API.

    Example:
        >>> provider = KyberProvider()
        >>> keypair = provider.generate_keypair()
        >>> ciphertext, shared_secret = provider.encapsulate(keypair.public_key)
        >>> decapsulated = provider.decapsulate(ciphertext, keypair.secret_key)
        >>> shared_secret == decapsulated
        True
    """

    def generate_keypair(self) -> _KyberKATKeyPair:
        """
        Generate a new Kyber keypair.

        Returns:
            _KyberKATKeyPair with public_key and secret_key attributes
        """
        kp = generate_kyber_keypair()
        # Copy secret_key to detach from KyberKeyPair's bytearray;
        # KyberKeyPair.__del__ wipes its own copy on scope exit.
        return _KyberKATKeyPair(public_key=kp.public_key, secret_key=bytearray(kp.secret_key))

    def encapsulate(self, public_key: bytes) -> tuple:
        """
        Encapsulate a shared secret.

        Args:
            public_key: Kyber public key

        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        result = kyber_encapsulate(public_key)
        return (result.ciphertext, result.shared_secret)

    def decapsulate(self, ciphertext: bytes, secret_key: Union[bytes, bytearray]) -> bytes:
        """
        Decapsulate a shared secret.

        Args:
            ciphertext: Kyber ciphertext
            secret_key: Kyber secret key

        Returns:
            Shared secret bytes
        """
        return kyber_decapsulate(ciphertext, secret_key)


# ============================================================================
# SECP256K1 NATIVE WRAPPERS
# ============================================================================


def native_secp256k1_pubkey_from_privkey(privkey: bytes) -> bytes:
    """
    Compute compressed SEC1 public key from 32-byte private key.

    Args:
        privkey: 32-byte secp256k1 private key

    Returns:
        33-byte compressed public key (0x02/0x03 prefix + X).

        Note the format boundary: this returns a *compressed* SEC 1 point, but
        :func:`native_secp256k1_ecdsa_verify` (and the other secp256k1 entry
        points) consume the 64-byte *uncompressed* ``X || Y`` form with no
        prefix. Convert with :func:`native_secp256k1_pubkey_decompress`, which
        also verifies the point is on the curve:

            pub64 = native_secp256k1_pubkey_decompress(
                native_secp256k1_pubkey_from_privkey(privkey)
            )

    Raises:
        ValueError: If privkey is not 32 bytes
        RuntimeError: If native library is not available
    """
    if len(privkey) != SECP256K1_PRIVKEY_BYTES:
        raise ValueError(f"Private key must be {SECP256K1_PRIVKEY_BYTES} bytes, got {len(privkey)}")

    if _native_lib is None or not _SECP256K1_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "secp256k1 native backend not available. " + _INSTALL_HINT
        )

    pubkey_buf = ctypes.create_string_buffer(SECP256K1_PUBKEY_BYTES)
    rc = _native_lib.ama_secp256k1_pubkey_from_privkey(privkey, pubkey_buf)
    if rc == AMA_ERROR_INVALID_PARAM:
        # A property of the input, not an internal failure — see the matching
        # note on native_nistp_pubkey_from_privkey. SEC 1 §3.2.1 requires a
        # private key in [1, n-1]; the native side now checks both ends.
        raise ValueError(
            "secp256k1 private scalar is out of range: a private key must be in "
            "[1, n-1], and this one is zero or at least the group order"
        )
    if rc != 0:
        raise RuntimeError(f"secp256k1 pubkey derivation failed (rc={rc})")

    return bytes(pubkey_buf)


SECP256K1_ECDSA_MAX_SIG_BYTES = 72
SECP256K1_UNCOMPRESSED_PUBKEY_BYTES = 64


def native_secp256k1_pubkey_decompress(compressed: bytes) -> bytes:
    """
    Recover ``X || Y`` from a compressed SEC 1 secp256k1 public key.

    The inverse of :func:`native_secp256k1_pubkey_from_privkey`'s output form.
    Compressed points are what X.509, JWK-adjacent tooling and most wire
    protocols carry, while every AMA secp256k1 entry point consumes the
    64-octet uncompressed form; without this, a caller holding a compressed
    point has to reimplement a square root over the field to use it.

    The native routine proves the recovered root: an X that is not on the
    curve yields a Y whose square does not match ``x^3 + 7``, and the call is
    refused rather than returning a point that is not on the curve. A
    non-canonical X (``>= p``) is refused for the same reason as everywhere
    else in AMA (INVARIANT-29).

    Every input is public, so this is variable time by design.

    Args:
        compressed: 33 octets, ``0x02``/``0x03`` prefix followed by
            big-endian X.

    Returns:
        64 octets, ``X || Y`` big-endian with no SEC 1 prefix.

    Raises:
        ValueError: If the input is not 33 octets, carries a prefix other
            than ``0x02``/``0x03``, has a non-canonical X, or names an X that
            is not on the curve.
        NativeBackendUnavailableError: If the native library is not available.
    """
    if len(compressed) != SECP256K1_PUBKEY_BYTES:
        raise ValueError(
            f"Compressed public key must be {SECP256K1_PUBKEY_BYTES} bytes, got {len(compressed)}"
        )

    if _native_lib is None or not _SECP256K1_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "secp256k1 native backend not available. " + _INSTALL_HINT
        )

    out = ctypes.create_string_buffer(SECP256K1_UNCOMPRESSED_PUBKEY_BYTES)
    rc = _native_lib.ama_secp256k1_pubkey_decompress(bytes(compressed), out)
    if rc != 0:
        raise ValueError(
            "secp256k1 point decompression failed: bad prefix, non-canonical X, "
            f"or X not on the curve (rc={rc})"
        )

    return bytes(out.raw[:SECP256K1_UNCOMPRESSED_PUBKEY_BYTES])


def native_secp256k1_ecdsa_sign(message_digest: bytes, privkey: bytes) -> bytes:
    """
    Sign a 32-byte message digest with ECDSA over secp256k1.

    Deterministic per RFC 6979 (HMAC-SHA-256): no randomness is consumed
    and the same inputs always produce the same signature. The emitted
    ``s`` is always the canonical low representative (``s <= (n-1)/2``),
    so a signature is a unique identifier for a (key, digest) pair —
    see ``native_secp256k1_ecdsa_verify`` for the matching policy.

    Args:
        message_digest: 32-byte digest. This function does NOT hash;
            pass a digest, not a message.
        privkey: 32-byte secp256k1 private key, big-endian, in [1, n-1].

    Returns:
        DER-encoded signature (8..72 bytes).

    Raises:
        ValueError: If either input has the wrong length.
        RuntimeError: If the native library is unavailable or the private
            key is out of range.
    """
    if len(message_digest) != 32:
        raise ValueError(f"Message digest must be 32 bytes, got {len(message_digest)}")
    if len(privkey) != SECP256K1_PRIVKEY_BYTES:
        raise ValueError(f"Private key must be {SECP256K1_PRIVKEY_BYTES} bytes, got {len(privkey)}")

    if _native_lib is None or not _SECP256K1_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "secp256k1 native backend not available. " + _INSTALL_HINT
        )

    sig_buf = ctypes.create_string_buffer(SECP256K1_ECDSA_MAX_SIG_BYTES)
    sig_len = ctypes.c_size_t(0)
    rc = _native_lib.ama_secp256k1_ecdsa_sign(
        sig_buf, ctypes.byref(sig_len), bytes(message_digest), bytes(privkey)
    )
    if rc != 0:
        raise RuntimeError(f"secp256k1 ECDSA signing failed (rc={rc})")
    return bytes(sig_buf.raw[: sig_len.value])


def native_secp256k1_ecdsa_verify(
    signature: bytes,
    message_digest: bytes,
    pubkey: bytes,
    *,
    allow_high_s: bool = False,
) -> bool:
    """
    Verify a DER-encoded ECDSA signature over secp256k1.

    Strict by default: only canonical DER is accepted (minimal lengths,
    minimal INTEGERs, no trailing bytes), ``r`` and ``s`` must lie in
    [1, n-1] rather than being reduced into range, the public-key
    coordinates must be canonical field elements (< p), and a high ``s`` is
    rejected. Each is a malleability control — without them a second,
    distinct byte string would verify for the same message.

    Set ``allow_high_s=True`` ONLY to verify conformant third-party X9.62
    signatures that do not follow the low-``s`` convention. It relaxes the
    low-``s`` rejection and nothing else — the DER, range, and canonical
    public-key checks are unconditional in both modes. Prefer the strict
    default whenever you control the signer.

    Verification is variable time by design; every input is public.

    Args:
        signature: DER-encoded signature.
        message_digest: 32-byte digest.
        pubkey: 64-byte uncompressed public key, X||Y big-endian,
            WITHOUT the SEC 1 ``0x04`` prefix. A 33-byte compressed point
            (as returned by :func:`native_secp256k1_pubkey_from_privkey`) or a
            65-byte ``0x04``-prefixed point is *not* accepted here; run it
            through :func:`native_secp256k1_pubkey_decompress` (compressed) or
            strip the leading ``0x04`` byte (uncompressed) first.
        allow_high_s: Accept the high-``s`` malleability twin (X9.62 interop).

    Returns:
        True if the signature is valid under the selected policy, False otherwise.

    Raises:
        ValueError: If the digest or public key has the wrong length.
        RuntimeError: If the native library is unavailable.
    """
    if len(message_digest) != 32:
        raise ValueError(f"Message digest must be 32 bytes, got {len(message_digest)}")
    if len(pubkey) != SECP256K1_UNCOMPRESSED_PUBKEY_BYTES:
        raise ValueError(
            f"Public key must be {SECP256K1_UNCOMPRESSED_PUBKEY_BYTES} bytes "
            f"(X||Y, no 0x04 prefix), got {len(pubkey)}"
        )

    if _native_lib is None or not _SECP256K1_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "secp256k1 native backend not available. " + _INSTALL_HINT
        )

    flags = AMA_SECP256K1_ECDSA_ALLOW_HIGH_S if allow_high_s else AMA_SECP256K1_ECDSA_VERIFY_STRICT
    rc = int(
        _native_lib.ama_secp256k1_ecdsa_verify_ex(
            bytes(signature), len(signature), bytes(message_digest), bytes(pubkey), flags
        )
    )
    return rc == 0


# ============================================================================
# NIST PRIME CURVE NATIVE WRAPPERS (P-256 / P-384 / P-521)
#
# ECDSA per FIPS 186-5 with RFC 6979 deterministic nonces, ECDH per
# SP 800-56A §5.7.1.2.  These are the curves TLS, X.509, JOSE/JWT, COSE,
# WebAuthn/FIDO2, CNSA 1.0 and most enterprise HSM fleets actually speak; the
# in-repo Curve25519 and secp256k1 support does not reach any of them.
#
# Conventions shared by every function below:
#   * ``curve`` is one of NISTP_CURVE_P256 / _P384 / _P521, or any name in
#     NISTP_CURVES_BY_NAME.
#   * A private key is ``NISTP_FIELD_BYTES[curve]`` big-endian bytes.
#   * A public key is ``2 * NISTP_FIELD_BYTES[curve]`` bytes, X||Y, with no
#     SEC 1 prefix octet (same shape as the secp256k1 wrappers above).
#   * These functions never hash. Pass a digest of 32, 48 or 64 bytes; its
#     width also selects the RFC 6979 HMAC, exactly as the RFC requires.
# ============================================================================


def _param_set_id(value: Union[int, str], by_name: dict, valid: tuple, family: str) -> int:
    """Normalise a parameter-set selector or name to its ABI integer."""
    if isinstance(value, bool):  # bool is an int subclass; never a parameter set
        raise ValueError(f"Invalid {family} parameter set: {value!r}")
    if isinstance(value, int):
        if value not in valid:
            raise ValueError(f"Unknown {family} parameter set: {value!r}; expected one of {valid}")
        return value
    try:
        return int(by_name[value])
    except KeyError:
        raise ValueError(
            f"Unknown {family} parameter set {value!r}; expected one of {sorted(by_name)}"
        ) from None


def _ml_kem_id(ps: Union[int, str]) -> int:
    return _param_set_id(ps, ML_KEM_BY_NAME, ML_KEM_PARAM_SETS, "ML-KEM")


def _ml_dsa_id(ps: Union[int, str]) -> int:
    return _param_set_id(ps, ML_DSA_BY_NAME, ML_DSA_PARAM_SETS, "ML-DSA")


def _ml_kem_require_native() -> None:
    """INVARIANT-7: refuse rather than substitute anything."""
    if _native_lib is None or not _ML_KEM_NATIVE_AVAILABLE:
        raise PQCUnavailableError("ML-KEM native backend not available. " + _INSTALL_HINT)


def _ml_dsa_require_native() -> None:
    """INVARIANT-7: refuse rather than substitute anything."""
    if _native_lib is None or not _ML_DSA_NATIVE_AVAILABLE:
        raise PQCUnavailableError("ML-DSA native backend not available. " + _INSTALL_HINT)


def ml_kem_sizes(ps: Union[int, str]) -> dict:
    """Public-key / secret-key / ciphertext octet widths for an ML-KEM set."""
    return dict(ML_KEM_SIZES[_ml_kem_id(ps)])


def ml_dsa_sizes(ps: Union[int, str]) -> dict:
    """Public-key / secret-key / signature octet widths for an ML-DSA set."""
    return dict(ML_DSA_SIZES[_ml_dsa_id(ps)])


# ---------------------------------------------------------------------------
# INVARIANT-6 helpers for the ctypes boundary
# ---------------------------------------------------------------------------
def _borrow(secret: _BufferInput) -> Any:
    """A ctypes-compatible view of an input secret, without copying it.

    ``ctypes.c_char_p`` takes ``bytes`` directly, so for an immutable caller
    there is nothing to do and nothing new to wipe. For a ``bytearray`` — the
    storage INVARIANT-6 asks callers to use precisely so they *can* wipe — this
    borrows the buffer in place with ``from_buffer`` rather than copying it.

    This is the non-context-manager sibling of :func:`_c_buffer_view`, which
    the AEAD wrappers already use; the flat form suits the ``try``/``finally``
    shape these wrappers need for their *output* buffers. The borrow is
    released when the returned object is collected, which is at latest when the
    wrapper returns.

    Deliberately not a copy-then-wipe helper. Copying to wipe the copy leaves
    the transient ``bytes`` that had to be made to get there — the exact
    un-wipeable object the exercise exists to avoid — and for a ``bytearray``
    caller it is strictly worse than passing the key straight through.
    """
    if isinstance(secret, bytes):
        return secret
    view = memoryview(secret)
    if view.readonly or view.ndim != 1 or view.itemsize != 1:
        return view.tobytes()
    return (ctypes.c_char * view.nbytes).from_buffer(view)


def _wipe(*buffers: Any) -> None:
    """Zero every buffer given. Safe on ``None`` so it can sit in a ``finally``.

    For *output* buffers only — ones this module allocated and filled with a
    secret the C side produced. The ML-KEM / ML-DSA / NIST-P wrappers dropped
    those while still populated: a fresh secret key, a decapsulated shared
    secret, an ECDH ``Z``. The older wrappers in this file have always
    ``memset`` them in a ``finally``, and this is that idiom named once instead
    of open-coded at every site.

    *Input* secrets go through :func:`_c_buffer_view` instead, which borrows a
    ``bytearray`` in place rather than copying it. A wipe-the-copy helper for
    inputs is worse than useless: the copy it wipes is the second one, and the
    transient it had to make to get there is the un-wipeable ``bytes`` the
    exercise was supposed to avoid.
    """
    for buf in buffers:
        if buf is not None:
            ctypes.memset(buf, 0, ctypes.sizeof(buf))


def native_ml_kem_keypair(ps: Union[int, str]) -> tuple:
    """
    Generate an ML-KEM keypair for any FIPS 203 parameter set.

    Args:
        ps: ``ML_KEM_512`` / ``768`` / ``1024``, or a name in ``ML_KEM_BY_NAME``.

    Returns:
        ``(public_key, secret_key)`` as bytes.

    Raises:
        ValueError: If the parameter set is unknown.
        PQCUnavailableError: If the native backend is unavailable.
        RuntimeError: If key generation failed.
    """
    pid = _ml_kem_id(ps)
    _ml_kem_require_native()
    sz = ML_KEM_SIZES[pid]
    pk = ctypes.create_string_buffer(sz["public_key"])
    sk = ctypes.create_string_buffer(sz["secret_key"])
    try:
        rc = _native_lib.ama_ml_kem_keypair(
            pid, pk, ctypes.c_size_t(sz["public_key"]), sk, ctypes.c_size_t(sz["secret_key"])
        )
        if rc != 0:
            raise RuntimeError(f"ML-KEM keypair generation failed (rc={rc})")
        return bytes(pk.raw[: sz["public_key"]]), bytes(sk.raw[: sz["secret_key"]])
    finally:
        _wipe(sk)


def native_ml_kem_keypair_from_seed(ps: Union[int, str], d: bytes, z: bytes) -> tuple:
    """
    Deterministic ML-KEM keypair from the (d, z) seed pair (FIPS 203 §7.1).

    This is the KAT entry point and the one a PKCS#8 ``seed`` private key needs:
    ``d || z`` is 64 octets and expands to the full key.

    Raises:
        ValueError: If a seed is not exactly 32 bytes, or the set is unknown.
    """
    pid = _ml_kem_id(ps)
    if len(d) != 32 or len(z) != 32:
        raise ValueError(f"ML-KEM seeds must be 32 bytes each, got d={len(d)}, z={len(z)}")
    _ml_kem_require_native()
    sz = ML_KEM_SIZES[pid]
    pk = ctypes.create_string_buffer(sz["public_key"])
    sk = ctypes.create_string_buffer(sz["secret_key"])
    d_buf = _borrow(d)
    z_buf = _borrow(z)
    try:
        rc = _native_lib.ama_ml_kem_keypair_from_seed(
            pid,
            d_buf,
            z_buf,
            pk,
            ctypes.c_size_t(sz["public_key"]),
            sk,
            ctypes.c_size_t(sz["secret_key"]),
        )
        if rc != 0:
            raise RuntimeError(f"ML-KEM deterministic keypair failed (rc={rc})")
        return bytes(pk.raw[: sz["public_key"]]), bytes(sk.raw[: sz["secret_key"]])
    finally:
        _wipe(sk)


def native_ml_kem_pubkey_from_privkey(ps: Union[int, str], secret_key: bytes) -> bytes:
    """
    Recover the encapsulation key from an ML-KEM decapsulation key, verifying
    the decapsulation key's internal consistency.

    FIPS 203 §7.1 lays ``dk`` out as ``dk_PKE || ek || H(ek) || z``, so ``ek``
    is embedded verbatim — but the fields are mutually redundant, and a ``dk``
    whose fields disagree decapsulates to a shared secret the sender never
    derived. ML-KEM's implicit rejection is *designed* to fail silently, so
    that mismatch raises no error anywhere downstream; it is only visible here.
    Two checks run: ``H(ek)`` must be SHA3-256 of the embedded ``ek``, and an
    encapsulate/decapsulate round trip must agree.

    Needed to import a PKCS#8 private key carrying only the ``expandedKey``
    arm, which has no public key to read.

    Raises:
        ValueError: On a wrong key length, an unknown parameter set, or a key
            whose embedded digest or key pair is inconsistent.
    """
    pid = _ml_kem_id(ps)
    sz = ML_KEM_SIZES[pid]
    if len(secret_key) != sz["secret_key"]:
        raise ValueError(
            f"ML-KEM-{pid} secret key must be {sz['secret_key']} bytes, got {len(secret_key)}"
        )
    _ml_kem_require_native()
    pk = ctypes.create_string_buffer(sz["public_key"])
    sk_buf = _borrow(secret_key)
    rc = _native_lib.ama_ml_kem_pubkey_from_privkey(
        pid,
        sk_buf,
        ctypes.c_size_t(sz["secret_key"]),
        pk,
        ctypes.c_size_t(sz["public_key"]),
    )
    if rc != 0:
        raise ValueError(
            f"ML-KEM-{pid} decapsulation key is internally inconsistent: the "
            f"embedded H(ek) or the key pair itself does not check out (rc={rc})"
        )
    return bytes(pk.raw[: sz["public_key"]])


def native_ml_kem_privkey_check(ps: Union[int, str], secret_key: bytes) -> bool:
    """
    Whether an ML-KEM decapsulation key is internally consistent.

    The verdict form of :func:`native_ml_kem_pubkey_from_privkey`; identical
    checks. Returns ``False`` rather than raising for an inconsistent key, so a
    caller validating untrusted material does not have to catch.

    Raises:
        ValueError: On a wrong key length or an unknown parameter set — those
            are caller errors, not verdicts.
    """
    pid = _ml_kem_id(ps)
    sz = ML_KEM_SIZES[pid]
    if len(secret_key) != sz["secret_key"]:
        raise ValueError(
            f"ML-KEM-{pid} secret key must be {sz['secret_key']} bytes, got {len(secret_key)}"
        )
    _ml_kem_require_native()
    sk_buf = _borrow(secret_key)
    rc = _native_lib.ama_ml_kem_privkey_check(pid, sk_buf, ctypes.c_size_t(sz["secret_key"]))
    return bool(rc == 0)


def native_ml_kem_pubkey_check(ps: Union[int, str], public_key: bytes) -> bool:
    """
    Whether an ML-KEM encapsulation key passes FIPS 203 §7.2 input validation.

    §7.2 mandates two checks before an encapsulation key may be used: the type
    check (length) and the **modulus check** — every 12-bit coefficient of
    ``t_hat`` must be below ``q = 3329``, equivalently
    ``ByteEncode_12(ByteDecode_12(ek))`` must reproduce ``ek``.

    The modulus check is the one implementations skip, and skipping it is not
    cosmetic: a conformant peer rejects an out-of-range key, so encapsulating to
    one produces a shared secret nobody else derives — and ML-KEM's implicit
    rejection is designed to fail silently, so nothing raises. 767 of every 4096
    encodable values are out of range, so a flipped bit in a real key has about
    a one-in-five chance of producing exactly this.

    :func:`native_ml_kem_encapsulate` performs both checks itself; this is for
    the import path, where a key should be refused rather than stored.

    Returns ``False`` for an out-of-range key rather than raising, so a caller
    validating untrusted material does not have to catch.

    Raises:
        ValueError: On a wrong key length or an unknown parameter set — those
            are caller errors, not verdicts.
    """
    pid = _ml_kem_id(ps)
    sz = ML_KEM_SIZES[pid]
    if len(public_key) != sz["public_key"]:
        raise ValueError(
            f"ML-KEM-{pid} public key must be {sz['public_key']} bytes, got {len(public_key)}"
        )
    _ml_kem_require_native()
    rc = _native_lib.ama_ml_kem_pubkey_check(
        pid, bytes(public_key), ctypes.c_size_t(sz["public_key"])
    )
    return bool(rc == 0)


def native_ml_kem_encapsulate(ps: Union[int, str], public_key: bytes) -> tuple:
    """
    ML-KEM encapsulation (FIPS 203 Algorithm 17).

    Returns:
        ``(ciphertext, shared_secret)``; the shared secret is 32 bytes for
        every parameter set.

    Raises:
        ValueError: If the public key has the wrong length for ``ps``.
    """
    pid = _ml_kem_id(ps)
    sz = ML_KEM_SIZES[pid]
    if len(public_key) != sz["public_key"]:
        raise ValueError(
            f"ML-KEM-{pid} public key must be {sz['public_key']} bytes, got {len(public_key)}"
        )
    _ml_kem_require_native()
    ct = ctypes.create_string_buffer(sz["ciphertext"])
    ct_len = ctypes.c_size_t(sz["ciphertext"])
    ss = ctypes.create_string_buffer(ML_KEM_SHARED_SECRET_BYTES)
    try:
        rc = _native_lib.ama_ml_kem_encapsulate(
            pid,
            bytes(public_key),
            ctypes.c_size_t(len(public_key)),
            ct,
            ctypes.byref(ct_len),
            ss,
            ctypes.c_size_t(ML_KEM_SHARED_SECRET_BYTES),
        )
        if rc != 0:
            raise RuntimeError(f"ML-KEM encapsulation failed (rc={rc})")
        return bytes(ct.raw[: ct_len.value]), bytes(ss.raw[:ML_KEM_SHARED_SECRET_BYTES])
    finally:
        _wipe(ss)


def native_ml_kem_decapsulate(
    ps: Union[int, str], ciphertext: bytes, secret_key: Union[bytes, bytearray]
) -> bytes:
    """
    ML-KEM decapsulation (FIPS 203 Algorithm 18).

    A malformed ciphertext does NOT raise: FIPS 203 mandates implicit
    rejection, so decapsulation returns a deterministic pseudorandom secret
    that differs from the sender's. Treating a mismatch as an error here would
    reintroduce the very oracle implicit rejection exists to close. Only a
    wrong *length* is an error, because that is a caller bug rather than an
    attacker-supplied ciphertext.
    """
    pid = _ml_kem_id(ps)
    sz = ML_KEM_SIZES[pid]
    if len(ciphertext) != sz["ciphertext"]:
        raise ValueError(
            f"ML-KEM-{pid} ciphertext must be {sz['ciphertext']} bytes, got {len(ciphertext)}"
        )
    if len(secret_key) != sz["secret_key"]:
        raise ValueError(
            f"ML-KEM-{pid} secret key must be {sz['secret_key']} bytes, got {len(secret_key)}"
        )
    _ml_kem_require_native()
    ss = ctypes.create_string_buffer(ML_KEM_SHARED_SECRET_BYTES)
    sk_buf = _borrow(secret_key)
    try:
        rc = _native_lib.ama_ml_kem_decapsulate(
            pid,
            bytes(ciphertext),
            ctypes.c_size_t(len(ciphertext)),
            sk_buf,
            ctypes.c_size_t(len(secret_key)),
            ss,
            ctypes.c_size_t(ML_KEM_SHARED_SECRET_BYTES),
        )
        if rc != 0:
            raise RuntimeError(f"ML-KEM decapsulation failed (rc={rc})")
        return bytes(ss.raw[:ML_KEM_SHARED_SECRET_BYTES])
    finally:
        _wipe(ss)


def native_ml_dsa_keypair(ps: Union[int, str]) -> tuple:
    """Generate an ML-DSA keypair for any FIPS 204 parameter set."""
    pid = _ml_dsa_id(ps)
    _ml_dsa_require_native()
    sz = ML_DSA_SIZES[pid]
    pk = ctypes.create_string_buffer(sz["public_key"])
    sk = ctypes.create_string_buffer(sz["secret_key"])
    try:
        rc = _native_lib.ama_ml_dsa_keypair(pid, pk, sk)
        if rc != 0:
            raise RuntimeError(f"ML-DSA keypair generation failed (rc={rc})")
        return bytes(pk.raw[: sz["public_key"]]), bytes(sk.raw[: sz["secret_key"]])
    finally:
        _wipe(sk)


def native_ml_dsa_keypair_from_seed(ps: Union[int, str], xi: bytes) -> tuple:
    """
    Deterministic ML-DSA keypair from the 32-octet seed xi (FIPS 204 §5.1).

    Raises:
        ValueError: If the seed is not exactly 32 bytes, or the set is unknown.
    """
    pid = _ml_dsa_id(ps)
    if len(xi) != 32:
        raise ValueError(f"ML-DSA seed must be 32 bytes, got {len(xi)}")
    _ml_dsa_require_native()
    sz = ML_DSA_SIZES[pid]
    pk = ctypes.create_string_buffer(sz["public_key"])
    sk = ctypes.create_string_buffer(sz["secret_key"])
    xi_buf = _borrow(xi)
    try:
        rc = _native_lib.ama_ml_dsa_keypair_from_seed(pid, xi_buf, pk, sk)
        if rc != 0:
            raise RuntimeError(f"ML-DSA deterministic keypair failed (rc={rc})")
        return bytes(pk.raw[: sz["public_key"]]), bytes(sk.raw[: sz["secret_key"]])
    finally:
        _wipe(sk)


def native_ml_dsa_pubkey_from_privkey(ps: Union[int, str], secret_key: bytes) -> bytes:
    """
    Recompute the public key from an expanded ML-DSA private key, verifying
    that private key's internal consistency.

    The expanded key ``rho || K || tr || s1 || s2 || t0`` is redundant: rho, s1
    and s2 determine ``t = A*s1 + s2``, hence ``t0``, hence the public key
    ``rho || t1``, hence ``tr = H(rho || t1)``. This recomputes that chain and
    requires the stored ``t0`` and ``tr`` to agree with it.

    Needed to import a PKCS#8 private key carrying only the ``expandedKey``
    arm, which has no public key to read. RFC 9881 §8.2 names the two failures
    this catches and Appendix C.4 ships a vector for each — a mismatched
    ``tr``, and ``s1``/``s2`` whose implied ``t`` has different low bits than
    the stored ``t0`` — noting that implementations which skip the check
    detect neither.

    Raises:
        ValueError: On a wrong key length, an unknown parameter set, an
            ``s1``/``s2`` coefficient outside ``[-eta, eta]`` (FIPS 204
            Algorithm 25), or a ``t0``/``tr`` disagreement.
    """
    pid = _ml_dsa_id(ps)
    sz = ML_DSA_SIZES[pid]
    if len(secret_key) != sz["secret_key"]:
        raise ValueError(
            f"ML-DSA-{pid} secret key must be {sz['secret_key']} bytes, got {len(secret_key)}"
        )
    _ml_dsa_require_native()
    pk = ctypes.create_string_buffer(sz["public_key"])
    sk_buf = _borrow(secret_key)
    rc = _native_lib.ama_ml_dsa_pubkey_from_privkey(pid, sk_buf, pk)
    if rc != 0:
        raise ValueError(
            f"ML-DSA-{pid} private key is internally inconsistent: its s1/s2 are "
            f"out of range, or the t0/tr it carries do not match the key those "
            f"vectors imply (rc={rc})"
        )
    return bytes(pk.raw[: sz["public_key"]])


def native_ml_dsa_privkey_check(ps: Union[int, str], secret_key: bytes) -> bool:
    """
    Whether an expanded ML-DSA private key is internally consistent.

    The verdict form of :func:`native_ml_dsa_pubkey_from_privkey`; identical
    checks. Returns ``False`` rather than raising for an inconsistent key, so a
    caller validating untrusted material does not have to catch.

    Raises:
        ValueError: On a wrong key length or an unknown parameter set — those
            are caller errors, not verdicts.
    """
    pid = _ml_dsa_id(ps)
    sz = ML_DSA_SIZES[pid]
    if len(secret_key) != sz["secret_key"]:
        raise ValueError(
            f"ML-DSA-{pid} secret key must be {sz['secret_key']} bytes, got {len(secret_key)}"
        )
    _ml_dsa_require_native()
    sk_buf = _borrow(secret_key)
    return bool(_native_lib.ama_ml_dsa_privkey_check(pid, sk_buf) == 0)


def native_ml_dsa_sign(
    ps: Union[int, str],
    message: bytes,
    secret_key: Union[bytes, bytearray],
    *,
    ctx: Optional[bytes] = None,
) -> bytes:
    """
    Sign with ML-DSA (FIPS 204), deterministic variant (rnd = 0^256).

    Args:
        ctx: When not None, applies the FIPS 204 §5.2 external/pure context
            wrapper ``0x00 || len(ctx) || ctx || M``. ``ctx=b""`` is the
            empty-context *external* form and is NOT the same signature as
            ``ctx=None`` (the internal interface) — they are different
            domains, which is the entire point of the wrapper.

    Raises:
        ValueError: On a wrong key length or a context longer than 255 bytes.
    """
    pid = _ml_dsa_id(ps)
    sz = ML_DSA_SIZES[pid]
    if len(secret_key) != sz["secret_key"]:
        raise ValueError(
            f"ML-DSA-{pid} secret key must be {sz['secret_key']} bytes, got {len(secret_key)}"
        )
    if ctx is not None and len(ctx) > 255:
        raise ValueError(f"ML-DSA context must be at most 255 bytes, got {len(ctx)}")
    _ml_dsa_require_native()

    sig = ctypes.create_string_buffer(sz["signature"])
    sig_len = ctypes.c_size_t(sz["signature"])
    sk_buf = _borrow(secret_key)
    if ctx is None:
        rc = _native_lib.ama_ml_dsa_sign(
            pid,
            sig,
            ctypes.byref(sig_len),
            bytes(message),
            ctypes.c_size_t(len(message)),
            sk_buf,
        )
    else:
        rc = _native_lib.ama_ml_dsa_sign_ctx(
            pid,
            sig,
            ctypes.byref(sig_len),
            bytes(message),
            ctypes.c_size_t(len(message)),
            bytes(ctx),
            ctypes.c_size_t(len(ctx)),
            sk_buf,
        )
    if rc == AMA_ERROR_INVALID_PARAM:
        # The signer applies FIPS 204 Algorithm 25's range gate to s1/s2, so a
        # secret key of the right length can still be refused here. That is a
        # property of the key the caller passed, not a failure of the operation,
        # and every other bad-input refusal in this module is a ValueError.
        raise ValueError(
            "ML-DSA signing refused the secret key: its s1/s2 carry a "
            "coefficient outside [-eta, eta] (FIPS 204 Algorithm 25), so it is "
            "not a well-formed private key"
        )
    if rc != 0:
        raise RuntimeError(f"ML-DSA signing failed (rc={rc})")
    return bytes(sig.raw[: sig_len.value])


def native_ml_dsa_verify(
    ps: Union[int, str],
    message: bytes,
    signature: bytes,
    public_key: bytes,
    *,
    ctx: Optional[bytes] = None,
) -> bool:
    """
    Verify an ML-DSA signature (FIPS 204).

    ``ctx`` must match what the signer used: ``None`` for the internal
    interface, or the same context octets for the external/pure form.

    Returns:
        True if valid. A wrong-length signature or public key returns False
        rather than raising — those are just invalid signatures.
    """
    pid = _ml_dsa_id(ps)
    sz = ML_DSA_SIZES[pid]
    # INVARIANT-7 first: with no backend loaded, `False` would read as "the
    # library checked this signature and it is invalid" when nothing checked
    # anything. Refusing is the only honest answer.
    _ml_dsa_require_native()
    if len(public_key) != sz["public_key"] or len(signature) != sz["signature"]:
        return False
    if ctx is not None and len(ctx) > 255:
        return False

    if ctx is None:
        rc = _native_lib.ama_ml_dsa_verify(
            pid,
            bytes(message),
            ctypes.c_size_t(len(message)),
            bytes(signature),
            ctypes.c_size_t(len(signature)),
            bytes(public_key),
        )
    else:
        rc = _native_lib.ama_ml_dsa_verify_ctx(
            pid,
            bytes(message),
            ctypes.c_size_t(len(message)),
            bytes(ctx),
            ctypes.c_size_t(len(ctx)),
            bytes(signature),
            ctypes.c_size_t(len(signature)),
            bytes(public_key),
        )
    return int(rc) == 0


def _nistp_curve_id(curve: Union[int, str]) -> int:
    """Normalise a curve selector or name to its ABI integer.

    Accepting the SEC 1 / OpenSSL aliases alongside the JOSE names is
    deliberate: callers arrive here from ASN.1 OIDs, JWK ``crv`` values and
    config files, and silently mapping an unknown name to P-256 would be the
    worst possible failure mode. Anything unrecognised raises.
    """
    if isinstance(curve, bool):  # bool is an int subclass; never a curve id
        raise ValueError(f"Invalid NIST curve selector: {curve!r}")
    if isinstance(curve, int):
        if curve not in NISTP_FIELD_BYTES:
            raise ValueError(f"Unknown NIST curve selector: {curve!r}")
        return curve
    try:
        return int(NISTP_CURVES_BY_NAME[curve])
    except KeyError:
        raise ValueError(
            f"Unknown NIST curve name {curve!r}; " f"expected one of {sorted(NISTP_CURVES_BY_NAME)}"
        ) from None


def _nistp_require_native() -> None:
    """INVARIANT-7: refuse rather than substitute anything."""
    if _native_lib is None or not _NISTP_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "NIST prime-curve native backend not available. " + _INSTALL_HINT
        )


def nistp_default_hash(curve: Union[int, str]) -> str:
    """The hash FIPS 186-5 / RFC 5480 practice pairs with ``curve``.

    P-256 with SHA-256, P-384 with SHA-384, P-521 with SHA-512 — the pairing
    JOSE spells ``ES256``/``ES384``/``ES512`` and COSE reuses. ``ama_nistp_*``
    hashes nothing itself (it takes a digest), so a caller has to choose, and
    choosing wrong is not an error anything reports: a SHA-256 digest signed
    under P-521 verifies perfectly and interoperates with nothing that expects
    ``ES512``.

    ``NISTP_DEFAULT_HASH`` was added as the table for this and then read by
    nothing, which is how a table stops being true. This is its one reader, and
    ``tests/test_nistp_curves.py`` checks the pairing against the digest widths
    the signer accepts rather than against a second copy of the table.
    """
    return str(NISTP_DEFAULT_HASH[_nistp_curve_id(curve)])


def _nistp_check_digest(digest: bytes) -> None:
    if len(digest) not in (32, 48, 64):
        raise ValueError(f"Digest must be 32, 48 or 64 bytes (SHA-256/384/512), got {len(digest)}")


def nistp_field_bytes(curve: Union[int, str]) -> int:
    """Octet width of a private key / field element for ``curve``."""
    return int(NISTP_FIELD_BYTES[_nistp_curve_id(curve)])


def native_nistp_keypair(curve: Union[int, str]) -> tuple:
    """
    Generate a fresh NIST prime-curve keypair from the platform CSPRNG.

    The private scalar is drawn by rejection sampling into [1, n-1], so its
    distribution is exactly uniform — it is not a wide random value reduced
    mod n, which would be measurably biased for P-521.

    Args:
        curve: Curve selector or name.

    Returns:
        ``(public_key, private_key)`` as bytes — public FIRST, matching every
        other keypair function in this module (``native_x25519_keypair``,
        ``native_ed25519_keypair``, ``native_ml_kem_keypair``, ...).

        The ordering is uniform on purpose. An earlier revision of this
        function returned ``(private_key, public_key)``, which meant a caller
        moving between two AMA keypair calls in the same file could land a
        private key in the variable they were about to publish. The convention
        is asserted across every keypair function by
        ``tests/test_keypair_conventions.py`` so it cannot drift again.

    Raises:
        ValueError: If the curve is unknown.
        NativeBackendUnavailableError: If the native library is unavailable.
        RuntimeError: If the CSPRNG failed.
    """
    cid = _nistp_curve_id(curve)
    _nistp_require_native()
    nb = NISTP_FIELD_BYTES[cid]
    priv = ctypes.create_string_buffer(nb)
    pub = ctypes.create_string_buffer(2 * nb)
    try:
        rc = _native_lib.ama_nistp_keypair(cid, priv, pub)
        if rc != 0:
            raise RuntimeError(f"NIST curve keypair generation failed (rc={rc})")
        return bytes(pub.raw[: 2 * nb]), bytes(priv.raw[:nb])
    finally:
        _wipe(priv)


def native_nistp_pubkey_from_privkey(curve: Union[int, str], privkey: bytes) -> bytes:
    """
    Derive the X||Y public key for an existing private scalar.

    Raises:
        ValueError: If the curve is unknown, the key length is wrong, or the
            scalar is not a valid private key (zero, or >= n). All three are
            properties of the *input*, which matters because this is reachable
            from the key-file parser: ``load_pkcs8`` turns a ``ValueError`` here
            into a ``KeyFormatError``, and previously could not, because an
            out-of-range scalar arrived as a ``RuntimeError`` and escaped the
            format layer entirely. Found by fuzz/python/fuzz_key_formats.py.
        RuntimeError: If the native library is unavailable, or on an internal
            failure that is not attributable to the arguments.
    """
    cid = _nistp_curve_id(curve)
    nb = NISTP_FIELD_BYTES[cid]
    if len(privkey) != nb:
        raise ValueError(f"Private key must be {nb} bytes for this curve, got {len(privkey)}")
    _nistp_require_native()
    pub = ctypes.create_string_buffer(2 * nb)
    priv_buf = _borrow(privkey)
    rc = _native_lib.ama_nistp_pubkey_from_privkey(cid, priv_buf, pub)
    if rc == AMA_ERROR_INVALID_PARAM:
        raise ValueError(
            "NIST curve private scalar is out of range: a private key must be in "
            "[1, n-1], and this one is zero or at least the group order"
        )
    if rc != 0:
        raise RuntimeError(f"NIST curve public-key derivation failed (rc={rc})")
    return bytes(pub.raw[: 2 * nb])


def native_nistp_pubkey_validate(curve: Union[int, str], pubkey: bytes) -> bool:
    """
    Full public-key validation: canonical coordinates in [0, p), on the curve,
    not the identity.

    All three curves have cofactor 1 and prime order, so this is exactly
    "member of the prime-order group". Returns False rather than raising for a
    wrong-length key, because a wrong length is just another invalid key.
    """
    cid = _nistp_curve_id(curve)
    nb = NISTP_FIELD_BYTES[cid]
    # INVARIANT-7 first — see native_ml_dsa_verify for why the order matters.
    _nistp_require_native()
    if len(pubkey) != 2 * nb:
        return False
    return int(_native_lib.ama_nistp_pubkey_validate(cid, bytes(pubkey))) == 0


def native_nistp_point_encode(
    curve: Union[int, str], pubkey: bytes, *, compressed: bool = False
) -> bytes:
    """Encode an X||Y public key as a prefixed SEC 1 point."""
    cid = _nistp_curve_id(curve)
    nb = NISTP_FIELD_BYTES[cid]
    if len(pubkey) != 2 * nb:
        raise ValueError(f"Public key must be {2 * nb} bytes (X||Y), got {len(pubkey)}")
    _nistp_require_native()
    out = ctypes.create_string_buffer(2 * nb + 1)
    out_len = ctypes.c_size_t(0)
    rc = _native_lib.ama_nistp_point_encode(
        cid, bytes(pubkey), 1 if compressed else 0, out, ctypes.byref(out_len)
    )
    if rc != 0:
        raise ValueError(f"Point encoding rejected the public key (rc={rc})")
    return bytes(out.raw[: out_len.value])


def native_nistp_point_decode(curve: Union[int, str], point: bytes) -> bytes:
    """
    Decode a prefixed SEC 1 point (0x04 uncompressed, 0x02/0x03 compressed)
    into X||Y.

    Decompression recovers ``y`` as a modular square root and then proves it
    by squaring, so an ``x`` that is not on the curve is rejected instead of
    yielding an off-curve point. The result is fully validated before return.

    Raises:
        ValueError: On any malformed, off-curve, or non-canonical input.
    """
    cid = _nistp_curve_id(curve)
    nb = NISTP_FIELD_BYTES[cid]
    _nistp_require_native()
    out = ctypes.create_string_buffer(2 * nb)
    rc = _native_lib.ama_nistp_point_decode(cid, bytes(point), len(point), out)
    if rc != 0:
        raise ValueError(f"Invalid SEC 1 point encoding (rc={rc})")
    return bytes(out.raw[: 2 * nb])


def native_nistp_ecdh(curve: Union[int, str], privkey: bytes, peer_pubkey: bytes) -> bytes:
    """
    ECDH shared secret (SP 800-56A §5.7.1.2 ECC CDH, cofactor 1).

    The peer key is fully validated *before* the private scalar touches it.
    That check is the invalid-curve defence: without it, a peer that submits a
    point on a different, smooth-order curve recovers the private key from a
    handful of exchanges.

    The return value is the raw x-coordinate ("Z" in SP 800-56A). It is key
    *material*, not a key — run it through a KDF (``native_hkdf_sha256`` and
    friends) before using it.

    Raises:
        ValueError: If a length is wrong, the peer key is not a valid point of
            the prime-order group, or the private scalar is outside [1, n-1].
            All three are properties of the *arguments*, and this is the entry
            point an attacker-supplied key reaches; classifying them as
            RuntimeError made "the peer sent a bad point" indistinguishable
            from "the backend broke".
        RuntimeError: If the native library is unavailable, or on an internal
            failure not attributable to the arguments.
    """
    cid = _nistp_curve_id(curve)
    nb = NISTP_FIELD_BYTES[cid]
    if len(privkey) != nb:
        raise ValueError(f"Private key must be {nb} bytes, got {len(privkey)}")
    if len(peer_pubkey) != 2 * nb:
        raise ValueError(f"Peer public key must be {2 * nb} bytes (X||Y), got {len(peer_pubkey)}")
    _nistp_require_native()
    out = ctypes.create_string_buffer(nb)
    priv_buf = _borrow(privkey)
    try:
        rc = _native_lib.ama_nistp_ecdh(cid, priv_buf, bytes(peer_pubkey), out)
        if rc == AMA_ERROR_INVALID_PARAM:
            # The peer key failed validation, or the private scalar is out of
            # range. Both are properties of the arguments, and this is the one
            # ECDH entry point an attacker's key reaches — a RuntimeError here
            # is indistinguishable from "the backend broke", which is exactly
            # the confusion the rest of this module refuses to create.
            raise ValueError(
                "NIST curve ECDH refused its inputs: the peer public key is not a "
                "valid point of the prime-order group, or the private scalar is "
                "not in [1, n-1]"
            )
        if rc != 0:
            raise RuntimeError(f"NIST curve ECDH failed (rc={rc})")
        return bytes(out.raw[:nb])
    finally:
        _wipe(out)


def native_nistp_ecdsa_sign(
    curve: Union[int, str],
    message_digest: bytes,
    privkey: bytes,
    *,
    raw: bool = False,
    hedged: bool = False,
    low_s: bool = False,
) -> bytes:
    """
    Sign a digest with ECDSA over a NIST prime curve.

    Deterministic per RFC 6979 by default, and *conformant* to it: ``s`` is
    emitted exactly as the RFC produces it, so this reproduces RFC 6979's own
    Appendix A.2.5 / A.2.6 / A.2.7 vectors byte-for-byte.

    Args:
        curve: Curve selector or name.
        message_digest: 32, 48 or 64 bytes. This function does NOT hash.
            The width also selects the RFC 6979 HMAC (SHA-256/384/512).
        privkey: Private scalar, big-endian, in [1, n-1].
        raw: Emit fixed-width ``r || s`` (JWS RFC 7515 §3.4 / COSE / WebAuthn)
            instead of DER (X.509 / TLS / PKCS#11).
        hedged: Mix 32 fresh CSPRNG bytes into the nonce DRBG per RFC 6979
            §3.6. Keeps the nonce safe if the RNG is broken *and* hardens the
            deterministic path against fault injection — at the cost of
            reproducibility.
        low_s: Emit the low-``s`` representative. This is X9.62-conformant but
            NOT RFC 6979-conformant: roughly half of all signatures will differ
            from the value the RFC specifies. It is a security property only
            when paired with ``require_low_s=True`` verification — on its own
            the high twin of the signature still verifies. Set both or neither
            (INVARIANT-34).

    Returns:
        DER signature (8..141 bytes) or ``2 * field_bytes`` raw bytes.

    Raises:
        ValueError: On a wrong length or an unsupported digest width.
        RuntimeError: If the native library is unavailable or signing failed.
    """
    cid = _nistp_curve_id(curve)
    nb = NISTP_FIELD_BYTES[cid]
    _nistp_check_digest(message_digest)
    if len(privkey) != nb:
        raise ValueError(f"Private key must be {nb} bytes, got {len(privkey)}")
    _nistp_require_native()

    flags = AMA_NISTP_ECDSA_SIGN_DEFAULT
    if low_s:
        flags |= AMA_NISTP_ECDSA_SIGN_LOW_S
    if hedged:
        flags |= AMA_NISTP_ECDSA_SIGN_HEDGED

    priv_buf = _borrow(privkey)
    if raw:
        out = ctypes.create_string_buffer(2 * nb)
        rc = _native_lib.ama_nistp_ecdsa_sign_raw_ex(
            cid, bytes(message_digest), len(message_digest), priv_buf, out, flags
        )
        if rc != 0:
            raise RuntimeError(f"NIST curve ECDSA signing failed (rc={rc})")
        return bytes(out.raw[: 2 * nb])

    out = ctypes.create_string_buffer(NISTP_MAX_SIG_LEN)
    out_len = ctypes.c_size_t(0)
    rc = _native_lib.ama_nistp_ecdsa_sign_ex(
        cid,
        bytes(message_digest),
        len(message_digest),
        priv_buf,
        out,
        ctypes.byref(out_len),
        flags,
    )
    if rc != 0:
        raise RuntimeError(f"NIST curve ECDSA signing failed (rc={rc})")
    return bytes(out.raw[: out_len.value])


def native_nistp_ecdsa_verify(
    curve: Union[int, str],
    signature: bytes,
    message_digest: bytes,
    pubkey: bytes,
    *,
    raw: bool = False,
    require_low_s: bool = False,
) -> bool:
    """
    Verify an ECDSA signature over a NIST prime curve.

    Unconditional in every mode: minimal DER only (short form, or the single
    long-form octet where a P-521 body genuinely exceeds 127 octets), minimal
    INTEGERs, no trailing bytes; ``r`` and ``s`` strictly in [1, n-1] rather
    than reduced into range; public-key coordinates strictly in [0, p); and the
    point on the curve and not the identity.

    High ``s`` is *accepted* by default. That is a deliberate divergence from
    the secp256k1 default (INVARIANT-28) and is what makes these curves usable
    against TLS, X.509, JWS and WebAuthn signers, none of which normalise
    ``s``.

    ``require_low_s=True`` rejects the high twin, making a signature a unique
    identifier for its (key, digest) pair — but only in combination with
    ``low_s=True`` on the signer. Either flag alone is incoherent: a strict
    verifier with a conformant signer rejects half of its own signatures, and
    a normalising signer with a permissive verifier prevents nothing. See
    INVARIANT-34.

    Verification is variable time by design; every input is public.

    Args:
        raw: Interpret ``signature`` as fixed-width ``r || s``.
        require_low_s: Reject the high-``s`` malleability twin.

    Returns:
        True if the signature is valid under the selected policy.

    Raises:
        ValueError: If the digest or public key has the wrong length.
        RuntimeError: If the native library is unavailable.
    """
    cid = _nistp_curve_id(curve)
    nb = NISTP_FIELD_BYTES[cid]
    _nistp_check_digest(message_digest)
    if len(pubkey) != 2 * nb:
        raise ValueError(f"Public key must be {2 * nb} bytes (X||Y), got {len(pubkey)}")
    _nistp_require_native()

    flags = AMA_NISTP_ECDSA_REQUIRE_LOW_S if require_low_s else AMA_NISTP_ECDSA_VERIFY_DEFAULT
    fn = _native_lib.ama_nistp_ecdsa_verify_raw_ex if raw else _native_lib.ama_nistp_ecdsa_verify_ex
    rc = int(
        fn(
            cid,
            bytes(message_digest),
            len(message_digest),
            bytes(pubkey),
            bytes(signature),
            len(signature),
            flags,
        )
    )
    return rc == 0


def native_nistp_sig_der_to_raw(curve: Union[int, str], der: bytes) -> bytes:
    """
    Convert a DER ECDSA signature to fixed-width ``r || s``.

    Re-applies the strict DER rules and the [1, n-1] range check, so the
    conversion cannot launder an out-of-range or sloppily encoded component
    into a well-formed one.

    Raises:
        ValueError: If the DER is not minimal or a component is out of range.
    """
    cid = _nistp_curve_id(curve)
    nb = NISTP_FIELD_BYTES[cid]
    _nistp_require_native()
    out = ctypes.create_string_buffer(2 * nb)
    out_len = ctypes.c_size_t(0)
    rc = _native_lib.ama_nistp_sig_der_to_raw(cid, bytes(der), len(der), out, ctypes.byref(out_len))
    if rc != 0:
        raise ValueError(f"Invalid DER ECDSA signature (rc={rc})")
    return bytes(out.raw[: out_len.value])


def native_nistp_sig_raw_to_der(curve: Union[int, str], raw: bytes) -> bytes:
    """
    Convert a fixed-width ``r || s`` ECDSA signature to minimal DER.

    Raises:
        ValueError: If the length is wrong or a component is out of range.
    """
    cid = _nistp_curve_id(curve)
    _nistp_require_native()
    out = ctypes.create_string_buffer(NISTP_MAX_SIG_LEN)
    out_len = ctypes.c_size_t(0)
    rc = _native_lib.ama_nistp_sig_raw_to_der(cid, bytes(raw), len(raw), out, ctypes.byref(out_len))
    if rc != 0:
        raise ValueError(f"Invalid raw ECDSA signature (rc={rc})")
    return bytes(out.raw[: out_len.value])


# ============================================================================
# HSS / LMS NATIVE WRAPPERS — RFC 8554 VERIFICATION
#
# Verification only. LMS is a stateful scheme and RFC 8554 §5.4.1 makes the
# one-time leaf index the whole of its security: a signer that releases a
# signature before durably reserving the index can, after a crash, sign twice
# under one LM-OTS key, and two signatures under one LM-OTS key yield a forged
# third. That guarantee lives in a durable state manager, not in the maths, so
# the signing half is withheld until such a manager exists and has been tested
# against interrupted writes. `lms_signing_available()` answers that question
# directly rather than leaving a caller to discover a missing name.
#
# Verification holds no secret and keeps no state, so it cannot be misused by
# being called twice — and it is the half with the interoperability value:
# HSS/LMS is deployed overwhelmingly as a firmware-update signature, one
# offline signer against a very large verifier population.
# ============================================================================


def _lms_require_native() -> None:
    """INVARIANT-7: refuse rather than substitute anything."""
    if _native_lib is None or not _LMS_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "HSS/LMS native backend not available. " + _INSTALL_HINT
        )


def lms_signing_available() -> bool:
    """
    Whether this build can *produce* HSS/LMS signatures.

    Always ``False``. See the section comment above for why that is a decision
    rather than an omission. Pinned by ``tests/test_rfc8554_vectors.py``.
    """
    if _native_lib is None or not _LMS_NATIVE_AVAILABLE:
        return False
    return bool(_native_lib.ama_lms_signing_available())


def native_lms_pubkey_params(pubkey: bytes) -> dict:
    """
    Report the parameter set an LMS public key names.

    Args:
        pubkey: A 56-byte LMS public key (``AMA_LMS_PUBKEY_LEN``). This is the
            *inner* key; an HSS public key is four bytes of ``L`` followed by
            one of these.

    Returns:
        ``{"lms_type", "lmots_type", "h", "w"}``.

    Raises:
        ValueError: If the key is malformed or names a typecode this library
            does not implement. An unrecognised typecode is refused, never
            resolved onto a neighbour (INVARIANT-35).
    """
    _lms_require_native()
    if len(pubkey) != AMA_LMS_PUBKEY_LEN:
        # An LMS public key is exactly u32(type) || u32(otstype) || I(16) ||
        # T[1](n=32) = 56 octets (RFC 8554 §5.3). Reject a wrong length at the
        # boundary with a legible message rather than letting the native rc
        # collapse every structural problem into one opaque code.
        raise ValueError(f"LMS public key must be {AMA_LMS_PUBKEY_LEN} bytes, got {len(pubkey)}")
    lms_type = ctypes.c_uint32(0)
    ots_type = ctypes.c_uint32(0)
    h = ctypes.c_uint32(0)
    w = ctypes.c_uint32(0)
    rc = _native_lib.ama_lms_pubkey_params(
        bytes(pubkey),
        len(pubkey),
        ctypes.byref(lms_type),
        ctypes.byref(ots_type),
        ctypes.byref(h),
        ctypes.byref(w),
    )
    if rc != 0:
        raise ValueError(f"Not a valid LMS public key (rc={rc})")
    lms_typecode = lms_type.value
    lmots_typecode = ots_type.value
    tree_height = h.value
    winternitz_w = w.value
    # Defence in depth against a C<->Python table drift: the height and
    # Winternitz width the native tables just reported must match the RFC 8554
    # registry transcribed here (Tables 1 and 2). A disagreement means one side
    # mapped a typecode onto the wrong parameter -- exactly the neighbour-
    # resolution failure INVARIANT-35 exists to prevent -- so refuse rather than
    # return a value the two halves do not agree on.
    if LMS_TREE_HEIGHT.get(lms_typecode) != tree_height:
        raise ValueError(
            f"LMS typecode {lms_typecode} reported height {tree_height}, "
            "which disagrees with the RFC 8554 Table 2 registry"
        )
    if LMOTS_WINTERNITZ_W.get(lmots_typecode) != winternitz_w:
        raise ValueError(
            f"LM-OTS typecode {lmots_typecode} reported width {winternitz_w}, "
            "which disagrees with the RFC 8554 Table 1 registry"
        )
    return {
        "lms_type": lms_typecode,
        "lmots_type": lmots_typecode,
        "h": tree_height,
        "w": winternitz_w,
    }


def native_lms_signature_length(signature: bytes) -> int:
    """
    Exact length of the LMS signature at the head of ``signature``.

    An LMS signature is self-describing but variable-length and HSS
    concatenates several, so splitting a buffer needs this.

    Returns:
        The length, or ``0`` if the head is not a structurally valid LMS
        signature that fits in the buffer.
    """
    _lms_require_native()
    return int(_native_lib.ama_lms_signature_length(bytes(signature), len(signature)))


def native_hss_pubkey_levels(pubkey: bytes) -> int:
    """
    The number of LMS levels an HSS public key commits to.

    Raises:
        ValueError: If the key is malformed, or names more levels than
            ``AMA_HSS_MAX_LEVELS``.
    """
    _lms_require_native()
    if len(pubkey) != AMA_HSS_PUBKEY_LEN:
        # An HSS public key is u32(L) || LMS_public_key = 4 + 56 = 60 octets
        # (RFC 8554 §6.1). Anything else cannot name a level count.
        raise ValueError(f"HSS public key must be {AMA_HSS_PUBKEY_LEN} bytes, got {len(pubkey)}")
    levels = ctypes.c_uint32(0)
    rc = _native_lib.ama_hss_pubkey_levels(bytes(pubkey), len(pubkey), ctypes.byref(levels))
    if rc != 0:
        raise ValueError(f"Not a valid HSS public key (rc={rc})")
    level_count = int(levels.value)
    # RFC 8554 §6.1 bounds L to [1, 8]; AMA_HSS_MAX_LEVELS pins the upper end.
    # The native walker already enforces this before returning rc==0, so a value
    # outside the range here means the native ABI and this wrapper have drifted.
    # Refuse rather than hand back a level count the format does not permit.
    if not 1 <= level_count <= AMA_HSS_MAX_LEVELS:
        raise ValueError(f"HSS level count {level_count} outside [1, {AMA_HSS_MAX_LEVELS}]")
    return level_count


def native_lms_verify(message: bytes, signature: bytes, pubkey: bytes) -> bool:
    """
    Verify a single-tree LMS signature (RFC 8554 §5.4.2, Algorithm 6).

    Args:
        message: The signed message.
        signature: The LMS signature. Must be consumed exactly — trailing data
            is rejected, because two byte strings that both verify for one
            message is signature malleability.
        pubkey: A 56-byte LMS public key.

    Returns:
        ``True`` if the signature is valid, ``False`` if it is not.

    Raises:
        ValueError: If the *public key* is malformed. A bad key is a caller
            error; a bad signature is an answer.
    """
    _lms_require_native()
    if len(pubkey) != AMA_LMS_PUBKEY_LEN:
        # A malformed key is a caller error, distinct from a failed signature.
        raise ValueError(f"LMS public key must be {AMA_LMS_PUBKEY_LEN} bytes, got {len(pubkey)}")
    rc = _native_lib.ama_lms_verify(
        bytes(message), len(message), bytes(signature), len(signature), bytes(pubkey), len(pubkey)
    )
    if rc == 0:
        return True
    if rc == AMA_ERROR_INVALID_PARAM:
        raise ValueError("Not a valid LMS public key")
    return False


def native_hss_verify(message: bytes, signature: bytes, pubkey: bytes) -> bool:
    """
    Verify a hierarchical HSS signature (RFC 8554 §6.3).

    Walks the chain of signed public keys from the root the public key commits
    to down to the tree that signed ``message``. Every intermediate signature
    must verify, the level count must match, and the buffer must be consumed
    exactly.

    Args:
        message: The signed message.
        signature: The HSS signature.
        pubkey: A 60-byte HSS public key (``AMA_HSS_PUBKEY_LEN``).

    Returns:
        ``True`` if the signature is valid, ``False`` if it is not.

    Raises:
        ValueError: If the *public key* is malformed.
    """
    _lms_require_native()
    if len(pubkey) != AMA_HSS_PUBKEY_LEN:
        # A malformed key is a caller error, distinct from a failed signature.
        raise ValueError(f"HSS public key must be {AMA_HSS_PUBKEY_LEN} bytes, got {len(pubkey)}")
    rc = _native_lib.ama_hss_verify(
        bytes(message), len(message), bytes(signature), len(signature), bytes(pubkey), len(pubkey)
    )
    if rc == 0:
        return True
    if rc == AMA_ERROR_INVALID_PARAM:
        raise ValueError("Not a valid HSS public key")
    return False


# ============================================================================
# X25519 NATIVE WRAPPERS
# ============================================================================


def native_x25519_keypair() -> tuple:
    """
    Generate X25519 keypair.

    Returns:
        (public_key, secret_key) — both 32 bytes

    Raises:
        RuntimeError: If native library is not available
    """
    if _native_lib is None or not _X25519_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError("X25519 native backend not available. " + _INSTALL_HINT)

    pk_buf = ctypes.create_string_buffer(X25519_KEY_BYTES)
    sk_buf = ctypes.create_string_buffer(X25519_KEY_BYTES)

    rc = _native_lib.ama_x25519_keypair(pk_buf, sk_buf)
    if rc != 0:
        raise RuntimeError(f"X25519 keypair generation failed (rc={rc})")

    return bytes(pk_buf), bytes(sk_buf)


def native_x25519_key_exchange(our_secret_key: bytes, their_public_key: bytes) -> bytes:
    """
    X25519 Diffie-Hellman key exchange.

    Args:
        our_secret_key: Our 32-byte secret key
        their_public_key: Their 32-byte public key

    Returns:
        32-byte shared secret

    Raises:
        RuntimeError: On low-order point or native library unavailable
    """
    if _native_lib is None or not _X25519_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError("X25519 native backend not available. " + _INSTALL_HINT)

    if len(our_secret_key) != 32:
        raise ValueError(f"X25519 secret key must be 32 bytes, got {len(our_secret_key)}")
    if len(their_public_key) != 32:
        raise ValueError(f"X25519 public key must be 32 bytes, got {len(their_public_key)}")

    ss_buf = ctypes.create_string_buffer(X25519_KEY_BYTES)
    rc = _native_lib.ama_x25519_key_exchange(ss_buf, our_secret_key, their_public_key)
    if rc != 0:
        raise RuntimeError(f"X25519 key exchange failed (rc={rc})")

    return bytes(ss_buf)


def native_x25519_scalarmult_batch(scalars: list[bytes], points: list[bytes]) -> list[bytes]:
    """
    Batched X25519 Diffie-Hellman key exchange.

    Computes ``shared[k] = X25519(scalars[k], points[k])`` for each k. On
    x86-64 hosts where the AVX2 4-way Montgomery-ladder kernel is opted in
    via ``AMA_DISPATCH_USE_X25519_AVX2=1``, batches with at least one full
    4-lane chunk (``count >= 4``) dispatch those full chunks to a SIMD
    path that runs four ladders in parallel; any tail (``count % 4``) and
    short batches (``count`` of 1, 2, or 3) are processed via the scalar
    single-shot path.  Without the opt-in, the additive batch API simply
    sequences the scalar fe64 / fe51 / gf16 single-shot path.  Output is
    byte-identical to ``len(scalars)`` sequential
    ``native_x25519_key_exchange`` calls in either case.

    Low-order rejection is aggregated across the batch — if ANY lane
    produces an all-zero shared secret (RFC 7748 §6.1) the whole batch
    fails with ``RuntimeError`` and no partial results are returned.

    Args:
        scalars: List of 32-byte secret keys.
        points: List of 32-byte u-coordinates (must match scalars in length).

    Returns:
        List of 32-byte shared secrets, in the same order as inputs.

    Raises:
        ValueError: On length mismatch or wrong-sized inputs.
        RuntimeError: On low-order rejection or native backend unavailable.
    """
    if _native_lib is None or not _X25519_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError("X25519 native backend not available. " + _INSTALL_HINT)
    if not hasattr(_native_lib, "ama_x25519_scalarmult_batch"):
        raise NativeBackendUnavailableError(
            "ama_x25519_scalarmult_batch is not exported by the loaded native "
            "library — rebuild against a newer libama_cryptography. " + _INSTALL_HINT
        )
    if len(scalars) != len(points):
        raise ValueError(f"batch length mismatch: {len(scalars)} scalars vs {len(points)} points")

    count = len(scalars)
    if count == 0:
        return []

    # Pack inputs directly into mutable ctypes buffers we can wipe — never
    # accumulate intermediate immutable bytes copies of secret scalars.
    # `create_string_buffer(size)` returns a `c_char * size` array, which
    # ctypes passes transparently to a `c_char_p` argument and which we
    # can ``ctypes.memset`` to zero on the way out.  ``bytearray`` would
    # also work for wipeability but does not satisfy the `c_char_p`
    # argtype contract without an extra cast that would re-introduce a
    # copy.  Validation is performed while packing (single pass) so a
    # caller passing e.g. a list with one short element doesn't leave
    # partial secret material in the blob before raising — the buffer
    # is wiped in the ``finally`` regardless of which validation step
    # raises.
    total_bytes = count * X25519_KEY_BYTES
    scalars_blob = ctypes.create_string_buffer(total_bytes)
    points_blob = ctypes.create_string_buffer(total_bytes)
    out_buf = ctypes.create_string_buffer(total_bytes)

    try:
        # Validate each element individually before joining.  A bare blob-
        # length check on a fixed-total buffer would let mixed-size
        # elements that happen to sum to count*32 (e.g. 16+48) slide
        # through and silently shift element boundaries inside the C
        # call.  Bytes-likeness is also enforced so a caller passing
        # e.g. a list of `int`s gets a clear error rather than a cryptic
        # ctypes failure.
        for i, scalar in enumerate(scalars):
            if not isinstance(scalar, (bytes, bytearray, memoryview)):
                raise ValueError(
                    f"scalar at index {i} must be bytes-like and " f"{X25519_KEY_BYTES} bytes long"
                )
            scalar_view = memoryview(scalar)
            if scalar_view.nbytes != X25519_KEY_BYTES:
                raise ValueError(
                    f"scalar at index {i} must be {X25519_KEY_BYTES} bytes; "
                    f"got {scalar_view.nbytes}"
                )
            offset = i * X25519_KEY_BYTES
            ctypes.memmove(
                ctypes.addressof(scalars_blob) + offset,
                bytes(scalar_view),
                X25519_KEY_BYTES,
            )

        for i, point in enumerate(points):
            if not isinstance(point, (bytes, bytearray, memoryview)):
                raise ValueError(
                    f"point at index {i} must be bytes-like and " f"{X25519_KEY_BYTES} bytes long"
                )
            point_view = memoryview(point)
            if point_view.nbytes != X25519_KEY_BYTES:
                raise ValueError(
                    f"point at index {i} must be {X25519_KEY_BYTES} bytes; "
                    f"got {point_view.nbytes}"
                )
            offset = i * X25519_KEY_BYTES
            ctypes.memmove(
                ctypes.addressof(points_blob) + offset,
                bytes(point_view),
                X25519_KEY_BYTES,
            )

        rc = _native_lib.ama_x25519_scalarmult_batch(out_buf, scalars_blob, points_blob, count)
        if rc != 0:
            raise RuntimeError(f"X25519 batch scalar-mult failed (rc={rc})")

        # Slice out per-lane shared secrets.  These are immutable bytes by
        # API contract (the caller may pin them in their own collections);
        # the wipeable buffers below are the wrapper's own intermediate
        # storage, which we MUST scrub.
        return [
            bytes(out_buf.raw[i * X25519_KEY_BYTES : (i + 1) * X25519_KEY_BYTES])
            for i in range(count)
        ]
    finally:
        # Scrub all wrapper-internal buffers regardless of which path we
        # took (validation error, native failure, or success).  The
        # caller's input lists and our returned shared-secret bytes are
        # outside this wrapper's lifetime contract — those are the
        # caller's to manage.  But `scalars_blob` (concatenated secret
        # keys) and `points_blob` (concatenated public points, also
        # zeroed for symmetry / defence-in-depth) and `out_buf`
        # (concatenated shared secrets, post-slice) are wrapper-owned
        # secret material that should not survive return.
        ctypes.memset(ctypes.addressof(scalars_blob), 0, total_bytes)
        ctypes.memset(ctypes.addressof(points_blob), 0, total_bytes)
        ctypes.memset(ctypes.addressof(out_buf), 0, total_bytes)


# ============================================================================
# ARGON2ID NATIVE WRAPPERS
# ============================================================================


def native_argon2id(
    password: bytes,
    salt: bytes,
    t_cost: int = 3,
    m_cost: int = 65536,
    parallelism: int = 4,
    out_len: int = 32,
) -> bytes:
    """
    Argon2id key derivation (RFC 9106).

    Args:
        password: Password bytes
        salt: Salt bytes (16+ recommended)
        t_cost: Time cost (iterations)
        m_cost: Memory cost in KiB
        parallelism: Degree of parallelism
        out_len: Desired output length

    Returns:
        Derived key bytes

    Raises:
        RuntimeError: If native library is not available
    """
    if _native_lib is None or not _ARGON2_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "Argon2id native backend not available. " + _INSTALL_HINT
        )

    _UINT32_MAX = 0xFFFFFFFF
    if len(salt) < 8:
        raise ValueError(f"Argon2id salt must be >= 8 bytes, got {len(salt)}")
    # Upper bound on ``out_len`` is the application-sane ceiling
    # ``_ARGON2ID_MAX_TAG_LEN`` (1024 bytes, 32× the default 32-byte
    # tag).  RFC 9106 §3.2 permits up to UINT32_MAX, but every real
    # deployment uses 16–64 bytes and sizes above ~128 add no
    # cryptographic value while turning a caller-controlled length
    # into a memory-exhaustion / DoS vector (a 4 GiB ``out_len`` would
    # trigger a 4 GiB ``ctypes.create_string_buffer`` allocation below).
    # Kept in sync with the C-side ``AMA_ARGON2ID_MAX_TAG_LEN`` in
    # ``include/ama_cryptography.h`` and the matching caps on the two
    # legacy-shim wrappers.
    if out_len < 4 or out_len > _ARGON2ID_MAX_TAG_LEN:
        raise ValueError(
            f"Argon2id out_len must be in [4, {_ARGON2ID_MAX_TAG_LEN}] bytes, got {out_len}"
        )
    if t_cost < 1 or t_cost > _UINT32_MAX:
        raise ValueError(f"Argon2id t_cost must be in [1, {_UINT32_MAX}], got {t_cost}")
    if parallelism < 1 or parallelism > _UINT32_MAX:
        raise ValueError(f"Argon2id parallelism must be in [1, {_UINT32_MAX}], got {parallelism}")
    if m_cost < 8 * parallelism or m_cost > _UINT32_MAX:
        raise ValueError(
            f"Argon2id m_cost must be in [{8 * parallelism}, {_UINT32_MAX}] KiB "
            f"(min 8 * parallelism for parallelism={parallelism}), got {m_cost}"
        )

    out_buf = ctypes.create_string_buffer(out_len)
    rc = _native_lib.ama_argon2id(
        password,
        len(password),
        salt,
        len(salt),
        t_cost,
        m_cost,
        parallelism,
        out_buf,
        out_len,
    )
    if rc != 0:
        raise RuntimeError(f"Argon2id failed (rc={rc})")

    return bytes(out_buf)


def native_argon2id_legacy(
    password: bytes,
    salt: bytes,
    t_cost: int = 3,
    m_cost: int = 65536,
    parallelism: int = 4,
    out_len: int = 32,
) -> bytes:
    """
    Derive an Argon2id tag using the pre-shim (buggy) derivation.

    **Do NOT use this for new password hashes.**  Earlier AMA Cryptography
    builds shipped a ``blake2b_long`` loop-termination bug that produces
    non-spec tags; this wrapper reproduces that derivation verbatim.  It
    exists so migration tooling and regression tests can generate reference
    tags without forking the old code — the safe, spec-compliant path is
    :func:`native_argon2id`.

    Every call emits a :class:`SecurityWarning` so accidental use in a
    production path is loud at runtime.  Suppress it only inside migration
    tooling that knows it is generating reference tags for verification.

    Args:
        password:    Password bytes.
        salt:        Salt bytes (≥ 8-byte minimum).
        t_cost:      Time cost (iterations, ≥ 1).
        m_cost:      Memory cost (KiB, ≥ 8 * parallelism).
        parallelism: Parallelism (lanes, ≥ 1).
        out_len:     Output tag length (≥ 4 bytes).

    Returns:
        Derived tag bytes of length ``out_len``.

    Raises:
        RuntimeError: If the native library is unavailable, or if the loaded
            native library does not export ``ama_argon2id_legacy`` (only
            builds that include the migration shim do).
        ValueError:   On parameter-range violations (same rules as
            :func:`native_argon2id`).
    """
    if _native_lib is None or not _ARGON2_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "Argon2id native backend not available. " + _INSTALL_HINT
        )
    if not hasattr(_native_lib, "ama_argon2id_legacy"):
        raise NativeBackendUnavailableError(
            "ama_argon2id_legacy() is not exported by the loaded native "
            "library — rebuild against a native library that exports "
            "``ama_argon2id_legacy`` to enable the pre-shim migration path."
        )

    _UINT32_MAX = 0xFFFFFFFF
    if len(salt) < 8:
        raise ValueError(f"Argon2id salt must be >= 8 bytes, got {len(salt)}")
    # Upper bound on ``out_len`` mirrors ``native_argon2id``:
    # ``_ARGON2ID_MAX_TAG_LEN`` (1024 bytes, 32× the default tag).  Kept
    # in sync with the C-side ``AMA_ARGON2ID_MAX_TAG_LEN``.
    if out_len < 4 or out_len > _ARGON2ID_MAX_TAG_LEN:
        raise ValueError(
            f"Argon2id out_len must be in [4, {_ARGON2ID_MAX_TAG_LEN}] bytes, got {out_len}"
        )
    if t_cost < 1 or t_cost > _UINT32_MAX:
        raise ValueError(f"Argon2id t_cost must be in [1, {_UINT32_MAX}], got {t_cost}")
    if parallelism < 1 or parallelism > _UINT32_MAX:
        raise ValueError(f"Argon2id parallelism must be in [1, {_UINT32_MAX}], got {parallelism}")
    if m_cost < 8 * parallelism or m_cost > _UINT32_MAX:
        raise ValueError(
            f"Argon2id m_cost must be in [{8 * parallelism}, {_UINT32_MAX}] KiB, got {m_cost}"
        )

    # Loud runtime signal that this is not the path callers should be on.
    # Raised once per call (not once per process) so call-site auditing
    # catches every invocation, and ``stacklevel=2`` points at the caller.
    # Emitted *after* both availability AND parameter validation so the
    # warning is only observed when the legacy derivation actually
    # executes — rejected-validation calls (e.g. short salt, out-of-range
    # out_len) raise ``ValueError`` without polluting
    # ``warnings.catch_warnings(record=True)`` collectors in
    # monitoring/migration tooling that count legacy-path usage.
    warnings.warn(
        "native_argon2id_legacy() reproduces the pre-shim blake2b_long bug "
        "for read-only migration verification ONLY. Use native_argon2id() "
        "for any new hash; new deployments must not store tags derived by "
        "this function. See CHANGELOG.md [3.0.0] § BREAKING.",
        SecurityWarning,
        stacklevel=2,
    )

    out_buf = ctypes.create_string_buffer(out_len)
    rc = _native_lib.ama_argon2id_legacy(
        password,
        len(password),
        salt,
        len(salt),
        t_cost,
        m_cost,
        parallelism,
        out_buf,
        out_len,
    )
    if rc != 0:
        raise RuntimeError(f"ama_argon2id_legacy failed (rc={rc})")

    return bytes(out_buf)


def native_argon2id_legacy_verify(
    password: bytes,
    salt: bytes,
    expected_tag: bytes,
    t_cost: int = 3,
    m_cost: int = 65536,
    parallelism: int = 4,
) -> bool:
    """
    Constant-time verify a pre-shim Argon2id tag.

    Earlier AMA Cryptography builds shipped a ``blake2b_long``
    loop-termination bug (see ``CHANGELOG.md`` [3.0.0] § BREAKING).
    Stored hashes derived by those versions sit in a non-spec bit-space and
    will not verify against the post-fix :func:`native_argon2id`.  This
    helper reproduces the legacy derivation and compares against
    ``expected_tag`` with :c:func:`ama_consttime_memcmp` so a deployment can
    run the "verify-with-legacy, re-derive-with-fixed, overwrite" migration
    recommended in the changelog without forking the old code.

    Args:
        password:     Password bytes.
        salt:         Salt bytes (same ≥ 8-byte minimum as native_argon2id).
        expected_tag: Stored tag bytes to compare against (≥ 4 bytes).
        t_cost:       Time cost that produced ``expected_tag``.
        m_cost:       Memory cost (KiB) that produced ``expected_tag``.
        parallelism:  Parallelism that produced ``expected_tag``.

    Returns:
        ``True`` on constant-time match, ``False`` on mismatch.

    Raises:
        RuntimeError: If the native library is unavailable, or if the loaded
            native library does not export ``ama_argon2id_legacy_verify``
            (only builds that include the migration shim do).
        ValueError:   On parameter-range violations (same rules as
            :func:`native_argon2id`).
    """
    if _native_lib is None or not _ARGON2_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "Argon2id native backend not available. " + _INSTALL_HINT
        )
    if not hasattr(_native_lib, "ama_argon2id_legacy_verify"):
        raise NativeBackendUnavailableError(
            "ama_argon2id_legacy_verify() is not exported by the loaded native "
            "library — rebuild against a native library that exports "
            "``ama_argon2id_legacy_verify`` to enable the pre-shim "
            "migration path."
        )

    _UINT32_MAX = 0xFFFFFFFF
    tag_len = len(expected_tag)
    if len(salt) < 8:
        raise ValueError(f"Argon2id salt must be >= 8 bytes, got {len(salt)}")
    # Upper bound on ``tag_len``: ``_ARGON2ID_MAX_TAG_LEN`` (1024 bytes,
    # 32× the default).  Tighter than the theoretical ``UINT32_MAX``
    # because a caller-controlled ``expected_tag`` length would
    # otherwise become a memory-exhaustion / DoS vector in the C
    # helper's ``calloc(tag_len, 1)`` for the freshly-derived
    # ``computed`` buffer.  Kept in sync with the C-side
    # ``AMA_ARGON2ID_MAX_TAG_LEN`` and the ``native_argon2id`` /
    # ``native_argon2id_legacy`` derivation caps.
    if tag_len < 4 or tag_len > _ARGON2ID_MAX_TAG_LEN:
        raise ValueError(
            f"expected_tag must be in [4, {_ARGON2ID_MAX_TAG_LEN}] bytes, got {tag_len}"
        )
    if t_cost < 1 or t_cost > _UINT32_MAX:
        raise ValueError(f"Argon2id t_cost must be in [1, {_UINT32_MAX}], got {t_cost}")
    if parallelism < 1 or parallelism > _UINT32_MAX:
        raise ValueError(f"Argon2id parallelism must be in [1, {_UINT32_MAX}], got {parallelism}")
    if m_cost < 8 * parallelism or m_cost > _UINT32_MAX:
        raise ValueError(
            f"Argon2id m_cost must be in [{8 * parallelism}, {_UINT32_MAX}] KiB, got {m_cost}"
        )

    rc = _native_lib.ama_argon2id_legacy_verify(
        password,
        len(password),
        salt,
        len(salt),
        t_cost,
        m_cost,
        parallelism,
        bytes(expected_tag),
        tag_len,
    )
    # AMA_SUCCESS (0) == match; AMA_ERROR_VERIFY_FAILED (-4) == mismatch.
    # Any other non-zero code is a hard error (parameters, allocation, etc.).
    if rc == 0:
        return True
    if rc == -4:
        return False
    raise RuntimeError(f"ama_argon2id_legacy_verify failed (rc={rc})")


# ============================================================================
# CHACHA20-POLY1305 NATIVE WRAPPERS
# ============================================================================


def native_chacha20poly1305_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> tuple:
    """
    ChaCha20-Poly1305 AEAD encryption (RFC 8439).

    Returns:
        (ciphertext, tag) — ciphertext same length as plaintext, 16-byte tag
    """
    if _native_lib is None or not _CHACHA20_POLY1305_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "ChaCha20-Poly1305 native backend not available. " + _INSTALL_HINT
        )

    if len(key) != 32:
        raise ValueError(f"ChaCha20-Poly1305 key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"ChaCha20-Poly1305 nonce must be 12 bytes, got {len(nonce)}")

    pt_len = len(plaintext)
    pt_ptr = plaintext if pt_len > 0 else None
    aad_ptr = aad if aad and len(aad) > 0 else None
    aad_len = len(aad) if aad else 0

    ct_buf = ctypes.create_string_buffer(pt_len)
    tag_buf = ctypes.create_string_buffer(POLY1305_TAG_BYTES)

    rc = _native_lib.ama_chacha20poly1305_encrypt(
        key,
        nonce,
        pt_ptr,
        pt_len,
        aad_ptr,
        aad_len,
        ct_buf,
        tag_buf,
    )
    if rc != 0:
        raise RuntimeError(f"ChaCha20-Poly1305 encrypt failed (rc={rc})")

    return bytes(ct_buf), bytes(tag_buf)


def native_chacha20poly1305_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> bytes:
    """
    ChaCha20-Poly1305 AEAD decryption (RFC 8439).

    Returns:
        Decrypted plaintext

    Raises:
        RuntimeError: On tag verification failure.  The underlying C
            entry point does not modify the plaintext buffer on tag
            mismatch (it never wrote to it in the first place); this
            wrapper raises before the freshly-allocated zero-initialised
            buffer is returned, so caller-visible behaviour is unchanged.
    """
    if _native_lib is None or not _CHACHA20_POLY1305_NATIVE_AVAILABLE:
        raise NativeBackendUnavailableError(
            "ChaCha20-Poly1305 native backend not available. " + _INSTALL_HINT
        )

    if len(key) != 32:
        raise ValueError(f"ChaCha20-Poly1305 key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"ChaCha20-Poly1305 nonce must be 12 bytes, got {len(nonce)}")
    if len(tag) != 16:
        raise ValueError(f"ChaCha20-Poly1305 tag must be 16 bytes, got {len(tag)}")

    ct_len = len(ciphertext)
    ct_ptr = ciphertext if ct_len > 0 else None
    aad_ptr = aad if aad and len(aad) > 0 else None
    aad_len = len(aad) if aad else 0

    pt_buf = ctypes.create_string_buffer(ct_len)

    rc = _native_lib.ama_chacha20poly1305_decrypt(
        key,
        nonce,
        ct_ptr,
        ct_len,
        aad_ptr,
        aad_len,
        tag,
        pt_buf,
    )
    if rc != 0:
        raise RuntimeError(f"ChaCha20-Poly1305 decrypt failed (rc={rc})")

    return bytes(pt_buf)


# ============================================================================
# DETERMINISTIC KEYGEN NATIVE WRAPPERS
# ============================================================================


def native_kyber_keypair_from_seed(d: bytes, z: bytes) -> tuple:
    """
    Deterministic Kyber-1024 keypair from seed.

    Args:
        d: 32-byte seed for key generation
        z: 32-byte seed for implicit rejection

    Returns:
        (public_key, secret_key)
    """
    if _native_lib is None or not _DETERMINISTIC_KEYGEN_AVAILABLE:
        raise NativeBackendUnavailableError("Deterministic keygen not available. " + _INSTALL_HINT)

    if len(d) != 32:
        raise ValueError(f"Kyber seed d must be 32 bytes, got {len(d)}")
    if len(z) != 32:
        raise ValueError(f"Kyber seed z must be 32 bytes, got {len(z)}")

    pk_buf = ctypes.create_string_buffer(KYBER_PUBLIC_KEY_BYTES)
    sk_buf = ctypes.create_string_buffer(KYBER_SECRET_KEY_BYTES)

    rc = _native_lib.ama_kyber_keypair_from_seed(d, z, pk_buf, sk_buf)
    if rc != 0:
        raise RuntimeError(f"Kyber deterministic keygen failed (rc={rc})")

    return bytes(pk_buf), bytes(sk_buf)


def native_dilithium_keypair_from_seed(xi: bytes) -> tuple:
    """
    Deterministic ML-DSA-65 keypair from seed.

    Args:
        xi: 32-byte seed

    Returns:
        (public_key, secret_key)
    """
    if _native_lib is None or not _DETERMINISTIC_KEYGEN_AVAILABLE:
        raise NativeBackendUnavailableError("Deterministic keygen not available. " + _INSTALL_HINT)

    if len(xi) != 32:
        raise ValueError(f"Dilithium seed xi must be 32 bytes, got {len(xi)}")

    pk_buf = ctypes.create_string_buffer(DILITHIUM_PUBLIC_KEY_BYTES)
    sk_buf = ctypes.create_string_buffer(DILITHIUM_SECRET_KEY_BYTES)

    rc = _native_lib.ama_dilithium_keypair_from_seed(xi, pk_buf, sk_buf)
    if rc != 0:
        raise RuntimeError(f"Dilithium deterministic keygen failed (rc={rc})")

    return bytes(pk_buf), bytes(sk_buf)


# ============================================================================
# FROST THRESHOLD ED25519 (RFC 9591) — NATIVE WRAPPERS
# ============================================================================

# Module-level availability aliases
FROST_AVAILABLE = _FROST_AVAILABLE
FROST_BACKEND = _FROST_BACKEND


def frost_keygen_trusted_dealer(
    threshold: int,
    num_participants: int,
    secret_key: Optional[bytes] = None,
) -> tuple:
    """Generate FROST key shares via trusted dealer (Shamir secret sharing).

    Args:
        threshold: Minimum number of signers (t >= 2)
        num_participants: Total participants (n >= t)
        secret_key: Optional 32-byte group secret key (None = random)

    Returns:
        Tuple of (group_public_key, list_of_participant_shares)
        where each share is 64 bytes (32 secret + 32 public).
    """
    if not _FROST_AVAILABLE or _native_lib is None:
        raise NativeBackendUnavailableError("FROST native library not available")
    if threshold < 2 or num_participants < threshold:
        raise ValueError("Require threshold >= 2 and num_participants >= threshold")
    if num_participants > 255:
        raise ValueError("num_participants must be <= 255")

    if secret_key is not None:
        if not isinstance(secret_key, bytes) or len(secret_key) != 32:
            raise ValueError("secret_key must be exactly 32 bytes")

    gpk_buf = ctypes.create_string_buffer(32)
    shares_buf = ctypes.create_string_buffer(num_participants * FROST_SHARE_BYTES)
    sk_ptr = secret_key if secret_key is not None else None

    rc = _native_lib.ama_frost_keygen_trusted_dealer(
        ctypes.c_uint8(threshold),
        ctypes.c_uint8(num_participants),
        gpk_buf,
        shares_buf,
        sk_ptr,
    )
    if rc != 0:
        raise RuntimeError(f"FROST keygen failed (rc={rc})")

    gpk = bytes(gpk_buf)
    raw = shares_buf.raw
    shares = [
        raw[i * FROST_SHARE_BYTES : (i + 1) * FROST_SHARE_BYTES] for i in range(num_participants)
    ]
    return gpk, shares


def frost_round1_commit(participant_share: bytes) -> tuple:
    """FROST Round 1: Generate nonce commitment.

    Args:
        participant_share: 64-byte participant share from keygen.

    Returns:
        Tuple of (nonce_pair, commitment) — nonce_pair is SECRET (64 bytes),
        commitment is PUBLIC (64 bytes).
    """
    if not _FROST_AVAILABLE or _native_lib is None:
        raise NativeBackendUnavailableError("FROST native library not available")
    if len(participant_share) != FROST_SHARE_BYTES:
        raise ValueError(f"participant_share must be {FROST_SHARE_BYTES} bytes")

    nonce_buf = ctypes.create_string_buffer(FROST_NONCE_BYTES)
    commit_buf = ctypes.create_string_buffer(FROST_COMMITMENT_BYTES)

    rc = _native_lib.ama_frost_round1_commit(nonce_buf, commit_buf, participant_share)
    if rc != 0:
        raise RuntimeError(f"FROST round1 commit failed (rc={rc})")

    return bytes(nonce_buf), bytes(commit_buf)


def frost_round2_sign(
    message: bytes,
    participant_share: bytes,
    participant_index: int,
    nonce_pair: bytes,
    commitments: bytes,
    signer_indices: bytes,
    num_signers: int,
    group_public_key: bytes,
) -> bytes:
    """FROST Round 2: Generate signature share.

    Args:
        message: Message to sign.
        participant_share: 64-byte share.
        participant_index: 1-based participant index.
        nonce_pair: 64-byte nonce pair from round 1 (SECRET).
        commitments: Concatenated commitments (num_signers * 64 bytes).
        signer_indices: Byte array of 1-based signer indices.
        num_signers: Number of signers in this session.
        group_public_key: 32-byte group public key.

    Returns:
        32-byte signature share.
    """
    if not _FROST_AVAILABLE or _native_lib is None:
        raise NativeBackendUnavailableError("FROST native library not available")
    if not (2 <= num_signers <= 255):
        raise ValueError("num_signers must be in [2, 255]")
    if len(participant_share) != FROST_SHARE_BYTES:
        raise ValueError(f"participant_share must be {FROST_SHARE_BYTES} bytes")
    if not (1 <= participant_index <= 255):
        raise ValueError("participant_index must be in [1, 255]")
    if len(nonce_pair) != FROST_NONCE_BYTES:
        raise ValueError(f"nonce_pair must be {FROST_NONCE_BYTES} bytes")
    if len(commitments) != num_signers * FROST_COMMITMENT_BYTES:
        raise ValueError(f"commitments must be {num_signers * FROST_COMMITMENT_BYTES} bytes")
    if len(signer_indices) != num_signers:
        raise ValueError(f"signer_indices must be {num_signers} bytes")
    if len(group_public_key) != 32:
        raise ValueError("group_public_key must be 32 bytes")

    sig_share_buf = ctypes.create_string_buffer(FROST_SIG_SHARE_BYTES)

    rc = _native_lib.ama_frost_round2_sign(
        sig_share_buf,
        message,
        ctypes.c_size_t(len(message)),
        participant_share,
        ctypes.c_uint8(participant_index),
        nonce_pair,
        commitments,
        signer_indices,
        ctypes.c_uint8(num_signers),
        group_public_key,
    )
    if rc != 0:
        raise RuntimeError(f"FROST round2 sign failed (rc={rc})")

    return bytes(sig_share_buf)


def frost_aggregate(
    sig_shares: bytes,
    commitments: bytes,
    signer_indices: bytes,
    num_signers: int,
    message: bytes,
    group_public_key: bytes,
) -> bytes:
    """Aggregate FROST signature shares into an Ed25519-compatible signature.

    Args:
        sig_shares: Concatenated signature shares (num_signers * 32 bytes).
        commitments: Concatenated commitments (num_signers * 64 bytes).
        signer_indices: Byte array of 1-based signer indices.
        num_signers: Number of signers.
        message: Original message.
        group_public_key: 32-byte group public key.

    Returns:
        64-byte Ed25519-format signature (R || z).
    """
    if not _FROST_AVAILABLE or _native_lib is None:
        raise NativeBackendUnavailableError("FROST native library not available")
    if not (2 <= num_signers <= 255):
        raise ValueError("num_signers must be in [2, 255]")
    if len(sig_shares) != num_signers * FROST_SIG_SHARE_BYTES:
        raise ValueError(f"sig_shares must be {num_signers * FROST_SIG_SHARE_BYTES} bytes")
    if len(commitments) != num_signers * FROST_COMMITMENT_BYTES:
        raise ValueError(f"commitments must be {num_signers * FROST_COMMITMENT_BYTES} bytes")
    if len(signer_indices) != num_signers:
        raise ValueError(f"signer_indices must be {num_signers} bytes")
    if any(idx == 0 for idx in signer_indices):
        raise ValueError("signer_indices must contain only 1-based indices in [1, 255]")
    if len(set(signer_indices)) != num_signers:
        raise ValueError("signer_indices must contain unique signer indices")
    if len(group_public_key) != 32:
        raise ValueError("group_public_key must be 32 bytes")

    sig_buf = ctypes.create_string_buffer(64)

    rc = _native_lib.ama_frost_aggregate(
        sig_buf,
        sig_shares,
        commitments,
        signer_indices,
        ctypes.c_uint8(num_signers),
        message,
        ctypes.c_size_t(len(message)),
        group_public_key,
    )
    if rc != 0:
        raise RuntimeError(f"FROST aggregate failed (rc={rc})")

    return bytes(sig_buf)
