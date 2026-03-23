#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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

import ctypes
import os
import platform
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from ama_cryptography.exceptions import (
    PQCUnavailableError,
    QuantumSignatureUnavailableError,
    SecurityWarning,
)

__all__ = [
    "PQCUnavailableError",
    "QuantumSignatureUnavailableError",
    "KyberUnavailableError",
    "SphincsUnavailableError",
    "SecurityWarning",
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

    # Project build directories (relative to this file's package)
    pkg_dir = Path(__file__).resolve().parent.parent
    build_dirs = [
        "build/lib",
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

        return True
    except AttributeError:
        # Library found but missing expected symbols — not built with AMA_USE_NATIVE_PQC
        return False


# Ed25519 native availability (separate from PQC to avoid breaking PQC on older libs)
_ED25519_NATIVE_AVAILABLE = False


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

        return True
    except AttributeError:
        return False


# AES-256-GCM native availability (separate from PQC)
_AES_GCM_NATIVE_AVAILABLE = False


def _setup_aes_gcm_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for AES-256-GCM functions. Separate from PQC setup."""
    try:
        lib.ama_aes256_gcm_encrypt.argtypes = [
            ctypes.c_char_p,  # key[32]
            ctypes.c_char_p,  # nonce[12]
            ctypes.c_char_p,  # plaintext
            ctypes.c_size_t,  # pt_len
            ctypes.c_char_p,  # aad
            ctypes.c_size_t,  # aad_len
            ctypes.c_char_p,  # ciphertext
            ctypes.c_char_p,  # tag[16]
        ]
        lib.ama_aes256_gcm_encrypt.restype = ctypes.c_int

        lib.ama_aes256_gcm_decrypt.argtypes = [
            ctypes.c_char_p,  # key[32]
            ctypes.c_char_p,  # nonce[12]
            ctypes.c_char_p,  # ciphertext
            ctypes.c_size_t,  # ct_len
            ctypes.c_char_p,  # aad
            ctypes.c_size_t,  # aad_len
            ctypes.c_char_p,  # tag[16]
            ctypes.c_char_p,  # plaintext
        ]
        lib.ama_aes256_gcm_decrypt.restype = ctypes.c_int

        return True
    except AttributeError:
        return False


# HKDF native availability
_HKDF_NATIVE_AVAILABLE = False


def _setup_hkdf_ctypes(lib: ctypes.CDLL) -> bool:
    """Configure ctypes for HKDF functions. Separate from PQC setup."""
    try:
        lib.ama_hkdf.argtypes = [
            ctypes.c_char_p,  # salt
            ctypes.c_size_t,  # salt_len
            ctypes.c_char_p,  # ikm
            ctypes.c_size_t,  # ikm_len
            ctypes.c_char_p,  # info
            ctypes.c_size_t,  # info_len
            ctypes.c_char_p,  # okm
            ctypes.c_size_t,  # okm_len
        ]
        lib.ama_hkdf.restype = ctypes.c_int

        return True
    except AttributeError:
        return False


# SHA3-256 native availability (raw hash, not HMAC)
_SHA3_256_NATIVE_AVAILABLE = False


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


# HMAC-SHA3-256 native availability (independent of HKDF)
_HMAC_SHA3_256_NATIVE_AVAILABLE = False


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
        return True
    except AttributeError:
        return False


# Argon2id native availability
_ARGON2_NATIVE_AVAILABLE = False


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
    _SHA3_256_NATIVE_AVAILABLE = _setup_sha3_256_ctypes(_native_lib)
    _HMAC_SHA3_256_NATIVE_AVAILABLE = _setup_hmac_sha3_256_ctypes(_native_lib)
    _SECP256K1_NATIVE_AVAILABLE = _setup_secp256k1_ctypes(_native_lib)
    _X25519_NATIVE_AVAILABLE = _setup_x25519_ctypes(_native_lib)
    _ARGON2_NATIVE_AVAILABLE = _setup_argon2_ctypes(_native_lib)
    _CHACHA20_POLY1305_NATIVE_AVAILABLE = _setup_chacha20poly1305_ctypes(_native_lib)
    _DETERMINISTIC_KEYGEN_AVAILABLE = _setup_deterministic_keygen_ctypes(_native_lib)


# Public API for checking availability
DILITHIUM_AVAILABLE: bool = _DILITHIUM_AVAILABLE
DILITHIUM_BACKEND: Optional[str] = _DILITHIUM_BACKEND
KYBER_AVAILABLE: bool = _KYBER_AVAILABLE
KYBER_BACKEND: Optional[str] = _KYBER_BACKEND
SPHINCS_AVAILABLE: bool = _SPHINCS_AVAILABLE
SPHINCS_BACKEND: Optional[str] = _SPHINCS_BACKEND

# SHA3-256 (raw hash) native availability
SHA3_256_NATIVE_AVAILABLE: bool = _SHA3_256_NATIVE_AVAILABLE

# HMAC-SHA3-256 availability — determined at import time.
# Cython binding is probed later (after function definitions), so we
# expose ctypes availability now and patch after the Cython probe.
HMAC_SHA3_256_AVAILABLE: bool = _HMAC_SHA3_256_NATIVE_AVAILABLE
HMAC_SHA3_256_BACKEND: Optional[str] = "native" if _HMAC_SHA3_256_NATIVE_AVAILABLE else None

# =============================================================================
# SECURITY WARNINGS AND CONSTANT-TIME ENFORCEMENT
# =============================================================================

# Installation instruction (must be defined before constant-time enforcement)
_INSTALL_HINT = (
    "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
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

# SPHINCS+-SHA2-256f-simple
SPHINCS_PUBLIC_KEY_BYTES = 64
SPHINCS_SECRET_KEY_BYTES = 128
SPHINCS_SIGNATURE_BYTES = 49856

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
    """

    secret_key: bytes = field(repr=False)  # 4032 bytes for ML-DSA-65 (excluded from repr)
    public_key: bytes  # 1952 bytes for ML-DSA-65


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
    """

    secret_key: bytes = field(repr=False)  # 3168 bytes for Kyber-1024 (excluded from repr)
    public_key: bytes  # 1568 bytes for Kyber-1024


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
    """

    secret_key: bytes = field(repr=False)  # 128 bytes for SPHINCS+-256f (excluded from repr)
    public_key: bytes  # 64 bytes for SPHINCS+-256f


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
            raise QuantumSignatureUnavailableError(
                f"Native dilithium_keypair failed with error code {rc}"
            )
        return DilithiumKeyPair(secret_key=bytes(sk_buf), public_key=bytes(pk_buf))

    raise QuantumSignatureUnavailableError(_DILITHIUM_UNKNOWN_STATE)


def dilithium_sign(message: bytes, secret_key: bytes) -> bytes:
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

    if DILITHIUM_BACKEND == "native" and _native_lib is not None:
        sig_buf = ctypes.create_string_buffer(DILITHIUM_SIGNATURE_BYTES)
        sig_len = ctypes.c_size_t(DILITHIUM_SIGNATURE_BYTES)
        rc = _native_lib.ama_dilithium_sign(
            sig_buf,
            ctypes.byref(sig_len),
            message,
            ctypes.c_size_t(len(message)),
            secret_key,
        )
        if rc != 0:
            raise QuantumSignatureUnavailableError(
                f"Native dilithium_sign failed with error code {rc}"
            )
        return bytes(sig_buf[: sig_len.value])  # type: ignore[arg-type]

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
            raise KyberUnavailableError(f"Native kyber_keypair failed with error code {rc}")
        return KyberKeyPair(secret_key=bytes(sk_buf), public_key=bytes(pk_buf))

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
            ciphertext=bytes(ct_buf[: ct_len.value]),  # type: ignore[arg-type]
            shared_secret=bytes(ss_buf),
        )

    raise KyberUnavailableError(_KYBER_UNKNOWN_STATE)


def kyber_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
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
        rc = _native_lib.ama_kyber_decapsulate(
            ciphertext,
            ctypes.c_size_t(len(ciphertext)),
            secret_key,
            ctypes.c_size_t(len(secret_key)),
            ss_buf,
            ctypes.c_size_t(KYBER_SHARED_SECRET_BYTES),
        )
        if rc != 0:
            raise KyberUnavailableError(f"Native kyber_decapsulate failed with error code {rc}")
        return bytes(ss_buf)

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
            raise SphincsUnavailableError(f"Native sphincs_keypair failed with error code {rc}")
        return SphincsKeyPair(secret_key=bytes(sk_buf), public_key=bytes(pk_buf))

    raise SphincsUnavailableError(_SPHINCS_UNKNOWN_STATE)


def sphincs_sign(message: bytes, secret_key: bytes) -> bytes:
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
        rc = _native_lib.ama_sphincs_sign(
            sig_buf,
            ctypes.byref(sig_len),
            message,
            ctypes.c_size_t(len(message)),
            secret_key,
        )
        if rc != 0:
            raise SphincsUnavailableError(f"Native sphincs_sign failed with error code {rc}")
        return bytes(sig_buf[: sig_len.value])  # type: ignore[arg-type]

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
        raise RuntimeError("Ed25519 native backend not available. " + _INSTALL_HINT)

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
        raise RuntimeError("Ed25519 native backend not available. " + _INSTALL_HINT)

    pk_buf = ctypes.create_string_buffer(ED25519_PUBLIC_KEY_BYTES)
    sk_buf = ctypes.create_string_buffer(ED25519_SECRET_KEY_BYTES)

    # Load seed into first 32 bytes of sk_buf
    ctypes.memmove(sk_buf, seed, 32)

    rc = _native_lib.ama_ed25519_keypair(pk_buf, sk_buf)
    if rc != 0:
        raise RuntimeError(f"Ed25519 keypair generation failed (rc={rc})")

    return bytes(pk_buf), bytes(sk_buf)


def native_ed25519_sign(message: bytes, secret_key: bytes) -> bytes:
    """
    Sign message with Ed25519 using native C backend.

    Args:
        message: Data to sign (arbitrary length)
        secret_key: 64-byte secret key (seed || public_key)

    Returns:
        64-byte Ed25519 signature

    Raises:
        RuntimeError: If native library is not available or signing fails
        ValueError: If secret_key has incorrect length
    """
    if _native_lib is None or not _ED25519_NATIVE_AVAILABLE:
        raise RuntimeError("Ed25519 native backend not available. " + _INSTALL_HINT)

    if len(secret_key) != ED25519_SECRET_KEY_BYTES:
        raise ValueError(
            f"Ed25519 secret key must be {ED25519_SECRET_KEY_BYTES} bytes, "
            f"got {len(secret_key)}"
        )

    sig_buf = ctypes.create_string_buffer(ED25519_SIGNATURE_BYTES)
    rc = _native_lib.ama_ed25519_sign(sig_buf, message, ctypes.c_size_t(len(message)), secret_key)
    if rc != 0:
        raise RuntimeError(f"Ed25519 signing failed (rc={rc})")

    return bytes(sig_buf)


def native_ed25519_verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """
    Verify Ed25519 signature using native C backend.

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
    if _native_lib is None or not _ED25519_NATIVE_AVAILABLE:
        raise RuntimeError("Ed25519 native backend not available. " + _INSTALL_HINT)

    if len(signature) != ED25519_SIGNATURE_BYTES:
        raise ValueError(
            f"Ed25519 signature must be {ED25519_SIGNATURE_BYTES} bytes, " f"got {len(signature)}"
        )
    if len(public_key) != ED25519_PUBLIC_KEY_BYTES:
        raise ValueError(
            f"Ed25519 public key must be {ED25519_PUBLIC_KEY_BYTES} bytes, "
            f"got {len(public_key)}"
        )

    rc: int = _native_lib.ama_ed25519_verify(
        signature, message, ctypes.c_size_t(len(message)), public_key
    )
    return rc == 0


# ============================================================================
# AES-256-GCM NATIVE C BACKEND (NIST SP 800-38D)
# ============================================================================


def native_aes256_gcm_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> tuple:
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
        raise RuntimeError("AES-256-GCM native backend not available. " + _INSTALL_HINT)

    if len(key) != AES256_KEY_BYTES:
        raise ValueError(f"AES-256 key must be {AES256_KEY_BYTES} bytes, got {len(key)}")
    if len(nonce) != AES256_GCM_NONCE_BYTES:
        raise ValueError(
            f"AES-256-GCM nonce must be {AES256_GCM_NONCE_BYTES} bytes, " f"got {len(nonce)}"
        )

    ct_buf = ctypes.create_string_buffer(len(plaintext))
    tag_buf = ctypes.create_string_buffer(AES256_GCM_TAG_BYTES)

    rc = _native_lib.ama_aes256_gcm_encrypt(
        key,
        nonce,
        plaintext if len(plaintext) > 0 else None,
        ctypes.c_size_t(len(plaintext)),
        aad if len(aad) > 0 else None,
        ctypes.c_size_t(len(aad)),
        ct_buf,
        tag_buf,
    )
    if rc != 0:
        raise RuntimeError(f"AES-256-GCM encryption failed (rc={rc})")

    return bytes(ct_buf), bytes(tag_buf)


def native_aes256_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
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
        raise RuntimeError("AES-256-GCM native backend not available. " + _INSTALL_HINT)

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

    rc = _native_lib.ama_aes256_gcm_decrypt(
        key,
        nonce,
        ciphertext if len(ciphertext) > 0 else None,
        ctypes.c_size_t(len(ciphertext)),
        aad if len(aad) > 0 else None,
        ctypes.c_size_t(len(aad)),
        tag,
        pt_buf,
    )
    if rc != 0:
        raise ValueError("AES-256-GCM authentication tag verification failed")

    return bytes(pt_buf)


# ============================================================================
# HKDF NATIVE C BACKEND (RFC 5869)
# ============================================================================


def native_hkdf(
    ikm: bytes,
    length: int,
    salt: "Optional[bytes]" = None,
    info: bytes = b"",
) -> bytes:
    """
    HKDF key derivation using native C backend (HMAC-SHA3-256).

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
    if _native_lib is None or not _HKDF_NATIVE_AVAILABLE:
        raise RuntimeError("HKDF native backend not available. " + _INSTALL_HINT)

    if length > 8160:
        raise ValueError(f"HKDF output length must be <= 8160, got {length}")
    if length <= 0:
        raise ValueError(f"HKDF output length must be > 0, got {length}")

    okm_buf = ctypes.create_string_buffer(length)

    rc = _native_lib.ama_hkdf(
        salt if salt else None,
        ctypes.c_size_t(len(salt) if salt else 0),
        ikm,
        ctypes.c_size_t(len(ikm)),
        info if len(info) > 0 else None,
        ctypes.c_size_t(len(info)),
        okm_buf,
        ctypes.c_size_t(length),
    )
    if rc != 0:
        raise RuntimeError(f"HKDF derivation failed (rc={rc})")

    return bytes(okm_buf)


# ============================================================================
# SHA3-256 NATIVE C BACKEND (FIPS 202)
# ============================================================================


def _probe_cython_sha3() -> "Optional[Callable[[bytes], bytes]]":
    """Detect Cython SHA3-256 binding at module load time."""
    try:
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
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
        return _cy_sha3_fn(data)

    if _native_lib is None or not _SHA3_256_NATIVE_AVAILABLE:
        raise RuntimeError("SHA3-256 native backend not available. " + _INSTALL_HINT)

    out_buf = ctypes.create_string_buffer(32)

    rc = _native_lib.ama_sha3_256(
        data,
        ctypes.c_size_t(len(data)),
        out_buf,
    )
    if rc != 0:
        raise RuntimeError(f"SHA3-256 failed (rc={rc})")

    return bytes(out_buf)


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
        raise RuntimeError("HMAC-SHA3-256 native backend not available. " + _INSTALL_HINT)

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


def _probe_cython_hmac() -> "Optional[Callable[[bytes, bytes], bytes]]":
    """Detect Cython HMAC-SHA3-256 binding at module load time."""
    try:
        from ama_cryptography.hmac_binding import cy_hmac_sha3_256

        return cy_hmac_sha3_256  # type: ignore[no-any-return]
    except ImportError:
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
    import warnings

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
        raise RuntimeError("HMAC-SHA3-256 backend not available. " + _INSTALL_HINT)
    if _cy_hmac_fn is not None:
        return _cy_hmac_fn(key, msg)
    return native_hmac_sha3_256(key, msg)


# ============================================================================
# PROVIDER WRAPPER CLASSES FOR KAT TESTS
# ============================================================================


@dataclass
class _DilithiumKATKeyPair:
    """Internal keypair structure for KAT test compatibility."""

    public_key: bytes
    secret_key: bytes


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
        return _DilithiumKATKeyPair(public_key=kp.public_key, secret_key=kp.secret_key)

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
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
    secret_key: bytes


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
        return _KyberKATKeyPair(public_key=kp.public_key, secret_key=kp.secret_key)

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

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
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
        33-byte compressed public key (0x02/0x03 prefix + X)

    Raises:
        ValueError: If privkey is not 32 bytes
        RuntimeError: If native library is not available
    """
    if len(privkey) != SECP256K1_PRIVKEY_BYTES:
        raise ValueError(f"Private key must be {SECP256K1_PRIVKEY_BYTES} bytes, got {len(privkey)}")

    if _native_lib is None or not _SECP256K1_NATIVE_AVAILABLE:
        raise RuntimeError("secp256k1 native backend not available. " + _INSTALL_HINT)

    pubkey_buf = ctypes.create_string_buffer(SECP256K1_PUBKEY_BYTES)
    rc = _native_lib.ama_secp256k1_pubkey_from_privkey(privkey, pubkey_buf)
    if rc != 0:
        raise RuntimeError(f"secp256k1 pubkey derivation failed (rc={rc})")

    return bytes(pubkey_buf)


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
        raise RuntimeError("X25519 native backend not available. " + _INSTALL_HINT)

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
        raise RuntimeError("X25519 native backend not available. " + _INSTALL_HINT)

    if len(our_secret_key) != 32:
        raise ValueError(f"X25519 secret key must be 32 bytes, got {len(our_secret_key)}")
    if len(their_public_key) != 32:
        raise ValueError(f"X25519 public key must be 32 bytes, got {len(their_public_key)}")

    ss_buf = ctypes.create_string_buffer(X25519_KEY_BYTES)
    rc = _native_lib.ama_x25519_key_exchange(ss_buf, our_secret_key, their_public_key)
    if rc != 0:
        raise RuntimeError(f"X25519 key exchange failed (rc={rc})")

    return bytes(ss_buf)


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
        raise RuntimeError("Argon2id native backend not available. " + _INSTALL_HINT)

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
        raise RuntimeError("ChaCha20-Poly1305 native backend not available. " + _INSTALL_HINT)

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
        RuntimeError: On tag verification failure
    """
    if _native_lib is None or not _CHACHA20_POLY1305_NATIVE_AVAILABLE:
        raise RuntimeError("ChaCha20-Poly1305 native backend not available. " + _INSTALL_HINT)

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
        raise RuntimeError("Deterministic keygen not available. " + _INSTALL_HINT)

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
        raise RuntimeError("Deterministic keygen not available. " + _INSTALL_HINT)

    if len(xi) != 32:
        raise ValueError(f"Dilithium seed xi must be 32 bytes, got {len(xi)}")

    pk_buf = ctypes.create_string_buffer(DILITHIUM_PUBLIC_KEY_BYTES)
    sk_buf = ctypes.create_string_buffer(DILITHIUM_SECRET_KEY_BYTES)

    rc = _native_lib.ama_dilithium_keypair_from_seed(xi, pk_buf, sk_buf)
    if rc != 0:
        raise RuntimeError(f"Dilithium deterministic keygen failed (rc={rc})")

    return bytes(pk_buf), bytes(sk_buf)
