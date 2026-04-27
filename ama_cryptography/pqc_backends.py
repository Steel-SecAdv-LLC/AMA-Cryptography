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
import logging
import os
import platform
import warnings
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional, Union, cast

from ama_cryptography._finalizer_health import record_finalizer_error
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
    # Context-based API
    "AmaContext",
    # FROST threshold Ed25519 (RFC 9591)
    "FROST_AVAILABLE",
    "FROST_BACKEND",
    "FROST_SHARE_BYTES",
    "FROST_NONCE_BYTES",
    "FROST_COMMITMENT_BYTES",
    "FROST_SIG_SHARE_BYTES",
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

# HMAC-SHA-512 native availability (for BIP32 key derivation)
_HMAC_SHA512_NATIVE_AVAILABLE = False


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
        # Legacy-verify shim (CHANGELOG [Unreleased] § BREAKING). Optional —
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
    _SHA3_256_NATIVE_AVAILABLE = _setup_sha3_256_ctypes(_native_lib)
    _HMAC_SHA3_256_NATIVE_AVAILABLE = _setup_hmac_sha3_256_ctypes(_native_lib)
    _HMAC_SHA512_NATIVE_AVAILABLE = _setup_hmac_sha512_ctypes(_native_lib)
    _SECP256K1_NATIVE_AVAILABLE = _setup_secp256k1_ctypes(_native_lib)
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
        raise RuntimeError("Ed25519 native backend not available. " + _INSTALL_HINT)

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
        raise RuntimeError("Ed25519 native backend not available. " + _INSTALL_HINT)

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
        raise RuntimeError("Ed25519 native backend not available. " + _INSTALL_HINT)

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

    # Primary path: Cython binding (zero marshaling overhead)
    if _cy_hkdf_fn is not None:
        hkdf_result: bytes = _cy_hkdf_fn(ikm, length, salt=salt, info=info if info else None)
        return hkdf_result

    if _native_lib is None or not _HKDF_NATIVE_AVAILABLE:
        raise RuntimeError("HKDF native backend not available. " + _INSTALL_HINT)

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
        raise RuntimeError("HMAC-SHA-512 native backend not available. " + _INSTALL_HINT)

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
        raise RuntimeError("HMAC-SHA3-256 backend not available. " + _INSTALL_HINT)
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
        raise RuntimeError("X25519 native backend not available. " + _INSTALL_HINT)
    if not hasattr(_native_lib, "ama_x25519_scalarmult_batch"):
        raise RuntimeError(
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
        raise RuntimeError("Argon2id native backend not available. " + _INSTALL_HINT)

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
        raise RuntimeError("Argon2id native backend not available. " + _INSTALL_HINT)
    if not hasattr(_native_lib, "ama_argon2id_legacy"):
        raise RuntimeError(
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
        "this function. See CHANGELOG.md [Unreleased] § BREAKING.",
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
    loop-termination bug (see ``CHANGELOG.md`` [Unreleased] § BREAKING).
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
        raise RuntimeError("Argon2id native backend not available. " + _INSTALL_HINT)
    if not hasattr(_native_lib, "ama_argon2id_legacy_verify"):
        raise RuntimeError(
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
        raise RuntimeError("FROST native library not available")
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
        raise RuntimeError("FROST native library not available")
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
        raise RuntimeError("FROST native library not available")
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
        raise RuntimeError("FROST native library not available")
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
