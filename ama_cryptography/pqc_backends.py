#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
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

AI Co-Architects: Eris ⯰ | Eden | Veritas 💠 | X ⚛ | Caduceus ⚚ | Dev ⚕
"""

import ctypes
import os
import platform
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

from ama_cryptography.exceptions import (  # noqa: F401 — re-exported for public API
    PQCUnavailableError,
    QuantumSignatureUnavailableError,
    SecurityWarning,
)

F = TypeVar("F", bound=Callable[..., Any])


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
    for build_dir in ["build/lib", "build", "cmake-build-release/lib", "cmake-build-debug/lib"]:
        search_dirs.append(pkg_dir / build_dir)

    # System paths
    search_dirs.extend([Path("/usr/local/lib"), Path("/usr/lib")])

    # LD_LIBRARY_PATH / DYLD_LIBRARY_PATH
    env_path = os.getenv("LD_LIBRARY_PATH", "") or os.getenv("DYLD_LIBRARY_PATH", "")
    for p in env_path.split(":"):
        if p:
            search_dirs.append(Path(p))

    return search_dirs


def _try_load_library(lib_path: Path) -> Optional[ctypes.CDLL]:
    """Try to load a shared library from the given path. Returns None on failure."""
    try:
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

        return True
    except AttributeError:
        # Library found but missing expected symbols — not built with AMA_USE_NATIVE_PQC
        return False


_native_lib = _find_native_library()
if _native_lib is not None and _setup_native_ctypes(_native_lib):
    _DILITHIUM_AVAILABLE = True
    _DILITHIUM_BACKEND = "native"
    _KYBER_AVAILABLE = True
    _KYBER_BACKEND = "native"
    _SPHINCS_AVAILABLE = True
    _SPHINCS_BACKEND = "native"


# Public API for checking availability
DILITHIUM_AVAILABLE: bool = _DILITHIUM_AVAILABLE
DILITHIUM_BACKEND: Optional[str] = _DILITHIUM_BACKEND
KYBER_AVAILABLE: bool = _KYBER_AVAILABLE
KYBER_BACKEND: Optional[str] = _KYBER_BACKEND
SPHINCS_AVAILABLE: bool = _SPHINCS_AVAILABLE
SPHINCS_BACKEND: Optional[str] = _SPHINCS_BACKEND

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
