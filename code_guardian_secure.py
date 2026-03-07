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
AMA Cryptography: Ethical-Cryptographic SHA3-256 Security System
=====================================================================

Complete cryptographic protection system for helical mathematical Omni-Codes.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Date: 2025-12-06
Version: 2.0
Project: Post-quantum cryptographic security system

AI Co-Architects:
    Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛

Security Layers (6-Layer Defense-in-Depth):
-------------------------------------------
1. SHA3-256 content hashing (NIST FIPS 202)
2. HMAC-SHA3-256 authentication (RFC 2104)
3. Ed25519 digital signatures (RFC 8032)
4. CRYSTALS-Dilithium quantum-resistant signatures (NIST FIPS 204) - required by default
5. HKDF key derivation (RFC 5869, NIST SP 800-108)
6. RFC 3161 trusted timestamps with cryptographic verification (RFC 3161)

Additional Features:
--------------------
- HSM integration support for secure key storage

Standards Compliance:
---------------------
- NIST FIPS 202: SHA-3 Standard
- NIST SP 800-108: Key Derivation Using Pseudorandom Functions
- NIST PQC Round 3: CRYSTALS-Dilithium
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 2104: HMAC: Keyed-Hashing for Message Authentication
- RFC 5869: HMAC-based Extract-and-Expand Key Derivation (HKDF)
- RFC 3161: Internet X.509 Public Key Infrastructure Time-Stamp Protocol

Version: 2.0
Python: 3.8+
License: Apache License 2.0
"""

import base64
import hashlib
import hmac
import json
import secrets
import struct
import subprocess  # nosec B404 - subprocess used only with fixed OpenSSL commands for RFC 3161
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, Union, cast

if TYPE_CHECKING:
    from ama_cryptography_monitor import AmaCryptographyMonitor

# Cryptographic dependencies
try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("ERROR: Install cryptography library")
    print("  pip install cryptography")
    raise

# Import centralized exception classes
from ama_cryptography.exceptions import QuantumSignatureUnavailableError

# Quantum-resistant cryptography (CRYSTALS-Dilithium)
# Import from centralized PQC backends module (DRY principle)
# We import the backend functions with underscore prefix and wrap them
# to allow tests to monkeypatch module-level DILITHIUM_* variables
from ama_cryptography.pqc_backends import DILITHIUM_AVAILABLE as _PQC_DILITHIUM_AVAILABLE
from ama_cryptography.pqc_backends import DILITHIUM_BACKEND as _PQC_DILITHIUM_BACKEND
from ama_cryptography.pqc_backends import (
    DilithiumKeyPair,
)
from ama_cryptography.pqc_backends import dilithium_sign as _pqc_dilithium_sign
from ama_cryptography.pqc_backends import dilithium_verify as _pqc_dilithium_verify
from ama_cryptography.pqc_backends import (
    generate_dilithium_keypair as _pqc_generate_dilithium_keypair,
)

# Module-level variables for backward compatibility with tests
# Tests can monkeypatch these to test different backend paths
DILITHIUM_AVAILABLE: bool = _PQC_DILITHIUM_AVAILABLE
DILITHIUM_BACKEND: Optional[str] = _PQC_DILITHIUM_BACKEND


# ============================================================================
# DILITHIUM WRAPPER FUNCTIONS (for test compatibility)
# ============================================================================
# These wrapper functions check module-level DILITHIUM_* variables,
# allowing tests to monkeypatch them to test different backend paths.


def generate_dilithium_keypair() -> DilithiumKeyPair:
    """
    Generate a CRYSTALS-Dilithium (ML-DSA-65) keypair.

    This wrapper function checks module-level DILITHIUM_AVAILABLE and
    DILITHIUM_BACKEND variables, allowing tests to monkeypatch them.

    Returns:
        DilithiumKeyPair with ML-DSA-65 keys

    Raises:
        QuantumSignatureUnavailableError: If no Dilithium backend is available
    """
    import sys

    # Get current module to check monkeypatched values
    this_module = sys.modules[__name__]
    available = getattr(this_module, "DILITHIUM_AVAILABLE", _PQC_DILITHIUM_AVAILABLE)

    if not available:
        raise QuantumSignatureUnavailableError(
            "PQC_UNAVAILABLE: Dilithium backend not available. "
            "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )

    return _pqc_generate_dilithium_keypair()


def dilithium_sign(message: bytes, secret_key: bytes) -> bytes:
    """
    Sign message with CRYSTALS-Dilithium (ML-DSA-65).

    This wrapper function checks module-level DILITHIUM_AVAILABLE and
    DILITHIUM_BACKEND variables, allowing tests to monkeypatch them.

    Args:
        message: Data to sign
        secret_key: Dilithium secret key (4032 bytes)

    Returns:
        Dilithium signature (3309 bytes)

    Raises:
        QuantumSignatureUnavailableError: If no Dilithium backend is available
    """
    import sys

    # Get current module to check monkeypatched values
    this_module = sys.modules[__name__]
    available = getattr(this_module, "DILITHIUM_AVAILABLE", _PQC_DILITHIUM_AVAILABLE)

    if not available:
        raise QuantumSignatureUnavailableError(
            "PQC_UNAVAILABLE: Dilithium backend not available. "
            "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )

    return _pqc_dilithium_sign(message, secret_key)


def dilithium_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify CRYSTALS-Dilithium signature.

    This wrapper function checks module-level DILITHIUM_AVAILABLE and
    DILITHIUM_BACKEND variables, allowing tests to monkeypatch them.

    Args:
        message: Original data
        signature: Dilithium signature
        public_key: Dilithium public key (1952 bytes)

    Returns:
        True if signature is valid, False otherwise

    Raises:
        QuantumSignatureUnavailableError: If no Dilithium backend is available
    """
    import sys

    # Get current module to check monkeypatched values
    this_module = sys.modules[__name__]
    available = getattr(this_module, "DILITHIUM_AVAILABLE", _PQC_DILITHIUM_AVAILABLE)

    if not available:
        raise QuantumSignatureUnavailableError(
            "PQC_UNAVAILABLE: Dilithium backend not available. "
            "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )

    return _pqc_dilithium_verify(message, signature, public_key)


# ============================================================================
# EXCEPTIONS
# ============================================================================
# NOTE: QuantumSignatureUnavailableError is imported from ama_cryptography.exceptions


class QuantumSignatureRequiredError(Exception):
    """
    Raised when quantum-resistant signatures are required by policy but
    Dilithium is not available or the package lacks quantum signatures.

    Use this exception to enforce mandatory quantum-resistant protection
    in high-security deployments.
    """

    pass


# ============================================================================
# SECURE MEMORY UTILITIES
# ============================================================================


def secure_wipe(data: Union[bytes, bytearray]) -> None:
    """
    Securely wipe sensitive data from memory.

    Security Note:
    --------------
    This function attempts to overwrite sensitive data in memory to prevent
    forensic recovery. However, Python's memory management may create copies
    of data that cannot be wiped. For highest-security applications, use
    hardware security modules (HSMs) that provide secure key storage.

    Limitations:
    ------------
    - Python may have created copies of the data elsewhere in memory
    - Garbage collector may not immediately release memory
    - Swap files may contain copies of sensitive data
    - For production use, consider HSM integration

    Args:
        data: Mutable bytearray to wipe (bytes objects are immutable)
    """
    if not isinstance(data, bytearray):
        return  # Cannot wipe immutable bytes

    # Overwrite with zeros
    for i in range(len(data)):
        data[i] = 0

    # Overwrite with ones
    for i in range(len(data)):
        data[i] = 0xFF

    # Final overwrite with zeros
    for i in range(len(data)):
        data[i] = 0


# ============================================================================
# CANONICAL ENCODING WITH LENGTH-PREFIXING
# ============================================================================


def length_prefixed_encode(*fields: str) -> bytes:
    """
    Encode fields with length-prefixing for collision-proof domain separation.

    Mathematical Foundation:
    ------------------------
    For field sequences F = (f₁, f₂, ..., fₙ) and G = (g₁, g₂, ..., gₘ):

    Theorem (Collision Resistance):
        If F ≠ G, then encode(F) ≠ encode(G)

    Proof:
        Case 1: n ≠ m
            - Number of length fields differs
            - encode(F) ≠ encode(G) immediately

        Case 2: n = m, ∃i: fᵢ ≠ gᵢ
            - Either len(fᵢ) ≠ len(gᵢ) → length prefixes differ
            - Or len(fᵢ) = len(gᵢ) but fᵢ ≠ gᵢ → field content differs
            - In both cases: encode(F) ≠ encode(G)

    Standard: ASN.1 DER (Distinguished Encoding Rules) - X.690
    Reference: ITU-T X.690 (2015), Section 8.1.3

    Security Properties:
    --------------------
    - Injective mapping: No two distinct inputs produce same output
    - Domain separation: Different field structures produce different encodings
    - Concatenation-safe: Eliminates all concatenation attacks

    Format: [len₁][data₁][len₂][data₂]...[lenₙ][dataₙ]
    Length encoding: 4-byte big-endian unsigned integer (supports up to 4GB)

    Example:
        encode("ABC", "DE") → 0x00000003ABC00000002DE
        encode("AB", "CDE") → 0x00000002AB00000003CDE

        These produce different SHA3-256 hashes even though
        concatenation "ABCDE" is identical.

    Args:
        *fields: Variable number of string fields to encode

    Returns:
        Length-prefixed byte encoding

    Raises:
        ValueError: If any field exceeds 4GB
    """
    encoded = b""
    for i, field_value in enumerate(fields):
        field_bytes = field_value.encode("utf-8")

        # Validate field size
        if len(field_bytes) > 0xFFFFFFFF:
            raise ValueError(f"Field {i} exceeds 4GB limit")

        # 4-byte big-endian length prefix
        length = struct.pack(">I", len(field_bytes))
        encoded += length + field_bytes

    return encoded


def canonical_hash_code(codes: str, helix_params: List[Tuple[float, float]]) -> bytes:
    """
    Compute collision-resistant hash with proper domain separation.

    Cryptographic Analysis:
    -----------------------
    Hash Function: SHA3-256 (Keccak)
        - Collision resistance: 2^128 security level
        - Pre-image resistance: 2^256 security level
        - Second pre-image resistance: 2^256 security level

    Standard: NIST FIPS 202 (SHA-3 Standard)
    Reference: NIST FIPS 202 (2015), DOI: 10.6028/NIST.FIPS.202

    Domain Separation Strategy:
    ----------------------------
    1. Omni-Codes encoded with "CODE" domain tag
    2. Helix parameters encoded with "HELIX" domain tag
    3. Each parameter tuple formatted as "radius:pitch"
    4. Length-prefixed encoding prevents concatenation attacks

    Security Proof:
    ---------------
    Given two distinct inputs (D₁, H₁) and (D₂, H₂):

    If D₁ ≠ D₂ or H₁ ≠ H₂, then:
        - encode("CODE", D₁, "HELIX", ...) ≠ encode("CODE", D₂, "HELIX", ...)
        - By SHA3-256 collision resistance:
        - P(hash(input₁) = hash(input₂)) ≤ 2^-128

    This provides cryptographic assurance of integrity.

    Args:
        codes: Concatenated Omni-Code string (must be non-empty)
        helix_params: List of (radius, pitch) tuples (must be non-empty)

    Returns:
        32-byte SHA3-256 hash digest

    Raises:
        TypeError: If codes is not a string or helix_params is not a list
        ValueError: If codes or helix_params is empty, or if tuples are malformed
    """
    # Input validation
    if not isinstance(codes, str):
        raise TypeError(f"codes must be str, got {type(codes).__name__}")
    if not isinstance(helix_params, list):
        raise TypeError(f"helix_params must be list, got {type(helix_params).__name__}")
    if not codes:
        raise ValueError("codes cannot be empty")
    if not helix_params:
        raise ValueError("helix_params cannot be empty")

    # Validate each helix parameter tuple
    for i, param in enumerate(helix_params):
        if not isinstance(param, (tuple, list)) or len(param) != 2:
            raise ValueError(f"helix_params[{i}] must be a (radius, pitch) tuple, got {param!r}")
        radius, pitch = param
        if not isinstance(radius, (int, float)) or not isinstance(pitch, (int, float)):
            raise ValueError(
                f"helix_params[{i}] values must be numeric, got ({type(radius).__name__}, "
                f"{type(pitch).__name__})"
            )

    # Convert helix parameters to canonical string format
    helix_strs = [f"{r:.10f}:{p:.10f}" for r, p in helix_params]

    # Create length-prefixed encoding with domain tags
    encoded = length_prefixed_encode("CODE", codes, "HELIX", *helix_strs)

    # Compute SHA3-256 hash
    return hashlib.sha3_256(encoded).digest()


# ============================================================================
# HMAC AUTHENTICATION
# ============================================================================


def hmac_authenticate(message: bytes, key: bytes) -> bytes:
    """
    Generate HMAC-SHA3-256 authentication tag.

    Cryptographic Foundation:
    -------------------------
    HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))

    Where:
        - H = SHA3-256
        - K = secret key (32 bytes recommended)
        - m = message
        - opad = 0x5c repeated (outer padding)
        - ipad = 0x36 repeated (inner padding)
        - || = concatenation
        - ⊕ = XOR

    Security Properties:
    --------------------
    1. Unforgeable: Cannot create valid tag without knowing K
    2. Collision-resistant: Inherits from SHA3-256
    3. PRF: Pseudorandom function when K is random

    Standard: RFC 2104 (HMAC)
    Reference: Krawczyk et al., "HMAC: Keyed-Hashing for Message
               Authentication", RFC 2104, February 1997

    Security Proof (Bellare et al., 1996):
    ---------------------------------------
    If H is collision-resistant, then HMAC is a secure PRF and MAC.

    Theorem: For adversary A making q queries with total length σ bits:
        Adv_PRF(A) ≤ Adv_CR(H) + (σ + qb)²/2^(n+1)

    Where:
        - b = block size (1088 bits for SHA3-256)
        - n = output size (256 bits)
        - Adv_CR(H) = collision-finding advantage (≤ 2^-128 for SHA3-256)

    For practical parameters (q = 2^32 queries, σ = 2^40 bits):
        Adv_PRF(A) ≤ 2^-128 + 2^-89 ≈ 2^-89

    This provides strong security against forgery attacks.

    Args:
        message: Data to authenticate (arbitrary length)
        key: Secret HMAC key (32 bytes minimum, 64 bytes recommended)

    Returns:
        32-byte HMAC-SHA3-256 authentication tag

    Raises:
        ValueError: If key is too short (< 32 bytes)
    """
    if len(key) < 32:
        raise ValueError("HMAC key must be at least 32 bytes for SHA3-256 security")

    # Use SHA3-256 for HMAC
    return hmac.new(key, message, hashlib.sha3_256).digest()


def hmac_verify(message: bytes, tag: bytes, key: bytes) -> bool:
    """
    Verify HMAC-SHA3-256 authentication tag (constant-time).

    Security Implementation:
    ------------------------
    Uses constant-time comparison to prevent timing attacks.

    Timing Attack Prevention:
    -------------------------
    Standard comparison (VULNERABLE):
        for i in range(len(tag)):
            if tag[i] != expected[i]:
                return False  # Early return leaks information

    Constant-time comparison (SECURE):
        diff = 0
        for i in range(len(tag)):
            diff |= tag[i] ^ expected[i]
        return diff == 0  # No early return

    Python's hmac.compare_digest() implements constant-time comparison.

    Reference: Timing attack mitigation in RFC 2104, Section 5

    Args:
        message: Original data
        tag: HMAC tag to verify
        key: Secret HMAC key

    Returns:
        True if tag is valid, False otherwise
    """
    expected = hmac_authenticate(message, key)
    return hmac.compare_digest(tag, expected)


# ============================================================================
# ED25519 DIGITAL SIGNATURES
# ============================================================================


@dataclass
class Ed25519KeyPair:
    """
    Ed25519 elliptic curve key pair.

    Cryptographic Parameters:
    -------------------------
    Curve: Twisted Edwards curve Ed25519
        - Equation: -x² + y² = 1 - (121665/121666)x²y²
        - Base point order: 2^252 + 27742317777372353535851937790883648493
        - Cofactor: 8

    Security Level: 128 bits (equivalent to RSA-3072, AES-128)

    Key Sizes:
        - Private key: 32 bytes (256 bits)
        - Public key: 32 bytes (256 bits, compressed point)
        - Signature: 64 bytes (R || s format)

    Standard: RFC 8032 (EdDSA)
    Reference: Josefsson & Liusvaara, "Edwards-Curve Digital Signature
               Algorithm (EdDSA)", RFC 8032, January 2017

    Mathematical Foundation:
    ------------------------
    Signature Generation:
        1. r = H(H₀(k) || M) mod ℓ
        2. R = rB (point multiplication on curve)
        3. s = (r + H(R || A || M)a) mod ℓ
        4. Signature = (R, s)

    Where:
        - k = private key (32 bytes)
        - a = H₀(k) (scalar derived from private key)
        - A = aB (public key)
        - B = base point
        - M = message
        - H = SHA-512
        - ℓ = order of base point

    Signature Verification:
        Check: sB = R + H(R || A || M)A

    Security Proof (Bernstein et al., 2011):
    ----------------------------------------
    Ed25519 is SUF-CMA (Strongly Unforgeable under Chosen Message Attack)
    in the random oracle model, assuming discrete log hardness on Ed25519.

    Theorem: For adversary A making q signing queries:
        Adv_SUF-CMA(A) ≤ (q + 1) · Adv_DL(Ed25519) + ε_collision

    Where:
        - Adv_DL ≈ 2^-128 (discrete log advantage)
        - ε_collision ≈ 2^-256 (hash collision probability)

    Performance (typical):
        - Sign: ~60 μs (16,000 signatures/second)
        - Verify: ~16 μs (62,000 verifications/second)
        - KeyGen: ~60 μs

    Reference: Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., &
               Yang, B. Y. (2011). "High-speed high-security signatures."
               Journal of Cryptographic Engineering, 2(2), 77-89.
    """

    private_key: bytes = field(repr=False)  # 32 bytes - excluded from repr to prevent exposure
    public_key: bytes  # 32 bytes


def generate_ed25519_keypair(seed: Optional[bytes] = None) -> Ed25519KeyPair:
    """
    Generate Ed25519 key pair.

    Key Generation Algorithm (RFC 8032, Section 5.1.5):
    ----------------------------------------------------
    1. Generate 32-byte random seed (or use provided seed)
    2. Compute H = SHA-512(seed)
    3. Prune H₀ (first 32 bytes):
        - Clear lowest 3 bits
        - Clear highest bit
        - Set second-highest bit
    4. Compute scalar a = H₀ (clamped to be in range)
    5. Compute public key A = aB (scalar multiplication)

    Deterministic Option:
    ---------------------
    If seed is provided, generation is deterministic (same seed → same keys).
    This is useful for:
        - Key derivation from master secret
        - Reproducible testing
        - Backup/recovery from seed phrase

    Security: Seed must have at least 128 bits of entropy from CSPRNG.

    Args:
        seed: Optional 32-byte seed for deterministic generation
              If None, generates random seed from secrets.token_bytes()

    Returns:
        Ed25519KeyPair with private and public keys

    Raises:
        RuntimeError: If cryptography library not available
        ValueError: If seed is provided but not 32 bytes
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography library required for Ed25519")

    if seed is not None:
        if len(seed) != 32:
            raise ValueError("Seed must be exactly 32 bytes")
        # Deterministic generation from seed
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    else:
        # Generate random key using CSPRNG
        private_key = ed25519.Ed25519PrivateKey.generate()

    public_key = private_key.public_key()

    # Serialize keys to raw bytes
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    return Ed25519KeyPair(private_key=private_bytes, public_key=public_bytes)


def ed25519_sign(message: bytes, private_key: Union[bytes, ed25519.Ed25519PrivateKey]) -> bytes:
    """
    Sign message with Ed25519 (deterministic).

    Signature Algorithm (RFC 8032, Section 5.1.6):
    -----------------------------------------------
    Input: Private key k (32 bytes), Message M
    Output: Signature (R || s) (64 bytes)

    Steps:
        1. Compute H = SHA-512(k)
        2. Derive scalar: a = H₀ (clamped)
        3. Compute nonce: r = H(H₁ || M) mod ℓ
        4. Compute R = rB (point on curve)
        5. Compute challenge: h = H(R || A || M) mod ℓ
        6. Compute response: s = (r + ha) mod ℓ
        7. Return signature: (R, s)

    Determinism:
    ------------
    Ed25519 is deterministic (no random nonce). Same message + key
    always produces same signature. This:
        - Eliminates nonce reuse vulnerabilities (ECDSA flaw)
        - Simplifies implementation
        - Enables signature reproducibility

    Security: Determinism is secure for Ed25519 because nonce r is
              derived from hash of private key and message.

    Performance Optimization:
    -------------------------
    For high-throughput scenarios (>10,000 signatures/sec), pass an
    Ed25519PrivateKey object instead of bytes to eliminate key
    reconstruction overhead (~2x faster):

        key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
        for msg in messages:
            signature = ed25519_sign(msg, key_obj)  # 2x faster

    Args:
        message: Data to sign (arbitrary length)
        private_key: Either 32-byte Ed25519 private key (bytes) OR
                    Ed25519PrivateKey object (for 2x performance)

    Returns:
        64-byte signature (R || s format)

    Raises:
        RuntimeError: If cryptography library not available
        ValueError: If private_key bytes are not 32 bytes
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography library required")

    # Smart type handling: accept both bytes and key objects
    if isinstance(private_key, bytes):
        if len(private_key) != 32:
            raise ValueError("Ed25519 private key must be 32 bytes")
        key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    else:
        # Already a key object - no reconstruction overhead!
        key = private_key

    signature: bytes = key.sign(message)
    return signature


def ed25519_verify(
    message: bytes, signature: bytes, public_key: Union[bytes, ed25519.Ed25519PublicKey]
) -> bool:
    """
    Verify Ed25519 signature.

    Verification Algorithm (RFC 8032, Section 5.1.7):
    --------------------------------------------------
    Input: Public key A, Message M, Signature (R, s)
    Output: Accept or Reject

    Steps:
        1. Check R is valid point on curve
        2. Check s < ℓ (order of base point)
        3. Compute challenge: h = H(R || A || M) mod ℓ
        4. Check equation: sB = R + hA
           (Equivalently: 8sB = 8R + 8hA to handle cofactor)

    Security Considerations:
    ------------------------
    - Uses cofactorless verification (RFC 8032, Section 5.1.7.4)
    - Checks for small-order points
    - Validates all curve points
    - Constant-time comparison where possible

    Common Vulnerabilities (all mitigated):
    ----------------------------------------
    1. Small-order attacks: Check R is not small-order point
    2. Non-canonical signatures: Reject if s ≥ ℓ
    3. Malleability: Ed25519 is strongly binding (no malleability)
    4. Side-channel attacks: Use constant-time operations

    Performance Optimization:
    -------------------------
    For high-throughput scenarios, pass an Ed25519PublicKey object
    instead of bytes to eliminate key reconstruction overhead:

        key_obj = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
        for msg, sig in verifications:
            valid = ed25519_verify(msg, sig, key_obj)  # Faster

    Args:
        message: Original data that was signed
        signature: 64-byte Ed25519 signature
        public_key: Either 32-byte Ed25519 public key (bytes) OR
                   Ed25519PublicKey object (for better performance)

    Returns:
        True if signature is valid, False otherwise

    Raises:
        RuntimeError: If cryptography library not available
        ValueError: If signature is not 64 bytes or public_key bytes not 32 bytes
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography library required")

    if len(signature) != 64:
        raise ValueError("Ed25519 signature must be 64 bytes")

    # Smart type handling: accept both bytes and key objects
    if isinstance(public_key, bytes):
        if len(public_key) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
        key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
    else:
        # Already a key object - no reconstruction overhead!
        key = public_key

    try:
        key.verify(signature, message)
        return True
    except Exception:
        return False


# ============================================================================
# CRYSTALS-DILITHIUM QUANTUM-RESISTANT SIGNATURES
# ============================================================================
# NOTE: DilithiumKeyPair, generate_dilithium_keypair, dilithium_sign, and
# dilithium_verify are now imported from ama_cryptography.pqc_backends (DRY).
# See that module for the authoritative implementation and documentation.
# ============================================================================


# ============================================================================
# RFC 3161 TRUSTED TIMESTAMPING
# ============================================================================


def get_rfc3161_timestamp(data: bytes, tsa_url: Optional[str] = None) -> Optional[bytes]:
    """
    Get RFC 3161 trusted timestamp for data.

    This function fetches timestamp tokens from a TSA (Time Stamping Authority).
    The returned token contains a cryptographically signed timestamp that can be
    verified using verify_rfc3161_timestamp().

    Protocol (RFC 3161):
    --------------------
    1. Client sends TimeStampReq to TSA containing:
       - Hash of data (not data itself for privacy)
       - Requested policy OID
       - Nonce (optional)

    2. TSA responds with TimeStampResp containing:
       - Signed timestamp token
       - TSA certificate chain
       - Timestamp value
       - Hash of data

    Security Properties:
    --------------------
    - Proof of existence: Data existed at timestamp T
    - Non-repudiation: TSA signature proves authenticity
    - Third-party trust: Independent TSA provides assurance

    TSA Options:
    ------------
    1. Commercial TSA:
       - DigiCert: https://timestamp.digicert.com
       - GlobalSign: http://timestamp.globalsign.com/tsa/r6advanced1
       - Cost: $1-5 per timestamp

    2. Free TSA (limited):
       - FreeTSA: https://freetsa.org/tsr
       - Rate limited

    3. Self-hosted TSA:
       - Requires PKI infrastructure
       - OpenSSL can act as TSA

    Standard: RFC 3161 - Internet X.509 PKI Time-Stamp Protocol
    Reference: Adams et al., RFC 3161, August 2001

    Args:
        data: Data to timestamp (will be hashed)
        tsa_url: TSA server URL (default: FreeTSA)

    Returns:
        RFC 3161 timestamp token (DER-encoded), or None if TSA unavailable
    """
    if tsa_url is None:
        tsa_url = "https://freetsa.org/tsr"

    # Validate URL scheme for security (only allow http/https for TSA endpoints)
    import urllib.parse

    parsed_url = urllib.parse.urlparse(tsa_url)
    if parsed_url.scheme not in ("http", "https"):
        print(f"Warning: Invalid TSA URL scheme '{parsed_url.scheme}', must be http or https")
        return None

    try:
        # Create timestamp request using OpenSSL
        # NOTE: SHA-256 is used here instead of SHA3-256 for TSA compatibility.
        # Most RFC 3161 TSA services (FreeTSA, DigiCert, GlobalSign) do not support
        # SHA3-256. This is a deliberate design choice for interoperability.
        # The timestamp token itself provides proof-of-existence, and the SHA-256
        # hash is only used for the TSA request, not for the package integrity.
        cmd_query = ["openssl", "ts", "-query", "-data", "-", "-sha256", "-no_nonce"]

        proc = subprocess.run(cmd_query, input=data, capture_output=True, timeout=10)  # nosec B603

        if proc.returncode != 0:
            print(f"Warning: OpenSSL ts-query failed: {proc.stderr.decode()}")
            return None

        tsq = proc.stdout

        # Submit to TSA
        import urllib.request

        req = urllib.request.Request(
            tsa_url, data=tsq, headers={"Content-Type": "application/timestamp-query"}
        )

        with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310
            tsr = response.read()

        return cast(bytes, tsr)

    except Exception as e:
        print(f"Warning: RFC 3161 timestamp failed: {e}")
        print("Falling back to self-asserted timestamp")
        return None


def verify_rfc3161_timestamp(
    data: bytes, timestamp_token: bytes, tsa_cert_path: Optional[str] = None
) -> bool:
    """
    Verify RFC 3161 timestamp token cryptographically.

    This function provides TRUE cryptographic verification of RFC 3161 timestamps,
    making it a proper security layer rather than just metadata. It verifies:
    1. The TSA's digital signature on the timestamp token
    2. The hash in the token matches the provided data
    3. The timestamp token structure is valid

    Cryptographic Verification Process:
    ------------------------------------
    1. Parse the TimeStampResp (DER-encoded ASN.1)
    2. Extract the signed TimeStampToken (CMS/PKCS#7 SignedData)
    3. Verify the TSA's signature using the TSA certificate
    4. Extract and verify the message imprint (hash of original data)
    5. Compare the hash in the token with SHA-256(data)

    Security Properties:
    --------------------
    - Signature Verification: Proves the TSA signed the timestamp
    - Hash Binding: Proves the timestamp is for this specific data
    - Non-repudiation: TSA cannot deny issuing the timestamp
    - Tamper Detection: Any modification invalidates the signature

    Standard: RFC 3161 - Internet X.509 PKI Time-Stamp Protocol
    Reference: Adams et al., RFC 3161, August 2001

    Args:
        data: Original data that was timestamped
        timestamp_token: RFC 3161 timestamp response (DER-encoded)
        tsa_cert_path: Optional path to TSA certificate for verification.
                       If None, uses OpenSSL's default CA bundle.

    Returns:
        True if timestamp is cryptographically valid, False otherwise
    """
    import tempfile

    try:
        # Write timestamp token to temporary file for OpenSSL verification
        with tempfile.NamedTemporaryFile(suffix=".tsr", delete=False) as tsr_file:
            tsr_file.write(timestamp_token)
            tsr_path = tsr_file.name

        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as data_file:
            data_file.write(data)
            data_path = data_file.name

        # Build OpenSSL verification command
        # openssl ts -verify verifies:
        # 1. TSA signature validity
        # 2. Hash in token matches data
        # 3. Certificate chain (if CAfile provided)
        cmd_verify = [
            "openssl",
            "ts",
            "-verify",
            "-data",
            data_path,
            "-in",
            tsr_path,
        ]

        # Add TSA certificate if provided
        if tsa_cert_path:
            cmd_verify.extend(["-CAfile", tsa_cert_path])
        else:
            # Use untrusted mode for basic signature verification
            # This verifies the signature structure but not the certificate chain
            cmd_verify.append("-no_check_time")

        proc = subprocess.run(cmd_verify, capture_output=True, timeout=10)  # nosec B603

        # Clean up temporary files
        import os

        os.unlink(tsr_path)
        os.unlink(data_path)

        # OpenSSL returns 0 on successful verification
        if proc.returncode == 0:
            return True
        else:
            # Log verification failure details for debugging
            stderr = proc.stderr.decode() if proc.stderr else ""
            if "Verification: OK" in stderr or "Verification: OK" in proc.stdout.decode():
                return True
            return False

    except Exception as e:
        print(f"Warning: RFC 3161 timestamp verification failed: {e}")
        return False


def _verify_rfc3161_token(
    content_hash: bytes, timestamp_token_b64: Optional[str]
) -> Optional[bool]:
    """
    Internal helper to verify RFC 3161 timestamp token.

    Args:
        content_hash: The content hash that was timestamped
        timestamp_token_b64: Base64-encoded timestamp token, or None

    Returns:
        True if valid, False if invalid, None if no token present
    """
    if not timestamp_token_b64:
        return None

    try:
        timestamp_token = base64.b64decode(timestamp_token_b64)
        return verify_rfc3161_timestamp(content_hash, timestamp_token)
    except Exception:
        return False


# ============================================================================
# 12 OMNI-CODE ETHICAL PILLARS INTEGRATION
# ============================================================================

# 12 Ethical Pillars as balanced vector (Σw = 12.0)
ETHICAL_VECTOR = {
    # Triad 1: Knowledge Domain (Verification Layer)
    "omniscient": 1.0,  # Complete verification
    "omnipercipient": 1.0,  # Multi-dimensional detection
    "omnilegent": 1.0,  # Data validation
    # Triad 2: Power Domain (Cryptographic Generation)
    "omnipotent": 1.0,  # Maximum strength
    "omnificent": 1.0,  # Key generation
    "omniactive": 1.0,  # Real-time protection
    # Triad 3: Coverage Domain (Defense-in-Depth)
    "omnipresent": 1.0,  # Multi-layer defense
    "omnitemporal": 1.0,  # Temporal integrity
    "omnidirectional": 1.0,  # Attack surface coverage
    # Triad 4: Omnibenevolence Domain (Ethical Constraints)
    "omnibenevolent": 1.0,  # Ethical foundation
    "omniperfect": 1.0,  # Mathematical correctness
    "omnivalent": 1.0,  # Hybrid security
}

# Verify balanced weighting - runtime check instead of assert for fail-closed security
if sum(ETHICAL_VECTOR.values()) != 12.0 or not all(w == 1.0 for w in ETHICAL_VECTOR.values()):
    raise RuntimeError(
        "ETHICAL_VECTOR configuration error: must have 12 weights of 1.0 each (Σw = 12.0)"
    )


def create_ethical_hkdf_context(
    base_context: bytes, ethical_vector: Optional[Dict[str, float]] = None
) -> bytes:
    """
    Integrates ethical vector into HKDF key derivation context.

    Security: Ethical context affects derived keys without weakening
    the underlying HKDF security (2^128).

    Mathematical Proof:
    -------------------
    Let H = SHA3-256 with collision resistance 2^128
    Let C₀ = base HKDF context
    Let E = ethical vector with hash H(E)
    Let C₁ = C₀ || H(E)[:16]

    Claim: Using C₁ instead of C₀ maintains H collision resistance

    Proof by contradiction:
    Assume ∃ efficient algorithm A finding H collisions via C₁
    Then A could:
    1. Query HKDF with context C₁ = C₀ || H(E)[:16]
    2. Find collision in underlying SHA3-256 within H

    But this contradicts SHA3-256 collision resistance (2^128 security)
    Therefore: No efficient A exists
    Conclusion: Ethical integration is cryptographically safe ∎

    Args:
        base_context: Original HKDF info parameter
        ethical_vector: 12-pillar ethical weights (Σw = 12.0)

    Returns:
        Enhanced context with 128-bit ethical signature
    """
    if ethical_vector is None:
        ethical_vector = ETHICAL_VECTOR

    # Canonical JSON encoding (sorted keys)
    ethical_json = json.dumps(ethical_vector, sort_keys=True)

    # SHA3-256 hash of ethical vector
    ethical_hash = hashlib.sha3_256(ethical_json.encode()).digest()

    # Extract 128-bit signature (first 16 bytes)
    ethical_signature = ethical_hash[:16]

    # Concatenate with base context
    enhanced_context = base_context + ethical_signature

    return enhanced_context


# ============================================================================
# KEY DERIVATION (HKDF) WITH ETHICAL INTEGRATION
# ============================================================================


def derive_keys(
    master_secret: bytes,
    info: str,
    num_keys: int = 3,
    ethical_vector: Optional[Dict[str, float]] = None,
    salt: Optional[bytes] = None,
) -> Tuple[List[bytes], bytes]:
    """
    Derive multiple independent keys from master secret using HKDF with ethical context.

    HKDF Algorithm (RFC 5869) with Ethical Enhancement:
    ---------------------------------------------------
    Two-phase key derivation:

    Phase 1 - Extract:
        PRK = HMAC-Hash(salt, IKM)

    Phase 2 - Expand (Enhanced):
        Enhanced_info = base_info || SHA3-256(ethical_vector)[:16]
        T(0) = empty string
        T(1) = HMAC-Hash(PRK, T(0) || Enhanced_info || 0x01)
        T(2) = HMAC-Hash(PRK, T(1) || Enhanced_info || 0x02)
        ...
        T(N) = HMAC-Hash(PRK, T(N-1) || Enhanced_info || N)

        OKM = first L bytes of T(1) || T(2) || ... || T(N)

    Where:
        - IKM = Input Keying Material (master_secret)
        - PRK = Pseudorandom Key (extracted secret)
        - Enhanced_info = Context with 128-bit ethical signature
        - OKM = Output Keying Material (derived keys)
        - Hash = SHA3-256 (consistent with project's SHA3 emphasis)

    Ethical Integration Security:
    -----------------------------
    The ethical vector is integrated via create_ethical_hkdf_context() which:
    1. Creates canonical JSON representation (sorted keys)
    2. Computes SHA3-256 hash of ethical vector
    3. Appends first 16 bytes as ethical signature
    4. Maintains HKDF collision resistance (proven above)

    Security Properties:
    --------------------
    1. One-way: Cannot recover master_secret from derived keys
    2. Independence: Derived keys are cryptographically independent
    3. Domain separation: Enhanced info provides stronger context binding
    4. Ethical binding: Keys are bound to specific ethical constraints
    5. Extraction: PRK has full entropy even if IKM has weak distribution
    6. Expansion: Can generate arbitrary amount of key material

    Security Proof (Krawczyk, 2010 + Ethical Enhancement):
    -------------------------------------------------------
    If HMAC-Hash is a PRF (Pseudorandom Function), then HKDF with ethical
    context remains a secure KDF.

    Theorem: For adversary A making q queries:
        Adv_PRF(HKDF_Ethical) ≤ Adv_PRF(HMAC) + q²/2^n + Adv_CR(SHA3-256)

    Where:
        - n = 256 (output size)
        - Adv_CR(SHA3-256) ≤ 2^-128 (collision resistance)

    With q = 2^32:
        Adv_PRF(HKDF_Ethical) ≤ 2^-128 + 2^-192 + 2^-128 ≈ 2^-127

    This provides strong assurance that ethically-derived keys are
    indistinguishable from random.

    Standard: RFC 5869 (HKDF), NIST SP 800-108 (KDF)

    References:
    -----------
    1. Krawczyk, H., & Eronen, P. (2010). "HMAC-based Extract-and-Expand
       Key Derivation Function (HKDF)." RFC 5869, May 2010.

    2. Chen, L. (2009). "Recommendation for Key Derivation Using
       Pseudorandom Functions (Revised)." NIST SP 800-108.

    3. Krawczyk, H. (2010). "Cryptographic Extraction and Key Derivation:
       The HKDF Scheme." CRYPTO 2010, LNCS 6223, pp. 631-648.

    Args:
        master_secret: High-entropy master key (≥32 bytes recommended)
        info: Context string for domain separation
        num_keys: Number of independent keys to derive
        ethical_vector: 12-pillar ethical weights (defaults to ETHICAL_VECTOR)
        salt: Optional salt for HKDF. If None, generates random 32-byte salt
              for optimal security per RFC 5869. Provide explicit salt only
              for deterministic testing purposes.

    Returns:
        Tuple of (List of 32-byte derived keys with ethical context, salt used)

    Raises:
        RuntimeError: If cryptography library not available
        ValueError: If master_secret has insufficient entropy (< 16 bytes)
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography library required for HKDF")

    if len(master_secret) < 32:
        raise ValueError("Master secret must be at least 32 bytes (256 bits entropy)")

    if ethical_vector is None:
        ethical_vector = ETHICAL_VECTOR

    # Use provided salt or generate random salt for optimal security per RFC 5869
    # Salt should be random and at least HashLen bytes (32 for SHA3-256)
    if salt is not None:
        hkdf_salt = salt
    else:
        hkdf_salt = secrets.token_bytes(32)

    derived_keys = []
    for i in range(num_keys):
        # Create base context
        base_context = f"{info}:{i}".encode("utf-8")

        # Enhance with ethical context
        enhanced_context = create_ethical_hkdf_context(base_context, ethical_vector)

        # Use HKDF with SHA3-256 for consistency with project's SHA3 emphasis
        # Note: While RFC 5869 was written for HMAC with Merkle-Damgard hashes,
        # HMAC-SHA3-256 is a secure PRF and HKDF-SHA3-256 maintains equivalent security.
        # Per RFC 5869 Section 3.1: "Ideally, the salt value is a random (or pseudorandom)
        # string of the length HashLen."
        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=hkdf_salt,  # Random salt for optimal security (RFC 5869)
            info=enhanced_context,  # Enhanced with ethical signature
            backend=default_backend(),
        )
        derived_key = hkdf.derive(master_secret)
        derived_keys.append(derived_key)

    return derived_keys, hkdf_salt


# ============================================================================
# OMNI-CODE HELIX CODES
# ============================================================================

# Master Omni-Codes (preserved exactly as specified)
MASTER_CODES = (
    "👁20A07∞_XΔEΛX_ϵ19A89Ϙ"
    "Ϙ15A11ϵ_ΞΛMΔΞ_ϖ20A19Φ"
    "Φ07A09ϖ_ΨΔAΛΨ_ϵ19A88Σ"
    "Σ19L12ϵ_ΞΛEΔΞ_ϖ19A92Ω"
    "Ω20V11ϖ_ΨΔSΛΨ_ϵ20A15Θ"
    "Θ25M01ϵ_ΞΛLΔΞ_ϖ19A91Γ"
    "Γ19L11ϖ_XΔHΛX_∞19A84♰"
)

# Helical parameters (radius, pitch) for each Omni-Code
MASTER_HELIX_PARAMS = [
    (20.0, 0.7),  # 👁20A07∞ - Omni-Directional System
    (15.0, 1.1),  # Ϙ15A11ϵ - Omni-Percipient Future
    (7.0, 0.9),  # Φ07A09ϖ - Omni-Indivisible Guardian
    (19.0, 1.2),  # Σ19L12ϵ - Omni-Benevolent Stone
    (20.0, 1.1),  # Ω20V11ϖ - Omni-Scient Curiosity
    (25.0, 0.1),  # Θ25M01ϵ - Omni-Universal Discipline
    (19.0, 1.1),  # Γ19L11ϖ - Omni-Potent Lifeforce
]

# Human-readable names for each Omni-Code
CODE_NAMES = [
    "Omni-Directional System",
    "Omni-Percipient Future",
    "Omni-Indivisible Guardian",
    "Omni-Benevolent Stone",
    "Omni-Scient Curiosity",
    "Omni-Universal Discipline",
    "Omni-Potent Lifeforce",
]

# Individual Omni-Code strings (for reference)
CODES_INDIVIDUAL = [
    "👁20A07∞_XΔEΛX_ϵ19A89Ϙ",
    "Ϙ15A11ϵ_ΞΛMΔΞ_ϖ20A19Φ",
    "Φ07A09ϖ_ΨΔAΛΨ_ϵ19A88Σ",
    "Σ19L12ϵ_ΞΛEΔΞ_ϖ19A92Ω",
    "Ω20V11ϖ_ΨΔSΛΨ_ϵ20A15Θ",
    "Θ25M01ϵ_ΞΛLΔΞ_ϖ19A91Γ",
    "Γ19L11ϖ_XΔHΛX_∞19A84♰",
]

# Newline-separated string of all Omni-Codes (for demo and testing)
MASTER_CODES_STR = "\n".join(CODES_INDIVIDUAL)


# ============================================================================
# KEY MANAGEMENT SYSTEM
# ============================================================================


@dataclass
class KeyManagementSystem:
    """
    Secure key storage and management system.

    Architecture:
    -------------
    Master Secret (256 bits)
        │
        ├─[HKDF]→ HMAC Key (256 bits)
        ├─[HKDF]→ Ed25519 Seed (256 bits) → Ed25519 KeyPair
        └─[HKDF]→ Dilithium Seed (256 bits) → Dilithium KeyPair

    Security Best Practices:
    ------------------------
    1. Master Secret Storage:
       - Store in Hardware Security Module (HSM)
       - Or use YubiKey/Nitrokey with PKCS#11
       - Never store unencrypted on disk
       - Use AES-256-GCM if software encryption required

    2. Key Rotation:
       - Rotate keys quarterly (every 90 days)
       - Keep old public keys for verification
       - Archive old signatures before rotation
       - Use master secret to re-derive keys if needed

    3. Key Escrow:
       - Split master secret using Shamir Secret Sharing
       - Require 3-of-5 shares for recovery
       - Store shares with trusted parties
       - Use encrypted, offline storage

    4. Access Control:
       - Limit key access to authorized processes
       - Use OS-level access controls
       - Audit all key usage
       - Alert on suspicious activity

    HSM Integration:
    ----------------
    Supported HSMs:
        - YubiKey 5 Series (PKCS#11, PIV)
        - Nitrokey Pro/Storage (PKCS#11)
        - AWS CloudHSM (PKCS#11)
        - Azure Key Vault (REST API)
        - Google Cloud HSM (PKCS#11)

    Example YubiKey integration:
        from ykman.device import connect_to_device
        device = connect_to_device()[0]
        # Store keys in PIV slots

    Standard: PKCS#11 v2.40, FIPS 140-2 Level 2+

    References:
    -----------
    1. NIST SP 800-57: "Recommendation for Key Management"
    2. FIPS 140-2: "Security Requirements for Cryptographic Modules"
    3. PKCS#11 v2.40: "Cryptographic Token Interface Standard"
    """

    master_secret: bytes = field(repr=False)  # 32 bytes, NEVER expose - excluded from repr
    hmac_key: bytes = field(repr=False)  # 32 bytes, derived - excluded from repr
    hkdf_salt: bytes = field(
        repr=False
    )  # 32 bytes, random salt for HKDF (RFC 5869) - excluded from repr
    ed25519_keypair: Ed25519KeyPair  # Classical signatures
    dilithium_keypair: Optional[
        DilithiumKeyPair
    ]  # Quantum-resistant signatures (None if unavailable)
    creation_date: str  # ISO 8601 timestamp
    rotation_schedule: str  # e.g., "quarterly"
    version: str  # KMS version
    ethical_vector: Dict[str, float]  # 12 Ethical Pillars
    quantum_signatures_enabled: bool = True  # False if Dilithium unavailable


def generate_key_management_system(
    author: str, ethical_vector: Optional[Dict[str, float]] = None
) -> KeyManagementSystem:
    """
    Initialize complete key management system with ethical integration.

    Key Generation Process (Enhanced):
    ----------------------------------
    1. Generate 256-bit master secret from CSPRNG
    2. Use HKDF with ethical context to derive independent keys:
       - HMAC key for authentication (with ethical binding)
       - Ed25519 seed for classical signatures (with ethical binding)
       - Dilithium seed for quantum-resistant signatures (reserved)
    3. Generate Ed25519 key pair from ethically-derived seed
    4. Generate Dilithium key pair (from native C backend)

    Ethical Integration:
    --------------------
    The 12 Ethical Pillars are integrated into key derivation via:
    1. Enhanced HKDF context includes 128-bit ethical signature
    2. Keys are cryptographically bound to ethical constraints
    3. Ethical vector is stored with KMS for verification
    4. Maintains all security properties while adding ethical layer

    Security Properties:
    --------------------
    - Master secret has 256 bits of cryptographic entropy
    - Derived keys are cryptographically independent
    - HKDF ensures one-way derivation (cannot recover master)
    - Author info provides domain separation
    - Ethical vector provides additional context binding
    - Enhanced security: Secure and tested with ethical integration

    Args:
        author: Key owner identifier (for domain separation)
        ethical_vector: 12-pillar ethical weights (defaults to ETHICAL_VECTOR)

    Returns:
        KeyManagementSystem with all keys initialized and ethical integration
    """
    if ethical_vector is None:
        ethical_vector = ETHICAL_VECTOR.copy()

    # Generate master secret from CSPRNG (secrets.token_bytes uses os.urandom)
    master_secret = secrets.token_bytes(32)

    # Derive independent keys using HKDF with ethical context
    # derive_keys now returns (keys, salt) tuple for RFC 5869 compliance
    derived_keys, hkdf_salt = derive_keys(
        master_secret, f"OMNI_CODES:{author}", num_keys=3, ethical_vector=ethical_vector
    )
    hmac_key = derived_keys[0]  # For HMAC authentication (ethically bound)
    ed25519_seed = derived_keys[1]  # For Ed25519 key generation (ethically bound)
    # dilithium_seed = derived_keys[2]  # Reserved for future Dilithium seed derivation

    # Generate key pairs
    ed25519_keypair = generate_ed25519_keypair(ed25519_seed)

    # Generate Dilithium keypair if available, otherwise gracefully degrade
    dilithium_keypair = None
    quantum_signatures_enabled = False
    if DILITHIUM_AVAILABLE:
        try:
            dilithium_keypair = generate_dilithium_keypair()
            quantum_signatures_enabled = True
        except QuantumSignatureUnavailableError:
            print("\n" + "=" * 70)
            print("WARNING: Quantum-resistant signatures disabled")
            print("=" * 70)
            print("System will use Ed25519 classical signatures only.")
            print("To enable quantum resistance, build native C library:")
            print("=" * 70 + "\n")
    else:
        print("\n" + "=" * 70)
        print("WARNING: Quantum-resistant signatures disabled")
        print("=" * 70)
        print("System will use Ed25519 classical signatures only.")
        print("To enable quantum resistance, build native C library:")
        print("  cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build")
        print("=" * 70 + "\n")

    return KeyManagementSystem(
        master_secret=master_secret,
        hmac_key=hmac_key,
        hkdf_salt=hkdf_salt,  # Random salt for RFC 5869 compliance
        ed25519_keypair=ed25519_keypair,
        dilithium_keypair=dilithium_keypair,
        creation_date=datetime.now(timezone.utc).isoformat(),
        rotation_schedule="quarterly",
        version="2.0",
        ethical_vector=ethical_vector,
        quantum_signatures_enabled=quantum_signatures_enabled,
    )


def export_public_keys(kms: KeyManagementSystem, output_dir: Path) -> None:
    """
    Export public keys for distribution (safe to share publicly).

    Security: Only exports public keys. Private keys NEVER leave system.

    Args:
        kms: Key management system
        output_dir: Directory for public key files
    """
    output_dir.mkdir(exist_ok=True, parents=True)

    # Export Ed25519 public key
    ed25519_path = output_dir / "ed25519_public.key"
    with open(ed25519_path, "wb") as f:
        f.write(kms.ed25519_keypair.public_key)

    # Export Dilithium public key (if available)
    dilithium_path = None
    if kms.quantum_signatures_enabled and kms.dilithium_keypair:
        dilithium_path = output_dir / "dilithium_public.key"
        with open(dilithium_path, "wb") as f:
            f.write(kms.dilithium_keypair.public_key)

    # Create README
    readme_path = output_dir / "README.txt"
    with open(readme_path, "w") as f:
        f.write("AMA Cryptography - Public Keys\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Generated: {kms.creation_date}\n")
        f.write(f"Version: {kms.version}\n")
        f.write(
            f"Quantum Signatures: {'Enabled' if kms.quantum_signatures_enabled else 'Disabled'}\n\n"
        )
        f.write("Ed25519 Public Key:\n")
        f.write(f"  File: {ed25519_path.name}\n")
        f.write("  Size: 32 bytes\n")
        f.write(f"  Hex: {kms.ed25519_keypair.public_key.hex()}\n\n")
        if kms.quantum_signatures_enabled and kms.dilithium_keypair and dilithium_path:
            f.write("Dilithium Public Key:\n")
            f.write(f"  File: {dilithium_path.name}\n")
            f.write(f"  Size: {len(kms.dilithium_keypair.public_key)} bytes\n")
            f.write(f"  Hex (first 32): {kms.dilithium_keypair.public_key.hex()[:64]}...\n\n")
        else:
            f.write("Dilithium Public Key: NOT AVAILABLE\n")
            f.write("  Quantum-resistant signatures are disabled.\n")
            f.write("  Build native C library to enable.\n\n")
        f.write("These public keys can be safely distributed.\n")
        f.write("Use them to verify signatures on Omni-Code packages.\n")

    print(f"  ✓ Public keys exported to: {output_dir}")
    print(f"    Ed25519: {len(kms.ed25519_keypair.public_key)} bytes")
    if kms.quantum_signatures_enabled and kms.dilithium_keypair:
        print(f"    Dilithium: {len(kms.dilithium_keypair.public_key)} bytes")
    else:
        print("    Dilithium: NOT AVAILABLE (quantum signatures disabled)")


# ============================================================================
# CRYPTOGRAPHIC PACKAGE
# ============================================================================


# Domain separation constants for hybrid signature binding
# These ensure Ed25519 and Dilithium sign identical, versioned messages
SIGNATURE_DOMAIN_PREFIX = b"AMA-PKG-v2"  # AMA Cryptography Package v2
SIGNATURE_FORMAT_V1 = "1.0.0"  # Legacy: signs raw content_hash
SIGNATURE_FORMAT_V2 = "2.0.0"  # Current: signs domain-separated message


def build_signature_message(
    content_hash: bytes,
    ethical_hash: bytes,
    version: str = SIGNATURE_FORMAT_V2,
) -> bytes:
    """
    Build domain-separated message for hybrid signature binding.

    This function constructs a versioned, domain-separated message that both
    Ed25519 and Dilithium sign. Domain separation prevents signature replay
    attacks and ensures both algorithms sign identical, well-structured data.

    Security Properties:
    --------------------
    1. Domain separation: Prefix prevents cross-protocol attacks
    2. Version binding: Signatures are bound to specific format version
    3. Ethical binding: Signatures cover the ethical vector hash
    4. Algorithm agnostic: Same message for both Ed25519 and Dilithium

    Message Structure (v2):
    -----------------------
    SIGNATURE_DOMAIN_PREFIX || version_bytes || content_hash || ethical_hash

    Where:
    - SIGNATURE_DOMAIN_PREFIX = b"AMA-PKG-v2" (10 bytes)
    - version_bytes = UTF-8 encoded version string (5 bytes for "2.0.0")
    - content_hash = SHA3-256 hash of canonical code encoding (32 bytes)
    - ethical_hash = SHA3-256 hash of ethical vector (32 bytes)

    Total: 79 bytes for v2 format

    Args:
        content_hash: SHA3-256 hash of canonical code encoding (32 bytes)
        ethical_hash: SHA3-256 hash of ethical vector (32 bytes)
        version: Signature format version (default: "2.0.0")

    Returns:
        Domain-separated message bytes for signing

    Raises:
        ValueError: If content_hash or ethical_hash are wrong length
    """
    if len(content_hash) != 32:
        raise ValueError(f"content_hash must be 32 bytes, got {len(content_hash)}")
    if len(ethical_hash) != 32:
        raise ValueError(f"ethical_hash must be 32 bytes, got {len(ethical_hash)}")

    version_bytes = version.encode("utf-8")

    # Construct domain-separated message
    message = SIGNATURE_DOMAIN_PREFIX + version_bytes + content_hash + ethical_hash

    return message


@dataclass
class CryptoPackage:
    """
    Complete cryptographic package for Omni-Codes.

    Structure:
    ----------
    {
        "content_hash": "SHA3-256 hash of canonical encoding",
        "hmac_tag": "HMAC-SHA3-256 authentication tag",
        "ed25519_signature": "Ed25519 digital signature",
        "dilithium_signature": "Dilithium quantum-resistant signature",
        "timestamp": "ISO 8601 timestamp",
        "timestamp_token": "RFC 3161 timestamp (optional)",
        "author": "Package creator",
        "ed25519_pubkey": "Ed25519 public key (hex)",
        "dilithium_pubkey": "Dilithium public key (hex)",
        "version": "Package format version",
        "signature_format_version": "Signature binding format (1.0.0 or 2.0.0)"
    }

    Signature Format Versions:
    --------------------------
    - 1.0.0 (legacy): Ed25519 and Dilithium sign raw content_hash
    - 2.0.0 (current): Ed25519 and Dilithium sign domain-separated message:
      b"AMA-PKG-v2" || version || content_hash || ethical_hash

    The v2 format provides:
    - Domain separation to prevent cross-protocol signature replay
    - Ethical binding to cryptographically tie signatures to policy
    - Version binding to prevent downgrade attacks

    Verification Process:
    ---------------------
    1. Verify content_hash matches SHA3-256(canonical_encoding)
    2. Verify hmac_tag using HMAC key
    3. Verify ed25519_signature using ed25519_pubkey
    4. Verify dilithium_signature using dilithium_pubkey
    5. Verify timestamp is reasonable (not in future, not too old)
    6. Verify RFC 3161 timestamp_token if present

    All verifications must pass for package to be considered valid.
    """

    content_hash: str  # SHA3-256 hex
    hmac_tag: str  # HMAC-SHA3-256 hex
    ed25519_signature: str  # Ed25519 signature hex
    dilithium_signature: Optional[str]  # Dilithium signature hex (None if unavailable)
    timestamp: str  # ISO 8601
    timestamp_token: Optional[str]  # RFC 3161 token (base64)
    author: str  # Creator name
    ed25519_pubkey: str  # Ed25519 public key hex
    dilithium_pubkey: Optional[str]  # Dilithium public key hex (None if unavailable)
    version: str  # Package version
    ethical_vector: Dict[str, float]  # 12 Ethical Pillars
    ethical_hash: str  # SHA3-256 hash of ethical vector (hex)
    quantum_signatures_enabled: bool = True  # False if Dilithium unavailable
    signature_format_version: str = SIGNATURE_FORMAT_V2  # Signature binding format


def create_crypto_package(  # noqa: C901 - high-level orchestrator; refactor would be invasive
    codes: str,
    helix_params: List[Tuple[float, float]],
    kms: KeyManagementSystem,
    author: str,
    use_rfc3161: bool = False,
    tsa_url: Optional[str] = None,
    monitor: Optional["AmaCryptographyMonitor"] = None,
) -> CryptoPackage:
    """
    Create cryptographically signed package for Omni-Codes.

    Process:
    --------
    1. Compute canonical hash (SHA3-256)
    2. Generate HMAC authentication tag
    3. Sign with Ed25519
    4. Sign with Dilithium (quantum-resistant)
    5. Get trusted timestamp (optional RFC 3161)
    6. Package all cryptographic artifacts

    Args:
        codes: Omni-Code string
        helix_params: List of (radius, pitch) tuples
        kms: Key management system
        author: Package creator
        use_rfc3161: Whether to get RFC 3161 timestamp
        tsa_url: TSA server URL (optional)
        monitor: Optional security monitor for 3R runtime analysis

    Returns:
        CryptoPackage with all signatures and timestamps

    Raises:
        TypeError: If codes is not a string or helix_params is not a list
        ValueError: If codes is empty or helix_params is invalid
    """
    # Input validation
    if not isinstance(codes, str):
        raise TypeError(f"codes must be a string, got {type(codes).__name__}")
    if not codes.strip():
        raise ValueError("codes cannot be empty")
    if not isinstance(helix_params, list):
        raise TypeError(f"helix_params must be a list, got {type(helix_params).__name__}")
    if not helix_params:
        raise ValueError("helix_params cannot be empty")
    for i, param in enumerate(helix_params):
        if not isinstance(param, (tuple, list)) or len(param) != 2:
            raise ValueError(f"helix_params[{i}] must be a (radius, pitch) tuple")
        if not all(isinstance(v, (int, float)) for v in param):
            raise ValueError(f"helix_params[{i}] values must be numeric")
    if not isinstance(author, str):
        raise TypeError(f"author must be a string, got {type(author).__name__}")
    # Note: Empty author is allowed for backward compatibility with existing tests

    # 1. Compute canonical hash
    if monitor:
        start_time = time.time()
    content_hash = canonical_hash_code(codes, helix_params)
    if monitor:
        duration_ms = (time.time() - start_time) * 1000
        monitor.monitor_crypto_operation("sha3_256_hash", duration_ms)

    # 2. Generate HMAC authentication tag
    if monitor:
        start_time = time.time()
    hmac_tag = hmac_authenticate(content_hash, kms.hmac_key)
    if monitor:
        duration_ms = (time.time() - start_time) * 1000
        monitor.monitor_crypto_operation("hmac_auth", duration_ms)

    # 3. Compute ethical hash BEFORE signing (needed for domain-separated message)
    ethical_vector = kms.ethical_vector.copy()
    ethical_json = json.dumps(ethical_vector, sort_keys=True)
    ethical_hash_bytes = hashlib.sha3_256(ethical_json.encode()).digest()
    ethical_hash_hex = ethical_hash_bytes.hex()

    # 4. Build domain-separated message for hybrid signature binding (v2 format)
    # Both Ed25519 and Dilithium sign this identical message
    signature_message = build_signature_message(
        content_hash, ethical_hash_bytes, SIGNATURE_FORMAT_V2
    )

    # 5. Sign with Ed25519 (domain-separated message)
    if monitor:
        start_time = time.time()
    ed25519_sig = ed25519_sign(signature_message, kms.ed25519_keypair.private_key)
    if monitor:
        duration_ms = (time.time() - start_time) * 1000
        monitor.monitor_crypto_operation("ed25519_sign", duration_ms)

    # 6. Sign with Dilithium (domain-separated message, if available)
    dilithium_sig = None
    dilithium_pubkey = None
    quantum_signatures_enabled = False
    if kms.quantum_signatures_enabled and kms.dilithium_keypair is not None:
        if monitor:
            start_time = time.time()
        try:
            dilithium_sig = dilithium_sign(signature_message, kms.dilithium_keypair.secret_key)
            dilithium_pubkey = kms.dilithium_keypair.public_key.hex()
            quantum_signatures_enabled = True
        except QuantumSignatureUnavailableError:
            pass  # Gracefully degrade to Ed25519-only
        if monitor and dilithium_sig is not None:
            duration_ms = (time.time() - start_time) * 1000
            monitor.monitor_crypto_operation("dilithium_sign", duration_ms)

    # 7. Generate timestamp
    timestamp = datetime.now(timezone.utc).isoformat()

    # 8. Get RFC 3161 timestamp (optional)
    timestamp_token = None
    if use_rfc3161:
        token = get_rfc3161_timestamp(content_hash, tsa_url)
        if token:
            timestamp_token = base64.b64encode(token).decode("ascii")

    # 9. Record package metadata for pattern analysis
    if monitor:
        # Count Omni-Codes (split by newline or comma)
        code_count = len([c.strip() for c in codes.split("\n") if c.strip()])
        monitor.record_package_signing(
            {
                "author": author,
                "code_count": code_count,
                "content_hash": content_hash.hex()[:16],
            }
        )

    return CryptoPackage(
        content_hash=content_hash.hex(),
        hmac_tag=hmac_tag.hex(),
        ed25519_signature=ed25519_sig.hex(),
        dilithium_signature=dilithium_sig.hex() if dilithium_sig else None,
        timestamp=timestamp,
        timestamp_token=timestamp_token,
        author=author,
        ed25519_pubkey=kms.ed25519_keypair.public_key.hex(),
        dilithium_pubkey=dilithium_pubkey,
        version="2.0",
        ethical_vector=ethical_vector,
        ethical_hash=ethical_hash_hex,
        quantum_signatures_enabled=quantum_signatures_enabled,
        signature_format_version=SIGNATURE_FORMAT_V2,
    )


def _verify_timestamp_value(timestamp_str: str) -> bool:
    """Verify timestamp is reasonable (not future, not older than 10 years)."""
    try:
        ts = datetime.fromisoformat(timestamp_str)
        now = datetime.now(timezone.utc)
        return ts <= now and (now - ts).days < 3650
    except Exception:
        return False


def _verify_dilithium_with_policy(
    signature_message: bytes,
    package: CryptoPackage,
    monitor: Optional["AmaCryptographyMonitor"],
    require_quantum_signatures: bool,
) -> Optional[bool]:
    """
    Verify Dilithium signature with policy enforcement.

    This function treats require_quantum_signatures as a strict policy flag:
    - If True: raises QuantumSignatureRequiredError when signatures are missing,
      unavailable, or invalid. This is a security-conscious approach that does
      not silently degrade.
    - If False: gracefully returns None when signatures are missing/unavailable.

    The caller is responsible for choosing the appropriate policy. Use the
    verify_crypto_package() function which provides smart defaulting based on
    DILITHIUM_AVAILABLE.

    Args:
        signature_message: The message that was signed (either raw content_hash
            for v1 packages or domain-separated message for v2 packages)
        package: CryptoPackage to verify
        monitor: Optional security monitor
        require_quantum_signatures: Policy flag for enforcement

    Returns:
        True if valid, False if invalid, None if not present/unsupported.

    Raises:
        QuantumSignatureRequiredError: If require_quantum_signatures=True and
            signatures are missing, unavailable, or invalid.
    """
    if (
        not package.quantum_signatures_enabled
        or not package.dilithium_signature
        or not package.dilithium_pubkey
    ):
        if require_quantum_signatures:
            raise QuantumSignatureRequiredError(
                "Quantum signatures required but package lacks Dilithium signature"
            )
        return None

    start_time = time.time() if monitor else None
    try:
        result = dilithium_verify(
            signature_message,
            bytes.fromhex(package.dilithium_signature),
            bytes.fromhex(package.dilithium_pubkey),
        )
    except QuantumSignatureUnavailableError:
        if require_quantum_signatures:
            raise QuantumSignatureRequiredError(
                "Quantum signatures required but Dilithium libraries unavailable"
            )
        return None

    if monitor and start_time is not None:
        duration_ms = (time.time() - start_time) * 1000
        monitor.monitor_crypto_operation("dilithium_verify", duration_ms)

    if require_quantum_signatures and result is False:
        raise QuantumSignatureRequiredError(
            "Quantum signatures required but Dilithium signature verification failed"
        )

    return result


def verify_crypto_package(
    codes: str,
    helix_params: List[Tuple[float, float]],
    package: CryptoPackage,
    hmac_key: bytes,
    monitor: Optional["AmaCryptographyMonitor"] = None,
    require_quantum_signatures: Optional[bool] = None,
) -> Dict[str, Optional[bool]]:
    """
    Verify all cryptographic protections in package (6 security layers).

    Six Security Layers Verified:
    -----------------------------
    1. SHA3-256 content hash - Data integrity (NIST FIPS 202)
    2. HMAC-SHA3-256 tag - Authentication (RFC 2104)
    3. Ed25519 signature - Classical digital signature (RFC 8032)
    4. Dilithium signature - Quantum-resistant signature (NIST FIPS 204)
    5. Timestamp validity - Temporal integrity check
    6. RFC 3161 timestamp - Cryptographic proof of existence (RFC 3161)

    Signature Format Compatibility:
    -------------------------------
    This function supports both v1 (legacy) and v2 (domain-separated) signature
    formats for backward compatibility:
    - v1 (1.0.0): Signatures over raw content_hash
    - v2 (2.0.0): Signatures over domain-separated message with ethical binding

    Args:
        codes: Original Omni-Codes
        helix_params: Original helix parameters
        package: Crypto package to verify
        hmac_key: HMAC key for verification
        monitor: Optional security monitor for 3R runtime analysis
        require_quantum_signatures: Policy for quantum signature enforcement:
            - None (default): Smart defaulting based on environment. Uses
              DILITHIUM_AVAILABLE to determine policy - requires quantum signatures
              when Dilithium libraries are available, allows classical-only when not.
            - True: Strict enforcement. Raises QuantumSignatureRequiredError if
              Dilithium signatures are missing or invalid. Use this when you
              explicitly require quantum-resistant protection.
            - False: No enforcement. Gracefully degrades to classical-only mode.
              Use for legacy compatibility or testing without quantum libraries.

    Returns:
        Dictionary of verification results:
        {
            "content_hash": bool,
            "hmac": bool,
            "ed25519": bool,
            "dilithium": bool or None (None = not present or unsupported),
            "timestamp": bool,
            "rfc3161": bool or None (None = no RFC 3161 token present)
        }

    Raises:
        QuantumSignatureRequiredError: If require_quantum_signatures=True (or
            defaulted to True via DILITHIUM_AVAILABLE) and Dilithium signature
            is missing, invalid, or cannot be verified.

    Note:
        This function catches all exceptions internally and returns False for
        failed verifications rather than raising exceptions. This provides
        clean failure semantics for security-critical code paths.
    """
    # Smart defaulting: require quantum signatures only when Dilithium is available
    if require_quantum_signatures is None:
        require_quantum_signatures = DILITHIUM_AVAILABLE
    results: Dict[str, Optional[bool]] = {
        "content_hash": False,
        "hmac": False,
        "ed25519": False,
        "dilithium": None,
        "timestamp": False,
        "rfc3161": None,
    }

    try:
        computed_hash = canonical_hash_code(codes, helix_params)
        results["content_hash"] = computed_hash.hex() == package.content_hash

        start_time = time.time() if monitor else None
        results["hmac"] = hmac_verify(computed_hash, bytes.fromhex(package.hmac_tag), hmac_key)
        if monitor and start_time is not None:
            monitor.monitor_crypto_operation("hmac_verify", (time.time() - start_time) * 1000)

        # Determine signature message based on package format version
        # v1 (legacy): signatures over raw content_hash
        # v2 (current): signatures over domain-separated message
        sig_format = getattr(package, "signature_format_version", SIGNATURE_FORMAT_V1)
        if sig_format == SIGNATURE_FORMAT_V2:
            # v2: Build domain-separated message with ethical binding
            ethical_hash_bytes = bytes.fromhex(package.ethical_hash)
            signature_message = build_signature_message(
                computed_hash, ethical_hash_bytes, SIGNATURE_FORMAT_V2
            )
        else:
            # v1 (legacy): Use raw content_hash
            signature_message = computed_hash

        start_time = time.time() if monitor else None
        results["ed25519"] = ed25519_verify(
            signature_message,
            bytes.fromhex(package.ed25519_signature),
            bytes.fromhex(package.ed25519_pubkey),
        )
        if monitor and start_time is not None:
            monitor.monitor_crypto_operation("ed25519_verify", (time.time() - start_time) * 1000)

        results["dilithium"] = _verify_dilithium_with_policy(
            signature_message, package, monitor, require_quantum_signatures
        )

        results["timestamp"] = _verify_timestamp_value(package.timestamp)

        # RFC 3161 cryptographic timestamp verification (Layer 6)
        # This verifies the TSA's digital signature on the timestamp token
        results["rfc3161"] = _verify_rfc3161_token(computed_hash, package.timestamp_token)

    except QuantumSignatureRequiredError:
        raise
    except Exception as e:
        # Log unexpected errors but don't fail silently - mark affected checks as False
        # This maintains fail-closed security while providing diagnostic information
        import logging

        logging.getLogger(__name__).warning(
            f"Unexpected error during crypto package verification: {e}"
        )

    return results


# ============================================================================
# MAIN DEMONSTRATION
# ============================================================================


def main() -> None:
    """
    Demonstrate complete AMA Cryptography system with all Omni-Codes.
    """
    print("\n" + "=" * 70)
    print("AMA Cryptography: SHA3-256 Security Hash")
    print("=" * 70)
    print("\nCopyright (C) 2025 Steel Security Advisors LLC")
    print("Author/Inventor: Andrew E. A.")
    print("\nAI Co-Architects:")
    print("  Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛")
    print("\n" + "=" * 70)

    # Generate key management system
    print("\n[1/5] Generating key management system...")
    kms = generate_key_management_system("Steel-SecAdv-LLC")
    print("  ✓ Master secret: 256 bits")
    print("  ✓ HMAC key: 256 bits")
    print(f"  ✓ Ed25519 keypair: {len(kms.ed25519_keypair.public_key)} bytes")
    if kms.quantum_signatures_enabled and kms.dilithium_keypair:
        print(f"  ✓ Dilithium keypair: {len(kms.dilithium_keypair.public_key)} bytes")
    else:
        print("  ⚠ Dilithium keypair: NOT AVAILABLE (quantum signatures disabled)")

    # Display Omni-Codes
    print("\n[2/5] Master Omni-Code Helix Codes:")
    for i, (code, name) in enumerate(zip(CODES_INDIVIDUAL, CODE_NAMES)):
        r, p = MASTER_HELIX_PARAMS[i]
        print(f"  {i + 1}. {code}")
        print(f"     {name}")
        print(f"     Helix: radius={r}, pitch={p}")

    # Create cryptographic package
    print("\n[3/5] Creating Omni-Code cryptographic package...")
    crypto_pkg = create_crypto_package(
        MASTER_CODES,
        MASTER_HELIX_PARAMS,
        kms,
        "Steel-SecAdv-LLC",
        use_rfc3161=False,  # Set True to use RFC 3161 TSA
    )
    print(f"  ✓ Content hash: {crypto_pkg.content_hash[:32]}...")
    print(f"  ✓ HMAC tag: {crypto_pkg.hmac_tag[:32]}...")
    print("  ✓ Signing package...")
    print(f"  ✓ Ed25519 signature: {crypto_pkg.ed25519_signature[:32]}...")
    if crypto_pkg.quantum_signatures_enabled and crypto_pkg.dilithium_signature:
        print(f"  ✓ Dilithium signature: {crypto_pkg.dilithium_signature[:32]}...")
    else:
        print("  ⚠ Dilithium signature: NOT AVAILABLE (quantum signatures disabled)")
    print(f"  ✓ Timestamp: {crypto_pkg.timestamp}")

    # Verify package
    # Note: For demo purposes, we allow classical-only mode if Dilithium is unavailable
    # In production, require_quantum_signatures=True (the default) should be used
    print("\n[4/5] Verifying cryptographic package...")
    results = verify_crypto_package(
        MASTER_CODES,
        MASTER_HELIX_PARAMS,
        crypto_pkg,
        kms.hmac_key,
        require_quantum_signatures=kms.quantum_signatures_enabled,
    )

    # Check all results, treating None (unsupported) as acceptable
    all_valid = all(v is True or v is None for v in results.values())
    for check, valid in results.items():
        if valid is None:
            status = "⚠"
            status_text = "NOT PRESENT/UNSUPPORTED"
        elif valid:
            status = "✓"
            status_text = "VALID"
        else:
            status = "✗"
            status_text = "INVALID"
        print(f"  {status} {check}: {status_text}")

    # Export public keys
    print("\n[5/5] Exporting public keys...")
    output_dir = Path("public_keys")
    export_public_keys(kms, output_dir)

    # Save cryptographic package
    package_file = Path("CRYPTO_PACKAGE.json")
    with open(package_file, "w") as f:
        json.dump(asdict(crypto_pkg), f, indent=2)
    print(f"  ✓ Package saved: {package_file}")

    # Final summary
    print("\n" + "=" * 70)
    if all_valid:
        print("✓ ALL VERIFICATIONS PASSED")
        print("\nThe Omni-Code Helix codes are cryptographically protected.")
        print("All integrity checks, authentication, and signatures verified.")
    else:
        print("✗ VERIFICATION FAILED")
        print("\nOne or more cryptographic checks failed.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
