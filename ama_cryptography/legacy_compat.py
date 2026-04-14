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
AMA Cryptography Legacy Compatibility Module
=============================================

This module contains functions and dataclasses ported from the former
``code_guardian_secure.py`` module.  They are kept separate from the new
clean API in ``crypto_api.py`` to avoid namespace collisions (notably
the legacy ``create_crypto_package`` / ``CryptoPackage`` vs. the new
``create_crypto_package`` / ``CryptoPackageResult``).

Import from this module explicitly::

    from ama_cryptography.legacy_compat import (
        derive_keys,
        generate_key_management_system,
        create_crypto_package,
        CryptoPackage,
    )

Do **not** rely on ``ama_cryptography`` top-level re-exports for these
symbols — they are intentionally excluded to prevent name collisions.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Version: 2.1.2
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import struct
import subprocess  # nosec B404 — subprocess used only with fixed OpenSSL commands for RFC 3161 (LC-001)
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, Union, cast

if TYPE_CHECKING:
    from ama_cryptography_monitor import AmaCryptographyMonitor

_logger = logging.getLogger(__name__)


# os.fdopen guard: when os.open() returns an fd and os.fdopen() is called
# immediately after, an exception inside os.fdopen() (before the with-block
# takes over) would leak the raw fd.  Guard with try/except BaseException and
# close the fd explicitly on failure — matching the pattern in crypto_api.py.


# ---------------------------------------------------------------------------
# Re-imports from ama_cryptography sub-modules so that monkeypatch targets
# (e.g. ``monkeypatch.setattr(dgs, "DILITHIUM_AVAILABLE", False)``) land
# in *this* module's namespace.
# ---------------------------------------------------------------------------
from ama_cryptography.pqc_backends import (
    _ED25519_NATIVE_AVAILABLE,
    _HKDF_NATIVE_AVAILABLE,
    hmac_sha3_256,
    native_ed25519_keypair,
    native_ed25519_keypair_from_seed,
    native_ed25519_sign,
    native_ed25519_verify,
    native_hkdf,
)
from ama_cryptography.secure_memory import constant_time_compare

# ---------------------------------------------------------------------------
# CRYPTO_AVAILABLE guard — must fail-closed at import time if the native
# C library is missing.  Tests that need CRYPTO_AVAILABLE=False monkeypatch
# it *after* import succeeds.
# ---------------------------------------------------------------------------
CRYPTO_AVAILABLE: bool = _ED25519_NATIVE_AVAILABLE and _HKDF_NATIVE_AVAILABLE
if not CRYPTO_AVAILABLE:
    raise RuntimeError(
        "AMA native C library required. "
        "Build with: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
    )

# Import centralized exception classes
# Re-import constants from equations for convenience
from ama_cryptography.equations import (
    CODE_NAMES,
    CODES_INDIVIDUAL,
    ETHICAL_VECTOR,
    MASTER_CODES,
    MASTER_CODES_STR,
    MASTER_HELIX_PARAMS,
)
from ama_cryptography.exceptions import (
    QuantumSignatureRequiredError,
    QuantumSignatureUnavailableError,
)

# Quantum-resistant cryptography — Dilithium wrappers
from ama_cryptography.pqc_backends import DILITHIUM_AVAILABLE as _PQC_DILITHIUM_AVAILABLE
from ama_cryptography.pqc_backends import DilithiumKeyPair
from ama_cryptography.pqc_backends import dilithium_sign as _pqc_dilithium_sign
from ama_cryptography.pqc_backends import dilithium_verify as _pqc_dilithium_verify
from ama_cryptography.pqc_backends import (
    generate_dilithium_keypair as _pqc_generate_dilithium_keypair,
)

# Module-level variable for backward compatibility with tests
DILITHIUM_AVAILABLE: bool = _PQC_DILITHIUM_AVAILABLE
DILITHIUM_BACKEND: str = "native" if _PQC_DILITHIUM_AVAILABLE else "none"


# ============================================================================
# DILITHIUM WRAPPER FUNCTIONS (for test compatibility)
# ============================================================================


def generate_dilithium_keypair() -> DilithiumKeyPair:
    """Generate a CRYSTALS-Dilithium (ML-DSA-65) keypair.

    This wrapper function checks module-level DILITHIUM_AVAILABLE,
    allowing tests to monkeypatch it.
    """
    import sys

    this_module = sys.modules[__name__]
    available = getattr(this_module, "DILITHIUM_AVAILABLE", _PQC_DILITHIUM_AVAILABLE)

    if not available:
        raise QuantumSignatureUnavailableError(
            "PQC_UNAVAILABLE: Dilithium backend not available. "
            "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )

    return _pqc_generate_dilithium_keypair()


def dilithium_sign(message: bytes, secret_key: Union[bytes, bytearray]) -> bytes:
    """Sign message with CRYSTALS-Dilithium (ML-DSA-65)."""
    import sys

    this_module = sys.modules[__name__]
    available = getattr(this_module, "DILITHIUM_AVAILABLE", _PQC_DILITHIUM_AVAILABLE)

    if not available:
        raise QuantumSignatureUnavailableError(
            "PQC_UNAVAILABLE: Dilithium backend not available. "
            "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )

    return _pqc_dilithium_sign(message, secret_key)


def dilithium_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify CRYSTALS-Dilithium signature."""
    import sys

    this_module = sys.modules[__name__]
    available = getattr(this_module, "DILITHIUM_AVAILABLE", _PQC_DILITHIUM_AVAILABLE)

    if not available:
        raise QuantumSignatureUnavailableError(
            "PQC_UNAVAILABLE: Dilithium backend not available. "
            "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )

    return _pqc_dilithium_verify(message, signature, public_key)


# ============================================================================
# SECURE MEMORY UTILITIES
# ============================================================================


def secure_wipe(data: Union[bytes, bytearray]) -> None:
    """Securely wipe sensitive data from memory.

    NOTE: This is NOT the same as ``secure_memzero``.  ``secure_wipe``
    accepts ``Union[bytes, bytearray]`` and raises ``TypeError`` with a
    specific message for ``bytes``.  ``secure_memzero`` accepts
    ``Union[bytearray, memoryview]``.
    """
    if not isinstance(data, bytearray):
        raise TypeError(
            f"secure_wipe() requires a mutable bytearray, got {type(data).__name__}. "
            "Convert keys to bytearray before use: bytearray(key_bytes)"
        )

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
# HASH FORMAT VERSIONING
# ============================================================================
HASH_FORMAT_V1 = "1"
HASH_FORMAT_V2 = "2"


# ============================================================================
# CANONICAL ENCODING WITH LENGTH-PREFIXING
# ============================================================================


def length_prefixed_encode(*fields: str) -> bytes:
    """Encode fields with length-prefixing for collision-proof domain separation.

    Format: [len1][data1][len2][data2]...[lenN][dataN]
    Length encoding: 4-byte big-endian unsigned integer (supports up to 4GB)
    """
    encoded = b""
    for i, field_value in enumerate(fields):
        field_bytes = field_value.encode("utf-8")

        if len(field_bytes) > 0xFFFFFFFF:
            raise ValueError(f"Field {i} exceeds 4GB limit")

        length = struct.pack(">I", len(field_bytes))
        encoded += length + field_bytes

    return encoded


def canonical_hash_code(
    codes: str,
    helix_params: List[Tuple[float, float]],
    hash_version: str = HASH_FORMAT_V2,
) -> bytes:
    """Compute collision-resistant hash with proper domain separation.

    Hash Function: SHA3-256 (NIST FIPS 202)
    """
    if not isinstance(codes, str):
        raise TypeError(f"codes must be str, got {type(codes).__name__}")
    if not isinstance(helix_params, list):
        raise TypeError(f"helix_params must be list, got {type(helix_params).__name__}")
    if not codes:
        raise ValueError("codes cannot be empty")
    if not helix_params:
        raise ValueError("helix_params cannot be empty")

    for i, param in enumerate(helix_params):
        if not isinstance(param, (tuple, list)) or len(param) != 2:
            raise ValueError(f"helix_params[{i}] must be a (radius, pitch) tuple, got {param!r}")
        radius, pitch = param
        if not isinstance(radius, (int, float)) or not isinstance(pitch, (int, float)):
            raise ValueError(
                f"helix_params[{i}] values must be numeric, got ({type(radius).__name__}, "
                f"{type(pitch).__name__})"
            )

    helix_parts = [f"{r:.10f}:{c:.10f}" for r, c in helix_params]

    if hash_version == HASH_FORMAT_V1:
        encoded = length_prefixed_encode("CODE", codes, "HELIX", *helix_parts)
    else:
        invariant_parts = []
        for r, c in helix_params:
            denom = r * r + c * c
            if denom == 0.0:
                invariant_parts.append("0.0000000000:0.0000000000")
            else:
                invariant_parts.append(f"{r / denom:.10f}:{c / denom:.10f}")

        encoded = length_prefixed_encode(
            "CODE",
            codes,
            "HELIX",
            *helix_parts,
            "HELIX_INVARIANT",
            "|".join(invariant_parts),
        )

    return hashlib.sha3_256(encoded).digest()


# ============================================================================
# HMAC AUTHENTICATION
# ============================================================================


def hmac_authenticate(message: bytes, key: bytes) -> bytes:
    """Generate HMAC-SHA3-256 authentication tag (RFC 2104)."""
    if len(key) < 32:
        raise ValueError("HMAC key must be at least 32 bytes for SHA3-256 security")

    return hmac_sha3_256(key, message)


def hmac_verify(message: bytes, tag: bytes, key: bytes) -> bool:
    """Verify HMAC-SHA3-256 authentication tag (constant-time)."""
    expected = hmac_authenticate(message, key)
    return constant_time_compare(tag, expected)


# ============================================================================
# ED25519 DIGITAL SIGNATURES
# ============================================================================


@dataclass
class Ed25519KeyPair:
    """Ed25519 elliptic curve key pair (RFC 8032).

    Key Sizes:
        - Private key: 64 bytes (seed || public_key)
        - Public key: 32 bytes (compressed point)
        - Signature: 64 bytes (R || s format)
    """

    private_key: bytes = field(
        repr=False
    )  # 64 bytes (seed||pk) — excluded from repr to prevent exposure
    public_key: bytes  # 32 bytes


def generate_ed25519_keypair(seed: Optional[bytes] = None) -> Ed25519KeyPair:
    """Generate Ed25519 key pair using native C backend (RFC 8032, Section 5.1.5)."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError(
            "AMA native C library required for Ed25519 key generation. "
            "Build with: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )
    if seed is not None:
        if len(seed) != 32:
            raise ValueError("Seed must be exactly 32 bytes")
        public_bytes, sk_bytes = native_ed25519_keypair_from_seed(seed)
        return Ed25519KeyPair(private_key=sk_bytes, public_key=public_bytes)
    else:
        public_bytes, sk_bytes = native_ed25519_keypair()
        return Ed25519KeyPair(private_key=sk_bytes, public_key=public_bytes)


def ed25519_sign(message: bytes, private_key: bytes) -> bytes:
    """Sign message with Ed25519 (deterministic) using native C backend."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError(
            "AMA native C library required for Ed25519 signing. "
            "Build with: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )

    if len(private_key) == 64:
        return native_ed25519_sign(message, private_key)
    elif len(private_key) == 32:
        _, sk_bytes = native_ed25519_keypair_from_seed(private_key)
        return native_ed25519_sign(message, sk_bytes)
    else:
        raise ValueError("Ed25519 private key must be 32 bytes (seed) or 64 bytes (expanded)")


def ed25519_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify Ed25519 signature using native C backend (RFC 8032, Section 5.1.7)."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError(
            "AMA native C library required for Ed25519 verification. "
            "Build with: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )
    if len(signature) != 64:
        raise ValueError("Ed25519 signature must be 64 bytes")
    if len(public_key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")

    return native_ed25519_verify(signature, message, public_key)


# ============================================================================
# RFC 3161 TRUSTED TIMESTAMPING
# ============================================================================


def get_rfc3161_timestamp(data: bytes, tsa_url: Optional[str] = None) -> Optional[bytes]:
    """Get RFC 3161 trusted timestamp for data.

    Returns RFC 3161 timestamp token (DER-encoded), or None for invalid URL
    schemes.  Raises RuntimeError on TSA request failure.

    NOTE: This is the LEGACY API returning ``Optional[bytes]``, NOT the same
    as ``rfc3161_timestamp.get_timestamp()`` which returns ``TimestampResult``.
    """
    if tsa_url is None:
        tsa_url = "https://freetsa.org/tsr"

    import urllib.parse

    parsed_url = urllib.parse.urlparse(tsa_url)
    if parsed_url.scheme not in ("http", "https"):
        _logger.warning("Invalid TSA URL scheme '%s', must be http or https", parsed_url.scheme)
        return None

    try:
        cmd_query = ["openssl", "ts", "-query", "-data", "-", "-sha256", "-no_nonce"]

        proc = subprocess.run(
            cmd_query, input=data, capture_output=True, timeout=10
        )  # nosec B603 — args are fixed literals, no user input (LC-002)

        if proc.returncode != 0:
            _logger.warning("OpenSSL ts-query failed: %s", proc.stderr.decode())
            return None

        tsq = proc.stdout

        import urllib.request

        req = urllib.request.Request(
            tsa_url, data=tsq, headers={"Content-Type": "application/timestamp-query"}
        )

        with urllib.request.urlopen(
            req, timeout=10
        ) as response:  # nosec B310 — URL scheme validated above (http/https only) (LC-003)
            tsr = response.read()

        return cast(bytes, tsr)

    except Exception as e:
        _logger.error("RFC 3161 timestamp request failed: %s", e)
        raise RuntimeError(
            f"RFC 3161 timestamp request failed: {e}. "
            "Cannot fall back silently — timestamps are a security layer."
        ) from e


def verify_rfc3161_timestamp(
    data: bytes, timestamp_token: bytes, tsa_cert_path: Optional[str] = None
) -> bool:
    """Verify RFC 3161 timestamp token cryptographically.

    NOTE: This is the LEGACY API taking raw ``bytes``, NOT the same as
    ``rfc3161_timestamp.verify_timestamp()`` which takes ``TimestampResult``.
    """
    import os
    import shutil
    import tempfile

    tmp_dir = tempfile.mkdtemp(prefix="ama_rfc3161_")
    os.chmod(tmp_dir, 0o700)
    try:
        tsr_path = os.path.join(tmp_dir, "timestamp.tsr")
        fd = os.open(tsr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            tsr_f = os.fdopen(fd, "wb")
        except BaseException:
            os.close(fd)
            raise
        with tsr_f:
            tsr_f.write(timestamp_token)

        data_path = os.path.join(tmp_dir, "data.dat")
        fd = os.open(data_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            dat_f = os.fdopen(fd, "wb")
        except BaseException:
            os.close(fd)
            raise
        with dat_f:
            dat_f.write(data)

        cmd_verify = [
            "openssl",
            "ts",
            "-verify",
            "-data",
            data_path,
            "-in",
            tsr_path,
        ]

        if tsa_cert_path:
            cmd_verify.extend(["-CAfile", tsa_cert_path])
        else:
            cmd_verify.append("-no_check_time")

        proc = subprocess.run(
            cmd_verify, capture_output=True, timeout=10
        )  # nosec B603 — args are fixed OpenSSL commands, paths validated by caller (LC-004)

        if proc.returncode == 0:
            return True
        else:
            stderr = proc.stderr.decode() if proc.stderr else ""
            if "Verification: OK" in stderr or "Verification: OK" in proc.stdout.decode():
                return True
            return False

    except Exception as e:
        _logger.error("RFC 3161 timestamp verification error: %s", e)
        raise RuntimeError(
            f"RFC 3161 timestamp verification encountered an error: {e}. "
            "Cannot distinguish 'verification failed' from 'verification never ran'."
        ) from e
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _verify_rfc3161_token(
    content_hash: bytes, timestamp_token_b64: Optional[str]
) -> Optional[bool]:
    """Internal helper to verify RFC 3161 timestamp token."""
    if not timestamp_token_b64:
        return None

    try:
        timestamp_token = base64.b64decode(timestamp_token_b64)
    except Exception as e:
        raise ValueError(f"Failed to decode base64 timestamp token: {e}") from e
    return verify_rfc3161_timestamp(content_hash, timestamp_token)


# ============================================================================
# ETHICAL HKDF CONTEXT
# ============================================================================


def create_ethical_hkdf_context(
    base_context: bytes, ethical_vector: Optional[Dict[str, float]] = None
) -> bytes:
    """Integrate ethical vector into HKDF key derivation context."""
    if ethical_vector is None:
        ethical_vector = ETHICAL_VECTOR

    ethical_json = json.dumps(ethical_vector, sort_keys=True)
    ethical_hash = hashlib.sha3_256(ethical_json.encode()).digest()
    ethical_signature = ethical_hash[:16]
    enhanced_context = base_context + ethical_signature

    return enhanced_context


# ============================================================================
# KEY DERIVATION (HKDF)
# ============================================================================


def derive_keys(
    master_secret: bytes,
    info: str,
    num_keys: int = 3,
    ethical_vector: Optional[Dict[str, float]] = None,
    salt: Optional[bytes] = None,
) -> Tuple[List[bytes], bytes]:
    """Derive multiple independent keys from master secret using HKDF (RFC 5869)."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError(
            "AMA native C library required for HKDF. "
            "Build with: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )

    if len(master_secret) < 32:
        raise ValueError("Master secret must be at least 32 bytes (256 bits entropy)")

    if ethical_vector is None:
        ethical_vector = ETHICAL_VECTOR

    if salt is not None:
        hkdf_salt = salt
    else:
        hkdf_salt = secrets.token_bytes(32)

    derived_keys = []
    for i in range(num_keys):
        base_context = f"{info}:{i}".encode("utf-8")
        enhanced_context = create_ethical_hkdf_context(base_context, ethical_vector)

        derived_key = native_hkdf(
            ikm=master_secret,
            length=32,
            salt=hkdf_salt,
            info=enhanced_context,
        )
        derived_keys.append(derived_key)

    return derived_keys, hkdf_salt


# ============================================================================
# KEY MANAGEMENT SYSTEM
# ============================================================================


@dataclass
class KeyManagementSystem:
    """Secure key storage and management system."""

    master_secret: bytes = field(repr=False)
    hmac_key: bytes = field(repr=False)
    hkdf_salt: bytes = field(repr=False)
    ed25519_keypair: Ed25519KeyPair
    dilithium_keypair: Optional[DilithiumKeyPair]
    creation_date: str
    rotation_schedule: str
    version: str
    ethical_vector: Dict[str, float]
    quantum_signatures_enabled: bool = True


def generate_key_management_system(
    author: str, ethical_vector: Optional[Dict[str, float]] = None
) -> KeyManagementSystem:
    """Initialize complete key management system with ethical integration."""
    if ethical_vector is None:
        ethical_vector = ETHICAL_VECTOR.copy()

    master_secret = secrets.token_bytes(32)

    derived_keys, hkdf_salt = derive_keys(
        master_secret, f"OMNI_CODES:{author}", num_keys=3, ethical_vector=ethical_vector
    )
    hmac_key = derived_keys[0]
    ed25519_seed = derived_keys[1]

    ed25519_keypair = generate_ed25519_keypair(ed25519_seed)

    dilithium_keypair = None
    quantum_signatures_enabled = False
    if DILITHIUM_AVAILABLE:
        try:
            dilithium_keypair = generate_dilithium_keypair()
            quantum_signatures_enabled = True
        except QuantumSignatureUnavailableError:
            _logger.warning(
                "Quantum-resistant signatures disabled. "
                "System will use Ed25519 classical signatures only. "
                "To enable quantum resistance, build native C library."
            )
    else:
        _logger.warning(
            "Quantum-resistant signatures disabled. "
            "System will use Ed25519 classical signatures only. "
            "To enable quantum resistance, build native C library: "
            "cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )

    return KeyManagementSystem(
        master_secret=master_secret,
        hmac_key=hmac_key,
        hkdf_salt=hkdf_salt,
        ed25519_keypair=ed25519_keypair,
        dilithium_keypair=dilithium_keypair,
        creation_date=datetime.now(timezone.utc).isoformat(),
        rotation_schedule="quarterly",
        version="2.1",
        ethical_vector=ethical_vector,
        quantum_signatures_enabled=quantum_signatures_enabled,
    )


def export_public_keys(kms: KeyManagementSystem, output_dir: Path) -> None:
    """Export public keys for distribution (safe to share publicly)."""
    output_dir.mkdir(exist_ok=True, parents=True)

    ed25519_path = output_dir / "ed25519_public.key"
    with open(ed25519_path, "wb") as f:
        f.write(kms.ed25519_keypair.public_key)

    dilithium_path = None
    if kms.quantum_signatures_enabled and kms.dilithium_keypair:
        dilithium_path = output_dir / "dilithium_public.key"
        with open(dilithium_path, "wb") as f:
            f.write(kms.dilithium_keypair.public_key)

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

    _logger.info("Public keys exported to: %s", output_dir)
    _logger.info("Ed25519: %d bytes", len(kms.ed25519_keypair.public_key))
    if kms.quantum_signatures_enabled and kms.dilithium_keypair:
        _logger.info("Dilithium: %d bytes", len(kms.dilithium_keypair.public_key))
    else:
        _logger.debug("Dilithium: NOT AVAILABLE (quantum signatures disabled)")


# ============================================================================
# CRYPTOGRAPHIC PACKAGE
# ============================================================================

# Domain separation constants for hybrid signature binding
SIGNATURE_DOMAIN_PREFIX = b"AMA-PKG-v2"
SIGNATURE_FORMAT_V1 = "1.0.0"
SIGNATURE_FORMAT_V2 = "2.0.0"


def build_signature_message(
    content_hash: bytes,
    ethical_hash: bytes,
    version: str = SIGNATURE_FORMAT_V2,
) -> bytes:
    """Build domain-separated message for hybrid signature binding."""
    if len(content_hash) != 32:
        raise ValueError(f"content_hash must be 32 bytes, got {len(content_hash)}")
    if len(ethical_hash) != 32:
        raise ValueError(f"ethical_hash must be 32 bytes, got {len(ethical_hash)}")

    version_bytes = version.encode("utf-8")
    message = SIGNATURE_DOMAIN_PREFIX + version_bytes + content_hash + ethical_hash

    return message


@dataclass
class CryptoPackage:
    """Complete cryptographic package for Omni-Codes (legacy format).

    NOTE: This is the LEGACY ``CryptoPackage`` dataclass.  It is DIFFERENT
    from ``CryptoPackageResult`` in ``crypto_api.py``.
    """

    content_hash: str
    hmac_tag: str
    ed25519_signature: str
    dilithium_signature: Optional[str]
    timestamp: str
    timestamp_token: Optional[str]
    author: str
    ed25519_pubkey: str
    dilithium_pubkey: Optional[str]
    version: str
    ethical_vector: Dict[str, float]
    ethical_hash: str
    quantum_signatures_enabled: bool = True
    signature_format_version: str = SIGNATURE_FORMAT_V2
    hash_format_version: str = HASH_FORMAT_V1


def create_crypto_package(  # noqa: C901 — legacy entry point; complexity is inherent (LC-005)
    codes: str,
    helix_params: List[Tuple[float, float]],
    kms: KeyManagementSystem,
    author: str,
    use_rfc3161: bool = False,
    tsa_url: Optional[str] = None,
    monitor: Optional[AmaCryptographyMonitor] = None,
) -> CryptoPackage:
    """Create cryptographically signed package for Omni-Codes (legacy API).

    .. deprecated::
        Use :func:`ama_cryptography.crypto_api.create_crypto_package` instead.
    """
    import warnings

    warnings.warn(
        "legacy_compat.create_crypto_package is deprecated. "
        "Use ama_cryptography.crypto_api.create_crypto_package instead.",
        DeprecationWarning,
        stacklevel=2,
    )
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

    # 1. Compute canonical hash
    start_time = time.time()
    content_hash = canonical_hash_code(codes, helix_params)
    if monitor:
        duration_ms = (time.time() - start_time) * 1000
        monitor.monitor_crypto_operation("sha3_256_hash", duration_ms)

    # 2. Generate HMAC authentication tag
    start_time = time.time()
    hmac_tag = hmac_authenticate(content_hash, kms.hmac_key)
    if monitor:
        duration_ms = (time.time() - start_time) * 1000
        monitor.monitor_crypto_operation("hmac_auth", duration_ms)

    # 3. Compute ethical hash BEFORE signing
    ethical_vector_copy = kms.ethical_vector.copy()
    ethical_json = json.dumps(ethical_vector_copy, sort_keys=True)
    ethical_hash_bytes = hashlib.sha3_256(ethical_json.encode()).digest()
    ethical_hash_hex = ethical_hash_bytes.hex()

    # 4. Build domain-separated message for hybrid signature binding (v2 format)
    signature_message = build_signature_message(
        content_hash, ethical_hash_bytes, SIGNATURE_FORMAT_V2
    )

    # 5. Sign with Ed25519
    start_time = time.time()
    ed25519_sig = ed25519_sign(signature_message, kms.ed25519_keypair.private_key)
    if monitor:
        duration_ms = (time.time() - start_time) * 1000
        monitor.monitor_crypto_operation("ed25519_sign", duration_ms)

    # 6. Sign with Dilithium (if available)
    dilithium_sig = None
    dilithium_pubkey = None
    quantum_signatures_enabled = False
    if kms.quantum_signatures_enabled and kms.dilithium_keypair is not None:
        start_time = time.time()
        try:
            dilithium_sig = dilithium_sign(signature_message, kms.dilithium_keypair.secret_key)
            dilithium_pubkey = kms.dilithium_keypair.public_key.hex()
            quantum_signatures_enabled = True
        except QuantumSignatureUnavailableError:
            _logger.debug(
                "Dilithium signing unavailable; quantum signature layer omitted. "
                "Package will lack ML-DSA-65 protection. "
                "Verify PQC backend is installed for production deployments."
            )
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
        version="2.1",
        ethical_vector=ethical_vector_copy,
        ethical_hash=ethical_hash_hex,
        quantum_signatures_enabled=quantum_signatures_enabled,
        signature_format_version=SIGNATURE_FORMAT_V2,
        hash_format_version=HASH_FORMAT_V2,
    )


def _verify_timestamp_value(timestamp_str: str) -> bool:
    """Verify timestamp is reasonable (not future, not older than 10 years)."""
    try:
        ts = datetime.fromisoformat(timestamp_str)
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid timestamp format '{timestamp_str}': {e}") from e
    now = datetime.now(timezone.utc)
    return ts <= now and (now - ts).days < 3650


def _verify_dilithium_with_policy(
    signature_message: bytes,
    package: CryptoPackage,
    monitor: Optional[AmaCryptographyMonitor],
    require_quantum_signatures: bool,
) -> Optional[bool]:
    """Verify Dilithium signature with policy enforcement."""
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
    except QuantumSignatureUnavailableError as e:
        if require_quantum_signatures:
            raise QuantumSignatureRequiredError(
                "Quantum signatures required but Dilithium libraries unavailable"
            ) from e
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
    monitor: Optional[AmaCryptographyMonitor] = None,
    require_quantum_signatures: Optional[bool] = None,
) -> Dict[str, Optional[bool]]:
    """Verify all cryptographic protections in package (6 security layers).

    .. deprecated::
        Use :func:`ama_cryptography.crypto_api.verify_crypto_package` instead.
    """
    import warnings

    warnings.warn(
        "legacy_compat.verify_crypto_package is deprecated. "
        "Use ama_cryptography.crypto_api.verify_crypto_package instead.",
        DeprecationWarning,
        stacklevel=2,
    )
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
        pkg_hash_ver = getattr(package, "hash_format_version", HASH_FORMAT_V1)
        computed_hash = canonical_hash_code(codes, helix_params, hash_version=pkg_hash_ver)
        results["content_hash"] = computed_hash.hex() == package.content_hash

        start_time = time.time() if monitor else None
        results["hmac"] = hmac_verify(computed_hash, bytes.fromhex(package.hmac_tag), hmac_key)
        if monitor and start_time is not None:
            monitor.monitor_crypto_operation("hmac_verify", (time.time() - start_time) * 1000)

        sig_format = getattr(package, "signature_format_version", SIGNATURE_FORMAT_V1)
        if sig_format == SIGNATURE_FORMAT_V2:
            ethical_hash_bytes = bytes.fromhex(package.ethical_hash)
            signature_message = build_signature_message(
                computed_hash, ethical_hash_bytes, SIGNATURE_FORMAT_V2
            )
        else:
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

        results["rfc3161"] = _verify_rfc3161_token(computed_hash, package.timestamp_token)

    except QuantumSignatureRequiredError:
        raise
    except Exception as e:
        logging.getLogger(__name__).error(
            f"Unexpected error during crypto package verification: {e}"
        )
        raise

    return results


# ============================================================================
# MAIN DEMONSTRATION
# ============================================================================


def main() -> None:
    """Demonstrate complete AMA Cryptography system with all Omni-Codes."""
    # Ensure UTF-8 stdout on Windows so Unicode symbols render correctly
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        import io

        if isinstance(sys.stdout, io.TextIOWrapper):
            sys.stdout.reconfigure(encoding="utf-8")
    print("\n" + "=" * 70)
    print("AMA Cryptography: SHA3-256 Security Hash")
    print("=" * 70)
    print("\nCopyright (C) 2025-2026 Steel Security Advisors LLC")
    print("Author/Inventor: Andrew E. A.")
    print("\nAI Co-Architects:")
    print("  Eris \u2720 | Eden \u2671 | Devin \u269b\ufe0e | Claude \u229b")
    print("\n" + "=" * 70)

    # Generate key management system
    print("\n[1/5] Generating key management system...")
    kms = generate_key_management_system("Steel-SecAdv-LLC")
    print("  \u2713 Master secret: 256 bits")
    print("  \u2713 HMAC key: 256 bits")
    print(f"  \u2713 Ed25519 keypair: {len(kms.ed25519_keypair.public_key)} bytes")
    if kms.quantum_signatures_enabled and kms.dilithium_keypair:
        print(f"  \u2713 Dilithium keypair: {len(kms.dilithium_keypair.public_key)} bytes")
    else:
        print("  \u26a0 Dilithium keypair: NOT AVAILABLE (quantum signatures disabled)")

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
        use_rfc3161=False,
    )
    print(f"  \u2713 Content hash: {crypto_pkg.content_hash[:32]}...")
    print(f"  \u2713 HMAC tag: {crypto_pkg.hmac_tag[:32]}...")
    print("  \u2713 Signing package...")
    print(f"  \u2713 Ed25519 signature: {crypto_pkg.ed25519_signature[:32]}...")
    if crypto_pkg.quantum_signatures_enabled and crypto_pkg.dilithium_signature:
        print(f"  \u2713 Dilithium signature: {crypto_pkg.dilithium_signature[:32]}...")
    else:
        print("  \u26a0 Dilithium signature: NOT AVAILABLE (quantum signatures disabled)")
    print(f"  \u2713 Timestamp: {crypto_pkg.timestamp}")

    # Verify package
    print("\n[4/5] Verifying cryptographic package...")
    results = verify_crypto_package(
        MASTER_CODES,
        MASTER_HELIX_PARAMS,
        crypto_pkg,
        kms.hmac_key,
        require_quantum_signatures=kms.quantum_signatures_enabled,
    )

    all_valid = all(v is True or v is None for v in results.values())
    for check, valid in results.items():
        if valid is None:
            status = "\u26a0"
            status_text = "NOT PRESENT/UNSUPPORTED"
        elif valid:
            status = "\u2713"
            status_text = "VALID"
        else:
            status = "\u2717"
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
    print(f"  \u2713 Package saved: {package_file}")

    # Final summary
    print("\n" + "=" * 70)
    if all_valid:
        print("\u2713 ALL VERIFICATIONS PASSED")
        print("\nThe Omni-Code Helix codes are cryptographically protected.")
        print("All integrity checks, authentication, and signatures verified.")
    else:
        print("\u2717 VERIFICATION FAILED")
        print("\nOne or more cryptographic checks failed.")
    print("=" * 70 + "\n")


# ============================================================================
# __all__ — public surface area
# ============================================================================
# NOTE: Private functions (_verify_dilithium_with_policy, _verify_rfc3161_token,
# _verify_timestamp_value) are exported solely for test compatibility and are
# candidates for eventual removal.

__all__ = [
    # Constants
    "CRYPTO_AVAILABLE",
    "HASH_FORMAT_V1",
    "HASH_FORMAT_V2",
    "SIGNATURE_DOMAIN_PREFIX",
    "SIGNATURE_FORMAT_V1",
    "SIGNATURE_FORMAT_V2",
    "ETHICAL_VECTOR",
    "MASTER_CODES",
    "CODES_INDIVIDUAL",
    "MASTER_HELIX_PARAMS",
    "MASTER_CODES_STR",
    "CODE_NAMES",
    # Dilithium re-exports
    "DILITHIUM_AVAILABLE",
    "DILITHIUM_BACKEND",
    "DilithiumKeyPair",
    "dilithium_sign",
    "dilithium_verify",
    "generate_dilithium_keypair",
    # Exceptions
    "QuantumSignatureRequiredError",
    "QuantumSignatureUnavailableError",
    # Dataclasses
    "Ed25519KeyPair",
    "KeyManagementSystem",
    "CryptoPackage",
    # Functions
    "canonical_hash_code",
    "length_prefixed_encode",
    "hmac_authenticate",
    "hmac_verify",
    "generate_ed25519_keypair",
    "ed25519_sign",
    "ed25519_verify",
    "derive_keys",
    "create_ethical_hkdf_context",
    "build_signature_message",
    "generate_key_management_system",
    "export_public_keys",
    "secure_wipe",
    "get_rfc3161_timestamp",
    "verify_rfc3161_timestamp",
    "create_crypto_package",
    "verify_crypto_package",
    "main",
    # Private functions exported for test compatibility
    "_verify_dilithium_with_policy",
    "_verify_rfc3161_token",
    "_verify_timestamp_value",
    # Re-exports from secure_memory
    "constant_time_compare",
]
