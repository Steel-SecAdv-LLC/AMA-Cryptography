#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography Key Management System
======================================

Enterprise-grade key management with:

- Hierarchical Deterministic (HD) key derivation (BIP32-style)
- Key rotation with zero-downtime
- Secure key storage and retrieval
- Key versioning and lifecycle management
- Hardware-backed key support (HSM/TPM ready)
"""

import base64
import contextlib
import hashlib
import json
import logging
import os
import secrets
import tempfile
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from pathlib import Path
from types import TracebackType
from typing import Any, Dict, List, Optional, Tuple, Type, cast

from ama_cryptography._finalizer_health import record_finalizer_error
from ama_cryptography.exceptions import (
    AmaHSMUnavailableError as AmaHSMUnavailableError,
)
from ama_cryptography.exceptions import (
    CryptoModuleError,
    NativeBackendUnavailableError,
)
from ama_cryptography.exceptions import (
    KeyManagementError as KeyManagementError,
)
from ama_cryptography.exceptions import (
    SecurityWarning as SecurityWarning,
)
from ama_cryptography.pqc_backends import _HMAC_SHA512_NATIVE_AVAILABLE, native_hmac_sha512
from ama_cryptography.secure_memory import secure_memzero


# INVARIANT-7 (revised): No cryptographic fallbacks, ever.
# When native constant-time backend is unavailable the library MUST refuse to
# operate.  Pure-Python fallback for any cryptographic primitive is prohibited.
#
# Documentation exception: Sphinx autodoc needs to import the module to
# extract docstrings.  Setting AMA_SPHINX_BUILD=1 (or SPHINX_BUILD=1) permits
# the import, but every call-time path still invokes _enforce_invariant7_km(),
# which will raise if the native library is truly absent.  The env-var check
# requires an explicit truthy value so ``AMA_SPHINX_BUILD=0`` / ``=false`` does
# NOT accidentally disable the guard.
def _env_flag_enabled(name: str) -> bool:
    """Return True only for an explicit truthy env value (INVARIANT-7)."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _atomic_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Atomically write ``data`` to ``path`` with restrictive permissions.

    Two properties matter for on-disk key material:

    * **No world-readable window.**  The staging file is created by
      ``tempfile.mkstemp`` (mode ``0o600`` at creation on POSIX) and its
      permissions are set *before* any bytes are written, so a concurrent
      local user can never open the file while it is briefly ``0o644`` — the
      race that the previous ``open()`` + ``os.chmod()`` ordering left open.
    * **Atomicity + durability.**  Contents are flushed and ``fsync``-ed, then
      ``os.replace`` swaps the staging file into place.  A crash leaves either
      the complete old file or the complete new file — never a truncated one.

    The staging file is created in the destination directory so ``os.replace``
    stays within one filesystem (a cross-device rename is not atomic).
    """
    directory = str(path.parent) or "."
    fd, tmp_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=directory)

    # Track descriptor ownership explicitly rather than closing blind on the
    # error path.  ``os.fdopen`` takes ownership of ``fd``: once it returns, the
    # file object owns the descriptor and closes it, and a later ``os.close(fd)``
    # would be a double close — which either raises EBADF or, worse, closes an
    # unrelated descriptor that the runtime has since handed out under the same
    # number.  The earlier version wrapped that close in ``except OSError: pass``,
    # which hid exactly that bug class (and CodeQL flagged the silent handler).
    # Knowing precisely who owns the descriptor removes the need to guess.
    fd_is_ours = True
    try:
        if hasattr(os, "fchmod"):
            # Best-effort: mkstemp already creates the file 0o600 on POSIX, so a
            # platform without fchmod (or a filesystem that refuses it) is not a
            # failure — the restrictive creation mode still holds.
            try:
                os.fchmod(fd, mode)
            except OSError as exc:  # pragma: no cover - platform dependent
                logger.debug("fchmod(%s) unsupported here: %s", tmp_name, exc)

        handle = os.fdopen(fd, "wb")
        fd_is_ours = False  # ownership transferred to ``handle``
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        if fd_is_ours:
            # fdopen never took the descriptor, so closing it here is correct
            # and cannot double-close.  Any error from this close is a real
            # fault and is allowed to propagate.
            os.close(fd)
        # The staging file may already have been consumed by os.replace or never
        # created; a missing file is the expected benign case and the only one
        # suppressed here.  Any other OSError (EACCES, EIO, ...) propagates.
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise


_HMAC_SHA512_NATIVE = _HMAC_SHA512_NATIVE_AVAILABLE
_AMA_DOCS_IMPORT = _env_flag_enabled("AMA_SPHINX_BUILD") or _env_flag_enabled("SPHINX_BUILD")

if not _AMA_DOCS_IMPORT and not _HMAC_SHA512_NATIVE:
    raise RuntimeError(
        "INVARIANT-7: Native HMAC-SHA512 C backend is unavailable. "
        "The library refuses to operate without a constant-time backend "
        "for BIP32 key derivation. Build the native C library: "
        "cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
    )


def _enforce_invariant7_km() -> None:
    """INVARIANT-7 call-time enforcement for key_management module.

    Mirrors crypto_api._enforce_invariant7() — verifies the native C
    library is still loaded before every cryptographic operation.
    """
    from ama_cryptography.pqc_backends import _native_lib

    if _native_lib is None:
        raise RuntimeError(
            "INVARIANT-7 (call-time): Native C cryptographic library is not loaded. "
            "The library refuses to operate without a constant-time backend. "
            "Build the native C library: "
            "cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )


def _hmac_sha512(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA-512 via native C backend (RFC 2104).

    INVARIANT-7 revised: no pure-Python fallback.  The import-time
    guard above ensures the native backend is always available.
    INVARIANT-12: Secret-dependent operation delegated to native
    constant-time backend.
    Does NOT use the stdlib ``hmac`` module (INVARIANT-1).
    """
    _enforce_invariant7_km()
    result: bytes = native_hmac_sha512(key, data)
    return result


# Configure module logger
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional HSM dependency (PKCS#11 via PyKCS11).
# PyKCS11 is an interface library, NOT a cryptographic primitive, and does
# not violate INVARIANT-1.  All actual crypto is performed inside the HSM
# hardware using its own FIPS-validated implementation.
# Use find_spec() rather than a probe import to avoid an unused-import
# binding that CodeQL and ruff would flag.
# ---------------------------------------------------------------------------
import importlib.util

HSM_AVAILABLE: bool = importlib.util.find_spec("PyKCS11") is not None


# ---------------------------------------------------------------------------
# KDF policy floor.
#
# ``.kdf_metadata.json`` names the algorithm and cost used to turn the master
# password into the storage key, and it is a plain unauthenticated file next
# to the key material.  Anyone who can write it can name a cheaper derivation.
# That does not expose keys already stored -- those were encrypted under a key
# derived with the *old* parameters, so a swapped file simply fails to decrypt
# them -- but it does govern every key written afterwards, and on a store that
# is initialised but not yet populated the downgrade is completely silent.
#
# The parameters therefore cannot be trusted merely because they are on disk.
# They are clamped from below here, on read, and refused rather than honoured
# when they fall short.  This is the control that actually stops the
# downgrade; binding them into the AEAD associated data (storage format v3,
# see ``_kdf_binding``) is what makes an attempt *diagnosable* rather than an
# opaque authentication failure.
#
# The floors match the values this class writes for new stores: OWASP 2024 for
# PBKDF2-HMAC-SHA256 and the RFC 9106 second recommended option for Argon2id.
MIN_PBKDF2_ITERATIONS = 600000
MIN_ARGON2_T_COST = 3
MIN_ARGON2_M_COST = 65536  # KiB, i.e. 64 MiB
MIN_ARGON2_PARALLELISM = 1
# Storage format version written by ``store_key``.  v3 binds the KDF
# parameters into the AEAD associated data; v2 bound only ``key_id`` and is
# still accepted on read so existing stores keep opening.
STORAGE_FORMAT_VERSION = 3


class KDFPolicyError(KeyManagementError):
    """Raised when stored KDF parameters fall below the policy floor.

    Carries the offending parameters so an operator can tell a genuine legacy
    store from a tampered one.  Recoverable by re-opening the store with
    ``allow_legacy_kdf=True`` and calling
    :meth:`SecureKeyStorage.migrate_kdf`.
    """

    pass


class KeyStatus(Enum):
    """Key lifecycle status"""

    ACTIVE = auto()
    ROTATING = auto()
    DEPRECATED = auto()
    REVOKED = auto()
    COMPROMISED = auto()


@dataclass
class KeyMetadata:
    """
    Metadata for cryptographic keys

    Attributes:
        key_id: Unique key identifier
        created_at: Creation timestamp
        expires_at: Expiration timestamp
        status: Current key status
        version: Key version number
        parent_id: Parent key ID (for HD derivation)
        derivation_path: HD derivation path
        usage_count: Number of times key has been used
        max_usage: Maximum allowed usage count
        purpose: Key purpose (signing, encryption, etc.)
        metadata: Additional custom metadata
    """

    key_id: str
    created_at: datetime
    expires_at: Optional[datetime]
    status: KeyStatus
    version: int
    parent_id: Optional[str]
    derivation_path: Optional[str]
    usage_count: int
    max_usage: Optional[int]
    purpose: str
    metadata: Dict[str, Any]


class HDKeyDerivation:
    """
    Hierarchical Deterministic Key Derivation (BIP32-compliant)

    Derives child keys from a master seed using HMAC-SHA512.
    Supports hardened and non-hardened derivation with proper
    modular arithmetic using the secp256k1 curve order.

    Derivation Path Format:
        m/purpose'/coin_type'/account'/change/address_index

    Example:
        m/44'/0'/0'/0/0 - First address of first account
        m/44'/0'/0'/1/0 - First change address

    Standard: BIP32 (Bitcoin Improvement Proposal 32)
    Security: Uses secp256k1 curve order for modular addition
    """

    HARDENED_OFFSET = 2**31

    # secp256k1 curve order (N) - used for modular arithmetic in BIP32
    # This is the order of the generator point G on the secp256k1 curve
    SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

    def __init__(self, seed: Optional[bytes] = None, seed_phrase: Optional[str] = None) -> None:
        """
        Initialize HD key derivation

        Args:
            seed: Master seed (64 bytes recommended)
            seed_phrase: Alternative: BIP39-style seed phrase
        """
        if seed is None and seed_phrase is None:
            # Generate random seed
            self.master_seed = secrets.token_bytes(64)
        elif seed is not None:
            self.master_seed = seed
        else:
            # Derive seed from phrase (simplified BIP39).
            # seed_phrase is guaranteed non-None here: the first `if` excluded
            # the (seed is None AND seed_phrase is None) case, and the `elif`
            # excluded seed is not None, so seed is None and seed_phrase is not None.
            self.master_seed = hashlib.pbkdf2_hmac(
                "sha512", cast(str, seed_phrase).encode("utf-8"), b"mnemonic", 2048, 64
            )

        # Generate master key
        self.master_key, self.master_chain_code = self._generate_master_key()

    def _generate_master_key(self) -> Tuple[bytes, bytes]:
        """Generate master key and chain code from seed"""
        hmac_result = _hmac_sha512(b"AMA Cryptography Master Key", self.master_seed)

        master_key = hmac_result[:32]
        chain_code = hmac_result[32:]

        # BIP32: a master key whose scalar is 0 or >= n is invalid and the
        # seed must be rejected (probability ~2^-127).  This check predates
        # nothing — it was silently absent, and an invalid scalar would have
        # surfaced later as an unexplained signing failure.
        master_int = int.from_bytes(master_key, "big")
        if master_int == 0 or master_int >= self.SECP256K1_N:
            raise ValueError(
                "Invalid BIP32 master key derived from this seed (scalar is 0 "
                "or >= n; probability ~2^-127). Use a different seed."
            )

        # FIPS 140-3 pairwise consistency test — the master key is the root
        # secp256k1 keypair this hierarchy mints (INVARIANT-41).
        self._pairwise_consistency_test(master_key, "secp256k1 (BIP32 master)")

        return master_key, chain_code

    @staticmethod
    def _pairwise_consistency_test(private_key: bytes, label: str) -> None:
        """Sign/verify pairwise consistency test for a freshly minted secp256k1 key.

        The public key is re-derived from the private scalar (compressed, then
        decompressed to the X||Y form the verifier consumes) and the pair must
        round-trip an ECDSA sign/verify.  A failure enters the module ERROR
        state via the shared helper (INVARIANT-41).

        Availability is pre-checked with an explanation: a build without the
        native secp256k1 backend cannot run this test, so HD keys are refused
        on it — including hierarchies that would otherwise use hardened-only
        derivation and never touch secp256k1.  That configuration is retired
        deliberately: an untestable keypair is not released.

        A ``ValueError`` out of the public-key derivation AFTER the caller has
        range-checked the scalar is the other story entirely: the scalar was
        valid, so a rejected derivation means the derivation itself is corrupt
        — the fault class under test — and it enters ERROR like any other
        pairwise failure.
        """
        from ama_cryptography._module_state import _set_error, pairwise_test_signature
        from ama_cryptography.pqc_backends import (
            _SECP256K1_NATIVE_AVAILABLE,
            native_secp256k1_ecdsa_sign,
            native_secp256k1_ecdsa_verify,
            native_secp256k1_pubkey_decompress,
            native_secp256k1_pubkey_from_privkey,
        )

        if not _SECP256K1_NATIVE_AVAILABLE:
            raise NativeBackendUnavailableError(
                "secp256k1 sign/verify unavailable: the FIPS 140-3 pairwise "
                "consistency test cannot run, so no HD key is released — "
                "hardened-only derivation included. Build the native library "
                "with the secp256k1 backend to use HD key derivation."
            )

        try:
            public_key_64 = native_secp256k1_pubkey_decompress(
                native_secp256k1_pubkey_from_privkey(private_key)
            )
        except ValueError as exc:
            # The caller validated the scalar against the curve order, so a
            # derivation rejection is corruption, not bad input.
            _set_error(f"Pairwise consistency test failed for {label}: {exc}")
            raise CryptoModuleError(
                f"Module in error state: Pairwise test failed for {label}"
            ) from exc
        # The ECDSA primitives take a 32-byte digest, not a message; hash the
        # helper's test message on both sides so sign and verify agree.
        pairwise_test_signature(
            lambda message, sk: native_secp256k1_ecdsa_sign(hashlib.sha256(message).digest(), sk),
            lambda message, signature, pk: native_secp256k1_ecdsa_verify(
                signature, hashlib.sha256(message).digest(), pk
            ),
            private_key,
            public_key_64,
            label,
        )

    def _ckd_private(
        self, parent_key: bytes, parent_chain: bytes, index: int
    ) -> Tuple[bytes, bytes]:
        """
        Child Key Derivation (Private) - BIP32 Compliant

        Implements proper BIP32 child key derivation using modular
        arithmetic with the secp256k1 curve order (N).

        Args:
            parent_key: Parent private key (32 bytes)
            parent_chain: Parent chain code (32 bytes)
            index: Child index (>= 2^31 for hardened)

        Returns:
            (child_key, child_chain_code)

        Raises:
            ValueError: If derived key is invalid (extremely rare, ~1 in 2^127)

        Note:
            Per BIP32, if the resulting key is invalid (>= N or == 0),
            the index should be incremented and derivation retried.
            This is astronomically unlikely (~1 in 2^127 probability).
        """
        if index >= self.HARDENED_OFFSET:
            # Hardened derivation: HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i))
            data = b"\x00" + parent_key + index.to_bytes(4, "big")
        else:
            # Non-hardened derivation: HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i))
            # BIP32 requires the compressed secp256k1 public key (33 bytes).
            from ama_cryptography.pqc_backends import native_secp256k1_pubkey_from_privkey

            compressed_pubkey = native_secp256k1_pubkey_from_privkey(parent_key)
            data = compressed_pubkey + index.to_bytes(4, "big")

        hmac_result = _hmac_sha512(parent_chain, data)

        # Split HMAC result: IL (left 32 bytes) and IR (right 32 bytes)
        il = hmac_result[:32]
        child_chain = hmac_result[32:]

        # Convert to integers for modular arithmetic
        il_int = int.from_bytes(il, "big")
        parent_key_int = int.from_bytes(parent_key, "big")

        # BIP32: child_key = (IL + parent_key) mod N
        # This is the critical fix: proper modular addition, not XOR
        child_key_int = (il_int + parent_key_int) % self.SECP256K1_N

        # Check for invalid key (extremely rare edge case per BIP32 spec)
        if il_int >= self.SECP256K1_N or child_key_int == 0:
            # Per BIP32: "In case parse256(IL) >= n or ki = 0, the resulting
            # key is invalid, and one should proceed with the next value for i."
            raise ValueError(
                f"Invalid derived key at index {index}. "
                "This is astronomically unlikely (~1 in 2^127). Try next index."
            )

        # Convert back to 32-byte big-endian representation
        child_key = child_key_int.to_bytes(32, "big")

        # FIPS 140-3 pairwise consistency test — a derived child is a newly
        # minted keypair, and derivation-time is when a fault-corrupted
        # intermediate (a flipped bit in IL, a miscomputed modular sum) is
        # still caught before release (INVARIANT-41).  The label deliberately
        # omits the derivation index: a failure writes the label into
        # operator logs, and wallet-structure metadata does not belong there.
        self._pairwise_consistency_test(child_key, "secp256k1 (BIP32 child)")

        return child_key, child_chain

    def derive_path(self, path: str) -> Tuple[bytes, bytes]:
        """
        Derive key from BIP32-style path

        Args:
            path: Derivation path (e.g., "m/44'/0'/0'/0/0")

        Returns:
            (derived_key, chain_code)

        Example:
            >>> hd = HDKeyDerivation()
            >>> key, chain = hd.derive_path("m/44'/0'/0'/0/0")
        """
        if not path.startswith("m"):
            raise ValueError("Path must start with 'm'")

        # Parse path
        parts = path.split("/")[1:]  # Skip 'm'
        key = self.master_key
        chain = self.master_chain_code

        for part in parts:
            # Check for hardened derivation (')
            hardened = part.endswith("'")
            if hardened:
                part = part[:-1]

            index = int(part)
            if hardened:
                index += self.HARDENED_OFFSET

            key, chain = self._ckd_private(key, chain, index)

        return key, chain

    def derive_key(self, purpose: int, account: int = 0, change: int = 0, index: int = 0) -> bytes:
        """
        Derive key using fully-hardened path structure.

        All four path levels use hardened derivation to avoid requiring
        the secp256k1 public key computation needed by non-hardened BIP32
        child key derivation.

        Path: m/{purpose}'/{account}'/{change}'/{index}'

        Args:
            purpose: Purpose (e.g., 44 for BIP44)
            account: Account number
            change: Change address (0=external, 1=internal)
            index: Address index

        Returns:
            Derived key (32 bytes)
        """
        path = f"m/{purpose}'/{account}'/{change}'/{index}'"
        key, _ = self.derive_path(path)
        return key


class KeyRotationManager:
    """
    Key Rotation Manager

    Manages cryptographic key lifecycle with zero-downtime rotation.
    Supports gradual migration from old to new keys.
    """

    def __init__(self, rotation_period: timedelta = timedelta(days=90)) -> None:
        """
        Initialize rotation manager

        Args:
            rotation_period: How often to rotate keys
        """
        self.rotation_period = rotation_period
        self.keys: Dict[str, KeyMetadata] = {}
        self.active_key_id: Optional[str] = None

    def register_key(
        self,
        key_id: str,
        purpose: str,
        parent_id: Optional[str] = None,
        derivation_path: Optional[str] = None,
        expires_in: Optional[timedelta] = None,
        max_usage: Optional[int] = None,
    ) -> KeyMetadata:
        """
        Register a new key

        Args:
            key_id: Unique key identifier
            purpose: Key purpose (e.g., 'signing', 'encryption')
            parent_id: Parent key ID (for HD keys)
            derivation_path: HD derivation path
            expires_in: Expiration duration
            max_usage: Maximum usage count

        Returns:
            KeyMetadata
        """
        now = datetime.now(timezone.utc)
        expires_at = now + expires_in if expires_in else None

        metadata = KeyMetadata(
            key_id=key_id,
            created_at=now,
            expires_at=expires_at,
            status=KeyStatus.ACTIVE,
            version=1,
            parent_id=parent_id,
            derivation_path=derivation_path,
            usage_count=0,
            max_usage=max_usage,
            purpose=purpose,
            metadata={},
        )

        self.keys[key_id] = metadata

        # Set as active if first key
        if self.active_key_id is None:
            self.active_key_id = key_id

        return metadata

    def get_active_key(self) -> Optional[str]:
        """Get currently active key ID"""
        return self.active_key_id

    def should_rotate(self, key_id: str) -> bool:
        """
        Check if key should be rotated

        Args:
            key_id: Key to check

        Returns:
            True if rotation is needed
        """
        if key_id not in self.keys:
            return False

        metadata = self.keys[key_id]

        # Check expiration
        if metadata.expires_at and datetime.now(timezone.utc) >= metadata.expires_at:
            return True

        # Check usage limit
        if metadata.max_usage and metadata.usage_count >= metadata.max_usage:
            return True

        # Check rotation period
        if datetime.now(timezone.utc) - metadata.created_at >= self.rotation_period:
            return True

        return False

    def initiate_rotation(self, old_key_id: str, new_key_id: str) -> None:
        """
        Initiate key rotation

        Args:
            old_key_id: Key being rotated out
            new_key_id: New replacement key
        """
        if old_key_id not in self.keys or new_key_id not in self.keys:
            raise ValueError("Key not found")

        # Mark old key as rotating
        self.keys[old_key_id].status = KeyStatus.ROTATING

        # Activate new key
        self.keys[new_key_id].status = KeyStatus.ACTIVE
        self.active_key_id = new_key_id

    def complete_rotation(self, old_key_id: str) -> None:
        """
        Complete key rotation by deprecating old key

        Args:
            old_key_id: Key to deprecate
        """
        if old_key_id not in self.keys:
            return

        self.keys[old_key_id].status = KeyStatus.DEPRECATED

    def revoke_key(self, key_id: str, reason: str = "compromised") -> None:
        """
        Revoke a key immediately

        Args:
            key_id: Key to revoke
            reason: Revocation reason
        """
        if key_id not in self.keys:
            return

        if reason == "compromised":
            self.keys[key_id].status = KeyStatus.COMPROMISED
        else:
            self.keys[key_id].status = KeyStatus.REVOKED

        # If active key, need to activate a backup
        if self.active_key_id == key_id:
            self.active_key_id = None

    def increment_usage(self, key_id: str) -> None:
        """Increment usage counter for a key"""
        if key_id in self.keys:
            self.keys[key_id].usage_count += 1

    def export_metadata(self, filepath: Optional[Path] = None) -> Dict[str, Any]:
        """
        Export key metadata to JSON

        Args:
            filepath: Optional file to save to

        Returns:
            Metadata dictionary
        """
        export_data: Dict[str, Any] = {
            "active_key_id": self.active_key_id,
            "rotation_period_days": self.rotation_period.days,
            "keys": {},
        }

        keys_dict: Dict[str, Any] = export_data["keys"]
        for key_id, metadata in self.keys.items():
            keys_dict[key_id] = {
                "key_id": metadata.key_id,
                "created_at": metadata.created_at.isoformat(),
                "expires_at": metadata.expires_at.isoformat() if metadata.expires_at else None,
                "status": metadata.status.name,
                "version": metadata.version,
                "parent_id": metadata.parent_id,
                "derivation_path": metadata.derivation_path,
                "usage_count": metadata.usage_count,
                "max_usage": metadata.max_usage,
                "purpose": metadata.purpose,
                "metadata": metadata.metadata,
            }

        if filepath:
            with open(filepath, "w") as f:
                json.dump(export_data, f, indent=2)

        return export_data


class SecureKeyStorage:
    """
    Secure key storage with encryption at rest

    Stores keys encrypted with a master password or HSM-backed key.
    Supports both software and hardware-backed storage.

    Security Features:
        - AES-256-GCM authenticated encryption (integrity + confidentiality)
        - PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2024)
        - Per-installation random salt (32 bytes)
        - Secure file permissions (0600)
        - KDF versioning for future algorithm upgrades
        - Backward compatibility with legacy AES-CFB encrypted keys
    """

    def __init__(
        self,
        storage_path: Path,
        master_password: Optional[str] = None,
        allow_legacy_kdf: bool = False,
    ) -> None:
        """
        Initialize secure storage

        Args:
            storage_path: Directory for key storage
            master_password: Master password for encryption
            allow_legacy_kdf: Permit key derivation with parameters weaker
                than the current policy floor.  ``.kdf_metadata.json`` is an
                unauthenticated file in a directory the key owner does not
                exclusively control on every platform, so the cost parameters
                it names are attacker-influenced input.  With this False (the
                default) parameters below the floor are refused instead of
                honoured; set it True only to open an old store long enough to
                call :meth:`migrate_kdf`.

        Raises:
            KDFPolicyError: If the stored KDF parameters are below the policy
                floor and ``allow_legacy_kdf`` is False.
        """
        self.allow_legacy_kdf = allow_legacy_kdf
        self.storage_path = Path(storage_path)
        # Create the key store 0o700 so key-id filenames are not enumerable and
        # the encrypted key files are not world-traversable.  ``mkdir(mode=...)``
        # is subject to umask and is a no-op when the directory already exists,
        # so follow with a best-effort ``chmod`` to tighten a pre-existing dir.
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if hasattr(os, "chmod"):
            try:
                os.chmod(self.storage_path, 0o700)
            except OSError:  # pragma: no cover - platform dependent
                pass

        # Key derivation parameters (versioned for future upgrades)
        self.KDF_VERSION = 3  # v3 = Argon2id, v2 = PBKDF2 600k, v1 = PBKDF2 100k
        self.KDF_ITERATIONS = 600000  # OWASP 2024 recommendation (PBKDF2 fallback)
        self.KDF_LEGACY_ITERATIONS = 100000  # Pre-v2 default iterations
        self.KDF_SALT_BYTES = 32  # Salt size in bytes
        self.KDF_KEY_BYTES = 32  # Derived key size (AES-256)
        # Argon2id parameters (RFC 9106 recommended minimums)
        self.ARGON2_T_COST = 3  # iterations
        self.ARGON2_M_COST = 65536  # 64 MiB
        self.ARGON2_PARALLELISM = 4  # lanes
        # Parameters actually used to derive ``self.encryption_key``.  Bound
        # into the AEAD associated data of every key written by this instance
        # (storage format v3) so a stored key records, tamper-evidently, the
        # derivation cost it was protected with.
        self.kdf_params: Dict[str, Any] = {}

        # Salt file with secure permissions
        self.salt_file = self.storage_path / ".salt"
        self.metadata_file = self.storage_path / ".kdf_metadata.json"

        if master_password:
            self._derive_key_from_password(master_password)
        else:
            # Generate random encryption key (should be HSM-backed in production)
            self.encryption_key = bytearray(secrets.token_bytes(32))
            self.salt: Optional[bytes] = None  # No salt needed for random key

    @staticmethod
    def _policy_cost(value: Any) -> Optional[int]:
        """``value`` as an int, or None when it is not a usable number.

        ``bool`` is rejected explicitly: it is an ``int`` subclass in Python,
        so a JSON ``true`` would otherwise read as an iteration count of 1 —
        the same trap INVARIANT-35 records for the parameter-set selectors.
        An integral float is accepted, because JSON has one number type and
        ``3.0`` is a legitimate spelling of 3; a non-integral one is not, since
        truncating it would silently use a different parameter than the file
        names.
        """
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return None

    @classmethod
    def _usable_cost(cls, value: Any, fallback: int) -> int:
        """``value`` as an int, falling back only where policy already allowed it.

        Reached only after :meth:`_enforce_kdf_policy` has returned, so a
        non-numeric ``value`` here means the caller passed
        ``allow_legacy_kdf=True`` and has already been warned about that exact
        parameter by name.  The fallback keeps such a store openable long
        enough to :meth:`migrate_kdf` it, which is the whole purpose of the
        flag; without the policy check in front of it, this same substitution
        is what let a malformed value pass unexamined.
        """
        parsed = cls._policy_cost(value)
        return fallback if parsed is None else parsed

    def _enforce_kdf_policy(self, params: Dict[str, Any]) -> None:
        """Refuse KDF parameters weaker than the policy floor.

        ``params`` comes from ``.kdf_metadata.json``, which is unauthenticated
        (see the module-level note on the floor).  Treat it as untrusted input
        and fail closed unless the caller has explicitly opted into legacy
        parameters in order to migrate.

        Raises:
            KDFPolicyError: If any parameter is below its floor.
        """
        algorithm = params.get("algorithm")
        shortfalls: List[str] = []

        # Algorithm downgrade, not just parameter downgrade.
        #
        # Clamping costs *within* an algorithm leaves the cheapest move on the
        # board: name a different algorithm. ``.kdf_metadata.json`` carries a
        # ``version`` field, and the branch that selects Argon2id keys off it,
        # so deleting that one field re-routes derivation to PBKDF2 — and
        # PBKDF2 at 600k iterations clears its own floor. The result passes
        # every cost check while discarding memory-hardness entirely, which is
        # the property that makes Argon2id worth using against GPU/ASIC
        # cracking. The parameter floors above cannot see this: they only ever
        # compare a number against the floor for whichever algorithm was named.
        #
        # So the algorithm is floored too. PBKDF2 is accepted only where it is
        # the genuine best available — a build with no native Argon2id, which
        # is what ``_derive_key_from_password`` itself falls back to when it
        # creates a store. Where Argon2id *is* available, a store claiming
        # PBKDF2 is either a real legacy store or a downgrade attempt, and
        # nothing in the unauthenticated file distinguishes them. Both are
        # handled the same way as sub-floor costs: refuse, and point at
        # ``allow_legacy_kdf`` + ``migrate_kdf()``.
        if algorithm != "Argon2id":
            from ama_cryptography.pqc_backends import _ARGON2_NATIVE_AVAILABLE

            if _ARGON2_NATIVE_AVAILABLE:
                shortfalls.append(
                    f"algorithm {algorithm!r} is weaker than the Argon2id this "
                    "build supports (no memory-hardness)"
                )

        # Cost floors, read through _policy_cost() rather than bare int().
        #
        # `int(params.get("iterations", 0))` raises TypeError on `null` or a
        # list and ValueError on a non-numeric string, and this function's whole
        # premise is that `params` is attacker-influenced: the file is
        # unauthenticated, which is the reason the floor exists at all. Three
        # things went wrong at that boundary, in increasing order of severity.
        #
        # The exception escaped as itself, so a caller doing the documented
        # thing — catching KDFPolicyError around store-opening — did not catch
        # it. It was raised on the first malformed value, before any shortfall
        # was collected, so the operator saw a bare TypeError naming no
        # parameter instead of the actionable message the rest of this function
        # is written to produce. And it fired regardless of `allow_legacy_kdf`,
        # which exists precisely so a legacy or damaged store can be opened
        # long enough to `migrate_kdf()` it — so the one documented recovery
        # path was unavailable exactly when it was needed.
        #
        # A value that is not a number is not evidence of a strong parameter,
        # so it is treated as a shortfall. That keeps the direction fail-closed
        # while leaving `allow_legacy_kdf` able to do its job.
        def _floor(name: str, minimum: int, unit: str = "") -> None:
            value = self._policy_cost(params.get(name))
            if value is None:
                shortfalls.append(
                    f"{name} {params.get(name)!r} is not a number, so it cannot be "
                    f"shown to meet the floor of {minimum}{unit}"
                )
            elif value < minimum:
                shortfalls.append(f"{name} {value} < {minimum}{unit}")

        if algorithm == "Argon2id":
            _floor("t_cost", MIN_ARGON2_T_COST)
            _floor("m_cost", MIN_ARGON2_M_COST, " KiB")
            _floor("parallelism", MIN_ARGON2_PARALLELISM)
        else:
            _floor("iterations", MIN_PBKDF2_ITERATIONS)

        if not shortfalls:
            return

        detail = "; ".join(shortfalls)
        if self.allow_legacy_kdf:
            warnings.warn(
                f"Key store at {self.storage_path} names KDF parameters below the "
                f"policy floor ({detail}). Opening anyway because "
                "allow_legacy_kdf=True. Call migrate_kdf() to re-encrypt at "
                "current strength, then reopen without allow_legacy_kdf.",
                SecurityWarning,
                stacklevel=2,
            )
            return

        raise KDFPolicyError(
            f"Key store at {self.storage_path} names KDF parameters below the "
            f"policy floor ({detail}). {self.metadata_file.name} is not "
            "authenticated, so weak parameters may be a downgrade attempt rather "
            "than a genuine legacy store. To open an old store and upgrade it, "
            "pass allow_legacy_kdf=True and call migrate_kdf()."
        )

    def _kdf_binding(self) -> bytes:
        """Canonical associated-data encoding of the active KDF parameters.

        Bound into the AEAD of every key written in storage format v3.  The
        parameters already influence the derived key, so a swapped
        ``.kdf_metadata.json`` would break decryption regardless; what this
        adds is *provenance*.  The key file records the cost it was written
        under, that record cannot be edited without invalidating the tag, and
        a mismatch reports which parameters changed instead of surfacing as an
        unexplained authentication failure.

        Sorted, separator-normalised JSON so the bytes are reproducible across
        interpreters and dict insertion orders.
        """
        return json.dumps(self.kdf_params, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _aad_for(self, key_id: str, storage_version: int, kdf_binding: bytes) -> bytes:
        """Build the AEAD associated data for a stored key.

        v2 bound ``key_id`` alone.  v3 additionally binds the storage format
        version and the KDF parameters, length-prefixed so that no two
        distinct (key_id, params) pairs can produce the same byte string by
        shifting the boundary between them.
        """
        if storage_version < 3:
            return key_id.encode("utf-8")
        key_id_bytes = key_id.encode("utf-8")
        return b"".join(
            (
                b"AMAKS\x03",
                len(key_id_bytes).to_bytes(4, "big"),
                key_id_bytes,
                len(kdf_binding).to_bytes(4, "big"),
                kdf_binding,
            )
        )

    def _derive_key_from_password(self, master_password: str) -> None:
        """Derive encryption key from password with proper salt handling.

        The parameters named by ``.kdf_metadata.json`` are passed through
        :meth:`_enforce_kdf_policy` before any derivation happens, and the set
        actually used is recorded in ``self.kdf_params`` for AEAD binding.

        Raises:
            KDFPolicyError: If the stored parameters are below the floor and
                ``allow_legacy_kdf`` is False.
        """
        # Check for existing salt (migration support)
        if self.salt_file.exists():
            with open(self.salt_file, "rb") as f:
                self.salt = f.read()

            # Load metadata to get iteration count
            if self.metadata_file.exists():
                with open(self.metadata_file, "r") as f:
                    metadata = json.load(f)
                iterations = metadata.get("iterations", self.KDF_LEGACY_ITERATIONS)
                version = metadata.get("version", 1)
            else:
                # Legacy mode: no metadata means old 100k iterations
                iterations = self.KDF_LEGACY_ITERATIONS
                version = 1
        else:
            # New installation: generate random salt
            self.salt = secrets.token_bytes(self.KDF_SALT_BYTES)

            # Save salt with secure permissions (0600), no world-readable window.
            _atomic_write_bytes(self.salt_file, self.salt)

            # Determine algorithm: prefer Argon2id, fall back to PBKDF2
            from ama_cryptography.pqc_backends import _ARGON2_NATIVE_AVAILABLE

            use_argon2 = _ARGON2_NATIVE_AVAILABLE

            if use_argon2:
                algorithm = "Argon2id"
                version = 3
            else:
                algorithm = "PBKDF2-HMAC-SHA256"
                version = 2

            # Save KDF metadata
            metadata = {
                "version": version,
                "algorithm": algorithm,
                "salt_bytes": self.KDF_SALT_BYTES,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            if algorithm == "PBKDF2-HMAC-SHA256":
                metadata["iterations"] = self.KDF_ITERATIONS
            else:
                metadata["t_cost"] = self.ARGON2_T_COST
                metadata["m_cost"] = self.ARGON2_M_COST
                metadata["parallelism"] = self.ARGON2_PARALLELISM
            with open(self.metadata_file, "w") as f:
                json.dump(metadata, f, indent=2)
            os.chmod(self.metadata_file, 0o600)
            iterations = self.KDF_ITERATIONS

        # Derive key using the appropriate algorithm
        if version >= 3:
            # Read stored Argon2id parameters so existing keystores remain
            # decryptable even if class-level defaults change later.
            t_cost = self.ARGON2_T_COST
            m_cost = self.ARGON2_M_COST
            parallelism = self.ARGON2_PARALLELISM
            if self.metadata_file.exists():
                # An UNREADABLE file is a different condition from a readable
                # one carrying a bad value, and only the first justifies
                # falling back to defaults.  This block used to conflate them:
                # it wrapped the `int()` coercions in the same
                # `except (OSError, ValueError, TypeError, KeyError)` and, on a
                # non-numeric cost, logged "using defaults" and continued.
                #
                # Two things were wrong with that, and both bypassed the floor
                # this release added.  The malformed value never reached
                # `_enforce_kdf_policy`, so the check that exists to adjudicate
                # untrusted metadata was not consulted about the one input it
                # could not parse.  And the recovery was *partial*: the
                # coercions run in sequence, so `t_cost` keeps an
                # attacker-chosen value while `m_cost` reverts to the default,
                # leaving a mixture the log line then described as "defaults".
                #
                # Read the values raw and let the policy check adjudicate.
                try:
                    with open(self.metadata_file, "r") as _f:
                        _meta = json.load(_f)
                except (OSError, json.JSONDecodeError) as _exc:
                    logger.warning(
                        "Could not read Argon2id params from %s, using defaults: %s",
                        self.metadata_file,
                        _exc,
                    )
                    _meta = {}
                algorithm = _meta.get("algorithm")
                if algorithm is not None and algorithm != "Argon2id":
                    raise RuntimeError(
                        f"Unsupported KDF algorithm for v{version} store: {algorithm}"
                    )
                t_cost = _meta.get("t_cost", t_cost)
                m_cost = _meta.get("m_cost", m_cost)
                parallelism = _meta.get("parallelism", parallelism)

            # Cost check BEFORE the derivation, so a downgraded file never
            # gets to produce a usable key.
            self.kdf_params = {
                "algorithm": "Argon2id",
                "t_cost": t_cost,
                "m_cost": m_cost,
                "parallelism": parallelism,
            }
            self._enforce_kdf_policy(self.kdf_params)

            # Past the policy check every cost is either a number at or above
            # its floor, or the caller passed `allow_legacy_kdf=True` and was
            # warned by name.  Only in that second case can a value still be
            # unusable, so that is the only case where a default is
            # substituted — and it is substituted per-parameter, after a
            # warning that named it, rather than silently and in bulk.
            t_cost = self._usable_cost(t_cost, self.ARGON2_T_COST)
            m_cost = self._usable_cost(m_cost, self.ARGON2_M_COST)
            parallelism = self._usable_cost(parallelism, self.ARGON2_PARALLELISM)
            self.kdf_params.update({"t_cost": t_cost, "m_cost": m_cost, "parallelism": parallelism})

            try:
                from ama_cryptography.pqc_backends import native_argon2id

                self.encryption_key = bytearray(
                    native_argon2id(
                        master_password.encode("utf-8"),
                        self.salt,
                        t_cost=t_cost,
                        m_cost=m_cost,
                        parallelism=parallelism,
                        out_len=self.KDF_KEY_BYTES,
                    )
                )
            except (ImportError, RuntimeError) as exc:
                raise RuntimeError(
                    "Argon2id native library required to open this key store "
                    "(written with KDF version 3). Rebuild: "
                    "cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
                ) from exc
        else:
            # Raw, not `int(iterations)`.  This coercion sat outside any
            # handler, so a tampered `"iterations": null` in the
            # unauthenticated metadata raised a bare TypeError from here —
            # before the policy check, not catchable as KDFPolicyError, and
            # unaffected by `allow_legacy_kdf`.  The policy check adjudicates
            # it now, as it does every other value from that file.
            self.kdf_params = {
                "algorithm": "PBKDF2-HMAC-SHA256",
                "iterations": iterations,
            }
            self._enforce_kdf_policy(self.kdf_params)
            iterations = self._usable_cost(iterations, self.KDF_ITERATIONS)
            self.kdf_params["iterations"] = iterations
            self.encryption_key = bytearray(
                hashlib.pbkdf2_hmac(
                    "sha256",
                    master_password.encode("utf-8"),
                    self.salt,
                    iterations,
                    self.KDF_KEY_BYTES,
                )
            )

        # Warn if using legacy parameters
        if version < 2:
            warnings.warn(
                f"SecureKeyStorage using legacy KDF v{version} with {iterations} iterations. "
                "Run migrate_kdf() to upgrade to current security standards.",
                SecurityWarning,
            )

    def migrate_kdf(self, master_password: str) -> bool:
        """
        Migrate to current KDF parameters.

        Re-encrypts all stored keys with new salt and iteration count.
        Returns True on success.
        """
        if not self.salt_file.exists():
            return False  # Nothing to migrate

        # Read all existing keys with old parameters
        old_keys: Dict[str, Tuple[bytes, Dict[str, Any]]] = {}
        for key_file in self.storage_path.glob("*.json"):
            if key_file.name.startswith("."):
                continue
            key_id = key_file.stem
            key_data = self.retrieve_key(key_id)
            # `is not None`, not truthiness.  A zero-length stored value —
            # a tombstone, a placeholder provisioned before its material
            # arrives, an empty result from an upstream serializer — is
            # falsy, so `if key_data:` skipped it.  The migration then
            # rotated the salt and metadata around it, leaving that record
            # encrypted under a key the new password no longer derives:
            # permanently unreadable, while list_keys() went on reporting it.
            # Silent, and not recoverable once the old salt is gone.
            if key_data is not None:
                with open(key_file, "r") as f:
                    metadata = json.load(f).get("metadata", {})
                old_keys[key_id] = (key_data, metadata)

        # Generate new salt
        new_salt = secrets.token_bytes(self.KDF_SALT_BYTES)

        # Derive new key — prefer Argon2id, fall back to PBKDF2
        from ama_cryptography.pqc_backends import _ARGON2_NATIVE_AVAILABLE, native_argon2id

        use_argon2 = _ARGON2_NATIVE_AVAILABLE

        if use_argon2:
            new_encryption_key = bytearray(
                native_argon2id(
                    master_password.encode("utf-8"),
                    new_salt,
                    t_cost=self.ARGON2_T_COST,
                    m_cost=self.ARGON2_M_COST,
                    parallelism=self.ARGON2_PARALLELISM,
                    out_len=self.KDF_KEY_BYTES,
                )
            )
        else:
            new_encryption_key = bytearray(
                hashlib.pbkdf2_hmac(
                    "sha256",
                    master_password.encode("utf-8"),
                    new_salt,
                    self.KDF_ITERATIONS,
                    self.KDF_KEY_BYTES,
                )
            )

        # Re-encrypt all keys under the new key.  This is the dangerous part:
        # each ``{key_id}.json`` is rewritten in place under ``new_encryption_key``
        # while the persisted ``.salt`` still selects the *old* key until the
        # very end.  If the process dies partway through, the keys already
        # rewritten are encrypted under a key that the on-disk salt can no longer
        # reproduce — i.e. permanently undecryptable.  The previous rollback
        # restored only ``self.encryption_key`` (not ``self.salt``, and not the
        # rewritten files), so any interrupted migration lost data.
        #
        # Crash-safety strategy:
        #   * snapshot the raw bytes of every file the migration overwrites,
        #   * write each key + the salt + metadata via ``_atomic_write_bytes``
        #     (atomic replace, so no file is ever torn),
        #   * on any exception restore the exact prior on-disk state from the
        #     snapshot and restore both ``encryption_key`` and ``salt`` in memory.
        old_key = self.encryption_key
        old_salt = self.salt

        snapshot: Dict[Path, Optional[bytes]] = {}
        for key_id in old_keys:
            key_path = self.storage_path / f"{key_id}.json"
            snapshot[key_path] = key_path.read_bytes() if key_path.exists() else None
        snapshot[self.salt_file] = self.salt_file.read_bytes() if self.salt_file.exists() else None
        snapshot[self.metadata_file] = (
            self.metadata_file.read_bytes() if self.metadata_file.exists() else None
        )

        old_kdf_params = self.kdf_params

        self.encryption_key = new_encryption_key
        self.salt = new_salt
        # Swap the recorded parameters over with the key, so the keys written
        # below are bound to the parameters they are actually protected by
        # rather than to the ones being migrated away from.
        if use_argon2:
            self.kdf_params = {
                "algorithm": "Argon2id",
                "t_cost": self.ARGON2_T_COST,
                "m_cost": self.ARGON2_M_COST,
                "parallelism": self.ARGON2_PARALLELISM,
            }
        else:
            self.kdf_params = {
                "algorithm": "PBKDF2-HMAC-SHA256",
                "iterations": self.KDF_ITERATIONS,
            }

        try:
            for key_id, (key_data, key_metadata) in old_keys.items():
                self.store_key(key_id, key_data, key_metadata)

            # Update salt file (atomic, 0600).
            _atomic_write_bytes(self.salt_file, new_salt)

            # Update metadata (atomic, 0600).
            metadata = {
                "version": self.KDF_VERSION if use_argon2 else 2,
                "algorithm": "Argon2id" if use_argon2 else "PBKDF2-HMAC-SHA256",
                "salt_bytes": self.KDF_SALT_BYTES,
                "migrated_at": datetime.now(timezone.utc).isoformat(),
            }
            if use_argon2:
                metadata["t_cost"] = self.ARGON2_T_COST
                metadata["m_cost"] = self.ARGON2_M_COST
                metadata["parallelism"] = self.ARGON2_PARALLELISM
            else:
                metadata["iterations"] = self.KDF_ITERATIONS
            _atomic_write_bytes(self.metadata_file, json.dumps(metadata, indent=2).encode("utf-8"))

            return True
        except Exception:
            # Restore the prior on-disk state so no key is left encrypted under a
            # key the persisted salt cannot reproduce, then restore in-memory key
            # and salt together (the old code left ``self.salt`` inconsistent).
            for path, original in snapshot.items():
                try:
                    if original is None:
                        if path.exists():
                            path.unlink()
                    else:
                        _atomic_write_bytes(path, original)
                except OSError:
                    logger.error(
                        "migrate_kdf rollback could not restore %s; the key store "
                        "may need manual recovery from backup",
                        path,
                    )
            self.encryption_key = old_key
            self.salt = old_salt
            self.kdf_params = old_kdf_params
            raise

    @classmethod
    def from_existing(
        cls,
        storage_path: Path,
        master_password: str,
        allow_legacy_kdf: bool = False,
    ) -> "SecureKeyStorage":
        """Recover storage instance from existing salt file.

        Args:
            storage_path: Directory holding ``.salt`` and the key files
            master_password: Master password for encryption
            allow_legacy_kdf: See :meth:`__init__`.  Defaults to False, so an
                existing store whose metadata names sub-floor parameters is
                refused rather than opened.

        Raises:
            KDFPolicyError: If the stored KDF parameters are below the policy
                floor and ``allow_legacy_kdf`` is False.
        """
        storage = cls.__new__(cls)
        storage.allow_legacy_kdf = allow_legacy_kdf
        storage.kdf_params = {}
        storage.storage_path = Path(storage_path)
        storage.KDF_VERSION = 3
        storage.KDF_ITERATIONS = 600000
        storage.KDF_LEGACY_ITERATIONS = 100000  # Pre-v2 default iterations
        storage.KDF_SALT_BYTES = 32  # Salt size in bytes
        storage.KDF_KEY_BYTES = 32  # Derived key size (AES-256)
        storage.ARGON2_T_COST = 3
        storage.ARGON2_M_COST = 65536
        storage.ARGON2_PARALLELISM = 4
        storage.salt_file = storage.storage_path / ".salt"
        storage.metadata_file = storage.storage_path / ".kdf_metadata.json"

        if not storage.salt_file.exists():
            raise FileNotFoundError(f"Salt file not found: {storage.salt_file}")

        storage._derive_key_from_password(master_password)
        return storage

    @staticmethod
    def _validate_key_id(key_id: str) -> None:
        """Reject ``key_id`` values that could escape ``storage_path``.

        ``key_id`` is interpolated directly into a filename
        (``storage_path / f"{key_id}.json"``), so it is the only thing standing
        between a caller-supplied identifier and a path-traversal write/read
        (``../../etc/foo``).  Restricting it to ``[A-Za-z0-9_-]`` makes any
        separator or ``..`` component impossible.  ``store_key``,
        ``retrieve_key`` and ``delete_key`` all funnel through this guard so the
        three cannot drift apart again.
        """
        if not key_id or not key_id.replace("-", "").replace("_", "").isalnum():
            raise ValueError("key_id must be non-empty alphanumeric (with - and _ allowed)")

    def store_key(
        self, key_id: str, key_data: bytes, metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Store key with AES-256-GCM authenticated encryption.

        Args:
            key_id: Key identifier (also used as associated data for authentication)
            key_data: Key bytes (will be encrypted)
            metadata: Optional metadata

        Raises:
            ValueError: If key_id is empty or contains invalid characters
        """
        from ama_cryptography.pqc_backends import native_aes256_gcm_encrypt

        # Validate key_id (this is the guard that keeps a caller-supplied id
        # from escaping ``storage_path`` — see ``_validate_key_id``).
        self._validate_key_id(key_id)

        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM (NIST recommended)

        # Associated data binds the ciphertext to key_id and, from format v3,
        # to the KDF parameters this instance derived its key with.  The
        # recorded parameters are covered by the tag, so the provenance a
        # reader sees cannot be edited independently of the ciphertext.
        kdf_binding = self._kdf_binding()
        aad = self._aad_for(key_id, STORAGE_FORMAT_VERSION, kdf_binding)

        # The native wrapper borrows this bytearray key through the buffer
        # protocol so the context manager can still wipe the only live copy.
        ct, tag = native_aes256_gcm_encrypt(self.encryption_key, nonce, key_data, aad)
        ciphertext = ct + tag  # Store as combined ct||tag for format compatibility

        storage_data = {
            "key_id": key_id,
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "algorithm": "AES-256-GCM",
            "version": STORAGE_FORMAT_VERSION,  # Storage format version
            "kdf_params": self.kdf_params,
            "metadata": metadata or {},
            "stored_at": datetime.now(timezone.utc).isoformat(),
        }

        key_file = self.storage_path / f"{key_id}.json"
        # Atomic 0600 write: no world-readable window and no torn file if the
        # process dies mid-write (load-bearing for crash-safe ``migrate_kdf``).
        _atomic_write_bytes(key_file, json.dumps(storage_data, indent=2).encode("utf-8"))

    def retrieve_key(self, key_id: str) -> Optional[bytes]:
        """
        Retrieve and decrypt key with authentication verification.

        Args:
            key_id: Key identifier

        Returns:
            Decrypted key bytes or None if not found

        Raises:
            ValueError: If authentication fails (tampering detected) or unknown algorithm
        """
        from ama_cryptography.pqc_backends import native_aes256_gcm_decrypt

        # Same traversal guard as ``store_key`` — a store you cannot write with
        # a malicious id must not be readable with one either.
        self._validate_key_id(key_id)

        key_file = self.storage_path / f"{key_id}.json"
        if not key_file.exists():
            return None

        with open(key_file, "r") as f:
            storage_data = json.load(f)

        algorithm = storage_data.get("algorithm", "AES-256-GCM")

        if algorithm == "AES-256-GCM":
            combined = base64.b64decode(storage_data["ciphertext"])
            nonce = base64.b64decode(storage_data["nonce"])

            if len(combined) < 16:
                raise ValueError(
                    f"Key '{key_id}' has corrupted ciphertext: "
                    "authentication tag is missing or truncated"
                )

            # Split combined ct||tag (last 16 bytes = tag)
            ct = combined[:-16]
            tag = combined[-16:]

            # Reconstruct the associated data this key was written with.  v2
            # files bound key_id alone; v3 also binds the KDF parameters, and
            # those are read back from the file rather than from the live
            # instance so a key written under one derivation still opens when
            # the store has since been migrated to another.
            storage_version = int(storage_data.get("version", 2))
            recorded_params = storage_data.get("kdf_params", {})
            recorded_binding = json.dumps(
                recorded_params, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            aad = self._aad_for(key_id, storage_version, recorded_binding)

            # Decrypt with authentication (raises ValueError if tampered);
            # keep the wipeable bytearray key on the buffer-protocol path.
            try:
                plaintext: bytes = native_aes256_gcm_decrypt(
                    self.encryption_key, nonce, ct, tag, aad
                )
            except ValueError:
                # A parameter mismatch is the one authentication failure with
                # a specific, actionable cause: the key was protected at a
                # different cost than the one now in force.  Name it, rather
                # than leaving the caller with a bare tamper error.
                if storage_version >= 3 and recorded_params and recorded_params != self.kdf_params:
                    raise KDFPolicyError(
                        f"Key '{key_id}' was stored under KDF parameters "
                        f"{recorded_params}, but this store derived its key with "
                        f"{self.kdf_params}. Either {self.metadata_file.name} has "
                        "changed since the key was written, or the key belongs to a "
                        "different store. Nothing has been decrypted."
                    ) from None
                raise
            return plaintext

        elif algorithm == "AES-256-CFB":
            raise ValueError(
                f"Key '{key_id}' uses legacy AES-256-CFB encryption which is no "
                "longer supported. Re-store this key using the current API to "
                "upgrade to AES-256-GCM authenticated encryption."
            )

        else:
            raise ValueError(f"Unknown encryption algorithm: {algorithm}")

    def delete_key(self, key_id: str) -> bool:
        """
        Securely delete a key

        Args:
            key_id: Key to delete

        Returns:
            True if deleted, False if not found
        """
        # Traversal guard: without it, a crafted key_id would let this method
        # overwrite-with-random-bytes and unlink an arbitrary writable *.json.
        self._validate_key_id(key_id)

        key_file = self.storage_path / f"{key_id}.json"
        if key_file.exists():
            # Best-effort overwrite before unlinking (see note below on the
            # limits of this on journaling/CoW/SSD filesystems).
            with open(key_file, "wb") as f:
                f.write(secrets.token_bytes(1024))
                f.flush()
                os.fsync(f.fileno())
            key_file.unlink()
            return True
        return False

    def list_keys(self) -> List[str]:
        """
        List all stored key IDs.

        Returns:
            List of key IDs stored in this storage
        """
        return [
            key_file.stem
            for key_file in self.storage_path.glob("*.json")
            if not key_file.name.startswith(".")
        ]

    def __enter__(self) -> "SecureKeyStorage":
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """Context manager exit - securely clear encryption key from memory."""
        # Securely zero the encryption key in-place (bytearray allows mutation)
        if hasattr(self, "encryption_key") and self.encryption_key:
            secure_memzero(self.encryption_key)
        return None


class HSMKeyStorage:
    """
    Hardware Security Module key storage via PKCS#11.

    Provides FIPS 140-2 Level 3 compliant key storage for production deployments.
    Keys generated inside HSM never leave the hardware in plaintext.

    Supported devices:
        - YubiKey 5 Series (libykcs11.so)
        - Nitrokey HSM/Pro (libsc-hsm-pkcs11.so)
        - SoftHSM2 (for development/testing)
        - AWS CloudHSM (via PKCS#11 library)
        - Thales Luna (via libCryptoki2.so)

    Example:
        >>> with HSMKeyStorage("softhsm", pin="1234") as hsm:
        ...     key_handle = hsm.generate_aes_key("my-key", 256)
        ...     nonce, ct, tag = hsm.encrypt(key_handle, b"secret data")
        ...     plaintext = hsm.decrypt(key_handle, nonce, ct, tag)
    """

    PKCS11_PATHS = {
        "yubikey": [
            "/usr/lib/x86_64-linux-gnu/libykcs11.so",
            "/usr/local/lib/libykcs11.so",
            "/Library/OpenSC/lib/libykcs11.dylib",  # macOS
        ],
        "nitrokey": [
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
            "/usr/lib/pkcs11/opensc-pkcs11.so",
        ],
        "softhsm": [
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
            "/opt/homebrew/lib/softhsm/libsofthsm2.so",  # macOS ARM
        ],
        "aws-cloudhsm": [
            "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
        ],
        "thales-luna": [
            "/usr/safenet/lunaclient/lib/libCryptoki2.so",
        ],
    }

    def __init__(
        self,
        hsm_type: str = "softhsm",
        library_path: Optional[str] = None,
        token_label: str = "AmaCryptography",
        pin: Optional[
            str
        ] = None,  # nosec B107 -- default None, not a hardcoded secret; PIN is caller-provided at runtime (KM-001)
        slot_index: Optional[int] = None,
    ) -> None:
        """
        Initialize HSM connection.

        Args:
            hsm_type: Type of HSM (yubikey, nitrokey, softhsm, aws-cloudhsm, thales-luna)
            library_path: Override path to PKCS#11 library
            token_label: Token label to use (must exist on HSM)
            pin: User PIN (will prompt if not provided)
            slot_index: Specific slot index to use (auto-detect if None)

        Raises:
            AmaHSMUnavailableError: If PyKCS11 is not installed
            ValueError: If HSM type is unknown
            RuntimeError: If token not found or login fails
        """
        if not HSM_AVAILABLE:
            raise AmaHSMUnavailableError(
                "HSM support requires PyKCS11. Install with: pip install ama-cryptography[hsm]"
            )
        self.pkcs11 = self._import_pykcs11()
        self._handle_map: Dict[bytes, Any] = {}  # bytes key -> PKCS11 handle object
        self.library_path = self._resolve_library_path(hsm_type, library_path)
        self.lib = self._load_pkcs11_library()
        self.slot = self._find_token_slot(token_label, slot_index)
        self.session = self._open_session()
        self._login(pin, token_label)
        self._logged_in = True

    def _import_pykcs11(self) -> Any:
        """Import PyKCS11 module (optional dependency)."""
        try:
            import PyKCS11

            return PyKCS11
        except ImportError as e:
            raise AmaHSMUnavailableError(
                "HSM support requires PyKCS11. Install with: pip install ama-cryptography[hsm]"
            ) from e

    def _resolve_library_path(self, hsm_type: str, library_path: Optional[str]) -> str:
        """Resolve PKCS#11 library path for the given HSM type."""
        if library_path:
            return library_path

        paths = self.PKCS11_PATHS.get(hsm_type)
        if not paths:
            raise ValueError(
                f"Unknown HSM type: {hsm_type}. "
                f"Supported: {', '.join(self.PKCS11_PATHS.keys())}"
            )

        for path in paths:
            if os.path.exists(path):
                return path

        raise RuntimeError(f"PKCS#11 library not found for {hsm_type}. Searched: {paths}")

    def _load_pkcs11_library(self) -> Any:
        """Load the PKCS#11 library."""
        lib = self.pkcs11.PyKCS11Lib()
        try:
            lib.load(self.library_path)
            return lib
        except self.pkcs11.PyKCS11Error as e:
            raise RuntimeError(f"Failed to load PKCS#11 library: {e}") from e

    def _find_token_slot(self, token_label: str, slot_index: Optional[int]) -> Any:
        """Find the HSM token slot by label or index."""
        slots = self.lib.getSlotList(tokenPresent=True)
        if not slots:
            raise RuntimeError("No HSM tokens found. Is the device connected?")

        if slot_index is not None:
            if slot_index < len(slots):
                return slots[slot_index]
            raise ValueError(f"Slot index {slot_index} out of range (0-{len(slots) - 1})")

        for slot in slots:
            try:
                info = self.lib.getTokenInfo(slot)
                # PKCS#11 token labels are public identifiers, not secret material.
                if (
                    info.label.strip() == token_label
                ):  # nosemgrep: non-constant-time-comparison -- PKCS#11 token labels are public identifiers, not secret material (KM-003)
                    return slot
            except self.pkcs11.PyKCS11Error:
                continue

        available = [self.lib.getTokenInfo(s).label.strip() for s in slots]
        raise RuntimeError(f"Token '{token_label}' not found. Available tokens: {available}")

    def _open_session(self) -> Any:
        """Open a PKCS#11 session with the HSM."""
        try:
            return self.lib.openSession(
                self.slot, self.pkcs11.CKF_SERIAL_SESSION | self.pkcs11.CKF_RW_SESSION
            )
        except self.pkcs11.PyKCS11Error as e:
            raise RuntimeError(f"Failed to open HSM session: {e}") from e

    def _login(self, pin: Optional[str], token_label: str) -> None:
        """Login to the HSM session."""
        if pin is None:
            import getpass

            pin = getpass.getpass(f"Enter PIN for HSM token '{token_label}': ")

        try:
            self.session.login(pin)
        except self.pkcs11.PyKCS11Error as e:
            self.session.closeSession()
            if "CKR_PIN_INCORRECT" in str(e):
                raise RuntimeError("Invalid PIN") from e
            raise RuntimeError(f"HSM login failed: {e}") from e

    def generate_aes_key(
        self,
        key_label: str,
        key_size: int = 256,
        extractable: bool = False,
    ) -> bytes:
        """
        Generate AES key inside HSM (never leaves hardware if extractable=False).

        Args:
            key_label: Label for the key (must be unique)
            key_size: Key size in bits (128, 192, or 256)
            extractable: Whether key can be exported (False for maximum security)

        Returns:
            Key handle (8 bytes) for referencing the key

        Raises:
            ValueError: If key_size is invalid
            RuntimeError: If key generation fails
        """
        if key_size not in (128, 192, 256):
            raise ValueError(f"Invalid key size: {key_size}. Must be 128, 192, or 256.")

        pk = self.pkcs11

        template = [
            (pk.CKA_CLASS, pk.CKO_SECRET_KEY),
            (pk.CKA_KEY_TYPE, pk.CKK_AES),
            (pk.CKA_VALUE_LEN, key_size // 8),
            (pk.CKA_LABEL, key_label),
            (pk.CKA_TOKEN, True),  # Persist on token
            (pk.CKA_PRIVATE, True),  # Require login
            (pk.CKA_SENSITIVE, True),  # Never reveal in plaintext
            (pk.CKA_EXTRACTABLE, extractable),
            (pk.CKA_ENCRYPT, True),
            (pk.CKA_DECRYPT, True),
            (pk.CKA_WRAP, True),  # Can wrap other keys
            (pk.CKA_UNWRAP, True),  # Can unwrap other keys
        ]

        try:
            handle = self.session.generateKey(template, pk.Mechanism(pk.CKM_AES_KEY_GEN))
            handle_int = handle.value() if hasattr(handle, "value") else int(handle)
            key_ref: bytes = handle_int.to_bytes(8, "big")
            self._handle_map[key_ref] = handle
            return key_ref
        except self.pkcs11.PyKCS11Error as e:
            raise RuntimeError(f"Failed to generate AES key: {e}") from e

    def find_key(self, key_label: str) -> Optional[bytes]:
        """
        Find existing key by label.

        Returns:
            Key handle (8 bytes) or None if not found
        """
        pk = self.pkcs11

        template = [
            (pk.CKA_CLASS, pk.CKO_SECRET_KEY),
            (pk.CKA_LABEL, key_label),
        ]

        try:
            objects = self.session.findObjects(template)
            if objects:
                obj = objects[0]
                handle_int = obj.value() if hasattr(obj, "value") else int(obj)
                key_ref: bytes = handle_int.to_bytes(8, "big")
                self._handle_map[key_ref] = obj
                return key_ref
            return None
        except self.pkcs11.PyKCS11Error:
            return None

    def encrypt(self, key_handle: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt using HSM-stored key with AES-GCM.

        Args:
            key_handle: Handle from generate_aes_key or find_key
            plaintext: Data to encrypt

        Returns:
            Tuple of (nonce, ciphertext, tag)
        """
        handle = self._handle_map.get(key_handle, int.from_bytes(key_handle, "big"))

        try:
            nonce = secrets.token_bytes(12)
            mechanism = self.pkcs11.AES_GCM_Mechanism(nonce, b"", 128)
            ciphertext_with_tag = bytes(self.session.encrypt(handle, plaintext, mechanism))

            # GCM appends the tag to ciphertext
            ciphertext = ciphertext_with_tag[:-16]
            tag = ciphertext_with_tag[-16:]

            return nonce, ciphertext, tag
        except self.pkcs11.PyKCS11Error as e:
            raise RuntimeError(f"HSM encryption failed: {e}") from e

    def decrypt(
        self,
        key_handle: bytes,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
    ) -> bytes:
        """
        Decrypt using HSM-stored key with AES-GCM.

        Args:
            key_handle: Handle from generate_aes_key or find_key
            nonce: Nonce from encryption
            ciphertext: Encrypted data
            tag: Authentication tag

        Returns:
            Decrypted plaintext

        Raises:
            RuntimeError: If decryption or authentication fails
        """
        handle = self._handle_map.get(key_handle, int.from_bytes(key_handle, "big"))

        try:
            mechanism = self.pkcs11.AES_GCM_Mechanism(nonce, b"", 128)
            plaintext = bytes(self.session.decrypt(handle, ciphertext + tag, mechanism))
            return plaintext
        except self.pkcs11.PyKCS11Error as e:
            if "CKR_ENCRYPTED_DATA_INVALID" in str(e):
                raise RuntimeError(
                    "Decryption failed: authentication tag mismatch (data tampered)"
                ) from e
            raise RuntimeError(f"HSM decryption failed: {e}") from e

    def delete_key(self, key_handle: bytes) -> bool:
        """
        Delete key from HSM.

        Returns:
            True if deleted, False if not found
        """
        handle = self._handle_map.pop(key_handle, int.from_bytes(key_handle, "big"))

        try:
            self.session.destroyObject(handle)
            return True
        except self.pkcs11.PyKCS11Error:
            return False

    def destroy_key(self, key_handle: bytes) -> bool:
        """Alias for delete_key — permanently destroys key inside HSM.

        Returns:
            True if destroyed, False if not found.
        """
        return self.delete_key(key_handle)

    def close(self) -> None:
        """Close HSM session and logout."""
        if hasattr(self, "_logged_in") and self._logged_in:
            try:
                self.session.logout()
            except Exception as e:
                logging.getLogger(__name__).warning("HSM logout failed during cleanup: %s", e)
            self._logged_in = False

        if hasattr(self, "session"):
            try:
                self.session.closeSession()
            except Exception as e:
                logging.getLogger(__name__).warning(
                    "HSM session close failed during cleanup: %s", e
                )

    def __enter__(self) -> "HSMKeyStorage":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception as exc:  # — INVARIANT-3/9: __del__ must not raise (FIN-004)
            # INVARIANT-3 addendum: silence is never the only outcome.
            record_finalizer_error("HSMKeyStorage", f"close() failed: {exc}")


# Example usage
if __name__ == "__main__":
    # Configure logging for demo
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    logger.info("=" * 70)
    logger.info("AMA Cryptography Key Management Demonstration")
    logger.info("=" * 70)

    # HD Key Derivation
    logger.info("\n1. Hierarchical Deterministic Key Derivation")
    logger.info("-" * 70)
    hd = HDKeyDerivation()

    # Derive keys for different purposes (hardened-only paths)
    signing_key, _ = hd.derive_path("m/44'/0'/0'")
    encryption_key, _ = hd.derive_path("m/44'/0'/1'")

    # Demo display uses a SHA3-256 fingerprint of each derived key rather
    # than the key bytes themselves (PR #277, Copilot review #2).  The
    # previous form printed the first 16 raw bytes (128 bits) of each
    # 32-byte key — even truncated, that is real key material that a
    # user copy-pasting the demo into a real environment would persist
    # to logs / terminal scrollback.  A SHA3-256 fingerprint is one-way,
    # supports `grep` / log-correlation just as well as a hex prefix,
    # and reveals nothing about the key value itself.
    sk_fp = hashlib.sha3_256(signing_key).hexdigest()[:16]
    ek_fp = hashlib.sha3_256(encryption_key).hexdigest()[:16]
    logger.info(f"Signing key fingerprint:    sha3-256:{sk_fp}")
    logger.info(f"Encryption key fingerprint: sha3-256:{ek_fp}")

    # Key Rotation
    logger.info("\n2. Key Rotation Management")
    logger.info("-" * 70)
    rotation_mgr = KeyRotationManager(rotation_period=timedelta(days=90))

    # Register keys
    rotation_mgr.register_key("key-v1", "signing", max_usage=1000)
    rotation_mgr.register_key("key-v2", "signing")

    logger.info(f"Active key: {rotation_mgr.get_active_key()}")
    logger.info(f"Should rotate: {rotation_mgr.should_rotate('key-v1')}")

    # Simulate key rotation
    rotation_mgr.initiate_rotation("key-v1", "key-v2")
    logger.info(f"After rotation, active key: {rotation_mgr.get_active_key()}")

    # Secure Storage
    logger.info("\n3. Secure Key Storage")
    logger.info("-" * 70)
    import tempfile

    demo_storage_path = Path(tempfile.gettempdir()) / "ama_keys_demo"
    demo_password = secrets.token_urlsafe(24)
    storage = SecureKeyStorage(demo_storage_path, master_password=demo_password)

    # Store a key
    test_key = secrets.token_bytes(32)
    storage.store_key("master-key-001", test_key, metadata={"purpose": "signing"})
    logger.info("✓ Key stored securely")

    # Retrieve key — demo-only equality check on a freshly-generated key.
    retrieved_key = storage.retrieve_key("master-key-001")
    logger.info(
        f"✓ Key retrieved: {retrieved_key == test_key}"  # nosemgrep: non-constant-time-comparison -- demo-only equality check on freshly-generated key in __main__ block (KM-004)
    )

    logger.info("\n" + "=" * 70)
    logger.info("✓ Key Management System operational")
    logger.info("=" * 70)
