#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography Key Management System
=====================================

Enterprise-grade key management with:
- Hierarchical Deterministic (HD) key derivation (BIP32-style)
- Key rotation with zero-downtime
- Secure key storage and retrieval
- Key versioning and lifecycle management
- Hardware-backed key support (HSM/TPM ready)
"""

import base64
import hashlib
import json
import logging
import os
import secrets
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from pathlib import Path
from types import TracebackType
from typing import Any, Dict, List, Optional, Tuple, Type

from ama_cryptography.exceptions import SecurityWarning  # noqa: F401 — re-exported for public API
from ama_cryptography.pqc_backends import _HMAC_SHA512_NATIVE_AVAILABLE, native_hmac_sha512
from ama_cryptography.secure_memory import secure_memzero

# INVARIANT-7: Detect native HMAC-SHA512 availability at module level.
_HMAC_SHA512_NATIVE = _HMAC_SHA512_NATIVE_AVAILABLE

if not _HMAC_SHA512_NATIVE:
    if os.environ.get("AMA_REQUIRE_CONSTANT_TIME", "").lower() in ("1", "true", "yes"):
        raise RuntimeError(
            "AMA_REQUIRE_CONSTANT_TIME is set but native HMAC-SHA512 C backend "
            "is unavailable. Cannot guarantee constant-time BIP32 key derivation. "
            "Either build the native C library or unset AMA_REQUIRE_CONSTANT_TIME."
        )
    logging.getLogger(__name__).warning(
        "native HMAC-SHA512 C backend unavailable; using pure-Python fallback "
        "for BIP32 key derivation without constant-time guarantees. Set "
        "AMA_REQUIRE_CONSTANT_TIME=true to enforce native-only execution."
    )


def _hmac_sha512(key: bytes, data: bytes) -> bytes:
    """
    HMAC-SHA-512 per RFC 2104.

    Primary: AMA native C library (ama_hmac_sha512).
    Fallback: pure-Python implementation using hashlib.sha512.
    Does NOT use the stdlib ``hmac`` module (INVARIANT-1).
    """
    if _HMAC_SHA512_NATIVE:
        try:
            result: bytes = native_hmac_sha512(key, data)
            return result
        except RuntimeError:
            pass  # native call failed at runtime; fall through to pure-Python below

    # Pure-Python HMAC-SHA512 (RFC 2104) — no stdlib hmac import.
    block_size = 128  # SHA-512 block size
    if len(key) > block_size:
        key = hashlib.sha512(key).digest()
    key = key.ljust(block_size, b"\x00")
    ipad = bytes(k ^ 0x36 for k in key)
    opad = bytes(k ^ 0x5C for k in key)
    inner = hashlib.sha512(ipad + data).digest()
    return hashlib.sha512(opad + inner).digest()


# Configure module logger
logger = logging.getLogger(__name__)


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
            # Derive seed from phrase (simplified BIP39)
            # seed_phrase is guaranteed non-None here: seed is None (from elif)
            # and not both None (from first if).
            assert seed_phrase is not None  # nosec B101 — mypy narrowing; always True here
            self.master_seed = hashlib.pbkdf2_hmac(
                "sha512", seed_phrase.encode("utf-8"), b"mnemonic", 2048, 64
            )

        # Generate master key
        self.master_key, self.master_chain_code = self._generate_master_key()

    def _generate_master_key(self) -> Tuple[bytes, bytes]:
        """Generate master key and chain code from seed"""
        hmac_result = _hmac_sha512(b"AMA Cryptography Master Key", self.master_seed)

        master_key = hmac_result[:32]
        chain_code = hmac_result[32:]

        return master_key, chain_code

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

    def __init__(self, storage_path: Path, master_password: Optional[str] = None) -> None:
        """
        Initialize secure storage

        Args:
            storage_path: Directory for key storage
            master_password: Master password for encryption
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

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

        # Salt file with secure permissions
        self.salt_file = self.storage_path / ".salt"
        self.metadata_file = self.storage_path / ".kdf_metadata.json"

        if master_password:
            self._derive_key_from_password(master_password)
        else:
            # Generate random encryption key (should be HSM-backed in production)
            self.encryption_key = bytearray(secrets.token_bytes(32))
            self.salt: Optional[bytes] = None  # No salt needed for random key

    def _derive_key_from_password(self, master_password: str) -> None:
        """Derive encryption key from password with proper salt handling."""
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

            # Save salt with secure permissions (0600)
            with open(self.salt_file, "wb") as f:
                f.write(self.salt)
            os.chmod(self.salt_file, 0o600)

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
                try:
                    with open(self.metadata_file, "r") as _f:
                        _meta = json.load(_f)
                    algorithm = _meta.get("algorithm")
                    if algorithm is not None and algorithm != "Argon2id":
                        raise RuntimeError(
                            f"Unsupported KDF algorithm for v{version} store: {algorithm}"
                        )
                    t_cost = int(_meta.get("t_cost", t_cost))
                    m_cost = int(_meta.get("m_cost", m_cost))
                    parallelism = int(_meta.get("parallelism", parallelism))
                except (OSError, ValueError, TypeError, KeyError) as _exc:
                    logger.warning(
                        "Could not read Argon2id params from %s, using defaults: %s",
                        self.metadata_file,
                        _exc,
                    )

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
            if key_data:
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

        # Re-encrypt all keys
        old_key = self.encryption_key
        self.encryption_key = new_encryption_key
        self.salt = new_salt

        try:
            for key_id, (key_data, metadata) in old_keys.items():
                self.store_key(key_id, key_data, metadata)

            # Update salt file
            with open(self.salt_file, "wb") as f:
                f.write(new_salt)
            os.chmod(self.salt_file, 0o600)

            # Update metadata
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
            with open(self.metadata_file, "w") as f:
                json.dump(metadata, f, indent=2)

            return True
        except Exception:
            # Rollback on failure
            self.encryption_key = old_key
            raise

    @classmethod
    def from_existing(cls, storage_path: Path, master_password: str) -> "SecureKeyStorage":
        """Recover storage instance from existing salt file."""
        storage = cls.__new__(cls)
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

        # Validate key_id
        if not key_id or not key_id.replace("-", "").replace("_", "").isalnum():
            raise ValueError("key_id must be non-empty alphanumeric (with - and _ allowed)")

        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM (NIST recommended)

        # Encrypt with key_id as associated data (binds ciphertext to key_id)
        # Convert bytearray to bytes for ctypes compatibility
        ct, tag = native_aes256_gcm_encrypt(
            bytes(self.encryption_key), nonce, key_data, key_id.encode("utf-8")
        )
        ciphertext = ct + tag  # Store as combined ct||tag for format compatibility

        storage_data = {
            "key_id": key_id,
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "algorithm": "AES-256-GCM",
            "version": 2,  # Storage format version
            "metadata": metadata or {},
            "stored_at": datetime.now(timezone.utc).isoformat(),
        }

        key_file = self.storage_path / f"{key_id}.json"
        with open(key_file, "w") as f:
            json.dump(storage_data, f, indent=2)
        os.chmod(key_file, 0o600)

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

            # Decrypt with authentication (raises ValueError if tampered)
            # Convert bytearray to bytes for ctypes compatibility
            plaintext: bytes = native_aes256_gcm_decrypt(
                bytes(self.encryption_key), nonce, ct, tag, key_id.encode("utf-8")
            )
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
        key_file = self.storage_path / f"{key_id}.json"
        if key_file.exists():
            # Overwrite file before deleting
            with open(key_file, "wb") as f:
                f.write(secrets.token_bytes(1024))
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
        pin: Optional[str] = None,  # nosec B107 — PIN is a parameter, not a hardcoded credential
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
            ImportError: If PyKCS11 is not installed
            ValueError: If HSM type is unknown
            RuntimeError: If token not found or login fails
        """
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
            raise ImportError(
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
                if info.label.strip() == token_label:
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
            key_ref = handle_int.to_bytes(8, "big")
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
                key_ref = handle_int.to_bytes(8, "big")
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
        nonce = secrets.token_bytes(12)
        handle = self._handle_map.get(key_handle, int.from_bytes(key_handle, "big"))

        try:
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
        self.close()


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

    logger.info(f"Signing key:    {signing_key.hex()[:32]}...")
    logger.info(f"Encryption key: {encryption_key.hex()[:32]}...")

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
    storage = SecureKeyStorage(
        demo_storage_path, master_password="test_password_123"
    )  # nosec B106 — demo-only hardcoded password, not used in production

    # Store a key
    test_key = secrets.token_bytes(32)
    storage.store_key("master-key-001", test_key, metadata={"purpose": "signing"})
    logger.info("✓ Key stored securely")

    # Retrieve key
    retrieved_key = storage.retrieve_key("master-key-001")
    logger.info(f"✓ Key retrieved: {retrieved_key == test_key}")

    logger.info("\n" + "=" * 70)
    logger.info("✓ Key Management System operational")
    logger.info("=" * 70)
