#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography - Encrypted Key Storage
==========================================

Provides encrypted-at-rest key storage using:
- Argon2id (RFC 9106) for wrapping key derivation via native C backend
- AES-256-GCM for encrypting stored keys
- Integration with KeyMetadata and key lifecycle system

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
"""

import json
import logging
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Try to import native C library for Argon2id and AES-GCM
_HAS_NATIVE = False
_HAS_ARGON2 = False

from ama_cryptography.pqc_backends import (
    _AES_GCM_NATIVE_AVAILABLE,
    _ARGON2_NATIVE_AVAILABLE,
    _native_lib,
    native_aes256_gcm_decrypt,
    native_aes256_gcm_encrypt,
    native_argon2id,
)

if _native_lib is not None and _AES_GCM_NATIVE_AVAILABLE:
    _HAS_NATIVE = True
if _native_lib is not None and _ARGON2_NATIVE_AVAILABLE:
    _HAS_ARGON2 = True


def _kdf_derive(passphrase: bytes, salt: bytes) -> bytes:
    """Derive 32-byte wrapping key from passphrase using native Argon2id (RFC 9106).

    INVARIANT-1 compliance: uses AMA's own native Argon2id implementation
    instead of stdlib hashlib.pbkdf2_hmac (which internally uses OpenSSL HMAC).
    """
    if not _HAS_ARGON2:
        raise RuntimeError(
            "Argon2id native backend required for key storage KDF. "
            "Build with: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )
    return native_argon2id(
        password=passphrase,
        salt=salt,
        t_cost=3,
        m_cost=65536,
        parallelism=4,
        out_len=32,
    )


def _encrypt_data(key: bytes, plaintext: bytes, aad: bytes = b"") -> Dict[str, bytes]:
    """Encrypt data with AES-256-GCM."""
    nonce = secrets.token_bytes(12)
    if _HAS_NATIVE:
        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, aad)
        return {"ciphertext": ct, "nonce": nonce, "tag": tag, "aad": aad}

    # Pure Python fallback using hashlib-based construction
    # (Not recommended for production — prefer building with native C)
    raise RuntimeError(
        "AES-256-GCM native backend required for key storage. "
        "Build with: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
    )


def _decrypt_data(
    key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes, aad: bytes = b""
) -> bytes:
    """Decrypt data with AES-256-GCM."""
    if _HAS_NATIVE:
        return native_aes256_gcm_decrypt(key, nonce, ciphertext, tag, aad)
    raise RuntimeError("AES-256-GCM native backend required for key storage.")


@dataclass
class StoredKey:
    """A key entry in the encrypted keystore."""

    key_id: str
    key_material_encrypted: bytes
    nonce: bytes
    tag: bytes
    purpose: str
    created_at: float
    metadata: Dict[str, Any]


class EncryptedKeyStore:
    """
    Encrypted keystore on disk.

    Keys at rest are encrypted with AES-256-GCM using a wrapping key
    derived from a passphrase via Argon2id (RFC 9106).

    File format: JSON with base64-encoded encrypted fields.
    """

    def __init__(
        self,
        store_path: Optional[str] = None,
        passphrase: Optional[str] = None,
    ) -> None:
        """
        Args:
            store_path: Path to the keystore file.
                Defaults to ~/.ama_cryptography/keystore.enc
            passphrase: Passphrase for deriving the wrapping key.
                If None, a random key is generated (non-persistent).
        """
        if store_path is None:
            data_dir = Path.home() / ".ama_cryptography"
            data_dir.mkdir(parents=True, exist_ok=True)
            self._store_path = data_dir / "keystore.enc"
        else:
            self._store_path = Path(store_path)
            self._store_path.parent.mkdir(parents=True, exist_ok=True)

        # Derive wrapping key
        if passphrase is not None:
            self._salt = self._load_or_create_salt()
            self._wrapping_key = _kdf_derive(passphrase.encode("utf-8"), self._salt)
        else:
            self._salt = secrets.token_bytes(32)
            self._wrapping_key = secrets.token_bytes(32)

        self._ephemeral = passphrase is None
        self._keys: Dict[str, Dict[str, Any]] = {}
        # Only load persisted store when a passphrase was provided — ephemeral
        # random keys cannot decrypt an existing store.
        if not self._ephemeral:
            self._load_store()

    def _load_or_create_salt(self) -> bytes:
        """Load or create the salt file atomically.

        Uses O_CREAT | O_EXCL to prevent TOCTOU races: if two processes
        attempt to create the salt simultaneously, only one succeeds (the
        exclusive-create winner writes the salt); the other receives
        FileExistsError and reads the winner's salt.  This guarantees all
        processes derive the same wrapping key for a given passphrase.
        """
        import os

        salt_path = self._store_path.parent / "keystore.salt"
        try:
            # Atomic exclusive create — fails if file already exists
            fd = os.open(str(salt_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                salt = secrets.token_bytes(32)
                os.write(fd, salt)
                os.fsync(fd)
            finally:
                os.close(fd)
            return salt
        except FileExistsError:
            # Another process created the salt first — read it.
            # Retry briefly in case the writer hasn't finished os.write() yet
            # (the file exists but may be empty/truncated for a few microseconds).
            import time as _time

            for _attempt in range(50):
                salt_data = salt_path.read_bytes()
                if len(salt_data) == 32:
                    return salt_data
                _time.sleep(0.01)
            raise RuntimeError(
                f"Salt file {salt_path} exists but contains {len(salt_data)} bytes "
                f"(expected 32). Another process may have crashed during creation."
            ) from None

    def _load_store(self) -> None:
        """Load the encrypted keystore from disk.

        After loading entries, validates the wrapping key by attempting to
        decrypt the first entry.  If decryption fails (wrong passphrase),
        clears the in-memory store and raises ``RuntimeError`` — preventing
        subsequent ``store_key()`` calls from mixing entries encrypted with
        different wrapping keys (which would silently corrupt the keystore).
        """
        if not self._store_path.exists():
            return
        try:
            import base64

            with open(self._store_path, "r") as f:
                data = json.load(f)
            for key_id, entry in data.get("keys", {}).items():
                self._keys[key_id] = {
                    "encrypted": base64.b64decode(entry["encrypted"]),
                    "nonce": base64.b64decode(entry["nonce"]),
                    "tag": base64.b64decode(entry["tag"]),
                    "purpose": entry.get("purpose", ""),
                    "created_at": entry.get("created_at", 0.0),
                    "metadata": entry.get("metadata", {}),
                }
        except FileNotFoundError:
            return
        except Exception as e:
            raise RuntimeError(f"Failed to load keystore from {self._store_path}: {e}") from e

        # Validate wrapping key against the first entry to detect wrong
        # passphrase BEFORE any store_key() call can mix entries encrypted
        # with different keys (silent corruption).
        if self._keys:
            first_key_id = next(iter(self._keys))
            first_entry = self._keys[first_key_id]
            aad = first_key_id.encode("utf-8")
            try:
                _decrypt_data(
                    self._wrapping_key,
                    first_entry["encrypted"],
                    first_entry["nonce"],
                    first_entry["tag"],
                    aad,
                )
            except (ValueError, RuntimeError) as e:
                self._keys.clear()
                raise RuntimeError(
                    f"Failed to validate wrapping key against existing keystore at "
                    f"{self._store_path}. The passphrase may be incorrect."
                ) from e

    def _save_store(self) -> None:
        """Save the encrypted keystore to disk using atomic write-rename.

        Skipped in ephemeral mode to prevent overwriting a persistent keystore
        with entries encrypted by a random (non-reproducible) wrapping key.
        """
        if self._ephemeral:
            return
        import base64
        import os
        import tempfile

        keys: dict[str, dict[str, object]] = {}
        for key_id, entry in self._keys.items():
            keys[key_id] = {
                "encrypted": base64.b64encode(entry["encrypted"]).decode(),
                "nonce": base64.b64encode(entry["nonce"]).decode(),
                "tag": base64.b64encode(entry["tag"]).decode(),
                "purpose": entry.get("purpose", ""),
                "created_at": entry.get("created_at", 0.0),
                "metadata": entry.get("metadata", {}),
            }
        data: dict[str, object] = {"version": 1, "keys": keys}
        # Atomic write: temp file + fsync + rename prevents data loss on crash
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._store_path.parent), suffix=".tmp", prefix=".keystore_"
        )
        try:
            f = os.fdopen(fd, "w")
        except BaseException:
            os.close(fd)
            try:
                os.unlink(tmp_path)
            except OSError:
                pass  # best-effort cleanup; don't mask the original fdopen error
            raise
        try:
            with f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, str(self._store_path))
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError as unlink_err:
                logger.debug("Failed to clean up temp keystore %s: %s", tmp_path, unlink_err)
            raise

    def store_key(
        self,
        key_id: str,
        key_material: bytes,
        purpose: str = "general",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Encrypt and store a key.

        Args:
            key_id: Unique key identifier
            key_material: Raw key bytes to encrypt and store
            purpose: Key purpose description
            metadata: Additional metadata
        """
        aad = key_id.encode("utf-8")
        result = _encrypt_data(self._wrapping_key, key_material, aad)
        self._keys[key_id] = {
            "encrypted": result["ciphertext"],
            "nonce": result["nonce"],
            "tag": result["tag"],
            "purpose": purpose,
            "created_at": time.time(),
            "metadata": metadata or {},
        }
        self._save_store()
        logger.info("Stored encrypted key: %s", key_id)

    def retrieve_key(self, key_id: str) -> Optional[bytes]:
        """
        Decrypt and retrieve a key.

        Args:
            key_id: Key identifier to retrieve

        Returns:
            Decrypted key material, or None if key not found
        """
        entry = self._keys.get(key_id)
        if entry is None:
            return None
        aad = key_id.encode("utf-8")
        return _decrypt_data(
            self._wrapping_key,
            entry["encrypted"],
            entry["nonce"],
            entry["tag"],
            aad,
        )

    def delete_key(self, key_id: str) -> bool:
        """Remove a key from the store."""
        if key_id in self._keys:
            del self._keys[key_id]
            self._save_store()
            return True
        return False

    def list_keys(self) -> List[Dict[str, Any]]:
        """List all stored key IDs and metadata (not key material)."""
        return [
            {
                "key_id": kid,
                "purpose": entry.get("purpose", ""),
                "created_at": entry.get("created_at", 0.0),
                "metadata": entry.get("metadata", {}),
            }
            for kid, entry in self._keys.items()
        ]
