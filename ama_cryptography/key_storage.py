#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography - Encrypted Key Storage
==========================================

Provides encrypted-at-rest key storage using:
- PBKDF2-HMAC-SHA256 for wrapping key derivation
- AES-256-GCM for encrypting stored keys
- Integration with KeyMetadata and key lifecycle system

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
"""

import hashlib
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
try:
    from ama_cryptography.pqc_backends import (
        _AES_GCM_NATIVE_AVAILABLE,
        _native_lib,
        native_aes256_gcm_decrypt,
        native_aes256_gcm_encrypt,
    )

    if _native_lib is not None and _AES_GCM_NATIVE_AVAILABLE:
        _HAS_NATIVE = True
except ImportError:
    logger.debug("Native PQC backend unavailable — key storage will use fallback")


def _pbkdf2_derive(passphrase: bytes, salt: bytes, iterations: int = 600_000) -> bytes:
    """Derive 32-byte key from passphrase using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", passphrase, salt, iterations, dklen=32)


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
    derived from a passphrase via PBKDF2-HMAC-SHA256.

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
            self._wrapping_key = _pbkdf2_derive(passphrase.encode("utf-8"), self._salt)
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
        """Load or create the salt file."""
        salt_path = self._store_path.parent / "keystore.salt"
        if salt_path.exists():
            return salt_path.read_bytes()
        salt = secrets.token_bytes(32)
        salt_path.write_bytes(salt)
        return salt

    def _load_store(self) -> None:
        """Load the encrypted keystore from disk."""
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
            with os.fdopen(fd, "w") as f:
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
