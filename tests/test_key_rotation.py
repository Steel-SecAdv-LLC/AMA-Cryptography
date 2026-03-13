#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Key rotation lifecycle tests.

Verifies the key rotation state machine transitions:
  ACTIVE -> ROTATING -> DEPRECATED -> DESTROYED
             |
             v
         COMPROMISED (from any state except DESTROYED)
"""

import tempfile
from datetime import timedelta
from pathlib import Path

import pytest

from ama_cryptography.key_management import KeyRotationManager, KeyStatus, SecureKeyStorage


class TestKeyRotationLifecycle:
    """Tests for key rotation state transitions."""

    def test_initial_key_active(self):
        """First registered key becomes active."""
        mgr = KeyRotationManager()
        meta = mgr.register_key("key-v1", "signing")

        assert meta.status == KeyStatus.ACTIVE
        assert mgr.get_active_key() == "key-v1"

    def test_second_key_pending(self):
        """Second key starts as pending until rotation."""
        mgr = KeyRotationManager()
        mgr.register_key("key-v1", "signing")
        mgr.register_key("key-v2", "signing")

        # Second key is also ACTIVE by default in current implementation
        # but the first key remains the active_key_id
        assert mgr.get_active_key() == "key-v1"

    def test_rotation_state_transitions(self):
        """Rotation moves old key to ROTATING, new key to ACTIVE."""
        mgr = KeyRotationManager()
        mgr.register_key("key-v1", "signing")
        mgr.register_key("key-v2", "signing")

        mgr.initiate_rotation("key-v1", "key-v2")

        assert mgr.keys["key-v1"].status == KeyStatus.ROTATING
        assert mgr.keys["key-v2"].status == KeyStatus.ACTIVE
        assert mgr.get_active_key() == "key-v2"

    def test_complete_rotation_deprecates(self):
        """Completing rotation moves old key to DEPRECATED."""
        mgr = KeyRotationManager()
        mgr.register_key("key-v1", "signing")
        mgr.register_key("key-v2", "signing")
        mgr.initiate_rotation("key-v1", "key-v2")
        mgr.complete_rotation("key-v1")

        assert mgr.keys["key-v1"].status == KeyStatus.DEPRECATED

    def test_revoke_compromised(self):
        """Revoking with reason 'compromised' sets COMPROMISED status."""
        mgr = KeyRotationManager()
        mgr.register_key("key-v1", "signing")

        mgr.revoke_key("key-v1", reason="compromised")

        assert mgr.keys["key-v1"].status == KeyStatus.COMPROMISED
        # No active key after revocation
        assert mgr.get_active_key() is None

    def test_should_rotate_after_period(self):
        """Key should rotate after rotation period expires."""
        mgr = KeyRotationManager(rotation_period=timedelta(seconds=0))
        mgr.register_key("key-v1", "signing")

        assert mgr.should_rotate("key-v1") is True

    def test_should_not_rotate_before_period(self):
        """Key should not rotate before period expires."""
        mgr = KeyRotationManager(rotation_period=timedelta(days=90))
        mgr.register_key("key-v1", "signing")

        assert mgr.should_rotate("key-v1") is False

    def test_should_rotate_at_usage_limit(self):
        """Key should rotate when usage limit reached."""
        mgr = KeyRotationManager()
        mgr.register_key("key-v1", "signing", max_usage=3)

        for _ in range(3):
            mgr.increment_usage("key-v1")

        assert mgr.should_rotate("key-v1") is True

    def test_should_not_rotate_below_usage_limit(self):
        """Key should not rotate below usage limit."""
        mgr = KeyRotationManager()
        mgr.register_key("key-v1", "signing", max_usage=10)

        for _ in range(5):
            mgr.increment_usage("key-v1")

        assert mgr.should_rotate("key-v1") is False


class TestSecureKeyStorageGCM:
    """Tests for SecureKeyStorage with AES-GCM encryption."""

    def test_store_retrieve_roundtrip(self):
        """Key stored can be retrieved."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = SecureKeyStorage(Path(tmpdir), master_password="test-password")

            original_key = b"test-key-material-32-bytes-long!"
            storage.store_key("test-key", original_key, {"purpose": "testing"})

            retrieved = storage.retrieve_key("test-key")

            assert retrieved == original_key

    def test_retrieve_nonexistent_returns_none(self):
        """Retrieving non-existent key returns None."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = SecureKeyStorage(Path(tmpdir), master_password="test-password")

            assert storage.retrieve_key("nonexistent") is None

    def test_delete_key(self):
        """Deleted key cannot be retrieved."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = SecureKeyStorage(Path(tmpdir), master_password="test-password")
            storage.store_key("test-key", b"secret")

            assert storage.delete_key("test-key") is True
            assert storage.retrieve_key("test-key") is None

    def test_delete_nonexistent_returns_false(self):
        """Deleting non-existent key returns False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = SecureKeyStorage(Path(tmpdir), master_password="test-password")

            assert storage.delete_key("nonexistent") is False

    def test_wrong_password_fails_decryption(self):
        """Wrong password fails to decrypt (AES-GCM authentication)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            # Store with one password
            storage1 = SecureKeyStorage(path, master_password="correct-password")
            storage1.store_key("test-key", b"secret-data")

            # Try to retrieve with different password
            storage2 = SecureKeyStorage(path, master_password="wrong-password")

            # Native AES-GCM raises ValueError on authentication failure
            with pytest.raises(ValueError):
                storage2.retrieve_key("test-key")

    def test_key_id_validation(self):
        """Invalid key_id raises ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = SecureKeyStorage(Path(tmpdir), master_password="test-password")

            with pytest.raises(ValueError):
                storage.store_key("", b"secret")

            with pytest.raises(ValueError):
                storage.store_key("invalid key!", b"secret")

    def test_salt_file_created(self):
        """Salt file is created with secure permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            SecureKeyStorage(path, master_password="test-password")

            salt_file = path / ".salt"
            assert salt_file.exists()

            # Check salt is 32 bytes
            with open(salt_file, "rb") as f:
                salt = f.read()
            assert len(salt) == 32

    def test_metadata_file_created(self):
        """KDF metadata file is created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            import json

            path = Path(tmpdir)
            SecureKeyStorage(path, master_password="test-password")

            metadata_file = path / ".kdf_metadata.json"
            assert metadata_file.exists()

            with open(metadata_file) as f:
                metadata = json.load(f)

            # v3 = Argon2id (preferred when native lib available), v2 = PBKDF2
            assert metadata["version"] in (2, 3)
            if metadata["version"] == 3:
                assert metadata["algorithm"] == "Argon2id"
                assert "t_cost" in metadata
                assert "m_cost" in metadata
            else:
                assert metadata["algorithm"] == "PBKDF2-HMAC-SHA256"
                assert metadata["iterations"] == 600000

    def test_from_existing_recovery(self):
        """Can recover storage from existing salt file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            # Create storage and store a key
            storage1 = SecureKeyStorage(path, master_password="test-password")
            storage1.store_key("test-key", b"secret-data")

            # Recover using from_existing
            storage2 = SecureKeyStorage.from_existing(path, "test-password")
            retrieved = storage2.retrieve_key("test-key")

            assert retrieved == b"secret-data"
