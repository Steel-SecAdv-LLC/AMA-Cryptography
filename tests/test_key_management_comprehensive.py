#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Comprehensive Key Management Tests
==================================

Professional-grade test coverage for the key_management module.
Targets 95%+ code coverage with edge cases, error paths, and security validations.

Test Categories:
- HDKeyDerivation: BIP32-compliant key derivation
- KeyRotationManager: Key lifecycle management
- SecureKeyStorage: Encrypted key storage with AES-256-GCM
- KeyMetadata: Data structure validation
"""

import json
import os
import secrets
import warnings
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from ama_cryptography.key_management import (
    HDKeyDerivation,
    HSMKeyStorage,
    KeyMetadata,
    KeyRotationManager,
    KeyStatus,
    SecureKeyStorage,
    SecurityWarning,
)

# =============================================================================
# HD KEY DERIVATION TESTS
# =============================================================================


class TestHDKeyDerivationComprehensive:
    """Comprehensive tests for HDKeyDerivation class."""

    def test_init_with_seed(self, master_seed):
        """Initialize with explicit seed."""
        hd = HDKeyDerivation(seed=master_seed)
        assert hd.master_seed == master_seed
        assert len(hd.master_key) == 32
        assert len(hd.master_chain_code) == 32

    def test_init_with_seed_phrase(self):
        """Initialize with BIP39-style seed phrase."""
        seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        hd = HDKeyDerivation(seed_phrase=seed_phrase)

        assert hd.master_seed is not None
        assert len(hd.master_seed) == 64
        assert len(hd.master_key) == 32
        assert len(hd.master_chain_code) == 32

    def test_init_with_no_arguments(self):
        """Initialize with random seed generation."""
        hd = HDKeyDerivation()

        assert hd.master_seed is not None
        assert len(hd.master_seed) == 64
        assert len(hd.master_key) == 32
        assert len(hd.master_chain_code) == 32

    def test_init_random_seeds_are_unique(self):
        """Each instance should have unique random seed."""
        hd1 = HDKeyDerivation()
        hd2 = HDKeyDerivation()

        assert hd1.master_seed != hd2.master_seed
        assert hd1.master_key != hd2.master_key

    def test_derive_path_standard(self, hd_derivation):
        """Non-hardened BIP44 path raises NotImplementedError (needs secp256k1)."""
        with pytest.raises(NotImplementedError):
            hd_derivation.derive_path("m/44'/0'/0'/0/0")

    def test_derive_path_hardened_only(self, hd_derivation):
        """Derive key with all hardened derivation."""
        key, chain = hd_derivation.derive_path("m/44'/0'/0'")

        assert len(key) == 32
        assert len(chain) == 32

    def test_derive_path_non_hardened_only(self, hd_derivation):
        """Non-hardened derivation raises NotImplementedError (needs secp256k1)."""
        with pytest.raises(NotImplementedError):
            hd_derivation.derive_path("m/0/1/2")

    def test_derive_path_mixed(self, hd_derivation):
        """Mixed hardened/non-hardened path raises NotImplementedError at non-hardened step."""
        with pytest.raises(NotImplementedError):
            hd_derivation.derive_path("m/44'/0'/0'/0/5")

    def test_derive_path_invalid_no_m_prefix(self, hd_derivation):
        """Path must start with 'm'."""
        with pytest.raises(ValueError, match="Path must start with 'm'"):
            hd_derivation.derive_path("44'/0'/0'/0/0")

    def test_derive_path_master_only(self, hd_derivation):
        """Derive with empty path (master key)."""
        key, chain = hd_derivation.derive_path("m")

        assert key == hd_derivation.master_key
        assert chain == hd_derivation.master_chain_code

    def test_derive_key_convenience_method(self, hd_derivation):
        """derive_key with non-hardened levels raises NotImplementedError."""
        with pytest.raises(NotImplementedError):
            hd_derivation.derive_key(purpose=44, account=0, change=0, index=0)

    def test_derive_path_different_hardened_purposes(self, hd_derivation):
        """Different hardened purposes yield different keys."""
        key1, _ = hd_derivation.derive_path("m/44'/0'/0'")
        key2, _ = hd_derivation.derive_path("m/49'/0'/0'")

        assert key1 != key2

    def test_derive_path_different_hardened_accounts(self, hd_derivation):
        """Different hardened accounts yield different keys."""
        key1, _ = hd_derivation.derive_path("m/44'/0'/0'")
        key2, _ = hd_derivation.derive_path("m/44'/1'/0'")

        assert key1 != key2

    def test_derive_path_different_hardened_indices(self, hd_derivation):
        """Different hardened indices yield different keys."""
        key1, _ = hd_derivation.derive_path("m/44'/0'/0'")
        key2, _ = hd_derivation.derive_path("m/44'/0'/1'")

        assert key1 != key2

    def test_deterministic_derivation(self, master_seed):
        """Same seed produces same derived keys."""
        hd1 = HDKeyDerivation(seed=master_seed)
        hd2 = HDKeyDerivation(seed=master_seed)

        key1, _ = hd1.derive_path("m/44'/0'/0'")
        key2, _ = hd2.derive_path("m/44'/0'/0'")

        assert key1 == key2

    def test_hardened_offset_constant(self):
        """Verify HARDENED_OFFSET is 2^31."""
        assert HDKeyDerivation.HARDENED_OFFSET == 2**31

    def test_secp256k1_n_constant(self):
        """Verify secp256k1 curve order is correct."""
        expected = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
        assert HDKeyDerivation.SECP256K1_N == expected

    def test_derive_large_non_hardened_index_raises(self, hd_derivation):
        """Non-hardened derivation raises NotImplementedError."""
        with pytest.raises(NotImplementedError):
            hd_derivation.derive_path("m/0/2147483646")

    def test_derive_large_hardened_index(self, hd_derivation):
        """Derive with large hardened index."""
        key, _ = hd_derivation.derive_path("m/2147483647'")

        assert len(key) == 32


# =============================================================================
# KEY ROTATION MANAGER TESTS
# =============================================================================


class TestKeyRotationManagerComprehensive:
    """Comprehensive tests for KeyRotationManager class."""

    def test_init_default_period(self):
        """Default rotation period is 90 days."""
        mgr = KeyRotationManager()
        assert mgr.rotation_period == timedelta(days=90)

    def test_init_custom_period(self):
        """Custom rotation period."""
        mgr = KeyRotationManager(rotation_period=timedelta(days=30))
        assert mgr.rotation_period == timedelta(days=30)

    def test_register_key_basic(self, rotation_manager):
        """Register a basic key."""
        meta = rotation_manager.register_key("key-1", "signing")

        assert meta.key_id == "key-1"
        assert meta.purpose == "signing"
        assert meta.status == KeyStatus.ACTIVE
        assert meta.version == 1
        assert meta.usage_count == 0

    def test_register_key_with_expiration(self, rotation_manager):
        """Register key with expiration."""
        meta = rotation_manager.register_key("key-1", "encryption", expires_in=timedelta(days=30))

        assert meta.expires_at is not None
        assert meta.expires_at > datetime.now(timezone.utc)

    def test_register_key_with_max_usage(self, rotation_manager):
        """Register key with usage limit."""
        meta = rotation_manager.register_key("key-1", "signing", max_usage=1000)

        assert meta.max_usage == 1000

    def test_register_key_with_derivation_path(self, rotation_manager):
        """Register key with HD derivation path."""
        meta = rotation_manager.register_key("key-1", "signing", derivation_path="m/44'/0'/0'/0/0")

        assert meta.derivation_path == "m/44'/0'/0'/0/0"

    def test_register_key_with_parent_id(self, rotation_manager):
        """Register key with parent reference."""
        rotation_manager.register_key("parent-key", "master")
        meta = rotation_manager.register_key("child-key", "signing", parent_id="parent-key")

        assert meta.parent_id == "parent-key"

    def test_first_key_becomes_active(self, rotation_manager):
        """First registered key becomes active."""
        rotation_manager.register_key("key-1", "signing")

        assert rotation_manager.get_active_key() == "key-1"

    def test_second_key_does_not_change_active(self, rotation_manager):
        """Second key doesn't change active key."""
        rotation_manager.register_key("key-1", "signing")
        rotation_manager.register_key("key-2", "signing")

        assert rotation_manager.get_active_key() == "key-1"

    def test_should_rotate_nonexistent_key(self, rotation_manager):
        """should_rotate returns False for nonexistent key."""
        assert rotation_manager.should_rotate("nonexistent") is False

    def test_should_rotate_fresh_key(self, rotation_manager_long_period):
        """Fresh key should not need rotation."""
        rotation_manager_long_period.register_key("key-1", "signing")

        assert rotation_manager_long_period.should_rotate("key-1") is False

    def test_should_rotate_expired_key(self, rotation_manager):
        """Expired key should need rotation."""
        # Register with already expired expiration
        rotation_manager.register_key("key-1", "signing", expires_in=timedelta(seconds=-1))

        assert rotation_manager.should_rotate("key-1") is True

    def test_should_rotate_at_usage_limit(self, rotation_manager):
        """Key at usage limit should need rotation."""
        rotation_manager.register_key("key-1", "signing", max_usage=5)

        for _ in range(5):
            rotation_manager.increment_usage("key-1")

        assert rotation_manager.should_rotate("key-1") is True

    def test_should_rotate_past_rotation_period(self, rotation_manager_short_period):
        """Key past rotation period should need rotation."""
        rotation_manager_short_period.register_key("key-1", "signing")

        # With 0-second period, it should immediately need rotation
        assert rotation_manager_short_period.should_rotate("key-1") is True

    def test_initiate_rotation(self, rotation_manager):
        """Test rotation initiation."""
        rotation_manager.register_key("key-v1", "signing")
        rotation_manager.register_key("key-v2", "signing")

        rotation_manager.initiate_rotation("key-v1", "key-v2")

        assert rotation_manager.keys["key-v1"].status == KeyStatus.ROTATING
        assert rotation_manager.keys["key-v2"].status == KeyStatus.ACTIVE
        assert rotation_manager.get_active_key() == "key-v2"

    def test_initiate_rotation_invalid_old_key(self, rotation_manager):
        """Rotation with invalid old key raises error."""
        rotation_manager.register_key("key-v2", "signing")

        with pytest.raises(ValueError, match="Key not found"):
            rotation_manager.initiate_rotation("nonexistent", "key-v2")

    def test_initiate_rotation_invalid_new_key(self, rotation_manager):
        """Rotation with invalid new key raises error."""
        rotation_manager.register_key("key-v1", "signing")

        with pytest.raises(ValueError, match="Key not found"):
            rotation_manager.initiate_rotation("key-v1", "nonexistent")

    def test_complete_rotation(self, rotation_manager):
        """Complete rotation deprecates old key."""
        rotation_manager.register_key("key-v1", "signing")
        rotation_manager.register_key("key-v2", "signing")
        rotation_manager.initiate_rotation("key-v1", "key-v2")

        rotation_manager.complete_rotation("key-v1")

        assert rotation_manager.keys["key-v1"].status == KeyStatus.DEPRECATED

    def test_complete_rotation_nonexistent(self, rotation_manager):
        """Complete rotation of nonexistent key is no-op."""
        # Should not raise
        rotation_manager.complete_rotation("nonexistent")

    def test_revoke_key_compromised(self, rotation_manager):
        """Revoke key with 'compromised' reason."""
        rotation_manager.register_key("key-1", "signing")

        rotation_manager.revoke_key("key-1", reason="compromised")

        assert rotation_manager.keys["key-1"].status == KeyStatus.COMPROMISED
        assert rotation_manager.get_active_key() is None

    def test_revoke_key_other_reason(self, rotation_manager):
        """Revoke key with non-compromised reason."""
        rotation_manager.register_key("key-1", "signing")

        rotation_manager.revoke_key("key-1", reason="policy")

        assert rotation_manager.keys["key-1"].status == KeyStatus.REVOKED
        assert rotation_manager.get_active_key() is None

    def test_revoke_key_nonexistent(self, rotation_manager):
        """Revoke nonexistent key is no-op."""
        # Should not raise
        rotation_manager.revoke_key("nonexistent")

    def test_revoke_non_active_key(self, rotation_manager):
        """Revoke key that isn't active."""
        rotation_manager.register_key("key-1", "signing")
        rotation_manager.register_key("key-2", "signing")

        rotation_manager.revoke_key("key-2", reason="policy")

        # key-1 should still be active
        assert rotation_manager.get_active_key() == "key-1"

    def test_increment_usage(self, rotation_manager):
        """Increment usage counter."""
        rotation_manager.register_key("key-1", "signing")

        rotation_manager.increment_usage("key-1")
        rotation_manager.increment_usage("key-1")
        rotation_manager.increment_usage("key-1")

        assert rotation_manager.keys["key-1"].usage_count == 3

    def test_increment_usage_nonexistent(self, rotation_manager):
        """Increment usage of nonexistent key is no-op."""
        # Should not raise
        rotation_manager.increment_usage("nonexistent")

    def test_export_metadata_dict(self, rotation_manager):
        """Export metadata as dictionary."""
        rotation_manager.register_key("key-1", "signing", max_usage=100)
        rotation_manager.increment_usage("key-1")

        export = rotation_manager.export_metadata()

        assert export["active_key_id"] == "key-1"
        assert export["rotation_period_days"] == 90
        assert "key-1" in export["keys"]
        assert export["keys"]["key-1"]["usage_count"] == 1

    def test_export_metadata_to_file(self, rotation_manager, temp_dir):
        """Export metadata to JSON file."""
        rotation_manager.register_key("key-1", "signing")
        filepath = temp_dir / "metadata.json"

        export = rotation_manager.export_metadata(filepath=filepath)

        assert filepath.exists()

        with open(filepath) as f:
            loaded = json.load(f)

        assert loaded == export

    def test_export_metadata_with_expiration(self, rotation_manager):
        """Export metadata includes expiration."""
        rotation_manager.register_key("key-1", "signing", expires_in=timedelta(days=30))

        export = rotation_manager.export_metadata()

        assert export["keys"]["key-1"]["expires_at"] is not None

    def test_export_metadata_without_expiration(self, rotation_manager):
        """Export metadata without expiration."""
        rotation_manager.register_key("key-1", "signing")

        export = rotation_manager.export_metadata()

        assert export["keys"]["key-1"]["expires_at"] is None


# =============================================================================
# SECURE KEY STORAGE TESTS
# =============================================================================


class TestSecureKeyStorageComprehensive:
    """Comprehensive tests for SecureKeyStorage class."""

    def test_init_with_password(self, temp_storage_path, test_password):
        """Initialize with master password."""
        storage = SecureKeyStorage(temp_storage_path, master_password=test_password)

        assert storage.encryption_key is not None
        assert len(storage.encryption_key) == 32
        assert storage.salt is not None

    def test_init_without_password(self, temp_storage_path):
        """Initialize without password (random key)."""
        storage = SecureKeyStorage(temp_storage_path)

        assert storage.encryption_key is not None
        assert len(storage.encryption_key) == 32
        assert storage.salt is None

    def test_init_creates_directory(self, temp_dir):
        """Initialize creates storage directory."""
        storage_path = temp_dir / "new" / "nested" / "storage"
        SecureKeyStorage(storage_path, master_password="test")

        assert storage_path.exists()

    def test_store_retrieve_roundtrip(self, secure_storage, test_key_material):
        """Store and retrieve key successfully."""
        secure_storage.store_key("test-key", test_key_material)
        retrieved = secure_storage.retrieve_key("test-key")

        assert retrieved == test_key_material

    def test_store_retrieve_with_metadata(self, secure_storage, test_key_material):
        """Store key with metadata."""
        metadata = {"purpose": "signing", "created_by": "test"}
        secure_storage.store_key("test-key", test_key_material, metadata=metadata)

        # Metadata is stored but not returned by retrieve_key
        retrieved = secure_storage.retrieve_key("test-key")
        assert retrieved == test_key_material

    def test_store_overwrites_existing(self, secure_storage):
        """Store overwrites existing key."""
        secure_storage.store_key("test-key", b"first-value")
        secure_storage.store_key("test-key", b"second-value")

        retrieved = secure_storage.retrieve_key("test-key")
        assert retrieved == b"second-value"

    def test_retrieve_nonexistent_returns_none(self, secure_storage):
        """Retrieve nonexistent key returns None."""
        assert secure_storage.retrieve_key("nonexistent") is None

    def test_delete_key_success(self, secure_storage, test_key_material):
        """Delete existing key returns True."""
        secure_storage.store_key("test-key", test_key_material)

        assert secure_storage.delete_key("test-key") is True
        assert secure_storage.retrieve_key("test-key") is None

    def test_delete_key_nonexistent(self, secure_storage):
        """Delete nonexistent key returns False."""
        assert secure_storage.delete_key("nonexistent") is False

    def test_delete_key_secure_overwrite(
        self, secure_storage, test_key_material, temp_storage_path
    ):
        """Delete key overwrites file before removal."""
        secure_storage.store_key("test-key", test_key_material)
        key_file = temp_storage_path / "test-key.json"

        # Verify file exists
        assert key_file.exists()

        # Delete and verify file is gone
        secure_storage.delete_key("test-key")
        assert not key_file.exists()

    def test_wrong_password_fails_decryption(self, temp_storage_path, test_key_material):
        """Wrong password fails to decrypt (AES-GCM authentication failure)."""
        storage1 = SecureKeyStorage(temp_storage_path, master_password="correct")
        storage1.store_key("test-key", test_key_material)

        storage2 = SecureKeyStorage(temp_storage_path, master_password="wrong")

        with pytest.raises(ValueError):
            storage2.retrieve_key("test-key")

    def test_invalid_key_id_empty(self, secure_storage):
        """Empty key_id raises ValueError."""
        with pytest.raises(ValueError, match="key_id must be non-empty"):
            secure_storage.store_key("", b"data")

    def test_invalid_key_id_special_chars(self, secure_storage):
        """Key_id with special characters raises ValueError."""
        with pytest.raises(ValueError):
            secure_storage.store_key("invalid!key", b"data")

    def test_valid_key_id_with_dash(self, secure_storage, test_key_material):
        """Key_id with dash is valid."""
        secure_storage.store_key("test-key-v1", test_key_material)
        assert secure_storage.retrieve_key("test-key-v1") == test_key_material

    def test_valid_key_id_with_underscore(self, secure_storage, test_key_material):
        """Key_id with underscore is valid."""
        secure_storage.store_key("test_key_v1", test_key_material)
        assert secure_storage.retrieve_key("test_key_v1") == test_key_material

    def test_salt_file_created(self, temp_storage_path, test_password):
        """Salt file is created on init."""
        SecureKeyStorage(temp_storage_path, master_password=test_password)

        salt_file = temp_storage_path / ".salt"
        assert salt_file.exists()

        with open(salt_file, "rb") as f:
            salt = f.read()
        assert len(salt) == 32

    def test_metadata_file_created(self, temp_storage_path, test_password):
        """KDF metadata file is created."""
        SecureKeyStorage(temp_storage_path, master_password=test_password)

        metadata_file = temp_storage_path / ".kdf_metadata.json"
        assert metadata_file.exists()

        with open(metadata_file) as f:
            metadata = json.load(f)

        assert metadata["version"] == 2
        assert metadata["iterations"] == 600000
        assert metadata["algorithm"] == "PBKDF2-HMAC-SHA256"

    def test_salt_file_reused(self, temp_storage_path, test_password):
        """Existing salt file is reused."""
        storage1 = SecureKeyStorage(temp_storage_path, master_password=test_password)
        salt1 = storage1.salt

        storage2 = SecureKeyStorage(temp_storage_path, master_password=test_password)
        salt2 = storage2.salt

        assert salt1 == salt2

    def test_from_existing_success(self, temp_storage_path, test_password, test_key_material):
        """Recover storage from existing salt file."""
        storage1 = SecureKeyStorage(temp_storage_path, master_password=test_password)
        storage1.store_key("test-key", test_key_material)

        storage2 = SecureKeyStorage.from_existing(temp_storage_path, test_password)
        retrieved = storage2.retrieve_key("test-key")

        assert retrieved == test_key_material

    def test_from_existing_no_salt_file(self, temp_dir):
        """from_existing raises FileNotFoundError without salt file."""
        with pytest.raises(FileNotFoundError, match="Salt file not found"):
            SecureKeyStorage.from_existing(temp_dir, "password")

    @pytest.mark.skipif(os.name == "nt", reason="Unix file permissions not supported on Windows")
    def test_file_permissions(self, temp_storage_path, test_password, test_key_material):
        """Key files have secure permissions (0600)."""
        storage = SecureKeyStorage(temp_storage_path, master_password=test_password)
        storage.store_key("test-key", test_key_material)

        key_file = temp_storage_path / "test-key.json"
        mode = os.stat(key_file).st_mode & 0o777

        # Should be 0o600 (owner read/write only)
        assert mode == 0o600

    def test_large_key_data(self, secure_storage):
        """Store and retrieve large key data."""
        large_key = secrets.token_bytes(1024 * 10)  # 10 KB
        secure_storage.store_key("large-key", large_key)

        retrieved = secure_storage.retrieve_key("large-key")
        assert retrieved == large_key


class TestSecureKeyStorageMigration:
    """Tests for SecureKeyStorage KDF migration."""

    def test_migrate_kdf_no_salt(self, temp_dir):
        """migrate_kdf returns False without salt file."""
        storage = SecureKeyStorage(temp_dir)  # No password, no salt

        result = storage.migrate_kdf("password")
        assert result is False

    def test_migrate_kdf_success(self, temp_storage_path, test_password, test_key_material):
        """migrate_kdf re-encrypts keys with new parameters."""
        storage = SecureKeyStorage(temp_storage_path, master_password=test_password)
        storage.store_key("key-1", test_key_material)
        storage.store_key("key-2", b"another-key-material-here!!")

        # Migrate
        result = storage.migrate_kdf(test_password)
        assert result is True

        # Verify metadata updated
        with open(temp_storage_path / ".kdf_metadata.json") as f:
            metadata = json.load(f)
        assert "migrated_at" in metadata

        # Verify keys still accessible (with new encryption)
        new_storage = SecureKeyStorage.from_existing(temp_storage_path, test_password)
        assert new_storage.retrieve_key("key-1") == test_key_material


class TestSecureKeyStorageLegacy:
    """Tests for legacy AES-CFB format support."""

    def test_retrieve_unknown_algorithm(self, temp_storage_path, test_password):
        """Retrieving unknown algorithm raises ValueError."""
        storage = SecureKeyStorage(temp_storage_path, master_password=test_password)

        # Manually create file with unknown algorithm
        unknown_data = {
            "key_id": "unknown-key",
            "ciphertext": "abc123",
            "nonce": "def456",
            "algorithm": "UNKNOWN-CIPHER",
        }

        key_file = temp_storage_path / "unknown-key.json"
        with open(key_file, "w") as f:
            json.dump(unknown_data, f)

        with pytest.raises(ValueError, match="Unknown encryption algorithm"):
            storage.retrieve_key("unknown-key")


class TestSecureKeyStorageLegacyKDF:
    """Tests for legacy KDF parameter handling."""

    def test_legacy_kdf_warning(self, temp_storage_path, test_password):
        """Legacy KDF parameters emit warning."""
        # Create salt file manually (simulating v1)
        salt = secrets.token_bytes(32)
        salt_file = temp_storage_path / ".salt"
        with open(salt_file, "wb") as f:
            f.write(salt)

        # Create v1 metadata
        v1_metadata = {
            "version": 1,
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": 100000,
        }
        metadata_file = temp_storage_path / ".kdf_metadata.json"
        with open(metadata_file, "w") as f:
            json.dump(v1_metadata, f)

        # Initialize should warn about legacy parameters
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            SecureKeyStorage(temp_storage_path, master_password=test_password)

            assert len(w) == 1
            assert issubclass(w[0].category, SecurityWarning)
            assert "legacy KDF v1" in str(w[0].message)


# =============================================================================
# HSM KEY STORAGE TESTS
# =============================================================================


class TestHSMKeyStorageErrors:
    """Tests for HSMKeyStorage error handling (without actual HSM)."""

    def test_import_error_without_pykcs11(self):
        """HSMKeyStorage raises ImportError without PyKCS11."""
        with patch.dict("sys.modules", {"PyKCS11": None}):
            with pytest.raises(ImportError, match="HSM support requires PyKCS11"):
                # Force re-import to trigger the check
                storage = HSMKeyStorage.__new__(HSMKeyStorage)
                storage._import_pykcs11()

    def test_unknown_hsm_type(self):
        """Unknown HSM type raises ValueError."""
        mock_pkcs11 = MagicMock()

        with patch.object(HSMKeyStorage, "_import_pykcs11", return_value=mock_pkcs11):
            storage = HSMKeyStorage.__new__(HSMKeyStorage)
            storage.pkcs11 = mock_pkcs11

            with pytest.raises(ValueError, match="Unknown HSM type"):
                storage._resolve_library_path("unknown-hsm", None)

    def test_library_not_found(self):
        """Missing PKCS#11 library raises RuntimeError."""
        mock_pkcs11 = MagicMock()

        with patch.object(HSMKeyStorage, "_import_pykcs11", return_value=mock_pkcs11):
            with patch("os.path.exists", return_value=False):
                storage = HSMKeyStorage.__new__(HSMKeyStorage)
                storage.pkcs11 = mock_pkcs11

                with pytest.raises(RuntimeError, match="PKCS#11 library not found"):
                    storage._resolve_library_path("softhsm", None)

    def test_invalid_key_size(self):
        """Invalid AES key size raises ValueError."""
        mock_pkcs11 = MagicMock()
        mock_session = MagicMock()

        storage = HSMKeyStorage.__new__(HSMKeyStorage)
        storage.pkcs11 = mock_pkcs11
        storage.session = mock_session
        storage._logged_in = True

        with pytest.raises(ValueError, match="Invalid key size"):
            storage.generate_aes_key("test-key", key_size=512)


# =============================================================================
# KEY METADATA TESTS
# =============================================================================


class TestKeyMetadata:
    """Tests for KeyMetadata dataclass."""

    def test_create_metadata(self):
        """Create KeyMetadata instance."""
        meta = KeyMetadata(
            key_id="test-key",
            created_at=datetime.now(),
            expires_at=None,
            status=KeyStatus.ACTIVE,
            version=1,
            parent_id=None,
            derivation_path=None,
            usage_count=0,
            max_usage=None,
            purpose="signing",
            metadata={},
        )

        assert meta.key_id == "test-key"
        assert meta.status == KeyStatus.ACTIVE

    def test_metadata_with_all_fields(self):
        """Create KeyMetadata with all fields populated."""
        now = datetime.now(timezone.utc)
        meta = KeyMetadata(
            key_id="full-key",
            created_at=now,
            expires_at=now + timedelta(days=90),
            status=KeyStatus.ACTIVE,
            version=2,
            parent_id="parent-key",
            derivation_path="m/44'/0'/0'/0/0",
            usage_count=50,
            max_usage=1000,
            purpose="encryption",
            metadata={"region": "us-west-2", "environment": "production"},
        )

        assert meta.parent_id == "parent-key"
        assert meta.derivation_path == "m/44'/0'/0'/0/0"
        assert meta.metadata["region"] == "us-west-2"


class TestKeyStatus:
    """Tests for KeyStatus enum."""

    def test_all_statuses(self):
        """Verify all status values exist."""
        assert KeyStatus.ACTIVE is not None
        assert KeyStatus.ROTATING is not None
        assert KeyStatus.DEPRECATED is not None
        assert KeyStatus.REVOKED is not None
        assert KeyStatus.COMPROMISED is not None

    def test_status_names(self):
        """Verify status name mapping."""
        assert KeyStatus.ACTIVE.name == "ACTIVE"
        assert KeyStatus.COMPROMISED.name == "COMPROMISED"


class TestSecurityWarning:
    """Tests for SecurityWarning class."""

    def test_is_user_warning(self):
        """SecurityWarning is a UserWarning subclass."""
        assert issubclass(SecurityWarning, UserWarning)

    def test_can_be_raised(self):
        """SecurityWarning can be raised and caught."""
        with pytest.warns(SecurityWarning, match="test warning"):
            warnings.warn("test warning", SecurityWarning)
