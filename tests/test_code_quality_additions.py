#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Tests for Code Quality Additions
================================

Tests covering the code quality improvements made to ensure:
1. SecureMemoryError exception handling works correctly
2. Logging infrastructure is properly configured
3. Type annotations work correctly in key_management.py
4. All error paths are tested

Organization: Steel Security Advisors LLC
Date: 2026-03-08
Version: 2.0
"""

import importlib
import logging
import warnings
from unittest.mock import patch

import pytest

import ama_cryptography.secure_memory

# Check if native backends are available
try:
    from ama_cryptography.pqc_backends import (
        _AES_GCM_NATIVE_AVAILABLE,
        _SECP256K1_NATIVE_AVAILABLE,
        _native_lib,
    )

    _NATIVE_AES_GCM = _native_lib is not None and _AES_GCM_NATIVE_AVAILABLE
    _NATIVE_SECP256K1 = _native_lib is not None and _SECP256K1_NATIVE_AVAILABLE
except ImportError:
    _NATIVE_AES_GCM = False
    _NATIVE_SECP256K1 = False

skip_no_native_aes = pytest.mark.skipif(
    not _NATIVE_AES_GCM,
    reason="Native AES-256-GCM backend not available (build with cmake)",
)

skip_no_native_secp256k1 = pytest.mark.skipif(
    not _NATIVE_SECP256K1,
    reason="Native secp256k1 backend not available (build with cmake)",
)

# =============================================================================
# SECURE MEMORY ERROR HANDLING TESTS
# =============================================================================


class TestSecureMemoryErrorClasses:
    """Tests for SecureMemoryError exception classes."""

    def test_secure_memory_error_exists(self):
        """SecureMemoryError class is defined."""
        from ama_cryptography.secure_memory import SecureMemoryError

        assert issubclass(SecureMemoryError, Exception)

    def test_secure_memory_not_available_exists(self):
        """SecureMemoryNotAvailable class is defined."""
        from ama_cryptography.secure_memory import SecureMemoryError, SecureMemoryNotAvailable

        assert issubclass(SecureMemoryNotAvailable, SecureMemoryError)

    def test_secure_memory_error_can_be_raised(self):
        """SecureMemoryError can be raised and caught."""
        from ama_cryptography.secure_memory import SecureMemoryError

        with pytest.raises(SecureMemoryError, match="test error message"):
            raise SecureMemoryError("test error message")

    def test_secure_memory_not_available_can_be_raised(self):
        """SecureMemoryNotAvailable can be raised and caught."""
        from ama_cryptography.secure_memory import SecureMemoryNotAvailable

        with pytest.raises(SecureMemoryNotAvailable, match="pynacl"):
            raise SecureMemoryNotAvailable("pynacl not installed")

    def test_check_nacl_available_raises_when_unavailable(self):
        """_check_nacl_available raises when pynacl is unavailable."""
        from ama_cryptography.secure_memory import SecureMemoryNotAvailable

        # Temporarily mock _HAS_NACL to False
        with patch("ama_cryptography.secure_memory._HAS_NACL", False):
            from ama_cryptography.secure_memory import _check_nacl_available

            with pytest.raises(SecureMemoryNotAvailable):
                _check_nacl_available()


class TestSecureMemoryFallbackBehavior:
    """Tests for fallback behavior when pynacl is unavailable."""

    def test_secure_memzero_fallback_works(self):
        """secure_memzero works without pynacl (fallback mode)."""
        from ama_cryptography.secure_memory import _fallback_memzero

        data = bytearray(b"sensitive data here")
        _fallback_memzero(data)

        assert all(b == 0 for b in data)

    def test_fallback_memzero_multipass(self):
        """Fallback memzero performs multi-pass overwrite."""
        from ama_cryptography.secure_memory import _fallback_memzero

        # Create data and verify fallback zeros it
        data = bytearray(100)
        for i in range(len(data)):
            data[i] = 0xAB

        _fallback_memzero(data)

        # All bytes should be zero
        assert all(b == 0 for b in data)

    def test_mlock_without_nacl_returns_false(self):
        """secure_mlock returns False when pynacl unavailable."""
        with patch("ama_cryptography.secure_memory._HAS_NACL", False):
            # Need to reload to pick up the patched value
            importlib.reload(ama_cryptography.secure_memory)

            data = bytearray(100)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", RuntimeWarning)
                result = ama_cryptography.secure_memory.secure_mlock(data)

            assert result is False

            # Restore
            importlib.reload(ama_cryptography.secure_memory)

    def test_munlock_without_nacl_returns_false(self):
        """secure_munlock returns False when pynacl unavailable."""
        with patch("ama_cryptography.secure_memory._HAS_NACL", False):
            importlib.reload(ama_cryptography.secure_memory)

            data = bytearray(100)
            result = ama_cryptography.secure_memory.secure_munlock(data)

            assert result is False

            # Restore
            importlib.reload(ama_cryptography.secure_memory)


class TestSecureMemoryGetStatus:
    """Tests for get_status function."""

    def test_get_status_returns_all_keys(self):
        """get_status returns all expected keys."""
        from ama_cryptography.secure_memory import get_status

        status = get_status()

        assert "available" in status
        assert "backend" in status
        assert "initialized" in status
        assert "mlock_available" in status

    def test_get_status_backend_values(self):
        """get_status backend is either libsodium or fallback."""
        from ama_cryptography.secure_memory import get_status

        status = get_status()
        assert status["backend"] in ("libsodium", "fallback")

    def test_get_status_types(self):
        """get_status returns correct types."""
        from ama_cryptography.secure_memory import get_status

        status = get_status()

        assert isinstance(status["available"], bool)
        assert isinstance(status["backend"], str)
        assert isinstance(status["initialized"], bool)
        assert isinstance(status["mlock_available"], bool)


# =============================================================================
# LOGGING INFRASTRUCTURE TESTS
# =============================================================================


class TestLoggingInfrastructure:
    """Tests for logging infrastructure in modules."""

    def test_equations_has_logger(self):
        """equations module has logger configured."""
        from ama_cryptography import equations

        assert hasattr(equations, "logger")
        assert isinstance(equations.logger, logging.Logger)
        assert equations.logger.name == "ama_cryptography.equations"

    def test_double_helix_engine_has_logger(self):
        """double_helix_engine module has logger configured."""
        from ama_cryptography import double_helix_engine

        assert hasattr(double_helix_engine, "logger")
        assert isinstance(double_helix_engine.logger, logging.Logger)
        assert double_helix_engine.logger.name == "ama_cryptography.double_helix_engine"

    def test_key_management_has_logger(self):
        """key_management module has logger configured."""
        from ama_cryptography import key_management

        assert hasattr(key_management, "logger")
        assert isinstance(key_management.logger, logging.Logger)
        assert key_management.logger.name == "ama_cryptography.key_management"

    def test_logger_hierarchy(self):
        """All loggers are under ama_cryptography namespace."""
        from ama_cryptography import double_helix_engine, equations, key_management

        for module in [equations, double_helix_engine, key_management]:
            assert module.logger.name.startswith("ama_cryptography.")


class TestLoggingLevels:
    """Tests for logging level configuration."""

    def test_logger_can_log_info(self):
        """Loggers can log at INFO level."""
        from ama_cryptography import equations

        # Should not raise
        equations.logger.info("Test info message")

    def test_logger_can_log_warning(self):
        """Loggers can log at WARNING level."""
        from ama_cryptography import equations

        # Should not raise
        equations.logger.warning("Test warning message")

    def test_logger_can_log_error(self):
        """Loggers can log at ERROR level."""
        from ama_cryptography import equations

        # Should not raise
        equations.logger.error("Test error message")

    def test_logger_can_log_debug(self):
        """Loggers can log at DEBUG level."""
        from ama_cryptography import equations

        # Should not raise
        equations.logger.debug("Test debug message")


# =============================================================================
# KEY MANAGEMENT DECRYPT PATH TESTS
# =============================================================================


class TestKeyManagementDecryptPaths:
    """Tests for key_management.py decrypt functionality."""

    @pytest.fixture
    def temp_storage(self, tmp_path):
        """Create a temporary storage directory."""
        from ama_cryptography.key_management import SecureKeyStorage

        storage_path = tmp_path / "test_keys"
        storage = SecureKeyStorage(storage_path, master_password="test_password_123")
        return storage

    @skip_no_native_aes
    def test_store_and_retrieve_key(self, temp_storage):
        """Store and retrieve a key using AES-256-GCM."""
        import secrets

        key_data = secrets.token_bytes(32)
        key_id = "test-key-001"

        # Store
        temp_storage.store_key(key_id, key_data, metadata={"purpose": "testing"})

        # Retrieve
        retrieved = temp_storage.retrieve_key(key_id)

        assert retrieved == key_data
        assert isinstance(retrieved, bytes)

    @skip_no_native_aes
    def test_retrieve_returns_bytes_type(self, temp_storage):
        """Retrieved key is explicitly bytes type."""
        import secrets

        key_data = secrets.token_bytes(32)
        key_id = "test-key-bytes"

        temp_storage.store_key(key_id, key_data)
        retrieved = temp_storage.retrieve_key(key_id)

        # Type check - this tests our type annotation fix
        assert type(retrieved) is bytes

    def test_retrieve_nonexistent_key_returns_none(self, temp_storage):
        """Retrieving non-existent key returns None."""
        result = temp_storage.retrieve_key("nonexistent-key")
        assert result is None

    @skip_no_native_aes
    def test_store_multiple_keys(self, temp_storage):
        """Store and retrieve multiple keys."""
        import secrets

        keys = {
            "key-1": secrets.token_bytes(32),
            "key-2": secrets.token_bytes(64),
            "key-3": secrets.token_bytes(16),
        }

        for key_id, key_data in keys.items():
            temp_storage.store_key(key_id, key_data)

        for key_id, expected_data in keys.items():
            retrieved = temp_storage.retrieve_key(key_id)
            assert retrieved == expected_data

    @skip_no_native_aes
    def test_delete_key(self, temp_storage):
        """Delete a key removes it from storage."""
        import secrets

        key_data = secrets.token_bytes(32)
        key_id = "delete-test-key"

        temp_storage.store_key(key_id, key_data)
        assert temp_storage.retrieve_key(key_id) == key_data

        result = temp_storage.delete_key(key_id)
        assert result is True

        assert temp_storage.retrieve_key(key_id) is None

    def test_delete_nonexistent_key_returns_false(self, temp_storage):
        """Deleting non-existent key returns False."""
        result = temp_storage.delete_key("nonexistent")
        assert result is False

    @skip_no_native_aes
    def test_list_keys(self, temp_storage):
        """List all stored keys."""
        import secrets

        key_ids = ["list-key-1", "list-key-2", "list-key-3"]

        for key_id in key_ids:
            temp_storage.store_key(key_id, secrets.token_bytes(32))

        listed = temp_storage.list_keys()

        for key_id in key_ids:
            assert key_id in listed


class TestKeyManagementContextManager:
    """Tests for SecureKeyStorage context manager."""

    @skip_no_native_aes
    def test_context_manager_closes(self, tmp_path):
        """SecureKeyStorage context manager closes properly."""
        from ama_cryptography.key_management import SecureKeyStorage

        storage_path = tmp_path / "context_test"

        with SecureKeyStorage(storage_path, master_password="test123") as storage:
            storage.store_key("ctx-key", b"test data")

        # After exit, should have cleaned up
        # (Implementation detail - just verify no crash)


class TestHDKeyDerivation:
    """Tests for HD key derivation."""

    def test_derive_key_returns_bytes(self):
        """derive_path with hardened-only path returns bytes."""
        from ama_cryptography.key_management import HDKeyDerivation

        hd = HDKeyDerivation()
        key, _ = hd.derive_path("m/44'/0'/0'")

        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_different_indices_different_keys(self):
        """Different hardened indices produce different keys."""
        from ama_cryptography.key_management import HDKeyDerivation

        hd = HDKeyDerivation()
        key1, _ = hd.derive_path("m/44'/0'/0'")
        key2, _ = hd.derive_path("m/44'/0'/1'")

        assert key1 != key2

    @skip_no_native_secp256k1
    def test_non_hardened_derivation(self):
        """Non-hardened derivation works with native secp256k1."""
        from ama_cryptography.key_management import HDKeyDerivation

        hd = HDKeyDerivation()
        key, chain = hd.derive_path("m/44'/0'/0'/0/0")
        assert len(key) == 32
        assert len(chain) == 32

    def test_deterministic_derivation(self):
        """Same seed produces same keys."""
        from ama_cryptography.key_management import HDKeyDerivation

        seed = b"x" * 64

        hd1 = HDKeyDerivation(seed=seed)
        hd2 = HDKeyDerivation(seed=seed)

        key1, _ = hd1.derive_path("m/44'/0'/0'")
        key2, _ = hd2.derive_path("m/44'/0'/0'")

        assert key1 == key2


class TestKeyRotationManager:
    """Tests for key rotation manager."""

    def test_register_key(self):
        """Register a new key."""
        from datetime import timedelta

        from ama_cryptography.key_management import KeyRotationManager

        manager = KeyRotationManager(rotation_period=timedelta(days=90))
        metadata = manager.register_key("key-v1", "signing")

        assert metadata is not None
        assert metadata.key_id == "key-v1"
        assert metadata.purpose == "signing"

    def test_get_active_key(self):
        """Get the active key."""
        from datetime import timedelta

        from ama_cryptography.key_management import KeyRotationManager

        manager = KeyRotationManager(rotation_period=timedelta(days=90))
        manager.register_key("key-v1", "signing")

        active = manager.get_active_key()
        assert active == "key-v1"

    def test_should_rotate_new_key(self):
        """New key should not need rotation."""
        from datetime import timedelta

        from ama_cryptography.key_management import KeyRotationManager

        manager = KeyRotationManager(rotation_period=timedelta(days=90))
        manager.register_key("key-v1", "signing")

        assert manager.should_rotate("key-v1") is False

    def test_initiate_rotation(self):
        """Initiate key rotation."""
        from datetime import timedelta

        from ama_cryptography.key_management import KeyRotationManager

        manager = KeyRotationManager(rotation_period=timedelta(days=90))
        manager.register_key("key-v1", "signing")
        manager.register_key("key-v2", "signing")

        manager.initiate_rotation("key-v1", "key-v2")

        assert manager.get_active_key() == "key-v2"


# =============================================================================
# SECURE RANDOM BYTES TESTS
# =============================================================================


class TestSecureRandomBytes:
    """Additional tests for secure random bytes."""

    def test_zero_length(self):
        """Zero length returns empty bytes."""
        from ama_cryptography.secure_memory import secure_random_bytes

        result = secure_random_bytes(0)
        assert result == b""

    def test_large_size(self):
        """Can generate large random buffers."""
        from ama_cryptography.secure_memory import secure_random_bytes

        size = 1024 * 100  # 100 KB
        result = secure_random_bytes(size)

        assert len(result) == size
        assert isinstance(result, bytes)

    def test_entropy_quality(self):
        """Random bytes have reasonable entropy."""
        from ama_cryptography.secure_memory import secure_random_bytes

        data = secure_random_bytes(1000)

        # Check that not all bytes are the same (extremely unlikely for good RNG)
        unique_bytes = len(set(data))
        assert unique_bytes > 200  # Should have good distribution


# =============================================================================
# CONSTANT TIME COMPARE EDGE CASES
# =============================================================================


class TestConstantTimeCompareEdgeCases:
    """Edge case tests for constant time comparison."""

    def test_single_byte_equal(self):
        """Single byte comparison (equal)."""
        from ama_cryptography.secure_memory import constant_time_compare

        assert constant_time_compare(b"\x00", b"\x00") is True
        assert constant_time_compare(b"\xff", b"\xff") is True

    def test_single_byte_different(self):
        """Single byte comparison (different)."""
        from ama_cryptography.secure_memory import constant_time_compare

        assert constant_time_compare(b"\x00", b"\x01") is False
        assert constant_time_compare(b"\x00", b"\xff") is False

    def test_null_bytes(self):
        """Comparison with null bytes."""
        from ama_cryptography.secure_memory import constant_time_compare

        a = b"\x00" * 32
        b = b"\x00" * 32

        assert constant_time_compare(a, b) is True

    def test_high_bytes(self):
        """Comparison with high bytes."""
        from ama_cryptography.secure_memory import constant_time_compare

        a = b"\xff" * 32
        b = b"\xff" * 32

        assert constant_time_compare(a, b) is True

    def test_one_bit_difference(self):
        """Detects single bit difference."""
        from ama_cryptography.secure_memory import constant_time_compare

        a = b"\x00" * 31 + b"\x00"
        b = b"\x00" * 31 + b"\x01"

        assert constant_time_compare(a, b) is False


# =============================================================================
# MODULE EXPORTS TESTS
# =============================================================================


class TestModuleExports:
    """Tests for module __all__ exports."""

    def test_secure_memory_exports(self):
        """secure_memory exports all expected names."""
        from ama_cryptography import secure_memory

        expected_exports = [
            "SecureBuffer",
            "SecureMemoryError",
            "SecureMemoryNotAvailable",
            "constant_time_compare",
            "get_status",
            "is_available",
            "secure_buffer",
            "secure_memzero",
            "secure_mlock",
            "secure_munlock",
            "secure_random_bytes",
        ]

        for name in expected_exports:
            assert hasattr(secure_memory, name), f"Missing export: {name}"

    def test_key_management_exports(self):
        """key_management exports expected classes."""
        from ama_cryptography import key_management

        expected_exports = [
            "HDKeyDerivation",
            "KeyRotationManager",
            "SecureKeyStorage",
            "KeyMetadata",
            "KeyStatus",
        ]

        for name in expected_exports:
            assert hasattr(key_management, name), f"Missing export: {name}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
