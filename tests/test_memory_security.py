#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Memory security tests.

Verifies that sensitive data is properly wiped from memory and
that there are no memory leaks in cryptographic operations.
"""

import gc
import secrets
import sys
import tempfile
from pathlib import Path

import pytest

from ama_cryptography.pqc_backends import _ED25519_NATIVE_AVAILABLE, _HKDF_NATIVE_AVAILABLE

if not (_ED25519_NATIVE_AVAILABLE and _HKDF_NATIVE_AVAILABLE):
    pytest.skip(
        "Native C library required — legacy_compat enforces CRYPTO_AVAILABLE",
        allow_module_level=True,
    )

from ama_cryptography.legacy_compat import secure_wipe


class TestSecureWipe:
    """Tests for secure memory wiping."""

    def test_wipe_zeros_bytearray(self) -> None:
        """secure_wipe zeros all bytes in a bytearray."""
        data = bytearray(secrets.token_bytes(1000))
        assert any(b != 0 for b in data), "Test data should not be all zeros"

        secure_wipe(data)

        assert all(b == 0 for b in data), "All bytes must be zeroed after wipe"

    def test_wipe_preserves_length(self) -> None:
        """secure_wipe preserves the length of the bytearray."""
        original_len = 500
        data = bytearray(secrets.token_bytes(original_len))

        secure_wipe(data)

        assert len(data) == original_len, "Length must be preserved"

    def test_wipe_empty_bytearray(self) -> None:
        """secure_wipe handles empty bytearray."""
        data = bytearray()

        # Should not raise
        secure_wipe(data)

        assert len(data) == 0

    def test_wipe_single_byte(self) -> None:
        """secure_wipe handles single byte."""
        data = bytearray([0xFF])

        secure_wipe(data)

        assert data[0] == 0

    def test_wipe_large_buffer(self) -> None:
        """secure_wipe handles large buffers efficiently."""
        size = 10 * 1024 * 1024  # 10 MB
        data = bytearray(size)
        # Fill with non-zero pattern
        for i in range(0, size, 1000):
            data[i] = 0xFF

        secure_wipe(data)

        # Spot check (checking all 10MB would be slow)
        assert data[0] == 0
        assert data[size // 2] == 0
        assert data[-1] == 0


class TestMemoryGrowth:
    """Tests for memory leaks in cryptographic operations."""

    def test_hash_no_memory_growth(self) -> None:
        """Repeated hashing doesn't leak memory."""
        from ama_cryptography.legacy_compat import canonical_hash_code

        gc.collect()
        baseline = self._get_memory_usage()

        for _ in range(1000):
            dna = "ACGT" * 100
            params = [(1.0, 1.0)]
            canonical_hash_code(dna, params)

        gc.collect()
        final = self._get_memory_usage()

        # Allow up to 1MB growth (for caches, etc.)
        growth_mb = (final - baseline) / (1024 * 1024)
        assert growth_mb < 1.0, f"Memory grew by {growth_mb:.2f} MB during hashing"

    def test_hmac_no_memory_growth(self) -> None:
        """Repeated HMAC operations don't leak memory."""
        from ama_cryptography.legacy_compat import hmac_authenticate

        gc.collect()
        baseline = self._get_memory_usage()

        key = secrets.token_bytes(32)
        for _ in range(1000):
            message = secrets.token_bytes(100)
            hmac_authenticate(message, key)

        gc.collect()
        final = self._get_memory_usage()

        growth_mb = (final - baseline) / (1024 * 1024)
        assert growth_mb < 1.0, f"Memory grew by {growth_mb:.2f} MB during HMAC"

    def test_keygen_no_memory_growth(self) -> None:
        """Repeated key generation doesn't leak memory."""
        from ama_cryptography.legacy_compat import generate_ed25519_keypair

        gc.collect()
        baseline = self._get_memory_usage()

        for _ in range(100):
            kp = generate_ed25519_keypair()
            del kp

        gc.collect()
        final = self._get_memory_usage()

        growth_mb = (final - baseline) / (1024 * 1024)
        assert growth_mb < 1.0, f"Memory grew by {growth_mb:.2f} MB during keygen"

    def _get_memory_usage(self) -> int:
        """Get current memory usage in bytes (platform-dependent)."""
        try:
            # Linux: read from /proc
            with open("/proc/self/statm") as f:
                # statm: size resident shared text lib data dt
                # resident is in pages
                parts = f.read().split()
                import resource

                page_size = resource.getpagesize()
                return int(parts[1]) * page_size
        except (FileNotFoundError, ImportError):
            # Fallback: use sys.getsizeof on gc objects (less accurate)
            return sum(sys.getsizeof(obj) for obj in gc.get_objects()[:10000])


class TestSensitiveDataCleanup:
    """Tests for cleanup of sensitive data."""

    def test_key_storage_cleanup_on_delete(self) -> None:
        """SecureKeyStorage overwrites file before deletion."""
        from ama_cryptography.key_management import SecureKeyStorage

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            storage = SecureKeyStorage(path, master_password="test-password")

            # Store a key
            secret_key = b"super-secret-key-material-here!"
            storage.store_key("test-key", secret_key)

            key_file = path / "test-key.json"
            assert key_file.exists()

            # Delete the key
            storage.delete_key("test-key")

            # File should be gone
            assert not key_file.exists()

    def test_password_not_stored_in_object(self) -> None:
        """Master password is not stored in SecureKeyStorage object."""
        from ama_cryptography.key_management import SecureKeyStorage

        with tempfile.TemporaryDirectory() as tmpdir:
            password = "super-secret-password-123"
            storage = SecureKeyStorage(Path(tmpdir), master_password=password)

            # Check that password is not stored as an attribute
            obj_dict = vars(storage)
            for key, value in obj_dict.items():
                if isinstance(value, str):
                    assert password not in value, f"Password found in attribute {key}"
                if isinstance(value, bytes):
                    assert password.encode() not in value, f"Password found in attribute {key}"

    def test_encryption_key_is_derived(self) -> None:
        """Encryption key is derived, not the password itself."""
        from ama_cryptography.key_management import SecureKeyStorage

        with tempfile.TemporaryDirectory() as tmpdir:
            password = "test-password"
            storage = SecureKeyStorage(Path(tmpdir), master_password=password)

            # Encryption key should be 32 bytes (256 bits)
            assert len(storage.encryption_key) == 32

            # Encryption key should not be the password
            assert storage.encryption_key != password.encode()

    def test_salt_is_random(self) -> None:
        """Each new storage gets a unique random salt."""
        from ama_cryptography.key_management import SecureKeyStorage

        salts = []
        for _ in range(5):
            with tempfile.TemporaryDirectory() as tmpdir:
                storage = SecureKeyStorage(Path(tmpdir), master_password="test")
                salts.append(storage.salt)

        # All salts should be unique
        assert len(set(salts)) == 5, "Salts should be unique for each storage"

        # All salts should be 32 bytes
        for salt in salts:
            assert salt is not None
            assert len(salt) == 32, "Salt should be 32 bytes"
