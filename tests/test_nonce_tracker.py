"""Tests for AES-GCM nonce counter safety and fork detection."""

import os
from unittest.mock import patch

import pytest


class TestAESGCMForkDetection:
    """Test that AESGCMProvider detects fork() and refuses to reuse nonce state."""

    def test_encrypt_after_fork_raises(self) -> None:
        """Simulate fork by changing os.getpid() return value."""
        try:
            from ama_cryptography.crypto_api import AESGCMProvider
        except RuntimeError:
            pytest.skip("AES-GCM native backend not available")

        provider = AESGCMProvider()
        key = os.urandom(32)

        # First encrypt should work
        result = provider.encrypt(b"test data", key)
        assert "ciphertext" in result

        # Simulate fork: change the PID
        original_pid = provider._pid_at_init
        provider._pid_at_init = original_pid + 99999  # different from current

        # Now encrypt should fail because PIDs don't match
        # But we need to reverse the logic: _pid_at_init was set at init,
        # and we check os.getpid() != self._pid_at_init
        # So we need os.getpid() to return something different
        provider._pid_at_init = original_pid  # restore
        with patch("ama_cryptography.crypto_api.os.getpid", return_value=original_pid + 1):
            with pytest.raises(RuntimeError, match="fork"):
                provider.encrypt(b"test data", key)

    def test_encrypt_same_pid_works(self) -> None:
        """Encrypt should work normally when PID matches."""
        try:
            from ama_cryptography.crypto_api import AESGCMProvider
        except RuntimeError:
            pytest.skip("AES-GCM native backend not available")

        provider = AESGCMProvider()
        key = os.urandom(32)
        result = provider.encrypt(b"hello", key)
        assert result["ciphertext"] is not None
        assert result["tag"] is not None
        assert result["nonce"] is not None

    def test_pid_at_init_is_set(self) -> None:
        """Verify _pid_at_init is set during construction."""
        try:
            from ama_cryptography.crypto_api import AESGCMProvider
        except RuntimeError:
            pytest.skip("AES-GCM native backend not available")

        provider = AESGCMProvider()
        assert provider._pid_at_init == os.getpid()


class TestAESGCMNonceCounter:
    """Test nonce counter tracking and safety limits."""

    def test_nonce_counter_increments(self) -> None:
        try:
            from ama_cryptography.crypto_api import AESGCMProvider
        except RuntimeError:
            pytest.skip("AES-GCM native backend not available")

        provider = AESGCMProvider()
        AESGCMProvider._ephemeral = True  # Don't persist to disk
        key = os.urandom(32)

        import hashlib

        key_id = hashlib.sha256(key).digest()
        initial = AESGCMProvider._encrypt_counters.get(key_id, 0)

        provider.encrypt(b"data1", key)
        assert AESGCMProvider._encrypt_counters[key_id] == initial + 1

        provider.encrypt(b"data2", key)
        assert AESGCMProvider._encrypt_counters[key_id] == initial + 2

        AESGCMProvider._ephemeral = False  # Restore

    def test_key_validation(self) -> None:
        try:
            from ama_cryptography.crypto_api import AESGCMProvider
        except RuntimeError:
            pytest.skip("AES-GCM native backend not available")

        provider = AESGCMProvider()
        with pytest.raises(ValueError, match="32 bytes"):
            provider.encrypt(b"data", b"short_key")

    def test_nonce_validation(self) -> None:
        try:
            from ama_cryptography.crypto_api import AESGCMProvider
        except RuntimeError:
            pytest.skip("AES-GCM native backend not available")

        provider = AESGCMProvider()
        key = os.urandom(32)
        with pytest.raises(ValueError, match="12 bytes"):
            provider.encrypt(b"data", key, nonce=b"short")

    def test_decrypt_roundtrip(self) -> None:
        try:
            from ama_cryptography.crypto_api import AESGCMProvider
        except RuntimeError:
            pytest.skip("AES-GCM native backend not available")

        provider = AESGCMProvider()
        key = os.urandom(32)
        plaintext = b"Round trip test data"

        enc = provider.encrypt(plaintext, key)
        dec = provider.decrypt(enc["ciphertext"], key, enc["nonce"], enc["tag"], enc["aad"])
        assert dec == plaintext

    def test_tampered_ciphertext_fails(self) -> None:
        try:
            from ama_cryptography.crypto_api import AESGCMProvider
        except RuntimeError:
            pytest.skip("AES-GCM native backend not available")

        provider = AESGCMProvider()
        key = os.urandom(32)
        enc = provider.encrypt(b"secret", key)

        tampered = bytearray(enc["ciphertext"])
        tampered[0] ^= 0xFF
        with pytest.raises((ValueError, RuntimeError)):
            provider.decrypt(bytes(tampered), key, enc["nonce"], enc["tag"])
