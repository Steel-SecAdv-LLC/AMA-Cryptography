#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Tests for the secure memory module (ama_cryptography.secure_memory).

Verifies:
- Memory zeroing functionality
- Memory locking raises NotImplementedError (libsodium removed)
- SecureBuffer context manager behavior
- Constant-time comparison
"""

import secrets
from typing import Any

import pytest


class TestSecureMemoryAvailability:
    """Tests for module availability and status."""

    def test_module_imports(self) -> None:
        """Module imports successfully."""
        from ama_cryptography import secure_memory

        # Should always have these functions
        assert hasattr(secure_memory, "secure_memzero")
        assert hasattr(secure_memory, "secure_mlock")
        assert hasattr(secure_memory, "secure_munlock")
        assert hasattr(secure_memory, "constant_time_compare")
        assert hasattr(secure_memory, "SecureBuffer")
        assert hasattr(secure_memory, "is_available")
        assert hasattr(secure_memory, "get_status")

    def test_is_available_returns_true(self) -> None:
        """is_available() returns True (stdlib implementation always available)."""
        from ama_cryptography.secure_memory import is_available

        result = is_available()
        assert result is True

    def test_get_status_returns_dict(self) -> None:
        """get_status() returns status dictionary."""
        from ama_cryptography.secure_memory import get_status

        status = get_status()
        assert isinstance(status, dict)
        assert status["available"] is True
        assert status["backend"] == "stdlib"
        assert status["initialized"] is True
        assert status["mlock_available"] is False


class TestSecureMemzero:
    """Tests for secure_memzero function."""

    def test_zeros_bytearray(self) -> None:
        """secure_memzero zeros all bytes in a bytearray."""
        from ama_cryptography.secure_memory import secure_memzero

        data = bytearray(secrets.token_bytes(1000))
        assert any(b != 0 for b in data), "Test data should not be all zeros"

        secure_memzero(data)

        assert all(b == 0 for b in data), "All bytes must be zeroed"

    def test_zeros_memoryview(self) -> None:
        """secure_memzero works with memoryview."""
        from ama_cryptography.secure_memory import secure_memzero

        data = bytearray(100)
        for i in range(len(data)):
            data[i] = 0xFF

        mv = memoryview(data)
        secure_memzero(mv)

        assert all(b == 0 for b in data)

    def test_handles_empty_buffer(self) -> None:
        """secure_memzero handles empty buffer."""
        from ama_cryptography.secure_memory import secure_memzero

        data = bytearray()
        secure_memzero(data)  # Should not raise
        assert len(data) == 0

    def test_preserves_length(self) -> None:
        """secure_memzero preserves buffer length."""
        from ama_cryptography.secure_memory import secure_memzero

        original_len = 500
        data = bytearray(secrets.token_bytes(original_len))

        secure_memzero(data)

        assert len(data) == original_len

    def test_rejects_immutable_bytes(self) -> None:
        """secure_memzero rejects immutable bytes."""
        from ama_cryptography.secure_memory import secure_memzero

        data: Any = b"immutable"
        with pytest.raises(TypeError):
            secure_memzero(data)

    def test_large_buffer(self) -> None:
        """secure_memzero handles large buffers."""
        from ama_cryptography.secure_memory import secure_memzero

        size = 1024 * 1024  # 1 MB
        data = bytearray(size)
        for i in range(0, size, 1000):
            data[i] = 0xFF

        secure_memzero(data)

        # Spot check
        assert data[0] == 0
        assert data[size // 2] == 0
        assert data[-1] == 0


class TestSecureMlock:
    """Tests for memory locking functionality (raises NotImplementedError)."""

    def test_mlock_raises_not_implemented(self) -> None:
        """secure_mlock raises NotImplementedError (libsodium removed)."""
        from ama_cryptography.secure_memory import secure_mlock

        data = bytearray(4096)
        with pytest.raises(NotImplementedError):
            secure_mlock(data)

    def test_munlock_raises_not_implemented(self) -> None:
        """secure_munlock raises NotImplementedError (libsodium removed)."""
        from ama_cryptography.secure_memory import secure_munlock

        data = bytearray(4096)
        with pytest.raises(NotImplementedError):
            secure_munlock(data)


class TestConstantTimeCompare:
    """Tests for constant-time comparison."""

    def test_equal_strings(self) -> None:
        """constant_time_compare returns True for equal bytes."""
        from ama_cryptography.secure_memory import constant_time_compare

        a = b"secret password"
        b = b"secret password"

        assert constant_time_compare(a, b) is True

    def test_unequal_strings(self) -> None:
        """constant_time_compare returns False for different bytes."""
        from ama_cryptography.secure_memory import constant_time_compare

        a = b"secret password"
        b = b"secret Password"  # Different case

        assert constant_time_compare(a, b) is False

    def test_different_lengths(self) -> None:
        """constant_time_compare returns False for different lengths."""
        from ama_cryptography.secure_memory import constant_time_compare

        a = b"short"
        b = b"longer string"

        assert constant_time_compare(a, b) is False

    def test_empty_strings(self) -> None:
        """constant_time_compare handles empty bytes."""
        from ama_cryptography.secure_memory import constant_time_compare

        assert constant_time_compare(b"", b"") is True
        assert constant_time_compare(b"", b"x") is False

    def test_random_bytes(self) -> None:
        """constant_time_compare works with random bytes."""
        from ama_cryptography.secure_memory import constant_time_compare

        a = secrets.token_bytes(32)
        b = secrets.token_bytes(32)

        # Different random bytes should not match
        assert constant_time_compare(a, b) is False

        # Same bytes should match
        assert constant_time_compare(a, a) is True


class TestSecureBuffer:
    """Tests for SecureBuffer context manager."""

    def test_basic_usage(self) -> None:
        """SecureBuffer can be used as context manager."""
        from ama_cryptography.secure_memory import SecureBuffer

        with SecureBuffer(32) as buf:
            assert len(buf) == 32
            buf[:] = secrets.token_bytes(32)

    def test_buffer_zeroed_on_exit(self) -> None:
        """SecureBuffer zeros data on context exit."""
        from ama_cryptography.secure_memory import SecureBuffer

        buffer_ref = None

        with SecureBuffer(100) as buf:
            buf[:] = b"x" * 100
            buffer_ref = buf

        # After exit, buffer should be zeroed
        assert all(b == 0 for b in buffer_ref)

    def test_access_outside_context_raises(self) -> None:
        """Accessing SecureBuffer.data outside context raises."""
        from ama_cryptography.secure_memory import SecureBuffer

        sb = SecureBuffer(32)

        with pytest.raises(RuntimeError):
            _ = sb.data  # Not in context

    def test_size_property(self) -> None:
        """SecureBuffer.size returns correct size."""
        from ama_cryptography.secure_memory import SecureBuffer

        sb = SecureBuffer(64)
        assert sb.size == 64

    def test_locked_property_always_false(self) -> None:
        """SecureBuffer.locked is always False (no libsodium)."""
        from ama_cryptography.secure_memory import SecureBuffer

        sb = SecureBuffer(32)
        assert sb.locked is False

    def test_negative_size_raises(self) -> None:
        """SecureBuffer with negative size raises ValueError."""
        from ama_cryptography.secure_memory import SecureBuffer

        with pytest.raises(ValueError):
            SecureBuffer(-1)

    def test_zero_size(self) -> None:
        """SecureBuffer with zero size works."""
        from ama_cryptography.secure_memory import SecureBuffer

        with SecureBuffer(0) as buf:
            assert len(buf) == 0

    def test_exception_still_zeros(self) -> None:
        """SecureBuffer zeros data even if exception occurs."""
        from ama_cryptography.secure_memory import SecureBuffer

        buffer_ref = None

        try:
            with SecureBuffer(50) as buf:
                buf[:] = b"sensitive" + b"\x00" * 41
                buffer_ref = buf
                raise ValueError("Test exception")
        except ValueError:
            pass

        # buf was zeroed by SecureBuffer.__exit__; buffer_ref is the same object
        assert buffer_ref is not None
        assert all(b == 0 for b in buffer_ref)


class TestSecureBufferFunction:
    """Tests for secure_buffer() context manager function."""

    def test_basic_usage(self) -> None:
        """secure_buffer() can be used as context manager."""
        from ama_cryptography.secure_memory import secure_buffer

        with secure_buffer(32) as buf:
            assert len(buf) == 32
            buf[:] = secrets.token_bytes(32)

    def test_buffer_zeroed_on_exit(self) -> None:
        """secure_buffer() zeros data on exit."""
        from ama_cryptography.secure_memory import secure_buffer

        buffer_ref = None

        with secure_buffer(100) as buf:
            buf[:] = b"x" * 100
            buffer_ref = buf

        assert all(b == 0 for b in buffer_ref)


class TestSecureRandomBytes:
    """Tests for secure random bytes generation."""

    def test_generates_correct_length(self) -> None:
        """secure_random_bytes generates correct length."""
        from ama_cryptography.secure_memory import secure_random_bytes

        for size in [0, 1, 16, 32, 100, 1000]:
            result = secure_random_bytes(size)
            assert len(result) == size

    def test_returns_bytes(self) -> None:
        """secure_random_bytes returns bytes type."""
        from ama_cryptography.secure_memory import secure_random_bytes

        result = secure_random_bytes(32)
        assert isinstance(result, bytes)

    def test_different_each_call(self) -> None:
        """secure_random_bytes returns different values each call."""
        from ama_cryptography.secure_memory import secure_random_bytes

        results = [secure_random_bytes(32) for _ in range(10)]
        # All should be unique (with overwhelming probability)
        assert len(set(results)) == 10

    def test_negative_size_raises(self) -> None:
        """secure_random_bytes with negative size raises ValueError."""
        from ama_cryptography.secure_memory import secure_random_bytes

        with pytest.raises(ValueError):
            secure_random_bytes(-1)


class TestPlatformCompatibility:
    """Tests for cross-platform compatibility."""

    def test_works_on_current_platform(self) -> None:
        """Module works on current platform."""
        from ama_cryptography.secure_memory import (
            SecureBuffer,
            constant_time_compare,
            get_status,
            secure_memzero,
            secure_random_bytes,
        )

        # All basic operations should work
        status = get_status()
        assert status is not None
        assert status["available"] is True

        data = bytearray(32)
        secure_memzero(data)
        assert all(b == 0 for b in data)

        assert constant_time_compare(b"test", b"test")
        assert not constant_time_compare(b"test", b"Test")

        rand = secure_random_bytes(16)
        assert len(rand) == 16

        with SecureBuffer(32) as buf:
            buf[:] = rand + rand
            assert len(buf) == 32
