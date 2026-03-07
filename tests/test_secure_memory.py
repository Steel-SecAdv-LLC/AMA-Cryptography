#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Tests for the secure memory module (ama_cryptography.secure_memory).

Verifies:
- Memory zeroing functionality
- Memory locking (mlock) when available
- SecureBuffer context manager behavior
- Constant-time comparison
- Graceful fallback when pynacl is not available
"""

import platform
import secrets

import pytest


class TestSecureMemoryAvailability:
    """Tests for module availability and status."""

    def test_module_imports(self):
        """Module imports successfully regardless of pynacl availability."""
        from ama_cryptography import secure_memory

        # Should always have these functions
        assert hasattr(secure_memory, "secure_memzero")
        assert hasattr(secure_memory, "secure_mlock")
        assert hasattr(secure_memory, "secure_munlock")
        assert hasattr(secure_memory, "constant_time_compare")
        assert hasattr(secure_memory, "SecureBuffer")
        assert hasattr(secure_memory, "is_available")
        assert hasattr(secure_memory, "get_status")

    def test_is_available_returns_bool(self):
        """is_available() returns a boolean."""
        from ama_cryptography.secure_memory import is_available

        result = is_available()
        assert isinstance(result, bool)

    def test_get_status_returns_dict(self):
        """get_status() returns status dictionary."""
        from ama_cryptography.secure_memory import get_status

        status = get_status()
        assert isinstance(status, dict)
        assert "available" in status
        assert "backend" in status
        assert "initialized" in status
        assert status["backend"] in ("libsodium", "fallback")


class TestSecureMemzero:
    """Tests for secure_memzero function."""

    def test_zeros_bytearray(self):
        """secure_memzero zeros all bytes in a bytearray."""
        from ama_cryptography.secure_memory import secure_memzero

        data = bytearray(secrets.token_bytes(1000))
        assert any(b != 0 for b in data), "Test data should not be all zeros"

        secure_memzero(data)

        assert all(b == 0 for b in data), "All bytes must be zeroed"

    def test_zeros_memoryview(self):
        """secure_memzero works with memoryview."""
        from ama_cryptography.secure_memory import secure_memzero

        data = bytearray(100)
        for i in range(len(data)):
            data[i] = 0xFF

        mv = memoryview(data)
        secure_memzero(mv)

        assert all(b == 0 for b in data)

    def test_handles_empty_buffer(self):
        """secure_memzero handles empty buffer."""
        from ama_cryptography.secure_memory import secure_memzero

        data = bytearray()
        secure_memzero(data)  # Should not raise
        assert len(data) == 0

    def test_preserves_length(self):
        """secure_memzero preserves buffer length."""
        from ama_cryptography.secure_memory import secure_memzero

        original_len = 500
        data = bytearray(secrets.token_bytes(original_len))

        secure_memzero(data)

        assert len(data) == original_len

    def test_rejects_immutable_bytes(self):
        """secure_memzero rejects immutable bytes."""
        from ama_cryptography.secure_memory import secure_memzero

        data = b"immutable"
        with pytest.raises(TypeError):
            secure_memzero(data)

    def test_large_buffer(self):
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
    """Tests for memory locking functionality."""

    def test_mlock_returns_bool(self):
        """secure_mlock returns boolean indicating success or graceful fallback."""
        import warnings

        from ama_cryptography.secure_memory import secure_mlock

        data = bytearray(4096)

        # Suppress expected warning when pynacl mlock is unavailable
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            result = secure_mlock(data)

        assert isinstance(result, bool)

    def test_mlock_munlock_roundtrip(self):
        """Can lock and unlock memory without error."""
        import warnings

        from ama_cryptography.secure_memory import secure_mlock, secure_munlock

        data = bytearray(4096)

        # Suppress expected warning when pynacl mlock is unavailable
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            locked = secure_mlock(data)
            # Whether it succeeds depends on system limits
            # Just verify no crash

            if locked:
                secure_munlock(data)
                # May or may not succeed depending on implementation

    def test_mlock_empty_buffer(self):
        """secure_mlock handles empty buffer."""
        import warnings

        from ama_cryptography.secure_memory import secure_mlock

        data = bytearray()

        # Suppress expected warning when pynacl mlock is unavailable
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            result = secure_mlock(data)  # Should not raise

        assert isinstance(result, bool)


class TestConstantTimeCompare:
    """Tests for constant-time comparison."""

    def test_equal_strings(self):
        """constant_time_compare returns True for equal bytes."""
        from ama_cryptography.secure_memory import constant_time_compare

        a = b"secret password"
        b = b"secret password"

        assert constant_time_compare(a, b) is True

    def test_unequal_strings(self):
        """constant_time_compare returns False for different bytes."""
        from ama_cryptography.secure_memory import constant_time_compare

        a = b"secret password"
        b = b"secret Password"  # Different case

        assert constant_time_compare(a, b) is False

    def test_different_lengths(self):
        """constant_time_compare returns False for different lengths."""
        from ama_cryptography.secure_memory import constant_time_compare

        a = b"short"
        b = b"longer string"

        assert constant_time_compare(a, b) is False

    def test_empty_strings(self):
        """constant_time_compare handles empty bytes."""
        from ama_cryptography.secure_memory import constant_time_compare

        assert constant_time_compare(b"", b"") is True
        assert constant_time_compare(b"", b"x") is False

    def test_random_bytes(self):
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

    def test_basic_usage(self):
        """SecureBuffer can be used as context manager."""
        import warnings

        from ama_cryptography.secure_memory import SecureBuffer

        # Suppress expected warning when pynacl mlock is unavailable
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            with SecureBuffer(32) as buf:
                assert len(buf) == 32
                buf[:] = secrets.token_bytes(32)
                # Can use buffer within context

        # Buffer is zeroed after context exits

    def test_buffer_zeroed_on_exit(self):
        """SecureBuffer zeros data on context exit."""
        import warnings

        from ama_cryptography.secure_memory import SecureBuffer

        buffer_ref = None

        # Suppress expected warning when pynacl mlock is unavailable
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            with SecureBuffer(100) as buf:
                buf[:] = b"x" * 100
                buffer_ref = buf

        # After exit, buffer should be zeroed
        assert all(b == 0 for b in buffer_ref)

    def test_access_outside_context_raises(self):
        """Accessing SecureBuffer.data outside context raises."""
        from ama_cryptography.secure_memory import SecureBuffer

        sb = SecureBuffer(32)

        with pytest.raises(RuntimeError):
            _ = sb.data  # Not in context

    def test_size_property(self):
        """SecureBuffer.size returns correct size."""
        from ama_cryptography.secure_memory import SecureBuffer

        sb = SecureBuffer(64)
        assert sb.size == 64

    def test_negative_size_raises(self):
        """SecureBuffer with negative size raises ValueError."""
        from ama_cryptography.secure_memory import SecureBuffer

        with pytest.raises(ValueError):
            SecureBuffer(-1)

    def test_zero_size(self):
        """SecureBuffer with zero size works."""
        import warnings

        from ama_cryptography.secure_memory import SecureBuffer

        # Suppress expected warning when pynacl mlock is unavailable
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            with SecureBuffer(0) as buf:
                assert len(buf) == 0

    def test_exception_still_zeros(self):
        """SecureBuffer zeros data even if exception occurs."""
        import warnings

        from ama_cryptography.secure_memory import SecureBuffer

        buffer_ref = None

        # Suppress expected warning when pynacl mlock is unavailable
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            with pytest.raises(ValueError):
                with SecureBuffer(50) as buf:
                    buf[:] = b"sensitive" + b"\x00" * 41
                    buffer_ref = buf
                    raise ValueError("Test exception")

        # Should still be zeroed
        assert all(b == 0 for b in buffer_ref)


class TestSecureBufferFunction:
    """Tests for secure_buffer() context manager function."""

    def test_basic_usage(self):
        """secure_buffer() can be used as context manager."""
        import warnings

        from ama_cryptography.secure_memory import secure_buffer

        # Suppress expected warning when pynacl mlock is unavailable
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            with secure_buffer(32) as buf:
                assert len(buf) == 32
                buf[:] = secrets.token_bytes(32)

    def test_buffer_zeroed_on_exit(self):
        """secure_buffer() zeros data on exit."""
        import warnings

        from ama_cryptography.secure_memory import secure_buffer

        buffer_ref = None

        # Suppress expected warning when pynacl mlock is unavailable
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            with secure_buffer(100) as buf:
                buf[:] = b"x" * 100
                buffer_ref = buf

        assert all(b == 0 for b in buffer_ref)


class TestSecureRandomBytes:
    """Tests for secure random bytes generation."""

    def test_generates_correct_length(self):
        """secure_random_bytes generates correct length."""
        from ama_cryptography.secure_memory import secure_random_bytes

        for size in [0, 1, 16, 32, 100, 1000]:
            result = secure_random_bytes(size)
            assert len(result) == size

    def test_returns_bytes(self):
        """secure_random_bytes returns bytes type."""
        from ama_cryptography.secure_memory import secure_random_bytes

        result = secure_random_bytes(32)
        assert isinstance(result, bytes)

    def test_different_each_call(self):
        """secure_random_bytes returns different values each call."""
        from ama_cryptography.secure_memory import secure_random_bytes

        results = [secure_random_bytes(32) for _ in range(10)]
        # All should be unique (with overwhelming probability)
        assert len(set(results)) == 10

    def test_negative_size_raises(self):
        """secure_random_bytes with negative size raises ValueError."""
        from ama_cryptography.secure_memory import secure_random_bytes

        with pytest.raises(ValueError):
            secure_random_bytes(-1)


class TestPlatformCompatibility:
    """Tests for cross-platform compatibility."""

    def test_works_on_current_platform(self):
        """Module works on current platform."""
        import warnings

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

        data = bytearray(32)
        secure_memzero(data)
        assert all(b == 0 for b in data)

        assert constant_time_compare(b"test", b"test")
        assert not constant_time_compare(b"test", b"Test")

        rand = secure_random_bytes(16)
        assert len(rand) == 16

        # Suppress expected warning when pynacl mlock is unavailable
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            with SecureBuffer(32) as buf:
                buf[:] = rand + rand
                assert len(buf) == 32

    @pytest.mark.skipif(platform.system() == "Windows", reason="mlock may fail on Windows")
    def test_mlock_on_unix(self):
        """Memory locking may work on Unix systems."""
        from ama_cryptography.secure_memory import get_status, secure_mlock

        status = get_status()
        if status["mlock_available"]:
            data = bytearray(4096)
            # May or may not succeed depending on ulimit
            result = secure_mlock(data)
            assert isinstance(result, bool)
