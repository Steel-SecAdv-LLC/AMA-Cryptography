#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Secure Memory Coverage Tests
==============================

Coverage closure for ama_cryptography/secure_memory.py (target: >= 85%).
Tests all memzero backends, mlock/munlock, constant-time compare,
SecureBuffer, and edge cases.

AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
"""

import pytest

from ama_cryptography.pqc_backends import _native_lib

NATIVE_AVAILABLE = _native_lib is not None

skip_no_native = pytest.mark.skipif(not NATIVE_AVAILABLE, reason="Native C library not available")


# ===========================================================================
# secure_memzero Tests
# ===========================================================================


class TestSecureMemzero:
    """Test secure_memzero with various backends and inputs."""

    def test_zeroes_bytearray(self) -> None:
        """secure_memzero fills bytearray with zeros."""
        from ama_cryptography.secure_memory import secure_memzero

        buf = bytearray(b"\xaa\xbb\xcc\xdd" * 16)
        secure_memzero(buf)
        assert all(b == 0 for b in buf)

    def test_empty_bytearray(self) -> None:
        """secure_memzero handles empty bytearray."""
        from ama_cryptography.secure_memory import secure_memzero

        buf = bytearray()
        secure_memzero(buf)  # Should not raise
        assert len(buf) == 0

    def test_memoryview_input(self) -> None:
        """secure_memzero works with memoryview."""
        from ama_cryptography.secure_memory import secure_memzero

        buf = bytearray(b"\xff" * 32)
        mv = memoryview(buf)
        secure_memzero(mv)
        assert all(b == 0 for b in buf)

    def test_invalid_type_raises(self) -> None:
        """secure_memzero rejects non-buffer types."""
        from ama_cryptography.secure_memory import secure_memzero

        with pytest.raises(TypeError):
            secure_memzero("not a buffer")  # type: ignore[arg-type] -- intentional wrong type for test (SMC-001)

    def test_large_buffer(self) -> None:
        """secure_memzero works with large buffers."""
        from ama_cryptography.secure_memory import secure_memzero

        buf = bytearray(b"\xaa" * 100000)
        secure_memzero(buf)
        assert all(b == 0 for b in buf)


# ===========================================================================
# Python Fallback Memzero Tests
# ===========================================================================


class TestPythonFallbackMemzero:
    """Test the pure-Python fallback memzero."""

    def test_python_fallback_zeroes(self) -> None:
        """_python_fallback_memzero correctly zeroes a bytearray."""
        from ama_cryptography.secure_memory import _python_fallback_memzero

        buf = bytearray(b"\xaa\xbb\xcc" * 10)
        _python_fallback_memzero(buf)
        assert all(b == 0 for b in buf)

    def test_python_fallback_empty(self) -> None:
        """_python_fallback_memzero handles empty input."""
        from ama_cryptography.secure_memory import _python_fallback_memzero

        buf = bytearray()
        _python_fallback_memzero(buf)


# ===========================================================================
# Constant-Time Compare Tests
# ===========================================================================


class TestConstantTimeCompare:
    """Test constant_time_compare with and without native backend."""

    def test_equal_inputs(self) -> None:
        """Identical inputs return True."""
        from ama_cryptography.secure_memory import constant_time_compare

        assert constant_time_compare(b"hello", b"hello") is True

    def test_different_inputs(self) -> None:
        """Different inputs return False."""
        from ama_cryptography.secure_memory import constant_time_compare

        assert constant_time_compare(b"hello", b"world") is False

    def test_different_lengths(self) -> None:
        """Different-length inputs return False."""
        from ama_cryptography.secure_memory import constant_time_compare

        assert constant_time_compare(b"short", b"longer string") is False

    def test_empty_inputs(self) -> None:
        """Empty inputs are equal."""
        from ama_cryptography.secure_memory import constant_time_compare

        assert constant_time_compare(b"", b"") is True

    def test_single_byte(self) -> None:
        """Single-byte comparison works."""
        from ama_cryptography.secure_memory import constant_time_compare

        assert constant_time_compare(b"\x00", b"\x00") is True
        assert constant_time_compare(b"\x00", b"\x01") is False


# ===========================================================================
# SecureBuffer Tests
# ===========================================================================


class TestSecureBuffer:
    """Test SecureBuffer context manager."""

    def test_basic_usage(self) -> None:
        """SecureBuffer provides a writable bytearray inside context."""
        from ama_cryptography.secure_memory import SecureBuffer

        sb = SecureBuffer(64)
        assert sb.size == 64
        with sb as buf:
            assert isinstance(buf, bytearray)
            assert len(buf) == 64
            for i in range(64):
                buf[i] = 0xAA
            assert buf[0] == 0xAA

    def test_zeroed_on_exit(self) -> None:
        """SecureBuffer is zeroed when exiting context."""
        from ama_cryptography.secure_memory import SecureBuffer

        sb = SecureBuffer(32)
        with sb as buf:
            data_ref = buf
            for i in range(32):
                data_ref[i] = 0xFF

        assert all(b == 0 for b in data_ref)

    def test_access_outside_context_raises(self) -> None:
        """Accessing .data outside context raises RuntimeError."""
        from ama_cryptography.secure_memory import SecureBuffer

        buf = SecureBuffer(16)
        with pytest.raises(RuntimeError):
            _ = buf.data

    def test_negative_size_raises(self) -> None:
        """Negative size raises ValueError."""
        from ama_cryptography.secure_memory import SecureBuffer

        with pytest.raises(ValueError):
            SecureBuffer(-1)

    def test_zero_size(self) -> None:
        """Zero-size buffer is valid."""
        from ama_cryptography.secure_memory import SecureBuffer

        sb = SecureBuffer(0)
        assert sb.size == 0
        with sb as buf:
            assert len(buf) == 0

    def test_size_property(self) -> None:
        """size property returns correct value."""
        from ama_cryptography.secure_memory import SecureBuffer

        sb = SecureBuffer(128)
        assert sb.size == 128
        with sb as buf:
            assert len(buf) == 128


# ===========================================================================
# secure_random_bytes Tests
# ===========================================================================


class TestSecureRandomBytes:
    """Test secure_random_bytes function."""

    def test_basic(self) -> None:
        """secure_random_bytes returns bytes of requested length."""
        from ama_cryptography.secure_memory import secure_random_bytes

        result = secure_random_bytes(32)
        assert len(result) == 32
        assert isinstance(result, bytes)

    def test_large_size(self) -> None:
        """secure_random_bytes handles large sizes."""
        from ama_cryptography.secure_memory import secure_random_bytes

        result = secure_random_bytes(1000)
        assert len(result) == 1000

    def test_negative_size_raises(self) -> None:
        """Negative size raises ValueError."""
        from ama_cryptography.secure_memory import secure_random_bytes

        with pytest.raises(ValueError):
            secure_random_bytes(-1)

    def test_zero_size(self) -> None:
        """Zero size is valid."""
        from ama_cryptography.secure_memory import secure_random_bytes

        result = secure_random_bytes(0)
        assert len(result) == 0

    def test_randomness(self) -> None:
        """Two calls produce different output (with overwhelming probability)."""
        from ama_cryptography.secure_memory import secure_random_bytes

        a = secure_random_bytes(32)
        b = secure_random_bytes(32)
        assert a != b


# ===========================================================================
# secure_mlock / secure_munlock Tests
# ===========================================================================


class TestSecureMlockMunlock:
    """Test memory locking functions."""

    def test_mlock_bytearray(self) -> None:
        """secure_mlock on a bytearray does not crash."""
        from ama_cryptography.secure_memory import secure_mlock

        buf = bytearray(4096)
        try:
            secure_mlock(buf)
        except (NotImplementedError, OSError):
            pass  # May not be available on all platforms

    def test_munlock_bytearray(self) -> None:
        """secure_munlock on a bytearray does not crash."""
        from ama_cryptography.secure_memory import secure_munlock

        buf = bytearray(4096)
        try:
            secure_munlock(buf)
        except (NotImplementedError, OSError):
            pass

    def test_mlock_empty(self) -> None:
        """secure_mlock with empty data does not crash."""
        from ama_cryptography.secure_memory import secure_mlock

        try:
            secure_mlock(bytearray())
        except (NotImplementedError, OSError):
            pass

    def test_munlock_empty(self) -> None:
        """secure_munlock with empty data does not crash."""
        from ama_cryptography.secure_memory import secure_munlock

        try:
            secure_munlock(bytearray())
        except (NotImplementedError, OSError):
            pass


# ===========================================================================
# _detect_mlock_available Tests
# ===========================================================================


class TestDetectMlockAvailable:
    """Test mlock availability detection."""

    def test_returns_bool(self) -> None:
        """_detect_mlock_available returns a boolean."""
        from ama_cryptography.secure_memory import _detect_mlock_available

        result = _detect_mlock_available()
        assert isinstance(result, bool)


# ===========================================================================
# Backend Selection Tests
# ===========================================================================


class TestBackendSelection:
    """Test memzero backend selection paths."""

    def test_native_backend_probe(self) -> None:
        """_try_native_ama_memzero probing does not crash."""
        from ama_cryptography.secure_memory import _try_native_ama_memzero

        # This returns a callable or None
        _try_native_ama_memzero()
        # On Linux with native lib, should return callable
        # Without native lib, should return None

    def test_libc_explicit_bzero_probe(self) -> None:
        """_try_libc_explicit_bzero probing does not crash."""
        from ama_cryptography.secure_memory import _try_libc_explicit_bzero

        _try_libc_explicit_bzero()
        # Returns callable or None depending on platform

    def test_libc_memset_s_probe(self) -> None:
        """_try_libc_memset_s probing does not crash."""
        from ama_cryptography.secure_memory import _try_libc_memset_s

        _try_libc_memset_s()
        # Returns callable or None depending on platform
