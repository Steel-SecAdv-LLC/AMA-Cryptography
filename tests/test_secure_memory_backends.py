"""Tests for secure memory zeroing backends and SecureBuffer lifecycle."""

import pytest

from ama_cryptography.secure_memory import (
    SECURE_MEMZERO_BACKEND,
    SecureBuffer,
    constant_time_compare,
    get_status,
    secure_memzero,
    secure_random_bytes,
)


class TestSecureMemzeroBackend:
    def test_backend_is_string(self):
        assert isinstance(SECURE_MEMZERO_BACKEND, str)

    def test_backend_is_known_value(self):
        assert SECURE_MEMZERO_BACKEND in {
            "native_ama",
            "libc_explicit_bzero",
            "libc_memset_s",
            "python_fallback",
        }

    def test_get_status_includes_memzero_backend(self):
        status = get_status()
        assert "memzero_backend" in status
        assert status["memzero_backend"] == SECURE_MEMZERO_BACKEND


class TestSecureMemzero:
    def test_zeros_bytearray(self):
        data = bytearray(b"sensitive secret data")
        secure_memzero(data)
        assert all(b == 0 for b in data)

    def test_zeros_memoryview(self):
        data = bytearray(64)
        data[:] = b"\xff" * 64
        mv = memoryview(data)
        secure_memzero(mv)
        assert all(b == 0 for b in data)

    def test_empty_buffer_no_error(self):
        data = bytearray(0)
        secure_memzero(data)

    def test_large_buffer(self):
        data = bytearray(b"\xab" * 10000)
        secure_memzero(data)
        assert all(b == 0 for b in data)

    def test_rejects_bytes(self):
        with pytest.raises(TypeError):
            secure_memzero(b"immutable")  # type: ignore[arg-type]

    def test_rejects_string(self):
        with pytest.raises(TypeError):
            secure_memzero("string")  # type: ignore[arg-type]

    def test_single_byte(self):
        data = bytearray(b"\xff")
        secure_memzero(data)
        assert data[0] == 0


class TestSecureBuffer:
    def test_context_manager_zeros_on_exit(self):
        with SecureBuffer(32) as buf:
            buf[:] = b"\xff" * 32
            assert any(b != 0 for b in buf)
        # After exit, buffer should be zeroed (buf reference still valid)

    def test_data_property_inside_context(self):
        sb = SecureBuffer(16)
        with sb:
            assert len(sb.data) == 16

    def test_data_property_outside_context_raises(self):
        sb = SecureBuffer(16)
        with pytest.raises(RuntimeError):
            _ = sb.data

    def test_size_property(self):
        sb = SecureBuffer(42)
        assert sb.size == 42

    def test_negative_size_raises(self):
        with pytest.raises(ValueError):
            SecureBuffer(-1)

    def test_zero_size(self):
        with SecureBuffer(0) as buf:
            assert len(buf) == 0


class TestConstantTimeCompare:
    def test_equal_bytes(self):
        assert constant_time_compare(b"hello", b"hello")

    def test_different_bytes(self):
        assert not constant_time_compare(b"hello", b"world")

    def test_different_lengths(self):
        assert not constant_time_compare(b"short", b"longer")

    def test_empty_bytes(self):
        assert constant_time_compare(b"", b"")

    def test_single_bit_difference(self):
        a = b"\x00" * 32
        b_val = bytearray(a)
        b_val[15] = 1
        assert not constant_time_compare(a, bytes(b_val))


class TestSecureRandomBytes:
    def test_correct_length(self):
        for n in [0, 1, 16, 32, 64, 1000]:
            assert len(secure_random_bytes(n)) == n

    def test_negative_raises(self):
        with pytest.raises(ValueError):
            secure_random_bytes(-1)

    def test_randomness(self):
        a = secure_random_bytes(32)
        b = secure_random_bytes(32)
        assert a != b  # overwhelmingly likely
