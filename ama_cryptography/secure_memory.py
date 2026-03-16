#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
AMA Cryptography Secure Memory Module
=================================

Provides secure memory operations for cryptographic applications
requiring memory protection.  This module is dependency-free and uses
only the Python standard library.

Features:
- Secure zeroing - multi-pass overwrite implementation
- Constant-time comparison - AMA C library or pure-Python XOR accumulator
- SecureBuffer context manager - automatic cleanup on exit
- Secure random byte generation - uses os.urandom

Implementation Notes:
    - secure_memzero: Multi-pass byte-level overwrite
    - secure_mlock/munlock: Not available without libsodium; raises NotImplementedError
    - constant_time_compare: ama_consttime_memcmp (C) or XOR accumulator (Python)
    - secure_random_bytes: Uses os.urandom (stdlib)

Usage:
    from ama_cryptography.secure_memory import (
        SecureBuffer,
        secure_memzero,
        constant_time_compare,
    )

    # Using SecureBuffer context manager (recommended)
    with SecureBuffer(32) as buf:
        buf[:] = secret_key_bytes
        # ... use buffer ...
    # Buffer automatically zeroed on exit

    # Manual operations
    secret = bytearray(b"sensitive data")
    secure_memzero(secret)  # Securely wipe (multi-pass)

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
"""

import ctypes
import os
from contextlib import contextmanager
from types import TracebackType
from typing import Any, Callable, Dict, Generator, NoReturn, Optional, Type, Union


class SecureMemoryError(Exception):
    """Exception raised for secure memory operation failures."""

    pass


def _load_native_consttime() -> Optional[Callable[..., Any]]:
    """Try to load ama_consttime_memcmp from AMA's native C library."""
    try:
        from ama_cryptography.pqc_backends import _find_native_library

        lib = _find_native_library()
        if lib is None:
            return None
        lib.ama_consttime_memcmp.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.ama_consttime_memcmp.restype = ctypes.c_int
        return lib.ama_consttime_memcmp
    except Exception:
        return None


_native_consttime_memcmp = _load_native_consttime()


def is_available() -> bool:
    """
    Check if secure memory operations are available.

    Returns:
        True — this module uses only the standard library and is always available.
    """
    return True


def secure_memzero(data: Union[bytearray, memoryview]) -> None:
    """
    Securely zero memory using a multi-pass overwrite.

    Overwrites the buffer with zeros, then ones, then zeros again
    to reduce the chance of the operation being optimized away.

    Args:
        data: Mutable buffer to zero (bytearray or memoryview)

    Raises:
        TypeError: If data is not a mutable buffer

    Example:
        >>> secret = bytearray(b"sensitive")
        >>> secure_memzero(secret)
        >>> assert all(b == 0 for b in secret)
    """
    if not isinstance(data, (bytearray, memoryview)):
        raise TypeError("data must be a mutable buffer (bytearray or memoryview)")

    if len(data) == 0:
        return

    _memzero(data)


def _memzero(data: Union[bytearray, memoryview]) -> None:
    """
    Multi-pass memory zeroing implementation.

    Uses three passes to increase likelihood of actual overwrite.
    """
    length = len(data)

    # Pass 1: Zero
    for i in range(length):
        data[i] = 0

    # Pass 2: Ones (to ensure actual write)
    for i in range(length):
        data[i] = 0xFF

    # Pass 3: Final zero
    for i in range(length):
        data[i] = 0


def secure_mlock(data: Union[bytes, bytearray, memoryview]) -> NoReturn:
    """
    Lock memory region to prevent swapping to disk.

    Raises:
        NotImplementedError: Always — memory locking requires libsodium,
            which has been removed.  This function is retained for API
            compatibility.
    """
    raise NotImplementedError(
        "secure_mlock requires libsodium (removed). "
        "Memory locking is not available in the pure-Python implementation."
    )


def secure_munlock(data: Union[bytes, bytearray, memoryview]) -> NoReturn:
    """
    Unlock previously locked memory region.

    Raises:
        NotImplementedError: Always — memory unlocking requires libsodium,
            which has been removed.  This function is retained for API
            compatibility.
    """
    raise NotImplementedError(
        "secure_munlock requires libsodium (removed). "
        "Memory unlocking is not available in the pure-Python implementation."
    )


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte sequences in constant time.

    Primary: uses ama_consttime_memcmp from AMA's native C library.
    Fallback: pure-Python XOR accumulator that pads both inputs to
    equal length and never short-circuits on length or content.

    Args:
        a: First byte sequence
        b: Second byte sequence

    Returns:
        True if sequences are equal, False otherwise

    Example:
        >>> constant_time_compare(b"secret", b"secret")
        True
        >>> constant_time_compare(b"secret", b"Secret")
        False
    """
    # Try AMA's native C constant-time comparison
    if _native_consttime_memcmp is not None:
        # Branch-free: both length check and content check always execute.
        # Pad to equal length so memcmp runs on the same number of bytes
        # regardless of input lengths.
        max_len = max(len(a), len(b), 1)
        a_pad = a.ljust(max_len, b"\x00")
        b_pad = b.ljust(max_len, b"\x00")
        length_diff = len(a) ^ len(b)
        content_diff: int = _native_consttime_memcmp(a_pad, b_pad, max_len)
        return (length_diff | content_diff) == 0

    # Fallback: pure-Python XOR accumulator — no imports, no early return
    result = len(a) ^ len(b)
    max_len = max(len(a), len(b))
    a_pad = a.ljust(max_len, b"\x00")
    b_pad = b.ljust(max_len, b"\x00")
    for x, y in zip(a_pad, b_pad):
        result |= x ^ y
    return result == 0


def secure_random_bytes(size: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Uses os.urandom from the standard library.

    Args:
        size: Number of random bytes to generate

    Returns:
        Cryptographically secure random bytes

    Raises:
        ValueError: If size is negative
    """
    if size < 0:
        raise ValueError("size must be non-negative")

    if size == 0:
        return b""

    return os.urandom(size)


class SecureBuffer:
    """
    Context manager for secure memory buffers.

    Provides a bytearray that is:
    - Automatically zeroed on exit
    - Protected from accidental exposure

    Usage:
        with SecureBuffer(32) as buf:
            buf[:] = crypto.generate_key()
            # Use the key...
        # Buffer automatically zeroed here

    Attributes:
        data: The underlying bytearray (only valid within context)
        size: Size of the buffer in bytes
    """

    def __init__(self, size: int, lock: bool = True) -> None:
        """
        Create a secure buffer.

        Args:
            size: Size of buffer in bytes
            lock: Ignored (retained for API compatibility)

        Raises:
            ValueError: If size is negative
        """
        if size < 0:
            raise ValueError("size must be non-negative")

        self._size = size
        self._data: Optional[bytearray] = None
        self._entered = False

    @property
    def size(self) -> int:
        """Size of the buffer in bytes."""
        return self._size

    @property
    def locked(self) -> bool:
        """Whether memory is currently locked (always False)."""
        return False

    @property
    def data(self) -> bytearray:
        """
        The underlying buffer data.

        Raises:
            RuntimeError: If accessed outside context manager
        """
        if not self._entered or self._data is None:
            raise RuntimeError("SecureBuffer must be used within 'with' statement")
        return self._data

    def __enter__(self) -> bytearray:
        """Enter context and allocate secure buffer."""
        self._data = bytearray(self._size)
        self._entered = True
        return self._data

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """Exit context and zero buffer."""
        if self._data is not None:
            secure_memzero(self._data)
            self._data = None

        self._entered = False
        return None  # Don't suppress exceptions


@contextmanager
def secure_buffer(size: int, lock: bool = True) -> Generator[bytearray, None, None]:
    """
    Functional context manager for secure buffers.

    Alternative to SecureBuffer class for simpler usage.

    Args:
        size: Size of buffer in bytes
        lock: Whether to attempt memory locking

    Yields:
        bytearray: Secure buffer

    Example:
        with secure_buffer(64) as key_material:
            key_material[:32] = encryption_key
            key_material[32:] = mac_key
    """
    buf = bytearray(size)

    try:
        yield buf
    finally:
        secure_memzero(buf)


def get_status() -> Dict[str, Union[bool, str]]:
    """
    Get secure memory module status.

    Returns:
        Dict with status information:
            - available: Always True (stdlib-only implementation)
            - backend: Always "stdlib"
            - initialized: Always True
            - mlock_available: Always False (requires libsodium)
    """
    return {
        "available": True,
        "backend": "stdlib",
        "initialized": True,
        "mlock_available": False,
    }


__all__ = [
    "SecureBuffer",
    "SecureMemoryError",
    "constant_time_compare",
    "get_status",
    "is_available",
    "secure_buffer",
    "secure_memzero",
    "secure_mlock",
    "secure_munlock",
    "secure_random_bytes",
]
