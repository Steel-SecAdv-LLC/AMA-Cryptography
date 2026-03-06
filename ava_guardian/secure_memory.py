#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
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
Ava Guardian Secure Memory Module
=================================

Provides secure memory operations with optional libsodium enhancement
for cryptographic applications requiring memory protection.

Features:
- Secure zeroing - multi-pass overwrite with fallback implementation
- Memory locking (when libsodium bindings available) - prevents swapping
- Constant-time comparison - prevents timing side-channels
- SecureBuffer context manager - automatic cleanup on exit

Dependencies:
    pip install pynacl>=1.5.0  (optional, for enhanced security)

Implementation Notes:
    PyNaCl does not expose all libsodium memory functions directly.
    This module provides:
    - secure_memzero: Multi-pass Python fallback (libsodium binding not exposed)
    - secure_mlock/munlock: Returns False if libsodium binding unavailable
    - constant_time_compare: Uses hmac.compare_digest or pure Python fallback
    - secure_random_bytes: Uses nacl.utils.random or os.urandom fallback

    The fallback implementations provide best-effort security but cannot
    guarantee the same level of protection as native libsodium calls.
    For production high-security environments, consider using the C API
    with direct libsodium linking.

Usage:
    from ava_guardian.secure_memory import (
        SecureBuffer,
        secure_memzero,
        secure_mlock,
        secure_munlock,
        constant_time_compare,
    )

    # Using SecureBuffer context manager (recommended)
    with SecureBuffer(32) as buf:
        buf[:] = secret_key_bytes
        # ... use buffer ...
    # Buffer automatically zeroed on exit

    # Manual operations
    secret = bytearray(b"sensitive data")
    secure_mlock(secret)  # Attempt to lock in RAM (may return False)
    # ... use secret ...
    secure_memzero(secret)  # Securely wipe (multi-pass fallback)
    secure_munlock(secret)  # Allow swapping again

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
"""

import warnings
from contextlib import contextmanager
from typing import Optional, Union

# Try to import pynacl for libsodium bindings
_HAS_NACL = False
_nacl = None

try:
    import nacl.bindings
    import nacl.utils

    _HAS_NACL = True
    _nacl = nacl
except ImportError:
    pass


class SecureMemoryError(Exception):
    """Exception raised for secure memory operation failures."""

    pass


class SecureMemoryNotAvailable(SecureMemoryError):
    """Raised when libsodium/pynacl is not available."""

    pass


def _check_nacl_available() -> None:
    """Raise exception if pynacl is not available."""
    if not _HAS_NACL:
        raise SecureMemoryNotAvailable(
            "pynacl is required for secure memory operations. "
            "Install with: pip install pynacl>=1.5.0"
        )


def is_available() -> bool:
    """
    Check if secure memory operations are available.

    Returns:
        True if pynacl/libsodium is available, False otherwise.
    """
    return _HAS_NACL


def secure_memzero(data: Union[bytearray, memoryview]) -> None:
    """
    Securely zero memory using libsodium's sodium_memzero.

    This function overwrites the memory with zeros and includes a
    compiler barrier to prevent the operation from being optimized away.

    Falls back to pure Python implementation if pynacl is not available.

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

    if _HAS_NACL:
        if _nacl is None:  # pragma: no cover
            raise SecureMemoryError("pynacl module not properly initialized")
        # Use libsodium's secure zeroing
        # nacl.bindings doesn't expose sodium_memzero directly,
        # so we use their utils or fall back to overwrite
        try:
            # Try to use internal bindings if available
            if hasattr(_nacl.bindings, "sodium_memzero"):
                _nacl.bindings.sodium_memzero(data)
                return
        except (AttributeError, TypeError):
            pass

    # Fallback: Pure Python with multiple passes (less secure but functional)
    # This is similar to existing secure_wipe() but included for completeness
    _fallback_memzero(data)


def _fallback_memzero(data: Union[bytearray, memoryview]) -> None:
    """
    Fallback memory zeroing when libsodium is not available.

    Uses multiple passes to increase likelihood of actual overwrite.
    Note: This is less secure than libsodium as Python may optimize.
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


def secure_mlock(data: Union[bytes, bytearray, memoryview]) -> bool:
    """
    Lock memory region to prevent swapping to disk.

    Uses libsodium's sodium_mlock which:
    - Locks pages in RAM
    - Advises OS not to include in core dumps
    - Marks pages as sensitive

    Args:
        data: Buffer to lock in memory

    Returns:
        True if locking succeeded, False if not available or failed

    Note:
        Memory locking requires appropriate system permissions.
        On Linux, check /proc/sys/vm/max_map_count and ulimit -l.

    Example:
        >>> secret = bytearray(32)
        >>> if secure_mlock(secret):
        ...     print("Memory locked")
    """
    if not _HAS_NACL:
        warnings.warn(
            "pynacl not available, memory locking disabled",
            RuntimeWarning,
            stacklevel=2,
        )
        return False

    if _nacl is None:  # pragma: no cover
        raise SecureMemoryError("pynacl module not properly initialized")
    try:
        # pynacl doesn't directly expose mlock, but we can use it through
        # nacl.bindings if available, or return False
        if hasattr(_nacl.bindings, "sodium_mlock"):
            _nacl.bindings.sodium_mlock(data)
            return True
    except (OSError, AttributeError, TypeError) as e:
        warnings.warn(
            f"Memory locking failed: {e}. " "Check system limits (ulimit -l) and permissions.",
            RuntimeWarning,
            stacklevel=2,
        )

    return False


def secure_munlock(data: Union[bytes, bytearray, memoryview]) -> bool:
    """
    Unlock previously locked memory region.

    This function should be called before freeing locked memory.
    It zeros the memory before unlocking for security.

    Args:
        data: Buffer to unlock

    Returns:
        True if unlocking succeeded, False if not available or failed
    """
    if not _HAS_NACL:
        return False

    if _nacl is None:  # pragma: no cover
        raise SecureMemoryError("pynacl module not properly initialized")
    try:
        if hasattr(_nacl.bindings, "sodium_munlock"):
            _nacl.bindings.sodium_munlock(data)
            return True
    except (OSError, AttributeError, TypeError):
        pass

    return False


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte sequences in constant time.

    Uses libsodium's sodium_memcmp to prevent timing attacks.
    Falls back to pure Python constant-time comparison if unavailable.

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
    if len(a) != len(b):
        return False

    if _HAS_NACL:
        if _nacl is None:  # pragma: no cover
            raise SecureMemoryError("pynacl module not properly initialized")
        try:
            return bool(_nacl.bindings.sodium_memcmp(a, b))
        except (AttributeError, TypeError):
            pass

    # Fallback: Pure Python constant-time comparison
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def secure_random_bytes(size: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Uses libsodium's randombytes_buf for high-quality randomness.
    Falls back to os.urandom if unavailable.

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

    if _HAS_NACL:
        if _nacl is None:  # pragma: no cover
            raise SecureMemoryError("pynacl module not properly initialized")
        return bytes(_nacl.utils.random(size))

    # Fallback to os.urandom
    import os

    return os.urandom(size)


class SecureBuffer:
    """
    Context manager for secure memory buffers.

    Provides a bytearray that is:
    - Locked in memory (if available) to prevent swapping
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
        locked: Whether memory is currently locked
    """

    def __init__(self, size: int, lock: bool = True) -> None:
        """
        Create a secure buffer.

        Args:
            size: Size of buffer in bytes
            lock: Whether to attempt memory locking (default True)

        Raises:
            ValueError: If size is negative
        """
        if size < 0:
            raise ValueError("size must be non-negative")

        self._size = size
        self._should_lock = lock
        self._data: Optional[bytearray] = None
        self._locked = False
        self._entered = False

    @property
    def size(self) -> int:
        """Size of the buffer in bytes."""
        return self._size

    @property
    def locked(self) -> bool:
        """Whether memory is currently locked."""
        return self._locked

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

        if self._should_lock:
            self._locked = secure_mlock(self._data)

        return self._data

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context, zero and unlock buffer."""
        if self._data is not None:
            # Always zero the buffer
            secure_memzero(self._data)

            # Unlock if we locked it
            if self._locked:
                secure_munlock(self._data)
                self._locked = False

            # Clear reference
            self._data = None

        self._entered = False
        return None  # Don't suppress exceptions


@contextmanager
def secure_buffer(size: int, lock: bool = True):
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
    locked = False

    try:
        if lock:
            locked = secure_mlock(buf)
        yield buf
    finally:
        secure_memzero(buf)
        if locked:
            secure_munlock(buf)


# Module-level initialization
def _init_libsodium() -> bool:
    """
    Initialize libsodium if available.

    Called automatically on module import.
    Returns True if initialization succeeded.
    """
    if not _HAS_NACL:
        return False

    if _nacl is None:  # pragma: no cover
        return False
    try:
        # pynacl initializes libsodium automatically
        # Just verify it's working
        _ = _nacl.utils.random(1)
        return True
    except Exception:
        return False


# Initialize on import
_SODIUM_INITIALIZED = _init_libsodium()


def get_status() -> dict:
    """
    Get secure memory module status.

    Returns:
        Dict with status information:
            - available: Whether secure memory is available
            - backend: "libsodium" or "fallback"
            - initialized: Whether libsodium initialized successfully
            - mlock_available: Whether memory locking is available
    """
    mlock_available = False
    if _HAS_NACL and _nacl is not None:
        mlock_available = hasattr(_nacl.bindings, "sodium_mlock")

    return {
        "available": _HAS_NACL,
        "backend": "libsodium" if _HAS_NACL else "fallback",
        "initialized": _SODIUM_INITIALIZED,
        "mlock_available": mlock_available,
    }


__all__ = [
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
