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
    - secure_mlock/munlock: Native C backend (VirtualLock/mlock) or POSIX fallback
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
import ctypes.util
import logging
import os
import sys
from contextlib import contextmanager
from types import TracebackType
from typing import Any, Callable, Dict, Generator, Optional, Type, Union

logger = logging.getLogger(__name__)


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
    except (ImportError, OSError, AttributeError):
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


# Module-level backend indicator for introspection and testing.
# One of: "native_ama", "libc_explicit_bzero", "libc_memset_s", "python_fallback"
SECURE_MEMZERO_BACKEND: str = "python_fallback"


def _try_native_ama_memzero() -> "Optional[Callable[[Union[bytearray, memoryview]], None]]":
    """Attempt to use ama_secure_memzero from AMA's native C library."""
    try:
        from ama_cryptography.pqc_backends import _find_native_library

        lib = _find_native_library()
        if lib is None:
            return None
        fn = lib.ama_secure_memzero
        fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        fn.restype = None

        def _zero_via_native(data: Union[bytearray, memoryview]) -> None:
            length = len(data)
            buf = (ctypes.c_char * length).from_buffer(data)
            fn(ctypes.addressof(buf), length)

        return _zero_via_native
    except (ImportError, OSError, AttributeError):
        return None


def _try_libc_explicit_bzero() -> "Optional[Callable[[Union[bytearray, memoryview]], None]]":
    """Attempt to use explicit_bzero from libc (Linux/BSD)."""
    if sys.platform == "win32":
        return None
    try:
        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            return None
        libc = ctypes.CDLL(libc_name)
        if not hasattr(libc, "explicit_bzero"):
            return None
        fn = libc.explicit_bzero
        fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        fn.restype = None

        def _zero_via_bzero(data: Union[bytearray, memoryview]) -> None:
            length = len(data)
            buf = (ctypes.c_char * length).from_buffer(data)
            fn(ctypes.addressof(buf), length)

        return _zero_via_bzero
    except (OSError, AttributeError):
        return None


def _try_libc_memset_s() -> "Optional[Callable[[Union[bytearray, memoryview]], None]]":
    """Attempt to use memset_s (macOS / C11 Annex K)."""
    if sys.platform != "darwin":
        return None
    try:
        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            return None
        libc = ctypes.CDLL(libc_name)
        if not hasattr(libc, "memset_s"):
            return None
        fn = libc.memset_s
        fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_size_t]
        fn.restype = ctypes.c_int

        def _zero_via_memset_s(data: Union[bytearray, memoryview]) -> None:
            length = len(data)
            buf = (ctypes.c_char * length).from_buffer(data)
            fn(ctypes.addressof(buf), length, 0, length)

        return _zero_via_memset_s
    except (OSError, AttributeError):
        return None


def _python_fallback_memzero(data: Union[bytearray, memoryview]) -> None:
    """Multi-pass byte-level overwrite.  Best-effort when no native backend is available.

    CPython's current bytecode interpreter does not elide these writes, but
    optimizing runtimes (PyPy JIT, a future CPython JIT) could treat
    subsequent-unobserved-stores as dead. The final ``acc`` verification read
    below forces the final zero pass to be materialized: every byte must be
    observed as zero, so the JIT/optimizer cannot discard the pass without
    breaking the assertion's value dependency.
    """
    length = len(data)
    for i in range(length):
        data[i] = 0
    for i in range(length):
        data[i] = 0xFF
    for i in range(length):
        data[i] = 0
    # Dead-store-elimination barrier: any optimizer that wanted to drop the
    # final zero-pass would have to prove `acc` is unused, which it can't —
    # this function returns None but the `assert` has a visible side effect
    # (an AssertionError) if any byte is non-zero.
    acc = 0
    for i in range(length):
        acc |= data[i]
    if acc != 0:
        raise SecureMemoryError(
            "_python_fallback_memzero: post-wipe verification failed "
            "(residual byte observed — optimizer elision or concurrent write)"
        )


# Select the best available backend at module load time.
# Start with the pure-Python fallback so the type is always a concrete callable,
# then upgrade to a faster/more-secure backend if one is available.
_memzero_fn: Callable[[Union[bytearray, memoryview]], None] = _python_fallback_memzero
SECURE_MEMZERO_BACKEND = "python_fallback"

_native_fn = _try_native_ama_memzero()
if _native_fn is not None:
    _memzero_fn = _native_fn
    SECURE_MEMZERO_BACKEND = "native_ama"
else:
    _bzero_fn = _try_libc_explicit_bzero()
    if _bzero_fn is not None:
        _memzero_fn = _bzero_fn
        SECURE_MEMZERO_BACKEND = "libc_explicit_bzero"
    else:
        _memset_fn = _try_libc_memset_s()
        if _memset_fn is not None:
            _memzero_fn = _memset_fn
            SECURE_MEMZERO_BACKEND = "libc_memset_s"
        else:
            logger.warning(
                "secure_memzero: using Python byte-by-byte fallback. "
                "Build the native C library for guaranteed secure zeroing."
            )


def _memzero(data: Union[bytearray, memoryview]) -> None:
    """Dispatch to the best available secure zeroing backend."""
    _memzero_fn(data)


def secure_mlock(data: Union[bytes, bytearray, memoryview]) -> None:
    """
    Lock memory region to prevent swapping to disk.

    Uses the native C library or POSIX mlock on the caller's actual buffer.
    For bytes objects (immutable), operates on the object's internal buffer
    via ctypes address extraction — no copy is made.

    Args:
        data: Memory region to lock (bytearray recommended for mutability)

    Raises:
        NotImplementedError: If no native backend available and not on POSIX
    """
    size = len(data)
    if size == 0:
        return

    # Get a ctypes pointer to the actual buffer (no copy).
    # Both bytearray and writable memoryview support from_buffer directly.
    if isinstance(data, (bytearray, memoryview)):
        ptr = (ctypes.c_char * size).from_buffer(data)
        addr = ctypes.addressof(ptr)
    else:
        # bytes: immutable, use id-based address (CPython implementation detail)
        # offset past PyBytesObject header to the ob_sval buffer
        if sys.implementation.name != "cpython":
            raise NotImplementedError(
                "secure_mlock on bytes objects requires CPython (id-based address layout). "
                f"Current implementation: {sys.implementation.name}"
            )
        addr = id(data) + bytes.__basicsize__ - 1
        # Runtime layout assertion: if CPython changes the PyBytesObject
        # layout (or a build uses a non-standard struct), the computed
        # address will no longer point at ob_sval[0]. Catch that here
        # rather than silently mlocking unrelated memory.
        probe = ctypes.string_at(addr, 1)
        if size > 0 and probe != data[:1]:
            raise NotImplementedError(
                "secure_mlock: PyBytesObject layout probe failed — "
                f"computed address does not point to bytes payload "
                f"(probe={probe!r} expected={data[:1]!r}). Refusing to mlock "
                "arbitrary memory. Pass a bytearray for mutable buffers."
            )

    try:
        from ama_cryptography.pqc_backends import _native_lib

        if _native_lib is not None and hasattr(_native_lib, "ama_secure_mlock"):
            _native_lib.ama_secure_mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            _native_lib.ama_secure_mlock.restype = ctypes.c_int
            ret = _native_lib.ama_secure_mlock(ctypes.c_void_p(addr), size)
            if ret != 0:
                raise SecureMemoryError(f"ama_secure_mlock failed with error code {ret}")
            return
    except (ImportError, AttributeError):
        # Native backend unavailable — fall through to POSIX fallback
        logger.debug("Native mlock unavailable, trying POSIX fallback")

    # POSIX fallback
    try:
        libc_name = ctypes.util.find_library("c")
        if libc_name:
            libc = ctypes.CDLL(libc_name, use_errno=True)
            if hasattr(libc, "mlock"):
                libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                libc.mlock.restype = ctypes.c_int
                ret = libc.mlock(ctypes.c_void_p(addr), size)
                if ret != 0:
                    errno = ctypes.get_errno()
                    raise SecureMemoryError(
                        f"mlock failed with errno {errno}: {os.strerror(errno)}"
                    )
                return
    except SecureMemoryError:
        raise
    except (OSError, AttributeError) as exc:
        raise NotImplementedError(
            "secure_mlock requires the AMA native C library or a POSIX system."
        ) from exc

    raise NotImplementedError("secure_mlock requires the AMA native C library or a POSIX system.")


def secure_munlock(data: Union[bytes, bytearray, memoryview]) -> None:
    """
    Unlock previously locked memory region.

    Uses the native C library or POSIX munlock on the caller's actual buffer.

    Args:
        data: Memory region to unlock (bytearray recommended for mutability)

    Raises:
        NotImplementedError: If no native backend available and not on POSIX
    """
    size = len(data)
    if size == 0:
        return

    # Get a ctypes pointer to the actual buffer (no copy).
    # Both bytearray and writable memoryview support from_buffer directly.
    if isinstance(data, (bytearray, memoryview)):
        ptr = (ctypes.c_char * size).from_buffer(data)
        addr = ctypes.addressof(ptr)
    else:
        # bytes: immutable, use id-based address (CPython implementation detail)
        if sys.implementation.name != "cpython":
            raise NotImplementedError(
                "secure_munlock on bytes objects requires CPython (id-based address layout). "
                f"Current implementation: {sys.implementation.name}"
            )
        addr = id(data) + bytes.__basicsize__ - 1
        # Layout probe — see secure_mlock() for rationale.
        probe = ctypes.string_at(addr, 1)
        if size > 0 and probe != data[:1]:
            raise NotImplementedError(
                "secure_munlock: PyBytesObject layout probe failed — "
                f"computed address does not point to bytes payload "
                f"(probe={probe!r} expected={data[:1]!r})."
            )

    try:
        from ama_cryptography.pqc_backends import _native_lib

        if _native_lib is not None and hasattr(_native_lib, "ama_secure_munlock"):
            _native_lib.ama_secure_munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            _native_lib.ama_secure_munlock.restype = ctypes.c_int
            ret = _native_lib.ama_secure_munlock(ctypes.c_void_p(addr), size)
            if ret != 0:
                raise SecureMemoryError(f"ama_secure_munlock failed with error code {ret}")
            return
    except (ImportError, AttributeError):
        # Native backend unavailable — fall through to POSIX fallback
        logger.debug("Native munlock unavailable, trying POSIX fallback")

    # POSIX fallback
    try:
        libc_name = ctypes.util.find_library("c")
        if libc_name:
            libc = ctypes.CDLL(libc_name, use_errno=True)
            if hasattr(libc, "munlock"):
                libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                libc.munlock.restype = ctypes.c_int
                ret = libc.munlock(ctypes.c_void_p(addr), size)
                if ret != 0:
                    errno = ctypes.get_errno()
                    raise SecureMemoryError(
                        f"munlock failed with errno {errno}: {os.strerror(errno)}"
                    )
                return
    except SecureMemoryError:
        raise
    except (OSError, AttributeError) as exc:
        raise NotImplementedError(
            "secure_munlock requires the AMA native C library or a POSIX system."
        ) from exc

    raise NotImplementedError("secure_munlock requires the AMA native C library or a POSIX system.")


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
            lock: Request page-locking via ``secure_mlock`` on enter and
                ``secure_munlock`` on exit. Best-effort — a ``SecureMemoryError``
                or ``NotImplementedError`` from the backend (e.g. RLIMIT_MEMLOCK
                exceeded, no POSIX/native support) is logged and the buffer
                proceeds unlocked. Inspect :attr:`locked` to confirm status.

        Raises:
            ValueError: If size is negative
        """
        if size < 0:
            raise ValueError("size must be non-negative")

        self._size = size
        self._data: Optional[bytearray] = None
        self._entered = False
        self._lock_requested = lock
        self._locked = False

    @property
    def size(self) -> int:
        """Size of the buffer in bytes."""
        return self._size

    @property
    def locked(self) -> bool:
        """Whether the buffer's memory is currently page-locked."""
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
        """Enter context, allocate buffer, and (optionally) page-lock it."""
        self._data = bytearray(self._size)
        self._entered = True
        if self._lock_requested and self._size > 0:
            try:
                secure_mlock(self._data)
                self._locked = True
            except (SecureMemoryError, NotImplementedError, OSError) as exc:
                # Common on Linux when RLIMIT_MEMLOCK is low, and on platforms
                # without native mlock support. The buffer is still usable —
                # pages may page to swap — so the caller is warned, not failed.
                logger.warning(
                    "SecureBuffer: mlock failed (%s); proceeding without page-lock", exc
                )
                self._locked = False
        return self._data

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """Exit context, munlock if locked, and zero buffer."""
        if self._data is not None:
            if self._locked:
                try:
                    secure_munlock(self._data)
                except (SecureMemoryError, NotImplementedError, OSError) as exc:
                    logger.warning("SecureBuffer: munlock failed: %s", exc)
                self._locked = False
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
        lock: Request page-locking via ``secure_mlock``. Best-effort — a
            ``SecureMemoryError``/``NotImplementedError`` is logged and the
            buffer proceeds unlocked.

    Yields:
        bytearray: Secure buffer

    Example:
        with secure_buffer(64) as key_material:
            key_material[:32] = encryption_key
            key_material[32:] = mac_key
    """
    buf = bytearray(size)
    did_lock = False
    if lock and size > 0:
        try:
            secure_mlock(buf)
            did_lock = True
        except (SecureMemoryError, NotImplementedError, OSError) as exc:
            logger.warning(
                "secure_buffer: mlock failed (%s); proceeding without page-lock", exc
            )

    try:
        yield buf
    finally:
        if did_lock:
            try:
                secure_munlock(buf)
            except (SecureMemoryError, NotImplementedError, OSError) as exc:
                logger.warning("secure_buffer: munlock failed: %s", exc)
        secure_memzero(buf)


def _detect_mlock_available() -> bool:
    """Check whether secure_mlock() will succeed on this platform."""
    try:
        from ama_cryptography.pqc_backends import _native_lib

        if _native_lib is not None and hasattr(_native_lib, "ama_secure_mlock"):
            return True
    except (ImportError, AttributeError):
        logger.debug("Native backend unavailable for mlock detection")
    # POSIX fallback: mlock available on Linux/macOS (may still fail due to ulimits)
    if sys.platform != "win32":
        libc_name = ctypes.util.find_library("c")
        if libc_name:
            try:
                libc = ctypes.CDLL(libc_name)
                if hasattr(libc, "mlock"):
                    return True
            except OSError as e:
                logger.debug("POSIX libc mlock probe failed: %s", e)
    return False


def get_status() -> Dict[str, Union[bool, str]]:
    """
    Get secure memory module status.

    Returns:
        Dict with status information:
            - available: Always True (stdlib-only implementation)
            - backend: Always "stdlib"
            - initialized: Always True
            - mlock_available: True if native C backend or POSIX mlock is available
    """
    return {
        "available": True,
        "backend": "stdlib",
        "initialized": True,
        "mlock_available": _detect_mlock_available(),
        "memzero_backend": SECURE_MEMZERO_BACKEND,
    }


__all__ = [
    "SECURE_MEMZERO_BACKEND",
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
