#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography Secure Memory Module
=====================================

Provides secure memory operations for cryptographic applications
requiring memory protection.  This module is dependency-free and uses
only the Python standard library.

Features:

- Secure zeroing — multi-pass overwrite implementation
- Constant-time comparison — AMA's native C library, and nothing else: the
  pure-Python XOR accumulator this module used to fall back to was not
  constant-time in fact (INVARIANT-7), so ``constant_time_compare`` now raises
  rather than substituting it
- SecureBuffer context manager — automatic cleanup on exit
- Secure random byte generation — routed through the FIPS 140-3 §4.9.2
  output-inhibited, health-tested CSPRNG (no longer a bare ``os.urandom``)

Implementation notes:

- ``secure_memzero``: Multi-pass byte-level overwrite
- ``secure_mlock`` / ``secure_munlock``: Native C backend (VirtualLock/mlock) or POSIX fallback
- ``constant_time_compare``: ``ama_consttime_memcmp`` (C), required — raises
  ``RuntimeError`` when the native library is absent
- ``lengths_match``: public (non-constant-time) length pre-check, for use
  before ``constant_time_compare`` where the expected size is fixed
- ``secure_random_bytes``: routed through ``_self_test.secure_token_bytes`` —
  the error-state-gated, continuous-health-tested draw (not bare ``os.urandom``)

Usage::

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


# The health-tested draw lives in the ``_module_state`` leaf (imports only the
# stdlib and ``exceptions``), so this import is safe at module level in every
# context this module is loaded from — including the build-time signer, which
# imports secure_memory before the package's POST has run.  The previous
# call-time import inside ``secure_random_bytes`` existed only because the draw
# lived in ``_self_test`` and importing the POST orchestrator here formed a
# cycle.
from ama_cryptography._module_state import secure_token_bytes
from ama_cryptography.exceptions import AmaCryptographyError


class SecureMemoryError(AmaCryptographyError):
    """Exception raised for secure memory operation failures."""

    pass


def _load_native_consttime() -> Optional[Callable[..., Any]]:
    """Try to load ama_consttime_memcmp from AMA's native C library."""
    try:
        # Verified discovery: a library the ABI handshake rejected must not
        # serve the constant-time comparison either — this module's own
        # handle would otherwise bypass the version gate pqc_backends applies
        # to its module-level binding.
        from ama_cryptography.pqc_backends import _find_verified_native_library

        lib = _find_verified_native_library()
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


# Env-flag gates for the python_fallback path.  Production deployments
# (where INVARIANT-7 already refuses to import without the native C
# accelerator) should never reach the fallback, but the secure_memzero
# code path is reachable from documentation builds, type-checkers, and
# editable installs where the native lib might be absent.  We refuse
# to silently use a best-effort multi-pass-Python wipe unless the
# operator has explicitly opted in.
_TRUE_ENV_VALUES = frozenset({"1", "true", "yes", "on"})


def _env_flag_enabled(name: str) -> bool:
    """Return True only for an explicit truthy env value."""
    return os.environ.get(name, "").strip().lower() in _TRUE_ENV_VALUES


# Computed at module load; updated lazily on every call via re-read so
# tests can flip the env var inside a single process.  The selection
# logic below sets SECURE_MEMZERO_BACKEND once at load time; this gate
# protects the *call* path.
_AMA_ALLOW_PYTHON_MEMZERO_ENV = "AMA_ALLOW_PYTHON_MEMZERO"
_AMA_SPHINX_BUILD_ENV = "AMA_SPHINX_BUILD"
_SPHINX_BUILD_ENV = "SPHINX_BUILD"


def _python_fallback_opt_in() -> bool:
    """True iff the caller has opted into best-effort Python memzero.

    Three gates are honoured:
      * ``AMA_ALLOW_PYTHON_MEMZERO=1`` — explicit dev/test opt-in.
      * ``AMA_SPHINX_BUILD=1`` / ``SPHINX_BUILD=1`` — autodoc builds
        that import the module for docstring extraction must not
        trigger a hard failure on a host without the native lib.

    Any other configuration MUST fail closed: silently falling back to
    a Python wipe in production would defeat the security contract
    that ``secure_memzero`` is the canonical wipe primitive.
    """
    return (
        _env_flag_enabled(_AMA_ALLOW_PYTHON_MEMZERO_ENV)
        or _env_flag_enabled(_AMA_SPHINX_BUILD_ENV)
        or _env_flag_enabled(_SPHINX_BUILD_ENV)
    )


def secure_memzero(data: Union[bytearray, memoryview]) -> None:
    """
    Securely zero memory using a multi-pass overwrite.

    Overwrites the buffer with zeros, then ones, then zeros again
    to reduce the chance of the operation being optimized away.

    Args:
        data: Mutable buffer to zero (bytearray or memoryview)

    Raises:
        TypeError: If ``data`` is not a mutable buffer.
        SecureMemoryError: Raised in two distinct fail-closed cases (the
            native ``ama_secure_memzero`` and the libc ``explicit_bzero`` /
            ``memset_s`` back-ends never raise).

            **Case 1 — no native backend, no opt-in.** If the active
            backend is the Python fallback AND none of
            ``AMA_ALLOW_PYTHON_MEMZERO=1`` / ``AMA_SPHINX_BUILD=1`` /
            ``SPHINX_BUILD=1`` is set, the module refuses to wipe at all.
            Falling back silently to a best-effort Python loop in
            production would defeat the security contract. Build the
            native C library
            (``cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build``)
            or set the opt-in env var for development / docs builds.

            **Case 2 — opt-in fallback with residual non-zero byte.** If
            the Python fallback path *is* in use (via opt-in) and the
            post-wipe verification observes a residual non-zero byte
            (optimizer elision, concurrent write, or mis-compiled
            ``memset_explicit``), the function raises. This is a
            deliberate hard failure — a silently incomplete wipe would
            leave secret material in memory.

    **Propagation from cleanup contexts.**  ``SecureBuffer.__exit__`` and
    ``secure_buffer()``'s ``finally`` clause both call ``secure_memzero``
    on the way out, so a ``SecureMemoryError`` raised here can propagate
    through a ``with`` statement's exit path.  That is intentional — a
    failed wipe is a security-critical signal that *must not* be
    silenced.  Callers that need to suppress it (e.g. because they are
    already handling an in-flight exception) should catch
    ``SecureMemoryError`` explicitly at the boundary they control.

    Example:
        >>> secret = bytearray(b"sensitive")
        >>> secure_memzero(secret)
        >>> assert all(b == 0 for b in secret)
    """
    if not isinstance(data, (bytearray, memoryview)):
        raise TypeError("data must be a mutable buffer (bytearray or memoryview)")

    if len(data) == 0:
        return

    # Fail-closed gate: refuse to silently use the python_fallback path
    # in production.  When the native backend is unavailable AND the
    # operator has not explicitly opted into the Python loop, raise so
    # the caller knows the wipe contract cannot be honoured.  This is
    # the "appropriate" fail-closed behaviour requested by INVARIANT-7
    # at the secure-memory layer.
    if SECURE_MEMZERO_BACKEND == "python_fallback" and not _python_fallback_opt_in():
        raise SecureMemoryError(
            "secure_memzero: native backend unavailable and Python fallback is "
            "not opted-in.  Refusing to silently use a best-effort wipe in "
            "production.  Build the native C library "
            "(cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build), "
            f"or set {_AMA_ALLOW_PYTHON_MEMZERO_ENV}=1 for development / "
            "test contexts where best-effort zeroing is acceptable."
        )

    _memzero(data)


# Module-level backend indicator for introspection and testing.
# One of: "native_ama", "libc_explicit_bzero", "libc_memset_s", "python_fallback"
SECURE_MEMZERO_BACKEND: str = "python_fallback"


def _try_native_ama_memzero() -> "Optional[Callable[[Union[bytearray, memoryview]], None]]":
    """Attempt to use ama_secure_memzero from AMA's native C library."""
    try:
        # Verified discovery — see _load_native_consttime for why.
        from ama_cryptography.pqc_backends import _find_verified_native_library

        lib = _find_verified_native_library()
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
    # final zero-pass would have to prove ``acc`` is unused, which it can't —
    # the ``if acc != 0`` check below has a visible side effect (a
    # ``SecureMemoryError``) if any byte is non-zero.  We deliberately do
    # *not* use ``assert`` here: assertions can be stripped with ``-O`` /
    # ``PYTHONOPTIMIZE`` which would silently defeat the barrier.
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
                "secure_memzero: native backend unavailable.  "
                "secure_memzero() will refuse to operate (fail-closed) until "
                "the native C library is built "
                "(cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build), "
                "or the operator explicitly opts into the best-effort Python "
                "fallback via AMA_ALLOW_PYTHON_MEMZERO=1.  "
                "Documentation builds (AMA_SPHINX_BUILD=1 / SPHINX_BUILD=1) "
                "are also permitted."
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
        # Layout-probe comparison: 1-byte sanity check, not a secret comparison.
        if (
            size > 0 and probe != data[:1]
        ):  # nosemgrep: non-constant-time-comparison -- 1-byte PyBytesObject layout probe, not secret comparison (SM-001)
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
        # Layout-probe comparison: 1-byte sanity check, not a secret comparison.
        if (
            size > 0 and probe != data[:1]
        ):  # nosemgrep: non-constant-time-comparison -- 1-byte PyBytesObject layout probe, not secret comparison (SM-002)
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

    Uses ``ama_consttime_memcmp`` from AMA's native C library, and refuses to
    operate without it.

    INVARIANT-7, no cryptographic fallbacks
    ---------------------------------------
    This function used to fall back to a pure-Python XOR accumulator, and both
    the docstring and ``CONSTANT_TIME_VERIFICATION.md`` described that
    accumulator as the constant-time fallback. INVARIANT-7 names exactly that
    substitution as unacceptable — *"a pure-Python fallback for any
    cryptographic primitive or secret-dependent operation"* — and this is a
    secret-dependent operation by INVARIANT-12's own definition, which lists
    "pre-verification MAC/tag comparisons" as secret material. Its callers are
    HMAC tag verification in ``crypto_api.verify_crypto_package`` and the
    pinned-responder-key check in ``secure_channel``.

    The loop was also not constant-time in fact, only in shape. ``ljust``
    allocates, ``zip`` builds tuples, and ``result |= x ^ y`` runs the CPython
    integer path with its small-int cache — none of which retires a fixed
    instruction count. A fallback that is documented as constant-time and is
    not is worse than no fallback, because callers stop asking.

    So the availability axis is enforced the way INVARIANT-7 requires, at call
    time and in the same shape ``pqc_backends`` uses: no native backend, no
    operation. Import still succeeds (this module has no import-time guard and
    is used for non-cryptographic memory hygiene too), which is also what keeps
    the documented ``AMA_SPHINX_BUILD`` docs path working — the refusal is on
    the call, not the import.

    Cost is bounded by the *shorter* operand
    ----------------------------------------
    Lengths are public metadata here and always have been: a MAC tag, a public
    key and a KEM shared secret each have one fixed size that is published in
    the specification, so an observer learns nothing from a comparison whose
    cost depends on them. What matters is that the cost cannot be driven by an
    attacker, and until this release it could be.

    The previous implementation padded *both* operands to
    ``max(len(a), len(b))`` with ``ljust``. Every caller of this function
    compares a locally computed value against one that arrived from outside —
    ``verify_crypto_package`` recomputes a 32-byte HMAC tag and compares it to
    ``package.hmac_tag``, which is whatever the package says it is. A package
    declaring an 8 MiB tag therefore caused 16 MiB of allocation and an 8 MiB
    scan to reject a 32-byte value — measured — before any other check could
    look at it, and nothing bounded the size it could declare. That is memory
    and CPU amplification on unauthenticated input, reachable from the one
    function whose job is to decide whether that input is authentic.

    Now ``min(len(a), len(b))`` bytes are compared in place — no padding, no
    allocation, no copy — and the length difference is OR-ed into the verdict
    rather than short-circuiting the content scan: a mismatched length does not
    skip the comparison, it is folded into its result. Work is bounded by the
    shorter operand, whichever argument that is, so the bound does not depend
    on a call site passing its own value first. The branch-free property with
    respect to *content* is unchanged: the native ``ama_consttime_memcmp``
    accumulates over all n bytes with no early exit.

    Callers that know the expected length up front should still say so, with
    :func:`lengths_match`, so a malformed length is refused explicitly rather
    than folded into a comparison verdict.

    Args:
        a: First byte sequence.  By convention the locally computed value.
        b: Second byte sequence.  By convention the untrusted one.

    Returns:
        True if sequences are equal, False otherwise

    Raises:
        RuntimeError: If the native constant-time backend is unavailable.

    Example:
        >>> constant_time_compare(b"secret", b"secret")
        True
        >>> constant_time_compare(b"secret", b"Secret")
        False
        >>> constant_time_compare(b"secret", b"secret-and-then-some")
        False

    .. versionchanged:: 4.0
       Work is bounded by ``min(len(a), len(b))`` instead of
       ``max(len(a), len(b))``, removing the padding allocations. Return values
       are unchanged for every input.
    """
    if _native_consttime_memcmp is None:
        raise RuntimeError(
            "INVARIANT-7: constant_time_compare requires AMA's native "
            "ama_consttime_memcmp and refuses to operate without it. A "
            "pure-Python comparison is not constant-time on CPython, and this "
            "function is used for MAC/tag verification and key pinning. Build "
            "the native library: "
            "cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )

    # Both terms always execute: the content scan is not skipped when the
    # lengths differ, and the length term is not skipped when they match.
    length_diff = len(a) ^ len(b)
    common = min(len(a), len(b))
    # ctypes passes a pointer to each object's own buffer, so `common` bounds
    # the read without slicing either operand.  n == 0 (both empty, or one
    # empty) is well defined: the native loop does not execute and returns 0,
    # leaving `length_diff` to decide.
    content_diff: int = _native_consttime_memcmp(a, b, common) if common else 0
    return (length_diff | content_diff) == 0


def lengths_match(a: bytes, b: bytes) -> bool:
    """Public length pre-check for values whose size is not secret.

    A deliberately ordinary, deliberately *not* constant-time comparison of two
    lengths, published as API so call sites can perform it explicitly instead
    of leaving it implicit inside :func:`constant_time_compare`.

    Why this is safe, stated once so call sites need not restate it: the values
    AMA compares in constant time — HMAC-SHA3-256 tags, Ed25519 / ML-DSA-65
    public keys, ML-KEM shared secrets — each have exactly one length fixed by
    their specification. An observer who learns that a candidate was the wrong
    length learns nothing they did not already know from the algorithm name.
    The secret is the *content*, and that is what
    :func:`constant_time_compare` protects.

    Why it is worth calling anyway:

    * It refuses malformed input at the boundary, where the error can say
      "expected a 32-byte tag, got 9", rather than folding a structural defect
      into a cryptographic verdict that reads as "the tag did not match".
    * It bounds work on untrusted input before any of it is scanned.
    * It documents, at the call site, that the caller thought about which of
      the two properties — length and content — is the secret one.

    Args:
        a: First byte sequence.
        b: Second byte sequence.

    Returns:
        True if the two have the same length.

    Example:
        >>> tag = b"\\x00" * 32
        >>> lengths_match(tag, b"\\x00" * 32)
        True
        >>> lengths_match(tag, b"short")
        False

    .. versionadded:: 4.0
    """
    return len(a) == len(b)


def secure_random_bytes(size: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Routed through :func:`ama_cryptography._self_test.secure_token_bytes`, which
    applies two controls this function previously had neither of:

    * **FIPS 140-3 §4.9.2 output inhibition** — a module in the error state must
      not emit key material, and this function is one of the places key material
      comes from.  It called ``os.urandom`` directly, so it kept producing
      output after POST had failed.
    * **The FIPS 140-3 §4.9.2 continuous RNG health test** — the repeated-block
      check lived in ``secure_token_bytes`` and nothing in the library called
      it, so the test was implemented and never ran against a single real draw.
      Every byte handed out here is now compared against the previous draw.

    Args:
        size: Number of random bytes to generate

    Returns:
        Cryptographically secure random bytes

    Raises:
        ValueError: If size is negative
        CryptoModuleError: If the module is in the FIPS error state, or the
            continuous RNG health test fails
    """
    if size < 0:
        raise ValueError("size must be non-negative")

    if size == 0:
        return b""

    return secure_token_bytes(size)


class SecureBuffer:
    """
    Context manager for secure memory buffers.

    Provides a bytearray that is:

    - Automatically zeroed on exit
    - Protected from accidental exposure

    Usage::

        with SecureBuffer(32) as buf:
            buf[:] = crypto.generate_key()
            # Use the key...
        # Buffer automatically zeroed here

    Attributes:
        data: The underlying bytearray (only valid within context).
        size: Size of the buffer in bytes.
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
                logger.warning("SecureBuffer: mlock failed (%s); proceeding without page-lock", exc)
                self._locked = False
        return self._data

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """Exit context: zero buffer first (while still pinned), then munlock.

        Raises:
            SecureMemoryError: If ``secure_memzero`` is on the Python
                fallback path and post-wipe verification observes a
                residual non-zero byte.  This is a deliberate hard
                failure — a silently incomplete wipe would defeat the
                security contract.  If raised here while an in-flight
                exception is already propagating through the ``with``
                block, Python's normal ``__exit__`` semantics apply:
                the ``SecureMemoryError`` replaces the pending
                exception.  Callers that need to preserve the original
                exception should wrap the inner body in their own
                ``try``/``except SecureMemoryError``.  A ``munlock``
                failure is *not* propagated — it is logged at WARNING
                and swallowed, since by that point the memory has
                already been zeroed.
        """
        if self._data is not None:
            # CRITICAL ORDER: zero FIRST while the pages are still mlocked
            # (pinned in RAM), THEN munlock.  If we reversed these two
            # operations the kernel could swap the still-sensitive pages to
            # disk between ``secure_munlock`` returning and
            # ``secure_memzero`` running, leaking secret material to
            # swapfile — a serious defence-in-depth regression.
            #
            # ``try/finally`` around the wipe is equally critical: if
            # ``secure_memzero`` raises ``SecureMemoryError`` (Python
            # fallback path, post-wipe verification failed), we still
            # MUST run ``secure_munlock`` and reset ``_locked`` / ``_data``
            # so the caller's process does not leak an mlock pin or
            # leave the ``SecureBuffer`` instance in a half-cleaned
            # state.  The wipe error itself is re-raised by the
            # ``finally`` implicit re-raise so callers still learn the
            # wipe failed (the documented contract above).
            data = self._data
            try:
                secure_memzero(data)
            finally:
                if self._locked:
                    try:
                        secure_munlock(data)
                    except (SecureMemoryError, NotImplementedError, OSError) as exc:
                        logger.warning("SecureBuffer: munlock failed: %s", exc)
                    self._locked = False
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

    Raises:
        SecureMemoryError: On the way out, if ``secure_memzero`` is on the
            Python fallback path and observes a residual non-zero byte
            during post-wipe verification. A ``munlock`` failure during
            cleanup is logged at WARNING and swallowed.

    Usage::

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
            logger.warning("secure_buffer: mlock failed (%s); proceeding without page-lock", exc)

    try:
        yield buf
    finally:
        # CRITICAL ORDER: zero FIRST while pages are still mlocked, THEN
        # munlock.  See ``SecureBuffer.__exit__`` for the full rationale —
        # reversing the order permits the kernel to page sensitive data
        # to swap between munlock returning and memzero running.
        #
        # ``try/finally`` around the wipe is equally critical here: if
        # ``secure_memzero`` raises, we still need to release the mlock
        # pin so the process does not leak locked pages on the way out.
        # The wipe error is re-raised by the ``finally`` implicit
        # re-raise so callers learn about the post-wipe verification
        # failure (same contract as ``SecureBuffer.__exit__``).
        try:
            secure_memzero(buf)
        finally:
            if did_lock:
                try:
                    secure_munlock(buf)
                except (SecureMemoryError, NotImplementedError, OSError) as exc:
                    logger.warning("secure_buffer: munlock failed: %s", exc)


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
    "lengths_match",
    "secure_buffer",
    "secure_memzero",
    "secure_mlock",
    "secure_munlock",
    "secure_random_bytes",
]
