#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Finalizer Health Tracking (INVARIANT-3 Addendum)
=================================================

Thread-safe infrastructure for making finalizer failures observable.

Finalizers (__del__) may catch broad exceptions to prevent propagation,
but silence must never be the only outcome.  Every finalizer that catches
an exception must produce an observable failure state via this module.

Observable states (any one suffices):
  1. Thread-safe internal error counter  (finalizer_error_count)
  2. Internal "finalizer error" flag     (has_finalizer_errors)
  3. Last-error code / detail            (last_finalizer_error)

Logging is optional and must NOT be relied upon as the sole artifact.
"""

import threading
from typing import Optional, Tuple

# ── Thread-safe counters ────────────────────────────────────────────────
_lock = threading.Lock()
_error_count: int = 0
_error_flag: bool = False
_last_error: Optional[Tuple[str, str]] = None  # (source_class, detail)


def record_finalizer_error(source: str, detail: str) -> None:
    """Record a finalizer failure in the global health state.

    This function is safe to call during interpreter shutdown.  The
    lock acquisition is wrapped in ``try/except Exception: pass`` so
    that a ``None``-ified ``_lock`` global does not escape ``__del__``.

    Args:
        source: The class or component whose finalizer failed
                (e.g. "DilithiumKeyPair").
        detail: A human-readable description of the failure
                (e.g. "wipe() raised RuntimeError: ...").
    """
    global _error_count, _error_flag, _last_error
    # KNOWN TRADEOFF (INVARIANT-3 addendum): Suppress all exceptions to
    # survive interpreter shutdown when _lock is None.  In practice _lock
    # is only None during shutdown.  Accepted per INVARIANT-3 addendum.
    # contextlib.suppress() is NOT used here because contextlib itself may
    # be None during shutdown, causing AttributeError before the context
    # manager is established.  try/except uses only language keywords.
    try:
        with _lock:
            _error_count += 1
            _error_flag = True
            _last_error = (source, detail)
    except Exception:  # nosec B110 # noqa: S110 -- _lock may be None at shutdown (FH-001)
        pass


def finalizer_error_count() -> int:
    """Return the cumulative number of finalizer errors since process start."""
    with _lock:
        return _error_count


def has_finalizer_errors() -> bool:
    """Return True if any finalizer has recorded an error."""
    with _lock:
        return _error_flag


def last_finalizer_error() -> Optional[Tuple[str, str]]:
    """Return (source, detail) of the most recent finalizer error, or None."""
    with _lock:
        return _last_error


def reset_finalizer_health() -> None:
    """Reset all counters (intended for test isolation only)."""
    global _error_count, _error_flag, _last_error
    with _lock:
        _error_count = 0
        _error_flag = False
        _last_error = None


def finalizer_health_check() -> Tuple[bool, int, Optional[Tuple[str, str]]]:
    """Composite health check for finalizer subsystem.

    Returns:
        (healthy, error_count, last_error) where *healthy* is True when
        no finalizer errors have been recorded.
    """
    with _lock:
        return (not _error_flag, _error_count, _last_error)


__all__ = [
    "finalizer_error_count",
    "finalizer_health_check",
    "has_finalizer_errors",
    "last_finalizer_error",
    "record_finalizer_error",
    "reset_finalizer_health",
]
