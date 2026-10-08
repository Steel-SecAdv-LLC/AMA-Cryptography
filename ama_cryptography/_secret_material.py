#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Wipeable storage for secret key material (INVARIANT-6)
======================================================

One implementation of the shape INVARIANT-6 requires of every object that holds
secret material: the secret lives in a mutable ``bytearray`` -- never an
immutable ``bytes``, which no caller can scrub -- ``wipe()`` zeroes it in
place, and collection wipes what is left.

Collection wipes only what dies with the container
---------------------------------------------------
A finalizer that zeroes its secret unconditionally zeroes it under anyone still
holding it.  CPython collects a temporary the moment its last reference goes,
so ``sk = generate_kyber_keypair().secret_key`` kept the ``bytearray`` and lost
the keypair in the same statement, and the keypair's ``__del__`` zeroed the
caller's key: an all-zero 3168-byte ML-KEM secret key, which decapsulation
does not refuse -- implicit rejection derives a well-formed, wrong shared
secret from it (measured 2026-10-08 on the four PQC keypair classes).

So ``__del__`` wipes a secret only when the container holds the last
reference to it.  A secret still referenced elsewhere has a new owner, whose
lifetime governs it from here on.  "The last reference" is read from the
reference count, against a threshold measured at import through this same
code path rather than written down, so it holds on any CPython whose
finalizer frame takes a different number of references.  ``wipe()`` is the
explicit form and always zeroes: a caller who asks has decided.
"""

from __future__ import annotations

import sys
from typing import Any, ClassVar, Dict, Tuple, Union

from ama_cryptography._finalizer_health import record_finalizer_error

#: Secret octets as the library hands them around: a wipeable ``bytearray``
#: wherever the library minted them, ``bytes`` where a caller supplied them.
SecretBytes = Union[bytes, bytearray]


def _as_wipeable(value: Any) -> Any:
    """``bytes`` become a ``bytearray``; a list is converted element-wise;
    a ``bytearray`` is adopted as is; anything else is left alone."""
    if isinstance(value, bytes):
        return bytearray(value)
    if isinstance(value, list):
        return [_as_wipeable(item) for item in value]
    return value


def zeroize(value: Any) -> None:
    """Zero ``value`` in place: a ``bytearray``, or a list of them.

    Anything else -- ``bytes``, ``None`` -- is immutable or empty and is left
    alone, so this can sit in a ``finally`` over a value of either kind.
    """
    if isinstance(value, bytearray):
        memoryview(value)[:] = bytes(len(value))
    elif isinstance(value, list):
        for item in value:
            zeroize(item)


_zero = zeroize


def _refs_in_dict(namespace: Dict[str, Any], name: str) -> int:
    return sys.getrefcount(namespace[name])


def _refs_in_list(items: list[Any], index: int) -> int:
    return sys.getrefcount(items[index])


class _Probe:
    pass


def _measure_sole_owner_baselines() -> Tuple[int, int]:
    probe = _Probe()
    probe.__dict__["secret"] = bytearray(1)
    in_dict = _refs_in_dict(probe.__dict__, "secret")
    items = [bytearray(1)]
    in_list = _refs_in_list(items, 0)
    return in_dict, in_list


_SOLE_IN_DICT, _SOLE_IN_LIST = _measure_sole_owner_baselines()


def _wipe_if_last_owner(namespace: Dict[str, Any], name: str) -> None:
    """Zero ``namespace[name]`` (a ``bytearray`` or a list of them) where the
    container holds the last reference; leave anything held elsewhere."""
    # Count BEFORE binding a local: the baseline was measured with no extra
    # reference, and a local here would make every secret look shared.
    if name not in namespace or _refs_in_dict(namespace, name) > _SOLE_IN_DICT:
        return
    value = namespace[name]
    if isinstance(value, bytearray):
        _zero(value)
    elif isinstance(value, list):
        for index in range(len(value)):
            if _refs_in_list(value, index) <= _SOLE_IN_LIST:
                _zero(value[index])


def release_if_unshared(value: Any, _calibrate: bool = False) -> Any:
    """Zero ``value`` (a ``bytearray``) when the calling frame holds the only
    reference to it.

    For an intermediate secret a library function obtained and is about to
    drop -- a component shared secret after it has been combined, say --
    which would otherwise be freed with its contents intact.  The value may
    have come from a caller-supplied callable that kept a reference of its
    own; that reference raises the count, and the value is then left alone:
    this never zeroes what someone else still holds.

    The threshold is measured at import by calling this function through the
    same path, from a frame holding the value in one local.
    """
    refs = sys.getrefcount(value)
    if _calibrate:
        return refs
    if isinstance(value, bytearray) and refs <= _SOLE_AS_LOCAL:
        _zero(value)
    return None


def _measure_sole_local() -> int:
    local = bytearray(1)
    refs: int = release_if_unshared(local, _calibrate=True)
    return refs


_SOLE_AS_LOCAL = _measure_sole_local()


def finalize_secret(owner: object, name: str, label: str) -> None:
    """The ``__del__`` body for a class that holds one secret attribute.

    Never raises: a finalizer exception is printed to stderr and swallowed by
    the interpreter, so a failure is recorded where it can be observed
    (INVARIANT-3) instead.
    """
    try:
        _wipe_if_last_owner(owner.__dict__, name)
    except Exception as exc:  # — INVARIANT-3/9: __del__ must not raise
        record_finalizer_error(label, f"wipe() failed: {exc}")


class SecretMaterial:
    """Mixin giving a class INVARIANT-6 storage for the attributes it names.

    Subclasses set ``_SECRET_ATTRS`` and call :meth:`_adopt_secrets` once
    those attributes exist (a dataclass's ``__post_init__``).  Each may hold
    ``bytes``, ``bytearray``, a list of them, or ``None``.
    """

    _SECRET_ATTRS: ClassVar[Tuple[str, ...]] = ()

    def _adopt_secrets(self) -> None:
        for name in self._SECRET_ATTRS:
            if name in self.__dict__:
                object.__setattr__(self, name, _as_wipeable(self.__dict__[name]))

    def wipe(self) -> None:
        """Zero every secret this object holds, in place.

        Explicit, so unconditional: anything sharing these buffers sees zeros.
        Take a copy first (``bytes(obj.field)``) of anything still needed.
        """
        for name in self._SECRET_ATTRS:
            _zero(self.__dict__.get(name))

    def __del__(self) -> None:
        for name in self._SECRET_ATTRS:
            finalize_secret(self, name, type(self).__name__)
