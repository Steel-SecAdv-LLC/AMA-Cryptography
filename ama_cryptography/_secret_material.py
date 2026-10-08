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

A buffer the container itself holds twice -- two attributes, or an attribute
and a list entry, naming one ``bytearray`` -- carries one reference per
holding, all of which die with the container.  Those are counted as the
container's own before the count is compared (PR #415 review: they read as
a second owner, and the buffer was freed unwiped).

Equality is constant-time in the secrets
----------------------------------------
A dataclass's generated ``__eq__`` compares fields with ``==`` and stops at
the first difference, and ``bytearray.__eq__`` is ``memcmp``: comparing an
attacker's candidate with a held key leaked where they first differ
(INVARIANT-12).  :func:`constant_time_equality` replaces it for every secret
container, comparing the secret fields through the native constant-time
comparison and never short-circuiting across fields.
"""

from __future__ import annotations

import dataclasses
import sys
from typing import Any, Callable, ClassVar, Dict, Tuple, TypeVar, Union, cast

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


def _held_by_container(namespace: Dict[str, Any], names: Tuple[str, ...], ident: int) -> int:
    """How many of the container's own holdings name the object ``ident``:
    the secret attributes ``names``, and the entries of any that is a list.
    Each is a reference that dies with the container."""
    count = 0
    for other in names:
        if other not in namespace:
            continue
        held = namespace[other]
        if id(held) == ident:
            count += 1
        if isinstance(held, list):
            count += sum(1 for item in held if id(item) == ident)
    return count


def _wipe_if_last_owner(namespace: Dict[str, Any], name: str, names: Tuple[str, ...] = ()) -> None:
    """Zero ``namespace[name]`` (a ``bytearray`` or a list of them) where the
    container holds every reference; leave anything held elsewhere.

    ``names`` are all of the container's secret attributes (default: just
    ``name``).  A buffer held under several of them, or under one and in a
    list, has one reference per holding, and those are the container's own.
    """
    names = names or (name,)
    if name not in namespace:
        return
    # Count BEFORE binding a local: the baseline was measured with no extra
    # reference, and a local here would make every secret look shared.  The
    # occurrence count is computed first and binds nothing that survives it.
    own = _held_by_container(namespace, names, id(namespace[name]))
    if _refs_in_dict(namespace, name) > _SOLE_IN_DICT + own - 1:
        return
    value = namespace[name]
    if isinstance(value, bytearray):
        _zero(value)
    elif isinstance(value, list):
        for index in range(len(value)):
            own = _held_by_container(namespace, names, id(value[index]))
            if _refs_in_list(value, index) <= _SOLE_IN_LIST + own - 1:
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


def finalize_secret(owner: object, name: str, label: str, names: Tuple[str, ...] = ()) -> None:
    """The ``__del__`` body for one secret attribute of ``owner``.

    ``names`` lists every secret attribute ``owner`` holds, so a buffer held
    under several is recognised as the owner's own (see
    :func:`_wipe_if_last_owner`).

    Never raises: a finalizer exception is printed to stderr and swallowed by
    the interpreter, so a failure is recorded where it can be observed
    (INVARIANT-3) instead.
    """
    try:
        _wipe_if_last_owner(owner.__dict__, name, names)
    except Exception as exc:  # — INVARIANT-3/9: __del__ must not raise
        record_finalizer_error(label, f"wipe() failed: {exc}")


def _wipe_children(value: Any) -> None:
    """Call ``wipe()`` on a secret holder, or on each one in a dict or list."""
    if value is None:
        return
    if isinstance(value, dict):
        children: Any = value.values()
    elif isinstance(value, (list, tuple)):
        children = value
    else:
        children = (value,)
    for child in children:
        child.wipe()


class SecretMaterial:
    """Mixin giving a class INVARIANT-6 storage for the attributes it names.

    Subclasses set ``_SECRET_ATTRS`` and call :meth:`_adopt_secrets` once
    those attributes exist (a dataclass's ``__post_init__``).  Each may hold
    ``bytes``, ``bytearray``, a list of them, or ``None``.

    ``_SECRET_CHILDREN`` names attributes holding other secret holders -- an
    object with a ``wipe()`` method, a dict or list of them, or ``None`` --
    that :meth:`wipe` cascades to.  Only the explicit wipe cascades: a child
    has its own finalizer, and one the caller still holds must survive the
    parent's death.
    """

    _SECRET_ATTRS: ClassVar[Tuple[str, ...]] = ()
    _SECRET_CHILDREN: ClassVar[Tuple[str, ...]] = ()

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
        for name in self._SECRET_CHILDREN:
            _wipe_children(self.__dict__.get(name))

    def __del__(self) -> None:
        for name in self._SECRET_ATTRS:
            finalize_secret(self, name, type(self).__name__, self._SECRET_ATTRS)


_C = TypeVar("_C")


def _secrets_equal(a: Any, b: Any) -> bool:
    """Equality of two secret field values, constant-time in their octets.

    Presence (``None``), type and length are public; the octets are compared
    by the native constant-time comparison, and a list element by element
    with no early exit.
    """
    from ama_cryptography.secure_memory import constant_time_compare

    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, list) or isinstance(b, list):
        if not (isinstance(a, list) and isinstance(b, list)) or len(a) != len(b):
            return False
        verdict = True
        for left, right in zip(a, b):
            verdict &= _secrets_equal(left, right)
        return verdict
    if isinstance(a, (bytes, bytearray)) and isinstance(b, (bytes, bytearray)):
        return constant_time_compare(a, b)
    return bool(a == b)


def constant_time_equality(
    secret: Tuple[str, ...] = (),
) -> Callable[[type[_C]], type[_C]]:
    """Class decorator, applied above ``@dataclass``: replace the generated
    ``__eq__`` with one that compares the secret fields in constant time.

    The secret fields are ``secret`` if given, else the class's
    ``_SECRET_ATTRS``.  Every field is compared, so where two values differ
    does not decide how much work is done.  ``__hash__`` is left as the
    dataclass set it.
    """

    def apply(cls: type[_C]) -> type[_C]:
        names = tuple(f.name for f in dataclasses.fields(cast(Any, cls)))
        secret_names = frozenset(secret or getattr(cls, "_SECRET_ATTRS", ()))

        def equal(self: Any, other: Any) -> Any:
            if other.__class__ is not self.__class__:
                return NotImplemented
            verdict = True
            for name in names:
                left, right = getattr(self, name), getattr(other, name)
                if name in secret_names:
                    verdict &= _secrets_equal(left, right)
                else:
                    verdict &= bool(left == right)
            return verdict

        equal.__name__ = "__eq__"
        equal.__qualname__ = f"{cls.__qualname__}.__eq__"
        equal.__doc__ = "Field-wise equality, constant-time in the secret fields."
        # Read by tests/test_secret_wipeability.py, which requires every secret
        # container to carry it.
        marker = "constant_time_secret_fields"
        setattr(equal, marker, secret_names)
        attribute = "__eq__"
        setattr(cls, attribute, equal)
        return cls

    return apply
