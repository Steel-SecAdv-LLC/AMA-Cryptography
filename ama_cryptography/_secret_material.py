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

import contextlib
import dataclasses
import sys
from typing import Any, Callable, ClassVar, Dict, Tuple, TypeVar, Union, cast

from ama_cryptography._finalizer_health import record_finalizer_error
from ama_cryptography._module_state import secrets_match

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


#: The octets a wipe copies over a secret, in one run no longer than
#: ``_ZERO_RUN``: a pre-built read-only ``memoryview`` of zeros.  Assigning a
#: slice of it into a ``memoryview`` of the secret copies octets once and
#: allocates nothing the size of the secret -- ``bytes(len(value))``, which this
#: replaced, made a key-sized all-zero object for every wipe, so a wipe running
#: under the very memory pressure that aborted an export could itself fail with
#: ``MemoryError`` and leave the secret in place.
_ZERO_RUN = 4096
_ZEROS = memoryview(bytes(_ZERO_RUN))


def zeroize(value: Any) -> None:
    """Zero ``value`` in place: a ``bytearray``, or a list of them.

    Anything else -- ``bytes``, ``None`` -- is immutable or empty and is left
    alone, so this can sit in a ``finally`` over a value of either kind.

    Allocates nothing proportional to ``len(value)``: the zeros come from a
    fixed run, copied over the secret one run at a time.
    """
    if isinstance(value, bytearray):
        size = len(value)
        target = memoryview(value)
        try:
            if size <= _ZERO_RUN:  # one run: the common case, without the loop
                target[:] = _ZEROS[:size]
            else:
                for start in range(0, size, _ZERO_RUN):
                    stop = min(start + _ZERO_RUN, size)
                    target[start:stop] = _ZEROS[: stop - start]
        finally:
            target.release()
    elif isinstance(value, list):
        for item in value:
            zeroize(item)


_zero = zeroize


class ZeroizingBytearray(bytearray):
    """A ``bytearray`` that zeroes its own contents when it is collected.

    What the library returns where it mints a secret in a *serialised* form --
    a private key's PKCS#8, PEM, JWK and COSE_Key encodings -- and the caller
    has no container to hold it in.  It is a ``bytearray`` in every way that
    matters to a consumer (``isinstance(x, bytearray)``, the buffer protocol,
    ``==`` against ``bytes``, slicing, ``bytes(x)``, ``Path.write_bytes``), and
    differs in four, each of them a way a secret leaks by accident:

    * **Collection zeroes it.**  ``__del__`` runs only when the reference
      count reaches zero -- a live ``memoryview`` or ctypes export keeps the
      object alive, so it is never zeroed under a holder -- which is why no
      last-owner test is needed here (contrast :func:`_wipe_if_last_owner`,
      whose container shares its buffer).  ``Path.write_bytes(key.to_pem())``
      therefore no longer frees an unwiped temporary.
    * **``repr`` and ``str`` print the length, never the content.**  CPython's
      ``bytearray.__str__`` calls the C repr directly, so ``__repr__`` alone
      would still leak through ``str(x)``, ``f"{x}"`` and ``"%s" % x``.
    * **No implicit copies.**  ``pickle``, ``copy.copy`` and ``copy.deepcopy``
      raise ``TypeError``: each would mint a second buffer nothing wipes.
    * Equality is ``bytearray`` equality (``memcmp``, not constant time), and
      it stays unhashable.  Compare secrets with
      :func:`ama_cryptography.secure_memory.constant_time_compare`.

    What it cannot do, stated so the type is not read as a guarantee it does
    not make: a *derived* object is a plain ``bytearray`` -- ``x[:n]``,
    ``x.copy()``, ``x + y``, ``bytearray(x)`` -- and so is every ``bytes`` and
    ``str`` made from it (``bytes(x)``, ``x.decode()``, ``json.loads``).  Those
    copies are the caller's, and outside what the library can wipe.  Growing
    the buffer (``extend``, ``+=``, ``append``) can move it and strand the old
    block unwiped; the library never does, and callers should not.
    """

    __slots__ = ()

    def __del__(self) -> None:
        # Never raises: a failure is recorded where it can be observed
        # (INVARIANT-3, as `finalize_secret` does).  `_zero` is a module
        # global, so at interpreter shutdown it can already be None; the
        # TypeError that causes lands here, and `record_finalizer_error` is
        # itself shutdown-safe.
        try:
            _zero(self)
        except Exception as exc:  # — INVARIANT-3/9: __del__ must not raise
            record_finalizer_error("ZeroizingBytearray", f"wipe() failed: {exc}")

    def __repr__(self) -> str:
        return f"ZeroizingBytearray(<{len(self)} octets redacted>)"

    def __str__(self) -> str:
        return self.__repr__()

    def __reduce__(self) -> Any:
        raise TypeError("a ZeroizingBytearray holds a secret and is not pickled or copied")

    def __reduce_ex__(self, protocol: Any) -> Any:
        raise TypeError("a ZeroizingBytearray holds a secret and is not pickled or copied")

    def __copy__(self) -> Any:
        raise TypeError("a ZeroizingBytearray holds a secret and is not pickled or copied")

    def __deepcopy__(self, memo: Any) -> Any:
        raise TypeError("a ZeroizingBytearray holds a secret and is not pickled or copied")


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


def _each(action: Callable[[Any], None], items: Any) -> None:
    """Apply ``action`` to every item, in order, even when one raises.

    A wipe that stopped at its first failure would leave every later secret
    populated.  Each call is an exit callback, so all of them run; a failure
    propagates once they have, a later one carrying the earlier as its
    ``__context__``.  Nothing is caught, so nothing is swallowed.
    """
    with contextlib.ExitStack() as stack:
        for item in reversed(list(items)):
            stack.callback(action, item)


def _wipe_child(child: Any) -> None:
    child.wipe()


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
    _each(_wipe_child, children)


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
        A failure wiping one attribute or child does not spare the rest: all
        are attempted before it propagates.
        """
        # One stack for both, run last-in first-out: the attributes in order,
        # then the children in order (see :func:`_each`).
        with contextlib.ExitStack() as stack:
            for name in reversed(self._SECRET_CHILDREN):
                stack.callback(_wipe_children, self.__dict__.get(name))
            for name in reversed(self._SECRET_ATTRS):
                stack.callback(_zero, self.__dict__.get(name))

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
        return secrets_match(a, b)
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


_H = TypeVar("_H")


class ScrubOnRaise:
    """Zero every secret a code path has minted if that path raises.

    A function that draws or derives secrets and then runs checks that can
    still refuse drops them intact on the refusal: nothing owns them yet, and
    an exception gives no later point at which to zero them (INVARIANT-6,
    every exit path).  Register each secret as it is minted
    (``secret = held(...)``): a ``bytearray``, a list of them, or an object
    with a ``wipe()`` method such as a keypair.  On a clean exit nothing is
    touched, because the result has taken ownership; on an exception all of
    it is zeroed before the exception propagates.

    Register only what this path minted.  A secret the caller supplied is the
    caller's, and zeroing it on the way out of a failed call would destroy
    their key.
    """

    __slots__ = ("_held",)

    def __init__(self) -> None:
        self._held: list[Any] = []

    def __call__(self, secret: _H) -> _H:
        self._held.append(secret)
        return secret

    def __enter__(self) -> ScrubOnRaise:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if exc_type is None:
            return
        for secret in self._held:
            wipe = getattr(secret, "wipe", None)
            if callable(wipe):
                wipe()
            else:
                _zero(secret)
