# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Record every immutable copy made of the ctypes char buffers a wrapper allocates
=============================================================================

A ``ctypes`` char array hands its contents out as ``bytes`` through ``.raw``,
``.value``, slicing and ``bytes()``, and ``ctypes.string_at`` does the same for
an address.  Each is an immutable object that no ``close()``, ``memset`` or
``finally`` can reach.  For a buffer holding a secret, each is therefore a copy
of the secret that outlives every wipe the wrapper performs (INVARIANT-6), and
a test that inspects only the buffer the wrapper keeps cannot see it.

:func:`record_char_buffer_copies` makes ``ctypes.create_string_buffer(n)``
return an instrumented array for every ``n`` in ``sizes``, wraps
``ctypes.string_at``, and returns the list every such copy is appended to.  A
test then asserts that no recorded copy contains the secret.

Not recorded, deliberately: reads through the buffer protocol
(``memoryview(buf)``).  A view is not a copy, and ``bytes(view[a:b])`` copies
only the range it names — which is how a wrapper reads a public half out of a
buffer whose other half is secret.  A test using this module takes its own
reference copy of the secret that way, so the reference is not itself counted.
"""

from __future__ import annotations

import ctypes
from typing import Any, Callable

import pytest


def record_char_buffer_copies(monkeypatch: pytest.MonkeyPatch, sizes: set[int]) -> list[bytes]:
    """Instrument ``create_string_buffer`` for ``sizes`` and ``string_at``.

    Returns the list of every ``bytes`` object handed out by an instrumented
    buffer or by ``ctypes.string_at`` while ``monkeypatch`` is active.
    """
    copies: list[bytes] = []
    classes: dict[int, Any] = {}
    real_create = ctypes.create_string_buffer
    real_string_at = ctypes.string_at

    def record(data: Any) -> Any:
        if isinstance(data, bytes):
            copies.append(data)
        return data

    def instrumented(size: int) -> Any:
        cls: Any = type(f"InstrumentedCharArray{size}", (ctypes.c_char * size,), {})
        # The ctypes metaclass installs ``raw`` and ``value`` on every char
        # array class it creates, subclasses included, so an override written
        # in a class body is replaced; they are overridden after creation.
        raw = cls.__dict__["raw"]
        value = cls.__dict__["value"]
        getitem: Callable[[Any, Any], Any] = cls.__getitem__

        cls.raw = property(
            lambda self: record(raw.__get__(self)), lambda self, v: raw.__set__(self, v)
        )
        cls.value = property(
            lambda self: record(value.__get__(self)), lambda self, v: value.__set__(self, v)
        )
        cls.__getitem__ = lambda self, key: record(getitem(self, key))
        cls.__bytes__ = lambda self: record(bytes(memoryview(self)))
        return cls

    def create_string_buffer(init: Any, size: Any = None) -> Any:
        if isinstance(init, int) and size is None and init in sizes:
            if init not in classes:
                classes[init] = instrumented(init)
            return classes[init]()
        return real_create(init) if size is None else real_create(init, size)

    def string_at(ptr: Any, size: int = -1) -> bytes:
        data: bytes = record(real_string_at(ptr, size))
        return data

    monkeypatch.setattr(ctypes, "create_string_buffer", create_string_buffer)
    monkeypatch.setattr(ctypes, "string_at", string_at)
    return copies
