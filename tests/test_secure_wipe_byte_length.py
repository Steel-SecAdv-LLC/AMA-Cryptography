# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A wipe must clear BYTES, not items — ``len()`` on a memoryview counts items.

WHY THIS TEST EXISTS

``secure_memzero`` and ``secure_mlock``/``secure_munlock`` accept
``memoryview``.  All three sized the region with ``len(data)``, and ``len()`` on
a memoryview counts ITEMS, not bytes.  For the byte-format views this module is
usually handed the two agree, and for a ``bytearray`` they always do — which is
exactly why the divergence went unnoticed.  On a view whose ``itemsize`` is
greater than one they differ by that factor.

Every native back-end then did::

    buf = (ctypes.c_char * length).from_buffer(data)

and ``from_buffer`` accepts a length SMALLER than the buffer, so nothing raised.
Measured before the fix, on ``memoryview(array('I', [0xDEADBEEF] * 8))`` — 8
items, 32 bytes — ``secure_memzero`` zeroed 8 bytes, returned normally, and left
**24 of 32 secret bytes intact**.  A wipe that reports success while three
quarters of the secret survives is worse than no wipe, because the caller stops
worrying (INVARIANT-6).

``secure_mlock``/``secure_munlock`` had the same defect with a different
consequence: locking ``len()`` bytes of a wider buffer leaves the rest of the
pages swappable, so secret material could still reach disk.

The non-contiguous case is refused rather than mis-wiped: a strided view's bytes
are not the ``nbytes`` bytes at its address, so any address+length wipe would
clear memory the caller did not pass and miss memory it did.
"""

from __future__ import annotations

import array

import pytest

from ama_cryptography.secure_memory import (
    SecureMemoryError,
    _byte_length,
    secure_memzero,
)

#: (typecode, itemsize) pairs whose itemsize is guaranteed > 1 on every CPython
#: build this project supports.
WIDE_TYPECODES = ["H", "i", "I", "q", "Q", "d"]


@pytest.mark.parametrize("typecode", WIDE_TYPECODES)
def test_every_byte_of_a_wide_memoryview_is_wiped(typecode: str) -> None:
    # Built per branch rather than with a shared filler: 'd' takes floats and
    # the integer typecodes take ints, and a union of the two is not a valid
    # argument to either constructor.
    buf = array.array("d", [1.5] * 8) if typecode == "d" else array.array(typecode, [0x41] * 8)
    view = memoryview(buf)
    assert view.itemsize > 1, typecode
    assert len(view) < view.nbytes, "fixture must exercise the items-vs-bytes gap"

    secure_memzero(view)

    residual = [b for b in memoryview(buf).cast("B") if b != 0]
    assert not residual, (
        f"{len(residual)} of {view.nbytes} bytes survived secure_memzero on an "
        f"itemsize-{view.itemsize} memoryview. The wipe was sized with len() "
        f"({len(view)} items) instead of .nbytes ({view.nbytes})."
    )


def test_byte_length_reports_bytes_for_a_wide_view() -> None:
    view = memoryview(array.array("I", [0] * 8))
    assert len(view) == 8
    assert _byte_length(view) == 32 == view.nbytes


def test_byte_length_is_unchanged_for_the_byte_shaped_inputs() -> None:
    """The common cases must not move: bytearray and byte-format views."""
    assert _byte_length(bytearray(41)) == 41
    assert _byte_length(memoryview(bytearray(41))) == 41
    assert _byte_length(b"\x00" * 41) == 41


def test_a_bytearray_is_still_wiped() -> None:
    secret = bytearray(b"sensitive-key-material")
    secure_memzero(secret)
    assert not any(secret)


def test_a_byte_memoryview_is_still_wiped() -> None:
    backing = bytearray(b"sensitive-key-material")
    secure_memzero(memoryview(backing))
    assert not any(backing)


def test_a_non_contiguous_view_is_refused_rather_than_partially_wiped() -> None:
    """A strided view's bytes are not the nbytes bytes at its address.

    Wiping it by address+length would clear memory the caller did not pass.
    ``ctypes.from_buffer`` already rejects it; the point of the explicit guard
    is that the refusal is this module's documented failure type instead of an
    escaping ``TypeError``.
    """
    strided = memoryview(array.array("I", [0x41414141] * 8))[::2]
    assert not strided.c_contiguous
    with pytest.raises(SecureMemoryError, match="C-contiguous"):
        secure_memzero(strided)


def test_the_empty_case_is_still_a_no_op() -> None:
    secure_memzero(bytearray())
    secure_memzero(memoryview(array.array("I")))
