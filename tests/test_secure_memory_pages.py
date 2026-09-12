# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Page-lock accounting, abandoned-buffer wiping and buffer-protocol compare.

Three properties of :mod:`ama_cryptography.secure_memory` that the previous
release documented but did not deliver, each pinned here against the kernel
or the interpreter rather than against the module's own bookkeeping:

* Releasing one locked buffer must not unlock a different live buffer that
  shares its page.  Read back from ``/proc/self/smaps`` (the kernel's own
  VM_LOCKED record), Linux only.
* A ``SecureBuffer`` that is entered and then dropped without ``__exit__``
  must still be wiped when it is collected.
* ``constant_time_compare`` must accept every type the package stores
  secrets in -- ``bytes``, ``bytearray`` and ``memoryview`` -- and give the
  same verdict for the same bytes.
"""

from __future__ import annotations

import ctypes
import gc
import sys
from typing import Union

import pytest

from ama_cryptography import secure_memory as sm


def _page_locked(addr: int) -> bool:
    """Whether the page holding ``addr`` carries the kernel's VM_LOCKED flag."""
    page = addr & ~(sm._PAGE_SIZE - 1)
    with open("/proc/self/smaps", encoding="ascii") as f:
        lines = f.read().splitlines()
    current = None
    for line in lines:
        if "-" in line.split(" ", 1)[0] and not line.startswith(("VmFlags", "Size")):
            start, end = line.split(" ", 1)[0].split("-")
            current = (int(start, 16), int(end, 16))
        elif line.startswith("VmFlags:") and current and current[0] <= page < current[1]:
            return " lo" in line or line.endswith("lo")
    raise AssertionError("page not found in /proc/self/smaps")


def _addr(buf: bytearray) -> int:
    return ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))


@pytest.mark.skipif(sys.platform != "linux", reason="reads /proc/self/smaps")
def test_unlocking_one_buffer_keeps_a_page_sharing_neighbour_locked() -> None:
    # Many small buffers so that at least two land on one page.
    buffers = [bytearray(48) for _ in range(256)]
    locked = []
    try:
        for b in buffers:
            sm.secure_mlock(b)
            locked.append(b)
    except (sm.SecureMemoryError, NotImplementedError) as exc:
        for b in locked:
            sm.secure_munlock(b)
        pytest.skip(f"mlock unavailable here: {exc}")
    by_page: dict[int, list[bytearray]] = {}
    for b in locked:
        by_page.setdefault(_addr(b) & ~(sm._PAGE_SIZE - 1), []).append(b)
    shared = next((v for v in by_page.values() if len(v) >= 2), None)
    if shared is None:
        for b in locked:
            sm.secure_munlock(b)
        pytest.skip("no two buffers shared a page in this allocator layout")
    a, b = shared[0], shared[1]
    assert _page_locked(_addr(b))
    sm.secure_munlock(a)
    assert _page_locked(_addr(b)), "unlocking a neighbour dropped the kernel lock on a live buffer"
    for other in locked:
        if other is not a:
            sm.secure_munlock(other)
    assert not _page_locked(_addr(b)), "the last unlock must release the page"


def test_abandoned_secure_buffer_is_wiped_by_its_finalizer() -> None:
    sb = sm.SecureBuffer(16, lock=False)
    data = sb.__enter__()
    data[:] = b"K" * 16
    del sb
    gc.collect()
    assert bytes(data) == b"\x00" * 16, "an entered-but-never-exited buffer kept its secret"


def test_exited_buffer_is_not_wiped_twice_by_the_finalizer() -> None:
    sb = sm.SecureBuffer(8, lock=False)
    with sb as data:
        data[:] = b"secret!!"
    # Reuse of the storage after __exit__ must not be clobbered by a stale finalizer.
    data[:] = b"reused!!"
    del sb
    gc.collect()
    assert bytes(data) == b"reused!!"


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (bytearray(b"secret"), b"secret", True),
        (b"secret", bytearray(b"secret"), True),
        (bytearray(b"secret"), bytearray(b"Secret"), False),
        (memoryview(bytearray(b"secret")), b"secret", True),
        (memoryview(b"secret"), bytearray(b"secret"), True),
        (memoryview(b"secret"), b"secre", False),
        (bytearray(), b"", True),
        (memoryview(bytearray()), bytearray(b"x"), False),
    ],
)
def test_constant_time_compare_accepts_every_secret_buffer_type(
    a: Union[bytes, bytearray, memoryview],
    b: Union[bytes, bytearray, memoryview],
    expected: bool,
) -> None:
    assert sm.constant_time_compare(a, b) is expected


def test_constant_time_compare_rejects_non_contiguous_views() -> None:
    with pytest.raises(TypeError):
        sm.constant_time_compare(memoryview(bytearray(b"abcdef"))[::2], b"ace")
