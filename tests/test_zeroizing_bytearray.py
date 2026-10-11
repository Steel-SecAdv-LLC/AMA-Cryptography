#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""``ZeroizingBytearray``: the buffer a private key's encodings are returned in.

A ``bytearray`` subclass that zeroes itself when collected, prints its length
and never its content, and refuses the copies ``pickle`` and ``copy`` make.
"""

from __future__ import annotations

import copy
import ctypes
import gc
import hashlib
import pickle
import subprocess
import sys
import textwrap
import tracemalloc
from pathlib import Path
from typing import Any, Callable

import pytest

import ama_cryptography._secret_writer as sw
import ama_cryptography.key_formats as kf
import ama_cryptography.pqc_backends as pb
from ama_cryptography import _finalizer_health as fh
from ama_cryptography import _secret_material as sm
from ama_cryptography._secret_material import ZeroizingBytearray
from tests.test_private_key_export import make_private

SECRET = bytes(range(1, 33))


@pytest.fixture
def zeroed(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, bytes]]:
    """Every object the module's own ``zeroize`` is asked to zero, as
    ``(id, contents after)``.  An id is not a reference, so recording it does
    not keep the buffer alive (a probe that held it would stop ``__del__``)."""
    seen: list[tuple[int, bytes]] = []
    real = sm.zeroize

    def spy(value: Any) -> None:
        real(value)
        seen.append((id(value), bytes(value) if isinstance(value, bytearray) else b""))

    monkeypatch.setattr(sm, "_zero", spy)
    return seen


def test_a_dropped_buffer_is_zeroed(zeroed: list[tuple[int, bytes]]) -> None:
    """PIN.  Collection zeroes the buffer, through the module's own
    ``zeroize``.  Deleting ``__del__`` (or its ``_zero(self)``) fails this."""
    buf = ZeroizingBytearray(SECRET)
    ident = id(buf)
    del buf
    gc.collect()
    assert (ident, bytes(len(SECRET))) in zeroed


def test_a_buffer_that_is_still_exported_is_not_zeroed_under_its_holder() -> None:
    """SMOKE.  A live ``memoryview`` keeps the object alive, so the finalizer
    has not run and the holder's bytes are intact: no last-owner test is
    needed.  This holds with or without a guard, and is CPython's rule."""
    buf = ZeroizingBytearray(SECRET)
    view = memoryview(buf)
    del buf
    gc.collect()
    assert bytes(view) == SECRET
    view.release()


def test_a_failed_wipe_is_recorded_and_never_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIN.  INVARIANT-3/9: a finalizer failure is recorded where it can be
    observed and is not raised (the interpreter would print it and carry on).
    Removing the ``except`` fails the unraisable check; removing the
    ``record_finalizer_error`` call fails the counter check."""

    def failing(_value: Any) -> None:
        raise RuntimeError("simulated wipe failure")

    unraisable: list[Any] = []
    monkeypatch.setattr(sys, "unraisablehook", unraisable.append)
    monkeypatch.setattr(sm, "_zero", failing)
    before = fh.finalizer_error_count()
    buf = ZeroizingBytearray(SECRET)
    del buf
    gc.collect()
    assert unraisable == []
    assert fh.finalizer_error_count() == before + 1
    last = fh.last_finalizer_error()
    assert last is not None and last[0] == "ZeroizingBytearray"


def test_shutdown_with_a_live_buffer_is_silent() -> None:
    """SMOKE.  A buffer still alive when the interpreter exits is finalized
    with module globals possibly already None; that must not print."""
    script = textwrap.dedent("""
        from ama_cryptography._secret_material import ZeroizingBytearray
        LIVE = ZeroizingBytearray(b"\\x5a" * 64)
        """)
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parent.parent),
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "Exception ignored" not in proc.stderr and "Traceback" not in proc.stderr


@pytest.mark.parametrize("show", [repr, str, "{}".format, "%s".__mod__, "%r".__mod__])
def test_the_text_forms_never_print_the_content(show: Any) -> None:
    """PIN.  ``repr`` and ``str`` (hence ``format``, ``%s``, f-strings, logging)
    print the length only.  CPython's ``bytearray.__str__`` calls the C repr
    directly, so redacting ``__repr__`` alone would not cover ``str``: removing
    ``__str__`` fails this for ``str``, ``format`` and ``%s``; removing
    ``__repr__`` fails it for ``repr`` and ``%r``."""
    buf = ZeroizingBytearray(SECRET)
    text = show(buf)
    assert "32 octets redacted" in text
    assert "\\x01" not in text and SECRET.hex() not in text and "x02" not in text


@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
def test_pickling_is_refused(protocol: int) -> None:
    """PIN.  An implicit pickle is a second buffer nothing wipes."""
    with pytest.raises(TypeError, match="not pickled or copied"):
        pickle.dumps(ZeroizingBytearray(SECRET), protocol)


@pytest.mark.parametrize("duplicate", [copy.copy, copy.deepcopy])
def test_copying_is_refused(duplicate: Any) -> None:
    """PIN.  ``copy.copy`` and ``copy.deepcopy`` raise rather than mint a
    second, unwiped secret."""
    with pytest.raises(TypeError, match="not pickled or copied"):
        duplicate(ZeroizingBytearray(SECRET))


def test_each_refusal_hook_is_called_directly() -> None:
    """PIN of the four hooks individually.  ``pickle`` and ``copy`` both reach
    ``__reduce_ex__``, so on the stdlib's paths it alone suffices and the other
    three are redundant; calling each hook pins that each one refuses."""
    buf = ZeroizingBytearray(SECRET)
    for hook in (
        buf.__reduce__,
        lambda: buf.__reduce_ex__(4),
        buf.__copy__,
        lambda: buf.__deepcopy__({}),
    ):
        with pytest.raises(TypeError):
            hook()


def test_it_is_a_bytearray_that_compares_equal_to_bytes() -> None:
    """SMOKE.  Every consumer that takes a ``bytearray`` works, ``==`` against
    ``bytes`` holds (the KATs compare so), ``==`` against ``str`` is silently
    False, and it is unhashable."""
    buf = ZeroizingBytearray(SECRET)
    assert isinstance(buf, bytearray) and not isinstance(buf, bytes)
    # Compared through `Any`: mypy's strict equality calls bytearray/bytes and
    # bytearray/str non-overlapping, which is the very behaviour under test.
    left: Any = buf
    assert left == SECRET and left == bytearray(SECRET) and not left == SECRET.hex()
    with pytest.raises(TypeError, match="unhashable"):
        hash(buf)


def test_derived_objects_are_plain_and_outside_the_guarantee() -> None:
    """SMOKE (a measurement the documentation states): slicing, ``copy()``,
    concatenation and ``bytearray(x)`` return a plain ``bytearray``; ``bytes(x)``
    and ``decode()`` are immutable.  None of them zeroes itself."""
    buf = ZeroizingBytearray(SECRET)
    assert type(buf[:4]) is bytearray
    assert type(buf.copy()) is bytearray
    assert type(buf + b"x") is bytearray
    assert type(b"x" + buf) is bytes
    assert type(buf * 2) is bytearray
    assert type(bytearray(buf)) is bytearray
    assert type(bytes(buf)) is bytes
    assert type(buf.decode("latin-1")) is str


def test_it_works_where_a_bytes_like_is_taken(tmp_path: Path) -> None:
    """SMOKE.  The buffer protocol, ``hashlib``, ctypes, files."""
    buf = ZeroizingBytearray(SECRET)
    assert hashlib.sha256(buf).digest() == hashlib.sha256(SECRET).digest()
    array = (ctypes.c_char * len(buf)).from_buffer(buf)
    assert bytes(array) == SECRET
    del array
    target = tmp_path / "secret.bin"
    target.write_bytes(buf)
    assert target.read_bytes() == SECRET
    text_writer: Any = target
    with pytest.raises(TypeError):
        text_writer.write_text(buf, encoding="utf-8")


# ---------------------------------------------------------------------------
# Collection wipes the whole buffer, at the sizes real exports have
# ---------------------------------------------------------------------------
def _observing(sink: list[tuple[int, bool, bool]]) -> type[ZeroizingBytearray]:
    """A ``ZeroizingBytearray`` that records, as its finalizer finishes,
    ``(length, held data on arrival, still holds data)``.  The record is made
    by the object itself after the real finalizer ran, so the test holds no
    reference to it (a holder would stop ``__del__``) and reads the contents
    the finalizer left, not the fact that some function was called."""

    class Observed(ZeroizingBytearray):
        def __del__(self) -> None:
            arrived = any(self)
            super().__del__()
            sink.append((len(self), arrived, any(self)))

    return Observed


@pytest.mark.parametrize("size", [1, 32, 64, 65, 241, 1000, 1001, 4096, 4097, 70_000])
def test_a_dropped_buffer_is_zero_at_every_size(size: int) -> None:
    """PIN.  The finalizer zeroes the whole buffer whatever its length."""
    sink: list[tuple[int, bool, bool]] = []
    buf = _observing(sink)(b"\xa5" * size)
    del buf
    gc.collect()
    assert sink == [(size, True, False)]


REAL_EXPORTS: dict[str, tuple[str, Callable[[Any], Any], int]] = {
    "PEM (P-256)": ("P-256", lambda k: k.to_pem(), 200),
    "PEM (ML-DSA-65, expanded key)": (
        "ML-DSA-65",
        lambda k: k.to_pem(pq_format="expandedKey"),
        5000,
    ),
    "PKCS#8 (ML-DSA-65, expanded key)": (
        "ML-DSA-65",
        lambda k: k.to_pkcs8(pq_format="expandedKey"),
        4000,
    ),
    "PKCS#8 (ML-KEM-1024, both)": ("ML-KEM-1024", lambda k: k.to_pkcs8(pq_format="both"), 3000),
    "JWK (P-521)": ("P-521", lambda k: k.to_jwk(), 200),
    "COSE (P-521)": ("P-521", lambda k: k.to_cose(), 200),
}


@pytest.mark.skipif(pb._native_lib is None, reason="native library not built")
@pytest.mark.parametrize("export", sorted(REAL_EXPORTS))
def test_a_dropped_export_is_zero_at_its_real_size(
    monkeypatch: pytest.MonkeyPatch, export: str
) -> None:
    """PIN.  The same on the buffers the library returns (all over 64 octets)."""
    name, run, at_least = REAL_EXPORTS[export]
    key = make_private(name)
    sink: list[tuple[int, bool, bool]] = []
    observed = _observing(sink)
    monkeypatch.setattr(sw, "ZeroizingBytearray", observed)
    monkeypatch.setattr(kf, "ZeroizingBytearray", observed)
    out = run(key)
    size = len(out)
    assert type(out) is observed and size > at_least
    del out
    gc.collect()
    assert (size, True, False) in sink, sink
    assert all(not after for _, _, after in sink), sink


# ---------------------------------------------------------------------------
# The wipe allocates nothing the size of the secret
# ---------------------------------------------------------------------------
_RUN = sm._ZERO_RUN


@pytest.mark.parametrize(
    "size", [0, 1, _RUN - 1, _RUN, _RUN + 1, 2 * _RUN, 2 * _RUN + 7, 3 * _RUN - 1, 5 * _RUN + 3]
)
def test_zeroize_zeroes_every_octet_across_run_boundaries(size: int) -> None:
    """RANGE.  The wipe copies zeros in runs of ``_ZERO_RUN``; every length
    around a run boundary comes out all-zero and the same length.  A loop that
    stops a run early, drops the short final run, or steps by the wrong width
    fails the row it breaks."""
    buf = bytearray(b"\xff") * size
    sm.zeroize(buf)
    assert len(buf) == size and not any(buf)


def test_zeroize_wipes_under_a_live_view_and_leaves_the_buffer_resizable() -> None:
    """SMOKE.  A holder's ``memoryview`` sees the zeros (the wipe is in place,
    not a replacement), and once the holder lets go the buffer can be resized,
    so the wipe left no export of its own behind."""
    buf = bytearray(b"\xff") * 100
    view = memoryview(buf)
    sm.zeroize(buf)
    assert not any(view)
    view.release()
    buf.extend(b"\x00")


def test_zeroizing_allocates_nothing_the_size_of_the_secret() -> None:
    """PIN.  Wiping 1 MiB peaks at a few KiB over the baseline.  The previous
    spelling, ``memoryview(value)[:] = bytes(len(value))``, allocated a
    key-sized all-zero object per wipe, so a wipe run under the memory pressure
    that aborted an export could itself fail with ``MemoryError``.  Restoring
    it (peak: 1 MiB) fails this."""
    big = bytearray(b"\xff") * (1 << 20)
    sm.zeroize(big)  # warm any lazy structure
    big = bytearray(b"\xff") * (1 << 20)
    tracemalloc.start()
    try:
        baseline = tracemalloc.get_traced_memory()[0]
        tracemalloc.reset_peak()
        sm.zeroize(big)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert not any(big)
    assert peak - baseline <= 2 * _RUN, f"wiping 1 MiB peaked at {peak - baseline} octets"
