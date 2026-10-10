#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The exact-size writer behind the private-key encodings.

``_secret_writer`` measures a structure from lengths alone, allocates one
buffer of exactly that size and copies every piece into it.  Pinned here:
header bytes against independent X.690 / RFC 8949 encoders, a failure leaves
a zeroed output, the piece tree keeps no reference to the secret, and no
temporary the size of the secret is allocated.
"""

from __future__ import annotations

import gc
import tracemalloc
from typing import Any, Callable

import pytest

from ama_cryptography import _secret_writer as sw
from ama_cryptography._secret_material import ZeroizingBytearray


# ---------------------------------------------------------------------------
# Independent encoders: the length rules, written out
# ---------------------------------------------------------------------------
def der_length(n: int) -> bytes:
    """X.690 §8.1.3, spelled out by threshold (no shared code with ``_asn1``)."""
    if n <= 127:
        return bytes([n])
    if n <= 0xFF:
        return bytes([0x81, n])
    if n <= 0xFFFF:
        return bytes([0x82, n >> 8, n & 0xFF])
    return bytes([0x83, n >> 16, (n >> 8) & 0xFF, n & 0xFF])


def cbor_bstr_head(n: int) -> bytes:
    """RFC 8949 §3, major type 2, shortest form, by threshold."""
    if n <= 23:
        return bytes([0x40 | n])
    if n <= 0xFF:
        return bytes([0x58, n])
    if n <= 0xFFFF:
        return bytes([0x59, n >> 8, n & 0xFF])
    return bytes([0x5A, n >> 24, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def secret(n: int) -> bytearray:
    return bytearray((i * 7 + 3) & 0xFF for i in range(n))


BOUNDARIES = [0, 1, 23, 24, 127, 128, 255, 256, 65535, 65536]


@pytest.mark.parametrize("n", BOUNDARIES)
def test_a_der_header_is_the_minimal_definite_length(n: int) -> None:
    """RANGE (an independent oracle over the length thresholds): 0, 1, 127,
    128, 255, 256, 65535 and 65536 octets, where the form changes.  A header
    that miscomputes a threshold fails the row at that boundary."""
    body = secret(n)
    out = sw.build(sw.tlv(0x04, sw.Sec(lambda: body)))
    assert bytes(out) == bytes([0x04]) + der_length(n) + bytes(body)


@pytest.mark.parametrize("n", BOUNDARIES)
def test_a_cbor_byte_string_head_is_the_shortest_form(n: int) -> None:
    """RANGE: 23/24 (inline vs one octet), 255/256 (one vs two), 65535/65536
    (two vs four)."""
    body = secret(n)
    out = sw.build(sw.cbor_bytes(sw.Sec(lambda: body)))
    assert bytes(out) == cbor_bstr_head(n) + bytes(body)


def test_nested_frames_size_from_the_inside_out() -> None:
    """RANGE.  A SEQUENCE of OCTET STRINGs whose inner lengths straddle 128:
    the outer header must be computed from the *sum*, headers included."""
    parts = [secret(100), secret(30)]  # 102 + 32 = 134 > 127
    out = sw.build(
        sw.tlv(
            0x30,
            sw.tlv(0x04, sw.Sec(lambda: parts[0])),
            sw.tlv(0x04, sw.Sec(lambda: parts[1])),
        )
    )
    expected = (
        bytes([0x04]) + der_length(100) + bytes(parts[0]) + bytes([0x04]) + der_length(30)
    ) + bytes(parts[1])
    assert bytes(out) == bytes([0x30]) + der_length(len(expected)) + expected


def test_cbor_map_is_sorted_by_encoded_key_and_refuses_a_repeat() -> None:
    """PIN of the ordering rule (RFC 8949 §4.2.1): sorted on the *encoded*
    key, so the negative integers (0x20..) follow the positive (0x01).
    Removing the sort fails this."""
    members = [
        (b"\x23", sw.Lit(b"\xf4")),
        (b"\x01", sw.Lit(b"\xf5")),
        (b"\x21", sw.Lit(b"\xf6")),
    ]
    assert bytes(sw.build(sw.cbor_map(members))) == b"\xa3\x01\xf5\x21\xf6\x23\xf4"
    with pytest.raises(ValueError, match="duplicate key"):
        sw.cbor_map([(b"\x01", sw.Lit(b"a")), (b"\x01", sw.Lit(b"b"))])


@pytest.mark.parametrize("n", [0, 1, 63, 64, 65, 127, 128, 129, 192, 193])
def test_wrapped_lines_are_64_columns_each_ended_by_lf(n: int) -> None:
    """RANGE.  Every line but the last is 64 characters, the last 1..64, each
    ended by LF; an empty secret is one empty line (as the text encoding always
    was)."""
    chars = bytearray(b"A" * n)
    out = bytes(sw.build(sw.Wrapped(lambda: chars, 64)))
    expected = b"\n" if n == 0 else b"".join(b"A" * min(64, n - i) + b"\n" for i in range(0, n, 64))
    assert out == expected


def test_the_output_is_a_zeroizing_bytearray_of_exactly_the_measured_size() -> None:
    """PIN.  ``build`` returns the self-zeroing type, at exactly ``size()``.
    Returning a plain ``bytearray`` fails the type check."""
    body = secret(40)
    piece = sw.tlv(0x04, sw.Sec(lambda: body))
    out = sw.build(piece)
    assert type(out) is ZeroizingBytearray
    assert len(out) == piece.size() == 42


# ---------------------------------------------------------------------------
# What may be written from
# ---------------------------------------------------------------------------
def test_a_lit_is_public_bytes_only() -> None:
    """PIN.  A secret never travels in a ``Lit``: ``bytearray`` (the key's own
    type), ``str`` and ``memoryview`` are refused.  Relaxing the type check
    fails this."""
    refusals: list[Any] = [bytearray(b"k"), "k", memoryview(b"k")]
    for refused in refusals:
        with pytest.raises(TypeError, match="public bytes"):
            sw.Lit(refused)


@pytest.mark.parametrize(
    "bad", [b"\x01\x02", "text", memoryview(b"\x01\x02")], ids=["bytes", "str", "readonly"]
)
def test_a_sec_refuses_an_immutable_secret(bad: Any) -> None:
    """PIN.  ``Sec`` writes from a ``bytearray`` or a writable view and
    refuses ``bytes``, ``str`` and a read-only view rather than copy a secret
    out of something nothing can wipe.  Accepting ``bytes`` fails this."""
    with pytest.raises(TypeError):
        sw.build(sw.tlv(0x04, sw.Sec(lambda: bad)))


def test_a_sec_writes_from_a_writable_view_slice() -> None:
    """SMOKE.  A writable ``memoryview`` slice of a larger buffer is written
    as its own octets (the PEM scanner and the importers rely on slices)."""
    whole = secret(64)
    view = memoryview(whole)
    out = sw.build(sw.Sec(lambda: view[8:24]))
    assert bytes(out) == bytes(whole[8:24])
    view.release()


# ---------------------------------------------------------------------------
# Every exit path
# ---------------------------------------------------------------------------
class _Recorder:
    """Captures the output buffers ``build`` allocates.  The writer names
    ``ZeroizingBytearray`` as a module global, so a subclass patched in there
    sees each one; holding it keeps the buffer alive for inspection."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.buffers: list[ZeroizingBytearray] = []
        recorder = self

        class Recording(ZeroizingBytearray):
            def __init__(self, *args: Any) -> None:
                super().__init__(*args)
                recorder.buffers.append(self)

        monkeypatch.setattr(sw, "ZeroizingBytearray", Recording)


def test_a_piece_that_raises_mid_write_leaves_the_output_zeroed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The first secret is already in the output when the second piece
    raises; the output is zeroed before the exception leaves ``build``.
    Removing the ``ScrubOnRaise`` registration fails this."""
    recorder = _Recorder(monkeypatch)
    first, second = secret(32), secret(32)

    class Boom(sw.Piece):
        def size(self) -> int:
            return 1

        def write(self, out: memoryview, at: int) -> int:
            raise RuntimeError("injected")

    piece = sw.cat(sw.Sec(lambda: first), Boom(), sw.Sec(lambda: second))
    with pytest.raises(RuntimeError, match="injected"):
        sw.build(piece)
    (buffer,) = recorder.buffers
    assert len(buffer) == 65 and not any(buffer)


def test_a_piece_that_disagrees_with_its_own_size_is_refused_and_zeroed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  ``size`` says 40, ``write`` stops at 32: a short or long write is
    a bug that must not ship a half-filled buffer.  Removing the ``end !=
    total`` check fails this."""
    recorder = _Recorder(monkeypatch)
    body = secret(32)

    class Liar(sw.Sec):
        def size(self) -> int:
            return 40

    with pytest.raises(ValueError, match="measured 40"):
        sw.build(Liar(lambda: body))
    (buffer,) = recorder.buffers
    assert not any(buffer)


def test_a_successful_build_does_not_scrub_its_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """SMOKE.  The scrub is for exceptions only; the result is the caller's."""
    body = secret(32)
    out = sw.build(sw.Sec(lambda: body))
    assert bytes(out) == bytes(body)


# ---------------------------------------------------------------------------
# No strong reference to the secret survives
# ---------------------------------------------------------------------------
def _holders(target: bytearray) -> list[Any]:
    """Every gc-tracked object other than frames and lists of the caller that
    refers to ``target``."""
    gc.collect()
    return [r for r in gc.get_referrers(target) if not isinstance(r, (type(_holders),))]


def test_the_piece_tree_holds_no_reference_to_the_secret_after_a_build() -> None:
    """PIN.  ``Sec`` takes a getter and binds the buffer only while it copies
    it, so a tree that outlives its ``build`` (a local in a frame kept by a
    traceback) refers to nothing that matters to the key's last-owner wipe.
    Making ``Sec`` hold the buffer directly puts the ``Sec`` among the
    referrers and fails this."""
    body = secret(32)

    def getter() -> bytearray:
        return body

    piece = sw.tlv(0x04, sw.Sec(getter))
    sw.build(piece)
    referrers = [type(r).__name__ for r in _holders(body)]
    assert "Sec" not in referrers and "Framed" not in referrers, referrers


def test_the_piece_tree_holds_no_reference_to_the_secret_after_a_failed_build() -> None:
    """PIN.  The same after a build that raised, with the exception (hence its
    traceback and the frames' locals) still alive."""
    body = secret(32)

    class Boom(sw.Piece):
        def size(self) -> int:
            return 1

        def write(self, out: memoryview, at: int) -> int:
            raise RuntimeError("injected")

    piece = sw.cat(sw.Sec(lambda: body), Boom())
    try:
        sw.build(piece)
    except RuntimeError as exc:
        kept = exc  # the traceback, with every frame's locals, stays alive
    referrers = [type(r).__name__ for r in _holders(body)]
    assert "Sec" not in referrers and "Framed" not in referrers, referrers
    assert kept.__traceback__ is not None


class _Overrun(sw.Piece):
    """Claims one octet, writes one, and reports having written nine: whatever
    follows it is written past the end of the output."""

    def size(self) -> int:
        return 1

    def write(self, out: memoryview, at: int) -> int:
        out[at : at + 1] = b"x"
        return at + 9


def test_a_failed_copy_releases_its_view_of_the_secret() -> None:
    """PIN.  When the copy in ``Sec.write`` raises, its view of the secret is
    already released, so the key's buffer can still be resized."""
    body = secret(32)
    piece = sw.cat(_Overrun(), sw.Sec(lambda: body))
    try:
        sw.build(piece)
    except ValueError as exc:
        kept = exc  # frames, with their locals, stay alive
    body.extend(b"\x00")  # raises BufferError while any export is live
    assert kept.__traceback__ is not None


def test_a_failed_wrapped_copy_releases_its_view_of_the_characters() -> None:
    """PIN.  When a line copy in ``Wrapped.write`` raises, its view of the Base64
    characters is already released."""
    chars = bytearray(b"A" * 100)
    piece = sw.cat(_Overrun(), sw.Wrapped(lambda: chars, 64))
    try:
        sw.build(piece)
    except (ValueError, IndexError) as exc:
        kept = exc  # frames, with their locals, stay alive
    chars.extend(b"\x00")  # raises BufferError while any export is live
    assert kept.__traceback__ is not None


@pytest.mark.parametrize("shape", ["plain", "typed", "two-dimensional"])
def test_a_sec_flattens_a_view_of_another_format_to_octets(shape: str) -> None:
    """PIN.  ``Sec`` writes the octets of a view of any format or shape, and
    releasing its cast leaves the caller's view usable."""
    body = secret(32)
    held = memoryview(body)
    views = {
        "plain": held,
        "typed": held.cast("I"),
        "two-dimensional": held.cast("B", shape=[4, 8]),
    }
    view = views[shape]
    piece = sw.Sec(lambda: view)
    assert piece.size() == 32
    out = sw.build(sw.tlv(0x04, piece))
    assert bytes(out) == bytes([0x04, 32]) + bytes(body)
    # The caller's view is still theirs: neither measuring nor writing released it.
    assert view.nbytes == 32 and view.tobytes() == bytes(body)
    for item in views.values():
        item.release()
    held.release()


def test_measuring_a_secret_leaves_no_view_of_it_behind() -> None:
    """SMOKE.  After ``Sec.size()`` the secret can still be resized."""
    body = secret(32)
    view = sw.Sec(lambda: body)
    assert view.size() == 32
    body.extend(b"\x00")  # a released view leaves no export behind


# ---------------------------------------------------------------------------
# No hidden temporary
# ---------------------------------------------------------------------------
def _peak_over_result(make: Callable[[], Any]) -> tuple[int, int]:
    """``(peak extra bytes while building, size of the result)``."""
    tracemalloc.start()
    try:
        baseline = tracemalloc.get_traced_memory()[0]
        tracemalloc.reset_peak()
        out = make()
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return peak - baseline, len(out)


def test_writing_a_large_secret_allocates_the_output_and_nothing_beside_it() -> None:
    """PIN.  ``bytearray[a:b] = x`` makes a hidden temporary copy of ``x`` when
    ``x`` is not a ``bytearray``, so the target is a ``memoryview`` and so is the source.  A 512 KiB
    secret builds in output + 8 KiB; assigning into the ``bytearray``
    directly, or through ``bytes(view)``, doubles it and fails this."""
    body = secret(512 * 1024)
    extra, size = _peak_over_result(lambda: sw.build(sw.tlv(0x04, sw.Sec(lambda: body))))
    assert size > 512 * 1024
    assert extra <= size + 8 * 1024, f"peak {extra} for a {size}-octet result"
