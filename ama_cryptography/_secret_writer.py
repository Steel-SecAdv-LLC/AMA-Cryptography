#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Exact-size writer for the encodings of a private key (INVARIANT-6)
===================================================================

A private key's PKCS#8, PEM, JWK and COSE_Key encodings contain the key.
:mod:`ama_cryptography._asn1` builds structure the way a parser's inverse
does -- ``bytes([tag]) + length + body``, ``b"".join(...)``,
``bytes(value)`` -- and every one of those spellings is a fresh *immutable*
copy of everything beneath it: a three-deep PKCS#8 left three to six
key-bearing ``bytes`` objects behind, none of which anything can zero.  So the
private path does not use it.  It is kept for public structure, and as the
byte-identity oracle in the tests.

The technique is the one OpenSSL's ``i2d(x, NULL)``-then-``malloc`` and
RustCrypto's ``encoded_len()``-then-``encode_to_slice`` use: **measure, then
write**.  A DER or CBOR header is a function of the body's length, so the whole
size is known from lengths alone, without touching a secret value.  Then one
buffer of exactly that size is allocated and every piece is copied into it.

* A piece is ``size() -> int`` and ``write(out, at) -> int``.
* :class:`Lit` is public octets (an OID, a header, a public key).
* :class:`Sec` is a secret, named by a *getter* rather than held: the piece
  tree binds no reference to the key's buffer, so a tree that outlives a
  failed export -- in a retained traceback, say -- cannot make the key's own
  last-owner wipe (:func:`ama_cryptography._secret_material.finalize_secret`)
  read as a second owner.  The buffer is bound only inside ``size`` and
  ``write``, through a ``memoryview`` released in a ``finally``.
* :func:`build` allocates the output, writes, and scrubs it on any exception.

Why these spellings
-------------------
* ``bytearray[a:b] = x`` makes a hidden temporary copy of ``x`` unless ``x`` is
  itself a ``bytearray``.  The **target is therefore a ``memoryview``** of the
  output, and the source a ``memoryview`` too: ``memoryview[a:b] = memoryview``
  copies the octets once and allocates no data.
* ``bytearray.extend`` can relocate the buffer, freeing the old block unwiped.
  **Nothing is ever appended**; the output is sized first.
* ``re.Match.group`` on a ``bytearray`` subject returns ``bytes``.  The
  scanners in :mod:`ama_cryptography.key_formats` use spans, never ``group``.

None of this is specified by the language; the tests pin the observable
consequences (``tests/test_private_key_export.py``), not the CPython
internals.  Swap, core dumps, registers and the C stack are out of scope, as
everywhere in this library.

INVARIANT-9: nothing here catches ``BaseException``.  A failure propagates
after :class:`~ama_cryptography._secret_material.ScrubOnRaise` has zeroed the
output.
"""

from __future__ import annotations

from typing import Callable, Sequence, Union

from ama_cryptography._asn1 import _cbor_head, _der_len
from ama_cryptography._secret_material import ScrubOnRaise, ZeroizingBytearray

__all__ = [
    "Framed",
    "Lit",
    "Piece",
    "Sec",
    "Wrapped",
    "build",
    "cat",
    "cbor_bytes",
    "cbor_map",
    "tlv",
]

#: What a :class:`Sec` writes from: the key's own ``bytearray``, or a writable
#: view of one.  Never ``bytes`` or ``str``: those are immutable, so a secret
#: held in one is a copy nothing can wipe.
Secret = Union[bytearray, memoryview]

#: Returns the secret to write.  Called inside ``size``/``write`` only.
SecretSource = Callable[[], Secret]


class Piece:
    """One run of output octets whose length is known before it is written."""

    __slots__ = ()

    def size(self) -> int:
        raise NotImplementedError

    def write(self, out: memoryview, at: int) -> int:
        """Write at ``out[at:]``; return the offset just past the last octet."""
        raise NotImplementedError


class Lit(Piece):
    """Public octets: a header, an OID, a version, a public key.

    ``bytes`` only.  A secret never travels in a ``Lit``; that it cannot is
    what makes the secret pieces auditable.
    """

    __slots__ = ("_data",)

    def __init__(self, data: bytes) -> None:
        if type(data) is not bytes:
            raise TypeError("a Lit holds public bytes; a secret is written with Sec")
        self._data = data

    def size(self) -> int:
        return len(self._data)

    def write(self, out: memoryview, at: int) -> int:
        end = at + len(self._data)
        out[at:end] = self._data
        return end


class Sec(Piece):
    """A secret, copied from ``source()`` into the output without an
    intermediate (``memoryview`` to ``memoryview``).

    ``source`` returns the key's own ``bytearray`` (or a writable view of
    one); ``bytes`` and ``str`` raise ``TypeError`` rather than being copied
    into something unwipeable.  Nothing here keeps what ``source`` returns.
    """

    __slots__ = ("_source",)

    def __init__(self, source: SecretSource) -> None:
        self._source = source

    def _view(self) -> memoryview:
        secret = self._source()
        if isinstance(secret, memoryview):
            if secret.readonly:
                raise TypeError("a secret is written from a writable buffer")
            # `cast` returns a fresh view, so releasing it never releases a
            # view the caller owns; it also flattens to one dimension of octets.
            return secret.cast("B")
        if isinstance(secret, bytearray):
            return memoryview(secret)
        raise TypeError(
            "a secret is written from a bytearray or a writable memoryview, "
            f"never {type(secret).__name__}"
        )

    def size(self) -> int:
        view = self._view()
        count = view.nbytes
        view.release()
        return count

    def write(self, out: memoryview, at: int) -> int:
        view = self._view()
        try:
            end = at + view.nbytes
            out[at:end] = view
            return end
        finally:
            view.release()


class Wrapped(Sec):
    """A secret of text characters (Base64), broken into ``width``-column
    lines each ended by LF -- RFC 7468 §2.  An empty secret is one empty line,
    as the textual encoding has always been."""

    __slots__ = ("_width",)

    def __init__(self, source: SecretSource, width: int = 64) -> None:
        super().__init__(source)
        self._width = width

    def size(self) -> int:
        count = super().size()
        return count + max(-(-count // self._width), 1)

    def write(self, out: memoryview, at: int) -> int:
        view = self._view()
        try:
            count = view.nbytes
            if count == 0:
                out[at] = 0x0A
                return at + 1
            for start in range(0, count, self._width):
                stop = min(start + self._width, count)
                end = at + (stop - start)
                out[at:end] = view[start:stop]
                out[end] = 0x0A
                at = end + 1
            return at
        finally:
            view.release()


class Framed(Piece):
    """Children behind a header that is a function of the body's length."""

    __slots__ = ("_children", "_head")

    def __init__(self, head: Callable[[int], bytes], *children: Piece) -> None:
        self._head = head
        self._children = children

    def _body(self) -> int:
        total = 0
        for child in self._children:
            total += child.size()
        return total

    def size(self) -> int:
        body = self._body()
        return len(self._head(body)) + body

    def write(self, out: memoryview, at: int) -> int:
        head = self._head(self._body())
        end = at + len(head)
        out[at:end] = head
        for child in self._children:
            end = child.write(out, end)
        return end


def _no_head(_length: int) -> bytes:
    return b""


def cat(*children: Piece) -> Framed:
    """The children one after another, with no header."""
    return Framed(_no_head, *children)


def tlv(tag: int, *children: Piece) -> Framed:
    """A DER TLV: ``tag``, the minimal definite length, then the children."""

    def head(length: int) -> bytes:
        return bytes([tag]) + _der_len(length)

    return Framed(head, *children)


def _bstr_head(length: int) -> bytes:
    return _cbor_head(2, length)


def cbor_bytes(*children: Piece) -> Framed:
    """A CBOR byte string (major type 2) whose content is the children."""
    return Framed(_bstr_head, *children)


def cbor_map(members: Sequence[tuple[bytes, Piece]]) -> Framed:
    """A CBOR map in core deterministic order (RFC 8949 §4.2.1).

    ``members`` pairs each key's *encoded* bytes (public) with its value
    piece.  Entries are sorted by the encoded key, which is what makes a
    COSE_Key's encoding -- and any hash of it -- well defined, and a repeated
    key is refused.
    """
    ordered = sorted(members, key=lambda member: member[0])
    keys = [encoded for encoded, _ in ordered]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key in CBOR map")
    entries = [cat(Lit(encoded), value) for encoded, value in ordered]
    return cat(Lit(_cbor_head(5, len(ordered))), *entries)


def build(piece: Piece) -> ZeroizingBytearray:
    """Measure ``piece``, allocate exactly that, write it, return it.

    The result is a :class:`ZeroizingBytearray`: the caller owns it from here
    and it zeroes itself when dropped.  Any failure -- a piece that raises, a
    piece that disagrees with its own ``size`` -- zeroes the output first.
    """
    total = piece.size()
    with ScrubOnRaise() as held:
        out = held(ZeroizingBytearray(total))
        view = memoryview(out)
        end = piece.write(view, 0)
        view.release()
        if end != total:
            raise ValueError(f"the writer produced {end} octets where it measured {total}")
        return out
