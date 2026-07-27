#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Strict DER and canonical CBOR codecs for the key-interoperability layer.
========================================================================

These are *encoding* primitives, not cryptography. They touch key material but
perform no cryptographic operation, so INVARIANT-7 does not apply to them: a
Python DER parser is not a "fallback for a cryptographic primitive", it is the
only sensible place for a byte-structure parser to live. What INVARIANT-7 does
require, and what this module observes, is that nothing here ever computes a
key, derives a secret, or decides whether a signature is valid — it moves
opaque octet strings between container formats and refuses anything malformed.

Why hand-rolled rather than a dependency
----------------------------------------
The same reason as the rest of the library (INVARIANT-1), plus one specific to
parsers: a general-purpose ASN.1 library is permissive by design, because it
has to read whatever the world produces. A key-import parser wants the
opposite. Every relaxation is a place where two distinct byte strings decode to
the same key, which is the same defect class as ECDSA signature malleability —
and it is reachable by anyone who can hand you a key file.

Strictness contract (DER)
-------------------------
This decoder accepts **only** DER, never the wider BER:

* definite-length only; the indefinite-length marker ``0x80`` is rejected;
* minimal length encoding — a length below 128 must use the short form, and a
  long form must not carry leading zero octets;
* INTEGERs must be minimally encoded, with no superfluous leading ``0x00`` and
  no negative values where the grammar forbids them;
* BIT STRINGs in the structures used here must have zero unused bits;
* no trailing data after the outermost structure;
* OBJECT IDENTIFIER arcs must be minimally encoded (no leading ``0x80``
  continuation octet), and the first two arcs must be in range.

Anything else raises ``KeyFormatError``. There is no lenient mode.

Strictness contract (CBOR)
--------------------------
COSE keys are decoded under RFC 8949 §4.2.1 *core deterministic encoding*:

* the shortest possible integer encoding for every head;
* definite-length maps and arrays only;
* map keys sorted by encoded bytewise order, and no duplicate keys;
* no floats, tags, or indefinite-length strings in the accepted subset.

A COSE_Key that is well-formed CBOR but not deterministically encoded is
rejected, because two encodings of the same key would otherwise produce two
distinct thumbprints.
"""

from __future__ import annotations

from typing import Any

from ama_cryptography.exceptions import KeyFormatError

__all__ = [
    "DerReader",
    "cbor_decode_canonical",
    "cbor_encode_canonical",
    "der_bit_string",
    "der_integer",
    "der_null",
    "der_octet_string",
    "der_sequence",
    "der_tagged",
    "oid_from_string",
    "oid_to_string",
]

# ASN.1 tag numbers used by the structures this package encodes.
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_SET = 0x31


# ---------------------------------------------------------------------------
# DER encoding
# ---------------------------------------------------------------------------
def _der_len(n: int) -> bytes:
    """Minimal DER length encoding."""
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if len(body) > 0x7E:  # pragma: no cover - no key structure gets this large
        raise KeyFormatError(f"length {n} too large to encode")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def der_integer(value: int) -> bytes:
    """Encode a non-negative INTEGER with minimal length."""
    if value < 0:
        raise KeyFormatError("negative INTEGERs are not produced by this layer")
    body = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    # Strip redundant leading zeros, keeping one when the high bit is set.
    while len(body) > 1 and body[0] == 0x00 and not (body[1] & 0x80):
        body = body[1:]
    return _tlv(TAG_INTEGER, body)


def der_octet_string(data: bytes) -> bytes:
    return _tlv(TAG_OCTET_STRING, data)


def der_bit_string(data: bytes) -> bytes:
    """Encode a BIT STRING with zero unused bits (the only form used here)."""
    return _tlv(TAG_BIT_STRING, b"\x00" + data)


def der_null() -> bytes:
    return b"\x05\x00"


def der_sequence(*elements: bytes) -> bytes:
    return _tlv(TAG_SEQUENCE, b"".join(elements))


def der_tagged(number: int, body: bytes, *, constructed: bool = True) -> bytes:
    """Encode a context-specific ``[number]`` tag."""
    if not 0 <= number <= 30:
        raise KeyFormatError(f"context tag {number} out of the supported range")
    tag = 0x80 | number | (0x20 if constructed else 0x00)
    return _tlv(tag, body)


def oid_from_string(dotted: str) -> bytes:
    """Encode a dotted OID string as a DER OBJECT IDENTIFIER."""
    try:
        arcs = [int(part) for part in dotted.split(".")]
    except ValueError:
        raise KeyFormatError(f"malformed OID {dotted!r}") from None
    if len(arcs) < 2 or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] >= 40):
        raise KeyFormatError(f"OID {dotted!r} has invalid leading arcs")
    if any(a < 0 for a in arcs):
        raise KeyFormatError(f"OID {dotted!r} has a negative arc")

    body = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunk = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            chunk.append((arc & 0x7F) | 0x80)
            arc >>= 7
        body.extend(reversed(chunk))
    return _tlv(TAG_OID, bytes(body))


def oid_to_string(body: bytes) -> str:
    """Decode an OBJECT IDENTIFIER *body* (no tag/length) to dotted form."""
    if not body:
        raise KeyFormatError("empty OBJECT IDENTIFIER")
    first = body[0]
    arcs = [min(first // 40, 2)]
    arcs.append(first - arcs[0] * 40)
    value = 0
    started = False
    for octet in body[1:]:
        if not started and octet == 0x80:
            # A continuation octet of 0x80 at the start of an arc is a
            # non-minimal encoding: it contributes no bits.
            raise KeyFormatError("non-minimal OID arc encoding")
        started = True
        value = (value << 7) | (octet & 0x7F)
        if not octet & 0x80:
            arcs.append(value)
            value = 0
            started = False
    if started:
        raise KeyFormatError("truncated OBJECT IDENTIFIER")
    return ".".join(str(a) for a in arcs)


# ---------------------------------------------------------------------------
# DER decoding
# ---------------------------------------------------------------------------
class DerReader:
    """A strict, non-backtracking DER reader over a byte string.

    Every accessor consumes exactly one TLV and validates it. ``finish()`` is
    mandatory: a structure with trailing data is an error, not a partial
    success, because trailing data is precisely how a second encoding of the
    same key is smuggled past a parser.
    """

    __slots__ = ("_buf", "_end", "_pos")

    def __init__(self, data: bytes, start: int = 0, end: int | None = None) -> None:
        self._buf = data
        self._pos = start
        self._end = len(data) if end is None else end

    @property
    def remaining(self) -> int:
        return self._end - self._pos

    def _need(self, n: int) -> None:
        if self.remaining < n:
            raise KeyFormatError("truncated DER structure")

    def _read_header(self, expected: int | None) -> tuple[int, int, int]:
        """Return ``(tag, body_start, body_end)`` for the next TLV."""
        self._need(2)
        tag = self._buf[self._pos]
        if expected is not None and tag != expected:
            raise KeyFormatError(f"expected DER tag 0x{expected:02X}, found 0x{tag:02X}")
        if tag & 0x1F == 0x1F:
            raise KeyFormatError("high-tag-number form is not accepted")
        length_octet = self._buf[self._pos + 1]
        pos = self._pos + 2

        if length_octet == 0x80:
            raise KeyFormatError("indefinite-length encoding is BER, not DER")
        if length_octet < 0x80:
            length = length_octet
        else:
            count = length_octet & 0x7F
            if count > 4:
                raise KeyFormatError("DER length field is implausibly large")
            if self._end - pos < count:
                raise KeyFormatError("truncated DER length")
            raw = self._buf[pos : pos + count]
            if raw[0] == 0x00:
                raise KeyFormatError("non-minimal DER length (leading zero)")
            length = int.from_bytes(raw, "big")
            if length < 0x80:
                raise KeyFormatError("non-minimal DER length (long form for short value)")
            pos += count

        if self._end - pos < length:
            raise KeyFormatError("DER length exceeds the available data")
        return tag, pos, pos + length

    def peek_tag(self) -> int | None:
        """The next tag, or None at the end of this reader's extent."""
        if self.remaining == 0:
            return None
        return self._buf[self._pos]

    def read_sequence(self) -> DerReader:
        _, start, end = self._read_header(TAG_SEQUENCE)
        self._pos = end
        return DerReader(self._buf, start, end)

    def read_tagged(self, number: int, *, constructed: bool = True) -> DerReader:
        tag = 0x80 | number | (0x20 if constructed else 0x00)
        _, start, end = self._read_header(tag)
        self._pos = end
        return DerReader(self._buf, start, end)

    def read_integer(self) -> int:
        _, start, end = self._read_header(TAG_INTEGER)
        body = self._buf[start:end]
        if not body:
            raise KeyFormatError("empty INTEGER")
        if body[0] & 0x80:
            raise KeyFormatError("negative INTEGER where a non-negative was required")
        if len(body) > 1 and body[0] == 0x00 and not (body[1] & 0x80):
            raise KeyFormatError("non-minimal INTEGER encoding")
        self._pos = end
        return int.from_bytes(body, "big")

    def read_octet_string(self) -> bytes:
        _, start, end = self._read_header(TAG_OCTET_STRING)
        self._pos = end
        return self._buf[start:end]

    def read_bit_string(self) -> bytes:
        _, start, end = self._read_header(TAG_BIT_STRING)
        if end - start < 1:
            raise KeyFormatError("empty BIT STRING")
        unused = self._buf[start]
        if unused != 0:
            raise KeyFormatError(
                f"BIT STRING has {unused} unused bits; this layer requires whole octets"
            )
        self._pos = end
        return self._buf[start + 1 : end]

    def read_oid(self) -> str:
        _, start, end = self._read_header(TAG_OID)
        self._pos = end
        return oid_to_string(self._buf[start:end])

    def read_null(self) -> None:
        _, start, end = self._read_header(TAG_NULL)
        if end != start:
            raise KeyFormatError("NULL with a non-empty body")
        self._pos = end

    def read_any_raw(self) -> bytes:
        """Consume one TLV and return its complete encoding."""
        start_tlv = self._pos
        _, _, end = self._read_header(None)
        self._pos = end
        return self._buf[start_tlv:end]

    def skip_any(self) -> None:
        _, _, end = self._read_header(None)
        self._pos = end

    def finish(self) -> None:
        if self.remaining:
            raise KeyFormatError(f"{self.remaining} trailing octet(s) after the DER structure")


# ---------------------------------------------------------------------------
# Canonical CBOR (RFC 8949 §4.2.1) — the subset COSE_Key needs
# ---------------------------------------------------------------------------
_CBOR_UINT = 0
_CBOR_NEGINT = 1
_CBOR_BYTES = 2
_CBOR_TEXT = 3
_CBOR_ARRAY = 4
_CBOR_MAP = 5


def _cbor_head(major: int, value: int) -> bytes:
    """Shortest-form head, as core deterministic encoding requires."""
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 0x100:
        return bytes([(major << 5) | 24, value])
    if value < 0x10000:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 0x100000000:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise KeyFormatError("CBOR value exceeds 64 bits")


def cbor_encode_canonical(value: Any) -> bytes:
    """Encode under RFC 8949 core deterministic encoding.

    Map keys are sorted by their *encoded bytes*, which is what makes a
    COSE_Key thumbprint well defined: two orderings of the same key would
    otherwise hash differently.
    """
    if isinstance(value, bool):
        # bool is an int subclass; encoding True as 1 would be silent data loss.
        raise KeyFormatError("booleans are not part of the accepted CBOR subset")
    if isinstance(value, int):
        if value >= 0:
            return _cbor_head(_CBOR_UINT, value)
        return _cbor_head(_CBOR_NEGINT, -value - 1)
    if isinstance(value, bytes):
        return _cbor_head(_CBOR_BYTES, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _cbor_head(_CBOR_TEXT, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _cbor_head(_CBOR_ARRAY, len(value)) + b"".join(
            cbor_encode_canonical(v) for v in value
        )
    if isinstance(value, dict):
        items = [(cbor_encode_canonical(k), cbor_encode_canonical(v)) for k, v in value.items()]
        encoded_keys = [k for k, _ in items]
        if len(set(encoded_keys)) != len(encoded_keys):
            raise KeyFormatError("duplicate key in CBOR map")
        items.sort(key=lambda kv: kv[0])
        return _cbor_head(_CBOR_MAP, len(items)) + b"".join(k + v for k, v in items)
    raise KeyFormatError(f"unsupported CBOR type {type(value).__name__}")


class _CborReader:
    __slots__ = ("_buf", "_pos")

    def __init__(self, data: bytes) -> None:
        self._buf = data
        self._pos = 0

    @property
    def pos(self) -> int:
        return self._pos

    def _need(self, n: int) -> None:
        if len(self._buf) - self._pos < n:
            raise KeyFormatError("truncated CBOR")

    def _head(self) -> tuple[int, int]:
        self._need(1)
        initial = self._buf[self._pos]
        self._pos += 1
        major, extra = initial >> 5, initial & 0x1F

        if extra < 24:
            return major, extra
        if extra == 24:
            self._need(1)
            value = self._buf[self._pos]
            self._pos += 1
            if value < 24:
                raise KeyFormatError("non-minimal CBOR head")
            return major, value
        if extra in (25, 26, 27):
            width = 2 << (extra - 25)
            self._need(width)
            value = int.from_bytes(self._buf[self._pos : self._pos + width], "big")
            self._pos += width
            minimum = (24, 0x100, 0x10000, 0x100000000)[extra - 24]
            if value < minimum:
                raise KeyFormatError("non-minimal CBOR head")
            return major, value
        if extra == 31:
            raise KeyFormatError("indefinite-length CBOR is not deterministic")
        raise KeyFormatError(f"reserved CBOR additional information {extra}")

    def decode(self) -> Any:
        major, value = self._head()
        if major == _CBOR_UINT:
            return value
        if major == _CBOR_NEGINT:
            return -1 - value
        if major == _CBOR_BYTES:
            self._need(value)
            out = self._buf[self._pos : self._pos + value]
            self._pos += value
            return out
        if major == _CBOR_TEXT:
            self._need(value)
            raw = self._buf[self._pos : self._pos + value]
            self._pos += value
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                raise KeyFormatError("invalid UTF-8 in CBOR text string") from None
        if major == _CBOR_ARRAY:
            return [self.decode() for _ in range(value)]
        if major == _CBOR_MAP:
            mapping: dict[Any, Any] = {}
            previous: bytes | None = None
            for _ in range(value):
                key_start = self._pos
                key = self.decode()
                key_bytes = self._buf[key_start : self._pos]
                if previous is not None and key_bytes <= previous:
                    raise KeyFormatError(
                        "CBOR map keys are not in canonical order (or are duplicated)"
                    )
                previous = key_bytes
                if isinstance(key, (list, dict)):
                    raise KeyFormatError("non-scalar CBOR map key")
                mapping[key] = self.decode()
            return mapping
        raise KeyFormatError(f"unsupported CBOR major type {major}")


def cbor_decode_canonical(data: bytes) -> Any:
    """Decode one canonically-encoded CBOR item, rejecting trailing data."""
    reader = _CborReader(data)
    value = reader.decode()
    if reader.pos != len(data):
        raise KeyFormatError(f"{len(data) - reader.pos} trailing octet(s) after the CBOR item")
    return value
