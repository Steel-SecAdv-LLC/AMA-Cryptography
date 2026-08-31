#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A hostile TSA's oversized TSTInfo nonce must fail closed as TimestampError.

2026-08 v5 audit, item 15 (rfc3161): a malicious/compromised TSA can return a
well-formed, GRANTED token whose nonce INTEGER is thousands of bytes. The value
is only ever equality-compared to the client's 64-bit request nonce, so it is a
guaranteed mismatch — but ``str()``-ing it in the mismatch report tripped
CPython's ``int_max_str_digits`` (4300) and raised a RAW ``ValueError`` that
escaped the documented ``TimestampError``-only contract (and could be a minor
DoS). ``tst_info_nonce`` now refuses an implausibly-large nonce as malformed.
"""
from __future__ import annotations

import pytest

from ama_cryptography import rfc3161_timestamp as ts


def _tlv(tag: int, body: bytes) -> bytes:
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    length = len(body)
    enc = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(enc)]) + enc + body


def _int(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        body = value.to_bytes((value.bit_length() + 7) // 8 + 1, "big").lstrip(b"\x00") or b"\x00"
        if body[0] & 0x80:
            body = b"\x00" + body
    return _tlv(0x02, body)


def _tstinfo_with_nonce(nonce_int: int) -> bytes:
    """A minimal TSTInfo SEQUENCE that tst_info_nonce parses:
    version, policy OID, messageImprint (any), serialNumber, genTime, nonce."""
    version = _int(1)
    policy = _tlv(0x06, b"\x2a\x03")  # arbitrary OID 1.2.3
    message_imprint = _tlv(0x30, _tlv(0x30, _tlv(0x06, b"\x2a\x03")) + _tlv(0x04, b"\x00" * 32))
    serial = _int(42)
    gentime = _tlv(0x18, b"20260101000000Z")
    nonce = _int(nonce_int)
    return _tlv(0x30, version + policy + message_imprint + serial + gentime + nonce)


class TestNonceBound:
    def test_oversized_nonce_raises_timestamperror_not_valueerror(self) -> None:
        # ~1786-byte nonce -> >4300 decimal digits, the value the reviewer used.
        huge = (1 << (1786 * 8)) - 1
        tst = _tstinfo_with_nonce(huge)
        with pytest.raises(ts.TimestampError):
            ts.tst_info_nonce(tst)
        # And specifically NOT a bare ValueError escaping the contract.
        try:
            ts.tst_info_nonce(tst)
        except ts.TimestampError:
            pass
        except ValueError as exc:  # pragma: no cover - the bug we fixed
            pytest.fail(f"raw ValueError escaped the TimestampError contract: {exc!r}")

    def test_normal_64bit_nonce_is_returned(self) -> None:
        n = 0x1234567890ABCDEF
        assert ts.tst_info_nonce(_tstinfo_with_nonce(n)) == n

    def test_generous_256bit_nonce_still_accepted(self) -> None:
        n = (1 << 256) - 1  # 256-bit nonce, well under the 512-bit ceiling
        assert ts.tst_info_nonce(_tstinfo_with_nonce(n)) == n
