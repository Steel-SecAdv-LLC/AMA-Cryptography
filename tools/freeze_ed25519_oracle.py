#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Ed25519 frozen-oracle fixture (freeze and replay)
====================================================================

Produces, and replays, ``tests/oracle/ed25519_frozen_oracle.txt``: a
deterministic corpus of Ed25519 inputs together with the answers one specific
library gave for them.

Why it exists
-------------
Until the twenty-first maintenance pass the tree carried two Ed25519
backends — the in-house one and a vendored x86-64 one — and a CI job that
compared them on every push.  The vendored backend has been removed; the
in-house backend is the only one.  A differential needs a second party, and
the RFC 8032 §7.1 vectors alone are a handful of cases.  So before the vendored
backend left, its answers over the whole differential corpus were recorded
here — inputs and outputs, byte for byte — and every build replays the
recording against the shipped backend.  The independent oracle survives the
code it was recorded from.

The corpus is generated from fixed seeds, never from the CSPRNG, so the
fixture can be regenerated from any library and diffed: ``--write`` against
the shipped backend on one architecture and ``--check`` on another is a
cross-platform determinism test as well.

Fixture format
--------------
One record per line, whitespace-separated ASCII, hex for bytes, ``-`` for an
empty message or a refused (non-zero return code) output.  Comment lines
start with ``#``.  Record kinds:

    K seed pk msg sig            keypair from seed, then sign msg
    V msg sig pk verdict         ama_ed25519_verify -> 1 valid / 0 invalid
    B v0 count msg sig0 pk sigh  batch of [sig0] + [sigh]*(count-1): entry 0
                                 must return v0, every other entry 1
    D op enc verdict             decode via point_add(enc, identity) (op=a) or
                                 scalarmult_public(2, enc) (op=m)
    P scalar out                 point_from_scalar
    M scalar point out           scalarmult_public
    A p q out                    point_add
    J s1 P1 s2 P2 out            double_scalarmult_public
    R wide64 out32               sc_reduce
    S a b c out                  sc_muladd

The same reader lives in tests/test_ed25519_frozen_oracle.py (pytest, every
Python lane including windows-latest) and tests/c/test_ed25519_frozen_oracle.c
(ctest, every C lane including the AArch64/QEMU and sanitizer lanes).

Usage::

    python tools/freeze_ed25519_oracle.py --library build/lib/libama_cryptography.so --write
    python tools/freeze_ed25519_oracle.py --library build/lib/libama_cryptography.so --check

Exit status: 0 on a clean write or a clean replay; 1 on any replay mismatch;
2 when the library cannot be loaded or the fixture is unreadable.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import sys
from pathlib import Path
from typing import Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PATH = REPO_ROOT / "tests" / "oracle" / "ed25519_frozen_oracle.txt"

#: Order of the base point and the field prime (RFC 8032 §5.1).
L = 2**252 + 27742317777372353535851937790883648493
P = 2**255 - 19

KEYPAIRS = 24

_ONE_ENC = bytes([1] + [0] * 31)  # y = 1, the identity
_ZERO_ENC = bytes(32)  # y = 0, order 4
_PM1_ENC = bytes([0xEC] + [0xFF] * 30 + [0x7F])  # y = p - 1, order 2
_P_ENC = bytes([0xED] + [0xFF] * 30 + [0x7F])  # y = p, non-canonical twin of y = 0
_MAX_ENC = bytes([0xFF] * 31 + [0x7F])  # y = 2^255 - 1, non-canonical
_ONE_SIGN_ENC = bytes([0x01] + [0x00] * 30 + [0x80])  # x = 0 with the sign bit set
_PM1_SIGN_ENC = bytes([0xEC] + [0xFF] * 30 + [0xFF])
_ZERO_SIGN_ENC = bytes(31) + bytes([0x80])
_TWO_G_ENC = bytes.fromhex("c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022")
_TWO_G_SIGN_ENC = _TWO_G_ENC[:31] + bytes([_TWO_G_ENC[31] ^ 0x80])
_TWO_SCALAR = bytes([2] + [0] * 31)

DECODE_ENCODINGS: tuple[bytes, ...] = (
    _ZERO_ENC,
    _ZERO_SIGN_ENC,
    _ONE_ENC,
    _ONE_SIGN_ENC,
    _PM1_ENC,
    _PM1_SIGN_ENC,
    _P_ENC,
    bytes([0xED] + [0xFF] * 30 + [0xFF]),
    _MAX_ENC,
    _TWO_G_ENC,
    _TWO_G_SIGN_ENC,
)


class Library:
    """The Ed25519 C ABI of one loaded libama_cryptography."""

    def __init__(self, path: Path) -> None:
        self.path = path
        lib = ctypes.CDLL(str(path))
        c_p = ctypes.c_char_p
        lib.ama_ed25519_keypair.restype = ctypes.c_int
        lib.ama_ed25519_keypair.argtypes = [c_p, c_p]
        lib.ama_ed25519_sign.restype = ctypes.c_int
        lib.ama_ed25519_sign.argtypes = [c_p, c_p, ctypes.c_size_t, c_p]
        lib.ama_ed25519_verify.restype = ctypes.c_int
        lib.ama_ed25519_verify.argtypes = [c_p, c_p, ctypes.c_size_t, c_p]
        lib.ama_ed25519_batch_verify.restype = ctypes.c_int
        lib.ama_ed25519_batch_verify.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_int),
        ]
        lib.ama_ed25519_sha512.restype = None
        lib.ama_ed25519_sha512.argtypes = [c_p, ctypes.c_size_t, c_p]
        lib.ama_ed25519_sc_reduce.restype = None
        lib.ama_ed25519_sc_reduce.argtypes = [c_p]
        lib.ama_ed25519_sc_muladd.restype = None
        lib.ama_ed25519_sc_muladd.argtypes = [c_p, c_p, c_p, c_p]
        lib.ama_ed25519_point_from_scalar.restype = ctypes.c_int
        lib.ama_ed25519_point_from_scalar.argtypes = [c_p, c_p]
        lib.ama_ed25519_point_add.restype = ctypes.c_int
        lib.ama_ed25519_point_add.argtypes = [c_p, c_p, c_p]
        lib.ama_ed25519_scalarmult_public.restype = ctypes.c_int
        lib.ama_ed25519_scalarmult_public.argtypes = [c_p, c_p, c_p]
        lib.ama_ed25519_double_scalarmult_public.restype = ctypes.c_int
        lib.ama_ed25519_double_scalarmult_public.argtypes = [c_p, c_p, c_p, c_p, c_p]
        self.lib = lib

    def backend(self) -> str:
        fn = getattr(self.lib, "ama_ed25519_active_backend", None)
        if fn is None:
            return "unknown"
        fn.restype = ctypes.c_char_p
        fn.argtypes = []
        raw = fn()
        return raw.decode() if raw is not None else "unknown"

    def keypair(self, seed: bytes) -> bytes:
        secret = ctypes.create_string_buffer(seed + bytes(32), 64)
        public = ctypes.create_string_buffer(32)
        if self.lib.ama_ed25519_keypair(public, secret) != 0:
            raise RuntimeError("ama_ed25519_keypair failed")
        return public.raw[:32]

    def sign(self, message: bytes, seed: bytes, public: bytes) -> bytes:
        secret = seed + public
        signature = ctypes.create_string_buffer(64)
        msg: Optional[bytes] = message if message else None
        if self.lib.ama_ed25519_sign(signature, msg, len(message), secret) != 0:
            raise RuntimeError("ama_ed25519_sign failed")
        return signature.raw[:64]

    def verify(self, message: bytes, signature: bytes, public: bytes) -> bool:
        if len(signature) != 64 or len(public) != 32:
            raise ValueError("signature must be 64 bytes and public key 32")
        msg: Optional[bytes] = message if message else None
        rc: int = self.lib.ama_ed25519_verify(signature, msg, len(message), public)
        return rc == 0

    def batch_verify(self, entries: Sequence[tuple[bytes, bytes, bytes]]) -> list[bool]:
        count = len(entries)
        messages = [ctypes.create_string_buffer(m, len(m) or 1) for m, _, _ in entries]

        class _Entry(ctypes.Structure):
            _fields_ = [
                ("message", ctypes.c_char_p),
                ("message_len", ctypes.c_size_t),
                ("signature", ctypes.c_char_p),
                ("public_key", ctypes.c_char_p),
            ]

        array = (_Entry * count)()
        for index, (message, signature, public) in enumerate(entries):
            if len(signature) != 64 or len(public) != 32:
                raise ValueError("batch entry sizes must be 64-byte sig, 32-byte key")
            array[index].message = ctypes.cast(messages[index], ctypes.c_char_p)
            array[index].message_len = len(message)
            array[index].signature = signature
            array[index].public_key = public
        results = (ctypes.c_int * count)()
        self.lib.ama_ed25519_batch_verify(ctypes.byref(array), count, results)
        return [results[i] == 1 for i in range(count)]

    def _out32(self, rc: int, out: ctypes.Array[ctypes.c_char]) -> Optional[bytes]:
        return None if rc != 0 else out.raw[:32]

    def point_from_scalar(self, scalar: bytes) -> Optional[bytes]:
        out = ctypes.create_string_buffer(32)
        return self._out32(self.lib.ama_ed25519_point_from_scalar(out, scalar), out)

    def point_add(self, p: bytes, q: bytes) -> Optional[bytes]:
        out = ctypes.create_string_buffer(32)
        return self._out32(self.lib.ama_ed25519_point_add(out, p, q), out)

    def scalarmult_public(self, scalar: bytes, point: bytes) -> Optional[bytes]:
        out = ctypes.create_string_buffer(32)
        return self._out32(self.lib.ama_ed25519_scalarmult_public(out, scalar, point), out)

    def double_scalarmult_public(
        self, s1: bytes, p1: bytes, s2: bytes, p2: bytes
    ) -> Optional[bytes]:
        out = ctypes.create_string_buffer(32)
        return self._out32(self.lib.ama_ed25519_double_scalarmult_public(out, s1, p1, s2, p2), out)

    def sc_reduce(self, wide: bytes) -> bytes:
        buf = ctypes.create_string_buffer(wide, 64)
        self.lib.ama_ed25519_sc_reduce(buf)
        return buf.raw[:32]

    def sc_muladd(self, a: bytes, b: bytes, c: bytes) -> bytes:
        out = ctypes.create_string_buffer(32)
        self.lib.ama_ed25519_sc_muladd(out, a, b, c)
        return out.raw[:32]

    def sha512(self, data: bytes) -> bytes:
        out = ctypes.create_string_buffer(64)
        self.lib.ama_ed25519_sha512(data if data else None, len(data), out)
        return out.raw[:64]


# --------------------------------------------------------------------------
# Deterministic corpus
# --------------------------------------------------------------------------


def _det(seed: str, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"ama-ed25519-oracle:{seed}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:length])


def _flip_bit(data: bytes, bit: int) -> bytes:
    mutated = bytearray(data)
    mutated[(bit // 8) % len(mutated)] ^= 1 << (bit % 8)
    return bytes(mutated)


def _with_s(signature: bytes, value: int) -> bytes:
    if not 0 <= value < 2**256:
        raise ValueError("S must fit in 32 bytes")
    return signature[:32] + value.to_bytes(32, "little")


def _clamp(seed: bytes) -> bytes:
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)


def _hx(b: Optional[bytes]) -> str:
    return "-" if b is None or len(b) == 0 else b.hex()


class _Xorshift:
    def __init__(self) -> None:
        self.state = 0x243F6A8885A308D3

    def word(self) -> int:
        x = self.state
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= x >> 7
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        self.state = x
        return x

    def bytes(self, count: int) -> bytes:
        return bytes((self.word() >> 24) & 0xFF for _ in range(count))


def _small_order_r_signature(
    lib: Library, message: bytes, seed: bytes, public: bytes, torsion_enc: bytes, tag: str
) -> bytes:
    """R = [r]B + T (T of small order), S = r + h·a: the canonically encoded
    torsion residue single verify rejects and a randomized aggregate verifier
    accepts with probability ~1/ord(T).  Scalar arithmetic in Python."""
    a_int = int.from_bytes(_clamp(seed), "little") % L
    r_int = int.from_bytes(_det(tag, 32), "little") % L
    r_base = lib.point_from_scalar(r_int.to_bytes(32, "little"))
    if r_base is None:
        raise RuntimeError("[r]B refused")
    r_sig = lib.point_add(r_base, torsion_enc)
    if r_sig is None:
        raise RuntimeError("[r]B + T refused")
    h_int = int.from_bytes(hashlib.sha512(r_sig + public + message).digest(), "little") % L
    s_int = (r_int + h_int * a_int) % L
    return r_sig + s_int.to_bytes(32, "little")


def _non_canonical_r_signature(lib: Library, message: bytes, seed: bytes, public: bytes) -> bytes:
    """R = identity with the sign bit set (a §5.1.3 must-refuse encoding) and
    S = h·a, so the group equation holds while the encoding is refused."""
    a = _clamp(seed)
    r_half = bytes([0x01]) + bytes(30) + bytes([0x80])
    h = lib.sc_reduce(lib.sha512(r_half + public + message))
    s_half = lib.sc_muladd(bytes(32), h, a)
    return r_half + s_half


def build_records(lib: Library) -> list[str]:
    """Every fixture record, with the library's own answers filled in."""
    rec: list[str] = []
    keys: list[tuple[bytes, bytes]] = []

    # K + V: honest signatures, the S + L twin, boundary S, structured bitflips.
    for index in range(KEYPAIRS):
        seed = _det(f"seed:{index}", 32)
        public = lib.keypair(seed)
        message = _det(f"msg:{index}", (index * 37) % 200)  # index 0 signs the empty message
        signature = lib.sign(message, seed, public)
        keys.append((seed, public))
        rec.append(f"K {seed.hex()} {public.hex()} {_hx(message)} {signature.hex()}")

        def v(msg: bytes, sig: bytes, pk: bytes) -> None:
            rec.append(f"V {_hx(msg)} {sig.hex()} {pk.hex()} {int(lib.verify(msg, sig, pk))}")

        v(message, signature, public)
        s = int.from_bytes(signature[32:], "little")
        if s + L < 2**256:
            v(message, _with_s(signature, s + L), public)
        for value in (L, L + 1, L - 1, 2**256 - 1):
            v(message, _with_s(signature, value), public)
        for bit in (0, 1, 7, 8, 63, 127, 254, 255):
            v(message, _flip_bit(signature[:32], bit) + signature[32:], public)
            v(message, signature[:32] + _flip_bit(signature[32:], bit), public)
            v(message, signature, _flip_bit(public, bit))
            if message:
                v(_flip_bit(message, bit), signature, public)

    # B: batch verify with a discriminating first entry, across the counts the
    # retired multi-scalar path switched behaviour at.
    seed0, public0 = keys[0]
    bmsg = b"frozen oracle: batch verify"
    honest = lib.sign(bmsg, seed0, public0)
    discriminators = [
        _non_canonical_r_signature(lib, bmsg, seed0, public0),
        _small_order_r_signature(lib, bmsg, seed0, public0, _PM1_ENC, "torsion2"),
        _small_order_r_signature(lib, bmsg, seed0, public0, _ZERO_ENC, "torsion4"),
        honest,
    ]
    # The construction of each discriminator is checked before it is frozen:
    # a fixture that recorded a broken discriminator would replay a defect as
    # the expected answer.
    for sig0, must in zip(discriminators, (False, False, False, True)):
        if lib.verify(bmsg, sig0, public0) != must:
            raise RuntimeError("batch discriminator did not verify as constructed")
    for sig0 in discriminators:
        for count in (1, 2, 3, 4, 5, 8, 16, 63, 64, 65, 80):
            entries = [(bmsg, sig0, public0)] + [(bmsg, honest, public0)] * (count - 1)
            verdicts = lib.batch_verify(entries)
            if any(not x for x in verdicts[1:]):
                raise RuntimeError("an honest batch entry was rejected while freezing")
            rec.append(
                f"B {int(verdicts[0])} {count} {bmsg.hex()} {sig0.hex()} "
                f"{public0.hex()} {honest.hex()}"
            )

    # D: compressed-point decode rules on both decode entry points.
    for enc in DECODE_ENCODINGS:
        rec.append(f"D a {enc.hex()} {int(lib.point_add(enc, _ONE_ENC) is not None)}")
        rec.append(f"D m {enc.hex()} {int(lib.scalarmult_public(_TWO_SCALAR, enc) is not None)}")

    # P / M / A / J: byte-exact arithmetic over a deterministic scalar and
    # point corpus that includes unreduced scalars and small-order points.
    xs = _Xorshift()
    scalars: list[bytes] = [
        bytes([2] + [0] * 31),
        bytes([7] + [0] * 31),
        bytes([3] + [0] * 31),
        bytes(32),
        bytes([0xFF] * 32),
        bytes([0x00] * 31 + [0x80]),
        L.to_bytes(32, "little"),
        (L - 1).to_bytes(32, "little"),
        (L + 1).to_bytes(32, "little"),
    ]
    scalars.extend(xs.bytes(32) for _ in range(24))
    points: list[bytes] = [_ONE_ENC, _ZERO_ENC, _PM1_ENC, _TWO_G_ENC]
    for _ in range(8):
        generated = lib.point_from_scalar(xs.bytes(32))
        if generated is not None:
            points.append(generated)
    points.extend(xs.bytes(32) for _ in range(8))
    points.extend(pk for _, pk in keys[:4])

    for scalar in scalars:
        rec.append(f"P {scalar.hex()} {_hx(lib.point_from_scalar(scalar))}")
    for point in points:
        for scalar in scalars:
            rec.append(
                f"M {scalar.hex()} {point.hex()} {_hx(lib.scalarmult_public(scalar, point))}"
            )
    for index, point in enumerate(points):
        for other in (points[(index + 1) % len(points)], points[(index * 7 + 3) % len(points)]):
            rec.append(f"A {point.hex()} {other.hex()} {_hx(lib.point_add(point, other))}")
    for index, point in enumerate(points):
        other = points[(index + 1) % len(points)]
        for s1, s2 in (
            (scalars[1], scalars[2]),
            (scalars[4], scalars[0]),
            (scalars[5], scalars[6]),
            (scalars[9], scalars[10]),
            (scalars[11], scalars[12]),
        ):
            rec.append(
                f"J {s1.hex()} {point.hex()} {s2.hex()} {other.hex()} "
                f"{_hx(lib.double_scalarmult_public(s1, point, s2, other))}"
            )

    # R / S: scalar arithmetic mod l.
    wides: list[bytes] = [bytes(64), bytes([0xFF] * 64), L.to_bytes(64, "little")]
    wides.extend(xs.bytes(64) for _ in range(16))
    for wide in wides:
        rec.append(f"R {wide.hex()} {lib.sc_reduce(wide).hex()}")
    for index in range(16):
        a, b, c = (
            scalars[index % len(scalars)],
            scalars[(index * 5 + 1) % len(scalars)],
            xs.bytes(32),
        )
        rec.append(f"S {a.hex()} {b.hex()} {c.hex()} {lib.sc_muladd(a, b, c).hex()}")
    return rec


# --------------------------------------------------------------------------
# Replay
# --------------------------------------------------------------------------


def _unhex(field: str) -> bytes:
    return b"" if field == "-" else bytes.fromhex(field)


def replay(lib: Library, lines: Sequence[str]) -> tuple[int, list[str]]:
    """Replay every record; return (records checked, mismatch descriptions)."""
    checked = 0
    mismatches: list[str] = []

    def expect(line_no: int, got: object, want: object, what: str) -> None:
        if got != want:
            mismatches.append(f"line {line_no}: {what}: expected {want!r}, got {got!r}")

    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        f = line.split()
        kind = f[0]
        checked += 1
        if kind == "K":
            seed, public, message, signature = (
                _unhex(f[1]),
                _unhex(f[2]),
                _unhex(f[3]),
                _unhex(f[4]),
            )
            got_pk = lib.keypair(seed)
            expect(line_no, got_pk.hex(), public.hex(), "keypair public key")
            expect(line_no, lib.sign(message, seed, public).hex(), signature.hex(), "signature")
        elif kind == "V":
            message, signature, public = _unhex(f[1]), _unhex(f[2]), _unhex(f[3])
            expect(
                line_no, int(lib.verify(message, signature, public)), int(f[4]), "verify verdict"
            )
        elif kind == "B":
            v0, count = int(f[1]), int(f[2])
            message, sig0, public, sigh = _unhex(f[3]), _unhex(f[4]), _unhex(f[5]), _unhex(f[6])
            entries = [(message, sig0, public)] + [(message, sigh, public)] * (count - 1)
            verdicts = lib.batch_verify(entries)
            expect(line_no, [int(x) for x in verdicts], [v0] + [1] * (count - 1), "batch verdicts")
        elif kind == "D":
            enc, want = _unhex(f[2]), int(f[3])
            if f[1] == "a":
                got = int(lib.point_add(enc, _ONE_ENC) is not None)
            else:
                got = int(lib.scalarmult_public(_TWO_SCALAR, enc) is not None)
            expect(line_no, got, want, f"decode via {f[1]}")
        elif kind == "P":
            expect(line_no, _hx(lib.point_from_scalar(_unhex(f[1]))), f[2], "point_from_scalar")
        elif kind == "M":
            expect(
                line_no, _hx(lib.scalarmult_public(_unhex(f[1]), _unhex(f[2]))), f[3], "scalarmult"
            )
        elif kind == "A":
            expect(line_no, _hx(lib.point_add(_unhex(f[1]), _unhex(f[2]))), f[3], "point_add")
        elif kind == "J":
            got_j = lib.double_scalarmult_public(
                _unhex(f[1]), _unhex(f[2]), _unhex(f[3]), _unhex(f[4])
            )
            expect(line_no, _hx(got_j), f[5], "double_scalarmult")
        elif kind == "R":
            expect(line_no, lib.sc_reduce(_unhex(f[1])).hex(), f[2], "sc_reduce")
        elif kind == "S":
            expect(
                line_no,
                lib.sc_muladd(_unhex(f[1]), _unhex(f[2]), _unhex(f[3])).hex(),
                f[4],
                "sc_muladd",
            )
        else:
            mismatches.append(f"line {line_no}: unknown record kind {kind!r}")
    return checked, mismatches


def _library_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render(lib: Library, git_commit: str) -> str:
    records = build_records(lib)
    kinds: dict[str, int] = {}
    for r in records:
        kinds[r[0]] = kinds.get(r[0], 0) + 1
    head = [
        "# ama-ed25519-oracle v1",
        "# Ed25519 inputs and the answers one library gave for them; replayed by",
        "# tests/test_ed25519_frozen_oracle.py and tests/c/test_ed25519_frozen_oracle.c.",
        "# Generated by tools/freeze_ed25519_oracle.py; see that file for the format.",
        f"# source-backend: {lib.backend()}",
        f"# source-library-sha256: {_library_digest(lib.path)}",
        f"# source-commit: {git_commit}",
        "# records: " + " ".join(f"{k}={kinds[k]}" for k in sorted(kinds)),
    ]
    return "\n".join(head + records) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze or replay the Ed25519 oracle fixture.")
    parser.add_argument("--library", type=Path, required=True, help="libama_cryptography to drive")
    parser.add_argument("--fixture", type=Path, default=FIXTURE_PATH)
    parser.add_argument("--commit", default="unknown", help="source commit recorded in the header")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="record this library's answers")
    mode.add_argument(
        "--check", action="store_true", help="replay the fixture against this library"
    )
    args = parser.parse_args(argv)

    try:
        lib = Library(args.library)
    except OSError as exc:
        print(f"ORACLE INCONCLUSIVE — could not load {args.library}: {exc}", file=sys.stderr)
        return 2

    if args.write:
        text = render(lib, args.commit)
        args.fixture.parent.mkdir(parents=True, exist_ok=True)
        args.fixture.write_text(text, encoding="utf-8", newline="")
        print(f"wrote {args.fixture} ({text.count(chr(10))} lines) from backend {lib.backend()!r}")
        return 0

    if not args.fixture.is_file():
        print(f"ORACLE INCONCLUSIVE — {args.fixture} is missing", file=sys.stderr)
        return 2
    lines = args.fixture.read_text(encoding="utf-8").splitlines()
    checked, mismatches = replay(lib, lines)
    if checked == 0:
        print("ORACLE INCONCLUSIVE — the fixture holds no records", file=sys.stderr)
        return 2
    if mismatches:
        print(f"ORACLE REPLAY FAILED — {len(mismatches)} mismatch(es) in {checked} records:")
        for m in mismatches[:50]:
            print("  " + m)
        return 1
    print(f"ORACLE REPLAY PASSED — {checked} records agree (backend {lib.backend()!r})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
