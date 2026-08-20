#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Out-of-band installed-tree verifier
===================================

Standalone, stdlib-only verifier for an installed ``ama_cryptography``
package directory.  It runs in a fresh interpreter, imports **nothing**
from the target package, and verifies the tree entirely from the
outside:

  1. the build-time Ed25519 signature in ``_integrity_signature.py``
     (parsed as *text*, never imported or exec'd);
  2. the SHA3-256 digest over the package's ``.py`` files and POST KAT
     vectors, recomputed exactly as ``_build_sign._compute_package_digest``;
  3. the SHA3-256 digest of the native library (``--native-lib``, or
     discovered next to the package), when the artefact binds one;
  4. the binding-extension digest map (v3 artefacts);
  5. execution integrity: every cached ``__pycache__`` ``.pyc`` for the
     running interpreter must be a faithful compile of its on-disk
     source, compared by executed surface exactly as
     ``_self_test._code_matches`` does.

Why this tool exists (the checker-poisoning boundary)
-----------------------------------------------------

The package's import-time integrity checks are IN-process: the checker's
own bytecode lives in the very tree it verifies, so an attacker with
write access to the installed tree can poison the checker's ``.pyc``
before it runs (SECURITY.md, "Execution integrity" — the recorded
2026-08 reassessment correctly rejects in-band narrowing of that
boundary).  The one genuine engineering resolution is to move the
verification *outside* the poisoned trusted computing base.  This tool
is that move: nothing it executes comes from the target tree.

Trust base — stated honestly
----------------------------

The operator's Python interpreter (and its stdlib), this single file,
**and the public key passed as ``--expected-pubkey``**.  Fetch this file
out of band — from the repository over an independent channel (a fresh
``git clone``, or a release tarball whose checksum you verified) — never
from the installation being verified.  Displacing the trust base out of
the verified tree is the point; a copy of this tool that shipped inside
a compromised tree proves nothing.  Run it with the same interpreter
(version and ``-O`` level) that runs the application, so the
``__pycache__`` slot it checks is the one that interpreter would load.

The key belongs in that list and not in the tree, for the same reason
the tool itself does.  The artefact carries the public key it was signed
under, so verifying against *that* key establishes only that whoever
wrote the artefact also wrote a matching signature — and an attacker who
can rewrite the installed tree, which is the threat this tool exists to
answer, can rewrite the sources, mint a keypair, re-sign, and produce a
tree where every digest and the signature all agree.  Supply the key you
hold: ``--expected-pubkey`` is compared before the signature is checked,
and without it the tool refuses to run unless ``--allow-unanchored`` is
given, in which case the verdict says UNANCHORED and claims internal
consistency rather than authenticity.  (Developer trees are the honest
use of that mode: their artefacts are signed with a per-build ephemeral
key that no operator holds.  A release wheel's key is the compiled trust
anchor ``ama_integrity_trust_anchor_pubkey_hex`` reports, which the
in-tree checker pins and which you can read from a trusted copy of the
release.)

INVARIANT-1 / sovereignty: the digests verified here are NOT computed
with ``hashlib`` (OpenSSL-backed on CPython — a forbidden stand-in for
AMA crypto, per the INVARIANT-36 benchmark finding).  SHA3-256
(FIPS 202), SHA-512 (FIPS 180-4, internal to Ed25519) and Ed25519
verification (RFC 8032) are implemented below from their
specifications, and every primitive must pass its startup KATs —
including a negative Ed25519 control — before anything is verified.
A failed self-KAT verifies nothing and exits nonzero (fail closed).

Usage::

    python3 tools/verify_install_oob.py <path-to-ama_cryptography-dir> \\
        --expected-pubkey <64 hex> [--native-lib PATH]

    # developer tree signed with a per-build ephemeral key nobody holds:
    python3 tools/verify_install_oob.py <dir> --allow-unanchored

Exit codes: 0 everything verified; 1 verification failure (report names
each fault); 2 unusable target, malformed anchor, or no trust anchor and
no explicit --allow-unanchored; 3 self-KAT failure.
"""

from __future__ import annotations

import argparse
import ast
import importlib.machinery
import importlib.util
import marshal
import math
import os
import sys
from pathlib import Path
from types import CodeType
from typing import Optional

# ============================================================================
# SHA3-256 — Keccak-f[1600], rate 136, pad 0x06...0x80 (FIPS 202)
# ============================================================================

_MASK64 = (1 << 64) - 1

# FIPS 202 round constants for Keccak-f[1600] (24 rounds).  Fixed spec
# constants; the startup KATs below fail closed on any transcription error.
_KECCAK_RC: tuple[int, ...] = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)


def _keccak_rho_offsets() -> tuple[int, ...]:
    """Rho rotation offsets, generated from the FIPS 202 (x, y) walk.

    Deriving the table from the spec's generating recurrence instead of
    transcribing 24 magic numbers removes one copy-error surface; lane (0, 0)
    keeps offset 0.  State layout is ``lane[x + 5*y]`` throughout.
    """
    offsets = [0] * 25
    x, y = 1, 0
    for t in range(24):
        offsets[x + 5 * y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return tuple(offsets)


_KECCAK_ROT: tuple[int, ...] = _keccak_rho_offsets()


def _rotl64(value: int, shift: int) -> int:
    """Rotate a 64-bit lane left by ``shift`` (0..63)."""
    return ((value << shift) | (value >> (64 - shift))) & _MASK64 if shift else value


def _keccak_f1600(lanes: list[int]) -> None:
    """One Keccak-f[1600] permutation over 25 lanes, in place."""
    for rc in _KECCAK_RC:
        # theta
        c = [
            lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20]
            for x in range(5)
        ]
        d = [c[(x + 4) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            dx = d[x]
            for y in range(0, 25, 5):
                lanes[x + y] ^= dx
        # rho + pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(lanes[x + 5 * y], _KECCAK_ROT[x + 5 * y])
        # chi + iota
        for x in range(5):
            for y in range(0, 25, 5):
                lanes[x + y] = b[x + y] ^ ((b[(x + 1) % 5 + y] ^ _MASK64) & b[(x + 2) % 5 + y])
        lanes[0] ^= rc


def sha3_256(data: bytes) -> bytes:
    """SHA3-256 per FIPS 202: rate 136, capacity 512, pad10*1 with 0x06."""
    rate = 136
    padded = bytearray(data)
    padded += b"\x00" * (rate - (len(data) % rate))
    padded[len(data)] ^= 0x06
    padded[-1] ^= 0x80

    lanes = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for i in range(rate // 8):
            lanes[i] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        _keccak_f1600(lanes)
    return b"".join(lanes[i].to_bytes(8, "little") for i in range(4))


# ============================================================================
# SHA-512 — FIPS 180-4 (internal to Ed25519 verification, RFC 8032 §5.1)
# ============================================================================
#
# The round constants and initial hash values are the 64-bit fractional parts
# of the cube/square roots of the first primes.  They are derived here with
# exact integer arithmetic (isqrt / integer cube root) rather than transcribed,
# and the SHA-512 KAT plus the Ed25519 KATs fail closed on any derivation bug.


def _first_primes(count: int) -> list[int]:
    """The first ``count`` primes, by trial division (spec-constant sized)."""
    primes: list[int] = []
    candidate = 2
    while len(primes) < count:
        if all(candidate % p for p in primes if p * p <= candidate):
            primes.append(candidate)
        candidate += 1
    return primes


def _icbrt(value: int) -> int:
    """Integer cube root: the largest x with x**3 <= value (Newton, exact)."""
    if value == 0:
        return 0
    x = 1 << ((value.bit_length() + 2) // 3)
    while True:
        y = (2 * x + value // (x * x)) // 3
        if y >= x:
            return x
        x = y


_SHA512_PRIMES = _first_primes(80)
_SHA512_H0: tuple[int, ...] = tuple(math.isqrt(p << 128) & _MASK64 for p in _SHA512_PRIMES[:8])
_SHA512_K: tuple[int, ...] = tuple(_icbrt(p << 192) & _MASK64 for p in _SHA512_PRIMES)


def _rotr64(value: int, shift: int) -> int:
    """Rotate a 64-bit word right by ``shift`` (1..63)."""
    return ((value >> shift) | (value << (64 - shift))) & _MASK64


def sha512(data: bytes) -> bytes:
    """SHA-512 per FIPS 180-4 (used only inside Ed25519 verification)."""
    h = list(_SHA512_H0)
    bit_length = len(data) * 8
    padded = bytearray(data)
    padded += b"\x80"
    padded += b"\x00" * ((-len(padded) - 16) % 128)
    padded += bit_length.to_bytes(16, "big")

    for offset in range(0, len(padded), 128):
        w = [int.from_bytes(padded[offset + 8 * i : offset + 8 * i + 8], "big") for i in range(16)]
        for i in range(16, 80):
            s0 = _rotr64(w[i - 15], 1) ^ _rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7)
            s1 = _rotr64(w[i - 2], 19) ^ _rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & _MASK64)
        a, b, c, d, e, f, g, hh = h
        for i in range(80):
            big_s1 = _rotr64(e, 14) ^ _rotr64(e, 18) ^ _rotr64(e, 41)
            ch = (e & f) ^ ((e ^ _MASK64) & g)
            t1 = (hh + big_s1 + ch + _SHA512_K[i] + w[i]) & _MASK64
            big_s0 = _rotr64(a, 28) ^ _rotr64(a, 34) ^ _rotr64(a, 39)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (big_s0 + maj) & _MASK64
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & _MASK64, c, b, a, (t1 + t2) & _MASK64
        h = [(x + y) & _MASK64 for x, y in zip(h, (a, b, c, d, e, f, g, hh))]
    return b"".join(x.to_bytes(8, "big") for x in h)


# ============================================================================
# Ed25519 verification — RFC 8032 §5.1 (verify-only; no signing here)
# ============================================================================

_ED_P = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_SQRT_M1 = pow(2, (_ED_P - 1) // 4, _ED_P)

#: Extended homogeneous coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z,
#: x*y = T/Z — the representation of RFC 8032's reference implementation.
_EdPoint = tuple[int, int, int, int]

_ED_IDENTITY: _EdPoint = (0, 1, 1, 0)


def _ed_point_add(p: _EdPoint, q: _EdPoint) -> _EdPoint:
    """Unified twisted-Edwards addition (RFC 8032 §5.1.4; complete, so it
    also serves as doubling, exactly as the RFC's reference code uses it)."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _ED_P
    b = (y1 + x1) * (y2 + x2) % _ED_P
    c = 2 * t1 * t2 * _ED_D % _ED_P
    d = 2 * z1 * z2 % _ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P)


def _ed_scalar_mul(scalar: int, point: _EdPoint) -> _EdPoint:
    """Double-and-add scalar multiplication (verification is not secret-
    dependent — every input to this tool is public, so no constant-time
    obligation applies)."""
    result = _ED_IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _ed_point_add(result, point)
        point = _ed_point_add(point, point)
        scalar >>= 1
    return result


def _ed_points_equal(p: _EdPoint, q: _EdPoint) -> bool:
    """Projective equality: X1/Z1 == X2/Z2 and Y1/Z1 == Y2/Z2 (mod p)."""
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    if (x1 * z2 - x2 * z1) % _ED_P != 0:
        return False
    return (y1 * z2 - y2 * z1) % _ED_P == 0


def _ed_recover_x(y: int, sign: int) -> Optional[int]:
    """Recover the x-coordinate for ``y`` per RFC 8032 §5.1.3, or None."""
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = x * _ED_SQRT_M1 % _ED_P
    if (x * x - x2) % _ED_P != 0:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x


def _ed_decode_point(encoded: bytes) -> Optional[_EdPoint]:
    """Decode a 32-byte point per RFC 8032 §5.1.3; None on any rejection."""
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _ED_P:
        return None
    x = _ed_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _ED_P)


# Standard base point B: y = 4/5 (mod p), x even (RFC 8032 §5.1).
_ED_BASE_Y = 4 * pow(5, _ED_P - 2, _ED_P) % _ED_P
_ED_BASE_X = _ed_recover_x(_ED_BASE_Y, 0)
if _ED_BASE_X is None:  # pragma: no cover - spec constant; unreachable
    raise RuntimeError("Ed25519 base point recovery failed — corrupted constants")
_ED_BASE: _EdPoint = (_ED_BASE_X, _ED_BASE_Y, 1, _ED_BASE_X * _ED_BASE_Y % _ED_P)


def ed25519_verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """RFC 8032 Ed25519 verification: ``[S]B == R + [k]A``.

    Rejects malformed lengths, non-canonical S (``S >= L``) and undecodable
    R/A.  Cofactorless group-equation check, matching the in-tree native
    verifier's semantics on every honestly-generated signature.
    """
    if len(signature) != 64 or len(public_key) != 32:
        return False
    a_point = _ed_decode_point(public_key)
    r_point = _ed_decode_point(signature[:32])
    if a_point is None or r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED_L:
        return False
    k = int.from_bytes(sha512(signature[:32] + public_key + message), "little") % _ED_L
    lhs = _ed_scalar_mul(s, _ED_BASE)
    rhs = _ed_point_add(r_point, _ed_scalar_mul(k, a_point))
    return _ed_points_equal(lhs, rhs)


# ============================================================================
# Startup self-KATs (fail closed: a failed KAT verifies nothing)
# ============================================================================

# FIPS 202 vectors — the same expected values the package's POST stage pins
# (``_self_test._kat_sha3_256``), plus SHA3-256('abc'); the 200-byte CAVP
# pattern forces a multi-block absorb so the permutation chaining is covered.
_SHA3_KATS: tuple[tuple[bytes, str], ...] = (
    (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    (
        b"\xa3" * 200,
        "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787",
    ),
)

# FIPS 180-4 vector (NIST examples): SHA-512('abc').
_SHA512_KATS: tuple[tuple[bytes, str], ...] = (
    (
        b"abc",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ),
)

# RFC 8032 §7.1 TEST 1 (empty message) — the repo's canonical copy lives in
# ``tests/test_ed25519_native.py`` (RFC8032_VECTORS[0]); byte-identical here.
_ED_KAT_PUBKEY = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
_ED_KAT_MESSAGE = b""
_ED_KAT_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


def run_self_kats() -> Optional[str]:
    """Run every startup KAT; return a failure description or None.

    Includes a NEGATIVE Ed25519 control (a flipped signature bit must be
    rejected) so a verifier broken into always-accept fails its KATs too.
    """
    for message, expected in _SHA3_KATS:
        got = sha3_256(message).hex()
        if got != expected:
            return f"SHA3-256 KAT failed ({len(message)}-byte message): got {got}"
    for message, expected in _SHA512_KATS:
        got = sha512(message).hex()
        if got != expected:
            return f"SHA-512 KAT failed ({len(message)}-byte message): got {got}"
    if not ed25519_verify(_ED_KAT_SIGNATURE, _ED_KAT_MESSAGE, _ED_KAT_PUBKEY):
        return "Ed25519 KAT failed: RFC 8032 TEST 1 signature rejected"
    tampered = bytearray(_ED_KAT_SIGNATURE)
    tampered[0] ^= 0x01
    if ed25519_verify(bytes(tampered), _ED_KAT_MESSAGE, _ED_KAT_PUBKEY):
        return "Ed25519 negative KAT failed: tampered signature accepted"
    return None


# ============================================================================
# Artefact parsing and signed-message reconstruction (never imports the tree)
# ============================================================================

_ARTEFACT_NAME = "_integrity_signature.py"

# Domain constants — MUST equal ``_build_sign._INTEGRITY_SIG_DOMAIN`` /
# ``_INTEGRITY_SIG_DOMAIN_V3`` byte for byte.  Duplicated (not imported) on
# purpose: importing target code would put the target inside this tool's TCB.
_SIG_DOMAIN_V2 = b"AMA-integrity-signature-v2\x00"
_SIG_DOMAIN_V3 = b"AMA-integrity-signature-v3\x00"

# Extension-enumeration criteria, mirrored from ``_self_test`` (which mirrors
# ``_build_sign``): every extension-suffixed file that is not the native
# library must be covered by the artefact's binding map.
_EXTENSION_SUFFIXES = (".so", ".pyd", ".dylib")
_NATIVE_LIB_PREFIXES = ("libama_cryptography", "ama_cryptography.dll")

_ARTEFACT_FIELDS = frozenset(
    {
        "INTEGRITY_DIGEST_HEX",
        "INTEGRITY_NATIVE_DIGEST_HEX",
        "INTEGRITY_BINDING_DIGESTS_HEX",
        "INTEGRITY_PUBKEY_HEX",
        "INTEGRITY_SIGNATURE_HEX",
    }
)


def artefact_shape_violation(tree: ast.Module) -> Optional[str]:
    """Why ``_integrity_signature.py`` is not pure data, or ``None``.

    The artefact is the ONE file excluded from the package digest, and it has
    to be: it carries that digest, so it cannot contain it.  The in-tree
    signer and verifier exclude it identically
    (``_build_sign._compute_package_digest`` / ``_self_test``), and that is
    correct and unavoidable.

    What was missing is the compensating control.  Nothing constrained the
    file's SHAPE, so the one file no digest covers was unconstrained
    executable Python — and this parser silently skipped every statement that
    was not an assignment.  Measured before this check existed: appending

        import os as _os
        _os.environ["PWNED"] = "1"

    to a shipped artefact, leaving all five signed fields untouched, made this
    tool print "RESULT: PASS — signature (anchored to the expected pubkey),
    source digest, native/binding digests and bytecode caches all verified out
    of band" and exit 0.  The strongest verdict the tool can emit, for a tree
    containing attacker-controlled Python that runs at import, before POST
    exists to have an opinion.  The ``[pyc]`` stage is no help either way: an
    absent cache reports "nothing to poison" and a present one is checked
    against the modified source, so a fresh compile matches.

    The rule is therefore "literal data only": a docstring, and assignments of
    plain names to literals.  Not a fixed field list — the artefact legitimately
    carries ``BUILD_PIPELINE_VERSION`` alongside the five signed fields, and a
    future signer may add another literal — but anything that can *execute*
    (import, call, def, class, if, loop, comprehension with a call in it) is
    refused.  ``ast.literal_eval`` is what draws that line, and it is the same
    function whose result this module already trusts.
    """
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                continue  # module docstring, or a bare string; inert.
            return f"line {node.lineno}: a bare non-string constant"
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets: list[ast.expr]
            value: Optional[ast.expr]
            if isinstance(node, ast.Assign):
                targets, value = list(node.targets), node.value
            else:
                targets, value = [node.target], node.value
            if value is None:
                return f"line {node.lineno}: an annotation with no value"
            for target in targets:
                if not isinstance(target, ast.Name):
                    return (
                        f"line {node.lineno}: assignment to "
                        f"{type(target).__name__}, not a plain name"
                    )
            try:
                ast.literal_eval(value)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                return (
                    f"line {node.lineno}: {targets[0].id if isinstance(targets[0], ast.Name) else '?'}"
                    " is not assigned a plain literal"
                )
            continue
        return (
            f"line {node.lineno}: {type(node).__name__} — the integrity "
            "artefact must contain only a docstring and literal assignments, "
            "because it is the one file no digest covers"
        )
    return None


def parse_artefact_fields(path: Path) -> tuple[Optional[dict[str, object]], Optional[str]]:
    """Read the artefact's fields from its TEXT — never import/exec it.

    ``ast.literal_eval`` on the assignment values reproduces exactly what the
    in-process verifier sees via ``getattr`` (an absent assignment is an
    absent field, which is what selects the v1/v2/v3 schema), while keeping
    target-tree code out of this process.

    The artefact's shape is checked first — see
    :func:`artefact_shape_violation` for why the file excluded from every
    digest must be constrained to literal data.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"cannot read {path.name}: {exc}"
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        return None, f"{path.name} is not parseable Python: {exc}"

    violation = artefact_shape_violation(tree)
    if violation is not None:
        return None, f"{path.name} contains more than literal data: {violation}"

    fields: dict[str, object] = {}
    for node in tree.body:
        targets: list[ast.expr]
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        for target in targets:
            if not isinstance(target, ast.Name) or target.id not in _ARTEFACT_FIELDS:
                continue
            try:
                fields[target.id] = ast.literal_eval(value)
            except ValueError:
                return None, f"{path.name}: field {target.id} is not a plain literal"
    return fields, None


def compute_package_digest(pkg_dir: Path) -> bytes:
    """SHA3-256 over the tree's ``.py`` files and ``_post_kats/`` vectors.

    Byte-for-byte the construction of ``_build_sign._compute_package_digest``
    (== ``_self_test._compute_module_digest``): sorted top-level ``*.py``
    excluding ``_integrity_signature.py``, each as name || content with CRLF
    normalised to LF; then every ``_post_kats/`` file, sorted by name, each
    prefixed ``b"_post_kats/"`` || name || normalised content.
    """
    chunks: list[bytes] = []
    for py_file in sorted(pkg_dir.glob("*.py")):
        if py_file.name == _ARTEFACT_NAME:
            continue
        chunks.append(py_file.name.encode("utf-8"))
        chunks.append(py_file.read_bytes().replace(b"\r\n", b"\n"))
    kat_dir = pkg_dir / "_post_kats"
    if kat_dir.is_dir():
        for kat_file in sorted((p for p in kat_dir.iterdir() if p.is_file()), key=lambda p: p.name):
            chunks.append(b"_post_kats/")
            chunks.append(kat_file.name.encode("utf-8"))
            chunks.append(kat_file.read_bytes().replace(b"\r\n", b"\n"))
    return sha3_256(b"".join(chunks))


def _serialize_binding_digests(binding_digests: dict[str, bytes]) -> bytes:
    """``name || 0x00 || digest`` per entry, sorted by name (v3 canonical
    serialization — mirrored byte-for-byte from ``_build_sign``)."""
    out = bytearray()
    for name in sorted(binding_digests):
        out += name.encode("utf-8") + b"\x00" + binding_digests[name]
    return bytes(out)


def _parse_native_digest_field(fields: dict[str, object]) -> tuple[Optional[bytes], Optional[str]]:
    """``(native_digest, error)``; ``(None, None)`` when the field is absent
    (a v1 artefact).  Mirrors ``_self_test._parse_embedded_native_digest``."""
    value = fields.get("INTEGRITY_NATIVE_DIGEST_HEX")
    if value is None:
        return None, None
    if not isinstance(value, str):
        return None, "artefact INTEGRITY_NATIVE_DIGEST_HEX is not a string"
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        return None, f"artefact INTEGRITY_NATIVE_DIGEST_HEX not hex: {exc}"
    if len(raw) != 32:
        return None, f"artefact native digest is {len(raw)} bytes (expected 32)"
    return raw, None


def _parse_binding_digest_field(
    fields: dict[str, object],
) -> tuple[Optional[dict[str, bytes]], Optional[str]]:
    """``(binding_digests, error)``; ``(None, None)`` when absent (pre-v3).

    Mirrors ``_self_test._parse_embedded_binding_digests`` — including the
    rule that an EMPTY dict is still a v3 artefact (the repair flow signs
    with binding digests empty; the field's presence selects the schema).
    """
    value = fields.get("INTEGRITY_BINDING_DIGESTS_HEX")
    if value is None:
        return None, None
    if not isinstance(value, dict):
        return None, "artefact INTEGRITY_BINDING_DIGESTS_HEX is not a dict"
    parsed: dict[str, bytes] = {}
    for name, digest_hex in value.items():
        if not isinstance(name, str) or not isinstance(digest_hex, str):
            return None, "artefact binding-digest entries must be str -> str"
        try:
            raw = bytes.fromhex(digest_hex)
        except ValueError as exc:
            return None, f"artefact binding digest for {name!r} not hex: {exc}"
        if len(raw) != 32:
            return None, f"artefact binding digest for {name!r} is {len(raw)} bytes (expected 32)"
        parsed[name] = raw
    return parsed, None


def resolve_signed_message(
    fields: dict[str, object], py_digest_raw: bytes
) -> tuple[str, Optional[bytes], Optional[dict[str, bytes]], Optional[bytes], Optional[str]]:
    """Reconstruct the exact message the artefact's signature must cover.

    Returns ``(schema, native_digest, binding_digests, message, error)``.
    Schema selection by field PRESENCE, mirroring
    ``_self_test._resolve_signed_message``: v1 signs the raw .py digest, v2
    ``SHA3-256(domain_v2 || py || native)``, v3 ``SHA3-256(domain_v3 || py ||
    native || serialized_bindings)``.  Moving fields between schemas changes
    the message and therefore fails the signature — never a downgrade.
    """
    native_raw, error = _parse_native_digest_field(fields)
    if error is not None:
        return "?", None, None, None, error
    binding, error = _parse_binding_digest_field(fields)
    if error is not None:
        return "?", native_raw, None, None, error

    if binding is not None:
        if native_raw is None:
            return (
                "?",
                None,
                None,
                None,
                "artefact malformed: binding digests present without a native "
                "digest (no signer emits this shape)",
            )
        message = sha3_256(
            _SIG_DOMAIN_V3 + py_digest_raw + native_raw + _serialize_binding_digests(binding)
        )
        return "v3", native_raw, binding, message, None
    if native_raw is not None:
        return "v2", native_raw, None, sha3_256(_SIG_DOMAIN_V2 + py_digest_raw + native_raw), None
    return "v1", None, None, py_digest_raw, None


# ============================================================================
# Execution-integrity: cached .pyc vs a fresh compile of the on-disk source
# ============================================================================


def _code_matches(fresh: CodeType, cached: CodeType) -> bool:
    """Execution-equivalence of two code objects.

    Mirrors ``_self_test._code_matches`` exactly: compares the executed
    surface (``co_code``, names, locals, flags, argument shape, and every
    constant — recursing into nested code objects, type-strict on constants
    so ``1``/``1.0``/``True`` cannot be swapped) and ignores ``co_filename``
    and the line tables, which legitimately differ for a tree compiled at a
    different path.

    That includes ``co_exceptiontable``, which both copies were missing.
    From Python 3.11 exception handling is a side table mapping instruction
    ranges to handlers rather than instructions in ``co_code`` (3.10's
    ``SETUP_FINALLY`` and friends), so a ``.pyc`` could delete or redirect any
    ``try``/``except`` in the target tree with ``co_code`` byte-identical, and
    both this tool and the in-process check called the result equivalent.
    Demonstrated on 3.11.15: table blanked, ``co_code`` and ``co_consts``
    identical, comparison True, behaviour changed from returning ``"handled"``
    to letting the exception escape.  Read with ``getattr`` because the
    support floor is 3.10, where the attribute does not exist and the same
    information is already inside ``co_code``.
    """
    if getattr(fresh, "co_exceptiontable", b"") != getattr(cached, "co_exceptiontable", b""):
        return False
    if (
        fresh.co_code != cached.co_code
        or fresh.co_names != cached.co_names
        or fresh.co_varnames != cached.co_varnames
        or fresh.co_freevars != cached.co_freevars
        or fresh.co_cellvars != cached.co_cellvars
        or fresh.co_flags != cached.co_flags
        or fresh.co_argcount != cached.co_argcount
        or fresh.co_posonlyargcount != cached.co_posonlyargcount
        or fresh.co_kwonlyargcount != cached.co_kwonlyargcount
        or fresh.co_nlocals != cached.co_nlocals
        or fresh.co_stacksize != cached.co_stacksize
    ):
        return False
    if len(fresh.co_consts) != len(cached.co_consts):
        return False
    for a, b in zip(fresh.co_consts, cached.co_consts):
        a_is_code = isinstance(a, CodeType)
        b_is_code = isinstance(b, CodeType)
        if a_is_code != b_is_code:
            return False
        if a_is_code:
            if not _code_matches(a, b):
                return False
        elif type(a) is not type(b) or a != b:
            return False
    return True


def _cache_header_is_live(source_path: str, header: bytes) -> bool:
    """True when the running interpreter would LOAD this ``.pyc`` header.

    Mirrors CPython's ``_bootstrap_external`` validation (PEP 552) and
    ``_self_test._cache_header_is_live``.  ``header`` is the 12 bytes after the
    magic number: a little-endian flags word, then either the source mtime and
    size (timestamp caches) or an 8-byte source hash.  A hash-based cache is
    validated by the interpreter only when its check_source bit is set; an
    unchecked one is loaded blindly and therefore always executes.

    Anything unresolvable — unreadable source, unknown flag bit — is reported
    live, so an odd cache is judged rather than waved through.
    """
    flags = int.from_bytes(header[:4], "little")
    if flags & 0b1:
        if not flags & 0b10:
            return True
        try:
            with open(source_path, "rb") as src_fh:
                source_bytes = src_fh.read()
        except OSError:
            return True
        return bool(importlib.util.source_hash(source_bytes) == header[4:12])
    try:
        stat = os.stat(source_path)
    except OSError:
        return True
    return (
        int.from_bytes(header[4:8], "little") == int(stat.st_mtime) & 0xFFFFFFFF
        and int.from_bytes(header[8:12], "little") == stat.st_size & 0xFFFFFFFF
    )


def _cached_bytecode(source_path: str) -> tuple[str, Optional[CodeType], Optional[str]]:
    """Load the ``.pyc`` the running interpreter would use for ``source_path``.

    Mirrors ``_self_test._cached_code_for``: ``("verified", code, None)`` when
    a cache for THIS interpreter exists and was read; ``("skipped", None,
    None)`` when there is nothing on disk this interpreter would load; and
    ``("verified", None, error)`` for a cache that exists but cannot be read
    as a code object (a fault, not a pass).
    """
    try:
        cache_path = importlib.util.cache_from_source(source_path)
    except (NotImplementedError, ValueError):
        return "skipped", None, None
    if not Path(cache_path).is_file():
        return "skipped", None, None
    try:
        with open(cache_path, "rb") as fh:
            magic = fh.read(4)
            if magic != importlib.util.MAGIC_NUMBER:
                # Built by a different interpreter version; the running one
                # recompiles from source instead of loading it.
                return "skipped", None, None
            header = fh.read(12)  # flags + (mtime,size) | source hash
            if len(header) != 12:
                return "verified", None, f"cached bytecode {cache_path} has a truncated header"
            if not _cache_header_is_live(source_path, header):
                # The running interpreter would reject this cache and recompile
                # from source, so it is not what executes — the same rule the
                # wrong-magic case above applies.  Judging it anyway reported a
                # tree whose executed bytecode IS the signed source as a
                # poisoned/stale .pyc failure.
                return "skipped", None, None
            cached_body = fh.read()
        # The code object is only materialised for comparison — NEVER exec'd;
        # reading the exact .pyc is precisely how a poisoned one is caught.
        cached_code = marshal.loads(cached_body)  # fmt: skip  # noqa: S302 # nosec B302 -- compared, never exec'd; reading the .pyc is how a poisoned one is caught (OOB-001)
    except (OSError, ValueError, EOFError) as exc:
        return "verified", None, f"cached bytecode {cache_path} is unreadable ({exc})"
    if not isinstance(cached_code, CodeType):
        return "verified", None, f"cached bytecode {cache_path} is not a code object"
    return "verified", cached_code, None


def verify_bytecode_cache(py_file: Path) -> tuple[str, Optional[str]]:
    """Bind one source file's cached ``.pyc`` to a fresh compile of it.

    Mirrors ``_self_test._verify_source_file_bytecode``, with out-of-band
    phrasing: here NEITHER side is pre-trusted (the signature check vouches
    for the source separately), so a mismatch is reported as a disagreement
    between the cache and the on-disk source — either a poisoned/stale
    ``.pyc`` or a source edited after compilation; the digest verdict says
    which.  Returns ``(status, error)`` with the same tri-state semantics.
    """
    source_path = str(py_file)
    status, cached_code, error = _cached_bytecode(source_path)
    if error is not None:
        return "verified", f"{py_file.name}: {error}"
    if status == "skipped" or cached_code is None:
        return "skipped", None

    # Read the source exactly as the import system would (BOM/encoding-cookie
    # and universal-newline handling), so a benign encoding difference is
    # never mistaken for tampering.
    try:
        source = importlib.machinery.SourceFileLoader(py_file.stem, source_path).get_source(
            py_file.stem
        )
    except (OSError, SyntaxError, ValueError) as exc:
        return "verified", f"{py_file.name}: source unavailable for the bytecode check ({exc})"
    if source is None:
        return "skipped", None
    try:
        # optimize=-1 tracks this interpreter's -O level — the same level
        # whose cache slot cache_from_source() resolved.
        fresh = compile(source, source_path, "exec", dont_inherit=True, optimize=-1)
    except SyntaxError as exc:
        return "verified", f"{py_file.name}: on-disk source does not compile ({exc})"

    if not _code_matches(fresh, cached_code):
        return "verified", (
            f"{py_file.name}: cached bytecode does not match a fresh compile of "
            "the on-disk source — poisoned/stale .pyc, or source modified "
            "after compilation"
        )
    return "verified", None


# ============================================================================
# Verification stages
# ============================================================================


def _verify_artefact(
    pkg_dir: Path,
    expected_pubkey: Optional[bytes],
) -> tuple[list[str], Optional[bytes], Optional[dict[str, bytes]]]:
    """Signature + .py digest verification.  Returns ``(failures,
    native_digest, binding_digests)``; the digests are None when the artefact
    could not be authenticated (later stages then have nothing to bind to).

    ``expected_pubkey`` is the anchor: the 32-byte Ed25519 public key the
    artefact MUST be signed under, supplied by the operator from outside the
    tree.  Checking it is what separates authenticity from internal
    consistency.  Without it, this stage proves only that whoever wrote the
    artefact also wrote a matching signature — which an attacker holding write
    access to the installed tree, the threat this tool exists to answer, can do
    with a keypair of their own: replace the sources, mint a key, re-sign, and
    every digest lines up.  ``main()`` refuses to report PASS unless an anchor
    was supplied or the weaker mode was explicitly requested.
    """
    fields, error = parse_artefact_fields(pkg_dir / _ARTEFACT_NAME)
    if fields is None:
        return [f"artefact unusable: {error}"], None, None

    digest_field = fields.get("INTEGRITY_DIGEST_HEX")
    pubkey_field = fields.get("INTEGRITY_PUBKEY_HEX")
    signature_field = fields.get("INTEGRITY_SIGNATURE_HEX")
    if (
        not isinstance(digest_field, str)
        or not isinstance(pubkey_field, str)
        or not isinstance(signature_field, str)
    ):
        return ["artefact malformed: missing or non-string mandatory field"], None, None
    try:
        stored_digest = bytes.fromhex(digest_field)
        pubkey = bytes.fromhex(pubkey_field)
        signature = bytes.fromhex(signature_field)
    except ValueError as exc:
        return [f"artefact fields not hex: {exc}"], None, None
    if len(stored_digest) != 32 or len(pubkey) != 32 or len(signature) != 64:
        return (
            [
                f"artefact field sizes wrong: digest={len(stored_digest)} "
                f"pubkey={len(pubkey)} signature={len(signature)} (expected 32, 32, 64)"
            ],
            None,
            None,
        )

    computed = compute_package_digest(pkg_dir)
    if computed != stored_digest:
        return (
            [
                f"py digest MISMATCH: computed={computed.hex()[:16]}... "
                f"signed={stored_digest.hex()[:16]}... — a .py file or a _post_kats/ "
                "vector changed after signing (per-file attribution, where a "
                "bytecode cache exists, follows in the [pyc] stage)"
            ],
            None,
            None,
        )
    print(f"[py-digest] verified: {computed.hex()}")

    schema, native_raw, binding, message, error = resolve_signed_message(fields, stored_digest)
    if message is None:
        return [error or "artefact schema unresolvable"], None, None
    bound = "none" if binding is None else str(len(binding))
    print(f"[artefact] schema {schema}; native bound: {native_raw is not None}; bindings: {bound}")

    # Anchor BEFORE verifying: a signature that verifies under the wrong key is
    # a stronger finding than one that does not verify at all, and reporting it
    # as "verified" for even one line of output would be the misleading half of
    # the result.
    if expected_pubkey is not None and pubkey != expected_pubkey:
        return (
            [
                "artefact pubkey is NOT the expected one: artefact carries "
                f"{pubkey.hex()} but --expected-pubkey names "
                f"{expected_pubkey.hex()} — the tree was signed by a different "
                "key, which is what re-signing tampered sources looks like"
            ],
            None,
            None,
        )

    if not ed25519_verify(signature, message, pubkey):
        return (
            [
                "Ed25519 signature did NOT verify over the reconstructed "
                f"{schema} message — artefact or tree tampered"
            ],
            None,
            None,
        )
    # Print the WHOLE key, not a prefix: the operator's only way to check an
    # unanchored run after the fact is to compare it against a key they hold,
    # and a 16-hex-digit prefix is not that comparison.
    anchored = "anchored to --expected-pubkey" if expected_pubkey is not None else "UNANCHORED"
    print(f"[signature] verified (Ed25519, {anchored}) pubkey={pubkey.hex()}")
    return [], native_raw, binding


def _discover_native_candidates(pkg_dir: Path) -> list[Path]:
    """Native-library files shipped inside the package dir, deduplicated
    through symlinks (the SONAME chain resolves to one real object)."""
    seen: dict[Path, Path] = {}
    for path in sorted(pkg_dir.iterdir()):
        if not path.is_file():
            continue
        if not path.name.startswith(_NATIVE_LIB_PREFIXES):
            continue
        if ".so" not in path.name and not path.name.endswith((".dylib", ".dll")):
            continue
        seen.setdefault(path.resolve(), path)
    return list(seen.values())


def _verify_native_library(
    pkg_dir: Path, native_digest: Optional[bytes], native_lib_arg: Optional[Path]
) -> tuple[list[str], list[str]]:
    """Bind the signed native digest to an actual file.  Returns
    ``(failures, warnings)``; an unresolvable library is a warning (reported,
    not blessed), a resolvable one must match."""
    if native_digest is None:
        if native_lib_arg is not None:
            return [
                f"--native-lib {native_lib_arg} given, but the artefact binds no "
                "native library digest — cannot verify it out of band"
            ], []
        return [], ["native library: artefact binds none (v1 artefact) — nothing verified"]

    candidates = (
        [native_lib_arg] if native_lib_arg is not None else _discover_native_candidates(pkg_dir)
    )
    if not candidates:
        return [], [
            "native library: signed digest present but no library found next to "
            "the package — pass --native-lib to verify it"
        ]
    failures: list[str] = []
    for candidate in candidates:
        try:
            actual = sha3_256(candidate.resolve().read_bytes())
        except OSError as exc:
            failures.append(f"native library {candidate} unreadable: {exc}")
            continue
        if actual != native_digest:
            failures.append(
                f"native library digest MISMATCH at {candidate} "
                f"(signed={native_digest.hex()[:16]}..., actual={actual.hex()[:16]}...)"
            )
        else:
            print(f"[native] verified: {candidate}")
    return failures, []


def _verify_binding_extensions(
    pkg_dir: Path, binding_digests: Optional[dict[str, bytes]]
) -> tuple[list[str], list[str]]:
    """Verify on-disk compiled extensions against the authenticated map.

    Out-of-band severity is fail-closed everywhere ``_self_test`` splits by
    anchored/developer: this tool cannot resolve the compiled-in trust anchor
    without loading the native library, so a listed-but-missing, mismatched
    or UNCOVERED extension is always a failure.  (A source tree whose
    repair-flow artefact binds nothing therefore fails here if extensions
    were built afterwards — deliberately: an out-of-band verifier cannot
    distinguish a developer rebuild from an implant, and must not bless it.)
    """
    on_disk: dict[str, Path] = {}
    for path in sorted(pkg_dir.iterdir()):
        if not path.is_file() or path.suffix not in _EXTENSION_SUFFIXES:
            continue
        if path.name.startswith(_NATIVE_LIB_PREFIXES):
            continue
        on_disk[path.name] = path

    if binding_digests is None:
        if on_disk:
            return [], [
                "binding extensions present but the artefact predates v3 (no "
                "map) — NOT verified: " + ", ".join(sorted(on_disk))
            ]
        return [], []

    failures: list[str] = []
    for name in sorted(binding_digests):
        listed = on_disk.get(name)
        if listed is None:
            failures.append(f"binding extension {name}: signed but missing on disk")
            continue
        try:
            actual = sha3_256(listed.read_bytes())
        except OSError as exc:
            failures.append(f"binding extension {name}: unreadable ({exc})")
            continue
        if actual != binding_digests[name]:
            failures.append(f"binding extension {name}: digest MISMATCH vs the signed build")
        else:
            print(f"[binding] verified: {name}")
    for name in sorted(on_disk):
        if name not in binding_digests:
            failures.append(
                f"binding extension {name}: present on disk but not covered by "
                "the signed artefact — unverifiable compiled code (fail closed)"
            )
    if not failures and not binding_digests:
        print("[binding] artefact binds no extensions (repair-flow artefact); none on disk")
    return failures, []


def _verify_all_bytecode_caches(pkg_dir: Path) -> tuple[list[str], int, int]:
    """Per-file execution-integrity pass over every top-level ``.py``
    (the same set ``_self_test._check_execution_integrity`` walks, including
    ``_integrity_signature.py``).  Returns ``(failures, verified, skipped)``.
    """
    failures: list[str] = []
    verified = 0
    skipped = 0
    for py_file in sorted(pkg_dir.glob("*.py")):
        status, error = verify_bytecode_cache(py_file)
        if error is not None:
            failures.append(error)
            print(f"[pyc] {py_file.name}: FAIL — {error}")
        elif status == "verified":
            verified += 1
            print(f"[pyc] {py_file.name}: cache matches source")
        else:
            skipped += 1
            print(f"[pyc] {py_file.name}: no cache for this interpreter (nothing to poison)")
    return failures, verified, skipped


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Out-of-band verifier for an installed ama_cryptography tree. "
            "Runs from outside the package (imports nothing from it) with "
            "hand-written SHA3-256/Ed25519 — see the module docstring for "
            "the trust base."
        )
    )
    parser.add_argument(
        "package_dir",
        type=Path,
        help="Path to the installed ama_cryptography package directory.",
    )
    parser.add_argument(
        "--native-lib",
        type=Path,
        default=None,
        help=(
            "Path to the libama_cryptography shared object to verify against "
            "the signed native digest (defaults to discovery inside the "
            "package directory)."
        ),
    )
    parser.add_argument(
        "--expected-pubkey",
        default=None,
        help=(
            "The 64-hex-character Ed25519 public key the artefact must be "
            "signed under, supplied from OUTSIDE the tree being checked. "
            "Without it the signature can only be checked against the key the "
            "tree itself carries, which an attacker who can rewrite the tree "
            "can replace with their own; PASS then requires --allow-unanchored."
        ),
    )
    parser.add_argument(
        "--allow-unanchored",
        action="store_true",
        help=(
            "Report PASS without --expected-pubkey. For developer trees, whose "
            "artefacts are signed with a per-build ephemeral key that no "
            "operator holds. The verdict then attests internal consistency, "
            "not authenticity."
        ),
    )
    args = parser.parse_args(argv)

    kat_error = run_self_kats()
    if kat_error is not None:
        print(f"SELF-KAT FAILED: {kat_error}", file=sys.stderr)
        print("Refusing to verify anything (fail closed).", file=sys.stderr)
        return 3
    print("[self-kat] SHA3-256 / SHA-512 / Ed25519 KATs passed (incl. negative control)")

    expected_pubkey: Optional[bytes] = None
    if args.expected_pubkey is not None:
        try:
            expected_pubkey = bytes.fromhex(args.expected_pubkey.strip())
        except ValueError as exc:
            print(f"ERROR: --expected-pubkey is not hex: {exc}", file=sys.stderr)
            return 2
        if len(expected_pubkey) != 32:
            print(
                f"ERROR: --expected-pubkey is {len(expected_pubkey)} bytes (expected 32)",
                file=sys.stderr,
            )
            return 2
    if expected_pubkey is None and not args.allow_unanchored:
        print(
            "ERROR: no trust anchor. This tool verifies a signature made with a "
            "key the target tree supplies, so without --expected-pubkey a PASS "
            "would mean only that the artefact is internally consistent — which "
            "an attacker who can rewrite the installed tree can arrange by "
            "re-signing it under a key of their own. Pass --expected-pubkey "
            "<64 hex> with the key you hold, or --allow-unanchored to accept "
            "the weaker claim deliberately.",
            file=sys.stderr,
        )
        return 2

    pkg_dir = args.package_dir.resolve()
    if not pkg_dir.is_dir():
        print(f"ERROR: {pkg_dir} is not a directory", file=sys.stderr)
        return 2
    if not (pkg_dir / _ARTEFACT_NAME).is_file():
        print(
            f"FAIL: {pkg_dir} carries no {_ARTEFACT_NAME} — an unsigned tree "
            "cannot be verified out of band (fail closed)",
            file=sys.stderr,
        )
        return 1

    artefact_failures, native_digest, binding_digests = _verify_artefact(pkg_dir, expected_pubkey)
    failures: list[str] = list(artefact_failures)
    warnings: list[str] = []

    # The native and binding stages bind on-disk bytes to digests that come
    # from the artefact.  When the artefact did not authenticate, there are no
    # such digests — `_verify_artefact` returns None for both — and running the
    # stages anyway made them describe the ARTEFACT rather than their own
    # situation: an authentic v3 artefact whose pubkey simply was not the
    # expected one produced "artefact binds none (v1 artefact)" and "the
    # artefact predates v3 (no map)", two lines after the tool had printed
    # `[artefact] schema v3; native bound: True; bindings: 6`.  Both statements
    # were false, and an operator triaging a key mismatch would read them as
    # "this installation carries an old artefact".  A verifier that states
    # something untrue about the thing it is verifying is the failure mode this
    # whole tool exists to remove, so the stages are skipped and the skip is
    # reported for what it is.  (No verdict changes: every path that returns
    # None also returns a failure, so the run was already FAIL.)
    if artefact_failures:
        warnings.append(
            "native library and binding extensions: NOT CHECKED — the artefact "
            "did not authenticate above, so no trusted digest exists to bind "
            "them to. This says nothing about whether the artefact carries "
            "them; resolve the failure above and re-run."
        )
    else:
        native_failures, native_warnings = _verify_native_library(
            pkg_dir, native_digest, args.native_lib
        )
        failures += native_failures
        warnings += native_warnings

        binding_failures, binding_warnings = _verify_binding_extensions(pkg_dir, binding_digests)
        failures += binding_failures
        warnings += binding_warnings

    pyc_failures, pyc_verified, pyc_skipped = _verify_all_bytecode_caches(pkg_dir)
    failures += pyc_failures
    print(f"[pyc] summary: {pyc_verified} cache(s) verified, {pyc_skipped} without a cache")

    for warning in warnings:
        print(f"WARNING: {warning}")
    if failures:
        print(f"RESULT: FAIL — {len(failures)} problem(s):")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    if expected_pubkey is None:
        print("RESULT: PASS (UNANCHORED) — source digest, native/binding digests and")
        print("bytecode caches are all consistent with the artefact, and the artefact's")
        print("signature verifies under the key the TREE ITSELF carries. That is")
        print("internal consistency, not authenticity: re-run with --expected-pubkey")
        print("<64 hex> to check the tree was signed by the key you hold.")
        return 0
    print("RESULT: PASS — signature (anchored to the expected pubkey), source digest,")
    print("native/binding digests and bytecode caches all verified out of band.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
