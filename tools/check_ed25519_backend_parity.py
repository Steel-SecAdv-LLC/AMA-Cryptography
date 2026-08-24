#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Ed25519 Backend Differential (INVARIANT-26 support)
======================================================================

Asserts that this repository's two Ed25519 backends return the **same verdict**
for every signature in its differential corpus — single verify, batch verify at
counts spanning donna's multi-scalar boundary, and canonically-encoded
small-order (torsion) signatures repeated across counts so a *probabilistic*
divergence cannot pass as one lucky sample. It does not claim to have tried
every possible signature; it claims the two backends — and single vs batch
within each — cannot disagree on the corpus that exercises the paths either
verifier takes.

Why
---
The library ships two implementations of one public API and selects between
them at configure time — ``CMakeLists.txt`` removes ``src/c/ama_ed25519.c``
from the source list and substitutes ``src/c/ed25519_donna_shim.c`` whenever
``AMA_ED25519_ASSEMBLY`` is ON, which is the default on x86-64:

* **ed25519-donna** — x86-64 assembly; what every x86-64 lane actually builds.
* **fe51** — the portable path in ``ama_ed25519.c``; ARM and everything else.

Before this check, no CI lane built fe51 on x86-64 and nothing anywhere
compared the two.  That gap had already produced a live divergence risk:
INVARIANT-26 fixed an RFC 8032 §5.1.7 canonical-``S`` defect present in both
backends **for different reasons** — donna's ``RS[63] & 224`` guard was too
weak (it only rejects ``S >= 2**253``), while fe51 had no range check at all.
A fix written against one could easily have left the other broken, and on
x86-64 nothing would have noticed.

What this is, and is not
------------------------
This is a **differential** test, not a known-answer test.  It does not decide
which backend is right; it asserts that they cannot disagree.  Correctness
against the standard is the job of the KAT/ACVP suites and the Wycheproof
corpus.  Both roles are needed: a KAT catches "both are wrong the same way",
a differential catches "one was fixed and the other was not".

Corpus
------
Five families.  The first three are generated at run time from freshly minted
keypairs, so the check needs no vendored data and stays meaningful as the code
changes; the fourth is a fixed table of compressed-point encodings
(``DECODE_CASES``), because the encodings that discriminate the canonical-``y``
rule are specific constants derived from ``p`` and cannot be stumbled upon by
generation — which is exactly why the first three families cannot test it; the
fifth compares output bytes rather than verdicts.

1. **Honest signatures** — produced by each backend, cross-verified by the
   other.  This also pins that the two agree on *signing*, not just verifying.
2. **Malleable twins** — ``(R, S + L)`` for each honest signature.  This is the
   exact INVARIANT-26 defect, and the case that would have caught a one-sided
   fix.
3. **Structured corruption** — single-bit flips across ``R``, ``S``, the
   message and the public key, plus out-of-range ``S`` values at the ``L``
   boundary.
4. **Compressed-point decode** (INVARIANT-38, and RFC 8032 §5.1.3) — canonical
   and non-canonical encodings of the same curve point, put to
   ``ama_ed25519_point_add`` and ``ama_ed25519_scalarmult_public`` rather than
   to verify.  Families 1-3 cannot test either decode rule: a rejected
   encoding is not the signer's key, so verify rejects it on the signature
   regardless and the two backends agree without either having applied the
   rule.  Family 4 pairs each must-reject encoding with a must-decode twin, so
   a backend that dropped a rule — or applied it on only some entry points, or
   "implemented" it by over-rejecting — becomes a disagreement:

   * canonical ``y``: ``y = 0`` (must decode) against ``y = p``, the same point
     non-canonically encoded (must be refused);
   * the x-sign rule: ``y = 1`` and ``y = p - 1`` — the only two points with
     ``x = 0``, hence the only two encodings §5.1.3 discriminates — each with
     the sign bit set (must be refused) and clear (must decode), plus ``y = 0``
     with the sign bit set (must decode, because ``x != 0`` there) and 2G in
     both parities.

   The x-sign entries were added after a measurement: with them absent, the
   rule was removed from the fe51 sources only, and this gate reported "both
   backends agree on every case" and exited 0 over two libraries that
   demonstrably disagreed.  The corpus is the gate; an encoding it does not
   contain is a rule it does not check.

5. **Byte-exact arithmetic** — ``point_from_scalar``, ``scalarmult_public``,
   ``point_add`` and ``double_scalarmult_public`` over a deterministic scalar
   and point corpus, compared on their 32 OUTPUT BYTES.  Families 1-4 compare
   verdicts, which cannot see a backend that returns ``AMA_SUCCESS`` with the
   wrong group element — and both backends did exactly that.  donna's
   ``ama_ed25519_double_scalarmult_public`` summed two PARTIAL points with
   ``ge25519_add_p1p1``, whose third product is ``p->t * q->t``, and neither
   ``t`` had been written: ``[7]B + [3]B`` returned ``906ebcd3…`` instead of
   ``[10]B``.  fe51's ``sc25519_to_wnaf`` dropped the carry out of bit 255, so
   ``[ff..ff]B`` returned ``-B``.  Neither was reachable from this gate as it
   stood: it compared ``rc == 0`` booleans, its only scalar was ``2``, and
   ``double_scalarmult_public`` had no ctypes binding at all.  The family also
   asserts two identities per backend, so a pair that agrees on a wrong answer
   is still caught: ``[s]P == [s mod l]P`` (the reduction contract stated in
   ``include/ama_cryptography.h``) and ``[s1]P1 + [s2]P2 == point_add([s1]P1,
   [s2]P2)`` (the identity donna's shim construction implements).

Exit status
-----------
``0`` when every case agrees and both non-vacuity guards were satisfied.

``1`` on any disagreement, or on a case where the two backends agreed on an
answer that is absolutely wrong (a genuine signature rejected by both, a
must-decode encoding refused by both) — each is printed with the inputs needed
to reproduce it.  Agreement is the property this tool exists to check, but it
is not on its own evidence of correctness, so the assertions that do not
depend on agreement are reported through the same exit code.

``2`` when the comparison could not be made to mean anything: a library that
would not load, a corpus with no genuine signature in it, a decode stage in
which no absolute assertion ran, or an arithmetic stage in which no case
produced output bytes.  An unrunnable comparison is never reported
as a passing one, and the distinct exit code keeps "inconclusive" from being
read as "failed".
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

#: Order of the Ed25519 base point (RFC 8032 §5.1).
L = 2**252 + 27742317777372353535851937790883648493

#: Number of independent keypairs to exercise.  Each contributes one honest
#: signature, four ``S``-boundary cases, and 32 structured-corruption cases,
#: plus the ``S + L`` malleable twin whenever that value still fits in 32
#: bytes — which it does for every canonical signature, since ``S < L`` gives
#: ``S + L < 2*L < 2**253``, but the code tests it rather than assuming it, so
#: the per-keypair count is 37 or 38 and not a fixed multiple.
KEYPAIRS = 24


class Backend:
    """A loaded AMA shared library exposing the Ed25519 C ABI."""

    def __init__(self, name: str, path: Path) -> None:
        self.name = name
        self.path = path
        self.lib = ctypes.CDLL(str(path))

        self.lib.ama_ed25519_keypair.restype = ctypes.c_int
        self.lib.ama_ed25519_keypair.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

        self.lib.ama_ed25519_sign.restype = ctypes.c_int
        self.lib.ama_ed25519_sign.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]

        self.lib.ama_ed25519_verify.restype = ctypes.c_int
        self.lib.ama_ed25519_verify.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]

        self.lib.ama_ed25519_batch_verify.restype = ctypes.c_int
        self.lib.ama_ed25519_batch_verify.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_int),
        ]

        self.lib.ama_ed25519_sha512.restype = None
        self.lib.ama_ed25519_sha512.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]

        self.lib.ama_ed25519_sc_reduce.restype = None
        self.lib.ama_ed25519_sc_reduce.argtypes = [ctypes.c_char_p]

        self.lib.ama_ed25519_sc_muladd.restype = None
        self.lib.ama_ed25519_sc_muladd.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        self.lib.ama_ed25519_point_from_scalar.restype = ctypes.c_int
        self.lib.ama_ed25519_point_from_scalar.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        self.lib.ama_ed25519_point_add.restype = ctypes.c_int
        self.lib.ama_ed25519_point_add.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        self.lib.ama_ed25519_scalarmult_public.restype = ctypes.c_int
        self.lib.ama_ed25519_scalarmult_public.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        self.lib.ama_ed25519_double_scalarmult_public.restype = ctypes.c_int
        self.lib.ama_ed25519_double_scalarmult_public.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

    def keypair(self) -> tuple[bytes, bytes]:
        public = ctypes.create_string_buffer(32)
        secret = ctypes.create_string_buffer(64)
        if self.lib.ama_ed25519_keypair(public, secret) != 0:
            raise RuntimeError(f"{self.name}: ama_ed25519_keypair failed")
        return public.raw[:32], secret.raw[:64]

    def sign(self, message: bytes, secret: bytes) -> bytes:
        signature = ctypes.create_string_buffer(64)
        if self.lib.ama_ed25519_sign(signature, message, len(message), secret) != 0:
            raise RuntimeError(f"{self.name}: ama_ed25519_sign failed")
        return signature.raw[:64]

    def point_add(self, p_enc: bytes, q_enc: bytes) -> bool:
        """True when both operands decoded and the addition succeeded.

        Exposed because the signature path cannot discriminate the
        canonical-``y`` rule (INVARIANT-38): a non-canonical public key is
        never the signer's key, so verify rejects it on the signature whether
        or not the encoding rule is enforced, and both backends agree
        vacuously.  ``ama_ed25519_point_add`` reports decode success directly,
        which is what makes the comparison in ``build_decode_cases`` able to
        fail.
        """
        if len(p_enc) != 32 or len(q_enc) != 32:
            raise ValueError("compressed points must be exactly 32 bytes")
        out = ctypes.create_string_buffer(32)
        return bool(self.lib.ama_ed25519_point_add(out, p_enc, q_enc) == 0)

    def scalarmult_public(self, scalar: bytes, point_enc: bytes) -> bool:
        """True when the point decoded and the scalar multiplication succeeded."""
        if len(scalar) != 32 or len(point_enc) != 32:
            raise ValueError("scalar and compressed point must be exactly 32 bytes")
        out = ctypes.create_string_buffer(32)
        return bool(self.lib.ama_ed25519_scalarmult_public(out, scalar, point_enc) == 0)

    # ---- byte-exact arithmetic surface -------------------------------
    #
    # Everything above compares VERDICTS: did both backends accept, did both
    # reject.  That is blind to a backend that accepts and then returns the
    # wrong group element, and both backends did exactly that.  donna's
    # ama_ed25519_double_scalarmult_public added two PARTIAL points with
    # ge25519_add_p1p1, whose third product is p->t * q->t, and neither t had
    # been written — [7]B + [3]B returned 906ebcd3... instead of [10]B with
    # AMA_SUCCESS.  fe51's sc25519_to_wnaf dropped the carry out of bit 255,
    # so [ff..ff]B returned -B.  Both were invisible here: `ops` compared
    # `rc == 0` booleans, its only scalar was _TWO_SCALAR = 2 (too small to
    # reach either defect), and double_scalarmult_public had no binding at
    # all.  These four wrappers return the OUTPUT BYTES, or None when the
    # call refused, so the comparison below can see a wrong answer.

    def point_from_scalar_bytes(self, scalar: bytes) -> Optional[bytes]:
        """Compressed [scalar]B, or None when the call refused."""
        if len(scalar) != 32:
            raise ValueError("scalar must be exactly 32 bytes")
        out = ctypes.create_string_buffer(32)
        if self.lib.ama_ed25519_point_from_scalar(out, scalar) != 0:
            return None
        return out.raw[:32]

    def point_add_bytes(self, p_enc: bytes, q_enc: bytes) -> Optional[bytes]:
        """Compressed P + Q, or None when either operand refused to decode."""
        if len(p_enc) != 32 or len(q_enc) != 32:
            raise ValueError("compressed points must be exactly 32 bytes")
        out = ctypes.create_string_buffer(32)
        if self.lib.ama_ed25519_point_add(out, p_enc, q_enc) != 0:
            return None
        return out.raw[:32]

    def scalarmult_public_bytes(self, scalar: bytes, point_enc: bytes) -> Optional[bytes]:
        """Compressed [scalar]P, or None when the call refused."""
        if len(scalar) != 32 or len(point_enc) != 32:
            raise ValueError("scalar and compressed point must be exactly 32 bytes")
        out = ctypes.create_string_buffer(32)
        if self.lib.ama_ed25519_scalarmult_public(out, scalar, point_enc) != 0:
            return None
        return out.raw[:32]

    def double_scalarmult_public_bytes(
        self, s1: bytes, p1_enc: bytes, s2: bytes, p2_enc: bytes
    ) -> Optional[bytes]:
        """Compressed [s1]P1 + [s2]P2, or None when the call refused."""
        if len({len(s1), len(p1_enc), len(s2), len(p2_enc)}) != 1:
            raise ValueError("all four arguments must be exactly 32 bytes")
        out = ctypes.create_string_buffer(32)
        if self.lib.ama_ed25519_double_scalarmult_public(out, s1, p1_enc, s2, p2_enc) != 0:
            return None
        return out.raw[:32]

    def reduce32(self, scalar: bytes) -> bytes:
        """``scalar mod l``, via the library's own 64-byte reducer."""
        if len(scalar) != 32:
            raise ValueError("scalar must be exactly 32 bytes")
        wide = ctypes.create_string_buffer(scalar + bytes(32), 64)
        self.lib.ama_ed25519_sc_reduce(wide)
        return wide.raw[:32]

    def batch_verify(self, entries: list[tuple[bytes, bytes, bytes]]) -> list[bool]:
        """Per-entry verdicts from ``ama_ed25519_batch_verify``.

        Exposed because the single-signature corpus cannot reach the batch
        path at all, and the batch path is where the two backends most
        recently disagreed: donna runs a multi-scalar routine only while
        `num > 3`, verifying per entry below that, and that routine decodes R
        instead of re-encoding it.  A gate whose docstring says the backends
        "return the same verdict for every signature put to them" has to put
        signatures to every verifier the library ships.

        `count` is driven above 3 by the caller for the same reason: at 1 or
        3 donna's fallback re-encodes and the multi-scalar path is never
        entered, which is exactly why the existing C coverage (counts 1 and 3)
        could not see it.
        """
        count = len(entries)
        messages = [ctypes.create_string_buffer(m) for m, _, _ in entries]

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
        return [bool(results[i] == 1) for i in range(count)]

    def non_canonical_r_signature(self, message: bytes, secret: bytes) -> bytes:
        """A signature whose R is the identity's sign-bit-set encoding.

        R = `01 00..00 | 0x80` decodes to the identity and drops the set sign
        bit (x = 0 has one root), and S = h * a mod L makes [S]B - [h]A the
        identity.  So the group equation holds while the encoding is one RFC
        8032 5.1.3 requires a decoder to refuse — the discriminating input for
        the batch path, produced with the signer's own key and no forgery.
        """
        expanded = ctypes.create_string_buffer(64)
        self.lib.ama_ed25519_sha512(secret[:32], 32, expanded)
        scalar = bytearray(expanded.raw[:32])
        scalar[0] &= 248
        scalar[31] &= 63
        scalar[31] |= 64
        scalar_bytes = bytes(scalar)

        public = ctypes.create_string_buffer(32)
        if self.lib.ama_ed25519_point_from_scalar(public, scalar_bytes) != 0:
            raise RuntimeError(f"{self.name}: ama_ed25519_point_from_scalar failed")

        r_half = bytes([0x01]) + bytes(30) + bytes([0x80])
        digest = ctypes.create_string_buffer(64)
        self.lib.ama_ed25519_sha512(r_half + public.raw[:32] + message, 64 + len(message), digest)
        reduced = ctypes.create_string_buffer(digest.raw, 64)
        self.lib.ama_ed25519_sc_reduce(reduced)
        h = reduced.raw[:32]

        s_half = ctypes.create_string_buffer(32)
        self.lib.ama_ed25519_sc_muladd(s_half, bytes(32), h, scalar_bytes)
        return r_half + s_half.raw[:32]

    def small_order_r_signature(
        self, message: bytes, public: bytes, secret: bytes, torsion_enc: bytes, seed: int = 0
    ) -> bytes:
        """A signature whose R carries a canonically-encoded small-order point.

        This is the B1 discriminator.  R = [r]B + T and S = r + h*a, built with
        the signer's OWN key and canonical encodings throughout — no forgery.
        Then [S]B - [h]A = [r + h*a]B - [h]A = [r]B = R - T, so single verify
        re-encodes R - T, compares it to R (which is R - T + T) and REJECTS.
        donna's retired aggregate summed r_i * (S_i*B - h_i*A_i - R_i) = r_i *
        (-T), neutral iff ord(T) | r_i, so it reported the entry VALID with
        probability ~1/ord over its uniform randomizer.  T is a fixed
        small-order encoding (order-2 y = p-1, or order-4 y = 0); both decode.

        Scalar arithmetic is done here in Python mod l rather than through the
        library, so the discriminator does not depend on the very code paths it
        is meant to police; only the group operations ([r]B, +T) go through the
        backend, and the derived scalar is checked to reproduce the public key.
        """
        a = _clamp_scalar(secret[:32])
        if self.point_from_scalar_bytes(a) != public:
            raise RuntimeError(f"{self.name}: derived scalar does not reproduce the public key")
        a_int = int.from_bytes(a, "little") % L
        r_int = int.from_bytes(_deterministic_bytes(seed, 32), "little") % L
        r_base = self.point_from_scalar_bytes(r_int.to_bytes(32, "little"))
        if r_base is None:
            raise RuntimeError(f"{self.name}: [r]B refused")
        r_sig = self.point_add_bytes(r_base, torsion_enc)
        if r_sig is None:
            raise RuntimeError(f"{self.name}: [r]B + T refused (T={torsion_enc.hex()})")
        h_int = int.from_bytes(hashlib.sha512(r_sig + public + message).digest(), "little") % L
        s_int = (r_int + h_int * a_int) % L
        return r_sig + s_int.to_bytes(32, "little")

    def active_backend(self) -> Optional[str]:
        """Which Ed25519 backend the library selected ("donna" / "fe51"), or None
        if the library predates ``ama_ed25519_active_backend`` (audit M14)."""
        fn = getattr(self.lib, "ama_ed25519_active_backend", None)
        if fn is None:
            return None
        fn.restype = ctypes.c_char_p
        fn.argtypes = []
        raw = fn()
        return raw.decode() if raw is not None else None

    def verify(self, message: bytes, signature: bytes, public: bytes) -> bool:
        # ama_ed25519_verify takes `const uint8_t signature[64]` with no length
        # parameter, so handing it a short buffer reads past the end.  This is
        # a real memory-safety guard, not a sanity check, so it raises rather
        # than asserting — `assert` is removed under `python -O`, which is
        # exactly when you would least want the guard gone.
        if len(signature) != 64:
            raise ValueError(f"signature must be exactly 64 bytes, got {len(signature)}")
        if len(public) != 32:
            raise ValueError(f"public key must be exactly 32 bytes, got {len(public)}")
        rc: int = self.lib.ama_ed25519_verify(signature, message, len(message), public)
        return rc == 0


def _deterministic_bytes(seed: int, length: int) -> bytes:
    """Reproducible pseudo-random bytes.

    Deliberately not ``random``/``os.urandom``: a differential failure must be
    reproducible from the printed case index alone, without a saved seed file.
    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"ama-ed25519-parity:{seed}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:length])


def _clamp_scalar(seed32: bytes) -> bytes:
    """The RFC 8032 secret scalar a = clamp(SHA-512(seed)[:32])."""
    h = bytearray(hashlib.sha512(seed32).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)


def _flip_bit(data: bytes, bit: int) -> bytes:
    mutated = bytearray(data)
    mutated[(bit // 8) % len(mutated)] ^= 1 << (bit % 8)
    return bytes(mutated)


def _with_s(signature: bytes, s_value: int) -> bytes:
    """Rebuild a signature with ``s_value`` as its S half.

    ``s_value`` must already fit in 32 bytes.  An earlier version silently
    reduced mod 2**256, which would have turned a caller's arithmetic mistake
    into a quietly different test case instead of an error — the opposite of
    what a differential harness should do.
    """
    if not 0 <= s_value < 2**256:
        raise ValueError(f"S must fit in 32 bytes, got {s_value.bit_length()} bits")
    return signature[:32] + s_value.to_bytes(32, "little")


@dataclass(frozen=True)
class Case:
    """One (message, signature, public key) triple to put to both backends.

    ``must_verify`` is carried as a field rather than inferred from ``label``.
    The first version of this file decided whether a case was a genuine
    signature by testing ``label.startswith("honest")`` — so renaming a label
    would have silently switched that assertion off while the tool went on
    reporting success.  That is the same "gate that reports coverage it does
    not have" failure this repository has already been bitten by twice.
    """

    label: str
    message: bytes
    signature: bytes
    public_key: bytes
    must_verify: bool = False


def build_cases(signer: Backend) -> list[Case]:
    """Return the cases to put to both backends."""
    cases: list[Case] = []

    for index in range(KEYPAIRS):
        public, secret = signer.keypair()
        message = _deterministic_bytes(index, 1 + (index * 37) % 200)
        signature = signer.sign(message, secret)

        cases.append(Case(f"honest[{index}]", message, signature, public, must_verify=True))

        # The INVARIANT-26 defect itself.  S + L must be rejected; before the
        # fix it verified.  A backend that regressed here would disagree with
        # the other, which is exactly what this file exists to catch.
        s = int.from_bytes(signature[32:], "little")
        if s + L < 2**256:
            cases.append(
                Case(f"malleable S+L[{index}]", message, _with_s(signature, s + L), public)
            )

        # Boundary values around L.  These fail the group equation too, so they
        # are not regression pins on their own — they catch a range check with
        # the bound in the wrong place, or one applied inconsistently.
        for label, value in (("S=L", L), ("S=L+1", L + 1), ("S=L-1", L - 1), ("S=max", 2**256 - 1)):
            cases.append(Case(f"{label}[{index}]", message, _with_s(signature, value), public))

        # Structured corruption across every field the verifier reads.  The
        # message is never empty (see its length expression above), so every
        # mutation below always applies — `_flip_bit` reduces the byte index
        # modulo the buffer length, so on a short message two bit indices can
        # land on the same byte and produce the same case.  That costs a
        # duplicate, never a skipped mutation.
        for bit in (0, 1, 7, 8, 63, 127, 254, 255):
            cases.append(
                Case(
                    f"R bitflip {bit}[{index}]",
                    message,
                    _flip_bit(signature[:32], bit) + signature[32:],
                    public,
                )
            )
            cases.append(
                Case(
                    f"S bitflip {bit}[{index}]",
                    message,
                    signature[:32] + _flip_bit(signature[32:], bit),
                    public,
                )
            )
            cases.append(
                Case(f"pk bitflip {bit}[{index}]", message, signature, _flip_bit(public, bit))
            )
            cases.append(
                Case(f"msg bitflip {bit}[{index}]", _flip_bit(message, bit), signature, public)
            )

    return cases


#: Compressed-point decode cases for INVARIANT-38 (canonical ``y``), as
#: (label, encoding, must_decode).
#:
#: Why these and not more signature cases: the corpus above cannot test the
#: ``y`` rule at all.  Its ``pk bitflip`` mutations essentially never land in
#: [p, 2^255) — that band needs limbs 1..30 all 0xFF and (byte31 & 0x7F) ==
#: 0x7F — and even if one did, the mutated key is not the signer's, so verify
#: rejects it on the signature and both backends agree whether or not either
#: enforces canonicality.  Agreement reached that way proves nothing.
#:
#: ``y = 0`` breaks the symmetry.  It is a genuine curve point: the curve
#: equation gives x^2 = -1 there, and -1 is a square mod p because p = 1 mod 4,
#: so the encoding decodes to the order-4 point.  ``y = p`` reduces to 0 and
#: therefore denotes the SAME point — the only thing that can separate the two
#: is the canonical-y rule.  Pairing a must-decode case with a must-reject case
#: over one point is what makes a backend that dropped the rule (or applied it
#: only on one entry point) show up as a disagreement instead of a silent pass.
_P_ENC = bytes([0xED] + [0xFF] * 30 + [0x7F])  # y = p, non-canonical
_ZERO_ENC = bytes(32)  # y = 0, canonical, same point
_ONE_ENC = bytes([1] + [0] * 31)  # y = 1, the identity (x = 0)
_MAX_ENC = bytes([0xFF] * 31 + [0x7F])  # y = 2^255 - 1, non-canonical
_PM1_ENC = bytes([0xEC] + [0xFF] * 30 + [0x7F])  # y = p - 1 = -1, the order-2 point
_TWO_SCALAR = bytes([2] + [0] * 31)  # small scalar for the scalarmult probe

#: The two x = 0 points with the x-sign bit SET.  RFC 8032 §5.1.3 step 3: "if
#: x = 0, and x_0 = 1, decoding fails."  These are the ONLY two encodings in
#: the whole 2^255 space that the rule discriminates, because x = 0 holds for
#: exactly two y values — y = 1 (the identity) and y = -1 (the order-2 point).
#:
#: They were missing from this corpus for the whole life of the rule they
#: exist to police.  The gate's own docstring says a one-sided fix "on x86-64
#: nothing would have noticed", and that is what happened to the gate itself:
#: removing the rule from the fe51 backend only, rebuilding, and running this
#: tool over the two libraries printed "both backends agree on every case" and
#: exited 0.  The nearest thing the corpus did contain — y = p with the sign
#: bit set — is refused by the OLDER canonical-y rule before the sign is ever
#: consulted, so it discriminates nothing about this one.
_ONE_SIGN_ENC = bytes([0x01] + [0x00] * 30 + [0x80])  # y = 1,   x_0 = 1
_PM1_SIGN_ENC = bytes([0xEC] + [0xFF] * 30 + [0xFF])  # y = p-1, x_0 = 1

#: y = 0 with the sign bit set.  The control for the pair above: y = 0 gives
#: x^2 = -1, which is a non-zero square mod p, so x != 0 and §5.1.3 does NOT
#: apply — this encoding must still decode.  A backend that "implemented" the
#: rule by refusing every set sign bit passes the two rejects above and fails
#: here, which is what keeps the rejects from being satisfiable by
#: over-rejection.
_ZERO_SIGN_ENC = bytes(31) + bytes([0x80])

#: An ordinary on-curve point, 2G, in both sign parities.  Neither has x = 0,
#: so both must decode; this catches a backend that over-rejects generally.
#: Value from RFC 8032 §7.1's curve arithmetic, cross-checked against
#: tests/test_ed25519_canonical_y.py.
_TWO_G_ENC = bytes.fromhex("c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022")
_TWO_G_SIGN_ENC = _TWO_G_ENC[:31] + bytes([_TWO_G_ENC[31] ^ 0x80])

#: ``expected`` is True (must decode), False (must be refused), or None
#: (no absolute requirement — the two backends must merely agree).
DECODE_CASES: tuple[tuple[str, bytes, Optional[bool]], ...] = (
    ("y=0 (canonical, decodes)", _ZERO_ENC, True),
    ("y=0 with sign bit set (x != 0, still decodes)", _ZERO_SIGN_ENC, True),
    ("y=1 (canonical identity, decodes)", _ONE_ENC, True),
    ("y=1 with x-sign set (RFC 8032 5.1.3, x=0)", _ONE_SIGN_ENC, False),
    ("y=p-1 (the order-2 point, decodes)", _PM1_ENC, True),
    ("y=p-1 with x-sign set (RFC 8032 5.1.3, x=0)", _PM1_SIGN_ENC, False),
    ("y=p (non-canonical twin of y=0)", _P_ENC, False),
    ("y=p with sign bit set", bytes([0xED] + [0xFF] * 30 + [0xFF]), False),
    ("y=2^255-1 (non-canonical)", _MAX_ENC, False),
    ("2G (ordinary on-curve point, decodes)", _TWO_G_ENC, True),
    ("2G with the other sign parity (decodes)", _TWO_G_SIGN_ENC, True),
)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Assert both Ed25519 backends return identical verdicts."
    )
    parser.add_argument(
        "--donna", type=Path, required=True, help="library built with AMA_ED25519_ASSEMBLY=ON"
    )
    parser.add_argument(
        "--fe51", type=Path, required=True, help="library built with AMA_ED25519_ASSEMBLY=OFF"
    )
    args = parser.parse_args(argv)

    try:
        donna = Backend("donna", args.donna)
        fe51 = Backend("fe51", args.fe51)
    except OSError as exc:
        print(
            f"BACKEND DIFFERENTIAL INCONCLUSIVE — could not load a library: {exc}", file=sys.stderr
        )
        print("An unrunnable comparison is not treated as a passing one.", file=sys.stderr)
        return 2

    # M14: refuse to run unless the two objects actually report DIFFERENT
    # backends.  A differential handed one library twice -- or two builds that
    # both fell back to fe51 (see the CMake FATAL_ERROR that now forbids the
    # silent downgrade) -- compares a library with itself and passes vacuously,
    # with none of the guards above able to notice.
    donna_backend = donna.active_backend()
    fe51_backend = fe51.active_backend()
    if donna_backend is None or fe51_backend is None:
        print(
            "BACKEND DIFFERENTIAL INCONCLUSIVE — a library does not export "
            "ama_ed25519_active_backend (build predates audit M14); rebuild both "
            "libraries so the differential can confirm it compares two backends.",
            file=sys.stderr,
        )
        return 2
    if donna_backend == fe51_backend:
        print(
            f"BACKEND DIFFERENTIAL INCONCLUSIVE — both libraries report backend "
            f"{donna_backend!r}; this compares a build with itself and passes "
            f"vacuously (M14).\n"
            f"  --donna {args.donna}\n"
            f"  --fe51  {args.fe51}\n"
            "Pass --donna a library built with AMA_ED25519_ASSEMBLY=ON and --fe51 "
            "one built with AMA_ED25519_ASSEMBLY=OFF.",
            file=sys.stderr,
        )
        return 2

    disagreements: list[str] = []
    checked = 0

    # Sign with each backend in turn so the corpus covers both signers.  A
    # divergence in signing shows up here as a cross-verification failure.
    must_verify_seen = 0

    for signer in (donna, fe51):
        for case in build_cases(signer):
            checked += 1
            a = donna.verify(case.message, case.signature, case.public_key)
            b = fe51.verify(case.message, case.signature, case.public_key)
            if a != b:
                disagreements.append(
                    f"  signed-by={signer.name:<5} case={case.label}\n"
                    f"      donna={a}  fe51={b}\n"
                    f"      msg={case.message.hex()[:64]}\n"
                    f"      sig={case.signature.hex()}\n"
                    f"      pk ={case.public_key.hex()}"
                )
            # Genuine signatures must additionally be ACCEPTED by both, not
            # merely agreed upon — two backends that both reject a valid
            # signature agree, and are both broken.
            if case.must_verify:
                must_verify_seen += 1
                if not (a and b):
                    disagreements.append(
                        f"  signed-by={signer.name:<5} case={case.label}\n"
                        f"      a genuine signature was rejected: donna={a} fe51={b}\n"
                        f"      (agreement alone is not correctness)\n"
                        f"      sig={case.signature.hex()}\n"
                        f"      pk ={case.public_key.hex()}"
                    )

    # Batch-verify parity.  Family 5, and the one whose absence let a real
    # divergence ship.
    #
    # Families 1-3 drive ama_ed25519_verify only.  The library exposes a
    # SECOND verifier, ama_ed25519_batch_verify, whose backends are entirely
    # different code — fe51's is a loop over ama_ed25519_verify, donna's is
    # ed25519-donna-batchverify.h's multi-scalar routine — and nothing here
    # ever put a signature to it, while this file's own docstring says it
    # asserts the backends "return the same verdict for every signature put to
    # them".
    #
    # Count 4, not 1 or 3.  donna verifies per entry `while (num > 3)` is
    # false, and that fallback re-encodes R; the multi-scalar routine, which
    # decodes R instead, is only reached at 4 and above.  The existing C
    # coverage in tests/c/test_ed25519_canonical_s.c drives batch at counts 1
    # and 3, below the boundary, which is why it could not see this either.
    batch_asserted = 0
    for signer in (donna, fe51):
        public, secret = signer.keypair()
        message = b"backend parity: batch verify"
        honest = signer.sign(message, secret)
        forged = signer.non_canonical_r_signature(message, secret)

        # The discriminating entry sits first among four honest ones, so a
        # backend that leaks a verdict between entries is caught too.
        entries = [(message, forged, public)] + [(message, honest, public)] * 3
        donna_verdicts = donna.batch_verify(entries)
        fe51_verdicts = fe51.batch_verify(entries)
        checked += 1
        if donna_verdicts != fe51_verdicts:
            disagreements.append(
                f"  batch   signed-by={signer.name:<5} count=4\n"
                f"      donna={donna_verdicts}  fe51={fe51_verdicts}\n"
                f"      sig[0]={forged.hex()}\n"
                f"      pk    ={public.hex()}"
            )

        # Agreement is not correctness, exactly as for the single path: both
        # backends must REJECT the non-canonical R and ACCEPT the three
        # honest entries.
        for name, verdicts in (("donna", donna_verdicts), ("fe51", fe51_verdicts)):
            batch_asserted += 1
            if verdicts[0]:
                disagreements.append(
                    f"  batch   signed-by={signer.name:<5} backend={name}\n"
                    f"      a non-canonical R was reported VALID by batch verify\n"
                    f"      (RFC 8032 5.1.7 step 1 -> 5.1.3)\n"
                    f"      sig={forged.hex()}"
                )
            if not all(verdicts[1:]):
                disagreements.append(
                    f"  batch   signed-by={signer.name:<5} backend={name}\n"
                    f"      genuine signatures were rejected in a batch: {verdicts}\n"
                    f"      sig={honest.hex()}"
                )

        # And the property the divergence actually broke: batch and single
        # must return the same verdict for the same input.
        for label, signature in (("non-canonical R", forged), ("honest", honest)):
            single_d = donna.verify(message, signature, public)
            single_f = fe51.verify(message, signature, public)
            batch_d = donna.batch_verify([(message, signature, public)] * 4)[0]
            batch_f = fe51.batch_verify([(message, signature, public)] * 4)[0]
            checked += 1
            batch_asserted += 1
            if single_d != batch_d or single_f != batch_f:
                disagreements.append(
                    f"  batch   signed-by={signer.name:<5} case={label}\n"
                    f"      batch and single disagree within one build:\n"
                    f"      donna single={single_d} batch={batch_d}\n"
                    f"      fe51  single={single_f} batch={batch_f}\n"
                    f"      sig={signature.hex()}"
                )

    # Batch-verify parity, torsion corpus.  Family 5b — the one that would have
    # caught B1.  The family above samples ONCE at count=4 with a NON-canonical
    # R; B1's divergence is a CANONICALLY encoded small-order (torsion) residue,
    # which donna's retired aggregate accepted with probability ~1/ord over its
    # uniform randomizer while single verify and fe51 always reject it.  One
    # sample is a coin flip, not a measurement, so sweep donna's multi-scalar
    # boundary (it verifies per entry while num <= 3, aggregate at >= 4) and
    # repeat each batch enough that a probabilistic accept cannot hide behind a
    # lucky draw: P(all 32 reject | 50% accept) < 1e-9.
    torsion_counts = (1, 2, 3, 4, 5, 8, 16, 63, 64, 65, 80)
    torsion_repeats = 32
    torsion_asserted = 0
    for signer in (donna, fe51):
        public, secret = signer.keypair()
        message = b"backend parity: torsion R"
        honest = signer.sign(message, secret)
        for tlabel, tenc in (("order-2 y=p-1", _PM1_ENC), ("order-4 y=0", _ZERO_ENC)):
            forged = signer.small_order_r_signature(message, public, secret, tenc, seed=0xB1)
            # Precondition: single verify MUST reject this in both backends.  If
            # either accepts it the construction is wrong, and a family that
            # cannot build its discriminator is not testing — fail closed.
            sd = donna.verify(message, forged, public)
            sf = fe51.verify(message, forged, public)
            checked += 1
            torsion_asserted += 1
            if sd or sf:
                disagreements.append(
                    f"  torsion signed-by={signer.name:<5} case={tlabel}\n"
                    f"      construction error: a torsion signature single verify must\n"
                    f"      reject was accepted (donna={sd} fe51={sf})\n"
                    f"      sig={forged.hex()}"
                )
                continue
            case_failed = False
            for count in torsion_counts:
                for _ in range(torsion_repeats):
                    entries = [(message, forged, public)] + [(message, honest, public)] * (
                        count - 1
                    )
                    dv = donna.batch_verify(entries)
                    fv = fe51.batch_verify(entries)
                    checked += 1
                    torsion_asserted += 1
                    # Index 0 is the torsion entry; both backends must reject it
                    # every time, and must agree, matching single verify.
                    if dv[0] or fv[0] or dv != fv:
                        disagreements.append(
                            f"  torsion signed-by={signer.name:<5} case={tlabel} count={count}\n"
                            f"      a canonically-encoded torsion signature single verify\n"
                            f"      rejects was reported VALID by batch verify, or the two\n"
                            f"      backends disagreed:  donna={dv}  fe51={fv}\n"
                            f"      sig[0]={forged.hex()}  pk={public.hex()}"
                        )
                        case_failed = True
                        break
                if case_failed:
                    break

    if batch_asserted == 0:
        print(
            "FATAL: the batch-verify family asserted nothing. A family that "
            "runs no assertion is a family that is not testing.",
            file=sys.stderr,
        )
        return 2

    if torsion_asserted == 0:
        print(
            "FATAL: the torsion batch corpus asserted nothing — the B1 " "discriminator never ran.",
            file=sys.stderr,
        )
        return 2

    # Compressed-point decode parity (INVARIANT-38).  Runs on the two decode
    # entry points rather than on verify, for the reason recorded on
    # DECODE_CASES: verify cannot distinguish the y rule, so a signature-only
    # corpus agrees vacuously and this gate would report "the backends accept
    # the same set of encodings" without ever having tested that claim.
    decode_asserted = 0
    for label, encoding, expected in DECODE_CASES:
        ops: tuple[tuple[str, Callable[[Any, bytes], Any]], ...] = (
            ("point_add", lambda be, e: be.point_add(e, _ONE_ENC)),
            ("scalarmult_public", lambda be, e: be.scalarmult_public(_TWO_SCALAR, e)),
        )
        for op_name, op in ops:
            checked += 1
            a = op(donna, encoding)
            b = op(fe51, encoding)
            if a != b:
                disagreements.append(
                    f"  decode  op={op_name:<18} case={label}\n"
                    f"      donna={a}  fe51={b}\n"
                    f"      point={encoding.hex()}"
                )
            elif expected is not None and a is not expected:
                decode_asserted += 1
                disagreements.append(
                    f"  decode  op={op_name:<18} case={label}\n"
                    f"      both backends returned {a}, expected {expected}\n"
                    f"      (agreement alone is not correctness — INVARIANT-38)\n"
                    f"      point={encoding.hex()}"
                )
            elif expected is not None:
                decode_asserted += 1

    # Byte-exact arithmetic parity.  The decode stage above compares
    # verdicts; this one compares the 32 output bytes, which is the only
    # thing that can see a backend that succeeds with the wrong answer.
    #
    # Scalar corpus.  _TWO_SCALAR = 2 was the gate's only scalar and it is
    # smaller than every defect this stage exists to catch.  The entries
    # below are deterministic (a fixed SHAKE-free xorshift stream, so the
    # corpus is identical on every host and consumes no CSPRNG) and
    # deliberately include values >= l and >= 2^255: the in-tree backend's
    # wNAF recoding used to represent such a scalar as s - 2^256.
    xs = 0x243F6A8885A308D3

    def _next_word() -> int:
        nonlocal xs
        xs ^= (xs << 13) & 0xFFFFFFFFFFFFFFFF
        xs ^= xs >> 7
        xs ^= (xs << 17) & 0xFFFFFFFFFFFFFFFF
        return xs

    def _next_bytes(count: int) -> bytes:
        return bytes((_next_word() >> 24) & 0xFF for _ in range(count))

    arith_scalars: list[bytes] = [
        bytes([2] + [0] * 31),  # the old corpus, kept
        bytes([7] + [0] * 31),
        bytes([3] + [0] * 31),
        bytes([0] * 32),  # zero
        bytes([0xFF] * 32),  # 2^256 - 1, unreduced
        bytes([0x00] * 31 + [0x80]),  # 2^255, unreduced
        bytes.fromhex(
            "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
        ),  # l itself
    ]
    arith_scalars.extend(_next_bytes(32) for _ in range(24))

    arith_points: list[bytes] = [_ONE_ENC, _ZERO_ENC, _PM1_ENC, _TWO_G_ENC]
    for _ in range(8):
        seed = _next_bytes(32)
        generated = donna.point_from_scalar_bytes(seed)
        if generated is not None:
            arith_points.append(generated)
    arith_points.extend(_next_bytes(32) for _ in range(8))

    arith_asserted = 0
    arith_agreed = 0
    for scalar in arith_scalars:
        d_out = donna.point_from_scalar_bytes(scalar)
        f_out = fe51.point_from_scalar_bytes(scalar)
        checked += 1
        if d_out != f_out:
            disagreements.append(
                f"  arith   op=point_from_scalar\n"
                f"      donna={d_out.hex() if d_out else 'REFUSED'}\n"
                f"      fe51 ={f_out.hex() if f_out else 'REFUSED'}\n"
                f"      scalar={scalar.hex()}"
            )
        elif d_out is not None:
            arith_agreed += 1
        arith_asserted += 1

    for point in arith_points:
        for scalar in arith_scalars:
            checked += 1
            d_out = donna.scalarmult_public_bytes(scalar, point)
            f_out = fe51.scalarmult_public_bytes(scalar, point)
            if d_out != f_out:
                disagreements.append(
                    f"  arith   op=scalarmult_public\n"
                    f"      donna={d_out.hex() if d_out else 'REFUSED'}\n"
                    f"      fe51 ={f_out.hex() if f_out else 'REFUSED'}\n"
                    f"      scalar={scalar.hex()} point={point.hex()}"
                )
            elif d_out is not None:
                arith_agreed += 1
            arith_asserted += 1

            # The reduction contract stated in include/ama_cryptography.h:
            # the result depends on the scalar only through scalar mod l.
            # Asserted per backend, so a pair that agrees on a wrong answer
            # is still caught.
            reduced = donna.reduce32(scalar)
            if reduced != scalar:
                for backend in (donna, fe51):
                    checked += 1
                    arith_asserted += 1
                    raw = backend.scalarmult_public_bytes(scalar, point)
                    red = backend.scalarmult_public_bytes(reduced, point)
                    if raw != red:
                        disagreements.append(
                            f"  arith   op=scalarmult_public/reduction-contract\n"
                            f"      {backend.name}: [s]P != [s mod l]P\n"
                            f"      [s]P     ={raw.hex() if raw else 'REFUSED'}\n"
                            f"      [s mod l]P={red.hex() if red else 'REFUSED'}\n"
                            f"      scalar={scalar.hex()} point={point.hex()}"
                        )
                    elif raw is not None:
                        arith_agreed += 1

    for index, point in enumerate(arith_points):
        other = arith_points[(index + 1) % len(arith_points)]
        for s1, s2 in (
            (arith_scalars[1], arith_scalars[2]),
            (arith_scalars[4], arith_scalars[0]),
            (arith_scalars[5], arith_scalars[6]),
            (arith_scalars[7], arith_scalars[8]),
        ):
            checked += 1
            arith_asserted += 1
            d_out = donna.double_scalarmult_public_bytes(s1, point, s2, other)
            f_out = fe51.double_scalarmult_public_bytes(s1, point, s2, other)
            if d_out != f_out:
                disagreements.append(
                    f"  arith   op=double_scalarmult_public\n"
                    f"      donna={d_out.hex() if d_out else 'REFUSED'}\n"
                    f"      fe51 ={f_out.hex() if f_out else 'REFUSED'}\n"
                    f"      s1={s1.hex()} P1={point.hex()}\n"
                    f"      s2={s2.hex()} P2={other.hex()}"
                )
            elif d_out is not None:
                arith_agreed += 1

            # [s1]P1 + [s2]P2 must equal the split composition, per backend.
            # This is the identity donna's shim construction implements, and
            # it failed on the first pair while both backends still "agreed"
            # on the return code.
            for backend in (donna, fe51):
                checked += 1
                arith_asserted += 1
                joint = backend.double_scalarmult_public_bytes(s1, point, s2, other)
                r1 = backend.scalarmult_public_bytes(s1, point)
                r2 = backend.scalarmult_public_bytes(s2, other)
                split = (
                    backend.point_add_bytes(r1, r2) if r1 is not None and r2 is not None else None
                )
                if joint != split:
                    disagreements.append(
                        f"  arith   op=double_scalarmult_public/split-identity\n"
                        f"      {backend.name}: joint != point_add(split halves)\n"
                        f"      joint={joint.hex() if joint else 'REFUSED'}\n"
                        f"      split={split.hex() if split else 'REFUSED'}\n"
                        f"      s1={s1.hex()} P1={point.hex()}\n"
                        f"      s2={s2.hex()} P2={other.hex()}"
                    )
                elif joint is not None:
                    arith_agreed += 1

    print(f"Compared {checked} Ed25519 verification case(s) across both backends.")
    print(f"  donna: {args.donna}")
    print(f"  fe51 : {args.fe51}")

    # A concrete finding is reported before either vacuity guard, and the
    # order is load-bearing rather than cosmetic.  `decode_asserted` only
    # advances on a case where the backends AGREED, so a pair that disagreed
    # on every decode case leaves it at zero — and with the guards first, the
    # worst possible result (total divergence) was reported as "the decode
    # stage asserted nothing", which names a corpus problem for what is
    # actually a library problem.  Both exits are non-zero, so nothing was
    # ever let through; the defect was in what the failure told the reader,
    # and INVARIANT-2 is explicit that a gate whose message names a condition
    # the reader cannot reproduce is one they learn to route around.
    if disagreements:
        print(
            f"\nED25519 BACKEND DIFFERENTIAL FAILED — {len(disagreements)} disagreement(s):\n",
            file=sys.stderr,
        )
        for row in disagreements:
            print(row, file=sys.stderr)
            print(file=sys.stderr)
        print(
            "Two implementations of one public API have diverged.  A caller's\n"
            "signature is valid or invalid depending on which CPU they run on.",
            file=sys.stderr,
        )
        return 1

    # Same fail-closed reasoning as must_verify_seen: a decode stage in which
    # every absolute assertion was skipped is not evidence of anything.  The
    # canonical y=0 / non-canonical y=p pair is the discriminating half, so
    # require that both halves actually ran.
    if decode_asserted == 0:
        print(
            "BACKEND DIFFERENTIAL INCONCLUSIVE — the decode stage asserted nothing,\n"
            "so the canonical-y rule (INVARIANT-38) was never tested.",
            file=sys.stderr,
        )
        return 2

    # Same fail-closed reasoning applied to the arithmetic stage.  Every
    # comparison there tolerates None (a refusal), so a pair of backends that
    # refused every input would agree on every case; `arith_agreed` only
    # advances on a case where both produced actual output bytes.
    if arith_agreed == 0:
        print(
            "BACKEND DIFFERENTIAL INCONCLUSIVE — the arithmetic stage compared\n"
            f"{arith_asserted} case(s) but not one produced output bytes, so\n"
            "byte-exact parity was never asserted.",
            file=sys.stderr,
        )
        return 2

    # A corpus with no must-verify case would let a pair of backends that
    # reject everything pass as "in agreement".  Fail closed rather than
    # report a green run over an assertion that never executed.
    if must_verify_seen == 0:
        print(
            "BACKEND DIFFERENTIAL INCONCLUSIVE — the corpus contained no genuine\n"
            "signature, so 'both accept valid input' was never asserted.",
            file=sys.stderr,
        )
        return 2

    print("\nED25519 BACKEND DIFFERENTIAL PASSED — both backends agree on every case.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
