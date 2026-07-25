#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
AMA Cryptography — Ed25519 Backend Differential (INVARIANT-26 support)
======================================================================

Asserts that this repository's two Ed25519 backends return the **same verdict**
for every signature put to them.

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
Three families, all generated at run time so the check needs no vendored data
and stays meaningful as the code changes:

1. **Honest signatures** — produced by each backend, cross-verified by the
   other.  This also pins that the two agree on *signing*, not just verifying.
2. **Malleable twins** — ``(R, S + L)`` for each honest signature.  This is the
   exact INVARIANT-26 defect, and the case that would have caught a one-sided
   fix.
3. **Structured corruption** — single-bit flips across ``R``, ``S``, the
   message and the public key, plus out-of-range ``S`` values at the ``L``
   boundary.

Exit status
-----------
``0`` when every case agrees, ``1`` on any disagreement (each is printed with
the inputs needed to reproduce it), ``2`` if a library could not be loaded —
an unrunnable comparison is never reported as a passing one.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

#: Order of the Ed25519 base point (RFC 8032 §5.1).
L = 2**252 + 27742317777372353535851937790883648493

#: Number of independent keypairs to exercise.  Each contributes one honest
#: signature plus every mutation below, so the case count is a multiple of it.
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
        # mutation below always applies.
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

    print(f"Compared {checked} Ed25519 verification case(s) across both backends.")
    print(f"  donna: {args.donna}")
    print(f"  fe51 : {args.fe51}")

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

    print("\nED25519 BACKEND DIFFERENTIAL PASSED — both backends agree on every case.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
