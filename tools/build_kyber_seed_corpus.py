#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — deterministic seed corpus for ``fuzz/fuzz_kyber.c``.

Why this exists
---------------
The committed corpus could not reach the parts of the harness that matter,
and a byte-level count says so rather than an opinion:

* **43 seeds, largest 70 bytes.**  An ML-KEM-1024 ciphertext is 1,568 bytes,
  an encapsulation key 1,568, a decapsulation key 3,168.  Not one seed was
  within a factor of twenty of any of them, so every length-gated branch in
  the harness was reachable only by libFuzzer growing an input two orders of
  magnitude and landing on an exact length by chance.
* **32 of the 43 selected the seed-driven keygen**, the one case with no
  attacker-supplied input in it at all.  Two selected the ciphertext-
  corruption case.
* **One seed was a single byte**, which the harness rejects at ``size < 2``
  before executing any library code — a corpus entry with a permanent
  coverage of zero.

The harness itself had the larger gap, and it is fixed in ``fuzz_kyber.c``:
the two entry points an attacker actually supplies bytes to — the ciphertext
of ``ama_kyber_decapsulate`` and the encapsulation key of
``ama_kyber_encapsulate`` — were not fuzzed at all, though the file's own
header listed "fully fuzzed decapsulate (attacker-controlled)" as a target.
This corpus is what makes the new cases reachable from the first execution
instead of the millionth.

Harness input layout (``fuzz/fuzz_kyber.c``)::

    selector[1] || payload[...]

``selector % 6`` chooses the case; the payload is that case's input.

What the seeds cover, and why these
-----------------------------------
Every interesting boundary here is a length, because every one of the
harness's contracts is length-gated:

* **case 3, fuzzed ciphertext** — 1,568 exactly (the branch where the FIPS 203
  Sec 6.3 return-code contract is asserted: arbitrary bytes MUST decapsulate
  to ``AMA_SUCCESS``, because a distinguishing return code is the
  plaintext-checking oracle the FO transform exists to deny), one below, one
  above, and the shortest input the harness accepts at all.  Three contents at
  the exact length: all-zero (every compressed coefficient at the bottom of
  its range), all-0xFF (the top), and pseudorandom.
* **case 4, fuzzed encapsulation key** — 1,568 exactly, one below, one above.
  All-0xFF at the exact length puts the 12-bit coefficients out of range, so
  the Sec 7.2 modulus check must take its *reject* arm; all-zero is in range,
  so the same check takes its *accept* arm on a degenerate key.  Both arms of
  an input-validation check reached deterministically is the whole point.
* **case 5, fuzzed decapsulation key** — 3,168 exactly, one below, one above.
  The exact length drives ``polyvec_frombytes`` and the pk / H(pk) / z slices
  taken from inside the key over arbitrary bytes, which is what a malformed
  imported key file does.
* **case 1, one-byte ciphertext corruption** — the first byte, the last byte
  of the u section, the first byte of the v section, the last byte of the
  whole ciphertext, and the ``payload_len == 1`` path where the harness
  supplies the 0x01 mask itself.  The payload is two big-endian position
  bytes then the mask: the harness's original single position byte
  (``pos = payload[0] % ct_len``) could not reach past byte 255, so the
  boundary and tail seeds this list has always named were actually hitting
  bytes 128 and 31 — the names were fiction until the position field was
  widened.  ``payload_len == 0`` is not generated: the harness returns at
  ``size < 2``, so an empty payload is unreachable for every case.
* **case 2, keygen from seed** — 64 bytes exactly (the minimum the case
  accepts) and 63 (one below, which must break out cleanly).
* **case 0, round-trip** — one minimal seed; the case takes no input.

Determinism
-----------
Every byte is a fixed function of the seed's descriptive name, so re-running
this script reproduces the corpus byte-for-byte.  ``--check`` verifies the
committed files match what the script would write, so drift between the
generator and the corpus fails loudly instead of silently.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent.parent / "fuzz" / "seed_corpus" / "fuzz_kyber"

#: ML-KEM-1024, from include/ama_cryptography.h.  Stated here rather than
#: imported because this script must run without a built library.
PK_BYTES = 1568
SK_BYTES = 3168
CT_BYTES = 1568

#: The u section of an ML-KEM-1024 ciphertext is du*k*32 = 11*4*32 = 1408
#: bytes; v follows.  The boundary is where a corruption stops perturbing the
#: polyvec and starts perturbing v.
CT_U_BYTES = 1408

#: (name, case, fill, length) — `fill` is "zero", "ff", "prng" or a literal
#: bytes object for the short hand-laid payloads.
_CASES: list[tuple[str, int, object, int]] = [
    # case 0 — round-trip; the case reads no payload.
    ("roundtrip", 0, b"\x00", 1),
    # case 1 — one-byte ciphertext corruption at chosen positions.  The
    # payload is two BIG-ENDIAN position bytes then the XOR mask; the
    # harness widened the position field from one byte because pos =
    # payload[0] % ct_len capped corruption at byte 255 of a 1,568-byte
    # ciphertext — these seeds carried the boundary/tail NAMES while
    # actually hitting bytes 128 and 31, and every position in v was
    # unreachable through this case.
    ("corrupt-first-byte", 1, bytes([0, 0, 0x01]), 3),
    (
        "corrupt-u-v-boundary",
        1,
        bytes([(CT_U_BYTES - 1) >> 8, (CT_U_BYTES - 1) & 0xFF, 0x80]),
        3,
    ),
    (
        "corrupt-last-byte",
        1,
        bytes([(CT_BYTES - 1) >> 8, (CT_BYTES - 1) & 0xFF, 0xFF]),
        3,
    ),
    ("corrupt-first-v-byte", 1, bytes([CT_U_BYTES >> 8, CT_U_BYTES & 0xFF, 0x80]), 3),
    ("corrupt-default-mask", 1, bytes([7]), 1),
    # case 2 — deterministic keygen from a 64-byte seed pair.
    ("keygen-seed-exact", 2, "prng", 64),
    ("keygen-seed-one-short", 2, "prng", 63),
    # case 3 — FULLY fuzzed ciphertext.  The exact length is where the
    # implicit-rejection return-code contract is asserted.
    ("ct-exact-zero", 3, "zero", CT_BYTES),
    ("ct-exact-ff", 3, "ff", CT_BYTES),
    ("ct-exact-prng", 3, "prng", CT_BYTES),
    ("ct-one-short", 3, "prng", CT_BYTES - 1),
    ("ct-one-long", 3, "prng", CT_BYTES + 1),
    ("ct-one-byte", 3, "ff", 1),
    # case 4 — FULLY fuzzed encapsulation key.  ff drives the Sec 7.2 modulus
    # check to its reject arm, zero to its accept arm.
    ("pk-exact-zero", 4, "zero", PK_BYTES),
    ("pk-exact-ff", 4, "ff", PK_BYTES),
    ("pk-exact-prng", 4, "prng", PK_BYTES),
    ("pk-one-short", 4, "prng", PK_BYTES - 1),
    ("pk-one-long", 4, "prng", PK_BYTES + 1),
    # case 5 — FULLY fuzzed decapsulation key.
    ("sk-exact-zero", 5, "zero", SK_BYTES),
    ("sk-exact-ff", 5, "ff", SK_BYTES),
    ("sk-exact-prng", 5, "prng", SK_BYTES),
    ("sk-one-short", 5, "prng", SK_BYTES - 1),
    ("sk-one-long", 5, "prng", SK_BYTES + 1),
]


def _selector(case: int) -> int:
    """The smallest byte with ``value % 6 == case``.

    Smallest rather than arbitrary so the mapping is obvious to a reader
    looking at a hex dump, and so a corpus file's first byte identifies its
    case without consulting this script.
    """
    if not 0 <= case < 6:
        raise AssertionError(f"case {case} is outside the harness's selector range")
    return case


def _payload(name: str, fill: object, length: int) -> bytes:
    """The payload bytes: constant fills, or a name-derived stream."""
    if isinstance(fill, (bytes, bytearray)):
        return bytes(fill)
    if fill == "zero":
        return b"\x00" * length
    if fill == "ff":
        return b"\xff" * length
    if fill == "prng":
        # SHAKE-free, stdlib-only, and a pure function of the name: one
        # SHA3-256 per 32 bytes, counter-indexed.
        out = bytearray()
        block = 0
        while len(out) < length:
            out += hashlib.sha3_256(name.encode("ascii") + block.to_bytes(4, "big")).digest()
            block += 1
        return bytes(out[:length])
    raise AssertionError(f"unknown fill {fill!r}")


#: ``LLVMFuzzerTestOneInput`` returns immediately on ``size < 2``, so a
#: one-byte seed executes no library code at all and its coverage is
#: permanently zero.  The committed corpus contained exactly one such file
#: (``d160e098...``, 1 byte); it is deleted, and this bound is what stops the
#: generator from producing another.  It also means an EMPTY payload is not a
#: reachable input to any case, so there is no point generating one.
HARNESS_MIN_INPUT_BYTES = 2


def _seed_bytes(name: str, case: int, fill: object, length: int) -> bytes:
    payload = _payload(name, fill, length)
    if len(payload) != length:
        raise AssertionError(f"{name}: payload is {len(payload)} bytes, expected {length}")
    seed = bytes([_selector(case)]) + payload
    if len(seed) < HARNESS_MIN_INPUT_BYTES:
        raise AssertionError(
            f"{name}: {len(seed)}-byte seed is below the harness's "
            f"size < {HARNESS_MIN_INPUT_BYTES} early return; it would execute "
            f"no library code"
        )
    return seed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed corpus matches what this script generates",
    )
    args = parser.parse_args(argv)

    expected = {
        f"{name}.bin": _seed_bytes(name, case, fill, length) for name, case, fill, length in _CASES
    }

    if args.check:
        problems: list[str] = []
        actual = {p.name for p in CORPUS_DIR.glob("*")} if CORPUS_DIR.is_dir() else set()
        for filename, content in expected.items():
            path = CORPUS_DIR / filename
            if not path.is_file():
                problems.append(f"missing: {filename}")
            elif path.read_bytes() != content:
                problems.append(f"content drift: {filename}")
        for filename in sorted(actual - set(expected)):
            # Extra files are allowed — a minimised corpus from a fuzzing run
            # may legitimately be merged in — but they are reported so the
            # reader knows the generator does not account for them.
            print(f"note: {filename} is not generated by this script")
        if problems:
            print("KYBER SEED CORPUS CHECK FAILED:", file=sys.stderr)
            for problem in problems:
                print(f"  {problem}", file=sys.stderr)
            print(f"Regenerate with: python {Path(__file__).name}", file=sys.stderr)
            return 1
        print(f"OK: {len(expected)} generated seed(s) match the committed corpus.")
        return 0

    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    for filename, content in expected.items():
        (CORPUS_DIR / filename).write_bytes(content)
    print(f"wrote {len(expected)} seed(s) to {CORPUS_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
