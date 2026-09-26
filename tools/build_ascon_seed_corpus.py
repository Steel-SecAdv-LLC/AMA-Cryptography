#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — deterministic seed corpus for ``fuzz/fuzz_ascon.c``.

Why this exists
---------------
``fuzz_ascon`` was the only registered libFuzzer target with **no seed corpus
at all**: ``fuzz/seed_corpus/fuzz_ascon/`` did not exist, and the fuzzing
workflow's ``if [ -d ... ]`` guard silently started the run from an empty
corpus (and, with no ``fuzz_ascon.dict`` either, with no dictionary).  Every
other target has 10-98 seeds.  An empty starting corpus is not wrong, but it
spends the CI campaign's fixed budget rediscovering structure the harness
documents on its face — 33 bytes of fixed header before a single body byte is
reached — instead of exercising the properties the harness exists to check.

The harness input layout (``fuzz/fuzz_ascon.c``)::

    key[16] || nonce[16] || split_selector[1] || body[0..4096]

``split_selector`` does double duty: ``% (body_len + 1)`` divides the body
into associated data and plaintext, and its low 7 bits select which tag bit
the forgery check flips.

What the seeds cover, and why these
-----------------------------------
The Ascon permutation absorbs at a 16-byte rate for AEAD (SP 800-232 §4) and
an 8-byte rate for Ascon-Hash256, and the harness asserts *properties* —
round-trip, forgery rejection, AD binding including the empty-AD guard,
fail-closed decryption — whose interesting cases sit exactly at those
boundaries:

* the empty input (``body_len == 0``: empty AD *and* empty plaintext);
* body lengths one below / at / one above each rate multiple (7, 8, 9, 15,
  16, 17, 31, 32, 33) — the partial-block padding paths on both absorb axes;
* the three split regimes for each interesting length: all-AD (the empty
  plaintext arm and its ``malloc(1)`` path), all-plaintext (the empty-AD
  guard the harness calls out), and mid-split (both absorb phases active);
* forged-bit selectors touching the first bit, a middle bit, and bit 127 of
  the tag — the two bytes the constant-time compare reads first and last;
* one body large enough to span many rate blocks (129 bytes) so the
  multi-block accumulation path is present from the first execution.

Determinism
-----------
Every byte is a fixed function of the seed's descriptive name.  Re-running
this script reproduces the corpus byte-for-byte; ``--check`` verifies the
committed files match what the script would write, so drift between the
generator and the corpus fails loudly instead of silently.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent.parent / "fuzz" / "seed_corpus" / "fuzz_ascon"

#: (name, body_len, split_mode, forged_bit) — split_mode in {"all_ad",
#: "all_pt", "mid"}.  The selector byte must satisfy BOTH roles it plays, so
#: it is solved for below rather than stored.
_CASES: list[tuple[str, int, str, int]] = [
    ("empty-body", 0, "all_pt", 0),
    ("hash-rate-minus-1-all-pt", 7, "all_pt", 0),
    ("hash-rate-all-pt", 8, "all_pt", 64),
    ("hash-rate-plus-1-all-pt", 9, "all_pt", 127),
    ("aead-rate-minus-1-all-pt", 15, "all_pt", 1),
    ("aead-rate-all-pt", 16, "all_pt", 64),
    ("aead-rate-plus-1-all-pt", 17, "all_pt", 127),
    ("aead-rate-minus-1-all-ad", 15, "all_ad", 0),
    ("aead-rate-all-ad", 16, "all_ad", 64),
    ("aead-rate-plus-1-all-ad", 17, "all_ad", 127),
    ("aead-rate-mid-split", 16, "mid", 32),
    ("two-blocks-minus-1-mid-split", 31, "mid", 0),
    ("two-blocks-mid-split", 32, "mid", 64),
    ("two-blocks-plus-1-mid-split", 33, "mid", 127),
    ("two-blocks-all-ad", 32, "all_ad", 96),
    ("two-blocks-all-pt", 32, "all_pt", 96),
    ("many-blocks-mid-split", 129, "mid", 7),
    ("one-byte-body-all-pt", 1, "all_pt", 0),
    ("one-byte-body-all-ad", 1, "all_ad", 127),
]


def _selector(body_len: int, split_mode: str, forged_bit: int) -> int:
    """A byte whose ``% (body_len+1)`` lands in the split regime, with its
    low 7 bits as close as possible to ``forged_bit``.

    The two roles share one byte in the harness, and they are not independent:
    for ``body_len == 8`` there is no value that is both ``% 9 == 0`` and has
    low-7 bits 64.  The split regime is the property each case is FOR, so it
    is the hard constraint; the forged-bit preference just spreads the tag
    positions the corpus starts from, so the nearest feasible value serves.
    Iterating the 256 possibilities is exhaustive, so a case with no
    split-satisfying value at all is a programming error here, not a runtime
    surprise.
    """
    feasible: list[int] = []
    for value in range(256):
        split = value % (body_len + 1) if body_len else 0
        if split_mode == "all_ad" and split != body_len:
            continue
        if split_mode == "all_pt" and split != 0:
            continue
        if split_mode == "mid" and not (0 < split < body_len):
            continue
        feasible.append(value)
    if not feasible:
        raise AssertionError(f"no selector byte satisfies body_len={body_len} split={split_mode}")
    return min(feasible, key=lambda value: (abs((value & 0x7F) - forged_bit), value))


def _seed_bytes(name: str, body_len: int, split_mode: str, forged_bit: int) -> bytes:
    """The seed: fixed layout, every byte a function of the name."""
    material = hashlib.sha3_512(name.encode("ascii")).digest()
    key = material[:16]
    nonce = material[16:32]
    body = bytes(
        hashlib.sha3_256(name.encode("ascii") + i.to_bytes(4, "big")).digest()[0]
        for i in range(body_len)
    )
    return key + nonce + bytes([_selector(body_len, split_mode, forged_bit)]) + body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed corpus matches what this script generates",
    )
    args = parser.parse_args(argv)

    expected = {
        f"{name}.bin": _seed_bytes(name, body_len, split_mode, forged_bit)
        for name, body_len, split_mode, forged_bit in _CASES
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
            print("ASCON SEED CORPUS CHECK FAILED:", file=sys.stderr)
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
