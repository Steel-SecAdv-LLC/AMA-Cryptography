#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — seeds for the fully-fuzzed verify cases of the PQC
signature harnesses (``fuzz_dilithium``, ``fuzz_sphincs``).

Why this exists
---------------
Both harnesses carry a case that hands ``ama_dilithium_verify`` /
``ama_sphincs_verify`` a signature and a public key made entirely of
attacker-supplied bytes.  Neither had ever executed:

* ``fuzz_dilithium`` case 1 needs ``payload_len >= 3,309 + 1,952 = 5,261``,
  so 5,262 bytes of input.  The largest seed in its corpus was 56 bytes.
* ``fuzz_sphincs`` case 1 needs ``49,856 + 64 = 49,920`` and case 2 needs
  ``49,856``.  The largest seed in its corpus was 36 bytes.

and the lane ran with ``-max_len=4096``, which libFuzzer applies to corpus
units as well as to mutations — a 60,001-byte seed enters the in-memory
corpus at 4,096 bytes, measured on this tree.  So the branches were
unreachable by construction, not merely improbable.
``tools/check_fuzz_input_reachability.py`` now derives each lane's ceiling
from the harness and fails if a branch sits above it; these seeds are what
make the branch execute on the first pass rather than after the mutator
happens to reach the exact length.

What the seeds cover, and why these
-----------------------------------
The verify path's work is parsing: a signature is unpacked into its hint,
challenge and response components, and a public key into ``rho`` and ``t1``
(ML-DSA), or a hypertree of Merkle authentication paths and WOTS+ chains
(SLH-DSA).  What separates inputs is therefore the byte VALUES at fixed
offsets, not the length — the length is fixed by the guard.  So each target
gets the exact length with three contents:

* all-zero — every packed field at the bottom of its range, and for ML-DSA
  the hint-count byte at 0, which is the "no hints" degenerate parse;
* all-0xFF — every field at the top, and for ML-DSA a hint count far above
  ``OMEGA``, which the unpacker must reject rather than walk;
* pseudorandom — a mid-range parse that lands neither extreme,

plus one seed a single byte SHORT of the guard, which must take the
``break`` and is the cheapest regression test that the guard still guards.

A trailing message is appended to the exact-length seeds so ``msg_len`` is
non-zero on the branch; the harness computes it as the remainder.

Determinism
-----------
Every byte is a fixed function of the seed's name, so re-running this script
reproduces the corpus byte-for-byte.  ``--check`` verifies the committed
files match, so drift between the generator and the corpus fails loudly.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_ROOT = REPO_ROOT / "fuzz" / "seed_corpus"

#: From include/ama_cryptography.h.  Stated here rather than imported because
#: this script must run without a built library; the reachability gate reads
#: the same guards out of the harnesses, so a drift between these numbers and
#: the header shows up there as an unreachable branch.
ML_DSA_65_SIGNATURE_BYTES = 3309
ML_DSA_65_PUBLIC_KEY_BYTES = 1952
SPHINCS_256F_SIGNATURE_BYTES = 49856
SPHINCS_256F_PUBLIC_KEY_BYTES = 64

#: A short message appended past the signature and key so the harness's
#: `msg_len` remainder is non-zero on the reached branch.
MESSAGE_BYTES = 16

#: target -> (selector byte for the fully-fuzzed verify case, payload bound)
_TARGETS: dict[str, tuple[int, int]] = {
    "fuzz_dilithium": (1, ML_DSA_65_SIGNATURE_BYTES + ML_DSA_65_PUBLIC_KEY_BYTES),
    "fuzz_sphincs": (1, SPHINCS_256F_SIGNATURE_BYTES + SPHINCS_256F_PUBLIC_KEY_BYTES),
}

_FILLS = ("zero", "ff", "prng")


def _payload(name: str, fill: str, length: int) -> bytes:
    if fill == "zero":
        return b"\x00" * length
    if fill == "ff":
        return b"\xff" * length
    if fill == "prng":
        out = bytearray()
        block = 0
        while len(out) < length:
            out += hashlib.sha3_256(name.encode("ascii") + block.to_bytes(4, "big")).digest()
            block += 1
        return bytes(out[:length])
    raise AssertionError(f"unknown fill {fill!r}")


def _seeds_for(target: str) -> dict[str, bytes]:
    selector, bound = _TARGETS[target]
    seeds: dict[str, bytes] = {}
    for fill in _FILLS:
        name = f"verify-exact-{fill}"
        seeds[f"{name}.bin"] = bytes([selector]) + _payload(name, fill, bound + MESSAGE_BYTES)
    name = "verify-one-short"
    seeds[f"{name}.bin"] = bytes([selector]) + _payload(name, "prng", bound - 1)
    return seeds


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed corpora match what this script generates",
    )
    args = parser.parse_args(argv)

    problems: list[str] = []
    written = 0
    for target in sorted(_TARGETS):
        corpus_dir = CORPUS_ROOT / target
        expected = _seeds_for(target)
        if args.check:
            actual = {p.name for p in corpus_dir.glob("*")} if corpus_dir.is_dir() else set()
            for filename, content in expected.items():
                path = corpus_dir / filename
                if not path.is_file():
                    problems.append(f"missing: {target}/{filename}")
                elif path.read_bytes() != content:
                    problems.append(f"content drift: {target}/{filename}")
            for filename in sorted(actual - set(expected)):
                # Extra files are allowed — the hand-written and
                # campaign-minimised seeds live alongside these — but they are
                # reported so the reader knows what this script accounts for.
                print(f"note: {target}/{filename} is not generated by this script")
        else:
            corpus_dir.mkdir(parents=True, exist_ok=True)
            for filename, content in expected.items():
                (corpus_dir / filename).write_bytes(content)
                written += 1

    if args.check:
        if problems:
            print("PQC VERIFY SEED CORPUS CHECK FAILED:", file=sys.stderr)
            for problem in problems:
                print(f"  {problem}", file=sys.stderr)
            print(f"Regenerate with: python {Path(__file__).name}", file=sys.stderr)
            return 1
        print(f"OK: generated seeds for {len(_TARGETS)} target(s) match the committed corpora.")
        return 0

    print(f"wrote {written} seed(s) across {len(_TARGETS)} target(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
