#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — deterministic seed corpus for ``fuzz/fuzz_lms.c``.

Why this exists
---------------
``fuzz_lms`` drives the RFC 8554 HSS/LMS verifier with attacker-supplied
public keys and signatures.  Random bytes almost never form a structurally
valid LMS signature, let alone one that verifies, so a corpus of random seeds
would leave the verifier's accepting path — and the harness's message-binding
property, which only fires on an accepted signature — unexecuted.  These seeds
are the two published RFC 8554 Appendix F test cases, taken from the corpus
the C and Python suites already verify
(``tests/kat/keyformats/rfc8554_hss_lms.json``), so the accepting path runs on
the first execution and the mutator starts one byte away from it.

The harness input layout (``fuzz/fuzz_lms.c``)::

    byte 0        mode: 0 -> ama_hss_verify, 1 -> ama_lms_verify
    bytes 1..2    message length, big-endian
    next K bytes  public key (60 for HSS, 56 for single-tree LMS)
    next M bytes  message
    the rest      signature

What the seeds are
------------------
For each test case:

* ``hss-case-N`` — the HSS public key, message and signature as published;
* ``lms-case-N`` — the bottom tree alone: the level-1 public key the HSS
  signature carries, the message, and the level-1 LMS signature that signs it,
  split out exactly as ``tests/c/test_lms.c`` splits it;

plus ``hss-case-1-truncated`` (the signature one byte short, which must be
refused rather than read past) and ``hss-bad-levels`` (L = 9, one above
``AMA_HSS_MAX_LEVELS``, which is the malformed-key verdict).

Determinism
-----------
Every byte comes from the vendored corpus, so re-running this script
reproduces the seeds byte-for-byte.  ``--check`` verifies the committed files
match; ``fuzzing.yml`` runs it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CORPUS_DIR = REPO / "fuzz" / "seed_corpus" / "fuzz_lms"
SOURCE = REPO / "tests" / "kat" / "keyformats" / "rfc8554_hss_lms.json"

#: RFC 8554 §4.1 Table 1: LM-OTS typecode -> (n, p).
_LMOTS = {1: (32, 265), 2: (32, 133), 3: (32, 67), 4: (32, 34)}
#: RFC 8554 §5.1 Table 2: LMS typecode -> (m, h).
_LMS = {5: (32, 5), 6: (32, 10), 7: (32, 15), 8: (32, 20), 9: (32, 25)}

_MODE_HSS = 0
_MODE_LMS = 1


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big")


def _lms_signature_length(sig: bytes) -> int:
    """RFC 8554 §5.4: q, the LM-OTS signature, the LMS type, and the path."""
    n, p = _LMOTS[_u32(sig, 4)]
    lm_ots = 4 + n + p * n
    m, h = _LMS[_u32(sig, 4 + lm_ots)]
    return 4 + lm_ots + 4 + h * m


def _seed(mode: int, key: bytes, message: bytes, signature: bytes) -> bytes:
    return bytes([mode]) + len(message).to_bytes(2, "big") + key + message + signature


def _cases() -> dict[int, dict[str, bytes]]:
    records = json.loads(SOURCE.read_text(encoding="utf-8"))["records"]
    cases: dict[int, dict[str, bytes]] = {}
    for record in records:
        blob = bytes.fromhex(record["hex"])
        if len(blob) != record["bytes"]:
            raise ValueError(f"{SOURCE.name}: record length disagrees with its hex")
        cases.setdefault(int(record["case"]), {})[record["kind"]] = blob
    return cases


def expected_seeds() -> dict[str, bytes]:
    seeds: dict[str, bytes] = {}
    for number, case in sorted(_cases().items()):
        message, public_key, signature = case["message"], case["public_key"], case["signature"]
        if _u32(signature, 0) != 1:
            raise ValueError(f"case {number}: expected a two-level HSS signature (Nspk = 1)")
        seeds[f"hss-case-{number}.bin"] = _seed(_MODE_HSS, public_key, message, signature)

        # Nspk || sig_0 || pub_1 || sig_1 — the bottom tree is (pub_1, sig_1).
        top_len = _lms_signature_length(signature[4:])
        pub_1_start = 4 + top_len
        pub_1_len = 24 + _LMS[_u32(signature, pub_1_start)][0]
        pub_1 = signature[pub_1_start : pub_1_start + pub_1_len]
        sig_1 = signature[pub_1_start + pub_1_len :]
        if _lms_signature_length(sig_1) != len(sig_1):
            raise ValueError(f"case {number}: the bottom signature is not consumed exactly")
        seeds[f"lms-case-{number}.bin"] = _seed(_MODE_LMS, pub_1, message, sig_1)

    case_1 = _cases()[1]
    seeds["hss-case-1-truncated.bin"] = _seed(
        _MODE_HSS, case_1["public_key"], case_1["message"], case_1["signature"][:-1]
    )
    seeds["hss-bad-levels.bin"] = _seed(
        _MODE_HSS,
        (9).to_bytes(4, "big") + case_1["public_key"][4:],
        case_1["message"],
        case_1["signature"],
    )
    return seeds


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed corpus matches what this script generates",
    )
    args = parser.parse_args(argv)
    expected = expected_seeds()

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
            print(f"note: {filename} is not generated by this script")
        if problems:
            print("LMS SEED CORPUS CHECK FAILED:", file=sys.stderr)
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
