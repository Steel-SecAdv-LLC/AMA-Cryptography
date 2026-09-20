#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""AMA Cryptography — deterministic seed corpus for ``fuzz/fuzz_nistp.c``.

Why this exists
---------------
``fuzz_nistp`` asserts *properties*, not just memory safety, and every one of
them is conditional: the canonical-DER check only runs once
``sig_der_to_raw`` has accepted the input, the point round trip only once
``point_decode`` has accepted it, the two-entry-point agreement only once a
signature has actually verified. Random bytes reach none of those states. A
P-256 DER signature is ~71 octets with a fixed ``30 .. 02 .. 02 ..`` skeleton
and two integers that must lie in ``[1, n-1]``; the chance of a mutation
stumbling onto one is nil.

So an empty corpus would leave the harness testing exactly one thing --- that
the parsers do not crash on garbage --- and silently never testing the four
properties it was written for. The seeds below start the campaign *inside*
those states, and the fuzzer's budget goes on perturbing them.

The harness input layout (``fuzz/fuzz_nistp.c``)::

    data[0]  curve selector   (% 3 -> P-256 / P-384 / P-521)
    data[1]  case selector    (% 6 -> which target)
    data[2:] payload

What the seeds cover, and why these
-----------------------------------
For each of the three curves:

* **case 0, DER parse + canonicality.** A real DER signature. Plus the two
  shapes that make the encoder's minimal-integer logic non-trivial: an ``r``
  whose top bit is set (so DER must prefix ``0x00``), and an ``r`` with a
  leading zero octet (so the encoder must strip it). On P-521 a signature body
  exceeds 0x80 octets, which is the only case reaching the one-octet long-form
  SEQUENCE length --- the branch ``30 81 <len>`` that a short-form-only parser
  would reject.
* **case 1, raw -> DER -> raw.** The same signatures as raw ``r || s``.
* **case 2, point decode + round trip.** Both SEC 1 encodings of a real point,
  compressed (``02``/``03``) and uncompressed (``04``), so the decoder's
  square-root branch and the parity selection are both entered.
* **case 3, fully fuzzed verify.** A public key and a DER signature that
  genuinely verify --- the only state in which the DER-vs-raw agreement
  property is checked at all. The harness reads its digest from
  ``payload[:32]`` and the payload opens with the public key, so the seed
  signs ``pub[:32]``; a signature over anything else would land on the
  rejecting branch and never reach the property. The builder asserts the seed
  verifies before writing it.
* **case 4, validated key.** A real public key, so compression round-trips.
* **case 5, scalar.** A valid private scalar and a peer public key, so ECDH
  runs rather than rejecting at the range check.

Determinism
-----------
Signatures are made over a fixed digest with the library's own signer. ECDSA
is randomised, so the bytes differ per run; that is fine --- these are seeds,
not vectors, and nothing asserts their content. What must be deterministic is
the *set of states* covered, and that is fixed by construction above.

Usage::

    python tools/build_nistp_seed_corpus.py            # write the corpus
    python tools/build_nistp_seed_corpus.py --check    # verify it is non-empty
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = REPO_ROOT / "fuzz" / "seed_corpus" / "fuzz_nistp"

sys.path.insert(0, str(REPO_ROOT))

#: Curve name -> the ``data[0]`` value selecting it (the harness takes ``% 3``).
CURVES: tuple[tuple[str, int], ...] = (("P-256", 0), ("P-384", 1), ("P-521", 2))

#: The harness's ``data[1] % 6`` cases.
CASE_DER_PARSE = 0
CASE_RAW_TO_DER = 1
CASE_POINT_DECODE = 2
CASE_VERIFY = 3
CASE_VALIDATE = 4
CASE_SCALAR = 5


def _seed(curve_sel: int, case: int, payload: bytes) -> bytes:
    return bytes([curve_sel, case]) + payload


def _write(out_dir: Path, name: str, blob: bytes) -> None:
    (out_dir / name).write_bytes(blob)


def build(out_dir: Path) -> int:
    from ama_cryptography import pqc_backends as pb

    out_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(b"ama nistp fuzz seed").digest()
    written = 0

    for name, sel in CURVES:
        nb = pb.nistp_field_bytes(name)
        pub, priv = pb.native_nistp_keypair(name)

        # A DER signature that verifies, and its raw form.
        der = pb.native_nistp_ecdsa_sign(name, digest, priv)
        raw = pb.native_nistp_sig_der_to_raw(name, der)

        _write(out_dir, f"{name}_der_signature", _seed(sel, CASE_DER_PARSE, der))
        _write(out_dir, f"{name}_raw_signature", _seed(sel, CASE_RAW_TO_DER, raw))
        written += 2

        # Raw r || s shapes that drive the encoder's minimal-integer logic:
        # a high top bit forces the 0x00 prefix, a leading zero forces the
        # strip. Neither is reachable by chance from a random signature.
        r, s = raw[:nb], raw[nb:]
        high = bytes([0xFF]) + r[1:]
        lead = bytes([0x00]) + r[1:]
        _write(out_dir, f"{name}_raw_high_bit", _seed(sel, CASE_RAW_TO_DER, high + s))
        _write(out_dir, f"{name}_raw_leading_zero", _seed(sel, CASE_RAW_TO_DER, lead + s))
        written += 2

        # Both SEC 1 encodings of a real point.
        for label, compressed in (("compressed", True), ("uncompressed", False)):
            enc = pb.native_nistp_point_encode(name, pub, compressed=compressed)
            _write(out_dir, f"{name}_point_{label}", _seed(sel, CASE_POINT_DECODE, enc))
            written += 1

        # The verify state, and the only seed that reaches property 2 (the DER
        # and raw entry points must agree).  The harness reads its digest from
        # payload[:32], and the payload begins with the public key -- so the
        # signature has to be made over pub[:32], not over an unrelated
        # digest.  Signed that way, this seed lands the campaign on a verify
        # that SUCCEEDS, which is the branch the agreement check hangs off.
        over_pub = pb.native_nistp_ecdsa_sign(name, pub[:32], priv)
        # A raise, not an assert: `python -O` strips asserts, and a seed that
        # silently stopped verifying would leave the agreement property
        # untested while the corpus still looked populated.
        if not pb.native_nistp_ecdsa_verify(name, over_pub, pub[:32], pub):
            raise RuntimeError(
                f"{name}: the verify seed does not verify, so it would not "
                f"reach the DER-vs-raw agreement property the harness exists "
                f"to check"
            )
        _write(out_dir, f"{name}_verifying_triple", _seed(sel, CASE_VERIFY, pub + over_pub))
        written += 1

        # A validated public key, and a scalar + peer key for ECDH.
        _write(out_dir, f"{name}_public_key", _seed(sel, CASE_VALIDATE, pub))
        _write(out_dir, f"{name}_scalar_and_peer", _seed(sel, CASE_SCALAR, priv + pub))
        written += 2

    return written


def check(out_dir: Path) -> int:
    if not out_dir.is_dir():
        print(f"FAIL: {out_dir} does not exist", file=sys.stderr)
        return 1
    seeds = sorted(p for p in out_dir.iterdir() if p.is_file())
    if not seeds:
        print(f"FAIL: {out_dir} is empty", file=sys.stderr)
        return 1
    largest = max(p.stat().st_size for p in seeds)
    print(f"OK    {len(seeds)} seed(s), largest {largest} bytes")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=CORPUS_DIR)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed corpus is present and non-empty",
    )
    args = parser.parse_args(argv)

    if args.check:
        return check(args.out)

    written = build(args.out)
    print(f"OK    wrote {written} seed(s) to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
