#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Measure the cost of key import, and of the PQ consistency checks specifically.

Why
---
``load_pkcs8`` of an ``expandedKey``-only ML-DSA key performs a full matrix
expansion; ML-KEM performs an encapsulation and a decapsulation. Those checks
are correct — RFC 9881 §8.2 and draft-ietf-lamps-kyber-certificates §C.4.1 ship
the negative vectors they exist to reject — but they sit on a **parser path**,
and until this was measured nobody could say what they cost. An unmeasured cost
on an attacker-reachable path is a denial-of-service lever nobody has sized.

``ama_cryptography.key_formats.set_pq_import_consistency`` makes the checks a
documented policy defaulting to enabled. This is what turns "they impose an
unannounced cost" into a number a deployment can reason about, in the same form
as the NIST curve measurements in ``docs/NIST_PRIME_CURVES.md``.

What is measured
----------------
For each algorithm and each private-key form:

* **parse** — the DER work alone, with PQ consistency checking off. This is the
  floor: it is what a caller pays for a key they have already validated.
* **checked** — the same import with checking on, the default.
* **ratio** — how many times more expensive the default is. That number is the
  denial-of-service lever, and it is the one to read.

Also reported, for scale: the cost of *generating* a key of the same algorithm.
An import that costs about as much as a keygen is the honest way to describe
what the ML-DSA ``expandedKey`` path does.

Usage::

    python3 benchmarks/keyformat_import.py             # human-readable table
    python3 benchmarks/keyformat_import.py --json      # machine-readable
    python3 benchmarks/keyformat_import.py --repeats 50
"""

from __future__ import annotations

import argparse
import functools
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import ama_cryptography.key_formats as kf  # noqa: E402 -- follows the sys.path insert
import ama_cryptography.pqc_backends as pb  # noqa: E402 -- same


def _time(fn: Callable[[], Any], repeats: int) -> float:
    """Median milliseconds per call.

    Median rather than mean: one scheduler preemption in a hundred iterations
    moves a mean and leaves a median alone, and the question here is what an
    import costs, not what the worst run of the benchmark did.
    """
    samples = []
    for _ in range(repeats):
        started = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - started) * 1000.0)
    return statistics.median(samples)


def _keygen(name: str) -> Callable[[], Any]:
    alg = kf.ALGORITHMS[name]
    if name == "Ed25519":
        return pb.native_ed25519_keypair
    if name == "X25519":
        return pb.native_x25519_keypair
    if name == "secp256k1":
        import os

        return lambda: pb.native_secp256k1_pubkey_from_privkey(os.urandom(32))
    if alg.kind == "ec":
        return lambda: pb.native_nistp_keypair(alg.ec_curve)
    if alg.pq_family == "ml-dsa":
        return lambda: pb.native_ml_dsa_keypair(alg.pq_set)
    return lambda: pb.native_ml_kem_keypair(alg.pq_set)


def _sample_key(name: str) -> kf.PrivateKey:
    alg = kf.ALGORITHMS[name]
    if alg.kind == "pq":
        seed = bytes((0x5A + i) & 0xFF for i in range(alg.pq_seed_bytes))
        if alg.pq_family == "ml-dsa":
            public, secret = pb.native_ml_dsa_keypair_from_seed(alg.pq_set, seed)
        else:
            public, secret = pb.native_ml_kem_keypair_from_seed(alg.pq_set, seed[:32], seed[32:])
        return kf.PrivateKey(name, secret, public, seed)
    if name == "Ed25519":
        public, secret = pb.native_ed25519_keypair()
        return kf.PrivateKey(name, secret[:32], public)
    if name == "X25519":
        public, secret = pb.native_x25519_keypair()
        return kf.PrivateKey(name, secret, public)
    if name == "secp256k1":
        import os

        secret = os.urandom(32)
        public = pb.native_secp256k1_pubkey_decompress(
            pb.native_secp256k1_pubkey_from_privkey(secret)
        )
        return kf.PrivateKey(name, secret, public)
    public, secret = pb.native_nistp_keypair(kf.ALGORITHMS[name].ec_curve)
    return kf.PrivateKey(name, secret, public)


def measure(repeats: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name in sorted(kf.ALGORITHMS):
        alg = kf.ALGORITHMS[name]
        private = _sample_key(name)
        keygen_ms = _time(_keygen(name), max(3, repeats // 4))

        forms = ["expandedKey", "seed", "both"] if alg.kind == "pq" else ["auto"]
        for form in forms:
            encoded = private.to_pkcs8(pq_format=form)
            # functools.partial rather than `lambda e=encoded:` — both bind the
            # current loop value, but a lambda with a default parameter has no
            # inferable type as a `Callable[[], Any]` argument and is callable
            # with an argument, which is not what a timing thunk is.
            checked = _time(functools.partial(kf.load_pkcs8, encoded), repeats)
            parse = _time(
                functools.partial(kf.load_pkcs8, encoded, verify_pq_consistency=False), repeats
            )
            rows.append(
                {
                    "algorithm": name,
                    "kind": alg.kind,
                    "form": form,
                    "bytes": len(encoded),
                    "parse_ms": round(parse, 4),
                    "checked_ms": round(checked, 4),
                    "ratio": round(checked / parse, 1) if parse > 0 else None,
                    "keygen_ms": round(keygen_ms, 4),
                }
            )
    return rows


def _table(rows: list[dict[str, Any]]) -> str:
    out = [
        "| Algorithm | Form | Bytes | Parse only | Checked (default) | Ratio | Keygen |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        ratio = f"{row['ratio']}x" if row["ratio"] is not None else "—"
        out.append(
            f"| {row['algorithm']} | {row['form']} | {row['bytes']} | "
            f"{row['parse_ms']:.3f} ms | {row['checked_ms']:.3f} ms | {ratio} | "
            f"{row['keygen_ms']:.3f} ms |"
        )
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=25)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if pb._native_lib is None:
        print("native library not built — nothing to measure", file=sys.stderr)
        return 1

    rows = measure(args.repeats)
    if args.json:
        print(json.dumps({"repeats": args.repeats, "rows": rows}, indent=1))
    else:
        print(_table(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
