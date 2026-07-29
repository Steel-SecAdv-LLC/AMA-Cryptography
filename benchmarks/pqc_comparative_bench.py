#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""PQC head-to-head: AMA vs OpenSSL 4.0.1 (via `cryptography` 49.0.0).

Only implementation pair on this host that both expose ML-KEM-1024 and
ML-DSA-65. Both sides are driven from Python, so both pay comparable call
overhead -- AMA through ctypes, OpenSSL through cryptography's Rust binding.
That is not free for either, and it is stated rather than netted out.

ML-DSA signing is rejection-sampled: its cost depends on the message, so it
is measured over N distinct random messages, never one fixed message.
"""

import json
import os
import statistics
import time

from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

from ama_cryptography.pqc_backends import (
    generate_dilithium_keypair,
    dilithium_sign,
    dilithium_verify,
    generate_kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
)

ROUNDS = 200
MSGS = [os.urandom(64) for _ in range(ROUNDS)]
rows = []


def bench(label, impl, fn, n=ROUNDS):
    fn()  # warm
    ts = []
    for i in range(n):
        t0 = time.perf_counter()
        fn(i)
        ts.append((time.perf_counter() - t0) * 1e6)
    med = statistics.median(ts)
    rows.append(
        {
            "primitive": label,
            "implementation": impl,
            "us_per_op": med,
            "ops_per_sec": 1e6 / med,
            "stdev_us": statistics.stdev(ts) if len(ts) > 1 else 0.0,
            "iterations": n,
        }
    )
    print(f"  {label:<26} {impl:<26} {med:10.1f} us  {1e6/med:10.1f} ops/s")


def main():
    # ── ML-DSA-65 ──
    akp = generate_dilithium_keypair()
    apk, ask = akp.public_key, akp.secret_key
    asig = dilithium_sign(MSGS[0], ask)
    # A raise, not an `assert`: `python -O` strips asserts, and this is the
    # check that the primitive actually works before its speed is published.
    # A benchmark of a broken code path is the fastest number in the table.
    if not dilithium_verify(MSGS[0], asig, apk):
        raise RuntimeError("AMA ML-DSA-65 self-verify failed; refusing to benchmark")

    okey = mldsa.MLDSA65PrivateKey.generate()
    opub = okey.public_key()
    osig = okey.sign(MSGS[0])
    opub.verify(osig, MSGS[0])

    bench("ML-DSA-65 keygen", "AMA", lambda i=0: generate_dilithium_keypair())
    bench("ML-DSA-65 keygen", "OpenSSL 4.0.1", lambda i=0: mldsa.MLDSA65PrivateKey.generate())
    bench("ML-DSA-65 sign", "AMA", lambda i=0: dilithium_sign(MSGS[i % ROUNDS], ask))
    bench("ML-DSA-65 sign", "OpenSSL 4.0.1", lambda i=0: okey.sign(MSGS[i % ROUNDS]))
    bench("ML-DSA-65 verify", "AMA", lambda i=0: dilithium_verify(MSGS[0], asig, apk))
    bench("ML-DSA-65 verify", "OpenSSL 4.0.1", lambda i=0: opub.verify(osig, MSGS[0]))

    # ── ML-KEM-1024 ──
    kkp = generate_kyber_keypair()
    kpk, ksk = kkp.public_key, kkp.secret_key
    kenc = kyber_encapsulate(kpk)
    kct, kss = kenc.ciphertext, kenc.shared_secret
    if kyber_decapsulate(kct, ksk) != kss:
        raise RuntimeError("AMA ML-KEM-1024 round-trip failed; refusing to benchmark")

    mkey = mlkem.MLKEM1024PrivateKey.generate()
    mpub = mkey.public_key()
    mss, mct = mpub.encapsulate()
    if mkey.decapsulate(mct) != mss:
        raise RuntimeError("OpenSSL ML-KEM-1024 round-trip failed; refusing to benchmark")

    bench("ML-KEM-1024 keygen", "AMA", lambda i=0: generate_kyber_keypair())
    bench("ML-KEM-1024 keygen", "OpenSSL 4.0.1", lambda i=0: mlkem.MLKEM1024PrivateKey.generate())
    bench("ML-KEM-1024 encaps", "AMA", lambda i=0: kyber_encapsulate(kpk))
    bench("ML-KEM-1024 encaps", "OpenSSL 4.0.1", lambda i=0: mpub.encapsulate())
    bench("ML-KEM-1024 decaps", "AMA", lambda i=0: kyber_decapsulate(kct, ksk))
    bench("ML-KEM-1024 decaps", "OpenSSL 4.0.1", lambda i=0: mkey.decapsulate(mct))

    out = "pqc_results.json"
    with open(out, "w") as f:
        json.dump({"rounds": ROUNDS, "results": rows}, f, indent=2)
    print(f"\nwrote {out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
