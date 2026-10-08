#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""PQC head-to-head: AMA vs the OpenSSL bundled by the `cryptography` wheel.

Only implementation pair on this host that both expose ML-KEM-1024 and
ML-DSA-65. Both sides are driven from Python, so both pay comparable call
overhead -- AMA through ctypes, OpenSSL through cryptography's Rust binding.
That is not free for either, and it is stated rather than netted out.

The peer label is read from the linked library at run time
(``openssl_version_text()``), never written as a literal: an earlier
revision hardcoded "OpenSSL 4.0.1" into every row, which was true of the
wheel installed on the 2026-07-29 measurement host and would silently
mislabel a run against any other wheel. The provenance block records the
``cryptography`` version beside it for the same reason.

ML-DSA signing is rejection-sampled: its cost depends on the message, so it
is measured over N distinct random messages, never one fixed message.
"""

import importlib
import json
import os
import statistics
import time
from collections.abc import Callable
from typing import Any, Dict, List

# ML-DSA and ML-KEM reached `cryptography` in 46.0; this file requires that
# floor.  Loaded through importlib rather than
# `from ... import mldsa, mlkem` so an older install fails HERE, naming the
# requirement, instead of raising a bare ImportError from a submodule that
# older versions simply do not have.
try:
    mldsa: Any = importlib.import_module("cryptography.hazmat.primitives.asymmetric.mldsa")
    mlkem: Any = importlib.import_module("cryptography.hazmat.primitives.asymmetric.mlkem")
except ImportError as exc:  # pragma: no cover - environment guard
    import cryptography as _cryptography

    raise SystemExit(
        "this benchmark needs `cryptography` >= 46.0 for ML-DSA / ML-KEM "
        f"(installed: {_cryptography.__version__}); it is the OpenSSL side of "
        f"the head-to-head and there is nothing to compare against without it "
        f"[{exc}]"
    ) from exc

import cryptography
from cryptography.hazmat.backends.openssl import backend as _openssl_backend

from ama_cryptography.pqc_backends import (
    generate_dilithium_keypair,
    dilithium_sign,
    dilithium_verify,
    generate_kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
)

#: The peer's row label, from the library actually linked -- e.g.
#: "OpenSSL 4.0.2" out of "OpenSSL 4.0.2 25 Aug 2026".  Two tokens, so a
#: build that reports a different vendor string is labelled as itself
#: rather than as OpenSSL-something-it-is-not.
OPENSSL_LABEL = " ".join(_openssl_backend.openssl_version_text().split()[:2])

ROUNDS = 200
MSGS = [os.urandom(64) for _ in range(ROUNDS)]
rows: List[Dict[str, Any]] = []


def bench(label: str, impl: str, fn: Callable[..., object], n: int = ROUNDS) -> None:
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


def main() -> None:
    # Provenance BEFORE measuring: it then describes the tree the numbers come
    # from.  It used to be computed inside the json.dump argument, after
    # open(out, "w") had already truncated the output -- which, run from
    # benchmarks/, is the tracked pqc_results.json, so the tree it inspected
    # was the one this run had just modified.
    provenance = _harness_provenance()
    # The peer's identity, recorded beside AMA's: the wheel version and the
    # full version string of the OpenSSL it bundles, which is the library
    # every peer row below actually exercised.
    provenance["peer"] = {
        "cryptography": cryptography.__version__,
        "openssl": _openssl_backend.openssl_version_text(),
    }

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
    bench("ML-DSA-65 keygen", OPENSSL_LABEL, lambda i=0: mldsa.MLDSA65PrivateKey.generate())
    bench("ML-DSA-65 sign", "AMA", lambda i=0: dilithium_sign(MSGS[i % ROUNDS], ask))
    bench("ML-DSA-65 sign", OPENSSL_LABEL, lambda i=0: okey.sign(MSGS[i % ROUNDS]))
    bench("ML-DSA-65 verify", "AMA", lambda i=0: dilithium_verify(MSGS[0], asig, apk))
    bench("ML-DSA-65 verify", OPENSSL_LABEL, lambda i=0: opub.verify(osig, MSGS[0]))

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
    bench("ML-KEM-1024 keygen", OPENSSL_LABEL, lambda i=0: mlkem.MLKEM1024PrivateKey.generate())
    bench("ML-KEM-1024 encaps", "AMA", lambda i=0: kyber_encapsulate(kpk))
    bench("ML-KEM-1024 encaps", OPENSSL_LABEL, lambda i=0: mpub.encapsulate())
    bench("ML-KEM-1024 decaps", "AMA", lambda i=0: kyber_decapsulate(kct, ksk))
    bench("ML-KEM-1024 decaps", OPENSSL_LABEL, lambda i=0: mkey.decapsulate(mct))

    out = "pqc_results.json"
    payload = json.dumps({"provenance": provenance, "rounds": ROUNDS, "results": rows}, indent=2)
    with open(out, "w", encoding="utf-8") as f:
        f.write(payload)
    print(f"\nwrote {out} ({len(rows)} rows)")


def _harness_provenance() -> Dict[str, Any]:
    """comparative_benchmark's provenance block, which this file shares.

    Same contract as comparative_benchmark.py: the competitive page refuses
    to render result files whose measuring build is unknown, and it
    cross-checks that BOTH files carry the same ama_commit.  Imported
    package-qualified -- the one spelling mypy --strict resolves under
    MYPYPATH=. -- with the repository root put on sys.path first, because the
    documented way of running this file is as a script, where sys.path[0] is
    benchmarks/ itself and the `benchmarks` package is not importable.  (A
    bare `from comparative_benchmark import ...` fallback would need a
    type-ignore, which INVARIANT-13 forbids here.)
    """
    import sys
    from pathlib import Path

    repo_root = str(Path(__file__).resolve().parent.parent)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from benchmarks.comparative_benchmark import _measurement_provenance

    provenance = _measurement_provenance()
    if not provenance["attributable"]:
        print("WARNING: these results will be recorded as UNATTRIBUTABLE:")
        for reason in provenance["unattributable_because"]:
            print(f"  - {reason}")
    return provenance


if __name__ == "__main__":
    main()
