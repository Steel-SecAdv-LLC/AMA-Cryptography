#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""PR #394 readiness falsification, §10 row 7: 3R timing-detector efficacy.

The branch states that the 3R runtime anomaly monitor has no detection-
efficacy evidence.  The mandate's exception rule does not accept that as a
constraint: a comparison against a trivial baseline classifier on the same
timing traces is pure software.  This script produces that comparison.

Traces
------
The benign trace is REAL: ``N`` wall-clock timings of one native operation
(ML-DSA-65 sign over a fixed message) taken in this process, so the noise
the detector sees is the noise it would see in production.  Three
anomaly families are injected into copies of that trace:

* ``point``  — isolated slow operations (duration multiplied by ``k``) at
  1 % of positions chosen uniformly at random;
* ``step``   — every operation after the midpoint slowed by a factor
  ``1 + s`` (a persistent regime change, the shape of a newly introduced
  timing dependency);
* ``burst``  — one run of 20 consecutive slow operations (``k`` times).

Detectors
---------
* ``3R``:  ``ResonanceTimingMonitor.record_timing`` with its defaults; an
  alarm is a non-None return (the per-sample decision the monitor makes).
* ``baseline``: trailing-window z-score, |x - mean| / std > 3 over the
  previous 100 samples, the most trivial classifier there is.

Metrics
-------
For ``point`` and ``burst``: true-positive rate over injected positions
(alarm at the injected index) and false-positive rate over untouched
positions.  For ``step``: whether any alarm fires after the shift, and the
delay in samples to the first alarm; false positives before the shift.
Each configuration is repeated ``--repeats`` times with fresh injection
positions; the table reports means.

Usage::

    python docs/audit/sweeps/r3_efficacy.py --samples 4000 --repeats 5 \\
        --out docs/audit/PR394_3R_EFFICACY.tsv
"""

from __future__ import annotations

import argparse
import random
import statistics
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

# E402: the package must be imported AFTER sys.path is pointed at the
# repository root above, so this script runs from a checkout without an
# editable install — the same shape tests/conftest.py uses. INVARIANT-13.
from ama_cryptography import pqc_backends  # noqa: E402 -- see the note above (INVARIANT-13)
from ama_cryptography.monitoring import ResonanceTimingMonitor  # noqa: E402 -- ditto (INVARIANT-13)

WINDOW = 100


def benign_trace(n: int) -> list[float]:
    """Real timings (ms) of ML-DSA-65 sign, fixed message, this process."""
    keypair = pqc_backends.generate_dilithium_keypair()
    sk = keypair.secret_key
    msg = b"\x00" * 64
    out: list[float] = []
    for _ in range(n + WINDOW):
        t0 = time.perf_counter_ns()
        pqc_backends.dilithium_sign(msg, sk)
        out.append((time.perf_counter_ns() - t0) / 1e6)
    return out[WINDOW:]  # drop warm-up


def baseline_alarms(trace: list[float]) -> list[bool]:
    alarms = [False] * len(trace)
    for i in range(WINDOW, len(trace)):
        window = trace[i - WINDOW : i]
        mean = statistics.fmean(window)
        std = statistics.pstdev(window)
        if std > 0 and abs(trace[i] - mean) / std > 3.0:
            alarms[i] = True
    return alarms


def r3_alarms(trace: list[float]) -> list[bool]:
    monitor = ResonanceTimingMonitor()
    alarms: list[bool] = []
    for x in trace:
        alarms.append(monitor.record_timing("ml_dsa_65_sign", x) is not None)
    return alarms


def inject_point(trace: list[float], k: float, rng: random.Random) -> tuple[list[float], set[int]]:
    t = list(trace)
    idx = set(rng.sample(range(WINDOW, len(t)), max(1, len(t) // 100)))
    for i in idx:
        t[i] *= k
    return t, idx


def inject_burst(trace: list[float], k: float, rng: random.Random) -> tuple[list[float], set[int]]:
    t = list(trace)
    start = rng.randrange(WINDOW, len(t) - 20)
    idx = set(range(start, start + 20))
    for i in idx:
        t[i] *= k
    return t, idx


def inject_step(trace: list[float], s: float) -> tuple[list[float], int]:
    t = list(trace)
    mid = len(t) // 2
    for i in range(mid, len(t)):
        t[i] *= 1.0 + s
    return t, mid


def rates(alarms: list[bool], injected: set[int]) -> tuple[float, float]:
    tp = sum(1 for i in injected if alarms[i])
    untouched = [i for i in range(WINDOW, len(alarms)) if i not in injected]
    fp = sum(1 for i in untouched if alarms[i])
    return tp / len(injected), fp / len(untouched)


def step_metrics(alarms: list[bool], mid: int) -> tuple[bool, int, float]:
    after = [i for i in range(mid, len(alarms)) if alarms[i]]
    before = [i for i in range(WINDOW, mid) if alarms[i]]
    delay = (after[0] - mid) if after else -1
    return bool(after), delay, len(before) / (mid - WINDOW)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--samples", type=int, default=4000)
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--seed", type=int, default=394)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    trace = benign_trace(args.samples)
    med = statistics.median(trace)
    mad = statistics.median(abs(x - med) for x in trace)
    rows = ["family\tparameter\tdetector\ttpr_or_detected\tfpr\tstep_delay_samples\trepeats"]
    print(f"benign trace: n={len(trace)} median={med:.4f} ms MAD={mad:.4f} ms", file=sys.stderr)

    # Clean-trace false-positive rate is the reference for every family.
    for name, fn in (("3R", r3_alarms), ("baseline", baseline_alarms)):
        alarms = fn(trace)
        fpr = sum(alarms[WINDOW:]) / (len(alarms) - WINDOW)
        rows.append(f"clean\t-\t{name}\t-\t{fpr:.4f}\t-\t1")

    for k in (1.5, 2.0, 3.0, 5.0, 10.0):
        for name, fn in (("3R", r3_alarms), ("baseline", baseline_alarms)):
            tprs, fprs = [], []
            for _ in range(args.repeats):
                t, idx = inject_point(trace, k, rng)
                tpr, fpr = rates(fn(t), idx)
                tprs.append(tpr)
                fprs.append(fpr)
            rows.append(
                f"point\tx{k}\t{name}\t{statistics.fmean(tprs):.3f}\t{statistics.fmean(fprs):.4f}\t-\t{args.repeats}"
            )
    for k in (1.5, 2.0, 3.0):
        for name, fn in (("3R", r3_alarms), ("baseline", baseline_alarms)):
            tprs, fprs = [], []
            for _ in range(args.repeats):
                t, idx = inject_burst(trace, k, rng)
                tpr, fpr = rates(fn(t), idx)
                tprs.append(tpr)
                fprs.append(fpr)
            rows.append(
                f"burst\tx{k}\t{name}\t{statistics.fmean(tprs):.3f}\t{statistics.fmean(fprs):.4f}\t-\t{args.repeats}"
            )
    for s in (0.05, 0.10, 0.30, 1.00):
        for name, fn in (("3R", r3_alarms), ("baseline", baseline_alarms)):
            t, mid = inject_step(trace, s)
            detected, delay, fpr = step_metrics(fn(t), mid)
            rows.append(f"step\t+{int(s*100)}%\t{name}\t{int(detected)}\t{fpr:.4f}\t{delay}\t1")

    out = REPO / args.out
    out.write_text(
        "\n".join(rows)
        + f"\n# benign_n={len(trace)} median_ms={med:.4f} mad_ms={mad:.4f} seed={args.seed}\n",
        encoding="utf-8",
    )
    print("\n".join(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
