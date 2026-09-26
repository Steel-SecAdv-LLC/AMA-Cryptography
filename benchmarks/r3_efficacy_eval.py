#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""3R timing-detector efficacy against a trivial baseline classifier.

``ResonanceTimingMonitor`` shipped without detection-efficacy evidence: no
measurement said whether it beats the most obvious alternative on the same
timing traces.  This script produces that comparison, and its table
(``benchmarks/r3_efficacy.tsv``) is what the README's 3R note states.

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
positions.  Each configuration is repeated ``--repeats`` times with fresh
injection positions; the table reports means.

For ``step`` every figure is PAIRED against the same detector run over the
unshifted trace.  Both runs see identical noise and differ only by the
shift, and both detectors are deterministic functions of the trace, so an
alarm the shifted run raises at an index where the clean run raises none is
caused by the shift, and an alarm both runs raise is not.  The table reports
whether any such attributable alarm fires after the shift, the delay to the
first one, the false-positive rate before the shift (identical in both runs,
since both detectors are causal), and the post-shift alarm rate minus the
clean run's rate over the same indices (``step_excess_alarm_rate``).

This metric used to count ANY alarm after the shift as a detection and
report the first as its delay.  With clean-trace false-positive rates of
1.8% and 3.2% that alarm is almost certain to exist with no shift at all,
so every row read ``detected=1`` and the delay was that of an ordinary false
alarm: the committed table showed the baseline at exactly 47 samples for
+5%, +10% and +30% and 3R at 19 for +10%, +30% and +100%, delays that did
not move across a six- to ten-fold change in shift size.  Measured on
5fdd02c: the baseline's first post-shift alarm at +5% also fired on the
clean trace at the same index, and a detector that ignores its input and
alarms on 2% of samples scored ``detected=1`` at both +5% and +100%.

Usage::

    python benchmarks/r3_efficacy_eval.py --samples 4000 --repeats 5 \\
        --out benchmarks/r3_efficacy.tsv
"""

from __future__ import annotations

import argparse
import random
import statistics
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
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


def step_metrics(alarms: list[bool], clean: list[bool], mid: int) -> tuple[bool, int, float, float]:
    """Score a step injection against the same detector's run on the clean trace.

    Returns ``(detected, delay, fpr_before, excess_rate)``.  ``detected`` and
    ``delay`` count only alarms the shift CAUSED: raised on the shifted trace
    at an index where the clean trace raised none (see the module docstring
    for why the pairing is sound).  ``excess_rate`` is the post-shift alarm
    rate minus the clean run's rate over the same indices.
    """
    if len(alarms) != len(clean):
        raise ValueError("the shifted and clean runs must cover the same indices")
    attributable = [i for i in range(mid, len(alarms)) if alarms[i] and not clean[i]]
    before = [i for i in range(WINDOW, mid) if alarms[i]]
    delay = (attributable[0] - mid) if attributable else -1
    post = len(alarms) - mid
    excess = (sum(alarms[mid:]) - sum(clean[mid:])) / post
    return bool(attributable), delay, len(before) / (mid - WINDOW), excess


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--samples", type=int, default=4000)
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--seed", type=int, default=394)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    rng = random.Random(args.seed)  # fmt: skip  # noqa: S311 -- anomaly-injection positions from a seeded PRNG so the experiment reproduces; nothing cryptographic is drawn (REE-001)

    trace = benign_trace(args.samples)
    med = statistics.median(trace)
    mad = statistics.median(abs(x - med) for x in trace)
    rows = [
        "family\tparameter\tdetector\ttpr_or_detected\tfpr\tstep_delay_samples\trepeats"
        "\tstep_excess_alarm_rate"
    ]
    print(f"benign trace: n={len(trace)} median={med:.4f} ms MAD={mad:.4f} ms", file=sys.stderr)

    # Clean-trace false-positive rate is the reference for every family, and
    # the clean run itself is the paired reference for every step row.
    clean_alarms: dict[str, list[bool]] = {}
    for name, fn in (("3R", r3_alarms), ("baseline", baseline_alarms)):
        alarms = fn(trace)
        clean_alarms[name] = alarms
        fpr = sum(alarms[WINDOW:]) / (len(alarms) - WINDOW)
        rows.append(f"clean\t-\t{name}\t-\t{fpr:.4f}\t-\t1\t-")

    for k in (1.5, 2.0, 3.0, 5.0, 10.0):
        for name, fn in (("3R", r3_alarms), ("baseline", baseline_alarms)):
            tprs, fprs = [], []
            for _ in range(args.repeats):
                t, idx = inject_point(trace, k, rng)
                tpr, fpr = rates(fn(t), idx)
                tprs.append(tpr)
                fprs.append(fpr)
            rows.append(
                f"point\tx{k}\t{name}\t{statistics.fmean(tprs):.3f}\t{statistics.fmean(fprs):.4f}\t-\t{args.repeats}\t-"
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
                f"burst\tx{k}\t{name}\t{statistics.fmean(tprs):.3f}\t{statistics.fmean(fprs):.4f}\t-\t{args.repeats}\t-"
            )
    for s in (0.05, 0.10, 0.30, 1.00):
        for name, fn in (("3R", r3_alarms), ("baseline", baseline_alarms)):
            t, mid = inject_step(trace, s)
            detected, delay, fpr, excess = step_metrics(fn(t), clean_alarms[name], mid)
            rows.append(
                f"step\t+{int(s*100)}%\t{name}\t{int(detected)}\t{fpr:.4f}\t{delay}\t1\t{excess:+.4f}"
            )

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
