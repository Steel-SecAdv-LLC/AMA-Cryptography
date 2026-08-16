#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Does the 3R timing-anomaly detector beat a trivial baseline?

WHY THIS EXISTS
---------------
``monitoring.py`` ships a timing-anomaly detector: a running Z-score OR'd with
a MAD modified-Z, per operation, with per-operation sigma thresholds.  Until
this script there was **no measurement of whether it detects anything**.  The
suite tests that the MAD arithmetic is correct; correctness of the statistic
is not efficacy of the detector.

5.0.0 removed the claims that had stood in for evidence (``ETHICAL_PILLARS``
asserted ">95% coverage" and "confidence >= 99.9%", which nothing measured).
Deleting an unsupported claim is not the same as earning a supported one, so
this measures the thing against baselines that cost nothing to implement:

  * ``knn``      — k-th nearest-neighbour distance in the trailing window, the
                   standard unsupervised outlier baseline.
  * ``quantile`` — flag anything above the q-th percentile of the trailing
                   window.  The most trivial detector that is not a constant.

THE FAIRNESS RULE
-----------------
The shipped detector is a binary rule with fixed thresholds; the baselines
produce scores.  Comparing a fixed rule against a tunable one at *its* best
operating point would flatter the baselines; comparing at an arbitrary point
would flatter the incumbent.  So every baseline is calibrated on the SAME
stream to raise the SAME number of alarms the shipped detector raised, and
precision/recall/F1 are reported at that matched alarm budget.  Equal alarm
budget is the only comparison an operator cares about: alarms cost review
time, so the question is which detector spends a fixed budget better.

All three run **online** over the same trailing window with the same warmup,
and see the samples in the same order.  No detector sees the future.

WHAT COUNTS AS AN ANOMALY
-------------------------
Ground truth is injected, because real labelled side-channel traces are not
available here — and that limitation is stated in the output rather than
hidden.  Two injection models, both things the monitor's docstrings claim to
be for:

  * ``spike``  — an isolated operation takes k x longer (contention, a
                 degraded path, an attacker probing).
  * ``shift``  — a sustained regime change in the mean (a fallback path being
                 taken from some point onward).

The normal distribution is NOT synthetic: it is real wall-clock timings of a
real primitive through the shipped API, so the heavy right tail and OS jitter
that make this problem hard are present.

Stdlib only, by INVARIANT-1 habit — KNN on 1-D windows is a sort.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ---------------------------------------------------------------------------
# Ground-truth stream construction
# ---------------------------------------------------------------------------
@dataclass
class Stream:
    """A timing stream plus the index set of injected anomalies."""

    values: list[float]
    anomalies: set[int]
    label: str
    source: str


def collect_real_timings(count: int) -> tuple[list[float], str]:
    """Wall-clock timings of a real primitive, or None if unavailable.

    Uses the shipped API so the baseline distribution carries the real tail
    behaviour.  Falls back to a lognormal synthetic only if the native backend
    is unavailable, and says so in the report rather than silently degrading.
    """
    try:
        from ama_cryptography.pqc_backends import (  # noqa: PLC0415
            native_ed25519_keypair,
            native_ed25519_sign,
        )

        _pk, sk = native_ed25519_keypair()
        msg = b"detector baseline evaluation"
        # Warm the code path so page faults and lazy dispatch are not counted
        # as anomalies of the crypto rather than of the measurement.
        for _ in range(200):
            native_ed25519_sign(msg, sk)

        out: list[float] = []
        for _ in range(count):
            t0 = time.perf_counter_ns()
            native_ed25519_sign(msg, sk)
            out.append((time.perf_counter_ns() - t0) / 1e6)  # ms
        return out, "real: ed25519_sign wall-clock via shipped API"
    except Exception as exc:  # pragma: no cover - environment dependent
        # S311 is correct in general and wrong here: this is the fallback
        # SHAPE of a timing distribution for a measurement harness, never key
        # material.  A seeded Mersenne Twister is what makes the fallback
        # reproducible, which is the property this needs.
        rng = random.Random(20260816)  # noqa: S311
        out = [rng.lognormvariate(-3.9, 0.22) for _ in range(count)]
        return out, f"synthetic lognormal (native backend unavailable: {exc})"


def inject_spikes(base: Sequence[float], *, rate: float, magnitude: float, seed: int) -> Stream:
    # noqa rationale as above: choosing WHICH samples to corrupt in a
    # benchmark stream is not a cryptographic draw, and seeding it is what
    # makes the evaluation reproducible run to run.
    rng = random.Random(seed)  # noqa: S311
    values = list(base)
    anomalies: set[int] = set()
    for i in range(len(values)):
        if rng.random() < rate:
            values[i] = values[i] * magnitude
            anomalies.add(i)
    return Stream(values, anomalies, f"spike x{magnitude:g} @ {rate:.1%}", "")


def inject_shift(base: Sequence[float], *, start_frac: float, magnitude: float) -> Stream:
    values = list(base)
    start = int(len(values) * start_frac)
    anomalies: set[int] = set()
    for i in range(start, len(values)):
        values[i] = values[i] * magnitude
        anomalies.add(i)
    return Stream(values, anomalies, f"shift x{magnitude:g} from {start_frac:.0%}", "")


# ---------------------------------------------------------------------------
# Detectors — all online, same window, same warmup
# ---------------------------------------------------------------------------
WINDOW = 100
WARMUP = 30

#: F1 gap below which two detectors are not distinguishable on these streams.
_TIE_F1 = 0.02


def shipped_detector(values: Sequence[float], sigma: float) -> list[bool]:
    """The production rule: running Z-score OR MAD modified-Z.

    Calls the real ``EWMAStats.is_anomaly_mad`` rather than a reimplementation,
    and mirrors ``AmaCryptographyMonitor.record_timing``'s combination of it
    with the running Z-score at the operation's sigma threshold.
    """
    from ama_cryptography.monitoring import EWMAStats  # noqa: PLC0415

    ewma = EWMAStats(window_size=WINDOW)
    window: list[float] = []
    flags: list[bool] = []
    for x in values:
        flag = False
        if len(window) >= WARMUP:
            mean = statistics.fmean(window)
            std = statistics.pstdev(window)
            if std > 0 and abs(x - mean) / std >= sigma - 0.01:
                flag = True
            if ewma.is_anomaly_mad(x):
                flag = True
        flags.append(flag)
        ewma.update(x)
        window.append(x)
        if len(window) > WINDOW:
            window.pop(0)
    return flags


def knn_scores(values: Sequence[float], k: int = 5) -> list[float]:
    """k-th nearest-neighbour distance within the trailing window."""
    window: list[float] = []
    scores: list[float] = []
    for x in values:
        if len(window) >= WARMUP:
            dists = sorted(abs(x - w) for w in window)
            scores.append(dists[min(k, len(dists) - 1)])
        else:
            scores.append(0.0)
        window.append(x)
        if len(window) > WINDOW:
            window.pop(0)
    return scores


def quantile_scores(values: Sequence[float]) -> list[float]:
    """How far above the trailing median, in trailing-IQR units.

    The most trivial non-constant detector: no model, no distributional
    assumption, one sort.
    """
    window: list[float] = []
    scores: list[float] = []
    for x in values:
        if len(window) >= WARMUP:
            s = sorted(window)
            med = s[len(s) // 2]
            q1 = s[len(s) // 4]
            q3 = s[(3 * len(s)) // 4]
            iqr = max(q3 - q1, 1e-12)
            scores.append((x - med) / iqr)
        else:
            scores.append(0.0)
        window.append(x)
        if len(window) > WINDOW:
            window.pop(0)
    return scores


def flags_at_budget(scores: Sequence[float], budget: int) -> list[bool]:
    """Flag the ``budget`` highest-scoring samples (warmup excluded)."""
    scored = [(s, i) for i, s in enumerate(scores) if i >= WARMUP]
    scored.sort(reverse=True)
    chosen = {i for _, i in scored[:budget]}
    return [i in chosen for i in range(len(scores))]


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
@dataclass
class Result:
    name: str
    alarms: int
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float


def score(flags: Sequence[bool], truth: set[int]) -> Result:
    tp = sum(1 for i, f in enumerate(flags) if f and i in truth and i >= WARMUP)
    fp = sum(1 for i, f in enumerate(flags) if f and i not in truth and i >= WARMUP)
    fn = sum(1 for i in truth if i >= WARMUP and not flags[i])
    alarms = tp + fp
    precision = tp / alarms if alarms else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return Result("", alarms, tp, fp, fn, precision, recall, f1)


def evaluate(stream: Stream, sigma: float) -> list[Result]:
    shipped = shipped_detector(stream.values, sigma)
    budget = sum(1 for i, f in enumerate(shipped) if f and i >= WARMUP)

    results: list[Result] = []
    r = score(shipped, stream.anomalies)
    r.name = f"3R shipped (z>={sigma:g} OR MAD>3.5)"
    results.append(r)

    # Baselines calibrated to the SAME alarm budget.
    if budget > 0:
        for name, scores in (
            ("KNN (k=5, matched budget)", knn_scores(stream.values)),
            ("Quantile/IQR (matched budget)", quantile_scores(stream.values)),
        ):
            rb = score(flags_at_budget(scores, budget), stream.anomalies)
            rb.name = name
            results.append(rb)
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--samples", type=int, default=4000)
    ap.add_argument("--sigma", type=float, default=2.0, help="ed25519_sign profile default")
    ap.add_argument("--json", type=str, default=None)
    args = ap.parse_args()

    base, source = collect_real_timings(args.samples)

    streams = [
        inject_spikes(base, rate=0.01, magnitude=3.0, seed=1),
        inject_spikes(base, rate=0.01, magnitude=1.5, seed=2),
        inject_spikes(base, rate=0.05, magnitude=2.0, seed=3),
        inject_shift(base, start_frac=0.6, magnitude=1.3),
    ]

    print("=" * 78)
    print("3R timing-anomaly detector vs trivial baselines")
    print("=" * 78)
    print(f"Baseline distribution : {source}")
    print(f"Samples per stream    : {len(base)}   window={WINDOW} warmup={WARMUP}")
    print("Comparison rule       : baselines calibrated to the shipped detector's")
    print("                        own alarm count on the same stream.")
    print()

    payload: dict[str, object] = {"source": source, "samples": len(base), "streams": []}
    total_evaluated = max(0, len(base) - WARMUP)

    for st in streams:
        print(f"--- {st.label} ---")
        print(f"    injected anomalies: {len([i for i in st.anomalies if i >= WARMUP])}")
        rows = evaluate(st, args.sigma)
        print(
            f"    {'detector':<34} {'alarms':>7} {'TP':>5} {'FP':>6} "
            f"{'prec':>6} {'recall':>7} {'F1':>6}"
        )
        for r in rows:
            print(
                f"    {r.name:<34} {r.alarms:>7} {r.tp:>5} {r.fp:>6} "
                f"{r.precision:>6.3f} {r.recall:>7.3f} {r.f1:>6.3f}"
            )
        print()
        payload["streams"].append(  # type: ignore[union-attr]
            {
                "label": st.label,
                "injected": len([i for i in st.anomalies if i >= WARMUP]),
                "detectors": [vars(r) for r in rows],
            }
        )

    # Verdict.  Deliberately NOT "did the incumbent lose", which is the
    # question whose answer flatters it: a detector that merely TIES a
    # one-line baseline has not earned its complexity, and one with 9%
    # precision has not earned deployment regardless of how the baseline did.
    # The first version of this block reported only "beaten on N of M" and
    # would have printed a clean-looking 0 of 4 over these numbers.
    print("=" * 78)
    print("VERDICT")
    print("=" * 78)
    ties = losses = wins = 0
    for s in payload["streams"]:  # type: ignore[union-attr]
        dets = s["detectors"]  # type: ignore[index]
        if len(dets) < 2:
            continue
        shipped_f1 = dets[0]["f1"]
        best = max(d["f1"] for d in dets[1:])
        if best > shipped_f1 + _TIE_F1:
            losses += 1
            verdict = "LOSES to baseline"
        elif shipped_f1 > best + _TIE_F1:
            wins += 1
            verdict = "beats baseline"
        else:
            ties += 1
            verdict = "TIES baseline (no advantage over one line of code)"
        rate = dets[0]["alarms"] / max(1, total_evaluated)
        print(
            f"  {s['label']:<28} F1={shipped_f1:.3f} vs best baseline "  # type: ignore[index]
            f"{best:.3f}  -> {verdict}"
        )
        print(
            f"  {'':<28} precision={dets[0]['precision']:.3f} "
            f"recall={dets[0]['recall']:.3f} alarm rate={rate:.1%}"
        )
    print()
    print(f"  beats baseline: {wins}   ties: {ties}   loses: {losses}")
    print()
    print("  READ THIS BEFORE QUOTING THE ABOVE:")
    print("  A tie means the EWMA + MAD + per-operation-sigma machinery bought")
    print("  nothing over 'flag the largest values in the trailing window'.")
    print("  Absolute numbers matter more than the comparison: on the isolated")
    print("  spike streams the detector raises ~13% of operations as alarms at")
    print("  <10% precision, and on the sustained shift it misses ~85% of a")
    print("  30% regime change.  Neither is a deployable operating point.")
    print("=" * 78)
    print()

    if args.json:
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
