#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Measure the 3R timing-anomaly detector — and gate on the measurement.

WHY THIS EXISTS
---------------
``monitoring.py`` ships a timing-anomaly detector.  Until this script there
was **no measurement of whether it detects anything**; the first measurement
(2026-08-16, commit 8d72b8c) was negative on every axis: ``threshold_sigma``
was inert (identical alarm sets at sigma 2/3/5), the fixed Gaussian MAD
threshold produced a 12.52% false-alarm rate on clean heavy-tailed traffic
(one in eight operations flagged), recall on a 30% sustained shift was
17.6%, and the whole apparatus tied a k-NN and a quantile baseline that cost
one line each.  The detector was rebuilt against that evidence — robust
score with an empirically calibrated per-operation false-alarm budget, plus
a distribution-free sign CUSUM for sustained shifts — and this script is now
the regression gate that keeps every one of those failures fixed:

  * clean-traffic false-alarm rate must stay within the declared budget,
  * a smaller budget must produce fewer alarms (budget is live),
  * a larger sigma floor must produce fewer alarms (sigma is live),
  * a 30% sustained shift must be alerted promptly and its regime covered,
  * and the point path must retain the same order of spike-ranking quality
    as the best trivial baseline at a matched alarm budget (measured ratio
    floor — the baselines rank somewhat better there, and that is stated,
    not hidden; see the gate comment for the full framing).

Run with ``--gate`` to enforce (CI does); without it the report is printed
and the exit code still reflects the gate so the lane cannot rot silently.

THE FAIRNESS RULE
-----------------
The baselines produce scores; the shipped detector is a binary rule.  Every
baseline is calibrated on the SAME stream to raise the SAME number of alarms
the shipped detector raised, and precision/recall/F1 are reported at that
matched alarm budget.  Equal alarm budget is the only comparison an operator
cares about: alarms cost review time, so the question is which detector
spends a fixed budget better.

All detectors run **online** and see the samples in the same order.  No
detector sees the future.

WHAT COUNTS AS AN ANOMALY — AND WHAT THIS EVIDENCE IS
-----------------------------------------------------
Ground truth is **synthetic injection**: spikes (an isolated operation takes
k x longer) and sustained shifts (a regime change from some point onward)
are injected at known indices into a stream of real wall-clock timings of a
real primitive through the shipped API.  This measures detector behaviour
against *known-position synthetic* anomalies over a *real* noise
distribution.  It is NOT evidence derived from observed attack traffic, and
no claim built on this file may present it as such — the JSON record carries
``evidence_class`` stating exactly this.

The comparison is deliberately unflattering and reported as measured: on
isolated spikes at a matched budget, the top-N KNN baseline ranks about as
well as the calibrated point path — while needing the shipped detector's own
calibrated alarm count as an oracle to run at all.  Measured mean F1 ratio
(shipped / best baseline): 0.95-0.99 on the deterministic gate streams, and
0.65-1.12 across runs on live host timings, where the base stream dominates
the spread.  Neither range supports a claim that the shipped point path
ranks isolated spikes better; it ranks them comparably.

What the machinery buys, stated no more strongly than the measurement
supports:

* The calibrated false-alarm budget.  No baseline has one — a top-N rule
  needs an N, and here it is handed the shipped detector's own alarm count.
  This is gated (clean-FAR, budget-monotonic, sigma-floor).
* A sustained-shift EVENT with a bounded detection delay.  The baselines
  have no event or regime concept at all, and their trailing window absorbs
  a new regime within WINDOW samples, so they cannot raise one — that is a
  structural fact about the algorithms, not a measured advantage.  What the
  measurement does NOT show is a large F1 advantage on the shift stream:
  the gaps there are inside this file's own tie band, and on live timings
  the shift row is further confounded because the host is already in the
  regime state for a substantial fraction of clean traffic (printed on every
  run).  The gated claim is the event and its delay, not the F1.

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
from typing import Dict, List, Sequence, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

#: First index at which detector behaviour is evaluated.  The monitor's
#: documented operating point needs 30 warmup samples, ~100 scores for
#: threshold calibration at the default 1% budget, and 200 samples to lock
#: the shift reference; evaluating from 400 measures the calibrated steady
#: state rather than the warmup posture, for the shipped detector and the
#: baselines alike.
EVAL_START = 400

#: Trailing window for the baseline detectors (matches the monitor's).
WINDOW = 100

#: Spike-stream seeds used to derive the tie band (see tie_band()).
SPIKE_SEEDS = (1, 2, 3, 4, 5)


# ---------------------------------------------------------------------------
# Ground-truth stream construction
# ---------------------------------------------------------------------------
@dataclass
class Stream:
    """A timing stream plus the index set of injected anomalies."""

    values: List[float]
    anomalies: Set[int]
    label: str


def collect_real_timings(count: int) -> Tuple[List[float], str, str]:
    """Wall-clock timings of a real primitive, or a labelled fallback.

    Uses the shipped API so the baseline distribution carries the real tail
    behaviour.  Falls back to a lognormal synthetic only if the native
    backend is unavailable, and says so in the report rather than silently
    degrading.
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

        out: List[float] = []
        for _ in range(count):
            t0 = time.perf_counter_ns()
            native_ed25519_sign(msg, sk)
            out.append((time.perf_counter_ns() - t0) / 1e6)  # ms
        return out, "real: ed25519_sign wall-clock via shipped API", "real-timings"
    except Exception as exc:  # pragma: no cover - environment dependent
        # S311 is correct in general and wrong here: this is the fallback
        # SHAPE of a timing distribution for a measurement harness, never key
        # material.  A seeded Mersenne Twister is what makes the fallback
        # reproducible, which is the property this needs.
        rng = random.Random(20260816)  # noqa: S311
        out = [rng.lognormvariate(-3.9, 0.22) for _ in range(count)]
        return (
            out,
            f"synthetic lognormal (native backend unavailable: {exc})",
            "synthetic-timings",
        )


def inject_spikes(base: Sequence[float], *, rate: float, magnitude: float, seed: int) -> Stream:
    # noqa rationale as above: choosing WHICH samples to corrupt in a
    # benchmark stream is not a cryptographic draw, and seeding it is what
    # makes the evaluation reproducible run to run.
    rng = random.Random(seed)  # noqa: S311
    values = list(base)
    anomalies: Set[int] = set()
    for i in range(len(values)):
        if rng.random() < rate:
            values[i] = values[i] * magnitude
            anomalies.add(i)
    return Stream(values, anomalies, f"spike x{magnitude:g} @ {rate:.1%} (seed {seed})")


def inject_shift(base: Sequence[float], *, start_frac: float, magnitude: float) -> Stream:
    values = list(base)
    start = int(len(values) * start_frac)
    anomalies: Set[int] = set()
    for i in range(start, len(values)):
        values[i] = values[i] * magnitude
        anomalies.add(i)
    return Stream(values, anomalies, f"shift x{magnitude:g} from {start_frac:.0%}")


#: Seed for the deterministic clean stream the GATES run on.  Gates and
#: measurements answer different questions and must not share a stream: a gate
#: is a regression tripwire and has to fail only when the detector changes,
#: while the reported measurement has to describe real timings.
GATE_BASE_SEED = 20260817


def synthetic_base(count: int, seed: int) -> List[float]:
    """A deterministic clean stream with NO regime change.

    Lognormal, matching the shape of the measured ed25519_sign distribution,
    with an occasional benign tail sample.  Reproducible from ``seed`` alone.

    This exists because a gate that runs on live host timings measures the
    host.  The shift path is the sharp case: a CPU that changes frequency
    mid-run produces a genuine sustained regime change, the detector correctly
    raises an event for it, and the gate then cannot tell that event from the
    one the injected shift should have produced — it re-baselines onto the
    host's new level and the injection becomes invisible.  Measured on this
    host, gating the shift path on live timings failed 7 runs in 30 with
    nothing wrong, and the delay and coverage numbers a passing run printed
    were not attributable to the injected anomaly.  On this stream the same
    gate is exactly reproducible: identical output across repeated runs at one
    sample count, and zero false shift events over eight seeds.  The delay and
    coverage it reports depend on --samples, so they are quoted with it —
    measured at 1,000 / 2,000 / 4,000 / 8,000 samples: delay 80 / 45 / 68 / 29 and coverage 0.73 / 0.85 / 0.77 / 0.90.  An earlier
    revision of this comment said "26-40 samples, coverage 0.87-0.91" with no
    sample count attached, and that pair describes none of the four.

    Live timings are still measured and reported on every run — that is the
    evidence — but the pass/fail decision is taken here, where a failure means
    the detector changed.
    """
    rng = random.Random(seed)  # noqa: S311 -- evaluation stream, not key material (DBE-001)
    out: List[float] = []
    for _ in range(count):
        value = rng.lognormvariate(-3.9, 0.22)
        if rng.random() < 0.01:
            value *= 1.6
        out.append(value)
    return out


# ---------------------------------------------------------------------------
# Detectors — the REAL shipped monitor, and the trivial baselines
# ---------------------------------------------------------------------------
@dataclass
class ShippedRun:
    """Everything the real monitor emitted over one stream.

    ``emitted`` is the per-sample alarm indicator — the operator's review
    load (point alarms plus edge-triggered shift EVENTS).  ``point_flags``
    is the point path alone — the spike detector, which is what the
    trivial-baseline comparison measures.  ``in_shift`` is the per-sample
    regime state read back through ``get_shift_state`` — coverage of a
    detected shifted regime between events.  These are deliberately
    distinct: a sustained shift is alerted once and then re-baselined, so
    counting regime samples as "alarms" would misstate the review load,
    and mixing regime coverage into the spike comparison lets the host's
    own regime changes drown the signal being compared.
    """

    emitted: List[bool]
    point_flags: List[bool]
    in_shift: List[bool]
    shift_events: List[int]


def run_shipped(
    values: Sequence[float],
    *,
    threshold_sigma: float = 3.0,
    alarm_budget: float = 0.01,
) -> ShippedRun:
    """Drive the real ``ResonanceTimingMonitor`` over a stream.

    Drives ``record_timing`` itself — no reimplementation.  (An earlier
    revision of this script mirrored the detector by hand and modelled a
    stronger z-branch than production shipped; measuring a re-implementation
    is how the sigma-inertness defect stayed invisible.)
    """
    from ama_cryptography.monitoring import ResonanceTimingMonitor  # noqa: PLC0415

    monitor = ResonanceTimingMonitor(
        anomaly_profiles={
            "eval_op": {
                "threshold_sigma": threshold_sigma,
                "alarm_budget": alarm_budget,
                "normalize_by_size": False,
            }
        }
    )
    emitted: List[bool] = []
    point_flags: List[bool] = []
    in_shift: List[bool] = []
    shift_events: List[int] = []
    for i, x in enumerate(values):
        anomaly = monitor.record_timing("eval_op", x)
        state = monitor.get_shift_state("eval_op")
        if anomaly is not None and anomaly.kind == "shift":
            shift_events.append(i)
        emitted.append(anomaly is not None)
        point_flags.append(anomaly is not None and anomaly.kind == "point")
        in_shift.append(bool(state is not None and state["in_shift"]))
    return ShippedRun(
        emitted=emitted, point_flags=point_flags, in_shift=in_shift, shift_events=shift_events
    )


def knn_scores(values: Sequence[float], k: int = 5) -> List[float]:
    """k-th nearest-neighbour distance within the trailing window."""
    window: List[float] = []
    scores: List[float] = []
    for x in values:
        if len(window) >= 30:
            dists = sorted(abs(x - w) for w in window)
            scores.append(dists[min(k, len(dists) - 1)])
        else:
            scores.append(0.0)
        window.append(x)
        if len(window) > WINDOW:
            window.pop(0)
    return scores


def quantile_scores(values: Sequence[float]) -> List[float]:
    """How far above the trailing median, in trailing-IQR units.

    The most trivial non-constant detector: no model, no distributional
    assumption, one sort.
    """
    window: List[float] = []
    scores: List[float] = []
    for x in values:
        if len(window) >= 30:
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


def flags_at_budget(scores: Sequence[float], budget: int) -> List[bool]:
    """Flag the ``budget`` highest-scoring samples inside the eval region."""
    scored = [(s, i) for i, s in enumerate(scores) if i >= EVAL_START]
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


def score(flags: Sequence[bool], truth: Set[int]) -> Result:
    tp = sum(1 for i, f in enumerate(flags) if f and i in truth and i >= EVAL_START)
    fp = sum(1 for i, f in enumerate(flags) if f and i not in truth and i >= EVAL_START)
    fn = sum(1 for i in truth if i >= EVAL_START and not flags[i])
    alarms = tp + fp
    precision = tp / alarms if alarms else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return Result("", alarms, tp, fp, fn, precision, recall, f1)


def evaluate(
    stream: Stream, *, use_regime_coverage: bool = False
) -> Tuple[List[Result], ShippedRun]:
    """Shipped detector vs both baselines at the matched alarm budget.

    For spike streams the shipped indicator is the POINT path alone — the
    spike detector against spike baselines, so the host's own regime
    changes (real frequency-scaling events in the recorded base) cannot
    drown the comparison.  For the shift stream ``use_regime_coverage``
    adds ``in_shift``: coverage of the flagged regime between
    edge-triggered events is exactly the property under comparison there.
    """
    run = run_shipped(stream.values)
    if use_regime_coverage:
        shipped = [p or e or s for p, e, s in zip(run.point_flags, run.emitted, run.in_shift)]
    else:
        shipped = run.point_flags
    budget = sum(1 for i, f in enumerate(shipped) if f and i >= EVAL_START)

    results: List[Result] = []
    r = score(shipped, stream.anomalies)
    r.name = "3R shipped (calibrated budget 1%)"
    results.append(r)

    if budget > 0:
        for name, scores_ in (
            ("KNN (k=5, matched budget)", knn_scores(stream.values)),
            ("Quantile/IQR (matched budget)", quantile_scores(stream.values)),
        ):
            rb = score(flags_at_budget(scores_, budget), stream.anomalies)
            rb.name = name
            results.append(rb)
    return results, run


def tie_band(per_seed_best_baseline_f1: Sequence[float]) -> float:
    """F1 gap below which two detectors are indistinguishable HERE.

    Derived from the data instead of asserted: twice the standard deviation
    of the best baseline's F1 across the evaluated spike streams, floored at
    0.01 so a zero-variance degenerate case cannot declare every difference
    significant.  (The first revision hard-coded 0.02 with no justification;
    this replaces the constant with the measurement that justifies one.)

    Each spike stream is built on its OWN independent base, so the band covers
    both sources of variation: which samples the injection seed corrupts, and
    which base stream they are corrupted in.  Sharing one base across the
    seeds measured only the first and understated the total by up to 5x on
    live timings, where the base is the dominant term.
    """
    if len(per_seed_best_baseline_f1) < 2:
        return 0.05
    return max(0.01, 2.0 * statistics.stdev(per_seed_best_baseline_f1))


# ---------------------------------------------------------------------------
# The gates
# ---------------------------------------------------------------------------
@dataclass
class GateResult:
    name: str
    passed: bool
    detail: str


def gate_clean_far(base: Sequence[float], budget: float) -> GateResult:
    """Clean traffic: the point path respects its budget and raises no regime.

    Two sub-checks, because the two alarm kinds have different contracts:

    * POINT alarms are budgeted by calibration: rate <= 2x budget (the
      declared spend plus binomial noise at n ~ 3,600 evaluated samples; the
      defect this gate exists to catch was 12.5x over budget).  Measured on
      this stream family: 0.0078-0.0117 against a 0.01 budget.
    * SHIFT events must not fire at all.  This stream contains no regime
      change by construction, so every event is a false one; measured zero
      over eight seeds.  On live timings the same count is a measurement of
      the host's frequency scaling rather than of the detector, which is why
      it is reported there and gated here.

    For reference, the structural bound on the event rate is the detect ->
    recover cycle: with k=0.5 the fastest ascent to h=10 takes 21 samples and
    the fastest recovery below h/2 takes 4, so the shortest cycle is ~25
    samples and the loosest defensible cap is n_eval/25.  The earlier text
    said ~50, which was wrong by 2x; on this stream the honest cap is zero.
    """
    run = run_shipped(base, alarm_budget=budget)
    n_eval = len(base) - EVAL_START
    events = [i for i in run.shift_events if i >= EVAL_START]
    point_alarms = sum(1 for i, f in enumerate(run.emitted) if f and i >= EVAL_START) - len(events)
    far = point_alarms / n_eval if n_eval else 0.0
    passed = far <= 2.0 * budget and not events
    return GateResult(
        "clean-FAR-within-budget",
        passed,
        f"clean point-alarm rate {far:.4f} vs declared budget {budget:.4f} "
        f"(limit {2 * budget:.4f}; 8d72b8c shipped 0.1252); "
        f"false shift events {len(events)} (must be 0 on a stream with no regime change)",
    )


def gate_budget_monotonic(base: Sequence[float]) -> GateResult:
    """A smaller alarm budget must yield fewer (never more) alarms.

    Counted from sample 600, not EVAL_START: calibration for a budget ``b``
    activates only after ``max(100, 1/b)`` scores, so the 0.002 run is still
    on the bare sigma floor until sample ~530 and fires MORE than a
    calibrated looser budget there.  Comparing budgets is only meaningful
    where every compared budget is calibrated.
    """
    budgets = (0.05, 0.01, 0.002)
    start = 600
    counts: List[int] = []
    for b in budgets:
        run = run_shipped(base, alarm_budget=b)
        counts.append(sum(1 for i, f in enumerate(run.emitted) if f and i >= start))
    monotone = all(counts[i] >= counts[i + 1] for i in range(len(counts) - 1))
    strict_overall = counts[0] > counts[-1]
    return GateResult(
        "alarm-budget-is-live",
        monotone and strict_overall,
        f"alarms at budgets {budgets} from sample {start}: {counts} "
        f"(must be non-increasing, ends strictly lower)",
    )


#: Alarm budget for the sigma gate.  See gate_sigma_floor_live for why it is
#: loose rather than tight.
_SIGMA_GATE_BUDGET = 0.05

#: First index the sigma gate counts from.  Calibration for budget b activates
#: after max(100, 1/b) scores; counting before that measures the uncalibrated
#: warmup, where sigma is the only threshold and separation is guaranteed
#: whether or not it survives calibration.
_SIGMA_GATE_START = 600


def gate_sigma_floor_live() -> GateResult:
    """The per-operation sigma floor must change behaviour WHERE IT IS USED.

    The operating threshold is ``max(sigma_floor, calibrated_quantile)``, so
    sigma only binds where it exceeds the calibrated threshold.  Two
    consequences the earlier version of this gate got wrong:

    * It counted from EVAL_START (400) with a 0.002 budget, whose calibration
      does not activate until ~530 samples.  All of its 2.0-vs-3.0 separation
      came from the 130-sample uncalibrated window.  Measured: from sample 600
      that budget gives (5, 5, 1) — sigma 2.0 and 3.0 identical — and a mutant
      that ignores sigma entirely the moment calibration is live still passed.
    * The budget has to be loose enough that all three floors sit above the
      calibrated quantile, or the comparison cannot separate them even when
      sigma is working perfectly.  At 0.05 the calibrated threshold is low and
      each floor binds: measured (94, 53, 1) from sample 600.

    So: a loose budget, counted in the calibrated steady state, requiring
    STRICT separation — which is what the docstring always claimed and the
    assertion (``>=``) did not enforce.  This is the direct regression gate on
    the 8d72b8c finding that sigma 2/3/5 produced exactly the same 497 alarms.
    """
    rng = random.Random(7)  # noqa: S311 -- deterministic evaluation stream (DBE-002)
    values: List[float] = []
    for _ in range(3000):
        x = 10.0 + 0.1483 * rng.gauss(0, 1)
        if rng.random() < 0.02:
            x = 10.0 + 0.1483 * 4.0
        values.append(x)
    counts = []
    for sigma in (2.0, 3.0, 5.0):
        run = run_shipped(values, threshold_sigma=sigma, alarm_budget=_SIGMA_GATE_BUDGET)
        counts.append(sum(1 for i, f in enumerate(run.emitted) if f and i >= _SIGMA_GATE_START))
    passed = counts[0] > counts[1] > counts[2]
    return GateResult(
        "sigma-floor-is-live",
        passed,
        f"alarms at sigma (2.0, 3.0, 5.0) from sample {_SIGMA_GATE_START} at budget "
        f"{_SIGMA_GATE_BUDGET}: {counts} (must be STRICTLY decreasing — equal counts "
        f"are what an inert sigma produces)",
    )


def gate_shift_detection(base: Sequence[float]) -> GateResult:
    """A 30% sustained regime change must be alerted, promptly, and covered.

    Four requirements on the injected shift stream:
      1. NO shift event before the onset — otherwise what follows is being
         credited to an injection that did not exist yet;
      2. at least one shift EVENT at or after the onset;
      3. the first such event lands within 150 samples of onset (the
         re-baseline horizon is 300, so a detection later than half of it is a
         regression); measured delay 80 / 45 / 68 / 29 at 1,000 / 2,000 /
         4,000 / 8,000 samples, 68 at the 4,000 CI runs;
      4. the regime state covers >= 70% of the window onset..onset+300;
         measured 0.73 / 0.85 / 0.77 / 0.90 at those same sample counts, 0.77
         at the 4,000 CI runs.
    8d72b8c had no event concept and flagged 17.6% of the regime.

    Requirement 1 is the one that forced this gate onto a deterministic
    stream.  On live timings the detector legitimately enters the shift state
    for the host's own frequency changes; when that happened before the
    injection, the CUSUM re-baselined onto the already-shifted level and the
    injected shift raised no event at all, while the coverage figure was
    satisfied by samples that predated it.  The gate then failed, or passed
    for the wrong reason, depending on the host — 7 failures in 30 runs
    measured here.  The live numbers are still measured and reported; the
    pass/fail decision is taken where an event can only come from the
    injection.
    """
    stream = inject_shift(base, start_frac=0.6, magnitude=1.3)
    onset = int(len(base) * 0.6)
    run = run_shipped(stream.values)
    events_before = [i for i in run.shift_events if EVAL_START <= i < onset]
    events_after = [i for i in run.shift_events if i >= onset]
    detected = bool(events_after)
    delay = (events_after[0] - onset) if detected else -1
    horizon = range(onset, min(onset + 300, len(base)))
    coverage = sum(1 for i in horizon if run.in_shift[i]) / len(horizon) if len(horizon) else 0.0
    passed = not events_before and detected and 0 <= delay <= 150 and coverage >= 0.70
    return GateResult(
        "shift-detection",
        passed,
        f"pre-onset events {len(events_before)} (must be 0) — "
        f"event={'yes' if detected else 'NO'} delay={delay} samples "
        f"(limit 150), regime coverage before re-baseline {coverage:.2f} (floor 0.70)",
    )


def gate_spike_ranking(samples: int) -> Tuple[GateResult, float]:
    """Ranking quality against the best trivial baseline, deterministically.

    MEASURED AND STATED PLAINLY: at a matched alarm budget a top-N KNN
    baseline ranks isolated spikes about as well as the calibrated point path.
    That comparison hands the baseline an oracle — its N is the shipped
    detector's own calibrated alarm count, and a top-N rule has no false-alarm
    control of its own, so it is not deployable without one — which is why the
    contract is "same order of ranking quality", not "wins".

    The floor is 0.85, from measurement with margin: the mean ratio is
    0.960 / 0.989 / 0.987 / 0.978 at 1,000 / 2,000 / 4,000 / 8,000 samples
    (0.987 at the 4,000 CI runs), and over four independent trials of five
    seeded streams at a fixed count it was 0.947-0.963.  The previous floor of
    0.7 was set from live-timing runs whose mean ratio ranged 0.652-1.123, i.e.
    it sat inside the statistic's own spread and one run in 25 failed it with
    nothing wrong; the range 0.80-0.98 that MONITORING.md published described
    neither those runs nor these.  Each stream gets its own base, so the
    ratio is reproducible from the seeds alone.

    Returns the gate and the tie band derived from the same streams.
    """
    ratios: List[float] = []
    best_f1s: List[float] = []
    for seed in SPIKE_SEEDS:
        base = synthetic_base(samples, GATE_BASE_SEED + seed)
        stream = inject_spikes(base, rate=0.01, magnitude=2.5, seed=seed)
        rows, _run = evaluate(stream)
        shipped = rows[0]
        best = max(r.f1 for r in rows[1:]) if len(rows) > 1 else 0.0
        if best > 0:
            ratios.append(shipped.f1 / best)
            best_f1s.append(best)
    mean_ratio = statistics.fmean(ratios) if ratios else 0.0
    band = tie_band(best_f1s)
    return (
        GateResult(
            "spike-ranking-quality",
            mean_ratio >= 0.85,
            f"mean shipped/best-baseline F1 ratio {mean_ratio:.3f} over "
            f"{len(ratios)} seeded streams on independent bases (floor 0.85; "
            f"metric's own noise band {band:.3f})",
        ),
        band,
    )


def run_gates(samples: int) -> List[GateResult]:
    """Every gate runs on a deterministic stream — see synthetic_base().

    The live-timing measurements printed above these gates are the evidence;
    these are the tripwires, and they must fail when the detector changes and
    not when the host does.
    """
    gate_base = synthetic_base(samples, GATE_BASE_SEED)
    ranking_gate, _band = gate_spike_ranking(samples)
    gates = [
        gate_clean_far(gate_base, 0.01),
        gate_budget_monotonic(gate_base),
        gate_sigma_floor_live(),
        gate_shift_detection(gate_base),
        ranking_gate,
    ]
    return gates


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--samples", type=int, default=4000)
    ap.add_argument("--json", type=str, default=None)
    ap.add_argument(
        "--gate",
        action="store_true",
        help="fail (exit 1) if any efficacy gate fails — CI mode",
    )
    args = ap.parse_args()

    base, source, evidence = collect_real_timings(args.samples)

    print("=" * 78)
    print("3R timing-anomaly detector: efficacy measurement and regression gates")
    print("=" * 78)
    print(f"Baseline distribution : {source}")
    print(f"Samples per stream    : {len(base)}   eval region starts at {EVAL_START}")
    print("Evidence class        : SYNTHETIC INJECTION over the distribution above —")
    print("                        known-position injected anomalies, NOT observed")
    print("                        attack traffic.  Do not quote as attack evidence.")
    print("Comparison rule       : baselines calibrated to the shipped detector's")
    print("                        own alarm count on the same stream.")
    print()

    payload: Dict[str, object] = {
        "source": source,
        "evidence_class": (
            f"{evidence}+synthetic-injection: injected ground truth over the "
            "measured distribution; not observed attack traffic"
        ),
        "samples": len(base),
        "eval_start": EVAL_START,
        "streams": [],
    }
    streams_out: List[Dict[str, object]] = payload["streams"]  # type: ignore[assignment]

    # Seeded spike streams (for the comparison and the derived tie band) and
    # the sustained shift stream.
    eval_streams: List[Stream] = [
        inject_spikes(base, rate=0.01, magnitude=3.0, seed=s) for s in SPIKE_SEEDS
    ]
    eval_streams.append(inject_shift(base, start_frac=0.6, magnitude=1.3))

    # How much of this host's own CLEAN traffic the detector already calls a
    # regime, printed before the shift row so that row can be read honestly:
    # the injected shift raises the fraction from this base rate, and the
    # difference — not the absolute coverage — is what the injection bought.
    clean_run = run_shipped(base)
    n_eval = len(base) - EVAL_START
    clean_shift_frac = (
        sum(1 for i in range(EVAL_START, len(base)) if clean_run.in_shift[i]) / n_eval
        if n_eval
        else 0.0
    )
    clean_events = [i for i in clean_run.shift_events if i >= EVAL_START]
    print(
        f"Host regime base rate : this host's clean traffic is already in the shift "
        f"state for {clean_shift_frac:.1%} of the\n"
        f"                        evaluated region ({len(clean_events)} event(s)) with "
        f"nothing injected — CPU\n"
        f"                        frequency scaling is a real regime change.  Read the "
        f"shift row below\n"
        f"                        against this baseline, not against zero."
    )
    print()
    payload["host_clean_shift_fraction"] = round(clean_shift_frac, 4)
    payload["host_clean_shift_events"] = len(clean_events)

    for st in eval_streams:
        rows, run = evaluate(st, use_regime_coverage=st.label.startswith("shift"))
        injected = len([i for i in st.anomalies if i >= EVAL_START])
        print(f"--- {st.label} ---")
        print(f"    injected anomalies in eval region: {injected}")
        print(
            f"    {'detector':<34} {'alarms':>7} {'TP':>5} {'FP':>6} "
            f"{'prec':>6} {'recall':>7} {'F1':>6}"
        )
        for r in rows:
            print(
                f"    {r.name:<34} {r.alarms:>7} {r.tp:>5} {r.fp:>6} "
                f"{r.precision:>6.3f} {r.recall:>7.3f} {r.f1:>6.3f}"
            )
        if run.shift_events:
            print(
                f"    shift events at indices {run.shift_events} "
                f"(edge-triggered; regime covered between event and re-baseline)"
            )
        print()
        streams_out.append(
            {
                "label": st.label,
                "injected": injected,
                "detectors": [vars(r) for r in rows],
                "shift_events": run.shift_events,
            }
        )

    print("=" * 78)
    print("REGRESSION GATES (each one pins a measured 8d72b8c failure)")
    print("=" * 78)
    print("Gates run on DETERMINISTIC seeded streams, not on the live timings")
    print("measured above: a gate must fail when the detector changes, and this")
    print("host's own frequency scaling is a genuine regime change that the shift")
    print("path correctly reacts to.  See synthetic_base() for the measurements")
    print("that forced the split.  The live numbers above are the evidence.")
    print()
    gates = run_gates(len(base))
    all_pass = True
    for g in gates:
        status = "PASS" if g.passed else "FAIL"
        if not g.passed:
            all_pass = False
        print(f"  [{status}] {g.name}: {g.detail}")
    payload["gates"] = [vars(g) for g in gates]
    print()
    if not all_pass:
        print("  GATE FAILURE: the detector no longer meets its measured contract.")
    else:
        print("  All gates pass on this stream.")
    print("=" * 78)

    if args.json:
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")

    # The exit code always reflects the gates: a lane that can pass while
    # the detector regresses is the failure mode this file exists to remove.
    del args.gate  # both modes gate; the flag documents CI intent
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
