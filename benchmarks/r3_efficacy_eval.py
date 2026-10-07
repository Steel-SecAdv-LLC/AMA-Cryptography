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
import os
import platform
import random
import statistics
from functools import partial
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Sequence

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

# E402: the package must be imported AFTER sys.path is pointed at the
# repository root above, so this script runs from a checkout without an
# editable install — the same shape tests/conftest.py uses. INVARIANT-13.
from ama_cryptography import pqc_backends  # noqa: E402 -- after sys.path insert (REE-002)
from ama_cryptography.monitoring import (  # noqa: E402 -- after sys.path insert (REE-002)
    ResonanceTimingMonitor,
)

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


def paired_rates(
    trace: list[float],
    inject: Callable[[list[float]], tuple[list[float], set[int]]],
    detectors: Sequence[tuple[str, Callable[[list[float]], list[bool]]]],
    repeats: int,
) -> dict[str, tuple[float, float]]:
    """Mean ``(tpr, fpr)`` per detector over ``repeats`` SHARED injections.

    The injection runs exactly once per repeat and EVERY detector scores
    that same trace — one draw per (family, parameter, repeat).  The first
    committed form put the detector loop outermost around a shared RNG, so
    3R consumed one set of injection placements and the baseline the next
    set, and the head-to-head columns compared different traces (review
    finding, 2026-10-07).  Pinned by the pairing test, which counts
    injections and compares the traces each detector received.
    """
    tprs: dict[str, list[float]] = {name: [] for name, _ in detectors}
    fprs: dict[str, list[float]] = {name: [] for name, _ in detectors}
    for _ in range(repeats):
        injected_trace, idx = inject(trace)
        for name, fn in detectors:
            tpr, fpr = rates(fn(injected_trace), idx)
            tprs[name].append(tpr)
            fprs[name].append(fpr)
    return {
        name: (statistics.fmean(tprs[name]), statistics.fmean(fprs[name])) for name, _ in detectors
    }


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


def _provenance_lines(seed: int) -> str:
    """The measurement's provenance, recorded with the figures it covers.

    AGENTS.md section 8 (item 7) requires every published performance
    figure to carry its host, build flags, and run identifier; the first
    committed revision of the table carried only n/median/MAD/seed and the
    README's generic host sentence (review finding, 2026-10-07).  Each
    value below is read from the measuring process itself, never typed in.

    The artifact line names the exact native library these timings ran on:
    the loaded backend from the module attestation, pinned by its mapped
    SHA3-256 preload digest.  The build line reuses
    ``benchmark_runner._native_build_configuration``, which attributes a
    ``CMakeCache.txt`` only after digest-matching a build tree's copy of
    the library to the measured object — a stale or unrelated local build
    tree is passed over and the line says the configuration is not
    recorded, never a guess from a tree that happens to exist (review
    finding, 2026-10-07; the first form of this function read
    ``build/CMakeCache.txt`` unconditionally and allowlisted three keys).
    """
    from ama_cryptography._self_test import module_attestation

    from benchmarks import benchmark_runner

    run_id = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + f"+seed{seed}"
    try:
        commit = subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "--short=12", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        # A commit only names the measuring code while the worktree matches
        # it: the native digest below covers neither this script nor the
        # detector's Python, so a dirty tree could publish different rows
        # under the same commit= value (review finding, 2026-10-07).
        status = subprocess.run(
            ["git", "-C", str(REPO), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if status:
            commit += "+dirty-worktree"
    except (OSError, subprocess.CalledProcessError):
        commit = "unrecorded (no git in the measuring environment)"
    model = platform.processor() or platform.machine()
    hypervised = ""
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                model = line.split(":", 1)[1].strip()
            elif line.lower().startswith("flags") and " hypervisor" in f" {line}":
                hypervised = ", virtualized"
    # Only facts the process can establish (review finding, 2026-10-07: the
    # first form hard-coded "shared cloud container, not pinned", which a
    # regeneration on a dedicated or pinned host would publish unexamined):
    # the CPU model, the visible core count, this process's actual affinity
    # mask, and the hypervisor CPUID bit.  Tenancy is not observable from
    # inside and is said so.
    affinity = (
        f"affinity {len(os.sched_getaffinity(0))}/{os.cpu_count()} cores"
        if hasattr(os, "sched_getaffinity")
        else "affinity unrecorded on this platform"
    )
    host = f"{model} x{os.cpu_count()} ({affinity}{hypervised}; tenancy unrecorded)"
    native = module_attestation().get("native_backend") or {}
    lib_name = Path(str(native.get("path") or "")).name
    digest = str(native.get("preload_digest_hex") or "")
    if lib_name and digest and native.get("preload_digest_is_of_mapped_bytes"):
        # The flag is the evidence that these bytes are the ones that
        # executed; on loaders where the preload digest is not of the
        # mapped object (no procfs re-read), claiming the artifact — and
        # deriving build flags from it — would outrun the evidence
        # (review finding, 2026-10-07; _self_test applies the same rule).
        artifact = f"{lib_name} sha3_256={digest}"
        build = benchmark_runner._native_build_configuration()
    elif lib_name and digest:
        artifact = (
            "unrecorded (preload digest is not of the mapped bytes on this "
            "loader; the measured object cannot be pinned)"
        )
        build = "unrecorded (no pinned artifact to attribute a build tree to)"
    else:
        artifact = "unrecorded (no native-backend attestation in the measuring process)"
        build = "unrecorded (no pinned artifact to attribute a build tree to)"
    return (
        f"# provenance: run_id={run_id} commit={commit} python={platform.python_version()}\n"
        f"# host: {host}\n"
        f"# artifact: {artifact}\n"
        f"# build: {build}\n"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--samples", type=int, default=4000)
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--seed", type=int, default=394)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    rng = random.Random(args.seed)  # fmt: skip  # noqa: S311 -- seeded PRNG, not crypto (REE-001)

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

    detectors = (("3R", r3_alarms), ("baseline", baseline_alarms))
    for k in (1.5, 2.0, 3.0, 5.0, 10.0):
        point_rates = paired_rates(
            trace, partial(inject_point, k=k, rng=rng), detectors, args.repeats
        )
        for name, _ in detectors:
            tpr_m, fpr_m = point_rates[name]
            rows.append(f"point\tx{k}\t{name}\t{tpr_m:.3f}" f"\t{fpr_m:.4f}\t-\t{args.repeats}\t-")
    for k in (1.5, 2.0, 3.0):
        burst_rates = paired_rates(
            trace, partial(inject_burst, k=k, rng=rng), detectors, args.repeats
        )
        for name, _ in detectors:
            tpr_m, fpr_m = burst_rates[name]
            rows.append(f"burst\tx{k}\t{name}\t{tpr_m:.3f}" f"\t{fpr_m:.4f}\t-\t{args.repeats}\t-")
    for s in (0.05, 0.10, 0.30, 1.00):
        # inject_step is deterministic, so the step family was paired
        # already; hoisting the injection makes that structural too.
        t, mid = inject_step(trace, s)
        for name, fn in detectors:
            detected, delay, fpr, excess = step_metrics(fn(t), clean_alarms[name], mid)
            rows.append(
                f"step\t+{int(s*100)}%\t{name}"
                f"\t{int(detected)}\t{fpr:.4f}"
                f"\t{delay}\t1\t{excess:+.4f}"
            )

    out = REPO / args.out
    out.write_text(
        "\n".join(rows)
        + f"\n# benign_n={len(trace)} median_ms={med:.4f} mad_ms={mad:.4f} seed={args.seed}\n"
        + _provenance_lines(args.seed),
        encoding="utf-8",
    )
    print("\n".join(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
