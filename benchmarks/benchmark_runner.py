#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography Benchmark Runner
================================

Performance regression detection for CI/CD pipelines.
Compares current performance against baseline.json and fails if
any benchmark regresses more than the configured threshold.

Usage:
    python benchmarks/benchmark_runner.py [--verbose]

Refreshing a baseline is deliberately NOT a flag on this runner.
`--update-baseline` used to be accepted here and then ignored — the parsed value
was never read, so a maintainer recalibrating floors saw a normal green run and
believed baseline.json had been rewritten.  Baselines are edited by hand, and
every changed line needs a justification entry that
`benchmarks/check_baseline_justification.py` enforces; an automatic write-back
would route around that gate.

Exit codes:
    0 - All benchmarks within acceptable range
    1 - Performance regression detected (slower than the operative tolerance)
    2 - Error running benchmarks

On the operative tolerance: `thresholds.regression_threshold_percent` (10) is
only a FALLBACK.  Every primitive in both shipped baselines carries its own
`tolerance_percent`, and a per-primitive value overrides the global one, so
the number that actually gates a run is never 10 in the shipped
configuration — it is 45 on `benchmarks/baseline.json` (x86-64) and 15 or 25
on `benchmarks/arm-baseline.json`.  Those values are derived from each lane's
measured noise and the reasoning is recorded in each file's
`metadata.description`: the x86 lane is a coarse safety net over a shared,
contended runner, and the ARM lane is the precision gate.  This docstring
previously advertised ">10%", which reads as a much tighter gate than the one
that runs.
"""

import argparse
import json
import os
import platform
import secrets
import shlex
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""

    name: str
    description: str
    ops_per_second: float
    baseline_value: float
    tolerance_percent: float
    regression_percent: float
    passed: bool
    optional: bool = False


#: Decimal places every PUBLISHED measurement is quantised to.
PUBLISHED_DECIMALS = 2


def published(value: float) -> float:
    """The quantised measurement both published records carry.

    ``benchmarks/benchmark-results.json`` is the machine-readable authority and
    stores ``round(x, PUBLISHED_DECIMALS)``; ``benchmark-report.md`` displays
    FEWER digits than that.  So the table must format the quantised value, not
    the raw one — otherwise the two artefacts disagree wherever the two
    roundings do, and the markdown is no longer what the generator produces
    from the JSON beside it.

    Measured, on the record this repaired: `hkdf_derive` was 122,478.37 ops/sec
    against a 131,341 floor, i.e. a regression of 6.747801524276505%.  The table
    formatted that raw value and rendered `+6.7%`; the JSON stored `6.75`, from
    which the same generator renders `+6.8%`.  The published pair contradicted
    itself by one displayed digit.  Caught by
    `test_the_published_report_matches_the_generator` in
    tests/test_benchmark_baseline_infra.py.

    Applied at the RENDERING boundary only.  The pass/fail decision
    (`regression <= tolerance`) stays on the raw value, because a gate must not
    move because a number was formatted.
    """
    return round(value, PUBLISHED_DECIMALS)


def load_baseline(baseline_path: Path) -> Dict[str, Any]:
    """Load baseline configuration from JSON file."""
    with open(baseline_path) as f:
        return cast(Dict[str, Any], json.load(f))


_RUNNER_CLASS_ALIASES = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "x86-64": "x86_64",
    "x86_64": "x86_64",
    "arm64": "aarch64",
    "aarch64": "aarch64",
}


def normalize_runner_cpu_class(value: str) -> str:
    """Normalize common runner architecture spellings for baseline matching."""
    return _RUNNER_CLASS_ALIASES.get(value.strip().lower(), value.strip().lower())


def validate_baseline_contract(
    baseline: Dict[str, Any],
    baseline_path: Path,
    expected_runner_cpu_class: str = "",
    require_populated_baseline: bool = False,
) -> None:
    """Validate baseline metadata before benchmark comparisons run."""
    metadata = baseline.get("metadata", {})
    actual = normalize_runner_cpu_class(str(metadata.get("runner_cpu_class", "")))
    expected = normalize_runner_cpu_class(expected_runner_cpu_class)
    if expected:
        if not actual:
            raise ValueError(
                f"{baseline_path} is missing metadata.runner_cpu_class; "
                f"expected {expected_runner_cpu_class!r}"
            )
        if actual != expected:
            raise ValueError(
                f"{baseline_path} targets runner_cpu_class={actual!r}, "
                f"but this runner is {expected!r}"
            )

    if not require_populated_baseline:
        return

    zero_entries = []
    for section in ("benchmarks", "pqc_benchmarks"):
        for name, entry in baseline.get(section, {}).items():
            if entry.get("baseline_value") == 0:
                zero_entries.append(name)
    if zero_entries:
        joined = ", ".join(sorted(zero_entries))
        raise ValueError(f"{baseline_path} contains unpopulated zero baselines: {joined}")


#: Minimum wall-clock a single timed batch must span, in seconds.
#:
#: The per-call ``iterations`` defaults (20-100) were chosen per primitive and
#: are three orders of magnitude apart in cost, so they bought wildly different
#: amounts of signal: 20 ML-DSA-65 signatures is about 6 ms of measurement, and
#: the whole 19-benchmark suite finished in roughly 0.4 s of wall clock on the
#: CI runner.  On a shared, unpinned GitHub-hosted runner a single scheduler
#: preemption is larger than that, so the reported number was dominated by
#: whatever else the host was doing.  Observed directly: three consecutive runs
#: of one unchanged binary measured 917, 1845 and 3086 ops/sec for
#: ``dilithium_sign`` -- a 3.4x spread with the code held constant, against a
#: 10% regression threshold.  A gate whose noise exceeds its threshold by 34x
#: cannot fail for the reason it claims to, which is the failure mode
#: ``tests/test_benchmark_baseline_freshness.py`` was written about.
#:
#: Batches are therefore sized from a calibration run rather than fixed, so
#: every primitive gets a comparable amount of signal regardless of its cost.
_MIN_SAMPLE_SECONDS = 0.15

#: Timed batches per benchmark; the fastest is reported.
#:
#: Throughput noise on a shared runner is one-sided -- interference can only
#: make an operation look slower, never faster -- so the fastest of several
#: batches is the best available estimate of the machine's actual capability
#: and is far more stable than the mean.  This is the estimator
#: ``benchmark_operation_best_of`` was written for and applied to the two
#: composite package benchmarks; it is now what every benchmark gets, from
#: ``benchmark_operation`` itself, which is why neither composite calls
#: ``benchmark_operation_best_of`` any more — doing so on top of
#: ``_SAMPLING_REPEATS`` multiplied the two and sampled one row 25 times while
#: publishing 5.
_ROUNDS = 3

#: Independent repeats of a whole benchmark, per primitive, beyond ``_ROUNDS``.
#:
#: ``_ROUNDS`` batches inside one call remove most WITHIN-call noise.  They do
#: not remove BETWEEN-run noise, and that is what a regression floor is exposed
#: to: the number a CI job publishes is the output of one whole run.
#:
#: Measured rather than assumed.  Five complete suite runs on an idle host
#: (4 vCPU, `taskset -c 0-3`, nothing else executing — the sanitiser and dudect
#: sweeps were drained first, because an earlier attempt taken alongside them
#: produced a different and useless answer):
#:
#:   * Two of the five runs were globally slow — mean throughput 96.1% and
#:     97.3% of the per-primitive best, against 98.6-98.9% for the other three.
#:     Interference lands on a whole run, not on one primitive.
#:   * Discarding each primitive's single worst observation collapses every
#:     spread to <= 6.4%, and 16 of 19 to <= 4%.
#:
#: So the fix is more independent observations, not a longer window: the
#: estimator already keeps the fastest, throughput noise is one-sided, and one
#: extra observation is what turns "this run was unlucky" into "this run was
#: unlucky and the other two were not".  Since these numbers become FLOORS, a
#: more robust estimate tightens the gate rather than loosening it.
#:
#: The listed primitives are exactly those whose cross-run spread exceeded 7%
#: over those five runs — 7% being the point at which the spread of the
#: measurement starts to be comparable to the tightest tolerance any baseline
#: carries (15%, on the ARM lane).  Two shapes appear in the list, and both are
#: real: the rejection-sampled ML-DSA family and the composites containing one
#: (under FIPS 204's deterministic variant the rejection count is a constant
#: per (key, message) pair, and the 256-input pool fixes only the message
#: half — the key is redrawn per run), and the very cheap primitives, whose
#: short windows make them the most exposed to a scheduling burst.
#:
#: Result, five more runs after the change, same host and conditions:
#: primitives over 7% cross-run spread went from 9 to 4, and every cheap
#: primitive landed at or under 2% (SHA3-256 9.0% -> 0.9%, HKDF 10.2% -> 0.8%,
#: HMAC 9.0% -> 1.1%, the three Ed25519 lanes 8.5-11.0% -> 0.8-1.2%,
#: ``full_package_verify`` 18.1% -> 3.5%).
#:
#: The ML-DSA family is the honest residue: 5-15% on THIS host, and the cause
#: is visible in the run-level data rather than inferred — one of the five runs
#: had a mean throughput of 93.7% of the per-primitive best across the ML-DSA
#: and package benchmarks while sitting at 97.9% overall.  These are the
#: longest-running benchmarks in the suite, so a whole-run stall on a contended
#: 4-vCPU VM lands hardest on them, and no number of repeats inside that run
#: escapes it.  The canonical measurement environment for the floors is the CI
#: runner fleet, where the ARM lane records <= 3% for deterministic primitives
#: and <= 1.2x for ``dilithium_sign`` after the 256-input pool; the floors in
#: ``benchmarks/*.json`` are measured there and are deliberately NOT
#: recalibrated from a developer VM.
#:
#: Cost is bounded and paid where it buys something: 11 primitives x 2 extra
#: repeats plus 2 composites x 4, at ~0.5 s of window each, is roughly 15 s
#: added to a run.
#:
#: ``tests/test_benchmark_baseline_infra.py`` pins that every name here is a
#: registered benchmark, so a rename cannot silently drop one back to a single
#: measurement.
_EXTRA_SAMPLED_ROUNDS = 3

#: The composites need more than the rest.  Each performs a whole hybrid sign
#: or verify, so it inherits the ML-DSA rejection-sampling variance on top of
#: its own; three repeats moved ``full_package_verify`` from 18.1% to 10.7%,
#: which is progress but not enough, and five brings it inside the band.
_COMPOSITE_SAMPLED_ROUNDS = 5

_SAMPLING_REPEATS: dict[str, int] = {
    # Rejection-sampled.
    "dilithium_keygen": _EXTRA_SAMPLED_ROUNDS,
    "dilithium_sign": _EXTRA_SAMPLED_ROUNDS,
    "dilithium_verify": _EXTRA_SAMPLED_ROUNDS,
    # Composites containing a rejection-sampled primitive.
    "full_package_create": _COMPOSITE_SAMPLED_ROUNDS,
    "full_package_verify": _COMPOSITE_SAMPLED_ROUNDS,
    # Cheap primitives: short windows, most exposed to a scheduling burst.
    "ama_sha3_256_hash": _EXTRA_SAMPLED_ROUNDS,
    "hmac_sha3_256": _EXTRA_SAMPLED_ROUNDS,
    "hkdf_derive": _EXTRA_SAMPLED_ROUNDS,
    "ed25519_keygen": _EXTRA_SAMPLED_ROUNDS,
    "ed25519_sign": _EXTRA_SAMPLED_ROUNDS,
    "ed25519_verify": _EXTRA_SAMPLED_ROUNDS,
    "aes_256_gcm_encrypt": _EXTRA_SAMPLED_ROUNDS,
    "chacha20poly1305_encrypt": _EXTRA_SAMPLED_ROUNDS,
}


def _measure_benchmark(name: str, func: "Callable[[], Optional[float]]") -> Optional[float]:
    """Run one registered benchmark, repeating it if it is a high-variance one.

    Repeats are whole independent measurements — fresh keys, fresh calibration
    — not extra batches inside one call, because the variance being sampled
    here lives *between* runs (see ``_SAMPLING_REPEATS``).  The fastest is
    reported, matching ``benchmark_operation``'s estimator; ``None`` (the
    primitive is absent from this build) short-circuits.
    """
    repeats = _SAMPLING_REPEATS.get(name, 1)
    best: Optional[float] = None
    for _ in range(repeats):
        value = func()
        if value is None:
            return None
        if best is None or value > best:
            best = value
    return best


#: Ceiling on a calibrated batch, so a primitive that gets much faster cannot
#: turn the benchmark job into a long-running one.
_MAX_ITERATIONS = 500_000

#: Distinct inputs cycled through by benchmarks of rejection-sampled
#: primitives (see ``_cycle``).
_INPUT_POOL = 256


def _cycle(items: "List[Any]") -> Callable[[], Any]:
    """Return a callable that yields ``items`` round-robin, one per call.

    ML-DSA-65 signing is FIPS 204's *deterministic* variant here (rnd = 0), so
    for a fixed (key, message) pair the rejection-loop count — and therefore
    the running time — is a constant, not a random variable.  A benchmark that
    signs one fixed message under one per-process keypair measures the luck of
    that single pair: across six runs of this suite on the ubuntu-24.04-arm CI
    runner, ``dilithium_sign`` reported 1,396 to 7,474 ops/sec (a 5.35x
    spread) while every non-rejection-sampled primitive on the same runs
    agreed within 3%.  ``full_package_create`` carries the same signature
    inside it and showed the same bimodality (2,701 vs 5,481).

    Cycling a pool of distinct inputs makes every timed batch average over
    ``_INPUT_POOL`` independent draws of the rejection count, so the reported
    number converges on the *expected* signing rate — the quantity a
    regression floor can meaningfully be set against.  The per-call cost of
    the cycling itself is two attribute loads and an integer increment,
    negligible against the >100 us primitives it is applied to.
    """
    n = len(items)
    state = {"i": 0}

    def next_item() -> Any:
        i = state["i"]
        state["i"] = (i + 1) % n
        return items[i]

    return next_item


def _timed_batch(operation: Callable[[], object], iterations: int) -> tuple[float, float]:
    """One timed batch, as ``(operations_per_second, elapsed_seconds)``."""
    start = time.perf_counter()
    for _ in range(iterations):
        operation()
    elapsed = time.perf_counter() - start
    ops = iterations / elapsed if elapsed > 0 else float("inf")
    return ops, elapsed


#: Hard stop on re-sizing, so a pathological operation cannot loop forever.
_MAX_SIZING_ATTEMPTS = 12


def _required_batch(rate: float) -> int:
    """Iterations needed to span ``_MIN_SAMPLE_SECONDS`` at ``rate`` ops/sec."""
    if rate <= 0.0 or rate == float("inf"):
        return 1
    return min(_MAX_ITERATIONS, max(1, int(rate * _MIN_SAMPLE_SECONDS) + 1))


def benchmark_operation(
    operation: Callable[[], object],
    iterations: int = 100,
    warmup: int = 5,
    rounds: int = _ROUNDS,
) -> float:
    """
    Benchmark an operation and return operations per second.

    ``iterations`` is a *floor*, not the batch size.  Batches are grown until
    a timed batch spans at least ``_MIN_SAMPLE_SECONDS`` of measured
    wall-clock time, so a cheap primitive gets many more iterations than an
    expensive one and both are measured over a comparable window.  ``rounds``
    full-window batches are collected and the fastest is reported (see
    ``_ROUNDS``).

    A batch qualifies as full-window on its own measured elapsed time, never
    on a predicted iteration count.  The sampling rule exists to keep a
    lucky-high rate off a short window out of the published number, and the
    measured window enforces that directly: ``rate = batch / elapsed`` with
    ``elapsed >= _MIN_SAMPLE_SECONDS`` *is* a full-window measurement,
    whatever the fastest rate observed elsewhere in the run happens to be.
    Qualification by predicted count (``batch >= fastest_rate * window``) was
    tried first and hard-failed legitimate runs on shared runners: every
    marginally faster observation raised the prediction, revoked the batches
    already credited, and restarted the count, so the attempt budget drained
    on re-validation instead of measurement.  A batch that spanned the window
    when it ran does not stop having done so because a later batch ran
    faster.  On a noisy host the two rules point in opposite directions —
    most batches run *slower* than the fastest rate seen, which lengthens
    their window (credit under this rule) while leaving their iteration count
    under each newly raised prediction (revocation under the old one).

    Sizing still keys off the fastest rate seen anywhere in the run, because
    throughput noise is one-sided: interference can only make an operation
    look slower than it is, never faster.  A slow batch therefore cannot
    shrink the sizing target, and a small batch that spans the window only
    because it stalled is credited (its rate can only be pessimistic, and the
    fastest round is what ships) but does not lock in its size for the
    remaining rounds.

    An operation too cheap to span the window inside ``_MAX_ITERATIONS``
    iterations is credited at the cap — the same ceiling
    ``_required_batch`` has always applied to the predicted target.  An
    under-sampled run still raises: fewer than ``rounds`` credited batches is
    a failure to MEASURE, and this function does not return numbers it cannot
    stand behind.

    Args:
        operation: Callable to benchmark
        iterations: Minimum iterations per timed batch
        warmup: Number of warmup iterations (not counted)
        rounds: Full-window batches to collect; the fastest is reported

    Returns:
        Operations per second
    """
    for _ in range(warmup):
        operation()

    batch = max(1, iterations)
    observed = 0.0  # fastest rate seen anywhere, used only for sizing
    best = 0.0  # fastest rate seen at a full-window batch, reported
    completed = 0
    for _attempt in range(rounds + _MAX_SIZING_ATTEMPTS):
        if completed >= rounds:
            break
        ops, elapsed = _timed_batch(operation, batch)
        if ops == float("inf"):
            # The clock could not resolve this batch at all (elapsed read as
            # exactly zero).  Returning that straight out was a fail-OPEN in
            # two directions: `inf` serialises as `Infinity`, which is not
            # valid JSON (RFC 8259) and which a strict reader rejects, and an
            # infinite rate clears every regression FLOOR it is compared
            # against.  A batch too short to time is a sizing problem, so it
            # is treated as one — grow and try again.  Checked before the
            # cap-credit below: a zero-elapsed batch must never be credited,
            # at the cap or anywhere else.
            batch = min(_MAX_ITERATIONS, max(batch + 1, batch * 8))
            continue
        observed = max(observed, ops)
        if elapsed >= _MIN_SAMPLE_SECONDS or batch >= _MAX_ITERATIONS:
            # Credited on this batch's own measured window (or at the
            # iteration cap, which bounds the job's runtime for operations
            # too cheap to span the window at all).  A credit is never
            # revoked: its validity is a fact about the batch that ran, not
            # about the estimates that came after it.
            best = max(best, ops)
            completed += 1
        target = _required_batch(observed)
        if batch < target:
            # Grow toward the target, capped at 8x a step so one wild
            # extrapolation cannot jump straight to _MAX_ITERATIONS.  A
            # credited batch grows too when it is under target — later
            # batches should be sized for the fastest rate seen — it just
            # keeps the credit it earned.
            batch = min(_MAX_ITERATIONS, max(batch + 1, min(target, batch * 8)))

    if completed >= rounds and best > 0.0:
        return best

    # Everything below is a failure to MEASURE, and every one of them used to
    # return a number anyway.
    #
    # `if best > 0.0: return best` returned after fewer than `rounds`
    # completed batches, and `if observed > 0.0: return observed` returned the
    # rate of an UNDER-TARGET batch — which this function's own docstring
    # forbids in as many words: "Only full-window batches are eligible to be
    # reported. An undersized batch can report a lucky-high rate off a very
    # short window, and since the baselines this feeds are *floors*, an
    # inflated number makes the gate weaker."  A short window is exactly where
    # a lucky-high rate comes from, so the fallback delivered the failure mode
    # the paragraph above it describes.
    if observed <= 0.0:
        # `observed` is only ever assigned from a FINITE rate: `_timed_batch`
        # returns `inf` exactly when it read `elapsed <= 0`, and the loop above
        # `continue`s on that before the `max()`.  So `observed == 0.0` says
        # precisely one thing — no batch was ever timed at all — and there is
        # no `observed == inf` case to test for.  (This condition carried that
        # disjunct.  A guard for a state the code cannot reach is a guard
        # nobody can check, which is the same objection this tree makes to a
        # suppression marker for a finding that does not exist.)
        #
        # Every attempt timed as zero is a broken clock rather than a fast
        # operation, and a number this function cannot stand behind must not be
        # returned as if it could — the JSON writer below refuses non-finite
        # values for the same reason.
        raise RuntimeError(
            "benchmark_operation could not obtain a measurable batch: every timed "
            "batch reported zero elapsed time, up to "
            f"{_MAX_ITERATIONS} iterations. The monotonic clock is not resolving "
            "this operation."
        )
    raise RuntimeError(
        f"benchmark_operation completed {completed} of {rounds} full-window "
        f"batches within {rounds + _MAX_SIZING_ATTEMPTS} attempts (batch size "
        f"reached {batch:,}, fastest observed rate {observed:,.1f} ops/sec). "
        "Reporting the fastest SHORT-WINDOW batch instead would publish a rate "
        "off a window shorter than the sampling rule requires, and these "
        "numbers feed regression FLOORS: an inflated one makes the gate weaker. "
        "Re-run on a quieter host, or raise the sampling budget."
    )


def benchmark_operation_best_of(
    operation: Callable[[], object],
    iterations: int,
    warmup: int,
    rounds: int,
) -> float:
    """Benchmark latency-spiky composite operations and keep the fastest round.

    Retained because callers and tests name it directly.  ``benchmark_operation``
    now takes the fastest of several batches for every benchmark, so this adds
    only the caller's explicit round count on top of that.
    """
    measurements = [
        benchmark_operation(operation, iterations=iterations, warmup=warmup) for _ in range(rounds)
    ]
    return max(measurements)


def run_sha3_256_benchmark(iterations: int = 100) -> float:
    """Benchmark AMA native C SHA3-256 hashing (FIPS 202)."""
    from ama_cryptography.pqc_backends import native_sha3_256

    data = b"A" * 1024  # 1KB data

    def operation() -> None:
        native_sha3_256(data)

    return benchmark_operation(operation, iterations)


def run_hmac_sha3_256_benchmark(iterations: int = 100) -> float:
    """Benchmark HMAC-SHA3-256 using project's own implementation."""
    from ama_cryptography.legacy_compat import hmac_authenticate

    key = secrets.token_bytes(32)
    data = b"A" * 1024

    def operation() -> None:
        hmac_authenticate(data, key)

    return benchmark_operation(operation, iterations)


def run_ed25519_keygen_benchmark(iterations: int = 50) -> float:
    """Benchmark Ed25519 key generation using native C backend."""
    from ama_cryptography.legacy_compat import generate_ed25519_keypair

    def operation() -> None:
        generate_ed25519_keypair()

    return benchmark_operation(operation, iterations)


def run_ed25519_sign_benchmark(iterations: int = 50) -> float:
    """Benchmark Ed25519 signing using native C backend."""
    from ama_cryptography.legacy_compat import ed25519_sign, generate_ed25519_keypair

    keypair = generate_ed25519_keypair()
    message = b"Test message for signing" * 10

    def operation() -> None:
        ed25519_sign(message, keypair.private_key)

    return benchmark_operation(operation, iterations)


def run_ed25519_verify_benchmark(iterations: int = 50) -> float:
    """Benchmark Ed25519 verification using native C backend."""
    from ama_cryptography.legacy_compat import (
        ed25519_sign,
        ed25519_verify,
        generate_ed25519_keypair,
    )

    keypair = generate_ed25519_keypair()
    message = b"Test message for signing" * 10
    signature = ed25519_sign(message, keypair.private_key)

    def operation() -> None:
        ed25519_verify(message, signature, keypair.public_key)

    return benchmark_operation(operation, iterations)


def run_hkdf_derive_benchmark(iterations: int = 100) -> float:
    """Benchmark HKDF key derivation using native C backend."""
    from ama_cryptography.pqc_backends import native_hkdf

    master_secret = secrets.token_bytes(32)
    salt = secrets.token_bytes(32)
    info = b"benchmark-test"

    def operation() -> None:
        native_hkdf(master_secret, 96, salt, info)

    return benchmark_operation(operation, iterations)


def run_full_package_create_benchmark(iterations: int = 20) -> float:
    """Benchmark complete crypto package creation (4-layer, hybrid signature).

    Measures :func:`ama_cryptography.crypto_api.create_crypto_package` — the
    shipped flagship API — under a long-lived signing identity
    (:class:`~ama_cryptography.crypto_api.KeypairCache`), which mirrors the
    agent flow the API documents and keeps the workload comparable to the
    pre-5.0.0 benchmark that reused one KMS across calls.  The deprecated
    ``legacy_compat`` shim this used to time emitted a ``DeprecationWarning``
    per call and measured a code path new integrations are told not to take.

    Package creation embeds an ML-DSA-65 signature, so the content is cycled
    for the same reason ``run_dilithium_sign_benchmark`` cycles its message
    (see ``_cycle``): with deterministic signing, one fixed (key, content)
    pair pins one rejection count, and the benchmark measures that pair's
    luck instead of the expected rate.
    """
    from ama_cryptography.crypto_api import (
        CryptoPackageConfig,
        KeypairCache,
        create_crypto_package,
    )

    cache = KeypairCache()
    public_key, secret_key = cache.get_or_generate()
    config = CryptoPackageConfig(signing_keypair=(public_key, secret_key))
    base = b"Benchmark package content " * 8
    next_content = _cycle([base + i.to_bytes(2, "big") for i in range(_INPUT_POOL)])

    def operation() -> None:
        create_crypto_package(next_content(), config)

    # Plain benchmark_operation, matching run_full_package_verify_benchmark.
    #
    # This used to be `benchmark_operation_best_of(..., rounds=5)` while
    # `_SAMPLING_REPEATS` ALSO registered this row for
    # `_COMPOSITE_SAMPLED_ROUNDS` (5).  The two mechanisms compound:
    # `_measure_benchmark` calls this function 5 times and keeps the max, and
    # each call ran `benchmark_operation` 5 more times, each of those 3
    # windows — 25 whole measurements and 75 windows, against 5 and 15 for its
    # sibling `full_package_verify`, which carries the SAME `_SAMPLING_REPEATS`
    # entry and calls plain `benchmark_operation`.
    #
    # So the provenance line published "full_package_create x5" for a row
    # sampled 25 times, and the cost model in the `_EXTRA_SAMPLED_ROUNDS`
    # docstring was out by ~4x for it.  Measured on this change: 17.7 s -> 5.5 s
    # for the row, and the reported rate moves 1,446.8 -> 1,371.7 ops/sec
    # (-5.2%) because the maximum is now taken over 15 windows rather than 75.
    # The floor is 1,983 with a 45% tolerance, i.e. a 1,091 ops/sec minimum, so
    # both numbers clear it with room; the two composites are now sampled
    # identically, which is what makes them comparable at all.
    return benchmark_operation(operation, iterations, warmup=2)


def run_full_package_verify_benchmark(iterations: int = 20) -> float:
    """Benchmark complete crypto package verification (4-layer, anchored).

    Measures :func:`ama_cryptography.crypto_api.verify_crypto_package` with
    ``expected_public_key`` supplied, so the timed path is the one 4.0.0
    callers must take for ``all_valid`` to mean anything (the unanchored form
    caps the result at ``core_valid``).  Verification is deterministic — no
    rejection sampling — so a fixed package is the right fixture.
    """
    from ama_cryptography.crypto_api import (
        CryptoPackageConfig,
        KeypairCache,
        create_crypto_package,
        verify_crypto_package,
    )

    cache = KeypairCache()
    public_key, secret_key = cache.get_or_generate()
    config = CryptoPackageConfig(signing_keypair=(public_key, secret_key))
    content = b"Benchmark package content for verification " * 4
    package = create_crypto_package(content, config)

    def operation() -> None:
        verify_crypto_package(content, package, expected_public_key=public_key)

    return benchmark_operation(operation, iterations, warmup=2)


def run_dilithium_keygen_benchmark(iterations: int = 20) -> Optional[float]:
    """Benchmark ML-DSA-65 key generation via native C library."""
    try:
        from ama_cryptography.pqc_backends import (
            DILITHIUM_AVAILABLE,
            generate_dilithium_keypair,
        )

        if not DILITHIUM_AVAILABLE:
            return None

        def operation() -> None:
            generate_dilithium_keypair()

        return benchmark_operation(operation, iterations, warmup=2)
    except (ImportError, Exception):
        return None


def run_dilithium_sign_benchmark(iterations: int = 20) -> Optional[float]:
    """Benchmark ML-DSA-65 signing via native C library."""
    try:
        from ama_cryptography.pqc_backends import (
            DILITHIUM_AVAILABLE,
            dilithium_sign,
            generate_dilithium_keypair,
        )

        if not DILITHIUM_AVAILABLE:
            return None

        kp = generate_dilithium_keypair()
        # Deterministic signing makes the rejection count a constant per
        # (key, message) pair — cycle distinct messages so the batch averages
        # over the rejection distribution instead of sampling one pair's luck
        # (see _cycle).
        base = b"Test message for ML-DSA-65 signing" * 10
        next_message = _cycle([base + i.to_bytes(2, "big") for i in range(_INPUT_POOL)])

        def operation() -> None:
            dilithium_sign(next_message(), kp.secret_key)

        return benchmark_operation(operation, iterations, warmup=2)
    except (ImportError, Exception):
        return None


def run_dilithium_verify_benchmark(iterations: int = 20) -> Optional[float]:
    """Benchmark ML-DSA-65 verification via native C library."""
    try:
        from ama_cryptography.pqc_backends import (
            DILITHIUM_AVAILABLE,
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
        )

        if not DILITHIUM_AVAILABLE:
            return None

        kp = generate_dilithium_keypair()
        message = b"Test message for ML-DSA-65 signing" * 10
        signature = dilithium_sign(message, kp.secret_key)

        def operation() -> None:
            dilithium_verify(message, signature, kp.public_key)

        return benchmark_operation(operation, iterations, warmup=2)
    except (ImportError, Exception):
        return None


def run_kyber_keygen_benchmark(iterations: int = 20) -> Optional[float]:
    """Benchmark ML-KEM-1024 key pair generation via native C library."""
    try:
        from ama_cryptography.pqc_backends import (
            KYBER_AVAILABLE,
            generate_kyber_keypair,
        )

        if not KYBER_AVAILABLE:
            return None

        def operation() -> None:
            generate_kyber_keypair()

        return benchmark_operation(operation, iterations, warmup=2)
    except Exception:
        return None


def run_kyber_encapsulate_benchmark(iterations: int = 20) -> Optional[float]:
    """Benchmark ML-KEM-1024 encapsulation via native C library."""
    try:
        from ama_cryptography.pqc_backends import (
            KYBER_AVAILABLE,
            generate_kyber_keypair,
            kyber_encapsulate,
        )

        if not KYBER_AVAILABLE:
            return None

        kp = generate_kyber_keypair()

        def operation() -> None:
            kyber_encapsulate(kp.public_key)

        return benchmark_operation(operation, iterations, warmup=2)
    except Exception:
        return None


def run_aes_gcm_benchmark(iterations: int = 100) -> Optional[float]:
    """Benchmark AES-256-GCM encryption of 1KB data via native C library."""
    try:
        from ama_cryptography.pqc_backends import native_aes256_gcm_encrypt

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = secrets.token_bytes(1024)
        aad = b"benchmark-aad"

        # Probe once — native_aes256_gcm_encrypt raises RuntimeError if unavailable.
        native_aes256_gcm_encrypt(key, nonce, plaintext, aad)

        def operation() -> None:
            native_aes256_gcm_encrypt(key, nonce, plaintext, aad)

        return benchmark_operation(operation, iterations, warmup=5)
    except Exception:
        return None


def run_chacha20poly1305_benchmark(iterations: int = 100) -> Optional[float]:
    """Benchmark ChaCha20-Poly1305 encryption of 1KB data via native C library."""
    try:
        from ama_cryptography.pqc_backends import native_chacha20poly1305_encrypt

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = secrets.token_bytes(1024)
        aad = b"benchmark-aad"

        # Probe once — native_chacha20poly1305_encrypt raises RuntimeError if unavailable.
        native_chacha20poly1305_encrypt(key, nonce, plaintext, aad)

        def operation() -> None:
            native_chacha20poly1305_encrypt(key, nonce, plaintext, aad)

        return benchmark_operation(operation, iterations, warmup=5)
    except Exception:
        return None


def run_x25519_benchmark(iterations: int = 100) -> Optional[float]:
    """Benchmark X25519 key exchange (scalar mult) via native C library."""
    try:
        from ama_cryptography.pqc_backends import native_x25519_key_exchange

        scalar = secrets.token_bytes(32)
        point = secrets.token_bytes(32)

        # Probe once — native_x25519_key_exchange raises RuntimeError if unavailable.
        native_x25519_key_exchange(scalar, point)

        def operation() -> None:
            native_x25519_key_exchange(scalar, point)

        return benchmark_operation(operation, iterations, warmup=5)
    except Exception:
        return None


def run_x25519_batch4_benchmark(iterations: int = 100) -> Optional[float]:
    """Benchmark X25519 batch-4 DH via native_x25519_scalarmult_batch.

    Reports the per-batch (count=4) ops/sec, NOT the per-op rate.  A
    canonical-host run that yields ~13K single-shot ops/sec should
    yield ~12.5K batch-of-4 ops/sec under the default dispatch policy
    (the batch is four sequential scalar ladders plus the wrapper's
    per-batch overhead — wrapper overhead is what brings batch-of-4
    throughput slightly under single-shot, NOT a regression).  A
    significantly slower number typically means the AVX2 4-way kernel
    was accidentally selected as the default; that is a regression on
    every shipped Broadwell+/Zen+ part (see PR #273 design note).
    """
    try:
        from ama_cryptography.pqc_backends import (
            _X25519_NATIVE_AVAILABLE,
            _native_lib,
            native_x25519_scalarmult_batch,
        )

        if (
            _native_lib is None
            or not _X25519_NATIVE_AVAILABLE
            or not hasattr(_native_lib, "ama_x25519_scalarmult_batch")
        ):
            return None

        scalars = [secrets.token_bytes(32) for _ in range(4)]
        points = [secrets.token_bytes(32) for _ in range(4)]

        # Probe once to trip availability checks before timing.
        native_x25519_scalarmult_batch(scalars, points)

        def operation() -> None:
            native_x25519_scalarmult_batch(scalars, points)

        return benchmark_operation(operation, iterations, warmup=5)
    except Exception:
        return None


# secp256k1 field prime p — used to decompress a SEC1 compressed public key
# (0x02/0x03 || X, what native_secp256k1_pubkey_from_privkey returns) into the
# 64-byte X||Y form ama_secp256k1_ecdsa_verify expects.
_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP256K1_BENCH_PRIVKEY = bytes.fromhex(
    "0123456789abcdeffedcba98765432100f1e2d3c4b5a69788796a5b4c3d2e1f0"
)
_SECP256K1_BENCH_DIGEST = bytes(range(1, 33))


def _secp256k1_uncompressed_pubkey(privkey: bytes) -> bytes:
    """Return the 64-byte uncompressed (X||Y) public key for ``privkey``.

    The native pubkey export is 33-byte SEC1 *compressed*; recover Y from X via
    the curve equation (secp256k1's p ≡ 3 mod 4, so the modular square root is a
    single exponentiation) and pick the parity the compression prefix encodes.
    """
    from ama_cryptography.pqc_backends import native_secp256k1_pubkey_from_privkey

    compressed = native_secp256k1_pubkey_from_privkey(privkey)
    prefix, x_bytes = compressed[0], compressed[1:]
    x = int.from_bytes(x_bytes, "big")
    alpha = (pow(x, 3, _SECP256K1_P) + 7) % _SECP256K1_P
    y = pow(alpha, (_SECP256K1_P + 1) // 4, _SECP256K1_P)
    if (y & 1) != (prefix & 1):
        y = _SECP256K1_P - y
    return x_bytes + y.to_bytes(32, "big")


def run_secp256k1_ecdsa_sign_benchmark(iterations: int = 100) -> Optional[float]:
    """Benchmark secp256k1 ECDSA signing (RFC 6979 deterministic) via native C."""
    try:
        from ama_cryptography.pqc_backends import (
            _SECP256K1_NATIVE_AVAILABLE,
            native_secp256k1_ecdsa_sign,
        )

        if not _SECP256K1_NATIVE_AVAILABLE:
            return None

        # Probe once — surfaces any availability error before timing.
        native_secp256k1_ecdsa_sign(_SECP256K1_BENCH_DIGEST, _SECP256K1_BENCH_PRIVKEY)

        def operation() -> None:
            native_secp256k1_ecdsa_sign(_SECP256K1_BENCH_DIGEST, _SECP256K1_BENCH_PRIVKEY)

        return benchmark_operation(operation, iterations, warmup=5)
    except Exception:
        return None


def run_secp256k1_ecdsa_verify_benchmark(iterations: int = 100) -> Optional[float]:
    """Benchmark secp256k1 ECDSA verification via native C library."""
    try:
        from ama_cryptography.pqc_backends import (
            _SECP256K1_NATIVE_AVAILABLE,
            native_secp256k1_ecdsa_sign,
            native_secp256k1_ecdsa_verify,
        )

        if not _SECP256K1_NATIVE_AVAILABLE:
            return None

        signature = native_secp256k1_ecdsa_sign(_SECP256K1_BENCH_DIGEST, _SECP256K1_BENCH_PRIVKEY)
        pubkey = _secp256k1_uncompressed_pubkey(_SECP256K1_BENCH_PRIVKEY)

        # Probe once — confirms the fixture verifies before timing.
        native_secp256k1_ecdsa_verify(signature, _SECP256K1_BENCH_DIGEST, pubkey)

        def operation() -> None:
            native_secp256k1_ecdsa_verify(signature, _SECP256K1_BENCH_DIGEST, pubkey)

        return benchmark_operation(operation, iterations, warmup=5)
    except Exception:
        return None


#: The benchmark a baseline name maps to.  Module level, not local to
#: :func:`run_all_benchmarks`, because :func:`main` has to answer a question the
#: loop cannot: whether a name the baseline asks for is one this runner is even
#: able to run.  A name only the baseline knows is a rename that silently
#: deleted a floor, and until the coverage check in main() nothing distinguished
#: it from a benchmark that passed.
BENCHMARK_FUNCTIONS: dict[str, Callable[[], Optional[float]]] = {
    "ama_sha3_256_hash": run_sha3_256_benchmark,
    "hmac_sha3_256": run_hmac_sha3_256_benchmark,
    "ed25519_keygen": run_ed25519_keygen_benchmark,
    "ed25519_sign": run_ed25519_sign_benchmark,
    "ed25519_verify": run_ed25519_verify_benchmark,
    "hkdf_derive": run_hkdf_derive_benchmark,
    "full_package_create": run_full_package_create_benchmark,
    "full_package_verify": run_full_package_verify_benchmark,
    # secp256k1 ECDSA sign/verify are HARD-gated (core, not the soft PQC
    # loop): the signing path (RFC 6979 nonce + base-point ladder + Fermat
    # inversion mod n) and the verify path (two scalar mults + canonical-
    # pubkey + curve checks). A regression in the ECDSA-specific scalar
    # arithmetic fails the build, not merely warns — the pubkey ladder the C
    # reporting harness covered is not enough. They return None only on a
    # build without native secp256k1 (never the benchmark CI job, which is
    # AMA_USE_NATIVE_PQC=ON); the None-skip below handles that gracefully.
    "secp256k1_ecdsa_sign": run_secp256k1_ecdsa_sign_benchmark,
    "secp256k1_ecdsa_verify": run_secp256k1_ecdsa_verify_benchmark,
}

PQC_BENCHMARK_FUNCTIONS: dict[str, Callable[[], Optional[float]]] = {
    "dilithium_keygen": run_dilithium_keygen_benchmark,
    "dilithium_sign": run_dilithium_sign_benchmark,
    "dilithium_verify": run_dilithium_verify_benchmark,
    "kyber_keygen": run_kyber_keygen_benchmark,
    "kyber_encapsulate": run_kyber_encapsulate_benchmark,
    "aes_256_gcm_encrypt": run_aes_gcm_benchmark,
    "chacha20poly1305_encrypt": run_chacha20poly1305_benchmark,
    "x25519_scalarmult": run_x25519_benchmark,
    # PR #277, Devin review #10: x25519_scalarmult_batch4 pins the
    # batch wrapper's throughput so a future change that flips the
    # AVX2 4-way kernel to default-on is caught by CI rather than
    # silently regressing per-batch latency.
    "x25519_scalarmult_batch4": run_x25519_batch4_benchmark,
}


def run_all_benchmarks(baseline: Dict[str, Any], verbose: bool = False) -> List[BenchmarkResult]:
    """Run all benchmarks and compare against baseline."""
    results = []
    threshold = baseline["thresholds"]["regression_threshold_percent"]

    # Run standard benchmarks
    for name, func in BENCHMARK_FUNCTIONS.items():
        if name not in baseline["benchmarks"]:
            continue

        config = baseline["benchmarks"][name]
        if verbose:
            print(f"Running {name}...", end=" ", flush=True)

        ops_per_sec = _measure_benchmark(name, func)
        # A core benchmark whose primitive is genuinely absent from this build
        # (returns None) is skipped rather than crashing the run. The shipped
        # core benchmarks never return None; this only spares an ECDSA/secp256k1
        # entry on a non-native-PQC build. In the benchmark CI job (always
        # AMA_USE_NATIVE_PQC=ON) the number is present and hard-gated below.
        if ops_per_sec is None:
            if verbose:
                print("SKIPPED (primitive not available in this build)")
            continue

        baseline_value = config["baseline_value"]
        tolerance = config.get("tolerance_percent", threshold)

        # Calculate percent change from baseline.
        # Positive = faster than baseline, negative = slower than baseline.
        # When baseline_value is 0 ("first run on this runner class — record
        # current measurement as the new baseline"), there is no prior
        # number to regress against, so report the recorded value as a
        # PASS rather than dividing by zero.
        if baseline_value == 0:
            pct_change = 0.0
        else:
            pct_change = ((ops_per_sec - baseline_value) / baseline_value) * 100
        # Only fail on regressions (slower).  Improvements always pass.
        regression = -pct_change  # positive = slower
        passed = regression <= tolerance

        results.append(
            BenchmarkResult(
                name=name,
                description=config["description"],
                ops_per_second=ops_per_sec,
                baseline_value=baseline_value,
                tolerance_percent=tolerance,
                regression_percent=regression,
                passed=passed,
            )
        )

        if verbose:
            status = "PASS" if passed else "FAIL"
            print(f"{ops_per_sec:.0f} ops/sec ({regression:+.1f}%) [{status}]")

    # Run PQC benchmarks (hard-gated when measured; skipped when the
    # native backend is absent — see the None path below)
    for name, pqc_func in PQC_BENCHMARK_FUNCTIONS.items():
        if name not in baseline.get("pqc_benchmarks", {}):
            continue

        config = baseline["pqc_benchmarks"][name]
        if verbose:
            print(f"Running {name}...", end=" ", flush=True)

        pqc_ops_per_sec = _measure_benchmark(name, pqc_func)

        if pqc_ops_per_sec is None:
            if verbose:
                print("SKIPPED (PQC not available)")
            continue

        baseline_value = config["baseline_value"]
        tolerance = config.get("tolerance_percent", threshold)

        # Same baseline_value==0 first-run guard as the core benchmark loop:
        # avoid ZeroDivisionError when seeding a fresh runner-class baseline.
        if baseline_value == 0:
            pct_change = 0.0
        else:
            pct_change = ((pqc_ops_per_sec - baseline_value) / baseline_value) * 100
        regression = -pct_change
        passed = regression <= tolerance

        results.append(
            BenchmarkResult(
                name=name,
                description=config["description"],
                ops_per_second=pqc_ops_per_sec,
                baseline_value=baseline_value,
                tolerance_percent=tolerance,
                regression_percent=regression,
                passed=passed,
                # HARD-gated.  These rows were built optional=True, which
                # main() maps to warn-and-exit-0 — so all nine populated
                # AEAD/PQC/X25519 floors had an infinite blind spot while
                # both baseline files described a 15-25% firing threshold
                # and cited the 2.1x AES-GCM wrapper regression as the case
                # the recalibration prevents.  Reproduced: halving the
                # aes_256_gcm_encrypt floor printed "+52.4%% [WARN]" and
                # exited 0.  A measured row now fails like every core row;
                # a build without native PQC still skips above (the None
                # path) before any row is built, which was always the only
                # legitimate meaning "optional" had here.
                optional=False,
            )
        )

        if verbose:
            status = "PASS" if passed else "FAIL"
            print(f"{pqc_ops_per_sec:.0f} ops/sec ({regression:+.1f}%) [{status}]")

    return results


def generate_report(results: List[BenchmarkResult]) -> Dict[str, Any]:
    """Generate a JSON report of benchmark results.

    Carries the same provenance block as the markdown report. It was markdown
    only, which put the two published records on different footings: a reader
    of ``benchmark-results.json`` — the machine-readable one, and so the one
    another tool is most likely to consume — had no way to tell which commit,
    host or sampling rule produced the numbers. A measurement without its
    provenance is a number somebody quotes.
    """
    json_overrides = _provenance_json_overrides()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provenance": {
            _provenance_key(label): json_overrides.get(label, _provenance_json_value(value))
            for label, value in _provenance()
        },
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed and not r.optional),
            "warnings": sum(1 for r in results if not r.passed and r.optional),
        },
        "results": [
            {
                "name": r.name,
                "description": r.description,
                "ops_per_second": published(r.ops_per_second),
                "baseline_value": r.baseline_value,
                "regression_percent": published(r.regression_percent),
                "tolerance_percent": r.tolerance_percent,
                "passed": r.passed,
                "optional": r.optional,
            }
            for r in results
        ],
    }


def _package_version() -> str:
    """The installed package version, or ``"unknown"``.

    Imported lazily and defensively: this report must be producible in a tree
    whose module is in the POST ERROR state, which is exactly when someone is
    measuring what broke.
    """
    try:
        from ama_cryptography import __version__

        return str(__version__)
    except Exception:
        return "unknown"


def _invocation() -> str:
    """The command this process was actually run with.

    Was a hard-coded string naming ``--baseline`` and ``--markdown``. Every
    real run also passes ``--output`` — the flag that writes the JSON record
    the string appeared in — so the one field a reader would copy to reproduce
    the run did not reproduce it. A provenance line that describes a different
    command than the one that ran is worse than no line at all.

    ``sys.argv[0]`` is normalised to a repository-relative path when it is one,
    so the record does not depend on where the checkout happens to live, and
    rendered with forward slashes so it does not depend on which platform
    measured.  ``str()`` gave ``benchmarks\\benchmark_runner.py`` on Windows,
    which ``shlex.quote`` then wrapped in single quotes because a backslash is
    a POSIX metacharacter — a command line that is neither valid Windows nor
    comparable with the same run recorded on Linux.

    The normalisation is applied to the script path only.  That path is one
    *this function derives*, so its form is ours to choose; the remaining
    arguments are the caller's own strings and are reproduced verbatim
    (shell-quoted, never rewritten), because silently altering what was
    actually passed is the failure this field exists to prevent.
    """
    argv = list(sys.argv) or ["benchmarks/benchmark_runner.py"]
    try:
        script = Path(argv[0]).resolve().relative_to(Path(__file__).resolve().parent.parent)
        argv[0] = script.as_posix()
    except Exception:
        argv[0] = Path(argv[0]).name
    return "python " + " ".join(shlex.quote(a) for a in argv)


def _provenance_json_value(value: str) -> str:
    """A provenance row's value with its MARKDOWN formatting removed.

    `_provenance()` renders one list for two artefacts, which is the point: two
    hand-kept copies drift.  What it emits is markdown, so the commit, version
    and command rows are wrapped in backticks — and `generate_report()` copied
    those straight into the JSON.  The JSON therefore recorded

        "commit": "`3ce4b5883f712a481228fd0119df58aa7c6d49e2`"

    which is not a commit id: a consumer comparing it to `git rev-parse HEAD`
    gets a mismatch it cannot interpret.  That is the same defect the "Tree"
    row was split out to fix, in the same field, and splitting the row did not
    touch it — the commit message that introduced "Tree" asserted the JSON now
    carried "a `commit` that equals `git rev-parse HEAD`", and it did not.

    Stripping happens HERE, at the boundary, rather than by removing the
    backticks from `_provenance()`: the markdown block is what a human reads,
    and a bare 40-character hash in a table cell is worse for them.
    """
    stripped = value.strip()
    if len(stripped) >= 2 and stripped.startswith("`") and stripped.endswith("`"):
        return stripped[1:-1]
    return stripped


def _provenance_json_overrides() -> "dict[str, str]":
    """Rows whose JSON value is not the markdown value with formatting removed.

    "Commit" is the only one.  Its markdown value carries the
    ``(working tree DIRTY)`` suffix, which reads well in a table and is what
    the tests assert on, but is exactly what must NOT reach a field a tool
    compares against ``git rev-parse HEAD``.  Adding the "Tree" row said the
    same fact in a place a tool can read; it did not remove the suffix from
    this one, so the JSON still recorded a non-commit for every dirty run.
    """
    commit, _dirty = _TREE_STATE if _TREE_STATE is not None else capture_tree_state()
    return {"Commit": commit}


def _provenance_key(label: str) -> str:
    """``"Extra whole-run repeats"`` -> ``"extra_whole_run_repeats"``.

    The markdown block is written for a human and the JSON block for a tool,
    so the label is rendered once and mechanically transformed rather than
    maintained twice — two hand-kept copies of the same list drift, which is
    the failure this whole provenance block exists to prevent.
    """
    return "".join(c if c.isalnum() else "_" for c in label.strip().lower()).strip("_")


def _git(*args: str) -> str:
    """Run a read-only git command, or return ``"unknown"``.

    Guarded on every axis that can fail, so producing a report never fails
    because the host has no git, no repository, or a slow filesystem.
    """
    try:
        out = subprocess.run(
            ["git", *args], capture_output=True, text=True, check=False, timeout=10
        )
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def capture_tree_state() -> "tuple[str, bool]":
    """Snapshot ``(commit, dirty)`` for the tree the measurements come from.

    Called once, **before** the first measurement.  Sampling it later is what
    the first version did, and it made the flag useless: the run writes
    ``benchmarks/benchmark-results.json`` before rendering the markdown, and
    that file is tracked, so ``git status --porcelain`` was never empty by the
    time the provenance block was built.  Every report the tool had ever
    produced said ``working tree DIRTY`` — including the ones produced from a
    pristine checkout — so a reader could not tell a genuinely modified tree
    from the tool observing its own output.

    A provenance field that always reports the same value carries no
    information, and one that always reports the *alarming* value is worse
    than absent: it trains the reader to ignore it.
    """
    return (_git("rev-parse", "HEAD"), _git("status", "--porcelain") not in ("", "unknown"))


_TREE_STATE: "tuple[str, bool] | None" = None


def _native_backend_summary() -> str:
    """Identify the native library actually measured.

    The single most load-bearing variable behind these numbers is how the
    native library was built — the CI figures are produced with
    ``-DAMA_ENABLE_AVX512=ON -DAMA_ENABLE_NATIVE_ARCH=ON`` while the wheels
    users install are built with neither, and nothing else in this block
    distinguished the two (audit Low).  There is no runtime accessor for the
    configure flags, but the mapped-bytes SHA3-256 of the loaded object pins
    the exact binary — a different build has a different digest — and it is the
    same value the integrity artefact signs, so a reader can match a figure to
    the object that produced it.  Falls back to a plain marker if the
    attestation is unavailable, so provenance never fails for want of a detail.
    """
    try:
        from ama_cryptography._self_test import module_attestation

        nb = module_attestation().get("native_backend") or {}
        if not nb.get("loaded"):
            return "not loaded (pure-Python / ctypes-fallback measurement)"
        digest = nb.get("preload_digest_hex") or ""
        version = nb.get("native_version") or "?"
        path = nb.get("path") or "?"
        digest_str = f"digest {digest[:16]}…" if digest else "digest unavailable"
        return f"v{version} · {digest_str} · {path}"
    except Exception:  # pragma: no cover - provenance must never raise
        return "unavailable"


def _provenance() -> "list[tuple[str, str]]":
    """Everything needed to reproduce or discard this report.

    A performance record without its provenance decays into a number somebody
    quotes: ``benchmark-report.md`` sat in the tree for weeks quoting baselines
    that had since been recalibrated, and nothing in the file said which
    commit, host or baseline it belonged to, so nothing could tell it was
    stale.  Emitted by the generator rather than written by hand, because a
    provenance block a human maintains is the first thing to drift.

    Read only; every lookup that can fail is guarded, so producing the report
    never fails because a host withheld a detail.
    """
    # Falls back to a live query when nothing captured the state first — a
    # direct call from a test, or an embedding that skips ``main``. That
    # reading is the pessimistic one (the report files may already be
    # written), which is the right direction for a field about trust.
    commit, dirty = _TREE_STATE if _TREE_STATE is not None else capture_tree_state()
    repeated = ", ".join(f"{k} x{v}" for k, v in sorted(_SAMPLING_REPEATS.items()))
    return [
        ("Commit", f"`{commit}`{' (working tree DIRTY)' if dirty else ''}"),
        # Cleanliness as its OWN row, not only as a suffix on the commit.
        #
        # The suffix reads correctly in the markdown, but _provenance_key()
        # turns each label into a JSON key, so the JSON recorded
        # `"commit": "<hash>"` for a clean run and
        # `"commit": "<hash> (working tree DIRTY)"` for a dirty one — a
        # consumer reading the field as a commit id gets a string that is not
        # one, and a consumer comparing it to `git rev-parse HEAD` finds a
        # mismatch it cannot interpret.  Neither notices the dirt.  A separate
        # boolean-valued row says the thing outright in both artefacts, and
        # "the numbers describe uncommitted code" is exactly the kind of fact
        # a provenance block exists to make unmissable.
        ("Tree", "clean" if not dirty else "DIRTY (uncommitted changes)"),
        ("Version", f"`{_package_version()}`"),
        ("Host", f"{platform.platform()} / {platform.machine()}"),
        ("CPU", f"{os.cpu_count()} logical processor(s)"),
        ("Python", f"{platform.python_version()} ({platform.python_implementation()})"),
        # Which native binary produced the numbers — the digest pins the build.
        ("Native backend", _native_backend_summary()),
        ("Command", f"`{_invocation()}`"),
        (
            "Sampling",
            f"batches grown (sized to the fastest rate observed) until a timed batch "
            f"spans >= {_MIN_SAMPLE_SECONDS:g}s of measured wall-clock; "
            f"{_ROUNDS} full-window batches per call",
        ),
        ("Extra whole-run repeats", repeated or "none"),
        (
            "Aggregation",
            "fastest observation (throughput noise is one-sided: interference "
            "can only make an operation look slower)",
        ),
        (
            "Reading these numbers",
            "the baseline column is a regression FLOOR measured on the named CI "
            "runner, not this host's expected throughput; a ratio below 1.0 on a "
            "developer machine is ordinary",
        ),
    ]


def generate_markdown_report(results: List[BenchmarkResult], report: Dict[str, Any]) -> str:
    """Generate a markdown report with tables and bar chart."""
    # Render from the PUBLISHED (quantised) measurements, so this page is a
    # pure function of the JSON record beside it — see published().  Every
    # subsequent use of `results` in this function, the table and the bar chart
    # alike, therefore reads the same numbers a reader regenerating from
    # benchmarks/benchmark-results.json would.
    results = [
        replace(
            r,
            ops_per_second=published(r.ops_per_second),
            regression_percent=published(r.regression_percent),
        )
        for r in results
    ]
    lines = []
    lines.append("# Benchmark Regression Report")
    lines.append("")
    lines.append(f"**Timestamp:** {report['timestamp']}")
    summary = report["summary"]
    lines.append(
        f"**Results:** {summary['passed']}/{summary['total']} passed, "
        f"{summary['failed']} failed, {summary['warnings']} warnings"
    )
    lines.append("")
    lines.append("## Provenance")
    lines.append("")
    lines.append("| Property | Value |")
    lines.append("|----------|-------|")
    # Prefer the provenance RECORDED IN THE REPORT over this process's own.
    #
    # A report rendered from a stored `benchmark-results.json` — regenerating
    # the presentation without re-running the suite — otherwise stamped the
    # rendering process's commit, host and argv onto someone else's
    # measurements, so the artefact claimed to have been produced by whatever
    # re-rendered it.  The recorded block is the one that describes the run the
    # numbers came from; `_provenance()` is the fallback for a live run, where
    # `report` was built by `generate_report()` moments earlier and the two are
    # the same thing.
    recorded = report.get("provenance")
    if isinstance(recorded, dict) and recorded:
        by_key = {_provenance_key(label): label for label, _ in _provenance()}
        # The JSON holds the RAW value (see _provenance_json_value); put the
        # code formatting back for the rows that carry it in a live render, so
        # a report regenerated from a recorded block reads the same as the one
        # written alongside the numbers.
        ticked = {
            _provenance_key(label)
            for label, value in _provenance()
            if value.strip().startswith("`")
        }
        for key, value in recorded.items():
            shown = f"`{value}`" if key in ticked and not str(value).startswith("`") else value
            lines.append(f"| {by_key.get(key, key.replace('_', ' ').capitalize())} | {shown} |")
    else:
        for key, value in _provenance():
            lines.append(f"| {key} | {value} |")
    lines.append("")

    # Results table
    #
    # The column is named "Regression", matching the machine-readable field
    # (`regression_percent` in benchmark-results.json) that carries the same
    # number.  It was called "Delta", which reads as "change" and so inverts:
    # `regression = -pct_change`, and `pct_change` is positive when FASTER, so
    # a row 43% slower than its floor rendered as "+43.0%" under a heading a
    # reader takes to mean improvement.  Nothing in the report said otherwise.
    # The JSON sibling named the field honestly, so only the human-facing
    # artefact was ambiguous — which is the one a human reads.
    lines.append("## Results")
    lines.append("")
    lines.append(
        "*Regression is measured against the floor: **positive means SLOWER** "
        "than `baseline_value`, negative means faster. It is the same number as "
        "`regression_percent` in `benchmark-results.json`. The floor is a "
        "measured median on the runner class named in Provenance above, not a "
        "discount of this run, so the two hosts differ and a positive value "
        "within Tolerance is an ordinary result.*"
    )
    lines.append("")
    lines.append("| Primitive | Ops/sec | Baseline | Regression | Tolerance | Status |")
    lines.append("|-----------|--------:|---------:|-----------:|----------:|--------|")
    for r in results:
        status = "PASS" if r.passed else ("WARN" if r.optional else "**FAIL**")
        lines.append(
            f"| {r.description} | {r.ops_per_second:,.0f} | {r.baseline_value:,.0f} "
            f"| {r.regression_percent:+.1f}% | {r.tolerance_percent:.0f}% | {status} |"
        )
    lines.append("")

    # ASCII bar chart
    if results:
        lines.append("## Throughput Comparison")
        lines.append("")
        lines.append("```")
        max_ops = max(r.ops_per_second for r in results) if results else 1
        max_label = max(len(r.name) for r in results)
        bar_width = 40
        for r in results:
            bar_len = int((r.ops_per_second / max_ops) * bar_width) if max_ops > 0 else 0
            bar = "\u2588" * bar_len
            marker = " " if r.passed else " !"
            lines.append(f"{r.name:>{max_label}} |{marker}{bar} {r.ops_per_second:,.0f}")
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AMA Cryptography Benchmark Runner - Performance Regression Detection"
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path(__file__).parent / "baseline.json",
        help="Path to baseline.json file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Path to write JSON report",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--require-runner-class",
        default=os.environ.get("AMA_RUNNER_CPU_CLASS", ""),
        help=(
            "Require baseline metadata.runner_cpu_class to match this runner "
            "(defaults to AMA_RUNNER_CPU_CLASS when set)."
        ),
    )
    parser.add_argument(
        "--require-populated-baseline",
        action="store_true",
        help="Fail if any selected baseline_value is zero.",
    )
    parser.add_argument(
        "--markdown",
        type=Path,
        help="Path to write markdown report with tables and charts",
    )

    args = parser.parse_args()

    # Before anything is measured and before any output file is written, so
    # the recorded commit and cleanliness describe the tree the numbers came
    # from rather than the tree after this run edited it.
    global _TREE_STATE
    _TREE_STATE = capture_tree_state()

    print("=" * 60)
    print("AMA CRYPTOGRAPHY - BENCHMARK REGRESSION DETECTION")
    print("=" * 60)
    print()

    # Load baseline
    try:
        baseline = load_baseline(args.baseline)
        validate_baseline_contract(
            baseline,
            args.baseline,
            expected_runner_cpu_class=args.require_runner_class,
            require_populated_baseline=args.require_populated_baseline,
        )
        print(f"Loaded baseline: {args.baseline}")
        print(f"Regression threshold: {baseline['thresholds']['regression_threshold_percent']}%")
        print()
    except Exception as e:
        print(f"ERROR: Failed to load baseline: {e}")
        return 2

    # Run benchmarks
    print("Running benchmarks...")
    print("-" * 60)

    try:
        results = run_all_benchmarks(baseline, verbose=args.verbose)
    except Exception as e:
        print(f"ERROR: Benchmark execution failed: {e}")
        import traceback

        traceback.print_exc()
        return 2

    print("-" * 60)
    print()

    # Generate report
    report = generate_report(results)

    if args.output:
        # SERIALISE FIRST, then write.
        #
        # allow_nan=False: the default emits `Infinity` / `NaN`, which are not
        # JSON (RFC 8259).  A record a strict reader cannot parse is worse than
        # no record, and a non-finite throughput would clear every regression
        # floor it is compared against, so the write must fail rather than
        # produce one.
        #
        # `json.dump(...)` alone does not deliver that: it encodes
        # incrementally into the open file and raises PART WAY THROUGH, leaving
        # a truncated JSON file on disk.  Measured: a report whose first
        # benchmark carries an infinite rate left `{\n  "benchmarks": {\n
        # "widget": {\n      "ops_per_sec": ` behind, and a downstream step
        # that checks whether the artefact exists would call that a run.
        # `json.dumps` raises before the file is created.
        payload = json.dumps(report, indent=2, allow_nan=False)
        with open(args.output, "w") as f:
            f.write(payload)
        print(f"Report written to: {args.output}")

    if args.markdown:
        md = generate_markdown_report(results, report)
        with open(args.markdown, "w") as f:
            f.write(md)
        print(f"Markdown report written to: {args.markdown}")

    # Summary
    summary = report["summary"]
    print("SUMMARY")
    print(f"  Total benchmarks: {summary['total']}")
    print(f"  Passed: {summary['passed']}")
    print(f"  Failed: {summary['failed']}")
    print(f"  Warnings (optional): {summary['warnings']}")
    print()

    # Coverage, before verdicts.
    #
    # Every `continue` in run_all_benchmarks is silent to the exit code, so a
    # run that measured NOTHING printed "All benchmarks within acceptable
    # range" and returned 0.  Reproduced against a copy of the shipped baseline
    # with every key renamed — which passes --require-populated-baseline, since
    # that only rejects zero `baseline_value`s: 19 populated floors, 0
    # benchmarks measured, exit 0.  A gate in that state is green precisely
    # because it stopped checking.
    #
    # Two distinct losses are separated here because they mean different
    # things.  A baseline name with no function behind it is a RENAME: the
    # floor still sits in the JSON, is still justified, and can never fire
    # again.  That is a defect on any host, so it fails unconditionally.  A
    # name that has a function but produced no measurement is the documented
    # "primitive absent from this build" skip — legitimate on a developer
    # machine, and never true of the CI job, which is why it is fatal exactly
    # under --require-populated-baseline, the flag CI already passes to mean
    # "this run must be worth trusting".
    measured = {r.name for r in results}
    runnable = set(BENCHMARK_FUNCTIONS) | set(PQC_BENCHMARK_FUNCTIONS)
    requested = set(baseline.get("benchmarks", {})) | set(baseline.get("pqc_benchmarks", {}))

    orphaned = sorted(requested - runnable)
    if orphaned:
        print("BASELINE NAMES NOTHING THIS RUNNER CAN RUN!")
        print("-" * 60)
        for name in orphaned:
            print(f"  {name}: in the baseline, but no benchmark function has that name")
        print()
        print("Each of these floors is unenforceable: the run skips the name and")
        print("still exits 0. Rename the baseline entry to match the function, or")
        print("delete the entry if the benchmark is gone.")
        return 2

    if not results:
        print("NO BENCHMARK WAS MEASURED!")
        print("-" * 60)
        print(f"The baseline names {len(requested)} benchmark(s) and none of them ran, so")
        print("this run compared nothing against anything. That is not a pass.")
        return 2

    unmeasured = sorted(requested - measured)
    if unmeasured and args.require_populated_baseline:
        print("BASELINE ENTRIES WERE NOT MEASURED!")
        print("-" * 60)
        for name in unmeasured:
            print(f"  {name}: skipped — the primitive is absent from this build")
        print()
        print("--require-populated-baseline says this run must be worth trusting,")
        print("and a floor that was skipped cannot fire. Build with the backend")
        print("these benchmarks need, or drop --require-populated-baseline for a")
        print("local run that knowingly covers less.")
        return 2
    if unmeasured:
        print(
            f"NOTE: {len(unmeasured)} baseline entr(y/ies) not measured on this build: "
            f"{', '.join(unmeasured)}"
        )
        print()

    # Check for failures
    failed = [r for r in results if not r.passed and not r.optional]

    if failed:
        print("REGRESSION DETECTED!")
        print("-" * 60)
        for r in failed:
            print(f"  {r.name}: {r.regression_percent:+.1f}% (threshold: {r.tolerance_percent}%)")
        print()
        print("CI will fail due to performance regression.")
        return 1

    print("All benchmarks within acceptable range.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
