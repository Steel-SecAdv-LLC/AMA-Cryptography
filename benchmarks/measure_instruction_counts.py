#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Measure retired instructions per cryptographic operation, reproducibly.

Why a second performance gate
-----------------------------
``benchmarks/baseline.json`` gates on ``operations_per_second`` from
``time.perf_counter()`` on a shared CI runner.  ``benchmark_runner.py``'s own
docstring records one UNCHANGED binary measuring 917, 1845 and 3086 ops/sec
across three runs.  The tolerances were widened to 45% so the gate would stop
flapping, and a 45% band cannot detect a 30% regression.  That lane measures
the runner fleet; it cannot measure this library.

Retired instruction count under callgrind is a property of the binary and its
input.  Same build, same input, same number — under load, on a quiet host, or
on a different CPU.  A 2% threshold is meaningful where 45% was decoration.

The difference method
---------------------
Per-operation cost is::

    (Ir(2N) - Ir(N)) / N

Process start-up, dynamic loading, key setup and dispatcher initialisation all
appear in both terms and cancel exactly, rather than being estimated and
subtracted.  Nothing has to be assumed about what the harness costs.

Auto-tune must be off, and this tool enforces it
------------------------------------------------
``AMA_DISPATCH_NO_AUTOTUNE=1`` is set for every child process here, and it is
not a tuning preference.  The dispatcher microbenchmarks each SIMD kernel
against its scalar reference at first use and demotes a slot that reads
slower; the verdict depends on host load, so with auto-tune live the process
executes DIFFERENT CODE between runs and no count reproduces.

Measured on an AVX-512 host (avx512f/bw/cd/dq/ifma/vbmi/vl, vaes,
vpclmulqdq), first ``ama_sha3_256`` call:

===================  ===============
auto-tune live       2,601,289,188 Ir
auto-tune disabled          632,977 Ir
===================  ===============

The auto-tune costs 2,600,710,540 instructions.  The operation it is tuning
costs 53,664.

Reproducibility is measured, not assumed
----------------------------------------
Every operation is measured three times end to end and its observed SPREAD is
recorded alongside the count.  Most operations reproduce exactly — spread 0.
Some carry a small intrinsic jitter: ML-KEM encapsulation draws a random
message by design and has no derandomised entry point in the public API, and
it was observed to move by 5 instructions in 804,598 (6 ppm).

A binary exact/not-exact rule would refuse to baseline that operation and
leave it ungated, which is worse than gating it at a 2% threshold 3,000 times
wider than its jitter.  So the rule is proportionate: an operation reproduces
if its spread is within ``--jitter-budget-percent`` (default 0.1%, twenty
times tighter than the gate's own 2% tolerance), and the measured spread is
written to the baseline so a reviewer can see which operations are exact and
which merely bounded.

An operation whose spread exceeds the budget is still reported and still kept
out of the baseline.  That is the case the loud failure is for: a cost that
depends on sampled or secret data cannot be gated on a fixed count, and
recording one anyway produces a gate that fails at random.

Exit status
-----------
0  every requested operation measured and reproduced
1  at least one operation did not reproduce
2  the measurement could not be performed
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

#: callgrind prints e.g. "==1234== Collected : 2,601,289,188" and a final
#: "refs: 2,601,289,188" line.  The latter is the total retired instruction
#: count and is what this tool reads.
_REFS_RE = re.compile(r"refs:\s+([\d,]+)")

#: Without this the dispatcher's auto-tune runs and the count stops being a
#: property of the binary.  See the module docstring.
_REQUIRED_ENV = {"AMA_DISPATCH_NO_AUTOTUNE": "1"}

DEFAULT_ITERATIONS = 20

#: An operation must reproduce this closely to be baselined.  Twenty times
#: tighter than the gate's own default tolerance, so intrinsic jitter can
#: never account for a gate failure.
DEFAULT_JITTER_BUDGET_PERCENT = 0.1

#: Measurements per operation.  Two can only say "same or different"; three
#: gives an observed spread to record and to compare against the budget.
SAMPLES_PER_OPERATION = 3


class MeasurementError(RuntimeError):
    """The measurement could not be performed at all."""


def _child_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update(_REQUIRED_ENV)
    return env


def retired_instructions(driver: Path, operation: str, iterations: int) -> int:
    """Total retired instructions for one driver run, under callgrind."""
    command = [
        "valgrind",
        "--tool=callgrind",
        "--callgrind-out-file=/dev/null",
        str(driver),
        operation,
        str(iterations),
    ]
    completed = subprocess.run(
        command, capture_output=True, text=True, env=_child_env(), check=False
    )
    if completed.returncode != 0:
        raise MeasurementError(
            f"{operation} at {iterations} iterations exited {completed.returncode}:\n"
            f"{completed.stderr[-2000:]}"
        )
    match = _REFS_RE.search(completed.stderr)
    if not match:
        raise MeasurementError(
            f"callgrind printed no 'refs:' total for {operation}. "
            f"stderr tail:\n{completed.stderr[-2000:]}"
        )
    return int(match.group(1).replace(",", ""))


def measure_operation(driver: Path, operation: str, iterations: int) -> int:
    """Instructions for ONE execution of ``operation``, harness cost removed."""
    at_n = retired_instructions(driver, operation, iterations)
    at_2n = retired_instructions(driver, operation, iterations * 2)
    delta = at_2n - at_n
    if delta <= 0:
        raise MeasurementError(
            f"{operation}: Ir(2N)={at_2n:,} is not greater than Ir(N)={at_n:,}. "
            f"The loop is being optimised away or the driver is not running it."
        )
    if delta % iterations:
        # Not fatal, but the caller should know the division is inexact.
        pass
    return delta // iterations


def dispatch_fingerprint(driver: Path) -> str:
    """The active dispatch configuration, as the baseline's lookup key.

    A count measured with AVX-512 kernels wired is not comparable to one
    measured with AVX2 kernels, so the baseline records a separate profile per
    configuration and the gate refuses to compare across them.
    """
    completed = subprocess.run(
        [str(driver), "--fingerprint"],
        capture_output=True,
        text=True,
        env=_child_env(),
        check=False,
    )
    if completed.returncode != 0:
        raise MeasurementError(f"{driver} --fingerprint failed: {completed.stderr}")
    fingerprint = completed.stdout.strip()
    if not fingerprint:
        raise MeasurementError(f"{driver} --fingerprint printed nothing")
    return fingerprint


def list_operations(driver: Path) -> list[str]:
    completed = subprocess.run([str(driver), "--list"], capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise MeasurementError(f"{driver} --list failed: {completed.stderr}")
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", required=True, type=Path, help="ic_driver binary")
    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"N in the difference method (default {DEFAULT_ITERATIONS})",
    )
    parser.add_argument(
        "--jitter-budget-percent",
        type=float,
        default=DEFAULT_JITTER_BUDGET_PERCENT,
        help=(
            "maximum spread across repeated measurements for an operation to "
            f"be baselined (default {DEFAULT_JITTER_BUDGET_PERCENT}%%)"
        ),
    )
    parser.add_argument(
        "--operations",
        nargs="*",
        help="operations to measure (default: everything the driver lists)",
    )
    parser.add_argument("--output", type=Path, help="write measurements here as JSON")
    args = parser.parse_args(argv)

    if shutil.which("valgrind") is None:
        print(
            "FATAL: valgrind is not installed. Instruction counts cannot be "
            "measured, and an unmeasured gate must not report success.",
            file=sys.stderr,
        )
        return 2
    if not args.driver.is_file():
        print(f"FATAL: driver {args.driver} does not exist.", file=sys.stderr)
        return 2
    if args.iterations < 1:
        print("FATAL: --iterations must be >= 1.", file=sys.stderr)
        return 2

    try:
        fingerprint = dispatch_fingerprint(args.driver)
        operations = args.operations or list_operations(args.driver)
    except MeasurementError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2
    if not operations:
        print("FATAL: no operations to measure.", file=sys.stderr)
        return 2

    measurements: dict[str, int] = {}
    non_deterministic: dict[str, tuple[int, int]] = {}
    failures: dict[str, str] = {}

    width = max(len(name) for name in operations)
    print(
        f"Measuring {len(operations)} operation(s), N={args.iterations}, "
        f"difference method, auto-tune disabled."
    )
    print(f"Dispatch: {fingerprint}\n")

    spreads: dict[str, int] = {}

    for operation in operations:
        try:
            samples = [
                measure_operation(args.driver, operation, args.iterations)
                for _ in range(SAMPLES_PER_OPERATION)
            ]
        except MeasurementError as exc:
            failures[operation] = str(exc)
            print(f"  {operation:<{width}}  ERROR")
            continue

        low, high = min(samples), max(samples)
        spread_absolute = high - low
        spread_percent = (spread_absolute / high * 100.0) if high else 0.0

        if spread_percent > args.jitter_budget_percent:
            non_deterministic[operation] = (low, high)
            print(
                f"  {operation:<{width}}  OVER JITTER BUDGET "
                f"{low:,}..{high:,}  ({spread_percent:.4f}%)"
            )
            continue

        # Median of three: robust to a single outlier, and an exact
        # reproduction makes all three equal so the choice is moot.
        baseline_value = sorted(samples)[1]
        measurements[operation] = baseline_value
        spreads[operation] = spread_absolute
        note = "exact" if spread_absolute == 0 else f"+/-{spread_absolute} Ir"
        print(f"  {operation:<{width}}  {baseline_value:>12,} Ir   ({note})")

    if failures:
        print("\nOperations that could not be measured:", file=sys.stderr)
        for operation, reason in failures.items():
            print(f"  - {operation}: {reason.splitlines()[0]}", file=sys.stderr)

    if non_deterministic:
        print(
            f"\nOperations whose spread exceeded the "
            f"{args.jitter_budget_percent}% jitter budget:",
            file=sys.stderr,
        )
        for operation, (low, high) in non_deterministic.items():
            print(f"  - {operation}: {low:,} .. {high:,}", file=sys.stderr)
        print(
            "\nThese are NOT written to the baseline. A cost that depends on "
            "sampled or secret data cannot be gated on a fixed count, and "
            "recording one anyway would produce a gate that fails at random.",
            file=sys.stderr,
        )

    if args.output:
        document = {
            "_comment": (
                "Retired instructions per operation, measured by "
                "benchmarks/measure_instruction_counts.py with the difference "
                "method and AMA_DISPATCH_NO_AUTOTUNE=1. A property of the "
                "binary and its input, not of the host that measured it."
            ),
            "measured_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "iterations": args.iterations,
            "method": "(Ir(2N) - Ir(N)) / N under callgrind",
            "dispatch": dict(_REQUIRED_ENV),
            "fingerprint": fingerprint,
            "jitter_budget_percent": args.jitter_budget_percent,
            "operations": dict(sorted(measurements.items())),
            "observed_spread_ir": dict(sorted(spreads.items())),
        }
        if non_deterministic:
            document["not_reproducible"] = {
                operation: list(pair) for operation, pair in sorted(non_deterministic.items())
            }
        args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        print(f"\nWrote {len(measurements)} measurement(s) to {args.output}")

    if failures or non_deterministic:
        return 1
    if not measurements:
        print("FATAL: nothing was measured.", file=sys.stderr)
        return 2
    exact = sum(1 for value in spreads.values() if value == 0)
    print(
        f"\nOK: {len(measurements)} operation(s) measured; {exact} reproduced "
        f"exactly, {len(measurements) - exact} within the "
        f"{args.jitter_budget_percent}% jitter budget."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
