#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Performance regression gate on retired instruction counts.

What this replaces, and why
---------------------------
``benchmarks/baseline.json`` gates ``operations_per_second`` measured with
``time.perf_counter()`` on shared CI runners.  That lane cannot do its job,
and the repository already records why:

* ``benchmarks/benchmark_runner.py`` documents one UNCHANGED binary measuring
  917, 1845 and 3086 ops/sec across three runs — a 3.4x spread from nothing
  but host state.
* The x86 tolerances were widened to a uniform 45% so the gate would stop
  flapping.  A 45% band cannot detect a 30% regression, so the lane reports
  green through the regressions it exists to catch.
* Measured while building this gate, on one binary with all inputs fixed:
  ``sha3_256`` ran at 200,150-209,714 ops/sec idle and 99,478-125,248 ops/sec
  under six busy loops on four cores — a 2.1x swing with no code change.

Retired instruction count is a property of the binary and its input.  The same
four operations measured under that same load came back bit-identical to their
idle values — ``sha3_256`` 38,072, ``ed25519_sign`` 206,910, ``kyber_keygen``
744,872, ``dilithium_sign`` 8,290,768, zero variance.  That is what makes a 2%
threshold meaningful here where 45% was decoration there.  (Those are the
counts of the tree that experiment ran on.  ``ed25519_sign`` has since doubled
its fixed-base work under INVARIANT-51 and retires 332,907 on 5fdd02c; the
recorded baseline carries the current figure, and
``tests/test_instruction_count_gate.py`` holds it to the acknowledged head
values so it cannot fall behind again.)

This gate does not delete the wall-clock lane.  Instruction counts are blind
to cache behaviour, memory-level parallelism and real frequency effects, so
wall-clock still carries signal for catastrophic regressions.  It stops being
the precision instrument it was never able to be.

Two ways to run this gate
-------------------------
**A/B (what CI uses, and the stronger form).**  Measure the merge-base build
and the head build on the SAME runner in the same job, and compare them to
each other.  No stored baseline is involved, so nothing can go stale, and the
runner's CPU class cannot matter because both measurements came from it.
``ubuntu-latest`` spans two CPU classes about 1.45x apart; a stored baseline
would fail closed on whichever class did not record it, which is correct
behaviour producing a useless gate.  A/B has no such failure mode.

**Against the recorded baseline** (``benchmarks/instruction-baseline.json``).
Useful locally and as a documented reference point for what each operation
costs.  A measurement file is accepted directly in place of a baseline file,
so the two modes share one implementation.

Why the baseline is keyed by dispatch fingerprint
-------------------------------------------------
An AVX-512 host and an AVX2 host wire different kernels and legitimately
produce different counts.  The baseline therefore holds one profile per
dispatch configuration, and a configuration with no recorded profile is a
FAILURE rather than a comparison against whatever profile happened to be
first.  A gate that silently compares across configurations reports the
machine as a regression.

The fingerprint deliberately reports DETECTED hardware tiers, not the kernels
finally wired.  The distinction decides what this gate can catch.  A runtime
override that moves a slot off its SIMD kernel — ``AMA_DISPATCH_NO_CHACHA_AVX2``,
a failed ISA bundle check, an auto-tune demotion — leaves the fingerprint
unchanged, so the cheaper kernel shows up as a REGRESSION instead of being
excused as "a different machine".  Verified while building this gate: forcing
ChaCha20-Poly1305 off its AVX2 kernel moved it from 11,483 to 28,265 Ir and the
gate failed it at +146.15%.  Had the fingerprint tracked wired kernels, that
same change would have looked up a different profile and reported nothing.

Acknowledged changes
--------------------
A branch that deliberately changes what the library computes will move these
counts, and it should: this one moves 14 of 17 — Keccak gains an AVX2 kernel
(-66%), Ed25519 is rewritten (-9 to -22%), and ML-DSA signing moves to the
FIPS 204 external interface, which changes the rejection path (+146%).

Refusing to gate because the numbers move is how the wall-clock lane ended up
at 45%. Instead, an out-of-tolerance change passes only when
``benchmarks/instruction-count-acknowledgements.json`` records it WITH ITS
MEASURED VALUES and a reason, the same shape as
``benchmarks/check_baseline_justification.py`` requires of the wall-clock
floors. An acknowledgement is checked against the measurement, so it cannot
be written once and left to cover later drift: if the operation moves again,
the recorded ``to`` no longer matches and the gate fails.

An entry whose operation is within tolerance is classified by what the
REFERENCE measures, because that is what tells a change that never happened
from one that has already merged:

* the reference measures the entry's ``from`` — the acknowledged move is not
  in this comparison at all. That is a stale entry, and it FAILS.
* the reference measures the entry's ``to`` (and not its ``from``) — the
  change has LANDED: it is part of the reference build, so the comparison
  shows no move. This is the state of every entry on the first pull request
  after the branch that wrote it merges, and failing it would turn every
  unrelated pull request red until someone edited a file it never touched.
  A landed entry is reported by name and excuses nothing: it can only be
  landed while its operation is inside tolerance.
* the reference measures neither — the entry describes neither this
  comparison nor the reference it runs against. It FAILS.

So every entry in the file is checked against a measurement on every run and
stays a true statement about either the comparison or its reference; the
moment its operation moves again it must be re-measured or removed.

Fail-closed behaviour
---------------------
None of these is ever reported as a pass:

* the running configuration has no profile in the baseline;
* an operation in the baseline profile was not measured;
* an operation was measured but is absent from the baseline profile;
* nothing was compared.

Exit status
-----------
0  every operation is within tolerance of its baseline
1  at least one operation regressed, or the baseline and measurement disagree
   about which operations exist
2  the comparison could not be performed
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

#: Instruction counts are exactly reproducible, so this band exists only for
#: legitimate codegen drift — not for host noise, which is zero here.  The
#: wall-clock lane needs 45% for noise; this needs two orders of magnitude
#: less.  Drift has two sources.  One is a compiler version change.  The
#: other is whole-program LTO, the shipped configuration: the link
#: re-optimises every function in the context of the whole unit, so a change
#: in one translation unit can move the count of an operation whose sources
#: did not change.  Measured: e9956d7, a value barrier in the two AVX2
#: AES-GCM decrypt kernels, moved x25519_scalarmult by -3.2% under LTO and
#: by nothing with -DAMA_ENABLE_LTO=OFF (1,071,941 Ir on both sides).  Such
#: a move is acknowledged with its cause like any other; it is not a reason
#: to widen this band.
DEFAULT_TOLERANCE_PERCENT = 2.0


class GateError(RuntimeError):
    """The comparison could not be performed."""


def load_json(path: Path, what: str) -> dict[str, Any]:
    if not path.is_file():
        raise GateError(f"{what} {path} does not exist.")
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GateError(f"{what} {path} is not valid JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise GateError(f"{what} {path} must hold a JSON object.")
    return loaded


def select_profile(baseline: dict[str, Any], fingerprint: str) -> dict[str, int]:
    """The baseline profile for this dispatch configuration, or fail.

    A measurement document (``fingerprint`` + ``operations``, no ``profiles``)
    is accepted directly, which is what makes the A/B mode possible without a
    second code path.
    """
    if "profiles" not in baseline and "operations" in baseline:
        reference_fingerprint = str(baseline.get("fingerprint", ""))
        if reference_fingerprint and reference_fingerprint != fingerprint:
            raise GateError(
                f"the two measurements were taken under different dispatch "
                f"configurations, so their counts are not comparable:\n"
                f"    reference: {reference_fingerprint}\n"
                f"    current:   {fingerprint}\n"
                f"In A/B mode both builds must be measured on the same runner."
            )
        operations = baseline.get("operations")
        if not isinstance(operations, dict) or not operations:
            raise GateError("the reference measurement records no operations.")
        return {str(k): int(v) for k, v in operations.items()}

    profiles = baseline.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise GateError(
            "the baseline holds no 'profiles' object. A baseline with no "
            "profile cannot be compared against anything."
        )
    profile = profiles.get(fingerprint)
    if profile is None:
        known = "\n".join(f"    {key}" for key in sorted(profiles))
        raise GateError(
            f"no baseline profile for the running dispatch configuration:\n"
            f"    {fingerprint}\n"
            f"Recorded profiles:\n{known}\n"
            f"Counts from different kernels are not comparable, so this is a "
            f"failure rather than a comparison against another machine's "
            f"numbers. Record a profile for this configuration with "
            f"benchmarks/measure_instruction_counts.py."
        )
    operations = profile.get("operations")
    if not isinstance(operations, dict) or not operations:
        raise GateError(f"baseline profile {fingerprint} records no operations.")
    return {str(k): int(v) for k, v in operations.items()}


def load_acknowledgements(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    document = load_json(path, "acknowledgements")
    entries = document.get("acknowledgements")
    if not isinstance(entries, dict):
        raise GateError(f"{path} has no 'acknowledgements' object.")
    for operation, entry in entries.items():
        if not isinstance(entry, dict):
            raise GateError(f"acknowledgement for {operation} is not an object.")
        for field in ("from", "to", "reason"):
            if field not in entry:
                raise GateError(
                    f"acknowledgement for {operation} has no {field!r}. An "
                    f"acknowledgement without its measured values cannot be "
                    f"checked against the measurement, and one without a "
                    f"reason explains nothing."
                )
        reason = str(entry["reason"])
        if len(reason) < 40:
            raise GateError(
                f"acknowledgement for {operation} gives no real reason "
                f"({reason!r}). Name what changed and why the cost moved."
            )
    return {str(k): v for k, v in entries.items()}


def _within(actual: int, expected: int, tolerance_percent: float) -> bool:
    if expected <= 0:
        return False
    return abs(actual - expected) / expected * 100.0 <= tolerance_percent


def compare(
    baseline_ops: dict[str, int],
    measured_ops: dict[str, int],
    tolerance_percent: float,
    allow_subset: bool = False,
    acknowledgements: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[str], list[tuple[str, int, int, float]], int, list[str]]:
    """Returns (problems, rows, compared, landed).

    ``landed`` names the acknowledged operations whose change the reference
    already contains (see the module docstring).  They are never problems,
    and they never excuse a move: an operation is only landed while it is
    inside tolerance.
    """
    acknowledged = acknowledgements or {}
    problems: list[str] = []
    rows: list[tuple[str, int, int, float]] = []
    landed: list[str] = []

    missing = sorted(set(baseline_ops) - set(measured_ops))
    if not allow_subset:
        for operation in missing:
            problems.append(
                f"{operation} is in the baseline but was not measured. A gate "
                f"that skips an operation silently stops covering it."
            )
    unexpected = sorted(set(measured_ops) - set(baseline_ops))
    for operation in unexpected:
        problems.append(
            f"{operation} was measured but has no baseline. Record it with "
            f"benchmarks/measure_instruction_counts.py rather than leaving it "
            f"ungated."
        )

    compared = 0
    for operation in sorted(set(baseline_ops) & set(measured_ops)):
        expected = baseline_ops[operation]
        actual = measured_ops[operation]
        if expected <= 0:
            problems.append(f"{operation} has a non-positive baseline ({expected}).")
            continue
        delta_percent = (actual - expected) / expected * 100.0
        rows.append((operation, expected, actual, delta_percent))
        compared += 1
        entry = acknowledged.get(operation)
        if abs(delta_percent) > tolerance_percent:
            direction = "REGRESSED" if delta_percent > 0 else "IMPROVED"
            if entry is None:
                problems.append(
                    f"{operation} {direction}: baseline {expected:,} Ir, "
                    f"measured {actual:,} Ir ({delta_percent:+.2f}%, "
                    f"tolerance +/-{tolerance_percent}%) — not acknowledged. "
                    f"Record it in the acknowledgements file with its measured "
                    f"values and a reason, or fix the regression."
                )
            elif not _within(expected, int(entry["from"]), tolerance_percent):
                problems.append(
                    f"{operation} is acknowledged from {int(entry['from']):,} Ir "
                    f"but the reference measures {expected:,} Ir. The "
                    f"acknowledgement describes a different comparison."
                )
            elif not _within(actual, int(entry["to"]), tolerance_percent):
                problems.append(
                    f"{operation} is acknowledged at {int(entry['to']):,} Ir but "
                    f"measures {actual:,} Ir. It moved again after being "
                    f"acknowledged; re-measure and re-acknowledge."
                )
        elif entry is not None:
            ack_from, ack_to = int(entry["from"]), int(entry["to"])
            if _within(expected, ack_from, tolerance_percent):
                problems.append(
                    f"{operation} carries an acknowledgement but is within "
                    f"tolerance ({delta_percent:+.2f}%), and the reference still "
                    f"measures its 'from' ({ack_from:,} Ir), so the acknowledged "
                    f"move is not in this comparison. Remove the stale entry — "
                    f"a file of acknowledgements that no longer apply explains "
                    f"nothing and hides the ones that do."
                )
            elif _within(expected, ack_to, tolerance_percent):
                # The reference already contains the acknowledged change: the
                # branch that recorded the entry has merged into it.
                landed.append(operation)
            else:
                problems.append(
                    f"{operation} is acknowledged from {ack_from:,} Ir to "
                    f"{ack_to:,} Ir, but the reference measures {expected:,} Ir "
                    f"— neither value — and this comparison is within tolerance "
                    f"({delta_percent:+.2f}%). The entry describes neither this "
                    f"comparison nor its reference; remove the stale entry."
                )
    for operation in sorted(set(acknowledged) - set(baseline_ops) - set(measured_ops)):
        problems.append(
            f"{operation} is acknowledged but is not an operation in either " f"measurement."
        )
    return problems, rows, compared, landed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument(
        "--measured",
        required=True,
        type=Path,
        help="output of benchmarks/measure_instruction_counts.py --output",
    )
    parser.add_argument("--tolerance-percent", type=float, default=DEFAULT_TOLERANCE_PERCENT)
    parser.add_argument(
        "--acknowledgements",
        type=Path,
        help=(
            "JSON file recording intended instruction-count changes. An "
            "out-of-tolerance operation passes only if it is recorded there "
            "with matching measured values and a reason."
        ),
    )
    parser.add_argument(
        "--allow-subset",
        action="store_true",
        help=(
            "permit a measurement covering only some baselined operations. "
            "Off by default: in CI a silently shrinking set is how coverage "
            "disappears. An operation with no baseline still fails."
        ),
    )
    args = parser.parse_args(argv)

    if args.tolerance_percent < 0:
        print("FATAL: --tolerance-percent must not be negative.", file=sys.stderr)
        return 2

    try:
        baseline = load_json(args.baseline, "baseline")
        measured = load_json(args.measured, "measurement")

        fingerprint = measured.get("fingerprint")
        if not fingerprint:
            raise GateError(
                "the measurement records no dispatch fingerprint, so it cannot "
                "be matched to a baseline profile."
            )
        measured_ops_raw = measured.get("operations")
        if not isinstance(measured_ops_raw, dict) or not measured_ops_raw:
            raise GateError("the measurement records no operations.")

        not_reproducible = measured.get("not_reproducible") or {}
        if not_reproducible:
            raise GateError(
                "the measurement reported operations whose counts did not "
                "reproduce: " + ", ".join(sorted(not_reproducible)) + ". "
                "A non-reproducible count cannot be gated; fix the "
                "non-determinism rather than widening a threshold around it."
            )

        measured_ops = {str(k): int(v) for k, v in measured_ops_raw.items()}
        baseline_ops = select_profile(baseline, str(fingerprint))
    except GateError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2

    try:
        acknowledgements = load_acknowledgements(args.acknowledgements)
    except GateError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2

    problems, rows, compared, landed = compare(
        baseline_ops,
        measured_ops,
        args.tolerance_percent,
        args.allow_subset,
        acknowledgements,
    )

    print(f"Dispatch: {fingerprint}")
    print(f"Tolerance: +/-{args.tolerance_percent}%")
    if args.allow_subset:
        skipped = len(set(baseline_ops) - set(measured_ops))
        if skipped:
            print(f"Subset run: {skipped} baselined operation(s) not measured.")
    print()
    width = max((len(r[0]) for r in rows), default=10)
    for operation, expected, actual, delta in rows:
        if operation in landed:
            flag = "L"
        elif abs(delta) <= args.tolerance_percent:
            flag = " "
        elif operation in acknowledgements:
            flag = "A"
        else:
            flag = "!"
        print(
            f" {flag} {operation:<{width}}  {expected:>12,} -> {actual:>12,} " f"({delta:+6.2f}%)"
        )
    if landed:
        print(
            f"\nLanded (L): {len(landed)} acknowledgement(s) describe a change "
            f"the reference already contains — it measures their 'to' — so "
            f"there is no move to excuse: {', '.join(landed)}. They stay true "
            f"until the operation moves again and may be removed."
        )

    if problems:
        print(
            f"\nINSTRUCTION COUNT GATE FAILED — {len(problems)} problem(s):",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "\nInstruction counts are exactly reproducible on any host, so a "
            "difference here is a real change in the work the library does, "
            "not measurement noise.",
            file=sys.stderr,
        )
        return 1

    if compared == 0:
        print("FATAL: no operation was actually compared.", file=sys.stderr)
        return 2

    print(f"\nOK: {compared} operation(s) within +/-{args.tolerance_percent}% of baseline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
