#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Baseline.json change guard.

Purpose
-------
Enforce that every modification to `benchmarks/baseline.json` is accompanied,
in the PR's commit messages and/or PR body, by:

  1. A **line-item justification per primitive** — each primitive whose
     `baseline_value` changed must be mentioned by its JSON key.
  2. A **measured ops/sec (or latency) number** — at least one numeric
     measurement must appear in the justification text so reviewers can
     audit the new baseline against a reproducible measurement.
  3. A **CI-runner identifier** — the text must name the runner on which
     the measurement was produced (e.g. ``ubuntu-latest``, ``macos-14``,
     ``self-hosted``, ``benchmark_c_raw``, an explicit hardware string).

The goal is to prevent silent baseline adjustments that mask real
regressions (the pattern documented in
docs/BENCHMARK_HISTORY.md as commits `c9f4722` and `6b2cf82`).

Usage
-----
Runs in CI (`.github/workflows/baseline-guard.yml`) but is fully
reproducible locally::

    python benchmarks/check_baseline_justification.py \\
        --base-ref origin/main \\
        --head-ref HEAD \\
        --pr-body "$(cat /tmp/pr-body.md)"

Exit codes
----------
* 0 — baseline.json either unchanged, or all changes are justified.
* 1 — baseline.json changed but at least one requirement is unmet.
* 2 — internal error (bad refs, JSON parse failure, git unavailable).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

BASELINE_PATH = "benchmarks/baseline.json"

# Companion baseline produced by the ubuntu-24.04-arm matrix entry of
# the benchmark-regression CI job.  Changes to either file must carry
# justification: a silent NEON regression dropping AArch64 throughput
# 20% would otherwise be masked by editing only the AArch64 baseline.
ARM_BASELINE_PATH = "benchmarks/arm-baseline.json"

ALL_BASELINE_PATHS = (BASELINE_PATH, ARM_BASELINE_PATH)

# Regex for "<digits>[,_<digits>] ops/sec" or "... ops/s" or "... us" / "... ms"
# latencies. Case-insensitive, tolerates commas/underscores in numbers.
_MEASUREMENT_RE = re.compile(
    r"\b\d[\d,_]*(?:\.\d+)?\s*(?:ops\s*/\s*(?:sec|s)\b|µs\b|us\b|ms\b|ns\b)",
    re.IGNORECASE,
)

# Tokens that plausibly identify a CI runner or measurement harness.
# Keeping this list explicit (not a catch-all) so the check fails on
# vague prose like "measured on our server".
_RUNNER_TOKENS = (
    "ubuntu-latest",
    "ubuntu-24.04",
    "ubuntu-22.04",
    "ubuntu-20.04",
    "macos-latest",
    "macos-14",
    "macos-13",
    "macos-12",
    "windows-latest",
    "self-hosted",
    "benchmark_c_raw",
    "benchmark_runner",
    "github actions",
    "x86_64",
    "x86-64",
    "aarch64",
    "arm64",
)


def _run_git(*args: str) -> str:
    result = subprocess.run(
        ("git", *args),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _load_baseline_at(ref: str, path: str = BASELINE_PATH) -> Dict[str, Dict[str, object]]:
    """Return {primitive_name: entry_dict} merged from benchmarks + pqc_benchmarks
    sections, as they appeared at ``ref``. Missing file yields {}."""
    try:
        raw = _run_git("show", f"{ref}:{path}")
    except subprocess.CalledProcessError:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"ERROR: could not parse {path}@{ref}: {exc}", file=sys.stderr)
        sys.exit(2)
    merged: Dict[str, Dict[str, object]] = {}
    for section in ("benchmarks", "pqc_benchmarks"):
        merged.update(data.get(section, {}))
    return merged


def _changed_baseline_values(
    before: Dict[str, Dict[str, object]], after: Dict[str, Dict[str, object]]
) -> List[Tuple[str, object, object]]:
    """Return [(name, before_value, after_value)] for every primitive whose
    ``baseline_value`` differs between the two snapshots. Includes adds and
    removes so a silent entry deletion is also flagged."""
    changes: List[Tuple[str, object, object]] = []
    keys = set(before) | set(after)
    for name in sorted(keys):
        b = before.get(name, {}).get("baseline_value")
        a = after.get(name, {}).get("baseline_value")
        if b != a:
            changes.append((name, b, a))
    return changes


def _collect_commit_text(base_ref: str, head_ref: str) -> str:
    """Concatenate every commit message in ``base_ref..head_ref`` that touches
    a baseline JSON (x86 or arm).  We only inspect the commits that
    actually modified one of the baseline files — unrelated commit
    messages would be noise.

    A shallow clone or an unreachable base ref yields a CalledProcessError
    from git; return an empty string in that case so the check falls back
    to requiring the full justification to live in the PR body.
    """
    try:
        return _run_git(
            "log",
            f"{base_ref}..{head_ref}",
            "--pretty=format:%H%n%B%n---END-COMMIT---",
            "--",
            *ALL_BASELINE_PATHS,
        )
    except subprocess.CalledProcessError as exc:
        print(
            f"WARN: `git log {base_ref}..{head_ref}` failed "
            f"({exc.stderr.strip() or 'no stderr'}); falling back to "
            "PR body only for justification scanning. This usually means "
            "the clone is shallow — CI should use fetch-depth: 0.",
            file=sys.stderr,
        )
        return ""


def _check_justification(
    changes: List[Tuple[str, object, object]],
    combined_text: str,
) -> List[str]:
    """Return a list of human-readable failures (empty list = all good)."""
    failures: List[str] = []

    if not _MEASUREMENT_RE.search(combined_text):
        failures.append(
            "No measurement value found. The justification must cite at "
            "least one numeric reading (e.g. '12,450 ops/sec', '62 us', "
            "'0.45 ms')."
        )

    lower = combined_text.lower()
    if not any(tok in lower for tok in _RUNNER_TOKENS):
        failures.append(
            "No CI-runner identifier found. The justification must name the "
            "runner where the measurement was produced (one of: "
            + ", ".join(sorted(_RUNNER_TOKENS))
            + ")."
        )

    unmentioned = [name for (name, _b, _a) in changes if name not in combined_text]
    if unmentioned:
        failures.append(
            "The following primitives had `baseline_value` changes but were "
            "not mentioned by name in any commit message or the PR body:\n"
            + "\n".join(f"  - {n}" for n in unmentioned)
            + "\nAdd a line-item entry for each in the commit message or "
            "PR body so a reviewer can audit the new number."
        )

    return failures


def _load_metadata_at(ref: str, path: str) -> Dict[str, object]:
    """``metadata`` from a baseline file as it appeared at ``ref``."""
    try:
        raw = _run_git("show", f"{ref}:{path}")
    except subprocess.CalledProcessError:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    meta = data.get("metadata", {})
    return meta if isinstance(meta, dict) else {}


#: Widest release component accepted, so a malformed field cannot become a
#: pathological input. Four digits covers any plausible major/minor/patch.
_MAX_RELEASE_COMPONENT_DIGITS = 4


def _release_tuple(value: object) -> Tuple[int, ...] | None:
    """Parse ``"X.Y.Z"`` into a comparable tuple, or ``None`` if malformed.

    Split-and-validate rather than ``re.fullmatch(r"(\\d+)\\.(\\d+)\\.(\\d+)")``.
    That pattern is three unbounded quantifiers separated by literals, which is
    the shape CodeQL reports as a polynomial ReDoS: measured here at 4.2x per
    doubling of input length, 1,545 ms on a 16,000-character run. The value
    parsed is a field out of a JSON file in this repository rather than
    anything a remote party supplies, so the exposure is small — but a version
    parser has no need of a regex at all, and "the input happens to be trusted
    today" is a weaker guarantee than not being quadratic.

    ``str.isdigit`` is true for non-ASCII digits (Arabic-Indic, and others),
    which ``int()`` would then happily accept, so the ASCII check is not
    redundant: a release string is defined over ASCII.
    """
    if not isinstance(value, str):
        return None
    parts = value.strip().split(".")
    if len(parts) != 3:
        return None
    if not all(
        0 < len(p) <= _MAX_RELEASE_COMPONENT_DIGITS and p.isascii() and p.isdigit() for p in parts
    ):
        return None
    return tuple(int(p) for p in parts)


def _check_validity_window(base_ref: str, head_ref: str) -> List[str]:
    """Refuse to extend a baseline's validity window without re-measuring it.

    ``tests/test_benchmark_baseline_freshness.py`` fails once the package
    version passes a baseline's ``applies_through_release``.  It has one
    escape: bumping that field is itself a way to satisfy it.  Nothing
    required the floors to be re-measured first, so the cheapest way to make
    the freshness test green was to declare the stale floors valid for longer.

    That is not hypothetical.  ``arm-baseline.json`` carries
    ``baseline_source_release: 3.1.0`` against ``applies_through_release:
    4.0.0`` — floors measured nine minor releases before the window they are
    declared valid for — and its own ``notes`` record that the 2026-07-29
    recalibration skipped AArch64 because no hardware was available.  The
    freshness gate passed throughout.

    So the window may move only in a commit that also moves the measurements:
    at least one ``baseline_value`` changed, or ``baseline_source_release``
    advanced.  Historical state is untouched — this is a rule about the diff,
    so it constrains the next extension rather than retroactively failing the
    current files.
    """
    failures: List[str] = []
    for path in ALL_BASELINE_PATHS:
        before_meta = _load_metadata_at(base_ref, path)
        after_meta = _load_metadata_at(head_ref, path)
        if not before_meta or not after_meta:
            continue

        old_through = _release_tuple(before_meta.get("applies_through_release"))
        new_through = _release_tuple(after_meta.get("applies_through_release"))
        if old_through is None or new_through is None or new_through <= old_through:
            continue

        old_source = _release_tuple(before_meta.get("baseline_source_release"))
        new_source = _release_tuple(after_meta.get("baseline_source_release"))
        source_advanced = (
            old_source is not None and new_source is not None and new_source > old_source
        )
        before_vals = _load_baseline_at(base_ref, path)
        after_vals = _load_baseline_at(head_ref, path)
        values_changed = bool(_changed_baseline_values(before_vals, after_vals))

        if not (source_advanced or values_changed):
            failures.append(
                f"{path}: applies_through_release moved "
                f"{before_meta.get('applies_through_release')!r} -> "
                f"{after_meta.get('applies_through_release')!r}, but no floor was "
                f"re-measured — no baseline_value changed and "
                f"baseline_source_release is still "
                f"{after_meta.get('baseline_source_release')!r}.\n"
                f"  Extending the window is how the freshness test in "
                f"tests/test_benchmark_baseline_freshness.py gets satisfied, so "
                f"extending it without re-measuring turns that test into a "
                f"formality: the floors keep describing an older tree and the "
                f"regression gate keeps passing because it cannot fail.\n"
                f"  Re-measure on the canonical runner for this file, update the "
                f"floors and baseline_source_release, and record the measurement "
                f"in metadata.baseline_change_log."
            )
    return failures


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-ref",
        default="origin/main",
        help="Base git ref to compare against (default: origin/main).",
    )
    parser.add_argument(
        "--head-ref",
        default="HEAD",
        help="Head git ref (default: HEAD).",
    )
    parser.add_argument(
        "--pr-body",
        default="",
        help="Optional PR body text, appended to the commit log for "
        "justification scanning. Mutually exclusive with "
        "--pr-body-file.",
    )
    parser.add_argument(
        "--pr-body-file",
        default=None,
        help="Path to a file containing the PR body. Preferred over "
        "--pr-body in CI because it avoids shell-quoting hazards "
        'when the body contains $, ", backticks, or backslashes.',
    )
    args = parser.parse_args(argv)

    if args.pr_body_file:
        if args.pr_body:
            print("ERROR: --pr-body and --pr-body-file are mutually exclusive.", file=sys.stderr)
            return 2
        try:
            args.pr_body = Path(args.pr_body_file).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: could not read --pr-body-file: {exc}", file=sys.stderr)
            return 2

    try:
        per_path_changes: List[Tuple[str, List[Tuple[str, object, object]]]] = []
        for path in ALL_BASELINE_PATHS:
            before_p = _load_baseline_at(args.base_ref, path)
            after_p = _load_baseline_at(args.head_ref, path)
            ch_p = _changed_baseline_values(before_p, after_p)
            if ch_p:
                per_path_changes.append((path, ch_p))
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: git show failed: {exc.stderr}", file=sys.stderr)
        return 2

    try:
        window_failures = _check_validity_window(args.base_ref, args.head_ref)
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: git show failed: {exc.stderr}", file=sys.stderr)
        return 2
    if window_failures:
        print("\n" + "=" * 72, file=sys.stderr)
        print(
            "FAIL: a baseline validity window was extended without re-measuring.", file=sys.stderr
        )
        print("=" * 72, file=sys.stderr)
        for msg in window_failures:
            print("\n" + msg, file=sys.stderr)
        return 1

    if not per_path_changes:
        print(
            f"OK: {' / '.join(ALL_BASELINE_PATHS)} have no baseline_value "
            f"changes in {args.base_ref}..{args.head_ref}."
        )
        return 0

    changes: List[Tuple[str, object, object]] = []
    for path, ch_p in per_path_changes:
        print(f"Detected {len(ch_p)} baseline_value change(s) in {path}:")
        for name, b, a in ch_p:
            print(f"  - {name}: {b!r} -> {a!r}")
        changes.extend(ch_p)

    commit_text = _collect_commit_text(args.base_ref, args.head_ref)
    combined_text = commit_text + "\n\n" + (args.pr_body or "")

    failures = _check_justification(changes, combined_text)
    if failures:
        print("\n" + "=" * 72, file=sys.stderr)
        print(
            "FAIL: benchmark baseline JSON changes are missing required justification.",
            file=sys.stderr,
        )
        print("=" * 72, file=sys.stderr)
        for msg in failures:
            print("\n" + msg, file=sys.stderr)
        print(
            "\nSee benchmarks/check_baseline_justification.py for the full "
            "contract and docs/BENCHMARK_HISTORY.md for why this guard "
            "exists.",
            file=sys.stderr,
        )
        return 1

    print(
        "\nOK: every changed baseline is named, a measurement value is "
        "cited, and a CI runner is identified."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
