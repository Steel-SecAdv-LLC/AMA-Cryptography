#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
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


def _load_baseline_at(ref: str) -> Dict[str, Dict]:
    """Return {primitive_name: entry_dict} merged from benchmarks + pqc_benchmarks
    sections, as they appeared at ``ref``. Missing file yields {}."""
    try:
        raw = _run_git("show", f"{ref}:{BASELINE_PATH}")
    except subprocess.CalledProcessError:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"ERROR: could not parse {BASELINE_PATH}@{ref}: {exc}", file=sys.stderr)
        sys.exit(2)
    merged: Dict[str, Dict] = {}
    for section in ("benchmarks", "pqc_benchmarks"):
        merged.update(data.get(section, {}))
    return merged


def _changed_baseline_values(
    before: Dict[str, Dict], after: Dict[str, Dict]
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
    BASELINE_PATH. We only inspect the commits that actually modified the
    file — unrelated commit messages would be noise.

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
            BASELINE_PATH,
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
             "when the body contains $, \", backticks, or backslashes.",
    )
    args = parser.parse_args(argv)

    if args.pr_body_file:
        if args.pr_body:
            print("ERROR: --pr-body and --pr-body-file are mutually exclusive.",
                  file=sys.stderr)
            return 2
        try:
            args.pr_body = Path(args.pr_body_file).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: could not read --pr-body-file: {exc}", file=sys.stderr)
            return 2

    try:
        before = _load_baseline_at(args.base_ref)
        after = _load_baseline_at(args.head_ref)
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: git show failed: {exc.stderr}", file=sys.stderr)
        return 2

    changes = _changed_baseline_values(before, after)
    if not changes:
        print(f"OK: {BASELINE_PATH} has no baseline_value changes in "
              f"{args.base_ref}..{args.head_ref}.")
        return 0

    print(f"Detected {len(changes)} baseline_value change(s):")
    for name, b, a in changes:
        print(f"  - {name}: {b!r} -> {a!r}")

    commit_text = _collect_commit_text(args.base_ref, args.head_ref)
    combined_text = commit_text + "\n\n" + (args.pr_body or "")

    failures = _check_justification(changes, combined_text)
    if failures:
        print("\n" + "=" * 72, file=sys.stderr)
        print("FAIL: baseline.json changes are missing required justification.",
              file=sys.stderr)
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

    print("\nOK: every changed baseline is named, a measurement value is "
          "cited, and a CI runner is identified.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
