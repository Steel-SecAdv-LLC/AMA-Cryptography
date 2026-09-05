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
from typing import Dict, List, Set, Tuple

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
    effective floor moved between the two snapshots.  Includes adds and
    removes so a silent entry deletion is also flagged.

    ``tolerance_percent`` is watched with the same weight as
    ``baseline_value``, because the runner's verdict is
    ``regression <= tolerance`` (benchmark_runner.run_all_benchmarks): the
    tolerance is exactly as load-bearing as the floor, and this gate used to
    read only the floor — so cutting ``dilithium_sign``'s ARM floor from
    3316 to 2653 demanded a named, measured, runner-identified line item,
    while raising its ``tolerance_percent`` from 25 to 40 produced the same
    2487 ops/sec effective minimum and printed ``OK: … no baseline_value
    changes``.  Nothing else in the tree watches the field.  A tolerance
    change is reported as its own pseudo-entry so the failure message names
    what actually moved."""
    changes: List[Tuple[str, object, object]] = []
    keys = set(before) | set(after)
    for name in sorted(keys):
        b = before.get(name, {}).get("baseline_value")
        a = after.get(name, {}).get("baseline_value")
        if b != a:
            changes.append((name, b, a))
        b_tol = before.get(name, {}).get("tolerance_percent")
        a_tol = after.get(name, {}).get("tolerance_percent")
        if b_tol != a_tol:
            changes.append((f"{name} tolerance_percent", b_tol, a_tol))
    return changes


def _commit_parents(sha: str) -> List[str]:
    """The parents of ``sha``.  Empty for a root commit."""
    try:
        line = _run_git("rev-list", "--parents", "-n", "1", sha).strip()
    except subprocess.CalledProcessError:
        return []
    return line.split()[1:]


def _commits_touching_baselines(base_ref: str, head_ref: str) -> List[str]:
    """SHAs in ``base_ref..head_ref`` that modified a baseline JSON, oldest first."""
    return _run_git(
        "log",
        "--reverse",
        "--pretty=format:%H",
        f"{base_ref}..{head_ref}",
        "--",
        *ALL_BASELINE_PATHS,
    ).split()


def _commit_message(sha: str) -> str:
    return _run_git("log", "-1", "--pretty=format:%B", sha)


def _values_at(ref: str) -> Dict[str, object]:
    """Every ``baseline_value`` visible at ``ref``, keyed ``path::primitive``.

    Keyed by path as well as name because the two baselines carry the same
    nineteen primitives with different numbers; merging them would let a change
    in one file be cancelled by the other.
    """
    out: Dict[str, object] = {}
    for path in ALL_BASELINE_PATHS:
        for name, entry in _load_baseline_at(ref, path).items():
            out[f"{path}::{name}"] = entry.get("baseline_value")
            # The tolerance under the same attribution rules as the floor:
            # the runner's verdict is `regression <= tolerance`, so a
            # tolerance raise IS a floor cut, and it must be attributable to
            # the single commit whose value stands.  The pseudo-name matches
            # the entries _changed_baseline_values emits for it.
            out[f"{path}::{name} tolerance_percent"] = entry.get("tolerance_percent")
    return out


def _changes_introduced_by(sha: str) -> Set[str]:
    """The ``path::primitive`` keys whose ``baseline_value`` THIS commit changed.

    A merge counts only what it introduces itself: a key qualifies when it
    differs from EVERY parent, so a floor merged in from the base branch is
    attributed to the commit that actually wrote it and not to the merge that
    carried it past.
    """
    parents = _commit_parents(sha)
    after = _values_at(sha)
    if not parents:
        return {k for k, v in after.items() if v is not None}
    befores = [_values_at(parent) for parent in parents]
    return {
        key for key, value in after.items() if all(before.get(key) != value for before in befores)
    } | {key for before in befores for key in before if key not in after}


def _text_justifies(text: str, primitive: str) -> bool:
    """One text is a line-item justification for one primitive.

    All three requirements must hold in the SAME text.  Splitting them across
    texts is exactly the hole this replaced: see the module docstring.

    The name must appear as a whole identifier, not a substring: with a bare
    ``in``, ``x25519_scalarmult`` was justified by any text that named only
    ``x25519_scalarmult_batch4`` — one primitive's line item silently
    covering its differently-floored sibling.  A pseudo-name like
    ``foo tolerance_percent`` (emitted by _changed_baseline_values for a
    tolerance move) is justified by prose that names BOTH identifiers
    anywhere in the same text — "tolerances become derived ... foo:
    12,450 ops/sec on ubuntu-latest" reads naturally; requiring the two
    words adjacent would make the rule unpayable by any real message.
    """

    def _named(identifier: str) -> bool:
        pattern = r"(?<![A-Za-z0-9_])" + re.escape(identifier) + r"(?![A-Za-z0-9_])"
        return re.search(pattern, text) is not None

    return (
        all(_named(part) for part in primitive.split())
        and bool(_MEASUREMENT_RE.search(text))
        and any(token in text.lower() for token in _RUNNER_TOKENS)
    )


def _check_justification_attributed(
    base_ref: str,
    head_ref: str,
    net_changes: List[Tuple[str, str, object, object]],
    pr_body: str,
) -> List[str]:
    """Require each net change to be justified by text that ACCOUNTS for it.

    ``net_changes`` is [(path, primitive, before, after)].  A change is
    justified when a single text -- the PR body, or the message of a commit
    that actually moved that number -- names the primitive, cites a
    measurement, and identifies a runner.  Commit messages from elsewhere in
    the branch do not count, which is the whole point.
    """
    failures: List[str] = []
    try:
        shas = _commits_touching_baselines(base_ref, head_ref)
    except subprocess.CalledProcessError as exc:
        return [
            "Could not list the commits that changed a baseline JSON "
            f"({exc.stderr.strip() or 'no stderr'}), so no change could be "
            "attributed to the commit that made it. This usually means a "
            "shallow clone; CI must use fetch-depth: 0. Put the full "
            "justification in the PR body, or fix the checkout."
        ]

    # key -> the LAST commit that moved it, which is the one whose value stands.
    #
    # Not "any commit that ever touched it".  An earlier commit justified the
    # number it wrote, and a later commit that moves the same floor again is a
    # new claim needing its own evidence -- measured: with `any`, a "wip"
    # commit halving ed25519_sign still passed, riding on the recalibration
    # commit that had set the previous value and named the primitive.
    attributed: Dict[str, Tuple[str, str]] = {}
    for sha in shas:
        try:
            keys = _changes_introduced_by(sha)
        except subprocess.CalledProcessError:
            continue
        if not keys:
            continue
        message = _commit_message(sha)
        for key in keys:
            attributed[key] = (sha, message)

    for path, name, before, after in net_changes:
        key = f"{path}::{name}"
        if _text_justifies(pr_body, name):
            continue
        source = attributed.get(key)
        if source is not None and _text_justifies(source[1], name):
            continue
        if source is None:
            failures.append(
                f"{path}: `{name}` moved {before!r} -> {after!r}, but no commit "
                f"in {base_ref}..{head_ref} accounts for it (it may have arrived "
                f"through a merge). Justify it in the PR body: name it, cite a "
                f"measured number, and identify the runner."
            )
            continue
        failures.append(
            f"{path}: `{name}` moved {before!r} -> {after!r}, last written by "
            f"{source[0][:8]}, and "
            f"neither that commit's message nor the PR body is a line-item "
            f"justification for it -- one single text must name `{name}`, cite "
            f"a measured number, AND identify the runner. Justification "
            f"scattered across other commits on this branch does not count: "
            f"the guard used to concatenate every commit message on the branch, "
            f"which on a long branch made the requirement unfalsifiable."
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


#: Paths whose contents the published floors describe.  A change under any of
#: them after the calibration commit means the floors and the shipped code have
#: drifted apart, whatever the change log asserts.
_FLOORED_CODE_PATHS = ("src/c", "include", "ama_cryptography", "benchmarks/benchmark_runner.py")

#: Extracts the commit from a calibration_evidence run entry, which records
#: ``"<counter> (<commit>, <class>)"``.
_CALIBRATION_COMMIT_RE = re.compile(r"\(([0-9a-f]{7,40})[,)]")


def _calibration_commit(metadata: Dict[str, object]) -> str | None:
    """The newest commit named in ``metadata.calibration_evidence.runs``."""
    evidence = metadata.get("calibration_evidence")
    if not isinstance(evidence, dict):
        return None
    runs = evidence.get("runs")
    if not isinstance(runs, dict) or not runs:
        return None

    # Keys are p1, p3, p4, p5...: take the highest-numbered, which is the last
    # calibration pass and therefore the tree the floors actually describe.
    def _pass_number(key: str) -> int:
        digits = "".join(ch for ch in key if ch.isdigit())
        return int(digits) if digits else -1

    latest = max(runs, key=_pass_number)
    value = runs[latest]
    if not isinstance(value, str):
        return None
    match = _CALIBRATION_COMMIT_RE.search(value)
    return match.group(1) if match else None


def _floored_code_changed_since_calibration(
    metadata: Dict[str, object], head_ref: str
) -> List[str]:
    """Files under the floored paths that changed since the calibration commit.

    Returns an empty list when the question cannot be answered (no recorded
    commit, or a commit this clone does not have) rather than inventing a
    failure: an unanswerable check must not masquerade as a passed one, and the
    prose-justification path below still applies.
    """
    commit = _calibration_commit(metadata)
    if commit is None:
        return []
    try:
        _run_git("cat-file", "-e", f"{commit}^{{commit}}")
        changed = _run_git(
            "diff", "--name-only", f"{commit}..{head_ref}", "--", *_FLOORED_CODE_PATHS
        )
    except subprocess.CalledProcessError:
        return []
    return [line.strip() for line in changed.splitlines() if line.strip()]


def _drift_is_acknowledged(metadata: Dict[str, object], changed_path: str) -> bool:
    """True when ``metadata.floor_drift_acknowledged`` names ``changed_path``.

    Each entry is ``{"path": <repo-relative FILE>, "reason": <why the floors
    still hold>}``.  Both fields are required: a path with no reason is an
    acknowledgement of nothing, and this gate exists because an unchecked
    assertion is worth nothing.

    Exact file paths only.  This used to also match a directory PREFIX, and
    two entries used it — ``include`` and ``ama_cryptography``, the two
    largest floored paths in the tree.  A prefix entry does not acknowledge
    the drift that was reviewed; it acknowledges all future drift anywhere
    beneath it, including in a file that does run inside a benchmarked call.
    The ``ama_cryptography`` entry's own reason was a careful list of what had
    changed in that pass and why none of it was on a benchmarked path — a
    statement about specific files, silently extended to every file the
    package will ever contain.

    The other 38 entries were already per file.  Both prefixes have been
    itemised, and the prefix match is gone rather than merely unused, so it
    cannot come back by someone writing the shorter form.
    """
    entries = metadata.get("floor_drift_acknowledged")
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        reason = entry.get("reason")
        if not isinstance(path, str) or not isinstance(reason, str) or not reason.strip():
            continue
        if changed_path == path:
            return True
    return False


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

        # A window extension with no new measurement is only defensible while
        # the floored code has not moved.  That claim used to live in prose in
        # the change log — "No src/c kernel, no dispatch path, and no Python
        # hot-path wrapper changed after the floors were measured" — where
        # nothing checked it, and it was false: the Kyber barrett_reduce
        # rewrite landed in the same commit that carried the extension.  So it
        # is checked here, against the commit the calibration evidence names.
        # The drift branch is deliberately unconditional — it fires whether or
        # not this diff also re-measured floors.  A re-measurement that leaves
        # metadata.calibration_evidence naming the old commit has not answered
        # the drift question: the evidence still says the floors describe that
        # older tree, and the changed files below are changed relative to it.
        # Only the message may not claim more than the check established, and
        # it used to: it said "with no floor re-measured" on every firing,
        # false in exactly the case a maintainer who had just re-measured and
        # forgotten calibration_evidence would hit.
        drifted = _floored_code_changed_since_calibration(after_meta, head_ref)
        drifted = [name for name in drifted if not _drift_is_acknowledged(after_meta, name)]
        if drifted:
            failures.append(
                f"{path}: applies_through_release moved "
                f"{before_meta.get('applies_through_release')!r} -> "
                f"{after_meta.get('applies_through_release')!r}, but "
                f"metadata.calibration_evidence still names commit "
                f"{_calibration_commit(after_meta)!r} and code the floors "
                f"describe has changed since it:\n"
                + "".join(f"    {name}\n" for name in drifted[:12])
                + (f"    ... and {len(drifted) - 12} more\n" if len(drifted) > 12 else "")
                + f"  A floor that describes a tree the branch no longer ships "
                f"is not a regression gate. Either re-measure on the canonical "
                f"runner for this file (updating the floors and "
                f"calibration_evidence), or acknowledge each path explicitly in "
                f"metadata.floor_drift_acknowledged — a list of "
                f"{{path, reason}} entries, where path is a repo-relative file "
                f"— exact paths only, a directory prefix would acknowledge every "
                f"future change beneath it. The acknowledgement is reviewable; the "
                f"prose sentence it replaces was not checked by anything and "
                f"was false when it was written."
            )
            continue

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

    net_changes: List[Tuple[str, str, object, object]] = []
    for path, ch_p in per_path_changes:
        print(f"Detected {len(ch_p)} baseline_value change(s) in {path}:")
        for name, b, a in ch_p:
            print(f"  - {name}: {b!r} -> {a!r}")
            net_changes.append((path, name, b, a))

    # Each change is justified by text that ACCOUNTS for it: the PR body, or
    # the message of a commit that actually moved that number.
    #
    # This used to concatenate every commit message on the branch that touched
    # a baseline JSON and scan the blob for "a name, a number, a runner"
    # anywhere.  On a long branch that is unfalsifiable, and measured on this
    # one it already was: 25 commits, 86,892 bytes of accumulated message text,
    # containing a measurement, a runner token, and all 19 primitive names
    # before any new commit was written.  A commit whose entire message was
    # "wip", halving ed25519_sign's floor, passed with an empty PR body and
    # exit 0 -- the guard reporting that "every changed baseline is named, a
    # measurement value is cited, and a CI runner is identified", all of it
    # from text written for unrelated changes.
    failures = _check_justification_attributed(
        args.base_ref, args.head_ref, net_changes, args.pr_body or ""
    )
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
