#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Fail-closed gate on Bandit findings, read from the JSON report.

Why this is not a `grep`
------------------------
The gate used to be::

    bandit ... --severity-level medium --confidence-level medium > report.txt
    if grep -E '^\\s*(Medium|High):\\s*[1-9]' report.txt; then exit 1; fi

Bandit's text report ends with *two* tallies that share their labels::

    Run metrics:
        Total issues (by severity):
            Undefined: 0
            Low: 7
            Medium: 0          <- the one the policy is about
            High: 0
        Total issues (by confidence):
            Undefined: 0
            Low: 0
            Medium: 6          <- the one the regex actually hit
            High: 1

The regex is anchored to the start of a line and both blocks are indented, so
it matched the *confidence* tally. This repository has seven Low-severity
findings, six of them Medium-confidence, so the pattern matched on a run whose
severity tally was `Medium: 0, High: 0` and whose findings list said "No issues
identified." The gate could not pass, and the failure it reported named a
condition that did not exist.

That is worth spelling out because it is the specific way a security gate rots:
it was not too permissive, it was *unreadable*, and an unreadable red gate gets
routed around. The fix is to stop parsing prose. Bandit's JSON report states
each finding's severity and confidence as fields, so the policy — block on
severity >= MEDIUM and confidence >= MEDIUM — is applied to the data rather
than to a rendering of it.

Fail-closed conditions
----------------------
Anything that means "the scan did not actually cover the tree" is a failure,
not a pass:

* the report is missing, unreadable, or not JSON;
* it has no ``results`` list or no ``metrics._totals``;
* Bandit recorded scan ``errors`` — a file that failed to parse was not
  examined, and an unexamined file is not a clean file;
* the report was pre-filtered (see ``--severity-level`` note below), so the
  findings list and the totals disagree and this tool cannot say what was
  dropped;
* nothing at all was scanned.

Pass an **unfiltered** report. Filtering with Bandit's ``--severity-level`` /
``--confidence-level`` prunes ``results`` but leaves ``metrics._totals``
counting every finding, which destroys the cross-check above. This tool applies
the thresholds itself.

Usage::

    bandit -r ama_cryptography/ --exit-zero -f json -o bandit-report.json
    python3 tools/check_bandit_severity.py bandit-report.json

Exit code:
    0  no finding at or above the blocking thresholds
    1  a blocking finding, or the report cannot be trusted
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

#: Bandit's rank ordering, lowest first. Comparisons below are by index.
RANKS = ("UNDEFINED", "LOW", "MEDIUM", "HIGH")

#: The documented policy, matching the thresholds the workflow used to pass to
#: Bandit on the command line. Justified findings carry an inline ``# nosec``
#: with a tracking ID, which ``tools/check_suppression_hygiene.py`` validates
#: separately (INVARIANT-13); the two gates together mean every Medium+ finding
#: is either fixed or justified in reviewable form.
BLOCK_SEVERITY = "MEDIUM"
BLOCK_CONFIDENCE = "MEDIUM"


class ReportError(Exception):
    """The report cannot be trusted to say whether the tree is clean."""


def _rank(value: str, what: str) -> int:
    try:
        return RANKS.index(value.upper())
    except (AttributeError, ValueError):
        raise ReportError(f"unrecognised {what} {value!r}; expected one of {RANKS}") from None


def load_report(path: Path) -> dict[str, Any]:
    """Read a Bandit JSON report, refusing anything that is not one."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"cannot read {path}: {exc}") from None
    try:
        report = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReportError(f"{path} is not valid JSON: {exc}") from None
    if not isinstance(report, dict):
        raise ReportError(f"{path} is not a Bandit report (top level is not an object)")
    if not isinstance(report.get("results"), list):
        raise ReportError(f"{path} has no 'results' list; this is not a Bandit JSON report")
    totals = report.get("metrics", {}).get("_totals")
    if not isinstance(totals, dict):
        raise ReportError(f"{path} has no 'metrics._totals'; this is not a Bandit JSON report")
    return report


def evaluate(
    report: dict[str, Any],
    severity: str = BLOCK_SEVERITY,
    confidence: str = BLOCK_CONFIDENCE,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """``(blocking, at_severity_but_below_confidence)``.

    The second list is returned rather than dropped so the caller can print it.
    A Medium-severity finding that this policy does not block is still
    something a reviewer should see; silently discarding it is how a threshold
    turns into a blind spot.
    """
    errors = report.get("errors") or []
    if errors:
        raise ReportError(
            f"Bandit recorded {len(errors)} scan error(s); files it could not parse were "
            f"not examined: {errors}"
        )

    totals = report["metrics"]["_totals"]
    min_severity = _rank(severity, "severity threshold")
    min_confidence = _rank(confidence, "confidence threshold")

    loc = totals.get("loc", 0)
    if not isinstance(loc, int) or loc <= 0:
        raise ReportError(
            f"the report covers {loc} lines of code — nothing was scanned, which must not "
            "read as a clean result"
        )

    at_severity: list[dict[str, Any]] = []
    for result in report["results"]:
        if not isinstance(result, dict):
            raise ReportError(f"malformed entry in 'results': {result!r}")
        if _rank(result.get("issue_severity", ""), "issue_severity") >= min_severity:
            at_severity.append(result)

    # Self-audit. `metrics._totals` is computed over every finding Bandit made,
    # while `results` holds the ones it chose to report. They agree only on an
    # unfiltered report — and a filtered one silently hides exactly the
    # findings this gate exists to catch, so disagreement is a hard error and
    # not a warning.
    expected = sum(totals.get(f"SEVERITY.{r}", 0) for r in RANKS[min_severity:])
    if expected != len(at_severity):
        raise ReportError(
            f"metrics._totals reports {expected} finding(s) at severity >= {severity} but "
            f"'results' contains {len(at_severity)}. The report was pre-filtered, so this "
            "gate cannot tell what was dropped. Generate it without --severity-level / "
            "--confidence-level and let this tool apply the thresholds."
        )

    blocking: list[dict[str, Any]] = []
    below: list[dict[str, Any]] = []
    for result in at_severity:
        target = (
            blocking
            if _rank(result.get("issue_confidence", ""), "issue_confidence") >= min_confidence
            else below
        )
        target.append(result)
    return blocking, below


def describe(result: dict[str, Any]) -> str:
    return (
        f"  {result.get('filename', '?')}:{result.get('line_number', '?')}: "
        f"[{result.get('test_id', '?')}:{result.get('test_name', '?')}] "
        f"severity={result.get('issue_severity', '?')} "
        f"confidence={result.get('issue_confidence', '?')}\n"
        f"      {result.get('issue_text', '').strip()}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed gate on a Bandit JSON report.")
    parser.add_argument("report", type=Path, help="path to a Bandit JSON report")
    parser.add_argument("--severity", default=BLOCK_SEVERITY, help="blocking severity floor")
    parser.add_argument("--confidence", default=BLOCK_CONFIDENCE, help="blocking confidence floor")
    args = parser.parse_args(argv)

    try:
        report = load_report(args.report)
        blocking, below = evaluate(report, args.severity, args.confidence)
    except ReportError as exc:
        print(f"::error::Bandit gate cannot verify this tree: {exc}")
        return 1

    totals = report["metrics"]["_totals"]
    print(
        "Bandit findings by severity: "
        + ", ".join(f"{r.title()}={totals.get(f'SEVERITY.{r}', 0)}" for r in RANKS)
        + f" over {totals['loc']} lines of code"
    )
    print(
        f"Blocking policy: severity >= {args.severity.upper()} and "
        f"confidence >= {args.confidence.upper()}"
    )

    if below:
        print(
            f"\n{len(below)} finding(s) at or above the severity floor but below the "
            "confidence floor (not blocking, shown for review):"
        )
        for result in below:
            print(describe(result))

    if blocking:
        print(f"\n{len(blocking)} blocking finding(s):")
        for result in blocking:
            print(describe(result))
        print(
            "::error::Bandit reports unjustified Medium+ findings — fix them, or justify "
            "each inline with a `# nosec` carrying a tracking ID per INVARIANT-13."
        )
        return 1

    print("\nNo blocking findings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
