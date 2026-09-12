#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Fail-closed gate on CodeQL findings, read from the SARIF the analysis writes.

Why this exists
---------------
``github/codeql-action/analyze`` uploads alerts and exits 0 whatever it found.
The ``codeql`` job in ``.github/workflows/static-analysis.yml`` ran it with no
severity threshold and no step that read the results, and
``static-analysis-gate`` then hand-checked ``needs.codeql.result == 'success'``
— so the merge-blocking gate proved only that the scan had *completed*.  A
genuine ``error``-level C or Python finding left it green.  (A separately
configured "Code scanning results / CodeQL" ruleset context could block, but
that lives outside the repository, and a control the repository cannot see is
not one it can claim.)

This is the same construction as ``tools/check_semgrep_severity.py`` and
``tools/check_bandit_severity.py``: apply the policy to the report data rather
than to an exit code the scanner never sets.

Policy
------
Block on any result whose effective SARIF level is ``error``.  ``warning`` and
``note`` results are reported and do not block, matching how the Semgrep gate
treats its WARNING-level constant-time advisories.

SARIF puts a result's level in one of two places: on the result itself
(``result.level``), or — far more often for CodeQL — only on the rule, in
``run.tool.driver.rules[].defaultConfiguration.level``.  Reading just
``result.level`` sees ``None`` for nearly every CodeQL finding and blocks on
nothing, which would rebuild the defect this gate exists to remove, so the
rule table is consulted whenever the result omits its own level.

Fail-closed
-----------
A missing, empty or unparseable SARIF file is a FAILURE, not a pass: the
scenario it most likely describes is an analysis step that did not run.

Exit status
-----------
  0  no error-level results.
  1  at least one error-level result, or the report could not be read.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

#: Levels that block. SARIF 2.1.0 defines: none, note, warning, error.
BLOCKING_LEVELS = frozenset({"error"})


def _rule_levels(run: dict[str, Any]) -> dict[str, str]:
    """``ruleId -> defaultConfiguration.level`` for one SARIF run."""
    driver = ((run.get("tool") or {}).get("driver")) or {}
    levels: dict[str, str] = {}
    for rule in driver.get("rules") or []:
        rule_id = rule.get("id")
        level = ((rule.get("defaultConfiguration") or {}).get("level")) or ""
        if rule_id and level:
            levels[str(rule_id)] = str(level)
    return levels


def _location(result: dict[str, Any]) -> str:
    for loc in result.get("locations") or []:
        phys = loc.get("physicalLocation") or {}
        uri = ((phys.get("artifactLocation") or {}).get("uri")) or "?"
        line = ((phys.get("region") or {}).get("startLine")) or 0
        return f"{uri}:{line}"
    return "<no location>"


def _message(result: dict[str, Any]) -> str:
    return str(((result.get("message") or {}).get("text")) or "").strip().replace("\n", " ")


def findings(sarif: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    """``(level, ruleId, location, message)`` for every result in the report."""
    out: list[tuple[str, str, str, str]] = []
    for run in sarif.get("runs") or []:
        rule_levels = _rule_levels(run)
        for result in run.get("results") or []:
            rule_id = str(result.get("ruleId") or "<no rule id>")
            level = str(result.get("level") or rule_levels.get(rule_id) or "warning")
            out.append((level, rule_id, _location(result), _message(result)))
    return out


def audit(paths: Iterable[Path]) -> tuple[list[str], int, int]:
    """Return ``(failures, blocking_count, total_count)`` over every report."""
    failures: list[str] = []
    blocking = 0
    total = 0
    seen_any = False
    for path in paths:
        if not path.is_file():
            failures.append(f"{path}: no SARIF report — the analysis step did not run")
            continue
        try:
            sarif = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"{path}: unreadable SARIF ({exc})")
            continue
        seen_any = True
        rows = findings(sarif)
        total += len(rows)
        for level, rule_id, location, message in rows:
            if level in BLOCKING_LEVELS:
                blocking += 1
                failures.append(f"{location}: [{level}] {rule_id}: {message}")
    if not seen_any and not failures:
        failures.append("no SARIF report was examined at all")
    return failures, blocking, total


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail on CodeQL results at or above error severity."
    )
    parser.add_argument(
        "reports",
        nargs="+",
        type=Path,
        help="SARIF file(s) written by github/codeql-action/analyze (output: <dir>).",
    )
    args = parser.parse_args(argv)

    paths: list[Path] = []
    for report in args.reports:
        if report.is_dir():
            paths.extend(sorted(report.glob("*.sarif")))
        else:
            paths.append(report)
    if not paths:
        print("CODEQL SEVERITY GATE FAILED — no SARIF files found", file=sys.stderr)
        return 1

    failures, blocking, total = audit(paths)
    print(f"CodeQL severity gate: {total} result(s) across {len(paths)} report(s)")
    if failures:
        print(
            f"\nCODEQL SEVERITY GATE FAILED — {blocking} error-level result(s):\n", file=sys.stderr
        )
        for row in failures:
            print(f"  {row}", file=sys.stderr)
        print(
            "\nFix the finding, or — if it is a false positive — dismiss it in the "
            "code-scanning UI with a reason, which removes it from the SARIF.",
            file=sys.stderr,
        )
        return 1
    print("PASS — no CodeQL result at or above error severity.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
