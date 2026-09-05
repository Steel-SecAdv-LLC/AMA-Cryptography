#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Every tracked Python file must be inside the ``mypy --strict`` run.

The type-check step used to name a hand-written list of paths — the shipped
package, the test tree, the gate scripts, four benchmark files — with the
chart, dashboard and comparative generators left out as "demo tooling ...
annotating them adds churn without protecting anything".  Two things were
wrong with that.  The list was maintained by hand, so a new tool joined the
check only if someone remembered to add it.  And the excluded third of the
Python in this repository was not inert: it held a ``dict[str, dict[str,
bool]]`` populated with ints, a coverage matrix built by ``zip`` that would
silently drop a library from the comparison if one row were short, three
``re.search(...).group(1)`` version reads that raise ``AttributeError``
instead of reporting a missing version, a Dilithium keypair dereferenced
without its ``Optional`` check, and four ``create_crypto_package(dna_codes=…)``
calls in the published integration examples naming a parameter the function
has never had.

``ARCHITECTURE.md`` says "type hints throughout (validated via mypy)".  This
gate is what makes that sentence checkable: the scope is now every tracked
``.py`` file, and a new one is in scope by existing rather than by being
remembered.

HOW IT WORKS
============

``mypy --linecoverage-report`` writes a ``coverage.json`` whose ``lines`` map
is keyed by the ABSOLUTE PATH of every file mypy actually analysed — including
files it reached by following an import rather than by being named on the
command line, which is how ``schemas/`` and ``wycheproof_vectors/`` are
covered (both are imported by ``tests/``, and both are genuinely checked: an
injected type error in either turns the run red).

This gate reads that report and compares it against ``git ls-files '*.py'``.
A tracked file the report does not mention was not type-checked, whatever the
run's exit status said.

Exit codes
----------
* 0 — every tracked ``.py`` file appears in the report.
* 1 — a tracked file is outside the checked scope, or the report looks
  truncated / unreadable (fail-closed).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: A report covering fewer files than this has broken, not shrunk.  The tree
#: carries 293 checked files today; the floor sits well below that so ordinary
#: growth and pruning do not trip it, while a collapsed run (one file, or an
#: empty map) cannot read as success.
MIN_REPORTED_FILES = 200

#: Files that are tracked but deliberately outside the type check, each with
#: the reason.  Empty, and meant to stay that way: an entry here is a file
#: whose breakage no one would see.
EXEMPT: dict[str, str] = {}


def tracked_python_files(root: Path) -> list[Path]:
    """Every ``*.py`` file git tracks, as absolute paths.

    git rather than a filesystem walk: a walk needs a hand-maintained list of
    directories to skip (``build/``, ``.venv/``, ``*.egg-info/``, whichever
    ``build-*`` a local run left behind), and that list is exactly the kind of
    thing that drifts and quietly narrows the check.
    """
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "*.py"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git ls-files failed ({proc.returncode}): {proc.stderr.strip()}")
    return [root / line for line in proc.stdout.splitlines() if line.strip()]


def reported_files(report: Path) -> set[Path]:
    """The absolute paths mypy recorded in ``coverage.json``."""
    data = json.loads(report.read_text(encoding="utf-8"))
    lines = data.get("lines")
    if not isinstance(lines, dict):
        raise ValueError(f"{report} has no 'lines' map; this is not a mypy coverage report")
    return {Path(key).resolve() for key in lines}


def audit(report: Path, root: Path = REPO) -> list[str]:
    problems: list[str] = []
    try:
        covered = reported_files(report)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"cannot read the mypy coverage report at {report}: {exc}"]

    if len(covered) < MIN_REPORTED_FILES:
        return [
            f"the coverage report lists only {len(covered)} file(s) (expected at "
            f"least {MIN_REPORTED_FILES}) — a collapsed run, not a clean tree"
        ]

    try:
        tracked = tracked_python_files(root)
    except RuntimeError as exc:
        return [str(exc)]

    if not tracked:
        return ["git tracks no .py files; refusing to report success on an empty scope"]

    for path in sorted(tracked):
        rel = path.relative_to(root).as_posix()
        if rel in EXEMPT:
            continue
        if path.resolve() not in covered:
            problems.append(
                f"{rel}: tracked but never type-checked. Add it to the mypy "
                f"invocation in .github/workflows/ci.yml (and ci-build-test.yml), "
                f"or make it reachable from a checked module."
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "report",
        help="path to coverage.json from `mypy --linecoverage-report <dir>`",
    )
    parser.add_argument("--root", default=str(REPO))
    args = parser.parse_args(argv)

    problems = audit(Path(args.report), Path(args.root))
    if problems:
        print("TYPE-CHECK SCOPE GATE FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    covered = reported_files(Path(args.report))
    tracked = tracked_python_files(Path(args.root))
    print(
        f"OK: all {len(tracked)} tracked .py file(s) are inside the mypy --strict "
        f"run ({len(covered)} module(s) analysed)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
