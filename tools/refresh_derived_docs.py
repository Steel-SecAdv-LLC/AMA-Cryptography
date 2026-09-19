#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Regenerate every derived figure in the documentation, to a fixpoint.

The problem this solves
-----------------------
Three tools maintain overlapping derived numbers and they do not agree with
each other in one pass:

``tools/update_docs.py --counts``
    test-function and test-file counts in README.md and docs/METRICS_REPORT.md
``tools/generate_visuals.py``
    the chart PNGs and ``assets/visuals_manifest.json``, which carries its own
    ``total_tests`` and ``n_files``
``tools/update_docs.py --loc``
    the lines-of-code tables in docs/METRICS_REPORT.md

Two gates then check them: ``tools/check_documented_counts.py`` and
``tools/generate_visuals.py --check``.

Running them in the wrong order leaves the tree failing its own gates, and
running them in the RIGHT order once is still not enough.  ``generate_visuals``
rewrites ``assets/visuals_manifest.json``, which changes the repository's line
count, which invalidates the LoC figures ``--loc`` just wrote.  Observed while
adding one test file: ``--loc`` reported "already current", then the gate
failed by exactly one line, and a second ``--loc`` pass was needed.

So this is a fixpoint computation, not a checklist.  Treating it as a
checklist is why commits in this repository's history exist for nothing but
repairing the desync, and why a contributor who adds a single test can watch
CI go red on a number no human wrote.

What this does
--------------
Runs the passes in dependency order and repeats until the tree stops changing
and both gates agree, or until ``--max-rounds`` is exhausted — in which case
it FAILS rather than leaving a half-converged tree.  Non-convergence means the
passes are fighting each other, which is a real defect and must be visible.

Exit status
-----------
0  converged; both gates pass
1  did not converge, or a gate still fails
2  a required tool is missing or a pass could not run
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

#: In dependency order. Counts first (visuals read the test tree), then the
#: visuals, then LoC last because the visuals rewrite a tracked JSON file and
#: change the very line count LoC measures.
PASSES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("test counts", ("tools/update_docs.py", "--counts")),
    ("visual assets", ("tools/generate_visuals.py",)),
    ("lines of code", ("tools/update_docs.py", "--loc")),
)

GATES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("documented counts", ("tools/check_documented_counts.py",)),
    ("visual assets", ("tools/generate_visuals.py", "--check")),
)

#: The files these passes write. Their combined digest is the convergence
#: signal: when a full round changes none of them, the tree is at a fixpoint.
TRACKED_OUTPUTS: tuple[str, ...] = (
    "README.md",
    "docs/METRICS_REPORT.md",
    "ARCHITECTURE.md",
    "assets/visuals_manifest.json",
)

DEFAULT_MAX_ROUNDS = 4


def _env() -> dict[str, str]:
    """Child environment for the passes.

    ``tests/conftest.py`` imports ``ama_cryptography``, and since 5.0.0 a
    failed POST raises rather than degrading, so a tree whose native library
    is stale takes the count tools down with it. These passes read source
    files and perform no cryptography, so the diagnostic import is correct
    here: the module completes its import in the ERROR state and every
    cryptographic operation stays refused.
    """
    env = dict(os.environ)
    env.setdefault("AMA_POST_DIAGNOSTIC_IMPORT", "1")
    return env


def _digest_outputs() -> str:
    digest = hashlib.sha256()
    for relative in TRACKED_OUTPUTS:
        path = REPO_ROOT / relative
        digest.update(relative.encode("utf-8"))
        digest.update(path.read_bytes() if path.is_file() else b"<absent>")
    return digest.hexdigest()


def _run(command: tuple[str, ...], *, quiet: bool) -> tuple[int, str]:
    script = REPO_ROOT / command[0]
    if not script.is_file():
        return 2, f"{command[0]} does not exist"
    completed = subprocess.run(
        [sys.executable, str(script), *command[1:]],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=_env(),
        check=False,
    )
    output = (completed.stdout or "") + (completed.stderr or "")
    if not quiet and output.strip():
        for line in output.splitlines():
            print(f"      {line}")
    return completed.returncode, output


def check_only(quiet: bool) -> int:
    """Report whether the derived figures are already current."""
    failures = []
    for label, command in GATES:
        code, _ = _run(command, quiet=quiet)
        status = "OK" if code == 0 else "DRIFTED"
        print(f"  {status:<8} {label}")
        if code != 0:
            failures.append(label)
    if failures:
        print(
            f"\nDerived figures have drifted: {', '.join(failures)}.\n"
            f"Regenerate them with: python tools/refresh_derived_docs.py",
            file=sys.stderr,
        )
        return 1
    print("\nOK: every derived figure matches the tree.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report drift without writing anything",
    )
    parser.add_argument("--max-rounds", type=int, default=DEFAULT_MAX_ROUNDS)
    parser.add_argument("--quiet", action="store_true", help="suppress pass output")
    args = parser.parse_args(argv)

    if args.max_rounds < 1:
        print("FATAL: --max-rounds must be at least 1.", file=sys.stderr)
        return 2

    if args.check:
        return check_only(args.quiet)

    for label, command in (*PASSES, *GATES):
        if not (REPO_ROOT / command[0]).is_file():
            print(f"FATAL: {command[0]} is missing; cannot refresh {label}.", file=sys.stderr)
            return 2

    previous = _digest_outputs()
    for round_number in range(1, args.max_rounds + 1):
        print(f"Round {round_number}:")
        for label, command in PASSES:
            code, output = _run(command, quiet=args.quiet)
            if code == 2:
                print(f"FATAL: {label}: {output}", file=sys.stderr)
                return 2
            if code != 0:
                print(f"  FAILED   {label} (exit {code})")
                # A pass that refuses to run — for example because a new file
                # is not staged — is not a convergence problem and retrying
                # will not fix it.
                print(
                    f"\nFATAL: the '{label}' pass exited {code} and did not "
                    f"rewrite anything. Read its output above; "
                    f"tools/update_docs.py refuses to measure a tree with "
                    f"unstaged new files, so `git add` them first.",
                    file=sys.stderr,
                )
                return 2
            print(f"  ran      {label}")

        current = _digest_outputs()
        if current == previous:
            print(f"\nConverged after {round_number} round(s); outputs stable.")
            break
        previous = current
    else:
        print(
            f"\nFATAL: derived figures did not converge in {args.max_rounds} "
            f"rounds. The passes are changing each other's inputs without "
            f"settling, which is a real defect — do not paper over it by "
            f"raising --max-rounds.",
            file=sys.stderr,
        )
        return 1

    print("\nVerifying against the gates CI runs:")
    return check_only(args.quiet)


if __name__ == "__main__":
    raise SystemExit(main())
