#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Decide whether a pull request touches any path a gate workflow watches.

Why this exists
---------------
A gate whose context is a required status check cannot be path-filtered at
the workflow level: GitHub creates no check run for a workflow that path
filtering skipped, so the context stays "Expected" forever.  This tree used
the documented no-op twin for that -- a second workflow with the same name and
the complementary ``paths-ignore:`` -- and the twin was not exclusive:
``paths:`` fires when ANY changed file matches and ``paths-ignore:`` fires when
ANY changed file is not ignored, so a pull request touching ``src/c/x.c`` and
``CHANGELOG.md`` ran both, and the no-op reported the gate's context green
minutes before the real lanes finished.

The replacement runs the real workflow on every pull request.  Its first job
calls this script with the watched patterns; every lane depends on the answer,
and the gate job maps "not relevant" to success itself.  One workflow, one
context, no race.

Semantics
---------
Patterns use GitHub's filter-pattern syntax, which is what the ``paths:`` lists
they replace used: ``*`` matches any run of characters except ``/``, ``**``
matches any run including ``/``, ``?`` matches one character except ``/``.
Negated (``!``) patterns are refused rather than half-implemented.

The comparison is the pull request's merge commit against its first parent,
the base branch head GitHub merged into, so the file list is exactly the
pull request's own changes.  For any event that is not a pull request the
answer is "relevant": pushes, schedules and dispatches run the lanes
unconditionally, as they did before.

Exit status is 0 with ``relevant=true|false`` written to ``$GITHUB_OUTPUT``
(and stdout); anything that prevents an answer -- a git failure, an empty or
malformed pattern list -- exits 1, and the gate treats a failed detection as a
failure, never as "not relevant".
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence


def pattern_regex(pattern: str) -> re.Pattern[str]:
    """Compile one GitHub filter pattern to an anchored regular expression."""
    if not pattern or pattern.startswith("!"):
        raise ValueError(f"unsupported pattern {pattern!r}: empty or negated")
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def watched_patterns(text: str) -> list[str]:
    """The non-empty lines of a newline-separated pattern list."""
    patterns = [line.strip() for line in text.splitlines() if line.strip()]
    if not patterns:
        raise ValueError("WATCHED_PATHS is empty: nothing to decide relevance against")
    return patterns


def touches(changed: Iterable[str], patterns: Sequence[str]) -> list[str]:
    """The changed paths that at least one pattern matches."""
    compiled = [pattern_regex(p) for p in patterns]
    return [path for path in changed if any(rx.match(path) for rx in compiled)]


def changed_files(base: str, head: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", base, head],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git diff {base} {head} failed: {result.stderr.strip()}")
    return [line for line in result.stdout.splitlines() if line]


def _emit(relevant: bool) -> None:
    line = f"relevant={'true' if relevant else 'false'}"
    print(line)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--event", required=True, help="github.event_name")
    parser.add_argument("--base", default="HEAD^1", help="base revision (default: HEAD^1)")
    parser.add_argument("--head", default="HEAD", help="head revision (default: HEAD)")
    args = parser.parse_args(argv)
    try:
        patterns = watched_patterns(os.environ.get("WATCHED_PATHS", ""))
        if args.event != "pull_request":
            print(f"event {args.event!r} is not a pull request: every lane runs")
            _emit(True)
            return 0
        matched = touches(changed_files(args.base, args.head), patterns)
    except (ValueError, RuntimeError) as exc:
        print(f"::error::cannot decide relevance: {exc}", file=sys.stderr)
        return 1
    for path in matched:
        print(f"  watched: {path}")
    _emit(bool(matched))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
