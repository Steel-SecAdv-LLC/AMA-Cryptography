# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the gcov parser in ``tools/measure_branch_coverage.py``.

Since GCC 8, gcov marks an executed line that holds a never-run basic block by
appending ``*`` to its count (``        5*:    4:``).  The parser's line pattern
admitted only digits, ``#`` and ``-`` in the count field, so a starred line
failed to match: its ``branch N`` rows were keyed to the previous source line,
with the branch index still counting from that line, and its text was never
recorded.  Starred lines are precisely the ones with partially executed
branches, so the inventory misplaced exactly what it exists to surface, and the
cross-translation-unit merge then reported phantom never-taken arcs.

Measured on this tree (gcc 13.3.0, Debug ``--coverage -O0 -g``, 193
translation units with coverage data, ``ctest`` 146 tests), the same gcov data
read by the old pattern gave 2,121 never-taken of 12,207 arcs, and by the
corrected one 1,504 of 11,507.

The report excerpts below are gcov 13.3.0 output, verbatim, for::

    int f(int x) {
        int r = 0;
        if (x > 0 && x < 100) r = 1; else r = 2;
        return r;
    }

called five times with ``x`` in 1..5 — so line 4's two false arcs never run.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "measure_branch_coverage.py"

#: gcov 13.3.0, the function above: line 4 is starred.
PARTIAL = """\
        -:    0:Source:demo.c
        -:    0:Graph:demo.gcno
        -:    0:Data:demo.gcda
        -:    0:Runs:1
        -:    1:#include <stdio.h>
function f called 5 returned 100% blocks executed 83%
        5:    2:int f(int x) {
        5:    3:    int r = 0;
       5*:    4:    if (x > 0 && x < 100) r = 1; else r = 2;
branch  0 taken 100% (fallthrough)
branch  1 taken 0%
branch  2 taken 100% (fallthrough)
branch  3 taken 0%
        5:    5:    return r;
        -:    6:}
"""

#: The same source in a translation unit whose callers take every arc.
FULL = """\
        -:    0:Source:demo.c
        -:    0:Graph:demo.gcno
        -:    0:Data:demo.gcda
        -:    0:Runs:1
        -:    1:#include <stdio.h>
function f called 7 returned 100% blocks executed 100%
        7:    2:int f(int x) {
        7:    3:    int r = 0;
        7:    4:    if (x > 0 && x < 100) r = 1; else r = 2;
branch  0 taken 71% (fallthrough)
branch  1 taken 29%
branch  2 taken 80% (fallthrough)
branch  3 taken 20%
        7:    5:    return r;
        -:    6:}
"""


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("measure_branch_coverage", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    return _load()


def _parse(
    tool: ModuleType, tmp_path: Path, *reports: str
) -> tuple[set[tuple[str, int, int]], set[tuple[str, int, int]], dict[tuple[str, int], str]]:
    taken: set[tuple[str, int, int]] = set()
    seen: set[tuple[str, int, int]] = set()
    text: dict[tuple[str, int], str] = {}
    for n, body in enumerate(reports):
        report = tmp_path / f"tu{n}.gcov"
        report.write_text(body, encoding="utf-8")
        tool._parse(report, taken, seen, text)
    return taken, seen, text


def test_a_starred_line_owns_its_branches(tool: ModuleType, tmp_path: Path) -> None:
    taken, seen, text = _parse(tool, tmp_path, PARTIAL)
    assert seen == {("demo.c", 4, i) for i in range(4)}, "branches keyed to the wrong line"
    assert taken == {("demo.c", 4, 0), ("demo.c", 4, 2)}
    assert text[("demo.c", 4)].strip().startswith("if (x > 0 && x < 100)")


def test_the_merge_reports_only_arcs_no_unit_took(tool: ModuleType, tmp_path: Path) -> None:
    """One unit starred, another fully executed: nothing is left untaken."""
    taken, seen, _ = _parse(tool, tmp_path, PARTIAL, FULL)
    assert seen - taken == set(), f"phantom never-taken arcs: {sorted(seen - taken)}"


def test_the_untaken_arcs_of_a_starred_line_are_reported_on_it(
    tool: ModuleType, tmp_path: Path
) -> None:
    taken, seen, _ = _parse(tool, tmp_path, PARTIAL)
    assert seen - taken == {("demo.c", 4, 1), ("demo.c", 4, 3)}


@pytest.mark.parametrize("count", ["5", "5*", "12345*", "#####", "=====", "-"])
def test_every_gcov_count_form_starts_a_source_line(tool: ModuleType, count: str) -> None:
    line = f"{count:>9}:   42:    if (x) {{"
    hit = tool._SRC_RE.match(line)
    assert hit is not None, f"{count!r} not recognised as a source line"
    assert hit.group(2) == "42"
