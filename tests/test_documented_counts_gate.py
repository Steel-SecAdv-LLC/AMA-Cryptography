# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for ``tools/check_documented_counts.py``.

The gate re-derives every count the documentation pins, on the argument that
"a documented number that has quietly gone wrong is worse than no number,
because a reader takes it as evidence". It was itself unpinned — mentioned in
prose by ``test_documented_examples.py`` and driven by nothing.

That mattered, and the way it mattered is the reason this module exists.
``docs/METRICS_REPORT.md`` carries two different file counts one table apart:
the Lines-of-Code table's ``Files`` column, and "Python test files under
``tests/`` matching the static regex". They are different measures — a raw glob
against a ``def test_`` match — that happened to print the same number. Only
the second was gated. When they diverged, the gated one stayed right and the
ungated one silently went stale, in the document that declares itself
authoritative and says "if a documented count and this report disagree, the
count is the bug". A row whose neighbour is checked reads as checked.

Both directions are pinned below: a wrong number must fail, a renamed row must
fail rather than silently stop being checked, and a correct tree must pass.
The last is not a formality — a checker that reports drift unconditionally is
as useless as one that never does, and rather more likely to be switched off.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "check_documented_counts.py"


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_documented_counts", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _synthetic_repo(
    tmp_path: Path,
    *,
    lib_py: int = 2,
    c_files: int = 3,
    test_files: int = 4,
    table_overrides: dict[str, int] | None = None,
) -> Path:
    """A miniature tree plus a METRICS_REPORT whose table describes it.

    By default the table is correct, so each test states exactly the one lie it
    is checking rather than inheriting a pile of unrelated mismatches.
    """
    repo = tmp_path / "repo"
    (repo / "ama_cryptography").mkdir(parents=True)
    (repo / "src" / "c").mkdir(parents=True)
    (repo / "include").mkdir(parents=True)
    (repo / "tests").mkdir(parents=True)
    (repo / "docs").mkdir(parents=True)

    for i in range(lib_py):
        (repo / "ama_cryptography" / f"mod{i}.py").write_text("x = 1\n", encoding="utf-8")
    for i in range(c_files):
        (repo / "src" / "c" / f"file{i}.c").write_text("int x;\n", encoding="utf-8")
    (repo / "include" / "hdr.h").write_text("/* h */\n", encoding="utf-8")
    for i in range(test_files):
        (repo / "tests" / f"test_{i}.py").write_text("def test_a():\n    pass\n", encoding="utf-8")

    counts = {
        "Library Python (`ama_cryptography/*.py`)": lib_py,
        "Native C (`src/c/**/*.c`, `include/**/*.h`)": c_files + 1,
        "Library total (Python + C + headers)": lib_py + c_files + 1,
        "Tests (`tests/**/*.py`)": test_files,
    }
    counts.update(table_overrides or {})
    rows = "\n".join(f"| {label} | {value} | 100 |" for label, value in counts.items())
    (repo / "docs" / "METRICS_REPORT.md").write_text(
        "## Lines of Code\n\n| Scope | Files | Lines |\n|---|---:|---:|\n" + rows + "\n",
        encoding="utf-8",
    )
    return repo


class TestLocTableFileCounts:
    def test_a_correct_table_is_clean(self, tool: ModuleType, tmp_path: Path) -> None:
        """Non-vacuity for everything below."""
        repo = _synthetic_repo(tmp_path)
        assert tool.check_loc_table_file_counts(repo) == []

    @pytest.mark.parametrize(
        "label",
        [
            "Library Python (`ama_cryptography/*.py`)",
            "Native C (`src/c/**/*.c`, `include/**/*.h`)",
            "Library total (Python + C + headers)",
            "Tests (`tests/**/*.py`)",
        ],
    )
    def test_every_gated_row_is_really_checked(
        self, tool: ModuleType, tmp_path: Path, label: str
    ) -> None:
        """One lie per run, so no row can be covered by another's failure."""
        repo = _synthetic_repo(tmp_path, table_overrides={label: 999})
        problems = tool.check_loc_table_file_counts(repo)
        assert len(problems) == 1
        assert label in problems[0]

    def test_a_renamed_row_fails_rather_than_stops_being_checked(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """The failure mode that produced this whole class of drift.

        A check that simply finds no match and moves on turns a reformatted
        document into a silently unverified one — which reads identically to a
        verified one in the CI log.
        """
        repo = _synthetic_repo(tmp_path)
        report = repo / "docs" / "METRICS_REPORT.md"
        report.write_text(
            report.read_text(encoding="utf-8").replace(
                "| Tests (`tests/**/*.py`) |", "| Test suite |"
            ),
            encoding="utf-8",
        )
        problems = tool.check_loc_table_file_counts(repo)
        assert any("no LoC-table row found" in p for p in problems)

    def test_a_missing_report_is_a_failure(self, tool: ModuleType, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        assert tool.check_loc_table_file_counts(empty) != []

    def test_adding_an_untested_helper_file_still_moves_the_count(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """The exact divergence: a ``tests/`` file with no ``def test_`` in it.

        ``conftest.py`` and ``ref_keyformat.py`` are counted by the raw glob and
        not by the regex, which is why the two numbers must be measured
        separately rather than assumed equal.
        """
        repo = _synthetic_repo(tmp_path)
        (repo / "tests" / "conftest.py").write_text("import pytest\n", encoding="utf-8")
        problems = tool.check_loc_table_file_counts(repo)
        assert any("Tests (`tests/**/*.py`)" in p for p in problems)


class TestAggregateTestCounts:
    def test_the_static_measure_ignores_files_without_a_test_function(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        repo = _synthetic_repo(tmp_path, test_files=4)
        (repo / "tests" / "conftest.py").write_text("import pytest\n", encoding="utf-8")
        functions, files = tool.measure_static_test_counts(repo)
        assert (functions, files) == (4, 4)

    def test_a_wrong_aggregate_claim_fails(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = _synthetic_repo(tmp_path, test_files=4)
        (repo / "OVERVIEW.md").write_text(
            "9,999 test functions across 42 Python test files.\n", encoding="utf-8"
        )
        problems = tool.check_aggregate_test_counts(repo)
        assert len(problems) == 2  # one for the function count, one for the file count

    def test_a_correct_aggregate_claim_passes(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = _synthetic_repo(tmp_path, test_files=4)
        (repo / "OVERVIEW.md").write_text(
            "4 test functions across 4 Python test files.\n", encoding="utf-8"
        )
        assert tool.check_aggregate_test_counts(repo) == []

    def test_a_revision_history_row_is_not_treated_as_a_live_claim(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """History records what was true then; matching it would freeze the gate red."""
        repo = _synthetic_repo(tmp_path, test_files=4)
        (repo / "OVERVIEW.md").write_text(
            "| 3.5.0 | 2026-07-30 | 3,057 test functions across 127 Python test files. |\n",
            encoding="utf-8",
        )
        assert tool.check_aggregate_test_counts(repo) == []


class TestTheGateIsNotVacuousOnThisRepository:
    def test_the_real_tree_matches_every_claim(self, tool: ModuleType) -> None:
        problems, checked = tool.audit(REPO_ROOT)
        assert problems == []
        assert checked >= tool.MIN_CLAIMS

    def test_the_claim_patterns_still_match_something(self, tool: ModuleType) -> None:
        """A reformat that stopped every pattern matching would otherwise pass."""
        _problems, checked = tool.audit(REPO_ROOT)
        assert checked > 10
