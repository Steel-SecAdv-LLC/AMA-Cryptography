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
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_tool_module(name: str) -> ModuleType:
    """Import ``tools/<name>.py`` by path.

    Dynamic on purpose: ``tools/`` is not a package on ``sys.path``, so a static
    ``import`` would leave ``mypy --strict tests/`` with an unresolved module —
    which is also why the fuzz-count test below loads the registration gate this
    way rather than importing it.
    """
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "tools" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    return _load_tool_module("check_documented_counts")


def _synthetic_repo(
    tool: ModuleType,
    tmp_path: Path,
    *,
    lib_py: int = 2,
    c_files: int = 3,
    test_files: int = 4,
    table_overrides: dict[str, int] | None = None,
    lines_overrides: dict[str, int] | None = None,
    composition_overrides: dict[str, int] | None = None,
) -> Path:
    """A miniature tree plus a METRICS_REPORT whose tables describe it.

    By default every gated figure is correct — rendered from the tool's own
    measurement functions — so each test states exactly the one lie it is
    checking rather than inheriting a pile of unrelated mismatches.  The
    report is written twice with an identical line count (a placeholder pass
    to fix the report's own contribution to the whole-project scope, then
    the measured pass), because the report is a tracked ``*.md`` and
    measures itself.
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

    def _render(
        table: dict[str, tuple[int, int]],
        composition: dict[str, tuple[int, str]],
        json_lines: int,
    ) -> str:
        for label, files in (table_overrides or {}).items():
            table[label] = (files, table[label][1])
        for label, lines in (lines_overrides or {}).items():
            table[label] = (table[label][0], lines)
        for label, lines in (composition_overrides or {}).items():
            composition[label] = (lines, composition[label][1])
        rows = "\n".join(
            f"| {label} | {files} | {lines:,} |" for label, (files, lines) in table.items()
        )
        comp_rows = "\n".join(
            f"| {label} | {lines:,} | {pct} | x |" for label, (lines, pct) in composition.items()
        )
        return (
            "## Lines of Code\n\n| Scope | Files | Lines |\n|---|---:|---:|\n"
            + rows
            + "\n\n### Scope Composition\n\n"
            + "| Scope | Lines | % of whole | Paths |\n|---|---:|---:|---|\n"
            + comp_rows
            + f"\n\ncorpora ({json_lines:,} lines of `*.json` alone)\n"
        )

    report = repo / "docs" / "METRICS_REPORT.md"
    # Placeholder pass fixes the report's own line count; measured pass fills
    # the real numbers into a byte-different but line-identical document.
    report.write_text(
        _render(
            dict.fromkeys(tool._LOC_TABLE_ROWS, (0, 0)),
            dict.fromkeys(
                (
                    "Library (Python + C + headers)",
                    "Tests",
                    "Top-level Python",
                    "Cython",
                    "Everything else (remainder)",
                    "**Whole-project total**",
                ),
                (0, "0.0%"),
            ),
            0,
        ),
        encoding="utf-8",
    )
    report.write_text(
        _render(
            tool.measure_loc_table(repo),
            tool.measure_scope_composition(repo),
            tool.measure_tracked_json_lines(repo),
        ),
        encoding="utf-8",
    )
    return repo


class TestLocTableFileCounts:
    def test_a_correct_table_is_clean(self, tool: ModuleType, tmp_path: Path) -> None:
        """Non-vacuity for everything below."""
        repo = _synthetic_repo(tool, tmp_path)
        assert tool.check_loc_table_file_counts(repo) == []

    @pytest.mark.parametrize(
        "label",
        [
            "Library Python (`ama_cryptography/*.py`)",
            "Native C (`src/c/**/*.c`, `include/**/*.h`)",
            "Library total (Python + C + headers)",
            "Top-level Python (monitors, benchmarks, demos)",
            "Tests (`tests/**/*.py`)",
            "Cython (`*.pyx`, `*.pxd`)",
            "**Whole project** (source + docs + config)",
        ],
    )
    def test_every_gated_row_is_really_checked(
        self, tool: ModuleType, tmp_path: Path, label: str
    ) -> None:
        """One lie per run, so no row can be covered by another's failure."""
        repo = _synthetic_repo(tool, tmp_path, table_overrides={label: 999})
        problems = tool.check_loc_table_file_counts(repo)
        assert len(problems) == 1
        assert label in problems[0]

    @pytest.mark.parametrize(
        "label",
        [
            "Library Python (`ama_cryptography/*.py`)",
            "Native C (`src/c/**/*.c`, `include/**/*.h`)",
            "Library total (Python + C + headers)",
            "Top-level Python (monitors, benchmarks, demos)",
            "Tests (`tests/**/*.py`)",
            "Cython (`*.pyx`, `*.pxd`)",
            "**Whole project** (source + docs + config)",
        ],
    )
    def test_every_line_total_is_really_checked(
        self, tool: ModuleType, tmp_path: Path, label: str
    ) -> None:
        """The 4.0.0 gate checked only the Files column; the line totals then
        drifted within two days of being re-measured.  Every Lines cell is
        now a gated claim of its own."""
        repo = _synthetic_repo(tool, tmp_path, lines_overrides={label: 999_999})
        problems = tool.check_loc_table_file_counts(repo)
        assert len(problems) == 1
        assert label in problems[0] and "999,999" in problems[0]

    @pytest.mark.parametrize(
        "label",
        [
            "Library (Python + C + headers)",
            "Tests",
            "Everything else (remainder)",
            "**Whole-project total**",
        ],
    )
    def test_scope_composition_rows_are_checked(
        self, tool: ModuleType, tmp_path: Path, label: str
    ) -> None:
        repo = _synthetic_repo(tool, tmp_path, composition_overrides={label: 888_888})
        problems = tool.check_loc_table_file_counts(repo)
        assert problems, "a wrong Scope Composition line total passed the gate"
        assert any(label in p and "888,888" in p for p in problems)

    def test_a_legacy_uncounted_files_cell_is_a_failure(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """A ``—`` Files cell reads as 'not applicable' but means 'never
        measured'; the gate treats it as a wrong count, and the regenerator
        fills the real one."""
        repo = _synthetic_repo(tool, tmp_path)
        report = repo / "docs" / "METRICS_REPORT.md"
        text = report.read_text(encoding="utf-8")
        text = re.sub(
            r"\| Cython \(`\*\.pyx`, `\*\.pxd`\) \| \d+ \|",
            "| Cython (`*.pyx`, `*.pxd`) | — |",
            text,
        )
        report.write_text(text, encoding="utf-8")
        problems = tool.check_loc_table_file_counts(repo)
        assert any("Cython" in p and "— files" in p for p in problems)

    def test_a_renamed_row_fails_rather_than_stops_being_checked(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """The failure mode that produced this whole class of drift.

        A check that simply finds no match and moves on turns a reformatted
        document into a silently unverified one — which reads identically to a
        verified one in the CI log.
        """
        repo = _synthetic_repo(tool, tmp_path)
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
        repo = _synthetic_repo(tool, tmp_path)
        (repo / "tests" / "conftest.py").write_text("import pytest\n", encoding="utf-8")
        problems = tool.check_loc_table_file_counts(repo)
        assert any("Tests (`tests/**/*.py`)" in p for p in problems)


class TestAggregateTestCounts:
    def test_the_static_measure_ignores_files_without_a_test_function(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        repo = _synthetic_repo(tool, tmp_path, test_files=4)
        (repo / "tests" / "conftest.py").write_text("import pytest\n", encoding="utf-8")
        functions, files = tool.measure_static_test_counts(repo)
        assert (functions, files) == (4, 4)

    def test_a_wrong_aggregate_claim_fails(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = _synthetic_repo(tool, tmp_path, test_files=4)
        (repo / "OVERVIEW.md").write_text(
            "9,999 test functions across 42 Python test files.\n", encoding="utf-8"
        )
        problems = tool.check_aggregate_test_counts(repo)
        assert len(problems) == 2  # one for the function count, one for the file count

    def test_a_correct_aggregate_claim_passes(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = _synthetic_repo(tool, tmp_path, test_files=4)
        (repo / "OVERVIEW.md").write_text(
            "4 test functions across 4 Python test files.\n", encoding="utf-8"
        )
        assert tool.check_aggregate_test_counts(repo) == []

    def test_a_revision_history_row_is_not_treated_as_a_live_claim(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """History records what was true then; matching it would freeze the gate red."""
        repo = _synthetic_repo(tool, tmp_path, test_files=4)
        (repo / "OVERVIEW.md").write_text(
            "| 3.5.0 | 2026-07-30 | 3,057 test functions across 127 Python test files. |\n",
            encoding="utf-8",
        )
        assert tool.check_aggregate_test_counts(repo) == []


class TestFuzzTargetCounts:
    """``check_fuzz_target_counts`` — the prose count vs the number built."""

    @staticmethod
    def _repo(tmp_path: Path, body: str) -> Path:
        repo = tmp_path / "repo"
        (repo / "docs").mkdir(parents=True)
        (repo / "docs" / "F.md").write_text(body, encoding="utf-8")
        return repo

    def test_a_matching_count_is_clean(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = self._repo(tmp_path, "The suite has 15 libFuzzer fuzz targets.\n")
        assert tool.check_fuzz_target_counts(repo, 15) == []

    def test_a_wrong_count_fails(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = self._repo(tmp_path, "The suite has 12 libFuzzer fuzz targets.\n")
        problems = tool.check_fuzz_target_counts(repo, 15)
        assert problems and "12" in problems[0]

    def test_the_parenthesised_and_trailing_forms_are_both_caught(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        repo = self._repo(tmp_path, "C fuzz harnesses (16 targets); 16 targets in `fuzz/`.\n")
        assert len(tool.check_fuzz_target_counts(repo, 15)) == 2

    def test_a_number_on_a_non_fuzz_line_is_ignored(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = self._repo(tmp_path, "There are 3 targets for this sprint.\n")
        assert tool.check_fuzz_target_counts(repo, 15) == []

    def test_the_source_file_count_is_not_read_as_a_target_count(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """ "16 ``fuzz_*.c`` sources / 15 entry points" is the correct pairing,
        not a drifted "16 targets" — the gate must not flag it."""
        repo = self._repo(tmp_path, "There are 16 `fuzz_*.c` sources, 15 libFuzzer entry points.\n")
        assert tool.check_fuzz_target_counts(repo, 15) == []

    def test_a_revision_history_row_is_ignored(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = self._repo(tmp_path, "| 2.1.0 | 2026-03-25 | fuzz testing (12 targets) |\n")
        assert tool.check_fuzz_target_counts(repo, 15) == []

    def test_the_count_is_imported_from_the_registration_gate(self, tool: ModuleType) -> None:
        """The authority is the same tool that enforces registration, so the
        two can never disagree about how many harnesses exist.

        Loaded the same dynamic way the ``tool`` fixture loads its module, so
        ``mypy --strict tests/`` has no unresolved static import to reject.
        """
        registration = _load_tool_module("check_fuzz_target_registration")
        assert (
            tool.count_libfuzzer_entry_points(REPO_ROOT)
            == len(registration._sources(REPO_ROOT))
            > 0
        )


class TestBreakingChangeCounts:
    """``check_breaking_change_counts`` — the restated total vs the CHANGELOG table."""

    _CHANGELOG = (
        "## [4.0.0]\n\n"
        "### Behavioural and breaking changes at a glance\n\n"
        "| # | Kind | Change |\n|---|---|---|\n"
        "| 1 | **Breaking** | a |\n"
        "| 2 | **Breaking** | b |\n"
        "| 3 | Behavioural | c |\n\n"
        "## [3.5.0]\n\nolder\n"
    )

    @staticmethod
    def _repo(tmp_path: Path, changelog: str, doc: str) -> Path:
        repo = tmp_path / "repo"
        (repo / "docs").mkdir(parents=True)
        (repo / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
        (repo / "docs" / "S.md").write_text(doc, encoding="utf-8")
        return repo

    def test_a_matching_word_count_is_clean(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = self._repo(
            tmp_path,
            self._CHANGELOG,
            "Superseded (two breaking changes — see CHANGELOG `[4.0.0]`).\n",
        )
        assert tool.check_breaking_change_counts(repo) == []

    def test_a_wrong_count_names_the_table_total(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = self._repo(
            tmp_path,
            self._CHANGELOG,
            "Superseded (three breaking changes — see CHANGELOG `[4.0.0]`).\n",
        )
        problems = tool.check_breaking_change_counts(repo)
        assert problems and "enumerates 2" in problems[0]

    def test_a_digit_spelling_also_resolves(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = self._repo(
            tmp_path,
            self._CHANGELOG,
            "There are 2 breaking changes — see CHANGELOG `[4.0.0]`.\n",
        )
        assert tool.check_breaking_change_counts(repo) == []

    def test_a_claim_about_a_missing_section_fails(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = self._repo(
            tmp_path,
            self._CHANGELOG,
            "Superseded (two breaking changes — see CHANGELOG `[9.9.9]`).\n",
        )
        problems = tool.check_breaking_change_counts(repo)
        assert problems and "no such section" in problems[0]

    def test_vague_prose_names_no_count_and_is_skipped(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        repo = self._repo(
            tmp_path,
            self._CHANGELOG,
            "Superseded (several breaking changes — see CHANGELOG `[4.0.0]`).\n",
        )
        assert tool.check_breaking_change_counts(repo) == []

    def test_a_revision_history_row_is_ignored(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = self._repo(
            tmp_path,
            self._CHANGELOG,
            "| 3.5.0 | 2026-07-30 | three breaking changes — see CHANGELOG `[4.0.0]` |\n",
        )
        assert tool.check_breaking_change_counts(repo) == []


class TestEntryPointCounts:
    """The gated-surface figures must track the tool the documents cite.

    INVARIANTS.md names ``tools/check_error_state_gating.py`` as "the
    authoritative figure" and then published 85 while the tool reported 86; the
    CHANGELOG's 5.0.0 section repeated the 85 in two places.  Nothing checked
    the sentence against the tool it names, which is precisely the shape this
    module exists to close.
    """

    def test_a_wrong_native_count_is_reported(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        (repo / "docs").mkdir(parents=True)
        native, _cython = tool.count_error_state_entry_points()
        (repo / "docs" / "SURFACE.md").write_text(
            f"The ERROR state inhibits {native + 7} native entry points.\n",
            encoding="utf-8",
        )
        problems = tool.check_entry_point_counts(repo)
        assert any("native entry points" in p for p in problems), problems

    def test_the_right_native_count_passes(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        (repo / "docs").mkdir(parents=True)
        native, cython = tool.count_error_state_entry_points()
        (repo / "docs" / "SURFACE.md").write_text(
            f"The ERROR state inhibits {native} native entry points and "
            f"{cython} Cython binding entry points.\n",
            encoding="utf-8",
        )
        assert tool.check_entry_point_counts(repo) == []

    def test_a_wrong_cython_count_is_reported(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        (repo / "docs").mkdir(parents=True)
        _native, cython = tool.count_error_state_entry_points()
        (repo / "docs" / "SURFACE.md").write_text(
            f"and {cython + 1} Cython binding entry points.\n", encoding="utf-8"
        )
        problems = tool.check_entry_point_counts(repo)
        assert any("Cython binding entry points" in p for p in problems), problems


class TestCSuiteCounts:
    """`N C test suites (M translation units)` must track tests/c.

    Both figures sit in README.md and neither was gated: adding one C test file
    moved them and nothing noticed.
    """

    @staticmethod
    def _repo_with_c_tests(tmp_path: Path, suites: int, helpers: int) -> Path:
        repo = tmp_path / "repo"
        (repo / "tests" / "c").mkdir(parents=True)
        for i in range(suites):
            (repo / "tests" / "c" / f"test_{i}.c").write_text(
                "int main(void){return 0;}\n", encoding="utf-8"
            )
        for i in range(helpers):
            (repo / "tests" / "c" / f"helper_{i}.c").write_text("int h;\n", encoding="utf-8")
        return repo

    def test_measurement_separates_suites_from_translation_units(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        repo = self._repo_with_c_tests(tmp_path, suites=5, helpers=2)
        assert tool.measure_c_suite_counts(repo) == (5, 7)

    def test_a_correct_claim_passes(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = self._repo_with_c_tests(tmp_path, suites=5, helpers=2)
        (repo / "docs").mkdir(parents=True)
        (repo / "docs" / "M.md").write_text(
            "covered by 5 C test suites (7 translation units).\n", encoding="utf-8"
        )
        assert tool.check_c_suite_counts(repo) == []

    def test_a_stale_suite_count_is_reported(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = self._repo_with_c_tests(tmp_path, suites=5, helpers=2)
        (repo / "docs").mkdir(parents=True)
        (repo / "docs" / "M.md").write_text(
            "covered by 4 C test suites (7 translation units).\n", encoding="utf-8"
        )
        problems = tool.check_c_suite_counts(repo)
        assert any("C test suites" in p for p in problems), problems

    def test_a_stale_translation_unit_count_is_reported(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        repo = self._repo_with_c_tests(tmp_path, suites=5, helpers=2)
        (repo / "docs").mkdir(parents=True)
        (repo / "docs" / "M.md").write_text(
            "covered by 5 C test suites (9 translation units).\n", encoding="utf-8"
        )
        problems = tool.check_c_suite_counts(repo)
        assert any("translation units" in p for p in problems), problems

    def test_the_bare_form_is_checked_too(self, tool: ModuleType, tmp_path: Path) -> None:
        """README carries both `N C test suites (M TU)` and a bare `N C test suites`."""
        repo = self._repo_with_c_tests(tmp_path, suites=5, helpers=2)
        (repo / "docs").mkdir(parents=True)
        (repo / "docs" / "M.md").write_text("anchored in 3 C test suites\n", encoding="utf-8")
        problems = tool.check_c_suite_counts(repo)
        assert any("C test suites" in p for p in problems), problems


class TestTheChangelogUnreleasedSectionIsLive:
    """`## [X.Y.Z] - Unreleased` describes the release being built, not history.

    ``_markdown_files`` skips CHANGELOG.md entirely as "historical by
    definition".  That is right for dated sections and wrong for the one at the
    top: both counts these checks were written for had an occurrence there, and
    a wrong figure in the release notes is a wrong figure, not a record.
    """

    @staticmethod
    def _changelog(repo: Path, unreleased_body: str, released_body: str = "") -> None:
        repo.mkdir(parents=True, exist_ok=True)
        (repo / "CHANGELOG.md").write_text(
            "# Changelog\n\n"
            "## [9.9.9] - Unreleased\n\n"
            f"{unreleased_body}\n\n"
            "## [1.0.0] - 2020-01-01\n\n"
            f"{released_body}\n",
            encoding="utf-8",
        )

    def test_the_unreleased_section_is_extracted(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        self._changelog(repo, "LIVE TEXT", "OLD TEXT")
        section = tool.changelog_unreleased_section(repo)
        assert "LIVE TEXT" in section
        assert "OLD TEXT" not in section

    def test_no_unreleased_section_yields_nothing(self, tool: ModuleType, tmp_path: Path) -> None:
        """Right after a release is dated there is no such section."""
        repo = tmp_path / "repo"
        repo.mkdir(parents=True)
        (repo / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [1.0.0] - 2020-01-01\n\nreleased\n", encoding="utf-8"
        )
        assert tool.changelog_unreleased_section(repo) == ""

    def test_a_stale_count_in_the_unreleased_section_is_reported(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        repo = tmp_path / "repo"
        native, _cython = tool.count_error_state_entry_points()
        self._changelog(repo, f"inhibits {native + 5} native entry points")
        problems = tool.check_entry_point_counts(repo)
        assert any("CHANGELOG.md [Unreleased]" in p for p in problems), problems

    def test_a_stale_count_in_a_released_section_is_not_reported(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """Dated sections stay history: they record what was true then."""
        repo = tmp_path / "repo"
        native, _cython = tool.count_error_state_entry_points()
        self._changelog(repo, "nothing to see", f"inhibits {native + 5} native entry points")
        assert tool.check_entry_point_counts(repo) == []


class TestTheGateIsNotVacuousOnThisRepository:
    def test_the_real_tree_matches_every_claim(self, tool: ModuleType) -> None:
        problems, checked = tool.audit(REPO_ROOT)
        assert problems == []
        assert checked >= tool.MIN_CLAIMS

    def test_the_claim_patterns_still_match_something(self, tool: ModuleType) -> None:
        """A reformat that stopped every pattern matching would otherwise pass."""
        _problems, checked = tool.audit(REPO_ROOT)
        assert checked > 10
