#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""``tools/update_docs.py`` must not corrupt the CHANGELOG it syncs.

``update_changelog`` refuses to create a section for a version that already has
one.  That guard was built on a regex requiring ``## [X.Y.Z] - YYYY-MM-DD``, so
it could not see the two headings a *pre-release* tree carries — the standing
``## [Unreleased]`` placeholder this file's own Keep a Changelog convention
mandates, and ``## [5.0.0] - Unreleased`` while a release is prepared but not
yet tagged.  With either at the top, the guard read the previous release's
version, concluded the current one had no section, and inserted a second
``## [5.0.0]`` above the hand-written one.

The consequences were not cosmetic: ``check_documented_counts`` derives the
documented breaking-change count from the FIRST matching section, which would
then be the generated one with no glance table — zero rows — so every
"four breaking changes" statement in the tree would read as drift.

These pin the heading parser directly, on both dated and undated forms.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

import pytest

from tools import update_docs

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestHeadingParsing:
    @pytest.mark.parametrize(
        "line,expected",
        [
            ("## [5.0.0] - 2026-08-14", "5.0.0"),
            ("## [5.0.0] - Unreleased", "5.0.0"),
            ("## [5.0.0]", "5.0.0"),
            ("##  [4.0.0]  -  2026-08-01", "4.0.0"),
            ("## [Unreleased]", "Unreleased"),
        ],
    )
    def test_a_heading_matches_with_or_without_a_date(self, line: str, expected: str) -> None:
        match = update_docs._CHANGELOG_HEADING_RE.match(line)
        assert match is not None, f"heading not recognised: {line}"
        assert match.group(1).strip() == expected

    @pytest.mark.parametrize(
        "line",
        [
            "### [5.0.0] - 2026-08-14",  # wrong level
            "## 5.0.0 - 2026-08-14",  # no brackets
            "Some prose mentioning ## [5.0.0]",
            "",
        ],
    )
    def test_non_headings_do_not_match(self, line: str) -> None:
        assert update_docs._CHANGELOG_HEADING_RE.match(line) is None


class TestLatestVersionSkipsThePlaceholder:
    def _with_changelog(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, body: str) -> None:
        path = tmp_path / "CHANGELOG.md"
        path.write_text(body, encoding="utf-8")
        monkeypatch.setattr(update_docs, "CHANGELOG", path)

    def test_unreleased_placeholder_is_not_a_version(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._with_changelog(
            monkeypatch,
            tmp_path,
            "# Changelog\n\n## [Unreleased]\n\n## [5.0.0] - Unreleased\n\n"
            "## [4.0.0] - 2026-08-01\n",
        )
        assert update_docs._latest_changelog_version() == "5.0.0"

    def test_an_undated_release_section_is_still_found(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The regression: this used to return 4.0.0 and re-create 5.0.0."""
        self._with_changelog(
            monkeypatch,
            tmp_path,
            "# Changelog\n\n## [5.0.0] - Unreleased\n\n## [4.0.0] - 2026-08-01\n",
        )
        assert update_docs._latest_changelog_version() == "5.0.0"

    def test_a_dated_release_section_is_found(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._with_changelog(
            monkeypatch,
            tmp_path,
            "# Changelog\n\n## [5.0.0] - 2026-09-01\n\n## [4.0.0] - 2026-08-01\n",
        )
        assert update_docs._latest_changelog_version() == "5.0.0"

    def test_no_sections_at_all(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self._with_changelog(monkeypatch, tmp_path, "# Changelog\n\nNothing yet.\n")
        assert update_docs._latest_changelog_version() is None


class TestTheRealTree:
    def test_the_guard_holds_on_this_repository(self) -> None:
        """The shipped CHANGELOG's top section must match the project version.

        This is the condition that keeps ``update_docs.py`` from adding a
        duplicate. It is asserted on the real files rather than a fixture,
        because the failure mode is a mismatch between two real files.
        """
        assert update_docs._latest_changelog_version() == update_docs._get_version()

    def test_exactly_one_section_per_version(self) -> None:
        """A duplicate heading is the corruption itself; assert it is absent."""
        seen: list[str] = []
        for line in (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8").splitlines():
            match = update_docs._CHANGELOG_HEADING_RE.match(line)
            if match:
                seen.append(match.group(1).strip())
        duplicates = {v for v in seen if seen.count(v) > 1}
        assert not duplicates, f"CHANGELOG has more than one section for: {sorted(duplicates)}"

    def test_the_current_release_section_carries_a_lifecycle_suffix(self) -> None:
        """The heading for the project version reads ``Unreleased`` or a date.

        Under Keep a Changelog the suffix on a version heading is the release
        date, so the tree carries exactly two legitimate states for it and
        moves between them once:

        * ``Unreleased`` while the version is prepared — a date here would
          state that a release which has not happened did;
        * ``YYYY-MM-DD`` from the release commit onward — ``Unreleased`` here
          would ship a document contradicting the tag, which is what
          ``tools/check_release_state.py`` refuses at preflight.

        Pinning either state alone puts this test in opposition to that tool:
        an assertion of ``Unreleased`` can only be satisfied by never
        releasing. So both are accepted and everything else is refused — a
        suffix that is neither is a malformed heading, which is the failure
        this test can still see.
        """
        text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        version = update_docs._get_version()
        for line in text.splitlines():
            match = update_docs._CHANGELOG_HEADING_RE.match(line)
            if match and match.group(1).strip() == version:
                suffix = (match.group(2) or "").strip()
                dated = re.fullmatch(r"\d{4}-\d{2}-\d{2}", suffix) is not None
                assert suffix.lower() == "unreleased" or dated, (
                    f"CHANGELOG heading for {version} carries {suffix!r}. It must "
                    f"read 'Unreleased' while the version is prepared, or an ISO "
                    f"'YYYY-MM-DD' release date from the release commit onward."
                )
                return
        pytest.fail(f"no CHANGELOG section for the project version {version}")


class TestTextIOIsPlatformIndependent:
    """Every document read and write must name its encoding and line ending.

    ``Path.read_text()`` with no encoding uses the *locale* encoding — the ANSI
    code page on Windows.  ``CHANGELOG.md`` is UTF-8 and carries em dashes,
    ``σ``, ``≤`` and ``·``, so every Windows job failed with::

        UnicodeDecodeError: 'charmap' codec can't decode byte 0x90

    The write side would have been worse than an error: text-mode
    ``write_text`` translates ``\\n`` to ``\\r\\n`` on Windows, so one run of
    the doc-sync tool would have rewritten every line ending in the files it
    maintains — which ``tools/check_line_endings.py`` then rejects.  The tool
    that maintains the documentation would have failed the repository's own
    gate on the documentation it maintains.

    Asserted against the source rather than by simulating a locale, because
    the property wanted is "no call omits it", which a behavioural test on one
    call cannot establish.
    """

    _MODULES = (
        "tools/update_docs.py",
        "tools/build_keyformat_corpus.py",
        "tools/build_post_kats.py",
        "tools/refresh_wycheproof_corpus.py",
        "benchmarks/generate_competitive.py",
        # Both write assets/visuals_manifest.json, a committed artefact the
        # line-endings gate holds to LF; each wrote it in text mode with no
        # newline argument, so a regeneration on Windows committed CRLF.
        "tools/generate_visuals.py",
        "tools/generate_dashboards.py",
    )

    @staticmethod
    def _calls(source: str, method: str) -> list[str]:
        """Keyword names of every ``.<method>(...)`` *call*, via the AST.

        Parsed rather than string-searched: the first version scanned raw text
        and matched ``Path.read_text()`` written inside a docstring explaining
        this very rule, so documenting the fix broke the test enforcing it.
        The AST sees calls and nothing else.
        """
        import ast

        found: list[str] = []
        for node in ast.walk(ast.parse(source)):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == method
            ):
                keywords = {kw.arg for kw in node.keywords if kw.arg}
                found.append(f"line {node.lineno}: keywords={sorted(keywords)}")
        return found

    @staticmethod
    def _keywords(call: str) -> set[str]:
        return set(call.split("keywords=", 1)[1].strip("[]").replace("'", "").split(", ")) - {""}

    @pytest.mark.parametrize("module", _MODULES)
    def test_reads_name_their_encoding(self, module: str) -> None:
        source = (REPO_ROOT / module).read_text(encoding="utf-8")
        bare = [c for c in self._calls(source, "read_text") if "encoding" not in self._keywords(c)]
        assert not bare, f"{module}: read_text without encoding: {bare}"

    @pytest.mark.parametrize("module", _MODULES)
    def test_writes_name_their_encoding_and_newline(self, module: str) -> None:
        source = (REPO_ROOT / module).read_text(encoding="utf-8")
        offenders = [
            c
            for c in self._calls(source, "write_text")
            if not {"encoding", "newline"} <= self._keywords(c)
        ]
        assert not offenders, f"{module}: write_text without encoding/newline: {offenders}"

    def test_the_package_digest_read_names_its_encoding(self) -> None:
        """The one in the shipped package, not just the tooling."""
        source = (REPO_ROOT / "ama_cryptography" / "_self_test.py").read_text(encoding="utf-8")
        bare = [c for c in self._calls(source, "read_text") if "encoding" not in self._keywords(c)]
        assert not bare, f"_self_test.py: read_text without encoding: {bare}"

    def test_the_changelog_really_does_contain_non_ascii(self) -> None:
        """Guards the premise: without this, the tests above prove nothing."""
        raw = (REPO_ROOT / "CHANGELOG.md").read_bytes()
        assert any(b > 0x7F for b in raw), "CHANGELOG is pure ASCII — premise no longer holds"

    def test_the_changelog_has_no_crlf(self) -> None:
        """The state a text-mode write on Windows would have destroyed."""
        assert b"\r\n" not in (REPO_ROOT / "CHANGELOG.md").read_bytes()


class TestLocRegeneratorRefusesUnstagedAdditions:
    """``--loc`` must not write figures the commit will invalidate.

    ``measure_loc_table`` enumerates with ``git ls-files``, which lists the
    INDEX.  A file written but not ``git add``-ed is invisible to it while
    being part of the commit about to be made, so running the regenerator
    before staging produces numbers that are right for the index and wrong for
    the commit — and the documented-counts gate then goes red on CI, one
    commit later, attributed to the wrong change.  It is silent in both
    directions without this guard: the regenerator reports success and the
    figures look plausible.
    """

    def test_the_guard_selects_a_countable_untracked_file(self, tmp_path: Path) -> None:
        import subprocess

        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        (repo / "tracked.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "add", "tracked.py"], cwd=repo, check=True)
        (repo / "brand_new.py").write_text("y = 2\n", encoding="utf-8")
        (repo / ".gitignore").write_text("ignored/\n", encoding="utf-8")
        subprocess.run(["git", "add", ".gitignore"], cwd=repo, check=True)
        (repo / "ignored").mkdir()
        (repo / "ignored" / "scratch.py").write_text("z = 3\n", encoding="utf-8")

        pending = update_docs._unstaged_additions_that_would_count(repo)

        assert "brand_new.py" in pending, "an untracked countable file must be reported"
        assert "ignored/scratch.py" not in pending, "ignored paths must not trip the guard"
        assert "tracked.py" not in pending, "staged files are visible to git ls-files"

    def test_a_staged_file_does_not_trip_the_guard(self, tmp_path: Path) -> None:
        import subprocess

        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        (repo / "new.py").write_text("x = 1\n", encoding="utf-8")
        assert update_docs._unstaged_additions_that_would_count(repo) == ["new.py"]

        subprocess.run(["git", "add", "new.py"], cwd=repo, check=True)
        assert update_docs._unstaged_additions_that_would_count(repo) == []

    def test_update_loc_metrics_raises_rather_than_measuring_around_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            update_docs,
            "_unstaged_additions_that_would_count",
            lambda: ["tools/brand_new_gate.py"],
        )
        with pytest.raises(update_docs.UnstagedAdditionsError) as excinfo:
            update_docs.update_loc_metrics(dry_run=True)
        assert "tools/brand_new_gate.py" in str(excinfo.value)
        assert "git add" in str(excinfo.value)

    def test_the_real_tree_has_no_unstaged_countable_additions(self) -> None:
        """Meta-check: this repository's own working tree is in the state the
        regenerator requires, so the guard above is not permanently tripped."""
        assert update_docs._unstaged_additions_that_would_count() == []


class TestStaticTestCountRegenerator:
    """The other half of the documented-counts gate now has a command too.

    ``--loc`` regenerated the Lines-of-Code figures; the static
    test-function/file claims across README.md, ARCHITECTURE.md and
    docs/METRICS_REPORT.md had to be found and hand-edited, and the gate that
    catches them named no command for them.  That asymmetry is the friction
    that produces a stale count, which is what put thirty-odd CI jobs red on
    this branch.

    These drive a REAL tests/ tree rather than a stubbed measurement, so the
    number written is the number the gate would measure.
    """

    @staticmethod
    def _tree(tmp_path: Path) -> tuple[int, int]:
        """A tests/ tree with 3 test functions across 2 files."""
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_a.py").write_text(
            "def test_one():\n    pass\n\n\ndef test_two():\n    pass\n", encoding="utf-8"
        )
        (tests / "test_b.py").write_text("def test_three():\n    pass\n", encoding="utf-8")
        (tests / "helper.py").write_text("def helper():\n    pass\n", encoding="utf-8")
        return 3, 2

    def test_the_rewrite_regex_matches_the_gate_it_serves(self) -> None:
        """A regenerator that recognises a different set than the gate leaves
        exactly the claims the gate fails on."""
        counts = update_docs._counts_module()
        samples = [
            "4,085 test functions across 173 Python test files",
            "4,085 Python test functions across 173 test files",
            "4085 static Python test functions across 127 files",
            "4,085 test\nfunctions across 173 Python test files",
        ]
        for sample in samples:
            gate_hits = counts._AGGREGATE_RE.findall(sample)
            rewrite_hits = update_docs._AGGREGATE_REWRITE_RE.findall(sample)
            assert len(gate_hits) == len(rewrite_hits) == 1, sample
            assert (gate_hits[0][0], gate_hits[0][1]) == (
                rewrite_hits[0][0],
                rewrite_hits[0][2],
            ), sample

    def test_a_stale_claim_is_rewritten_in_place(self, tmp_path: Path) -> None:
        functions, files = self._tree(tmp_path)
        readme = tmp_path / "README.md"
        readme.write_text(
            "- **Rigorous testing:** 1 test functions across 2 Python files plus 59 C suites\n",
            encoding="utf-8",
        )
        assert update_docs.update_static_test_counts(root=tmp_path) is True
        text = readme.read_text(encoding="utf-8")
        assert f"{functions} test functions across {files} Python files" in text
        assert "plus 59 C suites" in text, "the document's own wording must survive"

    def test_a_revision_history_row_is_left_alone(self, tmp_path: Path) -> None:
        """Rewriting a history row would falsify the record, not update a claim."""
        self._tree(tmp_path)
        doc = tmp_path / "README.md"
        history = (
            "| 3.5.0 | 2026-07-30 | Re-measured: 3,057 static Python test "
            "functions across 127 files. |\n"
        )
        doc.write_text(history, encoding="utf-8")
        assert update_docs.update_static_test_counts(root=tmp_path) is False
        assert doc.read_text(encoding="utf-8") == history

    def test_a_current_tree_reports_no_change(self, tmp_path: Path) -> None:
        functions, files = self._tree(tmp_path)
        doc = tmp_path / "README.md"
        doc.write_text(
            f"{functions} test functions across {files} Python files\n", encoding="utf-8"
        )
        assert update_docs.update_static_test_counts(root=tmp_path) is False

    def test_dry_run_writes_nothing(self, tmp_path: Path) -> None:
        self._tree(tmp_path)
        doc = tmp_path / "README.md"
        before = "1 test functions across 2 Python files\n"
        doc.write_text(before, encoding="utf-8")
        assert update_docs.update_static_test_counts(dry_run=True, root=tmp_path) is True
        assert doc.read_text(encoding="utf-8") == before

    def test_the_metrics_table_rows_are_rewritten(self, tmp_path: Path) -> None:
        functions, files = self._tree(tmp_path)
        (tmp_path / "docs").mkdir()
        doc = tmp_path / "docs" / "METRICS_REPORT.md"
        doc.write_text(
            "| Python test files under `tests/` matching the static regex | 1 |\n"
            "| Syntactic `def test_` matches under `tests/**/*.py` | **2** |\n",
            encoding="utf-8",
        )
        assert update_docs.update_static_test_counts(root=tmp_path) is True
        text = doc.read_text(encoding="utf-8")
        assert f"| Python test files under `tests/` matching the static regex | {files} |" in text
        assert f"| Syntactic `def test_` matches under `tests/**/*.py` | **{functions}** |" in text

    def test_a_wrapped_claim_is_rewritten_like_an_unwrapped_one(self, tmp_path: Path) -> None:
        """The gate reads a claim across a soft wrap, so the regenerator must too:
        otherwise the command the gate names leaves the claim it fails on."""
        functions, files = self._tree(tmp_path)
        readme = tmp_path / "README.md"
        readme.write_text("- 1 test\n  functions across 9 Python files\n", encoding="utf-8")
        assert update_docs.update_static_test_counts(root=tmp_path) is True
        text = readme.read_text(encoding="utf-8")
        assert text == f"- {functions} test\n  functions across {files} Python files\n"
        counts = update_docs._counts_module()
        assert counts.check_aggregate_test_counts(tmp_path) == []

    def test_the_agents_md_module_count_is_rewritten(self, tmp_path: Path) -> None:
        """AGENTS.md's "N Python test modules" drifted to nine below the tree
        with no pattern checking it and no pass rewriting it."""
        _functions, files = self._tree(tmp_path)
        agents = tmp_path / "AGENTS.md"
        agents.write_text(
            "| `tests/c/`, `tests/` | 86 C test suites, 248 Python test modules |\n",
            encoding="utf-8",
        )
        counts = update_docs._counts_module()
        assert counts.check_aggregate_test_counts(tmp_path), "the stale figure must be caught"
        assert update_docs.update_static_test_counts(root=tmp_path) is True
        assert f"86 C test suites, {files} Python test modules" in agents.read_text(
            encoding="utf-8"
        )
        assert counts.check_aggregate_test_counts(tmp_path) == []

    def test_the_real_tree_is_current_after_a_regeneration(self) -> None:
        """Meta-check: this repository's own aggregate claims are current, so
        the command the gate recommends does leave the gate green."""
        counts = update_docs._counts_module()
        problems = counts.check_aggregate_test_counts(REPO_ROOT)
        assert problems == [], problems


class TestInventoryCountsAreRegenerated:
    """`update_docs.py --counts` rewrites the C-suite and source-inventory
    counts the gate checks, so adding a C test or a header is one command, not
    a search across four documents."""

    @staticmethod
    def _tree(root: Path) -> None:
        (root / "tests" / "c").mkdir(parents=True)
        for name in ("test_a.c", "test_b.c", "helper.c"):
            (root / "tests" / "c" / name).write_text("int x;\n", encoding="utf-8")
        (root / "src" / "c" / "internal").mkdir(parents=True)
        (root / "src" / "c" / "one.c").write_text("int y;\n", encoding="utf-8")
        for name in ("a.h", "b.h", "c.h"):
            (root / "src" / "c" / "internal" / name).write_text("\n", encoding="utf-8")
        (root / "ama_cryptography").mkdir()
        for name in ("__init__.py", "m.py"):
            (root / "ama_cryptography" / name).write_text("\n", encoding="utf-8")

    def test_every_gated_spelling_is_rewritten(self, tmp_path: Path) -> None:
        self._tree(tmp_path)
        readme = tmp_path / "README.md"
        readme.write_text(
            "plus 9 C test suites (9 translation units) covering\n"
            "| `test_*.c` files under `tests/c/` | 9 |\n"
            "9 `test_*.c` registered via ctest\n"
            "the C suite is 9 suite files / 9 translation units\n"
            "- Top-level `src/c/*.c` — 9 translation units\n"
            "- `ama_cryptography/`, 9 modules + `__init__` + `__main__`\n"
            "- `src/c/internal/` — 9 `.c`: none; 9 `.h`: many\n",
            encoding="utf-8",
        )
        assert update_docs.update_inventory_counts(root=tmp_path) is True
        counts = update_docs._counts_module()
        assert counts.check_c_suite_counts(tmp_path) == []
        assert counts.check_source_inventory_counts(tmp_path) == []
        text = readme.read_text(encoding="utf-8")
        assert "plus 2 C test suites (3 translation units) covering" in text
        assert "`src/c/internal/` — 0 `.c`: none; 3 `.h`: many" in text

    def test_a_history_row_is_left_alone(self, tmp_path: Path) -> None:
        self._tree(tmp_path)
        doc = tmp_path / "README.md"
        row = "| 3.5.0 | 2026-07-30 | 9 C test suites (9 translation units) |\n"
        doc.write_text(row, encoding="utf-8")
        assert update_docs.update_inventory_counts(root=tmp_path) is False
        assert doc.read_text(encoding="utf-8") == row

    def test_a_wrapped_claim_is_rewritten(self, tmp_path: Path) -> None:
        self._tree(tmp_path)
        doc = tmp_path / "README.md"
        doc.write_text(
            "- plus 9 C\n  test suites (9 translation\n  units); the C\n"
            "  suite is 9 files / 9 translation units\n"
            "| 3.5.0 | 2026-07-30 | 9 C test suites |\n",
            encoding="utf-8",
        )
        assert update_docs.update_inventory_counts(root=tmp_path) is True
        assert doc.read_text(encoding="utf-8") == (
            "- plus 2 C\n  test suites (3 translation\n  units); the C\n"
            "  suite is 2 files / 3 translation units\n"
            "| 3.5.0 | 2026-07-30 | 9 C test suites |\n"
        )
        counts = update_docs._counts_module()
        assert counts.check_c_suite_counts(tmp_path) == []

    def test_the_real_tree_is_current(self) -> None:
        counts = update_docs._counts_module()
        assert counts.check_c_suite_counts(REPO_ROOT) == []
        assert counts.check_source_inventory_counts(REPO_ROOT) == []


class TestFuzzTargetCountsAreRegenerated:
    """`update_docs.py --counts` rewrites the fuzz-target counts the gate checks.

    Eleven prose counts across six documents restate the number of libFuzzer
    harnesses, the gate held them to it, and nothing rewrote them — so adding
    a harness (fuzz_lms) meant finding each by hand.
    """

    @staticmethod
    def _tree(root: Path, harnesses: int) -> None:
        (root / "fuzz").mkdir(parents=True)
        for i in range(harnesses):
            (root / "fuzz" / f"fuzz_t{i}.c").write_text(
                "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) {\n"
                "    (void)d; (void)n; return 0;\n}\n",
                encoding="utf-8",
            )
        # A support unit that names the entry point without defining it.
        (root / "fuzz" / "fuzz_rng.c").write_text(
            "/* linked into a harness; not an LLVMFuzzerTestOneInput */\n", encoding="utf-8"
        )

    def test_every_fuzz_line_is_rewritten_and_history_is_not(self, tmp_path: Path) -> None:
        self._tree(tmp_path, harnesses=3)
        doc = tmp_path / "README.md"
        doc.write_text(
            "- 9 libFuzzer fuzz targets run in CI\n"
            "Fuzz harnesses: 9 targets, plus 9 sources.\n"
            "| 3.5.0 | 2026-07-30 | 9 fuzz targets |\n"
            "\n"
            "The tree builds nine\n"
            "fuzzers, and Nine C harnesses feed them.\n"
            "\n"
            "9 targets in a paragraph that never mentions the word\n",
            encoding="utf-8",
        )
        counts = update_docs._counts_module()
        assert counts.check_fuzz_target_counts(tmp_path, 3), "the stale counts must be caught"
        assert update_docs.update_fuzz_target_counts(root=tmp_path) is True
        assert doc.read_text(encoding="utf-8") == (
            "- 3 libFuzzer fuzz targets run in CI\n"
            "Fuzz harnesses: 3 targets, plus 9 sources.\n"
            "| 3.5.0 | 2026-07-30 | 9 fuzz targets |\n"
            "\n"
            "The tree builds three\n"
            "fuzzers, and Three C harnesses feed them.\n"
            "\n"
            "9 targets in a paragraph that never mentions the word\n"
        )
        assert counts.check_fuzz_target_counts(tmp_path, 3) == []
        assert update_docs.update_fuzz_target_counts(root=tmp_path) is False


class TestThePublishedBenchmarkTableTracksTheRecord:
    """`wiki/Performance-Benchmarks.md`'s auto-table must match the record.

    `benchmark-report.md` has this pin (``test_the_published_report_matches_
    the_generator`` in tests/test_benchmark_baseline_infra.py), and it is what
    caught a rounding disagreement between the two published artefacts.  The
    WIKI page — the performance page README links, and the one an outside
    reader is most likely to quote — had none: it is written only by
    ``update_benchmark_docs``, nothing re-derived it, and a stale block or a
    deleted marker pair was invisible.

    The marker check is not decoration.  ``update_benchmark_docs`` substitutes
    between ``BENCH_START`` and ``BENCH_END``; delete either and the function
    silently stops writing the page while still exiting 0.
    """

    WIKI = REPO_ROOT / "wiki" / "Performance-Benchmarks.md"

    def _block(self) -> str:
        text = self.WIKI.read_text(encoding="utf-8")
        assert update_docs.BENCH_START in text, (
            f"{self.WIKI.name} has lost its {update_docs.BENCH_START} marker; "
            f"update_docs.update_benchmark_docs() would stop maintaining the "
            f"published table without reporting anything"
        )
        assert update_docs.BENCH_END in text, (
            f"{self.WIKI.name} has lost its {update_docs.BENCH_END} marker; "
            f"same consequence as a missing START marker"
        )
        start = text.index(update_docs.BENCH_START) + len(update_docs.BENCH_START)
        end = text.index(update_docs.BENCH_END)
        return text[start:end].strip("\n")

    def test_the_committed_block_is_what_the_generator_emits(self) -> None:
        expected = update_docs._generate_benchmark_table()
        assert expected, "the generator produced no table from the committed results JSON"
        assert self._block() == expected, (
            "wiki/Performance-Benchmarks.md's AUTO-BENCHMARK-TABLE block is not what "
            "tools/update_docs.py emits from benchmarks/benchmark-results.json; "
            "regenerate it with `python tools/update_docs.py` rather than editing it"
        )

    def test_the_generator_reads_the_measurement_record_not_the_floors(self) -> None:
        """The headline column must be the measured run, not baseline.json.

        Before 3.0.1 this generator pointed at ``baseline.json`` and published
        the regression FLOORS as headline throughput. The two files carry
        different numbers for the same primitive, so reading one row back
        against both is enough to say which one the table came from.
        """
        import json

        results = json.loads(
            (REPO_ROOT / "benchmarks" / "benchmark-results.json").read_text(encoding="utf-8")
        )
        block = self._block()
        # A row whose measured value and floor DIFFER, so finding the measured
        # one in the table is evidence about which file the generator read.
        # `>= 10_000` because that is the branch of the generator that formats
        # with `,.0f`; below it the cell carries one decimal place.
        row = next(
            (
                r
                for r in results["results"]
                if r["ops_per_second"] >= 10_000
                and round(r["ops_per_second"]) != round(r["baseline_value"])
            ),
            None,
        )
        assert row is not None, (
            "no row in benchmarks/benchmark-results.json has a measured value at "
            "or above 10,000 ops/sec that differs from its floor, so this "
            "assertion could not tell the two files apart — re-point it rather "
            "than letting it pass vacuously"
        )
        assert (
            f"| {row['ops_per_second']:,.0f} |" in block
        ), f"{row['name']}'s measured throughput is not in the published table"


class TestTheBenchmarkStatusLineSaysWhatHappened:
    """ "Already current" and "no markers found" are different outcomes.

    ``update_benchmark_docs`` printed the second for both, because the message
    was keyed to ``changed`` rather than to whether any file carried the
    markers.  A run over an up-to-date tree therefore reported that the
    AUTO-BENCHMARK-TABLE markers could not be found, in a tree where
    `wiki/Performance-Benchmarks.md` carries them — and a genuinely DELETED
    marker pair, which silently stops the published table tracking the
    measurements, read exactly like that no-op.
    """

    @staticmethod
    def _tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
        import json

        (tmp_path / "benchmarks").mkdir()
        results = tmp_path / "benchmarks" / "benchmark-results.json"
        results.write_text(
            json.dumps(
                {
                    "provenance": {"captured": "2026-01-01", "host": "h", "cpu": "c"},
                    "results": [
                        {
                            "name": "row_one",
                            "ops_per_second": 12345.0,
                            "baseline_value": 10000,
                            "tolerance_percent": 45,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (tmp_path / "benchmarks" / "baseline.json").write_text("{}", encoding="utf-8")
        (tmp_path / "page.md").write_text(body, encoding="utf-8")
        monkeypatch.setattr(update_docs, "ROOT", tmp_path)
        monkeypatch.setattr(update_docs, "BENCHMARK_RESULTS_JSON", results)
        monkeypatch.setattr(update_docs, "BASELINE_JSON", tmp_path / "benchmarks" / "baseline.json")

    def test_an_up_to_date_page_is_not_reported_as_missing_markers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._tree(
            tmp_path,
            monkeypatch,
            f"{update_docs.BENCH_START}\nplaceholder\n{update_docs.BENCH_END}\n",
        )
        assert update_docs.update_benchmark_docs() is True  # first run rewrites it
        capsys.readouterr()

        assert update_docs.update_benchmark_docs() is False  # second run is a no-op
        out = capsys.readouterr().out
        assert "already match" in out, out
        assert "no files with AUTO-BENCHMARK-TABLE markers found" not in out, out

    def test_a_page_without_markers_still_says_so(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._tree(tmp_path, monkeypatch, "no markers here\n")
        assert update_docs.update_benchmark_docs() is False
        out = capsys.readouterr().out
        assert "no files with AUTO-BENCHMARK-TABLE markers found" in out, out


class TestTheFullRunIsAFullRun:
    """``python tools/update_docs.py`` must rewrite every count ``--counts`` does.

    The full run stopped at the static test counts and never called
    ``update_inventory_counts``, so the run documented as "full update" left
    the C-suite and source-inventory figures stale while ``--counts`` — the
    narrower command — rewrote them.
    """

    _STEPS = (
        "update_changelog",
        "update_readme",
        "update_benchmark_docs",
        "update_pipeline_latency_docs",
        "update_wiki",
        "update_loc_metrics",
        "update_static_test_counts",
        "update_inventory_counts",
    )

    def _run(self, monkeypatch: pytest.MonkeyPatch, *argv: str) -> list[str]:
        called: list[str] = []
        for name in self._STEPS:

            def _record(dry_run: bool = False, _name: str = name) -> bool:
                called.append(_name)
                return False

            monkeypatch.setattr(update_docs, name, _record)
        monkeypatch.setattr("sys.argv", ["update_docs.py", *argv])
        update_docs.main()
        return called

    def test_the_full_run_includes_every_count_step(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        counts_only = set(self._run(monkeypatch, "--counts"))
        full = set(self._run(monkeypatch))
        capsys.readouterr()
        assert "update_inventory_counts" in counts_only, counts_only
        assert counts_only <= full, (
            f"--counts runs {sorted(counts_only - full)} and the full run does not, so "
            "`python tools/update_docs.py` leaves those figures stale"
        )

    def test_the_full_run_calls_every_step_once(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        called = self._run(monkeypatch)
        capsys.readouterr()
        assert sorted(called) == sorted(self._STEPS), called


class TestReplacementTextIsInsertedVerbatim:
    """Generated text is spliced in by a function, never as a ``re`` template.

    ``pattern.sub(f"...{table}...", text)`` hands the table to ``re`` as a
    template, and the table carries the measurement record's provenance.  A
    record captured on Windows made ``\\l`` and ``\\d`` a ``re.error: bad
    escape``, ``\\b`` a backspace, and ``\\1`` a group reference — measured
    against the pre-fix module, the first raised before any page was written.
    """

    _PROVENANCE: ClassVar[dict[str, str]] = {
        "host": r"C:\bench\host-01",
        "cpu": r"Intel\d Xeon",
        "command": r"LD_LIBRARY_PATH=build\lib python benchmarks\benchmark_runner.py \1",
        "sampling": r"5 runs \g<0>",
        "aggregation": "median",
        "native_backend": r"ama_cryptography.dll from build\lib",
    }

    def _tree(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        import json

        (tmp_path / "benchmarks").mkdir()
        results = tmp_path / "benchmarks" / "benchmark-results.json"
        results.write_text(
            json.dumps(
                {
                    "timestamp": "2026-09-24T00:00:00Z",
                    "provenance": self._PROVENANCE,
                    "results": [
                        {"name": "full_package_create", "ops_per_second": 500.0},
                        {"name": "dilithium_sign", "ops_per_second": 2000.0},
                        {"name": "ed25519_sign", "ops_per_second": 40000.0},
                    ],
                }
            ),
            encoding="utf-8",
        )
        (tmp_path / "benchmarks" / "baseline.json").write_text("{}", encoding="utf-8")
        page = tmp_path / "page.md"
        page.write_text(
            f"{update_docs.BENCH_START}\nold\n{update_docs.BENCH_END}\n\n"
            f"{update_docs.LATENCY_START}\nold\n{update_docs.LATENCY_END}\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(update_docs, "ROOT", tmp_path)
        monkeypatch.setattr(update_docs, "BENCHMARK_RESULTS_JSON", results)
        monkeypatch.setattr(update_docs, "BASELINE_JSON", tmp_path / "benchmarks" / "baseline.json")
        return page

    def test_backslashes_in_the_provenance_survive_both_tables(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        page = self._tree(tmp_path, monkeypatch)
        assert update_docs.update_benchmark_docs() is True
        assert update_docs.update_pipeline_latency_docs() is True
        capsys.readouterr()
        text = page.read_text(encoding="utf-8")
        bench = update_docs._generate_benchmark_table()
        latency = update_docs._generate_pipeline_latency_table()
        assert f"{update_docs.BENCH_START}\n{bench}\n{update_docs.BENCH_END}" in text
        assert f"{update_docs.LATENCY_START}\n{latency}\n{update_docs.LATENCY_END}" in text
        for value in self._PROVENANCE.values():
            assert value in text, f"{value!r} was not written verbatim"
        assert "\b" not in text

    def test_every_substitution_passes_a_function(self) -> None:
        """No ``sub`` call in the module takes a string template.

        Checked over the source because the property is "no call does it",
        which a behavioural test of the two provenance-bearing tables cannot
        establish for the version, date and count rewrites.
        """
        import ast

        source = (REPO_ROOT / "tools" / "update_docs.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        defined = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        offenders: list[str] = []
        calls = 0
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "sub"
            ):
                continue
            calls += 1
            module_level = isinstance(node.func.value, ast.Name) and node.func.value.id == "re"
            args = node.args[1:] if module_level else node.args
            repl = args[0] if args else None
            if isinstance(repl, ast.Lambda):
                continue
            if isinstance(repl, ast.Name) and repl.id in defined:
                continue
            if (
                isinstance(repl, ast.Call)
                and isinstance(repl.func, ast.Name)
                and repl.func.id == "_literal"
            ):
                continue
            offenders.append(f"line {node.lineno}: {ast.unparse(node)[:100]}")
        assert calls >= 10, f"found only {calls} sub() calls; the scan has stopped matching"
        assert not offenders, "sub() with a string template:\n" + "\n".join(offenders)
