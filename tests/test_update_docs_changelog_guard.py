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

from pathlib import Path

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

    def test_the_prepared_release_section_is_not_dated(self) -> None:
        """5.0.0 is prepared, not released — its heading must not claim a date.

        Under Keep a Changelog the date on a version heading is the release
        date. Writing one before the tag exists states that the release
        happened. It is filled in at tag time, after the mandatory release
        dry run.
        """
        text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        version = update_docs._get_version()
        for line in text.splitlines():
            match = update_docs._CHANGELOG_HEADING_RE.match(line)
            if match and match.group(1).strip() == version:
                suffix = (match.group(2) or "").strip()
                assert suffix.lower() == "unreleased", (
                    f"CHANGELOG heading for the in-development version {version} "
                    f"carries {suffix!r}. Under Keep a Changelog that is a release "
                    f"date, and no v{version} tag exists yet. Replace it with the "
                    f"real date at tag time."
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

    def test_the_real_tree_is_current_after_a_regeneration(self) -> None:
        """Meta-check: this repository's own aggregate claims are current, so
        the command the gate recommends does leave the gate green."""
        counts = update_docs._counts_module()
        problems = counts.check_aggregate_test_counts(REPO_ROOT)
        assert problems == [], problems


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
        row = next(r for r in results["results"] if r["ops_per_second"] >= 10_000)
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
