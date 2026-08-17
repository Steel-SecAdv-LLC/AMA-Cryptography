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
