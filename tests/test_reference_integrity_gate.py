# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for ``tools/check_reference_integrity.py``.

The gate rejects citations a reader cannot resolve. A gate nobody has watched
fail is a gate nobody has watched, so every shape it claims to catch is driven
through it here, and — the half that matters more for a pattern-based check —
so is every shape it must NOT catch.

The false-positive cases are not padding; they are most of the point. Earlier
versions of this gate also matched "the audit's", "a previous session",
"another session" and "the audit session". Every one of them caught real
dangling references — and every one also matched correct prose, because
``tools/check_error_state_gating.py`` defines a function named ``audit()`` and
this package implements ``SessionStore``. A pattern that forces correct prose to
change in order to satisfy a linter is a worse defect than the one it caught,
and a gate that cries wolf is a gate that gets switched off. Those clauses were
dropped, the four dangling uses they had found were fixed by hand, and the cases
below pin the boundary so it cannot drift back.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import ClassVar

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools.check_reference_integrity import (  # noqa: E402 -- repo-root path insert above (REF-001)
    EXEMPT,
    NOT_PROSE_TYPES,
    SCANNED_DIRS,
    SCANNED_NAMES,
    SCANNED_ROOT_FILES,
    SUFFIXES,
    TEST_CITATION_DIRS,
    _is_historical_record,
    _tracked_files,
    check,
    file_type,
    main,
    scan_test_citations,
    scan_text,
)


class TestTheShapesItMustCatch:
    """Each is a reference to something no reader of the repository can open."""

    @pytest.mark.parametrize(
        "text",
        [
            "# (2026-08 v5 audit, item 15 — alert-window suppression.)",
            "# see 2026-09 v5 audit for the rationale",
            "# fixed per item 15 of the audit",
            '"""Regression pin from the 2025-12 v4 audit."""',
            # Each of these passed before the patterns were widened.
            "# (v5 audit, 2026-08, item 15)",
            "# closes audit item 15",
            "# the 2026-08 audit's finding #5",
            "# The audit flagged exactly this (finding #7)",
            "# fixed per item 3 of the v5 audit",
        ],
    )
    def test_a_process_citation_is_reported(self, text: str) -> None:
        findings = scan_text(text)
        assert findings, f"not caught: {text!r}"
        assert "not in the repository" in findings[0][2]

    @pytest.mark.parametrize(
        "text",
        [
            "# the AEAD nonce at line 632",
            "# markers at lines 314 and 339",
            "# see line 1098 for the second draw",
            "# per lines 40",
            # Each of these passed before the patterns were widened.
            "# the nonce in line 632",
            "# the nonce (line 632) is drawn fresh",
            "# see line 7",
            "# Lifted byte-for-byte from src/c/ama_argon2.c lines 380-466.",
            "> `.gitignore` line 178 excludes the generated sources",
            "# hooked at `src/c/dispatch/ama_dispatch.c` lines 596-599",
            # A citation wrapped onto the next comment line.  Both of these
            # sat in src/c and passed while the gap before "line" was a bare
            # \s+, which cannot cross the continuation's ` * `.
            " * wired at `src/c/dispatch/ama_dispatch.c`\n * line 588-589).",
            " *     host (see\n *     lines 354-357 above).",
            "# hooked in src/c/ama_argon2.c\n# lines 380-466",
            "// wired in ama_dispatch.c\n// line 588",
        ],
    )
    def test_a_source_line_citation_is_reported(self, text: str) -> None:
        findings = scan_text(text)
        assert findings, f"not caught: {text!r}"
        assert "line number" in findings[0][2]

    def test_the_report_names_the_line_it_found(self) -> None:
        line, matched, _ = scan_text("alpha\nbeta\n# (2026-08 v5 audit)\n")[0]
        assert line == 3
        assert "2026-08 v5 audit" in matched


class TestTheShapesItMustNotCatch:
    """Correct prose must survive the gate untouched."""

    @pytest.mark.parametrize(
        "text",
        [
            # Protocol sessions are not development sessions.
            "# the AEAD nonce and this session ID are both bare draws",
            "* @param num_signers  Number of signers in this session",
            "ttl_seconds: Override default TTL for this session",
            "# a session that is closed in place must not be handed back",
            # `audit()` is a real function in tools/check_error_state_gating.py.
            "# Deleting the guard left the audit's output completely unchanged.",
            "# the one module this gate audits",
            # This package implements SessionStore/SessionState, so these read
            # as protocol prose.  Each phrasing below was written, caught real
            # instances, and was removed because it also matched correct code.
            "# a previous session's keys must not decrypt this one",
            "# rekeying starts another session",
            "# the audit session record is flushed on close",
            # Runtime messages carry a placeholder, not a citation.
            'raise ValueError(f"malformed entry at line {n}")',
            'printf("parse error at line %d\\n", lineno);',
            # A line COUNT is not a line citation.
            "# seventeen hundred lines above",
            "# the diff touched 632 lines",
            # A line of a published algorithm resolves in the standard.
            "defined in FIPS 204 §5.2 (lines 5–6) before invoking",
            "* mu = H(tr || M) — FIPS 204 Algorithm 7 line 6",
            # Line 1 is a fixed position; a fixture's lines are pinned beside it.
            "# `# type: ignore` on line 1 is mypy's whole-file form",
            "# The `if` sits on line 6 of the fixture (line 1 is blank).",
            # A CodeQL alert number resolves in code scanning; a dated audit
            # event is not an item citation.
            "# closes CodeQL findings #504/#505/#506",
            "# until the 2026-09 audit (A-2) it could not",
            "# kept in line with the header",
            # Wrapping onto a comment continuation cites nothing by itself.
            " * the layout of `foo.c`\n * lines up with the header",
            " * kept in\n * line with the header",
            " * defined in FIPS 204 §5.2 (see\n * lines 5-6) before invoking",
        ],
    )
    def test_correct_prose_is_left_alone(self, text: str) -> None:
        assert scan_text(text) == [], f"false positive on: {text!r}"


class TestTheExemptionsAreHonest:
    """An exemption is a hole; each one here must still be load-bearing."""

    def test_there_are_exactly_two(self) -> None:
        """``CHANGELOG.md`` was a third entry that could never take effect.

        It is not in ``SCANNED_ROOT_FILES``, so the gate never opened it and the
        exemption exempted nothing.  A dead exemption is still a hole: the day
        someone widens the scope, it silently decides the outcome.
        """
        assert set(EXEMPT) == {
            "tools/check_reference_integrity.py",
            "tests/test_reference_integrity_gate.py",
        }, (
            "the exemption list changed — a new entry is a new place for an "
            "unresolvable citation to hide, and needs its own justification"
        )

    def test_each_carries_a_reason(self) -> None:
        for name, reason in EXEMPT.items():
            assert reason.strip(), f"{name} is exempt with no stated reason"

    @pytest.mark.parametrize("name", sorted(EXEMPT))
    def test_each_exempt_file_really_would_trip_the_gate(self, name: str) -> None:
        # The point of the exemption is that the file legitimately contains a
        # rejected shape.  If it no longer does, the exemption has outlived its
        # reason and is now only a hole.
        path = REPO_ROOT / name
        assert path.is_file(), f"{name} is exempt but does not exist"
        assert scan_text(path.read_text(encoding="utf-8")), (
            f"{name} no longer contains any rejected shape, so its exemption "
            "now proves nothing — remove it from EXEMPT"
        )

    @pytest.mark.parametrize("name", sorted(EXEMPT))
    def test_each_exemption_is_inside_the_scanned_scope(self, name: str) -> None:
        """An exemption for a file the gate never reads is dead, not load-bearing."""
        in_dirs = name.split("/", 1)[0] in SCANNED_DIRS
        assert in_dirs or name in SCANNED_ROOT_FILES, f"{name} is exempt but never scanned"

    def test_the_changelog_is_out_of_scope_rather_than_exempt(self) -> None:
        assert "CHANGELOG.md" not in SCANNED_ROOT_FILES
        assert "CHANGELOG.md" not in EXEMPT

    def test_the_development_journal_is_out_of_scope_rather_than_exempt(self) -> None:
        """The dated entries moved out of the CHANGELOG are the same record.

        They sit under ``docs/``, which is scanned, so they are dropped from the
        scope by ``tools/_repo.py``'s ``is_historical_record`` rather than
        listed in ``EXEMPT``, whose entries must each be load-bearing.
        """
        journal = "docs/changelog/5.0.0-development-journal.md"
        assert (REPO_ROOT / journal).is_file()
        assert journal.split("/", 1)[0] in SCANNED_DIRS
        assert journal not in EXEMPT
        scanned = {p.relative_to(REPO_ROOT).as_posix() for p in _tracked_files(REPO_ROOT)}
        assert journal not in scanned
        assert "docs/METRICS_REPORT.md" in scanned, "docs/ itself fell out of scope"

    def test_an_exempt_file_is_not_scanned(self) -> None:
        _, problems = check(REPO_ROOT)
        for name in EXEMPT:
            assert not any(p.startswith(f"{name}:") for p in problems)


class TestTestCitationsInTheShippedCode:
    """Shape 3: a comment in the shipped code that names a test names one that exists.

    ``src/c/ama_dilithium.c`` cited ``test_a_permuted_hint_is_refused`` as the
    pin for ML-DSA's hint-ordering rule; the test never existed and the rule's
    rejection ran under no suite.
    """

    TRACKED: ClassVar[frozenset[str]] = frozenset({"tests/c/test_real.c", "tests/test_real.py"})
    SOURCES: ClassVar[dict[str, str]] = {"tests/test_real.py": "def test_present() -> None: ...\n"}

    def _scan(self, text: str) -> list[tuple[int, str, str]]:
        return scan_test_citations(text, set(self.TRACKED), self.SOURCES.__getitem__)

    def test_a_missing_test_file_is_reported(self) -> None:
        found = self._scan("/* pinned by tests/c/test_imagined.c */\n")
        assert [(line, cited) for line, cited, _ in found] == [(1, "tests/c/test_imagined.c")]

    def test_a_tracked_test_file_passes(self) -> None:
        assert self._scan("/* pinned by tests/c/test_real.c */\n") == []

    def test_a_path_wrapped_onto_a_comment_continuation_is_joined(self) -> None:
        assert self._scan("/* see tests/test_\n * real.py for the pin */\n") == []
        found = self._scan("/* see tests/test_\n * imagined.py for the pin */\n")
        assert [cited for _, cited, _ in found] == ["tests/test_imagined.py"]

    def test_a_missing_named_test_is_reported(self) -> None:
        found = self._scan("# pinned by `test_absent` in tests/test_real.py\n")
        assert [cited for _, cited, _ in found] == ["test_absent in tests/test_real.py"]

    def test_a_present_named_test_passes_even_when_wrapped(self) -> None:
        assert self._scan("/* pinned by\n * `test_present` in\n * tests/test_real.py */\n") == []

    def test_a_named_test_in_a_missing_file_is_reported_once(self) -> None:
        found = self._scan("# `test_x` in tests/test_gone.py\n")
        assert [cited for _, cited, _ in found] == ["tests/test_gone.py"]

    def test_the_scope_is_the_shipped_code(self) -> None:
        assert TEST_CITATION_DIRS == ("ama_cryptography", "src", "include")

    @pytest.mark.parametrize(
        ("where", "expected"),
        [("src/c/planted.c", 1), ("include/planted.h", 1), ("tests/c/planted.c", 0)],
    )
    def test_the_cli_fails_on_a_dangling_test_citation_in_scope(
        self, tmp_path: Path, where: str, expected: int
    ) -> None:
        """In tests/ a fictional path is a fixture, so the same text passes there."""
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        planted = tmp_path / where
        planted.parent.mkdir(parents=True)
        planted.write_text("/* pinned by tests/c/test_imagined.c */\n", encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
        assert main(["--repo", str(tmp_path)]) == expected


class TestTheTreeIsClean:
    """The gate's verdict on the repository as it actually stands."""

    def test_every_citation_in_the_shipped_tree_resolves(self) -> None:
        checked, problems = check(REPO_ROOT)
        assert problems == [], "\n".join(problems)
        assert checked > 100, f"only {checked} files scanned — scope collapsed"

    def test_the_cli_agrees(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--repo", str(REPO_ROOT)]) == 0
        assert "every citation resolves" in capsys.readouterr().out

    def test_the_cli_reports_failure_on_a_planted_violation(self, tmp_path: Path) -> None:
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        pkg = tmp_path / "ama_cryptography"
        pkg.mkdir()
        (pkg / "planted.py").write_text("# (2026-08 v5 audit, item 15)\n", encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
        assert main(["--repo", str(tmp_path)]) == 1

    def test_an_empty_scope_fails_closed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """ "OK 0 file(s) checked" was a pass over nothing."""
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        assert main(["--repo", str(tmp_path)]) == 1
        assert "0 files in scope" in capsys.readouterr().out

    def test_the_epilog_states_what_is_not_checked(self) -> None:
        text = subprocess.run(
            [sys.executable, "tools/check_reference_integrity.py", "--help"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        assert "NOT checked" in text
        assert "CHANGELOG.md" in text


class TestEveryProseFormatInScopeIsRead:
    """The suffix list had to be complete for the declared scope to be true.

    ``tests/`` and ``docs/`` were scanned directories, yet ``.rst`` (the Sphinx
    pages) and ``.txt`` (``tests/c/CMakeLists.txt``) were not scanned types.
    The CMake file carried two ``(2026-08 v5 audit)`` citations — this gate's
    own motivating shape — while it reported every citation resolved.
    """

    def test_every_tracked_file_in_scope_is_scanned_or_declared_data(self) -> None:
        """A partition, not a spot check: a new prose type cannot slip past."""
        listed = subprocess.run(
            ["git", "ls-files", "-z", *SCANNED_DIRS, *SCANNED_ROOT_FILES],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        scanned = {p.relative_to(REPO_ROOT).as_posix() for p in _tracked_files(REPO_ROOT)}
        unread = sorted(
            name
            for name in listed.split("\0")
            if name
            and name not in scanned
            and name not in EXEMPT
            and not _is_historical_record(name)
            and file_type(Path(name)) not in NOT_PROSE_TYPES
            and (REPO_ROOT / name).is_file()
        )
        assert unread == [], (
            "tracked files in the declared scope that the gate never reads; add "
            f"their type to SUFFIXES/SCANNED_NAMES or, if data, NOT_PROSE_TYPES: {unread}"
        )

    def test_no_type_is_both_prose_and_data(self) -> None:
        assert not (SUFFIXES | SCANNED_NAMES) & set(NOT_PROSE_TYPES)

    @pytest.mark.parametrize(
        "name",
        [
            "tests/c/CMakeLists.txt",
            "docs/index.rst",
            "docs/Doxyfile",
            "tools/constant_time/Makefile",
        ],
    )
    def test_the_formerly_skipped_files_are_scanned(self, name: str) -> None:
        scanned = {p.relative_to(REPO_ROOT).as_posix() for p in _tracked_files(REPO_ROOT)}
        assert name in scanned

    def test_a_citation_in_cmake_or_rst_fails_the_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        (tmp_path / "tests" / "c").mkdir(parents=True)
        (tmp_path / "docs").mkdir()
        (tmp_path / "tests" / "c" / "CMakeLists.txt").write_text(
            "# Item-8 post-free scrub (2026-08 v5 audit)\n", encoding="utf-8"
        )
        (tmp_path / "docs" / "page.rst").write_text(
            "Title\n=====\n\nThe nonce is derived at line 632.\n", encoding="utf-8"
        )
        subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
        assert main(["--repo", str(tmp_path)]) == 1
        out = capsys.readouterr().out
        assert "tests/c/CMakeLists.txt:1:" in out, out
        assert "docs/page.rst:4:" in out, out
