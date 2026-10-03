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
import time
from pathlib import Path
from typing import ClassVar

import pytest

from tools.check_reference_integrity import (
    EXEMPT,
    NOT_PROSE_TYPES,
    SCANNED_DIRS,
    SCANNED_NAMES,
    SCANNED_ROOT_FILES,
    SUFFIXES,
    TEST_CITATION_DIRS,
    SuiteIndex,
    _is_historical_record,
    _plugin_runs,
    _tracked_files,
    c_definitions,
    check,
    code_identifiers,
    extract_test_citations,
    file_type,
    main,
    scan_shipped_text,
    scan_test_citations,
    scan_text,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _git_repo(root: Path, files: dict[str, str]) -> Path:
    """A repository at ``root`` holding ``files``, all of them tracked."""
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    return root


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


#: The fixture repository the shape-3 tests resolve against.  Every Python
#: file is collected by pytest itself (see ``SuiteIndex``), so each case below
#: is a statement about what pytest collects, not about a model of it.
_PY_FIXTURE = (
    '"""test_in_prose is named here and nowhere else.\n'
    "def test_in_docstring_code(): ...\n"
    '"""\n'
    "\n"
    "import unittest\n"
    "\n"
    "import pytest\n"
    "\n"
    "\n"
    "def test_present() -> None: ...\n"
    "\n"
    "\n"
    "class TestGroup:\n"
    "    def test_method(self) -> None: ...\n"
    "\n"
    "    class TestNested:\n"
    "        def test_in_a_nested_class(self) -> None: ...\n"
    "\n"
    "\n"
    'HELPER = "test_in_a_string"\n'
    "\n"
    "\n"
    "def helper() -> None:\n"
    "    def test_inside_a_function() -> None: ...\n"
    "\n"
    "\n"
    "class Helper:\n"
    "    def test_in_an_uncollected_class(self) -> None: ...\n"
    "\n"
    "\n"
    "class TestWithInit:\n"
    "    def __init__(self) -> None: ...\n"
    "\n"
    "    def test_in_a_class_with_init(self) -> None: ...\n"
    "\n"
    "\n"
    "class TestSwitchedOff:\n"
    "    __test__ = False\n"
    "\n"
    "    def test_switched_off(self) -> None: ...\n"
    "\n"
    "\n"
    "def test_shadowed() -> None: ...\n"
    "\n"
    "\n"
    "test_shadowed = None\n"
    "\n"
    "\n"
    "class MyCase(unittest.TestCase):\n"
    "    def test_in_a_unittest_case(self) -> None: ...\n"
    "\n"
    "\n"
    "class _Mixin:\n"
    "    def test_inherited(self) -> None: ...\n"
    "\n"
    "\n"
    "class TestChild(_Mixin):\n"
    "    pass\n"
    "\n"
    "\n"
    "if True:\n"
    "\n"
    "    def test_under_if() -> None: ...\n"
    "\n"
    "\n"
    "try:\n"
    "\n"
    "    def test_under_try() -> None: ...\n"
    "\n"
    "except ImportError:\n"
    "    pass\n"
    "\n"
    "\n"
    "def _factory():\n"
    "    def made() -> None: ...\n"
    "\n"
    "    return made\n"
    "\n"
    "\n"
    "test_made_by_a_factory = _factory()\n"
    "\n"
    "\n"
    "async def test_async_function() -> None: ...\n"
    "\n"
    "\n"
    "class TestAsync:\n"
    "    async def test_async_method(self) -> None: ...\n"
    "\n"
    "\n"
    '@pytest.mark.parametrize("case", ["p256", "p384"])\n'
    "def test_parametrised(case: str) -> None: ...\n"
)

_C_FIXTURE = """/* test_in_a_comment(void) is described here only. */
static int test_defined(void) {
    return test_called_only(1);
}
static int test_declared_only(void);
static const char *const label = "test_in_a_c_string(void) {";
static void
test_split_signature(int unused)
{
    int rc = 0;
    if (rc == 0 &&
        test_called_in_a_condition(rc)) {
        rc = 1;
    }
    puts("done; static int test_after_a_string_brace(void) {");
    char open = '{';
    int test_nested_function(int y) { return y; }
}
/* Example; a harness may define
static int test_in_a_block_comment(void) {
   and nothing here closes it */
#if 0
static int test_under_if_0(void) {
    return 0;
}
#endif
#define TEST_OPEN_BRACE \\
    {
__attribute__((unused)) static int test_with_an_attribute(void) {
    return 0;
}
static int test_fn_ptr_param(int (*cb)(int)) {
    return cb(0);
}
"""

_H_FIXTURE = """#ifndef TEST_REAL_H
#define TEST_REAL_H
#ifdef __cplusplus
extern "C" {
#endif
static inline int test_in_a_header(void) { return 0; }
int test_prototype_in_a_header(void);
#ifdef __cplusplus
}
#endif
#endif
"""

_SUITE_FILES = {
    # python_files is widened here so that a module outside the default
    # pattern is collected only because the configuration says so.
    "pytest.ini": "[pytest]\npython_files = test_*.py check_*.py\n",
    "tests/conftest.py": (
        "import os\n\n"
        "# The gate sets this for the collection it runs; a conftest that\n"
        "# needs it (tests/conftest.py imports the package) collects nothing\n"
        "# without it.\n"
        'if os.environ.get("AMA_POST_DIAGNOSTIC_IMPORT") != "1":\n'
        '    raise RuntimeError("collected without AMA_POST_DIAGNOSTIC_IMPORT=1")\n\n'
        'collect_ignore = ["test_ignored_by_conftest.py"]\n\n\n'
        "def test_in_conftest() -> None: ...\n"
    ),
    "tests/test_real.py": _PY_FIXTURE,
    "tests/ref_helpers.py": "def test_in_a_helper_module() -> None: ...\n",
    "tests/check_extra.py": "def test_in_a_configured_module() -> None: ...\n",
    "tests/test_ignored_by_conftest.py": "def test_in_an_ignored_module() -> None: ...\n",
    "tests/test_broken.py": (
        "import a_module_that_does_not_exist  # the collection error under test\n\n\n"
        "def test_in_a_broken_module() -> None: ...\n"
    ),
    "tests/test_class_error.py": (
        "import pytest\n\n\n"
        "def test_beside_a_broken_class() -> None: ...\n\n\n"
        "class TestBroken:\n"
        '    @pytest.mark.parametrize("missing", [1])\n'
        "    def test_bad(self) -> None: ...\n"
    ),
    "tests/test_other.py": "def test_only_in_the_other_file() -> None: ...\n",
    "tests/test_syntax_error.py": (
        "def test_before_a_syntax_error() -> None: ...\n\n\ndef (:  # does not parse\n"
    ),
    "tests/test_deleted.py": "def test_in_a_deleted_file() -> None: ...\n",
    "tests/c/test_real.c": _C_FIXTURE,
    "tests/c/test_real.h": _H_FIXTURE,
    "tests/c/test_dup.c": "static int test_dup_one(void) { return 0; }\n",
    "tests/sub/test_dup.c": "static int test_dup_two(void) { return 0; }\n",
    "tests/data/vectors.json": '{"test_in_json": 1}\n',
    "tests/data/SLH-DSA-sigGen.json": "{}\n",
}


@pytest.fixture(scope="module")
def suite(tmp_path_factory: pytest.TempPathFactory) -> SuiteIndex:
    """The fixture repository, indexed once and collected in one pytest run.

    ``tests/test_deleted.py`` is tracked and then deleted from the working
    tree; ``tests/test_untracked.py`` is on disk and never added."""
    root = _git_repo(tmp_path_factory.mktemp("suite"), _SUITE_FILES)
    (root / "tests" / "test_deleted.py").unlink()
    (root / "tests" / "test_untracked.py").write_text(
        "def test_in_an_untracked_file() -> None: ...\n", encoding="utf-8"
    )
    index = SuiteIndex(root)
    index.prime_files(sorted(p for p in index.present if p.endswith(".py")))
    return index


def _scan(suite: SuiteIndex, text: str) -> list[tuple[int, str, str]]:
    return scan_test_citations(text, suite)


def _cited(suite: SuiteIndex, text: str) -> list[str]:
    return [cited for _, cited, _ in _scan(suite, text)]


class TestTestCitationsInTheShippedCode:
    """Shape 3: a comment in the shipped code that names a test names one that exists.

    ``src/c/ama_dilithium.c`` cited ``test_a_permuted_hint_is_refused`` as the
    pin for ML-DSA's hint-ordering rule; the test never existed and the rule's
    rejection ran under no suite.
    """

    def test_the_report_names_the_line_the_citation_starts_on(self, suite: SuiteIndex) -> None:
        text = (
            "alpha\n"
            "/* tests/c/test_imagined.c */\n"
            "beta\n"
            "/* pinned by\n"
            " * `test_absent` in\n"
            " * tests/test_real.py */\n"
        )
        assert [(line, cited) for line, cited, _ in _scan(suite, text)] == [
            (2, "tests/c/test_imagined.c"),
            (5, "test_absent in tests/test_real.py"),
        ]

    def test_a_missing_test_file_is_reported(self, suite: SuiteIndex) -> None:
        found = _scan(suite, "/* pinned by tests/c/test_imagined.c */\n")
        assert [(line, cited) for line, cited, _ in found] == [(1, "tests/c/test_imagined.c")]

    def test_a_tracked_test_file_passes(self, suite: SuiteIndex) -> None:
        assert _scan(suite, "/* pinned by tests/c/test_real.c */\n") == []

    def test_a_path_wrapped_onto_a_comment_continuation_is_joined(self, suite: SuiteIndex) -> None:
        assert _scan(suite, "/* see tests/test_\n * real.py for the pin */\n") == []
        found = _scan(suite, "/* see tests/test_\n * imagined.py for the pin */\n")
        assert [cited for _, cited, _ in found] == ["tests/test_imagined.py"]

    def test_a_path_that_ends_a_line_is_not_joined_to_the_next(self, suite: SuiteIndex) -> None:
        """A citation followed by prose on the next line is still the citation."""
        assert _scan(suite, "/* pinned by tests/test_real.py\n * and nothing else */\n") == []
        assert _scan(suite, "# every file under tests/c/\n# named here is compiled\n") == []

    def test_a_path_broken_after_a_slash_is_joined(self, suite: SuiteIndex) -> None:
        assert _scan(suite, "/* tests/c/\n * test_real.c pins it */\n") == []
        found = _scan(suite, "/* tests/c/\n * test_imagined.c pins it */\n")
        assert [cited for _, cited, _ in found] == ["tests/c/test_imagined.c"]

    def test_a_missing_named_test_is_reported(self, suite: SuiteIndex) -> None:
        found = _scan(suite, "# pinned by `test_absent` in tests/test_real.py\n")
        assert [cited for _, cited, _ in found] == ["test_absent in tests/test_real.py"]

    def test_a_present_named_test_passes_even_when_wrapped(self, suite: SuiteIndex) -> None:
        assert _scan(suite, "/* pinned by\n * `test_present` in\n * tests/test_real.py */\n") == []

    def test_a_named_test_whose_path_wraps_is_still_checked(self, suite: SuiteIndex) -> None:
        """The file resolves after unwrapping, so only the name can be wrong."""
        found = _scan(suite, "/* pinned by `test_absent` in tests/test_\n * real.py */\n")
        assert [cited for _, cited, _ in found] == ["test_absent in tests/test_real.py"]
        assert _scan(suite, "/* pinned by `test_present` in tests/test_\n * real.py */\n") == []

    @pytest.mark.parametrize(
        ("name", "path"),
        [
            ("test_present", "tests/test_real.py"),
            ("test_method", "tests/test_real.py"),
            ("test_in_a_nested_class", "tests/test_real.py"),
            ("test_parametrised", "tests/test_real.py"),
            ("test_defined", "tests/c/test_real.c"),
            ("test_split_signature", "tests/c/test_real.c"),
            ("test_with_an_attribute", "tests/c/test_real.c"),
            ("test_fn_ptr_param", "tests/c/test_real.c"),
            ("test_in_a_header", "tests/c/test_real.h"),
        ],
    )
    def test_a_defined_test_resolves(self, suite: SuiteIndex, name: str, path: str) -> None:
        assert _scan(suite, f"/* pinned by `{name}` in {path} */\n") == []

    @pytest.mark.parametrize(
        ("name", "path"),
        [
            ("test_in_prose", "tests/test_real.py"),
            ("test_in_a_string", "tests/test_real.py"),
            ("test_in_docstring_code", "tests/test_real.py"),
            ("test_in_a_comment", "tests/c/test_real.c"),
            ("test_called_only", "tests/c/test_real.c"),
            ("test_declared_only", "tests/c/test_real.c"),
            ("test_in_a_c_string", "tests/c/test_real.c"),
            ("test_called_in_a_condition", "tests/c/test_real.c"),
            ("test_after_a_string_brace", "tests/c/test_real.c"),
            ("test_nested_function", "tests/c/test_real.c"),
            ("test_in_a_block_comment", "tests/c/test_real.c"),
            ("test_under_if_0", "tests/c/test_real.c"),
            ("test_prototype_in_a_header", "tests/c/test_real.h"),
        ],
    )
    def test_a_name_that_is_only_mentioned_does_not_resolve(
        self, suite: SuiteIndex, name: str, path: str
    ) -> None:
        """A docstring, comment, string, call, prototype, nested function or
        ``#if 0`` region names a test; only a file-scope definition is one."""
        found = _scan(suite, f"/* pinned by `{name}` in {path} */\n")
        assert [cited for _, cited, _ in found] == [f"{name} in {path}"]

    def test_the_node_id_form_is_checked_too(self, suite: SuiteIndex) -> None:
        """``tests/test_x.py::test_y`` is as common in comments as
        "test_y in tests/test_x.py"; a dangling citation in that form used to
        pass the gate unread."""
        found = _scan(suite, "# pinned by `tests/test_real.py::test_absent`\n")
        assert [cited for _, cited, _ in found] == ["tests/test_real.py::test_absent"]
        assert _scan(suite, "# pinned by tests/test_real.py::test_present\n") == []

    @pytest.mark.parametrize(
        ("text", "cited"),
        [
            ("# pinned by `test_absent()` in `tests/test_real.py`\n", None),
            ("``test_absent`` in ``tests/test_real.py``.\n", None),
            ("# test_absent[p256] in tests/test_real.py\n", None),
            ("# test_absent of tests/test_real.py\n", None),
            ("# see test_absent from tests/test_real.py\n", None),
            ("# pinned: test_absent (tests/test_real.py)\n", None),
            (
                "# ``tests/test_real.py::TestGroup::test_absent``\n",
                "tests/test_real.py::TestGroup::test_absent",
            ),
            ("# tests/test_real.py::test_absent[p256]\n", "tests/test_real.py::test_absent"),
            # Each of these passed unread until 2026-09-28.
            ("# test_absent(self) in tests/test_real.py\n", None),
            ("# test_absent In tests/test_real.py\n", None),
            ("# test_absent at tests/test_real.py\n", None),
            ("# tests/test_real.py: test_absent\n", None),
            ("# tests/test_real.py (test_absent)\n", None),
            ("# test_absent in ./tests/test_real.py\n", "test_absent in tests/test_real.py"),
        ],
    )
    def test_the_spellings_prose_uses_are_read(
        self, suite: SuiteIndex, text: str, cited: str | None
    ) -> None:
        """Call parentheses (empty or not), a parametrised case, rst double
        backticks, ``in``/``of``/``from``/``at`` in any case, a parenthesised
        path, a path first, and a class-qualified node id: each let a dangling
        citation pass unread.  A node id is reported as the node id."""
        assert _cited(suite, text) == [cited or "test_absent in tests/test_real.py"], text

    @pytest.mark.parametrize(
        "text",
        [
            "# pinned by `test_present()` in `tests/test_real.py`\n",
            "``test_present`` in ``tests/test_real.py``.\n",
            "# test_method[p256] of tests/test_real.py\n",
            "# pinned: test_present (tests/test_real.py)\n",
            "# ``tests/test_real.py::TestGroup::test_method``\n",
            "# tests/test_real.py::TestGroup::TestNested::test_in_a_nested_class\n",
            "# test_method(self) In tests/test_real.py\n",
            "# tests/test_real.py: test_present\n",
            "# tests/test_real.py (test_present)\n",
            "# tests/test_real.py::test_parametrised[p256]\n",
        ],
    )
    def test_the_same_spellings_resolve_when_the_test_exists(
        self, suite: SuiteIndex, text: str
    ) -> None:
        assert _scan(suite, text) == [], text

    @pytest.mark.parametrize(
        "text",
        [
            "# test_absent and test_present in tests/test_real.py\n",
            "# test_present, test_absent in tests/test_real.py\n",
            "# test_present, test_method, and test_absent in tests/test_real.py\n",
            "# ``test_present`` or ``test_absent`` in ``tests/test_real.py``\n",
            "# tests/test_real.py: test_present, test_absent\n",
            "# tests/test_real.py (test_present and test_absent)\n",
        ],
    )
    def test_every_name_in_a_list_is_checked(self, suite: SuiteIndex, text: str) -> None:
        """``test_a and test_b in tests/y.py`` cites both; until 2026-09-28
        only the last name was read, so a dangling first one passed."""
        assert _cited(suite, text) == ["test_absent in tests/test_real.py"], text

    @pytest.mark.parametrize(
        "name",
        [
            "test_inside_a_function",
            "test_in_an_uncollected_class",
            "test_in_a_class_with_init",
            "test_switched_off",
            "test_shadowed",
        ],
    )
    def test_a_definition_pytest_would_not_collect_does_not_resolve(
        self, suite: SuiteIndex, name: str
    ) -> None:
        """A ``def`` nested in a function, a method of a class outside
        ``python_classes``, of a ``Test*`` class with an ``__init__`` or with
        ``__test__ = False``, and a ``def`` a later assignment shadows: pytest
        collects none of them, so none is the pin a citation claims.  The last
        three resolved while the gate modelled collection with :mod:`ast`."""
        found = _scan(suite, f"# pinned by `{name}` in tests/test_real.py\n")
        assert [cited for _, cited, _ in found] == [f"{name} in tests/test_real.py"]

    @pytest.mark.parametrize(
        "name",
        [
            "test_in_a_unittest_case",
            "test_inherited",
            "test_under_if",
            "test_under_try",
            "test_made_by_a_factory",
        ],
    )
    def test_a_test_pytest_collects_resolves_however_it_is_defined(
        self, suite: SuiteIndex, name: str
    ) -> None:
        """A ``unittest.TestCase`` method, a method a ``Test*`` class inherits
        from an uncollected base, a ``def`` under ``if`` or ``try``, and a test
        assigned from a factory: pytest runs each, and each was reported as
        missing while the gate modelled collection with :mod:`ast`."""
        assert _scan(suite, f"# pinned by `{name}` in tests/test_real.py\n") == []

    @pytest.mark.parametrize(
        ("path", "name"),
        [
            ("tests/conftest.py", "test_in_conftest"),
            ("tests/ref_helpers.py", "test_in_a_helper_module"),
            ("tests/test_ignored_by_conftest.py", "test_in_an_ignored_module"),
        ],
    )
    def test_a_module_pytest_does_not_collect_resolves_nothing(
        self, suite: SuiteIndex, path: str, name: str
    ) -> None:
        """``tests/ref_keyformat.py`` and ``tests/conftest.py`` are tracked
        modules that a plain ``pytest`` run never collects: one is outside
        ``python_files``, the other is a conftest; a ``collect_ignore`` entry
        drops a third.  Named explicitly on pytest's command line each would be
        collected, which is why the gate collects the way a plain run does."""
        found = _scan(suite, f"# pinned by `{name}` in {path}\n")
        assert [cited for _, cited, _ in found] == [f"{name} in {path}"]
        assert "pytest collects no test from it" in found[0][2]

    def test_the_pytest_configuration_decides_what_is_a_test_module(
        self, suite: SuiteIndex
    ) -> None:
        """The fixture's ``pytest.ini`` adds ``check_*.py`` to ``python_files``;
        the gate reads no pattern of its own, so the module resolves."""
        text = "# pinned by `test_in_a_configured_module` in tests/check_extra.py\n"
        assert _scan(suite, text) == []

    @pytest.mark.parametrize(
        ("plugin", "fixtures", "runs"),
        [
            ("_pytest.python", ("anyio_backend",), False),
            ("anyio.pytest_plugin", (), False),
            ("anyio.pytest_plugin", ("anyio_backend",), True),
            ("some_other_async_plugin", (), True),
        ],
    )
    def test_which_plugin_runs_an_async_item(
        self, plugin: str, fixtures: tuple[str, ...], runs: bool
    ) -> None:
        """anyio's plugin runs only an item that requests ``anyio_backend``.

        Counted as a runner for every async item, it let a citation of an
        unmarked async test resolve on any checkout that had anyio installed
        (it arrives with starlette and httpx), and the two tests below failed
        there.  Hermetic: the plugins are stand-ins, so this pins the rule
        whether or not anyio is installed where it runs.
        """

        class _Plugin:
            __name__ = plugin

        class _Item:
            fixturenames = fixtures

        assert _plugin_runs(_Plugin(), _Item()) is runs

    @pytest.mark.parametrize("name", ["test_async_function", "test_async_method"])
    def test_an_async_test_no_plugin_runs_does_not_resolve(
        self, suite: SuiteIndex, name: str
    ) -> None:
        """pytest collects an ``async def`` test and, with no async plugin,
        fails it without running its body: it pins nothing."""
        found = _scan(suite, f"# pinned by `{name}` in tests/test_real.py\n")
        assert [cited for _, cited, _ in found] == [f"{name} in tests/test_real.py"]
        assert "async test no plugin runs" in found[0][2]

    @pytest.mark.parametrize(
        ("text", "cited"),
        [
            (
                "# tests/test_broken.py::test_in_a_broken_module\n",
                "tests/test_broken.py::test_in_a_broken_module",
            ),
            (
                "# test_beside_a_broken_class in tests/test_class_error.py\n",
                "test_beside_a_broken_class in tests/test_class_error.py",
            ),
            (
                "# test_before_a_syntax_error in tests/test_syntax_error.py\n",
                "test_before_a_syntax_error in tests/test_syntax_error.py",
            ),
        ],
    )
    def test_a_file_pytest_cannot_collect_is_a_finding(
        self, suite: SuiteIndex, text: str, cited: str
    ) -> None:
        """A module that fails to import, a module one of whose classes fails
        to collect, and a module that does not parse: a plain run is
        interrupted before any test in it runs, so no citation of it resolves
        -- including the test beside the broken class, which pytest did
        collect.  A file the gate could not parse used to fall back to a
        line-anchored ``def`` search, which resolved it."""
        found = _scan(suite, text)
        assert [c for _, c, _ in found] == [cited]
        assert found[0][2].startswith("cannot collect"), found[0][2]

    @pytest.mark.parametrize(
        ("text", "resolves"),
        [
            ("tests/test_real.py::test_present", True),
            ("tests/test_real.py::TestGroup", True),
            ("tests/test_real.py::TestGroup::test_method", True),
            ("tests/test_real.py::TestGroup::TestNested::test_in_a_nested_class", True),
            ("tests/test_real.py::TestChild::test_inherited", True),
            ("tests/test_real.py::MyCase::test_in_a_unittest_case", True),
            ("tests/test_real.py::TestMissing::test_present", False),
            ("tests/test_real.py::test_method", False),
            ("tests/test_real.py::TestNested::test_in_a_nested_class", False),
            ("tests/test_real.py::TestGroup::test_present", False),
            ("tests/test_real.py::_Mixin::test_inherited", False),
            ("tests/test_real.py::TestSwitchedOff", False),
            ("tests/c/test_real.c::test_defined", True),
            ("tests/c/test_real.c::TestGroup::test_defined", False),
        ],
    )
    def test_a_node_id_resolves_exactly(self, suite: SuiteIndex, text: str, resolves: bool) -> None:
        """Every class in a node id is checked, in order: until 2026-09-28
        only the last name was, so ``::TestMissing::test_present`` passed
        wherever ``test_present`` existed, and a method cited as a
        module-level node passed too.  A C test has no class."""
        found = _scan(suite, f"# pinned by {text}\n")
        assert (found == []) is resolves, found
        if not resolves:
            assert [cited for _, cited, _ in found] == [text]

    def test_a_class_qualifier_on_a_c_path_says_why(self, suite: SuiteIndex) -> None:
        found = _scan(suite, "# tests/c/test_real.c::TestGroup::test_defined\n")
        assert "a C test has no class" in found[0][2]

    @pytest.mark.parametrize(
        ("text", "resolves"),
        [
            ("TestGroup.test_method in tests/test_real.py", True),
            ("TestNested.test_in_a_nested_class in tests/test_real.py", True),
            ("TestGroup.TestNested.test_in_a_nested_class in tests/test_real.py", True),
            ("TestMissing.test_present in tests/test_real.py", False),
            ("TestGroup.test_present in tests/test_real.py", False),
            ("TestGroup in tests/test_real.py", True),
            ("TestNested in tests/test_real.py", True),
            ("TestAbsent in tests/test_real.py", False),
            ("TestSwitchedOff in tests/test_real.py", False),
        ],
    )
    def test_a_class_named_in_prose_is_checked(
        self, suite: SuiteIndex, text: str, resolves: bool
    ) -> None:
        """``TestA.test_x in tests/y.py`` names the class as well as the test,
        and ``TestA in tests/y.py`` names a class: the dotted form used to
        lose its class, and the bare class passed unread."""
        found = _scan(suite, f"# pinned by ``{text.split(' in ')[0]}`` in tests/test_real.py\n")
        assert (found == []) is resolves, found
        if not resolves:
            assert [cited for _, cited, _ in found] == [text]

    def test_a_wrapped_node_id_is_joined(self, suite: SuiteIndex) -> None:
        """Wrapped inside the path, after ``::`` and before ``::``."""
        for text in (
            "/* tests/test_\n * real.py::test_absent */\n",
            "/* tests/test_real.py::\n * test_absent */\n",
            "/* tests/test_real.py\n * ::test_absent */\n",
        ):
            assert _cited(suite, text) == ["tests/test_real.py::test_absent"], text
        assert _scan(suite, "/* tests/test_real.py::\n * TestGroup::test_method */\n") == []

    def test_a_test_name_wrapped_mid_identifier_is_joined(self, suite: SuiteIndex) -> None:
        """``ama_cryptography/key_formats.py`` breaks a cited name after an
        underscore inside rst backticks."""
        assert _scan(suite, "``test_in_a_\n    nested_class`` pins it\n") == []
        assert _cited(suite, "``test_absent_\n    wrapped`` pins it\n") == ["test_absent_wrapped"]

    @pytest.mark.parametrize(
        ("text", "cited"),
        [
            ("# see ./tests/test_imagined.py\n", "tests/test_imagined.py"),
            ("# see ../tests/test_imagined.py\n", "tests/test_imagined.py"),
            ("# see ../../tests/c/test_imagined.c\n", "tests/c/test_imagined.c"),
            ("# see AMA-Cryptography/tests/test_imagined.py\n", "tests/test_imagined.py"),
            ("# ./tests/test_real.py::test_absent\n", "tests/test_real.py::test_absent"),
        ],
    )
    def test_a_relative_path_is_read(self, suite: SuiteIndex, text: str, cited: str) -> None:
        assert _cited(suite, text) == [cited]

    def test_a_path_in_another_directory_is_not_a_tests_path(self, suite: SuiteIndex) -> None:
        """``fuzz/tests/x.py`` is not under the repository's ``tests/``."""
        assert _scan(suite, "# see fuzz/tests/test_imagined.py\n") == []

    @pytest.mark.parametrize(
        ("text", "cited"),
        [
            (
                "/* tests/kat/fips205/slhdsa_shake_128s_siggen_acvp.json */\n",
                "tests/kat/fips205/slhdsa_shake_128s_siggen_acvp.json",
            ),
            ("/* vectors in tests/data/imagined.json. */\n", "tests/data/imagined.json"),
            ("/* see tests/nowhere/ */\n", "tests/nowhere/"),
            ("/* every tests/c/nothing_*.c */\n", "tests/c/nothing_*.c"),
            ("/* declared in tests/c/test_imagined.h */\n", "tests/c/test_imagined.h"),
            ("- **tests/test_gone.py** pinned it\n", "tests/test_gone.py"),
            ("/* every tests/*.c */\n", "tests/*.c"),
        ],
    )
    def test_a_path_of_any_kind_is_checked(self, suite: SuiteIndex, text: str, cited: str) -> None:
        """Any extension, a directory, a glob (whose ``*`` does not cross a
        ``/``).  Only ``.py``/``.c``/``.h`` were read until 2026-09-28, and
        ``src/c/ama_slhdsa.c`` cited a KAT file under a name it never had."""
        assert _cited(suite, text) == [cited]

    @pytest.mark.parametrize(
        "text",
        [
            "/* vectors in tests/data/vectors.json. */\n",
            "/* see tests/data/ and tests/c */\n",
            "/* every tests/c/test_*.c */\n",
            "/* pinned by tests/test_real.py. */\n",
            "- **tests/test_real.py** pins it\n",
            "/* pinned by tests/test_real.py*/\n",
            "/* vectors in tests/data/SLH-\n * DSA-sigGen.json */\n",
            "/* see tests/ref_\n * helpers.py */\n",
        ],
    )
    def test_a_path_that_exists_resolves(self, suite: SuiteIndex, text: str) -> None:
        """Trailing prose punctuation, markdown bold and a comment closer
        are not part of the path."""
        assert _scan(suite, text) == [], text

    @pytest.mark.parametrize(
        ("text", "cited", "reason"),
        [
            ("/* see test_real.c */\n", None, None),
            ("/* see test_imagined.c */\n", "test_imagined.c", "names no tracked file"),
            ("/* see test_dup.c */\n", "test_dup.c", "names 2 tracked files"),
            ("/* at test_real.c::test_defined */\n", None, None),
            ("/* at test_real.c::test_absent */\n", "test_real.c::test_absent", "no test named"),
            ("/* `test_absent` in `test_real.py` */\n", "test_absent in test_real.py", "no test"),
        ],
    )
    def test_a_bare_test_file_name_resolves_to_exactly_one_file(
        self, suite: SuiteIndex, text: str, cited: str | None, reason: str | None
    ) -> None:
        """``src/c/neon/ama_aes_gcm_neon.c`` cites
        ``test_dudect.c::test_aes_gcm_tag_verify``: a file name with no
        directory must name exactly one tracked file under ``tests/``."""
        found = _scan(suite, text)
        if cited is None:
            assert found == [], found
        else:
            assert [c for _, c, _ in found] == [cited]
            assert reason is not None and reason in found[0][2], found[0][2]

    @pytest.mark.parametrize(
        ("text", "cited"),
        [
            ("# ``test_present`` pins it\n", None),
            ("# which ``test_in_a_nested_class`` pins\n", None),
            ("# (``test_defined()``)\n", None),
            ("# ``TestGroup.test_method`` pins it\n", None),
            ("# ``test_absent`` pins it\n", "test_absent"),
            ("# `test_absent()` pins it\n", "test_absent"),
            ("# ``TestGroup.test_present`` pins it\n", "TestGroup.test_present"),
            ("# ``test_in_a_helper_module`` pins it\n", "test_in_a_helper_module"),
            # Not a whole code span, so not read: prose uses the shape for
            # fields, parameters and variables (``_self_test.py``).
            ("# ``(test_name, passed, detail)``\n", None),
            ("# the leak at test_absent\n", None),
        ],
    )
    def test_a_bare_test_name_in_a_code_span_must_be_collected_somewhere(
        self, suite: SuiteIndex, text: str, cited: str | None
    ) -> None:
        found = _scan(suite, text)
        assert [c for _, c, _ in found] == ([cited] if cited else []), found

    def test_a_bare_name_the_citing_file_defines_is_not_a_test(self, suite: SuiteIndex) -> None:
        """``def f(test_mode)`` documented as ````test_mode```` names the
        parameter, not a test."""
        text = 'def f(test_mode: bool) -> None:\n    """``test_mode`` selects it."""\n'
        identifiers = code_identifiers(text, "ama_cryptography/example.py")
        assert "test_mode" in identifiers
        assert scan_test_citations(text, suite, identifiers) == []
        assert _cited(suite, text) == ["test_mode"]

    @pytest.mark.parametrize(
        ("text", "path", "expected"),
        [
            ("x = 1  # ``test_absent``\n", "ama_cryptography/x.py", {"x"}),
            ('"""``test_absent`` in an unterminated docstring\n', "ama_cryptography/x.py", set()),
            ("/* ``test_absent`` */\nint test_local;\n", "src/c/x.c", {"int", "test_local"}),
            ("``test_absent`` in prose\n", "ama_cryptography/README.md", set()),
        ],
    )
    def test_a_files_identifiers_come_from_its_code_only(
        self, text: str, path: str, expected: set[str]
    ) -> None:
        """A name in a comment or docstring is not an identifier, and Python
        the tokenizer rejects has none: an exemption must never come from the
        citation itself."""
        assert code_identifiers(text, path) == expected

    def test_a_named_test_in_a_file_that_is_not_source_is_reported(self, suite: SuiteIndex) -> None:
        found = _scan(suite, "# `test_in_json` in tests/data/vectors.json\n")
        assert [c for _, c, _ in found] == ["test_in_json in tests/data/vectors.json"]
        assert "not a Python or C source" in found[0][2]

    def test_a_named_test_in_a_missing_file_is_reported_once(self, suite: SuiteIndex) -> None:
        found = _scan(suite, "# `test_x` in tests/test_gone.py\n")
        assert [cited for _, cited, _ in found] == ["tests/test_gone.py"]

    def test_a_tracked_file_deleted_from_the_working_tree_is_reported(
        self, suite: SuiteIndex
    ) -> None:
        """It used to crash the gate with a ``FileNotFoundError`` traceback."""
        found = _scan(suite, "# `test_in_a_deleted_file` in tests/test_deleted.py\n")
        assert [c for _, c, _ in found] == ["tests/test_deleted.py"]
        assert "deleted from the working tree" in found[0][2]

    def test_a_file_on_disk_that_git_does_not_track_is_reported(self, suite: SuiteIndex) -> None:
        """A citation must resolve in the repository, not in one checkout."""
        assert (suite.root / "tests" / "test_untracked.py").is_file()
        found = _scan(suite, "# `test_in_an_untracked_file` in tests/test_untracked.py\n")
        assert [c for _, c, _ in found] == ["tests/test_untracked.py"]
        assert "not tracked" in found[0][2]

    def test_a_name_is_resolved_in_the_cited_file_only(self, suite: SuiteIndex) -> None:
        found = _scan(suite, "# `test_only_in_the_other_file` in tests/test_real.py\n")
        assert [c for _, c, _ in found] == ["test_only_in_the_other_file in tests/test_real.py"]

    def test_the_scope_is_the_shipped_code(self) -> None:
        assert TEST_CITATION_DIRS == ("ama_cryptography", "src", "include")

    @pytest.mark.parametrize(
        ("where", "expected"),
        [
            ("src/c/planted.c", 1),
            ("include/planted.h", 1),
            ("ama_cryptography/planted.md", 1),
            ("tests/c/planted.c", 0),
        ],
    )
    def test_the_cli_fails_on_a_dangling_test_citation_in_scope(
        self, tmp_path: Path, where: str, expected: int
    ) -> None:
        """In tests/ a fictional path is a fixture, so the same text passes there."""
        _git_repo(tmp_path, {where: "/* pinned by tests/c/test_imagined.c */\n"})
        assert main(["--repo", str(tmp_path)]) == expected


class TestTheGateEndToEnd:
    """Through :func:`main`, over a planted repository: the paths ``check``
    itself owns (reading, resolving against the cited file, the citing file's
    identifiers, enumeration) are exercised here rather than through
    :func:`scan_test_citations`."""

    def test_a_name_defined_in_another_file_fails_the_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _git_repo(
            tmp_path,
            {
                "tests/test_a.py": "def test_only_in_a() -> None: ...\n",
                "tests/test_b.py": "def test_only_in_b() -> None: ...\n",
                "ama_cryptography/planted.py": "# pinned by test_only_in_a in tests/test_b.py\n",
            },
        )
        assert main(["--repo", str(tmp_path)]) == 1
        out = capsys.readouterr().out
        assert "ama_cryptography/planted.py:1: 'test_only_in_a in tests/test_b.py'" in out, out

    def test_a_resolving_citation_passes_the_cli(self, tmp_path: Path) -> None:
        _git_repo(
            tmp_path,
            {
                "tests/test_a.py": "def test_only_in_a() -> None: ...\n",
                "ama_cryptography/planted.py": (
                    "# pinned by test_only_in_a in tests/test_a.py and by\n"
                    "# ``test_only_in_a`` on its own\n"
                ),
            },
        )
        assert main(["--repo", str(tmp_path)]) == 0

    def test_the_citing_files_own_identifiers_are_not_tests(self, tmp_path: Path) -> None:
        _git_repo(
            tmp_path,
            {
                "tests/test_a.py": "def test_only_in_a() -> None: ...\n",
                "ama_cryptography/planted.py": (
                    "def f(test_mode: bool) -> None:\n"
                    '    """``test_mode`` selects the self-test vectors."""\n'
                ),
            },
        )
        assert main(["--repo", str(tmp_path)]) == 0

    def test_a_colon_line_citation_is_refused_in_shipped_code_only(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """``file.c:705`` is a line citation like ``at line 705`` and goes stale
        the same way; two in ``src/c`` had.  Outside the shipped code the same
        text is also quoted compiler output, which is left alone."""
        _git_repo(
            tmp_path,
            {
                "src/c/planted.c": "/* mirrors the scrub in other.c:434-438 */\n",
                "ama_cryptography/planted.py": "# see ``other.py:12`` for why\n",
                "tests/test_quoted.py": "WARNING = 'other.c:12:5: warning: unused'\n",
            },
        )
        assert main(["--repo", str(tmp_path)]) == 1
        out = capsys.readouterr().out
        assert "src/c/planted.c:1: 'other.c:434-438'" in out, out
        assert "ama_cryptography/planted.py:1: 'other.py:12'" in out, out
        assert "tests/test_quoted.py" not in out, out

    def test_a_file_name_without_a_line_number_is_not_a_line_citation(self) -> None:
        assert scan_shipped_text("see ama_aes_gcm.c and ama_aes256_gcm_decrypt()\n") == []
        assert scan_shipped_text("version 1.2:3 of x\n") == []
        assert [m for _, m, _ in scan_shipped_text("at src/c/a_b-c.h:9 and x.pyx:1-2\n")] == [
            "src/c/a_b-c.h:9",
            "x.pyx:1-2",
        ]

    def test_a_deleted_test_file_is_a_finding_not_a_traceback(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _git_repo(
            tmp_path,
            {
                "tests/test_a.py": "def test_only_in_a() -> None: ...\n",
                "src/c/planted.c": "/* pinned by test_only_in_a in tests/test_a.py */\n",
            },
        )
        (tmp_path / "tests" / "test_a.py").unlink()
        assert main(["--repo", str(tmp_path)]) == 1
        assert "deleted from the working tree" in capsys.readouterr().out

    def test_a_tracked_path_that_is_not_a_file_fails_closed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Skipping it, as the gate did until 2026-09-28, passed the clean
        file beside it and reported every citation resolved."""
        _git_repo(
            tmp_path,
            {"src/c/planted.c": "/* nothing cited */\n", "src/c/other.c": "/* clean */\n"},
        )
        (tmp_path / "src" / "c" / "planted.c").unlink()
        (tmp_path / "src" / "c" / "planted.c").mkdir()
        assert main(["--repo", str(tmp_path)]) == 1
        assert "cannot enumerate the tracked files" in capsys.readouterr().out


class TestCollectionFailsClosed:
    """When pytest cannot answer, every citation it was asked about is a finding."""

    def test_a_conftest_that_raises_is_reported(self, tmp_path: Path) -> None:
        root = _git_repo(
            tmp_path,
            {
                "tests/conftest.py": 'raise RuntimeError("conftest refuses")\n',
                "tests/test_a.py": "def test_only_in_a() -> None: ...\n",
            },
        )
        found = scan_test_citations("# test_only_in_a in tests/test_a.py\n", SuiteIndex(root))
        assert [c for _, c, _ in found] == ["test_only_in_a in tests/test_a.py"]
        assert found[0][2].startswith("cannot collect tests/test_a.py"), found[0][2]

    def test_a_pytest_that_cannot_start_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _git_repo(tmp_path, {"tests/test_a.py": "def test_only_in_a() -> None: ...\n"})
        monkeypatch.setattr(sys, "executable", str(tmp_path / "no-such-python"))
        found = scan_test_citations("# test_only_in_a in tests/test_a.py\n", SuiteIndex(root))
        assert [c for _, c, _ in found] == ["test_only_in_a in tests/test_a.py"]
        assert "pytest could not be run" in found[0][2]

    def test_pytest_addopts_does_not_reach_the_collection(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A developer's ``PYTEST_ADDOPTS`` (``-k``, ``--deselect``) must not
        decide what the gate thinks is collected."""
        root = _git_repo(tmp_path, {"tests/test_a.py": "def test_only_in_a() -> None: ...\n"})
        monkeypatch.setenv("PYTEST_ADDOPTS", "--deselect tests/test_a.py::test_only_in_a")
        found = scan_test_citations("# test_only_in_a in tests/test_a.py\n", SuiteIndex(root))
        assert found == []


class TestCDefinitions:
    """A C test is a file-scope definition, read from the blanked code."""

    @pytest.mark.parametrize(
        "source",
        [
            "/* Example:\n   static int test_in_a_comment(void) {\n */\n",
            "/* Example; a harness may define\nstatic int test_in_a_comment(void) {\n */\n",
            '// e.g. "; static int test_in_a_comment(void) {"\n',
            'static const char *s = "x; static int test_in_a_comment(void) {";\n',
        ],
    )
    def test_a_definition_quoted_in_a_comment_or_string_is_not_one(self, source: str) -> None:
        """The first shape is also refused by the declaration-specifier check
        (its prefix holds ``/*`` and ``:``); the others are refused only
        because comments and literals are blanked first."""
        assert c_definitions(source) == frozenset()

    def test_the_fixture_defines_exactly_these(self) -> None:
        assert c_definitions(_C_FIXTURE) == {
            "test_defined",
            "test_split_signature",
            "test_with_an_attribute",
            "test_fn_ptr_param",
        }

    def test_an_extern_c_block_is_not_a_scope(self) -> None:
        assert c_definitions(_H_FIXTURE) == {"test_in_a_header"}

    def test_the_else_of_if_1_is_disabled_and_the_else_of_if_0_is_not(self) -> None:
        source = (
            "#if 1\nstatic int test_a(void) { return 0; }\n#else\n"
            "static int test_b(void) { return 0; }\n#endif\n"
            "#if 0\nstatic int test_c(void) { return 0; }\n#else\n"
            "static int test_d(void) { return 0; }\n#endif\n"
        )
        assert c_definitions(source) == {"test_a", "test_d"}


class TestTheScanIsLinear:
    """The citation patterns used to backtrack exponentially.

    ``NAMED_TEST`` repeated a group whose alternatives both matched
    whitespace, and ``TEST_PATH`` let ``//`` be read two ways: measured
    against the 2026-09-27 patterns, a Python line followed by 24 spaces took
    6.8 s and doubled per space, ``test_x`` then three indented lines took
    105 s, and ``tests/a_`` then 20 ``//`` lines doubled per line.  The gate
    runs inside this suite, so that was a hang, not a slow report.

    The verdict is growth, not an absolute time.  This test used to run each
    input a thousand times larger and assert the scan finished inside half a
    second -- and on 2026-10-02 the shared macos-15-intel runner took 0.51 s
    and 0.57 s over two of the LINEAR scans (job 110957360556), a constant
    factor from a loaded host, exactly the false-positive class the
    zeroization gate's linearity test retired the same day.  The scan is now
    timed at three sizes spanning 4x, each the floor of interleaved rounds,
    and the verdict is the end-to-end span: linear work grows 4x across it,
    quadratic 16x, and the 2026-09-27 exponential patterns do not finish the
    smallest size at all.  The ceiling and the floor-of-interleaved-rounds
    estimator are the zeroization gate's, for the reasons recorded there."""

    PATHOLOGICAL: ClassVar[list[tuple[str, str, int]]] = [
        ("        x = test_vec\n", " ", 24),
        ("test_x", "\n" + " " * 8, 3),
        ("test_x", " \n * ", 10),
        ("tests/a_", "\n//", 20),
        ("``test_x`` in", " \n * ", 10),
        ("tests/a.py::", "\n# ::x", 20),
        ("test_a, test_b and ", "test_c, ", 20),
    ]

    #: Linear growth spans 4.0 across the 4x input span; quadratic spans 16.
    #: One noisy floor must move the span past the midpoint of the two to
    #: flip the verdict, twice the margin the absolute bound gave a single
    #: inflated reading.
    SPAN_CEILING: ClassVar[float] = 8.0
    SCALES: ClassVar[tuple[int, int, int]] = (250, 500, 1000)
    ROUNDS: ClassVar[int] = 3

    @pytest.mark.parametrize(("head", "unit", "count"), PATHOLOGICAL)
    def test_a_pathological_input_is_scanned_linearly(
        self, head: str, unit: str, count: int
    ) -> None:
        texts = {s: head + unit * (count * s) + "y = 1" for s in self.SCALES}
        floors = {s: float("inf") for s in self.SCALES}
        for _ in range(self.ROUNDS):
            for s in self.SCALES:  # interleaved: one slow moment cannot bias one size
                started = time.perf_counter()
                extract_test_citations(texts[s])
                scan_text(texts[s])
                floors[s] = min(floors[s], time.perf_counter() - started)
        if floors[self.SCALES[0]] < 1e-4:
            return  # too fast to measure growth: nothing here is pathological
        span = floors[self.SCALES[-1]] / floors[self.SCALES[0]]
        assert span < self.SPAN_CEILING, (
            f"{span:.1f}x growth over a 4x input span "
            f"({floors[self.SCALES[0]]:.4f}s -> {floors[self.SCALES[-1]]:.4f}s "
            f"on {len(texts[self.SCALES[-1]])} characters): "
            f"{texts[self.SCALES[-1]][:40]!r}"
        )


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
