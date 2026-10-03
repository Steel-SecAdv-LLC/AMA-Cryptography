#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for ``tools/check_suppression_hygiene.py``'s optional-import pass.

INVARIANT-13's third-party-import pass exists for one hazard: a bare
``# type: ignore`` on the fallback assignment of a guarded optional import::

    try:
        import numpy as np
    except ModuleNotFoundError:
        np = None  # type: ignore[assignment]

is *required* on a machine where the package is installed and an *error* under
``warn_unused_ignores`` on one where it is not, so the verdict depends on the
environment rather than on the code.

The pass reached that shape through a substring pre-filter, ``"ImportError" not
in source``, and ``"ModuleNotFoundError"`` does not contain ``"ImportError"``.
So a file guarded with the ``ModuleNotFoundError`` spelling was dropped before
it was ever parsed — while :func:`_third_party_import_fallback_lines`, the AST
pass behind the filter, has always accepted both spellings.  The gate reported
clean on exactly the files it could not see.

This pass had no tests, which is how that survived.  The MODULE was not
untested — ``tests/test_invariant_upgrades.py`` covers the first pass
(``check_source``, ``effective_suppressions``, ``main``) and the second
(``scan_c_tree``, ``c_tree_files``) in both directions — it touches neither
``scan_optional_imports`` nor ``_third_party_import_fallback_lines``.  Two
passes of three read as a covered tool.
"""

from __future__ import annotations

import importlib.util
import os
import re as _re
import shutil as _shutil
import subprocess as _subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import ClassVar

import pytest
import pytest as _pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_suppression_hygiene.py"


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_suppression_hygiene", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


#: The same file, written with every except-clause spelling the AST pass
#: accepts.  Each must be seen by the pre-filter AND reported.
_GUARDED = {
    "import-error": (
        "try:\n"
        "    import numpy as np\n"
        "except ImportError:\n"
        "    np = None  # type: ignore[assignment]\n"
    ),
    "module-not-found-error": (
        "try:\n"
        "    import numpy as np\n"
        "except ModuleNotFoundError:\n"
        "    np = None  # type: ignore[assignment]\n"
    ),
    "tuple-clause": (
        "try:\n"
        "    import numpy as np\n"
        "except (ModuleNotFoundError, AttributeError):\n"
        "    np = None  # type: ignore[assignment]\n"
    ),
    "nested-try": (
        "try:\n"
        "    try:\n"
        "        import numpy as np\n"
        "    except ModuleNotFoundError:\n"
        "        np = None  # type: ignore[assignment]\n"
        "except Exception:\n"
        "    raise\n"
    ),
}


class TestThePreFilter:
    @pytest.mark.parametrize("label", sorted(_GUARDED))
    def test_every_spelling_reaches_the_parser(self, gate: ModuleType, label: str) -> None:
        assert gate._may_hold_a_guarded_import(_GUARDED[label]) is True, label

    @pytest.mark.parametrize("label", sorted(_GUARDED))
    def test_every_spelling_is_found_by_the_ast_pass(self, gate: ModuleType, label: str) -> None:
        """Non-vacuity: the filter must not be the only thing that agrees."""
        assert gate._third_party_import_fallback_lines(_GUARDED[label]), label

    def test_a_file_with_no_suppression_is_filtered_out(self, gate: ModuleType) -> None:
        assert gate._may_hold_a_guarded_import("import numpy as np\n") is False

    def test_a_file_with_a_suppression_but_no_guard_is_filtered_out(self, gate: ModuleType) -> None:
        assert gate._may_hold_a_guarded_import("x = y  # type: ignore[assignment]\n") is False


class TestTheScan:
    @pytest.mark.parametrize("label", sorted(_GUARDED))
    def test_every_spelling_is_reported(self, gate: ModuleType, tmp_path: Path, label: str) -> None:
        pkg = tmp_path / "ama_cryptography"
        pkg.mkdir()
        (pkg / "thing.py").write_text(_GUARDED[label], encoding="utf-8")
        violations = gate.scan_optional_imports(tmp_path)
        assert violations, f"{label}: a bare type: ignore on a guarded import went unreported"
        assert any("thing.py" in v for v in violations), violations

    def test_an_aliased_annotation_is_accepted(self, gate: ModuleType, tmp_path: Path) -> None:
        """The remedy the message names must actually pass the gate."""
        pkg = tmp_path / "ama_cryptography"
        pkg.mkdir()
        (pkg / "thing.py").write_text(
            "from typing import Any\n"
            "try:\n"
            "    import numpy as _np\n"
            "except ModuleNotFoundError:\n"
            "    _np = None\n"
            "np: Any = _np\n",
            encoding="utf-8",
        )
        assert gate.scan_optional_imports(tmp_path) == []


class TestAnUnparseableFileIsRefused:
    """Tokenizing stops at a syntax error, so a suppression after it is unseen.

    ``scan_comments`` keeps what it read before the error, which is right for
    the candidate listing and wrong for a verdict: an unjustified ``noqa``
    written below an indentation error was not reported at all.  The file is
    refused whole instead.
    """

    SOURCE = "def f():\n    return 1\n  x = 2\ny = 3  # noqa\n"

    def test_the_scan_really_stops_at_the_error(self, gate: ModuleType) -> None:
        comments, _first = gate.scan_comments(self.SOURCE)
        assert comments == [], "fixture: the noqa must lie past the tokenize error"

    def test_the_file_is_refused(self, gate: ModuleType) -> None:
        violations = gate.check_source("bad.py", self.SOURCE)
        assert len(violations) == 1, violations
        assert violations[0].startswith("bad.py:3: cannot be parsed")


def test_the_shipped_tree_is_clean(gate: ModuleType) -> None:
    """The gate CI runs, run here — now that the pre-filter can see everything."""
    assert gate.scan_optional_imports(REPO_ROOT) == []


class TestCppcheckHasNoSuppressions:
    """INVARIANT-13 applied to the cppcheck configuration -- the strong form.

    The static-analysis workflow once silenced whole error IDs for whole
    files on the command line::

        --suppress=uninitvar:src/c/ama_nistp.c
        --suppress=arrayIndexOutOfBounds:src/c/dispatch/ama_dispatch.c

    then moved them to per-site pins in a ``.cppcheck-suppressions`` file,
    then -- the state this test now guards -- resolved every one AT SOURCE:
    the out-parameter ``uninitvar`` false positives by zero-initialising each
    output aggregate at its declaration (``ama_kyber.c``'s caller-owned matrix
    by a leading ``memset``), and the ``x >> 31`` / ``x >> 63`` sign-broadcast
    masks by the fully-defined ``0 - ((uint64_t)x >> n)`` rewrite that is
    bit-identical on two's-complement.  ``arrayIndexOutOfBounds`` stays live
    because ``-DPATH_MAX=4096`` removes it without a suppression.

    So the invariants are inverted from the per-site era: there must be NO
    suppressions file, NO ``--suppressions-list`` flag, and NO file- or
    class-wide command-line suppression -- only the run-wide
    environment/vendor-noise IDs.  Resolving a finding at source, not
    suppressing it, is the only way back to green.
    """

    WORKFLOW = REPO_ROOT / ".github" / "workflows" / "static-analysis.yml"
    SUPPRESSIONS = REPO_ROOT / ".cppcheck-suppressions"

    #: IDs that are legitimately run-wide: cppcheck's own environment or
    #: vendored/system noise, not a finding in a file this project maintains.
    RUN_WIDE_IDS: ClassVar[set[str]] = {
        "missingIncludeSystem",
        "unusedFunction",
    }

    def test_no_per_site_suppressions_file(self) -> None:
        assert not self.SUPPRESSIONS.exists(), (
            ".cppcheck-suppressions is back; every historical entry was resolved "
            "at source (zero-init out-parameters, defined-form shift masks), so "
            "the file and its --suppressions-list flag should stay gone."
        )
        text = self.WORKFLOW.read_text(encoding="utf-8")
        assert "--suppressions-list=" not in text, (
            "the workflow references a --suppressions-list again; there are no "
            "per-site suppressions to list."
        )

    #: Every ``--suppress=`` argument, wherever it sits on a command line.
    _SUPPRESS_ARG = _re.compile(r"--suppress=([^\s\\'\"]+)")

    @classmethod
    def _command_suppressions(cls, workflow_text: str) -> list[str]:
        """The ``--suppress=`` bodies of every ``run:`` script, comments dropped.

        Read from the parsed workflow rather than line by line: the first
        revision inspected only lines that STARTED with ``--suppress=``, so the
        flag on the ``cppcheck`` line itself, or a one-line invocation, was
        never read.  Shell comments are dropped so the workflow's prose about
        past suppressions is not mistaken for one.
        """
        found: list[str] = []
        data = yaml.safe_load(workflow_text) or {}
        for job in (data.get("jobs") or {}).values():
            for step in job.get("steps") or []:
                run = step.get("run") if isinstance(step, dict) else None
                if not isinstance(run, str):
                    continue
                code = "\n".join(
                    line for line in run.splitlines() if not line.lstrip().startswith("#")
                )
                found.extend(cls._SUPPRESS_ARG.findall(code))
        return found

    def _offenders(self, workflow_text: str) -> list[str]:
        offenders: list[str] = []
        for body in self._command_suppressions(workflow_text):
            error_id, _, target = body.partition(":")
            if target or error_id not in self.RUN_WIDE_IDS:
                offenders.append(f"--suppress={body}")
        return offenders

    def test_no_file_or_class_wide_suppression_on_the_command_line(self) -> None:
        text = self.WORKFLOW.read_text(encoding="utf-8")
        assert self._command_suppressions(text), "no --suppress= read at all: the scan is broken"
        offenders = self._offenders(text)
        assert not offenders, (
            f"cppcheck suppressions are back on the command line: {offenders}. "
            "Every finding this project maintains is resolved at source; only the "
            f"run-wide environment IDs {sorted(self.RUN_WIDE_IDS)} may remain."
        )

    @pytest.mark.parametrize(
        "run",
        [
            "cppcheck --suppress=uninitvar:src/c/ama_nistp.c \\\n  --force src/c",
            "cppcheck --force --suppress=uninitvar src/c",
            (
                "cppcheck \\\n  --suppress=missingIncludeSystem "
                "--suppress=knownConditionTrueFalse \\\n  src/c"
            ),
        ],
        ids=["file-scoped-on-the-invocation-line", "one-line", "second-flag-on-a-line"],
    )
    def test_a_suppression_anywhere_on_the_command_is_read(self, run: str) -> None:
        workflow = yaml.safe_dump({"jobs": {"cppcheck": {"steps": [{"run": run}]}}})
        assert self._offenders(workflow), run

    def test_prose_about_a_suppression_is_not_one(self) -> None:
        run = (
            "# was: --suppress=uninitvar:src/c/x.c\ncppcheck --suppress=missingIncludeSystem src/c"
        )
        workflow = yaml.safe_dump({"jobs": {"cppcheck": {"steps": [{"run": run}]}}})
        assert self._offenders(workflow) == []

    def test_array_index_out_of_bounds_needs_no_suppression(self) -> None:
        """-DPATH_MAX=4096 removes it and leaves the bounds check live."""
        text = self.WORKFLOW.read_text(encoding="utf-8")
        assert "-DPATH_MAX=4096" in text, (
            "the real PATH_MAX define is gone; without it --force invents "
            "dir[1] and arrayIndexOutOfBounds returns, needing a suppression."
        )
        assert "--suppress=arrayIndexOutOfBounds" not in text, (
            "arrayIndexOutOfBounds is suppressed again; -DPATH_MAX=4096 removes " "it without one."
        )


class TestFileScopedSuppressionsAreRefused:
    """INVARIANT-13's FIRST condition had no enforcement anywhere.

    The invariant states that a suppression must be "line-scoped, not
    file-scoped".  Every file-level linter directive is a STANDALONE comment,
    and ``effective_suppressions`` discarded standalone comments before
    ``_SUPPRESSION_RE`` ever saw them — the mechanism that stops the gate
    firing on its own prose is exactly what guaranteed the file-scoped forms
    were never examined.  ``mypy:`` was not in the marker set at all, so
    ``# mypy: ignore-errors`` was unrecognised even as a marker.

    The tree carried one: ``tests/test_fuzzing.py`` opened with
    ``# mypy: disable-error-code="misc"``.  It turned out to be dead — mypy
    --strict passes over that file without it — which is the ordinary fate of
    a suppression nothing checks.
    """

    FILE_SCOPED = (
        '# mypy: disable-error-code="misc"',
        "# mypy: ignore-errors",
        "# ruff: noqa",
        "# ruff: noqa: E501",
        "# flake8: noqa",
        "# pylint: skip-file",
    )

    @pytest.mark.parametrize("directive", FILE_SCOPED)
    def test_a_file_scoped_directive_is_refused(self, gate: ModuleType, directive: str) -> None:
        source = f"{directive}\n\n\ndef f() -> None:\n    pass\n"
        found = gate.check_source("pkg/mod.py", source)
        assert len(found) == 1, found
        assert "FILE-SCOPED" in found[0], found[0]

    @pytest.mark.parametrize("directive", FILE_SCOPED)
    def test_a_justification_does_not_make_it_acceptable(
        self, gate: ModuleType, directive: str
    ) -> None:
        """The invariant forbids the SCOPE, not the absence of a reason."""
        source = f"{directive}  -- needed for X (TAG-001)\n\ndef f() -> None:\n    pass\n"
        found = gate.check_source("pkg/mod.py", source)
        assert found and "FILE-SCOPED" in found[0], found

    def test_a_line_one_whole_file_type_ignore_is_refused(self, gate: ModuleType) -> None:
        source = "# type: ignore\n\ndef f() -> None:\n    pass\n"
        found = gate.check_source("pkg/mod.py", source)
        assert len(found) == 1 and "FILE-SCOPED" in found[0], found

    def test_a_trailing_type_ignore_is_still_line_scoped(self, gate: ModuleType) -> None:
        """The control: the ordinary line-scoped form must not be swept up.

        Same spelling, different position — so a position-blind pattern would
        break every justified suppression in the tree.
        """
        source = (
            "def f() -> None:\n"
            "    x = 1  # type: ignore[assignment]  -- narrowed on purpose (TAG-001)\n"
        )
        assert gate.check_source("pkg/mod.py", source) == []

    def test_prose_about_a_directive_is_not_a_directive(self, gate: ModuleType) -> None:
        """A standalone comment that only DISCUSSES a directive is prose."""
        source = (
            "# A file-scoped `# ruff: noqa` would be refused here.\n\ndef f() -> None:\n    pass\n"
        )
        assert gate.check_source("pkg/mod.py", source) == []


#: The opening every tracked ``.py`` file must carry (``check_headers.py``).
#: It occupies lines 1-3, which is why a whole-module ``# type: ignore`` in a
#: compliant file can never be on line 1.
_HEADER = (
    "#!/usr/bin/env python3\n"
    "# Copyright (C) 2025-2026 Steel Security Advisors LLC\n"
    "# SPDX-License-Identifier: Apache-2.0\n"
)

#: A module ``mypy --strict`` rejects: an untyped def returning a bad sum.
_BODY = '"""Doc."""\n\n\ndef f(x):\n    return x + "a" + 1\n'

#: Every file-scoped mypy form that sits AFTER the mandatory header, each
#: paired with the line it occupies.  The gate used to report none of them.
_FILE_SCOPED_AFTER_HEADER = {
    "type-ignore-before-docstring": (_HEADER + "# type: ignore\n" + _BODY, 4),
    "type-ignore-after-blank": (_HEADER + "\n# type: ignore\n\n" + _BODY, 5),
    "type-ignore-before-decorator": (
        _HEADER + "# type: ignore\nimport functools\n\n\n@functools.cache\ndef f(x):\n"
        '    return x + "a" + 1\n',
        4,
    ),
    "mypy-allow-untyped-defs": (
        _HEADER + "# mypy: allow-untyped-defs, no-warn-unused-ignores\n" + _BODY,
        4,
    ),
    "mypy-flag-false": (_HEADER + "# mypy: disallow-untyped-defs=False\n" + _BODY, 4),
    "mypy-inside-docstring": (
        _HEADER + '"""Doc.\n\n# mypy: ignore-errors\n"""\n\n\ndef f(x):\n'
        '    return x + "a" + 1\n',
        6,
    ),
}


class TestFileScopedMypyFormsAreFoundWhereMypyFindsThem:
    """mypy's file-scoped forms are defined by POSITION, not by line 1.

    A ``# type: ignore`` anywhere before the module's first statement makes
    mypy skip the whole module, and mypy reads ``# mypy: <options>`` from any
    raw line beginning with that prefix — including one inside a string.  The
    gate used to recognise the first only on line 1, which the header
    ``check_headers.py`` requires always occupies, and the second only for
    ``ignore-errors``/``disable-error-code`` in a real comment token.  Each
    case below was reported clean.
    """

    @pytest.mark.parametrize("label", sorted(_FILE_SCOPED_AFTER_HEADER))
    def test_it_is_refused_as_file_scoped(self, gate: ModuleType, label: str) -> None:
        source, lineno = _FILE_SCOPED_AFTER_HEADER[label]
        found = gate.check_source("pkg/mod.py", source)
        assert len(found) == 1, found
        assert found[0].startswith(f"pkg/mod.py:{lineno}: FILE-SCOPED"), found[0]

    @pytest.mark.parametrize("label", sorted(_FILE_SCOPED_AFTER_HEADER))
    def test_mypy_really_skips_the_module(self, label: str, tmp_path: Path) -> None:
        """The premise, measured: each form silences ``mypy --strict``.

        Paired with the control below, which proves the same body fails
        without the directive — so a mypy that stopped honouring a form would
        turn this red rather than leave the gate refusing a harmless line.
        """
        api = pytest.importorskip("mypy.api")
        source, _ = _FILE_SCOPED_AFTER_HEADER[label]
        target = tmp_path / "mod.py"
        target.write_text(source, encoding="utf-8")
        out, err, status = api.run(
            [
                "--strict",
                "--no-incremental",
                "--config-file=",
                f"--cache-dir={os.devnull}",
                str(target),
            ]
        )
        assert status == 0, f"{label}: mypy was NOT silenced:\n{out}{err}"

    def test_the_control_body_fails_mypy(self, tmp_path: Path) -> None:
        api = pytest.importorskip("mypy.api")
        target = tmp_path / "mod.py"
        target.write_text(_HEADER + _BODY, encoding="utf-8")
        out, _err, status = api.run(
            [
                "--strict",
                "--no-incremental",
                "--config-file=",
                f"--cache-dir={os.devnull}",
                str(target),
            ]
        )
        assert status == 1 and "error:" in out, out

    def test_a_standalone_type_ignore_after_the_first_statement_is_not_file_scoped(
        self, gate: ModuleType
    ) -> None:
        """The boundary: past the first statement mypy no longer reads it as whole-module."""
        source = _HEADER + '"""Doc."""\n# type: ignore\nx = 1\n'
        assert gate.check_source("pkg/mod.py", source) == []

    def test_a_trailing_type_ignore_on_the_first_statement_is_line_scoped(
        self, gate: ModuleType
    ) -> None:
        """The boundary is strict: ON the first statement's line mypy scopes it to that line."""
        source = _HEADER + (
            "import os  # type: ignore[import-untyped]  -- untyped on purpose (TAG-001)\n"
        )
        assert gate.check_source("pkg/mod.py", source) == []

    def test_a_type_ignore_between_a_decorator_and_its_def_is_not_file_scoped(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """A decorated first statement starts at its decorator, as mypy counts it.

        So a ``# type: ignore`` below the decorator is past the first statement
        and mypy still checks the module — measured here, so the gate's
        boundary is pinned to mypy's rather than to the ``def`` line.
        """
        source = _HEADER + '@staticmethod\n# type: ignore\ndef f(x):\n    return x + "a" + 1\n'
        assert gate.check_source("pkg/mod.py", source) == []
        api = pytest.importorskip("mypy.api")
        target = tmp_path / "mod.py"
        target.write_text(source, encoding="utf-8")
        out, _err, status = api.run(
            [
                "--strict",
                "--no-incremental",
                "--config-file=",
                f"--cache-dir={os.devnull}",
                str(target),
            ]
        )
        assert status == 1 and "error:" in out, out

    def test_an_indented_mypy_line_in_a_string_is_not_configuration(self, gate: ModuleType) -> None:
        """mypy matches the prefix at column 0 only; an indented quotation is prose."""
        source = _HEADER + '"""Doc.\n\n    # mypy: ignore-errors\n"""\nx = 1\n'
        assert gate.check_source("pkg/mod.py", source) == []


class TestCppcheckRunsCleanWithoutSuppressions:
    """The positive proof behind the inverted invariant above.

    The per-site era guaranteed each pin still named a live finding; with no
    pins, the guarantee that matters is the stronger one -- the cppcheck the
    CI runs, minus only the two run-wide environment suppressions, reports
    NOTHING over ``src/c``.  If a real finding appears, or a source resolution
    regresses (a dropped ``= {0}`` on an out-parameter, a signed shift mask
    creeping back), this goes red locally in a few seconds instead of only in
    the gate.

    Skipped where cppcheck is not installed or cannot load its own std.cfg --
    the Static Analysis job always has a working one, so the enforcement is
    not lost, and a developer who has it gets the answer before pushing.
    """

    _REPORT = _re.compile(r"^[^:]+:\d+:\d+: (error|warning|performance|portability):")

    @staticmethod
    def _repo_root() -> Path:
        return Path(__file__).resolve().parent.parent

    def test_cppcheck_reports_nothing_over_src_c(self) -> None:
        cppcheck = _shutil.which("cppcheck")
        if cppcheck is None:
            _pytest.skip("cppcheck is not installed (no `cppcheck` on PATH)")

        root = self._repo_root()
        proc = _subprocess.run(
            [
                cppcheck,
                "--enable=warning,performance,portability",
                "--suppress=missingIncludeSystem",
                "--suppress=unusedFunction",
                "--inline-suppr",
                "--std=c11",
                "-Iinclude/",
                "-DAMA_USE_NATIVE_PQC",
                "-DPATH_MAX=4096",
                "--force",
                "src/c/",
            ],
            cwd=root,
            capture_output=True,
            text=True,
        )
        combined = proc.stdout + proc.stderr

        # A cppcheck that cannot load its own std.cfg analyses nothing and says
        # so; keyed to its words rather than to an empty report, so a cppcheck
        # that really ran and found nothing still exercises the assertion.
        if "installation is broken" in combined or "Failed to load std.cfg" in combined:
            first = next((ln for ln in combined.splitlines() if ln.strip()), "no output")
            _pytest.skip(
                f"the cppcheck at {cppcheck} cannot load its own std.cfg, so it "
                f"analysed nothing: {first.strip()[:200]}"
            )

        findings = [ln for ln in combined.splitlines() if self._REPORT.match(ln.strip())]
        assert not findings, (
            "cppcheck reported findings that are no longer suppressed. Resolve "
            "each at source -- zero-init the out-parameter, or write the shift "
            "mask in the defined `0 - ((uint64_t)x >> n)` form -- rather than "
            "re-adding a suppression:\n" + "\n".join(findings[:40])
        )


# ---------------------------------------------------------------------------
# The C-tree scan sees compiler- and sanitizer-level suppressions
# ---------------------------------------------------------------------------
#
# The scan recognised analyser comment markers (NOLINT, cppcheck-suppress, …)
# only, so `#pragma GCC diagnostic ignored`, `no_sanitize` attributes and
# `optnone` silenced diagnostics in the crypto core while the gate reported the
# tree "carries none at all".  The real tree carried three.


def _c_tree(tmp_path: Path, **files: str) -> Path:
    """A repository-shaped tree with the given files under src/c/."""
    for name, body in files.items():
        path = tmp_path / "src" / "c" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    "line",
    [
        '#pragma GCC diagnostic ignored "-Wpedantic"',
        '#pragma clang diagnostic ignored "-Wcast-align"',
        "#pragma warning(disable: 4996)",
        "#pragma warning( suppress : 4127 )",
        '__attribute__((no_sanitize("address")))',
        "__attribute__((noinline, no_sanitize_address))",
        "__attribute__((no_sanitize_memory))",
        "__attribute__((optnone))",
    ],
)
def test_compiler_and_sanitizer_suppressions_are_violations(tmp_path: Path, line: str) -> None:
    from tools.check_suppression_hygiene import scan_c_tree

    violations = scan_c_tree(_c_tree(tmp_path, **{"a.c": f"int x;\n{line}\nvoid f(void) {{}}\n"}))
    assert len(violations) == 1, violations
    assert "src/c/a.c:2" in violations[0]


@pytest.mark.parametrize(
    "line",
    [
        "__attribute__((noinline, no_sanitize_address))",
        '_Pragma("GCC diagnostic ignored \\"-Wconversion\\"")',
        "__attribute__((noinline, optnone))",
        "[[clang::optnone]] void g(void);",
        '#pragma GCC optimize("O0")',
        "#pragma clang optimize off",
        "__attribute__((disable_sanitizer_instrumentation))",
    ],
)
def test_every_spelling_is_a_violation_in_every_file(tmp_path: Path, line: str) -> None:
    """No exemption register, and no spelling the regex misses.

    ``no_sanitize_address`` on ``ama_secure_stack_wipe`` was the one recorded
    exception, keyed by file, so the same marker anywhere else in that file
    passed.  It turned out to be unnecessary — the function writes only its own
    locals, and the ASan lane runs clean without it — so the register is gone.
    The other rows are spellings the scan used to miss.
    """
    from tools.check_suppression_hygiene import scan_c_tree

    violations = scan_c_tree(
        _c_tree(tmp_path, **{"ama_consttime.c": f"int x;\n{line}\nvoid f(void) {{}}\n"})
    )
    assert len(violations) == 1 and "src/c/ama_consttime.c:2" in violations[0], violations


def test_the_real_tree_carries_none() -> None:
    from tools.check_suppression_hygiene import scan_c_tree

    assert scan_c_tree(REPO_ROOT) == []
    for unit in ("ama_nistp.c", "ama_secp256k1.c"):
        assert "diagnostic ignored" not in (REPO_ROOT / "src" / "c" / unit).read_text(
            encoding="utf-8"
        ), f"{unit} hides a warning behind a pragma again"


# --------------------------------------------------------------------------
# A justification has to give a reason (INVARIANT-13 condition 3)
#
# The separator check alone accepted ``-- (CB-001)``: a separator, a tag, and
# nothing between them.  Measured at c6326b4, 32 trailing markers in the tree
# passed that way, including markers a review had reported as having lost
# their inline reason.  The reason rule refuses an absent reason; it does not
# grade a present one.
# --------------------------------------------------------------------------


class TestAJustificationGivesAReason:
    REFUSED: ClassVar[dict[str, str]] = {
        "tag only": "import os  # noqa: F401 -- (CB-001)\n",
        "tag after a fmt directive": "import os  # fmt: skip  # noqa: F401 -- (CB-001)\n",
        "fmt directive after the tag": "import os  # noqa: F401 -- (CB-001)  # fmt: skip\n",
        "one word": "x = f(y)  # type: ignore[arg-type]  # cast (PQC-002)\n",
        "same": "import os  # noqa: E402 -- same (KF-003)\n",
        "ditto": "import os  # noqa: E402 -- ditto (KF-003)\n",
        "a pointer": "import os  # noqa: E402 -- see the note above (KF-003)\n",
        # Natural-English paraphrases of the pointers, measured past the
        # original eleven-word set: a morphological variant ('noted') or one
        # filler word of three letters ('one', 'too', 'reason') defeated the
        # all-pointer test while the forms they paraphrase were refused.
        "a pointer, inflected": "import os  # noqa: E402 -- as noted above (KF-003)\n",
        "a pointer plus filler": "import os  # noqa: E402 -- same as the one above (KF-003)\n",
        "a pointer plus 'too'": "import os  # noqa: E402 -- see the note above too (KF-003)\n",
        "a pointer to a reason": "import os  # noqa: E402 -- same reason here (KF-003)\n",
        "type-ignore tag only": "import os  # type: ignore[import-not-found]  # (MON-001)\n",
    }
    ACCEPTED: ClassVar[dict[str, str]] = {
        "two words": "import subprocess  # nosec B404 -- fixed argv (AB-001)\n",
        "type-ignore reason": "x = f(y)  # type: ignore[arg-type]  # bad arity (CAP-003)\n",
        # The noqa marker borrows the nosec marker's reason on the same line.
        "stacked markers": "r = Req(u)  # noqa: S310  # nosec B310 -- HTTPS fetch (HF-001)\n",
        # The rule counts words, not ASCII: two Cyrillic words of nine and
        # seven letters satisfy it.  The ASCII-only pattern this pins against
        # refused both of these as giving no reason, shredding the accented
        # one into fragments its diagnostic then printed (['rifi']).
        "a reason in Cyrillic": (
            "import os  # noqa: E402 -- \u043f\u0440\u043e\u0432\u0435\u0440\u0435\u043d\u043e"
            " \u0432\u0440\u0443\u0447\u043d\u0443\u044e (KM-001)\n"
        ),
        "a reason with accents": (
            "import os  # noqa: E402 -- d\u00e9j\u00e0 v\u00e9rifi\u00e9 (KM-001)\n"
        ),
    }

    @pytest.mark.parametrize("label", sorted(REFUSED))
    def test_an_absent_reason_is_refused(self, gate: ModuleType, label: str) -> None:
        found = gate.check_source("pkg/mod.py", self.REFUSED[label])
        assert any("gives no reason" in v for v in found), (label, found)

    @pytest.mark.parametrize("label", sorted(ACCEPTED))
    def test_a_stated_reason_is_accepted(self, gate: ModuleType, label: str) -> None:
        assert gate.check_source("pkg/mod.py", self.ACCEPTED[label]) == [], label

    def test_the_words_counted_exclude_tags_codes_and_directives(self, gate: ModuleType) -> None:
        rest = ": S310  # nosec B310 -- HTTPS fetch (HF-001)  # fmt: skip"
        assert gate.justification_words(rest) == ["HTTPS", "fetch"]

    def test_the_words_counted_are_unicode_words(self, gate: ModuleType) -> None:
        """Accented words come back whole, not as their ASCII fragments."""
        rest = ": E402 -- d\u00e9j\u00e0 v\u00e9rifi\u00e9 (KM-001)"
        assert gate.justification_words(rest) == ["d\u00e9j\u00e0", "v\u00e9rifi\u00e9"]


# --------------------------------------------------------------------------
# A marker opening a comment-only line
#
# The gate skipped every comment-only line as prose.  bandit does not: it
# applies a ``# nosec`` written on its own line inside a multi-line statement
# to that statement (the premise test below measures it).  semgrep honours a
# comment-only ``# nosemgrep`` when its finding starts on the next line and
# ignores one placed any further above or on a non-first span line (measured,
# 1.179.0; corrected per AGENTS.md section 6.6 -- this said semgrep ignores
# the line-before form), so the form is a live suppression the justification
# rules never examine, or a dead marker that claims one.
# --------------------------------------------------------------------------


class TestAMarkerOnACommentOnlyLine:
    @pytest.mark.parametrize(
        "source",
        [
            (
                "def f(\n    pw: str = (\n        # nosec B107 -- default, not a secret (X-001)\n"
                '        "x"\n    ),\n) -> None:\n    pass\n'
            ),
            "# nosemgrep: non-constant-time-comparison -- public label (X-001)\nok = a == b\n",
            "# nosec-justification: the hash below is SHA-2 only\nx = 1\n",
        ],
    )
    def test_it_is_refused(self, gate: ModuleType, source: str) -> None:
        found = gate.check_source("pkg/mod.py", source)
        assert any("comment-only line" in v for v in found), found

    def test_prose_that_mentions_a_marker_is_not_one(self, gate: ModuleType) -> None:
        source = "# A justified finding carries an inline ``# nosec B105``.\nx = 1\n"
        assert gate.check_source("pkg/mod.py", source) == []

    def test_bandit_really_applies_a_comment_only_nosec(self, tmp_path: Path) -> None:
        """The premise, measured: the comment-only marker silences bandit.

        ``f`` carries the marker on its own line inside the signature; ``g``
        is the unsuppressed control.  If bandit stopped honouring the form,
        ``f`` would be reported too and this would fail, rather than leave the
        gate refusing a line that suppresses nothing.
        """
        pytest.importorskip("bandit")
        target = tmp_path / "mod.py"
        target.write_text(
            "def f(\n    password: str = (\n        # nosec B107\n"
            '        "hunter2"\n    ),\n) -> None:\n    pass\n\n\n'
            'def g(password: str = "hunter2") -> None:\n    pass\n',
            encoding="utf-8",
        )
        run = _subprocess.run(
            [sys.executable, "-m", "bandit", "-q", "-f", "json", str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        import json

        control_line = (
            target.read_text(encoding="utf-8")
            .splitlines()
            .index('def g(password: str = "hunter2") -> None:')
        )
        lines = sorted(r["line_number"] for r in json.loads(run.stdout)["results"])
        assert lines == [control_line + 1], f"expected only the unsuppressed g(): {lines}"


# --------------------------------------------------------------------------
# A marker HIDDEN in a comment-only line (the marker-first rule defeated)
#
# bandit matches its marker with ``search`` over the whole comment token
# (``NOSEC_COMMENT``, 1.9.4), and attributes a finding to its node's FULL
# span, bodies included (``linerange``/``get_nosec``).  So one character of
# leading prose -- or a second ``#`` -- before ``nosec`` defeats the
# marker-first rule above while leaving the suppression fully live, anywhere
# inside any multi-line node.  Outside every such span bandit has nothing to
# attribute, so a module-level prose mention stays prose; the premise test
# below measures both sides.
# --------------------------------------------------------------------------


class TestAMarkerHiddenInACommentOnlyLine:
    SIGNATURE = (
        "def f(\n    pw: str = (\n        {comment}\n" '        "x"\n    ),\n) -> None:\n    pass\n'
    )
    BODY = 'def f(pw: str = "x") -> None:\n    y = 1\n    {comment}\n    return y\n'

    REFUSED: ClassVar[dict[str, str]] = {
        "prose then marker, in a signature": SIGNATURE.format(
            comment="# default sentinel, not a credential  # nosec B107"
        ),
        "a second hash, in a signature": SIGNATURE.format(comment="## nosec B107"),
        "bare blanket after prose": SIGNATURE.format(comment="# see module docs  # nosec"),
        "prose then marker, deep in a body": BODY.format(
            comment="# measured against the control  # nosec"
        ),
    }
    #: semgrep's previous-line rule reads a comment-only line whose first
    #: alphanumeric run begins ``nosem`` -- case-insensitive, extra hashes
    #: and punctuation before it allowed, no space required -- as a nosemgrep
    #: for a finding starting on the next line (measured, semgrep 1.179.0 and
    #: CI's pinned 1.74.0 agreeing; the premise test below re-measures it
    #: where semgrep is installed).  Position does not matter to the gate:
    #: either a matchable line sits below, and the line is a live suppression
    #: the justification rules never examine, or none does and it is a dead
    #: marker claiming one.
    SEMGREP_REFUSED: ClassVar[dict[str, str]] = {
        "a second hash": "## nosemgrep: non-constant-time-comparison\nok = a == b\n",
        "a hash, spaces, a hash": "#  # nosemgrep\nok = a == b\n",
        "upper case": "# NOSEMGREP\nok = a == b\n",
        "the short form": "# nosem\nok = a == b\n",
        "a word merely starting with nosem": "# nosemantic cleanup\nok = a == b\n",
    }
    PROSE: ClassVar[dict[str, str]] = {
        "mention without a hash, in a signature": SIGNATURE.format(
            comment="# bandit honours a nosec written here"
        ),
        "prose then marker, at module level": (
            "# default sentinel, not a credential  # nosec B107\nx = 1\n"
        ),
        "a second hash, at module level": "## nosec B107\nx = 1\n",
        "prose before a nosemgrep": "# see docs  # nosemgrep\nok = a == b\n",
        "a word before the nosem run": "# a bare ``# nosemgrep`` suppresses\nok = a == b\n",
    }

    @pytest.mark.parametrize("label", sorted(REFUSED))
    def test_a_live_hidden_marker_is_refused(self, gate: ModuleType, label: str) -> None:
        found = gate.check_source("pkg/mod.py", self.REFUSED[label])
        assert any("live bandit suppression" in v for v in found), (label, found)

    @pytest.mark.parametrize("label", sorted(SEMGREP_REFUSED))
    def test_a_live_semgrep_shape_is_refused(self, gate: ModuleType, label: str) -> None:
        found = gate.check_source("pkg/mod.py", self.SEMGREP_REFUSED[label])
        assert any("live semgrep suppression" in v for v in found), (label, found)

    @pytest.mark.parametrize("label", sorted(PROSE))
    def test_what_bandit_cannot_read_stays_prose(self, gate: ModuleType, label: str) -> None:
        assert gate.check_source("pkg/mod.py", self.PROSE[label]) == [], label

    def test_the_span_is_every_multiline_node(self, gate: ModuleType) -> None:
        """The boundary itself: in a body it is live, between functions not."""
        spanned = gate.multiline_spanned_lines(
            "def f() -> int:\n    return 1\n\n\ndef g() -> int:\n    return 2\n"
        )
        assert {1, 2, 5, 6} <= spanned and 3 not in spanned and 4 not in spanned

    def test_bandit_really_applies_a_hidden_marker(self, tmp_path: Path) -> None:
        """The premise, measured, both sides of the boundary.

        ``f`` carries prose-then-marker deep in its BODY; bandit 1.9.4 still
        suppresses the signature's B107, because the finding's linerange is
        the whole function.  The identical comment at module level, between
        ``f`` and the control ``g``, suppresses nothing -- so if this fails
        with BOTH functions reported, bandit stopped honouring the hidden
        form and the gate's rule is refusing prose; if it fails with NEITHER
        reported, bandit widened further and the module-level PROSE cases
        above are the ones to revisit.
        """
        pytest.importorskip("bandit")
        target = tmp_path / "mod.py"
        target.write_text(
            'def f(password: str = "hunter2") -> None:\n'
            "    y = 1\n"
            "    # measured against the control  # nosec\n"
            "    del y\n\n\n"
            "# measured against the control  # nosec\n\n\n"
            'def g(password: str = "hunter2") -> None:\n    pass\n',
            encoding="utf-8",
        )
        run = _subprocess.run(
            [sys.executable, "-m", "bandit", "-q", "-f", "json", str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        import json

        control_line = (
            target.read_text(encoding="utf-8")
            .splitlines()
            .index('def g(password: str = "hunter2") -> None:')
        )
        lines = sorted(r["line_number"] for r in json.loads(run.stdout)["results"])
        assert lines == [control_line + 1], f"expected only the unsuppressed g(): {lines}"

    @pytest.mark.skipif(
        _shutil.which("semgrep") is None,
        reason="semgrep is not installed (no `semgrep` on PATH)",
    )
    def test_semgrep_really_honours_the_measured_boundary(self, tmp_path: Path) -> None:
        """The premise, measured against semgrep itself, on both sides.

        One run over three files with a ``$A == $B`` rule: a hidden
        ``## nosemgrep`` directly above the match suppresses it, as does the
        prose-shaped ``# nosemantic cleanup`` (its first alphanumeric run
        begins ``nosem``); the same marker with a line between itself and the
        match suppresses nothing.  If a semgrep release narrows the boundary,
        the first two files report and this fails rather than leave the gate
        refusing prose; if it widens past a leading word, the control in
        ``PROSE`` is the place to revisit.
        """
        (tmp_path / "rule.yml").write_text(
            "rules:\n"
            "- id: eq-rule\n"
            "  patterns:\n"
            "    - pattern: $A == $B\n"
            "  message: eq\n"
            "  languages: [python]\n"
            "  severity: WARNING\n",
            encoding="utf-8",
        )
        (tmp_path / "hidden.py").write_text(
            "## nosemgrep: eq-rule\nok = a == b\n", encoding="utf-8"
        )
        (tmp_path / "prefix_word.py").write_text(
            "# nosemantic cleanup\nok = a == b\n", encoding="utf-8"
        )
        (tmp_path / "further_above.py").write_text(
            "## nosemgrep: eq-rule\n\nok = a == b\n", encoding="utf-8"
        )
        run = _subprocess.run(
            [
                _shutil.which("semgrep") or "semgrep",
                "--config",
                str(tmp_path / "rule.yml"),
                "--json",
                "--disable-version-check",
                "--metrics=off",
                str(tmp_path / "hidden.py"),
                str(tmp_path / "prefix_word.py"),
                str(tmp_path / "further_above.py"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        import json

        reported = sorted(Path(r["path"]).name for r in json.loads(run.stdout)["results"])
        assert reported == ["further_above.py"], reported
