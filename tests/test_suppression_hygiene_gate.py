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
import re as _re
import shutil as _shutil
import subprocess as _subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import ClassVar

import pytest
import pytest as _pytest

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

    def test_no_file_or_class_wide_suppression_on_the_command_line(self) -> None:
        text = self.WORKFLOW.read_text(encoding="utf-8")
        offenders: list[str] = []
        for raw in text.splitlines():
            line = raw.strip().rstrip("\\").strip()
            if not line.startswith("--suppress="):
                continue
            body = line[len("--suppress=") :]
            error_id, _, target = body.partition(":")
            if target:
                offenders.append(line)  # any file-targeted suppression
            elif error_id not in self.RUN_WIDE_IDS:
                offenders.append(line)  # a class-wide ID that is not env noise
        assert not offenders, (
            f"cppcheck suppressions are back on the command line: {offenders}. "
            "Every finding this project maintains is resolved at source; only the "
            f"run-wide environment IDs {sorted(self.RUN_WIDE_IDS)} may remain."
        )

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
        source = "def f() -> None:\n    x = 1  # type: ignore[assignment]  -- why (TAG-001)\n"
        assert gate.check_source("pkg/mod.py", source) == []

    def test_prose_about_a_directive_is_not_a_directive(self, gate: ModuleType) -> None:
        """A standalone comment that only DISCUSSES a directive is prose."""
        source = (
            "# A file-scoped `# ruff: noqa` would be refused here.\n\ndef f() -> None:\n    pass\n"
        )
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
