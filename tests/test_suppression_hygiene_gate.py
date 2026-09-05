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


class TestCppcheckSuppressionsArePerSite:
    """INVARIANT-13 applied to the cppcheck configuration.

    The static-analysis workflow used to silence whole error IDs for whole
    files::

        --suppress=uninitvar:src/c/ama_nistp.c
        --suppress=uninitvar:src/c/ama_kyber.c
        --suppress=uninitvar:src/c/ama_dilithium.c
        --suppress=arrayIndexOutOfBounds:src/c/dispatch/ama_dispatch.c

    Each carried a justification and each was, at the time, a true statement
    about a false positive.  What the justification did not say is that a
    genuinely uninitialised read introduced later anywhere in the same file
    would be reported and discarded.  Measured by injecting one into
    ``ama_nistp.c``: the file-wide configuration reported it 0 times; the
    per-site configuration reported it at ``ama_nistp.c:469``.

    ``arrayIndexOutOfBounds`` needed no suppression at all — passing the real
    ``-DPATH_MAX=4096`` removes both findings and leaves the check live — so
    its absence from the suppressions file is asserted too.
    """

    WORKFLOW = REPO_ROOT / ".github" / "workflows" / "static-analysis.yml"
    SUPPRESSIONS = REPO_ROOT / ".cppcheck-suppressions"

    #: IDs that are legitimately whole-run rather than per-site: they are about
    #: cppcheck's own environment or about vendored code, not about a finding
    #: in a file this project maintains.
    RUN_WIDE_IDS: ClassVar[set[str]] = {
        "missingIncludeSystem",
        "unusedFunction",
        "shiftTooManyBitsSigned",
    }

    def test_the_suppressions_file_exists_and_is_referenced(self) -> None:
        assert self.SUPPRESSIONS.is_file(), "the per-site suppressions file is missing"
        text = self.WORKFLOW.read_text(encoding="utf-8")
        assert (
            "--suppressions-list=.cppcheck-suppressions" in text
        ), "the workflow does not use the per-site suppressions file"

    def test_no_file_wide_suppression_on_the_command_line(self) -> None:
        text = self.WORKFLOW.read_text(encoding="utf-8")
        offenders: list[str] = []
        for raw in text.splitlines():
            line = raw.strip().rstrip("\\").strip()
            if not line.startswith("--suppress="):
                continue
            body = line[len("--suppress=") :]
            error_id, _, target = body.partition(":")
            if not target:
                if error_id not in self.RUN_WIDE_IDS:
                    offenders.append(line)
                continue
            if target.startswith("src/c/vendor/"):
                continue  # third-party code this project does not maintain
            if ":" not in target:  # a path with no line number == file-wide
                offenders.append(line)
        assert not offenders, (
            f"file-wide cppcheck suppressions are back: {offenders}. A whole error "
            f"ID silenced for a whole file discards real findings introduced later "
            f"in that file; put the site and its reason in .cppcheck-suppressions."
        )

    def test_every_suppression_names_a_line(self) -> None:
        offenders: list[str] = []
        for number, raw in enumerate(
            self.SUPPRESSIONS.read_text(encoding="utf-8").splitlines(), start=1
        ):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) != 3 or not parts[2].isdigit():
                offenders.append(f"line {number}: {line!r}")
        assert not offenders, (
            f".cppcheck-suppressions entries must be <id>:<file>:<line>; a file-wide "
            f"entry here is the same defect the command line no longer has: {offenders}"
        )

    def test_array_index_out_of_bounds_is_not_suppressed(self) -> None:
        """It was never a cppcheck limitation — see the file's own header."""
        text = self.SUPPRESSIONS.read_text(encoding="utf-8")
        entries = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        assert not any(entry.startswith("arrayIndexOutOfBounds") for entry in entries), (
            "arrayIndexOutOfBounds is suppressed again; -DPATH_MAX=4096 removes "
            "the findings outright and keeps the bounds check live"
        )
        assert "-DPATH_MAX=4096" in self.WORKFLOW.read_text(encoding="utf-8"), (
            "the workflow no longer passes the real PATH_MAX, so cppcheck will "
            "invent dir[1] again and the findings will return"
        )

    def test_no_bare_hash_comment_lines(self) -> None:
        """cppcheck 2.13 rejects a line that is exactly ``#``.

        "Failed to add suppression. No id." — and it is a hard error, so the
        whole gate exits non-zero for a formatting reason rather than a
        finding.  Cost an iteration here; pinned so it costs none later.
        """
        bare = [
            number
            for number, line in enumerate(
                self.SUPPRESSIONS.read_text(encoding="utf-8").splitlines(), start=1
            )
            if line.strip() == "#"
        ]
        assert not bare, f"bare '#' lines cppcheck rejects, at lines {bare}"


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


class TestCppcheckSuppressionsStillPointAtRealFindings:
    """A pinned suppression must name the line cppcheck actually reports.

    ``.cppcheck-suppressions`` pins by exact ``id:file:line``.  The class above
    already checks that every entry NAMES a line, which was the previous
    failure mode, but nothing checked that the named line is still the site.
    It stops matching the moment code above it moves, and then the finding it
    was written for comes back as a hard CI failure with no local warning --
    twice in one working session: ``src/c/ama_dilithium.c`` when three
    ``dil_*_reduce`` calls were inserted (2219 -> 2355), and
    ``src/c/ama_nistp.c`` when ``nistp_mulx_gate`` became atomic
    (667/769/1136 -> 699/801/1168).  Both were found by CI, both were a wasted
    cycle, and both are exactly what this checks locally in about three
    seconds.

    Scoped to the files that carry pinned entries rather than the whole tree,
    and skipped where cppcheck is not installed -- the Static Analysis job
    always has it, so the enforcement is not lost, and a developer who has it
    gets the answer before pushing.
    """

    _ENTRY = _re.compile(r"^(?P<id>[a-zA-Z]+):(?P<file>[^:]+):(?P<line>\d+)\s*$")
    _REPORT = _re.compile(r"^(?P<file>[^:]+):(?P<line>\d+):\d+: \w+: .*\[(?P<id>\w+)\]\s*$")

    @staticmethod
    def _repo_root() -> Path:
        return Path(__file__).resolve().parent.parent

    @classmethod
    def _pinned(cls) -> list[tuple[str, str, int]]:
        text = (cls._repo_root() / ".cppcheck-suppressions").read_text(encoding="utf-8")
        out: list[tuple[str, str, int]] = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = cls._ENTRY.match(line)
            if m:
                out.append((m.group("id"), m.group("file"), int(m.group("line"))))
        return out

    def test_there_are_pinned_entries_to_check(self) -> None:
        """Non-vacuity: an empty parse would make the check below pass on anything."""
        pinned = self._pinned()
        assert len(pinned) >= 3, f"only {len(pinned)} line-pinned suppressions parsed"

    def test_every_pinned_line_is_still_the_line_cppcheck_reports(self) -> None:
        cppcheck = _shutil.which("cppcheck")
        if cppcheck is None:
            _pytest.skip("cppcheck is not installed (no `cppcheck` on PATH)")

        root = self._repo_root()
        pinned = self._pinned()
        files = sorted({f for _id, f, _ln in pinned})
        assert files, "no files carry a pinned suppression"

        proc = _subprocess.run(
            [
                cppcheck,
                "--enable=warning,performance,portability",
                "--suppress=missingIncludeSystem",
                "--suppress=unusedFunction",
                "--suppress=shiftTooManyBitsSigned",
                "--inline-suppr",
                "--std=c11",
                "-Iinclude/",
                "-DAMA_USE_NATIVE_PQC",
                "-DPATH_MAX=4096",
                "--force",
                *files,
            ],
            cwd=root,
            capture_output=True,
            text=True,
        )
        combined = proc.stdout + proc.stderr

        # Being on PATH is not the same as working.  The Windows runners carry
        # a cppcheck inside Strawberry Perl whose std.cfg path was baked at
        # build time to a directory that exists only on the machine that built
        # it (R:/winlibs64ucrt_stage/...), so it loads no configuration,
        # analyses nothing, and says so.  Every Windows lane failed here on the
        # commit that added this check, for a reason that is a property of that
        # runner's toolchain rather than of this repository's pins.
        #
        # The skip is keyed to cppcheck's own words rather than to "the report
        # was empty", so a cppcheck that really ran and found nothing still
        # fails the assertion below — which is the whole point of having it.
        if "installation is broken" in combined or "Failed to load std.cfg" in combined:
            first = next((ln for ln in combined.splitlines() if ln.strip()), "no output")
            _pytest.skip(
                f"the cppcheck at {cppcheck} cannot load its own std.cfg, so it "
                f"analysed nothing: {first.strip()[:200]}"
            )

        reported = set()
        for raw in combined.splitlines():
            m = self._REPORT.match(raw.strip())
            if m:
                reported.add((m.group("id"), m.group("file"), int(m.group("line"))))

        assert reported, (
            "cppcheck reported nothing at all over "
            f"{files} — either the invocation is wrong or this cppcheck did not "
            "analyse anything, and in both cases the check below would pass "
            "vacuously. Output:\n" + combined[:2000]
        )

        stale = [p for p in pinned if p not in reported]
        assert not stale, (
            "these suppressions name a line cppcheck no longer reports, so they "
            "suppress nothing and the finding they were written for will fail CI:\n"
            + "".join(f"    {i}:{f}:{ln}\n" for i, f, ln in stale)
            + "  Re-pin each to the line now reported for that id in that file. "
            "Lines shift whenever code above them is inserted or removed."
        )
