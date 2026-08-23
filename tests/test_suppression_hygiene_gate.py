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
import sys
from pathlib import Path
from types import ModuleType

import pytest

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
    RUN_WIDE_IDS = {"missingIncludeSystem", "unusedFunction", "shiftTooManyBitsSigned"}

    def test_the_suppressions_file_exists_and_is_referenced(self) -> None:
        assert self.SUPPRESSIONS.is_file(), "the per-site suppressions file is missing"
        text = self.WORKFLOW.read_text(encoding="utf-8")
        assert "--suppressions-list=.cppcheck-suppressions" in text, (
            "the workflow does not use the per-site suppressions file"
        )

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
