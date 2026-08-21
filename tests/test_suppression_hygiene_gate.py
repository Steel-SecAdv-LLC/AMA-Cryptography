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
