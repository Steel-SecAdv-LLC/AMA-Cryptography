# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The release smoke test's binding-coverage assertion must count, not match.

``tools/wheel_smoke_test.py::check_integrity_and_bindings`` documents itself as
distinguishing three outcomes: a digest MISMATCH (tampering), PARTIAL coverage,
and "uncovered (the wheel was built without ``--bind-extensions``)".  Its third
assertion tested ``"binding extension(s) verified" in detail``.

``_self_test._check_binding_extensions`` returns
``f"{len(binding_digests)} binding extension(s) verified"``, so an artefact that
binds NOTHING yields ``"0 binding extension(s) verified"`` — which contains that
substring.  The two assertions above it pass on the same string as well
("MISMATCH" absent, "PARTIALLY covered" and "not covered by the signed
artefact" absent).  All three were therefore green for exactly the pipeline
fault the function exists to catch, on a release wheel.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "wheel_smoke_test.py"


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("wheel_smoke_test", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("detail", "expected"),
    [
        ("0 binding extension(s) verified", 0),
        ("6 binding extension(s) verified", 6),
        ("signed integrity verified; 3 binding extension(s) verified", 3),
        ("signed integrity verified", None),
        ("", None),
    ],
)
def test_the_count_is_parsed_out_of_the_sentence(
    tool: ModuleType, detail: str, expected: int | None
) -> None:
    assert tool._bound_extension_count(detail) == expected


def test_zero_bound_extensions_is_not_a_pass(tool: ModuleType) -> None:
    """The defect, stated as the property it violated.

    A substring test cannot tell 0 from 6; a count can, and 0 is the state a
    release wheel must never ship in.
    """
    zero = tool._bound_extension_count("0 binding extension(s) verified")
    assert zero == 0
    assert not (
        zero is not None and zero > 0
    ), "an artefact that binds no extension satisfied the 'binds at least one' check"


def test_an_unreadable_detail_is_not_a_pass(tool: ModuleType) -> None:
    """Fail-closed: a smoke test that cannot read the count must not pass."""
    missing = tool._bound_extension_count("integrity verified (no count here)")
    assert missing is None
    assert not (missing is not None and missing > 0)


def test_a_real_count_still_passes(tool: ModuleType) -> None:
    """The control: the assertion must still accept a correctly built wheel."""
    six = tool._bound_extension_count("6 binding extension(s) verified")
    assert six is not None and six > 0
