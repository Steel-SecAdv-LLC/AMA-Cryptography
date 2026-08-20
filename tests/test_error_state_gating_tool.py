# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for ``tools/check_error_state_gating.py``.

This gate is the exhaustive, static half of INVARIANT-39/40 output inhibition:
``tests/test_post_failclosed.py`` drives a representative from each family in
the ERROR state, and this tool asserts that EVERY public entry point reaching
the native library is guarded. It is required in CI and, until this module, had
no test of its own — the gap INVARIANT-2 names.

Two properties are pinned here that the tool got wrong or could not express:

1. **Guard delegation.** ``ascon``'s public entry points call
   ``lib.ama_ascon_*(...)`` directly in their own bodies while the guard sits
   one level down, in ``_require_native()``. The tool's ``MODULES`` list
   excluded the module on the stated grounds that "a body-level scan cannot see
   the reach" — but the reach was always visible (``_native_call_lines`` is
   receiver-agnostic); it was the GUARD that was not. The tool now follows one
   level of delegation, and ``ascon`` is enforced statically.

2. **The delegation rule is narrow on purpose.** Only a private helper whose
   FIRST executable statement is a guard call counts. A helper that guards
   inside a branch guards only sometimes, and accepting it would make the gate
   assert something weaker than it claims.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "check_error_state_gating.py"


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_error_state_gating", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _helpers(tool: ModuleType, source: str) -> set[str]:
    return set(tool.guard_delegating_helpers(ast.parse(source)))


class TestGuardDelegation:
    def test_a_helper_that_opens_with_a_guard_qualifies(self, tool: ModuleType) -> None:
        source = """
def _require_native():
    check_crypto_permitted()
    if not AVAILABLE:
        raise RuntimeError("no")
    return _lib
"""
        assert "_require_native" in _helpers(tool, source)

    def test_a_docstring_does_not_disqualify_it(self, tool: ModuleType) -> None:
        source = '''
def _require_native():
    """Doc."""
    check_crypto_permitted()
    return _lib
'''
        assert "_require_native" in _helpers(tool, source)

    def test_the_module_qualified_guard_form_qualifies(self, tool: ModuleType) -> None:
        source = """
def _require_native():
    _module_state.check_crypto_permitted()
    return _lib
"""
        assert "_require_native" in _helpers(tool, source)

    def test_a_guard_inside_a_branch_does_not_qualify(self, tool: ModuleType) -> None:
        """Guarding sometimes is not guarding."""
        source = """
def _require_native():
    if strict:
        check_crypto_permitted()
    return _lib
"""
        assert _helpers(tool, source) == set()

    def test_a_guard_after_other_work_does_not_qualify(self, tool: ModuleType) -> None:
        """The native call could already have happened above it."""
        source = """
def _require_native():
    value = _lib.ama_thing()
    check_crypto_permitted()
    return value
"""
        assert _helpers(tool, source) == set()

    def test_a_helper_that_never_guards_does_not_qualify(self, tool: ModuleType) -> None:
        source = """
def _require_native():
    return _lib
"""
        assert _helpers(tool, source) == set()


class TestDelegationMakesTheAuditSeeTheGuard:
    """End to end over a synthetic module, both directions."""

    GUARDED = """
def _require_native():
    check_crypto_permitted()
    return _lib


def hash256(data):
    lib = _require_native()
    return lib.ama_ascon_hash256(data)
"""

    UNGUARDED = """
def _require_native():
    return _lib


def hash256(data):
    lib = _require_native()
    return lib.ama_ascon_hash256(data)
"""

    def test_delegated_guard_is_accepted(self, tool: ModuleType, tmp_path: Path) -> None:
        path = tmp_path / "mod.py"
        path.write_text(self.GUARDED, encoding="utf-8")
        ungated, _stale, checked = tool.audit(path, exempt={})
        assert checked == 1, "the native call must have been counted"
        assert ungated == []

    def test_a_helper_without_a_guard_is_reported(self, tool: ModuleType, tmp_path: Path) -> None:
        """The negative control: delegation must not be a blanket pass."""
        path = tmp_path / "mod.py"
        path.write_text(self.UNGUARDED, encoding="utf-8")
        ungated, _stale, checked = tool.audit(path, exempt={})
        assert checked == 1
        assert [name for name, _line in ungated] == ["hash256"]


class TestTheRealTree:
    def test_ascon_is_in_scope(self, tool: ModuleType) -> None:
        """The module the stale comment excluded is now enforced statically."""
        assert "ama_cryptography/ascon.py" in tool.MODULES

    def test_ascons_public_entry_points_are_counted(self, tool: ModuleType) -> None:
        """Non-vacuity: being "in scope" must mean entry points were found."""
        ungated, _stale, checked = tool.audit(
            REPO_ROOT / "ama_cryptography" / "ascon.py", exempt={}
        )
        assert checked >= 3, f"expected the three Ascon native entry points, counted {checked}"
        assert ungated == [], ungated

    def test_the_whole_scanned_surface_is_gated(self, tool: ModuleType) -> None:
        for rel in tool.MODULES:
            ungated, _stale, _checked = tool.audit(REPO_ROOT / rel)
            assert ungated == [], (rel, ungated)

    def test_entry_point_counts_are_positive_and_consistent(self, tool: ModuleType) -> None:
        """The figure the documentation cites must come from a real scan."""
        native, cython = tool.entry_point_counts()
        assert native > 0 and cython > 0
        recomputed = sum(tool.audit(REPO_ROOT / rel)[2] for rel in tool.MODULES)
        assert native == recomputed


class TestTheCythonBindingInventoryHasAFloor:
    """``BINDING_PYX`` is hand-maintained; a new binding must not go unnoticed."""

    def test_every_binding_pyx_in_the_tree_is_listed(self, tool: ModuleType) -> None:
        """Discovery, as a floor under the written list.

        The list names five ``.pyx`` files. Nothing checked it against the
        tree, so a sixth binding — a new ``cy_*`` surface reaching the C kernel
        while bypassing ``pqc_backends`` and POST alike — would simply not be
        scanned, and the gate would report a clean run over it.

        ``math_engine.pyx`` is deliberately not a binding: it exposes no
        ``cy_*`` entry point and reaches no ``ama_*`` symbol, so it is excluded
        by measurement rather than by name.
        """
        cython_dir = REPO_ROOT / "src" / "cython"
        listed = {Path(rel).name for rel in tool.BINDING_PYX}
        found = set()
        for path in sorted(cython_dir.glob("*.pyx")):
            text = path.read_text(encoding="utf-8")
            if "def cy_" in text:
                found.add(path.name)
        missing = sorted(found - listed)
        assert not missing, (
            "these .pyx files define cy_* entry points but are absent from "
            f"BINDING_PYX, so the gate never scans them: {missing}"
        )
        stale = sorted(listed - {p.name for p in cython_dir.glob("*.pyx")})
        assert not stale, f"BINDING_PYX names files that do not exist: {stale}"
