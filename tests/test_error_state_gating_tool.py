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


class TestModuleDiscovery:
    """Module-level discovery: no native-reaching module unaudited by omission (M16).

    ``MODULES`` was hand-maintained against eleven modules that reach the native
    library, so a new one was unaudited by default. Discovery now requires every
    native-reaching module to be audited (MODULES) or exempted with a reason
    (EXEMPT_MODULES).
    """

    def _mk(self, tmp_path: Path, name: str, body: str) -> Path:
        pkg = tmp_path / "ama_cryptography"
        pkg.mkdir(exist_ok=True)
        (pkg / name).write_text(body, encoding="utf-8")
        return tmp_path

    def test_every_native_reaching_module_is_classified(self, tool: ModuleType) -> None:
        discovered = set(tool.discover_native_reaching_modules(REPO_ROOT))
        classified = set(tool.MODULES) | set(tool.EXEMPT_MODULES)
        unclassified = sorted(discovered - classified)
        assert not unclassified, (
            "these modules reach the native library but are in neither MODULES nor "
            f"EXEMPT_MODULES, so they are unaudited by omission: {unclassified}"
        )

    def test_discovery_finds_the_known_native_modules(self, tool: ModuleType) -> None:
        """Non-vacuity: discovery must actually find the modules we know reach native."""
        discovered = set(tool.discover_native_reaching_modules(REPO_ROOT))
        for rel in (
            "ama_cryptography/pqc_backends.py",
            "ama_cryptography/ascon.py",
            "ama_cryptography/agent_binding.py",
            "ama_cryptography/secure_memory.py",
            "ama_cryptography/_self_test.py",
            "ama_cryptography/crypto_api.py",
            "ama_cryptography/hybrid_combiner.py",
            "ama_cryptography/key_management.py",
            "ama_cryptography/legacy_compat.py",
        ):
            assert rel in discovered, f"discovery missed a native-reaching module: {rel}"

    def test_exempt_modules_are_not_stale(self, tool: ModuleType) -> None:
        discovered = set(tool.discover_native_reaching_modules(REPO_ROOT))
        stale = sorted(m for m in tool.EXEMPT_MODULES if m not in discovered)
        assert not stale, f"EXEMPT_MODULES names modules that no longer reach native: {stale}"

    def test_agent_binding_and_secure_memory_are_audited_not_exempted(
        self, tool: ModuleType
    ) -> None:
        """Both have a directly-auditable public native surface, so they belong in
        MODULES (actively audited), not EXEMPT_MODULES."""
        assert "ama_cryptography/agent_binding.py" in tool.MODULES
        assert "ama_cryptography/secure_memory.py" in tool.MODULES
        # The two page-locking functions emit no key material and are the reason
        # secure_memory can be audited rather than exempted wholesale.
        assert "secure_mlock" in tool.EXEMPT
        assert "secure_munlock" in tool.EXEMPT

    def test_an_unclassified_native_module_is_discovered(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """Reproduce the M16 gap: a new module reaching native is discovered so
        main() can refuse it until it is audited or exempted on purpose."""
        repo = self._mk(
            tmp_path,
            "newthing.py",
            "from ama_cryptography.pqc_backends import _native_lib\n"
            "def do():\n    return _native_lib.ama_something()\n",
        )
        discovered = tool.discover_native_reaching_modules(repo)
        assert "ama_cryptography/newthing.py" in discovered

    def test_an_aliased_import_is_discovered(self, tool: ModuleType, tmp_path: Path) -> None:
        """``from .pqc_backends import _native_lib as lib`` reaches native.

        An aliased import is an ``ast.alias`` node — never a Name or an
        Attribute — and every later use is ``lib.ama_x``, so the Name/
        Attribute/getattr arms all miss it.  Before the Import/ImportFrom arm
        was added, such a module reached the library while appearing in
        neither MODULES nor EXEMPT_MODULES: the unaudited-by-omission state
        discovery exists to make impossible.
        """
        repo = self._mk(
            tmp_path,
            "aliased.py",
            "from ama_cryptography.pqc_backends import _native_lib as lib\n"
            "def do():\n    return lib.ama_something()\n",
        )
        assert "ama_cryptography/aliased.py" in tool.discover_native_reaching_modules(repo)

    def test_getattr_string_form_is_discovered(self, tool: ModuleType, tmp_path: Path) -> None:
        repo = self._mk(
            tmp_path,
            "dyn.py",
            "import sys\n"
            "def probe():\n"
            "    pb = sys.modules.get('ama_cryptography.pqc_backends')\n"
            "    return getattr(pb, '_native_lib', None)\n",
        )
        assert "ama_cryptography/dyn.py" in tool.discover_native_reaching_modules(repo)

    def test_comment_and_lookalike_are_not_false_positives(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """A comment mentioning _native_lib, and the _find_native_library name
        (which contains the substring), must not register as reaching native —
        the reason discovery is AST-based rather than a grep."""
        repo = self._mk(
            tmp_path,
            "innocent.py",
            "# this module does not touch _native_lib at all\n"
            "from ama_cryptography.pqc_backends import _find_native_library\n"
            "def where():\n    return _find_native_library()\n",
        )
        assert "ama_cryptography/innocent.py" not in tool.discover_native_reaching_modules(repo)
