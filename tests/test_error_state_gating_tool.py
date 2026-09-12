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
import subprocess
import sys
import textwrap
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
        # The Cython half is published too (check_documented_counts.py reads
        # both), so it needs the same recomputation: a count that started from
        # anything but zero would drift the documented figure by that much.
        recomputed_cython = sum(tool._count_cy_funcs(REPO_ROOT / rel) for rel in tool.BINDING_PYX)
        assert cython == recomputed_cython


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


# ---------------------------------------------------------------------------
# Contract pinning (audit R1).
#
# Mutation testing at PR #394 measured a 60.9 % kill rate for this file: 90 of
# 230 mutants survived the suite above.  Among them, inverting the comparison
# in ``_is_native_lib_ref`` — the predicate the whole gate rests on — left all
# 21 tests passing AND left the gate exiting 0 on the real tree.  A gate whose
# central predicate can be inverted without a single test noticing is a gate
# that cannot fail, which is the defect class this file exists to prevent.
#
# The classes below pin the contract function by function: what counts as the
# native handle, what counts as binding a native symbol, what counts as a call,
# which lines a docstring scan drops, and — the largest gap — what ``main()``
# returns for each way the audit can fail.  Every assertion states a property
# the gate must have, not merely a value it happens to produce.
# ---------------------------------------------------------------------------


def _expr(source: str) -> ast.expr:
    """The single expression in ``source``, as an AST node."""
    return ast.parse(source, mode="eval").body


def _fn(source: str) -> ast.FunctionDef:
    """The first function definition in ``source``."""
    node = ast.parse(textwrap.dedent(source).lstrip("\n")).body[0]
    assert isinstance(node, ast.FunctionDef)
    return node


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return path


class TestWhatCountsAsTheNativeHandle:
    """``_is_native_lib_ref`` decides whether an expression names the ctypes
    handle.  Every arm of the gate's reach detection funnels through it, so an
    inverted or emptied comparison here silently disarms the whole tool."""

    def test_the_bare_handle_is_the_handle(self, tool: ModuleType) -> None:
        assert tool._is_native_lib_ref(_expr("_native_lib")) is True

    def test_the_handle_on_any_receiver_is_the_handle(self, tool: ModuleType) -> None:
        assert tool._is_native_lib_ref(_expr("self._native_lib")) is True
        assert tool._is_native_lib_ref(_expr("mod.inner._native_lib")) is True

    def test_a_name_that_merely_contains_it_is_not(self, tool: ModuleType) -> None:
        """``_find_native_library`` and ``_native_libs`` are not the handle;
        matching them would make the gate demand guards on functions that reach
        nothing, and a gate that fires on correct code gets bypassed."""
        assert tool._is_native_lib_ref(_expr("_native_library")) is False
        assert tool._is_native_lib_ref(_expr("self._native_libs")) is False
        assert tool._is_native_lib_ref(_expr("lib")) is False

    def test_nothing_else_is_the_handle(self, tool: ModuleType) -> None:
        assert tool._is_native_lib_ref(_expr("'_native_lib'")) is False
        assert tool._is_native_lib_ref(_expr("f(_native_lib)")) is False


class TestWhatCountsAsBindingANativeSymbol:
    """``_binds_native_symbol`` decides whether an assigned expression yields a
    callable that reaches the C kernel.  Each arm below is a shape that, if it
    stopped being recognised, would let a function call into the library
    through a local name while the gate reported it as making no native call —
    and a function that makes no native call is never asked for a guard."""

    def test_a_resolved_symbol_binds(self, tool: ModuleType) -> None:
        assert tool._binds_native_symbol(_expr("getattr(_native_lib, name)")) is True

    def test_a_resolution_from_another_object_does_not(self, tool: ModuleType) -> None:
        assert tool._binds_native_symbol(_expr("getattr(config, name)")) is False

    def test_a_different_function_spelled_similarly_does_not(self, tool: ModuleType) -> None:
        assert tool._binds_native_symbol(_expr("getattr_safe(_native_lib, name)")) is False

    def test_a_resolution_with_no_arguments_does_not(self, tool: ModuleType) -> None:
        assert tool._binds_native_symbol(_expr("getattr()")) is False

    def test_an_ama_attribute_binds(self, tool: ModuleType) -> None:
        assert tool._binds_native_symbol(_expr("_native_lib.ama_kyber_keypair")) is True

    def test_a_non_ama_attribute_does_not(self, tool: ModuleType) -> None:
        """``lib.argtypes`` and ``lib.restype`` configure a signature; they do
        not perform cryptography."""
        assert tool._binds_native_symbol(_expr("_native_lib.restype")) is False

    def test_either_branch_of_a_conditional_binds(self, tool: ModuleType) -> None:
        """The shape ``native_nistp_ecdsa_verify`` has used since 2026-07-28."""
        assert tool._binds_native_symbol(_expr("a.ama_x if raw else plain")) is True
        assert tool._binds_native_symbol(_expr("plain if raw else a.ama_x")) is True

    def test_a_conditional_reaching_nothing_does_not(self, tool: ModuleType) -> None:
        assert tool._binds_native_symbol(_expr("one if raw else two")) is False

    def test_any_operand_of_a_boolean_binds(self, tool: ModuleType) -> None:
        assert tool._binds_native_symbol(_expr("fallback or lib.ama_x")) is True

    def test_a_boolean_reaching_nothing_does_not(self, tool: ModuleType) -> None:
        assert tool._binds_native_symbol(_expr("fallback or other")) is False

    def test_nothing_else_binds(self, tool: ModuleType) -> None:
        assert tool._binds_native_symbol(_expr("wrapper(_native_lib.ama_y)")) is False


class TestWhichLinesCountAsANativeCall:
    """``_native_call_lines`` is the reach half of the gate: no line here means
    no guard is demanded."""

    def test_a_symbol_resolved_and_called_in_one_expression_counts(self, tool: ModuleType) -> None:
        node = _fn("""
            def f(name):
                return getattr(_native_lib, name)(buf)
            """)
        assert tool._native_call_lines(node) == [2]

    def test_a_resolution_lookalike_does_not_count(self, tool: ModuleType) -> None:
        node = _fn("""
            def f(name):
                return getattr_safe(_native_lib, name)(buf)
            """)
        assert tool._native_call_lines(node) == []

    def test_a_resolution_from_another_object_does_not_count(self, tool: ModuleType) -> None:
        node = _fn("""
            def f(name):
                return getattr(config, name)(buf)
            """)
        assert tool._native_call_lines(node) == []

    def test_an_uncalled_resolution_does_not_count(self, tool: ModuleType) -> None:
        """Binding is not calling; only a later call *through* the alias counts."""
        node = _fn("""
            def f(name):
                probe = getattr(_native_lib, name, None)
                return probe is not None
            """)
        assert tool._native_call_lines(node) == []

    def test_a_call_through_an_alias_counts(self, tool: ModuleType) -> None:
        node = _fn("""
            def f(name):
                fn = getattr(_native_lib, name)
                return fn(a, b)
            """)
        assert tool._native_call_lines(node) == [3]

    def test_calls_native_reports_a_boolean(self, tool: ModuleType) -> None:
        assert tool._calls_native(_fn("def f():\n    return _native_lib.ama_x()\n")) is True
        assert tool._calls_native(_fn("def f():\n    return 1\n")) is False


class TestAliasTrackingScansTheWholeBody:
    """A binding that appears after unrelated statements must still be found:
    the alias scan cannot stop at the first thing it does not recognise."""

    def test_an_earlier_plain_assignment_does_not_end_the_scan(self, tool: ModuleType) -> None:
        node = _fn("""
            def f(name):
                size = 32
                fn = getattr(_native_lib, name)
                return fn(size)
            """)
        assert tool._native_handle_aliases(node) == {"fn"}

    def test_an_earlier_non_native_binding_does_not_end_the_scan(self, tool: ModuleType) -> None:
        node = _fn("""
            def f(name):
                helper = getattr(config, name)
                fn = getattr(_native_lib, name)
                return fn(helper)
            """)
        assert tool._native_handle_aliases(node) == {"fn"}

    def test_an_annotated_binding_is_found(self, tool: ModuleType) -> None:
        """``fn: Callable[..., int] = _native_lib.ama_x`` is the same binding
        wearing an annotation."""
        node = _fn("""
            def f():
                fn: Callable[..., int] = _native_lib.ama_x
                return fn(1)
            """)
        assert tool._native_handle_aliases(node) == {"fn"}

    def test_a_bare_annotation_binds_nothing(self, tool: ModuleType) -> None:
        node = _fn("""
            def f():
                fn: Callable[..., int]
                return 0
            """)
        assert tool._native_handle_aliases(node) == set()

    def test_only_native_bindings_become_aliases(self, tool: ModuleType) -> None:
        node = _fn("""
            def f(name):
                helper = getattr(config, name)
                return helper()
            """)
        assert tool._native_handle_aliases(node) == set()


class TestWhichLinesCountAsAGuard:
    """``_guard_call_lines`` is the other half: a guard the gate cannot see is
    a guard the gate will demand again, and a call it wrongly counts as a guard
    is an entry point that ships ungated."""

    def test_the_direct_form_counts(self, tool: ModuleType) -> None:
        node = _fn("def f():\n    check_crypto_permitted()\n    return _native_lib.ama_x()\n")
        assert tool._guard_call_lines(node) == [2]

    def test_the_second_guard_name_counts(self, tool: ModuleType) -> None:
        """``GUARDS`` has two members; both must be honoured, or a module using
        only the second one reports every entry point as ungated."""
        node = _fn("def f():\n    check_operational()\n    return _native_lib.ama_x()\n")
        assert tool._guard_call_lines(node) == [2]

    def test_the_module_qualified_form_counts(self, tool: ModuleType) -> None:
        node = _fn("def f():\n    _state.check_operational()\n    return 1\n")
        assert tool._guard_call_lines(node) == [2]

    def test_an_unrelated_call_is_not_a_guard(self, tool: ModuleType) -> None:
        node = _fn("def f():\n    prepare()\n    return 1\n")
        assert tool._guard_call_lines(node) == []

    def test_a_delegating_helper_counts_only_when_it_is_named(self, tool: ModuleType) -> None:
        node = _fn("def f():\n    lib = _require_native()\n    return lib.ama_x()\n")
        assert tool._guard_call_lines(node, {"_require_native"}) == [2]
        assert tool._guard_call_lines(node, set()) == []

    def test_naming_a_delegating_helper_does_not_bless_every_call(self, tool: ModuleType) -> None:
        """Passing a non-empty ``delegating`` set must not turn unrelated calls
        into guards: the membership test is what decides, not the set's
        truthiness."""
        node = _fn("def f():\n    prepare()\n    return _native_lib.ama_x()\n")
        assert tool._guard_call_lines(node, {"_require_native"}) == []

    def test_calls_guard_reports_a_boolean(self, tool: ModuleType) -> None:
        assert tool._calls_guard(_fn("def f():\n    check_operational()\n")) is True
        assert tool._calls_guard(_fn("def f():\n    return 1\n")) is False


class TestDelegatingHelperDiscoveryScansTheWholeModule:
    def test_an_empty_helper_earlier_does_not_end_the_scan(self, tool: ModuleType) -> None:
        """A function whose body is only a docstring is skipped, not fatal: the
        qualifying helper defined after it must still be found."""
        helpers = _helpers(
            tool,
            'def _placeholder():\n    """Nothing yet."""\n\n'
            "def _require_native():\n    check_crypto_permitted()\n    return _lib\n",
        )
        assert helpers == {"_require_native"}

    def test_a_non_call_first_statement_earlier_does_not_end_the_scan(
        self, tool: ModuleType
    ) -> None:
        helpers = _helpers(
            tool,
            "def _setup():\n    x = 1\n    return x\n\n"
            "def _require_native():\n    check_operational()\n    return _lib\n",
        )
        assert helpers == {"_require_native"}


class TestModuleDiscoveryReach:
    """``_module_reaches_native`` decides which modules the gate must classify.
    A module it fails to see is unaudited by omission — the exact state the
    discovery exists to make impossible."""

    @staticmethod
    def _reaches(tool: ModuleType, source: str) -> bool:
        """The tool's own answer, unwrapped: a helper that coerced it would let
        a detector returning ``None`` read as a clean ``False``."""
        result = tool._module_reaches_native(ast.parse(textwrap.dedent(source)))
        assert isinstance(result, bool), f"expected a bool, got {result!r}"
        return result

    def test_the_bare_handle_reaches(self, tool: ModuleType) -> None:
        assert self._reaches(tool, "def f():\n    return _native_lib\n") is True

    def test_the_handle_as_an_attribute_reaches(self, tool: ModuleType) -> None:
        """``mod._native_lib`` is the form a re-reading module uses; it is not a
        Name node, so it needs its own arm."""
        assert self._reaches(tool, "def f():\n    return backend._native_lib.ama_x()\n") is True

    def test_an_aliased_import_reaches(self, tool: ModuleType) -> None:
        assert self._reaches(tool, "from .pqc_backends import _native_lib as lib\n") is True

    def test_a_cython_binding_call_reaches(self, tool: ModuleType) -> None:
        assert self._reaches(tool, "def f():\n    return _cy_kyber_keypair()\n") is True

    def test_a_two_argument_dynamic_read_reaches(self, tool: ModuleType) -> None:
        """``getattr(mod, "_native_lib")`` has exactly two arguments; requiring
        more would miss it."""
        assert self._reaches(tool, 'def f():\n    return getattr(mod, "_native_lib")\n') is True

    def test_a_module_reaching_nothing_does_not(self, tool: ModuleType) -> None:
        assert self._reaches(tool, "def f():\n    return 1\n") is False


class TestModuleDiscoveryScansTheWholePackage:
    @staticmethod
    def _pkg(tmp_path: Path, files: dict[str, str]) -> Path:
        for rel, text in files.items():
            _write(tmp_path, f"ama_cryptography/{rel}", text)
        return tmp_path

    def test_cached_bytecode_directories_are_skipped(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """A stale copy under ``__pycache__`` is not a module of the package;
        reporting it would demand a classification for a path that cannot be
        imported."""
        repo = self._pkg(
            tmp_path,
            {
                "__pycache__/ghost.py": "def f():\n    return _native_lib.ama_x()\n",
                "real.py": "def f():\n    return _native_lib.ama_y()\n",
            },
        )
        assert tool.discover_native_reaching_modules(repo) == ["ama_cryptography/real.py"]

    def test_a_cached_copy_first_does_not_end_the_scan(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """``__pycache__`` sorts before ordinary module names, so a scan that
        stopped there instead of skipping would find nothing at all."""
        repo = self._pkg(
            tmp_path,
            {
                "__pycache__/ghost.py": "x = 1\n",
                "zz_real.py": "def f():\n    return _native_lib.ama_y()\n",
            },
        )
        assert "ama_cryptography/zz_real.py" in tool.discover_native_reaching_modules(repo)

    def test_an_unparseable_file_does_not_end_the_scan(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """A file the parser rejects is skipped, not fatal: a module defined
        after it alphabetically must still be discovered."""
        repo = self._pkg(
            tmp_path,
            {
                "aaa_broken.py": "def f(:\n",
                "zz_real.py": "def f():\n    return _native_lib.ama_y()\n",
            },
        )
        assert "ama_cryptography/zz_real.py" in tool.discover_native_reaching_modules(repo)


class TestTheAuditScansEveryEntryPoint:
    @staticmethod
    def _audit(
        tool: ModuleType, tmp_path: Path, source: str, exempt: dict[str, str] | None = None
    ) -> tuple[list[tuple[str, int]], list[str], int]:
        path = _write(tmp_path, "mod.py", source)
        ungated, stale, checked = tool.audit(path, exempt if exempt is not None else {})
        return list(ungated), list(stale), int(checked)

    def test_an_exempt_function_does_not_end_the_scan(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """An exemption excuses one function.  If it stopped the walk, every
        entry point defined after it would ship unaudited — the exemption list
        would become a way to silence the gate rather than to document a
        decision."""
        ungated, _stale, checked = self._audit(
            tool,
            tmp_path,
            """
            def excused():
                return _native_lib.ama_a()

            def forgotten():
                return _native_lib.ama_b()
            """,
            exempt={"excused": "emits no cryptographic output"},
        )
        assert [name for name, _line in ungated] == ["forgotten"]
        assert checked == 1

    def test_a_guard_reached_after_the_native_call_is_reported(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """Output has already been produced; the guard raises too late to
        inhibit it.  The reported line is the native call, not the def."""
        ungated, _stale, _checked = self._audit(
            tool,
            tmp_path,
            '''
            def late():
                """Emit first, ask afterwards."""
                out = _native_lib.ama_a()
                check_crypto_permitted()
                return out
            ''',
        )
        # The def is line 1; the native call is line 3.  The gate must name the
        # call, because that is where output escaped.
        assert ungated == [("late", 3)]

    def test_a_guard_before_the_native_call_is_accepted(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        ungated, _stale, checked = self._audit(
            tool,
            tmp_path,
            """
            def early():
                check_crypto_permitted()
                return _native_lib.ama_a()
            """,
        )
        assert ungated == []
        assert checked == 1

    def test_an_exemption_that_matched_is_not_stale(self, tool: ModuleType, tmp_path: Path) -> None:
        _ungated, stale, _checked = self._audit(
            tool,
            tmp_path,
            "def excused():\n    return _native_lib.ama_a()\n",
            exempt={"excused": "reason"},
        )
        assert stale == []

    def test_an_exemption_that_matched_nothing_is_stale(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """Dead weight that would silently cover a future function of the same
        name."""
        _ungated, stale, _checked = self._audit(
            tool,
            tmp_path,
            "def present():\n    check_operational()\n    return _native_lib.ama_a()\n",
            exempt={"vanished": "reason"},
        )
        assert stale == ["vanished"]


class TestTheCythonBindingScan:
    @staticmethod
    def _pyx(tool: ModuleType, tmp_path: Path, source: str) -> list[tuple[str, int]]:
        path = _write(tmp_path, "binding.pyx", source)
        return list(tool.audit_pyx(path))

    def test_two_guarded_functions_are_both_accepted(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """Each function's body must be delimited by the *next* def.  A window
        that ran backwards would leave every body empty and report every
        correctly guarded binding as ungated."""
        assert (
            self._pyx(
                tool,
                tmp_path,
                """
                def cy_one(buf):
                    check_crypto_permitted()
                    return ama_one(buf)

                def cy_two(buf):
                    check_crypto_permitted()
                    return ama_two(buf)
                """,
            )
            == []
        )

    def test_one_functions_guard_cannot_cover_the_next(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """A window that overran into the following def would find that
        function's guard and clear an unguarded binding."""
        assert (
            self._pyx(
                tool,
                tmp_path,
                """
            def cy_one(buf):
                pass

            def cy_two(buf):
                check_crypto_permitted()
                return ama_two(buf)
            """,
            )
            == [("cy_one", 1)]
        )

    def test_the_reported_line_is_the_def(self, tool: ModuleType, tmp_path: Path) -> None:
        assert (
            self._pyx(
                tool,
                tmp_path,
                """
            # a leading comment

            def cy_late(buf):
                return ama_late(buf)
            """,
            )
            == [("cy_late", 3)]
        )

    def test_a_guard_with_no_native_call_is_accepted(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """The ordering check must tolerate a body with no native call at all,
        rather than comparing a missing position against a real one."""
        assert (
            self._pyx(
                tool,
                tmp_path,
                """
                def cy_probe(buf):
                    check_crypto_permitted()
                    return len(buf)
                """,
            )
            == []
        )

    def test_a_guard_after_the_native_call_is_reported(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        assert (
            self._pyx(
                tool,
                tmp_path,
                """
            def cy_late(buf):
                out = ama_late(buf)
                check_crypto_permitted()
                return out
            """,
            )
            == [("cy_late", 1)]
        )

    def test_a_commented_out_guard_does_not_satisfy_the_check(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        assert (
            self._pyx(
                tool,
                tmp_path,
                """
            def cy_one(buf):
                # check_crypto_permitted()
                return ama_one(buf)
            """,
            )
            == [("cy_one", 1)]
        )

    def test_an_ordinary_call_is_not_a_guard(self, tool: ModuleType, tmp_path: Path) -> None:
        """The guard pattern must name the guards.  An alternation that also
        matched the empty string would accept any ``()`` in the body."""
        assert (
            self._pyx(
                tool,
                tmp_path,
                """
            def cy_one(buf):
                prepare()
                return ama_one(buf)
            """,
            )
            == [("cy_one", 1)]
        )

    def test_a_docstring_mentioning_a_native_symbol_is_not_a_call(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        assert (
            self._pyx(
                tool,
                tmp_path,
                '''
                def cy_one(buf):
                    """Wraps ama_one(buf) from the C kernel."""
                    check_crypto_permitted()
                    return ama_one(buf)
                ''',
            )
            == []
        )

    def test_counting_binding_entry_points(self, tool: ModuleType, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            "binding.pyx",
            """
            def cy_one(buf):
                pass

            def helper(buf):
                pass

            def cy_two(buf):
                pass

            def cy_three(buf):
                pass
            """,
        )
        assert tool._count_cy_funcs(path) == 3


class TestTheDocstringStripper:
    """``_strip_leading_docstring`` exists so a binding's prose — which names
    the ``ama_*`` symbols it wraps — is not read as a native call site.  Drop
    too little and every documented binding looks like it calls native before
    guarding; drop too much and real call sites disappear from the scan."""

    def test_a_body_with_no_docstring_is_returned_whole(self, tool: ModuleType) -> None:
        assert tool._strip_leading_docstring(["    return ama_x()"]) == ["    return ama_x()"]

    def test_leading_blank_lines_are_skipped_one_at_a_time(self, tool: ModuleType) -> None:
        assert tool._strip_leading_docstring(["", "    code()"]) == ["    code()"]
        assert tool._strip_leading_docstring(["", "", "    code()"]) == ["    code()"]

    def test_a_code_line_is_never_mistaken_for_a_docstring(self, tool: ModuleType) -> None:
        """Only the two triple-quote forms open a docstring.  A rule that
        matched the empty prefix would swallow the first line of every body."""
        assert tool._strip_leading_docstring(["    return ama_x()"]) == ["    return ama_x()"]
        assert tool._strip_leading_docstring(["    guard()"]) == ["    guard()"]

    def test_a_single_line_docstring_drops_exactly_itself(self, tool: ModuleType) -> None:
        """The rest of the body — including a later line that happens to hold
        triple quotes — must survive."""
        body = ['    """Wraps ama_x."""', "    guard()", '    s = """later"""']
        assert tool._strip_leading_docstring(body) == ["    guard()", '    s = """later"""']

    def test_an_empty_single_line_docstring_drops_exactly_itself(self, tool: ModuleType) -> None:
        """``\"\"\"\"\"\"`` is six characters: the shortest single-line docstring
        there is, and the boundary of the length rule."""
        body = ['    """"""', "    guard()", '    s = """later"""']
        assert tool._strip_leading_docstring(body) == ["    guard()", '    s = """later"""']

    def test_a_bare_opening_quote_is_not_a_single_line_docstring(self, tool: ModuleType) -> None:
        """``\"\"\"`` alone opens a multi-line docstring; treating it as closed
        would leave the prose in the scanned body."""
        body = ['    """', "    Wraps ama_x.", '    """', "    guard()"]
        assert tool._strip_leading_docstring(body) == ["    guard()"]

    def test_an_opening_line_long_enough_to_look_closed_is_not_closed(
        self, tool: ModuleType
    ) -> None:
        """A docstring's first line can be six characters or more and still not
        end the docstring — ``\"\"\"doc`` is the common shape.  All three parts
        of the single-line rule have to hold together: length ALONE deciding it
        would drop only the opening line and leave the prose in the scanned
        body, where its ``ama_*`` mentions read as native call sites."""
        body = ['    """doc', "    Wraps ama_x.", '    """', "    guard()"]
        assert tool._strip_leading_docstring(body) == ["    guard()"]

    def test_a_multi_line_docstring_closing_immediately_is_handled(self, tool: ModuleType) -> None:
        body = ['    """', '    """', "    guard()"]
        assert tool._strip_leading_docstring(body) == ["    guard()"]

    def test_the_single_quote_form_is_handled(self, tool: ModuleType) -> None:
        body = ["    '''Wraps ama_x.'''", "    guard()"]
        assert tool._strip_leading_docstring(body) == ["    guard()"]

    def test_a_docstring_after_a_blank_line_drops_exactly_itself(self, tool: ModuleType) -> None:
        body = ["", '    """Wraps ama_x."""', "    guard()"]
        assert tool._strip_leading_docstring(body) == ["    guard()"]

    def test_an_unterminated_docstring_drops_only_its_opening_line(self, tool: ModuleType) -> None:
        """Malformed input must still leave the rest of the body visible to the
        scan rather than hiding it."""
        body = ["", '    """', "    guard()"]
        assert tool._strip_leading_docstring(body) == ["    guard()"]

    def test_an_all_blank_body_is_returned_empty(self, tool: ModuleType) -> None:
        assert tool._strip_leading_docstring(["", ""]) == []

    def test_an_empty_body_is_returned_empty(self, tool: ModuleType) -> None:
        assert tool._strip_leading_docstring([]) == []


GATED_MODULE = """
def encrypt(buf):
    check_crypto_permitted()
    return _native_lib.ama_encrypt(buf)
"""

GATED_BINDING = """
def cy_encrypt(buf):
    check_crypto_permitted()
    return ama_encrypt(buf)

def cy_decrypt(buf):
    check_crypto_permitted()
    return ama_decrypt(buf)
"""


class TestTheExitCodeContract:
    """``main()`` is what CI runs, and its return value is the whole signal.
    Until this class the suite exercised the audit helpers and never once
    called ``main()``: every one of its failure paths could have returned 0
    with no test noticing, which would have made the CI step decorative.

    Each test drives one failure path over a synthetic repository and asserts
    the exact exit code, so a path that stops failing is a test failure.
    """

    @pytest.fixture
    def repo(self, tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        """A minimal, internally consistent tree the gate reports clean."""
        (tmp_path / "ama_cryptography").mkdir()
        _write(tmp_path, "ama_cryptography/backend.py", GATED_MODULE)
        _write(tmp_path, "src/cython/binding.pyx", GATED_BINDING)
        monkeypatch.setattr(tool, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(tool, "MODULES", ("ama_cryptography/backend.py",))
        monkeypatch.setattr(tool, "BINDING_PYX", ("src/cython/binding.pyx",))
        monkeypatch.setattr(tool, "EXEMPT", {})
        monkeypatch.setattr(tool, "EXEMPT_MODULES", {})
        return tmp_path

    def test_a_consistent_tree_passes_and_reports_the_exact_counts(
        self, tool: ModuleType, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert tool.main() == 0
        out = capsys.readouterr().out
        assert "all 1 public native entry points" in out
        assert "2 Cython binding entry points" in out

    def test_a_missing_module_is_an_error(
        self, tool: ModuleType, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A module that vanished must fail loudly.  Reporting a smaller count
        would let a deleted file quietly shrink the audited surface."""
        monkeypatch.setattr(tool, "MODULES", ("ama_cryptography/gone.py",))
        assert tool.main() == 1

    def test_a_missing_binding_is_an_error(
        self, tool: ModuleType, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tool, "BINDING_PYX", ("src/cython/gone.pyx",))
        assert tool.main() == 1

    def test_an_exemption_for_a_function_that_reaches_nothing_is_an_error(
        self, tool: ModuleType, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An exemption is justified only by the reach it excuses.  One that
        covers a function making no native call is dead weight that would
        silently cover a future function of the same name — so an exemption
        counts as matched only when the function it names actually reaches the
        library, not merely because the name appears in both places."""
        _write(
            repo,
            "ama_cryptography/backend.py",
            GATED_MODULE + "\ndef describe():\n    return 'metadata only'\n",
        )
        monkeypatch.setattr(tool, "EXEMPT", {"describe": "emits no cryptographic output"})
        assert tool.main() == 1

    def test_an_exemption_that_matches_a_reaching_function_is_accepted(
        self, tool: ModuleType, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write(
            repo,
            "ama_cryptography/backend.py",
            GATED_MODULE + "\ndef version():\n    return _native_lib.ama_version()\n",
        )
        monkeypatch.setattr(tool, "EXEMPT", {"version": "returns a build string"})
        assert tool.main() == 0

    def test_a_native_reaching_module_in_neither_list_is_an_error(
        self, tool: ModuleType, repo: Path
    ) -> None:
        """Unaudited by omission is the state the discovery exists to prevent."""
        _write(
            repo,
            "ama_cryptography/newcomer.py",
            "def sign(buf):\n    return _native_lib.ama_sign(buf)\n",
        )
        assert tool.main() == 1

    def test_a_module_exemption_that_no_longer_reaches_is_an_error(
        self, tool: ModuleType, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            tool, "EXEMPT_MODULES", {"ama_cryptography/departed.py": "was pure Python"}
        )
        assert tool.main() == 1

    def test_an_ungated_python_entry_point_is_an_error(self, tool: ModuleType, repo: Path) -> None:
        _write(
            repo,
            "ama_cryptography/backend.py",
            "def encrypt(buf):\n    return _native_lib.ama_encrypt(buf)\n",
        )
        assert tool.main() == 1

    def test_an_ungated_cython_binding_alone_is_an_error(
        self, tool: ModuleType, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The Python half being clean must not excuse the Cython half: the two
        inventories are reported together, and either one failing fails the
        gate."""
        _write(
            repo, "src/cython/binding.pyx", "def cy_encrypt(buf):\n    return ama_encrypt(buf)\n"
        )
        assert tool.main() == 1
        assert "1 public entry point(s)" in capsys.readouterr().err

    def test_the_error_counts_both_halves(
        self, tool: ModuleType, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _write(
            repo,
            "ama_cryptography/backend.py",
            "def encrypt(buf):\n    return _native_lib.ama_encrypt(buf)\n",
        )
        _write(
            repo, "src/cython/binding.pyx", "def cy_encrypt(buf):\n    return ama_encrypt(buf)\n"
        )
        assert tool.main() == 1
        assert "2 public entry point(s)" in capsys.readouterr().err


class TestTheGateRunsAsCiRunsIt:
    def test_invoking_the_script_audits_the_real_tree(self) -> None:
        """CI runs ``python tools/check_error_state_gating.py``.  If the script
        entry point stopped dispatching to ``main()`` the process would exit 0
        having audited nothing, and the CI step would pass by doing no work."""
        result = subprocess.run(
            [sys.executable, str(TOOL_PATH)],
            capture_output=True,
            text=True,
            check=False,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.startswith("OK: all "), result.stdout
        assert "Cython binding entry points" in result.stdout
