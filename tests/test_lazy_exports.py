# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Hold the package's three export declarations to each other.

Why
---
``ama_cryptography/__init__.py`` states its public surface three times:

1. ``_CRYPTO_API_EXPORTS`` / ``_KEY_FORMAT_EXPORTS`` — the names ``__getattr__``
   will resolve lazily, and the module each is resolved from.
2. the ``if TYPE_CHECKING:`` block — the same names, bound statically so that
   mypy, IDEs, and static analysers can see them.
3. ``__all__`` — what ``from ama_cryptography import *`` and the documentation
   promise exists.

Nothing made those three agree, and they did not. The ``TYPE_CHECKING`` block
covered 13 of 31 lazily-exported names, so eighteen public names were typed
``Any`` at every call site — not a warning, an absence: mypy cannot check a call
it cannot resolve, so the checking silently did not happen. ``KeyFormatError``
was worse than uncovered: it was declared in the *key-format* set but resolved
from ``ama_cryptography.exceptions``, a module imported eagerly a hundred lines
earlier, so the lazy entry was dead weight pointing at the wrong place.

``tests/test_lazy_imports.py`` already checks the runtime half — every name in
``__all__`` resolves, unknown names raise. That is necessary and not sufficient:
``__getattr__`` answers at runtime whatever the sets contain, so a name can
resolve perfectly and still be invisible to every tool that does not execute the
module. This file checks the static half, and checks that the static and runtime
halves name the same module.

How
---
The declarations are read out of the source with ``ast`` rather than from the
imported module, because the property under test is what a *reader* — human or
analyser — can see without running anything. Importing the package and asking it
what it exports would consult ``__getattr__`` and agree with itself by
construction.
"""

from __future__ import annotations

import ast
import importlib
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

PACKAGE_INIT = Path(__file__).resolve().parent.parent / "ama_cryptography" / "__init__.py"

#: Lazy-export set name -> the module ``__getattr__`` resolves those names from.
#:
#: The correspondence is the point, not an incidental detail: a name listed in
#: ``_KEY_FORMAT_EXPORTS`` that does not actually live in ``key_formats`` is a
#: defect, whether or not it happens to resolve.
LAZY_SETS = {
    "_CRYPTO_API_EXPORTS": "ama_cryptography.crypto_api",
    "_KEY_FORMAT_EXPORTS": "ama_cryptography.key_formats",
}

_TREE = ast.parse(PACKAGE_INIT.read_text(encoding="utf-8"), filename=str(PACKAGE_INIT))


def _is_type_checking_guard(test: ast.expr) -> bool:
    """``if TYPE_CHECKING:`` or ``if typing.TYPE_CHECKING:``."""
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    return isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"


def _absolute_module(node: ast.ImportFrom) -> str:
    """Resolve ``from .key_formats import x`` to ``ama_cryptography.key_formats``."""
    if node.level == 0:
        return node.module or ""
    # Only level 1 occurs here, and only ever relative to the package root.
    return f"ama_cryptography.{node.module}" if node.module else "ama_cryptography"


def _lazy_sets() -> dict[str, frozenset[str]]:
    """The ``frozenset({...})`` literals assigned at module level."""
    found: dict[str, frozenset[str]] = {}
    for node in _TREE.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or not target.id.endswith("_EXPORTS"):
            continue
        call = node.value
        assert isinstance(call, ast.Call), f"{target.id} is not a frozenset(...) call"
        found[target.id] = frozenset(ast.literal_eval(call.args[0]))
    return found


def _type_checking_bindings() -> dict[str, str]:
    """Name -> source module, for imports under ``if TYPE_CHECKING:``."""
    bindings: dict[str, str] = {}
    for node in _TREE.body:
        if not isinstance(node, ast.If) or not _is_type_checking_guard(node.test):
            continue
        for stmt in node.body:
            if isinstance(stmt, ast.ImportFrom):
                module = _absolute_module(stmt)
                for alias in stmt.names:
                    bindings[alias.asname or alias.name] = module
    return bindings


def _names_bound_by(node: ast.stmt) -> set[str]:
    """Names a single non-compound statement binds in its enclosing scope."""
    if isinstance(node, ast.Import):
        return {alias.asname or alias.name.split(".")[0] for alias in node.names}
    if isinstance(node, ast.ImportFrom):
        return {alias.asname or alias.name for alias in node.names}
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    if isinstance(node, ast.Assign):
        return {t.id for t in node.targets if isinstance(t, ast.Name)}
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return {node.target.id}
    return set()


def _nested_bodies(node: ast.stmt) -> list[list[ast.stmt]]:
    """The sub-bodies of a compound statement that still run at module level.

    The body of ``if TYPE_CHECKING:`` is deliberately excluded — that is the
    branch whose names exist only for the type checker.
    """
    if isinstance(node, ast.If):
        if _is_type_checking_guard(node.test):
            return [node.orelse]
        return [node.body, node.orelse]
    if isinstance(node, ast.Try):
        return [node.body, node.orelse, node.finalbody, *(h.body for h in node.handlers)]
    return []


def _eager_bindings() -> set[str]:
    """Names bound at module level *outside* the ``TYPE_CHECKING`` guard.

    These are the names a plain import really produces, and the ones a static
    analyser counts as definitions without having to trust a guard.
    """
    bound: set[str] = set()
    pending: list[list[ast.stmt]] = [_TREE.body]
    while pending:
        for node in pending.pop():
            bound |= _names_bound_by(node)
            pending.extend(_nested_bodies(node))
    return bound


def _declared_all() -> list[str]:
    for node in _TREE.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets
        ):
            return list(ast.literal_eval(node.value))
    raise AssertionError("__init__.py defines no __all__")


LAZY_BY_SET = _lazy_sets()
TYPE_CHECKING_BINDINGS = _type_checking_bindings()
EAGER_BINDINGS = _eager_bindings()
DECLARED_ALL = _declared_all()
#: Every lazily exported name, mapped to the module it is resolved from.
ALL_LAZY = {
    name: module for set_name, module in LAZY_SETS.items() for name in LAZY_BY_SET[set_name]
}


def test_the_known_lazy_sets_are_the_only_ones() -> None:
    """A third lazy set added without updating this file would go unchecked."""
    assert set(LAZY_BY_SET) == set(LAZY_SETS), (
        "the lazy-export sets in __init__.py no longer match the ones this test "
        "knows how to check; add the new set (and its source module) to LAZY_SETS"
    )


def test_the_declarations_are_not_vacuous() -> None:
    """Guard the extractors: an AST walk that silently finds nothing passes."""
    assert ALL_LAZY, "no lazy exports extracted"
    assert TYPE_CHECKING_BINDINGS, "no TYPE_CHECKING bindings extracted"
    assert DECLARED_ALL, "no __all__ entries extracted"


@pytest.mark.parametrize("name", sorted(ALL_LAZY))
def test_every_lazy_export_is_statically_bound(name: str) -> None:
    """The condition CodeQL's ``py/undefined-export`` checks, and mypy needs.

    Without this binding the name exists only inside ``__getattr__``, where no
    tool that does not execute the module can see it — so it is typed ``Any``
    and every call through it goes unchecked.
    """
    assert name in TYPE_CHECKING_BINDINGS, (
        f"{name!r} is exported lazily but is not bound in the `if TYPE_CHECKING:` "
        f"block, so static analysis cannot see it"
    )


@pytest.mark.parametrize("name", sorted(ALL_LAZY))
def test_the_static_and_runtime_views_name_the_same_module(name: str) -> None:
    """The static import must come from the module ``__getattr__`` will use.

    ``KeyFormatError`` was declared among the key-format exports and resolved
    from ``ama_cryptography.exceptions``; it worked, and it was wrong.
    """
    assert TYPE_CHECKING_BINDINGS[name] == ALL_LAZY[name], (
        f"{name!r} is declared to come from {ALL_LAZY[name]} but is imported "
        f"from {TYPE_CHECKING_BINDINGS[name]} under TYPE_CHECKING"
    )


@pytest.mark.parametrize("name", sorted(ALL_LAZY))
def test_a_lazy_export_is_not_also_eagerly_imported(name: str) -> None:
    """An eagerly bound name never reaches ``__getattr__``.

    Its entry in the lazy set is then dead, and — worse — misleading about where
    the name comes from.
    """
    assert name not in EAGER_BINDINGS, (
        f"{name!r} is bound eagerly at module level, so its entry in the lazy "
        f"export set is unreachable; drop it from the set"
    )


@pytest.mark.parametrize("name", sorted(ALL_LAZY))
def test_every_lazy_export_is_declared_in_all(name: str) -> None:
    """A lazily resolvable name absent from ``__all__`` is an undeclared export."""
    assert name in DECLARED_ALL, f"{name!r} is lazily exported but missing from __all__"


@pytest.mark.parametrize("name", sorted(set(DECLARED_ALL)))
def test_every_declared_export_is_resolvable_statically(name: str) -> None:
    """Every ``__all__`` entry is defined by something a reader can point at."""
    assert name in EAGER_BINDINGS or name in TYPE_CHECKING_BINDINGS, (
        f"__all__ promises {name!r} but nothing in __init__.py defines it "
        f"statically; either bind it or remove the promise"
    )


def test_all_has_no_duplicates() -> None:
    duplicates = sorted({n for n in DECLARED_ALL if DECLARED_ALL.count(n) > 1})
    assert not duplicates, f"__all__ lists {duplicates} more than once"


@pytest.mark.parametrize("name", sorted(ALL_LAZY))
def test_the_lazy_name_resolves_to_the_declared_module_object(name: str) -> None:
    """Runtime agreement: the object served is the one the declaration promises.

    Static bindings that disagree with what ``__getattr__`` actually returns
    would type-check against the wrong object, which is worse than not
    type-checking at all.
    """
    package = importlib.import_module("ama_cryptography")
    source = importlib.import_module(ALL_LAZY[name])
    assert getattr(package, name) is getattr(source, name)


def test_importing_the_package_does_not_import_the_lazy_modules() -> None:
    """The reason the indirection exists at all.

    ``crypto_api`` and ``key_formats`` pull in the native backend and its
    availability checks. If either is imported eagerly the laziness is gone and
    only this test would notice — the API keeps working, just slower and
    noisier for every caller who never touches a key file.
    """
    probe = textwrap.dedent(f"""
        import sys
        import ama_cryptography
        eager = sorted(m for m in {sorted(set(LAZY_SETS.values()))!r} if m in sys.modules)
        print(";".join(eager))
        """)
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, f"probe failed:\n{result.stdout}\n{result.stderr}"
    eager = [m for m in result.stdout.strip().split(";") if m]
    assert not eager, f"`import ama_cryptography` eagerly imported {eager}"


def test_an_unknown_attribute_still_raises() -> None:
    """The lazy sets must not have become a catch-all."""
    package = importlib.import_module("ama_cryptography")
    with pytest.raises(AttributeError, match="no attribute"):
        _ = package.definitely_not_an_export
