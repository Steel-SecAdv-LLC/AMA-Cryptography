#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""No import binding is created twice where the second is dead code.

CodeQL filed its ``py/repeated-import`` Note twice against
``ama_cryptography/monitoring.py`` (alerts #750/#751, 2026-10-05): ``import
importlib`` at module top and again inside two methods.  A sweep by the same
rule found 26 such sites across the tree; every one was a pure redundancy and
was deleted.  CodeQL's Note severity does not block CI, so without this test
the class could accumulate again unseen.

The gate's final scope (hardened across the review rounds, each refinement
mutation-pinned): comparisons are keyed on the ``(module, asname)`` BINDING
an import creates, the way the upstream query compares statements — so a
verbatim repeated alias (``import os as _os`` twice) is in scope, while a
plain local ``import os`` beside an aliased top-level import creates a
different binding and is load-bearing (measured: deleting it raises
NameError).  Two documented deliberate supersets go beyond the upstream
query: verbatim repeated dotted imports, and same-list repeats inside one
function or block (the upstream rule requires the original import to be
module-scoped).  Two measured exemptions: a module-level import guarded by
``try``/``if`` is a deliberate late-binding seam (this tree carries the
pattern at ``crypto_api.py``'s ``import fcntl`` and CodeQL has never filed
against it), and a class-suite import binds a class attribute that deleting
the statement would remove.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Callable, cast

import pytest

from tools._repo import tracked_names

REPO_ROOT = Path(__file__).resolve().parent.parent


def duplicate_plain_imports(source: str) -> list[tuple[int, str]]:
    """``(lineno, module)`` for each re-import in CodeQL's class.

    Keyed by the BINDING an import creates — the ``(module, asname)`` pair —
    which is how ``py/repeated-import`` itself compares statements (review
    finding, 2026-10-06; the first form of this gate skipped aliased imports
    on both sides, which exempted a verbatim repeated ``import os as _os``
    CodeQL reports).  Three shapes: a statement repeating a binding directly
    at module top level; a nested ``import`` repeating a binding the top
    level already creates; and a repeat among the direct statements of any
    one block (function, class, ``try``, ``if``, loop and ``with`` suites
    alike) — the last a deliberate superset of the upstream query, whose
    ``py/repeated-import`` requires the ORIGINAL import to be
    module-scoped, while a verbatim same-list repeat inside one function
    or block is equally dead code and is refused here on the same terms
    as the dotted superset below.  Keying by binding preserves the load-bearing exemption by
    construction: ``import os as _os`` binds ``_os``, so a local plain
    ``import os`` beside it creates a different binding and is never
    flagged — measured, deleting it raises NameError.  Two deliberate edges:
    a module-level import guarded by ``try``/``if`` is conditional, never
    counted as the earlier binding; and an ``import`` in a CLASS suite binds
    a class attribute, not a scope-visible name, so it is exempt from the
    cross-scope shape (deleting it would delete the attribute) while
    same-suite repeats inside one class body still count.  Verbatim repeats
    of a dotted ``import a.b`` are refused too — a deliberate superset of
    CodeQL's ``is_simple_import`` scope, safe because only the identical
    ``(module, asname)`` pair matches (``import a.b`` beside ``import a.c``
    binds ``a`` twice but imports different submodules, and never matches).
    """
    tree = ast.parse(source)
    top_ids = set(map(id, tree.body))
    found: set[tuple[int, str]] = set()
    top_seen = _scan_direct_imports(tree.body, found)
    class_scoped = _class_suite_import_ids(tree)
    shadowed = _shadowed_nested_import_bindings(tree)
    for walked in ast.walk(tree):
        # Same-list repeats are flagged in EVERY statement list the module
        # holds — function, class, try, if, loop and with bodies alike: a
        # pair inside one ``try`` body is as much a repeat as a pair at top
        # level, and scanning only function/class bodies left that corner of
        # the class open (found in review, 2026-10-06).  Scanning each list
        # independently keeps the guarded-import semantics: a ``try``-guarded
        # module-level import still never joins ``top_seen``, so a later
        # retry of it is still not counted.
        for field in ("body", "orelse", "finalbody"):
            block = getattr(walked, field, None)
            if isinstance(block, list) and block is not tree.body:
                _scan_direct_imports(block, found)
        if id(walked) in top_ids or not isinstance(walked, ast.Import):
            continue
        if id(walked) in class_scoped:
            continue
        for alias in walked.names:
            bound = alias.asname or alias.name.split(".")[0]
            if (id(walked), bound) in shadowed:
                # Third measured exemption (review finding, 2026-10-07):
                # binding equality against the top level does not prove a
                # nested import redundant when a STRICTLY ENCLOSING function
                # scope binds the same name — deleting the import would make
                # the name resolve to that enclosing binding, not the module
                # (measured: with a module-level ``import os``, an outer
                # ``os = 1`` and an inner ``import os``, deleting the inner
                # import raises AttributeError on ``os.sep``).  Class bodies
                # between the scopes do not exempt: Python's name resolution
                # skips class scope from nested functions, so the module
                # binding is what deletion exposes there.
                continue
            if (alias.name, alias.asname) in top_seen:
                found.add((walked.lineno, alias.name))
    return sorted(found)


def _scan_direct_imports(
    body: list[ast.stmt], found: set[tuple[int, str]]
) -> set[tuple[str, str | None]]:
    """Flag repeats among one statement list's import bindings; return the
    ``(module, asname)`` pairs the list binds."""
    seen: set[tuple[str, str | None]] = set()
    for stmt in body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                key = (alias.name, alias.asname)
                if key in seen:
                    found.add((stmt.lineno, alias.name))
                seen.add(key)
    return seen


def _function_bound_names(fn: ast.AST, include_imports: bool = True) -> set[str]:
    """Names a function's OWN scope binds: parameters plus body bindings.

    The walk stops at nested function and class bodies — their internal
    bindings live in their own scopes — while the nested statement's NAME
    itself binds here.  Comprehension targets are over-collected (they have
    their own scope since Python 3), which can only widen the shadowing
    exemption below; the exemption is the safe direction, since the
    alternative forces a behavior-changing deletion.  A walrus inside a
    nested function's decorator or default (which evaluates in this scope)
    is the one binding the stop skips — vanishingly rare, and missing it
    only leaves a flag standing for a human to judge.
    ``include_imports=False`` drops the bindings import statements create,
    for the own-scope question below (where the import under test must not
    exempt itself).
    """
    out: set[str] = set()
    args = getattr(fn, "args", None)
    if args is not None:
        params = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
        params += [a for a in (args.vararg, args.kwarg) if a is not None]
        out.update(a.arg for a in params)
    body = getattr(fn, "body", [])
    # A Lambda's body is a single expression, not a statement list.
    stack: list[ast.AST] = list(body) if isinstance(body, list) else [body]
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
            continue
        if isinstance(node, ast.Lambda):
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            out.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            out.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            out.add(node.name)
        elif isinstance(node, ast.Import) and include_imports:
            for alias in node.names:
                out.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and include_imports:
            for alias in node.names:
                out.add(alias.asname or alias.name)
        stack.extend(ast.iter_child_nodes(node))
    return out


def _shadowed_nested_import_bindings(tree: ast.Module) -> set[tuple[int, str]]:
    """``(id(Import node), bound name)`` pairs another binding shadows.

    Two shadowing shapes make a binding-keyed nested import load-bearing
    despite matching a top-level binding, because deleting it would resolve
    the name somewhere other than the module import the key matched:

    * a STRICTLY ENCLOSING function scope binds the name (parameter,
      assignment, any binding construct — an enclosing ``import`` counts
      too, since ``import foo as os`` binds a different module under the
      same name);
    * the import's OWN scope binds the name by a non-import construct
      (``os = 1`` anywhere in the function makes ``os`` function-local
      throughout, so without the import the use site hits that assignment
      or UnboundLocalError, never the module import).  Import-created
      bindings are excluded from the own-scope set so the import under
      test cannot exempt itself and a genuine same-scope re-import stays
      flagged.

    Class bodies pass the enclosing set through unchanged — nested
    functions skip class scope in name resolution, so a class-body binding
    exposes nothing on deletion.  Module scope contributes nothing: its
    bindings are the ``top_seen`` baseline the comparison is against.
    """
    out: set[tuple[int, str]] = set()

    def collect(scope_node: ast.AST, enclosing: frozenset[str]) -> None:
        if isinstance(scope_node, ast.Module):
            own_all: frozenset[str] = frozenset()
            exempt: frozenset[str] = frozenset()
        else:
            own_all = frozenset(_function_bound_names(scope_node))
            exempt = enclosing | frozenset(_function_bound_names(scope_node, include_imports=False))
        stack: list[ast.AST] = list(ast.iter_child_nodes(scope_node))
        while stack:
            child = stack.pop()
            if isinstance(child, ast.Import):
                for alias in child.names:
                    bound = alias.asname or alias.name.split(".")[0]
                    if bound in exempt:
                        out.add((id(child), bound))
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                collect(child, enclosing | own_all)
            else:
                stack.extend(ast.iter_child_nodes(child))

    collect(tree, frozenset())
    return out


def _class_suite_import_ids(tree: ast.Module) -> set[int]:
    """ids of ``Import`` nodes whose nearest enclosing scope is a class suite.

    A class-body ``import os`` after a top-level ``import os`` is NOT
    redundant: it binds the class attribute ``C.os``, which deleting the
    statement removes.  Nested function bodies open their own scope again,
    so the walk stops at them."""
    out: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        stack: list[ast.AST] = list(node.body)
        while stack:
            item = stack.pop()
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(item, ast.Import):
                out.add(id(item))
            stack.extend(ast.iter_child_nodes(item))
    return out


def test_a_planted_nested_duplicate_is_found() -> None:
    source = "import os\n\n\ndef f() -> str:\n    import os\n\n    return os.sep\n"
    assert duplicate_plain_imports(source) == [(5, "os")]


def test_a_second_top_level_import_is_found() -> None:
    """CodeQL's canonical example: the same module twice at top level."""
    source = "import os\nimport sys\nimport os\n\nprint(os.sep, sys.path)\n"
    assert duplicate_plain_imports(source) == [(3, "os")]


def test_a_same_scope_duplicate_is_found() -> None:
    source = "def f() -> str:\n    import os\n    import os\n\n    return os.sep\n"
    assert duplicate_plain_imports(source) == [(3, "os")]


def test_an_aliased_or_from_import_is_not_in_scope() -> None:
    source = (
        "import os\nimport ast\n\n\ndef f() -> str:\n"
        "    import os as _os\n    from ast import parse\n\n"
        "    return _os.sep + str(parse('1'))\n"
    )
    assert duplicate_plain_imports(source) == []


def test_a_plain_local_beside_an_aliased_top_import_is_load_bearing() -> None:
    """``import os as _os`` does not bind ``os``: the local import is the only
    binding the function has, and deleting it raises NameError — measured.
    The checker must not pressure that deletion."""
    source = "import os as _os\n\n\ndef f() -> str:\n    import os\n\n    return os.sep\n"
    assert duplicate_plain_imports(source) == []


def test_a_guarded_top_import_with_a_local_retry_is_not_counted() -> None:
    source = (
        "try:\n    import fcntl\nexcept ImportError:\n    fcntl = None\n\n\n"
        "def f() -> object:\n    import fcntl\n\n    return fcntl\n"
    )
    assert duplicate_plain_imports(source) == []


def test_a_repeated_identical_alias_is_found() -> None:
    """CodeQL keys on the bound alias: ``import os as _os`` twice repeats
    the ``_os`` binding and is in the class, same scope or across scopes."""
    source = "import os as _os\nimport os as _os\n\nprint(_os.sep)\n"
    assert duplicate_plain_imports(source) == [(2, "os")]
    source = (
        "import os as _os\n\n\ndef f() -> str:\n    import os as _os\n\n" "    return _os.sep\n"
    )
    assert duplicate_plain_imports(source) == [(5, "os")]


def test_a_class_suite_import_is_a_binding_not_a_duplicate() -> None:
    """``class C: import os`` binds ``C.os``; deleting it removes the
    attribute, so the cross-scope shape must not flag it — while a repeat
    inside the same class suite is still a repeat."""
    source = "import os\n\n\nclass C:\n    import os\n"
    assert duplicate_plain_imports(source) == []
    source = "class C:\n    import os\n    import os\n"
    assert duplicate_plain_imports(source) == [(3, "os")]


def test_a_same_block_duplicate_inside_try_or_if_is_found() -> None:
    source = (
        "try:\n    import os\n    import os\nexcept ImportError:\n    pass\n\n"
        "if True:\n    import sys\n    import sys\n"
    )
    assert duplicate_plain_imports(source) == [(3, "os"), (9, "sys")]


def test_a_shadowed_nested_import_is_load_bearing() -> None:
    """PIN (review finding, 2026-10-07): binding equality against the top
    level does not prove a nested import redundant when an enclosing
    function binds the same name — deleting it makes the name resolve to
    the enclosing binding, measured below as the AttributeError the review
    traced.  Mutation: dropping the shadowing exemption from
    ``duplicate_plain_imports`` fails exactly this test."""
    shadowed = (
        "import os\n\n\ndef outer():\n    os = 1\n\n    def inner():\n"
        "        import os\n\n        return os.sep\n\n    return inner\n"
    )
    assert duplicate_plain_imports(shadowed) == []
    # The premise, measured in place: WITHOUT the inner import, the call
    # resolves ``os`` to the enclosing int and breaks.
    namespace: dict[str, object] = {}
    deleted = shadowed.replace("        import os\n\n", "")
    code = compile(deleted, "<shadowed>", "exec")
    exec(code, namespace)  # noqa: S102 -- fixed test literal, premise measurement (TIH-001)
    outer = cast("Callable[[], Callable[[], str]]", namespace["outer"])
    with pytest.raises(AttributeError):
        outer()()
    # A parameter shadows the same way.
    param = (
        "import os\n\n\ndef f(os):\n    def g():\n        import os\n\n"
        "        return os.sep\n\n    return g\n"
    )
    assert duplicate_plain_imports(param) == []
    # Own-scope assignment: ``os`` is function-local THROUGHOUT the
    # function, so the import never duplicates the module-level binding.
    own = (
        "import os\n\n\ndef f():\n    import os\n\n    x = os.sep\n"
        "    os = 1\n    return x, os\n"
    )
    assert duplicate_plain_imports(own) == []


def test_a_class_body_binding_does_not_exempt_a_nested_duplicate() -> None:
    """Nested functions skip class scope in name resolution, so a class
    attribute of the same name exposes nothing on deletion — the method's
    re-import stays flagged, and the exemption cannot widen into classes."""
    source = (
        "import os\n\n\nclass C:\n    os = 1\n\n    def m(self):\n"
        "        import os\n\n        return os.sep\n"
    )
    assert duplicate_plain_imports(source) == [(8, "os")]


def test_the_tree_carries_no_duplicate_plain_import() -> None:
    tracked = tracked_names(REPO_ROOT, "*.py")
    assert len(tracked) > 300, "scope collapsed"
    offenders = [
        f"{name}:{lineno}: import {module}"
        for name in tracked
        for lineno, module in duplicate_plain_imports(
            (REPO_ROOT / name).read_text(encoding="utf-8")
        )
    ]
    assert offenders == [], "\n".join(offenders)
