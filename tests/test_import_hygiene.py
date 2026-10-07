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
import os
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
    Same-value siblings in exclusive branches need no dominance analysis:
    both are flagged, the half-deleted intermediate (which would raise
    UnboundLocalError on the emptied branch) is still flagged, so the only
    state this gate certifies is the behavior-preserving full deletion —
    measured, and pinned by the never-green-half-deleted test (review
    finding, 2026-10-07).  The single-deletion shape that WOULD break a
    branch while going green — a same-name, different-value sibling — is
    exactly what the pairwise own-scope exemption removes from the report.
    """
    tree = ast.parse(source)
    top_ids = set(map(id, tree.body))
    found: set[tuple[int, str]] = set()
    top_seen = _scan_direct_imports(tree.body, found)
    class_scoped = _class_suite_import_ids(tree)
    shadowed = _shadowed_nested_import_bindings(tree)
    # No separate module-rebinding filter is needed here: a module-scope
    # non-import rebinding (``import os`` then ``os = 1`` at top level)
    # makes the nested re-import load-bearing (review finding, 2026-10-07;
    # measured as AttributeError on the review's shape), and the same-list
    # reset inside _scan_direct_imports already drops the binding from the
    # returned ``top_seen`` — measured per section 6.3: an additional filter
    # over top_seen survived its own mutation test because this reset is the
    # load-bearing guard, so the property is pinned on the reset instead.
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
    ``(module, asname)`` pairs the list binds.

    An intervening statement that rebinds a name resets it: after
    ``import os; os = 1`` a second ``import os`` in the same list restores
    the module binding, so deleting it would leave the rebound value —
    load-bearing, not dead (the same rule the cross-scope shape applies at
    module scope; review finding, 2026-10-07).  Imports rebind too (review
    finding, 2026-10-07, second round): ``import pathlib as os`` and
    ``from pathlib import Path as os`` each rebind ``os``, so a later
    ``import os`` restores the module and is exempt.  An import resets a
    key only when it binds the same name to a DIFFERENT value —
    ``import os.path`` between two ``import os`` rebinds ``os`` to the
    same module object, so the repeat stays flagged (measured: deleting it
    changes nothing).  A plain alias binds its root module, an ``as``
    alias binds the full dotted module, and a from-import never binds a
    module this gate tracks, so it always resets.  The rebinding walk over
    a compound statement over-collects from its nested suites, which are
    scanned separately — over-collection only widens the reset, the safe
    direction.
    """

    def bound_name(key: tuple[str, str | None]) -> str:
        return key[1] or key[0].split(".")[0]

    def bound_value(key: tuple[str, str | None]) -> str:
        return key[0] if key[1] else key[0].split(".")[0]

    seen: set[tuple[str, str | None]] = set()
    for stmt in body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                key = (alias.name, alias.asname)
                if key in seen:
                    found.add((stmt.lineno, alias.name))
                seen = {
                    k
                    for k in seen
                    if bound_name(k) != bound_name(key) or bound_value(k) == bound_value(key)
                }
                seen.add(key)
            continue
        if isinstance(stmt, ast.ImportFrom):
            rebound = {alias.asname or alias.name for alias in stmt.names}
        else:
            rebound = _statement_bound_names(stmt)
        if rebound:
            seen = {key for key in seen if bound_name(key) not in rebound}
    return seen


def _statement_bound_names(stmt: ast.stmt) -> set[str]:
    """Names a non-import statement can rebind, for the reset above.

    ``Name`` stores and deletes, exception-handler and match captures, and
    nested def/class statement names; the walk stops at nested function and
    class bodies for the statement's own suites the caller scans separately,
    but a compound statement's directly nested suites are still walked —
    deliberate over-collection, documented at the call site.
    """
    out: set[str] = set()
    stack: list[ast.AST] = [stmt]
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
        elif isinstance(node, ast.MatchMapping) and node.rest:
            # ``rest`` is a plain string attribute, not a Name node
            # (review finding, 2026-10-07).
            out.add(node.rest)
        stack.extend(ast.iter_child_nodes(node))
    return out


def _function_bound_names(fn: ast.AST, include_imports: bool = True) -> set[str]:
    """Names a function's OWN scope binds: parameters plus body bindings.

    The walk stops at nested function and class bodies — their internal
    bindings live in their own scopes — while the nested statement's NAME
    itself binds here.  Comprehension TARGETS are excluded: since Python 3
    a comprehension is its own scope, so ``[os for os in ()]`` binds
    nothing in the containing function, and collecting it exempted a
    genuinely redundant nested import — a false-negative path in a
    CI-blocking gate (review finding, 2026-10-07; the first form of this
    walk over-collected them as "the safe direction").  A walrus inside a
    comprehension binds in the CONTAINING scope (PEP 572) and is still
    collected, because only the generator targets are skipped.  A walrus
    inside a nested function's decorator or default (which evaluates in
    this scope) is the one binding the stop skips — vanishingly rare, and
    missing it only leaves a flag standing for a human to judge.
    ``include_imports=False`` drops the bindings import statements create,
    for the own-scope question below: whether an import exempts its own
    scope is value-dependent, so it is answered pairwise by
    :func:`_import_bound_pairs`, not by this name set.
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
        elif isinstance(node, ast.MatchMapping) and node.rest:
            # The mapping-rest capture binds too, and ``rest`` is a plain
            # string attribute, not a Name node (review finding, 2026-10-07).
            out.add(node.rest)
        elif isinstance(node, ast.Import) and include_imports:
            for alias in node.names:
                out.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and include_imports:
            for alias in node.names:
                out.add(alias.asname or alias.name)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            # Walk the comprehension's expressions (a walrus there binds in
            # THIS scope) but never its generator targets, which bind only
            # inside the comprehension's own scope.
            generators = {id(gen) for gen in node.generators}
            stack.extend(
                child for child in ast.iter_child_nodes(node) if id(child) not in generators
            )
            for gen in node.generators:
                stack.extend(
                    child for child in ast.iter_child_nodes(gen) if child is not gen.target
                )
            continue
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
      or UnboundLocalError, never the module import), or by an import that
      binds the same name to a DIFFERENT value — ``import pathlib as os``
      and ``from pathlib import Path as os`` leave the plain ``import os``
      beside them as what restores the module, never a repeat (review
      finding, 2026-10-07, final Copilot round).  The own-scope import
      question is answered pairwise over ``(bound name, bound value)``, so
      an import cannot exempt itself and a same-value repeat —
      ``import os as _os`` twice — stays flagged.

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
            own_pairs: frozenset[tuple[str, str]] = frozenset()
        else:
            own_all = frozenset(_function_bound_names(scope_node))
            exempt = enclosing | frozenset(_function_bound_names(scope_node, include_imports=False))
            own_pairs = frozenset(_import_bound_pairs(scope_node))
        stack: list[ast.AST] = list(ast.iter_child_nodes(scope_node))
        while stack:
            child = stack.pop()
            if isinstance(child, ast.Import):
                for alias in child.names:
                    bound = alias.asname or alias.name.split(".")[0]
                    value = alias.name if alias.asname else alias.name.split(".")[0]
                    divergent = any(b == bound and v != value for b, v in own_pairs)
                    if bound in exempt or divergent:
                        out.add((id(child), bound))
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                collect(child, enclosing | own_all)
            else:
                stack.extend(ast.iter_child_nodes(child))

    collect(tree, frozenset())
    return out


def _import_bound_pairs(fn: ast.AST) -> set[tuple[str, str]]:
    """``(bound name, bound value)`` pairs the function's own imports bind.

    A plain ``import A.B`` binds ``A`` to module ``A``; ``import A.B as C``
    binds ``C`` to module ``A.B``; ``from M import N as C`` binds ``C`` to
    the attribute ``M.N``, encoded ``"from:M:N"`` so it can never equal a
    module path.  The pairs let the own-scope exemption above compare
    values, not just names: an import whose scope holds another import of
    the SAME name but a DIFFERENT value is load-bearing (it restores the
    module that other import displaced), while a same-value repeat is the
    duplicate the gate exists to flag.  The walk stops where
    :func:`_function_bound_names` stops (nested function and class bodies
    bind their own scopes).
    """
    out: set[tuple[str, str]] = set()
    body = getattr(fn, "body", [])
    stack: list[ast.AST] = list(body) if isinstance(body, list) else [body]
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    out.add((alias.asname, alias.name))
                else:
                    root = alias.name.split(".")[0]
                    out.add((root, root))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                out.add((alias.asname or alias.name, f"from:{node.module}:{alias.name}"))
        stack.extend(ast.iter_child_nodes(node))
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
    outer = cast(Callable[[], Callable[[], str]], namespace["outer"])
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
    # A mapping-rest capture in an enclosing function shadows the same way
    # (``MatchMapping.rest`` is a string attribute, not a Name node).
    match_shadow = (
        "import os\n\n\ndef outer(value):\n    match value:\n"
        "        case {**os}:\n            pass\n\n    def inner():\n"
        "        import os\n\n        return os.sep\n\n    return inner\n"
    )
    assert duplicate_plain_imports(match_shadow) == []
    # A comprehension target binds only the comprehension's own scope, so
    # it exempts NOTHING: the re-import stays flagged, and deleting it is
    # behavior-preserving (measured — review finding, 2026-10-07; the
    # first collector over-collected these targets and hid the duplicate).
    comp_target = (
        "import os\n\n\ndef f():\n    import os\n\n"
        "    values = [os for os in ()]\n    return os.sep, values\n"
    )
    assert duplicate_plain_imports(comp_target) == [(5, "os")]
    # A walrus INSIDE a comprehension binds the containing scope (PEP 572),
    # so it still exempts.
    comp_walrus = (
        "import os\n\n\ndef f():\n    import os\n\n"
        "    values = [(os := v) for v in (1,)]\n    return os, values\n"
    )
    assert duplicate_plain_imports(comp_walrus) == []


def test_a_module_scope_rebinding_makes_the_import_load_bearing() -> None:
    """PIN (review finding, 2026-10-07): after ``import os`` a module-scope
    ``os = 1`` leaves the global holding the int, so a nested re-import is
    what gives the function the module back (measured: deleting it raises
    AttributeError on ``os.sep``), and a later top-level re-import RESTORES
    the module binding rather than repeating it.  Both forms are exempt;
    without the rebinding both stay flagged (controls below).  Mutation:
    dropping the module-rebound filter fails the cross-scope case, dropping
    the same-list reset fails the top-level case — each exactly here."""
    rebound = "import os\n\nos = 1\n\n\ndef f():\n    import os\n\n    return os.sep\n"
    assert duplicate_plain_imports(rebound) == []
    restored = "import os\n\nos = 1\nimport os\n\nprint(os.sep)\n"
    assert duplicate_plain_imports(restored) == []
    control_nested = "import os\n\n\ndef f():\n    import os\n\n    return os.sep\n"
    assert duplicate_plain_imports(control_nested) == [(5, "os")]
    control_top = "import os\nimport os\n\nprint(os.sep)\n"
    assert duplicate_plain_imports(control_top) == [(2, "os")]
    # A match mapping-rest capture is a rebinding too — ``rest`` is a plain
    # string attribute, not a Name node, and the first collector form
    # missed it (review finding, 2026-10-07).  Same restore semantics.
    mapping_rest = (
        "import os\n\nmatch {1: 2}:\n    case {**os}:\n        pass\n\n"
        "import os\n\nprint(os.sep)\n"
    )
    assert duplicate_plain_imports(mapping_rest) == []


def test_an_import_rebinding_makes_the_restore_import_load_bearing() -> None:
    """PIN (review finding, 2026-10-07, final Copilot round): imports rebind
    too.  ``import pathlib as os`` and ``from pathlib import Path as os``
    each leave ``os`` bound to something other than the ``os`` module, so a
    later plain ``import os`` RESTORES the module — deleting it breaks the
    use sites (measured below: AttributeError on ``os.sep``) — while
    ``import os.path`` rebinds ``os`` to the SAME module object, so a
    repeat across it stays a flagged redundancy (measured: deletion changes
    nothing).  Mutation: dropping the value-aware reset from
    ``_scan_direct_imports`` fails the two top-level exemptions; dropping
    the divergent-import own-scope bindings from ``_function_bound_names``
    fails the two function-scope exemptions — each exactly here."""
    aliased = "import os\nimport pathlib as os\nimport os\n\nprint(os.sep)\n"
    assert duplicate_plain_imports(aliased) == []
    from_form = "import os\nfrom pathlib import Path as os\nimport os\n\nprint(os.sep)\n"
    assert duplicate_plain_imports(from_form) == []
    # The premise, measured in place: WITHOUT the restore import, the use
    # site resolves ``os`` to the rebound value and breaks.
    for deleted in (
        "import os\nimport pathlib as os\nos.sep\n",
        "import os\nfrom pathlib import Path as os\nos.sep\n",
    ):
        with pytest.raises(AttributeError):
            exec(  # noqa: S102 -- fixed test literal, premise measurement (TIH-001)
                compile(deleted, "<rebound>", "exec"), {}
            )
    # Same-value rebinding is no exemption: ``import os.path`` binds ``os``
    # to the os module itself, so the repeat across it stays flagged, and a
    # genuine duplicate aliased pair stays flagged (value-equality guard).
    same_value = "import os\nimport os.path\nimport os\n"
    assert duplicate_plain_imports(same_value) == [(3, "os")]
    aliased_pair = "import pathlib as p\nimport pathlib as p\n"
    assert duplicate_plain_imports(aliased_pair) == [(2, "pathlib")]
    # The same two shapes exempt at function scope (the own-scope set
    # counts divergent import bindings; a plain re-import still cannot
    # self-exempt — control below).
    fn_aliased = (
        "import os\n\n\ndef f():\n    import pathlib as os\n    import os\n\n" "    return os.sep\n"
    )
    assert duplicate_plain_imports(fn_aliased) == []
    fn_from = (
        "import os\n\n\ndef f():\n    from pathlib import Path as os\n"
        "    import os\n\n    return os.sep\n"
    )
    assert duplicate_plain_imports(fn_from) == []
    fn_control = "import os\n\n\ndef f():\n    import os\n    import os\n\n    return os.sep\n"
    assert duplicate_plain_imports(fn_control) == [(5, "os"), (6, "os")]


def test_a_class_body_binding_does_not_exempt_a_nested_duplicate() -> None:
    """Nested functions skip class scope in name resolution, so a class
    attribute of the same name exposes nothing on deletion — the method's
    re-import stays flagged, and the exemption cannot widen into classes."""
    source = (
        "import os\n\n\nclass C:\n    os = 1\n\n    def m(self):\n"
        "        import os\n\n        return os.sep\n"
    )
    assert duplicate_plain_imports(source) == [(8, "os")]


def test_sibling_same_value_imports_are_never_green_half_deleted() -> None:
    """The gate's fixpoint is safe without dominance analysis (review
    finding, 2026-10-07): two exclusive-branch ``import os`` siblings under
    a top-level ``import os`` are both flagged; deleting only one leaves
    ``os`` function-local through the surviving import (the emptied branch
    raises UnboundLocalError, measured) and the gate STILL flags that
    intermediate, so it can never certify it; the state it does certify —
    both deleted — resolves every use to the module binding the pair was
    redundant against.  The different-value sibling, where a single
    deletion WOULD be certified while breaking a branch, is the case the
    pairwise own-scope exemption already removes from the report."""
    both = (
        "import os\n\n\ndef f(mode):\n"
        "    if mode == 1:\n        import os\n\n        return os.sep\n"
        "    if mode == 2:\n        import os\n\n        return os.pathsep\n"
    )
    assert duplicate_plain_imports(both) == [(6, "os"), (10, "os")]
    half = (
        "import os\n\n\ndef f(mode):\n"
        "    if mode == 1:\n        return os.sep\n"
        "    if mode == 2:\n        import os\n\n        return os.pathsep\n"
    )
    # The unsafe intermediate stays red: the gate never demands it as an
    # end state, it refuses it.
    assert duplicate_plain_imports(half) == [(8, "os")]
    namespace: dict[str, object] = {}
    code = compile(half, "<half>", "exec")
    exec(code, namespace)  # noqa: S102 -- fixed test literal, premise measurement (TIH-001)
    half_f = cast(Callable[[int], str], namespace["f"])
    with pytest.raises(UnboundLocalError):
        half_f(1)
    green = (
        "import os\n\n\ndef f(mode):\n"
        "    if mode == 1:\n        return os.sep\n"
        "    if mode == 2:\n        return os.pathsep\n"
    )
    assert duplicate_plain_imports(green) == []
    namespace = {}
    code = compile(green, "<green>", "exec")
    exec(code, namespace)  # noqa: S102 -- fixed test literal, premise measurement (TIH-001)
    green_f = cast(Callable[[int], str], namespace["f"])
    assert green_f(1) == os.sep and green_f(2) == os.pathsep


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
