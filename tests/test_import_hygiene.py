#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""No module is plainly imported twice: once at top level and again inside a scope.

CodeQL filed its ``py/repeated-import`` Note twice against
``ama_cryptography/monitoring.py`` (alerts #750/#751, 2026-10-05): ``import
importlib`` at module top and again inside two methods.  A sweep by the same
rule found 26 such sites across the tree; every one was a pure redundancy and
was deleted.  CodeQL's Note severity does not block CI, so without this test
the class could accumulate again unseen.

Scope matches the measured defect class exactly: a function-local ``import X``
(no alias) whose ``X`` the module already imports at top level.  An ALIASED
local re-import (``import os as _os``) binds a different name, is not in
CodeQL's class, and seven such sites were examined and left; a local
``from X import name`` is frequently deliberate late binding (a monkeypatch
seam, or a fresh read of a rebindable module attribute) and is out of scope.
"""

from __future__ import annotations

import ast
from pathlib import Path

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
