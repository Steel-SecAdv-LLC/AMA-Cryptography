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
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def duplicate_plain_imports(source: str) -> list[tuple[int, str]]:
    """``(lineno, module)`` for each plain re-import in CodeQL's class.

    Three shapes, each measured against the rule's own documentation and
    examples (its canonical case is two plain top-level imports): a second
    unaliased ``import X`` directly at module top level; an unaliased local
    ``import X`` whose ``X`` the top level already plainly imports; and a
    second unaliased ``import X`` among the direct statements of one
    function or class body.  Only unaliased imports count on BOTH sides:
    ``import os as _os`` binds ``_os``, not ``os``, so a local plain
    ``import os`` beside it is load-bearing, not a duplicate — measured,
    deleting it raises NameError.  A module-level import guarded by
    ``try``/``if`` is conditional, never counted as the earlier binding.
    """
    tree = ast.parse(source)
    top_ids = set(map(id, tree.body))
    found: set[tuple[int, str]] = set()
    top_seen = _scan_direct_imports(tree.body, found)
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
        for alias in walked.names:
            if alias.asname is None and alias.name in top_seen:
                found.add((walked.lineno, alias.name))
    return sorted(found)


def _scan_direct_imports(body: list[ast.stmt], found: set[tuple[int, str]]) -> set[str]:
    """Flag repeats among one statement list's unaliased plain imports;
    return the names it binds."""
    seen: set[str] = set()
    for stmt in body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                if alias.asname is not None:
                    continue
                if alias.name in seen:
                    found.add((stmt.lineno, alias.name))
                seen.add(alias.name)
    return seen


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


def test_a_same_block_duplicate_inside_try_or_if_is_found() -> None:
    source = (
        "try:\n    import os\n    import os\nexcept ImportError:\n    pass\n\n"
        "if True:\n    import sys\n    import sys\n"
    )
    assert duplicate_plain_imports(source) == [(3, "os"), (9, "sys")]


def test_the_tree_carries_no_duplicate_plain_import() -> None:
    tracked = subprocess.run(
        ["git", "ls-files", "*.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    assert len(tracked) > 300, "scope collapsed"
    offenders = [
        f"{name}:{lineno}: import {module}"
        for name in tracked
        for lineno, module in duplicate_plain_imports(
            (REPO_ROOT / name).read_text(encoding="utf-8")
        )
    ]
    assert offenders == [], "\n".join(offenders)
