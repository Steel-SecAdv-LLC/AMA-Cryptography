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
    """``(lineno, module)`` for each unaliased re-import of a top-level import."""
    tree = ast.parse(source)
    top: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            top.update(alias.name for alias in node.names)
    found: list[tuple[int, str]] = []
    top_level = set(map(id, tree.body))
    for walked in ast.walk(tree):
        if id(walked) in top_level or not isinstance(walked, ast.Import):
            continue
        for alias in walked.names:
            if alias.asname is None and alias.name in top:
                found.append((walked.lineno, alias.name))
    return found


def test_a_planted_duplicate_is_found() -> None:
    source = "import os\n\n\ndef f() -> str:\n    import os\n\n    return os.sep\n"
    assert duplicate_plain_imports(source) == [(5, "os")]


def test_an_aliased_or_from_import_is_not_in_scope() -> None:
    source = (
        "import os\nimport ast\n\n\ndef f() -> str:\n"
        "    import os as _os\n    from ast import parse\n\n"
        "    return _os.sep + str(parse('1'))\n"
    )
    assert duplicate_plain_imports(source) == []


def test_the_tree_carries_no_duplicate_plain_import() -> None:
    tracked = subprocess.run(
        ["git", "ls-files", "*.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert len(tracked) > 300, "scope collapsed"
    offenders = [
        f"{name}:{lineno}: import {module}"
        for name in tracked
        for lineno, module in duplicate_plain_imports(
            (REPO_ROOT / name).read_text(encoding="utf-8")
        )
    ]
    assert offenders == [], "\n".join(offenders)
