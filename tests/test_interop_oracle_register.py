# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""INVARIANT-36's register names every interop-oracle test file.

The register in INVARIANTS.md lists, by hand, the test files that import a
second implementation (PyCA cryptography, PyNaCl, pycryptodome) under
``@pytest.mark.requires_interop_oracle``.  It listed four while five carried
the marker; ``tests/test_ed25519_expanded_key.py`` was missing, and a reader
takes a register as complete.  This test derives the set from the code, via
the AST, so a marker inside a string fixture does not count.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _carries_the_marker(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        for decorator in getattr(node, "decorator_list", []):
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if isinstance(target, ast.Attribute) and target.attr == "requires_interop_oracle":
                return True
    return False


def _register() -> set[str]:
    text = (REPO_ROOT / "INVARIANTS.md").read_text(encoding="utf-8")
    start = text.index("`@pytest.mark.requires_interop_oracle` in ")
    end = text.index("import\nPyCA cryptography", start)
    return set(re.findall(r"`(tests/test_\w+\.py)`", text[start:end]))


def test_the_register_names_exactly_the_marked_files() -> None:
    marked = {
        f"tests/{path.name}"
        for path in sorted((REPO_ROOT / "tests").glob("test_*.py"))
        if _carries_the_marker(path)
    }
    assert marked, "no file carries the marker; the scan is broken"
    assert _register() == marked
