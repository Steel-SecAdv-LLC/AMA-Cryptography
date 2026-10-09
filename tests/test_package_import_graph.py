# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The ``ama_cryptography`` package's import graph has no cycle.

A cycle makes a module's state depend on import order: a name read back from
a partially initialised module is missing or stale, and which one depends on
which module the caller happened to import first.  Every import counts, at
module level or inside a function -- a deferred import is still an edge,
taken at a time the reader cannot see -- which is how CodeQL's
``py/cyclic-import`` counts them.  PR #415 introduced two cycles that way
(``_module_state`` and ``_secret_material`` each importing ``secure_memory``
inside a function) and CodeQL flagged them after review; this test fails on
them locally, before a push.

Scope: cycles among the package's modules.  An edge INTO the package's
``__init__`` -- an import of a name the ``__init__`` defines -- is not
counted.  Counted, ``main`` has one cycle through it when this was written
(``_self_test`` reads ``_find_import_shadowing`` from the ``__init__``, which
imports ``_self_test``), and a gate that must carry it would be an exemption
list (AGENTS.md section 10).  It is recorded in the CHANGELOG, measured by
:func:`import_graph` with ``include_package_init=True``.  Within this scope
``main`` had no cycle, so the gate needs no exemption.
"""

from __future__ import annotations

import ast
import collections
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PACKAGE = "ama_cryptography"


def _module_name(root: Path, path: Path) -> str:
    parts = list(path.relative_to(root.parent).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def import_graph(root: Path, include_package_init: bool = False) -> dict[str, set[str]]:
    """Edges from each module of the package at ``root`` to the package
    modules it imports, wherever the import statement sits.  Edges into the
    package's own ``__init__`` are left out unless ``include_package_init``."""
    package = root.name
    paths = {_module_name(root, p): p for p in root.rglob("*.py") if "__pycache__" not in p.parts}
    graph: dict[str, set[str]] = {name: set() for name in paths}
    for name, path in paths.items():
        is_package = path.name == "__init__.py"
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    anchor = name.split(".")
                    if not is_package:
                        anchor.pop()
                    anchor = anchor[: len(anchor) - (node.level - 1)]
                    base = ".".join(anchor + ([node.module] if node.module else []))
                else:
                    base = node.module or ""
                # ``from pkg import sub`` imports the submodule ``pkg.sub``;
                # ``pkg`` itself is read only for a name that is not one.
                submodules = [
                    f"{base}.{alias.name}"
                    for alias in node.names
                    if f"{base}.{alias.name}" in graph
                ]
                targets = submodules if len(submodules) == len(node.names) else [base, *submodules]
            else:
                continue
            for target in targets:
                if target == package and not include_package_init:
                    continue
                if target != name and target in graph and target.startswith(package):
                    graph[name].add(target)
    return graph


def _shortest_cycle(graph: dict[str, set[str]], start: str) -> list[str] | None:
    queue = collections.deque([[start]])
    seen = {start}
    while queue:
        path = queue.popleft()
        for nxt in sorted(graph[path[-1]]):
            if nxt == start:
                return [*path, start]
            if nxt not in seen:
                seen.add(nxt)
                queue.append([*path, nxt])
    return None


def cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    """The shortest cycle through each module that lies on one, deduplicated."""
    found: dict[frozenset[str], list[str]] = {}
    for start in sorted(graph):
        cycle = _shortest_cycle(graph, start)
        if cycle is not None:
            found.setdefault(frozenset(cycle), cycle)
    return list(found.values())


def test_the_package_import_graph_has_no_cycle() -> None:
    """PIN.  Restoring ``_module_state``'s or ``_secret_material``'s
    function-level import of ``secure_memory`` fails this."""
    found = cycles(import_graph(REPO / PACKAGE))
    assert found == [], "import cycles: " + "; ".join(" -> ".join(c) for c in found)


def _write_package(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "pkg"
    root.mkdir()
    for name, body in files.items():
        (root / name).write_text(body, encoding="utf-8")
    return root


@pytest.mark.parametrize(
    "files",
    [
        pytest.param(
            {"__init__.py": "", "a.py": "from pkg.b import x\n", "b.py": "import pkg.a\nx = 1\n"},
            id="module-level",
        ),
        pytest.param(
            {
                "__init__.py": "",
                "a.py": "from pkg.b import x\n",
                "b.py": "x = 1\ndef f():\n    from pkg import a\n    return a\n",
            },
            id="inside-a-function",
        ),
        pytest.param(
            {"__init__.py": "", "a.py": "from .b import x\n", "b.py": "from . import a\nx = 1\n"},
            id="relative",
        ),
    ],
)
def test_the_graph_sees_every_form_of_import(tmp_path: Path, files: dict[str, str]) -> None:
    """PIN for the instrument: each planted cycle is found.  Without these
    rows the gate could pass by reading no edges at all."""
    assert cycles(import_graph(_write_package(tmp_path, files)))


def test_a_cycle_through_the_package_init_is_measured_not_gated(tmp_path: Path) -> None:
    """RANGE: the scope stated in the module docstring, both ways."""
    root = _write_package(
        tmp_path, {"__init__.py": "from .a import y\n", "a.py": "from pkg import z\ny = 1\n"}
    )
    assert cycles(import_graph(root)) == []
    assert cycles(import_graph(root, include_package_init=True))


def test_an_acyclic_package_reports_nothing(tmp_path: Path) -> None:
    """RANGE: a diamond is not a cycle."""
    root = _write_package(
        tmp_path,
        {
            "__init__.py": "",
            "a.py": "from pkg import b, c\n",
            "b.py": "from pkg.d import x\n",
            "c.py": "from .d import x\n",
            "d.py": "x = 1\n",
        },
    )
    assert cycles(import_graph(root)) == []


def test_importing_a_submodule_through_the_package_reads_nothing_from_init(
    tmp_path: Path,
) -> None:
    """PIN.  ``from pkg import b`` binds the submodule ``pkg.b``; it reads no
    name the ``__init__`` defines, so it is no edge into it.  Counting one
    reported three of ``main``'s modules as cycles through the ``__init__``
    that read nothing from it."""
    root = _write_package(
        tmp_path,
        {"__init__.py": "from . import a\n", "a.py": "from pkg import b\n", "b.py": "x = 1\n"},
    )
    assert cycles(import_graph(root, include_package_init=True)) == []
