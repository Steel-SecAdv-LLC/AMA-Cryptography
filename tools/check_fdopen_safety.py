#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
AMA Cryptography — File-Descriptor Ownership Checker
====================================================

Verifies the property that actually prevents descriptor leaks: **every
``os.fdopen`` call is enclosed in a ``try`` whose handlers can close the raw
descriptor if the hand-off fails.**

Why this replaces the previous check
------------------------------------
The prior gate was a ``grep`` for ``os.fdopen`` filtered through a hardcoded
list of *approved filenames*.  That construction cannot distinguish a correctly
guarded call from a leaking one — it only asks "is this file on the list?" —
so it is satisfied by editing the list.  It had also already rotted: the list
named ``key_storage.py``, a module that does not exist in this package, while
omitting the module that actually performs the call.  A gate that can be
satisfied by renaming things, and that silently references a phantom file, is
not a safety control.

``os.fdopen`` takes ownership of the descriptor: on success the resulting
file object closes it, but if the call itself raises (bad mode, EMFILE,
interpreter shutdown) ownership never transfers and the descriptor leaks.  In
a long-lived process that leak is unbounded.  The mitigation is structural —
wrap the call so a failure path can still ``os.close(fd)`` — and that is a
property of the *syntax tree*, which is exactly what this checker inspects.

Accepted shapes
---------------
A call is considered guarded when it is lexically inside a ``try`` statement
that has at least one handler capable of catching the failure, i.e. a bare
``except:``, or a handler naming ``BaseException``, ``Exception``, ``OSError``
or ``IOError`` (including tuple forms).  A ``finally``-only ``try`` also
qualifies, since ``finally`` runs on the raising path.

Usage
-----
    python tools/check_fdopen_safety.py            # scan tracked *.py
    python tools/check_fdopen_safety.py --paths a  # scan specific paths
"""

from __future__ import annotations

import argparse
import ast
import subprocess  # nosec B404 - fixed argv git invocation, no shell
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

# Handler types that can plausibly close the descriptor on the failure path.
_GUARDING_EXCEPTIONS = frozenset({"BaseException", "Exception", "OSError", "IOError"})


@dataclass(frozen=True)
class Violation:
    """An ``os.fdopen`` call that is not protected against a leak."""

    path: str
    line_no: int
    reason: str

    def render(self) -> str:
        return f"{self.path}:{self.line_no}: {self.reason}"


def _is_fdopen_call(node: ast.AST) -> bool:
    """True for ``os.fdopen(...)`` / ``<alias>.fdopen(...)`` / ``fdopen(...)``."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr == "fdopen":
        return True
    return isinstance(func, ast.Name) and func.id == "fdopen"


def _handler_guards(handler: ast.ExceptHandler) -> bool:
    """True when ``handler`` can catch an exception raised by the call."""
    if handler.type is None:
        return True  # bare `except:`
    names: list[str] = []
    target = handler.type
    if isinstance(target, ast.Tuple):
        candidates: Sequence[ast.expr] = target.elts
    else:
        candidates = [target]
    for item in candidates:
        if isinstance(item, ast.Name):
            names.append(item.id)
        elif isinstance(item, ast.Attribute):
            names.append(item.attr)
    return any(name in _GUARDING_EXCEPTIONS for name in names)


def _try_protects(try_node: ast.Try) -> bool:
    """True when this ``try`` can run cleanup on the raising path."""
    if try_node.finalbody:
        return True
    return any(_handler_guards(h) for h in try_node.handlers)


def count_call_sites(source: str) -> int:
    """Number of real ``os.fdopen`` CALL nodes in ``source``.

    Counted from the AST rather than by text search: this repository's own test
    fixtures embed ``os.fdopen(...)`` inside string literals, and counting those
    would report a call-site total that does not exist.  A checker that prints a
    number it cannot justify is not worth trusting on the numbers that matter.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return 0
    return sum(1 for node in ast.walk(tree) if _is_fdopen_call(node))


def check_source(rel_path: str, source: str) -> list[Violation]:
    """Return violations for ``source`` (already-loaded Python text)."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [Violation(rel_path, exc.lineno or 1, f"could not parse: {exc.msg}")]

    # Map each node to its ancestors so enclosure can be tested exactly, rather
    # than guessed from indentation or line proximity.
    parents: dict[ast.AST, Optional[ast.AST]] = {tree: None}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    violations: list[Violation] = []
    for node in ast.walk(tree):
        if not _is_fdopen_call(node):
            continue

        guarded = False
        current: Optional[ast.AST] = parents.get(node)
        inner: ast.AST = node
        while current is not None:
            # Only the try BODY is protected — a call sitting in an `except`
            # or `else` clause of the same statement is not.
            if isinstance(current, ast.Try) and any(
                inner is stmt or inner in set(ast.walk(stmt)) for stmt in current.body
            ):
                if _try_protects(current):
                    guarded = True
                    break
            inner = current
            current = parents.get(current)

        if not guarded:
            violations.append(
                Violation(
                    rel_path,
                    getattr(node, "lineno", 1),
                    (
                        "os.fdopen() is not inside a try/except(BaseException|"
                        "Exception|OSError)/finally — if the call raises, the raw "
                        "descriptor is never closed and leaks"
                    ),
                )
            )
    return violations


def _tracked_python_files(repo_root: Path) -> list[Path]:
    try:
        out = subprocess.run(  # nosec B603 - fixed argv, no shell, trusted binary
            ["git", "ls-files", "*.py"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: unable to enumerate files via git: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    return [repo_root / n for n in out.splitlines() if n.strip() and (repo_root / n).is_file()]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify every os.fdopen call is leak-guarded (AST-based)."
    )
    parser.add_argument("--paths", nargs="*", help="explicit paths to scan")
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent
    targets = (
        [Path(p).resolve() for p in args.paths] if args.paths else _tracked_python_files(repo_root)
    )

    violations: list[Violation] = []
    call_sites = 0
    for path in targets:
        try:
            rel = str(path.relative_to(repo_root)).replace("\\", "/")
        except ValueError:
            rel = str(path)
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "fdopen" not in source:
            continue
        call_sites += count_call_sites(source)
        violations.extend(check_source(rel, source))

    if violations:
        print("FD-OWNERSHIP CHECK FAILED — unguarded os.fdopen call(s):\n")
        for v in violations:
            print(f"  {v.render()}")
        print(
            "\nWrap the call so the raw descriptor is closed when the hand-off "
            "fails, e.g.:\n"
            "    fd, name = tempfile.mkstemp(...)\n"
            "    try:\n"
            "        with os.fdopen(fd, 'wb') as fh:\n"
            "            ...\n"
            "    except BaseException:\n"
            "        try:\n"
            "            os.close(fd)\n"
            "        except OSError:\n"
            "            pass\n"
            "        raise\n"
        )
        return 1

    print(f"FD-ownership check clean: {call_sites} os.fdopen call site(s), all leak-guarded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
