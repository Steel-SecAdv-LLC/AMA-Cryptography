#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
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

"Inside" stops at the nearest function, ``lambda`` or generator expression:
a ``try`` around a ``def`` guards the *definition*, not a call that runs later
when the function is invoked, so it does not count for calls in that body.
The first revision walked straight through the ``def`` and accepted exactly
that shape.

What counts as a call
---------------------
``<anything>.fdopen(...)``, a bare ``fdopen(...)``, a call through any name
bound to ``os.fdopen`` — ``from os import fdopen as f``, ``f = os.fdopen``,
and chains of either — and ``getattr(<x>, "fdopen")(...)``.  The first
revision recognised only the attribute and the literal name ``fdopen``, so
``from os import fdopen as f; f(fd)`` was never examined.

Every tracked ``*.py`` is parsed as Python parses it — from bytes, honouring a
PEP 263 coding declaration — so a file in another encoding is checked rather
than skipped, and a file that cannot be read or parsed is reported.

Usage
-----
    python tools/check_fdopen_safety.py            # scan tracked *.py
    python tools/check_fdopen_safety.py --paths a  # scan specific paths
    python tools/check_fdopen_safety.py --root R   # scan R's tracked *.py
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence, Union

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


#: Modules whose ``fdopen`` is ``os.fdopen`` (``os`` re-exports the platform
#: module's).  ``from <one of these> import fdopen [as x]`` binds an alias.
_FDOPEN_MODULES = frozenset({"os", "posix", "nt"})

#: A parsed source: text, or the raw bytes Python itself would decode.
Source = Union[str, bytes]


def _is_fdopen_reference(node: ast.AST, aliases: frozenset[str]) -> bool:
    """An expression that evaluates to ``os.fdopen`` as far as the AST shows."""
    if isinstance(node, ast.Attribute):
        return node.attr == "fdopen"
    if isinstance(node, ast.Name):
        return node.id == "fdopen" or node.id in aliases
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
    ):
        name = node.args[1]
        return isinstance(name, ast.Constant) and name.value == "fdopen"
    return False


def fdopen_aliases(tree: ast.AST) -> frozenset[str]:
    """Every plain name the module binds to ``os.fdopen``.

    ``from os import fdopen as f`` and ``f = os.fdopen`` (and ``g = f``, to a
    fixed point).  A flat, whole-module table rather than scope analysis: the
    question is whether a call through the name could be ``os.fdopen``, and a
    binding anywhere in the file answers it conservatively — the same shape
    ``tools/check_corpus_originality.py`` uses for its string bindings.
    """
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in _FDOPEN_MODULES:
            for alias in node.names:
                if alias.name == "fdopen":
                    aliases.add(alias.asname or alias.name)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            targets: list[ast.expr]
            if isinstance(node, ast.Assign):
                targets, value = list(node.targets), node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            elif isinstance(node, ast.NamedExpr):
                targets, value = [node.target], node.value
            else:
                continue
            if not _is_fdopen_reference(value, frozenset(aliases)):
                continue
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in aliases:
                    aliases.add(target.id)
                    changed = True
    return frozenset(aliases)


def _is_fdopen_call(node: ast.AST, aliases: frozenset[str] = frozenset()) -> bool:
    """True for a call that invokes ``os.fdopen`` under any spelling above.

    ``os.fdopen(...)`` / ``<alias>.fdopen(...)`` / ``fdopen(...)``, a call
    through a name in ``aliases`` (see :func:`fdopen_aliases`), and
    ``getattr(<x>, "fdopen")(...)``.
    """
    if not isinstance(node, ast.Call):
        return False
    return _is_fdopen_reference(node.func, aliases)


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


def count_call_sites(source: Source) -> int:
    """Number of real ``os.fdopen`` CALL nodes in ``source``.

    Counted from the AST rather than by text search: this repository's own test
    fixtures embed ``os.fdopen(...)`` inside string literals, and counting those
    would report a call-site total that does not exist.  A checker that prints a
    number it cannot justify is not worth trusting on the numbers that matter.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return 0
    aliases = fdopen_aliases(tree)
    return sum(1 for node in ast.walk(tree) if _is_fdopen_call(node, aliases))


#: Nodes whose body does not run where it is written: a function or lambda
#: body runs when called, a generator expression's element when iterated.  A
#: ``try`` outside one of these does not guard a call inside it.
_DEFERRED_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.GeneratorExp)


def _runs_eagerly_in(scope: ast.AST, child: ast.AST, call: ast.AST) -> bool:
    """True when ``call``, reached through ``child``, runs where ``scope`` is written.

    Two eager pieces of a deferred scope: a function's default values and
    decorators (evaluated at ``def`` time), and a generator expression's
    FIRST iterable (evaluated when the expression is created).
    """
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return child in scope.decorator_list or child is scope.args
    if isinstance(scope, ast.Lambda):
        return child is scope.args
    if isinstance(scope, ast.GeneratorExp):
        first = scope.generators[0]
        return child is first and any(call is node for node in ast.walk(first.iter))
    return False


def check_source(rel_path: str, source: Source) -> list[Violation]:
    """Return violations for ``source`` (Python text, or its raw bytes).

    Bytes are decoded by the parser exactly as the interpreter would decode
    them, PEP 263 coding declaration included.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [Violation(rel_path, exc.lineno or 1, f"could not parse: {exc.msg}")]
    except ValueError as exc:  # e.g. a NUL byte in the source
        return [Violation(rel_path, 1, f"could not parse: {exc}")]
    aliases = fdopen_aliases(tree)

    # Map each node to its ancestors so enclosure can be tested exactly, rather
    # than guessed from indentation or line proximity.
    parents: dict[ast.AST, Optional[ast.AST]] = {tree: None}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    violations: list[Violation] = []
    for node in ast.walk(tree):
        if not _is_fdopen_call(node, aliases):
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
            # A deferred body runs later, outside any `try` enclosing its
            # definition: stop looking outward at the scope boundary.
            if isinstance(current, _DEFERRED_SCOPES) and not _runs_eagerly_in(current, inner, node):
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
    """Every tracked ``*.py`` under ``repo_root``, via ``tools/_repo.py``.

    The bare ``git ls-files`` this used to run C-quoted a non-ASCII name, the
    ``is_file()`` filter then dropped it, and an unguarded ``os.fdopen`` in
    ``zz_é.py`` was never parsed.  The helper lists with ``-z`` and fails closed.
    """
    repo = str(Path(__file__).resolve().parent.parent)
    if repo not in sys.path:
        sys.path.insert(0, repo)
    from tools._repo import TrackedFilesError, tracked_files

    try:
        return tracked_files(repo_root, "*.py")
    except TrackedFilesError as exc:
        print(f"ERROR: unable to enumerate files via git: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify every os.fdopen call is leak-guarded (AST-based)."
    )
    parser.add_argument("--paths", nargs="*", help="explicit paths to scan")
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="repository whose tracked *.py to scan (default: this file's repository)",
    )
    args = parser.parse_args(argv)

    repo_root = (args.root or Path(__file__).resolve().parent.parent).resolve()
    targets = (
        [Path(p).resolve() for p in args.paths] if args.paths else _tracked_python_files(repo_root)
    )

    violations: list[Violation] = []
    call_sites = 0
    scanned = 0
    for path in targets:
        try:
            rel = str(path.relative_to(repo_root)).replace("\\", "/")
        except ValueError:
            rel = str(path)
        try:
            # Bytes, not text: the parser decodes them the way the interpreter
            # does, honouring a PEP 263 coding declaration.  Reading as UTF-8
            # raised UnicodeDecodeError on a tracked latin-1 module and the
            # enumeration path `continue`d past it — the file was never parsed
            # and the run still printed "clean".
            source = path.read_bytes()
        except OSError as exc:
            # Explicit or enumerated, a file that cannot be read is an error,
            # not a clean result; it used to be dropped and the run printed
            # "clean: 0 os.fdopen call site(s)".
            print(f"ERROR: {path} could not be read ({exc}); nothing was checked.")
            return 2
        scanned += 1
        if b"fdopen" not in source:
            continue
        call_sites += count_call_sites(source)
        violations.extend(check_source(rel, source))

    if scanned == 0:
        print("ERROR: the FD-ownership check read 0 files — refusing to report clean.")
        return 2

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
