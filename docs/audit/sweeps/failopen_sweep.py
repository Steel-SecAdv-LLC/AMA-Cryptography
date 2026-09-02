#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Fail-open sweep over the shipped package (mandate §7, "fail-open sweep").

Enumerates, by AST, every site in ``ama_cryptography/**`` where a check's
consequence can be short-circuited:

1. every ``os.environ`` / ``os.getenv`` read (name, file, line, and whether
   the read feeds a security decision is left to the reviewer: every site is
   listed, none is filtered);
2. every ``except`` clause whose body is ``pass``, a bare ``return``, a
   ``return <constant>``, ``continue``, or only a log call (a downgrade);
3. every ``dict.get(key, default)`` / ``getattr(obj, name, default)`` whose
   default is a truthy literal or a string naming a permissive rung
   (``"allow"``, ``"permissive"``, ``"warn"``, ``"skip"``, ``"unanchored"``);
4. every ``warnings.warn`` / ``logger.warning`` call inside a function whose
   name contains ``verify``, ``check``, ``validate``, ``integrity``, ``post``,
   ``self_test``, ``anchor`` or ``permitted`` (a warning where a refusal may
   belong);
5. every subprocess/status-code discard: ``subprocess.run(...)`` without
   ``check=True`` whose return value is not bound, and ``.returncode`` never
   read in the enclosing function.

The output is a TSV to stdout; the reviewer disposition is recorded in
docs/audit/PR394_FAILOPEN_SWEEP.tsv.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PKG = REPO / "ama_cryptography"
PERMISSIVE = {
    "allow",
    "permissive",
    "warn",
    "skip",
    "unanchored",
    "lenient",
    "ignore",
    "off",
    "disabled",
}
SECURITY_FN = (
    "verify",
    "check",
    "validate",
    "integrity",
    "post",
    "self_test",
    "anchor",
    "permitted",
    "gate",
    "refuse",
)


def enclosing_function(stack: list[ast.AST]) -> str:
    for node in reversed(stack):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name
    return "<module>"


def is_log_call(stmt: ast.AST) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Call)
        and isinstance(stmt.value.func, ast.Attribute)
        and stmt.value.func.attr
        in {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
    )


def _permissive_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and (
        node.value is True or (isinstance(node.value, str) and node.value.lower() in PERMISSIVE)
    )


Row = tuple[str, int, str, str, str]


class Sweeper:
    """One file's walk: the enclosing-function stack and the rows it yields."""

    def __init__(self, rel: str) -> None:
        self.rel = rel
        self.stack: list[ast.AST] = []
        self.rows: list[Row] = []

    def _row(self, node: ast.AST, kind: str, site: str) -> None:
        lineno = getattr(node, "lineno", 0)
        self.rows.append((self.rel, lineno, kind, enclosing_function(self.stack), site[:140]))

    def _call(self, node: ast.Call) -> None:
        f = node.func
        name = ast.unparse(f)
        fn = enclosing_function(self.stack)
        if name in ("os.environ.get", "os.getenv", "_os.environ.get", "_os.getenv") or (
            isinstance(f, ast.Attribute) and f.attr in ("get", "getenv") and "environ" in name
        ):
            self._row(node, "env-read", ast.unparse(node))
        if isinstance(f, ast.Attribute) and f.attr == "get" and len(node.args) >= 2:
            if _permissive_constant(node.args[1]):
                self._row(node, "permissive-default", ast.unparse(node))
        if isinstance(f, ast.Name) and f.id == "getattr" and len(node.args) >= 3:
            if _permissive_constant(node.args[2]):
                self._row(node, "permissive-default", ast.unparse(node))
        if name == "warnings.warn" or (
            isinstance(f, ast.Attribute)
            and f.attr in ("warning", "warn")
            and any(k in fn.lower() for k in SECURITY_FN)
        ):
            self._row(node, "warning-in-security-fn", ast.unparse(node))
        if name.endswith("subprocess.run") and not any(k.arg == "check" for k in node.keywords):
            parent = self.stack[-2] if len(self.stack) >= 2 else None
            if isinstance(parent, ast.Expr):
                self._row(node, "status-discarded", ast.unparse(node))

    def _except(self, node: ast.ExceptHandler) -> None:
        body = node.body
        kind: str | None = None
        if len(body) == 1 and isinstance(body[0], ast.Pass):
            kind = "except-pass"
        elif len(body) == 1 and isinstance(body[0], ast.Continue):
            kind = "except-continue"
        elif (
            len(body) == 1
            and isinstance(body[0], ast.Return)
            and (body[0].value is None or isinstance(body[0].value, ast.Constant))
        ):
            value = body[0].value
            kind = f"except-return-{ast.unparse(value) if value is not None else 'None'}"
        elif all(is_log_call(s) for s in body):
            kind = "except-log-only"
        if kind:
            exc = ast.unparse(node.type) if node.type else "<bare>"
            self._row(node, kind, f"except {exc}")

    def visit(self, node: ast.AST) -> None:
        self.stack.append(node)
        if isinstance(node, ast.Call):
            self._call(node)
        if isinstance(node, ast.Subscript) and "environ" in ast.unparse(node.value):
            self._row(node, "env-read", ast.unparse(node))
        if isinstance(node, ast.ExceptHandler):
            self._except(node)
        for child in ast.iter_child_nodes(node):
            self.visit(child)
        self.stack.pop()


def main() -> int:
    rows: list[Row] = []
    for path in sorted(PKG.rglob("*.py")):
        rel = path.relative_to(REPO).as_posix()
        sweeper = Sweeper(rel)
        sweeper.visit(ast.parse(path.read_text(encoding="utf-8")))
        rows.extend(sweeper.rows)
    print("path\tline\tclass\tfunction\tsite")
    for r in rows:
        print("\t".join(str(x) for x in r))
    print(f"# {len(rows)} sites", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
