#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""PR #394 readiness falsification, Phase D: measured mutation kill rate.

Why not mutmut
--------------
mutmut 3 serves mutants through an import hook from a ``mutants/`` copy of
the source tree.  The repository's gate tests load the gate module from its
path under ``tools/`` (``importlib.util.spec_from_file_location``) or run it
as a subprocess, so an import-hook mutant is never the code under test and
the tool would report survivors for mutations it never delivered.  For
``ama_cryptography/`` modules the power-on self-test refuses to import a
package whose ``.py`` digest no longer matches its signature, so every
mutant would be "killed" at import by the integrity check rather than by a
test — a kill rate measuring the wrong thing.

This driver mutates the file IN PLACE, one mutant at a time, restores it
after every run (and verifies the restoration by digest), and can re-sign
the package between mutants so a kill is a test's kill.  Every mutant is a
single-token edit at a recorded line and column, so a survivor can be read.

Operators: comparison flip (== <-> !=, < <-> >=, <= <-> >, is <-> is not,
in <-> not in), boolean flip (and <-> or), ``not`` removal, arithmetic flip
(+ <-> -, * <-> //), integer constant +1, boolean constant flip, non-empty
string constant emptied, ``return <expr>`` -> ``return None``,
``break`` <-> ``continue``.

Kill criteria: the named test files fail, or (for a gate tool) the tool
exits non-zero on the clean tree — CI runs both, so either is a detected
regression.  A test-run timeout is reported in its own column, not folded
into either count.

Usage::

    python docs/audit/sweeps/mutate.py --target tools/check_keygen_pct.py \\
        --tests tests/test_keygen_pct_gate.py --self-run \\
        --out docs/audit/logs/phaseD/mutation/check_keygen_pct.tsv
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SIGNATURE = REPO / "ama_cryptography" / "_integrity_signature.py"

_COMPARE_FLIP: dict[type[ast.cmpop], tuple[str, str]] = {
    ast.Eq: ("==", "!="),
    ast.NotEq: ("!=", "=="),
    ast.Lt: ("<", ">="),
    ast.GtE: (">=", "<"),
    ast.LtE: ("<=", ">"),
    ast.Gt: (">", "<="),
    ast.Is: ("is", "is not"),
    ast.IsNot: ("is not", "is"),
    ast.In: ("in", "not in"),
    ast.NotIn: ("not in", "in"),
}
_BINOP_FLIP: dict[type[ast.operator], tuple[str, str]] = {
    ast.Add: ("+", "-"),
    ast.Sub: ("-", "+"),
    ast.Mult: ("*", "//"),
}


@dataclass(frozen=True)
class Mutant:
    line: int  # 1-based
    col: int  # 0-based start column on `line`
    end_col: int
    original: str
    replacement: str
    operator: str


def _chars(line: str, byte_offset: int) -> int:
    """Character index for an ``ast`` byte offset (offsets are UTF-8 bytes).

    A line with an em dash or any other multi-byte character before the node
    would otherwise be sliced at the wrong place; the check_secrets.py run hit
    exactly that and aborted rather than mutate the wrong token.
    """
    return len(line.encode("utf-8")[:byte_offset].decode("utf-8", errors="ignore"))


def _segment_between(
    lines: list[str], a: ast.expr, b: ast.expr
) -> tuple[int, int, int, str] | None:
    """(line, start, end, text) of the source between two sibling nodes on one line."""
    if a.end_lineno != b.lineno or a.end_lineno is None or a.end_col_offset is None:
        return None
    line = lines[a.end_lineno - 1]
    start, end = _chars(line, a.end_col_offset), _chars(line, b.col_offset)
    return a.end_lineno, start, end, line[start:end]


def _span(node: ast.AST) -> tuple[int, int, int] | None:
    """(line, col, end_col) for a node that sits on one line, in characters."""
    lineno = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None)
    col = getattr(node, "col_offset", None)
    end_col = getattr(node, "end_col_offset", None)
    if lineno is None or end is None or col is None or end_col is None or lineno != end:
        return None
    line = LINES[lineno - 1]
    return lineno, _chars(line, col), _chars(line, end_col)


def _replace_token(
    lines: list[str], node_a: ast.expr, node_b: ast.expr, token: str, new: str, op: str
) -> Mutant | None:
    seg = _segment_between(lines, node_a, node_b)
    if seg is None:
        return None
    line, start, _end, text = seg
    # The operator is the only non-space, non-paren content between the operands.
    stripped = text.strip(" ()")
    if stripped != token:
        return None
    off = text.index(token)
    return Mutant(line, start + off, start + off + len(token), token, new, op)


def _docstring_ids(tree: ast.AST) -> set[int]:
    """``id()`` of every docstring constant, so they are not mutated."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if ast.get_docstring(node, clean=False) is not None and node.body:
                first = node.body[0]
                if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                    ids.add(id(first.value))
    return ids


def _operator_mutant(lines: list[str], node: ast.AST) -> Mutant | None:
    """Comparison, boolean and arithmetic operator flips."""
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        op_type = type(node.ops[0])
        if op_type in _COMPARE_FLIP:
            token, new = _COMPARE_FLIP[op_type]
            return _replace_token(lines, node.left, node.comparators[0], token, new, "compare")
    elif isinstance(node, ast.BoolOp) and len(node.values) >= 2:
        token, new = ("and", "or") if isinstance(node.op, ast.And) else ("or", "and")
        return _replace_token(lines, node.values[0], node.values[1], token, new, "boolop")
    elif isinstance(node, ast.BinOp) and type(node.op) in _BINOP_FLIP:
        token, new = _BINOP_FLIP[type(node.op)]
        return _replace_token(lines, node.left, node.right, token, new, "binop")
    return None


def _constant_mutant(lines: list[str], node: ast.Constant) -> Mutant | None:
    span = _span(node)
    if span is None:
        return None
    line, col, end_col = span
    text = lines[line - 1][col:end_col]
    if node.value is True or node.value is False:
        return Mutant(line, col, end_col, text, str(not node.value), "bool-const")
    if isinstance(node.value, int) and text.isdigit():
        return Mutant(line, col, end_col, text, str(node.value + 1), "int-const")
    if isinstance(node.value, str) and node.value and text.startswith(("'", '"')):
        quote = text[0]
        if text.count(quote) == 2 and len(text) < 120:
            return Mutant(line, col, end_col, text, quote + quote, "str-const")
    return None


def _statement_mutant(lines: list[str], node: ast.AST) -> Mutant | None:
    """``not`` removal, ``return <expr>`` -> ``return None``, break/continue swap."""
    span = _span(node)
    if span is None:
        return None
    line, col, end_col = span
    text = lines[line - 1][col:end_col]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        if text.startswith("not "):
            return Mutant(line, col, col + 4, "not ", "", "not-removal")
    elif isinstance(node, ast.Return) and node.value is not None:
        if text.startswith("return ") and text != "return None":
            return Mutant(line, col, end_col, text, "return None", "return-none")
    elif isinstance(node, (ast.Break, ast.Continue)):
        new = "continue" if text == "break" else "break"
        return Mutant(line, col, end_col, text, new, "loop-jump")
    return None


LINES: list[str] = []


def generate(source: str) -> list[Mutant]:
    """Every single-token mutant of `source`, in source order."""
    tree = ast.parse(source)
    lines = source.splitlines()
    LINES[:] = lines
    docstrings = _docstring_ids(tree)
    out: list[Mutant] = []
    for node in ast.walk(tree):
        m: Mutant | None
        if isinstance(node, ast.Constant):
            m = None if id(node) in docstrings else _constant_mutant(lines, node)
        else:
            m = _operator_mutant(lines, node) or _statement_mutant(lines, node)
        if m is not None:
            out.append(m)
    # Ordered and de-duplicated (a `not` inside a comparison can yield two).
    seen: set[tuple[int, int, str]] = set()
    unique: list[Mutant] = []
    for m in out:
        key = (m.line, m.col, m.replacement)
        if key not in seen:
            seen.add(key)
            unique.append(m)
    return sorted(unique, key=lambda m: (m.line, m.col))


def apply(source: str, m: Mutant) -> str:
    lines = source.splitlines(keepends=True)
    line = lines[m.line - 1]
    if line[m.col : m.end_col] != m.original:
        raise RuntimeError(f"mutant does not match source: {m} in {line!r}")
    lines[m.line - 1] = line[: m.col] + m.replacement + line[m.end_col :]
    return "".join(lines)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resign() -> None:
    if SIGNATURE.exists():
        SIGNATURE.unlink()
    env = dict(os.environ, AMA_BUILD_PIPELINE="1")
    subprocess.run(
        [sys.executable, "-m", "ama_cryptography.integrity", "--update", "--sign"],
        cwd=REPO,
        env=env,
        check=True,
        capture_output=True,
    )


def _run(cmd: list[str], timeout: int) -> tuple[int | None, str]:
    try:
        proc = subprocess.run(
            cmd, cwd=REPO, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return None, "TIMEOUT"
    tail = (proc.stdout + proc.stderr).strip().splitlines()[-3:]
    return proc.returncode, " | ".join(tail)[:300]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", required=True)
    ap.add_argument("--tests", nargs="+", required=True)
    ap.add_argument("--self-run", action="store_true", help="also run the target as a gate")
    ap.add_argument("--resign", action="store_true", help="re-sign the package per mutant")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    target = REPO / args.target
    original = target.read_text(encoding="utf-8")
    original_sha = _sha(target)
    mutants = generate(original)
    if args.limit:
        mutants = mutants[: args.limit]
    out = REPO / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    pytest_cmd = [sys.executable, "-m", "pytest", "-q", "-x", "--no-cov", "-p", "no:cacheprovider"]
    rows = [
        "id\tline\tcol\toperator\toriginal\treplacement\tpytest_rc\tself_run_rc\tstatus\tseconds\tlast_output"
    ]
    killed = survived = timed_out = 0
    started = time.time()
    try:
        for index, m in enumerate(mutants, 1):
            target.write_text(apply(original, m), encoding="utf-8")
            if args.resign:
                _resign()
            t0 = time.time()
            rc, tail = _run(pytest_cmd + args.tests, args.timeout)
            self_rc: int | None = 0
            if args.self_run and rc == 0:
                self_rc, self_tail = _run([sys.executable, str(target)], args.timeout)
                if self_rc != 0:
                    tail = self_tail
            if rc is None or self_rc is None:
                status = "timeout"
                timed_out += 1
            elif rc != 0 or self_rc != 0:
                status = "killed"
                killed += 1
            else:
                status = "survived"
                survived += 1
            rows.append(
                "\t".join(
                    [
                        str(index),
                        str(m.line),
                        str(m.col),
                        m.operator,
                        m.original.replace("\t", " "),
                        m.replacement.replace("\t", " "),
                        "timeout" if rc is None else str(rc),
                        "timeout" if self_rc is None else str(self_rc),
                        status,
                        f"{time.time() - t0:.1f}",
                        tail.replace("\t", " "),
                    ]
                )
            )
            print(
                f"{index}/{len(mutants)} L{m.line} {m.operator} {m.original!r}->{m.replacement!r}: {status}",
                flush=True,
            )
    finally:
        target.write_text(original, encoding="utf-8")
        if args.resign:
            _resign()
    if _sha(target) != original_sha:
        raise RuntimeError(f"{target} was not restored to its original digest")
    total = killed + survived + timed_out
    rate = (killed / (killed + survived)) if (killed + survived) else 0.0
    summary = (
        f"# target={args.target} tests={' '.join(args.tests)} self_run={args.self_run} "
        f"mutants={total} killed={killed} survived={survived} timeout={timed_out} "
        f"kill_rate={rate:.3f} wall_s={time.time() - started:.0f}"
    )
    out.write_text("\n".join(rows) + "\n" + summary + "\n", encoding="utf-8")
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
