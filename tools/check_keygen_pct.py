#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""INVARIANT-41 enforcement: every keygen entry point runs its pairwise test.

FIPS 140-3 requires a pairwise consistency test before a freshly generated
keypair is released.  ``ama_cryptography/pqc_backends.py`` implements that with
``pairwise_test_signature`` / ``pairwise_test_kem`` / ``pairwise_test_agreement``
and calls one of them from each keygen path.

WHY THIS FILE EXISTS
====================

INVARIANTS.md claimed the wiring was enforced::

    **Enforcement.** `tests/test_keygen_pct.py` pins the wiring (every keygen
    entry point invokes its helper — a new keygen path that forgets the test
    fails the coverage assertion)

There is no coverage assertion of that kind.  The test monkeypatches the three
helpers into recorders, then calls a HAND-WRITTEN list of eleven entry points,
building its ``expected`` list alongside, and asserts ``recorded == expected``.
A newly added ``native_<x>_keypair()`` that omits its pairwise test is never
called by that test, so ``recorded`` and ``expected`` are both unchanged and the
assertion still holds.  The test proves the eleven paths it knows about are
wired; it cannot notice a twelfth.

That is the same shape INVARIANT-39 had before
``tools/check_error_state_gating.py``, and this is the same answer: enumerate
the surface from the module's own AST and fail on any entry point that does not
reach a helper.  The list is discovered, so a new keygen path is covered the
day it is added rather than the day someone remembers to add it here.

WHAT COUNTS AS REACHING THE HELPER
----------------------------------

A direct call in the function body, or a call in a private helper the function
invokes — one level of delegation, and only when that helper itself calls a
pairwise test.  ``AmaContext`` generates its keypairs through
``_keypair_pairwise_test``, which is exactly that shape.  Deeper chains are not
followed: a gate that traces arbitrarily far stops being checkable by reading
it, and nothing in this module needs more than one hop.

A function that dispatches on key family — ``if kem: pairwise_test_kem(...)
else: pairwise_test_signature(...)`` — releases a keypair from EVERY arm, so
every arm of such a conditional must run a pairwise test or raise.  Name-set
matching alone cannot see one arm going dark: the function still calls
``pairwise_test_kem`` somewhere, so it still "reaches a helper".  Measured
before this rule existed, by planting the defect and re-running the gate:
replacing the signature arm's call in ``_keypair_pairwise_test`` with a no-op
left this gate at exit 0 while ``AmaContext.keypair_generate`` released
untested ML-DSA, SLH-DSA and hybrid keypairs.  Only explicit arms are judged
(``if``/``elif``/``else`` and ``match`` cases) are named line by line.

EVERY PATH, NOT SOME PATH
-------------------------

Name-set matching asked "does a pairwise test appear anywhere in the body",
and the arm rule above only compared arms that both exist.  An ``if`` with no
``else`` was never judged, so wrapping the call in
``if os.environ.get("AMA_SKIP_PCT") is None:`` — a keypair released untested
whenever the variable is set — passed.  So did an early ``return pk, sk`` ahead
of the test.

Each entry point (and each delegated helper) must now reach a pairwise test on
every path through the constructs that CONTAIN one, which
:func:`pct_on_every_path` decides by a small structural path walk: a missing
``else`` is an empty arm that falls through to the statements after the
``if``; a ``with``/``try`` body runs in-line (``finally`` too, and each
``except`` handler is its own path); a loop body may run zero times; a
``match`` with no irrefutable case may match nothing.  A path ends well at a
pairwise test (or a delegated helper) or at a ``raise``; it ends badly at a
``return`` or by falling off the end of the body.  Conditions are not
evaluated — ``if rc == 0:`` is as conditional as ``if os.environ.get(...)``:
a test the function can skip is a test the function can skip, and the fix is
to leave the function on the failure path first (``if rc != 0: return rc`` or
``raise``) and then run the test unconditionally, not to teach the gate which
conditions are benign.  Nested ``def``/``lambda`` bodies are not paths of the
enclosing function: defining a callable that would run the test is not running
it.

Stated limit: a construct with NO pairwise test in it is not judged, so an
early ``return`` in such a construct (``if bad_len: return -1``) is accepted.
Those are the input-validation and failure exits that precede key generation,
and separating them from ``if flag: return pk, sk`` needs to know where key
material comes into existence, which this gate does not model.

Exit codes
----------
* 0 — every discovered keygen entry point reaches a pairwise test.
* 1 — at least one does not, or the scan found nothing (fail-closed).
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: The module that owns every native keygen entry point.
BACKEND = "ama_cryptography/pqc_backends.py"

#: The three helpers.  Any one of them satisfies the invariant; which one is
#: correct for a given family is the family's own business and is pinned by
#: ``tests/test_keygen_pct.py``.
PCT_HELPERS = frozenset({"pairwise_test_signature", "pairwise_test_kem", "pairwise_test_agreement"})

#: Name fragments that make a function a keygen entry point.
_KEYGEN_MARKERS = ("keypair", "keygen")

#: Entry points that are NOT keygen paths, each with the reason.  A name-based
#: scan needs this; the alternative — a hand-maintained inventory of the paths
#: that ARE keygens — is the thing this gate exists to replace.
EXEMPT: dict[str, str] = {
    "_setup_deterministic_keygen_ctypes": (
        "declares ctypes argtypes/restype for the deterministic keygen symbols; "
        "it generates no key material"
    ),
    "_keypair_pairwise_test": (
        "IS the delegated helper — AmaContext.keypair_generate calls it — so "
        "counting it as an entry point would count the check as a thing that "
        "needs checking"
    ),
}

#: Floor under discovery.  A scan that finds two entry points has broken, and
#: reporting a clean run over it is the failure this gate exists to prevent.
MIN_ENTRY_POINTS = 10

#: The Cython binding sources.  Their keygens are importable, gated entry
#: points of the package like the ones above, and two of them released
#: keypairs with no pairwise test until 2026-09-24 because this gate read
#: ``pqc_backends.py`` alone.  Cython is not Python, so they are read by
#: indentation rather than by ``ast`` (see :func:`pyx_keygens_without_pct`).
PYX_GLOB = "src/cython/*.pyx"

#: The binding keygens known to exist; discovery finding fewer means the scan
#: of the ``.pyx`` sources broke, not that the keygens went away.
MIN_PYX_ENTRY_POINTS = 2


def _calls(node: ast.AST) -> set[str]:
    """Every plain function name called anywhere under ``node``."""
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


def _terminates(arm: list[ast.stmt]) -> bool:
    """True when ``arm`` ends by raising: no keypair leaves through it."""
    return bool(arm) and isinstance(arm[-1], ast.Raise)


def arms_without_pct(node: ast.AST) -> list[int]:
    """Line numbers of conditional arms that skip the test a sibling arm runs.

    Judged for every ``if``/``else`` and ``match`` under ``node`` in which at
    least one arm calls a pairwise test.  An arm passes when it calls one too
    or ends in ``raise``; anything else is a path that releases the keypair
    untested.  See "WHAT COUNTS AS REACHING THE HELPER" in the module
    docstring for why name matching cannot do this and for the stated limit.
    """
    missing: list[int] = []
    for child in ast.walk(node):
        arms: list[list[ast.stmt]]
        if isinstance(child, ast.If):
            if not child.orelse:
                continue
            arms = [child.body, child.orelse]
        elif isinstance(child, ast.Match):
            arms = [case.body for case in child.cases]
        else:
            continue
        tested = [any(_calls(stmt) & PCT_HELPERS for stmt in arm) for arm in arms]
        if not any(tested):
            continue
        for arm, ok in zip(arms, tested):
            if not ok and not _terminates(arm):
                missing.append(arm[0].lineno)
    return sorted(missing)


def _direct_calls(node: ast.AST) -> set[str]:
    """Names called by ``node`` itself — nested ``def``/``lambda``/class bodies excluded.

    A call inside a lambda or a nested function runs only when THAT callable
    is invoked, so it is not evidence that the enclosing statement runs it.
    """
    names: set[str] = set()
    stack: list[ast.AST] = [node]
    while stack:
        current = stack.pop()
        if current is not node and isinstance(
            current, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            continue
        if isinstance(current, ast.Call):
            func = current.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
        stack.extend(ast.iter_child_nodes(current))
    return names


def _is_irrefutable(case: ast.match_case) -> bool:
    """A ``case _:`` / ``case name:`` with no guard matches every subject."""
    pattern = case.pattern
    return case.guard is None and isinstance(pattern, ast.MatchAs) and pattern.pattern is None


_TryParts = tuple[list[ast.stmt], list[ast.stmt], list[ast.stmt], list[ast.ExceptHandler]]


def _try_parts(stmt: ast.stmt) -> _TryParts | None:
    """``(body, orelse, finalbody, handlers)`` of a ``try`` / ``try*``, else ``None``."""
    if isinstance(stmt, ast.Try):
        return stmt.body, stmt.orelse, stmt.finalbody, stmt.handlers
    if sys.version_info >= (3, 11) and isinstance(stmt, ast.TryStar):
        return stmt.body, stmt.orelse, stmt.finalbody, stmt.handlers
    return None


def _first_untested_exit(
    stmts: list[ast.stmt],
    tests: frozenset[str],
    loop_exit: list[ast.stmt] | None,
    end_line: int,
) -> int | None:
    """Line of a path through ``stmts`` that ends without a pairwise test.

    ``None`` means every path reaches a call in ``tests`` or a ``raise``.
    ``loop_exit`` is what runs after ``break``/``continue`` inside a loop body;
    ``end_line`` is reported when a path falls off the end of the body.
    """
    for index, stmt in enumerate(stmts):
        rest = stmts[index + 1 :]
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue  # a definition runs nothing
        if (
            not isinstance(stmt, (ast.Raise, ast.Return, ast.Break, ast.Continue))
            and not _direct_calls(stmt) & tests
        ):
            # A construct that runs no pairwise test anywhere is not judged:
            # its early exits are the input-validation / failure returns that
            # precede key generation, which this gate cannot tell apart from a
            # release (see the stated limit in the module docstring).
            continue
        if isinstance(stmt, ast.Raise):
            return None
        if isinstance(stmt, ast.Return):
            if stmt.value is not None and _direct_calls(stmt.value) & tests:
                return None
            return stmt.lineno
        if isinstance(stmt, (ast.Break, ast.Continue)):
            if loop_exit is None:
                return stmt.lineno
            return _first_untested_exit(loop_exit, tests, None, end_line)
        if isinstance(stmt, ast.If):
            if _direct_calls(stmt.test) & tests:
                return None
            for arm in (stmt.body, stmt.orelse):
                line = _first_untested_exit(arm + rest, tests, loop_exit, end_line)
                if line is not None:
                    return line
            return None
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            if any(_direct_calls(item.context_expr) & tests for item in stmt.items):
                return None
            return _first_untested_exit(stmt.body + rest, tests, loop_exit, end_line)
        parts = _try_parts(stmt)
        if parts is not None:
            body, orelse, finalbody, handlers = parts
            if finalbody and _first_untested_exit(finalbody, tests, None, end_line) is None:
                return None  # `finally` runs on every path out of the try
            paths = [body + orelse + finalbody + rest]
            paths.extend(handler.body + finalbody + rest for handler in handlers)
            for path in paths:
                line = _first_untested_exit(path, tests, loop_exit, end_line)
                if line is not None:
                    return line
            return None
        if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            header = stmt.test if isinstance(stmt, ast.While) else stmt.iter
            if _direct_calls(header) & tests:
                return None
            after = stmt.orelse + rest
            # Zero iterations, and one iteration followed by leaving the loop.
            for path, exit_path in ((after, loop_exit), (stmt.body + after, rest)):
                line = _first_untested_exit(path, tests, exit_path, end_line)
                if line is not None:
                    return line
            return None
        if isinstance(stmt, ast.Match):
            if _direct_calls(stmt.subject) & tests:
                return None
            paths = [case.body + rest for case in stmt.cases]
            if not any(_is_irrefutable(case) for case in stmt.cases):
                paths.append(rest)
            for path in paths:
                line = _first_untested_exit(path, tests, loop_exit, end_line)
                if line is not None:
                    return line
            return None
        if _direct_calls(stmt) & tests:
            return None
    return end_line


def pct_on_every_path(
    node: ast.FunctionDef | ast.AsyncFunctionDef, tests: frozenset[str]
) -> int | None:
    """``None`` when every path through ``node`` runs a call in ``tests`` or raises.

    Otherwise the line at which the first untested path leaves the function
    (a ``return``, or the function's last line when it falls off the end).
    See "EVERY PATH, NOT SOME PATH" in the module docstring.
    """
    end_line = node.end_lineno if node.end_lineno is not None else node.lineno
    return _first_untested_exit(node.body, tests, None, end_line)


def pct_delegating_helpers(tree: ast.AST) -> set[str]:
    """Functions and methods whose body calls a pairwise test on every path.

    Collected across the whole module, methods included, so a keygen that
    delegates to ``self._keypair_pairwise_test`` is recognised.  A helper
    with a conditional arm that skips the test is not a helper — delegating
    to it proves nothing for the family that arm serves.
    """
    helpers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if pct_on_every_path(node, PCT_HELPERS) is None and not arms_without_pct(node):
                helpers.add(node.name)
    return helpers


def keygen_entry_points(
    tree: ast.AST,
) -> list[tuple[str, int, ast.FunctionDef | ast.AsyncFunctionDef]]:
    """``(name, lineno, node)`` for every keygen entry point in the module.

    Module-level functions and public methods alike: a keypair released from a
    class is released just the same.
    """
    out: list[tuple[str, int, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        lowered = node.name.lower()
        if not any(marker in lowered for marker in _KEYGEN_MARKERS):
            continue
        if node.name in EXEMPT:
            continue
        out.append((node.name, node.lineno, node))
    return sorted(out, key=lambda item: item[1])


def audit(path: Path) -> tuple[list[tuple[str, int]], int]:
    """``(unwired entry points, number examined)`` for one module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    helpers = pct_delegating_helpers(tree)
    unwired: set[tuple[str, int]] = set()
    entry_points = keygen_entry_points(tree)
    tests = PCT_HELPERS | frozenset(helpers)
    for name, lineno, node in entry_points:
        dark_arms = arms_without_pct(node)
        for arm_line in dark_arms:
            unwired.add((f"{name} [conditional arm]", arm_line))
        if dark_arms:
            continue  # the arm lines already say where the untested path is
        if not _calls(node) & tests:
            unwired.add((name, lineno))
            continue
        exit_line = pct_on_every_path(node, tests)
        if exit_line is not None:
            unwired.add((f"{name} [path skips the test]", exit_line))
    # A delegated helper with a dark arm is named as well as its callers, so
    # the diagnostic points at the line to fix and not only at its effect.
    for candidate in ast.walk(tree):
        if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _calls(candidate) & PCT_HELPERS:
                for arm_line in arms_without_pct(candidate):
                    unwired.add((f"{candidate.name} [conditional arm]", arm_line))
    return sorted(unwired, key=lambda item: (item[1], item[0])), len(entry_points)


def pyx_keygens_without_pct(text: str) -> tuple[list[tuple[str, int, str]], int]:
    """``(problems, examined)`` for one Cython source.

    A keygen is a top-level ``def`` whose name carries a keygen marker.  It
    passes when a pairwise-test call is one of its TOP-LEVEL statements (so it
    runs on every path that reaches it, never inside an ``if``) and every
    ``return`` in the function comes after that call (so no path leaves with
    the keypair first).  Indentation is Cython's block structure, so reading
    it is exact for the one shape these functions have; anything the rule
    cannot see as unconditional is reported, not assumed.
    """
    lines = text.splitlines()
    problems: list[tuple[str, int, str]] = []
    examined = 0
    i = 0
    while i < len(lines):
        header = lines[i]
        if not header.startswith("def ") or not any(m in header for m in _KEYGEN_MARKERS):
            i += 1
            continue
        name = header[4:].split("(", 1)[0].strip()
        start = i + 1
        end = start
        while end < len(lines) and (
            not lines[end].strip() or lines[end][0] in " \t" or lines[end].startswith("#")
        ):
            end += 1
        examined += 1
        body = list(enumerate(lines[start:end], start=start + 1))
        helpers = tuple(f"{h}(" for h in PCT_HELPERS)
        pct_line = next(
            (
                n
                for n, line in body
                if line.startswith("    ")
                and not line.startswith("     ")
                and line.strip().startswith(helpers)
            ),
            None,
        )
        returns = [n for n, line in body if line.strip().startswith("return")]
        if pct_line is None:
            problems.append((name, i + 1, "no unconditional pairwise test"))
        elif any(n < pct_line for n in returns):
            problems.append((name, i + 1, "returns before the pairwise test"))
        i = end
    return problems, examined


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(REPO), help="repository root")
    args = parser.parse_args(argv)
    root = Path(args.root)

    path = root / BACKEND
    if not path.is_file():
        print(f"FATAL: {BACKEND} is missing; the scan has no scope.", file=sys.stderr)
        return 1

    unwired, examined = audit(path)

    if examined < MIN_ENTRY_POINTS:
        print(
            f"FATAL: discovered only {examined} keygen entry point(s) in {BACKEND} "
            f"(expected at least {MIN_ENTRY_POINTS}). An empty or collapsed scope "
            f"is a checker fault, not a clean tree.",
            file=sys.stderr,
        )
        return 1

    if unwired:
        print(
            f"INVARIANT-41 violation: {len(unwired)} keygen entry point(s) release a "
            f"keypair without a pairwise consistency test:",
            file=sys.stderr,
        )
        for name, lineno in unwired:
            print(f"  {BACKEND}:{lineno}: {name}()", file=sys.stderr)
        print(
            "\nCall pairwise_test_signature / pairwise_test_kem / "
            "pairwise_test_agreement before the keypair is returned, or delegate "
            "to a helper that does. A conditional arm named above is a path that "
            "releases the keypair without the test its sibling arm runs: give it "
            "the family's test, or make it raise. A '[path skips the test]' line "
            "is where a path leaves the function without the test having run on "
            "it — typically a pairwise test inside an `if` with no `else` (e.g. "
            "`if rc == 0:`) or a `return` that bypasses a test run on another "
            "path: leave on the failure path first (`if rc != 0: return rc`, or "
            "raise) and run the test unconditionally. If the function generates no "
            "key material, add it to EXEMPT in this file with the reason.",
            file=sys.stderr,
        )
        return 1

    pyx_problems: list[tuple[str, str, int, str]] = []
    pyx_examined = 0
    for pyx in sorted(root.glob(PYX_GLOB)):
        found, count = pyx_keygens_without_pct(pyx.read_text(encoding="utf-8"))
        pyx_examined += count
        rel = pyx.relative_to(root).as_posix()
        pyx_problems.extend((rel, name, line, why) for name, line, why in found)
    if pyx_examined < MIN_PYX_ENTRY_POINTS:
        print(
            f"FATAL: discovered only {pyx_examined} keygen entry point(s) in {PYX_GLOB} "
            f"(expected at least {MIN_PYX_ENTRY_POINTS}); the binding scan broke.",
            file=sys.stderr,
        )
        return 1
    if pyx_problems:
        print(
            f"INVARIANT-41 violation: {len(pyx_problems)} Cython keygen(s) release a "
            "keypair without an unconditional pairwise consistency test:",
            file=sys.stderr,
        )
        for rel, name, line, why in pyx_problems:
            print(f"  {rel}:{line}: {name}() — {why}", file=sys.stderr)
        print(
            "\nCall pairwise_test_signature / pairwise_test_kem / "
            "pairwise_test_agreement as a top-level statement of the function, "
            "after the keypair is built and before any return.",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: {examined} keygen entry point(s) in {BACKEND} and {pyx_examined} in "
        f"{PYX_GLOB}; every one reaches a pairwise consistency test."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
