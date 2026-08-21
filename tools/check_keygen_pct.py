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


def pct_delegating_helpers(tree: ast.AST) -> set[str]:
    """Functions and methods whose body calls a pairwise test.

    Collected across the whole module, methods included, so a keygen that
    delegates to ``self._keypair_pairwise_test`` is recognised.
    """
    helpers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _calls(node) & PCT_HELPERS:
                helpers.add(node.name)
    return helpers


def keygen_entry_points(tree: ast.AST) -> list[tuple[str, int, ast.AST]]:
    """``(name, lineno, node)`` for every keygen entry point in the module.

    Module-level functions and public methods alike: a keypair released from a
    class is released just the same.
    """
    out: list[tuple[str, int, ast.AST]] = []
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
    unwired: list[tuple[str, int]] = []
    entry_points = keygen_entry_points(tree)
    for name, lineno, node in entry_points:
        called = _calls(node)
        if called & PCT_HELPERS:
            continue
        if called & helpers:
            continue
        unwired.append((name, lineno))
    return unwired, len(entry_points)


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
            "to a helper that does. If the function generates no key material, "
            "add it to EXEMPT in this file with the reason.",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: {examined} keygen entry point(s) in {BACKEND}; every one reaches a "
        f"pairwise consistency test."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
