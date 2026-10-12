#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Generate the secret-holder inventory (``docs/SECRET_HOLDER_INVENTORY.md``).

PR #415's ``7a9283a8`` round found three holders that dropped their secret
unzeroed, through two scratch scans that were never committed — so no
mechanism held the property once the branch merged.  This instrument is
those scans, committed, producing the reviewed inventory AGENTS.md §10
prescribes where a blocking gate would need a standing exemption list:
``tests/test_secret_holder_inventory.py`` fails when the committed page
drifts from the tree, so a NEW row — a new holder class or a new bare-local
producer binding — cannot land without the diff showing it for review.

The two scans, and their stated limits (pattern, not proof)
-----------------------------------------------------------
1. **Secret-named attributes outside ``SecretMaterial``** — every class in
   the package that assigns a secret-named attribute (``*secret*``,
   ``*seed*``, ``*private*``, ``*_sk``, ``*password*``, ``*chain_code*``,
   or ``*_key``/``key`` without ``public``/``pub``/``verify`` in the name)
   on ``self`` while neither subclassing ``SecretMaterial`` nor declaring
   ``_SECRET_ATTRS``.  A row is a question for review, not a finding: the
   attribute may hold a public structure, a path, or a borrowed buffer the
   caller owns.
2. **Producer results bound to a bare local** — every module-level or
   function-level ``name = producer(...)`` where the producer is one of
   the library's secret mints (``secure_token_bytearray``,
   ``secure_random_bytes``, ``secure_random_fill`` targets aside, the
   ``native_*_keypair`` family, ``native_hkdf*``, ``native_ml_kem_*``,
   ``derive_key``).  A bare local is how ``7a9283a8``'s three defects
   looked; a row here is covered when the local is adopted by a guard, a
   ``finally`` or an owner before any raising step — which only reading
   the site establishes.

Name-pattern scans see neither aliasing nor dataflow; both scans
deliberately over-report so review sees every candidate.

Usage
-----
``python tools/measure_secret_holders.py --check`` (the default) exits 1
when the committed page does not match the tree; ``--write`` regenerates.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path
from typing import Sequence

REPO = Path(__file__).resolve().parent.parent
DOC = REPO / "docs" / "SECRET_HOLDER_INVENTORY.md"
PACKAGE = REPO / "ama_cryptography"

_SECRETISH = re.compile(r"secret|seed|private|_sk$|^sk_|password|chain_code", re.IGNORECASE)
_KEYISH = re.compile(r"(^|_)key(_|$)|_key$|^key$", re.IGNORECASE)
_PUBLICISH = re.compile(r"public|pub_|_pub|verify", re.IGNORECASE)

#: The library's secret producers for scan 2, by callable name.
PRODUCERS = (
    "secure_token_bytearray",
    "secure_random_bytes",
    "generate_keypair",
    "derive_key",
)
_PRODUCER_PREFIXES = ("native_", "generate_")


def _is_secret_name(name: str) -> bool:
    if _PUBLICISH.search(name):
        return False
    return bool(_SECRETISH.search(name) or _KEYISH.search(name))


def _callable_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _is_producer(func: ast.AST) -> bool:
    name = _callable_name(func)
    if name is None:
        return False
    if name in PRODUCERS:
        return True
    return name.startswith(_PRODUCER_PREFIXES) and (
        "keypair" in name or "hkdf" in name or "ml_kem" in name or "x25519" in name
    )


def _class_rows(tree: ast.Module, rel: str) -> list[str]:
    rows: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        bases = {
            base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
            for base in node.bases
        }
        if "SecretMaterial" in bases:
            continue
        declares_secret_attrs = any(
            isinstance(stmt, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "_SECRET_ATTRS" for t in stmt.targets)
            for stmt in node.body
        )
        if declares_secret_attrs:
            continue
        names: set[str] = set()
        for sub in ast.walk(node):
            if isinstance(sub, (ast.Assign, ast.AnnAssign)):
                targets = sub.targets if isinstance(sub, ast.Assign) else [sub.target]
                for target in targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                        and _is_secret_name(target.attr)
                    ):
                        names.add(target.attr)
        if names:
            rows.append(
                f"| `{rel}` | `{node.name}` | {', '.join(f'`{n}`' for n in sorted(names))} |"
            )
    return rows


def _producer_rows(tree: ast.Module, rel: str) -> list[str]:
    rows: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        if not _is_producer(node.value.func):
            continue
        plain = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not plain:
            continue
        producer = _callable_name(node.value.func)
        if producer is None:
            continue
        rows.append(
            f"| `{rel}:{node.lineno}` | `{producer}` | {', '.join(f'`{n}`' for n in plain)} |"
        )
    return rows


def render(root: Path) -> str:
    class_rows: list[str] = []
    producer_rows: list[str] = []
    package = root / "ama_cryptography"
    for path in sorted(package.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        class_rows.extend(_class_rows(tree, rel))
        producer_rows.extend(_producer_rows(tree, rel))

    lines = [
        "# Secret-Holder Inventory",
        "",
        "Generated by `tools/measure_secret_holders.py --write`; do not edit by",
        "hand.  `tests/test_secret_holder_inventory.py` fails when this page",
        "drifts from the tree, so a new row — a new candidate holder class or a",
        "new bare-local producer binding — cannot land without its diff being",
        "reviewed.  A row is a candidate for review, not a finding: the scans",
        "are by name pattern, see neither aliasing nor dataflow, and",
        "deliberately over-report (the tool's docstring states the limits).",
        "The rows below are the reviewed state of the tree: each was read and",
        "is covered by `SecretMaterial` adoption, a scrub guard or `finally`,",
        "a native wrapper that zeroes on every exit, borrowed storage a caller",
        "owns, or holds no secret despite its name.",
        "",
        "## Classes assigning secret-named attributes outside `SecretMaterial`",
        "",
        "| Module | Class | Attributes |",
        "|---|---|---|",
        *class_rows,
        "",
        "## Producer results bound to a bare local",
        "",
        "| Site | Producer | Bound names |",
        "|---|---|---|",
        *producer_rows,
        "",
        "## Counts",
        "",
        f"- Candidate holder classes: **{len(class_rows)}**",
        f"- Bare-local producer bindings: **{len(producer_rows)}**",
        "",
    ]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write", action="store_true", help="regenerate docs/SECRET_HOLDER_INVENTORY.md"
    )
    args = parser.parse_args(argv)
    page = render(REPO)
    if args.write:
        DOC.write_text(page, encoding="utf-8")
        print(f"wrote {DOC.relative_to(REPO)}")
        return 0
    current = DOC.read_text(encoding="utf-8") if DOC.exists() else ""
    if current != page:
        print(
            "FAIL: docs/SECRET_HOLDER_INVENTORY.md does not match the tree; a "
            "new or moved candidate row needs review — regenerate with: "
            "python tools/measure_secret_holders.py --write",
            file=sys.stderr,
        )
        return 1
    print("OK: docs/SECRET_HOLDER_INVENTORY.md matches the tree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
