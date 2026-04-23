#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Verify that the AMA Cryptography version string matches in every file that
declares it.  Run as part of CI to block releases where one version was
bumped without the others (audit 5a).

The canonical source is ``ama_cryptography/__init__.py``'s ``__version__``.
Every other occurrence must match literally (no range operators, etc.).

Also verifies that the root ``INVARIANTS.md`` stays byte-identical to
``.github/INVARIANTS.md`` — we inlined the content to remove the unhelpful
one-line pointer (audit 6a), so CI must catch any future drift.

Exit code:
    0  all versions and invariants agree
    1  a mismatch was detected
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def extract(file: str, pattern: str) -> str | None:
    """Return the single capture group from `pattern`, or None if not found.

    The regex is evaluated in ``re.MULTILINE`` mode so ``^`` / ``$`` match
    individual line boundaries.  Every pattern below anchors the
    declaration to the start of its own line — either directly with
    ``^<literal>`` (setup.py ``VERSION``, pyproject ``version``, docs
    ``version`` / ``release``, package ``__version__``,
    ``#define AMA_CRYPTOGRAPHY_VERSION_STRING``) or via a stanza opener
    (``^project`` in ``CMakeLists.txt``, whose lazy ``[^)]*?`` then spans
    newlines to reach ``VERSION`` inside the call without crossing ``)``).
    This avoids matching substrings of unrelated version references such
    as a changelog note that mentions ``version =`` in prose.
    """
    text = _read(REPO / file)
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1) if match else None


def main() -> int:
    canonical = extract("ama_cryptography/__init__.py", r'^__version__\s*=\s*"([^"]+)"')
    if canonical is None:
        print(
            "ERROR: could not locate __version__ in ama_cryptography/__init__.py", file=sys.stderr
        )
        return 1

    # (file, regex-with-one-capture-group, description)
    checks = [
        ("setup.py", r'^VERSION\s*=\s*"([^"]+)"', "setup.py VERSION literal"),
        ("pyproject.toml", r'^version\s*=\s*"([^"]+)"', "pyproject.toml [project].version"),
        (
            "CMakeLists.txt",
            # Anchored to the ``^project(...)`` stanza (start-of-line
            # ``project`` keyword) so an unrelated
            # ``cmake_minimum_required(VERSION X.Y.Z)`` (if ever written
            # in 3-part form) cannot match first. ``[^)]*?`` is lazy and
            # spans newlines, so the expression reaches into a multi-line
            # ``project(AmaCryptography\n    VERSION 2.1.5\n    ...)``
            # block without crossing the closing parenthesis.
            r"^project\s*\([^)]*?VERSION\s+(\d+\.\d+\.\d+)",
            "CMakeLists.txt project() VERSION",
        ),
        ("docs/conf.py", r'^version\s*=\s*"([^"]+)"', "docs/conf.py version"),
        ("docs/conf.py", r'^release\s*=\s*"([^"]+)"', "docs/conf.py release"),
        (
            "include/ama_cryptography.h",
            # Anchored to ``^#define AMA_CRYPTOGRAPHY_VERSION_STRING``
            # so a commented-out reference or a prose mention of the
            # macro name elsewhere in the header cannot match first.
            r'^\s*#\s*define\s+AMA_CRYPTOGRAPHY_VERSION_STRING\s+"([^"]+)"',
            "include/ama_cryptography.h AMA_CRYPTOGRAPHY_VERSION_STRING",
        ),
    ]

    failures: list[str] = []
    for file, pattern, desc in checks:
        found = extract(file, pattern)
        if found is None:
            failures.append(f"  - {desc}: pattern not found in {file}")
        elif found != canonical:
            failures.append(f"  - {desc}: {found!r} != canonical {canonical!r} (in {file})")
        else:
            print(f"OK    {desc:<60s} = {found}")

    # Invariants sync check (audit 6a).
    root_inv = _read(REPO / "INVARIANTS.md")
    github_inv = _read(REPO / ".github" / "INVARIANTS.md")
    if root_inv != github_inv:
        failures.append(
            "  - INVARIANTS.md mismatch: root copy diverges from "
            ".github/INVARIANTS.md (see audit 6a)"
        )
    else:
        print("OK    INVARIANTS.md root <-> .github/INVARIANTS.md: identical")

    if failures:
        print(
            f"\nFAIL: canonical version = {canonical!r}\n" f"Mismatches:\n" + "\n".join(failures),
            file=sys.stderr,
        )
        return 1

    print(f"\nAll declarations agree on version {canonical!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
