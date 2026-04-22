#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""Verify that the AMA Cryptography version string matches in every file
that declares it.

Run as part of CI to block releases where one version declaration was
bumped without the others. The canonical source is
``ama_cryptography/__init__.py``'s ``__version__``; every other
occurrence must match literally (no range operators, no suffixes).

Exit code:
    0  all version declarations agree
    1  a mismatch was detected or a declaration was missing
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def extract(file: str, pattern: str) -> str | None:
    """Return the single capture group from ``pattern``, or ``None`` if
    the pattern does not match anywhere in the file.

    The regex runs in ``re.MULTILINE`` mode so ``^`` anchors to line
    starts — every pattern below pins the declaration to its own line
    to avoid matching an unrelated substring (for example a changelog
    note that contains ``version =``).
    """
    text = _read(REPO / file)
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1) if match else None


# (file, regex-with-one-capture-group, human-readable description)
_CHECKS: tuple[tuple[str, str, str], ...] = (
    (
        "setup.py",
        r'^VERSION\s*=\s*"([^"]+)"',
        "setup.py VERSION literal",
    ),
    (
        "pyproject.toml",
        r'^version\s*=\s*"([^"]+)"',
        "pyproject.toml [project].version",
    ),
    (
        "CMakeLists.txt",
        r"VERSION\s+(\d+\.\d+\.\d+)",
        "CMakeLists.txt project() VERSION",
    ),
    (
        "docs/conf.py",
        r'^version\s*=\s*"([^"]+)"',
        "docs/conf.py version",
    ),
    (
        "docs/conf.py",
        r'^release\s*=\s*"([^"]+)"',
        "docs/conf.py release",
    ),
    (
        "include/ama_cryptography.h",
        r'AMA_CRYPTOGRAPHY_VERSION_STRING\s+"([^"]+)"',
        "include/ama_cryptography.h AMA_CRYPTOGRAPHY_VERSION_STRING",
    ),
)


def main() -> int:
    canonical = extract(
        "ama_cryptography/__init__.py",
        r'^__version__\s*=\s*"([^"]+)"',
    )
    if canonical is None:
        print(
            "ERROR: could not locate __version__ in "
            "ama_cryptography/__init__.py",
            file=sys.stderr,
        )
        return 1

    failures: list[str] = []
    for file, pattern, desc in _CHECKS:
        found = extract(file, pattern)
        if found is None:
            failures.append(f"  - {desc}: pattern not found in {file}")
        elif found != canonical:
            failures.append(
                f"  - {desc}: {found!r} != canonical {canonical!r} (in {file})"
            )
        else:
            print(f"OK    {desc:<60s} = {found}")

    if failures:
        print(
            f"\nFAIL: canonical version = {canonical!r}\n"
            "Mismatches:\n" + "\n".join(failures),
            file=sys.stderr,
        )
        return 1

    print(f"\nAll declarations agree on version {canonical!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
