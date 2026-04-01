#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""INVARIANT-13 enforcement: scan for unjustified static-analysis suppressions.

Exit codes:
    0  — all suppressions are justified
    1  — one or more violations found

Usage (CI):
    python tools/check_suppression_hygiene.py
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# Suppression tokens to scan for
_SUPPRESSION_RE = re.compile(r"#\s*(noqa|nosec|pylint:\s*disable|type:\s*ignore)")

# Tracking ID pattern: parenthesised alphanumeric tag, e.g. (KM-001), (FIN-002)
_TRACKING_ID_RE = re.compile(r"\([A-Z]+-\d+\)")

# Justification: an em-dash or double-hyphen followed by text
_JUSTIFICATION_RE = re.compile(r"[\u2014\u2013]|--")

# Forbidden directories: suppressions are absolutely prohibited here
_FORBIDDEN_DIRS: tuple[str, ...] = (
    "src/c/",
    "ama_cryptography/_primitive",
    "ama_cryptography/backend",
    "include/",
)


def _is_forbidden(filepath: str) -> bool:
    """Return True if the file lives under a forbidden directory."""
    for d in _FORBIDDEN_DIRS:
        if filepath.startswith(d) or f"/{d}" in filepath:
            return True
    return False


def _is_in_string(line: str, match_start: int) -> bool:
    """Heuristic: return True if position is inside a string literal."""
    in_single = False
    in_double = False
    i = 0
    while i < match_start:
        ch = line[i]
        if ch == "\\" and i + 1 < match_start:
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        i += 1
    return in_single or in_double


def _scan_file(filepath: str) -> list[str]:
    """Return a list of violation messages for the given file."""
    violations: list[str] = []
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                m = _SUPPRESSION_RE.search(line)
                if m is None:
                    continue

                # Skip suppression tokens that appear inside string literals
                if _is_in_string(line, m.start()):
                    continue

                tag = f"{filepath}:{lineno}"

                # Check forbidden directories
                if _is_forbidden(filepath):
                    violations.append(f"{tag}: suppression in forbidden directory")
                    continue

                # Check for justification text
                rest = line[m.end() :]
                if not _JUSTIFICATION_RE.search(rest):
                    violations.append(
                        f"{tag}: suppression missing justification "
                        f"(expected em-dash/-- followed by reason)"
                    )
                    continue

                # Check for tracking ID
                if not _TRACKING_ID_RE.search(rest):
                    violations.append(
                        f"{tag}: suppression missing tracking ID " f"(expected e.g. (KM-001))"
                    )
    except (OSError, UnicodeDecodeError):
        pass  # skip unreadable files
    return violations


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    os.chdir(repo_root)

    # Collect all Python files under ama_cryptography/ and tests/
    targets = list(Path("ama_cryptography").rglob("*.py")) + list(Path("tests").rglob("*.py"))

    all_violations: list[str] = []
    for path in sorted(targets):
        filepath = str(path)
        all_violations.extend(_scan_file(filepath))

    if all_violations:
        print(f"INVARIANT-13 violations ({len(all_violations)}):\n")
        for v in all_violations:
            print(f"  {v}")
        print(f"\n{len(all_violations)} suppression(s) need justification + tracking ID.")
        return 1

    print("INVARIANT-13: all suppressions are properly justified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
