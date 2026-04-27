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
import tokenize
from pathlib import Path

# Suppression tokens to scan for.
#
# ``nosemgrep`` is included here because INVARIANT-13 is worded "any
# equivalent suppression marker"; semgrep is part of the same defence-in-
# depth stack as bandit/ruff/mypy and the same tracking-ID + justification
# requirements apply.  Devin reviews #19/#20/#21/#22 (PR #277) caught four
# ``nosemgrep`` markers that lacked tracking IDs; extending the scanner is
# the regression check that would have caught those at PR-review time.
#
# Two-stage matching:
#   1. ``_SUPPRESSION_RE`` matches *any* suppression marker — including a
#      bare ``# nosemgrep`` with no rule id — so the line is always
#      flagged for the tracking-ID + justification pass.
#   2. For the ``nosemgrep`` family specifically, ``_NOSEMGREP_STRICT_RE``
#      then asserts the line-targeted form ``# nosemgrep: <rule_id>``
#      (Copilot review @ tools/check_suppression_hygiene.py:34).  Bare
#      ``# nosemgrep`` blanket-suppresses every rule on the line, which
#      is exactly the kind of catch-all the INVARIANT-13 audit trail is
#      meant to prevent.  Semgrep itself accepts both forms; this repo
#      requires the colon + rule id form so reviewers can verify *which*
#      rule each suppression silences.
_SUPPRESSION_RE = re.compile(r"#\s*(noqa|nosec|nosemgrep|pylint:\s*disable|type:\s*ignore)")
_NOSEMGREP_STRICT_RE = re.compile(r"^:\s*\S+")

# Tracking ID pattern: parenthesised alphanumeric tag, e.g. (KM-001), (FIN-002)
_TRACKING_ID_RE = re.compile(r"\([A-Z]+-\d+\)")

# Justification: an em-dash, double-hyphen, or inline comment (# ...) followed by text.
# The inline-comment form is required for ``type: ignore`` because mypy >=1.20
# rejects em-dashes inside the ``# type: ignore[code]`` directive.
_JUSTIFICATION_RE = re.compile(r"[\u2014\u2013]|--|#\s*\S")

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


def _get_comment_lines(filepath: str) -> set[int]:
    """Return the set of line numbers that contain real comments (via tokenize).

    This correctly handles triple-quoted strings, raw strings, and f-strings —
    only ``tokenize.COMMENT`` tokens are returned, never string content.
    """
    comment_lines: set[int] = set()
    try:
        with open(filepath, "rb") as fh:
            for tok in tokenize.tokenize(fh.readline):
                if tok.type == tokenize.COMMENT:
                    comment_lines.add(tok.start[0])
    except (OSError, tokenize.TokenError, SyntaxError):
        pass  # skip unreadable / unparseable files
    return comment_lines


def _scan_file(filepath: str) -> list[str]:
    """Return a list of violation messages for the given file."""
    violations: list[str] = []
    comment_lines = _get_comment_lines(filepath)
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                if lineno not in comment_lines:
                    continue
                for m in _SUPPRESSION_RE.finditer(line):
                    tag = f"{filepath}:{lineno}"
                    if _is_forbidden(filepath):
                        violations.append(f"{tag}: suppression in forbidden directory")
                        break
                    rest = line[m.end() :]
                    # nosemgrep strict form: require ":<rule_id>" so the
                    # marker targets a specific rule rather than blanket-
                    # suppressing every semgrep rule on the line.
                    if m.group(1) == "nosemgrep" and not _NOSEMGREP_STRICT_RE.match(rest):
                        violations.append(
                            f"{tag}: suppression 'nosemgrep' missing rule id "
                            f"(expected '# nosemgrep: <rule_id> -- justification (TAG-NNN)')"
                        )
                        continue
                    if not _JUSTIFICATION_RE.search(rest):
                        violations.append(
                            f"{tag}: suppression '{m.group()}' missing justification "
                            f"(expected em-dash, --, or # followed by reason and tracking ID)"
                        )
                    elif not _TRACKING_ID_RE.search(rest):
                        violations.append(
                            f"{tag}: suppression '{m.group()}' missing tracking ID "
                            f"(expected e.g. (KM-001))"
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
