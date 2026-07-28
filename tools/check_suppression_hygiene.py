#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""INVARIANT-13 enforcement: scan for unjustified static-analysis suppressions.

Exit codes:
    0  — all suppressions are justified
    1  — one or more violations found

Usage (CI):
    python tools/check_suppression_hygiene.py
"""

from __future__ import annotations

import io
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


def effective_suppressions(source: str) -> list[tuple[int, str]]:
    """Return ``(lineno, comment_text)`` for comments that actually suppress.

    Two filters, both of which the previous line-oriented scan lacked.

    **Comment text, not the whole line.** The scan used to collect the line
    *numbers* carrying a comment and then run the marker regex over the entire
    raw line, which put every string literal on such a line back in scope — the
    exact thing tokenizing was supposed to rule out. The comment token's own
    text is used here instead.

    **Trailing comments only.** ``bandit``, ``ruff`` and ``mypy`` all anchor a
    suppression to the line of the finding, so a full-line comment suppresses
    nothing; it is prose. That distinction never mattered while the scan
    covered only ``ama_cryptography/`` and ``tests/``, where nothing discusses
    markers in a comment. It matters immediately in ``tools/``, where the
    checkers *document their own subject matter*: eight comments explaining
    what a ``# nosec`` is were reported as unjustified suppressions the moment
    that tree was included. A gate that fires on its own documentation is one
    people learn to route around.

    The single standalone form that is real — mypy's file-level
    ``# type: ignore``, which must be the first line — is kept in scope
    explicitly rather than lost to the rule.
    """
    results: list[tuple[int, str]] = []
    try:
        lines = source.splitlines()
        readline = io.StringIO(source).readline
        for tok in tokenize.generate_tokens(readline):
            if tok.type != tokenize.COMMENT:
                continue
            lineno, col = tok.start
            physical = lines[lineno - 1] if lineno - 1 < len(lines) else ""
            trailing = bool(physical[:col].strip())
            file_level_type_ignore = lineno == 1 and tok.string.strip().startswith("# type: ignore")
            if trailing or file_level_type_ignore:
                results.append((lineno, tok.string))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return results  # unparseable file: report what was seen before the error
    return results


def check_source(filepath: str, source: str) -> list[str]:
    """Return violation messages for already-loaded Python ``source``."""
    violations: list[str] = []
    for lineno, comment in effective_suppressions(source):
        for m in _SUPPRESSION_RE.finditer(comment):
            tag = f"{filepath}:{lineno}"
            if _is_forbidden(filepath):
                violations.append(f"{tag}: suppression in forbidden directory")
                break
            rest = comment[m.end() :]
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
    return violations


def _scan_file(filepath: str) -> list[str]:
    """Return a list of violation messages for the given file."""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except (OSError, UnicodeDecodeError):
        return []  # skip unreadable files
    return check_source(filepath, source)


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    os.chdir(repo_root)

    # Collect all Python files under ama_cryptography/, tests/ and tools/.
    #
    # ``tools/`` was outside the scan until it was noticed that it holds the
    # gates themselves — the scripts whose whole purpose is to enforce this
    # repository's security policy. A suppression there silences a static
    # analyser inside the enforcement layer, which is the last place an
    # unexplained one belongs, and it was the only tree where they went
    # unpoliced. Two bare ``# noqa: S310`` markers were sitting in the corpus
    # fetchers when the scan was widened: no reason, no tracking ID, over
    # ``urllib`` calls that accepted ``file:`` and ``ftp:`` URLs. They now
    # check the scheme, so the suppression states a fact.
    targets = (
        list(Path("ama_cryptography").rglob("*.py"))
        + list(Path("tests").rglob("*.py"))
        + list(Path("tools").rglob("*.py"))
    )

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
