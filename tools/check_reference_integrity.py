#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Reject citations a reader cannot resolve.

Why
---
A comment that cites a source is making a promise: the thing it names can be
looked up. Two citation shapes in this tree could not be, and both had already
gone wrong by the time they were found.

**Process citations.** Eighteen comments in the shipped package cited
``(2026-08 v5 audit, item 15)``. No such document exists anywhere in the
repository — not in ``docs/``, not in ``CHANGELOG.md``, nowhere. All eighteen
carried the same item number while describing five unrelated defects
(alert-window suppression, a clock-step wedge, rotation accounting, a skipped
liveness check, note-artifact evasion), so the number was a decoration that
looked like a reference. A maintainer reading ``adaptive_posture.py`` in 2027
had no way to discover that, and no way to look it up.

**Source-line citations.** Three comments cited a line number.
``secure_channel.py`` said "the AEAD nonce at line 632"; line 632 had drifted
onto a ``raise SessionExpiredError``. The other two were still accurate and
were still wrong to write, because nothing could tell anyone when they stopped
being accurate. A line number is a reference with no name attached: the only
thing that keeps it true is that nobody edits above it.

Both are the failure mode INVARIANT-37 names for APIs, applied to prose: a
claim that presents itself as checkable while being unverifiable. The remedy is
the same one this repository applies everywhere else — cite something that has
a name, or state the fact directly.

What is checked
---------------
Over the shipped tree (``ama_cryptography/``, ``src/``, ``include/``,
``tools/``, ``tests/``, ``docs/`` and the root Markdown documents):

1. **Unresolvable process citations** — a dated internal audit
   (``2026-08 v5 audit``) or an "item N of the audit". Neither names anything a
   reader of the repository can open. Where the finding matters, state it;
   where its provenance matters, cite a commit or an ``INVARIANT-N``, both of
   which resolve.
2. **Source-line citations** — ``at line 632``, ``see lines 314 and 339``. Cite
   the identifier, the marker, or the function instead; those move with the
   code.

What is deliberately NOT checked
--------------------------------
``CHANGELOG.md`` is exempt, and the exemption is the point rather than a
convenience: it is a historical record. Its entries describe the tree as it
stood when they were written, and editing them to satisfy a present-day linter
would falsify the one file whose value is that it was not revised. A stale
reference in a changelog is a fact about the past; the same reference in
``ama_cryptography/session.py`` is a defect in the present.

This module and its test are exempt for a duller reason: both have to quote the
rejected shapes in order to reject them.  That is still a hole, so the test
asserts the list is exactly these three entries and that each genuinely contains
a rejected shape.  An exemption that stops being needed fails the suite instead
of lingering as a place to hide things.

This gate checks the *shape* of a citation, not its truth. It cannot tell that
``INVARIANT-41`` is the right invariant to cite, only that a reader can find
it. Truth is what review is for; resolvability is what this is for.

It is also narrower than the problem, deliberately. Three further phrasings
were written, tested, and removed:

* **"the audit's"** — ``tools/check_error_state_gating.py`` defines a function
  named ``audit()``, so "the audit's output" is a correct reference to a real
  symbol.
* **"a previous session", "another session"** — this package implements
  ``SessionStore`` and ``SessionState``. "A previous session's keys must not
  decrypt this one" is protocol prose, not a development-process reference.
* **"the audit session"** — the library emits audit records, so the phrase has
  a legitimate reading here too.

Each caught real instances, and each would have forced correct prose to change
in order to satisfy a linter. That is a worse defect than the one being fixed,
so the ambiguous phrasings are left to review and this gate keeps only shapes
that cannot mean anything else: a dated audit reference and a line number. Four
dangling references in those ambiguous forms were found while writing this and
fixed by hand; nothing here will catch a fifth. A narrow gate that never cries
wolf is worth more than a broad one that gets switched off.

Exit code:
    0  every citation in the shipped tree resolves
    1  at least one does not
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Directories whose prose ships or is read by contributors.
SCANNED_DIRS = ("ama_cryptography", "src", "include", "tools", "tests", "docs")

#: Root-level documents that ship.
SCANNED_ROOT_FILES = ("README.md", "SECURITY.md", "ARCHITECTURE.md", "INVARIANTS.md")

#: Files that may contain a rejected shape, and the reason each may.
#:
#: An exemption is a hole, so there are three and each is load-bearing:
#: ``tests/test_reference_integrity_gate.py`` asserts that every file listed
#: here really does contain a rejected shape, and that nothing else is listed.
#: A stale exemption therefore fails the suite rather than silently widening it.
EXEMPT = {
    "CHANGELOG.md": "a historical record; not revised to satisfy a linter",
    "tools/check_reference_integrity.py": "quotes the rejected shapes to define them",
    "tests/test_reference_integrity_gate.py": "drives the rejected shapes through the gate",
}

SUFFIXES = {".py", ".pyx", ".pyi", ".c", ".h", ".md", ".sh", ".yml", ".yaml"}

#: Citations that name a development artefact no reader of the repository has.
PROCESS_CITATION = re.compile(r"""(?xi)
    \b(?:
        \d{4}-\d{2}\s+v\d+\s+audit          # (2026-08 v5 audit, item 15)
      | item\s+\d+\s+of\s+the\s+audit
    )
    """)

#: Citations to a line number: unverifiable, and stale the moment code moves.
#: Requires literal digits, so runtime messages ("at line %d") do not match.
LINE_CITATION = re.compile(r"(?i)\b(?:at|on|see|per)\s+lines?\s+\d{2,4}\b")

CHECKS = (
    (
        PROCESS_CITATION,
        "cites a development artefact that is not in the repository; state the "
        "finding, or cite a commit or INVARIANT-N",
    ),
    (
        LINE_CITATION,
        "cites a source line number, which nothing can keep true; cite the "
        "identifier, marker or function instead",
    ),
)


def _tracked_files(repo_root: Path) -> list[Path]:
    """Every tracked file in scope, via ``git ls-files``."""
    out = subprocess.run(
        ["git", "ls-files", "-z", *SCANNED_DIRS, *SCANNED_ROOT_FILES],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    files = []
    for name in out.split("\0"):
        if not name:
            continue
        path = repo_root / name
        if name in EXEMPT or path.suffix not in SUFFIXES or not path.is_file():
            continue
        files.append(path)
    return files


def scan_text(text: str) -> list[tuple[int, str, str]]:
    """Return ``(line_number, matched_text, reason)`` for every bad citation."""
    findings: list[tuple[int, str, str]] = []
    for pattern, reason in CHECKS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append((line, match.group(0).strip(), reason))
    return sorted(findings)


def check(repo_root: Path) -> tuple[int, list[str]]:
    """Scan the tree.  Returns ``(files_checked, problem_lines)``."""
    problems: list[str] = []
    files = _tracked_files(repo_root)
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:  # a binary file that slipped the suffix net
            continue
        rel = path.relative_to(repo_root).as_posix()
        for line, matched, reason in scan_text(text):
            problems.append(f"{rel}:{line}: {matched!r} — {reason}")
    return len(files), problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reject citations a reader cannot resolve.",
        epilog=(
            "checked: process citations (a dated audit such as "
            "'2026-08 v5 audit', or an 'item N of the audit') and source-line "
            "citations ('at line 632').\n"
            "NOT checked: whether a resolvable citation is the RIGHT one — this "
            "gate checks that a reader can follow a reference, not that the "
            "reference is correct.  Ambiguous phrasings ('a previous session', "
            '"the audit\'s") are left to review: in this package they also '
            "match correct prose.\n"
            "exempt: CHANGELOG.md, a historical record that is not revised to "
            "satisfy a linter, plus this tool and its test, which must quote "
            "the rejected shapes in order to define them."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--repo", default=str(REPO_ROOT), help="repository root")
    args = parser.parse_args(argv)

    checked, problems = check(Path(args.repo))
    if problems:
        print(f"FAIL: {len(problems)} unresolvable citation(s):")
        for problem in problems:
            print(f"  - {problem}")
        print(
            "\nEach names something a reader of this repository cannot open. "
            "State the\nfact directly, or cite a commit or INVARIANT-N."
        )
        return 1
    print(f"OK    {checked} file(s) checked; every citation resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main())
