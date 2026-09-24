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

The shapes, as widened after measuring what the first patterns let through
("in line 632", "(line 632)", "see line 7", "(v5 audit, 2026-08, item 15)",
"audit item 15", "the 2026-08 audit's finding #5" all passed):

* a versioned audit (``v5 audit``) with or without a date, in either order;
* an audit item number (``audit item 15``, ``audit, item 15``, ``item 15 of
  the v5 audit``);
* a numbered audit finding (``the audit's finding #5``, ``finding #7``) — a
  ``CodeQL`` alert number is not one: it resolves in the repository's code
  scanning;
* ``at/on/per/in/from/near line NN`` (two or more digits, so "on line 6 of
  the fixture" describing a string beside it is left alone), ``see line N`` and
  ``(line N)`` (any number but 1 — line 1 is a fixed position, a shebang or a
  file-level pragma, and cannot drift), and a FILE NAME followed by a line
  number (``ama_argon2.c lines 380-466``, ``.gitignore`` line 178``);
* each of those wrapped before the word "line" onto a comment continuation
  (`` * line 588`` after a line ending in a file name) -- two such citations
  sat in ``src/c`` while the gap was a bare ``\\s+``, which cannot cross the
  continuation's comment leader;
* EXCEPT a line of a published algorithm (``FIPS 204 §5.2 (lines 5-6)``,
  ``Algorithm 7 line 3``): those are stable, numbered by the standard, and
  resolve in a document anyone can open.

What is deliberately NOT checked
--------------------------------
The historical record is out of SCOPE, and that is the point rather than a
convenience.  ``CHANGELOG.md`` is not in :data:`SCANNED_ROOT_FILES`, and the
development journals under ``docs/changelog/`` — the dated per-pass entries
moved out of it verbatim — are dropped from ``docs/`` by
``tools/_repo.py``'s ``is_historical_record``, the one definition of which
files those are.  Their entries describe the tree as it stood when they were
written, and editing them to satisfy a present-day linter would falsify the
documents whose value is that they were not revised. A stale reference in a
changelog is a fact about the past; the same reference in
``ama_cryptography/session.py`` is a defect in the present.  (``CHANGELOG.md``
used to be listed in :data:`EXEMPT` as well.  That entry could never take
effect — the file is not scanned — so it was a dead exemption, and it is gone;
the test now requires every exemption to sit inside the scanned scope.)

This module and its test are exempt for a duller reason: both have to quote the
rejected shapes in order to reject them.  That is still a hole, so the test
asserts the list is exactly these two entries, that each is in scope, and that
each genuinely contains a rejected shape.  An exemption that stops being needed
fails the suite instead of lingering as a place to hide things.

A dated audit on its own (``the 2026-09 audit``, ``2026-09 audit, A-2``) is
not rejected: it names an event rather than a numbered item, and whether those
finding IDs must resolve to an in-tree document is a policy question this gate
does not settle.

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
    1  at least one does not, or no file was in scope to check
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
#: An exemption is a hole, so there are two and each is load-bearing:
#: ``tests/test_reference_integrity_gate.py`` asserts that every file listed
#: here is inside the scanned scope, really does contain a rejected shape, and
#: that nothing else is listed.  A stale exemption therefore fails the suite
#: rather than silently widening it.
EXEMPT = {
    "tools/check_reference_integrity.py": "quotes the rejected shapes to define them",
    "tests/test_reference_integrity_gate.py": "drives the rejected shapes through the gate",
}

#: The file types that carry prose, and so can carry a citation.
#:
#: ``.txt``, ``.rst`` and ``.cmake`` were missing while ``tests/`` and
#: ``docs/`` were in scope: the Sphinx pages under ``docs/`` are ``.rst``, and
#: ``tests/c/CMakeLists.txt`` carried two ``(2026-08 v5 audit)`` citations —
#: the exact shape this module's docstring opens with — while the gate printed
#: "every citation resolves".
SUFFIXES = {
    ".py",
    ".pyx",
    ".pyi",
    ".c",
    ".h",
    ".md",
    ".rst",
    ".txt",
    ".sh",
    ".yml",
    ".yaml",
    ".cmake",
}

#: Prose-bearing files that have no suffix to match (see :func:`file_type`).
SCANNED_NAMES = {"Makefile", "Doxyfile", ".gitignore"}

#: In-scope file types (:func:`file_type`) that are machine-read data, not
#: prose, and the reason.  ``tests/test_reference_integrity_gate.py`` requires
#: every tracked file in scope to be scanned, historical, exempt, or of one of
#: these types — so a new prose format entering the tree fails the suite
#: instead of being skipped the way ``.rst`` and ``.txt`` were.
NOT_PROSE_TYPES = {
    ".json": "test vectors, attestations and SBOMs, read by tools rather than people",
    ".kat": "known-answer vectors",
    ".rsp": "NIST CAVP response vectors",
    ".typed": "the empty PEP 561 marker",
    ".gitkeep": "an empty placeholder",
}

#: Citations that name a development artefact no reader of the repository has.
PROCESS_CITATION = re.compile(r"""(?xi)
    \b(?:
        \d{4}-\d{2}(?:-\d{2})?\s+v\d+\s+audit     # (2026-08 v5 audit, item 15)
      | v\d+\s+audit\b                          # (v5 audit, 2026-08, item 15)
      | audit\W{0,3}\s*items?\s+\#?\d+           # audit item 15 / audit, item 15
      | items?\s+\#?\d+\s+(?:of|in|from)\s+the\s+(?:[\w-]+\s+){0,2}audit
      | audit(?:'s)?\s+findings?\s+\#?\s*\d+     # the audit's finding #5
    )
    | (?<!CodeQL\s)\bfindings?\s+\#\s*\d+        # (finding #7)
    """)

#: The gap before the word "line" in a citation: whitespace, or -- where the
#: citation wraps -- a line break followed by the next line's comment leader
#: (`*` in a C block comment, `#`, `//`, `>`).  With a bare `\s+` here a wrapped
#: citation passed, because `\s` cannot cross the ` * `: measured on the tree,
#: src/c/sve2/ama_sphincs_sve2.c carried "wired at
#: `src/c/dispatch/ama_dispatch.c`" / " * line 588-589" and the gate reported
#: every citation resolved.
_GAP = r"(?:[ \t]*\n[ \t]*(?:\*|\#|//|>)[ \t]*|\s+)"

#: Citations to a line number: unverifiable, and stale the moment code moves.
#: Requires literal digits, so runtime messages ("at line %d") do not match.
LINE_CITATION = re.compile(
    r"""(?xi)
    (?:
        \b(?:at|on|per|in|from|near)"""
    + _GAP
    + r"""lines?\s+\d{2,5}\b                                        # at line 632
      | (?:\bsee"""
    + _GAP
    + r"""|\(\s*)lines?\s+(?!1\b)\d{1,5}\b                          # see line 7, (line 632)
      | \.(?:py|pyx|pyi|c|h|md|sh|ya?ml|txt|toml|cfg|json|gitignore)
        `{0,2},?"""
    + _GAP
    + r"""(?:now\s+)?lines?\s+\d{1,5}\b                             # foo.c lines 380-466
    )
    """
)

#: A line of a published algorithm, cited by the standard's own numbering
#: (``FIPS 204 §5.2 (lines 5-6)``, ``Algorithm 7 line 3``).  Checked against
#: the text just before a LINE_CITATION match on the same line.
_STANDARD_CONTEXT = re.compile(r"(?i)(?:Algorithm\s+\d+|§\s*[\d.]+|FIPS\s+\d+)[^\n]{0,12}$")

CHECKS: tuple[tuple[re.Pattern[str], str, re.Pattern[str] | None], ...] = (
    (
        PROCESS_CITATION,
        "cites a development artefact that is not in the repository; state the "
        "finding, or cite a commit or INVARIANT-N",
        None,
    ),
    (
        LINE_CITATION,
        "cites a source line number, which nothing can keep true; cite the "
        "identifier, marker or function instead",
        _STANDARD_CONTEXT,
    ),
)


def _is_historical_record(name: str) -> bool:
    """CHANGELOG.md and ``docs/changelog/``: out of scope, see the module docstring."""
    root = str(Path(__file__).resolve().parents[1])
    if root not in sys.path:
        sys.path.insert(0, root)
    from tools._repo import is_historical_record

    return is_historical_record(name)


def file_type(path: Path) -> str:
    """A file's suffix, or its whole name when it has none (``Makefile``, ``.gitkeep``)."""
    return path.suffix or path.name


def _is_prose(path: Path) -> bool:
    """Whether ``path`` is a file type this gate reads."""
    kind = file_type(path)
    return kind in SUFFIXES or kind in SCANNED_NAMES


def _tracked_files(repo_root: Path) -> list[Path]:
    """Every tracked file in scope, via ``git ls-files``.

    The historical record is not in scope: ``CHANGELOG.md`` is never listed,
    and the journals under ``docs/changelog/`` are dropped here.
    """
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
        if name in EXEMPT or not _is_prose(path) or not path.is_file():
            continue
        if _is_historical_record(name):
            continue
        files.append(path)
    return files


def scan_text(text: str) -> list[tuple[int, str, str]]:
    """Return ``(line_number, matched_text, reason)`` for every bad citation."""
    findings: list[tuple[int, str, str]] = []
    for pattern, reason, excluded_context in CHECKS:
        for match in pattern.finditer(text):
            if excluded_context is not None:
                line_start = text.rfind("\n", 0, match.start()) + 1
                if excluded_context.search(text[line_start : match.start()]):
                    continue
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
            "not scanned: CHANGELOG.md and the development journals under "
            "docs/changelog/, the historical record, which is not revised to "
            "satisfy a linter (it is outside the scanned scope).\n"
            "exempt: this tool and its test, which must quote the rejected "
            "shapes in order to define them."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--repo", default=str(REPO_ROOT), help="repository root")
    args = parser.parse_args(argv)

    checked, problems = check(Path(args.repo))
    if checked == 0:
        # Fail closed: an empty scope means the layout moved or --repo points
        # somewhere else, and "every citation resolves" over nothing is the
        # report this gate must never give.
        print(
            f"FAIL: 0 files in scope under {args.repo} — the scanned directories "
            f"({', '.join(SCANNED_DIRS)}) hold no tracked prose file; that is a "
            "checker fault, not a clean tree."
        )
        return 1
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
