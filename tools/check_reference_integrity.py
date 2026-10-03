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
2. **Source-line citations** — ``at line 632``, ``see lines 314 and 339``, and
   in the shipped code (``ama_cryptography/``, ``src/``, ``include/``) the
   compiler-diagnostic form ``file.c:705``. Cite the identifier, the marker,
   or the function instead; those move with the code.
3. **Test citations in the shipped code** — a cited test file that is not
   there, or a cited test that pytest does not collect.  A comment beside a
   guard that names its test is the reader's evidence that the guard is
   protected.  On 2026-09-26 ``src/c/ama_dilithium.c`` named
   ``test_a_permuted_hint_is_refused`` in ``tests/test_pqc_param_sets.py`` as
   the pin for ML-DSA's hint-ordering rule; no such test existed in the
   tree's history, and the rule's rejection was executed by no suite.  Three
   more ``src/c`` comments cited test files under names they never had.
   Scoped to ``ama_cryptography/``, ``src/`` and ``include/``: ``tests/`` and
   ``tools/`` cite imaginary test paths on purpose, as fixtures for the path
   gates (``tests/x.py``), and scanning them would need a standing exemption
   list, which is not a gate.  What is read, and what resolves it:

   * **A path under** ``tests/``, of any extension, after an optional
     ``./``, ``../`` or ``AMA-Cryptography/`` prefix: a file ``git ls-files``
     lists and the working tree holds.  A path that names a directory (with
     or without its trailing ``/``) must hold such a file, and a path with a
     ``*`` must match one, segment by segment.  A tracked file deleted from
     the working tree, and a file on disk that git does not track, are
     findings.
   * **A bare test file name** (``test_x.c``, ``test_y.py``): the name of
     exactly one tracked file under ``tests/``.  None, or several, is a
     finding.
   * **A node id** -- ``tests/y.py::test_x``, ``tests/y.py::TestA::test_x``,
     ``tests/y.py::TestA`` or, after a bare file name, ``test_y.c::test_x``
     (a ``[case]`` suffix is ignored): exactly a node pytest collects, the
     module, then each named class in order, then the function.  With no
     class it must be a module-level test, so a method cited as
     ``tests/y.py::test_method`` is a finding; a class qualifier on a C path
     is a finding, since a C test has no class.
   * **A named test in a named file**: one name or a list of them (``test_a,
     test_b and test_c`` -- every listed name is checked), each optionally
     ``test_x()``, ``test_x(self)`` or ``test_x[case]`` in single or rst
     double backticks, then ``in``, ``of``, ``from`` or ``at`` in any case,
     then the file; also ``test_x (tests/y.py)``, ``tests/y.py: test_x`` and
     ``tests/y.py (test_x)``.  The name must be a test pytest collects
     anywhere in that file, function or method.  Written dotted
     (``TestA.test_x in tests/y.py``) the classes must be the innermost
     classes of such a test, and ``TestA in tests/y.py`` (``Test`` then a
     capital, a digit or ``_``, so the word "Tests" is not read as a class)
     must be a class pytest collects a test from.
   * **A bare test name** written as a whole code span with no file
     (````test_x```` or ```test_x()```): a test pytest collects from a
     tracked ``tests/`` file whose text contains the name, or a C test
     defined in a tracked ``tests/`` C file -- unless the name is an
     identifier in the citing file's own code, where it names that parameter
     or variable rather than a test.

   A citation wrapped onto the next line is joined across the line break and
   that line's comment leader (``*``, ``/*``, ``#``, ``//``, ``>``): a path
   broken after ``_`` or ``-``, or after ``/`` when the next line continues
   it with a file or directory name; a node id broken after or before
   ``::``; a test name broken after ``_``.  The text is joined in one linear
   pass, and the joined text is read with patterns in which no repeated group
   can match the same text two ways -- the ambiguity exponential
   backtracking needs.  The patterns this replaced repeated a group whose
   alternatives both matched whitespace, and took 105 s on ``test_x``
   followed by three indented lines; the test suite times those inputs, and
   the same inputs a thousand times larger.

   **Collection is pytest's.**  The Python test files the citations need are
   collected in one child process, ``python -c`` running ``pytest.main``
   with ``--collect-only`` at the repository root exactly as a plain
   ``pytest`` run collects -- its configuration and ``testpaths``,
   ``python_files``, ``python_classes`` and ``python_functions``, every
   ``conftest.py`` and installed plugin -- except that every file no citation
   needs is ignored, ``PYTEST_ADDOPTS`` is removed and
   ``AMA_POST_DIAGNOSTIC_IMPORT=1`` is set so the package imports on a tree
   whose native library is stale.  So a ``Test*`` class with an
   ``__init__``, a class with ``__test__ = False``, a ``def`` shadowed by a
   later assignment, ``tests/conftest.py`` and a helper module outside
   ``python_files`` (``tests/ref_keyformat.py``) resolve nothing, while a
   ``unittest.TestCase`` method, a method inherited from a base class, a
   ``def`` under ``if`` or ``try`` and ``test_x = factory()`` resolve.  An
   ``async def`` test resolves only if a plugin other than pytest's own
   implements ``pytest_pyfunc_call`` (without one, pytest fails the test
   without running it).  For anyio, the plugin that most often arrives unasked
   (with starlette and httpx), whether it runs the particular test is checked:
   only a test that requests ``anyio_backend`` resolves.  For any other plugin
   it is not checked.  A file pytest cannot collect is a finding ("cannot
   collect ... to verify ..."), never a pass.  **A C test** is a function
   definition in the cited file: the name, a balanced parameter list and a
   body, at file scope (brace depth 0; an ``extern "C"`` block does not count)
   of the code with comments, string and character literals, preprocessor lines
   and ``#if 0`` regions blanked, after nothing but declaration specifiers,
   ``*`` and ``__attribute__((...))``.  A call, a prototype, and a mention in a
   comment or a string are not definitions.  For a brace inside a function the
   depth-0 rule and the declaration-specifier rule are redundant -- the text
   before such a brace reaches back past the function's own ``{``, which no
   declaration holds -- so deleting either alone leaves a nested definition
   refused (measured), and the tests pin the property, which fails with both
   deleted.  Blanking is not redundant: a comment holding ``;`` and then
   ``static int test_x(void) {`` passes the specifier rule, and only blanking
   refuses it.

   NOT read: a test name with no file that is not a whole code span (``the
   leak at test_x``).  Prose uses that shape for tuple fields, parameters
   and variables as well as tests (``_self_test.py`` documents a
   ``(test_name, passed, detail)`` tuple), so it is left to review.  Nor is
   a path under any directory but the repository's ``tests/``
   (``fuzz/tests/x.py``), or a class cited in prose by a name outside the
   ``TestA`` shape (a ``unittest.TestCase`` named ``MyCase``).

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
    1  at least one does not, no file was in scope to check, or the tracked
       files could not be enumerated (git failed, or a tracked path is not a
       regular file and git does not report it deleted)
"""

from __future__ import annotations

import argparse
import bisect
import fnmatch
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import tokenize
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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


#: A source line cited as ``file.c:705`` or ``file.c:434-438``, the form a
#: compiler diagnostic prints.  Checked in the shipped code only
#: (``TEST_CITATION_DIRS``): there it is always a citation, and it went stale
#: exactly as the word forms do -- measured 2026-09-28, both instances in the
#: shipped tree (``ama_chacha20poly1305.c`` citing ``ama_aes_gcm.c:705``,
#: ``ama_aes_gcm_avx2.c`` citing ``ama_aes_gcm.c:434-438``) pointed at code
#: that had moved, and ``tools/check_secret_division.py`` carried five more.
#: Elsewhere the form is also quoted compiler output (the warning-gate tests),
#: and reading it there would need a standing exemption list.
COLON_LINE_CITATION = re.compile(
    r"(?<![\w.\-/])[\w\-/]*\w\.(?:c|h|py|pyx|pyi):\d{1,5}(?:-\d{1,5})?\b(?!\.\d)"
)

COLON_LINE_REASON = (
    "cites a source line number, which nothing can keep true; cite the "
    "identifier, marker or function instead"
)


def scan_shipped_text(text: str) -> list[tuple[int, str, str]]:
    """Return ``(line_number, matched_text, reason)`` for every ``file.c:NNN``
    line citation in a shipped file (see ``COLON_LINE_CITATION``)."""
    findings = []
    for match in COLON_LINE_CITATION.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        findings.append((line, match.group(0), COLON_LINE_REASON))
    return findings


#: Where a citation of a test is checked against the tests that exist -- the
#: shipped code only; see shape 3 in the module docstring for why not tests/.
TEST_CITATION_DIRS = ("ama_cryptography", "src", "include")

#: The repository's name, accepted as the leading component of a cited path
#: (``AMA-Cryptography/tests/x.py``), as ``./`` and ``../`` are.
REPO_NAME = "AMA-Cryptography"

#: The suffixes of the test sources a named test can be defined in.
PYTHON_TEST_SUFFIX = ".py"
C_TEST_SUFFIXES = (".c", ".h")
_TEST_SOURCE_SUFFIXES = (PYTHON_TEST_SUFFIX, *C_TEST_SUFFIXES)

#: A comment leader at the start of a line: ``/*`` or the ``*`` of a C block
#: comment, ``#`` or ``#:``, ``//``, the ``>`` of a quote.  Always matches.
_LEADER = re.compile(r"[ \t]*(?:/\*+|\*+(?!/)|#+:?|//+|>+)?[ \t]*")

#: The characters a citation that runs to the end of a line can end in.
_TAIL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:-")

#: A line that continues a path broken after ``/`` with a file or directory
#: name (``test_x.c``, ``kat/``), rather than with prose.
_PATH_CONTINUES = re.compile(r"[\w\-]+[./]\w")

#: A reference to a test file: a path under ``tests/`` (group 1), after an
#: optional ``./``, ``../`` or repository-name prefix, or a bare test file
#: name (group 2).
_FILE_REF = re.compile(
    r"(?<![\w.\-/])(?:"
    r"(?:\.\.?/|" + re.escape(REPO_NAME) + r"/)*(tests/[\w.\-/*]*)"
    r"|(test_\w+\.(?:py|c|h))(?![\w\-]|\.\w)"
    r")"
)

#: One ``::component`` of a node id.  A ``[case]`` after the last one is
#: not part of it, so it is never read.
_NODE_PART = re.compile(r"::(\w+)")

#: A test named in prose (group 2): ``test_x``, dotted ``TestA.test_x``, or a
#: class ``TestA``; in single or rst double backticks (groups 1 and 4), with
#: the ``(...)`` of a call or the ``[case]`` of a parametrisation (group 3).
_ITEM = re.compile(
    r"(?<![\w.:/])(`{0,2})"
    r"((?:[A-Z][\w.]*\.)?test_\w+|Test[A-Z0-9_]\w*)(?!\w|\.\w)"
    r"(\([^()\n]{0,200}\)|\[[^\]\n]{0,200}\])?(`{0,2})"
)

#: What separates two names in a list: ``,``, ``and``, ``or``, ``, and``.
_LIST_SEP = re.compile(r"(?i)[ \t]*,[ \t]*(?:(?:and|or)[ \t]+)?|[ \t]+(?:and|or)[ \t]+")

#: A name, then the file it is in: ``test_x in tests/y.py``.
_CONNECTOR = re.compile(r"[ \t]+(?i:in|of|from|at)[ \t]+`{0,2}")

#: A name, then its file in parentheses: ``test_x (tests/y.py)``.
_PAREN_FILE = re.compile(r"[ \t]*\(`{0,2}")

#: A file, then the names in it: ``tests/y.py: test_x``, ``tests/y.py (test_x)``.
_FILE_THEN_NAMES = re.compile(r"`{0,2}(?::[ \t]+|[ \t]*\()")


@dataclass(frozen=True)
class Citation:
    """One citation of a test file or a test, as the shipped code writes it.

    ``form`` is ``"path"`` (the file must exist), ``"node"`` (a node id,
    resolved exactly), ``"named"`` (a test anywhere in the file), ``"class"``
    (a test class in the file) or ``"bare"`` (a test with no file).  ``ref``
    is the cited file -- a repository-relative path, or a bare file name when
    ``bare_file`` -- and ``parts`` the classes and the test after it."""

    line: int
    shown: str
    form: str
    ref: str | None = None
    bare_file: bool = False
    parts: tuple[str, ...] = ()


def _tail(line: str) -> str:
    """The run of path and identifier characters ``line`` ends with."""
    start = len(line)
    while start > 0 and line[start - 1] in _TAIL_CHARS:
        start -= 1
    return line[start:]


def _is_file_node(tail: str) -> bool:
    """Whether ``tail`` is a test file, or a node id in one, up to its first ``::``."""
    return tail.split("::", 1)[0].endswith(_TEST_SOURCE_SUFFIXES)


def _joins(prev: str, nxt: str) -> bool:
    """Whether ``nxt`` continues a citation that ``prev`` broke off mid-token."""
    tail = _tail(prev)
    if not tail or not nxt:
        return False
    if nxt.startswith("::"):
        return _is_file_node(tail)
    if not (nxt[0] == "_" or nxt[0].isalnum()):
        return False
    if tail.endswith("::"):
        return _is_file_node(tail)
    if "tests/" in tail and tail.endswith(("_", "-")):
        return True
    if "tests/" in tail and tail.endswith("/"):
        return _PATH_CONTINUES.match(nxt) is not None
    last = re.split(r"[./:]", tail)[-1]
    return last.startswith("test_") and tail.endswith("_")


def join_lines(text: str) -> tuple[str, list[int]]:
    """``text`` as one line, and the offset each original line starts at.

    Each line loses its comment leader and trailing space and is joined to
    the one before it with a space, or with nothing where :func:`_joins`
    finds a citation broken across the two.  One pass, linear in ``text``."""
    pieces: list[str] = []
    starts: list[int] = []
    length = 0
    prev = ""
    for raw in text.split("\n"):
        leader = _LEADER.match(raw)
        content = raw[leader.end() if leader else 0 :].rstrip()
        if starts:
            sep = "" if _joins(prev, content) else " "
            pieces.append(sep)
            length += len(sep)
        starts.append(length)
        pieces.append(content)
        length += len(content)
        prev = content
    return "".join(pieces), starts


def _trim_path(path: str) -> str:
    """A cited path without the punctuation prose puts after it."""
    while path:
        if path.endswith("*/"):
            path = path[:-2]
        elif path.endswith("**"):
            path = path.rstrip("*")
        elif path[-1] in ".-":
            path = path[:-1]
        else:
            break
    return path


@dataclass(frozen=True)
class _FileRef:
    start: int
    end: int
    ref: str
    bare: bool


@dataclass(frozen=True)
class _Item:
    start: int
    end: int
    name: str
    whole_span: bool


def _file_refs(joined: str) -> list[_FileRef]:
    refs = []
    for match in _FILE_REF.finditer(joined):
        if match.group(1) is not None:
            path = _trim_path(match.group(1))
            end = match.start(1) + len(path)
            refs.append(_FileRef(match.start(), end, path, bare=False))
        else:
            refs.append(_FileRef(match.start(), match.end(), match.group(2), bare=True))
    return refs


def _items(joined: str) -> list[_Item]:
    items = []
    for match in _ITEM.finditer(joined):
        name = match.group(2)
        qualifiers = name.split(".")[:-1]
        if any(not re.fullmatch(r"[A-Z]\w*", q) for q in qualifiers):
            continue
        whole = bool(match.group(1)) and match.group(1) == match.group(4)
        items.append(_Item(match.start(), match.end(), name, whole))
    return items


def _chains(joined: str, items: list[_Item]) -> dict[int, list[_Item]]:
    """Every list of names, keyed by the offset of its first name."""
    chains: dict[int, list[_Item]] = {}
    current: list[_Item] = []
    for item in items:
        if current and _LIST_SEP.fullmatch(joined, current[-1].end, item.start):
            current.append(item)
            continue
        current = [item]
        chains[item.start] = current
    return chains


def _named(line: int, item: _Item, ref: _FileRef) -> Citation:
    parts = tuple(item.name.split("."))
    form = "class" if not parts[-1].startswith("test_") else "named"
    return Citation(line, f"{item.name} in {ref.ref}", form, ref.ref, ref.bare, parts)


def extract_test_citations(text: str) -> list[Citation]:
    """Every citation of a test file or a test in ``text`` (see shape 3)."""
    joined, starts = join_lines(text)

    def line_of(offset: int) -> int:
        return bisect.bisect_right(starts, offset)

    refs = _file_refs(joined)
    by_start = {ref.start: ref for ref in refs}
    items = _items(joined)
    chains = _chains(joined, items)
    bound: set[int] = set()
    found: list[Citation] = []
    for ref in refs:
        line = line_of(ref.start)
        found.append(Citation(line, ref.ref, "path", ref.ref, ref.bare))
        parts = []
        pos = ref.end
        while (part := _NODE_PART.match(joined, pos)) is not None:
            parts.append(part.group(1))
            pos = part.end()
        if parts:
            shown = "::".join([ref.ref, *parts])
            found.append(Citation(line, shown, "node", ref.ref, ref.bare, tuple(parts)))
            continue
        after = _FILE_THEN_NAMES.match(joined, ref.end)
        if after is not None and after.end() in chains:
            for item in chains[after.end()]:
                bound.add(item.start)
                found.append(_named(line, item, ref))
    for first, chain in chains.items():
        end = chain[-1].end
        link = _CONNECTOR.match(joined, end) or _PAREN_FILE.match(joined, end)
        target = by_start.get(link.end()) if link is not None else None
        if target is None:
            continue
        for item in chain:
            bound.add(item.start)
            found.append(_named(line_of(first), item, target))
    for item in items:
        is_test = item.name.rsplit(".", 1)[-1].startswith("test_")
        if item.start in bound or not item.whole_span or not is_test:
            continue
        found.append(
            Citation(line_of(item.start), item.name, "bare", parts=tuple(item.name.split(".")))
        )
    return found


# --------------------------------------------------------------------------
# C test sources
# --------------------------------------------------------------------------

_C_LEXEME = re.compile(r"/\*|//|[\"']")
_C_LITERAL_REST = {
    '"': re.compile(r'(?:[^"\\\n]|\\.)*"?'),
    "'": re.compile(r"(?:[^'\\\n]|\\.)*'?"),
}
_PP_DIRECTIVE = re.compile(r"[ \t]*#[ \t]*(\w*)(.*)")
_NOT_NEWLINE = re.compile(r"[^\n]")
_C_BRACE_OR_END = re.compile(r"[{};]")
_C_ATTRIBUTE = re.compile(r"\b(?:__attribute__|__declspec|_Alignas|alignas)\s*\(")
_C_SPECIFIERS = re.compile(r"[\w\s*]*")
_C_EXTERN_BLOCK = re.compile(r"\s*extern\s*")


def _blank(chunk: str) -> str:
    return _NOT_NEWLINE.sub(" ", chunk)


def _blank_literals(source: str) -> str:
    """``source`` with comments and string and character literals blanked."""
    out: list[str] = []
    pos = 0
    while (match := _C_LEXEME.search(source, pos)) is not None:
        out.append(source[pos : match.start()])
        lexeme = match.group(0)
        if lexeme == "/*":
            close = source.find("*/", match.end())
            end = len(source) if close < 0 else close + 2
        elif lexeme == "//":
            newline = source.find("\n", match.end())
            end = len(source) if newline < 0 else newline
        else:
            rest = _C_LITERAL_REST[lexeme].match(source, match.end())
            end = rest.end() if rest is not None else match.end()
        out.append(_blank(source[match.start() : end]))
        pos = end
    out.append(source[pos:])
    return "".join(out)


def _conditional(frames: list[list[str]], directive: str, argument: str) -> None:
    """Track ``#if 0`` / ``#if 1``: each frame is ``[kind, live]``."""
    if directive in ("if", "ifdef", "ifndef"):
        constant = argument.strip() if directive == "if" else ""
        kind = {"0": "zero", "1": "one"}.get(constant, "other")
        frames.append([kind, "no" if kind == "zero" else "yes"])
    elif directive in ("elif", "else") and frames:
        kind = frames[-1][0]
        if kind == "zero":
            frames[-1] = ["other" if directive == "elif" else "zero", "yes"]
        elif kind == "one":
            frames[-1][1] = "no"
    elif directive == "endif" and frames:
        frames.pop()


def c_code(source: str) -> str:
    """The C code in ``source``: comments, string and character literals,
    preprocessor lines (with their ``\\`` continuations) and the regions an
    ``#if 0`` (or the ``#else`` of an ``#if 1``) disables, blanked to spaces.
    Newlines are kept, so offsets and line numbers survive."""
    lines = _blank_literals(source).split("\n")
    frames: list[list[str]] = []
    continued = False
    for number, line in enumerate(lines):
        directive = None if continued else _PP_DIRECTIVE.fullmatch(line)
        dead = any(live == "no" for _, live in frames)
        if directive is not None:
            _conditional(frames, directive.group(1), directive.group(2))
        if continued or directive is not None or dead:
            continued = (continued or directive is not None) and line.endswith("\\")
            lines[number] = _blank(line)
    return "\n".join(lines)


def _balanced_open(head: str) -> int:
    """The index of the ``(`` that the ``)`` ``head`` ends with opens, or -1."""
    depth = 0
    for index in range(len(head) - 1, -1, -1):
        if head[index] == ")":
            depth += 1
        elif head[index] == "(":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _without_attributes(prefix: str) -> str | None:
    """``prefix`` without its ``__attribute__((...))`` groups, or None if one
    is unbalanced."""
    while (match := _C_ATTRIBUTE.search(prefix)) is not None:
        depth = 0
        for index in range(match.end() - 1, len(prefix)):
            depth += {"(": 1, ")": -1}.get(prefix[index], 0)
            if depth == 0:
                prefix = prefix[: match.start()] + " " + prefix[index + 1 :]
                break
        else:
            return None
    return prefix


def _defined_function(header: str) -> str | None:
    """The function a file-scope ``header`` (the text before a ``{``) defines.

    ``header`` is a definition when it ends in a balanced parameter list
    after an identifier, and everything before the identifier is declaration
    specifiers, ``*`` and attributes."""
    head = header.rstrip()
    if not head.endswith(")"):
        return None
    opening = _balanced_open(head)
    if opening < 0:
        return None
    before = head[:opening].rstrip()
    start = len(before)
    while start > 0 and (before[start - 1] == "_" or before[start - 1].isalnum()):
        start -= 1
    name = before[start:]
    if not name or name[0].isdigit():
        return None
    prefix = _without_attributes(before[:start])
    if prefix is None or _C_SPECIFIERS.fullmatch(prefix) is None:
        return None
    return name


def c_definitions(source: str) -> frozenset[str]:
    """The functions ``source`` defines with a body, at file scope."""
    code = c_code(source)
    names: set[str] = set()
    braces: list[bool] = []  # per open brace: whether it opens a scope
    depth = 0  # the scopes open: an ``extern "C"`` block is not one
    boundary = 0  # where the text before the next file-scope ``{`` starts
    for match in _C_BRACE_OR_END.finditer(code):
        lexeme = match.group(0)
        if lexeme == "{":
            header = code[boundary : match.start()]
            scope = depth > 0 or _C_EXTERN_BLOCK.fullmatch(header) is None
            if depth == 0 and scope:
                name = _defined_function(header)
                if name is not None:
                    names.add(name)
            braces.append(scope)
            depth += scope
        elif lexeme == "}" and braces:
            depth -= braces.pop()
        if depth == 0:
            boundary = match.end()
    return frozenset(names)


def code_identifiers(text: str, path: str) -> frozenset[str]:
    """The identifiers in ``text``'s code, outside its comments and strings.

    Python (``.py``, ``.pyi``, ``.pyx``) is read with :mod:`tokenize`; C
    (``.c``, ``.h``) with :func:`c_code`.  Any other file, or Python the
    tokenizer rejects, has none, so a bare name in it must be a test."""
    if path.endswith((".py", ".pyi", ".pyx")):
        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
        except (tokenize.TokenError, SyntaxError):
            return frozenset()
        return frozenset(token.string for token in tokens if token.type == tokenize.NAME)
    if path.endswith(C_TEST_SUFFIXES):
        return frozenset(re.findall(r"[A-Za-z_]\w*", c_code(text)))
    return frozenset()


# --------------------------------------------------------------------------
# Python test sources: pytest is the oracle
# --------------------------------------------------------------------------

#: How long one collection may take before the gate gives up on it (and
#: reports every citation it needed, rather than passing them).
ORACLE_TIMEOUT_SECONDS = 600

#: Loads this file under a private module name in the child and runs
#: :func:`run_pytest_oracle`; ``python -c`` keeps the child's ``sys.path`` the
#: one ``python -m pytest`` would have (the working directory first).
_ORACLE_BOOTSTRAP = (
    "import importlib.util, sys\n"
    "spec = importlib.util.spec_from_file_location('_reference_integrity_oracle', sys.argv[1])\n"
    "module = importlib.util.module_from_spec(spec)\n"
    "sys.modules[spec.name] = module\n"
    "spec.loader.exec_module(module)\n"
    "raise SystemExit(module.run_pytest_oracle(sys.argv[2], sys.argv[3:]))\n"
)

#: pytest's exit codes that still leave a per-file answer: OK, interrupted
#: by collection errors (recorded per node), no tests collected.
_ORACLE_ANSWERED = (0, 2, 5)


def _plugin_runs(plugin: object, item: object) -> bool:
    """Whether a ``pytest_pyfunc_call`` implementation runs this async item.

    pytest's own implementation runs none: it fails an ``async def`` test
    without running its body.  anyio's runs one only when the item requests
    the ``anyio_backend`` fixture, which the ``anyio`` marker adds; for any
    other item it returns ``None`` and pytest fails the test the same way
    (``anyio/pytest_plugin.py``, anyio 4.15.1).  anyio arrives with starlette
    and httpx, so counting its plugin as a runner for every async item let a
    citation of an unmarked async test, which pins nothing, resolve on any
    checkout that had it installed.  A plugin this function does not know is
    still assumed to run the item; that limit is stated in the module
    docstring.
    """
    name = getattr(plugin, "__name__", "")
    if name == "_pytest.python":
        return False
    if name == "anyio.pytest_plugin":
        return "anyio_backend" in getattr(item, "fixturenames", ())
    return True


def run_pytest_oracle(out: str, wanted: Sequence[str]) -> int:
    """Child process: collect ``wanted`` the way a plain ``pytest`` run
    collects the repository in the working directory, ignoring every other
    file, and write the node ids and the failed collections to ``out``."""
    import inspect

    import pytest

    root = Path.cwd()
    keep = {(root / name).resolve() for name in wanted}

    class Oracle:
        def __init__(self) -> None:
            self.items: list[tuple[str, bool]] = []
            self.errors: list[tuple[str, str]] = []

        @pytest.hookimpl(tryfirst=True)
        def pytest_ignore_collect(self, collection_path: Path) -> bool | None:
            if collection_path.is_dir() or collection_path.resolve() in keep:
                return None
            return True

        def pytest_collectreport(self, report: pytest.CollectReport) -> None:
            if report.failed:
                self.errors.append((report.nodeid, report.longreprtext))

        def pytest_collection_finish(self, session: pytest.Session) -> None:
            impls = session.config.hook.pytest_pyfunc_call.get_hookimpls()
            for item in session.items:
                func = getattr(item, "obj", None)
                is_async = (
                    inspect.iscoroutinefunction(func)
                    or inspect.isasyncgenfunction(func)
                    or bool(getattr(func, "_is_coroutine", False))
                )
                own = type(item).runtest is pytest.Function.runtest
                runner = any(_plugin_runs(i.plugin, item) for i in impls)
                self.items.append((item.nodeid, own and is_async and not runner))

    oracle = Oracle()
    code = pytest.main(
        ["--collect-only", "-q", "-p", "no:cacheprovider", f"--rootdir={root}"],
        plugins=[oracle],
    )
    payload = {"rc": int(code), "items": oracle.items, "errors": oracle.errors}
    Path(out).write_text(json.dumps(payload), encoding="utf-8")
    return 0


def _error_line(text: str) -> str:
    """The line of pytest's output that says what went wrong."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    errors = [line[1:].strip() for line in lines if line.startswith("E ")]
    return errors[-1] if errors else (lines[-1] if lines else "pytest wrote nothing")


@dataclass(frozen=True)
class Collected:
    """What pytest collects from one file: the node ids after the file, with
    any ``[case]`` removed; the async tests no plugin runs; or why the file
    could not be collected."""

    nodes: frozenset[tuple[str, ...]] = frozenset()
    unrun: frozenset[tuple[str, ...]] = frozenset()
    error: str | None = None


def _covers(nodeid: str, path: str) -> bool:
    """Whether a failed collection of ``nodeid`` leaves ``path`` uncollected."""
    return (
        nodeid in ("", ".", path) or path.startswith(nodeid + "/") or nodeid.startswith(path + "::")
    )


def _parse_oracle(data: Any, files: Sequence[str]) -> dict[str, Collected]:
    nodes: dict[str, set[tuple[str, ...]]] = {name: set() for name in files}
    unrun: dict[str, set[tuple[str, ...]]] = {name: set() for name in files}
    for nodeid, not_run in data["items"]:
        path, *parts = nodeid.split("[", 1)[0].split("::")
        if path in nodes and parts:
            (unrun if not_run else nodes)[path].add(tuple(parts))
    result = {}
    for name in files:
        failed = [text for nodeid, text in data["errors"] if _covers(nodeid, name)]
        error = _error_line(failed[-1]) if failed else None
        result[name] = Collected(frozenset(nodes[name]), frozenset(unrun[name]), error)
    return result


def collect_python(repo_root: Path, files: Sequence[str]) -> dict[str, Collected]:
    """Collect ``files`` (repository-relative) with pytest in a child process."""
    if not files:
        return {}
    env = {key: value for key, value in os.environ.items() if key != "PYTEST_ADDOPTS"}
    env["AMA_POST_DIAGNOSTIC_IMPORT"] = "1"
    with tempfile.TemporaryDirectory() as scratch:
        out = Path(scratch) / "collected.json"
        argv = [sys.executable, "-c", _ORACLE_BOOTSTRAP, str(Path(__file__).resolve())]
        try:
            proc = subprocess.run(
                [*argv, str(out), *files],
                cwd=repo_root,
                env=env,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=ORACLE_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {name: Collected(error=f"pytest could not be run: {exc}") for name in files}
        try:
            data = json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
    if not isinstance(data, dict) or data.get("rc") not in _ORACLE_ANSWERED:
        code = data.get("rc") if isinstance(data, dict) else proc.returncode
        reason = f"pytest exited {code}: {_error_line(proc.stdout + proc.stderr)}"
        return {name: Collected(error=reason) for name in files}
    return _parse_oracle(data, files)


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------


def _git_names(repo_root: Path, *args: str) -> list[str]:
    """``git <args>`` (which request ``-z``), decoded the way ``tools/_repo.py`` does."""
    _repo_root_on_path()
    from tools._repo import TrackedFilesError

    proc = subprocess.run(["git", *args], cwd=repo_root, capture_output=True, check=False)
    if proc.returncode != 0:
        raise TrackedFilesError(
            f"`git {' '.join(args)}` failed in {repo_root}: {os.fsdecode(proc.stderr).strip()}"
        )
    return [os.fsdecode(name) for name in proc.stdout.split(b"\0") if name]


def _matches(pattern: str, path: str) -> bool:
    """``fnmatch`` segment by segment, so ``*`` does not cross a ``/``."""
    want, have = pattern.split("/"), path.split("/")
    return len(want) == len(have) and all(map(fnmatch.fnmatchcase, have, want))


class SuiteIndex:
    """The test files under ``tests/`` as git tracks them, and the tests in
    them as pytest collects them (Python) or as they are defined (C)."""

    def __init__(self, repo_root: Path) -> None:
        self.root = repo_root
        _repo_root_on_path()
        from tools._repo import tracked_names

        #: Tracked, and a regular file in the working tree.
        self.present = frozenset(tracked_names(repo_root, "tests"))
        #: Tracked, and deleted from the working tree.
        self.deleted = frozenset(
            _git_names(repo_root, "ls-files", "-z", "--deleted", "--", "tests")
        )
        self._text: dict[str, str] = {}
        self._collected: dict[str, Collected] = {}
        self._c_defs: dict[str, frozenset[str]] = {}

    def text(self, rel: str) -> str:
        if rel not in self._text:
            self._text[rel] = (self.root / rel).read_text(encoding="utf-8", errors="replace")
        return self._text[rel]

    def python(self, rel: str) -> Collected:
        self.prime_files([rel])
        return self._collected[rel]

    def c_defines(self, rel: str, name: str) -> bool:
        if rel not in self._c_defs:
            self._c_defs[rel] = c_definitions(self.text(rel))
        return name in self._c_defs[rel]

    def prime_files(self, files: Iterable[str]) -> None:
        """Collect, in one pytest run, every file here not yet collected."""
        todo = sorted({name for name in files if name not in self._collected})
        self._collected.update(collect_python(self.root, todo))

    def prime(self, citations: Iterable[Citation]) -> None:
        """Collect every Python file ``citations`` can need, in one pytest run."""
        files: set[str] = set()
        for citation in citations:
            if citation.form == "path":
                continue
            candidates, _ = self.candidates(citation)
            files.update(name for name in candidates if name.endswith(PYTHON_TEST_SUFFIX))
        self.prime_files(files)

    def file_problem(self, ref: str, bare: bool) -> str | None:
        """Why the cited file does not resolve, or None."""
        if bare:
            named = sorted(p for p in self.present if p.rsplit("/", 1)[-1] == ref)
            if len(named) == 1:
                return None
            if not named:
                return "names no tracked file under tests/"
            return (
                f"names {len(named)} tracked files under tests/ ({', '.join(named)}); cite the path"
            )
        if "*" in ref:
            if any(_matches(ref, p) for p in self.present):
                return None
            return "matches no tracked file under tests/"
        if ref in self.present or any(p.startswith(ref.rstrip("/") + "/") for p in self.present):
            return None
        if ref in self.deleted:
            return "git tracks this test file, but it is deleted from the working tree"
        if (self.root / ref).exists():
            return "cites a test file that is on disk but not tracked by git"
        return "cites a test file that is not in the repository"

    def candidates(self, citation: Citation) -> tuple[list[str], str | None]:
        """The files ``citation``'s test can be in, or why there are none to read."""
        name = citation.parts[-1]
        if citation.ref is None:
            pool = sorted(p for p in self.present if p.endswith(_TEST_SOURCE_SUFFIXES))
            has = [p for p in pool if re.search(r"\b" + re.escape(name) + r"\b", self.text(p))]
            return has, None
        if self.file_problem(citation.ref, citation.bare_file) is not None:
            return [], "file"
        if citation.bare_file:
            return [p for p in self.present if p.rsplit("/", 1)[-1] == citation.ref], None
        if citation.ref in self.present:
            return [citation.ref], None
        prefix = citation.ref.rstrip("/") + "/"
        pool = sorted(
            p
            for p in self.present
            if (_matches(citation.ref, p) if "*" in citation.ref else p.startswith(prefix))
        )
        has = [p for p in pool if re.search(r"\b" + re.escape(name) + r"\b", self.text(p))]
        return has, None

    def resolve(self, citation: Citation, identifiers: frozenset[str]) -> str | None:
        """Why ``citation`` does not resolve, or None if it does."""
        if citation.form == "path":
            return self.file_problem(citation.ref or "", citation.bare_file)
        if citation.form == "bare" and citation.parts[-1] in identifiers:
            return None
        candidates, skip = self.candidates(citation)
        if skip is not None:
            return None  # the file itself is reported once, by its "path" citation
        problems = [self._resolve_in(citation, rel) for rel in candidates]
        if candidates and any(problem is None for problem in problems):
            return None
        if citation.ref is None or len(candidates) != 1:
            failed = [p for p in problems if p is not None and p.startswith("cannot collect")]
            if failed:
                return failed[0]
            where = "under tests/" if citation.ref is None else f"in {citation.ref}"
            return f"no test named {citation.parts[-1]} is collected or defined {where}"
        return problems[0]

    def _resolve_in(self, citation: Citation, rel: str) -> str | None:
        if rel.endswith(C_TEST_SUFFIXES):
            if len(citation.parts) > 1:
                return f"{rel} is C: a C test has no class, so {citation.shown} names nothing"
            if self.c_defines(rel, citation.parts[-1]):
                return None
            return f"{rel} has no test named {citation.parts[-1]}"
        if not rel.endswith(PYTHON_TEST_SUFFIX):
            return f"{rel} is not a Python or C source, so it defines no test"
        collected = self.python(rel)
        if collected.error is not None:
            return f"cannot collect {rel} to verify {citation.shown}: {collected.error}"
        if _found(citation, collected.nodes):
            return None
        if _found(citation, collected.unrun):
            return (
                f"{citation.shown} is an async test no plugin runs: pytest fails it "
                "without running it"
            )
        none = "" if collected.nodes else " (pytest collects no test from it)"
        if citation.form == "node":
            return f"pytest collects no node {rel}::{'::'.join(citation.parts)}{none}"
        kind = "test class" if citation.form == "class" else "test"
        return f"{rel} has no {kind} named {'.'.join(citation.parts)}{none}"


def _found(citation: Citation, nodes: Iterable[tuple[str, ...]]) -> bool:
    """Whether ``nodes`` (collected from the cited file) hold what ``citation`` names."""
    parts = citation.parts
    for node in nodes:
        if citation.form == "node":
            hit = node[: len(parts)] == parts
        elif citation.form == "class":
            hit = parts[0] in node[:-1]
        else:
            hit = len(node) >= len(parts) and node[len(node) - len(parts) :] == parts
        if hit:
            return True
    return False


def scan_test_citations(
    text: str, index: SuiteIndex, identifiers: frozenset[str] = frozenset()
) -> list[tuple[int, str, str]]:
    """Return ``(line_number, citation, reason)`` for every test citation in
    ``text`` that does not resolve against ``index``.  ``identifiers`` are the
    citing file's own code identifiers (see :func:`code_identifiers`)."""
    citations = extract_test_citations(text)
    index.prime(citations)
    findings = []
    for citation in citations:
        reason = index.resolve(citation, identifiers)
        if reason is not None:
            findings.append((citation.line, citation.shown, reason))
    return sorted(set(findings))


def _repo_root_on_path() -> None:
    """Put the repository root on ``sys.path`` so ``tools._repo`` imports.

    The gate also runs as a script, with ``tools/`` on the path instead.  Done
    on demand rather than at import, so the pytest child that loads this file
    (:func:`collect_python`) collects with the ``sys.path`` pytest would."""
    root = str(Path(__file__).resolve().parents[1])
    if root not in sys.path:
        sys.path.insert(0, root)


def _is_historical_record(name: str) -> bool:
    """CHANGELOG.md and ``docs/changelog/``: out of scope, see the module docstring."""
    _repo_root_on_path()
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
    """Every tracked file in scope, via ``tools/_repo.py``'s ``tracked_names``.

    That listing is NUL-separated and :func:`os.fsdecode`-decoded, and raises
    ``TrackedFilesError`` for a tracked path that is not a regular file and
    that git does not report deleted, rather than skipping it.  The historical
    record is not in scope: ``CHANGELOG.md`` is never listed, and the journals
    under ``docs/changelog/`` are dropped here.
    """
    _repo_root_on_path()
    from tools._repo import tracked_names

    files = []
    for name in tracked_names(repo_root, *SCANNED_DIRS, *SCANNED_ROOT_FILES):
        path = repo_root / name
        if name in EXEMPT or not _is_prose(path) or _is_historical_record(name):
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
    """Scan the tree.  Returns ``(files_checked, problem_lines)``.

    The test citations of every shipped file are extracted first, so the
    Python test files they need are collected in a single pytest run."""
    files = _tracked_files(repo_root)
    scanned: list[tuple[str, str, list[tuple[int, str, str]], list[Citation]]] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:  # a binary file that slipped the suffix net
            continue
        rel = path.relative_to(repo_root).as_posix()
        shipped = rel.split("/", 1)[0] in TEST_CITATION_DIRS
        citations = extract_test_citations(text) if shipped else []
        findings = scan_text(text) + (scan_shipped_text(text) if shipped else [])
        scanned.append((rel, text, findings, citations))
    index = SuiteIndex(repo_root)
    index.prime(citation for *_, citations in scanned for citation in citations)
    problems: list[str] = []
    for rel, text, findings, citations in scanned:
        bare = any(citation.form == "bare" for citation in citations)
        identifiers = code_identifiers(text, rel) if bare else frozenset()
        for citation in citations:
            reason = index.resolve(citation, identifiers)
            if reason is not None:
                findings.append((citation.line, citation.shown, reason))
        for line, matched, reason in sorted(set(findings)):
            problems.append(f"{rel}:{line}: {matched!r} — {reason}")
    return len(files), problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reject citations a reader cannot resolve.",
        epilog=(
            "checked: process citations (a dated audit such as "
            "'2026-08 v5 audit', or an 'item N of the audit'), source-line "
            "citations ('at line 632'), and, in ama_cryptography/, src/ and "
            "include/, 'file.c:705' line citations, citations of a tests/ path "
            "git does not track, and of a "
            "test (a node id, a named test in a named file, a bare test name "
            "in a code span) that pytest does not collect or, in C, that the "
            "cited file does not define.\n"
            "NOT checked: whether a resolvable citation is the RIGHT one — this "
            "gate checks that a reader can follow a reference, not that the "
            "reference is correct.  Ambiguous phrasings ('a previous session', "
            '"the audit\'s") are left to review: in this package they also '
            "match correct prose.  So is a bare test name outside a code span, "
            "the shape prose also uses for fields and variables.\n"
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

    _repo_root_on_path()
    from tools._repo import TrackedFilesError

    try:
        checked, problems = check(Path(args.repo))
    except TrackedFilesError as exc:
        # git could not list the tree, or a tracked path is not a file on
        # disk: the scope is unknown, so this is a failure, not a clean tree.
        print(f"FAIL: cannot enumerate the tracked files: {exc}")
        return 1
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
