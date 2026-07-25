#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Enforce one canonical license header on every source file in the tree.

Before this gate existed the repository carried five different header
shapes at once — a two-line ``Licensed under the Apache License,
Version 2.0`` note, the full thirteen-line Apache boilerplate block, a
``SPDX-License-Identifier`` tag on four files, a one-off
``Licensed under the Apache License 2.0`` variant, and the same
variations again in C block-comment form.  Machine license scanners
(SPDX / REUSE) could read none of them reliably, and a new file could
pick any shape without anything noticing.

The canonical header is two lines and carries a *registered* SPDX
identifier.  ``Apache-2.0`` is the identifier from the SPDX license
list; ``Apache 2.0`` is not one and does not parse.  The copyright
line keeps the ``2025-2026`` term the tree already asserted.

For ``#``-comment files (Python, Cython, YAML, shell, CMake, Docker,
pkg-config templates, tool configs)::

    # Copyright (C) 2025-2026 Steel Security Advisors LLC
    # SPDX-License-Identifier: Apache-2.0

For C translation units and headers::

    /* Copyright (C) 2025-2026 Steel Security Advisors LLC */
    /* SPDX-License-Identifier: Apache-2.0 */

Placement rules:
    * A ``#!`` shebang stays the first line; the header follows it.
    * Otherwise the header is the first thing in the file.
    * For Python the header sits *above* the module docstring and the
      docstring is left alone.
    * Existing license text — any of the five shapes — is removed from
      wherever it sits, including from inside a C doc block that also
      carries ``@file`` / ``@brief`` content.  Non-license content in
      that block is preserved.

The root ``LICENSE`` file remains the authoritative license text and
``NOTICE`` is untouched; the per-file header is a pointer, not a
restatement.

Enumeration is via ``git ls-files``, so untracked scratch files are
never rewritten.  Files are selected by extension or exact name (see
``_HASH_SUFFIXES`` / ``_HASH_NAMES`` / ``_C_SUFFIXES``) and then
filtered through ``EXEMPTIONS``, which is explicit and carries a
reason per entry — there is no silent skip.

Exit codes:
    0  every selected file carries the canonical header
    1  one or more files are missing it, carry a stale shape, or
       retain residual license text elsewhere in the file

Usage (CI):
    python tools/check_headers.py --check

Usage (developer):
    python tools/check_headers.py --apply
"""

from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

COPYRIGHT_LINE = "Copyright (C) 2025-2026 Steel Security Advisors LLC"
SPDX_LINE = "SPDX-License-Identifier: Apache-2.0"

HASH_HEADER = (f"# {COPYRIGHT_LINE}", f"# {SPDX_LINE}")
C_HEADER = (f"/* {COPYRIGHT_LINE} */", f"/* {SPDX_LINE} */")

# Files that must carry the ``#``-comment header, by suffix.
_HASH_SUFFIXES = frozenset(
    {".py", ".pyx", ".pyi", ".sh", ".yml", ".yaml", ".toml", ".cmake", ".in"}
)

# Files that must carry the ``#``-comment header, by exact base name.
# These have no suffix that identifies them, or a suffix (``.txt``) that
# is shared with data files we do not head.
_HASH_NAMES = frozenset(
    {
        "CMakeLists.txt",
        "Makefile",
        "Dockerfile",
        "Dockerfile.alpine",
        "Dockerfile.c-api",
        "Doxyfile",
        ".clang-tidy",
        ".clang-format",
        ".pre-commit-config.yaml",
        ".semgrep.yml",
    }
)

# Files that must carry the C block-comment header, by suffix.
_C_SUFFIXES = frozenset({".c", ".h"})

# Explicit exemptions, each with the reason it is exempt.  Entries are
# matched as exact repo-relative paths or, when they end in ``/``, as
# directory prefixes.  Nothing is skipped that is not named here.
EXEMPTIONS: dict[str, str] = {
    "LICENSE": "authoritative license text; a header pointing at itself is circular",
    "NOTICE": "attribution notice required verbatim by Apache-2.0 section 4(d)",
    "src/c/vendor/": (
        "vendored third-party sources (ed25519-donna, public domain) — upstream "
        "provenance must stay byte-identical; see src/c/PROVENANCE.md"
    ),
    "tests/c/dudect/": (
        "vendored third-party test harness (dudect, MIT) — upstream provenance "
        "must stay byte-identical"
    ),
    ".well-known/security.txt": (
        "RFC 9116 security.txt — the format is a fixed field list and a "
        "clear-signed body; a license header would break parsers"
    ),
}

# Phrases that identify a line as license boilerplate.  A line matches
# when, after stripping whitespace and any leading comment punctuation,
# it *begins* with one of these.  The "begins with" rule is what lets
# this module scan itself without matching its own pattern table: the
# entries below are source lines beginning with a quote character, not
# with the phrase.
_LICENSE_PHRASES: tuple[str, ...] = (
    "Copyright 2025",
    "Copyright (C) 2025",
    "Copyright (c) 2025",
    "Copyright 2025-2026",
    "SPDX-License-Identifier:",
    "Licensed under the Apache License",
    'Licensed under the Apache License, Version 2.0 (the "License");',
    "you may not use this file except in compliance with the License.",
    "You may obtain a copy of the License at",
    "http://www.apache.org/licenses/LICENSE-2.0",
    "https://www.apache.org/licenses/LICENSE-2.0",
    "Unless required by applicable law or agreed to in writing, software",
    'distributed under the License is distributed on an "AS IS" BASIS,',
    "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
    "See the License for the specific language governing permissions and",
    "limitations under the License.",
)

_COMMENT_PREFIXES = ("/**", "/*", "*/", "//", "#", "*")


def _strip_comment_prefix(line: str) -> str:
    """Return ``line`` with leading whitespace and one comment marker removed."""
    text = line.strip()
    for prefix in _COMMENT_PREFIXES:
        if text.startswith(prefix):
            return text[len(prefix) :].strip()
    return text


def is_license_line(line: str) -> bool:
    """True when ``line`` is license boilerplate rather than real content."""
    body = _strip_comment_prefix(line)
    return any(body.startswith(phrase) for phrase in _LICENSE_PHRASES)


def _is_bare_comment(line: str, style: str) -> bool:
    """True for a content-free comment line (``#``, `` *``) used as a spacer."""
    text = line.strip()
    if style == "hash":
        return text == "#"
    return text in {"*", "*/"} or (text.startswith("* ") and not text[2:].strip())


def _strip_hash_license(lines: list[str]) -> list[str]:
    """Remove ``#``-comment license text, and the spacers inside it.

    The removal window runs from the first license line to the last, so
    the blank ``#`` spacers *within* the Apache boilerplate go with it
    while a spacer separating the header from unrelated comment content
    below survives.  A blank line orphaned at the top of a module
    docstring — the shape left behind when the license was the
    docstring's opening paragraph, as in the Cython bindings — is
    dropped too.
    """
    idxs = [i for i, line in enumerate(lines) if is_license_line(line)]
    if not idxs:
        return list(lines)
    first, last = idxs[0], idxs[-1]
    kept: list[str] = []
    for i, line in enumerate(lines):
        if first <= i <= last and (is_license_line(line) or _is_bare_comment(line, "hash")):
            continue
        kept.append(line)
    # ``first`` is now the index of whatever followed the license text.
    if first > 0 and kept[first - 1].strip() in {'"""', "'''"}:
        while first < len(kept) and not kept[first].strip():
            del kept[first]
    return kept


def _find_block(lines: list[str], i: int) -> int | None:
    """Index of the line closing the ``/* ... */`` block opened at ``i``."""
    if "*/" in lines[i][lines[i].index("/*") + 2 :]:
        return i
    j = i + 1
    while j < len(lines):
        if "*/" in lines[j]:
            return j
        j += 1
    return None


def _block_content(lines: list[str], i: int, j: int) -> list[tuple[int, str]]:
    """``(index, content)`` for each line of the block spanning ``i..j``.

    The ``/*`` opener and ``*/`` closer tokens are stripped so a line
    that carries license text *inline with a delimiter* — the shape in
    ``ama_ed25519_canonical.h``, whose block opened
    ``/* Copyright ...`` — is classified on its text, not its
    punctuation.
    """
    out: list[tuple[int, str]] = []
    for k in range(i, j + 1):
        text = lines[k]
        if k == i:
            text = text[text.index("/*") + 2 :].lstrip("*")
        if k == j:
            text = text[: text.rindex("*/")]
        out.append((k, _strip_comment_prefix(text)))
    return out


def _strip_c_license(lines: list[str]) -> list[str]:
    """Remove license text from C sources, block by block.

    Operating per block — rather than over a flat line window — is what
    keeps the two mixed shapes in this tree correct.  A block that holds
    *only* license text is deleted outright; a block that opens with
    license lines and continues into ``@file`` / ``@brief`` content
    keeps that content, losing just the license lines and the spacer
    that separated them from it.
    """
    drop: set[int] = set()
    i = 0
    while i < len(lines):
        # Only a line whose first token is ``/*`` opens a block.  Testing
        # for ``/*`` anywhere would misread the token inside a string
        # literal as the start of a comment.
        if not lines[i].lstrip().startswith("/*"):
            if lines[i].lstrip().startswith("//") and is_license_line(lines[i]):
                drop.add(i)
            i += 1
            continue
        j = _find_block(lines, i)
        if j is None:
            break  # Unterminated block: leave the rest of the file alone.
        content = _block_content(lines, i, j)
        licensed = [k for k, text in content if text and is_license_line(text)]
        if licensed:
            body = [(k, text) for k, text in content if text]
            if len(licensed) == len(body):
                # Nothing but license text — the whole block goes.
                drop.update(range(i, j + 1))
                if j + 1 < len(lines) and not lines[j + 1].strip():
                    drop.add(j + 1)
            else:
                drop.update(licensed)
                # Drop the spacer lines that now sit directly under the
                # opener because the license lines above them are gone.
                for k, text in content[1:]:
                    if k in drop:
                        continue
                    if text:
                        break
                    drop.add(k)
        i = j + 1
    return [line for k, line in enumerate(lines) if k not in drop]


def strip_license(lines: list[str], style: str) -> list[str]:
    """Remove every trace of the old license header from ``lines``."""
    if style == "c":
        return _strip_c_license(lines)
    return _strip_hash_license(lines)


def _insertion_index(lines: list[str], style: str) -> int:
    """Index at which the canonical header belongs (after any shebang)."""
    if style == "hash" and lines and lines[0].startswith("#!"):
        return 1
    return 0


def render(text: str, style: str) -> str:
    """Return ``text`` rewritten so it carries exactly the canonical header."""
    trailing_newline = text.endswith("\n")
    lines = text.split("\n")
    if trailing_newline:
        lines = lines[:-1]

    lines = strip_license(lines, style)
    header = list(HASH_HEADER if style == "hash" else C_HEADER)
    at = _insertion_index(lines, style)

    # Collapse blank lines directly under the insertion point so the
    # header always sits flush against whatever follows it, then let the
    # original spacing below re-assert itself.
    while at < len(lines) and not lines[at].strip():
        del lines[at]

    lines[at:at] = header
    out = "\n".join(lines)
    return out + "\n" if trailing_newline else out


def style_for(rel: str) -> str | None:
    """Return ``"hash"``, ``"c"``, or None when ``rel`` is not a headed file."""
    path = Path(rel)
    if path.suffix in _C_SUFFIXES:
        return "c"
    if path.name in _HASH_NAMES:
        return "hash"
    if path.suffix in _HASH_SUFFIXES:
        return "hash"
    return None


def is_exempt(rel: str) -> bool:
    """True when ``rel`` is named in ``EXEMPTIONS``."""
    for entry in EXEMPTIONS:
        if entry.endswith("/"):
            if rel.startswith(entry):
                return True
        elif rel == entry:
            return True
    return False


def tracked_files(root: Path) -> list[str]:
    """Repo-relative paths of every file tracked by git under ``root``."""
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return [p for p in result.stdout.split("\0") if p]


def selected_files(root: Path) -> list[tuple[str, str]]:
    """``(relpath, style)`` for every tracked file that must carry a header."""
    out: list[tuple[str, str]] = []
    for rel in tracked_files(root):
        if is_exempt(rel):
            continue
        style = style_for(rel)
        if style is None:
            continue
        if not (root / rel).is_file():
            continue
        out.append((rel, style))
    return sorted(out)


def quoted_lines(text: str) -> frozenset[int]:
    """0-based line numbers inside a Python string literal, docstring aside.

    ``ama_cryptography/_build_sign.py`` holds the *template* for the
    generated ``_integrity_signature.py``, and that template contains a
    literal ``# SPDX-License-Identifier:`` line.  Read as raw text it is
    indistinguishable from a stray second header, so the residual scan
    has to know it is data inside a string rather than a comment.

    The module docstring is deliberately *not* excluded: the Cython
    bindings used to carry their license as the docstring's opening
    paragraph, and that shape must still be caught.

    Returns an empty set when ``text`` does not parse as Python — a
    ``.pyx`` using Cython-only syntax, for instance — which leaves the
    scan in its stricter whole-file mode rather than silently trusting
    an unparsed file.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return frozenset()

    docstring_span: set[int] = set()
    body = tree.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        doc = body[0].value
        docstring_span = set(range(doc.lineno - 1, doc.end_lineno or doc.lineno))

    inside: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            inside.update(range(node.lineno - 1, node.end_lineno or node.lineno))
    return frozenset(inside - docstring_span)


def diagnose(text: str, style: str) -> str | None:
    """Return a one-line reason ``text`` is non-compliant, or None if it is."""
    lines = text.split("\n")
    header = list(HASH_HEADER if style == "hash" else C_HEADER)
    at = _insertion_index(lines, style)
    if lines[at : at + len(header)] != header:
        if any(is_license_line(line) for line in lines):
            return "non-canonical license header"
        return "missing license header"
    # Header is in place; nothing else in the file may look like license text.
    skip = set(range(at, at + len(header))) | quoted_lines(text)
    residue = [
        f"{i + 1}: {line.strip()}"
        for i, line in enumerate(lines)
        if i not in skip and is_license_line(line)
    ]
    if residue:
        return f"residual license text at line {residue[0]}"
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--check",
        action="store_true",
        help="report non-compliant files and exit 1 (default)",
    )
    group.add_argument(
        "--apply",
        action="store_true",
        help="rewrite non-compliant files in place",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO,
        help="repository root to scan (default: this checkout)",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    files = selected_files(root)
    offenders: list[tuple[str, str]] = []

    for rel, style in files:
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            offenders.append((rel, "not valid UTF-8"))
            continue
        reason = diagnose(text, style)
        if reason is None:
            continue
        if args.apply:
            path.write_text(render(text, style), encoding="utf-8")
            still = diagnose(path.read_text(encoding="utf-8"), style)
            if still is not None:
                offenders.append((rel, f"rewrite did not converge: {still}"))
            continue
        offenders.append((rel, reason))

    if offenders:
        verb = "could not be normalized" if args.apply else "carry a non-canonical header"
        print(f"FAIL: {len(offenders)} of {len(files)} files {verb}:", file=sys.stderr)
        for rel, reason in offenders:
            print(f"  - {rel}: {reason}", file=sys.stderr)
        if not args.apply:
            print(
                "\nRun `python tools/check_headers.py --apply` to normalize them.",
                file=sys.stderr,
            )
        return 1

    action = "normalized" if args.apply else "checked"
    print(f"OK    {len(files)} files {action}; canonical header present in all of them")
    print(f"OK    {len(EXEMPTIONS)} documented exemptions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
