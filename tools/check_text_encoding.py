#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Every Text-Mode File Access Names Its Encoding
=================================================================

Refuses a text-mode file read or write in this tree's Python that leaves the
codec to the host locale.

Why this exists
---------------
Python's text I/O defaults to ``locale.getpreferredencoding()``: UTF-8 on the
Linux and macOS runners, cp1252 on the Windows runners.  A call that names no
encoding therefore reads or writes different bytes on different platforms, and
the difference only shows when the text is not ASCII.

It failed every Windows leg of 187934e6.  ``test_keygen_pct_gate`` copied the
Cython bindings into a scratch tree with UTF-8 named on each read and write,
then rewrote one of them with a bare ``write_text``.  The em dash in that
file's header went out as the single cp1252 byte 0x97, and the gate's UTF-8
read of the scratch copy raised before it could return its verdict.  A survey
of the tree then found 216 more calls of the same shape: 147 ``read_text`` /
``write_text`` and 69 text-mode ``open``.  None had failed yet; each was one
non-ASCII byte away from doing so on one platform only.

All of them name UTF-8 in the commit that added this gate, so the gate starts
at zero findings and holds the class shut.  There is no exemption list: a site
that genuinely wants the locale codec names ``encoding="locale"`` (Python
3.10+), which says so in the source and passes.

Why not ruff's PLW1514
----------------------
It is a preview rule in the pinned ruff, and enabling preview changes the
behaviour of stable rules across the tree.  It also only recognises
``read_text`` / ``write_text`` on a receiver it can infer to be a ``Path``;
measured on this tree it does not flag the ``tmp_path / ...`` expression the
Windows failure came from.  This gate matches by call shape, so it does.

What is checked
---------------
Every ``.py`` file under the scanned roots, parsed with ``ast``:

* ``<anything>.read_text(...)`` and ``<anything>.write_text(...)``;
* ``open(...)``, ``io.open(...)``, ``os.fdopen(...)`` and ``Path.open(...)``
  whose mode is text — omitted, or a string literal without ``b``.  ``os.open``
  returns a descriptor and involves no codec; any other ``.open`` whose first
  argument is not a mode literal (``OpenerDirector.open(request)``, an
  archive's ``.open(member)``) is not a text-file open and is not matched;
* ``tempfile.NamedTemporaryFile`` / ``TemporaryFile`` /
  ``SpooledTemporaryFile`` with a text mode (their default mode is binary).

Each must pass ``encoding=``.  A call that forwards ``**kwargs`` or computes its
mode at runtime cannot be decided statically and is reported, not guessed.

Exit status
-----------
0 no finding; 1 one or more findings (printed as ``path:line: message``).
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path
from typing import Iterator, NamedTuple, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Directories and files scanned, relative to the repository root.
SCAN_ROOTS: tuple[str, ...] = (
    "ama_cryptography",
    "benchmarks",
    "docs",
    "examples",
    "fuzz",
    "nist_vectors",
    "tests",
    "tools",
    "setup.py",
)

#: Path components never scanned: build output, virtual environments, caches.
SKIP_PARTS = frozenset({"_build", "build", "__pycache__", ".venv", "venv", ".claude"})

#: A floor on files parsed, so a mis-rooted run cannot pass by scanning nothing.
MIN_FILES = 300

_TEMPFILE_TEXT_FACTORIES = frozenset(
    {"NamedTemporaryFile", "TemporaryFile", "SpooledTemporaryFile"}
)

#: Receivers whose `.open` is the POSIX-level call returning a descriptor.
_FD_LEVEL_MODULES = frozenset({"os", "_os"})

#: Characters a Python file mode is made of; a literal outside them is a name.
_MODE_CHARS = frozenset("rwxabt+U")


def _is_mode_literal(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and bool(node.value)
        and set(node.value) <= _MODE_CHARS
    )


class Finding(NamedTuple):
    path: str
    line: int
    message: str


def _keyword(call: ast.Call, name: str) -> Optional[ast.keyword]:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword
    return None


def _forwards_kwargs(call: ast.Call) -> bool:
    return any(keyword.arg is None for keyword in call.keywords)


def _mode_node(call: ast.Call, positional_index: int) -> Optional[ast.expr]:
    keyword = _keyword(call, "mode")
    if keyword is not None:
        return keyword.value
    if len(call.args) > positional_index:
        return call.args[positional_index]
    return None


def _mode_is_text(node: Optional[ast.expr], default_text: bool) -> Optional[bool]:
    """True text, False binary, None undecidable."""
    if node is None:
        return default_text
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return "b" not in node.value
    return None


def _callee_name(call: ast.Call) -> Optional[str]:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    if isinstance(call.func, ast.Name):
        return call.func.id
    return None


def check_call(call: ast.Call) -> Optional[str]:
    """The finding for one call, or None when it names its encoding or is binary."""
    name = _callee_name(call)
    if name is None or _keyword(call, "encoding") is not None:
        return None
    if name in ("read_text", "write_text") and isinstance(call.func, ast.Attribute):
        if _forwards_kwargs(call):
            return f"`{name}` forwards **kwargs, so its encoding cannot be verified"
        return f"`{name}` without `encoding=` uses the locale codec (cp1252 on Windows)"
    if name == "open" and isinstance(call.func, ast.Attribute):
        receiver = ast.unparse(call.func.value)
        if receiver in _FD_LEVEL_MODULES:
            return None  # os.open returns a file descriptor; no codec is involved
        if receiver == "io":
            index = 1  # io.open is builtins.open
        else:
            # Path.open(mode, ...).  Any other `.open` whose first argument is
            # not a mode literal -- an OpenerDirector's `.open(request)`, an
            # archive's `.open(member)` -- is not a text-file open at all.
            first = call.args[0] if call.args else None
            if first is not None and not _is_mode_literal(first):
                return None
            index = 0
        text = _mode_is_text(_mode_node(call, index), default_text=True)
        if text is False:
            return None
        if text is None or _forwards_kwargs(call):
            return "`open` with a computed mode or **kwargs cannot be verified; name `encoding=`"
        return "text-mode `open` without `encoding=` uses the locale codec (cp1252 on Windows)"
    if name in ("open", "fdopen"):
        # builtins.open(file, mode, ...) and os.fdopen(fd, mode, ...).
        index = 1
        text = _mode_is_text(_mode_node(call, index), default_text=True)
        if text is False:
            return None
        if text is None or _forwards_kwargs(call):
            return "`open` with a computed mode or **kwargs cannot be verified; name `encoding=`"
        return "text-mode `open` without `encoding=` uses the locale codec (cp1252 on Windows)"
    if name in _TEMPFILE_TEXT_FACTORIES:
        text = _mode_is_text(_mode_node(call, 0), default_text=False)
        if text is False:
            return None
        if text is None or _forwards_kwargs(call):
            return f"`{name}` with a computed mode or **kwargs cannot be verified"
        return f"text-mode `{name}` without `encoding=` uses the locale codec"
    return None


def scan_source(source: str, path: str) -> list[Finding]:
    tree = ast.parse(source, filename=path)
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            message = check_call(node)
            if message is not None:
                findings.append(Finding(path, node.lineno, message))
    return sorted(findings)


def iter_files(root: Path) -> Iterator[Path]:
    for entry in SCAN_ROOTS:
        base = root / entry
        if base.is_file():
            yield base
            continue
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if SKIP_PARTS.isdisjoint(path.relative_to(root).parts):
                yield path


def scan(root: Path) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    count = 0
    for path in iter_files(root):
        count += 1
        rel = path.relative_to(root).as_posix()
        findings.extend(scan_source(path.read_text(encoding="utf-8"), rel))
    return findings, count


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Refuse text-mode file access that leaves the codec to the host locale."
    )
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root")
    parser.add_argument(
        "--min-files",
        type=int,
        default=MIN_FILES,
        help=f"fail when fewer files are parsed (default {MIN_FILES})",
    )
    args = parser.parse_args(argv)

    findings, count = scan(args.root)
    if count < args.min_files:
        print(
            f"FAIL: parsed {count} file(s), below the floor of {args.min_files}; "
            "the scan roots do not match this tree",
            file=sys.stderr,
        )
        return 1
    if findings:
        for finding in findings:
            print(f"{finding.path}:{finding.line}: {finding.message}")
        print(
            f"\nFAIL: {len(findings)} text-mode file access(es) name no encoding. "
            'Pass encoding="utf-8" (or encoding="locale" where the host codec is '
            "the intent).",
            file=sys.stderr,
        )
        return 1
    print(f"OK: {count} file(s); every text-mode read and write names its encoding.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
