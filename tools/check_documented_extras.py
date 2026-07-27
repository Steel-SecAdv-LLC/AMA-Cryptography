#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Documented Install Extra Verifier (INVARIANT-32)
===================================================================

Verifies that every optional-dependency extra named in a documented
``pip install`` command is actually declared in ``pyproject.toml``.

Why this exists
---------------
``pip`` does not fail on an extra a distribution does not provide.  It emits a
warning and installs the package **without** it, exiting 0:

.. code-block:: text

    $ pip install "./pkg[nosuchextra]"
    Would install extra-probe-0.1
    $ echo $?
    0

So a typo or a stale name in an install instruction does not produce an
error the reader can act on.  It produces a package that is missing the
dependencies the reader was told they were installing, and a success message.
The failure surfaces much later as an ``ImportError`` from a subsystem the
user believes they enabled.

That shipped.  ``wiki/Installation.md`` — a page published to the public
GitHub Wiki by ``wiki-sync.yml`` — offered an editable install for an extra
named ``secure-memory``, described it as *"Libsodium secure memory bindings"*,
and listed the same name in its *"Everything at once"* command.  No such extra
has ever existed, so anyone following the wiki's own recommended line got a
silently incomplete install.

The description was wrong in a second, worse way.
``ama_cryptography.secure_memory`` is dependency-free: Python standard library
plus the native C library already built in the preceding step, reached through
``ctypes`` for ``ama_consttime_memcmp`` / ``mlock`` / ``VirtualLock``, with a
pure-Python fallback when that library is absent.  There is no libsodium
anywhere in it — and INVARIANT-1 forbids libsodium by name.  So the public
install page advertised a third-party cryptographic dependency that the
project's foundational invariant prohibits, for a module that needs no
dependency at all.

An install instruction is API surface.  This checker treats it as such.

What is checked
---------------
Every ``pip install`` command in the tracked documentation set is parsed for
extras, and each extra is matched against ``[project.optional-dependencies]``
in ``pyproject.toml`` using PEP 685 normalisation (case-folded, with runs of
``-``, ``_`` and ``.`` collapsed to a single ``-``) — the same comparison pip
itself performs, so a name that differs only in punctuation is correctly
accepted rather than reported.

``CHANGELOG.md`` is excluded by design: it is a historical record, and an
extra that genuinely existed in an earlier release must remain readable in
the entry that introduced or removed it.

Both directions are pinned by ``tests/test_documented_extras.py``, so this
gate cannot silently degrade into a no-op.

Usage
-----
::

    python tools/check_documented_extras.py

Exits 0 when every documented extra is declared, 1 otherwise.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Callable, Optional

# ``tomllib`` is stdlib from Python 3.11.  This project supports 3.10
# (``requires-python >= 3.10``, and the mypy target is 3.10), so it cannot be
# imported unconditionally — ``tools/generate_sbom.py`` avoids it for the same
# reason.  Use it when present for an exact parse, and fall back to reading the
# one table this checker needs.  ``test_documented_extras.py`` asserts both
# paths return the same extras for the repository's own ``pyproject.toml``, so
# the fallback cannot silently drift from the real parser.
#
# The version test is written as ``sys.version_info`` rather than a
# try/except ImportError so that mypy — pinned to ``python_version = "3.10"``
# by pyproject.toml — narrows it statically instead of reporting the import as
# unresolvable on every run.
_toml_load: Optional[Callable[[Any], dict[str, Any]]]
if sys.version_info >= (3, 11):
    import tomllib

    _toml_load = tomllib.load
else:  # pragma: no cover - exercised only on Python 3.10
    _toml_load = None

# Directories and files scanned for install instructions.
DOC_GLOBS = ("*.md", "*.rst", "wiki/*.md", "docs/**/*.md", "docs/**/*.rst")

# A historical record, not an instruction to a current reader.
EXCLUDED = {"CHANGELOG.md"}

# An extras group attached to a requirement: the bracket must directly follow
# `.` (as in `-e ".[dev]"`) or a package-name character (as in
# `ama-cryptography[math]`).  Requiring that prefix is what keeps ordinary
# Markdown link syntax — `[Installation Guide](...)`, preceded by whitespace
# or a line start — from being read as an extras group.
EXTRAS_RE = re.compile(r"(?<=[\w.])\[([^\]\n]+)\]")

# Shape of a comma-separated extras list.  Anything else in brackets after a
# word character is not an extras group and is left alone.
EXTRAS_LIST_RE = re.compile(r"^[A-Za-z0-9._\- ]+(?:,[A-Za-z0-9._\- ]+)*$")

# PEP 685: compare extra names with case folded and punctuation runs collapsed.
_NORMALISE_RE = re.compile(r"[-_.]+")


def normalise(extra: str) -> str:
    """Return the PEP 685 comparison key for an extra name."""
    return _NORMALISE_RE.sub("-", extra.strip().lower())


OPTIONAL_TABLE = "[project.optional-dependencies]"

# A bare TOML key at the start of a line: `dev = [...]`.
_KEY_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*=")


def declared_extras_fallback(pyproject: Path) -> set[str]:
    """Read the extras table without a TOML parser (Python 3.10 path).

    Only the *keys* of ``[project.optional-dependencies]`` are needed, so this
    walks that one table and tracks bracket depth: a key is recognised only at
    depth zero, which keeps the contents of a multi-line dependency array —
    ``"pytest>=9.1.1",`` and friends — from being mistaken for keys.
    """
    extras: set[str] = set()
    in_table = False
    depth = 0

    for line in pyproject.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        # At depth zero a line opening with `[` can only be a table header —
        # array elements live at depth one or deeper.
        if depth == 0 and stripped.startswith("["):
            in_table = stripped.startswith(OPTIONAL_TABLE)
            continue

        if in_table and depth == 0:
            match = _KEY_RE.match(line)
            if match:
                extras.add(match.group(1))

        depth = max(depth + line.count("[") - line.count("]"), 0)

    return {normalise(name) for name in extras}


def declared_extras(pyproject: Path) -> set[str]:
    """Return the normalised set of extras declared in pyproject.toml."""
    if _toml_load is None:
        return declared_extras_fallback(pyproject)
    with pyproject.open("rb") as handle:
        data = _toml_load(handle)
    optional = data.get("project", {}).get("optional-dependencies", {}) or {}
    return {normalise(name) for name in optional}


def extras_in_line(line: str) -> set[str]:
    """Return every extra named in a single ``pip install`` line."""
    found: set[str] = set()
    for group in EXTRAS_RE.findall(line):
        if not EXTRAS_LIST_RE.match(group):
            continue
        for extra in group.split(","):
            extra = extra.strip()
            if extra:
                found.add(extra)
    return found


def scan(root: Path) -> dict[str, list[tuple[str, int, str]]]:
    """Map each documented extra to the (file, line, text) sites naming it."""
    sites: dict[str, list[tuple[str, int, str]]] = {}
    seen: set[Path] = set()

    for pattern in DOC_GLOBS:
        for path in sorted(root.glob(pattern)):
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            relative = path.relative_to(root).as_posix()
            if relative in EXCLUDED:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for number, line in enumerate(text.splitlines(), start=1):
                if "pip install" not in line:
                    continue
                for extra in extras_in_line(line):
                    sites.setdefault(extra, []).append((relative, number, line.strip()))
    return sites


def audit(root: Path) -> tuple[list[str], int, int]:
    """Check every documented extra.

    Returns ``(failures, documented_count, site_count)``.
    """
    declared = declared_extras(root / "pyproject.toml")
    sites = scan(root)

    failures: list[str] = []
    for extra in sorted(sites):
        if normalise(extra) in declared:
            continue
        for relative, number, line in sites[extra]:
            failures.append(
                f"{relative}:{number}: install command names extra "
                f"'{extra}', which pyproject.toml does not declare. pip "
                f"accepts this and installs WITHOUT it, exiting 0 — the "
                f"reader gets an incomplete install and no error.\n"
                f"        {line}\n"
                f"        declared extras: {', '.join(sorted(declared))}"
            )

    site_count = sum(len(entries) for entries in sites.values())
    return failures, len(sites), site_count


def main() -> int:
    root = Path.cwd()
    if not (root / "pyproject.toml").is_file():
        print("ERROR: pyproject.toml not found — run from the repository root.")
        return 1

    failures, documented, sites = audit(root)

    print("INVARIANT-32: documented install extras")
    print(f"  distinct extras documented: {documented} across {sites} site(s)")

    if failures:
        print(f"  FAIL — {len(failures)} finding(s):\n")
        for failure in failures:
            print(f"    ::error::{failure}\n")
        return 1

    print("  PASS — every documented extra is declared in pyproject.toml.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
