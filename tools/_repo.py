#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Shared git file enumeration for the gate scripts
===================================================================

Every gate that asks git "which files are in scope" goes through here, so the
enumeration is exact and fails closed in one place instead of six.

Why this module exists
----------------------
Six gates listed files with a bare ``git ls-files`` and split the output on
newlines.  Without ``-z`` git C-quotes any path holding a byte outside
printable ASCII (``core.quotePath``): ``clé_key.txt`` is printed as
``"cl\\303\\251_key.txt"``, quotes included.  That string names no file, so
``is_file()`` was False and every one of those gates dropped the file without
a word — a planted AWS key in ``clé_key.txt`` passed ``check_secrets.py``, a
bare ``# noqa`` in ``zz_é.py`` passed ``check_suppression_hygiene.py``.

Here the listing is NUL-separated (``-z``, which also disables quoting),
decoded with :func:`os.fsdecode` (the filesystem encoding with
``surrogateescape``, so a name that is not valid UTF-8 still round-trips to
the same bytes on disk), and every listed path must be a regular file on disk.
A tracked path that is not is an error, with exactly one exception: a path
that is absent from the working tree AND that ``git ls-files --deleted``
reports as deleted.  Deleting a file you are about to commit the removal of is
a normal development state; a tracked path that exists as something other
than a regular file (a directory, a dangling symlink, a submodule), or that is
missing without git agreeing it was deleted, is not — skipping it would be the
same silent narrowing this module removes.

Import
------
Gates run both as scripts (``python3 tools/check_X.py``, where ``tools/`` —
not the repository root — is on ``sys.path``) and as modules loaded by tests,
sometimes through ``importlib.util.spec_from_file_location`` under a bare
name.  Each caller therefore puts the repository root on ``sys.path`` and
imports ``from tools._repo import ...``, the pattern ``check_avx_scoping.py``
and ``build_post_kats.py`` already use for their sibling imports.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Sequence

__all__ = [
    "TrackedFilesError",
    "repo_root",
    "staged_files",
    "tracked_files",
    "tracked_names",
]

_GIT_TIMEOUT_SECONDS = 60


class TrackedFilesError(RuntimeError):
    """git could not enumerate, or a listed path is not a regular file on disk.

    A ``RuntimeError`` so callers that already treated an enumeration failure
    as ``RuntimeError`` keep doing so.
    """


def repo_root() -> Path:
    """The repository this module is checked out in."""
    return Path(__file__).resolve().parent.parent


def _git_names(root: Path, args: Sequence[str]) -> list[str]:
    """Run ``git <args>`` (which must request ``-z`` output) in ``root``."""
    argv = ["git", *args]
    try:
        proc = subprocess.run(
            argv,
            cwd=str(root),
            capture_output=True,
            check=False,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise TrackedFilesError(f"unable to run `{' '.join(argv)}` in {root}: {exc}") from exc
    if proc.returncode != 0:
        stderr = os.fsdecode(proc.stderr).strip()
        raise TrackedFilesError(
            f"`{' '.join(argv)}` failed in {root} (exit {proc.returncode}): {stderr}"
        )
    return [os.fsdecode(name) for name in proc.stdout.split(b"\0") if name]


def tracked_names(root: Path, *pathspecs: str) -> list[str]:
    """Every file git tracks under ``root`` matching ``pathspecs``, as git names it.

    Names are ``/``-separated and relative to ``root``, in git's order.
    ``pathspecs`` are passed to git verbatim after ``--`` (so ``"*.py"`` keeps
    git's wildmatch semantics and ``":(glob)src/c/*.c"`` its pathspec magic);
    none means every tracked file.

    Raises :class:`TrackedFilesError` if git fails or a listed path is not a
    regular file on disk and is not a working-tree deletion git confirms.
    """
    names = _git_names(root, ["ls-files", "-z", "--", *pathspecs])
    deleted: set[str] | None = None
    out: list[str] = []
    for name in names:
        path = root / name
        if path.is_file():
            out.append(name)
            continue
        if deleted is None:
            deleted = set(_git_names(root, ["ls-files", "-z", "--deleted", "--", *pathspecs]))
        if name in deleted and not os.path.lexists(path):
            continue  # deleted in the working tree; git agrees
        raise TrackedFilesError(
            f"git tracks {name!r} under {root} but it is not a regular file on disk "
            "(and git does not report it as deleted); refusing to skip it"
        )
    return out


def tracked_files(root: Path, *pathspecs: str) -> list[Path]:
    """:func:`tracked_names`, each joined onto ``root``."""
    return [root / name for name in tracked_names(root, *pathspecs)]


def staged_files(root: Path) -> list[Path]:
    """Files added, copied or modified in the index, as ``root / name``.

    ``root`` must be the top of the work tree: ``git diff --name-only`` reports
    paths relative to it.  A staged path that is not a regular file on disk is
    an error — its staged content still goes into the commit, so skipping it
    would pass exactly the file a pre-commit scan exists to see.
    """
    names = _git_names(root, ["diff", "--cached", "--name-only", "-z", "--diff-filter=ACM"])
    out: list[Path] = []
    for name in names:
        path = root / name
        if not path.is_file():
            raise TrackedFilesError(
                f"{name!r} is staged but is not a regular file in the working tree "
                f"under {root}; refusing to skip it"
            )
        out.append(path)
    return out
