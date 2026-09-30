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

Historical records
------------------
Several gates and tests leave the project's historical record alone: its
entries describe the tree as it stood when they were written, so a stale count,
a retired claim or a deleted path inside one is accurate about the past, and
editing it to satisfy a present-day check would falsify the one kind of document
whose value is that it is not revised.  That record used to be one file,
``CHANGELOG.md``, and each of those sites named it by file name.  Since the
5.0.0 development journal moved to ``docs/changelog/`` it is a file and a
directory, so :func:`is_historical_record` is the one definition every such
site asks, rather than each carrying its own copy of the list.  It is
deliberately exact: the root ``CHANGELOG.md`` and the files under
``docs/changelog/``, nothing matched by name or pattern anywhere else.

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
import posixpath
import re
import subprocess
from pathlib import Path
from typing import Callable, Collection, Sequence

__all__ = [
    "HISTORICAL_RECORD_DIRS",
    "HISTORICAL_RECORD_FILES",
    "TrackedFilesError",
    "is_historical_record",
    "repo_root",
    "staged_files",
    "tracked_files",
    "tracked_names",
    "worktree_names",
]

_GIT_TIMEOUT_SECONDS = 60

#: Repository-relative files that are historical records.
HISTORICAL_RECORD_FILES: frozenset[str] = frozenset({"CHANGELOG.md"})

#: Repository-relative directories every file under which is a historical
#: record: a release's dated development journal, moved out of
#: ``CHANGELOG.md`` so the changelog reads as release notes.
HISTORICAL_RECORD_DIRS: tuple[str, ...] = ("docs/changelog",)


def is_historical_record(path: str | os.PathLike[str], repo: Path | None = None) -> bool:
    """Whether ``path`` is one of the project's historical records.

    True for the root ``CHANGELOG.md`` and for any file under
    ``docs/changelog/``; False for everything else, including a file named
    ``CHANGELOG.md`` in any other directory.  See the module docstring for why
    the sites that exempt these files ask this rather than naming them.

    A relative ``path`` is read as relative to the repository root.  An
    absolute one is made relative to ``repo`` (default: :func:`repo_root`), so
    a gate scanning a fixture repository passes that repository; a path
    outside it is not a record of that repository and the answer is False.
    """
    candidate = Path(path)
    if candidate.is_absolute():
        base = repo if repo is not None else repo_root()
        try:
            candidate = candidate.relative_to(base)
        except ValueError:
            try:
                candidate = candidate.resolve().relative_to(base.resolve())
            except ValueError:
                return False
    relative = posixpath.normpath(candidate.as_posix())
    if relative in HISTORICAL_RECORD_FILES:
        return True
    return any(relative.startswith(f"{directory}/") for directory in HISTORICAL_RECORD_DIRS)


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


_GLOB_MAGIC = ":(glob)"


def _glob_pathspec(pathspec: str) -> Callable[[str], bool]:
    """The walk's reading of one ``:(glob)`` pathspec: a predicate on a
    ``/``-separated name relative to the root, true where ``git ls-files``
    would list that name.

    git (2.43, measured) matches ``:(glob)`` with wildmatch in pathname mode,
    over the name's bytes: ``*`` and ``?`` never match ``/``, and ``?`` is one
    byte (``cl?.md`` does not list ``clé.md``); a component of stars only
    (``**``) matches any run of whole directories (``**/X`` also matches a
    root-level ``X``).  Before that, a pathspec equal to a name, or to one of
    its leading directories, matches it literally (``:(glob)tests`` lists
    everything under ``tests/``).  A ``**`` that shares its component is
    refused, since git reads it as a ``*`` only in some positions: ``src/**.c``
    lists what ``src/*.c`` lists, but ``tests/test_**/*.py`` lists
    ``tests/test_z.py`` and ``tests/test_x/deep/y.py``, neither of which
    ``tests/test_*/*.py`` lists.  Anything outside this grammar raises
    ``ValueError`` in both modes of :func:`worktree_names`, so no caller
    depends on a pathspec git and the walk would read differently.
    """
    if not pathspec.startswith(_GLOB_MAGIC):
        raise ValueError(
            f"worktree_names takes only {_GLOB_MAGIC!r} pathspecs, which the walk "
            f"outside a checkout matches as git does; got {pathspec!r}"
        )
    pattern = pathspec[len(_GLOB_MAGIC) :]
    parts = pattern.split("/")
    if any(part in ("", ".", "..") for part in parts) or any(c in pattern for c in "[\\"):
        raise ValueError(
            f"{pathspec!r}: the walk matches literal characters, '*', '?' and "
            "'**' between non-empty path components, and nothing else"
        )
    if any("**" in part and part.strip("*") for part in parts):
        raise ValueError(
            f"{pathspec!r}: '**' must be a whole path component; git reads one "
            "that shares its component as a '*' only in some positions"
        )
    regex: list[bytes] = []
    for index, part in enumerate(os.fsencode(pattern).split(b"/")):
        last = index == len(parts) - 1
        if len(part) > 1 and not part.strip(b"*"):
            regex.append(b".*" if last else b"(?:.*/)?")
            continue
        regex.extend(
            b"[^/]*" if run == b"*" else b"[^/]" if run == b"?" else re.escape(run)
            for run in re.findall(rb"\*|\?|[^*?]+", part)
        )
        if not last:
            regex.append(b"/")
    compiled = re.compile(b"".join(regex), re.DOTALL)
    prefix = pattern + "/"
    return lambda name: (
        name == pattern
        or name.startswith(prefix)
        or compiled.fullmatch(os.fsencode(name)) is not None
    )


def worktree_names(root: Path, *pathspecs: str, walk_skip_dirs: Collection[str] = ()) -> list[str]:
    """Every file a scan of ``root`` should read, ``/``-separated and relative
    to it: in a checkout, what git tracks; outside one, every regular file.

    A build leaves untracked files in the work tree that are not the tree's
    documentation: Cython writes each ``.pyx`` docstring into a generated
    ``src/cython/*.c``, and packaging writes ``*.egg-info/``.  A walk reads
    them; git's list does not.

    Only the absence of ``.git`` selects the walk (a source tarball, a gate's
    own fixture directory): a ``.git`` that git cannot read is a checkout git
    failed on, and :class:`TrackedFilesError` says so rather than the scan
    quietly widening.

    ``pathspecs`` narrow the list as they narrow ``git ls-files``, whose list
    it is in a checkout; outside one the walk applies the same match
    (:func:`_glob_pathspec`, which also says why only ``:(glob)`` is taken).
    None means every file.  The walk never enters a ``.git`` (git lists no
    path through one) nor a directory named in ``walk_skip_dirs``: outside a
    checkout nothing says which directories are build output, so a caller
    that knows names them.  In a checkout git's list is the answer and
    ``walk_skip_dirs`` is not consulted.  Both modes return git's order.
    """
    matchers = [_glob_pathspec(pathspec) for pathspec in pathspecs]
    if (root / ".git").exists():
        return tracked_names(root, *pathspecs)
    names: list[str] = []
    for directory, subdirectories, files in os.walk(root):
        subdirectories[:] = [d for d in subdirectories if d != ".git" and d not in walk_skip_dirs]
        base = Path(directory).relative_to(root).as_posix()
        for file_name in files:
            name = file_name if base == "." else f"{base}/{file_name}"
            if file_name == ".git" or not os.path.isfile(os.path.join(directory, file_name)):
                continue
            if matchers and not any(match(name) for match in matchers):
                continue
            names.append(name)
    return sorted(names, key=os.fsencode)


def staged_files(root: Path) -> list[Path]:
    """Every path the index would commit content for, as ``root / name``.

    That is every staged change except a deletion: ``--diff-filter=d`` excludes
    ``D`` and nothing else.  The filter used to be ``ACM``, an allow-list, and
    two statuses fell outside it.  ``git diff`` detects renames by default, so
    ``git mv config.py settings.py`` followed by an edit and ``git add`` stages
    ``settings.py`` as ``R``; a symlink replaced by a regular file is ``T``.
    Both carry new content into the commit and both were dropped, so the
    pre-commit secret scan passed a key added to either.  Excluding the one
    status that carries no content, rather than listing the ones that do, keeps
    a status this list did not anticipate in scope.  With ``--name-only`` a
    rename or copy is reported by its new name, the file on disk.

    ``root`` must be the top of the work tree: ``git diff --name-only`` reports
    paths relative to it.  A staged path that is not a regular file on disk is
    an error — its staged content still goes into the commit, so skipping it
    would pass exactly the file a pre-commit scan exists to see.
    """
    names = _git_names(root, ["diff", "--cached", "--name-only", "-z", "--diff-filter=d"])
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
