#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Report the branch arcs under `src/c` that ctest (with `--python-suite`, every suite) never takes.

WHY THIS IS A REPORT AND NOT A GATE

A guard nothing executes is invisible: deleting it breaks no test, so the
suite stays green whatever it was protecting. Two such guards were found by
running this measurement against the tree (see the 2026-09-17 entries in
CHANGELOG.md) -- in both cases the shipped behaviour was already correct and
only the test weight was missing.

The obvious next step, failing CI on any never-taken arc, is the wrong one
here and is deliberately not taken. A large share of the arcs under `src/c`
are unreachable on any single machine by construction: CPU-feature branches
for ISAs the host does not implement, allocation-failure returns, and SIMD
kernels other runners cover. Turning that into a gate would require an
exemption list naming hundreds of arcs -- which is the shape of thing this
project removed in the twenty-second maintenance pass, on the grounds that a
suppression is not a fix. So this prints an inventory, and reading it is the
work; nothing here decides a build.

AGGREGATION IS THE POINT

gcov writes one report per object, and a header instantiated in several
translation units gets a separate report from each -- overwriting the last if
they share a directory. Reading any single one understates coverage, because
an arc taken in another instantiation looks untaken. Every object carrying a
.gcda (`x.c.o`, or `x.c.obj` as CMake names it on Windows) is therefore
expanded into its own directory and the results are merged: an arc counts as
covered when ANY translation unit took it.

An arc is keyed by file, line and the branch's index in gcov's row for the
line -- and, on a line several functions start on, by function too. There
gcov prints one block per function and restarts the index in each, so keyed
by line alone a never-taken arc of one function was hidden behind a taken
arc of another (two functions expanded from one macro line). Everywhere else
the function stays out of the key, as gcov itself leaves it out: the same
source is compiled under different names in different translation units
(`ama_ed25519_ge.h` through `GE_SYM`, `ama_x25519.c` renamed by an
equivalence test), and keyed by name those copies do not merge. Measured on
this tree, a name key reported 35 more never-taken arcs than this one -- 33
second copies of arcs already listed, and 2 that another copy takes.
The name comes from gcov's `function NAME called` summary, which precedes a
function's rows whether or not its line is shared, so a function grouped with
a neighbour in one translation unit and alone in another still merges.

A file is under `src/c` when its path -- symlinks resolved, case normalised
-- lies below this checkout's resolved `src/c`. gcov prints the path the
compiler was given, which is spelled differently when the build was
configured through a symlink, or on Windows. A run whose translation units
yield no instrumented arc under `src/c` measured nothing, and is refused
rather than reported as "never taken: 0".

USAGE

    cmake -S . -B build-cov -G Ninja -DCMAKE_BUILD_TYPE=Debug \
          -DAMA_USE_NATIVE_PQC=ON -DAMA_ENABLE_LTO=OFF \
          -DCMAKE_C_FLAGS="--coverage -O0 -g" \
          -DCMAKE_EXE_LINKER_FLAGS="--coverage"
    cmake --build build-cov
    ctest --test-dir build-cov
    python tools/measure_branch_coverage.py build-cov

    python tools/measure_branch_coverage.py build-cov --detail ama_ed25519

EVERY SUITE

Without `--python-suite` this measures `ctest` alone, and an arc only the
Python side reaches is reported as never taken: an inventory of what the C
suite misses, not of the guards no test protects. `--python-suite` closes
that gap. It needs an editable install (`pip install -e .`) whose package
directory holds the native library the bindings load. It copies the
instrumented native library from the build tree over the installed one,
re-signs the integrity artefact so the import-time self-test accepts it, runs
the two offline Python suites CI runs against the library -- `pytest tests/`
and `wycheproof_vectors/run_wycheproof.py` -- and restores and re-signs the
original library whatever the outcome. The Wycheproof runner is not a pytest
module; leaving it out reports every ECDSA DER-parser rejection in
`ama_nistp.c` as never taken, although CI executes each one on every PR.

The native library is `libama_cryptography.so.*` (the Linux soname chain),
`libama_cryptography*.dylib` (the macOS install-name chain), or a Windows DLL
spelled `ama_cryptography*.dll` or, as MinGW gcc names it,
`libama_cryptography*.dll`. The build tree is searched in `lib` and `bin`,
and in `lib/<Config>` and `bin/<Config>` for a multi-config generator
(<Config> one of Debug, Release, RelWithDebInfo, MinSizeRel). Exactly one real
(non-symlink) library must be found in the package directory, and exactly one
across all the build tree's directories together: two -- in one directory, or
one in each of two -- make an ambiguous tree, which is refused, not guessed at.

Each copy is written beside its destination and renamed over it, so the
installed library is at every moment the release build or the instrumented
one, never a partial file, and a process that already has the release library
mapped keeps the file it mapped. (The copy used to overwrite the file in
place, and killed such a process with SIGBUS.) A swap the OS refuses -- on
Windows, a DLL another process has loaded -- changes nothing, and is reported
as a refused swap. A restore happens only when the installed library is no
longer the release one.

The re-sign is `AMA_BUILD_PIPELINE=1 python -m ama_cryptography.integrity
--update --sign`, the command CI runs after its editable install. Besides the
untracked `_integrity_signature.py` it rewrites the tracked
`ama_cryptography/_integrity_digest.txt`, whose content changes only if the
package's `.py` sources (or its POST KAT vectors) differ from those the
committed digest covers; on a clean checkout it leaves no diff.

The instrumented library writes its counters into the build tree's `.gcda`
files, beside `ctest`'s, so the inventory is then of the arcs NO suite takes.
Whether the suites reached it is measured: a run that moves no `.gcda` is
refused.

    ctest --test-dir build-cov
    python tools/measure_branch_coverage.py build-cov --python-suite

The ACVP runner (`nist_vectors/run_vectors.py`) is left out because its
corpus is fetched over the network; run it by hand between the two commands
above, with the instrumented library still installed, to include it.

Exit codes:
    0  the inventory was produced
    1  an uncaught exception.  Under `--python-suite` its message says what
       the package holds: the release library could not be restored (the
       message names the kept backup), or it was restored and re-signing the
       integrity artefact over it failed (the message gives the command above)
    2  nothing was measured, and the installed library is as it was found:
         `gcov` is not on PATH;
         the build tree has no object beside a `.gcda` (checked before
           `--python-suite` swaps anything);
         gcov exited non-zero on an object (its stderr is printed);
         the translation units yielded no instrumented branch arc under
           `src/c` (a build of another checkout, or a gcov that cannot read
           the compiler's notes: GNU gcov refuses clang's);
         `--python-suite` did not find exactly one library in the package
           directory and in the build tree, or the OS refused the swap;
         `--python-suite` ran and the suites moved no `.gcda` counter
           (SuitesTookNoArcError): they did not execute the instrumented build
    3  `--python-suite` ran and a Python suite failed; the inventory is still
       printed, and describes a suite that did not pass
An interrupt (Ctrl-C) is not caught: Python dies of the SIGINT, which a POSIX
shell reports as 130. One that lands while the release library is being
restored or re-signed first prints the backup's path or the re-sign command.
"""

from __future__ import annotations

import argparse
import collections
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

REPO_ROOT = Path(__file__).resolve().parent.parent

# `<count>: <line>: <text>`.  The count is a number, `-` (no code), `#####`
# (never executed) or `=====` (reached only on an exceptional path), and since
# GCC 8 a number carries a trailing `*` when the line holds a basic block that
# never ran (`        5*:   42:  if (x)`).
#
# The `*` was outside this pattern.  A starred line failed to match, so its
# `branch N` rows were keyed to the PREVIOUS source line with the index still
# counting from it, and its text was never recorded.  Those are exactly the
# lines with partially executed branches — what this inventory exists to
# surface — and the damage compounded in the merge: a line fully executed in
# one translation unit (`10:`, arcs keyed correctly and taken) and starred in
# another (arcs keyed one line up, never taken) reported phantom never-taken
# arcs on the line above, which need not hold a branch at all.
_SRC_RE = re.compile(r"^\s*([\d#=\-]+\*?):\s*(\d+):(.*)$")
_BRANCH_RE = re.compile(r"^branch\s+(\d+)\s+(.*)$")
_TAKEN_RE = re.compile(r"taken (\d+)")
# `function NAME called N returned P% blocks executed Q%`: with `-b`, gcov
# prints one before each function's rows -- ahead of its first line, or, on a
# line several functions start on, at the head of that function's block.
_FUNCTION_RE = re.compile(r"^function (.+) called \d+ returned ")
# Frames the per-function blocks gcov prints for a line several functions
# start on; each block opens with a `NAME:` line after the separator.
_BLOCK_SEPARATOR = "------------------"

# An arc as one report states it: (source path as gcov printed it, line
# number, the function whose rows it is in, branch index within the row).
Arc = tuple[str, int, str, int]
# A (source path, line number).
Line = tuple[str, int]

#: The object names CMake gives a C translation unit: ``x.c.o``, or
#: ``x.c.obj`` on Windows (MinGW gcc and clang, the toolchains there that
#: write gcov data).  gcc names the counters ``x.c.gcda`` for both.
_OBJECT_GLOBS = ("*.c.o", "*.c.obj")

#: The one command that re-signs the integrity artefact over whatever library
#: the package holds; printed whenever this tool cannot finish that itself.
_RESIGN_COMMAND = "AMA_BUILD_PIPELINE=1 python -m ama_cryptography.integrity --update --sign"


def _objects_with_coverage(build_dir: Path) -> list[Path]:
    """Every compiled object that actually ran, i.e. has a .gcda beside it."""
    return sorted(
        obj
        for pattern in _OBJECT_GLOBS
        for obj in build_dir.rglob(pattern)
        if obj.with_suffix(".gcda").exists()
    )


class GcovError(RuntimeError):
    """gcov exited non-zero on an object, so its reports cannot be read as complete."""


def _expand(obj: Path, into: Path) -> str:
    """Run gcov for one object into its own directory, so per-TU reports of a
    shared header cannot overwrite each other.

    Returns what gcov wrote to stderr (warnings, on a run that succeeded).
    Raises GcovError, carrying that stderr, when gcov exits non-zero: GNU
    gcov given clang's notes, for one, prints ``version '408*', prefer
    'B33*'`` and ``no functions found`` and writes no report, which read as
    an object with no branches.
    """
    into.mkdir(parents=True, exist_ok=True)
    done = subprocess.run(
        ["gcov", "-b", "-o", str(obj.parent), obj.name],
        cwd=into,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        check=False,
    )
    if done.returncode != 0:
        raise GcovError(f"gcov exited {done.returncode} on {obj}:\n{done.stderr.rstrip()}")
    return done.stderr


def _parse(
    report: Path,
    taken: set[Arc],
    seen: set[Arc],
    text: dict[Line, str],
    shared: set[Line],
) -> None:
    """Merge one .gcov report into the running sets, adding to ``shared``
    each line it printed per-function blocks for."""
    try:
        lines = report.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    source = ""
    function = ""
    after_separator = False
    in_block = False
    line_no = 0
    index = 0
    for raw in lines:
        if raw.startswith("        -:    0:Source:"):
            source = raw.split("Source:", 1)[1].strip()
            continue
        if raw == _BLOCK_SEPARATOR:
            # Opens a function's block when a `NAME:` line follows; either
            # way it ends the block before it.
            after_separator, in_block = True, False
            continue
        if after_separator:
            after_separator = False
            if raw.endswith(":") and not raw[:1].isspace():
                in_block = True
                continue
        named = _FUNCTION_RE.match(raw)
        if named:
            function = named.group(1)
            continue
        hit = _SRC_RE.match(raw)
        if hit and hit.group(2) != "0":
            line_no = int(hit.group(2))
            index = 0
            text[(source, line_no)] = hit.group(3)
            if in_block:
                shared.add((source, line_no))
            continue
        branch = _BRANCH_RE.match(raw.strip())
        if branch and source:
            arc: Arc = (source, line_no, function, index)
            index += 1
            seen.add(arc)
            info = branch.group(2)
            if "never executed" in info:
                continue
            pct = _TAKEN_RE.search(info)
            if pct is not None and int(pct.group(1)) > 0:
                taken.add(arc)


def _merge_key(arc: Arc, shared: set[Line]) -> Arc:
    """The key ``arc`` merges under across translation units.

    The function stays in it only on a line in ``shared``, where gcov
    restarts the branch index for each function starting there; anywhere else
    it is dropped, so the copies of one source function that translation
    units compile under different names merge as one arc.
    """
    source, line, function, index = arc
    return (source, line, function if (source, line) in shared else "", index)


def _src_c_name(source: str, src_c: Path) -> str | None:
    """``source`` as ``src/c/<path>`` when it names a file under ``src_c``
    (a resolved path), else None.

    ``source`` is resolved and both sides are compared component by
    component after ``os.path.normcase``: a textual prefix test missed every
    file of a build configured through a symlink, and every file on Windows,
    where this checkout's path uses backslashes and gcov's may not.  A
    relative ``source`` names a file relative to a compilation directory
    gcov does not report, so it is not claimed.
    """
    path = Path(source)
    if not path.is_absolute():
        return None
    parts = path.resolve().parts
    root = src_c.parts
    if len(parts) <= len(root):
        return None
    if [os.path.normcase(p) for p in parts[: len(root)]] != [os.path.normcase(p) for p in root]:
        return None
    return "/".join(("src", "c", *parts[len(root) :]))


def _under_src_c(
    seen: set[Arc],
    taken: set[Arc],
    text: dict[Line, str],
    shared: set[Line],
    src_c: Path,
) -> tuple[set[Arc], set[Arc], dict[Line, str]]:
    """The merged arcs and the line texts under ``src_c``, with each file
    named ``src/c/...``, so every spelling gcov printed for it is one file."""
    sources = {arc[0] for arc in seen} | {key[0] for key in text} | {key[0] for key in shared}
    names = {source: _src_c_name(source, src_c) for source in sources}
    named_shared: set[Line] = set()
    for source, line in shared:
        name = names[source]
        if name is not None:
            named_shared.add((name, line))

    def rekey(arcs: set[Arc]) -> set[Arc]:
        out: set[Arc] = set()
        for source, line, function, index in arcs:
            name = names[source]
            if name is not None:
                out.add(_merge_key((name, line, function, index), named_shared))
        return out

    lines: dict[Line, str] = {}
    for (source, line), body in text.items():
        name = names[source]
        if name is not None:
            lines[(name, line)] = body
    return rekey(seen), rekey(taken), lines


#: The native library's file names, the shapes setup.py bundles into the
#: package: the Linux soname chain, the macOS install-name chain, and the
#: Windows DLL (``ama_cryptography.dll``, or ``libama_cryptography.dll`` as
#: MinGW gcc names it).  The ELF/Mach-O chains end in exactly one real file
#: and the rest are symlinks; the Windows DLL is a single real file.
_LIBRARY_GLOBS = (
    "libama_cryptography.so.*",
    "libama_cryptography*.dylib",
    "ama_cryptography*.dll",
    "libama_cryptography*.dll",
)

#: The configurations a multi-config generator (Visual Studio, Xcode, Ninja
#: Multi-Config) builds into per-config subdirectories of the output
#: directories -- the same four setup.py and pqc_backends search.
_CONFIGS = ("Debug", "Release", "RelWithDebInfo", "MinSizeRel")

#: Where a build tree puts the shared library.  CMake sends the ELF/Mach-O
#: library to ``LIBRARY_OUTPUT_DIRECTORY`` (``lib``) and the Windows runtime
#: DLL to ``RUNTIME_OUTPUT_DIRECTORY`` (``bin``), each with a ``<Config>``
#: subdirectory under a multi-config generator.  All are searched and exactly
#: one library must be found among them.
_BUILD_LIBRARY_DIRS = (
    "lib",
    "bin",
    *(f"{out}/{cfg}" for out in ("lib", "bin") for cfg in _CONFIGS),
)


def _real_libraries(directory: Path) -> set[Path]:
    """Every non-symlink native library in ``directory`` (none if it is absent)."""
    return {p for pattern in _LIBRARY_GLOBS for p in directory.glob(pattern) if not p.is_symlink()}


def _real_library(directory: Path) -> Path | None:
    """The one non-symlink native library in ``directory``, or None when there
    is none or more than one (an ambiguous tree is refused, not guessed at)."""
    found = _real_libraries(directory)
    return found.pop() if len(found) == 1 else None


def _instrumented_library(build_dir: Path) -> Path | None:
    """The build tree's shared library: the one real library found across
    every directory in ``_BUILD_LIBRARY_DIRS``.  None when there is none, or
    more than one -- two in one directory, or one in each of two (a leftover
    Release build beside the coverage one) -- since an ambiguous tree is
    refused, not guessed at."""
    found = {p for sub in _BUILD_LIBRARY_DIRS for p in _real_libraries(build_dir / sub)}
    return found.pop() if len(found) == 1 else None


def _resign() -> None:
    """Bind the package's current native library into the integrity artefact.

    The same command CI runs after its editable install; without it the
    import-time self-test refuses a library whose digest it was not signed
    over, and every test that loads the backend fails.
    """
    subprocess.run(
        [sys.executable, "-m", "ama_cryptography.integrity", "--update", "--sign"],
        cwd=REPO_ROOT,
        env={**os.environ, "AMA_BUILD_PIPELINE": "1"},
        stdout=subprocess.DEVNULL,
        check=True,
    )


def _pytest_command(pytest_args: list[str]) -> list[str]:
    """The pytest invocation, with ``--no-cov`` only where pytest-cov exists.

    ``--no-cov`` is pytest-cov's option, and pytest-cov is a dev extra, not a
    requirement of the package: on a plain install pytest rejects the flag
    (``unrecognized arguments: --no-cov``) and the whole Python-suite pass
    dies before a test runs.  It is still passed when the plugin is present:
    a caller with coverage options in ``PYTEST_ADDOPTS`` would otherwise have
    this run trace the Python side too, which is not what it measures.
    """
    command = [sys.executable, "-m", "pytest", "tests/", "-q"]
    if importlib.util.find_spec("pytest_cov") is not None:
        command.append("--no-cov")
    return command + list(pytest_args)


class SuitesTookNoArcError(RuntimeError):
    """The Python suites ran, and no coverage counter under the build tree moved."""


class SwapFailedError(RuntimeError):
    """The instrumented library could not be installed; the release one is untouched."""


def _gcda_state(build_dir: Path) -> dict[Path, int]:
    """Every ``.gcda`` counter file under ``build_dir`` with its mtime.

    The mtime is what a run moves.  A ``.gcda`` keeps its size from run to
    run -- measured on this tree, re-running two ctest suites moved 21 of 202
    counter mtimes and changed no size -- and a counter file a run creates
    shows as a new key.
    """
    return {path: path.stat().st_mtime_ns for path in build_dir.rglob("*.gcda")}


def _replace(src: Path, dst: Path) -> None:
    """Make ``dst`` a copy of ``src`` in one atomic step.

    The copy is written to a temporary file beside ``dst`` and renamed over
    it, so ``dst`` is at every moment the old file or the new one, never a
    partial one, and a process that has the old file mapped keeps it.  If
    anything fails before the rename, ``dst`` is untouched and the temporary
    file is removed.  Its name starts with a dot, so no library glob matches
    it while it exists.
    """
    handle, name = tempfile.mkstemp(prefix=f".{dst.name}.", suffix=".tmp", dir=dst.parent)
    os.close(handle)
    staged = Path(name)
    try:
        shutil.copy2(src, staged)
        os.replace(staged, dst)
    finally:
        staged.unlink(missing_ok=True)


def _fail(message: str, exc: BaseException) -> NoReturn:
    """Raise ``message`` chained to ``exc``; for an interrupt, print it and
    let the interrupt itself propagate."""
    if isinstance(exc, Exception):
        raise RuntimeError(message) from exc
    print(message, file=sys.stderr)
    raise exc


def _undo_swap(installed: Path, saved: Path, backup_dir: Path) -> None:
    """Put the release library back and re-sign over it, if it was replaced;
    then drop the backup.

    Whether it was replaced is read from the file, not from a flag set after
    the swap: an interrupt can land between the rename and any such flag.
    A swap refused before the rename leaves nothing to restore or re-sign.
    If the restore fails, the backup is the only release copy, so it is kept
    and named.  Once the library is back the backup has done its job, and it
    is removed whatever happens to the re-sign; a re-sign failure then says
    so in its own words -- a bare CalledProcessError replacing a suite's
    error would not tell the operator which library the package holds.
    """
    try:
        swapped = installed.read_bytes() != saved.read_bytes()
        if swapped:
            _replace(saved, installed)
    except BaseException as exc:
        _fail(
            f"could not restore the release library to {installed}; the backup is kept "
            f"at {saved} -- copy it back, then run {_RESIGN_COMMAND}",
            exc,
        )
    try:
        if swapped:
            _resign()
    except BaseException as exc:
        _fail(
            f"the release library was restored to {installed}, but re-signing the "
            f"integrity artefact over it did not complete; run {_RESIGN_COMMAND}",
            exc,
        )
    finally:
        shutil.rmtree(backup_dir, ignore_errors=True)


def _run_python_suite(build_dir: Path, pytest_args: list[str]) -> int | None:
    """Run the Python suites against the instrumented library.

    Returns the first non-zero exit status (0 when both pass), or None when
    the two libraries to swap were not both found.  Raises SwapFailedError,
    with nothing changed, when the instrumented library cannot be installed.
    Once it is, the release library is restored, and the artefact re-signed
    over it, on every path out (see ``_undo_swap``).
    """
    installed = _real_library(REPO_ROOT / "ama_cryptography")
    instrumented = _instrumented_library(build_dir)
    if installed is None or instrumented is None:
        return None
    backup_dir = Path(tempfile.mkdtemp(prefix="ama-release-library-"))
    saved = backup_dir / installed.name
    try:
        shutil.copy2(installed, saved)
    except BaseException:
        # Nothing is swapped yet, so the directory holds nothing anyone needs,
        # whether the copy failed or was interrupted.
        shutil.rmtree(backup_dir, ignore_errors=True)
        raise
    try:
        try:
            _replace(instrumented, installed)
        except OSError as exc:
            raise SwapFailedError(
                f"could not install {instrumented} over {installed} ({exc}); "
                "the installed library is unchanged"
            ) from exc
        _resign()
        # Whether the suites reach the instrumented library is measured, not
        # assumed from import order: the counters it writes are the evidence,
        # and a run that moved none of them measured the release library (or
        # nothing) and must not be published as the all-suite figure.
        before = _gcda_state(build_dir)
        status = 0
        for command in (
            _pytest_command(pytest_args),
            [sys.executable, "wycheproof_vectors/run_wycheproof.py"],
        ):
            # Both run whatever the first returns: each one's counters are data.
            returncode = subprocess.run(command, cwd=REPO_ROOT, check=False).returncode
            status = status or returncode
        if _gcda_state(build_dir) == before:
            raise SuitesTookNoArcError(
                f"the Python suites moved no coverage counter under {build_dir}: they "
                f"did not execute the instrumented library installed at {installed}"
            )
        return status
    finally:
        _undo_swap(installed, saved, backup_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("build_dir", type=Path, help="a build tree configured with --coverage")
    parser.add_argument(
        "--detail",
        metavar="SUBSTRING",
        help="also list each never-taken arc for source paths containing SUBSTRING",
    )
    parser.add_argument(
        "--python-suite",
        action="store_true",
        help="first run the Python suites against the instrumented library (see EVERY SUITE)",
    )
    parser.add_argument(
        "--pytest-arg",
        action="append",
        default=[],
        metavar="ARG",
        help="extra argument for pytest under --python-suite (repeatable)",
    )
    args = parser.parse_args(argv)

    if shutil.which("gcov") is None:
        print("gcov is not installed (no `gcov` on PATH)", file=sys.stderr)
        return 2

    build_dir = args.build_dir.resolve()
    # Checked before --python-suite swaps anything: a tree with no coverage
    # data cannot yield an inventory, however long the suites run.
    if not _objects_with_coverage(build_dir):
        print(
            f"no coverage data under {build_dir} (no *.c.o or *.c.obj object beside a "
            ".gcda): build with --coverage and run ctest first",
            file=sys.stderr,
        )
        return 2
    suite_status = 0
    if args.python_suite:
        try:
            status = _run_python_suite(build_dir, args.pytest_arg)
        except (SuitesTookNoArcError, SwapFailedError) as exc:
            print(exc, file=sys.stderr)
            return 2
        if status is None:
            searched = ", ".join(_BUILD_LIBRARY_DIRS)
            print(
                "--python-suite needs exactly one native library "
                "(libama_cryptography.so.*, libama_cryptography*.dylib, "
                "ama_cryptography*.dll or libama_cryptography*.dll) in "
                f"{REPO_ROOT / 'ama_cryptography'} (an editable install), and exactly "
                f"one across {searched} under {build_dir}",
                file=sys.stderr,
            )
            return 2
        suite_status = status
    # Counted again: the suites can write a .gcda that ctest did not.
    objects = _objects_with_coverage(build_dir)

    taken: set[Arc] = set()
    seen: set[Arc] = set()
    text: dict[Line, str] = {}
    shared: set[Line] = set()
    warnings: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        for n, obj in enumerate(objects):
            into = Path(tmp) / f"tu{n}"
            try:
                stderr = _expand(obj, into)
            except GcovError as exc:
                print(exc, file=sys.stderr)
                return 2
            warnings.extend(line for line in stderr.splitlines() if line.strip())
            for report in into.glob("*.gcov"):
                _parse(report, taken, seen, text, shared)
    for line in dict.fromkeys(warnings):
        print(f"gcov: {line}", file=sys.stderr)

    src_c = (REPO_ROOT / "src" / "c").resolve()
    instrumented = {_merge_key(arc, shared) for arc in seen}
    measured, covered, lines = _under_src_c(seen, taken, text, shared, src_c)
    if not measured:
        sources = sorted({arc[0] for arc in seen})
        print(
            f"nothing was measured: the translation units with coverage data "
            f"({len(objects)}) yielded no instrumented branch arc under {src_c}, "
            f"only {len(instrumented)} in other files ({len(sources)})"
            + (f", e.g. {sources[0]}" if sources else "")
            + ". Build this checkout, and use the gcov that matches the compiler "
            "(GNU gcov for gcc; `llvm-cov gcov` for clang).",
            file=sys.stderr,
        )
        return 2

    per_file: dict[str, list[tuple[int, str, int]]] = collections.defaultdict(list)
    for name, line_no, function, index in sorted(measured - covered):
        per_file[name].append((line_no, function, index))

    total = sum(len(v) for v in per_file.values())
    print(f"translation units with coverage data: {len(objects)}")
    print(f"instrumented branch arcs:             {len(instrumented)}")
    print(f"  of which under src/c:               {len(measured)}")
    print(f"never taken in ANY translation unit:  {total}")
    print()
    for name, arcs in sorted(per_file.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"{len(arcs):5d}  {name}")

    if args.detail:
        print(f"\n--- never-taken arcs in paths matching {args.detail!r} ---")
        for name, arcs in sorted(per_file.items()):
            if args.detail not in name:
                continue
            print(f"\n== {name} ({len(arcs)} arcs) ==")
            by_line: dict[int, int] = collections.Counter(line for line, _, _ in arcs)
            for line_no in sorted(by_line):
                body = lines.get((name, line_no), "?").strip()
                print(f"  L{line_no:<6d} [{by_line[line_no]}] {body[:88]}")

    if suite_status != 0:
        print(
            f"\na Python suite exited {suite_status}: this inventory is of a failing suite",
            file=sys.stderr,
        )
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
