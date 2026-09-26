#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Report the branch arcs under `src/c` that the C suite never takes.

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
.gcda is therefore expanded into its own directory and the results are merged:
an arc counts as covered when ANY translation unit took it.

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
suite misses, not of the guards no test protects.  `--python-suite` closes
that gap.  It needs an editable install (`pip install -e .`) whose package
directory holds the native library the bindings load.  It copies the
instrumented native library (`libama_cryptography.so.*`, or the
`libama_cryptography*.dylib` chain on macOS) from the build tree over the
installed one, re-signs the integrity artefact so the import-time self-test accepts it,
runs the two offline Python suites CI runs against the library -- `pytest
tests/` and `wycheproof_vectors/run_wycheproof.py` -- and restores and
re-signs the original library whatever the outcome.  The Wycheproof runner is
not a pytest module; leaving it out reports every ECDSA DER-parser rejection
in `ama_nistp.c` as never taken, although CI executes each one on every PR.
The instrumented library writes its counters into the same `.gcda` files
`ctest` did, so the inventory is then of the arcs NO suite takes:

    ctest --test-dir build-cov
    python tools/measure_branch_coverage.py build-cov --python-suite

The ACVP runner (`nist_vectors/run_vectors.py`) is left out because its
corpus is fetched over the network; run it by hand between the two commands
above, with the instrumented library still installed, to include it.

Exit codes:
    0  the inventory was produced
    2  the build directory carries no coverage data, or `--python-suite`
       could not find the two libraries it swaps
    3  `--python-suite` ran and a Python suite failed; the inventory is still
       printed, and describes a suite that did not pass
"""

from __future__ import annotations

import argparse
import collections
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

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

# A (source path, line number, branch index within that line).
Arc = tuple[str, int, int]


def _objects_with_coverage(build_dir: Path) -> list[Path]:
    """Every compiled object that actually ran, i.e. has a .gcda beside it."""
    return sorted(o for o in build_dir.rglob("*.c.o") if o.with_suffix(".gcda").exists())


def _expand(obj: Path, into: Path) -> None:
    """Run gcov for one object into its own directory, so per-TU reports of a
    shared header cannot overwrite each other."""
    into.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["gcov", "-b", "-o", str(obj.parent), obj.name],
        cwd=into,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def _parse(report: Path, taken: set[Arc], seen: set[Arc], text: dict[tuple[str, int], str]) -> None:
    """Merge one .gcov report into the running sets."""
    try:
        lines = report.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    source = ""
    line_no = 0
    index = 0
    for raw in lines:
        if raw.startswith("        -:    0:Source:"):
            source = raw.split("Source:", 1)[1].strip()
            continue
        hit = _SRC_RE.match(raw)
        if hit and hit.group(2) != "0":
            line_no = int(hit.group(2))
            index = 0
            text[(source, line_no)] = hit.group(3)
            continue
        branch = _BRANCH_RE.match(raw.strip())
        if branch and source:
            arc: Arc = (source, line_no, index)
            index += 1
            seen.add(arc)
            info = branch.group(2)
            if "never executed" in info:
                continue
            pct = _TAKEN_RE.search(info)
            if pct is not None and int(pct.group(1)) > 0:
                taken.add(arc)


#: The native library's file names: the Linux soname chain and the macOS
#: install-name chain, the same two shapes setup.py bundles into the package.
#: Each chain ends in exactly one real file; the rest are symlinks.
_LIBRARY_GLOBS = ("libama_cryptography.so.*", "libama_cryptography*.dylib")


def _real_library(directory: Path) -> Path | None:
    """The one non-symlink native library in ``directory``, or None when there
    is none or more than one (an ambiguous tree is refused, not guessed at)."""
    found = {p for pattern in _LIBRARY_GLOBS for p in directory.glob(pattern) if not p.is_symlink()}
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


def _run_python_suite(build_dir: Path, pytest_args: list[str]) -> int | None:
    """Run the Python suites against the instrumented library.

    Returns the first non-zero exit status (0 when both pass), or None when
    the two libraries to swap were not both found.  The installed library is
    restored, and the artefact re-signed over it, on every path out.  If the
    restore itself fails, the backup is kept and its path is in the error:
    deleting it then would leave the instrumented build installed with no
    copy of the release one.
    """
    installed = _real_library(REPO_ROOT / "ama_cryptography")
    instrumented = _real_library(build_dir / "lib")
    if installed is None or instrumented is None:
        return None
    backup_dir = Path(tempfile.mkdtemp(prefix="ama-release-library-"))
    saved = backup_dir / installed.name
    try:
        shutil.copy2(installed, saved)
    except OSError:
        shutil.rmtree(backup_dir, ignore_errors=True)
        raise
    try:
        shutil.copy2(instrumented, installed)
        _resign()
        status = 0
        for command in (
            [sys.executable, "-m", "pytest", "tests/", "-q", "--no-cov", *pytest_args],
            [sys.executable, "wycheproof_vectors/run_wycheproof.py"],
        ):
            # Both run whatever the first returns: each one's counters are data.
            returncode = subprocess.run(command, cwd=REPO_ROOT, check=False).returncode
            status = status or returncode
        return status
    finally:
        try:
            shutil.copy2(saved, installed)
        except OSError as exc:
            raise RuntimeError(
                f"could not restore the release library to {installed}; "
                f"the backup is kept at {saved}"
            ) from exc
        _resign()
        shutil.rmtree(backup_dir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
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
    args = parser.parse_args()

    if shutil.which("gcov") is None:
        print("gcov is not installed (no `gcov` on PATH)", file=sys.stderr)
        return 2

    build_dir = args.build_dir.resolve()
    suite_status = 0
    if args.python_suite:
        status = _run_python_suite(build_dir, args.pytest_arg)
        if status is None:
            print(
                "--python-suite needs exactly one native library (libama_cryptography.so.* "
                "or libama_cryptography*.dylib) in both "
                f"{REPO_ROOT / 'ama_cryptography'} (an editable install) and {build_dir / 'lib'}",
                file=sys.stderr,
            )
            return 2
        suite_status = status
    objects = _objects_with_coverage(build_dir)
    if not objects:
        print(
            f"no coverage data under {build_dir}: build with --coverage and run ctest first",
            file=sys.stderr,
        )
        return 2

    taken: set[Arc] = set()
    seen: set[Arc] = set()
    text: dict[tuple[str, int], str] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for n, obj in enumerate(objects):
            into = Path(tmp) / f"tu{n}"
            _expand(obj, into)
            for report in into.glob("*.gcov"):
                _parse(report, taken, seen, text)

    prefix = f"{REPO_ROOT}/"
    src_c = f"{REPO_ROOT}/src/c/"
    per_file: dict[str, list[tuple[int, int]]] = collections.defaultdict(list)
    for arc in sorted(seen - taken):
        source, line_no, index = arc
        if source.startswith(src_c):
            per_file[source[len(prefix) :]].append((line_no, index))

    total = sum(len(v) for v in per_file.values())
    print(f"translation units with coverage data: {len(objects)}")
    print(f"instrumented branch arcs:             {len(seen)}")
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
            by_line: dict[int, int] = collections.Counter(line for line, _ in arcs)
            for line_no in sorted(by_line):
                body = text.get((prefix + name, line_no), "?").strip()
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
