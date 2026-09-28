# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``tools/measure_branch_coverage.py``: the gcov parser, the
inventory's command line, and the ``--python-suite`` library swap.

Since GCC 8, gcov marks an executed line that holds a never-run basic block by
appending ``*`` to its count (``        5*:    4:``).  The parser's line pattern
admitted only digits, ``#`` and ``-`` in the count field, so a starred line
failed to match: its ``branch N`` rows were keyed to the previous source line,
with the branch index still counting from that line, and its text was never
recorded.  Starred lines are precisely the ones with partially executed
branches, so the inventory misplaced exactly what it exists to surface, and the
cross-translation-unit merge then reported phantom never-taken arcs.

Measured on this tree (gcc 13.3.0, Debug ``--coverage -O0 -g``, 193
translation units with coverage data, ``ctest`` 146 tests), the same gcov data
read by the old pattern gave 2,121 never-taken of 12,207 arcs, and by the
corrected one 1,504 of 11,507.

Every gcov report excerpt below is gcov 13.3.0 output, verbatim.  ``PARTIAL``
and ``FULL`` are for::

    int f(int x) {
        int r = 0;
        if (x > 0 && x < 100) r = 1; else r = 2;
        return r;
    }

called five times with ``x`` in 1..5 — so line 4's two false arcs never run.

Each test below that pins a behaviour was run against the tool with that
behaviour deleted and failed (AGENTS.md 6.2); the mutation and the failure it
produced are recorded in the commit that added the test.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from collections.abc import Callable
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "measure_branch_coverage.py"

#: gcov 13.3.0, the function above: line 4 is starred.
PARTIAL = """\
        -:    0:Source:demo.c
        -:    0:Graph:demo.gcno
        -:    0:Data:demo.gcda
        -:    0:Runs:1
        -:    1:#include <stdio.h>
function f called 5 returned 100% blocks executed 83%
        5:    2:int f(int x) {
        5:    3:    int r = 0;
       5*:    4:    if (x > 0 && x < 100) r = 1; else r = 2;
branch  0 taken 100% (fallthrough)
branch  1 taken 0%
branch  2 taken 100% (fallthrough)
branch  3 taken 0%
        5:    5:    return r;
        -:    6:}
"""

#: The same source in a translation unit whose callers take every arc.
FULL = """\
        -:    0:Source:demo.c
        -:    0:Graph:demo.gcno
        -:    0:Data:demo.gcda
        -:    0:Runs:1
        -:    1:#include <stdio.h>
function f called 7 returned 100% blocks executed 100%
        7:    2:int f(int x) {
        7:    3:    int r = 0;
        7:    4:    if (x > 0 && x < 100) r = 1; else r = 2;
branch  0 taken 71% (fallthrough)
branch  1 taken 29%
branch  2 taken 80% (fallthrough)
branch  3 taken 20%
        7:    5:    return r;
        -:    6:}
"""

#: Two functions expanded from one macro invocation, ``PAIR(fa, fb)``, both
#: called: ``fa(argc)`` once, so ``fa``'s false arc never runs, and
#: ``fb(argc)`` and ``fb(-argc)``.  gcov prints one block per function for the
#: invocation's row and restarts the branch index in each; the aggregate row
#: above the blocks carries none.
GROUPED = """\
        -:    0:Source:demo.c
        -:    0:Graph:demo.gcno
        -:    0:Data:demo.gcda
        -:    0:Runs:1
        -:    1:#define PAIR(a, b) \\
        -:    2:    static inline int a(int x) { return x > 0 ? 1 : 2; } \\
        -:    3:    static inline int b(int y) { return y > 0 ? 3 : 4; }
       3*:    4:PAIR(fa, fb)
------------------
fb:
function fb called 2 returned 100% blocks executed 100%
        2:    4:PAIR(fa, fb)
branch  0 taken 50% (fallthrough)
branch  1 taken 50%
------------------
fa:
function fa called 1 returned 100% blocks executed 80%
       1*:    4:PAIR(fa, fb)
branch  0 taken 100% (fallthrough)
branch  1 taken 0%
------------------
function main called 1 returned 100% blocks executed 100%
        1:    5:int main(int argc, char **argv) {
        -:    6:    (void)argv;
        1:    7:    int r = fa(argc);
call    0 returned 100%
        1:    8:    r += fb(argc);
call    0 returned 100%
        1:    9:    r += fb(-argc);
call    0 returned 100%
        1:   10:    return r == 0;
        -:   11:}
"""

#: The same line in a translation unit that calls only ``fa`` -- ``fa(argc)``
#: and ``fa(-argc)`` -- so ``fb`` is not emitted and gcov prints no block.
ALONE = """\
        -:    0:Source:demo.c
        -:    0:Graph:demo.gcno
        -:    0:Data:demo.gcda
        -:    0:Runs:1
        -:    1:#define PAIR(a, b) \\
        -:    2:    static inline int a(int x) { return x > 0 ? 1 : 2; } \\
        -:    3:    static inline int b(int y) { return y > 0 ? 3 : 4; }
function fa called 2 returned 100% blocks executed 100%
        2:    4:PAIR(fa, fb)
branch  0 taken 50% (fallthrough)
branch  1 taken 50%
function main called 1 returned 100% blocks executed 100%
        1:    5:int main(int argc, char **argv) {
        -:    6:    (void)argv;
        1:    7:    int r = fa(argc);
call    0 returned 100%
        1:    8:    r += fa(-argc);
call    0 returned 100%
        1:    9:    return r == 0;
        -:   10:}
"""

#: The two rows of ``x25519_scalarmult`` in ``src/c/ama_x25519.c`` that pick
#: the MULX ladder (``use_mulx``), as this tree's coverage build reports them
#: from the library's test object, and from ``tests/c/x25519_equiv_fe64.c``,
#: which compiles the same source with ``x25519_scalarmult`` renamed.
#: Excerpts: the header, the enclosing function's summary and the two rows,
#: verbatim, with the paths shortened.
LIBRARY_X25519 = """\
        -:    0:Source:/repo/src/c/ama_x25519.c
        -:    0:Graph:ama_x25519.c.gcno
        -:    0:Data:ama_x25519.c.gcda
        -:    0:Runs:6
function x25519_scalarmult called 4212 returned 100% blocks executed 100%
     4212:  426:    int use_mulx = (override_mode == -1) ? has_mulx : (override_mode != 0);
branch  0 taken 1% (fallthrough)
branch  1 taken 100%
     4212:  427:    if (use_mulx && has_mulx) {
branch  0 taken 100% (fallthrough)
branch  1 taken 1%
branch  2 taken 100% (fallthrough)
branch  3 taken 0%
"""

RENAMED_X25519 = """\
        -:    0:Source:/repo/src/c/ama_x25519.c
        -:    0:Graph:x25519_equiv_fe64.c.gcno
        -:    0:Data:x25519_equiv_fe64.c.gcda
        -:    0:Runs:1
function x25519_scalarmult_fe64 called 1024 returned 100% blocks executed 51%
    1024*:  426:    int use_mulx = (override_mode == -1) ? has_mulx : (override_mode != 0);
branch  0 taken 0% (fallthrough)
branch  1 taken 100%
     1024:  427:    if (use_mulx && has_mulx) {
branch  0 taken 100% (fallthrough)
branch  1 taken 0%
branch  2 taken 100% (fallthrough)
branch  3 taken 0%
"""

#: The macro line again, followed by a comment ending in a colon and by
#: ``main``, which calls ``fb`` only.  The row after the blocks' closing
#: separator ends in ``:`` like a block's ``NAME:`` line, but is a source row.
AFTER_A_GROUP = """\
        -:    0:Source:demo.c
        -:    0:Graph:demo.gcno
        -:    0:Data:demo.gcda
        -:    0:Runs:1
        -:    1:#define PAIR(a, b) \\
        -:    2:    static inline int a(int x) { return x > 0 ? 1 : 2; } \\
        -:    3:    static inline int b(int y) { return y > 0 ? 3 : 4; }
       1*:    4:PAIR(fa, fb)
------------------
fb:
function fb called 1 returned 100% blocks executed 80%
       1*:    4:PAIR(fa, fb)
branch  0 taken 100% (fallthrough)
branch  1 taken 0%
------------------
fa:
function fa called 0 returned 0% blocks executed 0%
    #####:    4:PAIR(fa, fb)
branch  0 never executed (fallthrough)
branch  1 never executed
------------------
        -:    5:// Returns:
function main called 1 returned 100% blocks executed 80%
        1:    6:int main(int argc, char **argv) {
        -:    7:    (void)argv;
       1*:    8:    return argc > 1 ? fa(argc) : fb(argc);
branch  0 taken 0% (fallthrough)
branch  1 taken 100%
call    2 never executed
call    3 returned 100%
        -:    9:}
"""


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("measure_branch_coverage", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    return _load()


Arcs = set[tuple[str, int, str, int]]


def _parse(
    tool: ModuleType, tmp_path: Path, *reports: str
) -> tuple[Arcs, Arcs, dict[tuple[str, int], str]]:
    """Parse ``reports`` as separate translation units; the arcs come back
    under the key the inventory merges them by."""
    taken: Arcs = set()
    seen: Arcs = set()
    text: dict[tuple[str, int], str] = {}
    shared: set[tuple[str, int]] = set()
    for n, body in enumerate(reports):
        report = tmp_path / f"tu{n}.gcov"
        report.write_text(body, encoding="utf-8")
        tool._parse(report, taken, seen, text, shared)
    return (
        {tool._merge_key(arc, shared) for arc in taken},
        {tool._merge_key(arc, shared) for arc in seen},
        text,
    )


def test_a_starred_line_owns_its_branches(tool: ModuleType, tmp_path: Path) -> None:
    taken, seen, text = _parse(tool, tmp_path, PARTIAL)
    assert seen == {("demo.c", 4, "", i) for i in range(4)}, "branches keyed to the wrong line"
    assert taken == {("demo.c", 4, "", 0), ("demo.c", 4, "", 2)}
    assert text[("demo.c", 4)].strip().startswith("if (x > 0 && x < 100)")


def test_the_merge_reports_only_arcs_no_unit_took(tool: ModuleType, tmp_path: Path) -> None:
    """One unit starred, another fully executed: nothing is left untaken."""
    taken, seen, _ = _parse(tool, tmp_path, PARTIAL, FULL)
    assert seen - taken == set(), f"phantom never-taken arcs: {sorted(seen - taken)}"


def test_the_untaken_arcs_of_a_starred_line_are_reported_on_it(
    tool: ModuleType, tmp_path: Path
) -> None:
    taken, seen, _ = _parse(tool, tmp_path, PARTIAL)
    assert seen - taken == {("demo.c", 4, "", 1), ("demo.c", 4, "", 3)}


@pytest.mark.parametrize("count", ["5", "5*", "12345*", "#####", "=====", "-"])
def test_every_gcov_count_form_starts_a_source_line(tool: ModuleType, count: str) -> None:
    line = f"{count:>9}:   42:    if (x) {{"
    hit = tool._SRC_RE.match(line)
    assert hit is not None, f"{count!r} not recognised as a source line"
    assert hit.group(2) == "42"


def test_functions_sharing_a_line_keep_their_own_arcs(tool: ModuleType, tmp_path: Path) -> None:
    """gcov restarts the branch index in each function's block of a shared
    line.  Keyed by line and index alone, ``fa``'s never-taken arc was the
    same key as ``fb``'s taken one, and vanished from the inventory."""
    taken, seen, _ = _parse(tool, tmp_path, GROUPED)
    assert len(seen) == 4, f"arcs of two functions collided: {sorted(seen)}"
    assert seen - taken == {("demo.c", 4, "fa", 1)}


def test_a_function_grouped_in_one_unit_and_alone_in_another_merges(
    tool: ModuleType, tmp_path: Path
) -> None:
    """A header's inline functions share a line in a unit that uses both and
    stand alone in one that uses one.  ``fa``'s false arc, untaken in the
    first unit and taken in the second, is covered."""
    taken, seen, _ = _parse(tool, tmp_path, GROUPED, ALONE)
    assert seen - taken == set(), f"phantom never-taken arcs: {sorted(seen - taken)}"


def test_one_function_compiled_under_two_names_merges(tool: ModuleType, tmp_path: Path) -> None:
    """``x25519_equiv_fe64.c`` compiles ``ama_x25519.c`` with the ladder
    renamed; the ``use_mulx`` row's first arc is taken by the library's copy
    only.  Keyed by name the two copies would not merge, and the arc would be
    reported never taken although a suite takes it."""
    taken, seen, _ = _parse(tool, tmp_path, LIBRARY_X25519, RENAMED_X25519)
    assert seen - taken == {("/repo/src/c/ama_x25519.c", 427, "", 3)}


def test_the_function_blocks_end_where_gcov_closes_them(tool: ModuleType, tmp_path: Path) -> None:
    """Only the shared line is keyed by function.  The separator after the
    last block closes the group, and the source row after it is a row even
    though it ends in a colon, as a block's ``NAME:`` line does: read as a
    block, it and ``main``'s rows would be keyed by function name, and a copy
    of ``main`` compiled under another name would no longer merge with it."""
    _, seen, text = _parse(tool, tmp_path, AFTER_A_GROUP)
    assert seen == {
        ("demo.c", 4, "fb", 0),
        ("demo.c", 4, "fb", 1),
        ("demo.c", 4, "fa", 0),
        ("demo.c", 4, "fa", 1),
        ("demo.c", 8, "", 0),
        ("demo.c", 8, "", 1),
    }
    assert text[("demo.c", 5)] == "// Returns:", "a source row was read as a block's name"


# --------------------------------------------------------------------------
# which files are under src/c
# --------------------------------------------------------------------------


def _link_directory(link: Path, target: Path) -> None:
    """``link`` -> ``target``, a directory: a symlink, or on Windows a
    junction, which needs no privilege and which ``Path.resolve`` follows."""
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


@pytest.mark.parametrize("spelling", ["through a link", "with a dot-dot", "native separators"])
def test_every_spelling_of_a_src_c_path_is_recognised(
    tool: ModuleType, tmp_path: Path, spelling: str
) -> None:
    """gcov prints the path the compiler was given.  Configured through a
    symlinked checkout, that path does not start with this checkout's
    resolved one, and a textual prefix test measured nothing (``never taken:
    0``, exit 0) -- as it did for every path on Windows, where the prefix
    mixed this checkout's backslashes with a ``/src/c/`` literal."""
    real = tmp_path / "real"
    (real / "src" / "c").mkdir(parents=True)
    (real / "src" / "c" / "ama_x.c").write_text("int x;\n", encoding="utf-8")
    src_c = (real / "src" / "c").resolve()
    if spelling == "through a link":
        _link_directory(tmp_path / "link", real)
        source = str(tmp_path / "link" / "src" / "c" / "ama_x.c")
    elif spelling == "with a dot-dot":
        source = f"{real}/build/../src/c/ama_x.c"
    else:
        source = os.sep.join((str(real), "src", "c", "ama_x.c"))
    assert tool._src_c_name(source, src_c) == "src/c/ama_x.c"


@pytest.mark.parametrize(
    "relative",
    [
        "src/cx/ama_x.c",  # a sibling whose name extends src/c
        "src/ama_x.c",
        "src/c",  # the directory itself
        None,  # a relative path
    ],
)
def test_a_path_outside_src_c_is_not_claimed(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str | None
) -> None:
    """A relative path names a file under a compilation directory gcov does
    not print; it is not guessed at, even from the checkout's own root."""
    root = tmp_path.resolve()
    src_c = root / "src" / "c"
    src_c.mkdir(parents=True)
    monkeypatch.chdir(root)
    source = "src/c/ama_x.c" if relative is None else str(root / relative)
    assert tool._src_c_name(source, src_c) is None


def test_paths_compare_under_the_platform_case_rule(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Windows compares paths without regard to case, and ``os.path.normcase``
    folds it there; a gcov path spelled ``.../SRC/C/...`` names this
    checkout's file.  ``normcase`` is the identity on POSIX, so the rule is
    modelled here by a case-folding ``normcase``, to be checked on every
    platform rather than only where it applies."""
    root = tmp_path.resolve()
    src_c = root / "src" / "c"
    src_c.mkdir(parents=True)
    monkeypatch.setattr(tool.os.path, "normcase", lambda path: path.lower())
    assert tool._src_c_name(str(root / "SRC" / "C" / "ama_x.c"), src_c) == "src/c/ama_x.c"


# --------------------------------------------------------------------------
# the command line: every exit status main() produces
# --------------------------------------------------------------------------


def _coverage_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: ModuleType) -> Path:
    """A fake checkout with ``src/c`` and a build tree holding one object and
    its counters, as ``ctest`` leaves them; returns the build tree."""
    repo = tmp_path / "repo"
    (repo / "src" / "c").mkdir(parents=True)
    obj_dir = repo / "build-cov" / "CMakeFiles" / "ama.dir" / "src" / "c"
    obj_dir.mkdir(parents=True)
    (obj_dir / "demo.c.o").write_bytes(b"")
    (obj_dir / "demo.c.gcda").write_bytes(b"\x00" * 64)
    monkeypatch.setattr(tool, "REPO_ROOT", repo)
    return repo / "build-cov"


def _fake_gcov(
    tool: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    reports: dict[str, str],
    returncode: int = 0,
    stderr: str = "",
) -> list[list[str]]:
    """Install a ``gcov`` that writes ``reports`` into its working directory
    and exits ``returncode`` with ``stderr``; returns the commands it ran."""
    ran: list[list[str]] = []

    def run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert cmd[0] == "gcov", f"ran {cmd!r}, not gcov"
        ran.append(cmd)
        into = Path(str(kwargs["cwd"]))
        for name, body in reports.items():
            (into / name).write_text(body, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, returncode, None, stderr)

    monkeypatch.setattr(tool.subprocess, "run", run)
    monkeypatch.setattr(tool.shutil, "which", lambda name: f"/usr/bin/{name}")
    return ran


def _src_c_report(tool: ModuleType) -> dict[str, str]:
    """``PARTIAL``, as gcov reports it for a file under the fake ``src/c``."""
    source = tool.REPO_ROOT / "src" / "c" / "demo.c"
    return {"demo.c.gcov": PARTIAL.replace("Source:demo.c", f"Source:{source}")}


def test_main_prints_the_inventory_and_exits_0(
    tool: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    build = _coverage_tree(tmp_path, monkeypatch, tool)
    _fake_gcov(tool, monkeypatch, _src_c_report(tool), stderr="demo.gcno:a warning\n")
    assert tool.main([str(build), "--detail", "demo"]) == 0
    out, err = capsys.readouterr()
    assert "never taken in ANY translation unit:  2" in out, out
    assert "L4      [2] if (x > 0 && x < 100)" in out, "the --detail line text was lost"
    assert "gcov: demo.gcno:a warning" in err, "gcov's stderr was swallowed"


def test_main_refuses_without_gcov(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build = _coverage_tree(tmp_path, monkeypatch, tool)
    monkeypatch.setattr(tool.shutil, "which", lambda _name: None)
    assert tool.main([str(build)]) == 2


def test_main_refuses_a_tree_without_coverage_data_before_swapping(
    tool: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The check comes first: a tree with no counters cannot yield an
    inventory however long the suites run, and swapping the installed
    library for it is a risk taken for nothing."""
    build = _coverage_tree(tmp_path, monkeypatch, tool)
    for counter in build.rglob("*.gcda"):
        counter.unlink()
    _fake_gcov(tool, monkeypatch, {})

    def no_swap(*_a: object) -> None:
        pytest.fail("swapped the library for a tree with no coverage data")

    monkeypatch.setattr(tool, "_run_python_suite", no_swap)
    assert tool.main([str(build), "--python-suite"]) == 2
    assert "no coverage data" in capsys.readouterr().err


def _suite_returns(status: int | None) -> Callable[[Path, list[str]], int | None]:
    def run(build_dir: Path, _args: list[str]) -> int | None:
        # The suites can write counters ctest did not: a second object's.
        (build_dir / "CMakeFiles" / "ama.dir" / "src" / "c" / "late.c.o").write_bytes(b"")
        (build_dir / "CMakeFiles" / "ama.dir" / "src" / "c" / "late.c.gcda").write_bytes(b"\x00")
        return status

    return run


def _suite_raises(exc: BaseException) -> Callable[[Path, list[str]], int | None]:
    def run(_build_dir: Path, _args: list[str]) -> int | None:
        raise exc

    return run


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        ("pass", 0),
        ("fail", 3),
        ("no library", 2),
        ("no counter moved", 2),
        ("swap refused", 2),
    ],
)
def test_main_exit_status_follows_the_python_suite(
    tool: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    outcome: str,
    expected: int,
) -> None:
    build = _coverage_tree(tmp_path, monkeypatch, tool)
    _fake_gcov(tool, monkeypatch, _src_c_report(tool))
    suite = {
        "pass": _suite_returns(0),
        "fail": _suite_returns(1),
        "no library": _suite_returns(None),
        "no counter moved": _suite_raises(tool.SuitesTookNoArcError("moved no coverage counter")),
        "swap refused": _suite_raises(tool.SwapFailedError("the installed library is unchanged")),
    }[outcome]
    monkeypatch.setattr(tool, "_run_python_suite", suite)
    assert tool.main([str(build), "--python-suite"]) == expected
    out = capsys.readouterr().out
    if expected in (0, 3):
        assert "translation units with coverage data: 2" in out, "objects not counted again"


def test_a_failing_gcov_is_reported_not_read_as_an_empty_object(
    tool: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """GNU gcov given clang's notes (the message is gcov 13.3.0's, measured)
    exits non-zero and writes no report.  Its return code was ignored and its
    stderr discarded, so the run printed an inventory of nothing, exit 0."""
    build = _coverage_tree(tmp_path, monkeypatch, tool)
    stderr = "demo.c.gcno:version '408*', prefer 'B33*'\ndemo.c.gcno:no functions found\n"
    _fake_gcov(tool, monkeypatch, {}, returncode=5, stderr=stderr)
    assert tool.main([str(build)]) == 2
    err = capsys.readouterr().err
    assert "gcov exited 5" in err and "no functions found" in err, err


def test_a_run_that_measures_nothing_under_src_c_is_refused(
    tool: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Translation units with counters, and not one arc under this
    checkout's ``src/c`` (a build of another checkout, say): that is nothing
    measured, not an inventory of 0."""
    build = _coverage_tree(tmp_path, monkeypatch, tool)
    elsewhere = tmp_path / "another-checkout" / "src" / "c" / "demo.c"
    _fake_gcov(tool, monkeypatch, {"demo.c.gcov": PARTIAL.replace("demo.c", str(elsewhere), 1)})
    assert tool.main([str(build)]) == 2
    err = capsys.readouterr().err
    assert "nothing was measured" in err and str(elsewhere) in err, err


def test_help_shows_the_whole_description(
    tool: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--help`` printed the docstring's first line only, which named the C
    suite; the usage, the ``--python-suite`` contract and the exit codes were
    not reachable from the command line."""
    with pytest.raises(SystemExit) as done:
        tool.main(["--help"])
    assert done.value.code == 0
    out = capsys.readouterr().out
    assert "\n    python tools/measure_branch_coverage.py build-cov --python-suite\n" in out
    assert "Exit codes:" in out
    for code in ("0", "1", "2", "3"):
        assert f"\n    {code}  " in out, f"exit code {code} is missing from --help"
    assert "SuitesTookNoArcError" in out and "130" in out


def test_objects_are_found_under_both_cmake_spellings_and_only_with_counters(
    tool: ModuleType, tmp_path: Path
) -> None:
    """CMake names an object ``x.c.o``, or ``x.c.obj`` on Windows (MinGW gcc
    and clang, the Windows toolchains that write gcov data); an object with
    no ``.gcda`` beside it never ran and is not a translation unit measured."""
    for directory, names in (
        (tmp_path / "gnu", ("ran.c.o", "ran.c.gcda", "idle.c.o")),
        (tmp_path / "win", ("ran.c.obj", "ran.c.gcda", "idle.c.obj")),
    ):
        directory.mkdir()
        for name in names:
            (directory / name).write_bytes(b"")
    found = tool._objects_with_coverage(tmp_path)
    assert found == [tmp_path / "gnu" / "ran.c.o", tmp_path / "win" / "ran.c.obj"]


# --------------------------------------------------------------------------
# --python-suite: the swap is restored on every path out
# --------------------------------------------------------------------------


def _ctest_counter(build_dir: Path) -> Path:
    """The counters a ``ctest`` run leaves in the build tree."""
    counter = build_dir / "CMakeFiles" / "ama_cryptography_shared.dir" / "ama_kyber.c.gcda"
    counter.parent.mkdir(parents=True, exist_ok=True)
    counter.write_bytes(b"\x00" * 64)
    return counter


def _python_suite_tree(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path]:
    """A fake repo whose package holds the release library and whose build
    tree holds the instrumented one, in this platform's layout: on Windows a
    single ``ama_cryptography.dll`` in the package and in ``bin``, as CMake's
    ``RUNTIME_OUTPUT_DIRECTORY`` puts it; elsewhere the ELF soname chain, one
    real file behind a symlink, in ``lib``.  The build tree also holds the
    counters ``ctest`` leaves."""
    repo = tmp_path / "repo"
    pkg = repo / "ama_cryptography"
    build = repo / "build-cov"
    if sys.platform == "win32":
        name, libdir = "ama_cryptography.dll", build / "bin"
    else:
        name, libdir = "libama_cryptography.so.5.0.0", build / "lib"
    for directory, body in ((pkg, b"release"), (libdir, b"instrumented")):
        directory.mkdir(parents=True)
        (directory / name).write_bytes(body)
        if sys.platform != "win32":
            (directory / "libama_cryptography.so.5").symlink_to(name)
    _ctest_counter(build)
    monkeypatch.setattr(tool, "REPO_ROOT", repo)
    return pkg / name, build


def _counters_move(build_dir: Path) -> None:
    """What a suite that reached the instrumented library leaves behind: its
    counters rewritten in place.  A ``.gcda`` keeps its size from run to run,
    so only the modification time moves (measured on this tree: re-running
    two ctest suites moved 21 of 202 counter mtimes and changed no size)."""
    for counter in build_dir.rglob("*.gcda"):
        stat = counter.stat()
        os.utime(counter, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))


class _Done:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode


def _suite_runs(build_dir: Path) -> Callable[..., _Done]:
    def run(*_a: object, **_k: object) -> _Done:
        _counters_move(build_dir)
        return _Done()

    return run


def _record_backups(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> list[Path]:
    """Every backup directory the swap makes, made under ``tmp_path``."""
    made: list[Path] = []
    real_mkdtemp = tool.tempfile.mkdtemp

    def recording_mkdtemp(**kwargs: str) -> str:
        path = str(real_mkdtemp(dir=tmp_path, **kwargs))
        made.append(Path(path))
        return path

    monkeypatch.setattr(tool.tempfile, "mkdtemp", recording_mkdtemp)
    return made


def _listing(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


@pytest.mark.parametrize("statuses", [(0, 0), (1, 0), (0, 2)])
def test_both_python_suites_run_on_the_instrumented_library_and_the_release_one_is_restored(
    tool: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    statuses: tuple[int, int],
) -> None:
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    signed_over: list[bytes] = []
    ran: list[tuple[str, bytes, object]] = []
    monkeypatch.setattr(tool, "_resign", lambda: signed_over.append(installed.read_bytes()))
    pending = list(statuses)

    def fake_run(cmd: list[str], **kwargs: object) -> _Done:
        ran.append((" ".join(cmd[1:3]), installed.read_bytes(), kwargs.get("cwd")))
        _counters_move(build_dir)
        return _Done(pending.pop(0))

    monkeypatch.setattr(tool.subprocess, "run", fake_run)
    expected = next((s for s in statuses if s != 0), 0)
    assert tool._run_python_suite(build_dir, []) == expected
    repo = installed.parent.parent
    assert ran == [
        ("-m pytest", b"instrumented", repo),
        ("wycheproof_vectors/run_wycheproof.py", b"instrumented", repo),
    ], "a suite was skipped, ran against the release library, or ran outside the checkout"
    assert signed_over == [b"instrumented", b"release"], "artefact not re-signed over each library"
    assert installed.read_bytes() == b"release", "the release library was not restored"


@pytest.mark.parametrize("installed_plugin", [True, False])
def test_no_cov_is_passed_only_where_pytest_cov_is_installed(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, installed_plugin: bool
) -> None:
    """``--no-cov`` belongs to pytest-cov, a dev extra: passed on a plain
    install, pytest refuses the whole invocation before any test runs."""
    _python_suite_tree(tool, tmp_path, monkeypatch)
    real_find_spec = importlib.util.find_spec

    def find_spec(name: str, package: str | None = None) -> ModuleSpec | None:
        if name == "pytest_cov":
            return ModuleSpec("pytest_cov", None) if installed_plugin else None
        return real_find_spec(name, package)

    monkeypatch.setattr(tool.importlib.util, "find_spec", find_spec)
    command = tool._pytest_command(["-x"])
    assert command[:5] == [sys.executable, "-m", "pytest", "tests/", "-q"]
    assert ("--no-cov" in command) is installed_plugin
    assert command[-1] == "-x", "the caller's pytest arguments were dropped"


def test_suites_that_move_no_counter_are_refused_not_published(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run whose Python suites left every ``.gcda`` untouched measured the
    release library, or nothing; its inventory must not become the all-suite
    figure.  The release library is restored on that path as on every other."""
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    monkeypatch.setattr(tool, "_resign", lambda: None)
    monkeypatch.setattr(tool.subprocess, "run", lambda *_a, **_k: _Done())
    with pytest.raises(tool.SuitesTookNoArcError, match="moved no coverage counter"):
        tool._run_python_suite(build_dir, [])
    assert installed.read_bytes() == b"release"


def test_a_failed_resign_after_a_restore_says_so_and_drops_the_backup(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Once the release library is back the backup is redundant, and the
    error must say which library the package holds — not surface as a bare
    signing failure in place of the suite's own error."""
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    calls = {"n": 0}

    def resign_fails_after_restore() -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("signer refused")

    monkeypatch.setattr(tool, "_resign", resign_fails_after_restore)
    backups = _record_backups(tool, tmp_path, monkeypatch)
    monkeypatch.setattr(tool.subprocess, "run", _suite_runs(build_dir))
    with pytest.raises(RuntimeError, match=r"was restored to .* but re-signing") as info:
        tool._run_python_suite(build_dir, [])
    assert isinstance(info.value.__cause__, RuntimeError)
    assert installed.read_bytes() == b"release"
    assert backups and not backups[0].exists(), "the backup directory was left behind"


def test_an_interrupt_during_the_final_resign_prints_the_command(
    tool: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Ctrl-C while the artefact is being re-signed over the restored
    library leaves it signed over the instrumented one, and every import then
    fails its self-test.  The interrupt propagates, but not before the
    command that finishes the job is printed; it used to propagate bare."""
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    calls = {"n": 0}

    def resign_interrupted_after_restore() -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(tool, "_resign", resign_interrupted_after_restore)
    backups = _record_backups(tool, tmp_path, monkeypatch)
    monkeypatch.setattr(tool.subprocess, "run", _suite_runs(build_dir))
    with pytest.raises(KeyboardInterrupt):
        tool._run_python_suite(build_dir, [])
    err = capsys.readouterr().err
    assert "AMA_BUILD_PIPELINE=1 python -m ama_cryptography.integrity --update --sign" in err, err
    assert installed.read_bytes() == b"release"
    assert backups and not backups[0].exists(), "the backup outlived the restore"


def test_the_release_library_is_restored_when_pytest_cannot_start(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    signed_over: list[bytes] = []
    monkeypatch.setattr(tool, "_resign", lambda: signed_over.append(installed.read_bytes()))

    def broken_run(*_: object, **__: object) -> None:
        raise OSError("no interpreter")

    monkeypatch.setattr(tool.subprocess, "run", broken_run)
    with pytest.raises(OSError):
        tool._run_python_suite(build_dir, [])
    assert installed.read_bytes() == b"release"
    assert (
        signed_over[-1] == b"release"
    ), "the artefact was left signed over the instrumented library"


def _copy_failing_at(
    tool: ModuleType, monkeypatch: pytest.MonkeyPatch, call: int, exc: BaseException
) -> None:
    """``shutil.copy2`` raising ``exc`` on its ``call``-th use (1: the
    backup, 2: the swap's staging copy, 3: the restore's)."""
    real_copy = tool.shutil.copy2
    copies: list[object] = []

    def copy(src: Path, dst: Path) -> object:
        copies.append(dst)
        if len(copies) == call:
            raise exc
        return real_copy(src, dst)

    monkeypatch.setattr(tool.shutil, "copy2", copy)


def test_a_failed_restore_keeps_the_backup_and_names_it(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The backup is the only copy of the release library once the swap is
    made; a restore that fails must not delete it."""
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    listing = _listing(installed.parent)
    monkeypatch.setattr(tool, "_resign", lambda: None)
    monkeypatch.setattr(tool.subprocess, "run", lambda *_, **__: _Done())
    backups = _record_backups(tool, tmp_path, monkeypatch)
    _copy_failing_at(tool, monkeypatch, 3, OSError("No space left on device"))
    with pytest.raises(RuntimeError, match="the backup is kept at") as caught:
        tool._run_python_suite(build_dir, [])
    backup = backups[0] / installed.name
    assert str(backup) in str(caught.value)
    assert backup.read_bytes() == b"release", "the backup was deleted or is not the release library"
    assert isinstance(caught.value.__cause__, OSError)
    assert installed.read_bytes() == b"instrumented", "the backup is the only release copy"
    assert _listing(installed.parent) == listing, "a staging file was left beside the library"


def test_an_interrupt_during_the_restore_still_names_the_backup(
    tool: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Ctrl-C while the release library is being copied back leaves the
    instrumented library installed and the backup as the only release copy;
    the interrupt propagates, but not before the backup's path is printed.
    Until 2026-09-27 only an OSError was named, and an interrupt left the
    operator to find the temporary directory by hand."""
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    monkeypatch.setattr(tool, "_resign", lambda: None)
    monkeypatch.setattr(tool.subprocess, "run", lambda *_, **__: _Done())
    backups = _record_backups(tool, tmp_path, monkeypatch)
    _copy_failing_at(tool, monkeypatch, 3, KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        tool._run_python_suite(build_dir, [])
    message = capsys.readouterr().err
    backup = backups[0] / installed.name
    assert f"the backup is kept at {backup}" in message, message
    assert backup.read_bytes() == b"release", "the backup was deleted or is not the release library"
    assert installed.read_bytes() == b"instrumented", "the backup is the only release copy"


def test_a_restored_run_leaves_no_backup_behind(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    monkeypatch.setattr(tool, "_resign", lambda: None)
    monkeypatch.setattr(tool.subprocess, "run", _suite_runs(build_dir))
    made = _record_backups(tool, tmp_path, monkeypatch)
    assert tool._run_python_suite(build_dir, []) == 0
    assert installed.read_bytes() == b"release"
    assert len(made) == 1 and not made[0].exists(), "the backup directory was left behind"


def _file_id(path: Path) -> tuple[int, int]:
    stat = path.stat()
    return stat.st_dev, stat.st_ino


def test_the_swap_and_the_restore_put_a_new_file_in_place_never_rewrite_one(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A process with the release library mapped (another Python session, a
    test run beside this one) must keep the file it mapped.  The swap copied
    over the installed file in place, rewriting the pages under such a
    mapping: a mapped reader was killed with SIGBUS once the new file was
    shorter.  A copy renamed into place leaves the old file to its holders,
    and leaves no staging file behind."""
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    listing = _listing(installed.parent)
    monkeypatch.setattr(tool, "_resign", lambda: None)
    identities = [_file_id(installed)]

    def run(*_a: object, **_k: object) -> _Done:
        identities.append(_file_id(installed))
        _counters_move(build_dir)
        return _Done()

    monkeypatch.setattr(tool.subprocess, "run", run)
    assert tool._run_python_suite(build_dir, []) == 0
    assert identities[1] != identities[0], "the swap rewrote the installed file in place"
    assert _file_id(installed) != identities[-1], "the restore rewrote the installed file in place"
    assert installed.read_bytes() == b"release"
    assert _listing(installed.parent) == listing, "a staging file was left beside the library"


def test_a_refused_swap_is_reported_as_one_and_changes_nothing(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On Windows a DLL another process has loaded cannot be replaced.  That
    swap fails before anything changes, so there is nothing to restore or
    re-sign: the error says the swap failed and carries the OS error, and the
    backup directory goes.  It was reported as a failed *restore*, naming a
    backup of a library that had never been touched."""
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    listing = _listing(installed.parent)
    monkeypatch.setattr(tool, "_resign", lambda: pytest.fail("re-signed with nothing swapped"))
    monkeypatch.setattr(tool.subprocess, "run", lambda *_a, **_k: pytest.fail("ran a suite"))
    backups = _record_backups(tool, tmp_path, monkeypatch)
    real_replace = tool.os.replace

    def locked(src: Path, dst: Path) -> None:
        if Path(dst) == installed:
            raise PermissionError(13, "The process cannot access the file", str(dst))
        real_replace(src, dst)

    monkeypatch.setattr(tool.os, "replace", locked)
    with pytest.raises(tool.SwapFailedError, match="unchanged") as caught:
        tool._run_python_suite(build_dir, [])
    assert isinstance(caught.value.__cause__, PermissionError)
    assert installed.read_bytes() == b"release"
    assert backups and not backups[0].exists(), "the backup directory was left behind"
    assert _listing(installed.parent) == listing, "a staging file was left beside the library"


@pytest.mark.parametrize(
    "exc", [OSError("No space left on device"), KeyboardInterrupt()], ids=["error", "interrupt"]
)
def test_a_backup_that_cannot_be_made_leaves_no_directory(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    """Nothing is swapped until the backup exists, so a backup copy that
    fails, or is interrupted, leaves nothing to keep: its temporary directory
    goes with it.  An interrupt there used to leak the directory."""
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    monkeypatch.setattr(tool, "_resign", lambda: pytest.fail("re-signed with nothing swapped"))
    backups = _record_backups(tool, tmp_path, monkeypatch)
    _copy_failing_at(tool, monkeypatch, 1, exc)
    with pytest.raises(type(exc)):
        tool._run_python_suite(build_dir, [])
    assert backups and not backups[0].exists(), "the backup directory was left behind"
    assert installed.read_bytes() == b"release"


def test_the_resign_is_ci_s_command_in_the_pipeline_environment(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``integrity --update`` refuses to run outside ``AMA_BUILD_PIPELINE=1``,
    it must run from the checkout, and a signer that fails must raise: with
    ``check=False`` the suites would run against a library the self-test
    refuses, and the restore would leave the artefact unsigned, silently."""
    monkeypatch.setattr(tool, "REPO_ROOT", tmp_path)
    calls: list[tuple[list[str], dict[str, object]]] = []

    def record(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(tool.subprocess, "run", record)
    tool._resign()
    ((cmd, kwargs),) = calls
    assert cmd == [sys.executable, "-m", "ama_cryptography.integrity", "--update", "--sign"]
    assert kwargs["cwd"] == tmp_path
    assert kwargs["check"] is True
    env = kwargs["env"]
    assert isinstance(env, dict) and env["AMA_BUILD_PIPELINE"] == "1"
    inherited = {k: v for k, v in os.environ.items() if k != "AMA_BUILD_PIPELINE"}
    assert {k: env.get(k) for k in inherited} == inherited, "the caller's environment was dropped"


# --------------------------------------------------------------------------
# --python-suite: which two libraries are swapped
# --------------------------------------------------------------------------


def test_a_macos_install_name_chain_is_found(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """clang --coverage writes gcov data on macOS too; the library there is
    libama_cryptography.<version>.dylib behind symlinks, not .so.<version>."""
    repo = tmp_path / "repo"
    pkg = repo / "ama_cryptography"
    lib = repo / "build-cov" / "lib"
    for directory, body in ((pkg, b"release"), (lib, b"instrumented")):
        directory.mkdir(parents=True)
        (directory / "libama_cryptography.5.0.0.dylib").write_bytes(body)
        (directory / "libama_cryptography.5.dylib").symlink_to("libama_cryptography.5.0.0.dylib")
        (directory / "libama_cryptography.dylib").symlink_to("libama_cryptography.5.dylib")
    _ctest_counter(lib.parent)
    monkeypatch.setattr(tool, "REPO_ROOT", repo)
    installed = pkg / "libama_cryptography.5.0.0.dylib"
    signed_over: list[bytes] = []
    monkeypatch.setattr(tool, "_resign", lambda: signed_over.append(installed.read_bytes()))
    monkeypatch.setattr(tool.subprocess, "run", _suite_runs(lib.parent))
    assert tool._run_python_suite(lib.parent, []) == 0
    assert signed_over == [b"instrumented", b"release"]
    assert installed.read_bytes() == b"release"


@pytest.mark.parametrize("name", ["ama_cryptography.dll", "libama_cryptography.dll"])
def test_a_windows_runtime_dll_is_found(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """On Windows the shared library is a single DLL, and CMake puts the
    build one under bin (RUNTIME_OUTPUT_DIRECTORY), not lib.  MSVC and clang
    name it ama_cryptography.dll; MinGW gcc -- the Windows toolchain that
    writes gcov data -- adds its lib prefix.  Reverting either .dll glob, or
    the bin search, makes this return None."""
    repo = tmp_path / "repo"
    pkg = repo / "ama_cryptography"
    build = repo / "build-cov"
    bindir = build / "bin"
    for directory, body in ((pkg, b"release"), (bindir, b"instrumented")):
        directory.mkdir(parents=True)
        (directory / name).write_bytes(body)
    _ctest_counter(build)
    monkeypatch.setattr(tool, "REPO_ROOT", repo)
    installed = pkg / name
    signed_over: list[bytes] = []
    monkeypatch.setattr(tool, "_resign", lambda: signed_over.append(installed.read_bytes()))
    monkeypatch.setattr(tool.subprocess, "run", _suite_runs(build))
    assert tool._run_python_suite(build, []) == 0
    assert signed_over == [b"instrumented", b"release"]
    assert installed.read_bytes() == b"release"


_CONFIGS = ("Debug", "Release", "RelWithDebInfo", "MinSizeRel")


def _library_named_for(subdir: str) -> str:
    return "ama_cryptography.dll" if subdir.startswith("bin") else "libama_cryptography.so.5.0.0"


@pytest.mark.parametrize(
    "subdir", ["lib", "bin", *(f"{out}/{cfg}" for out in ("lib", "bin") for cfg in _CONFIGS)]
)
def test_the_build_library_is_found_in_every_cmake_output_directory(
    tool: ModuleType, tmp_path: Path, subdir: str
) -> None:
    """A multi-config generator (Visual Studio, Xcode, Ninja Multi-Config)
    puts the library in ``lib/<Config>`` or ``bin/<Config>``, which setup.py
    and pqc_backends search and this tool did not."""
    directory = tmp_path.joinpath(*subdir.split("/"))
    directory.mkdir(parents=True)
    library = directory / _library_named_for(subdir)
    library.write_bytes(b"instrumented")
    assert tool._instrumented_library(tmp_path) == library


@pytest.mark.parametrize(
    "layout",
    [
        # lib/ ambiguous: the search used to fall through to bin/'s library.
        [
            "lib/libama_cryptography.so.5.0.0",
            "lib/libama_cryptography.so.6.0.0",
            "bin/libama_cryptography.dll",
        ],
        # One in each of two directories: the first used to win.
        ["lib/libama_cryptography.so.5.0.0", "bin/ama_cryptography.dll"],
        # A leftover Release build beside the Debug coverage one.
        ["lib/Debug/libama_cryptography.so.5.0.0", "lib/Release/libama_cryptography.so.5.0.0"],
        # Both DLL spellings in one configuration directory.
        ["bin/Debug/ama_cryptography.dll", "bin/Debug/libama_cryptography.dll"],
    ],
    ids=["ambiguous-lib", "lib-and-bin", "two-configs", "two-spellings"],
)
def test_an_ambiguous_build_tree_is_refused_not_guessed(
    tool: ModuleType, tmp_path: Path, layout: list[str]
) -> None:
    for relative in layout:
        path = tmp_path.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"a library")
    assert tool._instrumented_library(tmp_path) is None


def test_two_real_libraries_are_refused_not_guessed(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    (installed.parent / "libama_cryptography.5.0.0.dylib").write_bytes(b"stray")
    monkeypatch.setattr(tool, "_resign", lambda: pytest.fail("signed an ambiguous tree"))
    assert tool._run_python_suite(build_dir, []) is None


def test_the_python_suite_refuses_without_both_libraries(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    installed.unlink()
    monkeypatch.setattr(tool, "_resign", lambda: pytest.fail("signed with nothing to swap"))
    assert tool._run_python_suite(build_dir, []) is None
