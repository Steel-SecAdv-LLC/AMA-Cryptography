# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the gcov parser in ``tools/measure_branch_coverage.py``.

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

The report excerpts below are gcov 13.3.0 output, verbatim, for::

    int f(int x) {
        int r = 0;
        if (x > 0 && x < 100) r = 1; else r = 2;
        return r;
    }

called five times with ``x`` in 1..5 — so line 4's two false arcs never run.
"""

from __future__ import annotations

import importlib.util
import sys
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


def _parse(
    tool: ModuleType, tmp_path: Path, *reports: str
) -> tuple[set[tuple[str, int, int]], set[tuple[str, int, int]], dict[tuple[str, int], str]]:
    taken: set[tuple[str, int, int]] = set()
    seen: set[tuple[str, int, int]] = set()
    text: dict[tuple[str, int], str] = {}
    for n, body in enumerate(reports):
        report = tmp_path / f"tu{n}.gcov"
        report.write_text(body, encoding="utf-8")
        tool._parse(report, taken, seen, text)
    return taken, seen, text


def test_a_starred_line_owns_its_branches(tool: ModuleType, tmp_path: Path) -> None:
    taken, seen, text = _parse(tool, tmp_path, PARTIAL)
    assert seen == {("demo.c", 4, i) for i in range(4)}, "branches keyed to the wrong line"
    assert taken == {("demo.c", 4, 0), ("demo.c", 4, 2)}
    assert text[("demo.c", 4)].strip().startswith("if (x > 0 && x < 100)")


def test_the_merge_reports_only_arcs_no_unit_took(tool: ModuleType, tmp_path: Path) -> None:
    """One unit starred, another fully executed: nothing is left untaken."""
    taken, seen, _ = _parse(tool, tmp_path, PARTIAL, FULL)
    assert seen - taken == set(), f"phantom never-taken arcs: {sorted(seen - taken)}"


def test_the_untaken_arcs_of_a_starred_line_are_reported_on_it(
    tool: ModuleType, tmp_path: Path
) -> None:
    taken, seen, _ = _parse(tool, tmp_path, PARTIAL)
    assert seen - taken == {("demo.c", 4, 1), ("demo.c", 4, 3)}


@pytest.mark.parametrize("count", ["5", "5*", "12345*", "#####", "=====", "-"])
def test_every_gcov_count_form_starts_a_source_line(tool: ModuleType, count: str) -> None:
    line = f"{count:>9}:   42:    if (x) {{"
    hit = tool._SRC_RE.match(line)
    assert hit is not None, f"{count!r} not recognised as a source line"
    assert hit.group(2) == "42"


# --------------------------------------------------------------------------
# --python-suite: the swap is restored on every path out
# --------------------------------------------------------------------------


def _python_suite_tree(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path]:
    """A fake repo whose package holds the release library and whose build
    tree holds the instrumented one, each behind the usual symlink chain."""
    repo = tmp_path / "repo"
    pkg = repo / "ama_cryptography"
    lib = repo / "build-cov" / "lib"
    for directory, body in ((pkg, b"release"), (lib, b"instrumented")):
        directory.mkdir(parents=True)
        (directory / "libama_cryptography.so.5.0.0").write_bytes(body)
        (directory / "libama_cryptography.so.5").symlink_to("libama_cryptography.so.5.0.0")
    monkeypatch.setattr(tool, "REPO_ROOT", repo)
    return pkg / "libama_cryptography.so.5.0.0", lib.parent


@pytest.mark.parametrize("statuses", [(0, 0), (1, 0), (0, 2)])
def test_both_python_suites_run_on_the_instrumented_library_and_the_release_one_is_restored(
    tool: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    statuses: tuple[int, int],
) -> None:
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    signed_over: list[bytes] = []
    ran: list[tuple[str, bytes]] = []
    monkeypatch.setattr(tool, "_resign", lambda: signed_over.append(installed.read_bytes()))
    pending = list(statuses)

    class _Done:
        def __init__(self, returncode: int) -> None:
            self.returncode = returncode

    def fake_run(cmd: list[str], **_: object) -> _Done:
        ran.append((" ".join(cmd[1:3]), installed.read_bytes()))
        return _Done(pending.pop(0))

    monkeypatch.setattr(tool.subprocess, "run", fake_run)
    expected = next((s for s in statuses if s != 0), 0)
    assert tool._run_python_suite(build_dir, []) == expected
    assert ran == [
        ("-m pytest", b"instrumented"),
        ("wycheproof_vectors/run_wycheproof.py", b"instrumented"),
    ], "a suite was skipped, or ran against the release library"
    assert signed_over == [b"instrumented", b"release"], "artefact not re-signed over each library"
    assert installed.read_bytes() == b"release", "the release library was not restored"


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


def test_a_failed_restore_keeps_the_backup_and_names_it(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The backup is the only copy of the release library once the swap is
    made; a restore that fails must not delete it."""
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    monkeypatch.setattr(tool, "_resign", lambda: None)

    class _Done:
        returncode = 0

    monkeypatch.setattr(tool.subprocess, "run", lambda *_, **__: _Done())
    real_mkdtemp = tool.tempfile.mkdtemp
    monkeypatch.setattr(
        tool.tempfile, "mkdtemp", lambda **kwargs: real_mkdtemp(dir=tmp_path, **kwargs)
    )
    real_copy = tool.shutil.copy2
    copies: list[Path] = []

    def copy_then_fail_the_restore(src: Path, dst: Path) -> object:
        copies.append(Path(dst))
        if len(copies) == 3:  # backup, swap, restore
            raise OSError("No space left on device")
        return real_copy(src, dst)

    monkeypatch.setattr(tool.shutil, "copy2", copy_then_fail_the_restore)
    with pytest.raises(RuntimeError, match="the backup is kept at") as caught:
        tool._run_python_suite(build_dir, [])
    backup = Path(str(caught.value).rsplit("kept at ", 1)[1])
    assert backup.read_bytes() == b"release", "the backup was deleted or is not the release library"
    assert isinstance(caught.value.__cause__, OSError)
    assert installed.read_bytes() == b"instrumented", "the backup is the only release copy"


def test_a_restored_run_leaves_no_backup_behind(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed, build_dir = _python_suite_tree(tool, tmp_path, monkeypatch)
    monkeypatch.setattr(tool, "_resign", lambda: None)

    class _Done:
        returncode = 0

    monkeypatch.setattr(tool.subprocess, "run", lambda *_, **__: _Done())
    made: list[str] = []
    real_mkdtemp = tool.tempfile.mkdtemp

    def recording_mkdtemp(**kwargs: str) -> str:
        made.append(real_mkdtemp(dir=tmp_path, **kwargs))
        return made[-1]

    monkeypatch.setattr(tool.tempfile, "mkdtemp", recording_mkdtemp)
    assert tool._run_python_suite(build_dir, []) == 0
    assert installed.read_bytes() == b"release"
    assert len(made) == 1 and not Path(made[0]).exists(), "the backup directory was left behind"


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
    monkeypatch.setattr(tool, "REPO_ROOT", repo)
    installed = pkg / "libama_cryptography.5.0.0.dylib"
    signed_over: list[bytes] = []
    monkeypatch.setattr(tool, "_resign", lambda: signed_over.append(installed.read_bytes()))

    class _Done:
        returncode = 0

    monkeypatch.setattr(tool.subprocess, "run", lambda *_, **__: _Done())
    assert tool._run_python_suite(lib.parent, []) == 0
    assert signed_over == [b"instrumented", b"release"]
    assert installed.read_bytes() == b"release"


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
