#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for ``tools/_repo.py``, the shared git enumeration behind the gates.

Six gates listed files with a bare ``git ls-files`` split on newlines.  git
C-quotes a non-ASCII path there (``clé_key.txt`` comes out as
``"cl\\303\\251_key.txt"``, quotes included), the quoted string names no file,
and each gate dropped it silently: an AWS key planted in ``clé_key.txt``
scanned clean, a bare ``# noqa`` in ``zz_é.py`` was never audited, an
unguarded ``os.fdopen`` in ``zz_é.py`` was never parsed.

Every test here drives a throwaway git repository with ``core.quotePath``
forced on (the git default, pinned locally so a developer's global
``core.quotePath=false`` cannot make the regression invisible).  The
end-to-end tests copy the real gate and the real helper into that repository
and run the gate as a script, the way CI does, so they exercise the
script-mode import of ``tools._repo`` and the gate's own ``main``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from tools import _repo

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS = REPO_ROOT / "tools"

#: Assembled with str.join so this file carries no key-shaped literal: the
#: scanner deliberately joins adjacent and ``+``-concatenated string literals,
#: so a concatenation is still a finding.
FAKE_AWS_KEY_ID = "IA".join(("AK", "ABCDEFGHIJKLMNOP"))

SECRET_NAME = "clé_key.txt"
PY_NAME = "zz_é.py"


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        check=True,
    )
    return os.fsdecode(proc.stdout)


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q")
    _git(path, "config", "core.quotePath", "true")
    return path


def _quoting_is_active(repo: Path) -> None:
    """Precondition: without ``-z`` git really does quote the non-ASCII name.

    If it did not, every test below would pass against the defect too.
    """
    listing = _git(repo, "ls-files")
    assert "\\303\\251" in listing, listing


def _copy_gate(repo: Path, gate: str) -> None:
    """Copy one real gate plus the real helper into ``repo/tools``."""
    (repo / "tools").mkdir(exist_ok=True)
    for name in ("__init__.py", "_repo.py", gate):
        shutil.copyfile(TOOLS / name, repo / "tools" / name)


def _run_gate(repo: Path, gate: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env.pop("PYTHONPATH", None)
    return subprocess.run(
        [sys.executable, str(repo / "tools" / gate), *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )


@pytest.fixture()
def secret_repo(tmp_path: Path) -> Path:
    repo = _init_repo(tmp_path / "repo")
    (repo / SECRET_NAME).write_text(f'aws_key = "{FAKE_AWS_KEY_ID}"\n', encoding="utf-8")
    (repo / "README.txt").write_text("nothing to see\n", encoding="utf-8")
    _git(repo, "add", "--", ".")
    _quoting_is_active(repo)
    return repo


@pytest.fixture()
def py_repo(tmp_path: Path) -> Path:
    """A repository whose only Python problems live in a non-ASCII file."""
    repo = _init_repo(tmp_path / "repo")
    (repo / PY_NAME).write_text(
        "import os\n\n\ndef f(fd):\n    x = 1  # noqa\n    return os.fdopen(fd, 'wb')\n",
        encoding="utf-8",
    )
    (repo / "clean.py").write_text("X = 1\n", encoding="utf-8")
    _git(repo, "add", "--", ".")
    _quoting_is_active(repo)
    return repo


# ---------------------------------------------------------------------------
# The helper
# ---------------------------------------------------------------------------


class TestHelperListsNonAsciiNames:
    def test_tracked_names_returns_the_real_name(self, secret_repo: Path) -> None:
        assert SECRET_NAME in _repo.tracked_names(secret_repo)

    def test_tracked_files_returns_a_readable_path(self, secret_repo: Path) -> None:
        paths = _repo.tracked_files(secret_repo)
        assert secret_repo / SECRET_NAME in paths
        assert all(p.is_file() for p in paths)

    def test_pathspec_selects_a_non_ascii_python_file(self, py_repo: Path) -> None:
        assert set(_repo.tracked_names(py_repo, "*.py")) == {PY_NAME, "clean.py"}

    def test_staged_files_returns_the_real_name(self, secret_repo: Path) -> None:
        assert secret_repo / SECRET_NAME in _repo.staged_files(secret_repo)


class TestHelperFailsClosed:
    def test_outside_a_repository_is_an_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # GIT_CEILING_DIRECTORIES stops git walking up into an enclosing
        # checkout if tmp_path happens to sit inside one.
        plain = tmp_path / "plain"
        plain.mkdir()
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
        with pytest.raises(_repo.TrackedFilesError):
            _repo.tracked_files(plain)

    def test_a_tracked_path_that_is_a_directory_is_an_error(self, secret_repo: Path) -> None:
        target = secret_repo / "README.txt"
        target.unlink()
        target.mkdir()
        with pytest.raises(_repo.TrackedFilesError, match=r"README\.txt"):
            _repo.tracked_files(secret_repo)

    def test_a_working_tree_deletion_git_confirms_is_skipped(self, secret_repo: Path) -> None:
        (secret_repo / "README.txt").unlink()
        assert "README.txt" in _git(secret_repo, "ls-files", "--deleted")
        names = _repo.tracked_names(secret_repo)
        assert "README.txt" not in names
        assert SECRET_NAME in names

    def test_a_staged_path_missing_from_the_working_tree_is_an_error(
        self, secret_repo: Path
    ) -> None:
        (secret_repo / SECRET_NAME).unlink()
        with pytest.raises(_repo.TrackedFilesError):
            _repo.staged_files(secret_repo)


# ---------------------------------------------------------------------------
# The gates, end to end: copied into the repository and run as scripts
# ---------------------------------------------------------------------------


class TestCheckSecretsSeesNonAsciiFiles:
    def test_the_gate_fails_on_a_key_in_a_non_ascii_file(self, secret_repo: Path) -> None:
        _copy_gate(secret_repo, "check_secrets.py")
        _git(secret_repo, "add", "--", "tools")
        proc = _run_gate(secret_repo, "check_secrets.py")
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert SECRET_NAME in proc.stdout
        assert "aws-access-key-id" in proc.stdout

    def test_staged_mode_fails_on_a_key_in_a_non_ascii_file(self, secret_repo: Path) -> None:
        _copy_gate(secret_repo, "check_secrets.py")
        _git(secret_repo, "add", "--", "tools")
        proc = _run_gate(secret_repo, "check_secrets.py", "--staged")
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert SECRET_NAME in proc.stdout

    def test_an_enumeration_failure_exits_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tools.check_secrets import _tracked_files

        plain = tmp_path / "plain"
        plain.mkdir()
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
        with pytest.raises(SystemExit) as exc:
            _tracked_files(plain, staged_only=False)
        assert exc.value.code == 2


class TestCheckSuppressionHygieneSeesNonAsciiFiles:
    def test_the_gate_fails_on_a_bare_noqa_in_a_non_ascii_file(self, py_repo: Path) -> None:
        # The gate's C-tree pass fails closed on an empty scope; give it one
        # clean file under each root so the only finding is the Python one.
        for rel in ("src/c/ok.c", "include/ok.h"):
            (py_repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (py_repo / rel).write_text("int ok;\n", encoding="utf-8")
        _copy_gate(py_repo, "check_suppression_hygiene.py")
        # tools/ stays untracked: the copied gates carry justified markers of
        # their own, and this test is about the one in zz_é.py.
        proc = _run_gate(py_repo, "check_suppression_hygiene.py")
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert PY_NAME in proc.stdout
        assert "noqa" in proc.stdout


class TestCheckFdopenSafetySeesNonAsciiFiles:
    def test_the_gate_fails_on_an_unguarded_fdopen_in_a_non_ascii_file(self, py_repo: Path) -> None:
        _copy_gate(py_repo, "check_fdopen_safety.py")
        proc = _run_gate(py_repo, "check_fdopen_safety.py")
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert PY_NAME in proc.stdout


# ---------------------------------------------------------------------------
# The other migrated gates, at their enumeration functions
# ---------------------------------------------------------------------------


def _load(name: str) -> ModuleType:
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestOtherMigratedGates:
    def test_check_type_check_scope_lists_the_real_path(self, py_repo: Path) -> None:
        gate = _load("check_type_check_scope")
        assert py_repo / PY_NAME in gate.tracked_python_files(py_repo)

    def test_check_headers_lists_the_real_path(self, py_repo: Path) -> None:
        gate = _load("check_headers")
        assert PY_NAME in gate.tracked_files(py_repo)

    def test_check_headers_fails_closed_on_a_tracked_non_file(self, py_repo: Path) -> None:
        """check_headers already listed with ``-z``; its defect was the
        ``is_file()`` filter that dropped a tracked path it could not read."""
        gate = _load("check_headers")
        target = py_repo / "clean.py"
        target.unlink()
        target.mkdir()
        with pytest.raises(RuntimeError, match=r"clean\.py"):
            gate.selected_files(py_repo)

    def test_check_documented_counts_lists_the_real_path(self, py_repo: Path) -> None:
        gate = _load("check_documented_counts")
        assert PY_NAME in gate._tracked_or_globbed(py_repo, "*.py")
        assert PY_NAME in gate._loc_tracked_files(py_repo)

    def test_check_documented_counts_globs_only_without_a_repository(self, tmp_path: Path) -> None:
        """The documented tarball fallback survives; a broken git does not use it."""
        gate = _load("check_documented_counts")
        tarball = tmp_path / "tarball"
        tarball.mkdir()
        (tarball / "a.py").write_text("X = 1\n", encoding="utf-8")
        assert gate._git_tracked(tarball) is None
        assert [Path(p).name for p in gate._tracked_or_globbed(tarball, "*.py")] == ["a.py"]

        # A `.git` that git cannot use is a checkout git failed on, not a
        # tarball: that used to fall back to the glob silently.
        (tarball / ".git").write_text("gitdir: /nonexistent\n", encoding="utf-8")
        with pytest.raises(RuntimeError):
            gate._tracked_or_globbed(tarball, "*.py")
