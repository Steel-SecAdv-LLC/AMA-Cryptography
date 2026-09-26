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
# staged_files: every staged status that carries content into the commit
# ---------------------------------------------------------------------------

#: Long enough that appending one line keeps the edited file far above git's
#: 50% rename-similarity threshold, so the edit is staged as a rename.
_MODULE_BODY = "".join(f"SETTING_{i} = {i}\n" for i in range(40))


def _staged_status(repo: Path, name: str) -> str:
    """The status letter ``git diff --cached`` gives ``name`` (``R092`` -> ``R``)."""
    for line in _git(repo, "diff", "--cached", "--name-status").splitlines():
        fields = line.split("\t")
        if fields[-1] == name:
            return fields[0][0]
    raise AssertionError(f"{name} is not staged")


@pytest.fixture()
def committed_repo(tmp_path: Path) -> Path:
    """A repository with one commit: ``config.py`` and a symlink entry ``link.txt``.

    The symlink is written into the index with ``update-index --cacheinfo``
    rather than created on disk, so the test needs no symlink privilege on
    Windows; ``core.symlinks=true`` makes git take a later regular file at that
    path as the type change it is on every platform.  ``diff.renames`` is
    pinned to git's default so a developer's global override cannot turn the
    rename below into a delete-and-add and hide the regression.
    """
    repo = _init_repo(tmp_path / "repo")
    _git(repo, "config", "user.name", "gate test")
    _git(repo, "config", "user.email", "gate-test@example.invalid")
    _git(repo, "config", "diff.renames", "true")
    _git(repo, "config", "core.symlinks", "true")
    (repo / "config.py").write_text(_MODULE_BODY, encoding="utf-8")
    target = repo / "link-target.tmp"
    target.write_text("config.py", encoding="utf-8")
    blob = _git(repo, "hash-object", "-w", "--", target.name).strip()
    target.unlink()
    _git(repo, "update-index", "--add", "--cacheinfo", f"120000,{blob},link.txt")
    _git(repo, "add", "--", "config.py")
    _git(repo, "commit", "-q", "-m", "baseline")
    return repo


def _rename_and_plant_a_key(repo: Path) -> Path:
    _git(repo, "mv", "config.py", "settings.py")
    renamed = repo / "settings.py"
    renamed.write_text(_MODULE_BODY + f'aws_key = "{FAKE_AWS_KEY_ID}"\n', encoding="utf-8")
    _git(repo, "add", "--", "settings.py")
    assert _staged_status(repo, "settings.py") == "R"
    return renamed


def _replace_the_symlink_with_a_key(repo: Path) -> Path:
    replaced = repo / "link.txt"
    replaced.write_text(f'aws_key = "{FAKE_AWS_KEY_ID}"\n', encoding="utf-8")
    _git(repo, "add", "--", "link.txt")
    assert _staged_status(repo, "link.txt") == "T"
    return replaced


class TestStagedFilesListsEveryStatusThatCarriesContent:
    """``--diff-filter=ACM`` dropped renames (``R``) and type changes (``T``).

    Both put new content into the commit, so the pre-commit secret scan
    (``check_secrets.py --staged``) passed a key added to either.  Each test
    asserts its status first, so it cannot pass because git staged the change
    under a status the old filter already allowed.
    """

    def test_a_renamed_and_edited_file_is_listed(self, committed_repo: Path) -> None:
        renamed = _rename_and_plant_a_key(committed_repo)
        assert renamed in _repo.staged_files(committed_repo)

    def test_a_type_changed_path_is_listed(self, committed_repo: Path) -> None:
        replaced = _replace_the_symlink_with_a_key(committed_repo)
        assert replaced in _repo.staged_files(committed_repo)

    def test_a_staged_deletion_is_not_listed_and_not_an_error(self, committed_repo: Path) -> None:
        """Deletion is the one status with no content: excluding it is the filter."""
        _git(committed_repo, "rm", "-q", "--", "config.py")
        assert _staged_status(committed_repo, "config.py") == "D"
        assert committed_repo / "config.py" not in _repo.staged_files(committed_repo)


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


class TestCheckSecretsStagedSeesRenamesAndTypeChanges:
    """The pre-commit hook itself, run the way ``.pre-commit-config.yaml`` runs it."""

    def test_staged_mode_fails_on_a_key_in_a_renamed_file(self, committed_repo: Path) -> None:
        _rename_and_plant_a_key(committed_repo)
        _copy_gate(committed_repo, "check_secrets.py")
        proc = _run_gate(committed_repo, "check_secrets.py", "--staged")
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "settings.py" in proc.stdout
        assert "aws-access-key-id" in proc.stdout

    def test_staged_mode_fails_on_a_key_in_a_type_changed_file(self, committed_repo: Path) -> None:
        _replace_the_symlink_with_a_key(committed_repo)
        _copy_gate(committed_repo, "check_secrets.py")
        proc = _run_gate(committed_repo, "check_secrets.py", "--staged")
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "link.txt" in proc.stdout
        assert "aws-access-key-id" in proc.stdout


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
