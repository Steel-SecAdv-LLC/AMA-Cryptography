# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""tools/pr_touches_watched_paths.py: the relevance decision five gates rely on.

Each gate that used to be path-filtered (with a no-op twin) now runs on every
pull request and asks this script whether the change touches its watched
paths.  A wrong "false" skips every lane and the gate passes, so the pattern
semantics and the fail-closed paths are pinned here.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL = REPO_ROOT / "tools" / "pr_touches_watched_paths.py"


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("pr_touches_watched_paths", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("src/c/**", "src/c/ama_sha3.c", True),
        ("src/c/**", "src/c/avx2/ama_sha3_avx2.c", True),
        ("src/c/**", "src/cython/x.pyx", False),
        ("tests/c/dudect/**", "tests/c/dudect/a/b.c", True),
        ("*.md", "README.md", True),
        ("*.md", "docs/README.md", False),
        ("tools/constant_time/**", "tools/constant_time_x.py", False),
        ("CMakeLists.txt", "CMakeLists.txt", True),
        ("CMakeLists.txt", "tests/c/CMakeLists.txt", False),
        ("tests/c/test_?.c", "tests/c/test_a.c", True),
        ("tests/c/test_?.c", "tests/c/test_ab.c", False),
        (".github/workflows/dudect.yml", ".github/workflows/dudect.yml", True),
        (".github/workflows/dudect.yml", ".github/workflows/dudectXyml", False),
    ],
)
def test_github_filter_pattern_semantics(
    tool: ModuleType, pattern: str, path: str, expected: bool
) -> None:
    """``*`` stops at ``/``, ``**`` does not, ``?`` is one non-slash character,
    and every other character is literal (the ``.`` in a file name too)."""
    assert bool(tool.touches([path], [pattern])) is expected


@pytest.mark.parametrize("bad", ["!src/c/**", "", "   \n  "])
def test_a_negated_or_empty_pattern_list_is_refused(tool: ModuleType, bad: str) -> None:
    with pytest.raises(ValueError):
        tool.touches(["a"], tool.watched_patterns(bad) if bad.strip() else [""])


def _run(args: list[str], cwd: Path, watched: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, WATCHED_PATHS=watched)
    env.pop("GITHUB_OUTPUT", None)
    return subprocess.run(
        ["python3", str(TOOL), *args], cwd=cwd, env=env, capture_output=True, text=True
    )


def _repo(tmp_path: Path, changed: str) -> Path:
    def git(*argv: str) -> None:
        subprocess.run(["git", *argv], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "t@example.invalid")
    git("config", "user.name", "t")
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-q", "-m", "base")
    target = tmp_path / changed
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("change\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-q", "-m", "change")
    return tmp_path


def test_a_pull_request_touching_a_watched_path_is_relevant(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "src/c/new.c")
    result = _run(["--event", "pull_request"], repo, "src/c/**\n")
    assert result.returncode == 0, result.stderr
    assert "relevant=true" in result.stdout
    assert "watched: src/c/new.c" in result.stdout


def test_a_pull_request_touching_nothing_watched_is_not(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "docs/new.md")
    result = _run(["--event", "pull_request"], repo, "src/c/**\n")
    assert result.returncode == 0, result.stderr
    assert "relevant=false" in result.stdout


@pytest.mark.parametrize("event", ["push", "schedule", "workflow_dispatch", "workflow_call"])
def test_every_other_event_is_relevant(tmp_path: Path, event: str) -> None:
    repo = _repo(tmp_path, "docs/new.md")
    result = _run(["--event", event], repo, "src/c/**\n")
    assert result.returncode == 0 and "relevant=true" in result.stdout


def test_a_git_failure_is_an_error_not_a_no(tmp_path: Path) -> None:
    """No repository, so no diff: the gate must see a failed step, never
    "relevant=false" (which would skip every lane and pass the gate)."""
    result = _run(["--event", "pull_request"], tmp_path, "src/c/**\n")
    assert result.returncode == 1
    assert "relevant=" not in result.stdout


def test_an_empty_watched_list_is_an_error(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "src/c/new.c")
    result = _run(["--event", "pull_request"], repo, "")
    assert result.returncode == 1


def test_the_answer_reaches_github_output(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "src/c/new.c")
    output = tmp_path / "gh_output"
    env = dict(os.environ, WATCHED_PATHS="src/c/**", GITHUB_OUTPUT=str(output))
    subprocess.run(["python3", str(TOOL), "--event", "pull_request"], cwd=repo, env=env, check=True)
    assert output.read_text(encoding="utf-8") == "relevant=true\n"
