# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The pre-commit mypy hook must check exactly what CI's mypy step checks.

Two failures put this here.

The hook carried no ``--explicit-package-bases``, so on every
``pre-commit run --all-files`` mypy reached ``schemas/crypto_package_v1.py``
under two module names and stopped with "errors prevented further checking".
It type-checked nothing while reporting a hook failure that read like an
ordinary lint complaint.

Fixing that made the hook check all 275 Python files in the tree and surface
412 findings in demo tooling CI deliberately does not gate — the kind of
noise a developer learns to skip past, which is the other way to end up with
a hook that enforces nothing.  So the hook is scoped to the surface ci.yml
gates.

A scope written twice drifts.  This test derives CI's set from ci.yml itself
and requires the hook's ``files`` pattern to select the same files, so
adding a generator to one list and not the other fails here rather than
going quiet in the hook.
"""

from __future__ import annotations

import glob
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG = REPO_ROOT / ".pre-commit-config.yaml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _mypy_hook() -> dict[str, Any]:
    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    for repo in config["repos"]:
        for hook in repo.get("hooks", []):
            if hook["id"] == "mypy":
                return dict(hook)
    # `raise`, not `pytest.fail()`: both fail the test, but only this one is a
    # terminating statement to a reader that does not know pytest's NoReturn
    # annotation, so the function has one exit shape rather than an explicit
    # return beside an implicit fall-through None (CodeQL alert 635).
    raise AssertionError("the pre-commit mypy hook is gone")


def _ci_mypy_arguments() -> list[str]:
    """The path arguments of ci.yml's `mypy --strict ...` invocation.

    The command may carry a leading environment assignment (`MYPYPATH=.`) and
    option arguments that take a value (`--linecoverage-report <dir>`).  Both
    are stripped here: this function's subject is the SET OF PATHS mypy is
    pointed at, and a report directory is not one of them.  Matching only
    an unprefixed ``mypy --strict`` at the start of a line missed the
    invocation entirely once the env prefix
    was added, and the assertion below turned that into "this test has no
    subject" rather than a silent pass — which is why it is an assertion.
    """
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    match = re.search(
        r"^\s*(?:[A-Z_]+=\S*\s+)*mypy --strict (?P<args>(?:.|\n)*?)(?=\n\s*\n|\n\s*-\s)",
        text,
        re.M,
    )
    assert match, "no `mypy --strict` invocation found in ci.yml; this test has no subject"
    # Join the shell line continuations, then split as the shell would.
    joined = match.group("args").replace("\\\n", " ")

    #: Options that consume the argument after them, so that argument is not a
    #: path.  Listed rather than guessed: an unknown value-taking option would
    #: otherwise have its value read as a path and fail the `is_file` check
    #: below with a confusing message.
    value_taking = {"--linecoverage-report", "--linecount-report", "--lineprecision-report"}

    paths: list[str] = []
    skip_next = False
    for token in shlex.split(joined):
        if skip_next:
            skip_next = False
            continue
        if token in value_taking:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        paths.append(token)
    return paths


def _expand(arguments: list[str]) -> set[str]:
    """CI's arguments as the set of tracked .py files mypy would read."""
    files: set[str] = set()
    for argument in arguments:
        target = REPO_ROOT / argument
        if target.is_dir():
            files |= {
                p.relative_to(REPO_ROOT).as_posix()
                for p in target.rglob("*.py")
                if "__pycache__" not in p.parts
            }
        elif any(ch in argument for ch in "*?["):
            files |= {
                Path(p).relative_to(REPO_ROOT).as_posix()
                for p in glob.glob(str(REPO_ROOT / argument))
            }
        else:
            assert target.is_file(), f"ci.yml names {argument}, which does not exist"
            files.add(argument)
    return files


def _git_tracked_python_files() -> set[str]:
    """Every ``.py`` path git tracks, which is pre-commit's real input.

    Falls back to nothing useful rather than to an rglob: if git cannot answer
    here, the comparison below has no honest subject and the test should say
    so rather than substitute a set that means something else.
    """
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.py"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        "`git ls-files` failed, so pre-commit's real input set is unknown and "
        f"this test has no subject: {result.stderr.strip()}"
    )
    return {entry for entry in result.stdout.split("\0") if entry}


@pytest.fixture(scope="module")
def hook() -> dict[str, Any]:
    return _mypy_hook()


def test_the_hook_declares_a_scope(hook: dict[str, Any]) -> None:
    pattern = hook.get("files")
    assert isinstance(pattern, str) and pattern.strip(), (
        "the mypy hook has no `files` scope, so it runs on every Python file "
        "in the tree — including the demo tooling ci.yml deliberately leaves "
        "ungated, whose findings would make the hook noise"
    )


def test_the_hook_and_ci_check_the_same_files(hook: dict[str, Any]) -> None:
    # re.search, not re.match: that is what pre-commit itself does with a
    # hook's `files` pattern (`filter_by_include_exclude` searches). The two
    # coincide for a pattern anchored with `^(...)$`, which is what this hook
    # used to carry, so the difference stayed invisible — and then reported
    # every file in the tree as "the hook skips them" the moment the pattern
    # became an unanchored `\.py$`. A test that models the tool wrongly
    # reports on itself rather than on the subject.
    selector = re.compile(str(hook["files"]))
    ci_files = _expand(_ci_mypy_arguments())
    assert ci_files, "ci.yml's mypy step expanded to nothing; this test has no subject"

    hook_misses = sorted(f for f in ci_files if not selector.search(f))
    assert not hook_misses, (
        f"ci.yml gates these files but the pre-commit hook skips them: "
        f"{hook_misses[:10]}. The hook is weaker than CI."
    )

    # From `git ls-files`, not from rglob over the working tree.  pre-commit
    # only ever hands a hook files git knows about (staged paths on a commit,
    # tracked paths under `--all-files`), so an rglob models the wrong input:
    # it sweeps in every build artefact the tree happens to be carrying —
    # `build/lib/ama_cryptography/*.py`, dropped there by setuptools on any
    # `pip install -e .` or `python setup.py build`, plus any in-tree venv or
    # `.tox`.  That made this assertion fail on every machine that had built
    # the project, reporting ten build-output paths as "files the hook checks
    # and ci.yml does not" when pre-commit would never see one of them.  The
    # comment ten lines up warns about exactly this failure mode — a test that
    # models the tool wrongly reports on itself rather than on the subject —
    # and the variable was already named `tracked` for the set it was not.
    tracked = _git_tracked_python_files()
    hook_extra = sorted(f for f in tracked - ci_files if selector.search(f))
    assert not hook_extra, (
        f"the pre-commit hook checks files ci.yml does not: {hook_extra[:10]}. "
        f"Either add them to ci.yml or drop them here — a hook that reports "
        f"what CI will not is a hook developers learn to skip."
    )


def test_the_package_base_flag_is_present(hook: dict[str, Any]) -> None:
    """Without it the hook aborts at file collection and checks nothing.

    `schemas/` and `wycheproof_vectors/` have no `__init__.py`, so mypy sees
    their modules under two names and stops with "errors prevented further
    checking" — a total no-op that reports as an ordinary hook failure.
    """
    args = [str(a) for a in (hook.get("args") or [])]
    assert "--explicit-package-bases" in args, (
        "the mypy hook would abort at file collection on a tree that has a "
        "package-shaped directory without __init__.py"
    )


def test_the_directories_that_caused_the_abort_still_have_no_init() -> None:
    """The flag is load-bearing, not decorative.

    If both directories gained an `__init__.py`, the flag would be protecting
    nothing and this test should be re-examined rather than left asserting a
    condition that no longer exists.
    """
    unguarded = [
        d
        for d in ("schemas", "wycheproof_vectors")
        if (REPO_ROOT / d).is_dir()
        and any((REPO_ROOT / d).glob("*.py"))
        and not (REPO_ROOT / d / "__init__.py").exists()
    ]
    assert unguarded, (
        "no package-shaped directory without __init__.py remains, so "
        "--explicit-package-bases no longer guards anything measurable here"
    )


def test_the_hook_pins_the_stub_packages_ci_installs(hook: dict[str, Any]) -> None:
    """A hook whose findings CI cannot reproduce gets disbelieved.

    With only types-requests in its isolated venv the hook reported 16 errors
    CI does not have, because `pytest.skip()` is annotated NoReturn and that
    annotation is what narrows `Path | None` after a skip guard.
    """
    deps = [str(d) for d in (hook.get("additional_dependencies") or [])]
    names = {re.split(r"[=<>~!]", d, maxsplit=1)[0].lower() for d in deps}
    for required in ("pytest", "types-pyyaml"):
        assert required in names, (
            f"{required} is missing from the mypy hook's environment; without "
            f"it the hook reports findings CI does not have"
        )
