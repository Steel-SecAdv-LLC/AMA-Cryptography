# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The pre-commit configuration runs the derived-figures check before a commit.

``docs/METRICS_REPORT.md`` records line counts over the whole tree, so a
commit that touches any tracked file can leave them stale.  ``2ed1eb22`` did
exactly that: eight lines of JSON were added to two benchmark baselines
after the figures had been regenerated, and CI's documented-counts gate
refused the head on every Python lane.  The gate worked; it fired one push
late.  The hook pinned here runs the same check (``refresh_derived_docs.py
--check``) against the staged tree, so the drift fails the commit instead.

What is pinned is the configuration: the hook exists, it runs the check
mode of the refresh tool (never the writing mode, which would modify the
tree during a commit), it runs on every commit rather than only when a
listed file is staged, and the script it names exists.  That
``--check`` itself reports drift is ``test_check_mode_reports_drift_without_writing``
in ``tests/test_refresh_derived_docs.py``.  Both are needed: a hook that
runs a check which cannot fail guards nothing, and a check nothing runs
guards nothing either.
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG = REPO_ROOT / ".pre-commit-config.yaml"
HOOK_ID = "ama-derived-docs"
SCRIPT = "tools/refresh_derived_docs.py"


@pytest.fixture(scope="module")
def hook() -> dict[str, Any]:
    # Imported inside the fixture, not at module scope: check_documented_counts
    # collects cited test files with `pytest --collect-only` under the
    # pre-commit hook's own interpreter, which carries pytest and nothing else.
    # A module-scope third-party import would raise ModuleNotFoundError during
    # that collection; a lazy one keeps the module importable there.
    import yaml

    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    for repo in config["repos"]:
        for candidate in repo.get("hooks", []):
            if candidate.get("id") == HOOK_ID:
                assert repo.get("repo") == "local", f"{HOOK_ID} must be a local hook"
                return dict(candidate)
    raise AssertionError(
        f"the {HOOK_ID} pre-commit hook is gone; derived figures can drift "
        f"again without a commit noticing"
    )


@pytest.fixture(scope="module")
def entry(hook: dict[str, Any]) -> list[str]:
    value = hook.get("entry")
    assert isinstance(value, str) and value.strip(), f"{HOOK_ID} has no entry"
    return shlex.split(value)


def test_the_hook_runs_the_refresh_tool_in_check_mode(entry: list[str]) -> None:
    """Check mode only: the writing mode would rewrite files mid-commit."""
    assert SCRIPT in entry, f"{HOOK_ID} does not run {SCRIPT}: {entry}"
    assert "--check" in entry, f"{HOOK_ID} would REWRITE derived files during a commit: {entry}"


def test_the_script_the_hook_names_exists(entry: list[str]) -> None:
    index = entry.index(SCRIPT)
    assert (REPO_ROOT / entry[index]).is_file(), f"{SCRIPT} has moved; the hook runs nothing"


def test_the_hook_runs_on_every_commit(hook: dict[str, Any]) -> None:
    """The figures depend on every tracked file, so no `files:` scope is right.

    Without ``always_run`` a local hook with ``pass_filenames: false`` and no
    ``files`` pattern still runs only when some staged file matches the
    default pattern; pre-commit skips it on a commit that stages nothing it
    recognises.  A drift caused by a file the pattern misses is the case
    this hook exists for.
    """
    assert hook.get("always_run") is True, f"{HOOK_ID} is not always_run"
    assert hook.get("pass_filenames") is False, (
        f"{HOOK_ID} would receive staged filenames as arguments, which " f"{SCRIPT} does not accept"
    )


def test_the_hook_brings_its_own_pytest(hook: dict[str, Any]) -> None:
    """The counts are measured by `pytest --collect-only` under the hook's interpreter.

    Under ``language: system`` the hook ran whatever ``python3`` was on PATH;
    with one that could not import pytest, every documented file read as
    "collection produced no count" (measured: six false rows) and the commit
    was refused for a drift that did not exist.  An isolated environment with
    pytest pinned, the way the mypy hook pins its dependencies, makes the
    check's result independent of the developer's PATH.
    """
    assert hook.get("language") == "python", f"{HOOK_ID} depends on what python3 on PATH imports"
    deps = hook.get("additional_dependencies") or []
    assert any(
        isinstance(d, str) and d.split("==")[0].strip().lower() == "pytest" for d in deps
    ), f"{HOOK_ID} has no pytest in its environment; collection cannot run: {deps}"


def test_the_hook_is_quiet_but_not_silent(entry: list[str]) -> None:
    """``--quiet`` suppresses the passes' output, not the drift report.

    ``check_only`` prints the stale figures and the regenerating command to
    stderr whatever ``--quiet`` says; the flag only keeps a clean commit from
    echoing every checked claim.  Pinned so nobody adds an output redirect
    that would turn a refused commit into an unexplained one.
    """
    assert "--quiet" in entry
    assert not any(token.startswith(">") or token == "2>&1" for token in entry), entry


def test_this_module_imports_no_dev_extra_at_module_scope() -> None:
    """This file must import nothing beyond the standard library and pytest at
    module scope.

    ``check_documented_counts`` runs ``pytest --collect-only`` on every
    documented test file under the hook's own interpreter, which carries
    pytest and nothing else.  A module-scope import of a dev-only extra
    (PyYAML, hypothesis, cryptography, ...) raises ModuleNotFoundError during
    that collection and refuses the commit for a drift that does not exist.
    ``yaml`` here is imported inside the ``hook`` fixture for exactly that
    reason; moving it back to module scope fails this test.
    """
    import ast

    allowed = set(sys.stdlib_module_names) | {"pytest"}
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    offenders: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            offenders += [n.name for n in node.names if n.name.split(".")[0] not in allowed]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if node.module.split(".")[0] not in allowed:
                offenders.append(node.module)
    assert not offenders, (
        "module-scope imports outside the standard library and pytest break "
        f"collection under the hook's pytest-only interpreter: {offenders}"
    )
