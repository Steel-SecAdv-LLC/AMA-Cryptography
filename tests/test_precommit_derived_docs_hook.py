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

import ast
import importlib.util
import shlex
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG = REPO_ROOT / ".pre-commit-config.yaml"
HOOK_ID = "ama-derived-docs"
SCRIPT = "tools/refresh_derived_docs.py"


@pytest.fixture(scope="module")
def hook() -> dict[str, Any]:
    # Imported where it is used.  The hook never collects this module (it
    # collects the test files documented with a per-file count, which
    # test_every_file_the_hooks_collection_imports_needs_only_what_the_hook_has
    # holds to the hook's pytest-only environment), so this placement is
    # tidiness here, not a requirement.
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


#: What the hook's collection can import.  Its environment is pre-commit's
#: isolated one, carrying pytest and nothing else; the tree itself supplies
#: ``ama_cryptography`` and ``tests`` (``tests`` is a package, so collection
#: puts the repository root on ``sys.path``).
HOOK_IMPORTABLE = frozenset(sys.stdlib_module_names) | {
    "pytest",
    "_pytest",
    "ama_cryptography",
    "tests",
}


def _documented_test_files() -> list[str]:
    """Every test file a document gives a per-file count for.

    Found with ``check_documented_counts``' own claim pattern over its own
    document set, so this is exactly the set of files the gate runs
    ``pytest --collect-only`` on under the hook's interpreter.
    """
    spec = importlib.util.spec_from_file_location(
        "check_documented_counts_for_hook_test", REPO_ROOT / "tools" / "check_documented_counts.py"
    )
    assert spec is not None and spec.loader is not None
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    targets: set[str] = set()
    for document in gate._markdown_files(REPO_ROOT):
        text = document.read_text(encoding="utf-8")
        targets.update(match.group(1) for match in gate._TEST_COUNT_RE.finditer(text))
    return sorted(targets)


def _is_type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _import_time_modules(tree: ast.Module) -> list[str]:
    """Dotted names of every module imported when this module is imported.

    Everything outside a function body runs at import -- class bodies and
    top-level ``if`` / ``try`` / ``with`` blocks included -- except the body
    of an ``if TYPE_CHECKING:``, which never does.  A relative import names
    a module of ``tests``, and ``from tests import x`` may import the
    submodule ``tests.x``, so both are reported as ``tests.<name>``.  A
    guarded import (``try: import x`` / ``except ImportError``) is reported
    too: this does not try to prove that a handler absorbs the failure.
    """
    found: list[str] = []

    def visit(nodes: Iterable[ast.AST]) -> None:
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(node, ast.Import):
                found.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = f"tests.{node.module}" if node.module else "tests"
                else:
                    base = node.module or ""
                found.append(base)
                if base == "tests":
                    found.extend(f"tests.{alias.name}" for alias in node.names)
            elif isinstance(node, ast.If) and _is_type_checking(node.test):
                visit(node.orelse)
            else:
                visit(ast.iter_child_nodes(node))

    visit(tree.body)
    return found


def test_every_file_the_hooks_collection_imports_needs_only_what_the_hook_has() -> None:
    """The hook's collection imports each documented test file, the package's
    ``__init__.py`` and ``conftest.py``, and every ``tests`` module those
    import at module scope; none of them may import beyond
    ``HOOK_IMPORTABLE`` at import time.

    ``check_documented_counts`` runs ``pytest --collect-only`` on every test
    file documented with a per-file count, under the hook's own interpreter.
    A module-scope ``import yaml`` in any of them raises ModuleNotFoundError
    there and refuses the commit.  This used to pin the wrong file -- this
    module, which the hook never collects -- so adding ``import yaml`` to
    ``tests/test_secp256k1_ecdsa.py`` passed it.
    """
    documented = _documented_test_files()
    assert documented, "no document carries a per-file test count; the hook collects nothing"
    queue = [REPO_ROOT / relative for relative in documented]
    queue += [REPO_ROOT / "tests" / "__init__.py", REPO_ROOT / "tests" / "conftest.py"]
    seen: set[Path] = set()
    offenders: list[str] = []
    while queue:
        path = queue.pop()
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        for module in _import_time_modules(ast.parse(path.read_text(encoding="utf-8"))):
            if module.split(".")[0] not in HOOK_IMPORTABLE:
                offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}: {module}")
            elif module.startswith("tests."):
                queue.append(REPO_ROOT / (module.replace(".", "/") + ".py"))
    assert {REPO_ROOT / relative for relative in documented} <= seen, "a documented file is missing"
    assert not offenders, (
        "imports the pre-commit hook's pytest-only environment cannot satisfy, "
        "run when the hook collects these files for their documented counts "
        f"(move each into the test that needs it): {offenders}"
    )
