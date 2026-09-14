#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for ``tools/check_type_check_scope.py``.

``ARCHITECTURE.md`` states "type hints throughout (validated via mypy)" and
the CI pipeline summary says "mypy --strict (type checking, 0 errors)".  Until
5.0.0 the type check ran against a hand-written list of paths that left out
roughly a third of the Python in the repository — every chart, dashboard and
comparative generator under ``benchmarks/`` and ``tools/``, both published web
framework examples, ``setup.py``, and ``docs/conf.py``.  ``mypy --strict`` over
those files reported 323 errors in 13 files, among them four
``create_crypto_package(dna_codes=…)`` calls naming a parameter the function
has never had.

The scope is now every tracked ``.py`` file, and this gate is what keeps it
that way: a mypy run's exit status says nothing about what it looked at.

WHERE THE LIVE RUN LIVES
========================

This module used to run ``mypy --strict`` over the whole tree itself and
assert the run exited 0.  That put a pinned-toolchain lint gate inside a test
executed by all twenty-seven CI test-matrix jobs (``ci.yml::test`` is twelve,
``ci-build-test.yml::python-package`` fifteen), none of which provisions the
lint environment, and the verdict stopped being about this repository:

* the ``[dev]`` extra ships ``mypy`` but did not ship ``types-PyYAML``, so
  thirteen modules reported ``Library stubs not installed for "yaml"`` and the
  run exited 1 on every Linux and macOS job (fixed at source — the stubs are
  in the extra now, beside ``types-setuptools``);
* ``[dev]`` floats ``mypy>=2.3.0`` while the lint jobs pin ``2.3.0``, and
  2.3.1 hit an ``INTERNAL ERROR`` on ``benchmarks/generate_competitive.py`` on
  the Windows runners;
* with ``python_version = "3.10"`` and a NumPy new enough to write ``type X =
  ...`` in its own stubs, mypy stopped at ``numpy/__init__.pyi:737: Type
  statement is only supported in Python 3.12 and greater`` — "errors prevented
  further checking", exit 2, a truncated report — on the Windows 3.12 job and
  not on the Linux one, because the two resolved different NumPy wheels.

None of those are facts about the type-check SCOPE, which is what this gate
exists to defend.  The live full-tree run belongs to the one job that pins its
toolchain, and it is there in both workflows, with
``tools/check_type_check_scope.py`` wired to the report it writes.  What this
module keeps is stronger than the run it replaced, and it holds on every
platform:

* :class:`TestTheCIWiring` — the gate really is wired to the report mypy
  writes, in the same job, unskippably, in BOTH workflows, and the two
  workflows type-check the same set of paths (``ci-build-test.yml`` claims
  that in a comment and nothing checked it);
* :class:`TestTheCIWiring.test_the_ci_scope_reaches_every_tracked_file` — the
  path arguments cover every tracked ``.py`` file, checked without running
  mypy at all, which is the drift the gate was written for;
* :class:`TestTheRule` — the gate's own logic, both directions.
"""

from __future__ import annotations

import importlib.util
import json
import shlex
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_type_check_scope.py"
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

#: Both workflows that carry a ``code-quality``-style job.  Named rather than
#: globbed: a workflow that stops running the type check must fail this module,
#: not quietly drop out of the set it iterates.
TYPE_CHECKING_WORKFLOWS = ("ci.yml", "ci-build-test.yml")

#: mypy options that consume the next argument, so that argument is not a path.
#: Listed rather than guessed — an unknown value-taking option would otherwise
#: have its value read as a path.
_VALUE_TAKING = frozenset(
    {
        "--linecoverage-report",
        "--linecount-report",
        "--lineprecision-report",
        "--any-exprs-report",
        "--html-report",
        "--txt-report",
        "--xml-report",
        "--cobertura-xml-report",
        "--junit-xml",
        "--python-version",
        "--config-file",
        "--cache-dir",
        "--exclude",
    }
)


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_type_check_scope", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _repo(tmp_path: Path, files: list[str]) -> Path:
    """A throwaway git repo containing ``files``, so ``git ls-files`` has a scope."""
    root = tmp_path / "repo"
    root.mkdir()
    for rel in files:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    return root


def _report(tmp_path: Path, root: Path, files: list[str], pad_to: int = 250) -> Path:
    """A mypy-shaped ``coverage.json`` naming ``files`` (plus filler)."""
    lines: dict[str, list[list[int]]] = {str((root / rel).resolve()): [] for rel in files}
    for i in range(pad_to):
        lines[f"/nonexistent/filler_{i}.py"] = []
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps({"lines": lines}), encoding="utf-8")
    return report


def _workflow(name: str) -> dict[str, Any]:
    data = yaml.safe_load((WORKFLOW_DIR / name).read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{name} did not parse as a mapping"
    return data


def _steps(workflow: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """``(job_id, step)`` for every step in the workflow, in file order."""
    out: list[tuple[str, dict[str, Any]]] = []
    for job_id, job in (workflow.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            if isinstance(step, dict):
                out.append((str(job_id), step))
    return out


def _join_continuations(script: str) -> str:
    return script.replace("\\\n", " ")


def _mypy_invocations(script: str) -> list[list[str]]:
    """Every ``mypy --strict ...`` command in one ``run:`` block, tokenised.

    A leading environment assignment (``MYPYPATH=.``) is part of the command
    line, so the scan starts at the ``mypy`` token rather than at the start of
    the line — matching only an unprefixed ``mypy`` missed the invocation
    entirely once the prefix was added.
    """
    found: list[list[str]] = []
    for line in _join_continuations(script).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            tokens = shlex.split(stripped, comments=True)
        except ValueError:
            continue
        if "mypy" not in tokens:
            continue
        tokens = tokens[tokens.index("mypy") :]
        if "--strict" in tokens:
            found.append(tokens)
    return found


def _paths_and_report(tokens: list[str]) -> tuple[list[str], str | None]:
    """The path operands of a mypy command line, and its coverage report dir."""
    paths: list[str] = []
    report: str | None = None
    skip_next = False
    for index, token in enumerate(tokens[1:], start=1):
        if skip_next:
            skip_next = False
            continue
        if token in _VALUE_TAKING:
            if token == "--linecoverage-report" and index + 1 < len(tokens):
                report = tokens[index + 1]
            skip_next = True
            continue
        if token.startswith("--"):
            if token.startswith("--linecoverage-report="):
                report = token.split("=", 1)[1]
            continue
        paths.append(token)
    return paths, report


def _tracked_python() -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "*.py"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return [line for line in proc.stdout.splitlines() if line.strip()]


class TestTheCIWiring:
    """The gate is only a gate where it is wired to a report mypy wrote.

    Every assertion here is a file read: no mypy process, no stub packages, no
    NumPy wheel lottery.  That is deliberate — see the module docstring.
    """

    @pytest.mark.parametrize("name", TYPE_CHECKING_WORKFLOWS)
    def test_the_scope_gate_runs_on_the_report_mypy_writes(self, name: str) -> None:
        steps = _steps(_workflow(name))
        wired = 0
        for position, (job_id, step) in enumerate(steps):
            for tokens in _mypy_invocations(str(step.get("run") or "")):
                _paths, report = _paths_and_report(tokens)
                assert report is not None, (
                    f"{name}::{job_id}: `mypy --strict` runs without "
                    "--linecoverage-report, so the scope gate has no report to read"
                )
                assert step.get("continue-on-error") is not True, (
                    f"{name}::{job_id}: the type-check step is continue-on-error, "
                    "so the report it writes may be from a run nobody failed on"
                )
                expected = f"{report.rstrip('/')}/coverage.json"
                gates = [
                    later
                    for later_job, later in steps[position + 1 :]
                    if later_job == job_id
                    and "check_type_check_scope.py" in str(later.get("run") or "")
                    and expected in str(later.get("run") or "")
                ]
                assert gates, (
                    f"{name}::{job_id}: nothing runs "
                    f"tools/check_type_check_scope.py on {expected} after the "
                    "mypy step in this job, so the scope claim is unchecked"
                )
                for gate in gates:
                    assert (
                        gate.get("continue-on-error") is not True
                    ), f"{name}::{job_id}: the scope gate is continue-on-error"
                    assert "if" not in gate, (
                        f"{name}::{job_id}: the scope gate carries an `if:`, so it "
                        "is a gate that can decline to run"
                    )
                wired += 1
        assert wired == 1, (
            f"{name}: expected exactly one `mypy --strict` invocation to wire, " f"found {wired}"
        )

    def test_no_other_workflow_type_checks_outside_that_set(self) -> None:
        """``TYPE_CHECKING_WORKFLOWS`` is derived, not trusted.

        The two tests above check the workflows in that tuple.  A third
        workflow that ran ``mypy --strict`` would be a type check nothing here
        looks at — and, since only these two wire the scope gate, a run whose
        scope claim is unchecked.  Sweeping the directory is what makes the
        tuple a fact about the tree rather than a list someone remembered to
        update.
        """
        running = {
            path.name
            for path in sorted(WORKFLOW_DIR.glob("*.yml"))
            for _job_id, step in _steps(_workflow(path.name))
            if _mypy_invocations(str(step.get("run") or ""))
        }
        assert running == set(TYPE_CHECKING_WORKFLOWS), (
            "workflows running `mypy --strict` do not match TYPE_CHECKING_WORKFLOWS; "
            f"unlisted: {sorted(running - set(TYPE_CHECKING_WORKFLOWS))}; "
            f"listed but not running it: {sorted(set(TYPE_CHECKING_WORKFLOWS) - running)}"
        )

    def test_both_workflows_type_check_the_same_scope(self) -> None:
        """``ci-build-test.yml`` says "same scope as ci.yml"; this checks it.

        Two lists maintained by hand drift, and the one that drifts narrower
        reports a verdict the other does not hold to.
        """
        scopes: dict[str, list[str]] = {}
        for name in TYPE_CHECKING_WORKFLOWS:
            found = [
                sorted(_paths_and_report(tokens)[0])
                for _job_id, step in _steps(_workflow(name))
                for tokens in _mypy_invocations(str(step.get("run") or ""))
            ]
            # Collected, then required to be one — rather than assigned in a
            # loop, where a second invocation would silently win and this test
            # would be comparing whichever came last.  "There is exactly one"
            # is asserted here rather than borrowed from the test above: an
            # assertion that holds only because a sibling test passes is not
            # an assertion this test makes.
            assert len(found) == 1, f"{name}: {len(found)} `mypy --strict` invocations, expected 1"
            scopes[name] = found[0]
        assert set(scopes) == set(TYPE_CHECKING_WORKFLOWS), scopes
        first, second = TYPE_CHECKING_WORKFLOWS
        assert scopes[first] == scopes[second], (
            f"the two type-check scopes differ: only in {first}: "
            f"{sorted(set(scopes[first]) - set(scopes[second]))}; only in "
            f"{second}: {sorted(set(scopes[second]) - set(scopes[first]))}"
        )

    def test_the_ci_scope_reaches_every_tracked_file(self) -> None:
        """The drift the gate exists for, caught without running mypy.

        ``tools/check_type_check_scope.py`` catches a tracked file mypy did not
        analyse, from the report.  This catches the same thing one step
        earlier and everywhere: a tracked ``.py`` file that no path argument
        even points at.
        """
        (step,) = [
            step
            for _job_id, step in _steps(_workflow("ci.yml"))
            if _mypy_invocations(str(step.get("run") or ""))
        ]
        (tokens,) = _mypy_invocations(str(step.get("run") or ""))
        paths, _report = _paths_and_report(tokens)
        assert paths, "the mypy invocation names no paths"

        tracked = _tracked_python()
        assert len(tracked) >= 200, (
            f"git tracks only {len(tracked)} .py file(s); refusing to report "
            "success on a scope this small"
        )

        directories = tuple(p for p in paths if p.endswith("/"))
        files = {p for p in paths if not p.endswith("/")}
        for path in paths:
            assert (REPO_ROOT / path).exists(), f"the mypy scope names {path}, which does not exist"

        outside = [f for f in tracked if f not in files and not f.startswith(directories)]
        assert outside == [], (
            "tracked .py file(s) outside every path the CI type check names: "
            f"{outside}. Add them to the `mypy --strict` invocation in "
            ".github/workflows/ci.yml and .github/workflows/ci-build-test.yml."
        )

    def test_the_mypy_config_narrows_nothing(self) -> None:
        """A config-level ``exclude``/``files`` would shrink the run silently.

        The command line names the scope; ``[tool.mypy]`` could take it back
        without touching either workflow, and the two tests above would still
        pass.  ``tools/check_type_check_scope.py`` catches the consequence in
        CI from the coverage report — this names the cause, everywhere.
        """
        text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        section = text[text.index("[tool.mypy]") :]
        section = section[: section.index("[[tool.mypy.overrides]]")]
        for key in ("exclude", "files", "packages", "modules", "follow_imports"):
            assert f"\n{key}" not in "\n" + section, (
                f"[tool.mypy] sets `{key}`, which can narrow the run below the "
                "paths the workflows name"
            )


class TestTheRule:
    def test_a_fully_covered_tree_passes(self, gate: ModuleType, tmp_path: Path) -> None:
        files = ["pkg/a.py", "pkg/b.py", "top.py"]
        root = _repo(tmp_path, files)
        assert gate.audit(_report(tmp_path, root, files), root) == []

    def test_an_unchecked_file_is_reported(self, gate: ModuleType, tmp_path: Path) -> None:
        """The whole point: tracked, but absent from what mypy analysed."""
        files = ["pkg/a.py", "pkg/b.py", "top.py"]
        root = _repo(tmp_path, files)
        report = _report(tmp_path, root, ["pkg/a.py", "top.py"])
        problems = gate.audit(report, root)
        assert problems and "pkg/b.py" in problems[0], problems

    def test_a_collapsed_report_fails_closed(self, gate: ModuleType, tmp_path: Path) -> None:
        """A report listing almost nothing must not read as full coverage."""
        files = ["pkg/a.py"]
        root = _repo(tmp_path, files)
        report = _report(tmp_path, root, files, pad_to=0)
        problems = gate.audit(report, root)
        assert problems and "collapsed run" in problems[0], problems

    def test_an_unreadable_report_fails_closed(self, gate: ModuleType, tmp_path: Path) -> None:
        root = _repo(tmp_path, ["a.py"])
        missing = tmp_path / "does-not-exist.json"
        problems = gate.audit(missing, root)
        assert problems and "cannot read" in problems[0], problems

    def test_a_report_without_a_lines_map_fails_closed(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        root = _repo(tmp_path, ["a.py"])
        report = tmp_path / "coverage.json"
        report.write_text(json.dumps({"something-else": {}}), encoding="utf-8")
        problems = gate.audit(report, root)
        assert problems and "not a mypy coverage report" in problems[0], problems

    def test_a_tree_with_no_python_fails_closed(self, gate: ModuleType, tmp_path: Path) -> None:
        """No tracked files means no scope, which must not read as success."""
        root = _repo(tmp_path, ["README.md"])
        report = _report(tmp_path, root, [])
        problems = gate.audit(report, root)
        assert problems and "empty scope" in problems[0], problems

    def test_the_exempt_list_is_empty(self, gate: ModuleType) -> None:
        """An exemption is a file whose breakage nobody would see.

        Kept empty deliberately; this test is what makes adding one a visible
        decision rather than a quiet one.
        """
        assert gate.EXEMPT == {}

    def test_the_cli_reports_success(
        self, gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        files = ["pkg/a.py"]
        root = _repo(tmp_path, files)
        report = _report(tmp_path, root, files)
        assert gate.main([str(report), "--root", str(root)]) == 0
        assert "tracked .py file(s) are inside" in capsys.readouterr().out
