# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for the two strict merge gates: **CI Gate** (ci.yml) and
**Build and Test Gate** (ci-build-test.yml).

A green CI run proves the gates *pass* good input; it says nothing about whether
they *reject* bad input. A gate that cannot go red is not a gate. These tests
demonstrate the rejection direction three ways, hermetically (without leaving the
real PR red):

1. **Aggregation logic.** Both gates are `if: always()` jobs whose failing step
   fires on ``contains(needs.*.result, 'failure'|'skipped'|'cancelled')``. The
   real expression is parsed out of the workflow YAML and evaluated against
   synthetic dependency-result vectors: an all-``success`` fleet passes, and a
   single ``failure``/``skipped``/``cancelled`` turns the gate red. The literal
   set is pinned to exactly the three fail states, so a future weakening that
   drops ``skipped`` — the precise gap the gate comment warns about — fails here.

2. **CI Gate rejects bad input.** CI Gate depends on ``code-quality``, which runs
   ``tools/check_headers.py --check``. That script is driven end-to-end (as a
   subprocess, on a real git tree) and must exit non-zero on a missing license
   header and zero on the canonical one.

3. **Build and Test Gate rejects bad input.** That gate runs no check scripts;
   it depends on ``lint`` (ruff/black/mypy). ``ruff`` and ``black`` are driven on
   deliberately bad fixtures and must exit non-zero, and zero on clean input.

To reproduce a *real* red gate locally: ``ruff check`` a file with an unused
import, or drop the license header from a tracked source file and run
``python tools/check_headers.py --check`` — either turns its worker job, and
therefore the gate, red.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
CHECK_HEADERS = REPO_ROOT / "tools" / "check_headers.py"

FAIL_STATES = {"failure", "skipped", "cancelled"}

# (workflow file, gate job `name:`, worker jobs the gate MUST depend on)
GATES = [
    ("ci.yml", "CI Gate", {"test", "code-quality"}),
    ("ci-build-test.yml", "Build and Test Gate", {"c-library", "lint", "python-package"}),
]
GATE_IDS = [g[1] for g in GATES]


def _load_workflow(name: str) -> dict[str, Any]:
    return cast("dict[str, Any]", yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8")))


def _gate_job(workflow: dict[str, Any], gate_name: str) -> dict[str, Any]:
    for job in workflow["jobs"].values():
        if job.get("name") == gate_name:
            return cast("dict[str, Any]", job)
    raise AssertionError(f"no job named {gate_name!r} found in workflow")


def _fail_condition_literals(job: dict[str, Any]) -> set[str]:
    """The status literals in the gate's failing-step `if:` — the set of
    dependency results that turn the gate red."""
    for step in job.get("steps", []):
        cond = str(step.get("if", ""))
        if "contains(needs" in cond:
            return set(re.findall(r"contains\(\s*needs\.\*\.result\s*,\s*'([^']+)'\s*\)", cond))
    raise AssertionError("gate has no needs.*.result aggregation step")


class TestGateAggregationIsFailClosed:
    """The gates' own red/green logic, evaluated against synthetic results."""

    @pytest.mark.parametrize("wf_name,gate_name,expected_needs", GATES, ids=GATE_IDS)
    def test_gate_runs_always_and_gates_its_workers(
        self, wf_name: str, gate_name: str, expected_needs: set[str]
    ) -> None:
        job = _gate_job(_load_workflow(wf_name), gate_name)
        assert "always()" in str(job.get("if", "")), (
            f"{gate_name} must be `if: always()` so it resolves to a definitive "
            "red/green even when a dependency fails (else it sits `skipped`)"
        )
        needs = set(job.get("needs", []))
        missing = expected_needs - needs
        assert not missing, f"{gate_name} does not gate {missing}; needs={needs}"

    @pytest.mark.parametrize("wf_name,gate_name,_expected", GATES, ids=GATE_IDS)
    def test_gate_treats_any_non_success_as_red(
        self, wf_name: str, gate_name: str, _expected: set[str]
    ) -> None:
        job = _gate_job(_load_workflow(wf_name), gate_name)
        literals = _fail_condition_literals(job)
        assert literals == FAIL_STATES, (
            f"{gate_name} fail condition must be exactly {sorted(FAIL_STATES)}, got "
            f"{sorted(literals)} — a gate that stops treating 'skipped' as red is the "
            "exact silent-drift gap the gate comment warns about"
        )

        # Faithful model of the production expression: the failing step fires
        # (gate red) iff ANY dependency result is one of the fail literals.
        def gate_is_red(results: list[str]) -> bool:
            return any(lit in results for lit in literals)

        n = len(job.get("needs", []))
        assert n > 0, f"{gate_name} must depend on worker jobs"

        # Good fleet: every worker succeeded -> gate green.
        assert not gate_is_red(["success"] * n), f"{gate_name} must pass when all deps succeed"

        # Bad fleet: any single non-success -> gate red.
        for bad in sorted(FAIL_STATES):
            vector = ["success"] * (n - 1) + [bad]
            assert gate_is_red(vector), f"{gate_name} must go red when a dependency is {bad!r}"


def _git_tree(root: Path, files: dict[str, str]) -> Path:
    """A minimal git working tree (files staged, not committed — `git ls-files`
    sees staged paths) so tools/check_headers.py can enumerate them."""
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=root, check=True)
    for rel, content in files.items():
        (root / rel).write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    return root


_CANONICAL_HEADER = (
    "# Copyright (C) 2025-2026 Steel Security Advisors LLC\n"
    "# SPDX-License-Identifier: Apache-2.0\n"
)


class TestCiGateRejectsBadInput:
    """CI Gate -> code-quality -> tools/check_headers.py --check, end to end."""

    def test_check_headers_rejects_a_missing_license_header(self, tmp_path: Path) -> None:
        root = _git_tree(tmp_path / "bad", {"mod.py": "print('no header')\n"})
        result = subprocess.run(
            [sys.executable, str(CHECK_HEADERS), "--check", "--root", str(root)],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, (
            "check_headers.py must reject a missing header (this is what turns "
            f"code-quality, and CI Gate, red):\n{result.stdout}\n{result.stderr}"
        )

    def test_check_headers_accepts_the_canonical_header(self, tmp_path: Path) -> None:
        root = _git_tree(tmp_path / "good", {"mod.py": _CANONICAL_HEADER + "print('ok')\n"})
        result = subprocess.run(
            [sys.executable, str(CHECK_HEADERS), "--check", "--root", str(root)],
            capture_output=True,
            text=True,
        )
        assert (
            result.returncode == 0
        ), f"check_headers.py must accept the canonical header:\n{result.stdout}\n{result.stderr}"


@pytest.mark.skipif(shutil.which("ruff") is None, reason="ruff not installed")
class TestBuildAndTestGateRejectsRuffViolations:
    """Build and Test Gate -> lint -> ruff. The gate runs no check scripts, so a
    lint violation is how invalid changes are rejected."""

    def test_ruff_rejects_a_violation(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.py"
        bad.write_text("import os, sys\n", encoding="utf-8")  # unused + multi-import
        result = subprocess.run(["ruff", "check", str(bad)], capture_output=True, text=True)
        assert result.returncode != 0, f"ruff must flag the violation:\n{result.stdout}"

    def test_ruff_accepts_clean_input(self, tmp_path: Path) -> None:
        good = tmp_path / "good.py"
        good.write_text(_CANONICAL_HEADER + 'print("ok")\n', encoding="utf-8")
        result = subprocess.run(["ruff", "check", str(good)], capture_output=True, text=True)
        assert result.returncode == 0, f"ruff must accept clean input:\n{result.stdout}"


@pytest.mark.skipif(shutil.which("black") is None, reason="black not installed")
class TestBuildAndTestGateRejectsBlackViolations:
    """Build and Test Gate -> lint -> black --check."""

    def test_black_rejects_unformatted(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.py"
        bad.write_text("x={ 'a':1 ,'b':2}\n", encoding="utf-8")
        result = subprocess.run(["black", "--check", str(bad)], capture_output=True, text=True)
        assert result.returncode != 0, f"black --check must flag unformatted code:\n{result.stderr}"

    def test_black_accepts_formatted(self, tmp_path: Path) -> None:
        good = tmp_path / "good.py"
        good.write_text('x = {"a": 1, "b": 2}\n', encoding="utf-8")
        result = subprocess.run(["black", "--check", str(good)], capture_output=True, text=True)
        assert result.returncode == 0, f"black --check must accept formatted code:\n{result.stderr}"
