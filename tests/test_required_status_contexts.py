# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""``tools/check_required_contexts.py`` — every context the ruleset requires is
still produced by a pull-request job.

The failure this pins happened: removing the duplicated ubuntu/windows legs of
``ci-build-test.yml::python-package`` dropped ten contexts ``main``'s ruleset
requires, every check stayed green, and the pull request could not merge.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from tools import check_required_contexts as gate


@pytest.fixture(scope="module")
def workflows() -> list[tuple[str, dict[Any, Any]]]:
    return gate.load_workflows()


@pytest.fixture(scope="module")
def required() -> list[str]:
    return gate.load_snapshot()


def _without(
    workflows: list[tuple[str, dict[Any, Any]]], filename: str, mutate: Any
) -> list[tuple[str, dict[Any, Any]]]:
    out = []
    for name, workflow in workflows:
        if name == filename:
            workflow = copy.deepcopy(workflow)
            mutate(workflow)
        out.append((name, workflow))
    return out


def test_every_required_context_is_produced_by_a_pull_request_job(
    workflows: list[tuple[str, dict[Any, Any]]], required: list[str]
) -> None:
    produced, _ = gate.pull_request_contexts(workflows)
    assert gate.missing_contexts(required, produced) == []


def test_dropping_the_windows_legs_of_python_package_is_caught(
    workflows: list[tuple[str, dict[Any, Any]]], required: list[str]
) -> None:
    """The reverted de-duplication, replayed against the parsed workflow."""

    def drop_windows(workflow: dict[Any, Any]) -> None:
        matrix = workflow["jobs"]["python-package"]["strategy"]["matrix"]
        matrix["os"] = [os_ for os_ in matrix["os"] if os_ != "windows-latest"]

    mutated = _without(workflows, "ci-build-test.yml", drop_windows)
    produced, _ = gate.pull_request_contexts(mutated)
    missing = gate.missing_contexts(required, produced)
    assert missing == [c for c in required if c.endswith(" on windows-latest")]
    assert len(missing) == 4


def test_renaming_a_required_job_is_caught(
    workflows: list[tuple[str, dict[Any, Any]]], required: list[str]
) -> None:
    def rename(workflow: dict[Any, Any]) -> None:
        workflow["jobs"]["code-quality"]["name"] = "Code Quality"

    produced, _ = gate.pull_request_contexts(_without(workflows, "ci.yml", rename))
    assert gate.missing_contexts(required, produced) == ["Code Quality Checks"]


def test_a_job_that_runs_only_on_push_does_not_count() -> None:
    push_only = ("w.yml", {True: {"push": {"branches": ["main"]}}, "jobs": {"j": {"name": "X"}}})
    produced, _ = gate.pull_request_contexts([push_only])
    assert gate.missing_contexts(["X"], produced) == ["X"]


def test_a_pull_request_filtered_to_another_base_does_not_count() -> None:
    other = (
        "w.yml",
        {True: {"pull_request": {"branches": ["develop"]}}, "jobs": {"j": {"name": "X"}}},
    )
    assert gate.pull_request_contexts([other])[0] == {}


class TestMatrixExpansion:
    """GitHub's documented include/exclude semantics."""

    def test_include_extends_the_combinations_it_does_not_overwrite(self) -> None:
        combos = gate.matrix_combinations({"os": ["a", "b"], "include": [{"os": "a", "extra": 1}]})
        assert combos == [{"os": "a", "extra": 1}, {"os": "b"}]

    def test_include_that_overwrites_an_original_value_is_a_new_combination(self) -> None:
        combos = gate.matrix_combinations(
            {"os": ["a"], "py": ["1"], "include": [{"os": "c", "py": "2"}]}
        )
        assert combos == [{"os": "a", "py": "1"}, {"os": "c", "py": "2"}]

    def test_exclude_removes_matching_combinations(self) -> None:
        combos = gate.matrix_combinations(
            {"os": ["a", "b"], "py": ["1", "2"], "exclude": [{"os": "b", "py": "2"}]}
        )
        assert {"os": "b", "py": "2"} not in (combos or [])
        assert len(combos or []) == 3

    def test_an_include_only_matrix_is_one_combination_per_entry(self) -> None:
        combos = gate.matrix_combinations({"include": [{"k": "x"}, {"k": "y"}]})
        assert combos == [{"k": "x"}, {"k": "y"}]

    def test_an_expression_matrix_is_reported_not_guessed(self) -> None:
        assert gate.matrix_combinations("${{ fromJSON(needs.a.outputs.m) }}") is None
        contexts, unresolved = gate.job_contexts(
            "j", {"strategy": {"matrix": "${{ fromJSON(x) }}"}}
        )
        assert contexts == set() and unresolved

    def test_an_untemplated_name_gets_the_matrix_suffix(self) -> None:
        contexts, _ = gate.job_contexts(
            "j", {"name": "Kernels", "strategy": {"matrix": {"i": [1], "vl": [128]}}}
        )
        assert contexts == {"Kernels (1, 128)"}


def test_the_snapshot_names_its_source_and_ruleset() -> None:
    data = json.loads(gate.SNAPSHOT.read_text(encoding="utf-8"))
    assert data["source"].endswith("/rules/branches/main")
    assert isinstance(data["ruleset_id"], int)
    assert len(data["contexts"]) == len(set(data["contexts"])) > 0


def test_main_fails_on_a_context_no_job_produces(tmp_path: Path) -> None:
    snapshot = tmp_path / "s.json"
    snapshot.write_text(json.dumps({"contexts": ["No Such Job"]}), encoding="utf-8")
    assert gate.main(["--snapshot", str(snapshot)]) == 1


def test_main_passes_on_the_repository(capsys: pytest.CaptureFixture[str]) -> None:
    assert gate.main([]) == 0
    assert "required status context(s) each produced by a PR job" in capsys.readouterr().out
