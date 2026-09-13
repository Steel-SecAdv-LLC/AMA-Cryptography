#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``tools/refresh_derived_docs.py``.

Three tools maintain overlapping derived numbers in this repository and do not
agree in one pass. ``generate_visuals.py`` rewrites
``assets/visuals_manifest.json``, which changes the repository's line count,
which invalidates the LoC figures ``update_docs.py --loc`` just wrote. Running
the passes once in the right order is therefore NOT sufficient — measured
while writing this: adding a single test file needed two full rounds before
both gates agreed, in both directions (adding the file and removing it).

That is why the refresher iterates to a fixpoint rather than running a
checklist, and why failing to converge has to be an error instead of a
silently half-updated tree.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "refresh_derived_docs.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("refresh_derived_docs", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def tool() -> ModuleType:
    return _load()


def test_the_passes_run_in_dependency_order(tool: ModuleType) -> None:
    """LoC must come last: the visuals pass changes the tree's line count.

    Reversing these two produces a tree that fails its own gate by exactly the
    number of lines the manifest moved — a failure with no author, on a number
    no human wrote.
    """
    labels = [label for label, _ in tool.PASSES]
    assert labels.index("test counts") < labels.index(
        "visual assets"
    ), "the visuals pass reads the test tree, so counts must be measured first"
    assert labels.index("visual assets") < labels.index("lines of code"), (
        "generate_visuals.py rewrites assets/visuals_manifest.json, so the LoC "
        "pass must run after it or it measures a file that is about to change"
    )


def test_every_pass_and_gate_exists(tool: ModuleType) -> None:
    """A refresher naming a tool that is gone would fail at the worst moment."""
    for label, command in (*tool.PASSES, *tool.GATES):
        assert (REPO_ROOT / command[0]).is_file(), f"{label} names missing {command[0]}"


def test_both_ci_gates_are_verified(tool: ModuleType) -> None:
    """Converging without checking is how a half-updated tree ships."""
    gate_scripts = {command[0] for _, command in tool.GATES}
    assert "tools/check_documented_counts.py" in gate_scripts
    assert "tools/generate_visuals.py" in gate_scripts


def test_the_convergence_signal_covers_every_written_file(tool: ModuleType) -> None:
    """A file left out of the digest could oscillate forever unnoticed."""
    for relative in ("README.md", "docs/METRICS_REPORT.md", "assets/visuals_manifest.json"):
        assert relative in tool.TRACKED_OUTPUTS, (
            f"{relative} is rewritten by these passes but is not part of the "
            f"convergence signal, so a round that changes only it reads as stable"
        )


def test_more_than_one_round_is_allowed(tool: ModuleType) -> None:
    """Measured: two rounds were needed for a single added test file."""
    assert tool.DEFAULT_MAX_ROUNDS >= 2, (
        "one round is provably not enough — the visuals pass invalidates the "
        "LoC figures written in the same round"
    )


def test_non_convergence_fails(tool: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """Negative control: passes that never settle must be an error.

    Papering over this by raising --max-rounds would hide passes that are
    genuinely fighting each other.
    """
    monkeypatch.setattr(tool, "_run", lambda command, quiet: (0, ""))
    counter = iter(range(1000))
    monkeypatch.setattr(tool, "_digest_outputs", lambda: f"digest-{next(counter)}")
    assert tool.main(["--max-rounds", "2", "--quiet"]) == 1


def test_a_pass_that_refuses_to_run_is_fatal(
    tool: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """update_docs.py exits non-zero on unstaged new files; retrying is futile."""
    monkeypatch.setattr(tool, "_run", lambda command, quiet: (1, "refusing: unstaged files"))
    monkeypatch.setattr(tool, "_digest_outputs", lambda: "stable")
    assert tool.main(["--quiet"]) == 2


def test_check_mode_reports_drift_without_writing(
    tool: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], quiet: bool) -> tuple[int, str]:
        calls.append(command)
        return 1, "drifted"

    monkeypatch.setattr(tool, "_run", fake_run)
    assert tool.main(["--check", "--quiet"]) == 1
    ran = {command[0] for command in calls}
    assert "tools/update_docs.py" not in ran, "--check must not rewrite anything"


def test_check_mode_passes_on_a_current_tree(
    tool: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tool, "_run", lambda command, quiet: (0, "OK"))
    assert tool.main(["--check", "--quiet"]) == 0


def test_zero_rounds_is_rejected(tool: ModuleType) -> None:
    assert tool.main(["--max-rounds", "0", "--quiet"]) == 2


def test_the_real_tree_is_currently_converged(tool: ModuleType) -> None:
    """The committed tree must already satisfy the gates CI runs."""
    assert tool.main(["--check", "--quiet"]) == 0, (
        "derived figures have drifted in the committed tree; run "
        "`python tools/refresh_derived_docs.py`"
    )
