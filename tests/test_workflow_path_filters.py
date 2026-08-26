# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A path-filtered workflow must list every repository file it consumes.

WHY THIS TEST EXISTS

A ``paths:`` filter decides whether a workflow runs at all.  A gate that is
correct, non-vacuous and green is worth nothing on a change that never triggers
it, and that failure mode is silent in the most misleading way available: the
pull request shows no red check, because it shows no check.

Five workflows were in that state, and the sharpest case was the one guarding
this project's own headline finding.  ``dudect.yml`` runs
``tools/check_avx_scoping.py``, which disassembles the built object and fails if
a CPUID-gated instruction appears outside the kernel scoped for it.  The
property that gate enforces is set entirely by ``set_source_files_properties(...
COMPILE_FLAGS ...)`` in the root ``CMakeLists.txt`` — and ``CMakeLists.txt`` was
in neither of that workflow's filters.  A pull request that reintroduced a
library-wide ``-mavx2`` — the exact regression the gate was written for, and one
that touches only that file — would not have run the gate.  Nor was
``tools/check_avx_scoping.py`` itself listed, though its two sibling gates were,
under a comment saying precisely why they had to be.

The others: ``arm-qemu.yml`` is the only place ``check_secret_division.py`` runs
against an AArch64 object and did not list it; ``baseline-guard.yml`` did not
list the script that adjudicates the two baselines it watches;
``corpus-provenance.yml`` did not list the gate it runs over its corpora; and
``integrity-anchor-check.yml`` builds through CMake without listing
``CMakeLists.txt``.  ``dudect.yml``'s ``push`` and ``pull_request`` filters had
also drifted apart — six patterns against nine — so three gate scripts were
re-verified when a change arrived as a pull request and skipped when the same
change was pushed to ``main``, ``develop`` or a feature branch.

WHAT IT ENFORCES

For every workflow carrying a ``paths:`` filter:

  1. Every repository-relative script path named in any ``run:`` block is
     matched by one of that workflow's own patterns.
  2. A workflow that configures CMake lists ``CMakeLists.txt``.
  3. ``push`` and ``pull_request`` filters, where both exist, are identical —
     a change must not be gated on how it arrived.

Only paths that resolve to a file actually tracked in the repository are
required, so a shell word that merely looks like a path cannot fail the test.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

#: Repository-relative paths that appear in ``run:`` blocks.  Restricted to the
#: directories that hold executable helpers, so prose and output filenames in
#: the same block cannot be mistaken for inputs.
_SCRIPT_RE = re.compile(
    r"\b((?:tools|benchmarks|nist_vectors|wycheproof_vectors|fuzz|\.github/scripts)"
    r"/[\w./-]+\.(?:py|sh))"
)


def _tracked_files() -> frozenset[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout
    return frozenset(out.split())


TRACKED = _tracked_files()


def _workflows() -> list[Path]:
    return sorted(WORKFLOW_DIR.glob("*.yml"))


def _load(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), path
    return data


def _triggers(doc: dict[str, Any]) -> dict[str, Any]:
    # PyYAML resolves the bare key ``on`` to the boolean True (YAML 1.1), so the
    # trigger block is keyed by `True` rather than by the string. Both are
    # looked up because a quoted `"on":` would land under the string key, and a
    # dict[str, Any] cannot be `.get(True, ...)` under --strict.
    mapping: dict[Any, Any] = doc
    trig = mapping.get(True)
    if trig is None:
        trig = mapping.get("on")
    return trig if isinstance(trig, dict) else {}


def _filters(doc: dict[str, Any]) -> dict[str, list[str]]:
    """``{event: patterns}`` for the events that carry a ``paths:`` filter."""
    found: dict[str, list[str]] = {}
    for event in ("push", "pull_request"):
        cfg = _triggers(doc).get(event)
        if isinstance(cfg, dict) and isinstance(cfg.get("paths"), list):
            found[event] = list(cfg["paths"])
    return found


def _covers(pattern: str, path: str) -> bool:
    """True when a GitHub ``paths:`` pattern matches ``path``."""
    if pattern == path:
        return True
    if pattern.endswith("/**"):
        return path.startswith(pattern[:-2])
    if pattern.endswith("*"):
        return path.startswith(pattern[:-1])
    return False


def _run_blocks(node: Any) -> list[str]:
    """Every ``run:`` string anywhere in the document."""
    blocks: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "run" and isinstance(value, str):
                blocks.append(value)
            else:
                blocks.extend(_run_blocks(value))
    elif isinstance(node, list):
        for item in node:
            blocks.extend(_run_blocks(item))
    return blocks


FILTERED = [p for p in _workflows() if _filters(_load(p))]


def test_some_workflow_is_path_filtered() -> None:
    """Non-vacuity: if every filter disappeared, the tests below would all pass
    over an empty parametrisation and report green."""
    assert FILTERED, "no workflow carries a paths: filter — this test proves nothing"


@pytest.mark.parametrize("workflow", FILTERED, ids=lambda p: p.name)
def test_every_script_the_workflow_runs_is_in_its_own_filter(workflow: Path) -> None:
    doc = _load(workflow)
    patterns = [p for pats in _filters(doc).values() for p in pats]

    referenced = set()
    for block in _run_blocks(doc):
        for candidate in _SCRIPT_RE.findall(block):
            if candidate in TRACKED:
                referenced.add(candidate)

    missing = sorted(s for s in referenced if not any(_covers(p, s) for p in patterns))
    assert not missing, (
        f"{workflow.name} runs {missing} but its paths: filter does not list them. "
        f"A change to one of those scripts would not run the workflow that uses it, "
        f"so the change ships unexercised behind a pull request with no red check. "
        f"Add each to the filter (both events)."
    )


@pytest.mark.parametrize("workflow", FILTERED, ids=lambda p: p.name)
def test_a_cmake_configuring_workflow_lists_cmakelists(workflow: Path) -> None:
    doc = _load(workflow)
    blocks = "\n".join(_run_blocks(doc))
    if not re.search(r"\bcmake\s+(?:-S|-B|--build)", blocks):
        pytest.skip(f"{workflow.name} does not configure or drive CMake")

    patterns = [p for pats in _filters(doc).values() for p in pats]
    assert any(_covers(p, "CMakeLists.txt") for p in patterns), (
        f"{workflow.name} builds through CMake but does not list CMakeLists.txt in its "
        f"paths: filter. The per-file ISA scoping, the hardening flags and the test "
        f"registration all live there, so a change to that file can change what this "
        f"workflow verifies while preventing it from running at all."
    )


@pytest.mark.parametrize("workflow", FILTERED, ids=lambda p: p.name)
def test_push_and_pull_request_filters_agree(workflow: Path) -> None:
    filters = _filters(_load(workflow))
    if len(filters) < 2:
        pytest.skip(f"{workflow.name} filters only one event")

    push, pull = set(filters["push"]), set(filters["pull_request"])
    assert push == pull, (
        f"{workflow.name}: push and pull_request paths: filters differ. "
        f"only-in-pull_request={sorted(pull - push)}, only-in-push={sorted(push - pull)}. "
        f"The same change would be gated on how it arrived — verified as a pull request, "
        f"skipped when pushed to a branch this workflow watches."
    )
