#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Mutation tests for ``tools/check_build_floor_coherence.py``.

Every case below re-introduces a drift that was **actually measured in this
tree** on 2026-11-06 and asserts the gate reports it.  That is the whole point
of the file: AGENTS.md section 6.2 says a test is worth what its mutation
proves, and a coherence gate that cannot be made to fail is a gate that reads
nothing.  Each test names the drift it restores, so a reader can tell a PIN
from a SMOKE without re-running the experiment.

Six of the cases restore the half-finished state Dependabot PR #427 left: it
raised setuptools for GHSA-xmj3-9gf7-h52w in the three requirement manifests
and in the first line of the ``[build-system]`` comment, and left the floor
behind in six other places, including ``[build-system].requires`` itself.
Three more restore drifts that predate that PR.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tools import check_build_floor_coherence as gate
from tools import check_release_pins as pins

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Every file the gate reads.
_READ = ("pyproject.toml", "setup.py", "requirements-dev.txt")


def _scratch_tree(tmp_path: Path) -> Path:
    """A byte-identical copy of every file the gate reads, free to corrupt.

    Bytes, not text, so a test that mutates one line is testing that line and
    not the line endings.
    """
    root = tmp_path / "tree"
    (root / ".github" / "workflows").mkdir(parents=True)
    for relative in _READ:
        (root / relative).write_bytes((REPO_ROOT / relative).read_bytes())
    for workflow in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
        shutil.copyfile(workflow, root / ".github" / "workflows" / workflow.name)
    return root


def _findings(root: Path) -> list[str]:
    findings, fatal, counts = gate.run_checks(root)
    assert not fatal, fatal
    assert not gate._vacuity(counts), gate._vacuity(counts)
    return [str(finding) for finding in findings]


def _mutate(root: Path, relative: str, old: str, new: str, count: int = 1) -> None:
    path = root / relative
    text = path.read_text(encoding="utf-8")
    assert (
        text.count(old) == count
    ), f"{relative}: expected {count} occurrence(s) of {old!r}, found {text.count(old)}"
    path.write_text(text.replace(old, new), encoding="utf-8")


# --------------------------------------------------------------------------
# Baseline: the tree as it ships.
# --------------------------------------------------------------------------


def test_the_tree_as_it_ships_is_coherent() -> None:
    """The live tree passes. Every case below mutates a copy of this state."""
    findings, fatal, counts = gate.run_checks(REPO_ROOT)
    assert not fatal, fatal
    assert findings == [], [str(f) for f in findings]
    assert not gate._vacuity(counts), gate._vacuity(counts)


def test_the_gate_reads_every_declaration_site() -> None:
    """Non-vacuity: the counts the gate reports are the counts it claims."""
    _, _, counts = gate.run_checks(REPO_ROOT)
    assert counts["packages"] == 5, counts
    assert counts["prose"] >= gate.MIN_PROSE_RESTATEMENTS, counts
    assert counts["remedy"] == 5, counts
    assert counts["manifest"] >= gate.MIN_MANIFEST_FLOORS, counts
    assert counts["workflow"] >= gate.MIN_WORKFLOW_FLOORS, counts
    assert counts["workflows_read"] >= gate.MIN_WORKFLOWS_READ, counts


# --------------------------------------------------------------------------
# PIN: the six places Dependabot PR #427 left behind.
# --------------------------------------------------------------------------


def test_setup_py_preflight_floor_left_behind_is_caught(tmp_path: Path) -> None:
    """``_BUILD_REQS`` is the guard that claims to enforce the build floor.

    PR #427 left it at ``(84, 0, 0)`` — i.e. the preflight would have accepted
    exactly the setuptools release the advisory names.
    """
    root = _scratch_tree(tmp_path)
    _mutate(root, "setup.py", "        (84, 2, 1),", "        (84, 0, 0),")
    findings = _findings(root)
    assert any(
        "setup.py _BUILD_REQS" in f and "setuptools" in f and "below" in f for f in findings
    ), findings


def test_build_system_requires_left_behind_is_caught(tmp_path: Path) -> None:
    """``[build-system].requires`` is what an isolated PEP 517 build resolves.

    Lowering it while the four mirrors stay put is the shape of a floor raise
    that reached the manifests and not the build: every mirror then reads as
    *above* the declared floor, which is a disagreement either way round.
    """
    root = _scratch_tree(tmp_path)
    _mutate(
        root,
        "pyproject.toml",
        '    "setuptools>=84.2.1",\n    "wheel>=0.48.0",\n    "cmake>=4.4.4",',
        '    "setuptools>=84.0.0",\n    "wheel>=0.48.0",\n    "cmake>=4.4.4",',
    )
    findings = _findings(root)
    assert any(
        "setup.py _BUILD_REQS" in f and "setuptools" in f and "above" in f for f in findings
    ), findings


def test_build_system_comment_left_behind_is_caught(tmp_path: Path) -> None:
    """The comment that says the floor and the guard "cannot drift".

    This is the one Dependabot half-rewrote: its first line moved to 84.2.1
    and the sentence naming the pinned value did not.
    """
    root = _scratch_tree(tmp_path)
    _mutate(
        root,
        "pyproject.toml",
        "`setuptools >= 84.2.1` (the latest baseline, above that fix)",
        "`setuptools >= 84.0.0` (the latest baseline, above that fix)",
    )
    findings = _findings(root)
    assert any(
        "[build-system] comment" in f and "setuptools" in f and "below" in f for f in findings
    ), findings


def test_preflight_comment_left_behind_is_caught(tmp_path: Path) -> None:
    """``setup.py``'s comment claims the floor matches pyproject's."""
    root = _scratch_tree(tmp_path)
    _mutate(root, "setup.py", "#   * setuptools >= 84.2.1:", "#   * setuptools >= 84.0.0:")
    findings = _findings(root)
    assert any(
        "preflight comment" in f and "setuptools" in f and "below" in f for f in findings
    ), findings


def test_remedy_string_left_behind_is_caught(tmp_path: Path) -> None:
    """The remedy a failing preflight prints is an instruction to a user.

    A stale one tells them to install a version the guard will reject, or one
    an advisory names.  INVARIANT-32's concern, one layer in.
    """
    root = _scratch_tree(tmp_path)
    _mutate(root, "setup.py", "'setuptools>=84.2.1'", "'setuptools>=84.0.0'")
    findings = _findings(root)
    assert any("_REMEDY" in f and "setuptools" in f and "below" in f for f in findings), findings


def test_dev_extra_left_behind_is_caught(tmp_path: Path) -> None:
    """The ``[dev]`` extra mirrors the build/packaging block; #427 left it."""
    root = _scratch_tree(tmp_path)
    _mutate(
        root,
        "pyproject.toml",
        '    "build>=1.6.1",\n    "setuptools>=84.2.1",',
        '    "build>=1.6.1",\n    "setuptools>=84.0.0",',
    )
    findings = _findings(root)
    assert any(
        "optional-dependencies" in f and "setuptools" in f and "below" in f for f in findings
    ), findings


def test_requirements_dev_below_the_floor_is_caught(tmp_path: Path) -> None:
    """The declared developer environment must not resolve below the floor."""
    root = _scratch_tree(tmp_path)
    _mutate(root, "requirements-dev.txt", "setuptools>=84.2.1", "setuptools>=84.0.0")
    findings = _findings(root)
    assert any(
        "requirements-dev.txt" in f and "setuptools" in f and "below" in f for f in findings
    ), findings


# --------------------------------------------------------------------------
# PIN: the drifts that predated PR #427, found by the same sweep.
# --------------------------------------------------------------------------


def test_workflow_cmake_below_the_floor_is_caught(tmp_path: Path) -> None:
    """``static-analysis.yml`` built the reproducibility wheel on ``cmake>=4.4.3``
    beneath a declared floor of 4.4.4, and nothing reported it."""
    root = _scratch_tree(tmp_path)
    _mutate(root, ".github/workflows/static-analysis.yml", "'cmake>=4.4.4'", "'cmake>=4.4.3'")
    findings = _findings(root)
    assert any(
        "static-analysis.yml" in f and "cmake" in f and "below" in f for f in findings
    ), findings


def test_workflow_cython_below_the_floor_is_caught(tmp_path: Path) -> None:
    """Three lanes installed the Cython that compiles ``math_engine`` at a floor
    below the one the preflight enforces, so a resolve of 3.0.x aborted the
    very next step."""
    root = _scratch_tree(tmp_path)
    _mutate(
        root,
        ".github/workflows/ci.yml",
        'pip install "Cython>=3.3.0" "numpy>=1.24.0,<3.0.0"',
        'pip install "Cython>=3.0.0" "numpy>=1.24.0,<3.0.0"',
        count=2,
    )
    findings = _findings(root)
    assert (
        sum(1 for f in findings if "ci.yml" in f and "Cython" in f and "below" in f) == 2
    ), findings


def test_a_lowercase_package_name_is_still_matched(tmp_path: Path) -> None:
    """``integrity-anchor-check.yml`` spells it ``cython``; PEP 503 normalisation
    is what makes that site visible at all."""
    root = _scratch_tree(tmp_path)
    _mutate(
        root,
        ".github/workflows/integrity-anchor-check.yml",
        "'cython>=3.3.0'",
        "'cython>=3.2.0'",
    )
    findings = _findings(root)
    assert any(
        "integrity-anchor-check.yml" in f and "Cython" in f and "below" in f for f in findings
    ), findings


# --------------------------------------------------------------------------
# The quote-aware comment stripper is load-bearing, not decoration.
# --------------------------------------------------------------------------


def test_a_commented_historical_install_is_not_a_declaration(tmp_path: Path) -> None:
    """``release.yml`` documents, in a shell comment, the unpinned install it
    used to run — ``pip install 'cmake>=4.4.3' ...``.

    Reading workflow text with a regex rather than stripping comments reports
    that line as a live sub-floor install.  Removing the stripper makes this
    test fail, which is what makes it a PIN rather than a restatement of
    intent: the drift is already in the tree, it is deliberate, and it is
    prose.
    """
    root = _scratch_tree(tmp_path)
    text = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "cmake>=4.4.3" in text, (
        "release.yml no longer carries the historical commented install this "
        "test is scoped to; re-scope it to whatever comment replaced it"
    )
    assert _findings(root) == []


def test_an_inline_comment_does_not_hide_a_real_install(tmp_path: Path) -> None:
    """The converse: stripping must not swallow the command it trails."""
    root = _scratch_tree(tmp_path)
    _mutate(
        root,
        ".github/workflows/integrity-anchor-check.yml",
        "'cython>=3.3.0' 'numpy>=1.24.0'",
        "'cython>=3.2.0' 'numpy>=1.24.0'  # stale floor with a trailing note",
    )
    findings = _findings(root)
    assert any("Cython" in f and "below" in f for f in findings), findings


def test_a_hash_inside_quotes_is_not_a_comment() -> None:
    """A ``#`` inside a quoted argument is data, not the start of a comment."""
    script = "pip install 'pkg>=1.0'  # note\npip install \"other#1.0\"\n"
    assert gate.strip_shell_comments(script).splitlines()[0] == "pip install 'pkg>=1.0'  "
    assert gate.strip_shell_comments(script).splitlines()[1] == 'pip install "other#1.0"'


# --------------------------------------------------------------------------
# RANGE: what the gate deliberately does not claim.
# --------------------------------------------------------------------------


def test_a_bare_install_declares_no_floor() -> None:
    """``pip install --upgrade pip setuptools wheel`` resolves the latest and
    states no minimum, so there is nothing for this gate to compare.  Treating
    it as a floor of 0 would need an exemption list to stay quiet, which
    AGENTS.md section 10 refuses."""
    arguments = list(
        gate.pip_install_arguments("python -m pip install --upgrade pip setuptools wheel")
    )
    assert arguments == ["--upgrade", "pip", "setuptools", "wheel"]
    assert not any(">=" in argument for argument in arguments)


def test_a_floor_above_the_build_floor_is_permitted_in_a_workflow(tmp_path: Path) -> None:
    """A lane may ask for something newer than the build requires; only *below*
    is a defect.  Equality is demanded of the four sites that claim identity,
    and those are covered by the PIN cases above."""
    root = _scratch_tree(tmp_path)
    _mutate(root, ".github/workflows/static-analysis.yml", "'cmake>=4.4.4'", "'cmake>=4.5.0'")
    assert _findings(root) == []


def test_line_continuations_are_joined(tmp_path: Path) -> None:
    """``static-analysis.yml``'s install spans three lines with ``\\``; without
    joining them only the first argument would ever be read."""
    arguments = list(
        gate.pip_install_arguments(
            "pip install \\\n  'build>=1.6.1' \\\n  'setuptools>=84.2.1' 'wheel>=0.48.0'"
        )
    )
    assert arguments == ["'build>=1.6.1'".strip("'"), "setuptools>=84.2.1", "wheel>=0.48.0"]


@pytest.mark.parametrize("package", ["setuptools", "wheel", "cmake", "Cython", "numpy"])
def test_every_build_system_package_is_covered(package: str) -> None:
    """The gate's package set is read from ``[build-system].requires``, so a
    package added there is covered without touching this file.  This test
    fails if one is dropped from the gate's view."""
    _, _, _ = gate.run_checks(REPO_ROOT)
    floors = gate._floor_map(
        pins.pyproject_floors((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    )
    assert pins.normalize(package) in floors


def test_a_missing_package_in_the_preflight_table_is_caught(tmp_path: Path) -> None:
    """The two tables must name the same set, not merely agree where they
    overlap: a package absent from the preflight is unguarded at build time."""
    root = _scratch_tree(tmp_path)
    _mutate(
        root,
        "setup.py",
        '    "wheel": ((0, 48, 0), "GHSA-8rrh-rw8j-w5fx, GHSA-vgq5-9859-3mmw"),\n',
        "",
    )
    findings = _findings(root)
    assert any("wheel" in f and "missing from" in f for f in findings), findings


def test_vacuity_floor_fires_when_the_gate_stops_reading(tmp_path: Path) -> None:
    """A gate reporting PASS over nothing is the failure mode this guards.

    Emptying the workflow directory leaves every other check satisfied, so
    without the non-vacuity floors the run would be green.
    """
    root = _scratch_tree(tmp_path)
    for workflow in (root / ".github" / "workflows").glob("*.yml"):
        workflow.unlink()
    findings, fatal, counts = gate.run_checks(root)
    assert not fatal, fatal
    assert findings == [], [str(f) for f in findings]
    problems = gate._vacuity(counts)
    assert problems, "an empty workflow directory passed every non-vacuity floor"
    assert any("workflows read" in problem for problem in problems), problems
