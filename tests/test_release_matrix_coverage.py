# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Every wheel the release builds must have a pytest lane somewhere.

release.yml's build-wheels matrix states the invariant beside CIBW_BUILD: a
wheel for a platform and interpreter no CI lane exercises ships untested,
and the equality is per (runner architecture x interpreter), not merely per
Python range.  The invariant had already failed silently once: the release
matrix carried macos-15-intel (x86_64) while the only macOS pytest lane ran
on macos-latest (arm64), and the aarch64 test includes covered 3.11/3.13 of
the five interpreters aarch64 wheels are built for — 8 of 25 wheels shipped
with only cibuildwheel's import smoke test.  Nothing in the tree compared
the two sides, so the drift was invisible; this module is that comparison.

Parsed from the workflows rather than restated, so a matrix edit on either
side fails here instead of shipping an untested wheel: the release side is
build-wheels' runner labels crossed with CIBW_BUILD's cp tags; the test side is
the union of ci.yml's `test` matrix and ci-build-test.yml's `python-package`
matrix.  Every matrix is expanded by the same reader
``tools/check_required_contexts.py`` uses for the ruleset contexts —
GitHub's documented rules: the product of the base keys, minus every
``exclude`` entry, with each ``include`` merged or appended.  This module used
to read ``os`` x ``python-version`` plus the include entries and nothing else,
so an ``exclude:`` added to a test matrix would have removed a lane from CI
while it went on being counted here as coverage.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any, cast

import yaml

from tools.check_required_contexts import matrix_combinations

WORKFLOWS = pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows"

#: Runner label -> the (os-family, architecture) identity a wheel or a pytest
#: lane actually runs on.  `-latest` aliases resolve per GitHub's current
#: mapping; a NEW label showing up in a matrix fails the lookup loudly below
#: rather than being guessed at.
RUNNER_ARCH: dict[str, str] = {
    "ubuntu-latest": "linux-x86_64",
    "ubuntu-24.04": "linux-x86_64",
    "ubuntu-24.04-arm": "linux-aarch64",
    "ubuntu-22.04-arm": "linux-aarch64",
    "windows-latest": "windows-x86_64",
    "windows-2025": "windows-x86_64",
    "macos-latest": "macos-arm64",
    "macos-15": "macos-arm64",
    "macos-26": "macos-arm64",
    "macos-15-intel": "macos-x86_64",
}


def _load(name: str) -> dict[str, Any]:
    return cast(
        "dict[str, Any]",
        yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8")),
    )


def _cibw_pythons() -> set[str]:
    """The cpXYZ tags release.yml builds, as dotted interpreter versions."""
    text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    match = re.search(r'CIBW_BUILD:\s*"([^"]+)"', text)
    assert match is not None, "release.yml no longer pins CIBW_BUILD"
    tags = re.findall(r"cp(\d)(\d+)-\*", match.group(1))
    assert tags, f"CIBW_BUILD carries no cp tags: {match.group(1)!r}"
    return {f"{major}.{minor}" for major, minor in tags}


def _combinations(matrix: Any, where: str) -> list[dict[str, Any]]:
    """The cells a ``strategy.matrix`` really runs, ``exclude`` honoured."""
    combos = matrix_combinations(matrix)
    assert combos is not None, (
        f"{where}: the matrix is an expression that cannot be read statically, "
        f"so this gate cannot say which lanes it runs"
    )
    return combos


def _arch(label: Any, where: str) -> str:
    assert label in RUNNER_ARCH, (
        f"{where} uses runner label {label!r} that RUNNER_ARCH does not "
        f"classify; add it (with its real architecture) so this gate keeps "
        f"comparing the right sides"
    )
    return RUNNER_ARCH[label]


def _release_archs() -> set[str]:
    jobs = _load("release.yml")["jobs"]
    where = "release.yml build-wheels"
    return {
        _arch(combo["os"], where)
        for combo in _combinations(jobs["build-wheels"]["strategy"]["matrix"], where)
        if "os" in combo
    }


def _lanes(matrix: Any, where: str) -> set[tuple[str, str]]:
    """(arch, python) pairs a matrix actually runs."""
    lanes: set[tuple[str, str]] = set()
    for combo in _combinations(matrix, where):
        label = combo.get("os")
        version = combo.get("python-version")
        if label is None or version is None:
            continue
        lanes.add((_arch(label, where), str(version)))
    return lanes


def _matrix_lanes(
    workflow: str, job: str, parsed: dict[str, Any] | None = None
) -> set[tuple[str, str]]:
    data = parsed if parsed is not None else _load(workflow)
    return _lanes(data["jobs"][job]["strategy"]["matrix"], f"{workflow} {job}")


def _covered(
    ci: dict[str, Any] | None = None, ci_build_test: dict[str, Any] | None = None
) -> set[tuple[str, str]]:
    return _matrix_lanes("ci.yml", "test", ci) | _matrix_lanes(
        "ci-build-test.yml", "python-package", ci_build_test
    )


def _uncovered(
    ci: dict[str, Any] | None = None, ci_build_test: dict[str, Any] | None = None
) -> list[tuple[str, str]]:
    required = {(arch, python) for arch in _release_archs() for python in _cibw_pythons()}
    return sorted(required - _covered(ci, ci_build_test))


def test_every_released_wheel_has_a_pytest_lane() -> None:
    """The set difference that was 8/25 must stay empty."""
    missing = _uncovered()
    assert missing == [], (
        "release.yml builds wheels for platform+interpreter combinations no "
        "pytest lane exercises — each of these ships with only cibuildwheel's "
        f"import smoke test: {missing}. Extend ci.yml's test matrix or "
        "ci-build-test.yml's python-package matrix (see the CIBW_BUILD "
        "comment in release.yml), or shrink the release matrix deliberately."
    )


def test_an_excluded_cell_is_not_a_lane() -> None:
    """``exclude`` removes a cell from CI, so it must remove it from coverage."""
    matrix = {
        "os": ["ubuntu-latest", "windows-latest"],
        "python-version": ["3.10", "3.11"],
        "exclude": [{"os": "windows-latest", "python-version": "3.11"}],
    }
    assert _lanes(matrix, "synthetic") == {
        ("linux-x86_64", "3.10"),
        ("linux-x86_64", "3.11"),
        ("windows-x86_64", "3.10"),
    }


def test_excluding_a_released_cell_from_every_test_matrix_is_caught() -> None:
    """End to end on the real workflows: the gate names the wheel an exclude strands.

    Windows x86-64 on the newest released interpreter is exercised by both
    ``ci.yml::test`` and ``ci-build-test.yml::python-package``; excluding it
    from both leaves that wheel with no pytest lane, and the comparison above
    has to say exactly that.
    """
    newest = max(_cibw_pythons(), key=lambda v: tuple(int(p) for p in v.split(".")))
    ci = _load("ci.yml")  # a fresh parse each call, so editing it touches nothing shared
    ci_build_test = _load("ci-build-test.yml")
    for data, job in ((ci, "test"), (ci_build_test, "python-package")):
        matrix = data["jobs"][job]["strategy"]["matrix"]
        matrix.setdefault("exclude", []).append({"os": "windows-latest", "python-version": newest})
    assert _uncovered() == [], "precondition: the real tree has full coverage"
    assert _uncovered(ci, ci_build_test) == [("windows-x86_64", newest)]


def test_the_gate_is_not_vacuous() -> None:
    """Both sides must be non-trivially populated for the comparison to mean
    anything: five interpreters, five release architectures, and strictly
    more covered lanes than release architectures."""
    pythons = _cibw_pythons()
    archs = _release_archs()
    covered = _covered()
    assert len(pythons) >= 5, pythons
    assert len(archs) >= 5, archs
    assert len(covered) >= len(archs) * len(pythons), (
        "fewer pytest lanes than released wheels — the coverage test above "
        "can only be passing by accident"
    )


def test_no_artifact_upload_is_gated_on_success() -> None:
    """`if: success()` on an upload withholds evidence exactly on failure.

    ci.yml's Bandit upload documents the defect and the fix (always());
    the benchmark and constant-time uploads carried the same gate for
    another release.  Pin the property tree-wide rather than per incident:
    no upload-artifact step in any workflow may be success()-gated.
    """
    offenders: list[str] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_name, job in (data.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                uses = step.get("uses", "")
                if "upload-artifact" not in uses:
                    continue
                condition = str(step.get("if", "")).strip()
                if condition == "success()":
                    offenders.append(f"{path.name}:{job_name}: {step.get('name')}")
    assert offenders == [], (
        "artifact uploads gated on success() withhold their evidence exactly "
        f"when a gate fails and somebody needs it: {offenders}"
    )
