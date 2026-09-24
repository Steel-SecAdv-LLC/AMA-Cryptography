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
build-wheels' os list crossed with CIBW_BUILD's cp tags; the test side is
the union of ci.yml's `test` matrix (os x python-version plus its include
entries) and ci-build-test.yml's `python-package` matrix.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any, cast

import yaml

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


def _release_archs() -> set[str]:
    jobs = _load("release.yml")["jobs"]
    os_list = jobs["build-wheels"]["strategy"]["matrix"]["os"]
    archs = set()
    for label in os_list:
        assert label in RUNNER_ARCH, (
            f"release.yml build-wheels uses runner label {label!r} that "
            f"RUNNER_ARCH does not classify; add it (with its real "
            f"architecture) so this gate keeps comparing the right sides"
        )
        archs.add(RUNNER_ARCH[label])
    return archs


def _matrix_lanes(workflow: str, job: str) -> set[tuple[str, str]]:
    """(arch, python) pairs a job's matrix actually runs."""
    matrix = _load(workflow)["jobs"][job]["strategy"]["matrix"]
    lanes: set[tuple[str, str]] = set()
    for label in matrix.get("os", []):
        assert label in RUNNER_ARCH, (
            f"{workflow} {job} uses runner label {label!r} that RUNNER_ARCH "
            f"does not classify; add it so this gate keeps counting its lanes"
        )
        for version in matrix.get("python-version", []):
            lanes.add((RUNNER_ARCH[label], str(version)))
    for entry in matrix.get("include", []):
        label = entry.get("os")
        version = entry.get("python-version")
        if label is None or version is None:
            continue
        assert label in RUNNER_ARCH, (
            f"{workflow} {job} include entry uses unclassified runner " f"label {label!r}"
        )
        lanes.add((RUNNER_ARCH[label], str(version)))
    return lanes


def test_every_released_wheel_has_a_pytest_lane() -> None:
    """The set difference that was 8/25 must stay empty."""
    required = {(arch, python) for arch in _release_archs() for python in _cibw_pythons()}
    covered = _matrix_lanes("ci.yml", "test") | _matrix_lanes("ci-build-test.yml", "python-package")
    missing = sorted(required - covered)
    assert missing == [], (
        "release.yml builds wheels for platform+interpreter combinations no "
        "pytest lane exercises — each of these ships with only cibuildwheel's "
        f"import smoke test: {missing}. Extend ci.yml's test matrix or "
        "ci-build-test.yml's python-package matrix (see the CIBW_BUILD "
        "comment in release.yml), or shrink the release matrix deliberately."
    )


def test_the_gate_is_not_vacuous() -> None:
    """Both sides must be non-trivially populated for the comparison to mean
    anything: five interpreters, five release architectures, and strictly
    more covered lanes than release architectures."""
    pythons = _cibw_pythons()
    archs = _release_archs()
    covered = _matrix_lanes("ci.yml", "test") | _matrix_lanes("ci-build-test.yml", "python-package")
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


def test_no_pytest_lane_runs_twice_per_head() -> None:
    """ci.yml::test and ci-build-test.yml::python-package partition the lanes.

    Both matrices ran ubuntu-latest and windows-latest on all five interpreters
    with the same extras, the same SoftHSM2 token, the same
    AMA_CI_REQUIRE_BACKENDS / AMA_CI_REQUIRE_HISTORY escalation and the same
    ``tests/`` run, so ten pytest jobs per head were exact repeats — 161.7 of
    the 720.1 job-minutes PR #394's head d6270f28 consumed.  ci-build-test.yml
    now runs the macOS lanes only; the coverage upload those ten legs carried
    moved to ci.yml::test's ubuntu-latest / 3.11 cell.  This keeps the union
    (pinned against the release matrix above) from growing a duplicate again.
    """
    in_ci = _matrix_lanes("ci.yml", "test")
    in_build_test = _matrix_lanes("ci-build-test.yml", "python-package")
    both = sorted(in_ci & in_build_test)
    assert both == [], (
        "these (platform, interpreter) lanes run the full pytest suite in BOTH "
        f"ci.yml::test and ci-build-test.yml::python-package on every head: {both}. "
        "Keep each lane in one matrix; fold any step the other carries into it."
    )
    # Non-vacuity: both sides must still be populated, or the intersection is
    # empty because a matrix vanished rather than because it was partitioned.
    assert in_ci and in_build_test


def test_the_coverage_upload_runs_on_a_lane_that_exists() -> None:
    """The codecov upload survived the matrix consolidation, on a real cell.

    It lived on ci-build-test.yml::python-package's ubuntu-latest / 3.11 leg,
    one of the ten legs removed as duplicates of ci.yml::test; it moved to the
    same cell of ci.yml::test.  Pinned so a later matrix edit cannot drop it,
    or strand it behind an ``if:`` naming a cell no matrix runs any more.
    """
    uploads: list[tuple[str, str]] = []
    for workflow, job_id in (("ci.yml", "test"), ("ci-build-test.yml", "python-package")):
        job = _load(workflow)["jobs"][job_id]
        matrix = job["strategy"]["matrix"]
        cells = {
            (str(o), str(v)) for o in matrix.get("os", []) for v in matrix.get("python-version", [])
        }
        cells |= {
            (str(e["os"]), str(e["python-version"]))
            for e in matrix.get("include", [])
            if "os" in e and "python-version" in e
        }
        steps = job["steps"]
        for step in steps:
            if not str(step.get("uses", "")).startswith("codecov/codecov-action@"):
                continue
            condition = str(step.get("if", ""))
            match = re.fullmatch(
                r"matrix\.os == '([^']+)' && matrix\.python-version == '([^']+)'",
                condition.strip(),
            )
            assert match, f"{workflow}::{job_id} codecov step has an unexpected if: {condition!r}"
            assert (match.group(1), match.group(2)) in cells, (
                f"{workflow}::{job_id} uploads coverage only on {match.groups()}, a cell "
                f"its matrix does not run — the upload can never execute"
            )
            # The pytest step must actually write coverage.xml.
            pytest_runs = [
                str(s.get("run", "")) for s in steps if "pytest tests/" in str(s.get("run", ""))
            ]
            assert any(
                "--cov-report=xml" in run for run in pytest_runs
            ), f"{workflow}::{job_id} uploads coverage.xml but no pytest step writes it"
            uploads.append((workflow, job_id))
    assert (
        len(uploads) == 1
    ), f"expected exactly one coverage upload across the pytest lanes: {uploads}"
