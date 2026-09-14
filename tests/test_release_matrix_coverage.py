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
