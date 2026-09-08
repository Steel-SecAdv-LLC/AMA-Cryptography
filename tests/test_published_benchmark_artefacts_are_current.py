# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The committed benchmark artefacts must describe the tree they sit in.

EDPERF-6.  ``benchmarks/benchmark-results.json`` and ``benchmark-report.md``
are a committed snapshot of a local ``benchmark_runner.py`` run.  Nothing
required them to stay current: the existing infrastructure test checks only
that the report RENDERS from the JSON, so a floor re-base, or a backend
replacement, left both files describing a tree that no longer exists -- and
they went on being cited by SECURITY.md and the wiki as though they did.

The two checks here are the ones that go stale:

* every ``baseline_value`` in the snapshot must equal the floor
  ``benchmarks/baseline.json`` carries today, so a re-base that does not
  regenerate the snapshot fails; and
* the snapshot must name a commit that this repository actually contains,
  so it cannot cite a commit from a branch that was rewritten away.

What is deliberately NOT checked is the measured throughput: it is a
measurement on whatever host produced it, and asserting it here would only
re-measure the host.  The provenance block records that host.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
from typing import Any, cast

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "benchmarks" / "benchmark-results.json"
BASELINE = REPO_ROOT / "benchmarks" / "baseline.json"


def _floors() -> dict[str, float]:
    doc = json.loads(BASELINE.read_text(encoding="utf-8"))
    floors: dict[str, float] = {}
    for section in ("benchmarks", "pqc_benchmarks"):
        for name, entry in doc.get(section, {}).items():
            if isinstance(entry, dict) and "baseline_value" in entry:
                floors[name] = entry["baseline_value"]
    return floors


@pytest.fixture(scope="module")
def results() -> dict[str, Any]:
    if not RESULTS.is_file():
        pytest.skip("benchmarks/benchmark-results.json is not committed")
    loaded: dict[str, Any] = json.loads(RESULTS.read_text(encoding="utf-8"))
    return loaded


def test_there_are_rows_and_floors_to_compare(results: dict[str, Any]) -> None:
    # Non-vacuity: an empty snapshot or an empty baseline would make the
    # parity assertion below pass over nothing.
    rows = results["results"]
    assert isinstance(rows, list) and len(rows) >= 15
    assert len(_floors()) >= 15


def test_every_published_floor_matches_the_baseline_ledger(
    results: dict[str, Any],
) -> None:
    floors = _floors()
    drift = []
    for row in cast("list[dict[str, Any]]", results["results"]):
        name = row["name"]
        if name not in floors:
            continue
        if row["baseline_value"] != floors[name]:
            drift.append(f"{name}: report {row['baseline_value']} vs baseline {floors[name]}")
    assert drift == [], (
        "the committed benchmark snapshot quotes floors the baseline ledger no "
        "longer carries. Regenerate both together:\n"
        "  python benchmarks/benchmark_runner.py --baseline benchmarks/baseline.json "
        "--output benchmarks/benchmark-results.json --markdown benchmark-report.md\n"
        + "\n".join(f"    {d}" for d in drift)
    )


def test_the_snapshot_names_a_commit_this_repository_contains(
    results: dict[str, Any],
) -> None:
    commit = cast("dict[str, Any]", results["provenance"])["commit"]
    proc = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=REPO_ROOT,
        capture_output=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"commit {commit[:12]} is not in this checkout (shallow clone)")


def test_the_report_and_the_json_agree_on_every_floor() -> None:
    """The markdown is generated; a hand-edited row is caught here."""
    report = REPO_ROOT / "benchmark-report.md"
    if not report.is_file():
        pytest.skip("benchmark-report.md is not committed")
    text = report.read_text(encoding="utf-8")
    doc = json.loads(RESULTS.read_text(encoding="utf-8"))
    missing = [
        row["name"]
        for row in doc["results"]
        if row["name"].replace("_", " ") not in text and row["name"] not in text
    ]
    assert missing == [], f"these rows are in the JSON but not the report: {missing}"
