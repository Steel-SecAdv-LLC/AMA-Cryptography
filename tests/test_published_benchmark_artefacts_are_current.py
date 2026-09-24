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
  so it cannot cite a commit from a branch that was rewritten away; and
* every other field the runner copies out of the ledger into a row -- its
  ``description`` and ``tolerance_percent`` -- must equal the ledger's today,
  for the same reason as the floor.  The description check was missing, and
  the record run at 4e4fa7f went on labelling the ``ed25519_sign`` row "native
  C, expanded key" after c126037 rewrote the ledger to say what the row
  measures -- INVARIANT-51's per-call derivation, beside the separate
  ``ed25519_sign_expanded`` row that IS the once-at-load form.  The dashboard
  republishes that field.

What is deliberately NOT checked is the measured throughput: it is a
measurement on whatever host produced it, and asserting it here would only
re-measure the host.  The provenance block records that host.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
from typing import Any, cast

import pytest

import benchmarks.benchmark_runner as br

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


def _ledger_rows() -> dict[str, dict[str, Any]]:
    """Each ledger row as the runner copies it into a result.

    ``run_all_benchmarks`` takes ``description`` verbatim and
    ``tolerance_percent`` with ``thresholds.regression_threshold_percent`` as
    the default, so that is what a current row must carry.
    """
    doc = json.loads(BASELINE.read_text(encoding="utf-8"))
    default_tolerance = doc["thresholds"]["regression_threshold_percent"]
    rows: dict[str, dict[str, Any]] = {}
    for section in ("benchmarks", "pqc_benchmarks"):
        for name, entry in doc.get(section, {}).items():
            if isinstance(entry, dict):
                rows[name] = {
                    "description": entry["description"],
                    "tolerance_percent": entry.get("tolerance_percent", default_tolerance),
                }
    return rows


def _cells(row: str) -> list[str]:
    """A markdown table row's cells, split where GFM splits them."""
    return [c.strip() for c in re.split(r"(?<!\\)\|", row.strip())[1:-1]]


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
    published = {row["name"] for row in cast("list[dict[str, Any]]", results["results"])}
    # A rename on either side would leave the loop below comparing nothing.
    assert len(published & set(floors)) >= 15, sorted(published ^ set(floors))
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


@pytest.mark.requires_git_history
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


def _report_results_rows(text: str) -> dict[str, list[str]]:
    """The Results table of benchmark-report.md, keyed by its Primitive cell.

    The generator writes ``| description | ops | baseline | regression |
    tolerance | status |`` with ``|`` inside a description escaped, so the
    rows are split the way GFM splits them and the escapes undone.
    """
    rows: dict[str, list[str]] = {}
    in_results = False
    for line in text.splitlines():
        if line.startswith("## "):
            in_results = line.strip() == "## Results"
            continue
        if not in_results or not line.startswith("|"):
            continue
        cells = [c.replace("\\|", "|") for c in _cells(line)]
        if len(cells) != 6 or cells[0] == "Primitive" or set(cells[1]) <= {"-", ":"}:
            continue
        rows[cells[0]] = cells[1:]
    return rows


def test_the_report_and_the_json_agree_on_every_floor() -> None:
    """The markdown is generated; a hand-edited row is caught here.

    Every JSON result must have a Results-table row, joined on its
    description, whose Ops/sec, Baseline, Regression and Tolerance cells are
    the values the generator renders from the JSON.  The first revision only
    asked whether each snake_case NAME occurred anywhere in the report -- and
    every one did, in the ASCII throughput chart -- so an edited Baseline
    cell, or a deleted Results table, passed.
    """
    report = REPO_ROOT / "benchmark-report.md"
    if not report.is_file():
        pytest.skip("benchmark-report.md is not committed")
    rows = _report_results_rows(report.read_text(encoding="utf-8"))
    doc = json.loads(RESULTS.read_text(encoding="utf-8"))
    assert len(rows) >= 15, f"the Results table has {len(rows)} rows"
    drift: list[str] = []
    for result in doc["results"]:
        cells = rows.get(result["description"])
        if cells is None:
            drift.append(f"{result['name']}: no Results row")
            continue
        expected = [
            f"{result['ops_per_second']:,.0f}",
            f"{result['baseline_value']:,.0f}",
            f"{result['regression_percent']:+.1f}%",
            f"{result['tolerance_percent']:.0f}%",
        ]
        if cells[:4] != expected:
            drift.append(f"{result['name']}: report {cells[:4]} vs JSON {expected}")
    assert drift == [], "benchmark-report.md disagrees with the JSON:\n  " + "\n  ".join(drift)


def test_every_published_row_carries_the_ledgers_description_and_tolerance(
    results: dict[str, Any],
) -> None:
    ledger = _ledger_rows()
    compared = 0
    drift = []
    for row in cast("list[dict[str, Any]]", results["results"]):
        expected = ledger.get(row["name"])
        if expected is None:
            continue
        compared += 1
        for field, value in expected.items():
            if row[field] != value:
                drift.append(f"{row['name']}.{field}: report {row[field]!r} vs baseline {value!r}")
    assert compared >= 15, f"non-vacuity: only {compared} rows matched a ledger entry"
    assert drift == [], (
        "the committed benchmark snapshot describes rows in words the baseline "
        "ledger no longer uses. The runner copies these fields from the ledger; "
        "regenerate the snapshot rather than editing either side:\n"
        + "\n".join(f"    {d}" for d in drift)
    )


def test_every_results_row_of_the_report_has_six_cells() -> None:
    """A description containing ``|`` must not split its row.

    ``ed25519_sign``'s ledger description names the key layout ``seed || A``;
    rendered unescaped, GFM split that row into eight cells, moved the
    description's tail into the Ops/sec and Baseline columns and dropped the
    Tolerance and Status cells.
    """
    text = (REPO_ROOT / "benchmark-report.md").read_text(encoding="utf-8")
    table = text.split("## Results", 1)[1].split("\n## ", 1)[0]
    rows = [line for line in table.splitlines() if line.startswith("| ")]
    header, body = rows[0], rows[1:]
    assert _cells(header)[0] == "Primitive" and len(_cells(header)) == 6, header
    assert len(body) >= 15, "non-vacuity: the Results table lost its rows"
    wrong = [f"{len(_cells(line))} cells: {line[:90]}" for line in body if len(_cells(line)) != 6]
    assert wrong == [], wrong


def test_the_generator_escapes_a_bar_inside_a_cell() -> None:
    """The generator, not only today's artefact: any future description."""
    row = br.BenchmarkResult(
        name="bar_row",
        description="key = seed || A | tail",
        ops_per_second=100.0,
        baseline_value=90.0,
        tolerance_percent=45.0,
        regression_percent=-11.1,
        passed=True,
    )
    report = {"timestamp": "t", "summary": {"passed": 1, "total": 1, "failed": 0, "warnings": 0}}
    md = br.generate_markdown_report([row], report)
    line = next(line for line in md.splitlines() if line.startswith("| key = seed"))
    assert _cells(line) == [
        "key = seed \\|\\| A \\| tail",
        "100",
        "90",
        "-11.1%",
        "45%",
        "PASS",
    ], line
