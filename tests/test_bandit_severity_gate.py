# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for the Bandit severity gate (``tools/check_bandit_severity.py``).

The gate this replaces could not pass. It grepped Bandit's text report for
``^\\s*(Medium|High):\\s*[1-9]``, and that report prints two tallies under the
same labels — one by severity, one by confidence, both indented::

    Total issues (by severity):     Total issues (by confidence):
        Medium: 0                       Medium: 6

So the pattern matched the *confidence* block and turned the job red on a tree
whose Medium+ severity count was zero. The gate was not too permissive; it was
unreadable, and an unreadable red gate is one people learn to ignore.

Replacing a broken gate with a working one is only worth anything if the new one
demonstrably goes red on bad input, so these are negative controls first:

1. the exact shape that broke the old gate — Low severity, Medium confidence —
   must pass;
2. a Medium-severity, Medium-confidence finding must fail;
3. the confidence floor must be real (Medium severity, Low confidence passes)
   *and* visible (it is printed, not silently dropped);
4. every "the report cannot be trusted" condition must fail closed rather than
   read as a clean tree;
5. both workflows must actually invoke the tool, and neither may still carry the
   grep that could not work.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "check_bandit_severity.py"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

#: The workflows that must run the gate. Both previously carried the same
#: broken grep; a fix applied to only one of them would leave the other red.
GATED_WORKFLOWS = ("security.yml", "ci-build-test.yml")


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_bandit_severity", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _finding(severity: str, confidence: str, test_id: str = "B105") -> dict[str, Any]:
    return {
        "filename": "ama_cryptography/example.py",
        "line_number": 42,
        "issue_severity": severity,
        "issue_confidence": confidence,
        "issue_text": "Possible hardcoded password: '1632'",
        "test_id": test_id,
        "test_name": "hardcoded_password_string",
    }


def _report(*findings: dict[str, Any], loc: int = 20000) -> dict[str, Any]:
    """A Bandit JSON report carrying exactly ``findings``.

    ``metrics._totals`` is derived from the findings rather than written by
    hand, because the gate cross-checks the two and a hand-written total would
    make every fixture a test of the cross-check instead of what it is for.
    """
    totals: dict[str, Any] = {f"SEVERITY.{r}": 0 for r in ("UNDEFINED", "LOW", "MEDIUM", "HIGH")}
    totals.update({f"CONFIDENCE.{r}": 0 for r in ("UNDEFINED", "LOW", "MEDIUM", "HIGH")})
    totals["loc"] = loc
    for f in findings:
        # `.get(..., 0) + 1` rather than `+=`: one fixture deliberately
        # carries a rank Bandit never emits, and the tally has to survive
        # long enough for the tool to be the thing that rejects it.
        for prefix, rank in (
            ("SEVERITY", f["issue_severity"]),
            ("CONFIDENCE", f["issue_confidence"]),
        ):
            totals[f"{prefix}.{rank}"] = totals.get(f"{prefix}.{rank}", 0) + 1
    return {
        "errors": [],
        "generated_at": "",
        "metrics": {"_totals": totals},
        "results": list(findings),
    }


def _run(tmp_path: Path, report: Any) -> tuple[int, str]:
    """Drive the tool's ``main`` on a written-out report."""
    path = tmp_path / "bandit.json"
    path.write_text(json.dumps(report) if not isinstance(report, str) else report)
    import contextlib
    import io

    module = sys.modules["check_bandit_severity"]
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        rc = module.main([str(path)])
    return rc, buffer.getvalue()


# ---------------------------------------------------------------------------
# 1. The exact shape that broke the old gate
# ---------------------------------------------------------------------------
def test_low_severity_medium_confidence_passes(tool: ModuleType, tmp_path: Path) -> None:
    """This is this repository's real state, and it is what the old grep hit.

    Seven Low-severity findings, six of them Medium-confidence: the by-severity
    tally read ``Medium: 0`` while the by-confidence tally read ``Medium: 6``,
    and the regex matched the second one.
    """
    report = _report(*[_finding("LOW", "MEDIUM") for _ in range(6)], _finding("LOW", "HIGH"))
    rc, out = _run(tmp_path, report)
    assert rc == 0, out
    assert "No blocking findings" in out


# ---------------------------------------------------------------------------
# 2/3. The thresholds are real, and what they exclude is still visible
# ---------------------------------------------------------------------------
def test_medium_severity_medium_confidence_blocks(tool: ModuleType, tmp_path: Path) -> None:
    rc, out = _run(tmp_path, _report(_finding("MEDIUM", "MEDIUM")))
    assert rc == 1, out
    assert "1 blocking finding" in out
    assert "ama_cryptography/example.py:42" in out


@pytest.mark.parametrize("severity", ["MEDIUM", "HIGH"])
@pytest.mark.parametrize("confidence", ["MEDIUM", "HIGH"])
def test_every_combination_at_or_above_both_floors_blocks(
    tool: ModuleType, tmp_path: Path, severity: str, confidence: str
) -> None:
    rc, _ = _run(tmp_path, _report(_finding(severity, confidence)))
    assert rc == 1, (severity, confidence)


@pytest.mark.parametrize("confidence", ["UNDEFINED", "LOW"])
def test_below_the_confidence_floor_does_not_block_but_is_printed(
    tool: ModuleType, tmp_path: Path, confidence: str
) -> None:
    """A Medium-severity finding the policy does not block is still reported.

    Dropping it silently is how a threshold becomes a blind spot: nobody sees
    the finding, so nobody decides whether the threshold is still right.
    """
    rc, out = _run(tmp_path, _report(_finding("MEDIUM", confidence)))
    assert rc == 0, out
    assert "below the confidence floor" in out
    assert "ama_cryptography/example.py:42" in out


@pytest.mark.parametrize("severity", ["UNDEFINED", "LOW"])
def test_below_the_severity_floor_is_not_reported_at_all(
    tool: ModuleType, tmp_path: Path, severity: str
) -> None:
    rc, out = _run(tmp_path, _report(_finding(severity, "HIGH")))
    assert rc == 0, out
    assert "below the confidence floor" not in out


# ---------------------------------------------------------------------------
# 4. Fail-closed: an unusable report is a failure, never a clean tree
# ---------------------------------------------------------------------------
def test_a_missing_report_fails(tool: ModuleType, tmp_path: Path) -> None:
    rc = tool.main([str(tmp_path / "does-not-exist.json")])
    assert rc == 1


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("not json", "this is not json"),
        ("json but not an object", "[]"),
        ("no results list", '{"metrics": {"_totals": {"loc": 1}}}'),
        ("no metrics", '{"results": []}'),
        ("no _totals", '{"results": [], "metrics": {}}'),
    ],
)
def test_a_report_that_is_not_a_bandit_report_fails(
    tool: ModuleType, tmp_path: Path, label: str, payload: str
) -> None:
    rc, out = _run(tmp_path, payload)
    assert rc == 1, (label, out)
    assert "cannot verify this tree" in out


def test_scan_errors_fail_the_gate(tool: ModuleType, tmp_path: Path) -> None:
    """A file Bandit could not parse was not examined, and an unexamined file
    is not a clean file."""
    report = _report()
    report["errors"] = [{"filename": "ama_cryptography/broken.py", "reason": "syntax error"}]
    rc, out = _run(tmp_path, report)
    assert rc == 1 and "scan error" in out


def test_an_empty_scan_fails(tool: ModuleType, tmp_path: Path) -> None:
    """Zero findings over zero lines of code means the scan pointed at nothing.

    This is the failure mode a `grep`-based gate cannot distinguish from
    success, and the one a misconfigured path produces.
    """
    rc, out = _run(tmp_path, _report(loc=0))
    assert rc == 1 and "nothing was scanned" in out


def test_a_pre_filtered_report_fails(tool: ModuleType, tmp_path: Path) -> None:
    """``--severity-level medium`` prunes ``results`` but not ``metrics._totals``.

    Handed such a report the gate cannot tell what was dropped, so it refuses
    to certify the tree rather than reporting the findings it can still see.
    """
    report = _report(_finding("MEDIUM", "MEDIUM"))
    report["results"] = []  # what --confidence-level would have pruned
    rc, out = _run(tmp_path, report)
    assert rc == 1 and "pre-filtered" in out


def test_an_unrecognised_severity_fails(tool: ModuleType, tmp_path: Path) -> None:
    rc, out = _run(tmp_path, _report(_finding("CATASTROPHIC", "HIGH")))
    assert rc == 1 and "unrecognised" in out


# ---------------------------------------------------------------------------
# 5. The gate is actually wired up, and the broken grep is gone
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("workflow", GATED_WORKFLOWS)
def test_the_workflow_runs_the_gate(workflow: str) -> None:
    text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    assert (
        "tools/check_bandit_severity.py" in text
    ), f"{workflow} no longer runs the Bandit severity gate"


def _bandit_commands(workflow: str) -> list[str]:
    """Every line in ``workflow`` that *invokes* bandit.

    Parsed out of the YAML and matched line by line rather than grepped from
    the file text. The surrounding comments explain why the filters are absent
    and `pip install bandit` merely names it; neither is an invocation, and a
    substring search over the whole file cannot tell the three apart.
    """
    document = yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))
    commands = []
    for job in document["jobs"].values():
        for step in job.get("steps", []):
            run = step.get("run", "")
            if not isinstance(run, str):
                continue
            commands += [
                line.strip() for line in run.splitlines() if line.strip().startswith("bandit ")
            ]
    return commands


@pytest.mark.parametrize("workflow", GATED_WORKFLOWS)
def test_the_workflow_generates_an_unfiltered_report(workflow: str) -> None:
    """The cross-check that proves nothing was pruned only works on an
    unfiltered report, so the scan must not carry Bandit's own filters."""
    commands = _bandit_commands(workflow)
    assert commands, f"{workflow} no longer invokes bandit at all"
    for command in commands:
        for flag in ("--severity-level", "--confidence-level"):
            assert flag not in command, (
                f"{workflow} passes {flag} to bandit, which prunes 'results' but not "
                "'metrics._totals' — the gate's cross-check then fails closed"
            )
        assert "-f json" in command, (
            f"{workflow} runs bandit without JSON output; the gate reads JSON "
            "because the text report's severity and confidence tallies share "
            "their labels"
        )


def test_no_workflow_still_greps_the_text_report() -> None:
    """The regex that matched the confidence tally must not come back."""
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        assert "bandit-medium-plus.txt" not in text, (
            f"{path.name} still parses Bandit's text report; the by-severity and "
            "by-confidence tallies share their labels there"
        )


# ---------------------------------------------------------------------------
# End to end, on the real tree
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    subprocess.run(
        [sys.executable, "-m", "bandit", "--version"], capture_output=True, check=False
    ).returncode
    != 0,
    reason="bandit is not installed",
)
def test_the_real_tree_passes_the_gate(tmp_path: Path) -> None:
    """The shipped package must have no Medium+ finding — and the gate must be
    the thing that says so, on a report it generated itself."""
    report = tmp_path / "bandit.json"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            "ama_cryptography/",
            "--exit-zero",
            "-f",
            "json",
            "-o",
            str(report),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
    )
    done = subprocess.run(
        [sys.executable, str(TOOL_PATH), str(report)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    # Non-vacuity: a gate that passed because it read an empty report would
    # also print zero blocking findings.
    assert "lines of code" in done.stdout
    assert json.loads(report.read_text())["metrics"]["_totals"]["loc"] > 1000
