# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for the Semgrep severity gate (``tools/check_semgrep_severity.py``).

The step this replaces could not fail. The CI job ran::

    semgrep --config .semgrep.yml ama_cryptography/ --json -o semgrep-report.json

``semgrep scan`` exits 0 whether or not it finds anything unless ``--error`` is
passed, and nothing ever read ``semgrep-report.json``. So the merge-blocking
"Semgrep security scan" step was a green light wired to nothing: a file that
trips the config's own ERROR-severity rules — ``insecure-random-usage``,
``weak-hash-algorithm``, ``deprecated-cryptography-api``, ``private-key-logging``,
``unsafe-pickle-usage``, ``bare-memset-zero-secret-named-buffer`` — still exited 0.

Replacing a broken gate with a working one is only worth anything if the new one
demonstrably goes red on bad input, so these are negative controls first:

1. a finding at or above the ERROR floor must fail;
2. WARNING- and INFO-severity findings (the config's constant-time and
   hardcoded-secret advisories) must pass — they are tracked, not merge-blocking;
3. every "the scan did not actually run over the tree" condition must fail closed
   rather than read as a clean tree;
4. the config's declared ERROR rules must be exactly the severities the gate
   blocks on, so the two cannot drift apart silently;
5. the workflow must actually invoke the tool, on the report the scan wrote, with
   nothing swallowing the gate's exit code.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "check_semgrep_severity.py"
SEMGREP_CONFIG = REPO_ROOT / ".semgrep.yml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

#: The step in ci.yml that must run the gate.
GATE_STEP_NAME = "Semgrep security scan"


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_semgrep_severity", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _finding(
    severity: str,
    check_id: str = "insecure-random-usage",
    path: str = "ama_cryptography/example.py",
    line: int = 42,
) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line},
        "end": {"line": line},
        "extra": {
            "severity": severity,
            "message": f"{check_id} matched",
        },
    }


def _report(
    *findings: dict[str, Any],
    errors: list[dict[str, Any]] | None = None,
    scanned: list[str] | None = None,
) -> dict[str, Any]:
    """A Semgrep JSON report carrying exactly ``findings``.

    ``paths.scanned`` defaults to a non-empty list because an empty scan is one
    of the fail-closed conditions, not the happy path — a fixture that left it
    empty would test that branch by accident on every call.
    """
    return {
        "version": "1.74.0",
        "results": list(findings),
        "errors": errors if errors is not None else [],
        "paths": {"scanned": scanned if scanned is not None else ["ama_cryptography/example.py"]},
    }


def _run(tmp_path: Path, tool: ModuleType, report: Any) -> tuple[int, str]:
    """Drive the tool's ``main`` on a written-out report, capturing all output.

    Failures print to stderr and the clean-tree line to stdout, so both are
    redirected into one buffer and returned together.
    """
    path = tmp_path / "semgrep.json"
    path.write_text(report if isinstance(report, str) else json.dumps(report))
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
        rc = tool.main([str(path)])
    return rc, buffer.getvalue()


# ---------------------------------------------------------------------------
# 1. A finding at or above the ERROR floor fails
# ---------------------------------------------------------------------------
def test_error_severity_finding_blocks(tool: ModuleType, tmp_path: Path) -> None:
    rc, out = _run(tmp_path, tool, _report(_finding("ERROR")))
    assert rc == 1, out
    assert "at or above ERROR" in out
    assert "ama_cryptography/example.py:42" in out


def test_error_finding_among_advisories_still_blocks(tool: ModuleType, tmp_path: Path) -> None:
    """One ERROR finding is fatal even when buried under lower-severity noise."""
    report = _report(
        _finding("INFO", "non-constant-time-comparison"),
        _finding("WARNING", "hardcoded-secret-key"),
        _finding("ERROR", "weak-hash-algorithm"),
    )
    rc, out = _run(tmp_path, tool, report)
    assert rc == 1, out
    assert "1 finding(s) at or above ERROR" in out


# ---------------------------------------------------------------------------
# 2. Lower-severity findings pass (tracked, not merge-blocking)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("severity", ["INFO", "WARNING"])
def test_below_the_floor_passes(tool: ModuleType, tmp_path: Path, severity: str) -> None:
    report = _report(
        _finding(severity, "non-constant-time-comparison"),
        _finding(severity, "hardcoded-secret-key"),
    )
    rc, out = _run(tmp_path, tool, report)
    assert rc == 0, out
    # Non-vacuity: the pass names how many advisory findings it looked past, so a
    # pass over an empty report reads differently from a pass over real findings.
    assert "2 lower-severity advisory finding(s)" in out


def test_a_clean_scan_passes(tool: ModuleType, tmp_path: Path) -> None:
    rc, out = _run(tmp_path, tool, _report())
    assert rc == 0, out
    assert "no finding at or above ERROR" in out


# ---------------------------------------------------------------------------
# 3. Fail-closed: a scan that did not run over the tree is not a clean tree
# ---------------------------------------------------------------------------
def test_a_missing_report_fails(tool: ModuleType, tmp_path: Path) -> None:
    rc = tool.main([str(tmp_path / "does-not-exist.json")])
    assert rc == 1


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("not json", "this is not json"),
        ("json but not an object", "[]"),
        ("no results key", '{"paths": {"scanned": ["x.py"]}}'),
    ],
)
def test_a_report_that_is_not_a_semgrep_report_fails(
    tool: ModuleType, tmp_path: Path, label: str, payload: str
) -> None:
    rc, out = _run(tmp_path, tool, payload)
    assert rc == 1, (label, out)
    assert "SEMGREP GATE FAILED" in out


def test_scan_errors_fail_the_gate(tool: ModuleType, tmp_path: Path) -> None:
    """A rule that failed to compile or a file that failed to parse was not
    evaluated, and an unevaluated tree is not a clean tree."""
    report = _report(errors=[{"message": "rule X failed to parse", "type": "PartialParsing"}])
    rc, out = _run(tmp_path, tool, report)
    assert rc == 1, out
    assert "scan error" in out


def test_an_empty_scan_fails(tool: ModuleType, tmp_path: Path) -> None:
    """Zero files scanned means the config or target path pointed at nothing —
    the exact failure a `semgrep && exit 0` step could not distinguish from
    success."""
    rc, out = _run(tmp_path, tool, _report(scanned=[]))
    assert rc == 1, out
    assert "zero files" in out


# ---------------------------------------------------------------------------
# 4. The gate's floor and the config's declared ERROR severities cannot drift
# ---------------------------------------------------------------------------
def _config_error_rule_ids() -> list[str]:
    document = yaml.safe_load(SEMGREP_CONFIG.read_text(encoding="utf-8"))
    return [
        str(rule["id"])
        for rule in document.get("rules", [])
        if str(rule.get("severity", "")).upper() == "ERROR"
    ]


def test_config_declares_at_least_one_error_rule() -> None:
    """If the config had no ERROR rules the parametrised test below would be
    vacuously green — assert the premise it depends on."""
    assert _config_error_rule_ids(), ".semgrep.yml declares no ERROR-severity rule"


@pytest.mark.parametrize("rule_id", _config_error_rule_ids())
def test_each_config_error_rule_is_a_blocking_finding(
    tool: ModuleType, tmp_path: Path, rule_id: str
) -> None:
    """Every rule the config marks ERROR must, when it fires, fail the gate.

    This ties the gate's ERROR floor to the config's declared severities: demote
    a rule to WARNING in .semgrep.yml and this stops asserting it blocks; the
    gate and the config move together or this test goes red.
    """
    rc, out = _run(tmp_path, tool, _report(_finding("ERROR", rule_id)))
    assert rc == 1, (rule_id, out)


# ---------------------------------------------------------------------------
# 5. The gate is wired into CI, on the scan's own report, un-swallowed
# ---------------------------------------------------------------------------
def _gate_step() -> dict[str, Any]:
    document = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    for job in document["jobs"].values():
        for step in job.get("steps", []):
            if step.get("name") == GATE_STEP_NAME:
                return step
    raise AssertionError(f"ci.yml has no step named {GATE_STEP_NAME!r}")


def test_the_workflow_runs_the_gate() -> None:
    run = _gate_step().get("run", "")
    assert "tools/check_semgrep_severity.py" in run, (
        "the Semgrep step no longer runs the severity gate — it is back to a "
        "scan whose exit code cannot fail on a finding"
    )


def test_the_gate_reads_the_report_the_scan_wrote() -> None:
    """The scan must emit JSON to a file and the gate must read that same file;
    a gate pointed at a file the scan never wrote fails closed on every run."""
    run = _gate_step().get("run", "")
    assert "--json -o semgrep-report.json" in run
    assert "check_semgrep_severity.py semgrep-report.json" in run


def test_the_gate_exit_code_is_not_swallowed() -> None:
    """`|| true` / `|| echo` after the gate would discard its verdict, which is
    exactly how the previous step could not fail. `continue-on-error` must also
    be false so a red gate blocks the merge."""
    step = _gate_step()
    assert step.get("continue-on-error", False) is False
    for line in step.get("run", "").splitlines():
        if "check_semgrep_severity.py" in line:
            assert "|| true" not in line and "|| echo" not in line, (
                "the gate's exit code is swallowed; a finding would not fail CI"
            )


# ---------------------------------------------------------------------------
# End to end, on the real tree
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    subprocess.run(
        [sys.executable, "-m", "semgrep", "--version"], capture_output=True, check=False
    ).returncode
    != 0,
    reason="semgrep is not installed",
)
def test_the_real_tree_passes_the_gate(tmp_path: Path) -> None:
    """The shipped package must have no ERROR-severity finding — and the gate
    must be the thing that says so, on a report it generated itself."""
    report = tmp_path / "semgrep.json"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "semgrep",
            "--config",
            str(SEMGREP_CONFIG),
            "ama_cryptography/",
            "--json",
            "-o",
            str(report),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
    )
    done = subprocess.run(
        [sys.executable, str(TOOL_PATH), str(report)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    # Non-vacuity: a gate that passed on an empty report would also print zero
    # blocking findings.
    assert "scanned" in done.stdout
    assert json.loads(report.read_text())["paths"]["scanned"]
