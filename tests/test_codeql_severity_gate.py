# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""``tools/check_codeql_severity.py`` — the gate over CodeQL's SARIF output.

The gate had no tests.  It blocked on ``result.level == "error"`` only, and
CodeQL's security queries mostly carry ``warning`` with the CVSS-style rating in
the rule's ``properties.security-severity`` — so a warning-level result rated
9.8 passed (measured with the crafted report below).  Results at or above
:data:`SECURITY_SEVERITY_FLOOR` now block at any level.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools import check_codeql_severity as gate


def _sarif(*results: tuple[str, str | None, str | None]) -> dict[str, Any]:
    """A one-run SARIF with one rule per result: (rule id, level, security-severity)."""
    rules = []
    rows = []
    for index, (rule_id, level, rating) in enumerate(results):
        rule: dict[str, Any] = {"id": rule_id}
        if level is not None:
            rule["defaultConfiguration"] = {"level": level}
        if rating is not None:
            rule["properties"] = {"security-severity": rating}
        rules.append(rule)
        rows.append(
            {
                "ruleId": rule_id,
                "message": {"text": f"finding {index}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/c/x.c"},
                            "region": {"startLine": index + 1},
                        }
                    }
                ],
            }
        )
    return {"runs": [{"tool": {"driver": {"name": "CodeQL", "rules": rules}}, "results": rows}]}


def _write(tmp_path: Path, sarif: dict[str, Any]) -> Path:
    path = tmp_path / "r.sarif"
    path.write_text(json.dumps(sarif), encoding="utf-8")
    return path


def test_a_warning_rated_high_blocks(tmp_path: Path) -> None:
    """The measured hole: cpp/weak-cryptographic-algorithm at warning, 9.8."""
    report = _write(tmp_path, _sarif(("cpp/weak-cryptographic-algorithm", "warning", "9.8")))
    failures, blocking, total = gate.audit([report])
    assert (blocking, total) == (1, 1)
    assert "security-severity 9.8" in failures[0]
    assert gate.main([str(report)]) == 1


def test_a_warning_rated_below_the_floor_does_not_block(tmp_path: Path) -> None:
    report = _write(tmp_path, _sarif(("cpp/some-quality-rule", "warning", "6.9")))
    failures, blocking, total = gate.audit([report])
    assert (failures, blocking, total) == ([], 0, 1)
    assert gate.main([str(report)]) == 0


def test_the_floor_itself_blocks(tmp_path: Path) -> None:
    report = _write(tmp_path, _sarif(("py/x", "note", str(gate.SECURITY_SEVERITY_FLOOR))))
    assert gate.audit([report])[1] == 1


def test_an_error_level_result_blocks_without_a_rating(tmp_path: Path) -> None:
    report = _write(tmp_path, _sarif(("cpp/use-after-free", "error", None)))
    assert gate.audit([report])[1] == 1


def test_an_unrated_warning_does_not_block(tmp_path: Path) -> None:
    report = _write(tmp_path, _sarif(("cpp/style", "warning", None)))
    assert gate.audit([report]) == ([], 0, 1)


def test_a_rating_on_an_extension_rule_is_honoured(tmp_path: Path) -> None:
    """CodeQL packs can publish rules under tool.extensions, not the driver."""
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {"name": "CodeQL", "rules": []},
                    "extensions": [
                        {
                            "name": "codeql/cpp-queries",
                            "rules": [
                                {
                                    "id": "cpp/ext-rule",
                                    "defaultConfiguration": {"level": "warning"},
                                    "properties": {"security-severity": "8.1"},
                                }
                            ],
                        }
                    ],
                },
                "results": [{"ruleId": "cpp/ext-rule", "message": {"text": "m"}}],
            }
        ]
    }
    assert gate.audit([_write(tmp_path, sarif)])[1] == 1


def test_a_non_numeric_rating_is_ignored_not_fatal(tmp_path: Path) -> None:
    report = _write(tmp_path, _sarif(("cpp/odd", "warning", "n/a")))
    assert gate.audit([report]) == ([], 0, 1)


def test_a_missing_report_fails(tmp_path: Path) -> None:
    failures, blocking, total = gate.audit([tmp_path / "absent.sarif"])
    assert failures and blocking == 0 and total == 0


def test_a_directory_with_no_sarif_fails(tmp_path: Path) -> None:
    assert gate.main([str(tmp_path)]) == 1


@pytest.mark.parametrize("level", ["error", "warning"])
def test_result_level_overrides_the_rule_default(tmp_path: Path, level: str) -> None:
    sarif = _sarif(("cpp/r", "note", None))
    sarif["runs"][0]["results"][0]["level"] = level
    blocking = gate.audit([_write(tmp_path, sarif)])[1]
    assert blocking == (1 if level == "error" else 0)


def test_the_static_analysis_workflow_invokes_the_gate() -> None:
    workflow = (
        Path(__file__).resolve().parent.parent / ".github" / "workflows" / "static-analysis.yml"
    ).read_text(encoding="utf-8")
    assert "tools/check_codeql_severity.py" in workflow


def test_a_non_blocking_result_is_printed_not_only_counted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The log is where a reviewer without ``security-events: read`` sees the
    findings; a count alone ("1 result(s)") names nothing to review."""
    report = _write(tmp_path, _sarif(("py/unused-import", "note", None)))
    assert gate.main([str(report)]) == 0
    out = capsys.readouterr().out
    assert "1 non-blocking result(s):" in out
    assert "src/c/x.c:1: [note] py/unused-import: finding 0" in out


def test_a_blocking_result_is_not_listed_twice(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _write(tmp_path, _sarif(("cpp/r", "error", None)))
    assert gate.main([str(report)]) == 1
    captured = capsys.readouterr()
    assert "non-blocking" not in captured.out
    assert "cpp/r" in captured.err


def test_the_upload_keeps_mains_code_scanning_category() -> None:
    """Without the pinned category the PR's analysis files under a different
    configuration from main's, and code scanning cannot compute the alerts the
    PR introduces (measured at dfd35dcb: "1 configuration not found:
    /language:c-cpp")."""
    import yaml

    workflow = yaml.safe_load(
        (
            Path(__file__).resolve().parent.parent / ".github" / "workflows" / "static-analysis.yml"
        ).read_text(encoding="utf-8")
    )
    analyze = [
        step
        for step in workflow["jobs"]["codeql"]["steps"]
        if str(step.get("uses", "")).startswith("github/codeql-action/analyze@")
    ]
    assert len(analyze) == 1
    assert analyze[0]["with"]["category"] == "/language:c-cpp"
