# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A primitive maps to a NON-DEPRECATED registry entry, so the Status column is read.

INVARIANT-1's Algorithm Registry addendum says every primitive "must map to a
non-deprecated entry in CSRC_STANDARDS.md". ``tools/check_algorithm_registry.py``
checked that a mapping token appeared in some row and never read the Status
column, so a row marked "Withdrawn" satisfied a mapping exactly as a "Final"
one did.

The synthetic trees reuse the header and token lists of
``tests/test_algorithm_registry_gate.py`` and add a Status column. Each
negative control was mutation-checked: with the mechanism it names removed from
the gate, it fails.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

from tests import test_algorithm_registry_gate as base

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_algorithm_registry.py"


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_algorithm_registry_status", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _registry(status: dict[str, str] | None = None, extra: str = "") -> str:
    """Every token in its own row with a Status column; ``status`` overrides per token."""
    overrides = status or {}
    rule = base.TestTheRule
    lines = ["| Algorithm | Standard | Status |", "|---|---|---|"]
    for token in rule.PARAM_TOKENS:
        lines.append(f"| {token} (alias) | filler | {overrides.get(token, 'Final')} |")
    for token in rule.FAMILY_TOKENS:
        if token in rule.PARAM_TOKENS:
            continue
        lines.append(f"| row | {token} | {overrides.get(token, 'Final')} |")
    for index in range(len(lines) - 2, 45):
        lines.append(f"| filler-{index} | filler-{index} | Final |")
    return "\n".join(lines) + "\n" + extra


def _audit(gate: ModuleType, tmp_path: Path, registry: str) -> list[str]:
    root = base._tree(tmp_path, base.TestTheRule.HEADER, registry)
    return list(gate.audit(root))


class TestTheStatusColumn:
    def test_an_all_final_registry_passes(self, gate: ModuleType, tmp_path: Path) -> None:
        assert _audit(gate, tmp_path, _registry()) == []

    def test_a_withdrawn_only_row_does_not_satisfy_its_mapping(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        problems = _audit(gate, tmp_path, _registry({"ML-DSA-44": "Withdrawn"}))
        assert any(
            "no current row's Algorithm column names 'ML-DSA-44'" in problem for problem in problems
        ), problems

    def test_a_withdrawn_family_row_does_not_satisfy_its_mapping(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        problems = _audit(gate, tmp_path, _registry({"NIST SP 800-208": "Withdrawn"}))
        assert any(
            "no current row mentions 'NIST SP 800-208'" in problem for problem in problems
        ), problems

    def test_a_deprecated_row_fails_even_when_another_row_covers_the_token(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """The registry lists shipping code only; a deprecated row is itself a defect."""
        extra_row = "| SHA-1 | FIPS 202 | Deprecated |\n"
        problems = _audit(gate, tmp_path, _registry(extra=extra_row))
        assert len(problems) == 1 and "'SHA-1' is not a current entry" in problems[0], problems

    @pytest.mark.parametrize(
        "status", ["Draft", "Superseded", "Final (deprecated after 2030)", "Disallowed", ""]
    )
    def test_anything_but_an_approved_status_fails(
        self, gate: ModuleType, tmp_path: Path, status: str
    ) -> None:
        """An allow-set: "Draft" contains no bad word and still is not current."""
        problems = _audit(gate, tmp_path, _registry({"HMAC-SHA-384": status}))
        assert any(
            "'HMAC-SHA-384 (alias)' is not a current entry" in problem for problem in problems
        ), problems

    def test_the_status_column_is_found_by_its_header(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        reordered = _registry(
            extra=(
                "\n| Algorithm | Status | Standard |\n|---|---|---|\n"
                "| SHA-1 | Withdrawn | FIPS 180 |\n"
            )
        )
        problems = _audit(gate, tmp_path, reordered)
        assert len(problems) == 1 and "'SHA-1'" in problems[0], problems


class TestATableWithoutAStatusColumn:
    """The RFC table has no Status column; its rows are still held to the rule."""

    def test_a_row_describing_itself_as_deprecated_fails(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        rfc_table = (
            "\n| Algorithm | RFC | Notes |\n|---|---|---|\n"
            "| Old-KDF | RFC 0000 | Deprecated by RFC 9999 |\n"
        )
        problems = _audit(gate, tmp_path, _registry(extra=rfc_table))
        assert len(problems) == 1 and "'Old-KDF'" in problems[0], problems

    def test_a_row_that_does_not_is_current(self, gate: ModuleType, tmp_path: Path) -> None:
        rfc_table = (
            "\n| Algorithm | RFC | Notes |\n|---|---|---|\n"
            "| New-KDF | RFC 9999 | IETF construction |\n"
        )
        assert _audit(gate, tmp_path, _registry(extra=rfc_table)) == []


class TestTheShippedRegistry:
    def test_every_nist_row_has_a_parsed_approved_status(self, gate: ModuleType) -> None:
        """Non-vacuity on the real document: the Status column is actually read."""
        entries = gate.registry_entries(REPO_ROOT / gate.REGISTRY)
        with_status = [entry for entry in entries if entry.status is not None]
        assert len(with_status) >= 28, len(with_status)
        assert {entry.status for entry in with_status} <= set(gate.APPROVED_STATUSES)
        assert all(entry.not_current() is None for entry in entries)
