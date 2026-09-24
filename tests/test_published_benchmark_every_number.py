# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Every number in README's published-bench region is pinned, not only unit-tagged ones.

The gate's first version read a figure only when a recognised unit (ops/sec,
micro-seconds, the multiplication sign, %, KB) immediately followed it. That
left every figure whose unit was not adjacent — and the whole of the CI
four-run table, whose cells are "363,574 (362,192–484,921)" under a column
header that carries the unit — free to change. Now every number token is
pinned against ``benchmarks/published-benchmarks.json`` unless its digits are
part of a name (``ML-DSA-65``, ``Ed25519``, ``64-byte``).

Each negative control edits one number of a copy of the real README, and each
was mutation-checked: with the mechanism it names removed from the gate, it
fails.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import check_published_benchmarks as gate

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    record = json.loads((REPO_ROOT / gate.RECORD).read_text(encoding="utf-8"))
    for relative in [*record["documents"], gate.RECORD]:
        (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / relative).write_text(
            (REPO_ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8"
        )
    return tmp_path


def _edit(tree: Path, old: str, new: str) -> None:
    readme = tree / gate.README
    text = readme.read_text(encoding="utf-8")
    region = gate.extract_region(text)
    assert region is not None and region.count(old) == 1, old
    readme.write_text(text.replace(old, new, 1), encoding="utf-8")


def _run(tree: Path) -> int:
    return gate.main(["--repo", str(tree)])


class TestNumbersWithoutAnAdjacentUnit:
    @pytest.mark.parametrize(
        ("old", "new"),
        [
            # A median, a range bound on the other architecture, a job id.
            ("| 18,984 (18,894–24,705) |", "| 19,984 (18,894–24,705) |"),
            ("| 25,400 (25,394–25,410) |", "| 25,400 (25,394–29,410) |"),
            ("x86_64 jobs 106170292775,", "x86_64 jobs 106170292776,"),
            # A date, a superseded median quoted in prose, a derivation input.
            ("2026-09-20 to 2026-09-21", "2026-09-20 to 2026-09-24"),
            ("(Ed25519 70,496 / 58,762 sign", "(Ed25519 70,496 / 68,762 sign"),
            ("70,496 / 1.8469 = 38,170", "70,496 / 1.7469 = 38,170"),
            # A source constant with no unit at all.
            ("across 4096 random vectors", "across 8192 random vectors"),
        ],
    )
    def test_an_edited_figure_fails(self, tree: Path, old: str, new: str) -> None:
        assert _run(tree) == 0
        _edit(tree, old, new)
        assert _run(tree) == 1

    def test_a_figure_added_in_an_unlisted_unit_fails(self, tree: Path) -> None:
        _edit(tree, "across 4096 random vectors", "across 4096 random vectors in 3 ms")
        assert _run(tree) == 1

    def test_deleting_one_of_two_identical_figures_fails(self, tree: Path) -> None:
        """The comb sentence's "256 doublings + 256 additions" is two figures, one key."""
        _edit(tree, "256 doublings + 256 additions", "256 doublings + additions")
        assert _run(tree) == 1


class TestWhatIsAndIsNotAFigure:
    def test_units_beyond_the_original_five_are_recorded(self) -> None:
        found = gate.extract_measurements("| **X** | 5 ms | 7 ns | 12.5 MB/s |\n")
        assert [(entry["value"], entry["unit"]) for entry in found] == [
            ("5", "ms"),
            ("7", "ns"),
            ("12.5", "MB/s"),
        ]

    def test_digits_inside_a_name_are_not_figures(self) -> None:
        text = "ML-DSA-65 on x86-64 with a 64-byte Ed25519 key and radix-2^51\n"
        assert gate.extract_measurements(text) == []

    def test_a_standalone_number_is_a_figure_without_a_unit(self) -> None:
        found = gate.extract_measurements("FIPS 204, q=8380417, 2026-04-25\n")
        assert [(entry["value"], entry["unit"]) for entry in found] == [
            ("204", ""),
            ("8380417", ""),
            ("2026-04-25", ""),
        ]

    def test_a_table_cell_median_and_range_are_three_figures(self) -> None:
        found = gate.extract_measurements("| `x` — row | 363,574 (362,192–484,921) |\n")
        assert [(entry["label"], entry["value"]) for entry in found] == [
            ("`x` — row", "363,574"),
            ("`x` — row", "362,192"),
            ("`x` — row", "484,921"),
        ]

    def test_a_link_target_is_an_address_not_a_figure(self) -> None:
        assert gate.extract_measurements("[log](CHANGELOG.md#300---2026-04-27)\n") == []

    def test_a_heading_number_is_pinned(self) -> None:
        found = gate.extract_measurements("### ML-KEM-1024 (FIPS 203)\n")
        assert [(entry["label"], entry["value"]) for entry in found] == [("(heading)", "203")]
