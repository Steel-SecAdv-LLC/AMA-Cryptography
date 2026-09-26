# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Every number in README's canonical-bench region is pinned, not only unit-tagged ones.

``tools/check_canonical_benchmarks.py`` read a figure only when a recognised
unit (ops/sec, micro-seconds, the multiplication sign, %, KB) immediately
followed it. Inside the pinned region that left "~10,834 Decaps ops/sec",
"~4,845 KeyGen, ~3,929 Sign" and every measurement date free to change, and a
figure published in ms, ns or MB/s was invisible. Now every number token is
pinned against ``benchmarks/canonical-host.json`` unless its digits are part of
a name (``ML-DSA-65``, ``Ed25519``, ``64-byte``). A letter glued to the right of
the digits (``5x``, ``1.5M``, ``10k``) is the figure's unit, not a name, and a
git revision (``974cb019``) is pinned whole.

Each negative control edits one number of a copy of the real README, and each
was mutation-checked: with the mechanism it names removed from the gate, it
fails.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import check_canonical_benchmarks as gate

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    (tmp_path / "benchmarks").mkdir()
    for relative in (gate.README, gate.RECORD):
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
            ("~16,117 Decaps", "~19,117 Decaps"),
            ("~9,358 KeyGen", "~8,358 KeyGen"),
            ("Sign ~3,360", "Sign ~3,860"),
            (
                "measured 2026-09-24; median of five runs, min–max KeyGen 3,402",
                "measured 2026-09-25; median of five runs, min–max KeyGen 3,402",
            ),
            ("Python 3.11.15", "Python 3.12.1"),
            ("(3,199–3,880)", "(3,199–3,980)"),
            ("~12,465 →", "~12,965 →"),
        ],
    )
    def test_an_edited_figure_fails(self, tree: Path, old: str, new: str) -> None:
        assert _run(tree) == 0
        _edit(tree, old, new)
        assert _run(tree) == 1

    def test_a_figure_added_in_an_unlisted_unit_fails(self, tree: Path) -> None:
        _edit(
            tree,
            "~16,117 Decaps ops/sec (medians)",
            "~16,117 Decaps ops/sec, ~0.06 ms each (medians)",
        )
        assert _run(tree) == 1

    @pytest.mark.parametrize("figure", ["5x", "~1.5M", "10k"])
    def test_a_letter_suffixed_figure_added_to_the_region_fails(
        self, tree: Path, figure: str
    ) -> None:
        """A letter glued to the RIGHT of the digits is a unit, not a name.

        The name rule used to accept a letter on either side, so each of these
        was read as a name, pinned by nothing, and the gate passed with it
        added to the region (measured before the fix: exit 0 for all three).
        """
        _edit(
            tree,
            "per-call FFI overhead, not field arithmetic.",
            f"per-call FFI overhead, not field arithmetic; the kernel is {figure} faster.",
        )
        assert _run(tree) == 1

    def test_an_edited_letter_suffixed_figure_fails(self, tree: Path) -> None:
        """Both directions: record a ``5x`` claim, then change it to ``9x``."""
        _edit(
            tree,
            "per-call FFI overhead, not field arithmetic.",
            "per-call FFI overhead, not field arithmetic; the kernel is 5x faster.",
        )
        record_path = tree / gate.RECORD
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["measurements"].append(
            {
                "heading": "Core Cryptographic Primitives (Python API via ctypes)",
                "label": "(prose)",
                "approx": False,
                "value": "5",
                "unit": "x",
                "source": "canonical-bench-host",
            }
        )
        record_path.write_text(json.dumps(record), encoding="utf-8")
        assert _run(tree) == 0
        _edit(tree, "the kernel is 5x faster", "the kernel is 9x faster")
        assert _run(tree) == 1

    def test_an_edited_build_revision_fails(self, tree: Path) -> None:
        """The revision the figures were measured at is provenance, pinned whole."""
        assert _run(tree) == 0
        _edit(tree, "`974cb019`", "`e0dcc427`")
        assert _run(tree) == 1

    def test_deleting_one_of_two_identical_figures_fails(self, tree: Path) -> None:
        """The Core Primitives table dates each of its rows "2026-09-24": ten
        figures under one key, so dropping one of them must still be seen."""
        assert _run(tree) == 0
        _edit(
            tree,
            "| 412,231 ops/sec | canonical bench, 2026-09-24 |",
            "| 412,231 ops/sec | canonical bench |",
        )
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

    def test_names_whose_letters_lead_or_share_the_word_are_not_figures(self) -> None:
        text = "fe64, SHA3-256, HKDF-SHA3-256 (3-key derive), AVX-512F, cp310, BMI1/BMI2\n"
        assert gate.extract_measurements(text) == []

    def test_a_letter_suffix_is_the_figures_unit(self) -> None:
        found = gate.extract_measurements("5x faster, ~1.5M ops/sec, 10k runs, 2-3x\n")
        assert [(entry["approx"], entry["value"], entry["unit"]) for entry in found] == [
            (False, "5", "x"),
            (True, "1.5", "M"),
            (False, "10", "k"),
            (False, "2", ""),
            (False, "3", "x"),
        ]

    def test_a_git_revision_is_pinned_whole(self) -> None:
        """Digit-led or letter-led, a revision is one value; hex-only prose
        words and plain digit runs are not revisions."""
        found = gate.extract_measurements("at `974cb019`, then a30b8d1; defaced 1234567\n")
        assert [(entry["value"], entry["unit"]) for entry in found] == [
            ("974cb019", ""),
            ("a30b8d1", ""),
            ("1234567", ""),
        ]

    def test_a_standalone_number_is_a_figure_without_a_unit(self) -> None:
        found = gate.extract_measurements("FIPS 204, q=8380417, 2026-04-25\n")
        assert [(entry["value"], entry["unit"]) for entry in found] == [
            ("204", ""),
            ("8380417", ""),
            ("2026-04-25", ""),
        ]

    def test_a_link_target_is_an_address_not_a_figure(self) -> None:
        assert gate.extract_measurements("[log](CHANGELOG.md#300---2026-04-27)\n") == []

    def test_a_heading_number_is_pinned(self) -> None:
        found = gate.extract_measurements("### ML-KEM-1024 (FIPS 203)\n")
        assert [(entry["label"], entry["value"]) for entry in found] == [("(heading)", "203")]
