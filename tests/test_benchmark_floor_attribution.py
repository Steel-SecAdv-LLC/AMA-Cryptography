# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A documented floor must be THAT benchmark's floor on THAT architecture.

``tools/check_benchmark_claims.py`` used to accept a figure documented as a
floor if it equalled ANY floor of ANY benchmark on either architecture, though
its docstring said matching was "by benchmark identifier and architecture
label". So HMAC-SHA3-256's 215,299 could be republished as the ed25519_sign
floor and pass. And the aarch64 half of wiki/Performance-Benchmarks.md's HMAC
sentence ("... and 285,176 on aarch64") was never parsed at all: the claim
regex needed "floor" before the figure and "ops/sec" after it.

Each negative control here is a one-figure edit of the real wiki passage, or a
minimal sentence, and each was mutation-checked: with the mechanism it names
removed from the gate, it fails.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_benchmark_claims.py"
WIKI = REPO_ROOT / "wiki" / "Performance-Benchmarks.md"

#: The live HMAC passage, as the gate must read it.
X86_CLAIM = "The **enforced floor** is 215,299 ops/sec on x86-64"
ARM_CLAIM = "and 285,176 on aarch64"


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_benchmark_claims_floors", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _ledgers(gate: ModuleType) -> tuple[dict[str, Any], dict[str, Any]]:
    x86 = json.loads((REPO_ROOT / gate.X86_BASELINE_JSON).read_text(encoding="utf-8"))
    arm = json.loads((REPO_ROOT / gate.ARM_BASELINE_JSON).read_text(encoding="utf-8"))
    return x86, arm


def _floor(gate: ModuleType, ledger: dict[str, Any], name: str) -> str:
    return f"{int(gate._floors(ledger)[name]['baseline_value']):,}"


def _check(gate: ModuleType, tmp_path: Path, text: str, name: str = "PAGE.md") -> list[str]:
    """Run check_documented_floors over a one-page tree carrying ``text``."""
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(text, encoding="utf-8")
    x86, arm = _ledgers(gate)
    report = gate.Report()
    gate.check_documented_floors(report, tmp_path, x86, arm)
    return list(report.failures)


def _wiki(tmp_path: Path, old: str = "", new: str = "") -> Path:
    text = WIKI.read_text(encoding="utf-8")
    if old:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    target = tmp_path / "wiki" / "Performance-Benchmarks.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def _names(gate: ModuleType) -> set[str]:
    x86, arm = _ledgers(gate)
    return set(gate._floors(x86)) | set(gate._floors(arm))


class TestTheLiveWikiPassage:
    def test_both_architectures_are_parsed_and_attributed(self, gate: ModuleType) -> None:
        """The aarch64 figure is a claim now, attributed to HMAC on aarch64."""
        text = WIKI.read_text(encoding="utf-8")
        assert X86_CLAIM in text and ARM_CLAIM in text
        claims = {
            (claim.benchmark, claim.architecture, claim.value)
            for claim in gate.extract_floor_claims(text, "wiki", _names(gate))
        }
        assert ("hmac_sha3_256", "x86-64", "215,299") in claims
        assert ("hmac_sha3_256", "aarch64", "285,176") in claims

    def test_the_live_passage_passes(self, gate: ModuleType, tmp_path: Path) -> None:
        _wiki(tmp_path)
        assert _check(gate, tmp_path, "", name="EMPTY.md") == []

    def test_another_benchmarks_floor_fails(self, gate: ModuleType, tmp_path: Path) -> None:
        """HMAC's x86 floor replaced by ed25519_sign's: a real floor, the wrong one."""
        x86, _ = _ledgers(gate)
        wrong = _floor(gate, x86, "ed25519_sign")
        _wiki(tmp_path, "floor** is 215,299", f"floor** is {wrong}")
        failures = _check(gate, tmp_path, "", name="EMPTY.md")
        assert len(failures) == 1, failures
        assert "hmac_sha3_256" in failures[0] and "215,299" in failures[0]

    def test_the_other_architectures_floor_fails(self, gate: ModuleType, tmp_path: Path) -> None:
        """HMAC's x86 floor cited as its aarch64 floor."""
        _wiki(tmp_path, ARM_CLAIM, "and 215,299 on aarch64")
        failures = _check(gate, tmp_path, "", name="EMPTY.md")
        assert len(failures) == 1, failures
        assert "aarch64" in failures[0] and "285,176" in failures[0]

    def test_a_wrong_aarch64_figure_fails(self, gate: ModuleType, tmp_path: Path) -> None:
        """Invisible before: the aarch64 phrasing was never parsed."""
        _, arm = _ledgers(gate)
        _wiki(tmp_path, ARM_CLAIM, f"and {_floor(gate, arm, 'ed25519_sign')} on aarch64")
        failures = _check(gate, tmp_path, "", name="EMPTY.md")
        assert len(failures) == 1, failures
        assert "285,176" in failures[0]


class TestAttribution:
    def test_a_claim_naming_no_benchmark_fails(self, gate: ModuleType, tmp_path: Path) -> None:
        failures = _check(gate, tmp_path, "The enforced floor is 215,299 ops/sec on x86-64.\n")
        assert len(failures) == 1 and "cannot be attributed" in failures[0], failures

    def test_a_claim_naming_no_architecture_fails(self, gate: ModuleType, tmp_path: Path) -> None:
        failures = _check(gate, tmp_path, "The hmac_sha3_256 floor is 215,299 ops/sec.\n")
        assert len(failures) == 1 and "no architecture" in failures[0], failures

    def test_a_sentence_naming_two_benchmarks_is_ambiguous(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        failures = _check(
            gate,
            tmp_path,
            "The ed25519_sign and hmac_sha3_256 floors are 38,811 ops/sec on x86-64.\n",
        )
        assert len(failures) == 1 and "cannot be attributed" in failures[0], failures
        # The failure names the ambiguity rather than claiming nothing was named.
        assert "names ed25519_sign, hmac_sha3_256" in failures[0], failures

    def test_the_paragraph_names_the_benchmark_when_the_sentence_does_not(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """The section names two benchmarks; the claim's own list item names one."""
        text = (
            "## Section\n\nThe ed25519_sign row is described elsewhere.\n\n"
            "- `hmac_sha3_256` over 1 KB. Its floor is 38,811 ops/sec on x86-64.\n"
        )
        failures = _check(gate, tmp_path, text)
        assert len(failures) == 1 and "215,299" in failures[0], failures

    def test_the_blockquote_names_the_benchmark_when_the_paragraph_does_not(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """The live wiki shape: the benchmark is named once, in the blockquote's closing line."""
        text = (
            "## Section\n\nThe ed25519_sign row is described elsewhere.\n\n"
            "> - The enforced floor is 38,811 ops/sec on x86-64.\n"
            ">\n"
            "> All of the above are measurements of `ama_hmac_sha3_256`.\n"
        )
        failures = _check(gate, tmp_path, text)
        assert len(failures) == 1 and "215,299" in failures[0], failures

    def test_an_attributed_correct_claim_passes(self, gate: ModuleType, tmp_path: Path) -> None:
        text = "The `ed25519_sign` floor is 38,811 ops/sec on x86-64 and 32,852 on aarch64.\n"
        assert _check(gate, tmp_path, text) == []

    def test_a_name_is_not_matched_inside_a_longer_name(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """``ed25519_sign`` must not be read inside ``ed25519_sign_expanded``."""
        text = "The ed25519_sign_expanded floor is 61,671 ops/sec on x86-64.\n"
        assert _check(gate, tmp_path, text) == []

    def test_a_refuted_figure_is_not_a_claim(self, gate: ModuleType, tmp_path: Path) -> None:
        text = "The hmac_sha3_256 floor is 215,299 ops/sec on x86-64, not 76,215 on x86-64.\n"
        assert _check(gate, tmp_path, text) == []

    def test_a_derivation_that_mentions_a_floor_is_not_a_claim(self, gate: ModuleType) -> None:
        """README's history sentence names old figures; it asserts no current floor."""
        text = (
            "The x86_64 `ed25519_sign` floor was first set by a host-independent "
            "derivation (70,496 / 1.8469 = 38,170) and is now the runner's own "
            "four-run median.\n"
        )
        assert gate.extract_floor_claims(text, "README.md", _names(gate)) == []

    def test_a_floor_column_in_a_table_is_checked_per_row(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        table = (
            "| Benchmark | Floor (ops/sec, x86-64) |\n"
            "|---|---|\n"
            "| hmac_sha3_256 | 215,299 |\n"
            "| ed25519_sign | 215,299 |\n"
        )
        failures = _check(gate, tmp_path, table)
        assert len(failures) == 1 and "ed25519_sign" in failures[0], failures


class TestTheClaimShapes:
    """Each phrasing the gate reads as a floor claim, driven with a wrong figure."""

    def test_a_figure_that_is_the_predicate_of_floor_needs_no_unit(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        text = "The aarch64 hmac_sha3_256 floor is 215,299.\n"
        failures = _check(gate, tmp_path, text)
        assert len(failures) == 1 and "285,176" in failures[0], failures

    def test_a_figure_before_the_word_floor_is_a_claim(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """Also pins the hyphenated spelling of a benchmark identifier."""
        text = "HMAC-SHA3-256 has a 38,811 ops/sec floor on x86-64.\n"
        failures = _check(gate, tmp_path, text)
        assert len(failures) == 1 and "215,299" in failures[0], failures
