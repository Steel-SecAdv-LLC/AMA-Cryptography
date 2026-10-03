# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The canonical-host figures README publishes must be pinned by a record.

``tools/check_benchmark_claims.py`` pins what is re-derivable from
``benchmarks/benchmark-results.json``.  It never saw the canonical-host tables,
because nothing in the tree carried those figures as data.  That was measured,
not assumed: with the ML-DSA-65 KeyGen row edited from ``3,626 ops/sec`` to
``9,626 ops/sec``, the existing gate reported ``OK    86 benchmark claim(s)
consistent with their records`` and exited 0.

``tools/check_canonical_benchmarks.py`` closes that, and these tests are what
establish it does.  Each one is a negative control: a tree the gate must
reject.  A gate is only worth what its failures are worth, so every assertion
below drives the gate with a deliberately broken input and requires the
specific non-zero exit, rather than confirming the healthy tree still passes —
which it would do with the comparison deleted.

The classification these earn is PIN: each fails when the mechanism is removed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools import check_canonical_benchmarks as gate

REPO_ROOT = Path(__file__).resolve().parent.parent

README_PATH = REPO_ROOT / gate.README
RECORD_PATH = REPO_ROOT / gate.RECORD


def _run(repo: Path) -> int:
    return gate.main(["--repo", str(repo)])


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    """A copy of the real README and record, for a test to then break."""
    (tmp_path / "benchmarks").mkdir()
    (tmp_path / gate.README).write_text(README_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / gate.RECORD).write_text(RECORD_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    return tmp_path


def _record(tree: Path) -> dict[str, Any]:
    loaded = json.loads((tree / gate.RECORD).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _write_record(tree: Path, record: dict[str, Any]) -> None:
    (tree / gate.RECORD).write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


class TestTheShippedTreeAgrees:
    """The committed README and record must already match, or nothing else means anything."""

    def test_the_real_tree_passes(self) -> None:
        assert _run(REPO_ROOT) == 0

    def test_every_published_figure_is_recorded(self) -> None:
        region = gate.extract_region(README_PATH.read_text(encoding="utf-8"))
        assert region is not None
        published = gate.extract_measurements(region)
        assert published, "the markers must enclose at least one figure"
        recorded = {gate._key(entry) for entry in _record(REPO_ROOT)["measurements"]}
        assert {gate._key(entry) for entry in published} == recorded


class TestADriftedFigureIsRejected:
    """The failure the gate exists for: a published number that changed silently."""

    def test_an_edited_throughput_figure_fails(self, tree: Path) -> None:
        readme = tree / gate.README
        text = readme.read_text(encoding="utf-8")
        assert "1,617 ops/sec" in text
        readme.write_text(text.replace("1,617 ops/sec", "9,617 ops/sec"), encoding="utf-8")
        assert _run(tree) == 1

    def test_an_edited_latency_figure_fails(self, tree: Path) -> None:
        readme = tree / gate.README
        text = readme.read_text(encoding="utf-8")
        assert "~315µs" in text
        readme.write_text(text.replace("~315µs", "~135µs"), encoding="utf-8")
        assert _run(tree) == 1

    def test_dropping_the_approximation_mark_fails(self, tree: Path) -> None:
        """``618µs`` and ``~618µs`` are different claims about the same number."""
        readme = tree / gate.README
        text = readme.read_text(encoding="utf-8")
        assert "~618µs" in text
        readme.write_text(text.replace("~618µs", "618µs"), encoding="utf-8")
        assert _run(tree) == 1


class TestAnUnbackedFigureIsRejected:
    """A new number cannot enter the region without a record entry behind it."""

    def test_an_added_row_fails(self, tree: Path) -> None:
        readme = tree / gate.README
        text = readme.read_text(encoding="utf-8")
        anchor = "| Ed25519 Verify | 30,299 ops/sec | canonical bench, 2026-09-24 |"
        assert anchor in text
        added = f"{anchor}\n| Ed25519 Batch | 99,999 ops/sec | canonical bench, 2026-09-24 |"
        readme.write_text(text.replace(anchor, added), encoding="utf-8")
        assert _run(tree) == 1

    def test_a_record_entry_citing_no_known_source_fails(self, tree: Path) -> None:
        record = _record(tree)
        record["measurements"][0]["source"] = "a-host-that-is-not-described"
        _write_record(tree, record)
        assert _run(tree) == 1


class TestADeletedFigureIsRejected:
    """The other direction: a claim is not retired by deleting the line that quotes it."""

    def test_removing_a_published_row_fails(self, tree: Path) -> None:
        readme = tree / gate.README
        lines = readme.read_text(encoding="utf-8").splitlines()
        kept = [ln for ln in lines if "| **Encapsulate** | 17,984 ops/sec" not in ln]
        assert len(kept) == len(lines) - 1
        readme.write_text("\n".join(kept) + "\n", encoding="utf-8")
        assert _run(tree) == 1


class TestProvenanceIsMandatory:
    """INVARIANT-36: a published figure names where it came from."""

    @pytest.mark.parametrize("field", ["description", "measured", "command"])
    def test_a_source_missing_a_provenance_field_fails(self, tree: Path, field: str) -> None:
        record = _record(tree)
        del record["sources"]["canonical-bench-host"][field]
        _write_record(tree, record)
        assert _run(tree) == 1

    def test_an_empty_sources_map_fails(self, tree: Path) -> None:
        record = _record(tree)
        record["sources"] = {}
        _write_record(tree, record)
        assert _run(tree) == 1


class TestTheGateCannotPassVacuously:
    """A gate that checks nothing must say so, not report success."""

    def test_missing_markers_exit_two(self, tree: Path) -> None:
        readme = tree / gate.README
        text = readme.read_text(encoding="utf-8")
        readme.write_text(text.replace(gate.BEGIN_MARKER, ""), encoding="utf-8")
        assert _run(tree) == 2

    def test_an_empty_region_exits_two(self, tree: Path) -> None:
        """Deleting the whole region must not read as "nothing to check, so OK"."""
        readme = tree / gate.README
        text = readme.read_text(encoding="utf-8")
        start = text.index(gate.BEGIN_MARKER) + len(gate.BEGIN_MARKER)
        end = text.index(gate.END_MARKER)
        readme.write_text(text[:start] + "\n\n" + text[end:], encoding="utf-8")
        assert _run(tree) == 2

    def test_a_missing_record_exits_two(self, tree: Path) -> None:
        (tree / gate.RECORD).unlink()
        assert _run(tree) == 2

    def test_a_malformed_record_exits_two(self, tree: Path) -> None:
        (tree / gate.RECORD).write_text("{ not json", encoding="utf-8")
        assert _run(tree) == 2

    def test_an_empty_measurement_list_fails(self, tree: Path) -> None:
        record = _record(tree)
        record["measurements"] = []
        _write_record(tree, record)
        assert _run(tree) == 1


class TestTheGateRunsInCI:
    """A gate no lane invokes is a script, not a gate (INVARIANT-31)."""

    def test_ci_invokes_the_gate(self) -> None:
        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        assert "python tools/check_canonical_benchmarks.py" in workflow
