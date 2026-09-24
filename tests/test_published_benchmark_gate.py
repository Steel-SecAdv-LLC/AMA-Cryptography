# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The performance figures README publishes must be pinned by a record.

``tools/check_benchmark_claims.py`` pins what is re-derivable from
``benchmarks/benchmark-results.json``.  It does not see the table of CI
four-run medians README carries, because nothing it reads holds those figures
as data.  That was measured, not assumed: with the ``ama_sha3_256_hash`` x86_64
median edited from ``363,574`` to ``963,574``, it reported ``OK    91
benchmark claim(s) consistent with their records`` and exited 0 — and so did
the canonical-host gate this one replaced, whose region did not reach that
table.

``tools/check_published_benchmarks.py`` closes that, and these tests are what
establish it does.  Each one is a negative control: a tree the gate must
reject.  A gate is only worth what its failures are worth, so every assertion
below drives the gate with a deliberately broken input and requires the
specific non-zero exit, rather than confirming the healthy tree still passes —
which it would do with the comparison deleted.

The classification these earn is PIN, established by mutating the gate: each
fails when the mechanism it names is removed.  One property is enforced
redundantly (AGENTS.md section 6.3), and the tests say so where it applies:
an *edited* figure is caught by both comparison directions, so removing either
direction alone leaves ``TestADriftedFigureIsRejected`` passing and removing
both fails it.  An *invented* figure is caught only by the published-to-record
direction and a *deleted* one only by the record-to-published direction; each
of those tests fails when its one direction is removed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools import check_published_benchmarks as gate

REPO_ROOT = Path(__file__).resolve().parent.parent

README_PATH = REPO_ROOT / gate.README
RECORD_PATH = REPO_ROOT / gate.RECORD

#: A row of the CI four-run table, as README prints it.
SHA3_ROW_X86 = "| 363,574 (362,192–484,921) |"


def _run(repo: Path) -> int:
    return gate.main(["--repo", str(repo)])


def _documents() -> list[str]:
    """The pages the committed record pins, README first."""
    documents = json.loads(RECORD_PATH.read_text(encoding="utf-8"))["documents"]
    assert isinstance(documents, list) and documents[0] == gate.README
    return [str(name) for name in documents]


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    """A copy of the real record and every page it pins, for a test to then break."""
    for relative in [*_documents(), gate.RECORD]:
        (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / relative).write_text(
            (REPO_ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8"
        )
    return tmp_path


def _record(tree: Path) -> dict[str, Any]:
    loaded = json.loads((tree / gate.RECORD).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _write_record(tree: Path, record: dict[str, Any]) -> None:
    (tree / gate.RECORD).write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _sources_of_kind(kind: str) -> list[str]:
    return [
        name for name, source in _record(REPO_ROOT)["sources"].items() if source.get("kind") == kind
    ]


def _replace_once(tree: Path, old: str, new: str) -> None:
    readme = tree / gate.README
    text = readme.read_text(encoding="utf-8")
    region = gate.extract_region(text)
    assert region is not None and region.count(old) == 1, old
    readme.write_text(text.replace(old, new, 1), encoding="utf-8")


class TestTheShippedTreeAgrees:
    """The committed README and record must already match, or nothing else means anything."""

    def test_the_real_tree_passes(self) -> None:
        assert _run(REPO_ROOT) == 0

    def test_every_published_figure_is_recorded(self) -> None:
        published = []
        for document in _documents():
            regions = gate.extract_regions((REPO_ROOT / document).read_text(encoding="utf-8"))
            assert regions, document
            found = [m for region in regions for m in gate.extract_measurements(region, document)]
            assert found, f"the markers in {document} must enclose at least one figure"
            published.extend(found)
        recorded = {gate._key(entry) for entry in _record(REPO_ROOT)["measurements"]}
        assert {gate._key(entry) for entry in published} == recorded

    def test_the_region_holds_the_ci_table(self) -> None:
        """The table the old region missed is the one this region exists to pin."""
        region = gate.extract_region(README_PATH.read_text(encoding="utf-8"))
        assert region is not None
        assert SHA3_ROW_X86 in region
        assert "35545407750" in region

    def test_every_measurement_source_names_its_runs(self) -> None:
        measurements = _sources_of_kind("measurement")
        assert measurements, "the record must carry at least one measurement source"
        for name in measurements:
            runs = _record(REPO_ROOT)["sources"][name]["runs"]
            assert runs and all(run.strip() for run in runs), name


class TestADriftedFigureIsRejected:
    """The failure the gate exists for: a published number that changed silently.

    These pin the property, not one implementation of it: an edit leaves the new
    value unrecorded AND the old recorded value unpublished, so either
    comparison direction rejects it on its own.
    """

    def test_an_edited_median_fails(self, tree: Path) -> None:
        _replace_once(tree, SHA3_ROW_X86, "| 963,574 (362,192–484,921) |")
        assert _run(tree) == 1

    def test_an_edited_range_bound_fails(self, tree: Path) -> None:
        _replace_once(tree, SHA3_ROW_X86, "| 363,574 (362,192–584,921) |")
        assert _run(tree) == 1

    def test_an_edited_run_identifier_fails(self, tree: Path) -> None:
        _replace_once(tree, "runs 35545407750,", "runs 35545407751,")
        assert _run(tree) == 1

    def test_dropping_the_approximation_mark_fails(self, tree: Path) -> None:
        """``1.9 KB`` and ``~1.9 KB`` are different claims about the same number."""
        _replace_once(tree, "~1.9 KB", "1.9 KB")
        assert _run(tree) == 1


class TestAnUnbackedFigureIsRejected:
    """A new number cannot enter the region without a record entry behind it."""

    def test_an_added_row_fails(self, tree: Path) -> None:
        anchor = next(
            line
            for line in (tree / gate.README).read_text(encoding="utf-8").splitlines()
            if line.startswith("| `x25519_scalarmult_batch4`")
        )
        added = f"{anchor}\n| `avx512_everything` — invented | 999,999 (999,000–999,999) | — |"
        _replace_once(tree, anchor, added)
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
        kept = [ln for ln in lines if not ln.startswith("| `kyber_encapsulate`")]
        assert len(kept) == len(lines) - 1
        readme.write_text("\n".join(kept) + "\n", encoding="utf-8")
        assert _run(tree) == 1


class TestProvenanceIsMandatory:
    """INVARIANT-53 and AGENTS.md section 8 item 7: a published figure names where it came from."""

    @pytest.mark.parametrize(
        "field", ["description", "measured", "host", "build", "command", "sampling", "aggregation"]
    )
    def test_a_measurement_missing_a_provenance_field_fails(self, tree: Path, field: str) -> None:
        record = _record(tree)
        del record["sources"][_sources_of_kind("measurement")[0]][field]
        _write_record(tree, record)
        assert _run(tree) == 1

    @pytest.mark.parametrize("runs", [None, [], [""], "35545407750"])
    def test_a_measurement_without_named_runs_fails(self, tree: Path, runs: Any) -> None:
        """A figure whose run cannot be cited is the figure section 8 item 7 prohibits."""
        record = _record(tree)
        source = record["sources"][_sources_of_kind("measurement")[0]]
        if runs is None:
            del source["runs"]
        else:
            source["runs"] = runs
        _write_record(tree, record)
        assert _run(tree) == 1

    @pytest.mark.parametrize("kind", ["ledger", "specification", "source-constant"])
    def test_a_non_measurement_source_missing_its_reference_fails(
        self, tree: Path, kind: str
    ) -> None:
        record = _record(tree)
        del record["sources"][_sources_of_kind(kind)[0]]["reference"]
        _write_record(tree, record)
        assert _run(tree) == 1

    @pytest.mark.parametrize("kind", [None, "host", "canonical-bench-host"])
    def test_a_source_of_unknown_kind_fails(self, tree: Path, kind: Any) -> None:
        """A kind with no provenance rule would let a figure in under no rule at all."""
        record = _record(tree)
        source = record["sources"][_sources_of_kind("measurement")[0]]
        if kind is None:
            del source["kind"]
        else:
            source["kind"] = kind
        _write_record(tree, record)
        assert _run(tree) == 1

    def test_relabelling_a_measurement_as_a_constant_needs_a_reference(self, tree: Path) -> None:
        """Changing the kind does not drop the obligation: the new kind brings its own."""
        record = _record(tree)
        record["sources"][_sources_of_kind("measurement")[0]]["kind"] = "source-constant"
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


class TestTheRetiredRecordStaysRetired:
    """The canonical-host record and gate were removed, not renamed around."""

    def test_the_canonical_host_record_is_gone(self) -> None:
        assert not (REPO_ROOT / "benchmarks" / "canonical-host.json").exists()
        assert not (REPO_ROOT / "tools" / "check_canonical_benchmarks.py").exists()

    def test_the_readme_region_carries_no_canonical_host_figure(self) -> None:
        region = gate.extract_region(README_PATH.read_text(encoding="utf-8"))
        assert region is not None
        assert "canonical bench" not in region.lower()
        assert "canonical-host" not in region.lower()


class TestTheGateRunsInCI:
    """A gate no lane invokes is a script, not a gate (INVARIANT-31)."""

    def test_ci_invokes_the_gate(self) -> None:
        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        assert "python tools/check_published_benchmarks.py" in workflow
