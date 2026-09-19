# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The dashboard must label measurements with THEIR provenance, not the tree's.

``benchmarks/generate_dashboard.py`` used to read ``__version__`` out of the
working tree and stamp ``datetime.now()`` as the only date on the page —
so rendering an archived ``benchmark-results.json`` produced a page carrying
today's package version and today's date, with nothing saying when or at
which commit the numbers were measured.  That is the same relabelling defect
``generate_competitive.py`` documents (numbers measured at 3.4.0 republished
under an AMA 5.0.0 label), on the artefact whose entire purpose is to be
attributable.

The input JSON has carried its own ``provenance`` block and ``timestamp``
since ``benchmark_runner.generate_report`` started writing them; the page
must use those, keep "measured at" distinct from "generated", and fall back
to the working tree only for inputs that predate the block — saying so on
the page when it does.
"""

from __future__ import annotations

from typing import Any

import benchmarks.generate_dashboard as gd


def _bench(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "timestamp": "2026-08-23T05:50:47.624757+00:00",
        "provenance": {
            "commit": "f8f2a35edaf80d0cde4de99e4f4aa58e5d31f1a0",
            "tree": "clean",
            "version": "9.9.9-test",
            "host": "test-host",
        },
        "results": [
            {
                "name": "ama_sha3_256_hash",
                "description": "SHA3-256",
                "ops_per_second": 1000.0,
                "baseline_value": 900.0,
                "passed": True,
            }
        ],
    }
    base.update(overrides)
    return base


def _render(bench: dict[str, Any]) -> str:
    return gd.build(bench, rawc=[], baseline={"metadata": {}})


class TestMeasuredProvenanceIsRendered:
    def test_the_page_carries_the_artefacts_version_not_the_trees(self) -> None:
        # 9.9.9-test exists only in the synthetic artefact; if the page shows
        # it, the version was read from the measurement record.  The tree's
        # real version must not appear as the page's headline version.
        page = _render(_bench())
        assert "v9.9.9-test" in page

    def test_measured_at_is_distinct_from_generated(self) -> None:
        page = _render(_bench())
        assert "Measured at commit <code>f8f2a35edaf8</code>" in page
        assert "2026-08-23 05:50 UTC" in page
        assert "Page generated " in page
        # The measured timestamp is the artefact's, never the render clock's.
        assert page.index("Measured at commit") < page.index("Page generated")

    def test_a_dirty_measurement_tree_is_flagged(self) -> None:
        bench = _bench()
        bench["provenance"]["tree"] = "DIRTY (uncommitted changes)"
        assert "working tree DIRTY at measurement" in _render(bench)

    def test_legacy_commit_suffix_dirt_is_recognised(self) -> None:
        """Older records carried dirt as a suffix on the commit string."""
        bench = _bench()
        del bench["provenance"]["tree"]
        bench["provenance"][
            "commit"
        ] = "f8f2a35edaf80d0cde4de99e4f4aa58e5d31f1a0 (working tree DIRTY)"
        page = _render(bench)
        assert "working tree DIRTY at measurement" in page
        # The commit renders as an id, without the suffix leaking into it.
        assert "Measured at commit <code>f8f2a35edaf8</code>" in page

    def test_a_missing_timestamp_does_not_invent_one(self) -> None:
        bench = _bench()
        del bench["timestamp"]
        assert "an unrecorded time" in _render(bench)


class TestLegacyInputsFallBackLoudly:
    def test_an_input_without_provenance_says_so_on_the_page(self) -> None:
        bench = _bench()
        del bench["provenance"]
        page = _render(bench)
        assert "predates its provenance block" in page
        assert "read from the working tree at generation time" in page
        # And in that mode the tree's real version is the only honest label.
        assert "v9.9.9-test" not in page
