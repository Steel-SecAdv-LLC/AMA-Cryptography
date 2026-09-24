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

import json
from pathlib import Path
from typing import Any

import pytest

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


_TEMPLATE = Path(gd.__file__).resolve().parent / "_dashboard_template.html"
_SENTINEL = "payload-sentinel-6b1f0c"


def _script_body(page: str) -> str:
    """The text of the page's one ``<script>`` element."""
    start = page.index("<script>") + len("<script>")
    return page[start : page.index("</script>", start)]


def _embedded_data(page: str) -> Any:
    """The object the page's script binds to ``DATA``, parsed back."""
    body = _script_body(page)
    start = body.index("const DATA = ") + len("const DATA = ")
    return json.loads(body[start : body.index(";\n", start)])


class TestThePayloadIsEmbeddedOnceAndStaysInItsScript:
    """The template's header comment named the markers it documents.

    ``str.replace`` substitutes every occurrence, so each render carried a
    second copy of the whole data payload inside that ``<!-- -->`` comment
    (the committed ``benchmarks/dashboard.html`` shows it on line 2), where a
    ``-->`` in any change-log string would have closed the comment and
    printed the rest of the JSON as page text.  The remaining copy had the
    same exposure to ``</script>``, and the chained substitutions would have
    rewritten a marker spelled inside the already-inserted JSON.
    """

    def test_the_shipped_template_names_no_marker_inside_a_comment(self) -> None:
        tmpl = _TEMPLATE.read_text(encoding="utf-8")
        comments = gd._HTML_COMMENT_RE.findall(tmpl)
        assert comments, "non-vacuity: the template's header comment is gone"
        for comment in comments:
            assert gd._MARKER_RE.findall(comment) == [], comment

    def test_the_payload_appears_once_and_inside_the_script(self) -> None:
        bench = _bench()
        bench["results"][0]["description"] = _SENTINEL
        page = _render(bench)
        assert page.count(_SENTINEL) == 1, "the data payload is embedded more than once"
        assert _SENTINEL in _script_body(page)

    def test_free_text_cannot_close_the_script_or_open_a_comment(self) -> None:
        hostile = f"{_SENTINEL} --> </script><!-- <b>x</b> __VERSION__ __MEASURED__"
        bench = _bench()
        bench["results"][0]["description"] = hostile
        page = _render(bench)
        tmpl = _TEMPLATE.read_text(encoding="utf-8")
        # Every structural sequence in the page is the template's own.
        for seq in ("</script>", "<!--", "-->"):
            assert page.count(seq) == tmpl.count(seq), seq
        # And the reader parses back exactly what was written: no escaping
        # artefact and no marker substituted inside the data.
        assert _embedded_data(page)["results"][0]["description"] == hostile

    def test_a_template_naming_a_marker_in_a_comment_is_refused(self) -> None:
        tmpl = "<!-- fills __VERSION__ -->\n__VERSION__ __MEASURED__ __GENERATED__ /*__DATA__*/"
        with pytest.raises(RuntimeError, match="inside an HTML comment"):
            gd.fill_template(tmpl, {})

    @pytest.mark.parametrize("marker", [gd.DATA_MARKER, gd.MEASURED_MARKER, gd.GENERATED_MARKER])
    def test_a_single_place_marker_must_occur_exactly_once(self, marker: str) -> None:
        tmpl = f"__VERSION__ __MEASURED__ __GENERATED__ /*__DATA__*/ {marker}"
        with pytest.raises(RuntimeError, match="exactly once"):
            gd.fill_template(tmpl, {})
