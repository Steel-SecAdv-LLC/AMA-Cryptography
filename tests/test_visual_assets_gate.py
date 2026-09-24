# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The committed visual assets must not decay into false claims.

Two confirmed defects, one mechanism:

* The README-embedded coverage chart dropped 46% of the test suite (114 of
  200 files, 2,159 of 4,702 test functions when measured) while its title
  and footer claimed to describe every ``tests/test_*.py`` file —
  ``total_tests`` summed only bucketed files, ``n_files`` counted all of
  them, and the only signal was a stdout WARN nothing in CI ever ran.
* The five README PNGs are produced only by two manual generators, neither
  of which had a ``--check`` mode or any CI/Makefile/pre-commit wiring, so
  the committed assets sat frozen and version-stamped at v3.4.0 two majors
  behind HEAD.

The repairs: an ``Other`` bucket so the chart's total genuinely covers the
walked set, and ``assets/visuals_manifest.json`` written beside the PNGs
with ``tools/generate_visuals.py --check`` re-deriving the tree-computable
numbers in CI (and holding the measurement-derived dashboards to the
package version).  These tests pin both, plus the wiring.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import zlib
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "generate_visuals.py"


@pytest.fixture(scope="module")
def gv() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_visuals", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestTheChartAccountsForEveryFile:
    def test_the_total_equals_an_independent_count_over_all_test_files(
        self, gv: ModuleType
    ) -> None:
        """The [0]-defect pin: bucketing is presentation, never exclusion."""
        counts, total, _unbucketed = gv._count_test_functions_by_category()
        independent = 0
        for path in sorted((REPO_ROOT / "tests").glob("test_*.py")):
            independent += len(
                re.findall(r"^\s*def test_", path.read_text(encoding="utf-8"), re.MULTILINE)
            )
        assert total == independent, (
            f"the chart's total ({total}) drops tests the tree has ({independent}); "
            f"the Other bucket exists so this cannot happen"
        )
        assert total == sum(counts)

    def test_unbucketed_files_land_in_the_trailing_other_bucket(self, gv: ModuleType) -> None:
        counts, _total, unbucketed = gv._count_test_functions_by_category()
        assert len(counts) == len(gv._TEST_CATEGORY_RULES) + 1
        assert counts[-1] == sum(n for _, n in unbucketed)

    def test_the_stale_metrics_anchor_is_gone(self, gv: ModuleType) -> None:
        """The docstring pinned the chart to a 2,026-of-2,028 figure from
        v2.1.5, two majors out of date; frozen figures belong in the manifest
        where they are checked, not in prose where they rot."""
        doc = gv._count_test_functions_by_category.__doc__ or ""
        assert "2,026" not in doc and "2,028" not in doc
        assert "METRICS_REPORT" in doc


def _png(text: dict[str, str] | None = None) -> bytes:
    """A valid 1x1 greyscale PNG carrying ``text`` as ``tEXt`` chunks."""

    def chunk(kind: bytes, body: bytes) -> bytes:
        return (
            struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
        )

    out = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
    for keyword, value in (text or {}).items():
        out += chunk(b"tEXt", keyword.encode("latin-1") + b"\0" + value.encode("latin-1"))
    return out + chunk(b"IDAT", zlib.compress(b"\x00\x00")) + chunk(b"IEND", b"")


def _stage_assets(
    gv: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    chart_inputs: dict[str, object] | None,
) -> None:
    """A faithful manifest beside PNGs; ``test_coverage.png`` records ``chart_inputs``.

    The real ``assets/`` directory is left alone: these tests are about what
    the check does, not about whether the committed charts are current (that
    is ``test_the_committed_chart_draws_the_trees_numbers``).
    """
    assets = tmp_path / "assets"
    assets.mkdir()
    recorded = gv._live_manifest_entry()
    recorded["dashboards"] = {"version": gv._PKG_VERSION}
    (assets / "visuals_manifest.json").write_text(json.dumps(recorded), encoding="utf-8")
    for name in gv._OWNED_OUTPUTS:
        (assets / name).write_bytes(_png())
    text = (
        {}
        if chart_inputs is None
        else {gv._CHART_INPUTS_KEY: gv._encode_chart_inputs(chart_inputs)}
    )
    (assets / "test_coverage.png").write_bytes(_png(text))
    monkeypatch.setattr(gv, "ASSETS_DIR", assets)
    monkeypatch.setattr(gv, "MANIFEST_PATH", assets / "visuals_manifest.json")


class TestManifestCheck:
    def _manifest_with(self, gv: ModuleType, tmp_path: Path, **overrides: object) -> Path:
        recorded = gv._live_manifest_entry()
        recorded["dashboards"] = {"version": gv._PKG_VERSION}
        recorded.update(overrides)
        path = tmp_path / "visuals_manifest.json"
        path.write_text(json.dumps(recorded), encoding="utf-8")
        return path

    def test_a_faithful_manifest_passes(
        self, gv: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stage_assets(gv, tmp_path, monkeypatch, gv._live_test_coverage_inputs())
        assert gv.check_manifest() == []

    def test_a_drifted_count_fails(
        self, gv: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stale = gv._live_manifest_entry()
        stale["test_coverage"]["total_tests"] += 1
        stale["dashboards"] = {"version": gv._PKG_VERSION}
        path = tmp_path / "visuals_manifest.json"
        path.write_text(json.dumps(stale), encoding="utf-8")
        monkeypatch.setattr(gv, "MANIFEST_PATH", path)
        problems = gv.check_manifest()
        assert problems and any("does not match the tree" in p for p in problems)

    def test_a_missing_manifest_fails(
        self, gv: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(gv, "MANIFEST_PATH", tmp_path / "absent.json")
        assert gv.check_manifest(), "an absent manifest must fail, not pass vacuously"

    def test_stale_dashboards_version_fails(
        self, gv: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The two-majors-stale case that motivated all of this: the
        committed performance dashboard carried a v3.4.0 title into a 5.0.0
        tree because nothing compared these."""
        path = self._manifest_with(gv, tmp_path, dashboards={"version": "3.4.0"})
        monkeypatch.setattr(gv, "MANIFEST_PATH", path)
        problems = gv.check_manifest()
        assert problems and any("3.4.0" in p for p in problems)

    def test_the_committed_manifest_matches_the_tree(self, gv: ModuleType) -> None:
        """The real assets, held to the real tree — the CI step's substance.

        Version drift in the dashboards entry is asserted separately above;
        here the tree-computable numbers must match what is committed, so a
        test added without regenerating the chart fails this test with the
        regeneration command in the message.
        """
        recorded = json.loads(gv.MANIFEST_PATH.read_text(encoding="utf-8"))
        live = gv._live_manifest_entry()
        for key, value in live.items():
            assert recorded.get(key) == value, (
                f"assets/visuals_manifest.json {key!r} does not match the tree; "
                f"regenerate with `python tools/generate_visuals.py` and commit "
                f"the PNGs and manifest together"
            )


class TestTheChartIsBoundToItsNumbers:
    """``--check`` validated the manifest, never the PNG it describes.

    Measured before the fix: with a manifest faithful to the tree and
    ``test_coverage.png`` replaced by a different chart altogether (a copy of
    ``quantum_comparison.png``), ``check_manifest()`` returned ``[]``.  The
    failure message prints the exact expected JSON, so an environment without
    matplotlib — the one ``--check`` is for — could turn the gate green by
    pasting it into the manifest while the chart still drew the old totals.
    Recording a PNG digest in the manifest would not have closed that: the
    pasted numbers leave the old digest matching the old PNG.  The chart now
    records the numbers it drew in its own ``AMA-Chart-Inputs`` text chunk.
    """

    def test_a_chart_drawing_other_numbers_fails(
        self, gv: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stale = gv._live_test_coverage_inputs()
        total = stale["total_tests"]
        assert isinstance(total, int)
        stale["total_tests"] = total - 1
        _stage_assets(gv, tmp_path, monkeypatch, stale)
        problems = gv.check_manifest()
        assert any("draws numbers the tree no longer has" in p for p in problems), problems
        assert any("total_tests" in p for p in problems), problems

    def test_a_chart_recording_nothing_fails(
        self, gv: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stage_assets(gv, tmp_path, monkeypatch, None)
        problems = gv.check_manifest()
        assert any("records no AMA-Chart-Inputs" in p for p in problems), problems

    def test_a_hand_edited_chunk_fails_its_crc(
        self, gv: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stage_assets(gv, tmp_path, monkeypatch, gv._live_test_coverage_inputs())
        chart = gv.ASSETS_DIR / "test_coverage.png"
        data = bytearray(chart.read_bytes())
        at = data.index(b'"total_tests": ') + len(b'"total_tests": ')
        data[at] = ord("9") if data[at] != ord("9") else ord("8")
        chart.write_bytes(bytes(data))
        problems = gv.check_manifest()
        assert any("fails its CRC" in p for p in problems), problems

    def test_the_manifest_alone_cannot_vouch_for_the_chart(
        self, gv: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The pasted-JSON path, end to end, through the command line."""
        stale = gv._live_test_coverage_inputs()
        n_files = stale["n_files"]
        assert isinstance(n_files, int)
        stale["n_files"] = n_files + 3
        _stage_assets(gv, tmp_path, monkeypatch, stale)
        assert gv.main(["--check"]) == 1

    def test_the_renderer_records_what_it_drew(
        self, gv: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pytest.importorskip("matplotlib")
        if not gv._HAVE_MATPLOTLIB:
            pytest.skip("the plotting stack did not import in the tool")
        monkeypatch.setattr(gv, "ASSETS_DIR", tmp_path)
        gv.create_test_coverage()
        recorded = gv._png_text_chunks(tmp_path / "test_coverage.png")[gv._CHART_INPUTS_KEY]
        assert json.loads(recorded) == gv._live_test_coverage_inputs()

    def test_the_committed_chart_draws_the_trees_numbers(self, gv: ModuleType) -> None:
        """The real chart, held to the real tree, as ``--check`` does in CI."""
        assert gv._check_rendered_inputs() == []


class TestWiredIntoCI:
    def test_ci_runs_the_check(self) -> None:
        ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        assert "generate_visuals.py --check" in ci, (
            "the visuals check is not wired into ci.yml; without it the "
            "committed PNGs return to rotting silently"
        )


class TestCheckNeedsNoPlottingStack:
    """The CI job that runs ``--check`` installs no matplotlib and no numpy —
    by design: the check is for environments that cannot regenerate.  A bare
    module-level ``import numpy`` broke exactly that job (ModuleNotFoundError
    before argparse ever ran), while every local environment with the stack
    installed called the tool healthy.  These tests run the tool in a real
    subprocess with both imports blocked, the way CI actually runs it.
    """

    @pytest.fixture()
    def blocked_stack(self, tmp_path: Path) -> dict[str, str]:
        for name in ("numpy", "matplotlib"):
            pkg = tmp_path / name
            pkg.mkdir()
            (pkg / "__init__.py").write_text(
                f'raise ImportError("{name} deliberately absent for this test")\n'
            )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(tmp_path)
        return env

    def test_check_passes_without_numpy_or_matplotlib(self, blocked_stack: dict[str, str]) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL_PATH), "--check"],
            capture_output=True,
            text=True,
            env=blocked_stack,
            cwd=REPO_ROOT,
        )
        assert (
            result.returncode == 0
        ), f"--check must work without the plotting stack; stderr:\n{result.stderr}"
        assert "OK" in result.stdout

    def test_render_refuses_politely_without_the_stack(self, blocked_stack: dict[str, str]) -> None:
        """No traceback: the guarded import must turn a missing stack into the
        documented exit-2 message, for the render path too."""
        result = subprocess.run(
            [sys.executable, str(TOOL_PATH)],
            capture_output=True,
            text=True,
            env=blocked_stack,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 2, result.stderr
        assert "matplotlib is required to render" in result.stderr
        assert "Traceback" not in result.stderr
