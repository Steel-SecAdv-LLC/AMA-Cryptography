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
import re
import sys
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
        monkeypatch.setattr(gv, "MANIFEST_PATH", self._manifest_with(gv, tmp_path))
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


class TestWiredIntoCI:
    def test_ci_runs_the_check(self) -> None:
        ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        assert "generate_visuals.py --check" in ci, (
            "the visuals check is not wired into ci.yml; without it the "
            "committed PNGs return to rotting silently"
        )
