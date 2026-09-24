# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The competitive harnesses' provenance names the build that was measured.

``benchmarks/comparative_benchmark.py`` stamped every result file with
``git rev-parse HEAD`` of the working tree, run with ``check=True`` AFTER the
benchmarks:

* on a host without git, or from an sdist or ``git archive`` export, the
  ``CalledProcessError`` (or ``FileNotFoundError``) arrived after minutes of
  measuring and no results file was written;
* with an installed wheel from another commit imported, the file was stamped
  with the checkout's HEAD anyway, and ``generate_competitive.py`` then
  published "Measured at commit <HEAD>" over another build's numbers -- the
  relabelling the provenance block was added to prevent;
* nothing recorded whether the measured code carried uncommitted changes.

``pqc_comparative_bench.py`` shared the function and called it inside the
``json.dump`` argument, after ``open(out, "w")`` had truncated its own
tracked output.  These tests pin the repair on both harnesses and on the
page generator that consumes the block.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import ama_cryptography
import benchmarks.comparative_benchmark as cb

REPO_ROOT = Path(__file__).resolve().parent.parent
HEAD = "a" * 40


def _fake_git(monkeypatch: pytest.MonkeyPatch, *, toplevel: str | None, status: str = "") -> None:
    answers: dict[str, str | None] = {
        "--show-toplevel": None if toplevel is None else toplevel + "\n",
        "HEAD": None if toplevel is None else HEAD + "\n",
        "--porcelain": None if toplevel is None else status,
    }

    def fake(*args: str, cwd: Path) -> str | None:
        for key, value in answers.items():
            if key in args:
                return value
        raise AssertionError(f"unexpected git query {args}")

    monkeypatch.setattr(cb, "_git_stdout", fake)


class TestTheBlockNamesOnlyWhatItCanShow:
    def test_a_clean_checkout_that_is_the_imported_build_is_attributed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Non-vacuity: every refusal below could otherwise be a block that never attributes."""
        _fake_git(monkeypatch, toplevel=str(REPO_ROOT))
        block = cb._measurement_provenance()
        assert block["attributable"] is True
        assert block["ama_commit"] == HEAD
        assert block["ama_version"] == ama_cryptography.__version__
        assert block["tree_dirty"] is False
        assert "unattributable_because" not in block

    def test_a_host_without_git_still_produces_a_block(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Real subprocess, no git on PATH: the old code raised here, after the run."""
        monkeypatch.setenv("PATH", str(tmp_path))
        block = cb._measurement_provenance()
        assert block["attributable"] is False
        assert block["ama_commit"] == "unknown"
        assert any("git" in reason for reason in block["unattributable_because"])

    def test_an_imported_build_outside_the_checkout_is_not_stamped_with_its_head(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _fake_git(monkeypatch, toplevel=str(REPO_ROOT))
        elsewhere = tmp_path / "site-packages" / "ama_cryptography" / "__init__.py"
        monkeypatch.setattr(ama_cryptography, "__file__", str(elsewhere))
        block = cb._measurement_provenance()
        assert block["attributable"] is False
        assert (
            block["ama_commit"] == "unknown"
        ), "the checkout's HEAD does not name a build imported from outside it"
        assert any("outside the checkout" in r for r in block["unattributable_because"])

    def test_uncommitted_changes_to_the_measured_code_are_unattributable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _fake_git(monkeypatch, toplevel=str(REPO_ROOT), status=" M src/c/ama_sha3.c\n")
        block = cb._measurement_provenance()
        assert block["attributable"] is False
        assert block["ama_commit"] == "unknown"
        assert block["dirty_paths"] == ["src/c/ama_sha3.c"]

    def test_unrelated_dirt_is_recorded_without_disowning_the_run(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An earlier run's output is not a change to the measured build."""
        _fake_git(monkeypatch, toplevel=str(REPO_ROOT), status=" M benchmarks/pqc_results.json\n")
        block = cb._measurement_provenance()
        assert block["attributable"] is True
        assert block["ama_commit"] == HEAD
        assert block["tree_dirty"] is True
        assert block["dirty_paths"] == ["benchmarks/pqc_results.json"]


class TestProvenanceIsTakenBeforeMeasuring:
    def test_comparative_benchmark(self, monkeypatch: pytest.MonkeyPatch) -> None:
        order: list[str] = []
        block = {"attributable": True, "ama_commit": HEAD}

        def provenance() -> dict[str, Any]:
            order.append("provenance")
            return block

        monkeypatch.setattr(cb, "_measurement_provenance", provenance)
        for method in (
            "benchmark_ama_raw_c",
            "benchmark_ama_cryptography",
            "benchmark_libsodium_ed25519",
            "benchmark_cryptography_ed25519",
            "benchmark_aes_gcm_comparison",
        ):
            monkeypatch.setattr(
                cb.ComparativeBenchmark,
                method,
                lambda self, _m=method: order.append(_m),
            )
        saved: list[Any] = []

        def save_results(
            self: object, filename: str = "x", provenance: Any = None
        ) -> dict[str, Any]:
            saved.append(provenance)
            return {}

        monkeypatch.setattr(cb.ComparativeBenchmark, "save_results", save_results)
        cb.main()
        assert order[0] == "provenance", f"provenance was taken after measuring: {order}"
        assert saved == [block], "the block taken before the run is the one saved"

    def test_pqc_comparative_bench(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        spec = importlib.util.spec_from_file_location(
            "pqc_comparative_bench_under_test",
            REPO_ROOT / "benchmarks" / "pqc_comparative_bench.py",
        )
        assert spec is not None and spec.loader is not None
        mod: ModuleType = importlib.util.module_from_spec(spec)
        path_before = list(sys.path)
        try:
            spec.loader.exec_module(mod)
            order: list[str] = []
            block = {"attributable": True, "ama_commit": HEAD}

            def provenance() -> dict[str, Any]:
                order.append("provenance")
                return block

            monkeypatch.setattr(mod, "_harness_provenance", provenance, raising=False)
            monkeypatch.setattr(mod, "bench", lambda *a, **k: order.append("bench"))
            monkeypatch.chdir(tmp_path)
            mod.main()
            assert order and order[0] == "provenance", f"measured before provenance: {order}"
            written = json.loads((tmp_path / "pqc_results.json").read_text(encoding="utf-8"))
            assert written["provenance"] == block
        finally:
            sys.path[:] = path_before


class TestThePageRefusesAnUnattributableRun:
    @staticmethod
    def _load() -> ModuleType:
        spec = importlib.util.spec_from_file_location(
            "generate_competitive_under_test", REPO_ROOT / "benchmarks" / "generate_competitive.py"
        )
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    @staticmethod
    def _write(directory: Path, provenance: dict[str, Any]) -> None:
        for name in ("multi_library_results.json", "pqc_results.json"):
            (directory / name).write_text(json.dumps({"provenance": provenance}), encoding="utf-8")

    def test_two_unknown_commits_agree_but_are_still_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        gc = self._load()
        self._write(
            tmp_path,
            {
                "ama_commit": "unknown",
                "ama_version": "5.0.0",
                "attributable": False,
                "unattributable_because": ["git could not describe the checkout"],
            },
        )
        monkeypatch.setattr(gc, "BENCH", tmp_path)
        with pytest.raises(RuntimeError, match="unattributable"):
            gc._source_provenance()

    def test_an_attributed_pair_still_renders(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        gc = self._load()
        block = {"ama_commit": HEAD, "ama_version": "5.0.0", "attributable": True}
        self._write(tmp_path, block)
        monkeypatch.setattr(gc, "BENCH", tmp_path)
        assert gc._source_provenance() == block
