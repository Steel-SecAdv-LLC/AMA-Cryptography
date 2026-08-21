#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for ``tools/check_type_check_scope.py``.

``ARCHITECTURE.md`` states "type hints throughout (validated via mypy)" and
the CI pipeline summary says "mypy --strict (type checking, 0 errors)".  Until
5.0.0 the type check ran against a hand-written list of paths that left out
roughly a third of the Python in the repository — every chart, dashboard and
comparative generator under ``benchmarks/`` and ``tools/``, both published web
framework examples, ``setup.py``, and ``docs/conf.py``.  ``mypy --strict`` over
those files reported 323 errors in 13 files, among them four
``create_crypto_package(dna_codes=…)`` calls naming a parameter the function
has never had.

The scope is now every tracked ``.py`` file, and this gate is what keeps it
that way: a mypy run's exit status says nothing about what it looked at.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_type_check_scope.py"


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_type_check_scope", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _repo(tmp_path: Path, files: list[str]) -> Path:
    """A throwaway git repo containing ``files``, so ``git ls-files`` has a scope."""
    root = tmp_path / "repo"
    root.mkdir()
    for rel in files:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    return root


def _report(tmp_path: Path, root: Path, files: list[str], pad_to: int = 250) -> Path:
    """A mypy-shaped ``coverage.json`` naming ``files`` (plus filler)."""
    lines: dict[str, list[list[int]]] = {str((root / rel).resolve()): [] for rel in files}
    for i in range(pad_to):
        lines[f"/nonexistent/filler_{i}.py"] = []
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps({"lines": lines}), encoding="utf-8")
    return report


class TestTheShippedTree:
    def test_the_repository_is_fully_covered(self, gate: ModuleType, tmp_path: Path) -> None:
        """The real thing: run mypy over the CI scope and check every file.

        This is the assertion the ARCHITECTURE.md sentence rests on, so it is
        made against a live run rather than a fixture.
        """
        out = tmp_path / "cov"
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "mypy",
                "--strict",
                "--explicit-package-bases",
                "--linecoverage-report",
                str(out),
                "ama_cryptography/",
                "tests/",
                "tools/",
                "benchmarks/",
                "examples/",
                "fuzz/python/",
                "nist_vectors/",
                "schemas/",
                "wycheproof_vectors/",
                "docs/conf.py",
                "setup.py",
                "ama_cryptography_monitor.py",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            env={**__import__("os").environ, "MYPYPATH": "."},
        )
        assert proc.returncode == 0, proc.stdout[-4000:]
        assert gate.audit(out / "coverage.json", REPO_ROOT) == []


class TestTheRule:
    def test_a_fully_covered_tree_passes(self, gate: ModuleType, tmp_path: Path) -> None:
        files = ["pkg/a.py", "pkg/b.py", "top.py"]
        root = _repo(tmp_path, files)
        assert gate.audit(_report(tmp_path, root, files), root) == []

    def test_an_unchecked_file_is_reported(self, gate: ModuleType, tmp_path: Path) -> None:
        """The whole point: tracked, but absent from what mypy analysed."""
        files = ["pkg/a.py", "pkg/b.py", "top.py"]
        root = _repo(tmp_path, files)
        report = _report(tmp_path, root, ["pkg/a.py", "top.py"])
        problems = gate.audit(report, root)
        assert problems and "pkg/b.py" in problems[0], problems

    def test_a_collapsed_report_fails_closed(self, gate: ModuleType, tmp_path: Path) -> None:
        """A report listing almost nothing must not read as full coverage."""
        files = ["pkg/a.py"]
        root = _repo(tmp_path, files)
        report = _report(tmp_path, root, files, pad_to=0)
        problems = gate.audit(report, root)
        assert problems and "collapsed run" in problems[0], problems

    def test_an_unreadable_report_fails_closed(self, gate: ModuleType, tmp_path: Path) -> None:
        root = _repo(tmp_path, ["a.py"])
        missing = tmp_path / "does-not-exist.json"
        problems = gate.audit(missing, root)
        assert problems and "cannot read" in problems[0], problems

    def test_a_report_without_a_lines_map_fails_closed(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        root = _repo(tmp_path, ["a.py"])
        report = tmp_path / "coverage.json"
        report.write_text(json.dumps({"something-else": {}}), encoding="utf-8")
        problems = gate.audit(report, root)
        assert problems and "not a mypy coverage report" in problems[0], problems

    def test_a_tree_with_no_python_fails_closed(self, gate: ModuleType, tmp_path: Path) -> None:
        """No tracked files means no scope, which must not read as success."""
        root = _repo(tmp_path, ["README.md"])
        report = _report(tmp_path, root, [])
        problems = gate.audit(report, root)
        assert problems and "empty scope" in problems[0], problems

    def test_the_exempt_list_is_empty(self, gate: ModuleType) -> None:
        """An exemption is a file whose breakage nobody would see.

        Kept empty deliberately; this test is what makes adding one a visible
        decision rather than a quiet one.
        """
        assert gate.EXEMPT == {}

    def test_the_cli_reports_success(
        self, gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        files = ["pkg/a.py"]
        root = _repo(tmp_path, files)
        report = _report(tmp_path, root, files)
        assert gate.main([str(report), "--root", str(root)]) == 0
        assert "tracked .py file(s) are inside" in capsys.readouterr().out
