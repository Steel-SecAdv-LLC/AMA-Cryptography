# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A corrupt measurement file must not be charted as though it were a baseline.

``benchmarks/generate_charts.py`` keeps hardcoded baseline tables and overlays
live figures from ``benchmark_results.json`` when that file is present.
``load_live_data`` answered ``None`` for two states a caller cannot tell
apart: "no benchmark has ever run" and "the results file is damaged".  Only
the first is a reason to chart the baselines, and the charts carry no marking
that says which one produced them — so a damaged file silently published the
hardcoded constants as measurements.

That is the substitution this repository's verification rules exist to
prevent, so these pin the two states apart.  The unreachable ``KeyError`` arm
and the uncaught ``OSError`` are covered here too: ``json.load`` cannot raise
the former, and the latter is what actually occurs between ``exists()`` and
``open()``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import benchmarks.generate_charts as gc

#: Environment for a child interpreter with a NON-UTF-8 preferred encoding.
#: Both routes by which CPython would otherwise quietly hand it UTF-8 anyway
#: are disabled: PEP 538 C-locale coercion and PEP 540 UTF-8 mode.
_ASCII_LOCALE = {
    "LC_ALL": "C",
    "LANG": "C",
    "PYTHONCOERCECLOCALE": "0",
    "PYTHONUTF8": "0",
}


def _point(bench_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Aim the module's module-level results path at ``bench_file``."""
    monkeypatch.setattr(gc, "BENCH_FILE", bench_file)


class TestLoadLiveData:
    """The two answers ``load_live_data`` may give, and the one it may not."""

    def test_an_absent_results_file_is_no_data(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No run yet is a legitimate state: the baselines are charted."""
        _point(tmp_path / "benchmark_results.json", monkeypatch)
        assert gc.load_live_data() is None

    def test_a_readable_results_file_is_returned(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The measured figures reach the caller unchanged."""
        payload = {"cryptographic_operations": {"ed25519_sign": {"ops_per_sec": 21_000}}}
        bench = tmp_path / "benchmark_results.json"
        bench.write_text(json.dumps(payload), encoding="utf-8")
        _point(bench, monkeypatch)
        assert gc.load_live_data() == payload

    def test_a_corrupt_results_file_is_not_reported_as_no_data(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Truncated JSON must not read as "nobody has benchmarked yet".

        This is the case that was swallowed.  ``None`` here would draw every
        chart from the hardcoded tables and label them as measurements.
        """
        bench = tmp_path / "benchmark_results.json"
        bench.write_text('{"cryptographic_operations": {', encoding="utf-8")
        _point(bench, monkeypatch)
        with pytest.raises(SystemExit) as excinfo:
            gc.load_live_data()
        assert "benchmark_results.json" in str(excinfo.value)

    def test_undecodable_bytes_are_not_reported_as_no_data(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A file that is not decodable at all is damage, not absence.

        This pins the raise-rather-than-swallow behaviour only.  It says
        nothing about *which* codec is used, because these bytes are invalid
        under UTF-8 and under the ASCII/cp1252 locale defaults alike --
        ``TestTheReadIsUtf8RegardlessOfHostLocale`` is what covers that.
        """
        bench = tmp_path / "benchmark_results.json"
        bench.write_bytes(b"\xff\xfe\x00\x00")
        _point(bench, monkeypatch)
        with pytest.raises(SystemExit):
            gc.load_live_data()

    def test_an_unreadable_path_is_not_reported_as_no_data(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``exists()`` is true and ``open()`` still fails: an OSError.

        The original handler caught ``json.JSONDecodeError`` and ``KeyError``
        — the second of which ``json.load`` cannot raise — and let this one
        propagate uncaught.  A directory is the portable way to make
        ``open()`` fail on a path that exists.
        """
        bench = tmp_path / "benchmark_results.json"
        bench.mkdir()
        _point(bench, monkeypatch)
        with pytest.raises(SystemExit):
            gc.load_live_data()


class TestTheDiagnosticIsActionable:
    """A refusal that does not say what to do just moves the problem."""

    def test_it_names_the_silent_substitution_and_both_remedies(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Re-run, or delete the file to chart the baselines deliberately."""
        bench = tmp_path / "benchmark_results.json"
        bench.write_text("not json", encoding="utf-8")
        _point(bench, monkeypatch)
        with pytest.raises(SystemExit) as excinfo:
            gc.load_live_data()
        message = str(excinfo.value)
        assert "baseline" in message
        assert "Re-run" in message
        assert "remove the file" in message


class TestTheReadIsUtf8RegardlessOfHostLocale:
    """The host locale must not decide how a results file is decoded.

    ``open(BENCH_FILE)`` carried no ``encoding``, so the codec came from the
    interpreter's locale: UTF-8 on the Linux runners, the ANSI codepage on
    windows-latest.  A results file holding any non-ASCII byte therefore read
    back as mojibake on one runner and raised on another, from identical
    bytes.  Mutation-tested: dropping the explicit ``encoding="utf-8"`` does
    not disturb any other test in this file, because this host's preferred
    encoding is already UTF-8 -- which is exactly why the check has to be
    made in a subprocess that does not have one.
    """

    def test_a_non_ascii_results_file_reads_back_unchanged(self, tmp_path: Path) -> None:
        """Same bytes, same parsed value, whatever codec the locale prefers."""
        import os
        import subprocess
        import sys

        repo_root = Path(__file__).resolve().parents[1]
        bench = tmp_path / "benchmark_results.json"
        # A label a real benchmark run can carry, encoded as UTF-8 on disk.
        payload = {"cryptographic_operations": {}, "note": "latence \u00e9lev\u00e9e"}
        bench.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

        program = (
            "import json, sys\n"
            "import benchmarks.generate_charts as gc\n"
            "gc.BENCH_FILE = __import__('pathlib').Path(sys.argv[1])\n"
            "sys.stdout.buffer.write(json.dumps(gc.load_live_data()).encode())\n"
        )
        env = dict(os.environ, PYTHONPATH=str(repo_root), **_ASCII_LOCALE)
        proc = subprocess.run(
            [sys.executable, "-c", program, str(bench)],
            capture_output=True,
            cwd=str(repo_root),
            env=env,
            timeout=120,
        )

        assert proc.returncode == 0, (
            "reading a UTF-8 results file failed under a non-UTF-8 locale: "
            f"{proc.stderr.decode('utf-8', 'replace')[-2000:]}"
        )
        # Compared as a value, not as bytes: a codepage that decodes without
        # raising still produces the wrong string, and that is the failure
        # windows-latest would have shown rather than an exception.
        assert json.loads(proc.stdout.decode("utf-8")) == payload


class TestNoHarnessOverheadInsideATimedThunk:
    """A benchmark that times its own import is measuring the harness.

    ``benchmarks/validation_suite.py``'s SHA3-256 thunk was::

        def sha3_hash() -> bytes:
            from ama_cryptography.pqc_backends import native_sha3_256
            return native_sha3_256(test_data)

    so every iteration re-executed the ``from ... import`` — a sys.modules
    lookup and an attribute bind — inside the timed region.  Measured on one
    host, 200,000 iterations, median of five runs::

        with the import inside : 2147.9 ns/op
        with it hoisted        : 1572.0 ns/op

    575.9 ns, 26.8% of the reported figure, against a documented claim of
    about 2 us.  The row had been rewritten specifically "to measure AMA's
    SHA3, not hashlib", and it was measuring the harness.

    Every other timed thunk in the directory already hoisted its import, so
    the rule below held everywhere except the one place it mattered.  A nested
    function in ``benchmarks/`` is a timed thunk by construction — the drivers
    define one and hand it to ``benchmark_operation`` / ``benchmark`` — so
    "no nested function imports" is the property, stated where it can be
    checked.
    """

    def test_no_nested_function_in_benchmarks_contains_an_import(self) -> None:
        import ast

        benchmarks_dir = Path(__file__).resolve().parent.parent / "benchmarks"
        offenders: list[str] = []
        for path in sorted(benchmarks_dir.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for outer in ast.walk(tree):
                if not isinstance(outer, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for node in ast.walk(outer):
                    if node is outer:
                        continue
                    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    for inner in ast.walk(node):
                        if isinstance(inner, (ast.Import, ast.ImportFrom)):
                            offenders.append(f"{path.name}:{inner.lineno} inside {node.name}()")

        assert not offenders, (
            "these nested functions import inside what is almost certainly a timed "
            f"thunk, so the reported figure includes the import: {offenders}. Hoist "
            "the import into the enclosing driver — measured at 26.8% of the "
            "reported number the last time this happened."
        )
