# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A validation run that measured almost nothing must not look like a pass.

``benchmarks/validation_suite.py``'s verdict was ``passed == total`` over
``self.results`` — and every measurement block except ``master_secret_gen``
sat inside a try/except whose SKIP arm only printed, appending nothing to
``self.results``.  On a build without the native backend the suite validated
1-2 of its documented claims, printed ``Pass rate: 100.0%`` and ``All
benchmark claims validated successfully!``, and exited 0.  Seven documented
claims (``full_kms`` and all of Section 1.3 among them) had no measurement
block at all, so even a fully-featured run silently validated 11 of 18.

These tests pin the repair from three directions:

* the coverage accounting itself (``unmeasured_claims`` /
  ``record_skip`` / ``ON_DEMAND_CLAIMS``),
* the verdict: an incomplete run never prints the all-clear, and fails
  outright under ``--require-complete``,
* the suite's own completeness: a real (short-iteration) run measures every
  documented claim that is not exempt-by-design, so a future claim added to
  ``documented_claims`` without a measurement block fails here instead of
  silently deflating the denominator again.

Every SKIP print is also required to record the claims it forfeits, so no
new skip path can reopen the print-only hole.
"""

from __future__ import annotations

import ast
import importlib.util
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Iterator

import pytest

import benchmarks.validation_suite as vs

REPO_ROOT = Path(__file__).resolve().parent.parent
SUITE_PATH = REPO_ROOT / "benchmarks" / "validation_suite.py"


@pytest.fixture
def sandboxed_suite(tmp_path: Path) -> Iterator[ModuleType]:
    """The suite loaded from a copy in ``tmp_path``.

    ``main()`` writes ``validation_report.md`` / ``validation_results.json``
    next to ``__file__``, so tests that call it must not run the module from
    ``benchmarks/`` or they would write artifacts into the working tree.
    The copy's ``sys.path.insert`` of its parent's parent is undone on
    teardown.
    """
    dst = tmp_path / "validation_suite_under_test.py"
    shutil.copy(SUITE_PATH, dst)
    spec = importlib.util.spec_from_file_location("validation_suite_under_test", dst)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    path_before = list(sys.path)
    try:
        spec.loader.exec_module(mod)
        yield mod
    finally:
        sys.path[:] = path_before
        sys.modules.pop("validation_suite_under_test", None)


class TestCoverageAccounting:
    def test_a_fresh_validator_reports_every_non_exempt_claim_unmeasured(self) -> None:
        v = vs.BenchmarkValidator(iterations=1, warmup=0)
        unmeasured = v.unmeasured_claims()
        assert set(unmeasured) == set(v.documented_claims) - vs.ON_DEMAND_CLAIMS
        # A claim nothing attempted carries the coverage-hole diagnostic,
        # not a skip reason.
        assert "no measurement block" in unmeasured["full_kms"]

    def test_a_recorded_skip_carries_its_reason_and_a_measurement_clears_it(self) -> None:
        v = vs.BenchmarkValidator(iterations=1, warmup=0)
        v.record_skip("native Ed25519 not available", "ed25519_sign", "ed25519_verify")
        unmeasured = v.unmeasured_claims()
        assert unmeasured["ed25519_sign"] == "native Ed25519 not available"
        assert unmeasured["ed25519_verify"] == "native Ed25519 not available"

        v.validate_claim("ed25519_sign", 0.001)
        assert "ed25519_sign" not in v.unmeasured_claims()
        assert "ed25519_verify" in v.unmeasured_claims()

    def test_exempt_claims_are_documented_and_only_the_on_demand_one(self) -> None:
        v = vs.BenchmarkValidator(iterations=1, warmup=0)
        # The exemption list must stay a subset of the documented claims —
        # an entry that drifts out of documented_claims would be a silent
        # no-op — and must not grow into a general escape hatch: pattern
        # analysis is the only operation the library runs on-demand rather
        # than per-operation.
        assert vs.ON_DEMAND_CLAIMS <= set(v.documented_claims)
        assert vs.ON_DEMAND_CLAIMS == {"pattern_analysis_overhead"}


class TestVerdict:
    """The exit-0-measured-nothing failure mode, replayed against main()."""

    @staticmethod
    def _stub_runs(mod: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
        """Reproduce the historic near-empty run: one passing measured row."""

        def one_row(self: object) -> None:
            assert isinstance(self, mod.BenchmarkValidator)
            self.validate_claim("master_secret_gen", 0.001)

        def nothing(self: object) -> None:
            pass

        monkeypatch.setattr(mod.BenchmarkValidator, "run_key_generation_benchmarks", one_row)
        monkeypatch.setattr(mod.BenchmarkValidator, "run_crypto_operation_benchmarks", nothing)
        monkeypatch.setattr(mod.BenchmarkValidator, "run_package_operation_benchmarks", nothing)
        monkeypatch.setattr(mod.BenchmarkValidator, "run_3r_monitoring_benchmarks", nothing)

    def test_require_complete_fails_a_run_with_unmeasured_claims(
        self,
        sandboxed_suite: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._stub_runs(sandboxed_suite, monkeypatch)
        assert sandboxed_suite.main(["--require-complete"]) == 1

    def test_an_incomplete_run_never_prints_the_all_clear(
        self,
        sandboxed_suite: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        self._stub_runs(sandboxed_suite, monkeypatch)
        # Without the flag the exit code still reflects the measured rows —
        # but the historic lie is gone: the run names each claim it did not
        # measure and withholds the success banner.
        assert sandboxed_suite.main([]) == 0
        out = capsys.readouterr().out
        assert "validated successfully" not in out
        assert "produced no measurement" in out
        assert "dilithium_sign" in out
        assert "package_verification" in out

    def test_a_complete_passing_run_still_exits_zero_under_the_flag(
        self,
        sandboxed_suite: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def all_rows(self: object) -> None:
            assert isinstance(self, sandboxed_suite.BenchmarkValidator)
            for name in self.documented_claims:
                if name not in sandboxed_suite.ON_DEMAND_CLAIMS:
                    self.validate_claim(name, 0.0)

        def nothing(self: object) -> None:
            pass

        mod = sandboxed_suite
        monkeypatch.setattr(mod.BenchmarkValidator, "run_key_generation_benchmarks", all_rows)
        monkeypatch.setattr(mod.BenchmarkValidator, "run_crypto_operation_benchmarks", nothing)
        monkeypatch.setattr(mod.BenchmarkValidator, "run_package_operation_benchmarks", nothing)
        monkeypatch.setattr(mod.BenchmarkValidator, "run_3r_monitoring_benchmarks", nothing)
        assert mod.main(["--require-complete"]) == 0


class TestSuiteCompleteness:
    def test_a_real_run_measures_every_non_exempt_documented_claim(
        self,
        sandboxed_suite: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Run the actual measurement blocks (tiny iteration counts).

        This is the forward-looking pin: a claim added to
        ``documented_claims`` without a measurement block reappears in
        ``unmeasured_claims()`` and fails here.  Pass/fail of the individual
        rows is deliberately not asserted — at 3 iterations the timings are
        noise — coverage is the property under test.
        """
        mod = sandboxed_suite
        instances: list[Any] = []
        real_validator = mod.BenchmarkValidator

        def capturing(iterations: int = 1000, warmup: int = 100) -> Any:
            v = real_validator(iterations=3, warmup=1)
            instances.append(v)
            return v

        monkeypatch.setattr(mod, "BenchmarkValidator", capturing)
        exit_code = mod.main([])
        assert exit_code in (0, 1)  # row noise may fail; coverage may not
        (validator,) = instances
        assert validator.unmeasured_claims() == {}


class TestNoPrintOnlySkips:
    def test_every_skip_print_sits_beside_a_record_skip_call(self) -> None:
        """No SKIP arm may report to stdout without recording the forfeit.

        The historic defect was precisely a print-only SKIP: the claim
        vanished from the verdict's denominator.  Every statement block that
        prints ``SKIP:`` must call ``self.record_skip`` in that same block,
        so the checked granularity is the smallest enclosing block (an
        ``except`` body, an ``if`` body), not the whole function.
        """
        tree = ast.parse(SUITE_PATH.read_text(encoding="utf-8"))

        offenders: list[int] = []
        for block in ast.walk(tree):
            for field in ("body", "orelse", "finalbody"):
                stmts = getattr(block, field, None)
                if not isinstance(stmts, list):
                    continue
                has_skip_print = False
                has_record = False
                skip_line = 0
                for stmt in stmts:
                    for node in ast.walk(stmt):
                        if not isinstance(node, ast.Call):
                            continue
                        if isinstance(node.func, ast.Name) and node.func.id == "print":
                            # f-string parts are Constant nodes inside the
                            # JoinedStr, so ast.walk sees them either way.
                            for const in ast.walk(node):
                                if (
                                    isinstance(const, ast.Constant)
                                    and isinstance(const.value, str)
                                    and "SKIP:" in const.value
                                ):
                                    has_skip_print = True
                                    skip_line = node.lineno
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "record_skip":
                            has_record = True
                if has_skip_print and not has_record:
                    offenders.append(skip_line)

        assert offenders == [], (
            f"print-only SKIP arms at lines {offenders} of validation_suite.py: "
            "each SKIP must call self.record_skip(...) in the same statement "
            "block, or its claims silently leave the verdict's denominator "
            "again (the exit-0-measured-nothing defect)."
        )
