#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for benchmark baseline runner-class enforcement."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from benchmarks.benchmark_runner import (
    benchmark_operation_best_of,
    normalize_runner_cpu_class,
    run_full_package_create_benchmark,
    validate_baseline_contract,
)


def _baseline(runner_cpu_class: str = "aarch64", baseline_value: int = 1) -> dict[str, Any]:
    return {
        "metadata": {"runner_cpu_class": runner_cpu_class},
        "benchmarks": {
            "ama_sha3_256_hash": {
                "description": "SHA3-256",
                "baseline_value": baseline_value,
            }
        },
        "pqc_benchmarks": {},
    }


def test_normalize_runner_cpu_class_aliases() -> None:
    """Common architecture spellings collapse to the matrix baseline key."""
    assert normalize_runner_cpu_class("arm64") == "aarch64"
    assert normalize_runner_cpu_class("AMD64") == "x86_64"


def test_validate_baseline_contract_accepts_matching_arm_alias() -> None:
    """A GitHub arm64 runner may consume an aarch64 baseline."""
    validate_baseline_contract(
        _baseline("aarch64"),
        Path("benchmarks/arm-baseline.json"),
        expected_runner_cpu_class="arm64",
    )


def test_validate_baseline_contract_rejects_runner_mismatch() -> None:
    """x86 baselines must not be used on the AArch64 matrix entry."""
    with pytest.raises(ValueError, match="runner_cpu_class"):
        validate_baseline_contract(
            _baseline("x86_64"),
            Path("benchmarks/baseline.json"),
            expected_runner_cpu_class="aarch64",
        )


def test_validate_baseline_contract_rejects_zero_when_required() -> None:
    """Strict baseline publication mode refuses first-run zero placeholders."""
    with pytest.raises(ValueError, match="unpopulated zero baselines"):
        validate_baseline_contract(
            _baseline("aarch64", baseline_value=0),
            Path("benchmarks/arm-baseline.json"),
            expected_runner_cpu_class="aarch64",
            require_populated_baseline=True,
        )


def test_benchmark_operation_best_of_uses_fastest_round(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Latency-spiky composite benchmarks compare steady-state throughput."""

    measurements = iter([10.0, 42.0, 17.0])

    def fake_benchmark_operation(
        operation: Callable[[], object], iterations: int = 100, warmup: int = 5
    ) -> float:
        assert iterations == 20
        assert warmup == 2
        return next(measurements)

    import benchmarks.benchmark_runner as br

    monkeypatch.setattr(br, "benchmark_operation", fake_benchmark_operation)

    assert benchmark_operation_best_of(lambda: None, iterations=20, warmup=2, rounds=3) == 42.0


def test_full_package_create_uses_best_of_rounds(monkeypatch: pytest.MonkeyPatch) -> None:
    """The GC-heavy package-create benchmark samples multiple rounds."""

    calls: list[tuple[int, int, int]] = []

    def fake_best_of(
        operation: Callable[[], object], iterations: int, warmup: int, rounds: int
    ) -> float:
        calls.append((iterations, warmup, rounds))
        return 123.0

    monkeypatch.setattr("benchmarks.benchmark_runner.benchmark_operation_best_of", fake_best_of)

    assert run_full_package_create_benchmark() == 123.0
    assert calls == [(20, 2, 5)]


class TestSampleWindow:
    """Every benchmark must be measured over a window long enough to mean something.

    The per-benchmark ``iterations`` defaults span 20-100 across primitives whose
    costs differ by three orders of magnitude, so they bought very different
    amounts of signal — 20 ML-DSA-65 signatures is roughly 6 ms, and the whole
    19-benchmark suite finished in about 0.4 s on the CI runner. Measured
    directly on an unchanged binary, ``dilithium_sign`` reported 917, 1845 and
    3086 ops/sec on three consecutive runs: a 3.4x spread against a 10%
    regression threshold. These pin the batch sizing that fixes it.
    """

    @staticmethod
    def _virtual_clock(monkeypatch: pytest.MonkeyPatch) -> dict[str, float]:
        """A perf_counter that only advances when the operation says it did.

        Real timing would make these tests flaky for exactly the reason the
        suite is being fixed.

        Patched through the string target rather than ``br.time`` so that
        ``mypy --strict`` does not read it as importing a name the runner
        never re-exported (``no_implicit_reexport``). monkeypatch restores it
        when the test ends.
        """
        clock = {"t": 0.0}
        monkeypatch.setattr("benchmarks.benchmark_runner.time.perf_counter", lambda: clock["t"])
        return clock

    def test_batch_grows_until_the_window_is_reached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A too-small starting batch is grown, not accepted."""
        import benchmarks.benchmark_runner as br

        clock = self._virtual_clock(monkeypatch)
        sizes: list[int] = []
        real_batch = br._timed_batch

        def spy(op: Callable[[], object], n: int) -> tuple[float, float]:
            sizes.append(n)
            return real_batch(op, n)

        monkeypatch.setattr(br, "_timed_batch", spy)

        def op() -> None:
            clock["t"] += 0.001  # 1 ms per op -> 150 needed for a 0.15 s window

        rate = br.benchmark_operation(op, iterations=5, warmup=0, rounds=2)
        assert rate == pytest.approx(1000.0, rel=0.05)
        assert sizes[0] == 5, "should start from the caller's floor"
        assert (
            sizes[-1] >= br._MIN_SAMPLE_SECONDS / 0.001
        ), f"settled batch {sizes[-1]} spans less than _MIN_SAMPLE_SECONDS at 1 ms/op"

    def test_batch_growth_is_capped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An operation too cheap to fill the window cannot run unbounded."""
        import benchmarks.benchmark_runner as br

        clock = self._virtual_clock(monkeypatch)
        sizes: list[int] = []
        real_batch = br._timed_batch

        def spy(op: Callable[[], object], n: int) -> tuple[float, float]:
            sizes.append(n)
            return real_batch(op, n)

        monkeypatch.setattr(br, "_timed_batch", spy)

        def op() -> None:
            clock["t"] += 1e-9  # would need 150M iterations to fill the window

        br.benchmark_operation(op, iterations=1, warmup=0, rounds=1)
        assert max(sizes) <= br._MAX_ITERATIONS

    def test_an_unlucky_slow_batch_does_not_lock_in_a_short_window(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The case that broke the first version of this sizing.

        A batch that is slow because it was unlucky satisfies an
        elapsed-time target with very few iterations. Sizing on elapsed time
        alone therefore accepted a 5-iteration batch and reused it for every
        remaining round. Keying the target off the fastest rate seen recovers,
        because interference can only make an operation look slower.
        """
        import benchmarks.benchmark_runner as br

        clock = self._virtual_clock(monkeypatch)
        sizes: list[int] = []
        real_batch = br._timed_batch

        def spy(op: Callable[[], object], n: int) -> tuple[float, float]:
            sizes.append(n)
            return real_batch(op, n)

        monkeypatch.setattr(br, "_timed_batch", spy)
        calls = {"n": 0}

        def op() -> None:
            calls["n"] += 1
            # The first batch of 5 stalls at 100 ms/op; everything after is 1 ms.
            clock["t"] += 0.1 if calls["n"] <= 5 else 0.001

        rate = br.benchmark_operation(op, iterations=5, warmup=0, rounds=2)
        assert (
            sizes[-1] >= br._MIN_SAMPLE_SECONDS / 0.001
        ), f"settled batch {sizes[-1]} was locked in by the stalled first batch"
        assert rate == pytest.approx(
            1000.0, rel=0.05
        ), "the stalled batch's rate was reported instead of the recovered one"

    def test_reported_rate_is_the_fastest_full_window_round(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Throughput noise is one-sided, so the fastest round is the estimate.

        Fails if the mean is reported: the mean of these rounds is well below
        the fastest.
        """
        import benchmarks.benchmark_runner as br

        self._virtual_clock(monkeypatch)
        rates = iter([500.0, 2000.0, 800.0])
        # Every batch is already full-window, so sizing never intervenes.
        monkeypatch.setattr(br, "_required_batch", lambda rate: 1)
        monkeypatch.setattr(br, "_timed_batch", lambda op, n: (next(rates), 0.2))

        assert br.benchmark_operation(lambda: None, iterations=10, warmup=0, rounds=3) == 2000.0

    def test_a_slow_batch_cannot_shrink_the_target(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sizing keys off the fastest rate seen, not the most recent one.

        With the target derived from the latest batch, one slow reading while
        the batch is still small drops the requirement to almost nothing, and
        that small batch is accepted — reporting the slow rate. Because
        interference is one-sided, the fastest rate seen is the better
        estimate of what the batch must be to fill the window.
        """
        import benchmarks.benchmark_runner as br

        self._virtual_clock(monkeypatch)
        # Fast, then a stall while the batch is still tiny, then fast again.
        rates = iter([1_000.0, 10.0] + [1_000.0] * 40)
        sizes: list[int] = []

        def scripted(op: Callable[[], object], n: int) -> tuple[float, float]:
            sizes.append(n)
            return next(rates), 0.0

        monkeypatch.setattr(br, "_timed_batch", scripted)

        rate = br.benchmark_operation(lambda: None, iterations=1, warmup=0, rounds=1)
        needed = br._required_batch(1_000.0)
        assert sizes[-1] >= needed, (
            f"settled at batch {sizes[-1]}, below the {needed} needed at the "
            f"fastest observed rate — a slow batch shrank the target"
        )
        assert rate == pytest.approx(1_000.0), f"reported the stalled rate ({rate})"

    def test_undersized_batches_cannot_inflate_the_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Baselines are floors, so a lucky short batch must not be reported.

        The first batch is undersized and reports an implausibly high rate.
        It may inform sizing; it must not be the number that ships.
        """
        import benchmarks.benchmark_runner as br

        self._virtual_clock(monkeypatch)
        rates = iter([9_999.0, 1_000.0, 1_000.0])
        monkeypatch.setattr(br, "_required_batch", lambda rate: 50)
        monkeypatch.setattr(br, "_timed_batch", lambda op, n: (next(rates), 0.2))

        rate = br.benchmark_operation(lambda: None, iterations=10, warmup=0, rounds=1)
        assert rate == 1_000.0, f"an undersized batch's {rate} ops/sec reached the report"
