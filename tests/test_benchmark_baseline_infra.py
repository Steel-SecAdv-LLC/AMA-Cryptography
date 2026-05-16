#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
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
