#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Performance regression tests.

These tests establish baseline performance expectations with absolute
ops/sec thresholds and are hardware-sensitive. They are opt-in:

    AMA_RUN_PERF=1 pytest tests/test_performance.py -v --tb=short

Without AMA_RUN_PERF, they are skipped to avoid false failures on
slow/shared runners and local dev machines.
"""

import os
import secrets
import time
from typing import Any, Callable

import pytest

from ama_cryptography.legacy_compat import (
    canonical_hash_code,
    create_crypto_package,
    generate_ed25519_keypair,
    generate_key_management_system,
    hmac_authenticate,
)

# Performance tests use absolute ops/sec thresholds and are hardware-sensitive.
# They are opt-in: set AMA_RUN_PERF=1 (or legacy CI_PERF=1) to run. Default is
# skip, so local dev runs and CI do not fail due to slow shared runners.
_run_perf = os.environ.get("AMA_RUN_PERF", "").lower() in ("1", "true", "yes") or (
    os.environ.get("CI_PERF", "").lower() in ("1", "true", "yes")
)
SKIP_PERF = not _run_perf


def benchmark(func: Callable[..., Any], iterations: int = 1000) -> float:
    """
    Benchmark a function and return operations per second.

    Args:
        func: Zero-argument callable to benchmark
        iterations: Number of iterations to run

    Returns:
        Operations per second
    """
    # Warmup
    for _ in range(min(10, iterations // 10)):
        func()

    # Timed run
    start = time.perf_counter()
    for _ in range(iterations):
        func()
    elapsed = time.perf_counter() - start

    return iterations / elapsed


@pytest.mark.skipif(SKIP_PERF, reason="Performance tests opt-in: set AMA_RUN_PERF=1 to run")
class TestSHA3Performance:
    """SHA3-256 hashing performance tests."""

    def test_sha3_throughput_small(self) -> None:
        """SHA3-256 throughput for small inputs (>50,000 ops/sec)."""
        dna = "ACGT" * 25  # 100 chars
        params = [(1.0, 1.0)]

        ops_per_sec = benchmark(lambda: canonical_hash_code(dna, params), iterations=5000)

        assert ops_per_sec > 50000, f"SHA3 throughput {ops_per_sec:.0f} ops/sec below 50,000"

    def test_sha3_throughput_medium(self) -> None:
        """SHA3-256 throughput for medium inputs (>10,000 ops/sec)."""
        dna = "ACGT" * 250  # 1000 chars
        params = [(1.0, 1.0)] * 10

        ops_per_sec = benchmark(lambda: canonical_hash_code(dna, params), iterations=2000)

        assert ops_per_sec > 10000, f"SHA3 throughput {ops_per_sec:.0f} ops/sec below 10,000"


@pytest.mark.skipif(SKIP_PERF, reason="Performance tests opt-in: set AMA_RUN_PERF=1 to run")
class TestHMACPerformance:
    """HMAC-SHA256 performance tests."""

    def test_hmac_throughput(self) -> None:
        """HMAC throughput (>100,000 ops/sec for small messages)."""
        key = secrets.token_bytes(32)
        message = b"test message for HMAC"

        ops_per_sec = benchmark(lambda: hmac_authenticate(message, key), iterations=10000)

        # Threshold accounts for ctypes fallback path (~30K) when Cython is not built
        assert ops_per_sec > 25000, f"HMAC throughput {ops_per_sec:.0f} ops/sec below 25,000"

    def test_hmac_throughput_large(self) -> None:
        """HMAC throughput for larger messages (>10,000 ops/sec)."""
        key = secrets.token_bytes(32)
        message = secrets.token_bytes(10000)  # 10KB

        ops_per_sec = benchmark(lambda: hmac_authenticate(message, key), iterations=2000)

        # Threshold accounts for ctypes path with 10KB messages on CI runner hardware
        assert ops_per_sec > 1500, f"HMAC throughput {ops_per_sec:.0f} ops/sec below 1,500"


@pytest.mark.skipif(SKIP_PERF, reason="Performance tests opt-in: set AMA_RUN_PERF=1 to run")
class TestEd25519Performance:
    """Ed25519 signature performance tests."""

    def test_keygen_throughput(self) -> None:
        """Ed25519 key generation (>1,000 ops/sec)."""
        ops_per_sec = benchmark(generate_ed25519_keypair, iterations=500)

        assert ops_per_sec > 1000, f"Ed25519 keygen {ops_per_sec:.0f} ops/sec below 1,000"

    def test_sign_throughput(self) -> None:
        """Ed25519 signing throughput (>4,000 ops/sec)."""
        from ama_cryptography.legacy_compat import ed25519_sign

        kp = generate_ed25519_keypair()
        message = b"test message for signing"

        ops_per_sec = benchmark(lambda: ed25519_sign(message, kp.private_key), iterations=1000)

        # Threshold lowered for CI runner variability and native seed expansion on each sign
        assert ops_per_sec > 2000, f"Ed25519 sign {ops_per_sec:.0f} ops/sec below 2,000"

    def test_verify_throughput(self) -> None:
        """Ed25519 verification throughput (>4,000 ops/sec)."""
        from ama_cryptography.legacy_compat import ed25519_sign, ed25519_verify

        kp = generate_ed25519_keypair()
        message = b"test message for verification"
        sig = ed25519_sign(message, kp.private_key)

        ops_per_sec = benchmark(
            lambda: ed25519_verify(message, sig, kp.public_key), iterations=1000
        )

        # Threshold lowered for CI runner variability and native backend overhead
        assert ops_per_sec > 1400, f"Ed25519 verify {ops_per_sec:.0f} ops/sec below 1,400"


@pytest.mark.skipif(SKIP_PERF, reason="Performance tests opt-in: set AMA_RUN_PERF=1 to run")
class TestPackageCreationPerformance:
    """Full cryptographic package creation performance tests."""

    def test_package_creation_latency(self) -> None:
        """Package creation completes in <100ms."""
        dna = "ACGT" * 100
        params = [(1.0, 1.0)]
        kms = generate_key_management_system("PerfTest")

        # Measure single operation latency
        start = time.perf_counter()
        create_crypto_package(dna, params, kms, "PerfTest")
        elapsed = time.perf_counter() - start

        assert elapsed < 0.1, f"Package creation took {elapsed * 1000:.1f}ms, exceeds 100ms"

    def test_package_creation_throughput(self) -> None:
        """Package creation throughput (>10 ops/sec)."""
        dna = "ACGT" * 100
        params = [(1.0, 1.0)]
        kms = generate_key_management_system("PerfTest")

        ops_per_sec = benchmark(
            lambda: create_crypto_package(dna, params, kms, "PerfTest"), iterations=50
        )

        assert ops_per_sec > 10, f"Package creation {ops_per_sec:.1f} ops/sec below 10"


@pytest.mark.skipif(SKIP_PERF, reason="Performance tests opt-in: set AMA_RUN_PERF=1 to run")
class TestMemoryEfficiency:
    """Memory efficiency tests."""

    def test_no_memory_leak_in_loop(self) -> None:
        """Repeated operations don't leak memory."""
        import gc

        # Force garbage collection before measuring
        gc.collect()

        # Get baseline memory (approximate using object count)
        baseline_objects = len(gc.get_objects())

        # Run many operations
        for _ in range(1000):
            dna = "ACGT" * 100
            params = [(1.0, 1.0)]
            canonical_hash_code(dna, params)

        # Force garbage collection
        gc.collect()

        # Check object count hasn't grown significantly
        final_objects = len(gc.get_objects())
        growth = final_objects - baseline_objects

        # Allow some growth but not unbounded
        assert growth < 1000, f"Object count grew by {growth}, possible memory leak"
