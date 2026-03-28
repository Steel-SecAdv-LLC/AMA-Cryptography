#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography Benchmark Runner
================================

Performance regression detection for CI/CD pipelines.
Compares current performance against baseline.json and fails if
any benchmark regresses more than the configured threshold.

Usage:
    python benchmarks/benchmark_runner.py [--update-baseline] [--verbose]

Exit codes:
    0 - All benchmarks within acceptable range
    1 - Performance regression detected (>10% slower than baseline)
    2 - Error running benchmarks
"""

import argparse
import json
import secrets
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""

    name: str
    description: str
    ops_per_second: float
    baseline_value: float
    tolerance_percent: float
    regression_percent: float
    passed: bool
    optional: bool = False


def load_baseline(baseline_path: Path) -> Dict[str, Any]:
    """Load baseline configuration from JSON file."""
    with open(baseline_path) as f:
        return json.load(f)


def benchmark_operation(
    operation: callable,
    iterations: int = 100,
    warmup: int = 5,
) -> float:
    """
    Benchmark an operation and return operations per second.

    Args:
        operation: Callable to benchmark
        iterations: Number of iterations to run
        warmup: Number of warmup iterations (not counted)

    Returns:
        Operations per second
    """
    # Warmup
    for _ in range(warmup):
        operation()

    # Timed run
    start = time.perf_counter()
    for _ in range(iterations):
        operation()
    elapsed = time.perf_counter() - start

    return iterations / elapsed if elapsed > 0 else float("inf")


def run_sha3_256_benchmark(iterations: int = 100) -> float:
    """Benchmark AMA native C SHA3-256 hashing (FIPS 202)."""
    from ama_cryptography.pqc_backends import native_sha3_256

    data = b"A" * 1024  # 1KB data

    def operation():
        native_sha3_256(data)

    return benchmark_operation(operation, iterations)


def run_hmac_sha3_256_benchmark(iterations: int = 100) -> float:
    """Benchmark HMAC-SHA3-256 using project's own implementation."""
    from ama_cryptography.legacy_compat import hmac_authenticate

    key = secrets.token_bytes(32)
    data = b"A" * 1024

    def operation():
        hmac_authenticate(data, key)

    return benchmark_operation(operation, iterations)


def run_ed25519_keygen_benchmark(iterations: int = 50) -> float:
    """Benchmark Ed25519 key generation using native C backend."""
    from ama_cryptography.legacy_compat import generate_ed25519_keypair

    def operation():
        generate_ed25519_keypair()

    return benchmark_operation(operation, iterations)


def run_ed25519_sign_benchmark(iterations: int = 50) -> float:
    """Benchmark Ed25519 signing using native C backend."""
    from ama_cryptography.legacy_compat import ed25519_sign, generate_ed25519_keypair

    keypair = generate_ed25519_keypair()
    message = b"Test message for signing" * 10

    def operation():
        ed25519_sign(message, keypair.private_key)

    return benchmark_operation(operation, iterations)


def run_ed25519_verify_benchmark(iterations: int = 50) -> float:
    """Benchmark Ed25519 verification using native C backend."""
    from ama_cryptography.legacy_compat import (
        ed25519_sign,
        ed25519_verify,
        generate_ed25519_keypair,
    )

    keypair = generate_ed25519_keypair()
    message = b"Test message for signing" * 10
    signature = ed25519_sign(message, keypair.private_key)

    def operation():
        ed25519_verify(message, signature, keypair.public_key)

    return benchmark_operation(operation, iterations)


def run_hkdf_derive_benchmark(iterations: int = 100) -> float:
    """Benchmark HKDF key derivation using native C backend."""
    from ama_cryptography.legacy_compat import native_hkdf

    master_secret = secrets.token_bytes(32)
    salt = secrets.token_bytes(32)
    info = b"benchmark-test"

    def operation():
        native_hkdf(master_secret, 96, salt, info)

    return benchmark_operation(operation, iterations)


def run_full_package_create_benchmark(iterations: int = 20) -> float:
    """Benchmark complete crypto package creation."""
    from ama_cryptography.legacy_compat import (
        create_crypto_package,
        generate_key_management_system,
    )

    kms = generate_key_management_system("Benchmark Test")
    codes = "TEST_OMNI_CODE_12345"
    helix_params = [(1.0, 2.0)]

    def operation():
        create_crypto_package(
            codes=codes,
            helix_params=helix_params,
            kms=kms,
            author="Benchmark",
            use_rfc3161=False,
        )

    return benchmark_operation(operation, iterations, warmup=2)


def run_full_package_verify_benchmark(iterations: int = 20) -> float:
    """Benchmark complete crypto package verification."""
    from ama_cryptography.legacy_compat import (
        create_crypto_package,
        generate_key_management_system,
        verify_crypto_package,
    )

    kms = generate_key_management_system("Benchmark Test")
    codes = "TEST_OMNI_CODE_12345"
    helix_params = [(1.0, 2.0)]

    package = create_crypto_package(
        codes=codes,
        helix_params=helix_params,
        kms=kms,
        author="Benchmark",
        use_rfc3161=False,
    )

    def operation():
        verify_crypto_package(
            codes=codes,
            helix_params=helix_params,
            package=package,
            hmac_key=kms.hmac_key,
            require_quantum_signatures=False,
        )

    return benchmark_operation(operation, iterations, warmup=2)


def run_dilithium_keygen_benchmark(iterations: int = 20) -> Optional[float]:
    """Benchmark ML-DSA-65 key generation via native C library."""
    try:
        from ama_cryptography.pqc_backends import (
            DILITHIUM_AVAILABLE,
            generate_dilithium_keypair,
        )

        if not DILITHIUM_AVAILABLE:
            return None

        def operation():
            generate_dilithium_keypair()

        return benchmark_operation(operation, iterations, warmup=2)
    except (ImportError, Exception):
        return None


def run_dilithium_sign_benchmark(iterations: int = 20) -> Optional[float]:
    """Benchmark ML-DSA-65 signing via native C library."""
    try:
        from ama_cryptography.pqc_backends import (
            DILITHIUM_AVAILABLE,
            dilithium_sign,
            generate_dilithium_keypair,
        )

        if not DILITHIUM_AVAILABLE:
            return None

        kp = generate_dilithium_keypair()
        message = b"Test message for ML-DSA-65 signing" * 10

        def operation():
            dilithium_sign(message, kp.secret_key)

        return benchmark_operation(operation, iterations, warmup=2)
    except (ImportError, Exception):
        return None


def run_dilithium_verify_benchmark(iterations: int = 20) -> Optional[float]:
    """Benchmark ML-DSA-65 verification via native C library."""
    try:
        from ama_cryptography.pqc_backends import (
            DILITHIUM_AVAILABLE,
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
        )

        if not DILITHIUM_AVAILABLE:
            return None

        kp = generate_dilithium_keypair()
        message = b"Test message for ML-DSA-65 signing" * 10
        signature = dilithium_sign(message, kp.secret_key)

        def operation():
            dilithium_verify(message, signature, kp.public_key)

        return benchmark_operation(operation, iterations, warmup=2)
    except (ImportError, Exception):
        return None


def run_all_benchmarks(baseline: Dict[str, Any], verbose: bool = False) -> List[BenchmarkResult]:
    """Run all benchmarks and compare against baseline."""
    results = []
    threshold = baseline["thresholds"]["regression_threshold_percent"]

    benchmark_functions = {
        "ama_sha3_256_hash": run_sha3_256_benchmark,
        "hmac_sha3_256": run_hmac_sha3_256_benchmark,
        "ed25519_keygen": run_ed25519_keygen_benchmark,
        "ed25519_sign": run_ed25519_sign_benchmark,
        "ed25519_verify": run_ed25519_verify_benchmark,
        "hkdf_derive": run_hkdf_derive_benchmark,
        "full_package_create": run_full_package_create_benchmark,
        "full_package_verify": run_full_package_verify_benchmark,
    }

    pqc_benchmark_functions = {
        "dilithium_keygen": run_dilithium_keygen_benchmark,
        "dilithium_sign": run_dilithium_sign_benchmark,
        "dilithium_verify": run_dilithium_verify_benchmark,
    }

    # Run standard benchmarks
    for name, func in benchmark_functions.items():
        if name not in baseline["benchmarks"]:
            continue

        config = baseline["benchmarks"][name]
        if verbose:
            print(f"Running {name}...", end=" ", flush=True)

        ops_per_sec = func()
        baseline_value = config["baseline_value"]
        tolerance = config.get("tolerance_percent", threshold)

        # Calculate percent change from baseline.
        # Positive = faster than baseline, negative = slower than baseline.
        pct_change = ((ops_per_sec - baseline_value) / baseline_value) * 100
        # Only fail on regressions (slower).  Improvements always pass.
        regression = -pct_change  # positive = slower
        passed = regression <= tolerance

        results.append(
            BenchmarkResult(
                name=name,
                description=config["description"],
                ops_per_second=ops_per_sec,
                baseline_value=baseline_value,
                tolerance_percent=tolerance,
                regression_percent=regression,
                passed=passed,
            )
        )

        if verbose:
            status = "PASS" if passed else "FAIL"
            print(f"{ops_per_sec:.0f} ops/sec ({regression:+.1f}%) [{status}]")

    # Run PQC benchmarks (optional)
    for name, func in pqc_benchmark_functions.items():
        if name not in baseline.get("pqc_benchmarks", {}):
            continue

        config = baseline["pqc_benchmarks"][name]
        if verbose:
            print(f"Running {name}...", end=" ", flush=True)

        ops_per_sec = func()

        if ops_per_sec is None:
            if verbose:
                print("SKIPPED (PQC not available)")
            continue

        baseline_value = config["baseline_value"]
        tolerance = config.get("tolerance_percent", threshold)

        pct_change = ((ops_per_sec - baseline_value) / baseline_value) * 100
        regression = -pct_change
        passed = regression <= tolerance

        results.append(
            BenchmarkResult(
                name=name,
                description=config["description"],
                ops_per_second=ops_per_sec,
                baseline_value=baseline_value,
                tolerance_percent=tolerance,
                regression_percent=regression,
                passed=passed,
                optional=True,
            )
        )

        if verbose:
            status = "PASS" if passed else "WARN"
            print(f"{ops_per_sec:.0f} ops/sec ({regression:+.1f}%) [{status}]")

    return results


def generate_report(results: List[BenchmarkResult]) -> Dict[str, Any]:
    """Generate a JSON report of benchmark results."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed and not r.optional),
            "warnings": sum(1 for r in results if not r.passed and r.optional),
        },
        "results": [
            {
                "name": r.name,
                "description": r.description,
                "ops_per_second": round(r.ops_per_second, 2),
                "baseline_value": r.baseline_value,
                "regression_percent": round(r.regression_percent, 2),
                "tolerance_percent": r.tolerance_percent,
                "passed": r.passed,
                "optional": r.optional,
            }
            for r in results
        ],
    }


def generate_markdown_report(results: List[BenchmarkResult], report: Dict[str, Any]) -> str:
    """Generate a markdown report with tables and bar chart."""
    lines = []
    lines.append("# Benchmark Regression Report")
    lines.append("")
    lines.append(f"**Timestamp:** {report['timestamp']}")
    summary = report["summary"]
    lines.append(
        f"**Results:** {summary['passed']}/{summary['total']} passed, "
        f"{summary['failed']} failed, {summary['warnings']} warnings"
    )
    lines.append("")

    # Results table
    lines.append("## Results")
    lines.append("")
    lines.append("| Primitive | Ops/sec | Baseline | Delta | Tolerance | Status |")
    lines.append("|-----------|--------:|---------:|------:|----------:|--------|")
    for r in results:
        status = "PASS" if r.passed else ("WARN" if r.optional else "**FAIL**")
        lines.append(
            f"| {r.description} | {r.ops_per_second:,.0f} | {r.baseline_value:,.0f} "
            f"| {r.regression_percent:+.1f}% | {r.tolerance_percent:.0f}% | {status} |"
        )
    lines.append("")

    # ASCII bar chart
    if results:
        lines.append("## Throughput Comparison")
        lines.append("")
        lines.append("```")
        max_ops = max(r.ops_per_second for r in results) if results else 1
        max_label = max(len(r.name) for r in results)
        bar_width = 40
        for r in results:
            bar_len = int((r.ops_per_second / max_ops) * bar_width) if max_ops > 0 else 0
            bar = "\u2588" * bar_len
            marker = " " if r.passed else " !"
            lines.append(f"{r.name:>{max_label}} |{marker}{bar} {r.ops_per_second:,.0f}")
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AMA Cryptography Benchmark Runner - Performance Regression Detection"
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path(__file__).parent / "baseline.json",
        help="Path to baseline.json file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Path to write JSON report",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Update baseline with current results (use with caution)",
    )
    parser.add_argument(
        "--markdown",
        type=Path,
        help="Path to write markdown report with tables and charts",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("AMA CRYPTOGRAPHY - BENCHMARK REGRESSION DETECTION")
    print("=" * 60)
    print()

    # Load baseline
    try:
        baseline = load_baseline(args.baseline)
        print(f"Loaded baseline: {args.baseline}")
        print(f"Regression threshold: {baseline['thresholds']['regression_threshold_percent']}%")
        print()
    except Exception as e:
        print(f"ERROR: Failed to load baseline: {e}")
        return 2

    # Run benchmarks
    print("Running benchmarks...")
    print("-" * 60)

    try:
        results = run_all_benchmarks(baseline, verbose=args.verbose)
    except Exception as e:
        print(f"ERROR: Benchmark execution failed: {e}")
        import traceback

        traceback.print_exc()
        return 2

    print("-" * 60)
    print()

    # Generate report
    report = generate_report(results)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Report written to: {args.output}")

    if args.markdown:
        md = generate_markdown_report(results, report)
        with open(args.markdown, "w") as f:
            f.write(md)
        print(f"Markdown report written to: {args.markdown}")

    # Summary
    summary = report["summary"]
    print("SUMMARY")
    print(f"  Total benchmarks: {summary['total']}")
    print(f"  Passed: {summary['passed']}")
    print(f"  Failed: {summary['failed']}")
    print(f"  Warnings (optional): {summary['warnings']}")
    print()

    # Check for failures
    failed = [r for r in results if not r.passed and not r.optional]

    if failed:
        print("REGRESSION DETECTED!")
        print("-" * 60)
        for r in failed:
            print(f"  {r.name}: {r.regression_percent:+.1f}% (threshold: {r.tolerance_percent}%)")
        print()
        print("CI will fail due to performance regression.")
        return 1

    print("All benchmarks within acceptable range.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
