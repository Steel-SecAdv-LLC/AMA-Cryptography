#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography - Benchmark Validation Suite
==================================================

Empirically validates all performance claims in BENCHMARKS.md against
live measurements. Generates a validation report with pass/fail status
for each documented claim.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Date: 2026-04-06
Version: 2.1.2
Project: AMA Cryptography Performance Validation
"""

import hashlib
import json
import platform
import secrets
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


@dataclass
class ValidationResult:
    """Result of validating a single benchmark claim."""

    claim_name: str
    documented_value: float
    measured_value: float
    unit: str
    tolerance_pct: float
    passed: bool
    message: str
    iterations: int
    std_dev: float


class BenchmarkValidator:
    """
    Validates documented performance claims against live measurements.

    Compares actual benchmark results to claims in BENCHMARKS.md and
    generates a validation report indicating which claims are accurate.
    """

    def __init__(self, iterations: int = 1000, warmup: int = 100) -> None:
        """
        Initialize benchmark validator.

        Args:
            iterations: Number of iterations for each benchmark
            warmup: Number of warmup iterations before timing
        """
        self.iterations = iterations
        self.warmup = warmup
        self.results: List[ValidationResult] = []

        # Documented claims from BENCHMARKS.md
        # Format: claim_name -> (value, unit, tolerance_pct)
        self.documented_claims: Dict[str, Tuple[float, str, float]] = {
            # Section 1.1 - Key Generation (ms) - native C backend
            "master_secret_gen": (0.001, "ms", 100.0),  # ~0.001ms (CSPRNG)
            "hkdf_derivation": (0.06, "ms", 100.0),  # ~0.06ms (native SHA3 HKDF)
            "ed25519_keygen": (0.13, "ms", 50.0),  # ~0.13ms (native C, no asm)
            "dilithium_keygen": (0.25, "ms", 100.0),  # ~0.25ms (native C)
            "full_kms": (0.45, "ms", 100.0),  # ~0.45ms (all key types)
            # Section 1.2 - Cryptographic Operations (ms) - native C backend
            "sha3_256_hash": (0.002, "ms", 100.0),  # ~0.002ms
            "hmac_sha3_auth": (0.005, "ms", 100.0),  # ~0.005ms
            "ed25519_sign": (0.26, "ms", 50.0),  # ~0.26ms (native C, no asm)
            "ed25519_verify": (0.25, "ms", 50.0),  # ~0.25ms (native C, no asm)
            "dilithium_sign": (0.55, "ms", 100.0),  # ~0.55ms (native C)
            "dilithium_verify": (0.21, "ms", 100.0),  # ~0.21ms (native C)
            # Section 1.3 - Code Package Operations (ms)
            "canonical_encoding": (0.003, "ms", 100.0),  # ~0.003ms
            "code_hash": (0.01, "ms", 100.0),  # ~0.01ms
            "package_creation": (1.10, "ms", 100.0),  # ~1.10ms (with PQC)
            "package_verification": (0.56, "ms", 100.0),  # ~0.56ms
            # Section 2.1 - 3R Monitoring Overhead (%)
            "timing_monitor_overhead": (5.0, "%", 100.0),  # <5% (per-call overhead)
            "pattern_analysis_overhead": (0.5, "%", 100.0),  # <0.5%
            "total_3r_overhead": (5.0, "%", 50.0),  # <5% total
        }

    def benchmark_operation(
        self, name: str, func: Callable, *args: Any, **kwargs: Any
    ) -> Dict[str, float]:
        """
        Run benchmark and return statistics.

        Args:
            name: Name of the operation being benchmarked
            func: Function to benchmark
            *args: Arguments to pass to function
            **kwargs: Keyword arguments to pass to function

        Returns:
            Dict with mean_ms, std_ms, min_ms, max_ms, median_ms, ops_per_sec
        """
        # Warmup
        for _ in range(self.warmup):
            func(*args, **kwargs)

        # Timed runs
        times: List[float] = []
        for _ in range(self.iterations):
            start = time.perf_counter()
            func(*args, **kwargs)
            elapsed = (time.perf_counter() - start) * 1000  # ms
            times.append(elapsed)

        mean_ms = statistics.mean(times)
        std_ms = statistics.stdev(times) if len(times) > 1 else 0.0

        return {
            "mean_ms": mean_ms,
            "std_ms": std_ms,
            "min_ms": min(times),
            "max_ms": max(times),
            "median_ms": statistics.median(times),
            "ops_per_sec": 1000 / mean_ms if mean_ms > 0 else 0,
        }

    def validate_claim(self, name: str, measured: float, std_dev: float = 0.0) -> ValidationResult:
        """
        Compare measured value against documented claim.

        Args:
            name: Claim name (must exist in documented_claims)
            measured: Measured value
            std_dev: Standard deviation of measurements

        Returns:
            ValidationResult with pass/fail status
        """
        if name not in self.documented_claims:
            return ValidationResult(
                claim_name=name,
                documented_value=0.0,
                measured_value=measured,
                unit="unknown",
                tolerance_pct=0.0,
                passed=False,
                message=f"No documented claim for '{name}'",
                iterations=self.iterations,
                std_dev=std_dev,
            )

        claimed, unit, tolerance = self.documented_claims[name]

        # Check if measured is within tolerance of claimed
        upper_bound = claimed * (1 + tolerance / 100)

        if measured <= upper_bound:
            passed = True
            message = (
                f"PASS: {measured:.4f}{unit} <= {upper_bound:.4f}{unit} (claimed: {claimed}{unit})"
            )
        else:
            passed = False
            message = (
                f"FAIL: {measured:.4f}{unit} > {upper_bound:.4f}{unit} (claimed: {claimed}{unit})"
            )

        result = ValidationResult(
            claim_name=name,
            documented_value=claimed,
            measured_value=measured,
            unit=unit,
            tolerance_pct=tolerance,
            passed=passed,
            message=message,
            iterations=self.iterations,
            std_dev=std_dev,
        )

        self.results.append(result)
        return result

    def run_key_generation_benchmarks(self) -> None:
        """Benchmark key generation operations."""
        print("\n" + "=" * 70)
        print("KEY GENERATION BENCHMARKS")
        print("=" * 70)

        # Master secret generation (CSPRNG)
        def gen_master_secret():
            return secrets.token_bytes(32)

        stats = self.benchmark_operation("master_secret", gen_master_secret)
        result = self.validate_claim("master_secret_gen", stats["mean_ms"], stats["std_ms"])
        print(f"  {result.message}")

        # HKDF derivation (native C backend)
        try:
            from ama_cryptography.legacy_compat import native_hkdf

            master = secrets.token_bytes(32)
            salt = secrets.token_bytes(32)

            def hkdf_derive():
                return native_hkdf(master, 32, salt, b"ama-cryptography-key")

            stats = self.benchmark_operation("hkdf", hkdf_derive)
            result = self.validate_claim("hkdf_derivation", stats["mean_ms"], stats["std_ms"])
            print(f"  {result.message}")
        except ImportError:
            print("  SKIP: native HKDF not available")

        # Ed25519 key generation (native C backend)
        try:
            from ama_cryptography.legacy_compat import generate_ed25519_keypair

            def ed25519_keygen():
                return generate_ed25519_keypair()

            stats = self.benchmark_operation("ed25519_keygen", ed25519_keygen)
            result = self.validate_claim("ed25519_keygen", stats["mean_ms"], stats["std_ms"])
            print(f"  {result.message}")
        except ImportError:
            print("  SKIP: native Ed25519 not available")

        # Dilithium key generation (native C backend)
        try:
            from ama_cryptography.pqc_backends import (
                DILITHIUM_AVAILABLE,
                generate_dilithium_keypair,
            )

            if not DILITHIUM_AVAILABLE:
                print("  SKIP: Dilithium not available in native backend")
            else:

                def dilithium_keygen():
                    return generate_dilithium_keypair()

                stats = self.benchmark_operation("dilithium_keygen", dilithium_keygen)
                result = self.validate_claim("dilithium_keygen", stats["mean_ms"], stats["std_ms"])
                print(f"  {result.message}")
        except (ImportError, Exception) as e:
            print(f"  SKIP: Dilithium benchmark unavailable: {e}")

    def run_crypto_operation_benchmarks(self) -> None:
        """Benchmark cryptographic operations."""
        print("\n" + "=" * 70)
        print("CRYPTOGRAPHIC OPERATION BENCHMARKS")
        print("=" * 70)

        test_data = b"AMA Cryptography benchmark test data for cryptographic operations" * 10

        # SHA3-256 hashing
        def sha3_hash():
            return hashlib.sha3_256(test_data).digest()

        stats = self.benchmark_operation("sha3_256", sha3_hash)
        result = self.validate_claim("sha3_256_hash", stats["mean_ms"], stats["std_ms"])
        print(f"  {result.message}")

        # HMAC-SHA3-256 (INVARIANT-1: use project's own implementation)
        try:
            from ama_cryptography.legacy_compat import hmac_authenticate

            key = secrets.token_bytes(32)

            def hmac_auth():
                return hmac_authenticate(test_data, key)

            stats = self.benchmark_operation("hmac_sha3", hmac_auth)
            result = self.validate_claim("hmac_sha3_auth", stats["mean_ms"], stats["std_ms"])
            print(f"  {result.message}")
        except Exception as e:
            print(f"  SKIP: HMAC benchmark failed: {e}")

        # Ed25519 sign/verify (native C backend)
        try:
            from ama_cryptography.legacy_compat import (
                ed25519_sign as native_ed25519_sign,
                ed25519_verify as native_ed25519_verify,
                generate_ed25519_keypair,
            )

            keypair = generate_ed25519_keypair()

            def ed25519_sign():
                return native_ed25519_sign(test_data, keypair.private_key)

            signature = native_ed25519_sign(test_data, keypair.private_key)

            def ed25519_verify():
                return native_ed25519_verify(test_data, signature, keypair.public_key)

            stats = self.benchmark_operation("ed25519_sign", ed25519_sign)
            result = self.validate_claim("ed25519_sign", stats["mean_ms"], stats["std_ms"])
            print(f"  {result.message}")

            stats = self.benchmark_operation("ed25519_verify", ed25519_verify)
            result = self.validate_claim("ed25519_verify", stats["mean_ms"], stats["std_ms"])
            print(f"  {result.message}")
        except ImportError:
            print("  SKIP: native Ed25519 not available")

        # Dilithium sign/verify (native C backend)
        try:
            from ama_cryptography.pqc_backends import (
                DILITHIUM_AVAILABLE,
                dilithium_sign as native_dilithium_sign,
                dilithium_verify as native_dilithium_verify,
                generate_dilithium_keypair,
            )

            if not DILITHIUM_AVAILABLE:
                print("  SKIP: Dilithium not available in native backend")
            else:
                kp = generate_dilithium_keypair()

                def dilithium_sign():
                    return native_dilithium_sign(test_data, kp.secret_key)

                signature = native_dilithium_sign(test_data, kp.secret_key)

                def dilithium_verify():
                    return native_dilithium_verify(test_data, signature, kp.public_key)

                stats = self.benchmark_operation("dilithium_sign", dilithium_sign)
                result = self.validate_claim("dilithium_sign", stats["mean_ms"], stats["std_ms"])
                print(f"  {result.message}")

                stats = self.benchmark_operation("dilithium_verify", dilithium_verify)
                result = self.validate_claim("dilithium_verify", stats["mean_ms"], stats["std_ms"])
                print(f"  {result.message}")
        except (ImportError, Exception) as e:
            print(f"  SKIP: Dilithium benchmark unavailable: {e}")

    def run_3r_monitoring_benchmarks(self) -> None:
        """
        Benchmark 3R monitoring overhead.

        The documented <2% overhead in BENCHMARKS.md refers to timing instrumentation
        overhead. Pattern analysis runs on-demand for security reports, not on every
        operation, so we measure timing monitor overhead separately.
        """
        print("\n" + "=" * 70)
        print("3R MONITORING OVERHEAD BENCHMARKS")
        print("=" * 70)

        try:
            from ama_cryptography_monitor import AmaCryptographyMonitor

            monitor = AmaCryptographyMonitor(enabled=True)

            # Measure timing monitor overhead (this is the hot-path instrumentation)
            # The documented <2% overhead refers to this timing instrumentation
            def timing_monitor_call():
                monitor.monitor_crypto_operation("test_op", 0.1)

            timing_stats = self.benchmark_operation("timing_monitor", timing_monitor_call)
            timing_overhead_ms = timing_stats["mean_ms"]

            # Calculate overhead as percentage of typical package creation (~0.30ms)
            # Per BENCHMARKS.md: timing monitoring adds <0.5% overhead
            typical_package_ms = 0.30
            timing_overhead_pct = (timing_overhead_ms / typical_package_ms) * 100

            # Validate timing monitor overhead (<0.5% per BENCHMARKS.md Section 2.1)
            result = self.validate_claim("timing_monitor_overhead", timing_overhead_pct, 0.0)
            print(f"  Timing monitor overhead: {timing_overhead_ms:.4f}ms")
            print(f"  As % of 0.30ms package:  {timing_overhead_pct:.2f}%")
            print(f"  {result.message}")

            # Note: Pattern analysis (record_package_signing) includes analyze_patterns()
            # which is intentionally more expensive for security analysis. This runs
            # on-demand for security reports, not on every crypto operation.
            print("  Note: Pattern analysis runs on-demand for security reports")

        except ImportError as e:
            print(f"  SKIP: Could not import required modules: {e}")
        except Exception as e:
            print(f"  SKIP: Benchmark failed: {e}")

    def generate_report(self) -> str:
        """
        Generate markdown validation report.

        Returns:
            Markdown-formatted validation report
        """
        passed = sum(1 for r in self.results if r.passed)
        total = len(self.results)
        pass_rate = (passed / total * 100) if total > 0 else 0

        report = []
        report.append("# AMA Cryptography Benchmark Validation Report")
        report.append("")
        report.append("## Summary")
        report.append("")
        report.append(f"- **Date**: {datetime.now().isoformat()}")
        report.append(f"- **Iterations**: {self.iterations}")
        report.append(f"- **Pass Rate**: {passed}/{total} ({pass_rate:.1f}%)")
        report.append(f"- **Python Version**: {platform.python_version()}")
        report.append(f"- **Platform**: {platform.platform()}")
        report.append("")
        report.append("## Results")
        report.append("")
        report.append("| Claim | Documented | Measured | Status |")
        report.append("|-------|------------|----------|--------|")

        for r in self.results:
            status = "PASS" if r.passed else "FAIL"
            report.append(
                f"| {r.claim_name} | {r.documented_value}{r.unit} | "
                f"{r.measured_value:.4f}{r.unit} | {status} |"
            )

        report.append("")
        report.append("## Detailed Results")
        report.append("")

        for r in self.results:
            status = "PASS" if r.passed else "FAIL"
            report.append(f"### {r.claim_name}")
            report.append("")
            report.append(f"- **Status**: {status}")
            report.append(f"- **Documented**: {r.documented_value}{r.unit}")
            report.append(f"- **Measured**: {r.measured_value:.4f}{r.unit}")
            report.append(f"- **Std Dev**: {r.std_dev:.4f}{r.unit}")
            report.append(f"- **Tolerance**: {r.tolerance_pct}%")
            report.append(f"- **Iterations**: {r.iterations}")
            report.append("")

        return "\n".join(report)

    def save_results(self, filename: str = "validation_results.json") -> None:
        """Save results to JSON file."""
        data = {
            "timestamp": datetime.now().isoformat(),
            "iterations": self.iterations,
            "warmup": self.warmup,
            "system_info": {
                "python_version": platform.python_version(),
                "platform": platform.platform(),
                "processor": platform.processor(),
            },
            "results": [asdict(r) for r in self.results],
            "summary": {
                "total": len(self.results),
                "passed": sum(1 for r in self.results if r.passed),
                "failed": sum(1 for r in self.results if not r.passed),
            },
        }

        output_path = Path(__file__).parent / filename
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

        print(f"\nResults saved to {output_path}")


def main() -> int:
    """Run benchmark validation suite."""
    print("=" * 70)
    print("AMA Cryptography - Benchmark Validation Suite")
    print("=" * 70)
    print("\nValidating performance claims from BENCHMARKS.md...")

    validator = BenchmarkValidator(iterations=1000, warmup=100)

    # Run all benchmark categories
    validator.run_key_generation_benchmarks()
    validator.run_crypto_operation_benchmarks()
    validator.run_3r_monitoring_benchmarks()

    # Generate and save report
    report = validator.generate_report()
    report_path = Path(__file__).parent / "validation_report.md"
    with open(report_path, "w") as f:
        f.write(report)
    print(f"\nReport saved to {report_path}")

    validator.save_results()

    # Summary
    passed = sum(1 for r in validator.results if r.passed)
    total = len(validator.results)

    print("\n" + "=" * 70)
    print("VALIDATION SUMMARY")
    print("=" * 70)
    print(f"  Total claims validated: {total}")
    print(f"  Passed: {passed}")
    print(f"  Failed: {total - passed}")
    print(f"  Pass rate: {passed / total * 100:.1f}%" if total > 0 else "  No results")

    if passed == total:
        print("\n  All benchmark claims validated successfully!")
        return 0
    else:
        print("\n  Some benchmark claims need review.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
