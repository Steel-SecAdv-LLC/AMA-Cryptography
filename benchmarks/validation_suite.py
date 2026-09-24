#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography - Benchmark Validation Suite
==================================================

Validates this suite's own acceptance table -- ``documented_claims`` in
:class:`BenchmarkValidator` -- against live measurements, and writes a
report with a pass/fail status for each row.

The table is the authority for these thresholds; nothing else in the tree
states them.  Earlier versions of this file cited "BENCHMARKS.md Sections
1.1-2.1" as their source.  No such document is tracked: ``BENCHMARKS.md`` is
a gitignored report that ``benchmarks/benchmark_suite.py`` writes locally,
and it has no numbered sections and states no threshold.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Date: 2026-04-17
Version: 3.0.0
Project: AMA Cryptography Performance Validation
"""

import argparse
import itertools
import json
import math
import platform
import secrets
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


#: Real monitored packages captured to build the 3R replay workload (see
#: run_3r_monitoring_benchmarks).  Several rather than one, so the replayed
#: durations carry the run-to-run variation real packages record.
_CAPTURED_PACKAGES = 64

#: The rows run_package_operation_benchmarks and run_3r_monitoring_benchmarks
#: measure -- the two sections --only-3r runs.
PACKAGE_CLAIMS: Tuple[str, ...] = (
    "canonical_encoding",
    "code_hash",
    "package_creation",
    "package_verification",
)
MONITORING_CLAIMS: Tuple[str, ...] = (
    "timing_monitor_overhead",
    "pattern_analysis_overhead",
    "total_3r_overhead",
)


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
    Validates the acceptance table below against live measurements.

    Compares each measured row with its entry in ``documented_claims`` and
    generates a validation report indicating which rows are within bounds.
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
        # Documented claims this run could NOT measure, with the reason.
        # Every SKIP path must record the claims it forfeits here: the
        # verdict in main() is computed over `results`, so a skip that
        # only prints leaves no trace in the accounting and the run can
        # report "all claims validated" after validating almost none of
        # them (the exit-0-measured-nothing failure mode).
        self.skipped: List[Tuple[str, str]] = []
        # Mean package-creation time (ms) measured by
        # run_package_operation_benchmarks in THIS run.  Every 3R overhead
        # row is a percentage of it; through 5.0.0 they were percentages of a
        # hard-coded 0.30 ms that no run measured.
        self.package_creation_ms: Optional[float] = None

        # This suite's acceptance table.  It is the only place these bounds
        # are stated: the "Section N.N" labels below group the rows and are
        # not references to another document.
        # Format: claim_name -> (value, unit, tolerance_pct); a row passes
        # when measured <= value * (1 + tolerance_pct / 100).
        self.documented_claims: Dict[str, Tuple[float, str, float]] = {
            # Section 1.1 - Key Generation (ms) - native C backend
            "master_secret_gen": (0.005, "ms", 100.0),  # ~0.005ms (secrets.token_bytes CSPRNG)
            "hkdf_derivation": (0.06, "ms", 100.0),  # ~0.06ms (native SHA3 HKDF)
            "ed25519_keygen": (0.13, "ms", 50.0),  # ~0.13ms (native C, no asm)
            "dilithium_keygen": (0.85, "ms", 100.0),  # ~0.85ms slow CI (canonical ~0.28ms)
            # full_kms: generate_key_management_system(), i.e. an Ed25519 and an
            # ML-DSA-65 keypair, each with its INVARIANT-41 pairwise test, plus
            # the HD master and HMAC key.  Measured 1.18-1.29 ms over four runs
            # (Intel Xeon @ 2.80GHz, 4 vCPU container, CPython 3.11.15, Release
            # build, 2026-09-24); the components were ed25519_keygen 0.089 ms
            # and dilithium_keygen 0.984 ms in the same run.  The earlier
            # 0.45 ms predates the pairwise tests and was below this table's
            # own dilithium_keygen row, which full_kms contains.
            "full_kms": (1.25, "ms", 100.0),
            # Section 1.2 - Cryptographic Operations (ms) - native C backend
            "sha3_256_hash": (0.002, "ms", 100.0),  # ~0.002ms
            "hmac_sha3_auth": (0.030, "ms", 100.0),  # ~0.03ms slow CI (canonical ~0.008ms)
            "ed25519_sign": (0.26, "ms", 50.0),  # ~0.26ms (native C, no asm)
            "ed25519_verify": (0.25, "ms", 50.0),  # ~0.25ms (native C, no asm)
            "dilithium_sign": (3.0, "ms", 200.0),  # ~3ms slow CI ±200% rej. (canonical ~0.34ms)
            "dilithium_verify": (0.75, "ms", 100.0),  # ~0.75ms slow CI (canonical ~0.13ms)
            # Section 1.3 - Code Package Operations (ms)
            "canonical_encoding": (0.003, "ms", 100.0),  # ~0.003ms
            # code_hash: measured 0.0186-0.0214 ms over seven runs, same host
            # and build as full_kms above.  The earlier 0.01 ms put the bound
            # (0.02 ms) inside the measured spread, so the row failed on some
            # runs and passed on others with no code change.
            "code_hash": (0.019, "ms", 100.0),
            "package_creation": (1.10, "ms", 100.0),  # ~1.10ms (with PQC)
            "package_verification": (0.56, "ms", 100.0),  # ~0.56ms
            # Section 2.1 - 3R Monitoring Overhead (% of package_creation
            # measured in the same run; see run_3r_monitoring_benchmarks).
            #
            # These three bounds are set to measured reality, not to the
            # figures they replace.  The old rows (<5% / <0.5% / <5% total)
            # timed ONE monitor_crypto_operation call against a hard-coded
            # 0.30 ms "typical package" and exempted pattern analysis as
            # on-demand; a monitored package makes four timing calls and a
            # pattern check, against a measured 0.69-0.77 ms.
            #
            # Provenance: 2026-09-24, Intel Xeon @ 2.80GHz (4 vCPU, Linux
            # 6.18 container), CPython 3.11.15, gcc 13.3.0 Release build
            # (-DAMA_USE_NATIVE_PQC=ON) plus `setup.py build_ext --inplace`,
            # tree a62bb446 + this change; command
            # `python benchmarks/validation_suite.py --only-3r`, 1,000 timed
            # iterations after 100 warm-up per row, mean.
            #   timing_monitor_overhead: 22.4 / 25.0 / 25.6 / 24.1 % before
            #     the pattern-analysis change and 23.1 / 24.3 / 23.6 / 23.0 /
            #     27.3 % after it (the timing path did not change): median
            #     24.2%.  Bound 25% +50%.
            #   pattern_analysis_overhead: 674 / 742 / 657 / 699 % while
            #     record_package_signing re-ran the full O(n) analyze_patterns
            #     on every package (5.0-5.2 ms at the default 10,000-entry
            #     history); 1.67 / 1.76 / 2.33 / 1.73 / 2.28 % once it reads
            #     O(1) exact running moments (12.9-17.1 us).  Bound 2% +100%:
            #     4%.  Mutation-tested: with record_package_signing made to
            #     do its pattern work ten times per package, this row
            #     measured 13.8% and 18.0% (124-131 us) and FAILED both runs.
            #   total_3r_overhead: 24.7 / 26.0 / 26.0 / 24.8 / 29.6 % after.
            #     Bound 27% +50%.
            "timing_monitor_overhead": (25.0, "%", 50.0),
            "pattern_analysis_overhead": (2.0, "%", 100.0),
            "total_3r_overhead": (27.0, "%", 50.0),
        }

    def benchmark_operation(
        self, name: str, func: "Callable[..., Any]", *args: Any, **kwargs: Any
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

    def record_skip(self, reason: str, *claim_names: str) -> None:
        """
        Record documented claims this run could not measure.

        Args:
            reason: Why the measurement was skipped (printed and reported)
            *claim_names: The documented_claims entries the skip forfeits
        """
        for name in claim_names:
            self.skipped.append((name, reason))

    def unmeasured_claims(self) -> Dict[str, str]:
        """
        Documented claims this run produced no measurement for.

        Returns:
            Mapping of claim name -> reason for every row of the table that
            has no measurement.  There is no exemption: every row times code
            the library runs.  A claim that was skipped carries its recorded
            skip reason; a claim no code path even attempted carries a fixed
            diagnostic, because that state means the validator itself has a
            coverage hole.
        """
        measured = {r.claim_name for r in self.results}
        skip_reasons = dict(self.skipped)
        reasons: Dict[str, str] = {}
        for name in self.documented_claims:
            if name in measured:
                continue
            reasons[name] = skip_reasons.get(
                name, "no measurement block in this suite attempted this claim"
            )
        return reasons

    def run_key_generation_benchmarks(self) -> None:
        """Benchmark key generation operations."""
        print("\n" + "=" * 70)
        print("KEY GENERATION BENCHMARKS")
        print("=" * 70)

        # Master secret generation (CSPRNG)
        def gen_master_secret() -> bytes:
            return secrets.token_bytes(32)

        stats = self.benchmark_operation("master_secret", gen_master_secret)
        result = self.validate_claim("master_secret_gen", stats["mean_ms"], stats["std_ms"])
        print(f"  {result.message}")

        # HKDF derivation (native C backend)
        try:
            from ama_cryptography.pqc_backends import native_hkdf

            master = secrets.token_bytes(32)
            salt = secrets.token_bytes(32)

            def hkdf_derive() -> bytes:
                return native_hkdf(master, 32, salt, b"ama-cryptography-key")

            stats = self.benchmark_operation("hkdf", hkdf_derive)
            result = self.validate_claim("hkdf_derivation", stats["mean_ms"], stats["std_ms"])
            print(f"  {result.message}")
        except ImportError:
            self.record_skip("native HKDF not available", "hkdf_derivation")
            print("  SKIP: native HKDF not available")

        # Ed25519 key generation (native C backend)
        try:
            from ama_cryptography.legacy_compat import generate_ed25519_keypair

            def ed25519_keygen() -> Any:
                return generate_ed25519_keypair()

            stats = self.benchmark_operation("ed25519_keygen", ed25519_keygen)
            result = self.validate_claim("ed25519_keygen", stats["mean_ms"], stats["std_ms"])
            print(f"  {result.message}")
        except ImportError:
            self.record_skip("native Ed25519 not available", "ed25519_keygen")
            print("  SKIP: native Ed25519 not available")

        # Dilithium key generation (native C backend)
        try:
            from ama_cryptography.pqc_backends import (
                DILITHIUM_AVAILABLE,
                generate_dilithium_keypair,
            )

            if not DILITHIUM_AVAILABLE:
                self.record_skip("Dilithium not available in native backend", "dilithium_keygen")
                print("  SKIP: Dilithium not available in native backend")
            else:

                def dilithium_keygen() -> Any:
                    return generate_dilithium_keypair()

                stats = self.benchmark_operation("dilithium_keygen", dilithium_keygen)
                result = self.validate_claim("dilithium_keygen", stats["mean_ms"], stats["std_ms"])
                print(f"  {result.message}")
        except (ImportError, Exception) as e:
            self.record_skip(f"Dilithium benchmark unavailable: {e}", "dilithium_keygen")
            print(f"  SKIP: Dilithium benchmark unavailable: {e}")

        # Complete KMS generation — the documented `full_kms` claim
        # (Section 1.1, "all key types"). Mirrors benchmark_suite.py's
        # kms_generation row. Until 5.0.0 this claim, and all of Section
        # 1.3 below, sat in documented_claims with no measurement block —
        # and because the verdict counted only measured rows, the suite
        # printed "All benchmark claims validated successfully!" without
        # ever measuring them.
        try:
            from ama_cryptography.legacy_compat import generate_key_management_system

            def full_kms_gen() -> Any:
                return generate_key_management_system("benchmark")

            stats = self.benchmark_operation("full_kms", full_kms_gen)
            result = self.validate_claim("full_kms", stats["mean_ms"], stats["std_ms"])
            print(f"  {result.message}")
        except ImportError:
            self.record_skip("KMS generation not available", "full_kms")
            print("  SKIP: KMS generation not available")

    def run_package_operation_benchmarks(self) -> None:
        """Benchmark code-package operations (acceptance table Section 1.3)."""
        print("\n" + "=" * 70)
        print("CODE PACKAGE OPERATION BENCHMARKS")
        print("=" * 70)

        # The operations behind these four claims mirror
        # benchmark_suite.py's benchmark_dna_operations rows exactly, so a
        # claim validated here is validated against the same operation the
        # reporting suite publishes numbers for.
        section_claims = PACKAGE_CLAIMS
        try:
            from ama_cryptography.legacy_compat import (
                MASTER_CODES,
                MASTER_HELIX_PARAMS,
                canonical_hash_code,
                create_crypto_package,
                generate_key_management_system,
                length_prefixed_encode,
                verify_crypto_package,
            )
        except ImportError as e:
            self.record_skip(f"package operations not available: {e}", *section_claims)
            print(f"  SKIP: package operations not available: {e}")
            return

        def canonical_encode() -> Any:
            return length_prefixed_encode("Code", MASTER_CODES, "HELIX", "test")

        stats = self.benchmark_operation("canonical_encoding", canonical_encode)
        result = self.validate_claim("canonical_encoding", stats["mean_ms"], stats["std_ms"])
        print(f"  {result.message}")

        def code_hash() -> Any:
            return canonical_hash_code(MASTER_CODES, MASTER_HELIX_PARAMS)

        stats = self.benchmark_operation("code_hash", code_hash)
        result = self.validate_claim("code_hash", stats["mean_ms"], stats["std_ms"])
        print(f"  {result.message}")

        kms = generate_key_management_system("benchmark")

        def package_create() -> Any:
            return create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "benchmark")

        stats = self.benchmark_operation("package_creation", package_create)
        self.package_creation_ms = stats["mean_ms"]
        result = self.validate_claim("package_creation", stats["mean_ms"], stats["std_ms"])
        print(f"  {result.message}")

        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "benchmark")

        def package_verify() -> Any:
            return verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key)

        stats = self.benchmark_operation("package_verification", package_verify)
        result = self.validate_claim("package_verification", stats["mean_ms"], stats["std_ms"])
        print(f"  {result.message}")

    def run_crypto_operation_benchmarks(self) -> None:
        """Benchmark cryptographic operations."""
        print("\n" + "=" * 70)
        print("CRYPTOGRAPHIC OPERATION BENCHMARKS")
        print("=" * 70)

        test_data = b"AMA Cryptography benchmark test data for cryptographic operations" * 10

        # SHA3-256 hashing.
        #
        # AMA's native kernel, not hashlib: this function validates the
        # documented `sha3_256_hash` claim, and hashlib.sha3_256 is OpenSSL's
        # implementation on CPython — so the claim was being "validated"
        # against a throughput AMA does not produce, and AMA's own SHA3 could
        # regress arbitrarily while this printed PASS (INVARIANT-36).
        #
        # The import is hoisted OUT of the timed thunk, and that is a
        # correctness fix, not tidying.  Inside it, every iteration
        # re-executed the `from ... import` statement — a sys.modules lookup
        # and an attribute bind — so the row that was rewritten "to measure
        # AMA's SHA3, not hashlib" was measuring the harness instead.
        # Measured on this host, 200,000 iterations, median of five runs:
        #
        #   thunk with the import inside : 2147.9 ns/op
        #   thunk with it hoisted        : 1572.0 ns/op
        #
        # 575.9 ns, or 26.8% of the reported figure, against a documented
        # claim of ~2 us.  Every other timed thunk in benchmarks/ already
        # hoists its import; this was the only one that did not, and
        # tests/test_benchmark_chart_inputs.py now pins the rule.
        from ama_cryptography.pqc_backends import native_sha3_256

        def sha3_hash() -> bytes:
            return native_sha3_256(test_data)

        stats = self.benchmark_operation("sha3_256", sha3_hash)
        result = self.validate_claim("sha3_256_hash", stats["mean_ms"], stats["std_ms"])
        print(f"  {result.message}")

        # HMAC-SHA3-256 (INVARIANT-1: use project's own implementation)
        try:
            from ama_cryptography.legacy_compat import hmac_authenticate

            key = secrets.token_bytes(32)

            def hmac_auth() -> bytes:
                return hmac_authenticate(test_data, key)

            stats = self.benchmark_operation("hmac_sha3", hmac_auth)
            result = self.validate_claim("hmac_sha3_auth", stats["mean_ms"], stats["std_ms"])
            print(f"  {result.message}")
        except Exception as e:
            self.record_skip(f"HMAC benchmark failed: {e}", "hmac_sha3_auth")
            print(f"  SKIP: HMAC benchmark failed: {e}")

        # Ed25519 sign/verify (native C backend)
        try:
            from ama_cryptography.legacy_compat import (
                ed25519_sign as native_ed25519_sign,
                ed25519_verify as native_ed25519_verify,
                generate_ed25519_keypair,
            )

            keypair = generate_ed25519_keypair()

            def ed25519_sign() -> bytes:
                return native_ed25519_sign(test_data, keypair.private_key)

            signature = native_ed25519_sign(test_data, keypair.private_key)

            def ed25519_verify() -> bool:
                return native_ed25519_verify(test_data, signature, keypair.public_key)

            stats = self.benchmark_operation("ed25519_sign", ed25519_sign)
            result = self.validate_claim("ed25519_sign", stats["mean_ms"], stats["std_ms"])
            print(f"  {result.message}")

            stats = self.benchmark_operation("ed25519_verify", ed25519_verify)
            result = self.validate_claim("ed25519_verify", stats["mean_ms"], stats["std_ms"])
            print(f"  {result.message}")
        except ImportError:
            self.record_skip("native Ed25519 not available", "ed25519_sign", "ed25519_verify")
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
                self.record_skip(
                    "Dilithium not available in native backend",
                    "dilithium_sign",
                    "dilithium_verify",
                )
                print("  SKIP: Dilithium not available in native backend")
            else:
                kp = generate_dilithium_keypair()

                def dilithium_sign() -> bytes:
                    return native_dilithium_sign(test_data, kp.secret_key)

                signature = native_dilithium_sign(test_data, kp.secret_key)

                def dilithium_verify() -> bool:
                    return native_dilithium_verify(test_data, signature, kp.public_key)

                stats = self.benchmark_operation("dilithium_sign", dilithium_sign)
                result = self.validate_claim("dilithium_sign", stats["mean_ms"], stats["std_ms"])
                print(f"  {result.message}")

                stats = self.benchmark_operation("dilithium_verify", dilithium_verify)
                result = self.validate_claim("dilithium_verify", stats["mean_ms"], stats["std_ms"])
                print(f"  {result.message}")
        except (ImportError, Exception) as e:
            self.record_skip(
                f"Dilithium benchmark unavailable: {e}", "dilithium_sign", "dilithium_verify"
            )
            print(f"  SKIP: Dilithium benchmark unavailable: {e}")

    def run_3r_monitoring_benchmarks(self) -> None:
        """
        Benchmark what 3R monitoring adds to one monitored package.

        Every row is a percentage of ``package_creation`` as measured by
        :meth:`run_package_operation_benchmarks` in this same run -- an
        unmonitored ``create_crypto_package`` -- so numerator and
        denominator come from one host, one build and one process.

        The workload is read off the library rather than assumed.
        ``_CAPTURED_PACKAGES`` real ``create_crypto_package(...,
        monitor=...)`` calls are made against a recording monitor, and the
        calls each one makes into the monitor are what the timed thunks
        replay, cycling through the captured packages:

        * ``timing_monitor_overhead`` -- every ``monitor_crypto_operation``
          call one package makes (one per timed primitive, with the
          durations and input sizes that package actually recorded).
        * ``pattern_analysis_overhead`` -- every ``record_package_signing``
          call one package makes, with the metadata the library passed.
          ``record_package_signing`` runs the pattern-anomaly check on
          EVERY monitored package; through 5.0.0 this row was exempted as
          "on-demand for security reports", which was false.  It is timed
          with the pattern history in steady state -- filled to
          ``max_history`` through the same call first -- because its cost
          at an empty history says nothing about a long-running service.
        * ``total_3r_overhead`` -- the sum of the two: everything the
          monitor executes per monitored package.
        """
        print("\n" + "=" * 70)
        print("3R MONITORING OVERHEAD BENCHMARKS")
        print("=" * 70)

        section_claims = MONITORING_CLAIMS
        package_ms = self.package_creation_ms
        if package_ms is None or package_ms <= 0.0:
            self.record_skip(
                "package_creation was not measured this run, and every 3R row "
                "is a percentage of it",
                *section_claims,
            )
            print("  SKIP: package_creation not measured; 3R rows are relative to it")
            return

        try:
            from ama_cryptography.legacy_compat import (
                MASTER_CODES,
                MASTER_HELIX_PARAMS,
                create_crypto_package,
                generate_key_management_system,
            )
            from ama_cryptography.monitoring import AmaCryptographyMonitor
        except ImportError as e:
            self.record_skip(f"Could not import required modules: {e}", *section_claims)
            print(f"  SKIP: Could not import required modules: {e}")
            return

        class _RecordingMonitor(AmaCryptographyMonitor):
            """Records the calls one monitored package makes, then forwards them."""

            def __init__(self) -> None:
                super().__init__(enabled=True)
                self.timing_calls: List[Tuple[str, float, Optional[int]]] = []
                self.signing_calls: List[Dict[str, Any]] = []

            def monitor_crypto_operation(
                self, operation: str, duration_ms: float, input_size: Optional[int] = None
            ) -> None:
                self.timing_calls.append((operation, duration_ms, input_size))
                super().monitor_crypto_operation(operation, duration_ms, input_size)

            def record_package_signing(self, metadata: Dict[Any, Any]) -> None:
                self.signing_calls.append(dict(metadata))
                super().record_package_signing(metadata)

        kms = generate_key_management_system("benchmark")
        timing_workload: List[List[Tuple[str, float, Optional[int]]]] = []
        signing_workload: List[List[Dict[str, Any]]] = []
        for _ in range(_CAPTURED_PACKAGES):
            recorder = _RecordingMonitor()
            create_crypto_package(
                MASTER_CODES, MASTER_HELIX_PARAMS, kms, "benchmark", monitor=recorder
            )
            timing_workload.append(recorder.timing_calls)
            signing_workload.append(recorder.signing_calls)

        timing_calls = len(timing_workload[0])
        signing_calls = len(signing_workload[0])
        print(
            f"  One monitored package makes {timing_calls} monitor_crypto_operation "
            f"call(s) and {signing_calls} record_package_signing call(s)"
        )

        timing_monitor = AmaCryptographyMonitor(enabled=True)
        timing_replay = itertools.cycle(timing_workload)

        def timing_per_package() -> None:
            for operation, duration_ms, input_size in next(timing_replay):
                timing_monitor.monitor_crypto_operation(
                    operation, duration_ms, input_size=input_size
                )

        pattern_monitor = AmaCryptographyMonitor(enabled=True)
        signing_replay = itertools.cycle(signing_workload)

        def pattern_per_package() -> None:
            for metadata in next(signing_replay):
                pattern_monitor.record_package_signing(metadata)

        # Steady state: the history is a bounded deque, so a service that has
        # signed max_history packages analyses a full window on every call
        # from then on.  Fill it through the call under test.
        for _ in range(pattern_monitor.patterns.max_history):
            pattern_per_package()

        timing_stats = self.benchmark_operation("timing_monitor", timing_per_package)
        pattern_stats = self.benchmark_operation("pattern_analysis", pattern_per_package)

        def pct(ms: float) -> float:
            return ms / package_ms * 100.0

        timing_pct = pct(timing_stats["mean_ms"])
        pattern_pct = pct(pattern_stats["mean_ms"])
        total_pct = timing_pct + pattern_pct

        print(f"  package_creation (this run):   {package_ms:.4f}ms")
        print(
            f"  Timing instrumentation/package: {timing_stats['mean_ms']:.4f}ms "
            f"({timing_pct:.2f}%)"
        )
        print(
            f"  Pattern analysis/package:       {pattern_stats['mean_ms']:.4f}ms "
            f"({pattern_pct:.2f}%, history {len(pattern_monitor.patterns.package_history)})"
        )

        result = self.validate_claim(
            "timing_monitor_overhead", timing_pct, pct(timing_stats["std_ms"])
        )
        print(f"  {result.message}")
        result = self.validate_claim(
            "pattern_analysis_overhead", pattern_pct, pct(pattern_stats["std_ms"])
        )
        print(f"  {result.message}")
        # The two thunks are timed separately, so their spread does not add
        # linearly; report the root-sum-square as the total's deviation.
        total_std = pct(math.hypot(timing_stats["std_ms"], pattern_stats["std_ms"]))
        result = self.validate_claim("total_3r_overhead", total_pct, total_std)
        print(f"  {result.message}")

    def generate_report(self) -> str:
        """
        Generate markdown validation report.

        Returns:
            Markdown-formatted validation report
        """
        passed = sum(1 for r in self.results if r.passed)
        total = len(self.results)
        pass_rate = (passed / total * 100) if total > 0 else 0
        documented = len(self.documented_claims)
        measured = len({r.claim_name for r in self.results})
        unmeasured = self.unmeasured_claims()

        report = []
        report.append("# AMA Cryptography Benchmark Validation Report")
        report.append("")
        report.append("## Summary")
        report.append("")
        report.append(f"- **Date**: {datetime.now().isoformat()}")
        report.append(f"- **Iterations**: {self.iterations}")
        report.append(f"- **Pass Rate**: {passed}/{total} ({pass_rate:.1f}%)")
        report.append(f"- **Coverage**: {measured}/{documented} documented claims measured")
        report.append(f"- **Python Version**: {platform.python_version()}")
        report.append(f"- **Platform**: {platform.platform()}")
        report.append("")
        if unmeasured:
            report.append("## Unmeasured Claims")
            report.append("")
            report.append(
                "The pass rate above covers measured rows only; these documented "
                "claims produced no measurement this run:"
            )
            report.append("")
            for name, reason in sorted(unmeasured.items()):
                report.append(f"- **{name}**: {reason}")
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
            "skipped": [{"claim_name": n, "reason": r} for n, r in self.skipped],
            "unmeasured": self.unmeasured_claims(),
            "package_creation_ms": self.package_creation_ms,
            "summary": {
                "total": len(self.results),
                "passed": sum(1 for r in self.results if r.passed),
                "failed": sum(1 for r in self.results if not r.passed),
                "documented": len(self.documented_claims),
                "measured": len({r.claim_name for r in self.results}),
            },
        }

        output_path = Path(__file__).parent / filename
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

        print(f"\nResults saved to {output_path}")


def main(argv: "List[str] | None" = None) -> int:
    """Run benchmark validation suite."""
    parser = argparse.ArgumentParser(
        description="Validate documented performance claims against live measurements."
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help=(
            "Exit non-zero when any documented claim produced no measurement "
            "(mirrors benchmark_runner.py's --require-populated-baseline: a run "
            "that validated almost nothing must not be allowed to look like a "
            "clean bill of health). Without the flag, coverage gaps are still "
            "reported but the exit code reflects only the measured rows."
        ),
    )
    parser.add_argument(
        "--only-3r",
        action="store_true",
        help=(
            "Run only the code-package and 3R monitoring sections. The 3R rows "
            "are percentages of package_creation, so that section always runs "
            "first. The other rows are then reported unmeasured, and "
            "--require-complete fails the run."
        ),
    )
    args = parser.parse_args(argv)

    print("=" * 70)
    print("AMA Cryptography - Benchmark Validation Suite")
    print("=" * 70)
    print("\nValidating the acceptance table in benchmarks/validation_suite.py...")

    validator = BenchmarkValidator(iterations=1000, warmup=100)

    # Run all benchmark categories
    if args.only_3r:
        # Name the rows this run chose not to measure, so the report does not
        # read them as validator coverage holes.
        validator.record_skip(
            "not run (--only-3r)",
            *(
                name
                for name in validator.documented_claims
                if name not in PACKAGE_CLAIMS and name not in MONITORING_CLAIMS
            ),
        )
    else:
        validator.run_key_generation_benchmarks()
        validator.run_crypto_operation_benchmarks()
    validator.run_package_operation_benchmarks()
    validator.run_3r_monitoring_benchmarks()

    # Generate and save report
    report = validator.generate_report()
    report_path = Path(__file__).parent / "validation_report.md"
    with open(report_path, "w") as f:
        f.write(report)
    print(f"\nReport saved to {report_path}")

    validator.save_results()

    # Summary. The verdict has two independent axes and conflating them was
    # this suite's historic defect: `passed == total` over self.results says
    # nothing when the SKIP paths kept claims out of self.results entirely —
    # a build with no native backend used to validate 1-2 of the documented
    # claims, print "Pass rate: 100.0%", and exit 0.
    passed = sum(1 for r in validator.results if r.passed)
    total = len(validator.results)
    documented = len(validator.documented_claims)
    measured = len({r.claim_name for r in validator.results})
    unmeasured = validator.unmeasured_claims()

    print("\n" + "=" * 70)
    print("VALIDATION SUMMARY")
    print("=" * 70)
    print(f"  Documented claims:      {documented}")
    print(f"  Measured this run:      {measured}")
    print(f"  Passed: {passed}")
    print(f"  Failed: {total - passed}")
    print(f"  Pass rate: {passed / total * 100:.1f}%" if total > 0 else "  No results")

    exit_code = 0
    if passed != total:
        print("\n  Some benchmark claims need review.")
        exit_code = 1

    if unmeasured:
        print(f"\n  {len(unmeasured)} documented claim(s) produced no measurement:")
        for name, reason in sorted(unmeasured.items()):
            print(f"    - {name}: {reason}")
        if args.require_complete:
            print(
                "\n  --require-complete: a documented claim without a measurement"
                "\n  is a validation gap, not a pass. Failing."
            )
            exit_code = 1
        elif exit_code == 0:
            print(
                "\n  Measured rows all passed, but the run is incomplete;"
                "\n  re-run with --require-complete to fail on coverage gaps."
            )
    elif exit_code == 0:
        print("\n  All measurable documented claims validated successfully!")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
