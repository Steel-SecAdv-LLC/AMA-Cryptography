#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Comparative Performance Benchmarking
=====================================

Compare AMA Cryptography performance against other peer cryptographic
libraries for the primitives AMA implements:

- **libsodium via PyNaCl** — Ed25519 keygen / sign / verify reference.
- **cryptography library (OpenSSL backend)** — Ed25519 sign / verify.
- **liboqs-python** — ML-DSA-65 sign / verify and ML-KEM-1024 encap / decap.
- **AMA Cryptography** — Ed25519 and ML-DSA-65 signatures, ML-KEM-1024
  encap / decap, via the existing ctypes FFI to libama_cryptography.so.

For every operation the runner reports (a) ops/sec and (b) a ratio vs.
AMA ("libsodium Ed25519 sign: 14.2x faster"). Operations whose peer
library is not installed in the environment are reported as
``available=False`` so the output is self-descriptive rather than
silently dropping columns.
"""

import json
import statistics
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@dataclass
class BenchmarkResult:
    """Single benchmark result"""

    implementation: str
    operation: str
    iterations: int
    mean_time_ms: float
    median_time_ms: float
    ops_per_sec: float
    available: bool
    error: Optional[str] = None


class ComparativeBenchmark:
    """Compare AMA Cryptography against other implementations"""

    def __init__(self, iterations: int = 1000):
        self.iterations = iterations
        self.results: List[BenchmarkResult] = []

    def benchmark_operation(self, name: str, operation: str, func, *args) -> BenchmarkResult:
        """Benchmark a single operation"""
        print(f"  Benchmarking {name} - {operation}...")

        times = []
        errors = []

        # Warmup
        for _ in range(min(10, self.iterations // 10)):
            try:
                func(*args)
            except Exception as e:
                errors.append(str(e))

        if len(errors) > 5:
            return BenchmarkResult(
                implementation=name,
                operation=operation,
                iterations=0,
                mean_time_ms=0,
                median_time_ms=0,
                ops_per_sec=0,
                available=False,
                error=errors[0],
            )

        # Actual benchmark
        for _ in range(self.iterations):
            start = time.perf_counter()
            try:
                func(*args)
                end = time.perf_counter()
                times.append((end - start) * 1000)  # Convert to ms
            except Exception as e:
                errors.append(str(e))

        if not times:
            return BenchmarkResult(
                implementation=name,
                operation=operation,
                iterations=0,
                mean_time_ms=0,
                median_time_ms=0,
                ops_per_sec=0,
                available=False,
                error=errors[0] if errors else "No successful iterations",
            )

        mean_time = statistics.mean(times)
        median_time = statistics.median(times)
        ops_per_sec = 1000 / mean_time if mean_time > 0 else 0

        print(f"    ✓ {mean_time:.4f}ms ({ops_per_sec:.2f} ops/sec)")

        return BenchmarkResult(
            implementation=name,
            operation=operation,
            iterations=len(times),
            mean_time_ms=mean_time,
            median_time_ms=median_time,
            ops_per_sec=ops_per_sec,
            available=True,
        )

    def benchmark_ama_cryptography(self):
        """Benchmark AMA Cryptography hybrid implementation"""
        print("\n" + "=" * 70)
        print("AMA CRYPTOGRAPHY HYBRID IMPLEMENTATION")
        print("=" * 70)

        try:
            from ama_cryptography.legacy_compat import (
                ed25519_sign,
                ed25519_verify,
                generate_ed25519_keypair,
            )

            # Ed25519 operations
            test_data = b"Test message for benchmarking performance" * 10

            self.results.append(
                self.benchmark_operation(
                    "AMA Cryptography",
                    "Ed25519 KeyGen",
                    generate_ed25519_keypair,
                )
            )

            ed_keypair = generate_ed25519_keypair()

            self.results.append(
                self.benchmark_operation(
                    "AMA Cryptography",
                    "Ed25519 Sign",
                    lambda: ed25519_sign(test_data, ed_keypair.private_key),
                )
            )

            ed_sig = ed25519_sign(test_data, ed_keypair.private_key)
            self.results.append(
                self.benchmark_operation(
                    "AMA Cryptography",
                    "Ed25519 Verify",
                    lambda: ed25519_verify(test_data, ed_sig, ed_keypair.public_key),
                )
            )

            # Try Dilithium if available
            try:
                from ama_cryptography.legacy_compat import (
                    dilithium_sign,
                    dilithium_verify,
                    generate_dilithium_keypair,
                )

                dil_keypair = generate_dilithium_keypair()
                if dil_keypair:
                    self.results.append(
                        self.benchmark_operation(
                            "AMA Cryptography",
                            "ML-DSA-65 Sign",
                            lambda: dilithium_sign(test_data, dil_keypair.secret_key),
                        )
                    )

                    dil_sig = dilithium_sign(test_data, dil_keypair.secret_key)
                    self.results.append(
                        self.benchmark_operation(
                            "AMA Cryptography",
                            "ML-DSA-65 Verify",
                            lambda: dilithium_verify(test_data, dil_sig, dil_keypair.public_key),
                        )
                    )

                    # Hybrid operation (both signatures)
                    def hybrid_sign():
                        ed25519_sign(test_data, ed_keypair.private_key)
                        dilithium_sign(test_data, dil_keypair.secret_key)

                    def hybrid_verify():
                        ed25519_verify(test_data, ed_sig, ed_keypair.public_key)
                        dilithium_verify(test_data, dil_sig, dil_keypair.public_key)

                    self.results.append(
                        self.benchmark_operation("AMA Cryptography", "Hybrid Sign", hybrid_sign)
                    )
                    self.results.append(
                        self.benchmark_operation("AMA Cryptography", "Hybrid Verify", hybrid_verify)
                    )
            except Exception as e:
                print(f"  ⚠ Dilithium not available: {e}")

            # ML-KEM-1024 encap/decap via the same ctypes FFI that PQC
            # backends use. Kept separate from the ML-DSA block because
            # ML-KEM is available independently.
            try:
                from ama_cryptography.pqc_backends import (
                    generate_kyber_keypair,
                    kyber_decapsulate,
                    kyber_encapsulate,
                )

                kem_kp = generate_kyber_keypair()
                enc = kyber_encapsulate(kem_kp.public_key)
                self.results.append(
                    self.benchmark_operation(
                        "AMA Cryptography",
                        "ML-KEM-1024 Encap",
                        lambda: kyber_encapsulate(kem_kp.public_key),
                    )
                )
                self.results.append(
                    self.benchmark_operation(
                        "AMA Cryptography",
                        "ML-KEM-1024 Decap",
                        lambda: kyber_decapsulate(enc.ciphertext, kem_kp.secret_key),
                    )
                )
            except Exception as e:
                print(f"  ⚠ ML-KEM-1024 not available: {e}")

        except Exception as e:
            print(f"  ❌ Error benchmarking AMA Cryptography: {e}")

    def benchmark_libsodium_ed25519(self):
        """Benchmark libsodium Ed25519 via PyNaCl.

        PyNaCl wraps libsodium 1.0.x and its hand-tuned AVX2 ref10
        implementation. This is the de-facto reference for Ed25519
        throughput on x86-64 — SUPERCOP bench-amd64 numbers are typically
        within 10% of libsodium's.
        """
        print("\n" + "=" * 70)
        print("LIBSODIUM (PyNaCl)")
        print("=" * 70)

        try:
            import subprocess

            check = subprocess.run(
                [sys.executable, "-c", "from nacl.signing import SigningKey"],
                capture_output=True,
                timeout=5,
            )
            if check.returncode != 0:
                raise ImportError("PyNaCl not importable")

            from nacl.signing import SigningKey, VerifyKey  # noqa: F401

            test_data = b"Test message for benchmarking performance" * 10

            self.results.append(
                self.benchmark_operation(
                    "libsodium (PyNaCl)",
                    "Ed25519 KeyGen",
                    SigningKey.generate,
                )
            )

            signer = SigningKey.generate()
            verifier = signer.verify_key

            # nacl.signing.SigningKey.sign returns a SignedMessage; the
            # verify method accepts either a SignedMessage or (sig, msg).
            self.results.append(
                self.benchmark_operation(
                    "libsodium (PyNaCl)",
                    "Ed25519 Sign",
                    lambda: signer.sign(test_data),
                )
            )

            signed = signer.sign(test_data)
            self.results.append(
                self.benchmark_operation(
                    "libsodium (PyNaCl)",
                    "Ed25519 Verify",
                    lambda: verifier.verify(signed),
                )
            )

        except (ImportError, OSError, Exception) as e:
            print(f"  SKIP: PyNaCl not available ({type(e).__name__})")
            for op in ("Ed25519 KeyGen", "Ed25519 Sign", "Ed25519 Verify"):
                self.results.append(
                    BenchmarkResult(
                        implementation="libsodium (PyNaCl)",
                        operation=op,
                        iterations=0,
                        mean_time_ms=0,
                        median_time_ms=0,
                        ops_per_sec=0,
                        available=False,
                        error=f"PyNaCl not available: {type(e).__name__}",
                    )
                )

    def benchmark_liboqs_ml_kem(self):
        """Benchmark liboqs ML-KEM-1024 encap/decap.

        liboqs 0.10+ exposes the NIST-final ML-KEM-1024 name directly.
        Older liboqs builds shipped ``Kyber1024`` instead — the try/except
        handles both so the harness does not silently skip on pre-0.10
        installs.
        """
        print("\n" + "=" * 70)
        print("LIBOQS ML-KEM-1024 (Direct)")
        print("=" * 70)

        try:
            import oqs

            algo = None
            for candidate in ("ML-KEM-1024", "Kyber1024"):
                try:
                    probe = oqs.KeyEncapsulation(candidate)
                    probe.generate_keypair()
                    algo = candidate
                    break
                except Exception:
                    continue
            if algo is None:
                raise RuntimeError("liboqs has no ML-KEM-1024 / Kyber1024")

            client = oqs.KeyEncapsulation(algo)
            public_key = client.generate_keypair()

            # Encapsulation uses the public key — instantiate a separate
            # session to match production usage (one side encaps for the
            # other).
            peer = oqs.KeyEncapsulation(algo)
            ciphertext, _shared = peer.encap_secret(public_key)

            self.results.append(
                self.benchmark_operation(
                    "liboqs-python",
                    "ML-KEM-1024 Encap",
                    lambda: peer.encap_secret(public_key),
                )
            )

            self.results.append(
                self.benchmark_operation(
                    "liboqs-python",
                    "ML-KEM-1024 Decap",
                    lambda: client.decap_secret(ciphertext),
                )
            )

        except (ImportError, Exception) as e:
            print(f"  SKIP: liboqs ML-KEM not available ({type(e).__name__})")
            for op in ("ML-KEM-1024 Encap", "ML-KEM-1024 Decap"):
                self.results.append(
                    BenchmarkResult(
                        implementation="liboqs-python",
                        operation=op,
                        iterations=0,
                        mean_time_ms=0,
                        median_time_ms=0,
                        ops_per_sec=0,
                        available=False,
                        error=f"liboqs ML-KEM not available: {type(e).__name__}",
                    )
                )

    def benchmark_cryptography_ed25519(self):
        """Benchmark cryptography library (OpenSSL backend) Ed25519"""
        print("\n" + "=" * 70)
        print("CRYPTOGRAPHY LIBRARY (OpenSSL Backend)")
        print("=" * 70)

        try:
            # Pre-check: verify cryptography library is functional
            # (guards against broken CFFI/Rust/pyo3 bindings that panic on import)
            import subprocess

            check = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey",
                ],
                capture_output=True,
                timeout=5,
            )
            if check.returncode != 0:
                raise ImportError("cryptography library has broken bindings")

            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )

            test_data = b"Test message for benchmarking performance" * 10

            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key()

            self.results.append(
                self.benchmark_operation(
                    "cryptography (OpenSSL)",
                    "Ed25519 Sign",
                    lambda: private_key.sign(test_data),
                )
            )

            signature = private_key.sign(test_data)
            self.results.append(
                self.benchmark_operation(
                    "cryptography (OpenSSL)",
                    "Ed25519 Verify",
                    lambda: public_key.verify(signature, test_data),
                )
            )

        except (ImportError, OSError, Exception) as e:
            print(f"  SKIP: cryptography library not available ({type(e).__name__})")
            self.results.append(
                BenchmarkResult(
                    implementation="cryptography (OpenSSL)",
                    operation="Ed25519",
                    iterations=0,
                    mean_time_ms=0,
                    median_time_ms=0,
                    ops_per_sec=0,
                    available=False,
                    error=f"cryptography library not available: {type(e).__name__}",
                )
            )

    def benchmark_liboqs_direct(self):
        """Benchmark pure liboqs-python (if available)"""
        print("\n" + "=" * 70)
        print("LIBOQS-PYTHON (Direct)")
        print("=" * 70)

        try:
            import oqs

            test_data = b"Test message for benchmarking performance" * 10

            # Test ML-DSA-65 (official NIST name, replaces Dilithium3)
            try:
                signer = oqs.Signature("ML-DSA-65")
                public_key = signer.generate_keypair()

                self.results.append(
                    self.benchmark_operation(
                        "liboqs-python",
                        "ML-DSA-65 Sign",
                        lambda: signer.sign(test_data),
                    )
                )

                signature = signer.sign(test_data)
                self.results.append(
                    self.benchmark_operation(
                        "liboqs-python",
                        "ML-DSA-65 Verify",
                        lambda: signer.verify(test_data, signature, public_key),
                    )
                )
            except Exception as e:
                print(f"  SKIP: ML-DSA-65 error: {e}")
                self.results.append(
                    BenchmarkResult(
                        implementation="liboqs-python",
                        operation="ML-DSA-65",
                        iterations=0,
                        mean_time_ms=0,
                        median_time_ms=0,
                        ops_per_sec=0,
                        available=False,
                        error=str(e),
                    )
                )

        except (ImportError, Exception) as e:
            print(f"  SKIP: liboqs-python not available ({type(e).__name__})")
            self.results.append(
                BenchmarkResult(
                    implementation="liboqs-python",
                    operation="ML-DSA-65",
                    iterations=0,
                    mean_time_ms=0,
                    median_time_ms=0,
                    ops_per_sec=0,
                    available=False,
                    error=f"liboqs-python not available: {type(e).__name__}",
                )
            )

    def benchmark_hybrid_openssl_liboqs(self):
        """Benchmark hybrid Ed25519 (OpenSSL) + ML-DSA-65 (liboqs)"""
        print("\n" + "=" * 70)
        print("HYBRID: OpenSSL Ed25519 + liboqs ML-DSA-65")
        print("=" * 70)

        try:
            # Pre-check: verify both libraries are functional
            import subprocess

            check = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import oqs; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey",
                ],
                capture_output=True,
                timeout=5,
            )
            if check.returncode != 0:
                raise ImportError("oqs and/or cryptography library not available")

            import oqs
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            test_data = b"Test message for benchmarking performance" * 10

            # Setup Ed25519
            ed_private = Ed25519PrivateKey.generate()
            ed_public = ed_private.public_key()

            # Setup ML-DSA-65
            ml_signer = oqs.Signature("ML-DSA-65")
            ml_public = ml_signer.generate_keypair()

            # Hybrid sign (both signatures)
            def hybrid_sign():
                ed_private.sign(test_data)
                ml_signer.sign(test_data)

            # Hybrid verify (both verifications)
            ed_sig = ed_private.sign(test_data)
            ml_sig = ml_signer.sign(test_data)

            def hybrid_verify():
                ed_public.verify(ed_sig, test_data)
                ml_signer.verify(test_data, ml_sig, ml_public)

            self.results.append(
                self.benchmark_operation("OpenSSL+liboqs", "Hybrid Sign", hybrid_sign)
            )
            self.results.append(
                self.benchmark_operation("OpenSSL+liboqs", "Hybrid Verify", hybrid_verify)
            )

        except (ImportError, Exception) as e:
            print(
                f"  SKIP: Hybrid benchmark requires both cryptography and liboqs ({type(e).__name__})"
            )
            self.results.append(
                BenchmarkResult(
                    implementation="OpenSSL+liboqs",
                    operation="Hybrid",
                    iterations=0,
                    mean_time_ms=0,
                    median_time_ms=0,
                    ops_per_sec=0,
                    available=False,
                    error=f"Dependencies not available: {type(e).__name__}",
                )
            )

    def calculate_comparative_metrics(self) -> Dict:
        """Calculate comparative metrics between implementations"""
        print("\n" + "=" * 70)
        print("COMPARATIVE ANALYSIS")
        print("=" * 70)

        comparisons = {}

        # Group by operation
        by_operation = {}
        for result in self.results:
            if result.available:
                if result.operation not in by_operation:
                    by_operation[result.operation] = []
                by_operation[result.operation].append(result)

        # Calculate relative performance. Ratio is expressed as
        # peer_ops_per_sec / ama_ops_per_sec so readers see "libsodium
        # Ed25519 sign: 14.2x faster" rather than a slowdown factor that
        # has to be mentally flipped for the peer-faster case.
        for operation, results in by_operation.items():
            if len(results) < 2:
                continue

            ama_result = next((r for r in results if r.implementation == "AMA Cryptography"), None)
            if not ama_result or ama_result.ops_per_sec <= 0:
                continue

            print(f"\n{operation}:")
            print(
                f"  AMA Cryptography: {ama_result.mean_time_ms:.4f}ms "
                f"({ama_result.ops_per_sec:,.0f} ops/sec)"
            )

            for result in results:
                if result.implementation == "AMA Cryptography":
                    continue
                if result.ops_per_sec <= 0 or ama_result.mean_time_ms <= 0:
                    continue

                peer_ratio = result.ops_per_sec / ama_result.ops_per_sec
                slowdown = result.mean_time_ms / ama_result.mean_time_ms
                if peer_ratio >= 1.0:
                    verdict = f"{peer_ratio:.2f}x faster than AMA"
                else:
                    verdict = f"AMA {1/peer_ratio:.2f}x faster"

                print(
                    f"  {result.implementation}: {result.mean_time_ms:.4f}ms "
                    f"({result.ops_per_sec:,.0f} ops/sec) — {verdict}"
                )

                comparisons[f"{operation}_{result.implementation}"] = {
                    "peer_to_ama_ratio": peer_ratio,
                    "slowdown_factor": slowdown,
                    "ama_cryptography_faster_by_percent": (slowdown - 1) * 100,
                    "verdict": verdict,
                }

        return comparisons

    def save_results(self, filename: str = "comparative_benchmark_results.json"):
        """Save results to JSON"""
        data = {
            "timestamp": datetime.now().isoformat(),
            "iterations": self.iterations,
            "results": [
                {
                    "implementation": r.implementation,
                    "operation": r.operation,
                    "iterations": r.iterations,
                    "mean_time_ms": r.mean_time_ms,
                    "median_time_ms": r.median_time_ms,
                    "ops_per_sec": r.ops_per_sec,
                    "available": r.available,
                    "error": r.error,
                }
                for r in self.results
            ],
            "comparisons": self.calculate_comparative_metrics(),
        }

        output_path = Path(__file__).parent / filename
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

        print(f"\n✓ Results saved to {output_path}")
        return data


def main():
    """Run comparative benchmarks"""
    print("=" * 70)
    print("AMA CRYPTOGRAPHY - COMPARATIVE PERFORMANCE BENCHMARK")
    print("=" * 70)
    print()
    print("Comparing AMA Cryptography against:")
    print("  1. libsodium via PyNaCl (Ed25519)")
    print("  2. cryptography library (OpenSSL backend, Ed25519)")
    print("  3. liboqs-python — ML-DSA-65 and ML-KEM-1024")
    print()

    bench = ComparativeBenchmark(iterations=1000)

    # Run all benchmarks
    bench.benchmark_ama_cryptography()
    bench.benchmark_libsodium_ed25519()
    bench.benchmark_cryptography_ed25519()
    bench.benchmark_liboqs_direct()
    bench.benchmark_liboqs_ml_kem()
    bench.benchmark_hybrid_openssl_liboqs()

    # Calculate and display comparisons
    comparisons = bench.calculate_comparative_metrics()

    # Save results
    bench.save_results()

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    available = [r for r in bench.results if r.available]
    unavailable = [r for r in bench.results if not r.available]

    print(f"Total benchmarks: {len(bench.results)}")
    print(f"Available: {len(available)}")
    print(f"Unavailable: {len(unavailable)}")

    if comparisons:
        print("\nKey Findings:")
        for key, data in comparisons.items():
            if "slowdown_factor" in data:
                print(f"  {key}: {data['slowdown_factor']:.2f}x slowdown")


if __name__ == "__main__":
    main()
