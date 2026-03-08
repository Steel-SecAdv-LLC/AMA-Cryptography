#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
AMA Cryptography: Comprehensive Benchmark Suite
====================================================

Live empirical performance analysis with ethical integration.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Date: 2026-03-08
Version: 2.0
Project: AMA Cryptography Performance Analysis

AI Co-Architects:
    Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

import hashlib
import json
import os
import platform
import secrets
import statistics
import time
from datetime import datetime, timezone
from typing import Dict

# psutil is optional — used for richer system info when available
try:
    import psutil

    _HAS_PSUTIL = True
except ImportError:
    psutil = None  # type: ignore[assignment]
    _HAS_PSUTIL = False

from code_guardian_secure import (
    DILITHIUM_AVAILABLE,
    DILITHIUM_BACKEND,
    ETHICAL_VECTOR,
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    canonical_hash_code,
    create_crypto_package,
    create_ethical_hkdf_context,
    derive_keys,
    dilithium_sign,
    dilithium_verify,
    ed25519_sign,
    ed25519_verify,
    generate_dilithium_keypair,
    generate_ed25519_keypair,
    generate_key_management_system,
    hmac_authenticate,
    hmac_verify,
    length_prefixed_encode,
    native_hkdf,
    verify_crypto_package,
)


class BenchmarkSuite:
    """Comprehensive performance benchmarking for AMA Cryptography."""

    def __init__(self):
        self.results = {}
        self.system_info = self._get_system_info()

    def _get_system_info(self) -> Dict:
        """Collect system information for benchmark context."""
        info: Dict = {
            "platform": platform.platform(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "cpu_count": os.cpu_count() or 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dilithium_backend": DILITHIUM_BACKEND,
            "dilithium_available": DILITHIUM_AVAILABLE,
        }
        if _HAS_PSUTIL:
            info["cpu_count"] = psutil.cpu_count()
            info["memory_gb"] = round(psutil.virtual_memory().total / (1024**3), 2)
        return info

    def benchmark_operation(
        self, operation_name: str, operation_func, iterations: int = 1000
    ) -> Dict:
        """Benchmark a single operation with statistical analysis."""
        print(f"  📊 Benchmarking {operation_name} ({iterations} iterations)...")

        times = []
        for i in range(iterations):
            start = time.perf_counter()
            try:
                operation_func()
                end = time.perf_counter()
                times.append((end - start) * 1000)  # Convert to milliseconds
            except Exception as e:
                print(f"    ❌ Error in iteration {i}: {e}")
                continue

        if not times:
            return {"error": "All iterations failed"}

        stats = {
            "iterations": len(times),
            "mean_ms": round(statistics.mean(times), 4),
            "median_ms": round(statistics.median(times), 4),
            "min_ms": round(min(times), 4),
            "max_ms": round(max(times), 4),
            "std_dev_ms": round(statistics.stdev(times) if len(times) > 1 else 0, 4),
            "ops_per_sec": round(1000 / statistics.mean(times), 2),
        }

        print(f"    ✓ Mean: {stats['mean_ms']}ms ({stats['ops_per_sec']} ops/sec)")
        return stats

    def benchmark_key_generation(self) -> Dict:
        """Benchmark key generation operations."""
        print("🔑 Benchmarking Key Generation...")

        results = {}

        # Master secret generation
        results["master_secret"] = self.benchmark_operation(
            "Master Secret Generation", lambda: secrets.token_bytes(32), iterations=10000
        )

        # HKDF key derivation
        master_secret = secrets.token_bytes(32)
        results["hkdf_derivation"] = self.benchmark_operation(
            "HKDF Key Derivation",
            lambda: derive_keys(master_secret, "test", num_keys=3),
            iterations=1000,
        )

        # Ed25519 key generation
        results["ed25519_keygen"] = self.benchmark_operation(
            "Ed25519 Key Generation", lambda: generate_ed25519_keypair(), iterations=1000
        )

        # Dilithium key generation
        results["dilithium_keygen"] = self.benchmark_operation(
            "Dilithium Key Generation",
            lambda: generate_dilithium_keypair(),
            iterations=100,  # Slower, fewer iterations
        )

        # Complete KMS generation
        results["kms_generation"] = self.benchmark_operation(
            "Complete KMS Generation",
            lambda: generate_key_management_system("benchmark"),
            iterations=100,
        )

        return results

    def benchmark_cryptographic_operations(self) -> Dict:
        """Benchmark core cryptographic operations."""
        print("🔐 Benchmarking Cryptographic Operations...")

        # Setup test data
        test_data = b"Benchmark test data for AMA Cryptography cryptographic operations"
        kms = generate_key_management_system("benchmark")

        results = {}

        # SHA3-256 hashing
        results["sha3_256"] = self.benchmark_operation(
            "SHA3-256 Hashing", lambda: hashlib.sha3_256(test_data).digest(), iterations=10000
        )

        # HMAC authentication
        results["hmac_auth"] = self.benchmark_operation(
            "HMAC Authentication",
            lambda: hmac_authenticate(test_data, kms.hmac_key),
            iterations=10000,
        )

        # HMAC verification
        hmac_tag = hmac_authenticate(test_data, kms.hmac_key)
        results["hmac_verify"] = self.benchmark_operation(
            "HMAC Verification",
            lambda: hmac_verify(test_data, hmac_tag, kms.hmac_key),
            iterations=10000,
        )

        # Ed25519 signing
        results["ed25519_sign"] = self.benchmark_operation(
            "Ed25519 Signing",
            lambda: ed25519_sign(test_data, kms.ed25519_keypair.private_key),
            iterations=1000,
        )

        # Ed25519 verification
        ed25519_sig = ed25519_sign(test_data, kms.ed25519_keypair.private_key)
        results["ed25519_verify"] = self.benchmark_operation(
            "Ed25519 Verification",
            lambda: ed25519_verify(test_data, ed25519_sig, kms.ed25519_keypair.public_key),
            iterations=1000,
        )

        # Dilithium signing
        results["dilithium_sign"] = self.benchmark_operation(
            "Dilithium Signing",
            lambda: dilithium_sign(test_data, kms.dilithium_keypair.secret_key),
            iterations=100,
        )

        # Dilithium verification
        dilithium_sig = dilithium_sign(test_data, kms.dilithium_keypair.secret_key)
        results["dilithium_verify"] = self.benchmark_operation(
            "Dilithium Verification",
            lambda: dilithium_verify(test_data, dilithium_sig, kms.dilithium_keypair.public_key),
            iterations=100,
        )

        return results

    def benchmark_dna_operations(self) -> Dict:
        """Benchmark Code-specific operations."""
        print("🧬 Benchmarking Code Operations...")

        results = {}

        # Canonical encoding
        results["canonical_encoding"] = self.benchmark_operation(
            "Canonical Encoding",
            lambda: length_prefixed_encode("Code", MASTER_CODES, "HELIX", "test"),
            iterations=10000,
        )

        # Omni-Code hash computation
        results["code_hash"] = self.benchmark_operation(
            "Omni-Code Hash Computation",
            lambda: canonical_hash_code(MASTER_CODES, MASTER_HELIX_PARAMS),
            iterations=10000,
        )

        # Complete package creation
        kms = generate_key_management_system("benchmark")
        results["package_creation"] = self.benchmark_operation(
            "Complete Package Creation",
            lambda: create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "benchmark"),
            iterations=100,
        )

        # Package verification
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "benchmark")
        results["package_verification"] = self.benchmark_operation(
            "Package Verification",
            lambda: verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key),
            iterations=100,
        )

        return results

    def benchmark_ethical_integration(self) -> Dict:
        """Benchmark ethical integration overhead."""
        print("⚖️ Benchmarking Ethical Integration...")

        results = {}

        # Ethical context creation
        results["ethical_context"] = self.benchmark_operation(
            "Ethical Context Creation",
            lambda: create_ethical_hkdf_context(b"test", ETHICAL_VECTOR),
            iterations=10000,
        )

        # HKDF with vs without ethical context (both use native C backend)
        master_secret = secrets.token_bytes(32)
        hkdf_salt = secrets.token_bytes(32)
        plain_info = b"benchmark:baseline:0"

        # Raw native HKDF without ethical context (genuine baseline)
        results["hkdf_standard"] = self.benchmark_operation(
            "Standard HKDF (Native)",
            lambda: native_hkdf(
                ikm=master_secret, length=32, salt=hkdf_salt, info=plain_info
            ),
            iterations=1000,
        )

        # HKDF via derive_keys which adds ethical context overhead
        results["hkdf_ethical"] = self.benchmark_operation(
            "Ethical HKDF (Native)",
            lambda: derive_keys(
                master_secret, "benchmark:ethical", num_keys=1, ethical_vector=ETHICAL_VECTOR
            ),
            iterations=1000,
        )

        # Calculate overhead
        if "mean_ms" in results["hkdf_standard"] and "mean_ms" in results["hkdf_ethical"]:
            overhead_ms = results["hkdf_ethical"]["mean_ms"] - results["hkdf_standard"]["mean_ms"]
            overhead_pct = (overhead_ms / results["hkdf_standard"]["mean_ms"]) * 100
            results["ethical_overhead"] = {
                "overhead_ms": round(overhead_ms, 4),
                "overhead_pct": round(overhead_pct, 2),
            }
            print(f"    📈 Ethical overhead: {overhead_ms}ms ({overhead_pct:.2f}%)")

        return results

    def benchmark_scalability(self) -> Dict:
        """Benchmark scalability with different input sizes."""
        print("📈 Benchmarking Scalability...")

        results = {}
        kms = generate_key_management_system("benchmark")

        # Test different Omni-Code lengths
        dna_sizes = [1, 10, 100, 1000]
        for size in dna_sizes:
            codes = MASTER_CODES * size
            helix_params = MASTER_HELIX_PARAMS * size

            # Bind codes/helix_params via default args to avoid closure-over-loop-variable bug
            results[f"dna_size_{size}"] = self.benchmark_operation(
                f"Code Processing (size={size})",
                lambda c=codes, h=helix_params: create_crypto_package(c, h, kms, "benchmark"),
                iterations=50,
            )

        return results

    def run_comprehensive_benchmark(self) -> Dict:
        """Run complete benchmark suite."""
        print("🚀 Starting Comprehensive AMA Cryptography Benchmark Suite...")
        print(f"System: {self.system_info['platform']}")
        print(f"CPU: {self.system_info['cpu_count']} cores")
        if "memory_gb" in self.system_info:
            print(f"Memory: {self.system_info['memory_gb']} GB")
        print(f"Dilithium: {self.system_info['dilithium_backend']}")
        print("=" * 70)

        start_time = time.time()

        self.results = {
            "system_info": self.system_info,
            "benchmark_start": datetime.now(timezone.utc).isoformat(),
            "key_generation": self.benchmark_key_generation(),
            "cryptographic_operations": self.benchmark_cryptographic_operations(),
            "dna_operations": self.benchmark_dna_operations(),
            "ethical_integration": self.benchmark_ethical_integration(),
            "scalability": self.benchmark_scalability(),
        }

        total_time = time.time() - start_time
        self.results["benchmark_duration_sec"] = round(total_time, 2)
        self.results["benchmark_end"] = datetime.now(timezone.utc).isoformat()

        print("=" * 70)
        print(f"✅ Benchmark suite completed in {total_time:.2f} seconds")

        return self.results

    def save_results(self, filename: str = "benchmark_results.json"):
        """Save benchmark results to JSON file."""
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"📊 Results saved to: {filename}")


def main():
    """Run benchmark suite and save results."""
    suite = BenchmarkSuite()
    results = suite.run_comprehensive_benchmark()
    suite.save_results()

    # Print summary
    print("\n🎯 PERFORMANCE SUMMARY:")
    print("=" * 50)

    crypto_ops = results["cryptographic_operations"]
    print(
        f"Ed25519 Sign:     {crypto_ops['ed25519_sign']['mean_ms']:>8.2f}ms ({crypto_ops['ed25519_sign']['ops_per_sec']:>6.0f} ops/sec)"
    )
    print(
        f"Ed25519 Verify:   {crypto_ops['ed25519_verify']['mean_ms']:>8.2f}ms ({crypto_ops['ed25519_verify']['ops_per_sec']:>6.0f} ops/sec)"
    )
    print(
        f"Dilithium Sign:   {crypto_ops['dilithium_sign']['mean_ms']:>8.2f}ms ({crypto_ops['dilithium_sign']['ops_per_sec']:>6.0f} ops/sec)"
    )
    print(
        f"Dilithium Verify: {crypto_ops['dilithium_verify']['mean_ms']:>8.2f}ms ({crypto_ops['dilithium_verify']['ops_per_sec']:>6.0f} ops/sec)"
    )

    dna_ops = results["dna_operations"]
    print(
        f"Package Create:   {dna_ops['package_creation']['mean_ms']:>8.2f}ms ({dna_ops['package_creation']['ops_per_sec']:>6.0f} ops/sec)"
    )
    print(
        f"Package Verify:   {dna_ops['package_verification']['mean_ms']:>8.2f}ms ({dna_ops['package_verification']['ops_per_sec']:>6.0f} ops/sec)"
    )

    if "ethical_overhead" in results["ethical_integration"]:
        overhead = results["ethical_integration"]["ethical_overhead"]
        print(
            f"Ethical Overhead: {overhead['overhead_ms']:>8.2f}ms ({overhead['overhead_pct']:>6.2f}%)"
        )


if __name__ == "__main__":
    main()
