#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Comparative Performance Benchmarking
=====================================

Compare AMA Cryptography performance against other peer cryptographic
libraries for the primitives AMA implements:

- **libsodium via PyNaCl** — Ed25519 keygen / sign / verify reference.
- **cryptography library (OpenSSL backend)** — Ed25519 sign / verify.
- **AMA Cryptography** — Ed25519 and ML-DSA-65 signatures, ML-KEM-1024
  encap / decap, via the existing ctypes FFI to libama_cryptography.so.

For every operation the runner reports (a) ops/sec and (b) a ratio vs.
AMA ("libsodium Ed25519 sign: 14.2x faster"). Operations whose peer
library is not installed in the environment are reported as
``available=False`` so the output is self-descriptive rather than
silently dropping columns.

Peer libraries (PyNaCl / libsodium, cryptography) are
BENCHMARK-ONLY comparison targets. They are **NOT** dependencies of
AMA Cryptography and **are NOT used in any production code path** —
they appear in this file, in ``benchmarks/requirements-bench.txt``,
in the ``benchmark`` extra of ``pyproject.toml``, and in nothing else.
The INVARIANT-1 "zero external crypto dependencies" property of the
production library is unaffected by this script. To install the peer
libraries for local benchmarking, either::

    pip install ".[benchmark]"

(when the repo is installable via its build backend — the preferred
form), or the equivalent flat pin file::

    pip install -r benchmarks/requirements-bench.txt
"""

import json
import statistics
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from collections.abc import Callable
from typing import Any, Dict, List, Optional

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

    def benchmark_operation(
        self, name: str, operation: str, func: Callable[..., object], *args: Any
    ) -> BenchmarkResult:
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

    def benchmark_ama_raw_c(self) -> None:
        """Run the raw-C harness (`benchmarks/benchmark_c_raw`) and record
        its ops/sec numbers as a separate implementation column.

        The Python/ctypes path measured elsewhere in this script pays a
        ~2-15 µs per-call FFI tax on top of every primitive (GIL release /
        re-acquire, ctypes argument marshalling, Python wrapper dispatch).
        That overhead dominates the measurement for sub-microsecond
        primitives like SHA3-256, making a peer-vs-AMA ratio computed off
        the ctypes path unfairly pessimistic for AMA's actual C throughput.

        By sourcing a separate "AMA Cryptography (Raw C)" column from the
        harness binary, reviewers can see:
          - the raw C number (what the library actually does),
          - the ctypes-taxed number (what Python callers see today), and
          - the peer library (PyNaCl / cryptography) on the same
            Python surface.

        The "Ed25519 Verify" row exercises the build-selected verify
        scalar-mult path for the active backend.  For the in-tree C
        backend (AMA_ED25519_ASSEMBLY=OFF), AMA_ED25519_VERIFY_SHAMIR
        selects Shamir/Straus joint mult (default,
        -DAMA_ED25519_VERIFY_SHAMIR=1) or the legacy split layout
        (-DAMA_ED25519_VERIFY_SHAMIR=0).  When the donna shim is in use
        (AMA_ED25519_ASSEMBLY=ON, auto-enabled on MSVC x64), those
        CMake gates are ignored, so toggling AMA_ED25519_VERIFY_SHAMIR
        does not change the benchmarked verify path.

        Build prerequisite: the harness binary must exist.  Build with
        `cmake --build build --target benchmark_c_raw` before running, or
        `make -C benchmarks benchmark_c_raw`.  When the binary is missing
        the method emits an `available=False` placeholder row so the
        column shows up as "SKIP" in the summary rather than silently
        vanishing.
        """
        print("\n" + "=" * 70)
        print("AMA CRYPTOGRAPHY (RAW C — no ctypes)")
        print("=" * 70)

        import subprocess

        # Search common locations for the harness binary.  On Windows the
        # CMake target produces benchmark_c_raw.exe in Release/Debug
        # subdirectories, and the Unix-style executable-bit check (`st_mode
        # & 0o111`) is not meaningful — os.access(path, os.X_OK) gives the
        # right answer on both platforms (ACL-checked on Windows, mode-
        # checked on POSIX).
        import os

        repo_root = Path(__file__).parent.parent
        names = ("benchmark_c_raw", "benchmark_c_raw.exe")
        search_roots = [
            repo_root / "build" / "bin",
            repo_root / "build" / "bin" / "Release",
            repo_root / "build" / "bin" / "Debug",
            repo_root / "build",
            repo_root / "benchmarks",
            repo_root / "benchmarks" / "build",
            Path("."),
        ]
        candidates = [root / name for root in search_roots for name in names]
        binary = next(
            (p for p in candidates if p.is_file() and os.access(p, os.X_OK)),
            None,
        )

        if binary is None:
            print(
                "  SKIP: benchmark_c_raw binary not found. "
                "Build with `cmake --build build --target benchmark_c_raw`."
            )
            self.results.append(
                BenchmarkResult(
                    implementation="AMA Cryptography (Raw C)",
                    operation="Raw C harness",
                    iterations=0,
                    mean_time_ms=0,
                    median_time_ms=0,
                    ops_per_sec=0,
                    available=False,
                    error="benchmark_c_raw binary not built",
                )
            )
            return

        print(f"  Using: {binary}")
        try:
            # The ceiling follows the harness's own cost model, not the "~8s
            # total" an earlier comment asserted: SLH-DSA keygen alone is
            # ITERS_SLOW (200) x ~164 ms ≈ 33 s, and the full run measures
            # 109 s on a 4-core x86-64 sandbox (2026-08-30, Release build).
            # The old timeout=60 therefore expired on every run since the
            # SLH-DSA rows landed, silently degrading the entire raw-C
            # column to "harness error: TimeoutExpired".  600 s is ~5.5x the
            # measured total, headroom for slower shared runners.
            completed = subprocess.run(
                [str(binary), "--json"],
                capture_output=True,
                text=True,
                timeout=600,
                check=True,
            )
            data = json.loads(completed.stdout)
        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            json.JSONDecodeError,
        ) as e:
            print(f"  SKIP: harness run failed ({type(e).__name__}: {e})")
            self.results.append(
                BenchmarkResult(
                    implementation="AMA Cryptography (Raw C)",
                    operation="Raw C harness",
                    iterations=0,
                    mean_time_ms=0,
                    median_time_ms=0,
                    ops_per_sec=0,
                    available=False,
                    error=f"harness error: {type(e).__name__}",
                )
            )
            return

        # Map harness operation names to the labels used elsewhere in
        # this script so the comparative-metrics grouping finds them.
        name_map = {
            "Ed25519 KeyGen": "Ed25519 KeyGen",
            "Ed25519 Sign": "Ed25519 Sign",
            "Ed25519 Verify": "Ed25519 Verify",
            "ML-DSA-65 KeyGen": "ML-DSA-65 KeyGen",
            "ML-DSA-65 Sign": "ML-DSA-65 Sign",
            "ML-DSA-65 Verify": "ML-DSA-65 Verify",
            "ML-KEM-1024 KeyGen": "ML-KEM-1024 KeyGen",
            "ML-KEM-1024 Encaps": "ML-KEM-1024 Encap",
            "ML-KEM-1024 Decaps": "ML-KEM-1024 Decap",
        }
        for row in data.get("results", []):
            op_src = row.get("operation", "")
            op_dst = name_map.get(op_src)
            if op_dst is None:
                continue  # not one of the peer-comparable ops
            mean_ms = float(row.get("mean_us", 0)) / 1000.0
            median_ms = float(row.get("median_us", 0)) / 1000.0
            self.results.append(
                BenchmarkResult(
                    implementation="AMA Cryptography (Raw C)",
                    operation=op_dst,
                    iterations=int(row.get("iterations", 0)),
                    mean_time_ms=mean_ms,
                    median_time_ms=median_ms,
                    ops_per_sec=float(row.get("ops_per_sec", 0)),
                    available=True,
                )
            )
            print(
                f"  ✓ {op_dst}: {mean_ms:.4f} ms "
                f"({float(row.get('ops_per_sec', 0)):,.0f} ops/sec)"
            )

    def benchmark_ama_cryptography(self) -> None:
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
                    def hybrid_sign() -> None:
                        ed25519_sign(test_data, ed_keypair.private_key)
                        dilithium_sign(test_data, dil_keypair.secret_key)

                    def hybrid_verify() -> None:
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

    def benchmark_libsodium_ed25519(self) -> None:
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

            from nacl.signing import SigningKey, VerifyKey  # fmt: skip  # noqa: F401 -- imported only to probe PyNaCl availability for the comparison benchmark (CB-001)

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

    def benchmark_cryptography_ed25519(self) -> None:
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

    def benchmark_aes_gcm_comparison(self) -> None:
        """Benchmark AES-256-GCM at 1 / 4 / 16 / 64 KB.

        PR A (2026-04) — adds the 4 KB / 16 KB / 64 KB rows requested in
        the brief; the existing 1 KB row is the historical reference
        point.  Compares the AMA dispatched path (which routes through
        the VAES + VPCLMULQDQ YMM kernel on Ice Lake+ / Alder Lake+ /
        Zen 3+ hosts via ``ama_cpuid_has_vaes_aesgcm``) against the
        ``cryptography`` library's OpenSSL AES-NI reference path.

        Both columns route through the same Python overhead floor
        (ctypes call for AMA, CFFI for ``cryptography``) so the
        comparison reflects per-byte kernel cost plus a roughly
        constant FFI overhead — the bare-metal raw-C numbers in
        ``benchmark_c_raw.c`` are the authoritative measurement of
        kernel throughput.
        """
        print("\n" + "=" * 70)
        print("AES-256-GCM @ 1 / 4 / 16 / 64 KB — AMA vs OpenSSL AES-NI")
        print("=" * 70)

        sizes = [1024, 4096, 16384, 65536]

        # AMA side via the existing native ctypes wrapper.
        try:
            from ama_cryptography.pqc_backends import (
                native_aes256_gcm_decrypt,
                native_aes256_gcm_encrypt,
            )

            key = b"\x42" * 32
            nonce = b"\x01" * 12
            aad = b""

            for sz in sizes:
                pt = b"\x00" * sz
                # Probe — surfaces RuntimeError on a build without
                # native AES-GCM linked in.
                ct, tag = native_aes256_gcm_encrypt(key, nonce, pt, aad)
                self.results.append(
                    self.benchmark_operation(
                        "AMA Cryptography",
                        f"AES-256-GCM Enc {sz // 1024}KB",
                        lambda p=pt: native_aes256_gcm_encrypt(key, nonce, p, aad),
                    )
                )
                self.results.append(
                    self.benchmark_operation(
                        "AMA Cryptography",
                        f"AES-256-GCM Dec {sz // 1024}KB",
                        lambda c=ct, t=tag: native_aes256_gcm_decrypt(key, nonce, c, t, aad),
                    )
                )
        except Exception as e:
            print(f"  SKIP AMA AES-GCM: {type(e).__name__}: {e}")
            self.results.append(
                BenchmarkResult(
                    implementation="AMA Cryptography",
                    operation="AES-256-GCM",
                    iterations=0,
                    mean_time_ms=0,
                    median_time_ms=0,
                    ops_per_sec=0,
                    available=False,
                    error=f"native AES-GCM not available: {type(e).__name__}",
                )
            )

        # OpenSSL AES-NI reference via the cryptography library.
        try:
            # Pre-check: verify cryptography library is functional
            # (guards against broken CFFI/Rust/pyo3 bindings that panic
            # on import — same pattern as benchmark_cryptography_ed25519
            # above, so the benchmark suite SKIPs cleanly instead of
            # aborting the whole process on a broken install).
            import subprocess

            check = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from cryptography.hazmat.primitives.ciphers.aead import AESGCM",
                ],
                capture_output=True,
                timeout=5,
            )
            if check.returncode != 0:
                raise ImportError("cryptography library has broken bindings")

            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            key = b"\x42" * 32
            nonce = b"\x01" * 12
            aad = b""
            aead = AESGCM(key)

            for sz in sizes:
                pt = b"\x00" * sz
                ct = aead.encrypt(nonce, pt, aad)
                self.results.append(
                    self.benchmark_operation(
                        "cryptography (OpenSSL)",
                        f"AES-256-GCM Enc {sz // 1024}KB",
                        lambda p=pt: aead.encrypt(nonce, p, aad),
                    )
                )
                self.results.append(
                    self.benchmark_operation(
                        "cryptography (OpenSSL)",
                        f"AES-256-GCM Dec {sz // 1024}KB",
                        lambda c=ct: aead.decrypt(nonce, c, aad),
                    )
                )
        except Exception as e:
            print(f"  SKIP OpenSSL AES-GCM: {type(e).__name__}")
            self.results.append(
                BenchmarkResult(
                    implementation="cryptography (OpenSSL)",
                    operation="AES-256-GCM",
                    iterations=0,
                    mean_time_ms=0,
                    median_time_ms=0,
                    ops_per_sec=0,
                    available=False,
                    error=f"cryptography library not available: {type(e).__name__}",
                )
            )

    def calculate_comparative_metrics(self) -> Dict[str, Any]:
        """Calculate comparative metrics between implementations"""
        print("\n" + "=" * 70)
        print("COMPARATIVE ANALYSIS")
        print("=" * 70)

        comparisons = {}

        # Group by operation
        by_operation: Dict[str, List[BenchmarkResult]] = {}
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
            # Raw-C first if present, so the FFI overhead is visible as
            # the gap between the Raw-C and ctypes lines.
            raw_c_result = next(
                (r for r in results if r.implementation == "AMA Cryptography (Raw C)"),
                None,
            )
            if raw_c_result:
                print(
                    f"  AMA Cryptography (Raw C): {raw_c_result.mean_time_ms:.4f}ms "
                    f"({raw_c_result.ops_per_sec:,.0f} ops/sec)"
                )
            print(
                f"  AMA Cryptography: {ama_result.mean_time_ms:.4f}ms "
                f"({ama_result.ops_per_sec:,.0f} ops/sec)"
            )

            for result in results:
                if result.implementation == "AMA Cryptography (Raw C)":
                    continue  # already printed above
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
                    # Positive = peer is slower (AMA wins); negative = peer
                    # is faster (AMA loses). The old field name
                    # `ama_cryptography_faster_by_percent` was read as "how
                    # much faster AMA is than peer", but the computed sign
                    # actually matches "how much slower the peer is than
                    # AMA". Renamed to make the sign convention match the
                    # name. Computed as (peer_ms / ama_ms - 1) * 100, which
                    # is the same as (ama_ops / peer_ops - 1) * 100.
                    "peer_slower_by_percent": (slowdown - 1) * 100,
                    "verdict": verdict,
                }

        return comparisons

    def save_results(self, filename: str = "comparative_benchmark_results.json") -> Dict[str, Any]:
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
        # The provenance block generate_competitive.py hard-requires.  Its
        # error message has always said "re-run the harness (which records
        # it)" — until this line, the harness recorded no such thing and the
        # committed block existed only because someone once added it by
        # hand, so the very next regeneration would have detached the page
        # from any honest version stamp.
        data["provenance"] = _measurement_provenance()

        output_path = Path(__file__).parent / filename
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

        print(f"\n✓ Results saved to {output_path}")
        return data


def _measurement_provenance() -> "dict[str, str]":
    """The block generate_competitive.py refuses to render without.

    Version from the imported package (the build actually measured, not the
    working tree's source text), commit from git at measurement time.
    """
    import subprocess
    from datetime import datetime, timezone

    import ama_cryptography

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
        cwd=Path(__file__).parent,
    ).stdout.strip()
    return {
        "ama_version": ama_cryptography.__version__,
        "ama_commit": commit,
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "note": "written by the harness at measurement time",
    }


def main() -> None:
    """Run comparative benchmarks"""
    print("=" * 70)
    print("AMA CRYPTOGRAPHY - COMPARATIVE PERFORMANCE BENCHMARK")
    print("=" * 70)
    print()
    print("Comparing AMA Cryptography against:")
    print("  1. libsodium via PyNaCl (Ed25519)")
    print("  2. cryptography library (OpenSSL backend, Ed25519)")
    print()

    bench = ComparativeBenchmark(iterations=1000)

    # Run all benchmarks.  Raw-C goes first so the summary table displays
    # the unfiltered C number above the ctypes-taxed AMA column, making
    # the FFI overhead visually obvious.
    bench.benchmark_ama_raw_c()
    bench.benchmark_ama_cryptography()
    bench.benchmark_libsodium_ed25519()
    bench.benchmark_cryptography_ed25519()
    bench.benchmark_aes_gcm_comparison()

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
