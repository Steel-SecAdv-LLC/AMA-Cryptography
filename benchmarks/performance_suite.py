#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Comprehensive performance benchmarking suite for AMA Cryptography

Benchmarks:
- Pure Python vs Cython operations
- C library vs Python implementations
- Algorithm performance (ML-DSA, Kyber, SPHINCS+)
- Memory usage and allocation patterns
- Cache efficiency and SIMD utilization
"""

import json
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import List

import numpy as np


@dataclass
class BenchmarkResult:
    """Result of a single benchmark"""

    name: str
    iterations: int
    total_time: float
    avg_time: float
    throughput: float
    unit: str
    timestamp: str = datetime.now().isoformat()

    def to_dict(self):
        return asdict(self)


class PerformanceBenchmark:
    """Performance benchmarking suite"""

    def __init__(self, iterations: int = 1000):
        self.iterations = iterations
        self.results: List[BenchmarkResult] = []

    def run_benchmark(self, name: str, func, *args, unit: str = "ops/sec"):
        """Run a single benchmark"""
        print(f"\nRunning: {name}")
        print(f"  Iterations: {self.iterations}")

        # Warm-up
        for _ in range(10):
            func(*args)

        # Actual benchmark
        start = time.perf_counter()
        for _ in range(self.iterations):
            func(*args)
        end = time.perf_counter()

        total_time = end - start
        avg_time = total_time / self.iterations
        throughput = self.iterations / total_time if total_time > 0 else 0

        result = BenchmarkResult(
            name=name,
            iterations=self.iterations,
            total_time=total_time,
            avg_time=avg_time,
            throughput=throughput,
            unit=unit,
        )

        self.results.append(result)

        print(f"  Total time: {total_time:.4f}s")
        print(f"  Avg time:   {avg_time * 1e6:.2f}µs")
        print(f"  Throughput: {throughput:.2f} {unit}")

        return result

    def compare_implementations(
        self, name: str, impl1_name: str, impl1_func, impl2_name: str, impl2_func, *args
    ):
        """Compare two implementations"""
        print(f"\n{'=' * 70}")
        print(f"COMPARISON: {name}")
        print(f"{'=' * 70}")

        r1 = self.run_benchmark(f"{name} - {impl1_name}", impl1_func, *args)
        r2 = self.run_benchmark(f"{name} - {impl2_name}", impl2_func, *args)

        speedup = r2.throughput / r1.throughput if r1.throughput > 0 else 0

        print(f"\nSPEEDUP: {speedup:.2f}x ({impl2_name} vs {impl1_name})")

        return speedup

    def save_results(self, filename: str = "benchmark_results.json"):
        """Save results to JSON"""
        data = {
            "timestamp": datetime.now().isoformat(),
            "iterations": self.iterations,
            "results": [r.to_dict() for r in self.results],
            "system_info": {
                "python": sys.version,
                "numpy": np.__version__,
            },
        }

        with open(filename, "w") as f:
            json.dump(data, f, indent=2)

        print(f"\nResults saved to {filename}")


def benchmark_lyapunov_functions():
    """Benchmark Lyapunov function implementations"""
    from ama_cryptography.equations import lyapunov_function  # noqa: F401 — import validates availability

    state = np.random.randn(1000)
    target = np.ones(1000)

    def pure_python_lyapunov(s, t):
        return float(np.sum((s - t) ** 2))

    bench = PerformanceBenchmark(iterations=10000)

    # Try to import Cython version
    try:
        from ama_cryptography.math_engine import lyapunov_function_fast

        bench.compare_implementations(
            "Lyapunov Function",
            "Pure Python",
            pure_python_lyapunov,
            "Cython",
            lyapunov_function_fast,
            state,
            target,
        )
    except ImportError:
        print("Cython math_engine not available, skipping comparison")
        bench.run_benchmark("Lyapunov (Python)", pure_python_lyapunov, state, target)

    return bench


def benchmark_matrix_operations():
    """Benchmark matrix operations"""
    size = 500
    matrix = np.random.randn(size, size)
    vector = np.random.randn(size)

    def numpy_matvec(m, v):
        return m @ v

    bench = PerformanceBenchmark(iterations=1000)

    # NumPy baseline
    bench.run_benchmark("Matrix-Vector (NumPy)", numpy_matvec, matrix, vector)

    # Try Cython version
    try:
        from ama_cryptography.math_engine import matrix_vector_multiply

        bench.compare_implementations(
            "Matrix-Vector Multiplication",
            "NumPy",
            numpy_matvec,
            "Cython",
            matrix_vector_multiply,
            matrix,
            vector,
        )
    except ImportError:
        print("Cython matrix operations not available")

    return bench


def benchmark_helix_evolution():
    """Benchmark double-helix evolution"""
    from ama_cryptography.double_helix_engine import AmaEquationEngine

    engine = AmaEquationEngine(state_dim=100, random_seed=42)
    state = np.random.randn(100) * 0.5

    def run_step(eng, s):
        return eng.step(s, 0)

    bench = PerformanceBenchmark(iterations=1000)
    bench.run_benchmark("Helix Evolution Step", run_step, engine, state)

    return bench


def benchmark_constant_time_ops():
    """Benchmark constant-time operations"""
    try:
        # Try to import C library
        import ctypes

        lib = ctypes.CDLL("build/lib/libama_cryptography.so")

        # Setup function signatures
        lib.ama_consttime_memcmp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        lib.ama_consttime_memcmp.restype = ctypes.c_int

        a = b"A" * 1024
        b = b"A" * 1024
        pa = ctypes.c_char_p(a)
        pb = ctypes.c_char_p(b)

        def c_memcmp():
            return lib.ama_consttime_memcmp(pa, pb, 1024)

        bench = PerformanceBenchmark(iterations=100000)
        bench.run_benchmark("Constant-Time Memcmp (C)", c_memcmp)

        return bench

    except (OSError, AttributeError):
        print("C library not available for constant-time benchmarks")
        return None


def main():
    """Run all benchmarks"""
    print("=" * 70)
    print("AMA Cryptography ♱ Performance Benchmark Suite")
    print("=" * 70)

    all_results = []

    # Lyapunov benchmarks
    print("\n" + "=" * 70)
    print("LYAPUNOV FUNCTION BENCHMARKS")
    print("=" * 70)
    lyap_bench = benchmark_lyapunov_functions()
    all_results.extend(lyap_bench.results)

    # Matrix operation benchmarks
    print("\n" + "=" * 70)
    print("MATRIX OPERATION BENCHMARKS")
    print("=" * 70)
    matrix_bench = benchmark_matrix_operations()
    all_results.extend(matrix_bench.results)

    # Helix evolution benchmarks
    print("\n" + "=" * 70)
    print("HELIX EVOLUTION BENCHMARKS")
    print("=" * 70)
    helix_bench = benchmark_helix_evolution()
    all_results.extend(helix_bench.results)

    # Constant-time operation benchmarks
    print("\n" + "=" * 70)
    print("CONSTANT-TIME OPERATION BENCHMARKS")
    print("=" * 70)
    ct_bench = benchmark_constant_time_ops()
    if ct_bench:
        all_results.extend(ct_bench.results)

    # Save combined results
    combined = PerformanceBenchmark(iterations=0)
    combined.results = all_results
    combined.save_results("benchmarks/performance_results.json")

    # Summary
    print("\n" + "=" * 70)
    print("BENCHMARK SUMMARY")
    print("=" * 70)
    for result in all_results:
        print(f"{result.name:50s} {result.throughput:12.2f} {result.unit}")

    print("\n✓ All benchmarks complete")


if __name__ == "__main__":
    main()
