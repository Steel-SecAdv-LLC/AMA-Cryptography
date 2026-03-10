#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License 2.0

"""
Ed25519 Performance Comparison: Native C vs Python ctypes
==========================================================

Demonstrates the performance of the native C Ed25519 implementation
accessed via ctypes bindings.
"""

import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from code_guardian_secure import (  # noqa: E402
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
)


def benchmark_native_ed25519(iterations=1000):
    """Benchmark native C Ed25519 via ctypes"""
    print("\n" + "=" * 70)
    print("NATIVE C Ed25519 (via ctypes)")
    print("=" * 70)

    test_data = b"Test message for benchmarking performance" * 10
    keypair = generate_ed25519_keypair()

    # Sign benchmark
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        ed25519_sign(test_data, keypair.private_key)
        end = time.perf_counter()
        times.append((end - start) * 1000)

    sign_mean = statistics.mean(times)
    sign_ops = 1000 / sign_mean
    print(f"  Sign:   {sign_mean:.4f}ms ({sign_ops:.2f} ops/sec)")

    # Verify benchmark
    signature = ed25519_sign(test_data, keypair.private_key)
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        ed25519_verify(test_data, signature, keypair.public_key)
        end = time.perf_counter()
        times.append((end - start) * 1000)

    verify_mean = statistics.mean(times)
    verify_ops = 1000 / verify_mean
    print(f"  Verify: {verify_mean:.4f}ms ({verify_ops:.2f} ops/sec)")

    return sign_ops, verify_ops


def benchmark_keygen(iterations=1000):
    """Benchmark Ed25519 key generation"""
    print("\n" + "=" * 70)
    print("Ed25519 KEY GENERATION")
    print("=" * 70)

    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        generate_ed25519_keypair()
        end = time.perf_counter()
        times.append((end - start) * 1000)

    mean_time = statistics.mean(times)
    ops = 1000 / mean_time
    print(f"  KeyGen: {mean_time:.4f}ms ({ops:.2f} ops/sec)")

    return ops


def benchmark_message_sizes(iterations=100):
    """Benchmark Ed25519 across different message sizes"""
    print("\n" + "=" * 70)
    print("Ed25519 PERFORMANCE BY MESSAGE SIZE")
    print("=" * 70)

    keypair = generate_ed25519_keypair()
    sizes = [32, 256, 1024, 4096, 16384, 65536]

    for size in sizes:
        test_data = b"A" * size

        # Sign
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            ed25519_sign(test_data, keypair.private_key)
            end = time.perf_counter()
            times.append((end - start) * 1000)

        sign_mean = statistics.mean(times)
        sign_ops = 1000 / sign_mean

        # Verify
        signature = ed25519_sign(test_data, keypair.private_key)
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            ed25519_verify(test_data, signature, keypair.public_key)
            end = time.perf_counter()
            times.append((end - start) * 1000)

        verify_mean = statistics.mean(times)
        verify_ops = 1000 / verify_mean

        print(
            f"  {size:>6} bytes | Sign: {sign_mean:.4f}ms ({sign_ops:>10,.2f} ops/sec) "
            f"| Verify: {verify_mean:.4f}ms ({verify_ops:>10,.2f} ops/sec)"
        )


def main():
    print("=" * 70)
    print("Ed25519 Native C Performance Analysis")
    print("=" * 70)
    print("Testing 1,000 iterations each...")

    sign_ops, verify_ops = benchmark_native_ed25519()
    keygen_ops = benchmark_keygen()
    benchmark_message_sizes()

    print("\n" + "=" * 70)
    print("PERFORMANCE SUMMARY")
    print("=" * 70)
    print(f"\n  KeyGen: {keygen_ops:>10,.2f} ops/sec")
    print(f"  Sign:   {sign_ops:>10,.2f} ops/sec")
    print(f"  Verify: {verify_ops:>10,.2f} ops/sec")
    print(f"\n  Backend: Native C (zero external dependencies)")


if __name__ == "__main__":
    main()
