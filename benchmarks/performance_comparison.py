#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License 2.0

"""
Ed25519 Performance Comparison: Bytes vs Key Objects
====================================================

Demonstrates the performance improvement from passing Ed25519PrivateKey
objects instead of reconstructing from bytes on every operation.
"""

import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from code_guardian_secure import (  # noqa: E402
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
)


def benchmark_bytes_approach(iterations=1000):
    """Benchmark signing with bytes (reconstructs key every time)"""
    print("\n" + "=" * 70)
    print("APPROACH 1: Passing bytes (original)")
    print("=" * 70)

    test_data = b"Test message for benchmarking performance" * 10
    keypair = generate_ed25519_keypair()

    # Sign benchmark - bytes approach
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        ed25519_sign(test_data, keypair.private_key)  # Passes bytes
        end = time.perf_counter()
        times.append((end - start) * 1000)

    sign_mean = statistics.mean(times)
    sign_ops = 1000 / sign_mean
    print(f"  Sign (bytes):   {sign_mean:.4f}ms ({sign_ops:.2f} ops/sec)")

    # Verify benchmark - bytes approach
    signature = ed25519_sign(test_data, keypair.private_key)
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        ed25519_verify(test_data, signature, keypair.public_key)  # Passes bytes
        end = time.perf_counter()
        times.append((end - start) * 1000)

    verify_mean = statistics.mean(times)
    verify_ops = 1000 / verify_mean
    print(f"  Verify (bytes): {verify_mean:.4f}ms ({verify_ops:.2f} ops/sec)")

    return sign_ops, verify_ops


def benchmark_keyobject_approach(iterations=1000):
    """Benchmark signing with key objects (optimized)"""
    print("\n" + "=" * 70)
    print("APPROACH 2: Passing key objects (optimized)")
    print("=" * 70)

    test_data = b"Test message for benchmarking performance" * 10
    keypair = generate_ed25519_keypair()

    # Reconstruct key objects ONCE
    private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(keypair.private_key)
    public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(keypair.public_key)

    # Sign benchmark - key object approach
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        ed25519_sign(test_data, private_key_obj)  # Passes key object!
        end = time.perf_counter()
        times.append((end - start) * 1000)

    sign_mean = statistics.mean(times)
    sign_ops = 1000 / sign_mean
    print(f"  Sign (object):   {sign_mean:.4f}ms ({sign_ops:.2f} ops/sec)")

    # Verify benchmark - key object approach
    signature = ed25519_sign(test_data, private_key_obj)
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        ed25519_verify(test_data, signature, public_key_obj)  # Passes key object!
        end = time.perf_counter()
        times.append((end - start) * 1000)

    verify_mean = statistics.mean(times)
    verify_ops = 1000 / verify_mean
    print(f"  Verify (object): {verify_mean:.4f}ms ({verify_ops:.2f} ops/sec)")

    return sign_ops, verify_ops


def main():
    print("=" * 70)
    print("Ed25519 Performance: Bytes vs Key Objects")
    print("=" * 70)
    print("Testing 1,000 iterations each...")

    bytes_sign, bytes_verify = benchmark_bytes_approach()
    keyobj_sign, keyobj_verify = benchmark_keyobject_approach()

    print("\n" + "=" * 70)
    print("PERFORMANCE COMPARISON")
    print("=" * 70)

    sign_speedup = keyobj_sign / bytes_sign
    verify_speedup = keyobj_verify / bytes_verify

    print("\nSign Performance:")
    print(f"  Bytes:      {bytes_sign:>10,.2f} ops/sec")
    print(f"  Key Object: {keyobj_sign:>10,.2f} ops/sec")
    print(f"  Speedup:    {sign_speedup:>10.2f}x")

    print("\nVerify Performance:")
    print(f"  Bytes:      {bytes_verify:>10,.2f} ops/sec")
    print(f"  Key Object: {keyobj_verify:>10,.2f} ops/sec")
    print(f"  Speedup:    {verify_speedup:>10.2f}x")

    print("\n" + "=" * 70)
    print("RECOMMENDATION")
    print("=" * 70)
    print(
        """
For high-throughput scenarios (>10,000 signatures/sec):

  # Reconstruct key objects ONCE
  from cryptography.hazmat.primitives.asymmetric import ed25519
  private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
  public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

  # Then reuse for all operations
  for message in messages:
      signature = ed25519_sign(message, private_key)  # Fast!
      valid = ed25519_verify(message, signature, public_key)  # Fast!
"""
    )


if __name__ == "__main__":
    main()
