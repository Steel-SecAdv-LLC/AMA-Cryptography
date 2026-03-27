#!/usr/bin/env python3
"""Phase 0: Establish honest performance baselines for all AMA primitives."""

import ctypes
import json
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Load native C library directly for lowest-overhead measurement
LIB_PATH = Path(__file__).parent.parent / "build" / "lib" / "libama_cryptography.so"
lib = ctypes.CDLL(str(LIB_PATH))

# Setup ctypes signatures
lib.ama_sha3_256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
lib.ama_sha3_256.restype = ctypes.c_int

lib.ama_hmac_sha3_256.argtypes = [
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
]
lib.ama_hmac_sha3_256.restype = ctypes.c_int

lib.ama_hkdf.argtypes = [
    ctypes.c_char_p,
    ctypes.c_size_t,  # salt, salt_len
    ctypes.c_char_p,
    ctypes.c_size_t,  # ikm, ikm_len
    ctypes.c_char_p,
    ctypes.c_size_t,  # info, info_len
    ctypes.c_char_p,
    ctypes.c_size_t,  # okm, okm_len
]
lib.ama_hkdf.restype = ctypes.c_int

lib.ama_ed25519_keypair.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.ama_ed25519_keypair.restype = ctypes.c_int

lib.ama_ed25519_sign.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
]
lib.ama_ed25519_sign.restype = ctypes.c_int

lib.ama_ed25519_verify.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
]
lib.ama_ed25519_verify.restype = ctypes.c_int

# ML-DSA-65 (Dilithium)
try:
    lib.ama_dilithium_keypair.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.ama_dilithium_keypair.restype = ctypes.c_int
    lib.ama_dilithium_sign.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
    ]
    lib.ama_dilithium_sign.restype = ctypes.c_int
    lib.ama_dilithium_verify.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
    ]
    lib.ama_dilithium_verify.restype = ctypes.c_int
    DILITHIUM_AVAILABLE = True
except AttributeError:
    DILITHIUM_AVAILABLE = False


def benchmark(func, iterations=500, warmup=50):
    """Run benchmark returning (ops_per_sec, per_call_us, raw_times)."""
    for _ in range(warmup):
        func()

    times = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        func()
        t1 = time.perf_counter_ns()
        times.append(t1 - t0)

    median_ns = statistics.median(times)
    mean_ns = statistics.mean(times)
    p95_ns = sorted(times)[int(len(times) * 0.95)]
    ops_per_sec = 1e9 / median_ns if median_ns > 0 else float("inf")
    return {
        "ops_per_sec": ops_per_sec,
        "median_ns": median_ns,
        "mean_ns": mean_ns,
        "p95_ns": p95_ns,
        "median_us": median_ns / 1000,
        "stdev_ns": statistics.stdev(times),
    }


def bench_sha3_256():
    data = b"A" * 1024
    out = ctypes.create_string_buffer(32)

    def op():
        lib.ama_sha3_256(data, 1024, out)

    return benchmark(op, iterations=1000, warmup=100)


def bench_sha3_256_short():
    data = b"A" * 64
    out = ctypes.create_string_buffer(32)

    def op():
        lib.ama_sha3_256(data, 64, out)

    return benchmark(op, iterations=1000, warmup=100)


def bench_hmac_sha3_256():
    key = os.urandom(32)
    msg = b"A" * 1024
    out = ctypes.create_string_buffer(32)

    def op():
        lib.ama_hmac_sha3_256(key, 32, msg, 1024, out)

    return benchmark(op, iterations=500, warmup=50)


def bench_hkdf():
    ikm = os.urandom(32)
    salt = os.urandom(32)
    info = b"benchmark"
    out = ctypes.create_string_buffer(96)

    def op():
        lib.ama_hkdf(salt, 32, ikm, 32, info, 9, out, 96)

    return benchmark(op, iterations=500, warmup=50)


def bench_ed25519_keygen():
    pk = ctypes.create_string_buffer(32)
    sk = ctypes.create_string_buffer(64)

    def op():
        lib.ama_ed25519_keypair(pk, sk)

    return benchmark(op, iterations=200, warmup=20)


def bench_ed25519_sign():
    pk = ctypes.create_string_buffer(32)
    sk = ctypes.create_string_buffer(64)
    lib.ama_ed25519_keypair(pk, sk)
    msg = b"Test message for benchmarking" * 8
    sig = ctypes.create_string_buffer(64)

    def op():
        lib.ama_ed25519_sign(sig, msg, len(msg), sk)

    return benchmark(op, iterations=200, warmup=20)


def bench_ed25519_verify():
    pk = ctypes.create_string_buffer(32)
    sk = ctypes.create_string_buffer(64)
    lib.ama_ed25519_keypair(pk, sk)
    msg = b"Test message for benchmarking" * 8
    sig = ctypes.create_string_buffer(64)
    lib.ama_ed25519_sign(sig, msg, len(msg), sk)

    def op():
        lib.ama_ed25519_verify(sig, msg, len(msg), pk)

    return benchmark(op, iterations=200, warmup=20)


def bench_dilithium_keygen():
    pk = ctypes.create_string_buffer(1952)
    sk = ctypes.create_string_buffer(4032)

    def op():
        lib.ama_dilithium_keypair(pk, sk)

    return benchmark(op, iterations=100, warmup=10)


def bench_dilithium_sign():
    pk = ctypes.create_string_buffer(1952)
    sk = ctypes.create_string_buffer(4032)
    lib.ama_dilithium_keypair(pk, sk)
    msg = b"Test message for ML-DSA-65" * 10
    sig = ctypes.create_string_buffer(3309)
    siglen = ctypes.c_size_t(3309)

    def op():
        lib.ama_dilithium_sign(sig, ctypes.byref(siglen), msg, len(msg), sk)

    return benchmark(op, iterations=100, warmup=10)


def bench_dilithium_verify():
    pk = ctypes.create_string_buffer(1952)
    sk = ctypes.create_string_buffer(4032)
    lib.ama_dilithium_keypair(pk, sk)
    msg = b"Test message for ML-DSA-65" * 10
    sig = ctypes.create_string_buffer(3309)
    siglen = ctypes.c_size_t(3309)
    lib.ama_dilithium_sign(sig, ctypes.byref(siglen), msg, len(msg), sk)

    def op():
        lib.ama_dilithium_verify(msg, len(msg), sig, siglen.value, pk)

    return benchmark(op, iterations=100, warmup=10)


# Also measure Python-level overhead (ctypes vs Cython for HMAC)
def bench_hmac_python_api():
    from ama_cryptography.pqc_backends import native_hmac_sha3_256

    key = os.urandom(32)
    msg = b"A" * 1024

    def op():
        native_hmac_sha3_256(key, msg)

    return benchmark(op, iterations=500, warmup=50)


def bench_sha3_python_api():
    from ama_cryptography.pqc_backends import native_sha3_256

    data = b"A" * 1024

    def op():
        native_sha3_256(data)

    return benchmark(op, iterations=1000, warmup=100)


# Package create/verify
def bench_package_create():
    from code_guardian_secure import (
        create_crypto_package,
        generate_key_management_system,
    )

    kms = generate_key_management_system("Benchmark Test")
    codes = "TEST_OMNI_CODE_12345"
    helix_params = [(1.0, 2.0)]

    def op():
        create_crypto_package(
            codes=codes,
            helix_params=helix_params,
            kms=kms,
            author="Benchmark",
            use_rfc3161=False,
        )

    return benchmark(op, iterations=50, warmup=5)


def bench_package_verify():
    from code_guardian_secure import (
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

    def op():
        verify_crypto_package(
            codes=codes,
            helix_params=helix_params,
            package=package,
            hmac_key=kms.hmac_key,
            require_quantum_signatures=False,
        )

    return benchmark(op, iterations=50, warmup=5)


def main():
    print("=" * 72)
    print("AMA CRYPTOGRAPHY — PHASE 0 BASELINE PROFILING")
    print("=" * 72)
    print()

    results = {}

    benchmarks = [
        ("SHA3-256 (1KB)", bench_sha3_256),
        ("SHA3-256 (64B)", bench_sha3_256_short),
        ("SHA3-256 Python API (1KB)", bench_sha3_python_api),
        ("HMAC-SHA3-256 (1KB)", bench_hmac_sha3_256),
        ("HMAC-SHA3-256 Python API (1KB)", bench_hmac_python_api),
        ("HKDF-SHA3-256 (96B output)", bench_hkdf),
        ("Ed25519 keygen", bench_ed25519_keygen),
        ("Ed25519 sign (240B)", bench_ed25519_sign),
        ("Ed25519 verify (240B)", bench_ed25519_verify),
        ("Package create", bench_package_create),
        ("Package verify", bench_package_verify),
    ]

    if DILITHIUM_AVAILABLE:
        benchmarks.extend(
            [
                ("ML-DSA-65 keygen", bench_dilithium_keygen),
                ("ML-DSA-65 sign", bench_dilithium_sign),
                ("ML-DSA-65 verify", bench_dilithium_verify),
            ]
        )

    print(f"{'Primitive':<35} {'ops/sec':>12} {'median_us':>12} {'p95_us':>12} {'stdev_us':>12}")
    print("-" * 83)

    for name, func in benchmarks:
        try:
            r = func()
            results[name] = r
            print(
                f"{name:<35} {r['ops_per_sec']:>12,.0f} {r['median_us']:>12.1f} {r['p95_ns']/1000:>12.1f} {r['stdev_ns']/1000:>12.1f}"
            )
        except Exception as e:
            print(f"{name:<35} ERROR: {e}")
            results[name] = {"error": str(e)}

    print()
    print("=" * 72)

    # Save results
    out_path = Path(__file__).parent / "phase0_baseline_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to: {out_path}")

    return results


if __name__ == "__main__":
    main()
