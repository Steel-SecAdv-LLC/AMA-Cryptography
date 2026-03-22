# AMA Cryptography — Performance Benchmarks

**Version:** 2.1
**Date:** 2026-03-22
**Organization:** Steel Security Advisors LLC

> Every number in this document is empirically measured. No number is estimated, projected, or taken from a specification sheet. Every benchmark is reproducible using the commands in [Reproducing These Results](#reproducing-these-results).

---

## Test Environment

| Parameter | Value |
|-----------|-------|
| **OS** | Linux 6.18.5 x86_64 |
| **CPU** | 4 cores (shared CI runner) |
| **Python** | 3.11.14 |
| **C Compiler** | GCC (system default) |
| **Build** | `cmake -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release` |
| **Backend** | Native C library (`libama_cryptography.so`) via ctypes — zero external PQC dependencies |
| **Timer** | `time.perf_counter()` (nanosecond resolution) |
| **Methodology** | 10–50 warmup iterations discarded, then 200–5,000 measured iterations per operation |

---

## Post-Quantum Digital Signatures — ML-DSA-65 (FIPS 204)

| Operation | Mean Latency | Throughput | Iterations | Notes |
|-----------|-------------|-----------|-----------|-------|
| KeyGen | 0.22 ms | 4,527 ops/sec | 200 | NTT q=8380417, constant-time |
| Sign | 0.97 ms | 1,027 ops/sec | 200 | Rejection sampling |
| Verify | 0.20 ms | 5,067 ops/sec | 200 | NIST ACVP validated (15/15 SigVer) |

**Key sizes:** Public key 1,952 B | Secret key 4,032 B | Signature 3,309 B
**Security level:** NIST Level 3 (~192-bit quantum security)

---

## Post-Quantum Key Encapsulation — ML-KEM-1024 (FIPS 203)

| Operation | Mean Latency | Throughput | Iterations | Notes |
|-----------|-------------|-----------|-----------|-------|
| KeyGen | 0.10 ms | 9,798 ops/sec | 200 | NTT q=3329 |
| Encapsulate | 0.11 ms | 9,480 ops/sec | 200 | IND-CCA2 secure |
| Decapsulate | 0.11 ms | 8,913 ops/sec | 200 | Fujisaki-Okamoto, implicit rejection |

**Key sizes:** Public key 1,568 B | Secret key 3,168 B | Ciphertext 1,568 B | Shared secret 32 B
**Security level:** NIST Level 5 (~256-bit quantum security)

---

## Hash-Based Signatures — SLH-DSA-SHA2-256f (FIPS 205)

| Operation | Mean Latency | Throughput | Iterations | Notes |
|-----------|-------------|-----------|-----------|-------|
| KeyGen | 11.38 ms | 88 ops/sec | 10 | WOTS+ + FORS + hypertree d=17 |
| Sign | 236.88 ms | 4.2 ops/sec | 5 | Stateless, SHA2-256f-simple variant |
| Verify | 5.95 ms | 168 ops/sec | 10 | NIST ACVP validated (14/14 SigVer) |

**Key sizes:** Public key 64 B | Secret key 128 B | Signature 49,856 B
**Security level:** NIST Level 5 (~256-bit quantum security)

> SLH-DSA is intentionally slow to sign — this is the cost of stateless hash-based security with no state management. Use ML-DSA-65 for high-throughput signing; SLH-DSA for maximum conservative post-quantum assurance.

---

## Classical Signatures — Ed25519 (RFC 8032)

| Operation | Mean Latency | Throughput | Iterations | Notes |
|-----------|-------------|-----------|-----------|-------|
| KeyGen | 0.07 ms | 14,611 ops/sec | 1,000 | Radix 2^51 field arithmetic (fe51.h) |
| Sign | 0.07 ms | 14,976 ops/sec | 1,000 | Expanded 64-byte key optimization |
| Verify | 0.13 ms | 7,716 ops/sec | 1,000 | RFC 8032 Test Vector 1 validated |

**Key sizes:** Public key 32 B | Secret key 64 B (expanded) | Signature 64 B
**Security level:** ~128-bit classical (vulnerable to quantum attacks)

---

## Authenticated Encryption — AES-256-GCM (SP 800-38D)

| Operation | Data Size | Mean Latency | Throughput | Iterations |
|-----------|----------|-------------|-----------|-----------|
| Encrypt | 1 KB | 0.92 ms | 1,087 ops/sec | 2,000 |
| Decrypt | 1 KB | 0.91 ms | 1,098 ops/sec | 2,000 |
| Encrypt | 64 KB | 56.46 ms | 17.7 ops/sec | 500 |
| Decrypt | 64 KB | 55.98 ms | 17.9 ops/sec | 500 |

> Pure C table-based implementation. Production deployments on x86_64 should consider AES-NI hardware acceleration for ~100x improvement. Bitsliced S-box variant (`-DAMA_AES_CONSTTIME=ON`) provides cache-timing hardening at equivalent throughput.

---

## Authenticated Encryption — ChaCha20-Poly1305 (RFC 8439)

| Operation | Data Size | Mean Latency | Throughput | Iterations |
|-----------|----------|-------------|-----------|-----------|
| Encrypt | 1 KB | 0.006 ms | 155,725 ops/sec | 2,000 |
| Decrypt | 1 KB | 0.006 ms | 168,937 ops/sec | 2,000 |

> ChaCha20-Poly1305 significantly outperforms AES-256-GCM on this platform (no AES-NI). On hardware with AES-NI, AES-GCM may match or exceed ChaCha20 performance.

---

## Hash Functions — SHA3-256 (FIPS 202)

| Operation | Data Size | Mean Latency | Throughput | Iterations |
|-----------|----------|-------------|-----------|-----------|
| Hash | 32 B | 0.002 ms | 477,055 ops/sec | 5,000 |
| Hash | 1 KB | 0.006 ms | 158,832 ops/sec | 5,000 |

**Implementation:** Fully unrolled Keccak-f[1600] sponge construction.

---

## Message Authentication — HMAC-SHA3-256 (RFC 2104 + FIPS 202)

| Operation | Data Size | Mean Latency | Throughput | Iterations |
|-----------|----------|-------------|-----------|-----------|
| Authenticate | 1 KB | 0.009 ms | 114,278 ops/sec | 5,000 |

**Implementation:** Native C HMAC-SHA3-256. stdlib `hmac` module is never used (INVARIANT-1).

---

## Key Derivation — HKDF-SHA3-256 (RFC 5869)

| Operation | Output Size | Mean Latency | Throughput | Iterations |
|-----------|-----------|-------------|-----------|-----------|
| Derive | 96 B (3 keys) | 0.014 ms | 73,318 ops/sec | 2,000 |

---

## Key Exchange — X25519 (RFC 7748)

| Operation | Mean Latency | Throughput | Iterations |
|-----------|-------------|-----------|-----------|
| KeyGen | 0.78 ms | 1,282 ops/sec | 1,000 |
| DH Exchange | 0.78 ms | 1,280 ops/sec | 1,000 |

**Key sizes:** Public key 32 B | Secret key 32 B | Shared secret 32 B

---

## Password Hashing — Argon2id (RFC 9106)

| Operation | Parameters | Mean Latency | Throughput | Iterations |
|-----------|-----------|-------------|-----------|-----------|
| Hash | t=3, m=64 MB, p=4, out=32 B | 252.75 ms | 4.0 ops/sec | 5 |

> Argon2id is intentionally memory-hard and slow. The parameters above (3 iterations, 64 MB memory, 4 parallel lanes) are suitable for password hashing. Faster results would indicate a security concern, not a performance improvement.

---

## 6-Layer Package Operations (End-to-End)

Complete cryptographic package with all 6 defense layers:
**SHA3-256 + HMAC-SHA3-256 + Ed25519 + ML-DSA-65 + HKDF + optional RFC 3161**

| Operation | Mean Latency | Throughput | Iterations |
|-----------|-------------|-----------|-----------|
| Package Create | 0.48 ms | 2,093 ops/sec | 100 |
| Package Verify | 0.38 ms | 2,607 ops/sec | 100 |

---

## Scalability (Package Creation by Input Size)

| Input Scale | Mean Latency | Throughput | Iterations |
|------------|-------------|-----------|-----------|
| 1x (baseline) | 0.84 ms | 1,188 ops/sec | 50 |
| 10x | 0.58 ms | 1,719 ops/sec | 50 |
| 100x | 2.90 ms | 344 ops/sec | 50 |
| 1,000x | 100.74 ms | 9.9 ops/sec | 50 |

---

## Cython Optimization (Optional)

When Cython extensions are built (`python setup.py build_ext --inplace`), mathematical operations achieve significant speedup over pure Python:

| Operation | Pure Python | Cython | Speedup |
|-----------|-----------|--------|---------|
| Lyapunov function | 12.3 ms | 0.45 ms | **27.3x** |
| Matrix-vector (500x500) | 8.7 ms | 0.31 ms | **28.1x** |
| NTT (degree 256) | 45.2 ms | 1.2 ms | **37.7x** |
| Helix evolution | 3.4 ms | 0.18 ms | **18.9x** |

> Cython acceleration applies to the mathematical engine (3R monitoring, helical computations). Core cryptographic operations use the native C library directly regardless of Cython availability.

---

## Performance Regression Detection (CI)

The CI pipeline runs `benchmarks/benchmark_runner.py` against `benchmarks/baseline.json` on every push. A benchmark fails if throughput drops below the baseline minus the configured tolerance:

| Benchmark | Baseline (ops/sec) | Tolerance | Tier |
|-----------|-------------------|-----------|------|
| SHA3-256 (1 KB) | 15,000 | 30% | Microbenchmark |
| HMAC-SHA3-256 | 12,000 | 40% | Microbenchmark |
| Ed25519 KeyGen | 10,600 | 35% | Microbenchmark |
| Ed25519 Sign | 8,527 | 35% | Microbenchmark |
| Ed25519 Verify | 3,416 | 35% | Microbenchmark |
| HKDF derive | 6,500 | 35% | Microbenchmark |
| Package Create | 280 | 50% | Complex operation |
| Package Verify | 380 | 50% | Complex operation |
| ML-DSA-65 KeyGen | 500 | 40% | PQC (optional) |
| ML-DSA-65 Sign | 140 | 40% | PQC (optional) |
| ML-DSA-65 Verify | 530 | 40% | PQC (optional) |

Baselines are conservative (set to ~65% of measured CI performance) to accommodate shared-runner variance. PQC benchmarks are optional — failure produces a warning, not a CI failure.

---

## Reproducing These Results

```bash
# 1. Build native C library
cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build

# 2. Run CI regression benchmarks
python benchmarks/benchmark_runner.py --verbose

# 3. Run full benchmark suite (generates this file)
python benchmark_suite.py

# 4. Benchmark a single algorithm
python -c "
import time, secrets, statistics, sys
sys.path.insert(0, '.')
from ama_cryptography.pqc_backends import generate_dilithium_keypair, dilithium_sign, dilithium_verify

kp = generate_dilithium_keypair()
msg = b'test' * 50
sig = dilithium_sign(msg, kp.secret_key)

# Warmup
for _ in range(10): dilithium_verify(msg, sig, kp.public_key)

# Measure
times = []
for _ in range(200):
    t0 = time.perf_counter()
    dilithium_verify(msg, sig, kp.public_key)
    times.append(time.perf_counter() - t0)

mean = statistics.mean(times)
print(f'ML-DSA-65 Verify: {mean*1e6:.1f} us ({1/mean:.0f} ops/sec)')
"
```

---

## Caveats

1. **Shared CI runners** — Throughput varies 20–40% run-to-run due to noisy neighbors. Regression baselines account for this.
2. **ctypes overhead** — Python-to-C calls via ctypes add ~1–5 us per call. Raw C performance is higher.
3. **AES-GCM without AES-NI** — The table-based AES implementation is significantly slower than hardware-accelerated AES-NI. The ChaCha20-Poly1305 numbers better represent this platform's AEAD throughput.
4. **SLH-DSA signing is slow by design** — SPHINCS+ trades signing speed for stateless hash-based security. This is a feature, not a bug.
5. **Argon2id is slow by design** — Memory-hard password hashing should be slow. Fast Argon2id would indicate a security problem.
6. **Numbers are platform-specific** — ARM64, Apple Silicon, and AVX2-enabled x86_64 will produce different results.

---

*Last updated: 2026-03-22*
*Copyright 2025-2026 Steel Security Advisors LLC*
