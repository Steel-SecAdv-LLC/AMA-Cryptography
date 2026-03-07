# AMA Cryptography ♱ Benchmark Results

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 2.0 |
| Test Date | 2026-03-06 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Executive Summary

Performance benchmarks for AMA Cryptography ♱ v1.2 with **fully native PQC implementations** (FIPS 203/204/205). All post-quantum cryptography is provided by the built-in C library — no external dependencies (liboqs, pqcrypto) required.

**Test Environment:**
- OS: Linux 4.4.0 x86_64
- CPU: 16 cores
- Memory: 13.0 GB
- Python: 3.11
- PQC Backend: Native C (FIPS 203/204/205)
- Iterations: 1,000 per operation

---

## Native PQC Performance (FIPS 203/204/205)

### ML-DSA-65 — Digital Signatures (FIPS 204)

| Operation | Latency | Throughput |
|-----------|---------|------------|
| **KeyGen** | 0.326 ms | 3,066 ops/sec |
| **Sign** | 0.473 ms | 2,115 ops/sec |
| **Verify** | 0.156 ms | 6,398 ops/sec |

### ML-KEM-1024 — Key Encapsulation (FIPS 203)

| Operation | Latency | Throughput |
|-----------|---------|------------|
| **KeyGen** | 0.233 ms | 4,289 ops/sec |
| **Encapsulate** | 0.157 ms | 6,384 ops/sec |
| **Decapsulate** | 0.106 ms | 9,464 ops/sec |

### SLH-DSA-SHA2-256f — Hash-Based Signatures (FIPS 205)

| Operation | Latency | Throughput |
|-----------|---------|------------|
| **KeyGen** | 2.420 ms | 413 ops/sec |
| **Sign** | 45.757 ms | 22 ops/sec |
| **Verify** | 1.222 ms | 818 ops/sec |

> **Note:** SLH-DSA signing is inherently slower due to the hash-based Merkle tree construction. This is expected per the FIPS 205 specification and provides stateless hash-based security as a conservative fallback.

---

## C Library Performance

Direct C library benchmarks (10,000 iterations + 100 warmup).

### SHA3-256 (Keccak-f[1600])

| Input Size | Throughput | Latency |
|------------|------------|---------|
| 13 bytes | **1,264,198 ops/sec** | 0.791 µs/op |
| 1 KB | **169,237 ops/sec** | 5.909 µs/op |

### HKDF-SHA3-256

| Output Size | Throughput | Latency |
|-------------|------------|---------|
| 32 bytes | **165,419 ops/sec** | 6.045 µs/op |

### Ed25519 (Native C — Experimental)

| Operation | Throughput | Latency |
|-----------|------------|---------|
| Sign (32-byte msg) | **9,182 ops/sec** | 108.9 µs/op |

> **Note:** The native C Ed25519 implementation is experimental. For production, the Python API leverages the cryptography (OpenSSL) library for Ed25519.

### Constant-Time Utilities

| Operation | Throughput | Latency |
|-----------|------------|---------|
| consttime_memcmp (512 bytes) | **3,421,027 ops/sec** | 0.292 µs/op |
| secure_memzero (64 bytes) | **80,691,364 ops/sec** | 0.012 µs/op |

---

## Hybrid Operations (Ed25519 + ML-DSA-65)

| Operation | Latency | Throughput |
|-----------|---------|------------|
| **Hybrid Sign** | ~0.57 ms | ~1,750 ops/sec |
| **Hybrid Verify** | ~0.28 ms | ~3,600 ops/sec |

> Hybrid operations combine Ed25519 (classical) + ML-DSA-65 (post-quantum) for defense-in-depth.

---

## Full 6-Layer Package Performance

AMA Cryptography's complete security package includes:

| Layer | Component | Time |
|-------|-----------|------|
| 1 | SHA3-256 Content Hash | ~0.001 ms |
| 2 | HMAC-SHA3-256 Auth | ~0.006 ms |
| 3 | Ed25519 Signature | ~0.100 ms |
| 4 | ML-DSA-65 Signature | ~0.473 ms |
| 5 | HKDF Key Derivation | ~0.006 ms |
| 6 | RFC 3161 Timestamp | (optional) |

---

## C vs Python Performance Comparison

| Operation | C Library | Python API | C Speedup |
|-----------|-----------|------------|-----------|
| SHA3-256 (short) | 1,264,198 ops/sec | 292,790 ops/sec | **4.3x** |
| HKDF (32B) | 165,419 ops/sec | 21,443 ops/sec | **7.7x** |
| Ed25519 Sign | 9,182 ops/sec | 10,453 ops/sec | 0.88x* |

\*Python Ed25519 uses the optimized cryptography/OpenSSL library. C implementation is experimental.

---

## Architecture Notes

### Native PQC — No External Dependencies

As of v1.2, AMA Cryptography uses fully native C implementations for all post-quantum algorithms:

- **ML-KEM-1024** (FIPS 203): Key encapsulation with IND-CCA2 security
- **ML-DSA-65** (FIPS 204): Digital signatures with EUF-CMA security
- **SLH-DSA-SHA2-256f** (FIPS 205): Stateless hash-based signatures

All implementations include NIST Known Answer Test (KAT) validation. No liboqs, pqcrypto, or other external PQC libraries are required.

### Build

```bash
cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build
```

---

**Generated:** 2026-03-06
**Copyright:** 2025-2026 Steel Security Advisors LLC
**License:** Apache License 2.0
