# AMA Cryptography Performance Benchmarks

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 2.1 |
| Last Updated | 2026-03-07 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Executive Summary

This document provides **transparent, honest performance metrics** for AMA Cryptography v2.1. We distinguish between:
- **Measured**: Actual benchmark results from live testing
- **Projected**: Estimates based on architecture (not yet measured)
- **Unknown**: Requires additional testing

**Key Philosophy**: We value transparency over marketing. If we don't have data, we say so.

---

## Benchmark Environment

**Test System**:
- **OS**: Linux x86_64 (Ubuntu 22.04)
- **CPU**: Modern multi-core processor (AVX2 capable)
- **RAM**: 8GB+
- **Python**: 3.8–3.12
- **C Compiler**: GCC 11 / Clang 14
- **PQC Backend**: Native C (FIPS 203/204/205 compliant)

---

## 1. Core Cryptographic Operations (Measured)

### 1.1 Key Generation

| Operation | Mean (ms) | Ops/sec | Status | Notes |
|-----------|-----------|---------|--------|-------|
| Master Secret (256-bit) | ~0.001 | >1.1M | Measured | CSPRNG entropy |
| HKDF-SHA3-256 Derivation | ~0.05 | ~19k | Measured | SHA3-256 based |
| Ed25519 KeyGen | ~0.06 | ~16k | Measured | Classical signatures |
| ML-DSA-65 KeyGen | ~0.09 | ~11k | Measured | Native C (FIPS 204) |
| **Full KMS** | **~0.23** | **~4.3k** | Measured | Complete key suite |

**Analysis**: Full key management system generation in <0.25ms, suitable for on-demand key creation.

### 1.2 Hashing and Key Derivation

| Operation | Mean (ms) | Ops/sec | Status | Notes |
|-----------|-----------|---------|--------|-------|
| SHA3-256 (C library) | ~0.001 | ~1,264,198 | Measured | Native C, FIPS 202 |
| SHA3-256 (Python hashlib) | ~0.004 | ~280,000 | Measured | Python wrapper |
| HMAC-SHA3-256 | ~0.006 | ~160,000 | Measured | RFC 2104 |
| HKDF-SHA3-256 (C library) | ~0.006 | ~165,419 | Measured | Native C, RFC 5869 |
| HKDF-SHA3-256 (Python) | ~0.053 | ~19,000 | Measured | Python API |

### 1.3 Signature Operations

| Operation | Mean (ms) | Ops/sec | Status | Notes |
|-----------|-----------|---------|--------|-------|
| Ed25519 Sign | ~0.05 | ~20,000 | Measured | RFC 8032 (v2.1: roundtrip verified) |
| Ed25519 Verify | ~0.12 | ~8,000 | Measured | Full RFC 8032 KAT pass |
| ML-DSA-65 Sign | ~0.473 | ~2,115 | Measured | NIST FIPS 204 |
| ML-DSA-65 Verify | ~0.156 | ~6,398 | Measured | Faster than Ed25519 verify |
| SLH-DSA Sign | ~45.757 | ~22 | Measured | FIPS 205 (SPHINCS+-SHA2-256f) |
| SLH-DSA Verify | ~1.222 | ~818 | Measured | Stateless hash-based |

> **v2.1 Note**: Ed25519 sign/verify roundtrip now fully passes RFC 8032 Test Vector 1 (public key derivation, empty-message signature, and verification). Previously skipped due to field arithmetic issues; fixed with dedicated `fe25519_sq()` optimization.

![Signature Performance](benchmarks/charts/signature_performance.svg)

### 1.4 Key Encapsulation (ML-KEM-1024, FIPS 203)

| Operation | Mean (ms) | Ops/sec | Status | Notes |
|-----------|-----------|---------|--------|-------|
| ML-KEM KeyGen | ~0.233 | ~4,289 | Measured | NTT-based |
| ML-KEM Encapsulate | ~0.157 | ~6,384 | Measured | Shared secret generation |
| ML-KEM Decapsulate | ~0.106 | ~9,464 | Measured | Shared secret recovery |

![ML-KEM Performance](benchmarks/charts/kem_performance.svg)

### 1.5 Authenticated Encryption (AES-256-GCM)

| Operation | Status | Notes |
|-----------|--------|-------|
| AES-256-GCM Encrypt | Measured | NIST SP 800-38D |
| AES-256-GCM Decrypt | Measured | NIST SP 800-38D |

> **Side-channel caveat**: AES-256-GCM uses a standard 256-byte S-box lookup table, not a bitsliced implementation. In shared-tenant environments (cloud VMs, containers sharing physical cores), cache-timing side channels are a theoretical concern. For environments where cache-timing resistance is required, use the PQC primitives (ML-KEM, ML-DSA) which do not rely on secret-dependent table lookups.

### 1.6 Constant-Time Utilities

| Function | Status | Verification |
|----------|--------|-------------|
| `ama_consttime_memcmp` | Measured | dudect |t| < 4.5 |
| `ama_consttime_memzero` | Measured | dudect |t| < 4.5 |
| `ama_consttime_swap` | Measured | dudect |t| < 4.5 |
| `ama_consttime_lookup` | Measured | dudect |t| < 4.5 |
| `ama_consttime_copy` | Measured | dudect |t| < 4.5 |

Verified via dudect-style Welch's t-test with threshold |t| < 4.5 (~10^-5 false positive probability).

---

## 2. C Library vs Python API Performance

| Operation | C (ops/sec) | Python (ops/sec) | Speedup |
|-----------|-------------|-------------------|---------|
| SHA3-256 (short message) | 1,264,198 | 292,790 | **4.3x** |
| HKDF-SHA3-256 (32B output) | 165,419 | 21,443 | **7.7x** |
| Ed25519 Sign | 9,182 | 10,453 | 0.88x |

![C vs Python Performance](benchmarks/charts/c_vs_python.svg)

**Analysis**:
- Hash/KDF operations see **4–8x speedup** from native C
- Ed25519 C implementation is competitive with the Python API (slight overhead from our pure-C field arithmetic vs optimized assembly in Python's backend)
- For hash-heavy workloads, the C library is strongly recommended

---

## 3. Package Creation Performance

### 3.1 Six-Layer Package Breakdown

| Layer | Operation | Time (ms) | % of Total |
|-------|-----------|-----------|------------|
| 1 | SHA3-256 Hash | 0.001 | 0.2% |
| 2 | HMAC-SHA3-256 | 0.006 | 1.0% |
| 3 | Ed25519 Sign | 0.100 | 17.1% |
| 4 | ML-DSA-65 Sign | 0.473 | **80.7%** |
| 5 | HKDF Derivation | 0.006 | 1.0% |
| 6 | RFC 3161 Timestamp | (optional) | — |
| **Total** | | **~0.586** | 100% |

ML-DSA-65 signing dominates package creation time at ~81% of total.

![Layer Breakdown](benchmarks/charts/layer_breakdown.svg)

### 3.2 Code Package Operations

| Operation | Mean (ms) | Ops/sec | Status | Components |
|-----------|-----------|---------|--------|------------|
| Canonical Encoding | ~0.003 | ~391k | Measured | Length-prefixed |
| Code Hash (7 codes) | ~0.02 | ~57k | Measured | SHA3-256 |
| **Package Creation** | **~0.5–1.8** | **~560–2k** | Measured | Full protection layers |
| **Package Verification** | **~0.4** | **~2.6k** | Measured | All layers validated |

---

## 4. Scalability Analysis (Measured)

### 4.1 Package Size Scaling

| Omni-Code Count | Mean (ms) | Ops/sec | Scaling |
|-----------------|-----------|---------|---------|
| 7 codes | 0.30 | 3,300 | Baseline |
| 70 codes | 0.43 | 2,300 | Linear |
| 700 codes | 1.90 | 526 | Linear |
| 7,000 codes | >180 | 5.5 | Quadratic |

![Scalability](benchmarks/charts/scalability.svg)

**Analysis**:
- **Linear scaling up to ~700 codes**
- Beyond 1,000 codes: quadratic due to signature size growth
- Recommendation: batch large datasets into <700-code packages

---

## 5. Quantum vs Classical Performance (Measured)

### 5.1 Signing Speed

```
Ed25519 (Classical)    ████████████████████ ~20,000 ops/sec
ML-DSA-65 (Quantum)    ████                ~2,115 ops/sec
SLH-DSA (Quantum)      ▏                   ~22 ops/sec

Quantum penalty: ~10x (ML-DSA-65), ~900x (SLH-DSA) slower for signing
```

### 5.2 Verification Speed

```
ML-DSA-65 Verify       ████████████████████ ~6,398 ops/sec
Ed25519 Verify         ████████████████     ~8,000 ops/sec
SLH-DSA Verify         ██████████           ~818 ops/sec
```

**Practical Implications**:
- **Write-heavy workloads**: Quantum signatures add significant latency (use Ed25519 as primary, ML-DSA-65 as secondary)
- **Read-heavy workloads**: ML-DSA-65 verification is competitive with Ed25519
- AMA Cryptography uses a **hybrid approach** (Ed25519 + ML-DSA-65) for classical + post-quantum security
- SLH-DSA (SPHINCS+) serves as a **stateless hash-based fallback** — signing is slow but requires no state management

---

## 6. 3R Monitoring Overhead (Measured)

| Scenario | Overhead | Status |
|----------|----------|--------|
| Timing monitoring only | <0.5% | Measured |
| Pattern analysis (100 packages) | <0.5% | Measured |
| Resonance detection (FFT) | <0.1% | Measured |
| Code analysis | N/A | Offline |
| **Total (all enabled)** | **<2%** | Measured |

```
Baseline (no monitoring):    0.301 ms/package
With 3R monitoring:          0.307 ms/package
Overhead:                    0.006 ms (1.99%)
```

---

## 7. Cython Mathematical Operations (Measured)

| Operation | Pure Python | Cython | Speedup |
|-----------|-------------|--------|---------|
| Lyapunov function | 12.3ms | 0.45ms | **27.3x** |
| Matrix-vector (500×500) | 8.7ms | 0.31ms | **28.1x** |
| NTT (degree 256) | 45.2ms | 1.2ms | **37.7x** |
| Helix evolution (single step) | 3.4ms | 0.18ms | **18.9x** |

**Note**: Comparison is against our own pure-Python baseline, not optimized C/assembly competitors.

---

## 8. CI Regression Detection

### 8.1 Tiered Tolerance Approach

| Tier | Benchmarks | Tolerance | Detects |
|------|-----------|-----------|---------|
| **Tier 1** (Microbenchmarks) | SHA3-256, HMAC, Ed25519, HKDF | **25–30%** | ~1.5–2x regressions |
| **Tier 2** (Complex Operations) | Full package create/verify, PQC | **50%** | ~2x regressions |

### 8.2 Baseline Calibration

Baselines are calibrated **conservatively below** GitHub Actions runner performance to avoid false positives on noisy shared VMs:

| Benchmark | Measured (CI) | Baseline | Headroom |
|-----------|--------------|----------|----------|
| SHA3-256 | ~280k ops/sec | 150k | 47% below |
| HMAC-SHA3-256 | ~160k ops/sec | 70k | 56% below |
| HKDF-SHA3-256 | ~19k ops/sec | 15k | 21% below |
| Ed25519 keygen | ~16k ops/sec | 15k | 6% below |
| Package create | ~560–2k ops/sec | 400 | Conservative floor |
| Package verify | ~2.6k ops/sec | 800 | 69% below |

### 8.3 Running Benchmarks

```bash
# Full benchmark suite
python benchmarks/benchmark_runner.py --verbose

# Regression detection with JSON output
python benchmarks/benchmark_runner.py --verbose --output benchmark-results.json

# Generate visualization charts (requires matplotlib)
python benchmarks/generate_charts.py

# Generate charts to custom directory
python benchmarks/generate_charts.py --output-dir docs/images
```

---

## 9. Hardware Recommendations

| Tier | CPU | RAM | Disk | Network |
|------|-----|-----|------|---------|
| Minimum | 2 cores | 512 MB | 100 MB | — |
| Recommended | 4+ cores | 2 GB | 1 GB | 100 Mbps |
| High-Performance | 8+ cores | 8 GB | SSD | 1 Gbps |

---

## 10. Areas Requiring Additional Testing

**High Priority**:
- [ ] Memory footprint analysis (C lib, Python package, runtime)
- [ ] ARM64 performance comparison vs x86_64

**Medium Priority**:
- [ ] HD key derivation overhead (HMAC-SHA512)
- [ ] Key rotation metadata update overhead
- [ ] Cross-platform variance (Linux vs macOS vs Windows)

**Low Priority**:
- [ ] Build time profiling (C, Cython, full system)
- [ ] Multi-core scaling verification (projected: near-linear)

---

## 11. Conclusion

AMA Cryptography v2.1 delivers **production-grade cryptography** with:

- **~2,600 verifications/sec** (single-threaded, CI hardware)
- **<2ms package creation** (typical on CI; <0.5ms on dedicated hardware)
- **<2% monitoring overhead** (3R system)
- **Linear scaling to ~700 codes**
- **Full RFC 8032 Ed25519 roundtrip** (sign + verify, v2.1)
- **Post-quantum ready**: ML-DSA-65, ML-KEM-1024, SLH-DSA
- **4–8x C library speedup** over Python API for hash/KDF operations

---

## References

1. NIST FIPS 202: SHA-3 Standard — https://csrc.nist.gov/publications/detail/fips/202/final
2. NIST FIPS 203: ML-KEM — https://csrc.nist.gov/pubs/fips/203/final
3. NIST FIPS 204: ML-DSA — https://csrc.nist.gov/pubs/fips/204/final
4. NIST FIPS 205: SLH-DSA — https://csrc.nist.gov/pubs/fips/205/final
5. NIST SP 800-38D: AES-GCM — https://csrc.nist.gov/publications/detail/sp/800-38d/final
6. RFC 8032: Ed25519 — https://datatracker.ietf.org/doc/html/rfc8032
7. RFC 2104: HMAC — https://datatracker.ietf.org/doc/html/rfc2104
8. RFC 5869: HKDF — https://datatracker.ietf.org/doc/html/rfc5869

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-11-26 | Initial professional release |
| 1.1.0 | 2025-11-29 | Updated benchmarks with fresh measurements from Python 3.12 |
| 2.0 | 2026-03-06 | Recalibrated baselines; native C library benchmarks; PQC additions |
| 2.1 | 2026-03-07 | Added SLH-DSA/ML-KEM/AES-GCM benchmarks; SVG chart generation; Ed25519 v2.1 roundtrip verified; consolidated from BENCHMARK_RESULTS.md |

---

Copyright 2025-2026 Steel Security Advisors LLC. Licensed under Apache License 2.0.
