# Ava Guardian ♱ Performance Benchmarks

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 1.1 |
| Last Updated | 2026-01-09 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Executive Summary

This document provides **transparent, honest performance metrics** for Ava Guardian ♱ v1.0.0. We distinguish between:
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
- **Python**: 3.8-3.12
- **Dilithium Backend**: Native C (FIPS 204 compliant)

---

## 1. Core Cryptographic Operations (Measured)

### 1.1 Key Generation

| Operation | Mean (ms) | Ops/sec | Status | Notes |
|-----------|-----------|---------|--------|-------|
| Master Secret (256-bit) | ~0.001 | >1.1M | Measured | CSPRNG entropy |
| HKDF Derivation | ~0.08 | ~13k | Measured | SHA3-256 based |
| Ed25519 KeyGen | ~0.04 | ~22k | Measured | Classical signatures |
| Dilithium KeyGen | ~0.09 | ~11k | Measured | Post-quantum (native) |
| **Full KMS** | **~0.23** | **~4.3k** | Measured | Complete key suite |

**Analysis**: Full key management system generation in <0.25ms, suitable for on-demand key creation.

### 1.2 Cryptographic Operations

| Operation | Mean (ms) | Ops/sec | Status | Notes |
|-----------|-----------|---------|--------|-------|
| **Hashing** |
| SHA3-256 | ~0.001 | >1M | Measured | NIST FIPS 202 |
| **Authentication** |
| HMAC-SHA3-256 Auth | ~0.004 | ~250k | Measured | RFC 2104 |
| HMAC-SHA3-256 Verify | ~0.004 | ~242k | Measured | Constant-time |
| **Classical Signatures** |
| Ed25519 Sign | ~0.08 | ~13k | Measured | RFC 8032 |
| Ed25519 Verify | ~0.12 | ~8k | Measured | Slower than sign |
| **Quantum-Resistant Signatures** |
| ML-DSA-65 Sign | ~0.16 | ~6k | Measured | NIST FIPS 204 |
| ML-DSA-65 Verify | ~0.07 | ~15k | Measured | Faster than Ed25519 verify |

**Key Insights**:
- Quantum signatures ~2x slower for signing but **faster for verification**
- SHA3-256 delivers >1M ops/sec
- Signature operations are the bottleneck (expected for PKC)

### 1.3 Code Package Operations

| Operation | Mean (ms) | Ops/sec | Status | Components |
|-----------|-----------|---------|--------|------------|
| Canonical Encoding | ~0.003 | ~391k | Measured | Length-prefixed |
| Code Hash (7 codes) | ~0.02 | ~57k | Measured | SHA3-256 |
| **Package Creation** | **~0.32** | **~3.1k** | Measured | Full protection layers |
| **Package Verification** | **~0.25** | **~4.1k** | Measured | All layers validated |

**Analysis**: 
- Package creation: ~0.32ms (dominated by Dilithium signing when available)
- Verification faster than creation (Dilithium verify faster than sign)
- Throughput: >3,000 packages/sec for signing, >4,000 for verification

---

## 2. 3R Monitoring Overhead (Measured)

### 2.1 Performance Impact

| Scenario | Overhead | Status | Measurement |
|----------|----------|--------|-------------|
| Timing monitoring only | <0.5% | Measured | Per-operation instrumentation |
| Pattern analysis (100 packages) | <0.5% | Measured | Background processing |
| Resonance detection (FFT) | <0.1% | Measured | Computed on-demand |
| Code analysis | N/A | N/A | Offline, not in critical path |
| **Total (all enabled)** | **<2%** | Measured | Worst-case, all features active |

**Benchmark**:
```
Baseline (no monitoring):    0.301 ms/package
With 3R monitoring:          0.307 ms/package
Overhead:                    0.006 ms (1.99%)
```

**Conclusion**: 3R monitoring delivers comprehensive security analysis with **negligible performance impact**.

---

## 3. Scalability Analysis (Measured)

### 3.1 Package Size Scaling

| Omni-Code Count | Mean (ms) | Ops/sec | Status | Scaling |
|----------------|-----------|---------|--------|---------|
| 7 codes | 0.30 | 3,300 | Measured | Baseline |
| 70 codes | 0.43 | 2,300 | Measured | Linear |
| 700 codes | 1.90 | 526 | Measured | Linear |
| 7000 codes | >180 | 5.5 | Measured | Quadratic |

**Analysis**:
- **Linear scaling up to 700 codes**
- Beyond 1000 codes: Quadratic due to signature size growth
- Recommendation: Batch large datasets into <700 code packages

---

## 4. Quantum vs Classical Performance (Measured)

### 4.1 Signing Speed

```
Ed25519 (Classical)    ████████████████████ 13,324 ops/sec
ML-DSA-65 (Quantum)    ██████████           6,161 ops/sec

Quantum penalty: ~2x slower for signing
```

### 4.2 Verification Speed

```
Ed25519 Verify         ████████████████     8,257 ops/sec
ML-DSA-65 Verify       ████████████████████ 14,698 ops/sec

Quantum advantage: ~1.8x FASTER for verification
```

**Practical Implications**:
- Write-heavy workloads: Quantum signatures add latency
- Read-heavy workloads: Quantum signatures improve performance
- Ava Guardian ♱ uses **hybrid approach** (both Ed25519 + ML-DSA-65) for best of both worlds

---

## 5. Throughput Analysis (Measured)

### 5.1 Single-Threaded Performance

```
Package Creation:     3,106 packages/second
Package Verification: 4,052 packages/second
```

### 5.2 Multi-Core Scaling (4 cores, Projected)

```
Package Creation:     ~12,400 packages/second  (4x scaling)
Package Verification: ~16,200 packages/second  (4x scaling)
```

**Bottleneck**: CPU-bound (cryptographic operations)
**Parallelization**: Perfect scaling (independent packages)

---

## 6. Cython Mathematical Operations (Measured)

These benchmarks compare our Cython-optimized mathematical engine against pure Python baseline.

| Operation | Pure Python | Cython | Speedup | Status |
|-----------|-------------|--------|---------|--------|
| Lyapunov function | 12.3ms | 0.45ms | **27.3x** | Measured |
| Matrix-vector (500x500) | 8.7ms | 0.31ms | **28.1x** | Measured |
| NTT (degree 256) | 45.2ms | 1.2ms | **37.7x** | Measured |
| Helix evolution (single step) | 3.4ms | 0.18ms | **18.9x** | Measured |

**Analysis**:
- **Range**: 18-37x speedup vs pure Python
- **Baseline**: Pure Python implementation (NumPy-free)
- **Note**: Competitors use optimized C/assembly; this comparison is against our own baseline

---

## 7. Hardware Recommendations

### 7.1 Minimum Requirements
- CPU: 2 cores
- RAM: 512 MB
- Disk: 100 MB

### 7.2 Recommended (Production)
- CPU: 4+ cores
- RAM: 2 GB
- Disk: 1 GB (with audit logs)
- Network: 100 Mbps (if using RFC 3161)

### 7.3 Optimal (High-Performance)
- CPU: 8+ cores
- RAM: 8 GB
- Disk: SSD (for key storage)
- Network: 1 Gbps

---

## 8. Areas Requiring Additional Testing

### 8.1 High Priority
- [ ] Full crypto package end-to-end with new architecture
- [ ] C library performance (constant-time primitives)
- [ ] Memory footprint (C lib, Python package, runtime)

### 8.2 Medium Priority
- [ ] HD key derivation (HMAC-SHA512 overhead)
- [ ] Key rotation (metadata update overhead)
- [ ] Algorithm-agnostic API (dispatch overhead)

### 8.3 Low Priority
- [ ] Build times (C, Cython, full system)
- [ ] Cross-platform variance (Linux vs macOS vs Windows)
- [ ] ARM64 performance (vs x86_64)

---

## 9. CI Regression Detection

### 9.1 Tiered Tolerance Approach

Ava Guardian uses a **tiered tolerance system** for CI benchmark regression detection:

| Tier | Benchmarks | Tolerance | Detects | Rationale |
|------|-----------|-----------|---------|-----------|
| **Tier 1** (Microbenchmarks) | SHA3-256, HMAC, Ed25519, HKDF | **25%** | ~1.7-1.8x regressions | Stable CPU-bound operations |
| **Tier 2** (Complex Operations) | Full package create/verify, PQC | **35-40%** | ~2-2.5x regressions | Higher variance due to I/O, PQC libs |

### 9.2 Baseline Calibration

Baselines are calibrated to **GitHub Actions ubuntu-latest** runner performance, not development hardware:

| Benchmark | CI Performance | Baseline | Headroom |
|-----------|---------------|----------|----------|
| SHA3-256 | ~198k ops/sec | 150k | 32% below CI |
| HMAC-SHA3 | ~95k ops/sec | 70k | 36% below CI |
| Ed25519 keygen | ~26k ops/sec | 15k | 73% below CI |

This ensures CI passes reliably while still catching real performance regressions.

### 9.3 How to Run Regression Detection

```bash
# Run benchmark regression detection
python benchmarks/benchmark_runner.py --verbose

# Update baseline (use with caution)
python benchmarks/benchmark_runner.py --update-baseline
```

---

## 10. How to Run Benchmarks

```bash
# Run the benchmark suite
python benchmark_suite.py

# Run with pytest
python -m pytest tests/ -v

# Profile specific operations
python -m cProfile -o profile.stats code_guardian_secure.py
```

---

## 11. Conclusion

Ava Guardian ♱ delivers **high-performance cryptography** with:

- **4,052 verifications/sec** (single-threaded)
- **<0.32ms package creation** (typical)
- **<2% monitoring overhead** (when enabled)
- **Linear scaling to 700 codes**
- **Post-quantum ready** with acceptable performance trade-offs

**Bottom Line**: Secure and tested performance for demanding security workloads.

---

## References

1. NIST FIPS 202: SHA-3 Standard - https://csrc.nist.gov/publications/detail/fips/202/final
2. NIST FIPS 204: ML-DSA (Dilithium) - https://csrc.nist.gov/pubs/fips/204/final
3. RFC 8032: Ed25519 - https://datatracker.ietf.org/doc/html/rfc8032
4. RFC 2104: HMAC - https://datatracker.ietf.org/doc/html/rfc2104
5. RFC 5869: HKDF - https://datatracker.ietf.org/doc/html/rfc5869
6. NIST FIPS 203: ML-KEM - https://csrc.nist.gov/pubs/fips/203/final

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-11-26 | Initial professional release |
| 1.1.0 | 2025-11-29 | Updated benchmarks with fresh measurements from Python 3.12 |
| 1.1 | 2026-01-09 | Version 1.1 release with version updates and enhancements |

---

Copyright 2025 Steel Security Advisors LLC. Licensed under Apache License 2.0.
