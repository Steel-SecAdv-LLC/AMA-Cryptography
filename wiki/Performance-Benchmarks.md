# Performance Benchmarks

> **Authoritative source:** `BENCHMARKS.md` (generated locally by running `python benchmark_suite.py`; not checked into version control) is the authoritative benchmark document. It includes raw C performance numbers (without ctypes overhead), three-column comparisons, and competitive context against libsodium/liboqs. This wiki page shows Python/ctypes measurements from a specific benchmark run.

Benchmark results for AMA Cryptography on Linux x86_64. All measurements use the native C library via Python/ctypes.

**Platform:** Linux-6.18.5-x86_64 | **CPU:** 4 cores | **Python:** 3.11.15
**Date:** 2026-04-08 | **Dilithium Backend:** native C | **Version:** 2.1.2 (post-PR #188)

---

## Summary Dashboard

| Operation | Mean (ms) | Ops/sec | vs. v2.1.2-pre-perf |
|-----------|----------:|--------:|---------------------:|
| SHA3-256 | 0.001 | 1,244,198 | +12% |
| HMAC-SHA3-256 auth | 0.003 | 295,279 | +43% |
| HMAC-SHA3-256 verify | 0.004 | 241,257 | +29% |
| HKDF-SHA3-256 | 0.006 | 175,859 | +6.6x (stack alloc) |
| Ed25519 keygen | 0.083 | 12,052 | — |
| Ed25519 sign | 0.084 | 11,969 | — |
| Ed25519 verify | 0.118 | 8,479 | — |
| ML-DSA-65 keygen | 0.255 | 3,921 | — |
| ML-DSA-65 sign | 0.445 | 2,249 | — |
| ML-DSA-65 verify | 0.135 | 7,424 | — |
| KMS generation | 0.407 | 2,456 | — |
| Package creation (multi-layer) | 0.871 | 1,148 | +54% (precomputed hash) |
| Package verification | 0.299 | 3,348 | +64% (parallel hybrid) |

---

## Key Generation

| Operation | Mean (ms) | Ops/sec | Iterations |
|-----------|----------:|--------:|-----------:|
| master_secret | 0.0005 | 2,088,993 | 10,000 |
| hkdf_derivation (3-key via KMS) | 0.0340 | 29,431 | 1,000 |
| ed25519_keygen | 0.0830 | 12,052 | 1,000 |
| dilithium_keygen | 0.2550 | 3,921 | 100 |
| kms_generation | 0.4072 | 2,456 | 100 |

---

## Cryptographic Operations

| Operation | Mean (ms) | Ops/sec | Iterations |
|-----------|----------:|--------:|-----------:|
| sha3_256 | 0.0008 | 1,244,198 | 10,000 |
| hmac_auth | 0.0034 | 295,279 | 10,000 |
| hmac_verify | 0.0041 | 241,257 | 10,000 |
| ed25519_sign | 0.0836 | 11,969 | 1,000 |
| ed25519_verify | 0.1179 | 8,479 | 1,000 |
| dilithium_sign | 0.4446 | 2,249 | 100 |
| dilithium_verify | 0.1347 | 7,424 | 100 |

---

## Package Operations (Multi-Layer)

| Operation | Mean (ms) | Ops/sec | Iterations |
|-----------|----------:|--------:|-----------:|
| canonical_encoding | 0.0013 | 759,254 | 10,000 |
| code_hash | 0.0128 | 78,197 | 10,000 |
| package_creation | 0.8711 | 1,148 | 100 |
| package_verification | 0.2987 | 3,348 | 100 |

---

## Ethical Integration Overhead

| Operation | Mean (ms) | Ops/sec |
|-----------|----------:|--------:|
| ethical_context | 0.0036 | 281,241 |
| hkdf_standard | 0.0057 | 175,859 |
| hkdf_with_ethical | 0.0115 | 86,870 |

> Ethical context overhead: 0.0058 ms (101.75% over standard HKDF)

---

## Scalability (Package Creation by Input Size)

| Input Scale | Mean (ms) | Ops/sec | Iterations |
|------------:|----------:|--------:|-----------:|
| 1x baseline | 0.4459 | 2,243 | 50 |
| 10x | 0.6857 | 1,458 | 50 |
| 100x | 2.2622 | 442 | 50 |
| 1000x | 71.9053 | 14 | 50 |

---

## Performance Notes

### Cython Acceleration

When built with Cython (`python setup.py build_ext --inplace`), mathematical operations in the 3R monitoring engine (Lyapunov stability, helical computations, NTT polynomial operations) show:
- **18–37x speedup** over the pure Python mathematical baseline
- NumPy-integrated batch operations

Cython acceleration does **not** affect C-implemented cryptographic primitives (they are already native). The speedup comparison baseline is pure Python loops — not the native C library.

### Algorithm Comparison

| Algorithm | Sign (ms) | Verify (ms) | Sig Size |
|-----------|----------:|------------:|---------:|
| Ed25519 | 0.07 | 0.13 | 64 bytes |
| ML-DSA-65 | 0.97 | 0.20 | 3,309 bytes |
| Hybrid (Ed25519 + ML-DSA-65) | ~1.04 | ~0.33 | 3,373 bytes |
| SPHINCS+-SHA2-256f | ~237 | ~5.95 | 49,856 bytes |

> ML-DSA-65 is ~14x slower to sign than Ed25519 but provides 192-bit quantum security. Numbers from BENCHMARKS.md authoritative benchmark run.

### 3R Monitoring Overhead

- **Monitoring overhead:** < 2% on typical workloads
- Anomaly detection runs asynchronously in the background
- FFT computations use NumPy for batch processing when available

---

## Reproducing Benchmarks

```bash
# Install dependencies
pip install -e ".[dev,monitoring]"

# Build native library
cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Run benchmark suite
python3 benchmark_suite.py

# Or run the regression runner
python3 benchmarks/benchmark_runner.py -v
```

Results are saved to `benchmark_results.json`, `BENCHMARKS.md`, and `benchmarks/regression_results.json`.

---

*\* HMAC-SHA3-256 uses Cython binding (zero marshaling overhead) calling native C `ama_hmac_sha3_256`. Fallback: ctypes (~30,878 ops/sec).*

> **Note on HMAC throughput numbers:** The README reports ~262,200 ops/sec while
> this wiki shows ~30,878 ops/sec for the ctypes fallback. Both numbers are
> correct under different conditions. The 262,200 figure is a Cython
> microbenchmark (direct C call, zero marshaling overhead, 32-byte message). The
> 30,878 figure measures the ctypes fallback path with full Python-to-C
> marshaling overhead on a 1KB message. CI benchmark baselines use the ctypes
> path (~12,000 ops/sec on GitHub Actions runners) since Cython extensions are
> not compiled in CI.

---

## Regression Baselines (from `benchmarks/baseline.json`)

<!-- AUTO-BENCHMARK-TABLE-START -->
| Benchmark | Baseline (ops/sec) | Tolerance | Tier |
|-----------|-------------------:|----------:|------|
| Ama Sha3 256 Hash | 808,929 | ±35% | microbenchmark |
| Hmac Sha3 256 | 191,931 | ±40% | microbenchmark |
| Ed25519 Keygen | 7,834 | ±35% | microbenchmark |
| Ed25519 Sign | 7,780 | ±35% | microbenchmark |
| Ed25519 Verify | 5,511 | ±35% | microbenchmark |
| Hkdf Derive | 114,308 | ±35% | microbenchmark |
| Full Package Create | 746 | ±50% | complex_operation |
| Full Package Verify | 2,176 | ±50% | complex_operation |
| Dilithium Keygen *(optional)* | 2,549 | ±40% | microbenchmark |
| Dilithium Sign *(optional)* | 1,462 | ±40% | microbenchmark |
| Dilithium Verify *(optional)* | 4,825 | ±40% | microbenchmark |
<!-- AUTO-BENCHMARK-TABLE-END -->

*See [Cryptography Algorithms](Cryptography-Algorithms) for algorithm key sizes, or [Architecture](Architecture) for the multi-language performance architecture.*

---

## Standards Compliance Note

This library implements algorithms specified in FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), and FIPS 202 (SHA-3). This implementation has **NOT** been submitted for CMVP validation and is **NOT** FIPS 140-3 certified. See `CSRC_STANDARDS.md` for detailed compliance status.
