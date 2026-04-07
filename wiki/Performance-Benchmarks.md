# Performance Benchmarks

> **Authoritative source:** [BENCHMARKS.md](/BENCHMARKS.md) in the repository root is the authoritative benchmark document. It includes raw C performance numbers (without ctypes overhead), three-column comparisons, and competitive context against libsodium/liboqs. This wiki page shows Python/ctypes measurements from a specific benchmark run.

Benchmark results for AMA Cryptography on Linux x86_64. All measurements use the native C library via Python/ctypes.

**Platform:** Linux-6.18.5-x86_64 | **CPU:** 4 cores | **Python:** 3.11.14
**Date:** 2026-04-06 | **Dilithium Backend:** native C

---

## Summary Dashboard

| Operation | Mean (ms) | Ops/sec |
|-----------|----------:|--------:|
| SHA3-256 | 0.001 | 1,109,669 |
| HMAC-SHA3-256 auth | 0.005 | 206,010 |
| HMAC-SHA3-256 verify | 0.005 | 186,782 |
| HKDF-SHA3-256 | 0.038 | 26,529 |
| Ed25519 keygen | 0.052 | 19,388 |
| Ed25519 sign | 0.054 | 18,657 |
| Ed25519 verify | 0.103 | 9,702 |
| ML-DSA-65 keygen | 0.181 | 5,536 |
| ML-DSA-65 sign | 0.275 | 3,639 |
| ML-DSA-65 verify | 0.154 | 6,490 |
| KMS generation | 0.285 | 3,509 |
| Package creation (multi-layer) | 0.789 | 1,268 |
| Package verification | 0.332 | 3,009 |

---

## Key Generation

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| master_secret | 0.0005 | 0.0005 | 0.0004 | 1,880,164 | 10,000 |
| hkdf_derivation | 0.0377 | 0.0359 | 0.0068 | 26,529 | 1,000 |
| ed25519_keygen | 0.0516 | 0.0505 | 0.0045 | 19,388 | 1,000 |
| dilithium_keygen | 0.1806 | 0.1774 | 0.0104 | 5,536 | 100 |
| kms_generation | 0.2850 | 0.2830 | 0.0202 | 3,509 | 100 |

---

## Cryptographic Operations

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| sha3_256 | 0.0009 | 0.0008 | 0.0006 | 1,109,669 | 10,000 |
| hmac_auth | 0.0049 | 0.0039 | 0.0027 | 206,010 | 10,000 |
| hmac_verify | 0.0054 | 0.0045 | 0.0026 | 186,782 | 10,000 |
| ed25519_sign | 0.0536 | 0.0512 | 0.0066 | 18,657 | 1,000 |
| ed25519_verify | 0.1031 | 0.1012 | 0.0084 | 9,702 | 1,000 |
| dilithium_sign | 0.2748 | 0.2729 | 0.0122 | 3,639 | 100 |
| dilithium_verify | 0.1541 | 0.1484 | 0.0169 | 6,490 | 100 |

---

## Package Operations (Multi-Layer)

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| canonical_encoding | 0.0014 | 0.0013 | 0.0007 | 716,826 | 10,000 |
| code_hash | 0.0137 | 0.0132 | 0.0028 | 72,807 | 10,000 |
| package_creation | 0.7886 | 0.7826 | 0.0370 | 1,268 | 100 |
| package_verification | 0.3323 | 0.3151 | 0.0605 | 3,009 | 100 |

---

## Ethical Integration Overhead

| Operation | Mean (ms) | Ops/sec |
|-----------|----------:|--------:|
| ethical_context | 0.0046 | 217,721 |
| hkdf_standard | 0.0076 | 132,116 |
| hkdf_with_ethical | 0.0150 | 66,489 |

> Ethical context overhead: 0.0074 ms (97.37% over standard HKDF)

---

## Scalability (Package Creation by Input Size)

| Input Scale | Mean (ms) | Ops/sec | Iterations |
|------------:|----------:|--------:|-----------:|
| 1x baseline | 0.5478 | 1,825 | 50 |
| 10x | 0.4995 | 2,002 | 50 |
| 100x | 2.3768 | 421 | 50 |
| 1000x | 81.1257 | 12 | 50 |

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
| Ama Sha3 256 Hash | 113,388 | ±35% | microbenchmark |
| Hmac Sha3 256 | 76,215 | ±40% | microbenchmark |
| Ed25519 Keygen | 10,560 | ±35% | microbenchmark |
| Ed25519 Sign | 10,430 | ±35% | microbenchmark |
| Ed25519 Verify | 5,113 | ±35% | microbenchmark |
| Hkdf Derive | 53,193 | ±35% | microbenchmark |
| Full Package Create | 746 | ±50% | complex_operation |
| Full Package Verify | 2,044 | ±50% | complex_operation |
| Dilithium Keygen *(optional)* | 1,943 | ±40% | microbenchmark |
| Dilithium Sign *(optional)* | 1,918 | ±40% | microbenchmark |
| Dilithium Verify *(optional)* | 4,303 | ±40% | microbenchmark |
<!-- AUTO-BENCHMARK-TABLE-END -->

*See [Cryptography Algorithms](Cryptography-Algorithms) for algorithm key sizes, or [Architecture](Architecture) for the multi-language performance architecture.*

---

## Standards Compliance Note

This library implements algorithms specified in FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), and FIPS 202 (SHA-3). This implementation has **NOT** been submitted for CMVP validation and is **NOT** FIPS 140-3 certified. See `CSRC_STANDARDS.md` for detailed compliance status.
