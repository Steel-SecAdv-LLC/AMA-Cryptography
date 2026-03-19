# Performance Benchmarks

Benchmark results for AMA Cryptography on Linux x86_64. All measurements use the native C library.

**Platform:** Linux-6.18.5-x86_64 | **CPU:** 4 cores | **Python:** 3.11.14
**Date:** 2026-03-19 | **Dilithium Backend:** native C

---

## Summary Dashboard

| Operation | Mean (ms) | Ops/sec |
|-----------|----------:|--------:|
| SHA3-256 | 0.001 | 907,822 |
| HMAC-SHA3-256 auth (Cython binding)* | 0.004 | 262,200 |
| HMAC-SHA3-256 verify | 0.004 | 252,100 |
| HKDF-SHA3-256 | 0.213 | 4,689 |
| Ed25519 keygen | 0.294 | 3,407 |
| Ed25519 sign | 0.298 | 3,361 |
| Ed25519 verify | 0.540 | 1,851 |
| ML-DSA-65 keygen | 1.554 | 644 |
| ML-DSA-65 sign | 4.204 | 238 |
| ML-DSA-65 verify | 1.602 | 624 |
| KMS generation | 2.122 | 471 |
| Package creation (6-layer) | 2.165 | 462 |
| Package verification | 2.043 | 489 |

---

## Key Generation

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| master_secret | 0.0008 | 0.0007 | 0.0006 | 1,322,495 | 10,000 |
| hkdf_derivation | 0.2597 | 0.2525 | 0.0174 | 3,850 | 1,000 |
| ed25519_keygen | 0.3694 | 0.3639 | 0.0176 | 2,707 | 1,000 |
| dilithium_keygen | 1.9586 | 1.9524 | 0.0467 | 511 | 100 |
| kms_generation | 2.9882 | 2.6285 | 0.6234 | 335 | 100 |

---

## Cryptographic Operations

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| sha3_256 | 0.0017 | 0.0018 | 0.0015 | 591,593 | 10,000 |
| hmac_auth* | 0.0038 | 0.0036 | 0.0008 | 262,200 | 10,000 |
| hmac_verify* | 0.0040 | 0.0038 | 0.0008 | 252,100 | 10,000 |
| ed25519_sign | 0.3771 | 0.3722 | 0.0176 | 2,652 | 1,000 |
| ed25519_verify | 0.6795 | 0.6720 | 0.0200 | 1,472 | 1,000 |
| dilithium_sign | 2.3329 | 2.3200 | 0.0500 | 429 | 100 |
| dilithium_verify | 1.8644 | 1.8500 | 0.0400 | 536 | 100 |

---

## Package Operations (6-Layer)

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| canonical_encoding | 0.0019 | 0.0019 | 0.0006 | 528,095 | 10,000 |
| code_hash | 0.0132 | 0.0130 | 0.0025 | 75,505 | 10,000 |
| package_creation | 3.3754 | 3.3500 | 0.0800 | 296 | 100 |
| package_verification | 2.6225 | 2.6000 | 0.0700 | 381 | 100 |

---

## Ethical Integration Overhead

| Operation | Mean (ms) | Ops/sec |
|-----------|----------:|--------:|
| ethical_context | 0.0051 | 194,982 |
| hkdf_standard | 0.0779 | 12,839 |
| hkdf_with_ethical | 0.0868 | 11,514 |

> Ethical context overhead: 0.0089 ms (11.42% over standard HKDF)

---

## Scalability (Package Creation by Input Size)

| Input Scale | Mean (ms) | Ops/sec | Iterations |
|------------:|----------:|--------:|-----------:|
| 1x baseline | 3.4140 | 293 | 50 |
| 10x | 6.8212 | 147 | 50 |
| 100x | 4.7049 | 213 | 50 |
| 1000x | 187.2885 | 5.34 | 50 |

---

## Performance Notes

### Cython Acceleration

When built with Cython (`python setup.py build_ext --inplace`), mathematical operations in the 3R engine (equations, double-helix computations) show:
- **18-37x speedup** over pure Python baseline
- NumPy-integrated batch operations

Cython acceleration does **not** affect C-implemented cryptographic primitives (they are already native).

### Algorithm Comparison

| Algorithm | Sign (ms) | Verify (ms) | Sig Size |
|-----------|----------:|------------:|---------:|
| Ed25519 | 0.377 | 0.680 | 64 bytes |
| ML-DSA-65 | 2.333 | 1.864 | 3,309 bytes |
| Hybrid (Ed25519 + ML-DSA-65) | ~2.710 | ~2.544 | 3,373 bytes |
| SPHINCS+-SHA2-256f | ~741 | ~19 | 49,856 bytes |

> ML-DSA-65 is ~6x slower to sign than Ed25519 but provides 192-bit quantum security.

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

*See [Cryptography Algorithms](Cryptography-Algorithms) for algorithm key sizes, or [Architecture](Architecture) for the multi-language performance architecture.*
