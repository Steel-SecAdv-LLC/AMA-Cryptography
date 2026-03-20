# Performance Benchmarks

Benchmark results for AMA Cryptography on Linux x86_64. All measurements use the native C library.

**Platform:** Linux-6.18.5-x86_64 | **CPU:** 4 cores | **Python:** 3.11.14
**Date:** 2026-03-20 | **Dilithium Backend:** native C
**Compiler:** GCC 13.3.0 | **Flags:** `-O3 -march=native -funroll-loops`

---

## Summary Dashboard

| Operation | Mean (ms) | Ops/sec |
|-----------|----------:|--------:|
| SHA3-256 | 0.001 | 907,822 |
| HMAC-SHA3-256 auth (Cython binding)* | 0.004 | 262,200 |
| HMAC-SHA3-256 verify | 0.004 | 252,100 |
| HKDF-SHA3-256 | 0.213 | 4,689 |
| Ed25519 keygen | 0.045 | 22,123 |
| Ed25519 sign | 0.047 | 21,177 |
| Ed25519 verify | 0.100 | 9,979 |
| ML-DSA-65 keygen | 0.203 | 4,925 |
| ML-DSA-65 sign | 0.232 | 4,315 |
| ML-DSA-65 verify | 0.001 | 1,174,398 |
| Package creation (6-layer) | 0.516 | 1,939 |
| Package verification | 0.465 | 2,152 |

---

## Key Generation

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| master_secret | 0.0008 | 0.0007 | 0.0006 | 1,322,495 | 10,000 |
| hkdf_derivation | 0.2597 | 0.2525 | 0.0174 | 3,850 | 1,000 |
| ed25519_keygen | 0.0452 | 0.0451 | 0.0010 | 22,123 | 50,000 |
| dilithium_keygen | 0.2030 | 0.2028 | 0.0050 | 4,925 | 10,000 |

---

## Cryptographic Operations

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| sha3_256 | 0.0017 | 0.0018 | 0.0015 | 591,593 | 10,000 |
| hmac_auth* | 0.0038 | 0.0036 | 0.0008 | 262,200 | 10,000 |
| hmac_verify* | 0.0040 | 0.0038 | 0.0008 | 252,100 | 10,000 |
| ed25519_sign | 0.0472 | 0.0470 | 0.0010 | 21,177 | 50,000 |
| ed25519_verify | 0.1002 | 0.1000 | 0.0020 | 9,979 | 20,000 |
| dilithium_sign | 0.2318 | 0.2315 | 0.0050 | 4,315 | 10,000 |
| dilithium_verify | 0.0009 | 0.0009 | 0.0001 | 1,174,398 | 100,000 |

---

## Package Operations (6-Layer)

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| canonical_encoding | 0.0019 | 0.0019 | 0.0006 | 528,095 | 10,000 |
| code_hash | 0.0132 | 0.0130 | 0.0025 | 75,505 | 10,000 |
| package_creation | 0.5160 | 0.5150 | 0.0100 | 1,939 | 1,000 |
| package_verification | 0.4650 | 0.4640 | 0.0100 | 2,152 | 1,000 |

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
| Ed25519 | 0.047 | 0.100 | 64 bytes |
| ML-DSA-65 | 0.232 | 0.001 | 3,309 bytes |
| Hybrid (Ed25519 + ML-DSA-65) | ~0.279 | ~0.101 | 3,373 bytes |
| SPHINCS+-SHA2-256f | ~741 | ~19 | 49,856 bytes |

> ML-DSA-65 is ~5x slower to sign than Ed25519 but provides 192-bit quantum security.

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
