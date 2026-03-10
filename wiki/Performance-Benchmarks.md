# Performance Benchmarks

Benchmark results for AMA Cryptography on Linux x86_64. All measurements use the native C library.

**Platform:** Linux-6.18.5-x86_64 | **CPU:** 4 cores | **Python:** 3.11.14  
**Date:** 2026-03-10 | **Dilithium Backend:** native C

---

## Summary Dashboard

| Operation | Mean (ms) | Ops/sec |
|-----------|----------:|--------:|
| SHA3-256 | 0.001 | 1,046,450 |
| HMAC-SHA3-256 auth | 0.003 | 291,466 |
| HMAC-SHA3-256 verify | 0.004 | 278,528 |
| HKDF-SHA3-256 | 0.050 | 20,117 |
| Ed25519 keygen | 0.120 | 8,354 |
| Ed25519 sign | 0.235 | 4,248 |
| Ed25519 verify | 0.246 | 4,070 |
| ML-DSA-65 keygen | 0.220 | 4,554 |
| ML-DSA-65 sign | 1.019 | 981 |
| ML-DSA-65 verify | 0.208 | 4,809 |
| KMS generation | 0.403 | 2,481 |
| Package creation (6-layer) | 0.590 | 1,694 |
| Package verification | 0.449 | 2,225 |

---

## Key Generation

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| master_secret | 0.0005 | 0.0004 | 0.0005 | 2,117,409 | 10,000 |
| hkdf_derivation | 0.0497 | 0.0465 | 0.0101 | 20,117 | 1,000 |
| ed25519_keygen | 0.1197 | 0.1167 | 0.0127 | 8,354 | 1,000 |
| dilithium_keygen | 0.2196 | 0.2212 | 0.0163 | 4,554 | 100 |
| kms_generation | 0.4030 | 0.4082 | 0.0279 | 2,481 | 100 |

---

## Cryptographic Operations

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| sha3_256 | 0.0010 | 0.0009 | 0.0005 | 1,046,450 | 10,000 |
| hmac_auth | 0.0034 | 0.0033 | 0.0011 | 291,466 | 10,000 |
| hmac_verify | 0.0036 | 0.0034 | 0.0013 | 278,528 | 10,000 |
| ed25519_sign | 0.2354 | 0.2351 | 0.0108 | 4,248 | 1,000 |
| ed25519_verify | 0.2457 | 0.2486 | 0.0163 | 4,070 | 1,000 |
| dilithium_sign | 1.0190 | 1.0276 | 0.0556 | 981 | 100 |
| dilithium_verify | 0.2079 | 0.2061 | 0.0060 | 4,809 | 100 |

---

## Package Operations (6-Layer)

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| canonical_encoding | 0.0013 | 0.0013 | 0.0006 | 747,422 | 10,000 |
| code_hash | 0.0098 | 0.0093 | 0.0025 | 102,448 | 10,000 |
| package_creation | 0.5904 | 0.6004 | 0.0417 | 1,694 | 100 |
| package_verification | 0.4494 | 0.4564 | 0.0267 | 2,225 | 100 |

---

## Ethical Integration Overhead

| Operation | Mean (ms) | Ops/sec |
|-----------|----------:|--------:|
| ethical_context | 0.0061 | 163,698 |
| hkdf_standard | 0.0088 | 114,276 |
| hkdf_with_ethical | 0.0169 | 59,139 |

> Ethical context overhead: 0.0081 ms (~92% over standard HKDF — the ethical binding adds a second HKDF derivation pass)

---

## Scalability (Package Creation by Input Size)

| Input Scale | Mean (ms) | Ops/sec | Iterations |
|------------:|----------:|--------:|-----------:|
| 1× baseline | 0.7380 | 1,355 | 50 |
| 10× | 0.9613 | 1,040 | 50 |
| 100× | 1.9756 | 506 | 50 |
| 1000× | 138.9809 | 7.2 | 50 |

---

## Performance Notes

### Cython Acceleration

When built with Cython (`python setup.py build_ext --inplace`), mathematical operations in the 3R engine (equations, double-helix computations) show:
- **18–37× speedup** over pure Python baseline
- NumPy-integrated batch operations

Cython acceleration does **not** affect C-implemented cryptographic primitives (they are already native).

### Algorithm Comparison

| Algorithm | Sign (ms) | Verify (ms) | Sig Size |
|-----------|----------:|------------:|---------:|
| Ed25519 | 0.235 | 0.246 | 64 bytes |
| ML-DSA-65 | 1.019 | 0.208 | 3,309 bytes |
| Hybrid (Ed25519 + ML-DSA-65) | ~1.254 | ~0.454 | 3,373 bytes |
| SPHINCS+-SHA2-256f | ~200+ | ~50 | 49,856 bytes |

> ML-DSA-65 is ~4× slower to sign than Ed25519 but provides 192-bit quantum security. Verification is comparable.

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
python3 -m pytest tests/test_performance.py -v --benchmark-only

# Or run the dedicated benchmark script
python3 benchmarks/run_benchmarks.py
```

Results are saved to `benchmarks/regression_report.md` and `benchmarks/validation_report.md`.

---

*See [Cryptography Algorithms](Cryptography-Algorithms) for algorithm key sizes, or [Architecture](Architecture) for the multi-language performance architecture.*
