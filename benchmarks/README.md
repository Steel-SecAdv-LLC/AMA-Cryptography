# AMA Cryptography — Benchmarks

This directory contains benchmarking tools for measuring the performance of the AMA Cryptography library.

## Raw C Benchmark (`benchmark_c_raw.c`)

Directly calls C library functions without Python or ctypes involvement. Provides the most accurate measurement of C library performance.

### Build

```bash
# Option 1: Build via the benchmarks Makefile (auto-detects library)
make -C benchmarks benchmark_c_raw

# Option 2: Build via cmake (adds benchmark_c_raw target)
cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build
make -C benchmarks benchmark_c_raw
```

### Run

```bash
# Human-readable table (default)
./benchmarks/benchmark_c_raw

# Machine-parseable CSV
./benchmarks/benchmark_c_raw --csv

# Machine-parseable JSON
./benchmarks/benchmark_c_raw --json
```

### What It Benchmarks

| Category | Operations |
|----------|-----------|
| Hash | SHA3-256 (32B, 1KB), SHA3-512 (32B, 1KB) |
| MAC | HMAC-SHA3-256 (32B, 1KB) |
| KDF | HKDF-SHA3-256 (96B output) |
| Signatures | Ed25519 (keygen/sign/verify), ML-DSA-65 (keygen/sign/verify) |
| KEM | ML-KEM-1024 (keygen/encaps/decaps) |
| AEAD | AES-256-GCM (1KB/4KB/64KB enc+dec) |
| Key Exchange | X25519 (keygen, DH exchange) |

### Methodology

- Timer: `clock_gettime(CLOCK_MONOTONIC)` (nanosecond resolution)
- Warmup: 50 iterations discarded before measurement
- Iterations: 200–5,000 depending on operation speed
- Statistics: mean, median, stddev, min, max, ops/sec

### Output Format

The default table output includes a comparison-ready format:

```
Operation                      | Raw C ops/sec  | Raw C latency
-------------------------------|----------------|---------------
SHA3-256 (32B)                 |        555556  |       1.80 us
Ed25519 Sign                   |         15625  |      64.00 us
ML-DSA-65 Sign                 |          1053  |     950.00 us
```

## Python/ctypes Benchmarks

| Script | Purpose |
|--------|---------|
| `benchmark_runner.py` | CI/CD regression detection against `baseline.json` |
| `performance_suite.py` | Comprehensive Python vs Cython vs C comparison |
| `phase0_baseline.py` | Establishes ctypes-based performance baselines |
| `validation_suite.py` | Validates documented claims against measured performance |
| `comparative_benchmark.py` | Compares AMA vs OpenSSL+liboqs |

### Running CI Benchmarks

```bash
python benchmarks/benchmark_runner.py --verbose
```

### Running the Full Suite

```bash
python benchmark_suite.py --markdown BENCHMARKS.md --json benchmark_results.json
```

## Interpreting Results

See [BENCHMARKS.md](/BENCHMARKS.md) in the repository root for the authoritative performance document, including:

- Three-column comparison (Raw C | Python/ctypes | ctypes overhead)
- Competitive context against libsodium, liboqs, and OpenSSL
- Detailed analysis of ctypes overhead impact per operation
