# AMA Cryptography — Benchmarks

This directory contains the benchmarking, regression-detection, and
validation tools for measuring the performance of the AMA Cryptography
library.

## Provenance Policy

Every number quoted in a chart, README, or dashboard must be traceable to
one of the artifacts below (or to live output regenerated from them):

| Artifact | Scope | Produced by |
|----------|-------|-------------|
| [`baseline.json`](baseline.json) | CI regression tolerances (65% of measured performance) | Edited manually when primitives land/change |
| [`phase0_baseline_results.json`](phase0_baseline_results.json) | Python/ctypes-path per-op medians | `python benchmarks/phase0_baseline.py` |
| `../benchmark_results.json` (runtime-only) | Suite output consumed by dashboards | `python benchmark_suite.py --json benchmark_results.json` |
| `../build/bin/benchmark_c_raw` (runtime-only) | Raw C per-op medians (no ctypes overhead) | `cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release && cmake --build build --target benchmark_c_raw && build/bin/benchmark_c_raw --json` |
| [`../CSRC_ALIGN_REPORT.md`](../CSRC_ALIGN_REPORT.md) | NIST ACVP vector counts (1,215/1,215/0 — 815 AFT + 400 SHA-3 MCT) | Updated with each alignment run |

If a chart cannot cite one of these, it should not be in the repository.
The fallback tables in [`generate_charts.py`](generate_charts.py) are
anchored to `phase0_baseline_results.json` and `benchmark_c_raw`; they
are overridden by live data from `benchmark_results.json` when available.


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

## Properties Table — Beyond ops/sec

Throughput is only one axis on which a cryptographic library should be
compared.  The table below fixes four other axes that readers routinely
care about but rarely find side-by-side.  Citations are linked inline;
every row points to the project's own documentation rather than a
second-hand summary.  "—" in a cell indicates the project does not make
an explicit claim on that axis (not necessarily "no" — absence of claim).

| Property                         | AMA Cryptography | PyNaCl / libsodium | cryptography / OpenSSL | liboqs |
|----------------------------------|------------------|--------------------|-----------------------|--------|
| Constant-time guarantee          | Documented per-primitive in [`CONSTANT_TIME_VERIFICATION.md`](../CONSTANT_TIME_VERIFICATION.md); empirical verification via in-tree [dudect](https://github.com/oreparaz/dudect) harness under `-DAMA_ENABLE_DUDECT=ON`. | Documented at the library level; "designed to be constant-time in secret data" per [libsodium docs](https://doc.libsodium.org/internals). No dudect harness shipped. | OpenSSL 3.x documents constant-time for ECDSA, ECDH; historical audit findings (CVE-2020-0601, CVE-2020-1971) show carve-outs on some codepaths. | liboqs [Constant-time Policy](https://github.com/open-quantum-safe/liboqs/wiki/Contributing-Guide#constant-time) applies to PQC kernels; upstream CI runs `valgrind --tool=memcheck` with uninit-tainting. |
| Supply-chain surface             | **Zero runtime crypto deps** (INVARIANT-1); only in-tree C + optional vendored ed25519-donna (public domain, compiled from source). SBOM at `schemas/*.spdx`. | libsodium native binary (`libsodium.so`) installed via OS package or wheel; PyNaCl is a thin CFFI wrapper. | OpenSSL native binary (`libcrypto.so`); `cryptography` wheels ship a Rust binding on top. | liboqs native binary (`liboqs.so`) compiled from C source; Python wrapper is a thin ctypes shim. |
| Self-test (FIPS-style POST)      | Startup POST via `ama_self_test()` covers AES-GCM, SHA3, Ed25519, ML-DSA, ML-KEM, HKDF self-tests (see `src/c/ama_core.c`). | None shipped with libsodium / PyNaCl. | OpenSSL FIPS provider (when built) runs full FIPS 140-3 KAT suite at init; default build does not. | liboqs ships KAT test binaries (`tests/kat_sig_algs`, `tests/kat_kem_algs`), run offline; no startup POST. |
| Audit LoC (native C)             | ~12 k lines in `src/c/*.c` + `*.h`; plus ~3 k lines of vendored ed25519-donna under `src/c/vendor/`. Per-primitive provenance in [`src/c/PROVENANCE.md`](../src/c/PROVENANCE.md). | libsodium: ~45 k lines of hand-tuned C + assembly (including portable / assembly / ARM / SSE variants). | OpenSSL libcrypto: ~500 k lines of C covering TLS, PKCS#11, legacy algorithms, engines, FIPS module. | liboqs: ~60 k lines for PQC primitives alone (ML-KEM, ML-DSA, SLH-DSA, HQC, Classic McEliece, Frodo, etc.). |
| ACVP / NIST KAT coverage         | 1,215 / 1,215 vectors in-tree (see `CSRC_ALIGN_REPORT.md`); continuously enforced in `.github/workflows/acvp_validation.yml`. | No ACVP self-attestation; libsodium has not pursued FIPS. | OpenSSL FIPS provider validated against NIST ACVP when built in FIPS mode. | PQClean upstream ships KAT vectors; liboqs CI runs them. |

### Why this table matters

Throughput comparisons alone rank a PQC or classical-crypto library on
one narrow axis.  A production deployment routinely has to trade a 2×
throughput gain for a 10× expansion in supply-chain surface or the loss
of a constant-time guarantee.  Making those trade-offs explicit is the
point of this table: a 5× speedup that comes via pulling in 500 k
additional audit LoC is a different engineering choice than a 5×
speedup that comes from a better in-tree algorithm.

## Interpreting Results

See `BENCHMARKS.md` (generated locally by running `python benchmark_suite.py`; not checked into version control) for the authoritative performance document, including:

- Three-column comparison (Raw C | Python/ctypes | ctypes overhead)
- Competitive context against libsodium, liboqs, and OpenSSL
- Detailed analysis of ctypes overhead impact per operation
