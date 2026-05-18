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
| `benchmark_results.json` (runtime-only) | Suite output consumed by dashboards | `python benchmarks/benchmark_suite.py --json benchmarks/benchmark_results.json` |
| `../build/bin/benchmark_c_raw` (runtime-only) | Raw C per-op medians (no ctypes overhead) | `cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release && cmake --build build --target benchmark_c_raw && build/bin/benchmark_c_raw --json` |
| [`../docs/compliance/CSRC_ALIGN_REPORT.md`](../docs/compliance/CSRC_ALIGN_REPORT.md) | NIST ACVP vector counts (1,215/1,215/0 — 815 AFT + 400 SHA-3 MCT) | Updated with each alignment run |

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
| Signatures (classical) | Ed25519 (keygen/sign/verify, plus Shamir wNAF double-scalar-mult), SLH-DSA-SHAKE-128s (FIPS 205 L1 keygen/sign/verify) |
| Signatures (PQC) | ML-DSA-65 (keygen/sign/verify); ML-DSA-65 NTT / invNTT kernel isolation (scalar vs dispatched) |
| KEM | ML-KEM-1024 (keygen/encaps/decaps); ML-KEM-1024 poly add/sub/reduce kernels (scalar vs dispatched) |
| AEAD | AES-256-GCM (1KB/4KB/16KB/64KB enc+dec), ChaCha20-Poly1305 (256B/1KB/4KB/64KB) |
| Password hashing | Argon2id (m=64 KiB, m=1 MiB) |
| Key Exchange | X25519 (keygen, DH exchange, batch×{1,4,8,16}); X25519 DH with MULX/ADX kernel **off** vs **on** (BMI2+ADX gate quantification) |
| Elliptic curves (Bitcoin) | secp256k1 pubkey-from-privkey (SEC1 compressed) |
| Threshold signatures | FROST 2-of-3 round1 commit / round2 sign / aggregate (RFC 9591) |

#### Kernel-isolation rows

Three benchmark families produce paired `(scalar)` / `(dispatch)` rows so
the per-kernel SIMD win is measurable directly, not folded into an
end-to-end primitive cost:

- **ML-DSA-65 NTT / invNTT** — uses the benchmark-only
  `ama_dilithium_ntt_bench()` / `ama_dilithium_invntt_bench()` entry
  points (in `include/ama_cryptography.h`) which route through the
  exact same `dil_ntt_cached` / `dil_invntt_cached` code paths as
  production sign/verify but bind the dispatch slot explicitly.
- **ML-KEM-1024 poly\_{add,sub,reduce}** — runs the SVE2-targeted
  helper-kernel pair against the inline scalar reference; on AVX2 / NEON
  hosts the dispatch slot is NULL and both rows time the same
  compiler auto-vectorised loop (which is itself useful: the
  zero-delta is the documented contract on those hosts).
- **X25519 DH (MULX off / MULX on)** — uses the benchmark/test-only
  `ama_x25519_set_mulx_override()` API to pin the runtime BMI2+ADX
  gate without rebuilding. On hosts without the kernel (CPUID gate
  fails or `AMA_HAVE_X25519_FE64_MULX_IMPL` not defined at build),
  both rows time the pure-C fe64 path and the equal numbers are
  themselves informative ("no kernel on this host").

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
python benchmarks/benchmark_suite.py --markdown BENCHMARKS.md --json benchmarks/benchmark_results.json
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
| ACVP / NIST KAT coverage         | 1,215 / 1,215 vectors in-tree (see `docs/compliance/CSRC_ALIGN_REPORT.md`); continuously enforced in `.github/workflows/acvp_validation.yml`. | No ACVP self-attestation; libsodium has not pursued FIPS. | OpenSSL FIPS provider validated against NIST ACVP when built in FIPS mode. | PQClean upstream ships KAT vectors; liboqs CI runs them. |

### Why this table matters

Throughput comparisons alone rank a PQC or classical-crypto library on
one narrow axis.  A production deployment routinely has to trade a 2×
throughput gain for a 10× expansion in supply-chain surface or the loss
of a constant-time guarantee.  Making those trade-offs explicit is the
point of this table: a 5× speedup that comes via pulling in 500 k
additional audit LoC is a different engineering choice than a 5×
speedup that comes from a better in-tree algorithm.

## Benchmark coverage map (2026-05)

The raw-C harness was extended in 2026-05 to close the explicit coverage gaps
called out in the May 2026 brief. Each gap is now backed by at least one
benchmark row in `benchmark_c_raw.c`, named so it can be grepped from JSON
output:

| Gap (May 2026 brief)                                | Status | Row(s) in `benchmark_c_raw` |
|-----------------------------------------------------|--------|-----------------------------|
| MULX/ADX on-vs-off X25519 ratio                     | ✅ closed | `X25519 DH (MULX off)`, `X25519 DH (MULX on)` |
| SLH-DSA / SPHINCS+ (FIPS 205)                       | ✅ closed | `SLH-DSA-SHAKE-128s KeyGen` / `Sign` / `Verify` (NIST L1) |
| secp256k1                                            | ✅ closed | `secp256k1 pubkey` (compressed SEC1) |
| FROST                                                | ✅ closed | `FROST round1 commit` / `round2 sign` / `aggregate` (2-of-3, RFC 9591) |
| Dilithium NTT kernel isolation                       | ✅ closed | `ML-DSA-65 NTT (scalar)` / `NTT (dispatch)` / `invNTT (scalar)` / `invNTT (dispatch)` |
| ML-KEM-1024 decapsulate                              | ✅ already covered | `ML-KEM-1024 Decaps` (`benchmark_c_raw.c` decaps row) |
| X25519 batch×4 (no env gating)                       | ✅ already covered | `X25519 DH Batch×4` (unconditional) |
| Argon2id                                             | ✅ already covered | `Argon2id (m=64KiB,t=1)`, `Argon2id (m=1MiB,t=1)` |
| Raw HKDF-SHA3-256                                    | ✅ already covered | `HKDF-SHA3-256 (96B)` |

The benchmark/test-only entry points that enable the new rows
(`ama_x25519_set_mulx_override`, `ama_dilithium_ntt_bench`,
`ama_dilithium_invntt_bench`) are documented in
`include/ama_cryptography.h` and explicitly marked as **not part of the
production crypto surface**. They exist so a single shipped binary can
measure paired scalar-vs-dispatched and kernel-on-vs-off rows without
rebuilding the library with different `-D` flags.

## VAES AES-256-GCM dispatch (PR A, 2026-04)

The library grew an optional bulk-throughput AES-256-GCM kernel in
PR A: VAES + VPCLMULQDQ on YMM, runtime-dispatched behind an
OSXSAVE-gated CPUID probe (see `ama_cpuid_has_vaes_aesgcm()`).

The VAES + VPCLMULQDQ AES-GCM path targets **YMM (256-bit), not
ZMM**. Zen 3+ / Ice Lake+ CPUs execute these without the AVX-512
ZMM frequency penalty documented for Skylake-SP / Cascade Lake.
Cloud VM variance on shared hosts is still the dominant noise
source; published throughput numbers are from bare-metal runs, not
CI. The regression baseline tracked in
[`baseline.json`](baseline.json) continues to target the AVX2
AES-NI + PCLMULQDQ path shipped in #253 / #254 / #260 / #261, and
the VAES kernel will only be promoted to the published throughput
number after a 3-run stability check on dedicated silicon — mirroring
the 2026-04-21 dilithium_sign recalibration pattern already in
`baseline.json::metadata.baseline_change_log`.

Hosts without VAES (or any non-x86-64 host) automatically route
through the AVX2 AES-NI + PCLMULQDQ fallback, which was already
validated by ACVP and is byte-identical to the VAES path
(see `tests/c/test_aes_gcm_vaes_equiv.c`).

## Interpreting Results

See `BENCHMARKS.md` (generated locally by running `python benchmarks/benchmark_suite.py`; not checked into version control) for the authoritative performance document, including:

- Three-column comparison (Raw C | Python/ctypes | ctypes overhead)
- Competitive context against libsodium, liboqs, and OpenSSL
- Detailed analysis of ctypes overhead impact per operation
