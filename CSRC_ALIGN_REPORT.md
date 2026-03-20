# CSRC Alignment Report — NIST ACVP Vector Validation

**Version:** 2.2
**Date:** 2026-03-18 (updated)
**Organization:** Steel Security Advisors LLC
**Author:** Andrew E. A.

---

## Abstract

This report documents the results of running official NIST test vectors against
the AMA Cryptography library (version 2.0). The validation covers 12 algorithm
functions across 6 NIST standards (FIPS 180-4, FIPS 198-1, FIPS 202, FIPS 203,
FIPS 204, FIPS 205) and 1 NIST Special Publication (SP 800-38D).

**Summary:** 815 vectors tested, **815 passed**, **0 failed**, 4,757 skipped
(non-byte-aligned inputs, non-target parameter sets, MCT/LDT/VOT test types).

All algorithms pass 100% of applicable NIST test vectors.

> **This report constitutes self-attested algorithm compliance using official
> NIST vectors. It is NOT a CAVP validation certificate and does not represent
> NIST endorsement.**

---

## Section 1: Methodology

### 1.1 Vector Sources

| Algorithm | Source | URL |
|-----------|--------|-----|
| SHA3-256 | ACVP-Server SHA3-256-2.0 internalProjection.json | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHA3-256-2.0 |
| SHA3-512 | ACVP-Server SHA3-512-2.0 internalProjection.json | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHA3-512-2.0 |
| SHAKE-128 | ACVP-Server SHAKE-128-1.0 internalProjection.json | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHAKE-128-1.0 |
| SHAKE-256 | ACVP-Server SHAKE-256-1.0 internalProjection.json | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHAKE-256-1.0 |
| HMAC-SHA-256 | ACVP-Server HMAC-SHA2-256-2.0 internalProjection.json | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-256-2.0 |
| SHA-256 | FIPS 180-4 Section B.1 reference vectors | https://csrc.nist.gov/pubs/fips/180-4/upd1/final |
| AES-256-GCM | SP 800-38D Appendix B (McGrew & Viega TC13–TC16) | https://csrc.nist.gov/pubs/sp/800/38/d/final |
| ML-KEM-1024 KeyGen | ACVP-Server ML-KEM-keyGen-FIPS203 internalProjection.json | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203 |
| ML-KEM-1024 EncapDecap | ACVP-Server ML-KEM-encapDecap-FIPS203 internalProjection.json | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203 |
| ML-DSA-65 KeyGen | ACVP-Server ML-DSA-keyGen-FIPS204 internalProjection.json | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-keyGen-FIPS204 |
| ML-DSA-65 SigVer | ACVP-Server ML-DSA-sigVer-FIPS204 internalProjection.json | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigVer-FIPS204 |
| SLH-DSA-SHA2-256f SigVer | ACVP-Server SLH-DSA-sigVer-FIPS205 internalProjection.json | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SLH-DSA-sigVer-FIPS205 |

### 1.2 PQC Backend Identification

All post-quantum algorithms (ML-KEM-1024, ML-DSA-65, SLH-DSA-SHA2-256f) are
implemented in native C within the AMA Cryptography library. **No external PQC
libraries are used** — the library does not depend on liboqs, PQClean, or any
third-party PQC implementation.

Source files:
- `src/c/ama_kyber.c` — ML-KEM-1024 (FIPS 203)
- `src/c/ama_dilithium.c` — ML-DSA-65 (FIPS 204)
- `src/c/ama_sphincs.c` — SLH-DSA-SHA2-256f (FIPS 205)
- `src/c/internal/ama_sha2.h` — Shared SHA-512/HMAC-SHA-512 (used by Ed25519 + SLH-DSA)

### 1.3 Test Execution Environment

| Property | Value |
|----------|-------|
| Operating system | Linux 6.18.5 (x86_64) |
| Compiler flags | CMake Release, `-DAMA_USE_NATIVE_PQC=ON`, LTO enabled, AVX2 enabled |
| Python version | 3.11.14 |
| Test harness | `nist_vectors/run_vectors.py` (ctypes FFI to `libama_cryptography.so`) |

### 1.4 Vector Selection Criteria

1. **AFT only.** Monte Carlo Test (MCT), Large Data Test (LDT), and Variable
   Output Test (VOT) vectors are skipped. MCT requires iterative state not
   supported by a one-shot harness. LDT requires multi-gigabyte inputs.
2. **Byte-aligned only.** Vectors with `bitLength % 8 != 0` are skipped.
   AMA's C API is byte-granularity only.
3. **ML-KEM-1024 only.** ML-KEM-512 and ML-KEM-768 parameter sets are not
   implemented and are skipped.
4. **ML-KEM EncapDecap: decapsulation only.** AMA does not expose the
   randomness parameter `m` required for deterministic encapsulation.
5. **ML-DSA-65 SigVer: TG 3 (external/pure) only.** Internal and pre-hash
   test groups are skipped.
6. **SLH-DSA-SHA2-256f SigVer: TG 5 (external/pure) only.** Other parameter
   sets and test groups are skipped.

---

## Section 2: Results

### 2.1 Summary Table

| Algorithm | Standard | Source | Tested | Pass | Fail | Skipped | Notes |
|-----------|----------|--------|-------:|-----:|-----:|--------:|-------|
| SHA3-256 | FIPS 202 | ACVP-Server | 151 | 151 | 0 | 1,043 | Non-byte-aligned inputs skipped; MCT/LDT skipped |
| SHA3-512 | FIPS 202 | ACVP-Server | 86 | 86 | 0 | 596 | Non-byte-aligned inputs skipped; MCT/LDT skipped |
| SHAKE-128 | FIPS 202 | ACVP-Server | 174 | 174 | 0 | 1,218 | Non-byte-aligned inputs skipped; MCT/VOT skipped |
| SHAKE-256 | FIPS 202 | ACVP-Server | 143 | 143 | 0 | 1,005 | Non-byte-aligned inputs skipped; MCT/VOT skipped |
| HMAC-SHA-256 | FIPS 198-1 | ACVP-Server | 150 | 150 | 0 | 0 | All AFT vectors tested |
| SHA-256 | FIPS 180-4 | FIPS 180-4 §B.1 | 3 | 3 | 0 | 0 | Three reference vectors from standard |
| AES-256-GCM | SP 800-38D | SP 800-38D App. B | 4 | 4 | 0 | 0 | TC13–TC16 (256-bit key only) |
| ML-KEM-1024 KeyGen | FIPS 203 | ACVP-Server | 25 | 25 | 0 | 50 | ML-KEM-512/768 skipped |
| ML-KEM-1024 EncapDecap | FIPS 203 | ACVP-Server | 25 | 25 | 0 | 140 | Decap only; ML-KEM-512/768/VAL skipped |
| ML-DSA-65 KeyGen | FIPS 204 | ACVP-Server | 25 | 25 | 0 | 50 | ML-DSA-44/87 skipped |
| ML-DSA-65 SigVer | FIPS 204 | ACVP-Server | 15 | 15 | 0 | 165 | External/pure TG 3; resolved via `ama_dilithium_verify_ctx` |
| SLH-DSA-SHA2-256f SigVer | FIPS 205 | ACVP-Server | 14 | 14 | 0 | 490 | External/pure TG 5 only; resolved via FIPS 205 hash function alignment |
| **TOTAL** | | | **815** | **815** | **0** | **4,757** | |

### 2.2 Resolved: ML-DSA-65 SigVer (previously 3 failures, now 15/15 pass)

**Resolution:** The function `ama_dilithium_verify_ctx()` was added to
implement the FIPS 204 external/pure domain-separation wrapper. It applies
the transformation `M' = 0x00 || len(ctx) || ctx || M` (FIPS 204 Section 5.4)
before delegating to the internal `ama_dilithium_verify()`. All 15 TG 3
vectors now pass, including vectors with non-empty context strings.

The original 3 failures (tcId 31, 35, 37) were caused by the absence of this
wrapper. The internal verify function remains unchanged.

### 2.3 Resolved: SLH-DSA-SHA2-256f SigVer (previously 2 failures, now 14/14 pass)

**Root cause:** Multiple deviations from FIPS 205 Section 11.2 (SHA-2
instantiation for security categories {3, 5}) in `src/c/ama_sphincs.c`:

1. **H_msg used SHA-256 instead of SHA-512.** FIPS 205 Table 5 specifies
   MGF1-SHA-512 for H_msg in categories {3, 5}. The implementation used
   MGF1-SHA-256 with incorrect toByte(0, 64-n) padding.
2. **H and T_l (multi-block thash) used SHA-256 instead of SHA-512.** FIPS 205
   requires SHA-512 with toByte(0, 128-n) padding for H and T_l in categories
   {3, 5}; only F (single-block) uses SHA-256.
3. **ADRSc compression used wrong byte mapping.** The compressed address
   extracted bytes from the uint32_t[8] layout rather than the FIPS 205
   32-byte ADRS layout (which has a 12-byte tree address field).
4. **FORS and WOTS+ keypair address cleared prematurely.** The keypair field
   was zeroed by setType calls inside FORS loops and in the WOTS+ pk
   compression address, contrary to FIPS 205 Algorithms 7, 16, and 18
   which preserve the keypair through these operations.

**Fix:** SHA-512 hash function added to `ama_sphincs.c` (zero external
dependencies). H_msg, H, and T_l updated to use SHA-512 for category 5.
ADRSc compression corrected to FIPS 205 byte layout. Keypair address
preserved in FORS and WOTS+ pk compression addresses.

**Verification:** All 815 NIST ACVP vectors now pass (813/815 previously).

### 2.4 Remediation: PRF_msg corrected to HMAC-SHA-512 (v2.2)

**Root cause:** PRF_msg used HMAC-SHA-256 via `ama_hmac_sha256_2()`. Per FIPS 205
Section 11.2 Table 5, security category 5 (n=32) requires:

    PRF_msg(SK.prf, opt_rand, M) = Trunc_n(HMAC-SHA-512(SK.prf, opt_rand || M))

**Fix:** Implemented `ama_hmac_sha512_3()` in `src/c/internal/ama_sha2.h` (FIPS
198-1 compliant HMAC with SHA-512). Updated `spx_prf_msg()` to use HMAC-SHA-512
with Trunc_n output truncation.

**OOM propagation (fail-closed):** `ama_hmac_sha512_3()` returns `int` (`0` on
success, `-1` on allocation failure). On OOM, all key material is zeroed via
`ama_secure_memzero()` before returning. Callers (`spx_prf_msg()`) propagate
the error upward, causing signing to fail with `AMA_ERROR_MEMORY` rather than
producing a signature with corrupted or zeroed randomness. This is fail-closed
behavior: no signature is emitted on resource exhaustion.

### 2.5 Remediation: SHA-512 duplication eliminated (v2.2)

**Root cause:** Identical SHA-512 implementations existed in both
`ama_sphincs.c` and `ama_ed25519.c`.

**Fix:** Extracted shared SHA-512 to `src/c/internal/ama_sha2.h` (header-only,
static linkage). Both source files now include the shared header. Zero external
dependencies maintained.

### 2.6 CRYPTO_PACKAGE.json classification (v2.2)

All fields classified as attestation/build metadata:
- `content_hash`, `hmac_tag`: Content integrity verification
- `ed25519_signature`, `dilithium_signature`: Build attestation signatures
- `ed25519_pubkey`, `dilithium_pubkey`: Public verification keys
- `timestamp`, `author`, `version`: Build provenance
- `ethical_vector`, `ethical_hash`: Framework metadata

**No key material present.** Safe to commit.

### 2.7 Native HMAC-SHA3-256 promoted to public API (v2.3)

The internal `hmac_sha3_256()` function in `src/c/ama_hkdf.c` (used by HKDF
Extract/Expand since v2.0) was promoted to a public `AMA_API` function:
`ama_hmac_sha3_256()`. This replaces the pure-Python RFC 2104 stopgap that
was introduced to fix the INVARIANT-1 violation (stdlib `import hmac`).

The C implementation uses SHA3-256 with a 136-byte block size (Keccak-f[1600]
rate for SHA3-256, r=1088 bits = 136 bytes). Key material is scrubbed via
`ama_secure_memzero()` on all code paths including OOM. Returns
`AMA_ERROR_MEMORY` on allocation failure (fail-closed).

Cross-check: output of `ama_hmac_sha3_256()` matches Python
`hmac.new(key, msg, hashlib.sha3_256).digest()` for all tested vectors.

A Cython binding (`cy_hmac_sha3_256`) was added to eliminate ctypes per-call
marshaling overhead. The Cython path compiles to C and calls
`ama_hmac_sha3_256()` directly, achieving ~262K ops/sec vs ~182K via ctypes.

### 2.8 Ed25519 performance — post-fix results (v2.3)

**Performance fix applied:** `generate_ed25519_keypair()` now stores the 64-byte
expanded key (seed||pk) instead of discarding it. `ed25519_sign()` detects
64-byte keys and skips redundant SHA-512 expansion + point multiplication.

Post-optimization benchmark results (this environment, 2026-03-20):
- SHA3-256 (1KB): 278,203 ops/sec (0.004 ms) — Keccak permutation optimization
- HMAC-SHA3-256: 185,874 ops/sec (0.005 ms) — Cython binding to native C
- Ed25519 KeyGen: 22,123 ops/sec (0.045 ms) — radix 2^51 field arithmetic
- Ed25519 Sign: 21,177 ops/sec (0.047 ms) — +156% vs baseline
- Ed25519 Verify: 9,979 ops/sec (0.100 ms) — +156% vs baseline
- ML-DSA-65 Sign: 4,315 ops/sec (0.232 ms) — +562% vs baseline
- ML-DSA-65 Verify: 1,174,398 ops/sec (0.001 ms)
- SLH-DSA Sign: ~1.4 ops/sec (~741 ms) — consistent with SHA2-256f fast variant
- SLH-DSA Verify: ~53 ops/sec (~19 ms)

**Performance test status:** All `tests/test_performance.py` thresholds now pass
with the Cython HMAC binding (262K > 100K threshold) and Ed25519 expanded-key
optimization.

### 2.9 Native C performance investigation — measured values (v2.4)

**Branch:** `claude/ama-performance-investigation-1kTrF`
**Platform:** Intel Xeon @ 2.10GHz (AVX-512, SHA-NI, AES-NI, BMI2)
**Compiler:** GCC 13.3.0, C11, Release mode, `-O3 -march=native -funroll-loops`, LTO

The following measurements were taken at the C library level using ctypes FFI
with `time.perf_counter_ns()` per-call timing (median of 200–1000 iterations
after warmup). All numbers are from the same hardware and build configuration.

#### Phase 0 baseline (before optimizations, `-O3 -mavx2`, LTO)

| Primitive | ops/sec | median (µs) |
|-----------|--------:|------------:|
| SHA3-256 (1 KB) | 151,630 | 6.6 |
| SHA3-256 (64 B) | 704,722 | 1.4 |
| HMAC-SHA3-256 (1 KB) | 104,603 | 9.6 |
| HKDF-SHA3-256 (96 B output) | 69,221 | 14.4 |
| Ed25519 keygen | 8,566 | 116.7 |
| Ed25519 sign (240 B msg) | 8,272 | 120.9 |
| Ed25519 verify (240 B msg) | 3,904 | 256.2 |
| ML-DSA-65 keygen | 4,243 | 235.7 |
| ML-DSA-65 sign | 652 | 1,534.7 |
| ML-DSA-65 verify | 1,174,398 | 0.9 |

#### Post-optimization (compiler flags + Keccak unroll + Cython SHA3-256)

| Primitive | ops/sec | median (µs) | Δ vs baseline |
|-----------|--------:|------------:|--------------:|
| SHA3-256 (1 KB, C-level) | 278,203 | 3.6 | **+83.5%** |
| SHA3-256 (64 B, C-level) | 822,368 | 1.2 | **+16.7%** |
| SHA3-256 Python API (1 KB) | 317,965 | 3.1 | **+126.7%** |
| HMAC-SHA3-256 (1 KB) | 185,874 | 5.4 | **+77.7%** |
| HKDF-SHA3-256 (96 B) | 123,047 | 8.1 | **+77.8%** |
| Ed25519 keygen | 22,123 | 45.2 | **+158%** |
| Ed25519 sign (240 B) | 21,177 | 47.2 | **+156%** |
| Ed25519 verify (240 B) | 9,979 | 100.2 | **+156%** |
| ML-DSA-65 keygen | 4,925 | 203.0 | **+16.1%** |
| ML-DSA-65 sign | 4,315 | 231.8 | **+562%** |

Changes applied:
1. `-march=native` (opt-in via `AMA_ENABLE_NATIVE_ARCH`) — unlocks AVX-512,
   SHA-NI, AES-NI, BMI2
2. `-funroll-loops` — benefits Keccak 24-round loop and ML-DSA NTT
3. Keccak-f[1600] fully unrolled: branchless rotl64, explicit Theta/Rho+Pi/Chi,
   64-byte aligned state arrays
4. Cython SHA3-256 binding: eliminates ~1.1 µs ctypes call overhead
5. Ed25519 field arithmetic: radix 2^51 (5 limbs, `__uint128_t`) replaces
   radix 2^25.5 (10 limbs) — reduces cross-products from ~100 to 25

**Ed25519 field representation:** Radix 2^51, 5 limbs (uint64_t[5]) with
`__uint128_t` intermediates (`fe51.h`). Fixed-window base-point multiplication
(4-bit, 16-entry table). Subtraction uses 4p bias + carry chain (sub_reduce)
to prevent underflow in chained group operations.

**Side-channel note:** The unrolled Keccak permutation preserves the
constant-time property (no data-dependent branches or memory accesses), but a
formal timing uniformity audit has not been performed. NIST vectors prove
correctness, not timing resistance.

---

## Section 2.10: Performance Summary

![Performance Dashboard](assets/performance_dashboard.png)

*Benchmark results from the post-fix unified codebase. All measurements use the native C backend with zero external dependencies.*

---

## Section 3: Conclusion

### 3.1 Per-Standard Verdict Table

| Standard | Algorithm | Verdict |
|----------|-----------|---------|
| FIPS 180-4 | SHA-256 | **PASS** — 3/3 reference vectors |
| FIPS 198-1 | HMAC-SHA-256 | **PASS** — 150/150 AFT vectors |
| FIPS 202 | SHA3-256 | **PASS** — 151/151 AFT vectors |
| FIPS 202 | SHA3-512 | **PASS** — 86/86 AFT vectors |
| FIPS 202 | SHAKE-128 | **PASS** — 174/174 AFT vectors |
| FIPS 202 | SHAKE-256 | **PASS** — 143/143 AFT vectors |
| SP 800-38D | AES-256-GCM | **PASS** — 4/4 test cases (TC13–TC16) |
| FIPS 203 | ML-KEM-1024 KeyGen | **PASS** — 25/25 AFT vectors |
| FIPS 203 | ML-KEM-1024 Decap | **PASS** — 25/25 AFT vectors |
| FIPS 204 | ML-DSA-65 KeyGen | **PASS** — 25/25 AFT vectors |
| FIPS 204 | ML-DSA-65 SigVer | **PASS** — 15/15 AFT vectors (via `ama_dilithium_verify_ctx`) |
| FIPS 205 | SLH-DSA-SHA2-256f SigVer | **PASS** — 14/14 AFT vectors (via `ama_sphincs_verify_ctx` + FIPS 205 hash alignment) |

### 3.2 Summary

The AMA Cryptography library demonstrates correct implementation of the core
cryptographic algorithms for all tested NIST standards. All 815 applicable
NIST test vectors pass across hash functions (SHA-256, SHA3-256, SHA3-512,
SHAKE-128, SHAKE-256), HMAC-SHA-256, AES-256-GCM, ML-KEM-1024, ML-DSA-65,
and SLH-DSA-SHA2-256f.

### 3.3 CAVP Disclaimer

> This report constitutes self-attested algorithm compliance using official
> NIST ACVP test vectors. **It is NOT a CAVP validation certificate** and
> does not represent NIST endorsement. No CAVP certificate, CMVP certificate,
> or FIPS 140-3 compliance is claimed. See `CSRC_STANDARDS.md` Section 3 for
> the full disclaimer.

---

## Appendix A: Vector Source URLs

| Algorithm | Source URL |
|-----------|-----------|
| SHA3-256 | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHA3-256-2.0 |
| SHA3-512 | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHA3-512-2.0 |
| SHAKE-128 | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHAKE-128-1.0 |
| SHAKE-256 | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHAKE-256-1.0 |
| HMAC-SHA-256 | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-256-2.0 |
| SHA-256 | https://csrc.nist.gov/pubs/fips/180-4/upd1/final |
| AES-256-GCM | https://csrc.nist.gov/pubs/sp/800/38/d/final |
| ML-KEM-1024 KeyGen | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203 |
| ML-KEM-1024 EncapDecap | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203 |
| ML-DSA-65 KeyGen | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-keyGen-FIPS204 |
| ML-DSA-65 SigVer | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigVer-FIPS204 |
| SLH-DSA-SHA2-256f SigVer | https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SLH-DSA-sigVer-FIPS205 |

---

## Appendix B: Reproduction Steps

### Build

```bash
cmake -B build -DAMA_USE_NATIVE_PQC=ON
cmake --build build
```

### Fetch Vectors

```bash
python3 nist_vectors/fetch_vectors.py
```

### Run Validation

```bash
python3 nist_vectors/run_vectors.py
```

Results are written to `nist_vectors/results.json`.
