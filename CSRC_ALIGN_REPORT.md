# CSRC Alignment Report — NIST ACVP Vector Validation

**Version:** 2.1.5
**Date:** 2026-04-20
**Organization:** Steel Security Advisors LLC
**Author:** Andrew E. A.

> **Customer-facing attestation:** this report is the technical evidence
> underlying [`docs/compliance/ACVP_SELF_ATTESTATION.md`](docs/compliance/ACVP_SELF_ATTESTATION.md)
> (human-readable) and [`docs/compliance/acvp_attestation.json`](docs/compliance/acvp_attestation.json)
> (machine-readable). Continuous validation runs in
> [`.github/workflows/acvp_validation.yml`](.github/workflows/acvp_validation.yml).

---

## Abstract

This report documents the results of running official NIST test vectors against
the AMA Cryptography library (version 2.1). The validation covers 12 algorithm
functions across 6 NIST standards (FIPS 180-4, FIPS 198-1, FIPS 202, FIPS 203,
FIPS 204, FIPS 205) and 1 NIST Special Publication (SP 800-38D).

**Summary:** 1,215 vectors tested, **1,215 passed**, **0 failed**, 5,789 skipped
(non-byte-aligned inputs, non-target parameter sets, LDT/VOT test types).
Monte Carlo Test (MCT) coverage for the SHA-3 family was added on the
v2.1.5 line in this PR (+400 vectors = 4 algorithms × 1 tcId × 100
outer iterations per FIPS-202 MCT spec, across
SHA3-256/SHA3-512/SHAKE-128/SHAKE-256) and will ship in the next
release tag.

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

**Provenance:** Each PQC primitive is **clean-room from the NIST FIPS text**.
The three `src/c/ama_{kyber,dilithium,sphincs}.c` files were written against
the FIPS 203 / 204 / 205 specifications directly, without consulting or copying
from pq-crystals, PQClean, liboqs, or any other third-party PQC source tree.
This is the opposite of the common ecosystem pattern (liboqs, AWS-LC,
BoringSSL, OpenSSL 3.5+, and CIRCL all derive from pq-crystals or PQClean and
say so explicitly), and is stated in the file-level `Provenance:` block of
each PQC source and in full in [`src/c/PROVENANCE.md`](src/c/PROVENANCE.md).
"Clean-room" here means a clean-room transcription of the standard's
pseudocode into C, not a formal proof of correctness — the ACVP vectors in
Section 2.1 are the correctness bar.

Source files:
- `src/c/ama_kyber.c` — ML-KEM-1024 (FIPS 203), clean-room from §5–§7
- `src/c/ama_dilithium.c` — ML-DSA-65 (FIPS 204), clean-room from §5–§8
- `src/c/ama_sphincs.c` — SLH-DSA-SHA2-256f (FIPS 205), clean-room from §9–§11
- `src/c/internal/ama_sha2.h` — Shared SHA-512/HMAC-SHA-512 (used by Ed25519 + SLH-DSA)
- `src/c/PROVENANCE.md` — Per-primitive derivation status, known divergences, and the clean-room attestation

Ed25519 (`src/c/ama_ed25519.c`) is **vendored** rather than clean-room: the
field arithmetic and base-point tables in `src/c/vendor/ed25519-donna/`
come from the public-domain floodyberry/ed25519-donna project with its
LICENSE preserved verbatim. The AMA wrapper above it (API contract, FROST
integration, expanded-key fast path) is in-house.

### 1.3 Test Execution Environment

| Property | Value |
|----------|-------|
| Operating system | Linux 6.18.5 (x86_64) |
| Compiler flags | CMake Release, `-DAMA_USE_NATIVE_PQC=ON`, LTO enabled, AVX2 enabled |
| Python version | 3.11.14 |
| Test harness | `nist_vectors/run_vectors.py` (ctypes FFI to `libama_cryptography.so`) |

### 1.4 Vector Selection Criteria

1. **AFT + MCT for SHA-3 family.** AFT vectors are run for every covered
   algorithm. Monte Carlo Test (MCT) vectors are run for SHA3-256, SHA3-512,
   SHAKE-128, and SHAKE-256 — the one-shot C API (`ama_sha3_256`,
   `ama_sha3_512`, `ama_shake128`, `ama_shake256`) is sufficient because the
   FIPS-202 MCT spec feeds each iteration's digest back as the next
   iteration's full input (no streaming accumulation across iterations).
   The MCT runner is implemented in `nist_vectors/run_vectors.py::_run_sha3_mct`
   and `_run_shake_mct`. **Large Data Test (LDT)** vectors remain skipped —
   they require multi-gigabyte inputs that are impractical in CI — and
   **Variable Output Test (VOT)** vectors remain skipped for SHAKE because
   their output-length coverage is subsumed by the AFT tests in the upstream
   vector files.
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
| SHA3-256 (AFT + MCT) | FIPS 202 | ACVP-Server | 251 | 251 | 0 | 1,047 | 151 AFT byte-aligned + 100 MCT (1 tcId × 100 outer iterations); 1,043 AFT non-byte-aligned skipped + 4 LDT tcIds skipped |
| SHA3-512 (AFT + MCT) | FIPS 202 | ACVP-Server | 186 | 186 | 0 | 600 | 86 AFT byte-aligned + 100 MCT (1 tcId × 100 outer iterations); 596 AFT non-byte-aligned skipped + 4 LDT tcIds skipped |
| SHAKE-128 (AFT + MCT) | FIPS 202 | ACVP-Server | 274 | 274 | 0 | 1,730 | 174 AFT byte-aligned + 100 MCT (variable-output MCT with rightmost-16-bit feedback); 1,218 AFT non-byte-aligned skipped + 512 VOT tcIds skipped |
| SHAKE-256 (AFT + MCT) | FIPS 202 | ACVP-Server | 243 | 243 | 0 | 1,517 | 143 AFT byte-aligned + 100 MCT; 1,005 AFT non-byte-aligned skipped + 512 VOT tcIds skipped |
| HMAC-SHA-256 | FIPS 198-1 | ACVP-Server | 150 | 150 | 0 | 0 | All AFT vectors tested |
| SHA-256 | FIPS 180-4 | FIPS 180-4 §B.1 | 3 | 3 | 0 | 0 | Three reference vectors from standard |
| AES-256-GCM | SP 800-38D | SP 800-38D App. B | 4 | 4 | 0 | 0 | TC13–TC16 (256-bit key only) |
| ML-KEM-1024 KeyGen | FIPS 203 | ACVP-Server | 25 | 25 | 0 | 50 | ML-KEM-512/768 skipped |
| ML-KEM-1024 EncapDecap | FIPS 203 | ACVP-Server | 25 | 25 | 0 | 140 | Decap only; ML-KEM-512/768/VAL skipped |
| ML-DSA-65 KeyGen | FIPS 204 | ACVP-Server | 25 | 25 | 0 | 50 | ML-DSA-44/87 skipped |
| ML-DSA-65 SigVer | FIPS 204 | ACVP-Server | 15 | 15 | 0 | 165 | External/pure TG 3; resolved via `ama_dilithium_verify_ctx` |
| SLH-DSA-SHA2-256f SigVer | FIPS 205 | ACVP-Server | 14 | 14 | 0 | 490 | External/pure TG 5 only; resolved via FIPS 205 hash function alignment |
| **TOTAL** | | | **1,215** | **1,215** | **0** | **5,789** | 4,757 AFT-filtered + 1,032 non-AFT (LDT+VOT) |

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

**Fail-closed error paths:** `ama_hmac_sha512_3()` returns `int` (`0` on
success, `-1` on `calloc` allocation failure, `-2` on `size_t` overflow
guard against oversized `part1||part2||part3` concatenation — see
`src/c/internal/ama_sha2.h:199–212`). On either failure path, `k_pad` and
the derived key hash are zeroed via `ama_secure_memzero()` before
returning.

Public-API callers map the raw return to a typed error:

- `ama_hkdf.c:54–57` — `ama_hmac_sha512()` maps `-2 → AMA_ERROR_OVERFLOW`
  and any other non-zero → `AMA_ERROR_MEMORY`.
- `ama_sphincs.c:1065–1067` — `spx_prf_msg()` propagates any non-zero
  return as `AMA_ERROR_MEMORY`, causing signing to fail rather than
  producing a signature with corrupted or zeroed randomness.

This is fail-closed behavior: no signature is emitted on resource
exhaustion or pathological input sizes.

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

Post-fix benchmark results (2026-03-21, native C backend, 4-core Linux):
- HMAC-SHA3-256: 206,010 ops/sec (0.005 ms) — native C via ctypes
- Ed25519 KeyGen: 19,388 ops/sec (0.052 ms) — radix 2^51 field arithmetic
- Ed25519 Sign: 18,657 ops/sec (0.054 ms) — expanded-key fast path
- Ed25519 Verify: 9,702 ops/sec (0.103 ms)
- ML-DSA-65 KeyGen: 5,536 ops/sec (0.181 ms)
- ML-DSA-65 Sign: 3,639 ops/sec (0.275 ms)
- ML-DSA-65 Verify: 6,490 ops/sec (0.154 ms)
- SLH-DSA Sign: ~1.4 ops/sec (~741 ms) — consistent with SHA2-256f fast variant
- SLH-DSA Verify: ~53 ops/sec (~19 ms)

**Performance test status:** All `tests/test_performance.py` thresholds now pass
with the Cython HMAC binding (262K > 100K threshold) and Ed25519 expanded-key
optimization.

---

## Section 2.9: Performance Summary

![Performance Dashboard](assets/performance_dashboard.png)

*Benchmark results from the post-fix unified codebase. All measurements use the native C backend with zero external dependencies.*

---

## Section 3: Conclusion

### 3.1 Per-Standard Verdict Table

| Standard | Algorithm | Verdict |
|----------|-----------|---------|
| FIPS 180-4 | SHA-256 | **PASS** — 3/3 reference vectors |
| FIPS 198-1 | HMAC-SHA-256 | **PASS** — 150/150 AFT vectors |
| FIPS 202 | SHA3-256 | **PASS** — 251/251 (151 AFT + 100 MCT) |
| FIPS 202 | SHA3-512 | **PASS** — 186/186 (86 AFT + 100 MCT) |
| FIPS 202 | SHAKE-128 | **PASS** — 274/274 (174 AFT + 100 MCT) |
| FIPS 202 | SHAKE-256 | **PASS** — 243/243 (143 AFT + 100 MCT) |
| SP 800-38D | AES-256-GCM | **PASS** — 4/4 test cases (TC13–TC16) |
| FIPS 203 | ML-KEM-1024 KeyGen | **PASS** — 25/25 AFT vectors |
| FIPS 203 | ML-KEM-1024 Decap | **PASS** — 25/25 AFT vectors |
| FIPS 204 | ML-DSA-65 KeyGen | **PASS** — 25/25 AFT vectors |
| FIPS 204 | ML-DSA-65 SigVer | **PASS** — 15/15 AFT vectors (via `ama_dilithium_verify_ctx`) |
| FIPS 205 | SLH-DSA-SHA2-256f SigVer | **PASS** — 14/14 AFT vectors (via `ama_sphincs_verify_ctx` + FIPS 205 hash alignment) |

### 3.2 Summary

The AMA Cryptography library demonstrates correct implementation of the core
cryptographic algorithms for all tested NIST standards. All 1,215 applicable
NIST test vectors pass across hash functions (SHA-256, SHA3-256, SHA3-512,
SHAKE-128, SHAKE-256) — including the 400 newly-added FIPS-202 Monte Carlo
Test vectors for the SHA-3 family — HMAC-SHA-256, AES-256-GCM, ML-KEM-1024,
ML-DSA-65, and SLH-DSA-SHA2-256f.

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

---

## Section 4 — Design Alignment with FIPS 140-3 Level 1 Requirements (Pending Future CMVP Validation)

> **Important:** The controls in this section represent design alignment with FIPS 140-3 Security Level 1 technical requirements. This implementation has **NOT** been submitted for CMVP validation and is **NOT** FIPS 140-3 certified. These controls are implemented as a step toward future formal validation.

**Date:** 2026-04-20
**Implementation:** `ama_cryptography/_self_test.py`, `ama_cryptography/integrity.py`

### 4.1 Power-On Self-Tests (POST)

The module runs Known Answer Tests at import time (`_run_self_tests()` called
from `ama_cryptography/__init__.py`). The following KATs execute on every module
load:

| Algorithm | KAT Type | Vector Source |
|-----------|----------|---------------|
| SHA3-256 | Fixed hash of empty string | FIPS 202 reference |
| HMAC-SHA3-256 | Determinism + output length | RFC 2104 with SHA3-256 |
| AES-256-GCM | Encrypt/decrypt roundtrip | Fixed key/nonce/plaintext |
| ML-KEM-1024 | Keygen + encaps + decaps roundtrip | Runtime generated |
| ML-DSA-65 | Keygen + sign + verify roundtrip + negative test | Runtime generated |
| SLH-DSA (SPHINCS+) | Keygen + sign + verify roundtrip | Runtime generated |
| Ed25519 | Keygen + sign + verify roundtrip | Runtime generated |
| RNG | Two consecutive `secrets.token_bytes(32)` non-equality | Runtime |

**POST Budget:** All self-tests complete in <300ms (measured ~260ms on
4-core Linux), well within the 500ms budget.

### 4.2 Module Integrity Verification

At startup, SHA3-256 is computed over all `.py` files in the
`ama_cryptography/` package directory. The digest is compared against a
stored known-good value in `ama_cryptography/_integrity_digest.txt`.

To regenerate after legitimate code changes:

```bash
python -m ama_cryptography.integrity --update
```

To verify:

```bash
python -m ama_cryptography.integrity --verify
```

### 4.3 Error State Machine

The module maintains one of three states:

| State | Meaning | Crypto Operations |
|-------|---------|-------------------|
| `SELF_TEST` | POST in progress | Blocked |
| `OPERATIONAL` | All tests passed | Allowed |
| `ERROR` | A test or check failed | Blocked — raises `CryptoModuleError` |

Query state: `ama_cryptography.module_status()` → `"OPERATIONAL"` | `"ERROR"` | `"SELF_TEST"`

Recovery: `ama_cryptography.reset_module()` re-runs all self-tests.

### 4.4 Pairwise Consistency Tests

The library provides helper functions (`pairwise_test_signature()`,
`pairwise_test_kem()`) that perform a sign-verify or encaps-decaps
roundtrip on a fixed test message. Callers (e.g. key-generation wrappers)
are responsible for invoking these helpers after generating a keypair.
On failure, the module enters ERROR state and the caller should discard
the keypair. Covered algorithms:

- Ed25519: sign + verify
- ML-DSA-65: sign + verify
- ML-KEM-1024: encaps + decaps

These helpers do **not** automatically intercept every key generation;
they must be called explicitly by application code or wrapper functions.

### 4.5 Continuous RNG Test

`secure_token_bytes(n)` wraps `secrets.token_bytes(n)` with a comparison
to the previous output. If two consecutive calls return identical bytes,
the module enters ERROR state immediately. This is aligned with the
continuous random number generator testing described in FIPS 140-3
Section 4.9.2.

> **Note:** This is a design-aligned implementation, not a CMVP-validated module. See Section 3 of `CSRC_STANDARDS.md` for full compliance status.
