# NIST ACVP Self-Attestation

| Field | Value |
|---|---|
| Organization | Steel Security Advisors LLC |
| Library | AMA Cryptography |
| Document ID | ACVP-SELF-ATTEST-2026-001 |
| Version | 2.1.5 |
| Date | 2026-04-21 |
| Classification | Public |
| Attestation Type | **Self-Attestation (NOT CAVP, NOT CMVP, NOT FIPS 140-3)** |
| Source Report | [`CSRC_ALIGN_REPORT.md`](../../CSRC_ALIGN_REPORT.md) |
| Machine-readable | [`acvp_attestation.json`](acvp_attestation.json) |

---

## 1. Scope Statement

This document formally attests to the results of running official NIST ACVP
test vectors against the AMA Cryptography library. It restructures the
evidence in [`CSRC_ALIGN_REPORT.md`](../../CSRC_ALIGN_REPORT.md) into a
customer-facing format.

### 1.1 What IS Covered

- **Algorithm correctness** against NIST ACVP Algorithm Functional Test (AFT)
  vectors for **12 algorithm functions** across **7 NIST standards**
  (FIPS 180-4, FIPS 198-1, FIPS 202, FIPS 203, FIPS 204, FIPS 205, SP 800-38D).
- **Deterministic, reproducible** pass/fail results against upstream
  `usnistgov/ACVP-Server` vector projections, plus published FIPS/SP
  reference vectors for SHA-256 and AES-256-GCM.
- **Native C implementation** of post-quantum algorithms (no external PQC
  libraries — no liboqs, no PQClean).

### 1.2 What is NOT Covered

This attestation **does not** represent, claim, or imply any of the following:

- NIST Cryptographic Algorithm Validation Program (CAVP) validation or
  CAVP certificate.
- NIST Cryptographic Module Validation Program (CMVP) certification.
- FIPS 140-3 compliance, validation, or accreditation at any security level.
- Side-channel resistance guarantees (timing, power, EM, cache).
- Implementation correctness beyond the specific AFT test vectors listed in
  §3. Monte Carlo Test (MCT), Large Data Test (LDT), Variable Output Test
  (VOT), non-byte-aligned inputs, and non-target parameter sets are out of
  scope (see §4).
- A substitute for an independent third-party cryptographic audit.
- NIST endorsement of any kind.

---

## 2. Test Environment

From [`CSRC_ALIGN_REPORT.md` §1.3](../../CSRC_ALIGN_REPORT.md):

| Property | Value |
|---|---|
| Operating system | Linux 6.18.5 (x86_64) |
| Build system | CMake Release configuration |
| Compiler flags | `-DAMA_USE_NATIVE_PQC=ON`, LTO enabled, AVX2 enabled |
| Python version | 3.11.14 |
| Test harness | `nist_vectors/run_vectors.py` (ctypes FFI to `libama_cryptography.so`) |
| PQC backend | Native C — no liboqs, no PQClean, no third-party PQC dependency |

Source files for post-quantum algorithms:

- `src/c/ama_kyber.c` — ML-KEM-1024 (FIPS 203)
- `src/c/ama_dilithium.c` — ML-DSA-65 (FIPS 204)
- `src/c/ama_sphincs.c` — SLH-DSA-SHA2-256f (FIPS 205)
- `src/c/internal/ama_sha2.h` — Shared SHA-512 / HMAC-SHA-512 internals

---

## 3. Algorithm Coverage

All results taken from [`CSRC_ALIGN_REPORT.md` §2.1](../../CSRC_ALIGN_REPORT.md).
Vector counts are also independently anchored in
[`docs/METRICS_REPORT.md` §"NIST ACVP Vector Counts"](../METRICS_REPORT.md)
with reproduction commands.

| Algorithm | NIST Standard | FIPS/SP Reference | Parameter Set | Vectors Tested | Vectors Passed | Pass Rate |
|---|---|---|---|---:|---:|---:|
| SHA-256 | FIPS 180-4 | FIPS 180-4 §B.1 | 256-bit | 3 | 3 | 100% |
| HMAC-SHA-256 | FIPS 198-1 | ACVP HMAC-SHA2-256-2.0 | 256-bit | 150 | 150 | 100% |
| SHA3-256 | FIPS 202 | ACVP SHA3-256-2.0 | 256-bit | 151 | 151 | 100% |
| SHA3-512 | FIPS 202 | ACVP SHA3-512-2.0 | 512-bit | 86 | 86 | 100% |
| SHAKE-128 | FIPS 202 | ACVP SHAKE-128-1.0 | XOF, rate=1344 | 174 | 174 | 100% |
| SHAKE-256 | FIPS 202 | ACVP SHAKE-256-1.0 | XOF, rate=1088 | 143 | 143 | 100% |
| AES-256-GCM | SP 800-38D | SP 800-38D App. B (TC13–TC16) | 256-bit key | 4 | 4 | 100% |
| ML-KEM KeyGen | FIPS 203 | ACVP ML-KEM-keyGen-FIPS203 | ML-KEM-1024 | 25 | 25 | 100% |
| ML-KEM EncapDecap | FIPS 203 | ACVP ML-KEM-encapDecap-FIPS203 | ML-KEM-1024 (decap only) | 25 | 25 | 100% |
| ML-DSA KeyGen | FIPS 204 | ACVP ML-DSA-keyGen-FIPS204 | ML-DSA-65 | 25 | 25 | 100% |
| ML-DSA SigVer | FIPS 204 | ACVP ML-DSA-sigVer-FIPS204 | ML-DSA-65 (external/pure, TG 3) | 15 | 15 | 100% |
| SLH-DSA SigVer | FIPS 205 | ACVP SLH-DSA-sigVer-FIPS205 | SLH-DSA-SHA2-256f (external/pure, TG 5) | 14 | 14 | 100% |
| **TOTAL** | | | | **815** | **815** | **100%** |

4,757 vectors were skipped (MCT, LDT, VOT, non-byte-aligned, non-target
parameter sets). Skip rationale is documented in §4.

---

## 4. Vector Selection Criteria

From [`CSRC_ALIGN_REPORT.md` §1.4](../../CSRC_ALIGN_REPORT.md):

1. **AFT only.** Monte Carlo Test (MCT), Large Data Test (LDT), and Variable
   Output Test (VOT) vectors are skipped. MCT requires iterative state not
   supported by the one-shot harness; LDT requires multi-gigabyte inputs.
2. **Byte-aligned only.** Vectors with `bitLength % 8 != 0` are skipped —
   the AMA C API is byte-granularity only.
3. **ML-KEM-1024 only.** ML-KEM-512 and ML-KEM-768 parameter sets are not
   implemented.
4. **ML-KEM EncapDecap: decapsulation only.** The library does not expose the
   randomness parameter `m` required for deterministic encapsulation under AFT.
5. **ML-DSA-65 SigVer: external/pure (TG 3) only.** Internal and pre-hash
   test groups are skipped.
6. **SLH-DSA-SHA2-256f SigVer: external/pure (TG 5) only.** Other parameter
   sets and test groups are skipped.

---

## 5. Reproduction Instructions

From [`CSRC_ALIGN_REPORT.md` Appendix B](../../CSRC_ALIGN_REPORT.md).

### 5.1 Build

```bash
cmake -B build -DAMA_USE_NATIVE_PQC=ON
cmake --build build
```

### 5.2 Fetch ACVP Vectors

```bash
python3 nist_vectors/fetch_vectors.py
```

This pulls `internalProjection.json` files from the upstream
`usnistgov/ACVP-Server` repository. SHA-256 and AES-256-GCM vectors are
hardcoded from their respective FIPS/SP publications.

### 5.3 Run Validation

```bash
python3 nist_vectors/run_vectors.py
```

Results are written to `nist_vectors/results.json`. The harness exits non-zero
if any vector fails.

### 5.4 Continuous Validation

Continuous validation runs on every push to `main` and on a weekly schedule
via [`.github/workflows/acvp_validation.yml`](../../.github/workflows/acvp_validation.yml).
The workflow parses `results.json` and enforces three conditions:

1. **Floor:** `total_tested >= EXPECTED_VECTORS` (currently 815). Coverage
   can expand above this floor; it cannot drop below it.
2. **Zero failures:** `total_failed == 0`, and no algorithm may report a
   non-zero `fail_count` or a `vectors_tested == 0`.
3. **Attestation cross-check:** `docs/compliance/acvp_attestation.json`
   totals and per-algorithm `vectors_tested`/`vectors_passed` must match
   `nist_vectors/results.json` exactly. Expanding coverage therefore
   requires updating the attestation JSON and the `EXPECTED_VECTORS`
   floor in the same commit — the published attestation and the CI
   measurement move together.

A `nist_vectors/validation_summary.json` artifact is published on every
run with timestamp, git SHA, `acvp_ref`, per-algorithm counts, and split
skip accounting (`total_skipped_non_mct` vs `total_mct_skipped`).

---

## 6. Remediation History

The following issues were identified during validation and have been
resolved. All 815/815 vectors pass after remediation.

### 6.1 ML-DSA-65 SigVer — external/pure wrapper (now 15/15)

From [§2.2 of the source report](../../CSRC_ALIGN_REPORT.md). Added
`ama_dilithium_verify_ctx()` implementing the FIPS 204 §5.4
external/pure domain-separation transform
`M' = 0x00 || len(ctx) || ctx || M` before delegating to the internal
verify. Previously failed tcId 31, 35, 37 (non-empty context strings);
now all 15 TG 3 vectors pass.

### 6.2 SLH-DSA-SHA2-256f — FIPS 205 hash alignment (now 14/14)

From [§2.3 of the source report](../../CSRC_ALIGN_REPORT.md). Four
deviations from FIPS 205 §11.2 were corrected in `src/c/ama_sphincs.c`:

- `H_msg`, `H`, and `T_l` now use SHA-512 with `toByte(0, 128-n)` padding
  for security category 5 (previously SHA-256).
- ADRSc compression fixed to use the FIPS 205 32-byte ADRS byte layout
  (12-byte tree-address field) instead of the internal `uint32_t[8]` layout.
- Keypair address preserved through FORS and WOTS+ pk-compression
  operations (was prematurely zeroed by `setType` calls).

### 6.3 PRF_msg corrected to HMAC-SHA-512

From [§2.4 of the source report](../../CSRC_ALIGN_REPORT.md). FIPS 205
§11.2 Table 5 requires HMAC-SHA-512 for PRF_msg in category 5, truncated
to `n` bytes. Implemented `ama_hmac_sha512_3()` (FIPS 198-1 compliant)
in `src/c/internal/ama_sha2.h` (static-linkage helper) with two
fail-closed early-return paths: `-2` on `size_t` overflow of the input
lengths (guard at `ama_sha2.h:199–205`) and `-1` on `calloc` allocation
failure (`ama_sha2.h:207–212`). Both paths zero `k_pad` and the
derived key hash via `ama_secure_memzero()` before returning.
Public-API callers map the raw return:

- `ama_hkdf.c:54–57` — `ama_hmac_sha512()` maps `-2 → AMA_ERROR_OVERFLOW`
  and any other non-zero → `AMA_ERROR_MEMORY`.
- `ama_sphincs.c:1065–1067` — `spx_prf_msg()` wraps
  `ama_hmac_sha512_3()` and propagates any non-zero return as
  `AMA_ERROR_MEMORY` upward, so signing fails fail-closed rather than
  emitting a signature with zeroed or corrupted randomness.

### 6.4 SHA-512 duplication eliminated

From [§2.5 of the source report](../../CSRC_ALIGN_REPORT.md). The two
identical SHA-512 copies in `ama_sphincs.c` and `ama_ed25519.c` were
extracted to the header-only `src/c/internal/ama_sha2.h` with static
linkage. Zero external dependencies maintained.

### 6.5 Native HMAC-SHA3-256 promoted to public API

From [§2.7 of the source report](../../CSRC_ALIGN_REPORT.md). The
internal `hmac_sha3_256()` in `src/c/ama_hkdf.c` was promoted to
`ama_hmac_sha3_256()` with `AMA_API` export, replacing the pure-Python
RFC 2104 stopgap introduced to resolve an `import hmac` INVARIANT-1
violation. Key material is scrubbed via `ama_secure_memzero()` on all
paths including OOM.

---

## 7. Disclaimers

> ### **⚠ This document is a self-attestation. It is NOT a CAVP certificate.**
>
> ### **⚠ This document does NOT represent NIST endorsement.**
>
> ### **⚠ This document is NOT a substitute for an independent cryptographic audit.**

Per [`CSRC_ALIGN_REPORT.md` lines 22–24](../../CSRC_ALIGN_REPORT.md)
and [§3.3](../../CSRC_ALIGN_REPORT.md):

> This report constitutes self-attested algorithm compliance using official
> NIST ACVP test vectors. **It is NOT a CAVP validation certificate** and
> does not represent NIST endorsement. No CAVP certificate, CMVP certificate,
> or FIPS 140-3 compliance is claimed. See `CSRC_STANDARDS.md` Section 3 for
> the full disclaimer.

**Self-attestation means:** Steel Security Advisors LLC has run the official
NIST ACVP test vectors against its own implementation and is reporting the
results. No independent laboratory has reviewed, witnessed, or validated
these results. No NIST program has reviewed this library. No government
authority has issued any certificate relating to this library.

**Customers deploying this library in regulated environments** (FedRAMP,
DoD, HIPAA-adjacent, FIPS-mandated contexts) should not rely on this
document alone and must obtain a formal CAVP/CMVP validation through an
accredited Cryptographic and Security Testing (CST) Laboratory.

---

## 8. Attestation Signature

| Field | Value |
|---|---|
| Organization | Steel Security Advisors LLC |
| Authorized Signer | _________________________ |
| Title | _________________________ |
| Date | _________________________ |
| Signature | _________________________ |

---

*This document is generated from the evidence in
[`CSRC_ALIGN_REPORT.md`](../../CSRC_ALIGN_REPORT.md) and verified by the
continuous validation workflow at
[`.github/workflows/acvp_validation.yml`](../../.github/workflows/acvp_validation.yml).
The machine-readable counterpart is
[`acvp_attestation.json`](acvp_attestation.json).*
