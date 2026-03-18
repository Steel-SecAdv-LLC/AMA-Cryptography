# CSRC Alignment Report — NIST ACVP Vector Validation

**Version:** 2.0
**Date:** 2026-03-18
**Organization:** Steel Security Advisors LLC
**Author:** Andrew E. A.

---

## Abstract

This report documents the results of running official NIST test vectors against
the AMA Cryptography library (version 2.0). The validation covers 12 algorithm
functions across 6 NIST standards (FIPS 180-4, FIPS 198-1, FIPS 202, FIPS 203,
FIPS 204, FIPS 205) and 1 NIST Special Publication (SP 800-38D).

**Summary:** 815 vectors tested, **810 passed**, **5 failed**, 4,757 skipped
(non-byte-aligned inputs, non-target parameter sets, MCT/LDT/VOT test types).

All 5 failures occur in signature verification (ML-DSA-65 SigVer: 3 failures;
SLH-DSA-SHA2-256f SigVer: 2 failures) and are attributed to the absence of the
FIPS 204/205 external/pure domain-separation wrapper in the library's verify
functions. All hash, KDF, AEAD, KEM, and key generation functions pass 100% of
applicable vectors.

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
| ML-DSA-65 SigVer | FIPS 204 | ACVP-Server | 15 | 12 | **3** | 165 | External/pure TG 3 only; see §2.2 |
| SLH-DSA-SHA2-256f SigVer | FIPS 205 | ACVP-Server | 14 | 12 | **2** | 490 | External/pure TG 5 only; see §2.3 |
| **TOTAL** | | | **815** | **810** | **5** | **4,757** | |

### 2.2 Deviation: ML-DSA-65 SigVer (3 failures)

**Root cause:** The AMA `ama_dilithium_verify()` function implements the
**internal** ML-DSA verification interface. It verifies signatures over raw
messages without applying the FIPS 204 external/pure domain-separation wrapper.

FIPS 204 Section 5.4 specifies that for the external/pure signature interface,
the message is pre-processed as:

```
M' = IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx || M
```

where `ctx` is the optional context string. The AMA verify function passes the
message directly to the internal verification algorithm without this
transformation.

**Failed vectors:**

| tcId | Expected | Actual | Context Length |
|------|----------|--------|----------------|
| 31 | testPassed=True | testPassed=False (rc=-4) | 183 bytes |
| 35 | testPassed=True | testPassed=False (rc=-4) | 0 bytes |
| 37 | testPassed=True | testPassed=False (rc=-4) | 133 bytes |

All 3 failures are `testPassed=True` vectors (valid signatures) that the
library rejected. This is consistent with the domain-separation hypothesis:
the signature was generated over the wrapped message `M'`, but the library
verifies against the raw message `M`.

Note: tcId 35 has a zero-length context but still fails, confirming that
even with empty context the `0x00 || 0x00` prefix is part of the signed
message in the external/pure interface.

**Recommendation:** Add an external/pure wrapper API (e.g.,
`ama_dilithium_verify_external()`) that applies the FIPS 204 §5.4
domain-separation transformation before calling the internal verify. This
does not require changes to the core ML-DSA implementation.

### 2.3 Deviation: SLH-DSA-SHA2-256f SigVer (2 failures)

**Root cause:** Analogous to the ML-DSA issue. The AMA `ama_sphincs_verify()`
function implements the internal SLH-DSA verification interface without the
FIPS 205 external/pure domain-separation wrapper.

FIPS 205 Section 10.3 specifies that for the external/pure signature interface,
the message is pre-processed as:

```
M' = IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx || M
```

**Failed vectors:**

| tcId | Expected | Actual | Context Length |
|------|----------|--------|----------------|
| 64 | testPassed=True | testPassed=False (rc=-4) | 103 bytes |
| 70 | testPassed=True | testPassed=False (rc=-4) | 251 bytes |

Both failures are `testPassed=True` vectors that the library rejected.
All `testPassed=False` vectors (invalid signatures) were correctly rejected.

**Recommendation:** Add an external/pure wrapper API (e.g.,
`ama_sphincs_verify_external()`) that applies the FIPS 205 §10.3
domain-separation transformation before calling the internal verify.

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
| FIPS 204 | ML-DSA-65 SigVer | **PARTIAL** — 12/15 (3 failures: missing external/pure wrapper) |
| FIPS 205 | SLH-DSA-SHA2-256f SigVer | **PARTIAL** — 12/14 (2 failures: missing external/pure wrapper) |

### 3.2 Summary

The AMA Cryptography library demonstrates correct implementation of the core
cryptographic algorithms for all tested NIST standards. Hash functions
(SHA-256, SHA3-256, SHA3-512, SHAKE-128, SHAKE-256), HMAC-SHA-256,
AES-256-GCM, ML-KEM-1024 (key generation and decapsulation), and ML-DSA-65
(key generation) all pass 100% of applicable NIST test vectors.

The 5 signature verification failures in ML-DSA-65 and SLH-DSA-SHA2-256f are
caused by a known architectural gap: the library exposes only the **internal**
verification interface and does not implement the FIPS 204/205 external/pure
domain-separation wrapper (`M' = 0x00 || len(ctx) || ctx || M`). This is a
well-defined, fixable gap that does not indicate any deficiency in the core
signature verification algorithm itself.

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
