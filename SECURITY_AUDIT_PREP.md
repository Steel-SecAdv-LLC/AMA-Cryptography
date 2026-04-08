# AMA Cryptography: Security Audit Preparation

**Copyright (C) 2025-2026 Steel Security Advisors LLC**
**Version:** 2.1.2
**Date:** 2026-04-08
**Classification:** Public — Intended for Independent Security Auditors

---

## 1. Threat Model Summary

Full threat model: [THREAT_MODEL.md](THREAT_MODEL.md)

AMA Cryptography uses a 4-layer defense-in-depth architecture with NIST-approved algorithms:

| Layer | Function | Algorithm | Standard |
|-------|----------|-----------|----------|
| 1 | Content Integrity | SHA3-256 | NIST FIPS 202 |
| 2 | Keyed Authentication | HMAC-SHA3-256 | RFC 2104 |
| 3 | Digital Signature | Ed25519 + ML-DSA-65 | RFC 8032 + NIST FIPS 204 |
| 4 | Key Independence | HKDF-SHA3-256 | RFC 5869 |

Optional add-ons: AES-256-GCM (SP 800-38D), ML-KEM-1024 (FIPS 203), SPHINCS+-256f (FIPS 205), RFC 3161 timestamps.

**Threat Catalog:** 22 threats across 4 categories (T1: Cryptographic, T2: Implementation, T3: Operational, T4: Supply Chain). All mitigations implemented. Two HIGH-risk residual items: table-based AES S-box cache timing (T2.1) and key compromise without HSM (T3.1).

---

## 2. Cryptographic Algorithm Inventory

| Algorithm | Standard | Key/Sig Sizes | Security Level | Implementation |
|-----------|----------|---------------|----------------|----------------|
| SHA3-256 | FIPS 202 | 256-bit digest | 128-bit collision | `src/c/ama_sha3.c` |
| HMAC-SHA3-256 | RFC 2104 | 256-bit key | 128-bit forgery | `src/c/ama_sha3.c` (via HMAC construction) |
| Ed25519 | RFC 8032 | 32B pub / 64B sec / 64B sig | 128-bit classical | `src/c/ama_ed25519.c` |
| ML-DSA-65 | FIPS 204 | 1952B pub / 4032B sec / 3309B sig | 192-bit quantum | `src/c/ama_dilithium.c` |
| ML-KEM-1024 | FIPS 203 | 1568B pub / 3168B sec / 1568B ct | 256-bit classical | `src/c/ama_kyber.c` |
| SPHINCS+-SHA2-256f | FIPS 205 | 64B pub / 128B sec / 49856B sig | 256-bit classical | `src/c/ama_sphincs.c` |
| AES-256-GCM | SP 800-38D | 256-bit key / 96-bit IV / 128-bit tag | 128-bit quantum | `src/c/ama_aes_gcm.c` |
| ChaCha20-Poly1305 | RFC 8439 | 256-bit key / 96-bit nonce | 128-bit quantum | `src/c/ama_chacha20poly1305.c` |
| X25519 | RFC 7748 | 32B pub / 32B sec | 128-bit classical | `src/c/ama_x25519.c` |
| Argon2id | RFC 9106 | Variable | Memory-hard | `src/c/ama_argon2.c` |
| HKDF-SHA3-256 | RFC 5869 | Variable | 128-bit | `src/c/ama_hkdf.c` |
| secp256k1 | SEC 2 | 33B pub / 32B sec | 128-bit classical | `src/c/ama_secp256k1.c` |

**Zero-dependency architecture:** All algorithms implemented in native C (INVARIANT-1). No external crypto libraries (OpenSSL, libsodium, liboqs) are linked.

---

## 3. Constant-Time Verification Status

Full methodology: [CONSTANT_TIME_VERIFICATION.md](CONSTANT_TIME_VERIFICATION.md)

### Verified Constant-Time Functions (dudect, |t| < 4.5)

| Function | Purpose | Source | dudect |
|----------|---------|--------|--------|
| `ama_consttime_memcmp()` | Byte comparison | `ama_consttime.c` | PASS |
| `ama_secure_memzero()` | Secure zeroing | `ama_consttime.c` | PASS |
| `ama_consttime_swap()` | Conditional swap | `ama_consttime.c` | PASS |
| `ama_consttime_lookup()` | Table lookup | `ama_consttime.c` | PASS |
| `ama_consttime_copy()` | Conditional copy | `ama_consttime.c` | PASS |

### Upstream Constant-Time Guarantees

| Component | Status | Notes |
|-----------|--------|-------|
| Ed25519 sign | Constant-time | Montgomery ladder scalar multiplication |
| Ed25519 verify | Vartime (by design) | Verification scalar is public |
| ML-DSA-65/Kyber NTT | Constant-time | Polynomial arithmetic, no secret-dependent branches |
| SPHINCS+ | Constant-time | Hash-based, inherently constant-time |

### Known Side-Channel Caveats

| Component | Risk | Mitigation |
|-----------|------|------------|
| AES-256-GCM S-box (default) | Cache timing in shared environments | Build with `-DAMA_AES_CONSTTIME=ON` for bitsliced S-box, or use AES-NI hardware |
| AES-NI availability | Falls back to table-based on non-x86 | Runtime detection via `ama_cpuid.c`; ChaCha20-Poly1305 as constant-time alternative |
| Compiler optimization | May optimize away `memzero` | Mitigated with `volatile` pointer + compiler barrier |

---

## 4. Known Limitations and Attack Surface

### Critical Audit Points

1. **No FIPS 140-3 certification.** This implementation has NOT been submitted for CMVP validation.
2. **No third-party security audit.** All analysis is self-assessed.
3. **AES S-box cache timing** in default build (T2.1). Bitsliced alternative available.
4. **Ed25519 quantum vulnerability** mitigated by ML-DSA-65 hybrid layer.
5. **PQC algorithm maturity.** ML-DSA-65 and ML-KEM-1024 are NIST-standardized but have limited deployment history.

### Attack Surface Map

| Entry Point | Trust Boundary | Validation |
|-------------|---------------|------------|
| `create_crypto_package(content)` | User input → crypto | Type check, emptiness check |
| `verify_crypto_package(content, pkg)` | User input → crypto | Type check, signature length check |
| All C functions via ctypes | Python → C FFI | INVARIANT-5: input validation before dispatch |
| Cython bindings | Python → Cython → C | INVARIANT-5: validation before Cython dispatch |
| Key material (HKDF, HMAC keys) | Generated internally | 256-bit from OS CSPRNG |
| Nonces (AES-GCM) | Generated internally | 96-bit from OS CSPRNG |

---

## 5. Side-Channel Mitigations Per Algorithm

| Algorithm | Timing | Cache | Power/EM | Mitigations |
|-----------|--------|-------|----------|-------------|
| SHA3-256 | Safe | Safe | N/A (public data) | Keccak-f[1600] has no secret-dependent branches |
| Ed25519 sign | CT | CT | Partial | Montgomery ladder; constant-time field arithmetic |
| Ed25519 verify | Vartime | Vartime | N/A | Public scalar — timing is not secret |
| ML-DSA-65 | CT | CT | Partial | Constant-time NTT/polynomial operations |
| ML-KEM-1024 | CT | CT | Partial | Constant-time NTT; implicit rejection |
| AES-256-GCM | **Vartime** | **Cache risk** | Partial | AES-NI eliminates; `-DAMA_AES_CONSTTIME=ON` for software |
| ChaCha20-Poly1305 | CT | CT | Partial | ARX construction; inherently constant-time |
| HKDF | CT | CT | N/A | Based on SHA3 (constant-time) |

CT = Constant-time implementation verified. Vartime = Variable-time (documented, acceptable for the use case).

---

## 6. INVARIANT Compliance Matrix

Full invariant definitions: [INVARIANTS.md](INVARIANTS.md)

| ID | Invariant | Status | Verification |
|----|-----------|--------|-------------|
| INVARIANT-1 | Zero external crypto dependencies | **COMPLIANT** | All primitives in `src/c/`; no libsodium/OpenSSL/liboqs |
| INVARIANT-2 | Thread-safe CPU dispatch via platform once-primitive | **COMPLIANT** | `pthread_once` (POSIX) / `InitOnceExecuteOnce` (Win) |
| INVARIANT-5 | Input validation before Cython/C dispatch | **COMPLIANT** | Enforced in `pqc_backends.py` before all native calls |
| INVARIANT-7 | Native C backend required for crypto operations | **COMPLIANT** | `_INVARIANT7_OK` flag checked per-call |
| INVARIANT-13 | Cython type:ignore comments require tracking IDs | **COMPLIANT** | PQC-005/006/007 tracking IDs on all Cython suppressions |

---

## 7. Test Infrastructure Summary

| Category | Count | Details |
|----------|-------|---------|
| Python unit tests | 1,884 | `pytest tests/ -v` |
| C unit tests | 8 | `ctest --test-dir build` |
| KAT vector test suites | 10 | FIPS 202/203/204/205, SP 800-38D, RFC 8032/8439/5869/7748/9106 |
| libFuzzer harnesses | 11 | `fuzz/fuzz_*.c` covering all primitives |
| dudect timing harness | 1 | 5 constant-time functions verified |
| SIMD KAT tests | 5 | SHA3, AES-GCM, Ed25519, HMAC, ChaCha20 |
| Adversarial tests | 20+ | Crash safety, malformed input, boundary conditions |

### CI Pipelines

| Pipeline | Scope |
|----------|-------|
| `ci.yml` | Full test suite, benchmarks, cross-platform |
| `ci-build-test.yml` | Linux/macOS/Windows MSVC matrix |
| `security.yml` | pip-audit, secret scanning, dependency audit |
| `static-analysis.yml` | CodeQL, Semgrep, cppcheck |
| `fuzzing.yml` | 11 libFuzzer targets, 30s each |
| `dudect.yml` | Constant-time verification |

---

## 8. Files for Auditor Review (Priority Order)

### Critical Path (Crypto Primitives)
1. `src/c/ama_ed25519.c` — Ed25519 field arithmetic, scalar multiplication
2. `src/c/ama_dilithium.c` — ML-DSA-65 NTT, signing, verification
3. `src/c/ama_kyber.c` — ML-KEM-1024 NTT, encapsulation, decapsulation
4. `src/c/ama_aes_gcm.c` — AES-256-GCM encryption, GHASH
5. `src/c/ama_sha3.c` — Keccak-f[1600], SHA3-256, SHAKE
6. `src/c/ama_hkdf.c` — HKDF-SHA3-256 extract/expand
7. `src/c/ama_consttime.c` — Constant-time utilities
8. `src/c/ama_x25519.c` — X25519 Diffie-Hellman

### Python API Layer
9. `ama_cryptography/crypto_api.py` — Main API, `create_crypto_package()`, `verify_crypto_package()`
10. `ama_cryptography/pqc_backends.py` — C library loading, ctypes bindings, Cython dispatch

### Configuration & Build
11. `CMakeLists.txt` — Build flags, SIMD dispatch, security options
12. `include/ama_cryptography.h` — Public C API header

---

## 9. Reproducing Verification

```bash
# Build native library
cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Install Python package
pip install -e ".[dev]"

# Run full test suite (1,884 tests)
python -m pytest tests/ -v --timeout=300

# Run benchmarks
python benchmark_suite.py

# Static analysis
python -m ruff check .
python -m mypy ama_cryptography/ --strict

# C static analysis
cppcheck --enable=all --std=c11 src/c/ include/
```

---

Copyright 2025-2026 Steel Security Advisors LLC. Licensed under Apache License 2.0.
