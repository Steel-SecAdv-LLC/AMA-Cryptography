# AMA Cryptography: Threat Model

**Copyright (C) 2025-2026 Steel Security Advisors LLC**
**Version:** 1.0
**Date:** 2026-03-10
**Classification:** Public

---

## 1. System Overview

AMA Cryptography is a zero-dependency native C cryptographic library providing quantum-resistant protection for Omni-Code data structures. The system uses a 4-Layer defense-in-depth architecture with NIST-approved algorithms.

### Assets Under Protection

| Asset | Sensitivity | Storage |
|-------|------------|---------|
| Master secret (IKM) | **CRITICAL** | HSM/TPM (FIPS 140-2 Level 3+) |
| Ed25519 private key | **CRITICAL** | HSM/TPM or encrypted at rest |
| ML-DSA-65 private key | **CRITICAL** | HSM/TPM or encrypted at rest |
| HMAC key material | **HIGH** | Derived via HKDF; ephemeral |
| AES-256-GCM session keys | **HIGH** | Derived via HKDF; ephemeral |
| Omni-Code plaintext | **HIGH** | Application-dependent |
| Public keys | PUBLIC | Certificate or key server |
| Signatures / MACs | PUBLIC | Attached to signed data |

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  TRUSTED ZONE (HSM / Secure Enclave)                        │
│  ┌────────────────┐  ┌────────────────┐                     │
│  │  Master Secret  │  │  Private Keys  │                     │
│  └────────────────┘  └────────────────┘                     │
├─────────────────────────────────────────────────────────────┤
│  APPLICATION ZONE (Process Memory)                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐ ┌───────────┐  │
│  │ AES Keys │ │ HMAC Keys│ │ Derived Keys │ │ Plaintext │  │
│  └──────────┘ └──────────┘ └──────────────┘ └───────────┘  │
├─────────────────────────────────────────────────────────────┤
│  UNTRUSTED ZONE (Network / Storage)                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐ ┌───────────┐  │
│  │Ciphertext│ │Signatures│ │ Public Keys  │ │ Timestamps│  │
│  └──────────┘ └──────────┘ └──────────────┘ └───────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Threat Actors

| Actor | Capability | Motivation | Examples |
|-------|-----------|------------|----------|
| **Remote attacker** | Network access, ~2^80 computation | Data theft, forgery | Nation-state, organized crime |
| **Quantum adversary** | Access to large-scale quantum computer | Break classical crypto | Future nation-state (2030+) |
| **Co-tenant** | Shared CPU, cache side-channels | Key extraction | Cloud VM neighbor |
| **Insider** | Source code access, CI/CD access | Backdoor, supply chain | Malicious contributor |
| **Physical attacker** | Device access, power analysis | Key extraction | Lab-based attacker |

---

## 3. Threat Catalog

### T1: Cryptographic Algorithm Attacks

| ID | Threat | Target | Likelihood | Impact | Risk |
|----|--------|--------|-----------|--------|------|
| T1.1 | SHA3-256 collision | Integrity layer | Negligible (2^128 ops) | HIGH | **LOW** |
| T1.2 | HMAC-SHA3-256 forgery | Authentication layer | Negligible (2^128 ops) | HIGH | **LOW** |
| T1.3 | Ed25519 forgery (classical) | Signature layer | Negligible (2^126 ops) | CRITICAL | **LOW** |
| T1.4 | Ed25519 forgery (quantum) | Signature layer | Medium (future) | CRITICAL | **MEDIUM** |
| T1.5 | ML-DSA-65 forgery (quantum) | PQC signature layer | Negligible (2^190 ops) | CRITICAL | **LOW** |
| T1.6 | HKDF key recovery | Key derivation | Negligible (2^256 ops) | CRITICAL | **LOW** |
| T1.7 | AES-256-GCM key recovery | Encryption layer | Negligible (2^128 quantum) | HIGH | **LOW** |
| T1.8 | Kyber-1024 decapsulation | KEM layer | Negligible (2^254 ops) | HIGH | **LOW** |

### T2: Implementation Attacks

| ID | Threat | Target | Likelihood | Impact | Risk |
|----|--------|--------|-----------|--------|------|
| T2.1 | Cache-timing on AES S-box | AES-GCM key extraction | Medium (shared environments) | CRITICAL | **HIGH** |
| T2.2 | Timing on Ed25519 verify | Public key recovery | Low (verify uses public data) | LOW | **LOW** |
| T2.3 | Memory disclosure (Heartbleed-class) | Key material in process memory | Low (no TLS stack) | CRITICAL | **MEDIUM** |
| T2.4 | Buffer overflow in C code | Code execution | Low (bounds-checked) | CRITICAL | **MEDIUM** |
| T2.5 | Integer overflow in size calculations | Memory corruption | Low (overflow guards) | HIGH | **MEDIUM** |
| T2.6 | Use-after-free | Code execution | Low (simple alloc patterns) | CRITICAL | **LOW** |

### T3: Operational Attacks

| ID | Threat | Target | Likelihood | Impact | Risk |
|----|--------|--------|-----------|--------|------|
| T3.1 | Key compromise (theft/leak) | Private keys | Medium | CRITICAL | **HIGH** |
| T3.2 | Nonce reuse in AES-GCM | Confidentiality | Low (random nonce) | CRITICAL | **MEDIUM** |
| T3.3 | Weak entropy source | Key generation | Low (OS RNG) | CRITICAL | **MEDIUM** |
| T3.4 | TSA compromise | Timestamp integrity | Low | MEDIUM | **LOW** |
| T3.5 | Misconfiguration (disabled layers) | 4-Layer defense bypass | Medium | HIGH | **MEDIUM** |

### T4: Supply Chain Attacks

| ID | Threat | Target | Likelihood | Impact | Risk |
|----|--------|--------|-----------|--------|------|
| T4.1 | Backdoored dependency | Build pipeline | Low (zero runtime deps) | CRITICAL | **LOW** |
| T4.2 | Compromised CI/CD | Release artifacts | Low | CRITICAL | **MEDIUM** |
| T4.3 | Source code tampering | Repository integrity | Low | CRITICAL | **LOW** |

---

## 4. Mitigations

### M1: Cryptographic Mitigations

| Threat | Mitigation | Status | Evidence |
|--------|-----------|--------|----------|
| T1.1 | SHA3-256 (FIPS 202) — 128-bit collision resistance | **IMPLEMENTED** | `ama_sha3.c`, NIST KAT vectors pass |
| T1.2 | HMAC-SHA3-256 (RFC 2104) — keyed authentication | **IMPLEMENTED** | `ama_hkdf.c`, constant-time comparison |
| T1.3 | Ed25519 (RFC 8032) — 128-bit classical security | **IMPLEMENTED** | `ama_ed25519.c`, deterministic signing |
| T1.4 | ML-DSA-65 (FIPS 204) — quantum-resistant backup | **IMPLEMENTED** | `ama_dilithium.c`, 10/10 NIST KAT pass |
| T1.5 | ML-DSA-65 lattice hardness — 192-bit quantum security | **IMPLEMENTED** | MLWE assumption, FIPS 204 compliant |
| T1.6 | HKDF-SHA3-256 (RFC 5869) — one-way derivation | **IMPLEMENTED** | `ama_hkdf.c`, domain-separated contexts |
| T1.7 | AES-256-GCM (SP 800-38D) — 128-bit quantum security | **IMPLEMENTED** | `ama_aes_gcm.c`, NIST test vectors |
| T1.8 | Kyber-1024 (FIPS 203) — 256-bit quantum security | **IMPLEMENTED** | `ama_kyber.c`, 10/10 NIST KAT pass |

### M2: Side-Channel Mitigations

| Threat | Mitigation | Status | Evidence |
|--------|-----------|--------|----------|
| T2.1 | Constant-time AES S-box (full-table scan) | **IMPLEMENTED** | `ama_aes_bitsliced.c`, `-DAMA_AES_CONSTTIME=ON` |
| T2.1 | Hardware AES-NI (no table access) | **RECOMMENDED** | Application-level; not in this library |
| T2.2 | Ed25519 verify uses public scalar (non-secret) | **BY DESIGN** | Verification scalar = H(R,A,M), public |
| T2.2 | Ed25519 sign uses constant-time scalar mul | **IMPLEMENTED** | `ama_ed25519.c`, Montgomery ladder |
| T2.3 | Secure memory zeroing on all sensitive buffers | **IMPLEMENTED** | `ama_secure_memzero()`, volatile+barrier |
| T2.3 | Cleanup on all exit paths (including error) | **IMPLEMENTED** | Audited: all `free()` preceded by zeroing |
| T2.4 | Static analysis (cppcheck, clang-analyzer, CodeQL) | **IMPLEMENTED** | `.github/workflows/static-analysis.yml` |
| T2.4 | Coverage-guided fuzzing (libFuzzer, 11 harnesses) | **IMPLEMENTED** | `fuzz/`, `.github/workflows/fuzzing.yml` |
| T2.5 | Integer overflow guards before allocation | **IMPLEMENTED** | `SIZE_MAX` checks in `ama_dilithium.c`, `ama_ed25519.c` |
| T2.6 | Simple allocation patterns (malloc→use→zero→free) | **BY DESIGN** | No complex object lifetimes |

### M3: Operational Mitigations

| Threat | Mitigation | Status | Evidence |
|--------|-----------|--------|----------|
| T3.1 | HSM/TPM required for production key storage | **REQUIRED** | Documented in SECURITY.md |
| T3.1 | Secure memory zeroing prevents post-use leakage | **IMPLEMENTED** | `ama_secure_memzero()` on all key material |
| T3.2 | 96-bit random nonce from OS CSPRNG | **IMPLEMENTED** | `ama_platform_rand.c` (getrandom/BCrypt) |
| T3.3 | Platform CSPRNG (getrandom, getentropy, BCryptGenRandom) | **IMPLEMENTED** | `ama_platform_rand.c`, no userspace PRNG |
| T3.4 | RFC 3161 TSA with independent verification | **IMPLEMENTED** | `rfc3161_timestamp.py`, multiple TSA support |
| T3.5 | Defense-in-depth requires all layers by default | **IMPLEMENTED** | `code_guardian_secure.py` enforces 4 layers |

### M4: Supply Chain Mitigations

| Threat | Mitigation | Status | Evidence |
|--------|-----------|--------|----------|
| T4.1 | Zero external runtime dependencies | **BY DESIGN** | All crypto implemented in native C |
| T4.1 | Dependency pinning and SBOM generation | **IMPLEMENTED** | `requirements-lock.txt`, SBOM workflow |
| T4.2 | Multi-platform CI with security scanning | **IMPLEMENTED** | `ci.yml`, `security.yml`, `fuzzing.yml` |
| T4.2 | Secret scanning (TruffleHog) | **IMPLEMENTED** | `.github/workflows/security.yml` |
| T4.3 | Signed commits (recommended) | **RECOMMENDED** | GPG/SSH signing on main branch |

---

## 5. Residual Risks

These risks are accepted or require external mitigation:

| Risk | Severity | Rationale |
|------|----------|-----------|
| Table-based AES S-box (default build) | **MEDIUM** | Constant-time backend available via `AMA_AES_CONSTTIME`. Default uses fast table-based for non-shared environments. |
| No third-party security audit | **MEDIUM** | Self-assessed. Recommended before high-value production deployment. |
| PQC algorithm maturity | **LOW** | ML-DSA-65 and Kyber-1024 are NIST-standardized (FIPS 203/204) but have limited deployment history. |
| Ed25519 quantum vulnerability | **LOW** | Mitigated by ML-DSA-65 quantum-resistant layer. Ed25519 provides classical defense only. |
| RFC 3161 TSA trust dependency | **LOW** | Timestamps depend on external TSA integrity. Use multiple TSAs for defense-in-depth. |
| Compiler optimization of secure zeroing | **LOW** | Mitigated with `volatile` pointers and compiler barriers (`__asm__ __volatile__`). |

---

## 6. Verification Matrix

How each defense layer is verified:

| Layer | Unit Tests | KAT Vectors | Fuzzing | Timing Analysis | CI |
|-------|-----------|------------|---------|----------------|-----|
| SHA3-256 | `test_sha3.c` | FIPS 202 | `fuzz_sha3` | `dudect_crypto` | Yes |
| HMAC-SHA3-256 | `test_hkdf.c` | RFC 5869 | `fuzz_hkdf` | `dudect_crypto` | Yes |
| Ed25519 | `test_ed25519.c` | RFC 8032 | `fuzz_ed25519` | `dudect_crypto` | Yes |
| ML-DSA-65 | `test_kat.c` | FIPS 204 | `fuzz_dilithium` | — | Yes |
| Kyber-1024 | `test_kat.c` | FIPS 203 | `fuzz_kyber` | — | Yes |
| SPHINCS+-256f | `test_kat.c` | FIPS 205 | `fuzz_sphincs` | — | Yes |
| AES-256-GCM | `test_kat.c` | SP 800-38D | `fuzz_aes_gcm` | `dudect_crypto` | Yes |
| ChaCha20-Poly1305 | — | RFC 8439 | `fuzz_chacha20poly1305` | — | Yes |
| X25519 | — | RFC 7748 | `fuzz_x25519` | — | Yes |
| Argon2id | — | RFC 9106 | `fuzz_argon2` | — | Yes |
| Const-time utils | `test_consttime.c` | — | `fuzz_consttime` | `dudect_harness` | Yes |

---

## 7. Incident Response

### Key Compromise Response

1. **Immediate:** Rotate all derived keys via HKDF with new master secret
2. **Short-term:** Re-sign all Omni-Codes with new Ed25519/ML-DSA-65 keys
3. **Medium-term:** Audit all packages signed with compromised key
4. **Long-term:** Investigate root cause, update HSM access controls

### Algorithm Compromise Response

If a NIST-approved algorithm is broken:

1. **Ed25519 broken (quantum):** ML-DSA-65 provides continued protection. Disable Ed25519 verification requirement.
2. **ML-DSA-65 broken:** Upgrade to SPHINCS+-256f (hash-based, conservative assumption). Switch via adaptive posture system.
3. **SHA3-256 broken:** Switch to SHA-512 or BLAKE3. Update all hash-dependent layers.
4. **AES-256-GCM broken:** Switch to ChaCha20-Poly1305 (already implemented as alternative).

### Vulnerability Disclosure

Security vulnerabilities should be reported to: **steel.sa.llc@gmail.com**

Do NOT open public GitHub issues for security vulnerabilities.

---

## 8. Review Schedule

| Review | Frequency | Scope |
|--------|-----------|-------|
| Threat model update | Quarterly | New threats, algorithm status |
| Dependency audit | Monthly | `pip-audit`, `safety` |
| Static analysis | Every PR | cppcheck, clang-analyzer, CodeQL |
| Fuzzing campaign | Every PR | libFuzzer, 30s per target |
| Constant-time verification | Every PR | dudect harness, 50K iterations |
| Full security review | Annually | External audit recommended |
