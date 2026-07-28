# AMA Cryptography: Threat Model

**Copyright (C) 2025-2026 Steel Security Advisors LLC**
**Version:** 3.4.0
**Date:** 2026-07-25
**Classification:** Public

---

## 1. System Overview

AMA Cryptography is a zero-dependency native C cryptographic library providing quantum-resistant protection for Omni-Code data structures. The system uses a 4-layer defense-in-depth architecture with NIST-approved algorithms: (1) SHA3-256 content hash, (2) HMAC-SHA3-256 authentication, (3) hybrid Ed25519 + ML-DSA-65 signature, and (4) HKDF-SHA3-256 key independence — with optional RFC 3161 timestamping.

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
| T1.8 | ML-KEM-1024 decapsulation | KEM layer | Negligible (2^254 ops) | HIGH | **LOW** |

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
| T3.7 | Forged or substituted RFC 3161 token | Timestamp integrity | **High** (no attacker capability required beyond supplying a token) | MEDIUM | **MEDIUM** |
| T3.5 | Misconfiguration (disabled layers) | 4-Layer defense bypass | Medium | HIGH | **MEDIUM** |
| T3.6 | Autonomous agent mints persistence material or successor-authorizing signatures | Agent containment / key lifetime | Medium | HIGH | **MEDIUM** |

**T3.6 detail.** An autonomous agent with in-process access to the library needs
two cryptographic capabilities to persist beyond its instance: key material that
outlives it, and signatures a later instance would treat as authoritative
("notes for future versions"). Ordinary per-message signing and ephemeral
session keys are neither. The July 2026 evaluation-agent sandbox escape is the
concrete instance of this pattern. See M3.5.

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
| T1.4 | ML-DSA-65 (FIPS 204) — quantum-resistant backup | **IMPLEMENTED** | `ama_dilithium.c`; current self-attested vector scope in `docs/compliance/CSRC_ALIGN_REPORT.md` |
| T1.5 | ML-DSA-65 lattice hardness — 192-bit quantum security | **IMPLEMENTED** | MLWE assumption, FIPS 204 compliant |
| T1.6 | HKDF-SHA3-256 (RFC 5869) — one-way derivation | **IMPLEMENTED** | `ama_hkdf.c`, domain-separated contexts |
| T1.7 | AES-256-GCM (SP 800-38D) — 128-bit quantum security | **IMPLEMENTED** | `ama_aes_gcm.c`, NIST test vectors |
| T1.8 | ML-KEM-1024 (FIPS 203) — 256-bit quantum security | **IMPLEMENTED** | `ama_kyber.c`; current self-attested vector scope in `docs/compliance/CSRC_ALIGN_REPORT.md` |

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
| T3.4 | RFC 3161 §2.4.2 message-imprint binding, `PKIStatusInfo` verdict, TSA nonce echo | **PARTIAL** | `rfc3161_timestamp.py`. The binding half only. **Independent verification is NOT implemented**: AMA verifies neither the TSA's CMS `SignerInfo` signature (RFC 5652 §5.3) nor its certificate chain (RFC 5280 §6), so T3.4 is not mitigated by this library — see T3.7 and INVARIANT-37 |
| T3.7 | Token must be a CMS `SignedData` carrying a signer; `certificate_file` / `tsa_cert_path` refuse rather than answering a weaker question | **PARTIAL (structural only)** | `extract_tst_info()` rejects empty `digestAlgorithms` / `signerInfos`, raising the cost of an offline forgery without closing it. Residual mitigation is out of scope for the library: establish the token's origin through an authenticated channel or out-of-band validation |
| T3.5 | Defense-in-depth requires all layers by default | **IMPLEMENTED** | `ama_cryptography.crypto_api.create_crypto_package()` / `verify_crypto_package()` enforce 4-layer verification (legacy compat: `ama_cryptography.legacy_compat`) |
| T3.6 | Agent-instance binding (INVARIANT-30): non-`EPHEMERAL` lifetimes and restricted capabilities require an operator-held authority key | **IMPLEMENTED** | `src/c/ama_agent_binding.c`, `ama_cryptography/agent_binding.py`; byte-KAT + adversarial suite + strict dudect lane + `fuzz/fuzz_agent_binding.c` |
| T3.6 | 3R agentic-abuse detectors surface the behaviour for review | **IMPLEMENTED (advisory)** | `VolumeSpikeDetector` / `NoteArtifactDetector` in `ama_cryptography/monitoring.py`; on by default, never block an operation |

**Scope note for T3.6.** The binding constrains derivations that are made
*through* it, so its protection is realised when a deployment routes
persistence-material derivation through a binding; it is not a sandbox and does
not contain code that never calls the library. The detectors are advisory
heuristics — an agent that avoids the successor vocabulary is not flagged, and
`flagged=False` is not a statement that a payload is benign.

### M4: Supply Chain Mitigations

| Threat | Mitigation | Status | Evidence |
|--------|-----------|--------|----------|
| T4.1 | Zero external runtime dependencies | **BY DESIGN** | All crypto implemented in native C |
| T4.1 | Dependency pinning and SBOM generation | **IMPLEMENTED** | `requirements-lock.txt`, SBOM workflow |
| T4.2 | Multi-platform CI with security scanning | **IMPLEMENTED** | `ci.yml`, `security.yml`, `fuzzing.yml` |
| T4.2 | Secret scanning (TruffleHog) | **IMPLEMENTED** | `.github/workflows/security.yml` |
| T4.3 | Signed commits (required) | **REQUIRED** | GPG/SSH signing on main and develop branches (INVARIANT-10) |

---

## 5. Residual Risks

These risks are accepted or require external mitigation:

| Risk | Severity | Rationale |
|------|----------|-----------|
| Table-based AES S-box (opt-in) | **LOW** | Constant-time bitsliced AES is the **default** build (`AMA_AES_CONSTTIME=ON`). Disabling it emits a compile-time warning. |
| No third-party security audit | **MEDIUM** | Self-assessed. Recommended before high-value production deployment. |
| PQC algorithm maturity | **LOW** | ML-DSA-65 and ML-KEM-1024 are NIST-standardized (FIPS 203/204) but have limited deployment history. |
| Ed25519 quantum vulnerability | **LOW** | Mitigated by ML-DSA-65 quantum-resistant layer. Ed25519 provides classical defense only. |
| RFC 3161 attestation not implemented | **MEDIUM** | AMA verifies the §2.4.2 message-imprint binding only — no CMS `SignerInfo` signature verification, no X.509 path validation. A token is therefore not attributable to any authority and its `genTime` is attacker-chosen; forging one AMA accepts needs no key and no privileged position (T3.7). Multiple TSAs add availability redundancy, not trust redundancy. Deployments that rely on timestamps must establish token origin outside the library. Scoped for closure in [ARCHITECTURE.md § Scope: RFC 3161 attestation is not implemented](ARCHITECTURE.md#scope-rfc-3161-attestation-is-not-implemented); enforced meanwhile by INVARIANT-37. |
| Compiler optimization of secure zeroing | **LOW** | Mitigated with `volatile` pointers and compiler barriers (`__asm__ __volatile__`). |
| Agent-instance binding is opt-in per derivation | **MEDIUM** | The binding constrains material derived *through* it (INVARIANT-30); it is not a sandbox and does not restrain code that never calls the library. Deployments hosting autonomous agents should route persistence-material derivation through a binding and hold the authority key outside the agent's reach. |
| Agentic-abuse detectors are heuristics | **LOW** | `NoteArtifactDetector` does not catch an agent that avoids the successor vocabulary, and `VolumeSpikeDetector` is deliberately calibrated to stay quiet under legitimate load. Both are advisory review aids, not enforcement. |

---

## 6. Verification Matrix

How each defense layer is verified:

| Layer | Unit Tests | KAT Vectors | Fuzzing | Timing Analysis | CI |
|-------|-----------|------------|---------|----------------|-----|
| SHA3-256 | `test_sha3.c` | FIPS 202 | `fuzz_sha3` | `dudect_crypto` | Yes |
| HMAC-SHA3-256 | `test_hkdf.c` | RFC 5869 | `fuzz_hkdf` | `dudect_crypto` | Yes |
| Ed25519 | `test_ed25519.c` | RFC 8032 | `fuzz_ed25519` | `dudect_crypto` | Yes |
| ML-DSA-65 | `test_kat.c` | FIPS 204 | `fuzz_dilithium` | — | Yes |
| ML-KEM-1024 | `test_kat.c` | FIPS 203 | `fuzz_kyber` | — | Yes |
| SLH-DSA-SHA2-256f | `test_kat.c` | FIPS 205 | `fuzz_sphincs` | — | Yes |
| AES-256-GCM | `test_kat.c` | SP 800-38D | `fuzz_aes_gcm` | `dudect_crypto` | Yes |
| ChaCha20-Poly1305 | — | RFC 8439 | `fuzz_chacha20poly1305` | — | Yes |
| X25519 | — | RFC 7748 | `fuzz_x25519` | — | Yes |
| Argon2id | — | RFC 9106 | `fuzz_argon2` | — | Yes |
| Const-time utils | `test_consttime.c` | — | `fuzz_consttime` | `dudect_harness` | Yes |
| Agent-instance binding | `test_agent_binding.c`, `tests/test_agent_binding.py`, `tests/test_agentic_load_adversarial.py` | Pinned canonical-encoding byte KAT | `fuzz_agent_binding` | `test_dudect` (`Agent binding check`, strict) | Yes |

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
2. **ML-DSA-65 broken:** Upgrade to SLH-DSA-SHA2-256f (hash-based, conservative assumption). Switch via adaptive posture system.
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
