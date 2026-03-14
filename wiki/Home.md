# AMA Cryptography Wiki

**Post-Quantum Security System — built for people, data, and networks**

> A hybrid classical and post-quantum cryptographic framework combining NIST-standardized algorithms with defense-in-depth architecture and runtime observability.

---

## How to use this wiki

- **Build & integrate:** [Installation](Installation) → [Quick Start](Quick-Start) → [API Reference](API-Reference)
- **Assure correctness:** [Security Model](Security-Model) → [Key Management](Key-Management) → [Adaptive Posture](Adaptive-Posture)
- **Operate & observe:** [Secure Memory](Secure-Memory) → [Hybrid Cryptography](Hybrid-Cryptography) → [Performance Benchmarks](Performance-Benchmarks)
- **Need a map?** Start with the system flow below; every node links to deeper pages.

---

## System Blueprint — cryptographic package lifecycle

| Stage | Operation | Standard |
|-------|-----------|----------|
| **1. Prepare** | Canonicalize input + length-prefix | — |
| **2. Hash** | SHA3-256 content digest | NIST FIPS 202 |
| **3. Authenticate** | HMAC-SHA3-256 tag | RFC 2104 |
| **4. Sign (classical)** | Ed25519 digital signature | RFC 8032 |
| **5. Sign (quantum-safe)** | ML-DSA-65 (Dilithium) signature | NIST FIPS 204 |
| **6. Timestamp** | RFC 3161 trusted timestamp | RFC 3161 |
| **7. Package** | Bundle all artifacts into `CryptoPackage` | — |
| **8. Verify** | HKDF-derived keys + integrity + all signatures | RFC 5869 |
| **9. Observe** | 3R monitor (Resonance / Recursion / Refactoring) | — |
| **10. Adapt** | Posture switch: lockdown, rotate keys, or switch algorithms | — |

**Why it matters:** Each stage is independently checkable. An attacker must subvert the assurance, cryptographic, and execution layers in sequence — a defense-in-depth chain instead of a single gate.

---

## Runtime Safety Loop — observability without guessing

| Step | 3R Monitor Stage | Output |
|------|-----------------|--------|
| **1** | **Resonance** — FFT frequency scan of crypto events | Timing anomaly score |
| **2** | **Recursion** — Multi-scale pattern detection | Structural deviation flag |
| **3** | **Refactoring** — Complexity and entropy scoring | Risk classification |
| **4** | **Verdict** — Permit / Flag / Escalate | Policy decision |
| **5** | **Adapt** — Posture switch (algorithm swap, key rotation, lockdown) | Runtime reconfiguration |
| **6** | **Record** — Telemetry + audit trail | Immutable log entry |
| **7** | **Learn** — Feed results back to threat model | Updated security baseline |

---

## Navigation by intent

- **Build & Integrate:**
  - [Installation](Installation) — requirements, toolchains, wheels
  - [Quick Start](Quick-Start) — minimal create/verify package in 5 minutes
  - [API Reference](API-Reference) + [C API](C-API-Reference) — production calls, return codes
- **Assurance & Lifecycle:**
  - [Security Model](Security-Model) — threat coverage, residual risks, disclosure path
  - [Key Management](Key-Management) — hardened HD derivation, rotation, custody
  - [Adaptive Posture](Adaptive-Posture) — runtime policy toggles and allowed fallbacks
- **Operations & Performance:**
  - [Secure Memory](Secure-Memory) — zeroization, constant-time expectations
  - [Hybrid Cryptography](Hybrid-Cryptography) — binding combiners and KEM flow
  - [Performance Benchmarks](Performance-Benchmarks) — throughput, latency, scaling curves

---

## Build-with-confidence checklist

1. **Define the trust surface:** choose HSM/HKDF parameters; align with [Security Model](Security-Model).
2. **Assemble the pipeline:** wire the API call sequence from [Quick Start](Quick-Start) or [API Reference](API-Reference).
3. **Harden execution:** enable zeroization + monitoring from [Secure Memory](Secure-Memory) and [Adaptive Posture](Adaptive-Posture).
4. **Measure and observe:** run the 3R loop and record telemetry per [Performance Benchmarks](Performance-Benchmarks).

---

## Status snapshot

| Property | Value |
|----------|-------|
| Version | 2.0 |
| Algorithms | ML-DSA-65, Kyber-1024, SPHINCS+, Ed25519, AES-256-GCM, Argon2id |
| Platforms | Linux, macOS, Windows |
| Python | 3.8 – 3.13 |
| Audit | Community-tested · Not externally audited |
| License | Apache 2.0 |

> **Production guardrails:** Use a FIPS 140-2 Level 3+ HSM for master secrets, enforce constant-time verification, and perform independent cryptographic review before deployment. See [Security-Model](Security-Model) for requirements.

---

**Contact:** steel.sa.llc@gmail.com — [Report a vulnerability](Security-Model#reporting-vulnerabilities) — [Contribute](Contributing)  
*Built by Steel Security Advisors LLC. Last updated: 2026-03-11.*
