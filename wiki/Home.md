<div align="center">

# AMA Cryptography Wiki

**Post-Quantum Security System**

*Protecting people, data, and networks with quantum-resistant cryptography*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org)
[![C](https://img.shields.io/badge/C-C11-blue.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![PQC](https://img.shields.io/badge/PQC-FIPS%20203%20%7C%20204%20%7C%20205-purple.svg)](Cryptography-Algorithms)
[![Version](https://img.shields.io/badge/version-2.0-green.svg)](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography)

</div>

---

## What is AMA Cryptography?

AMA Cryptography is a **production-grade, post-quantum cryptographic protection system** that provides quantum-resistant integrity protection for sensitive data structures. It delivers a hybrid classical + post-quantum (PQC) cryptographic framework built on a multi-language architecture (C + Cython + Python).

```
+==============================================================================+
|                            AMA CRYPTOGRAPHY ♱                                |
|                       Post-Quantum Security System                           |
|                                                                              |
|   6-Layer Defense      |   Quantum-Resistant    |   Defense-in-Depth         |
|   Cython-Optimized     |   3R Anomaly Monitor   |   Cross-Platform           |
|   HD Key Derivation    |   Algorithm-Agnostic   |   NIST PQC Standards       |
|                                                                              |
|   C Layer (Native)     |   Cython Layer         |   Python API               |
|   ─────────────────    |   ─────────────────    |   ─────────────────        |
|   SHA3/HKDF/Ed25519    |   18-37x Speedup       |   Algorithm Agnostic       |
|   ML-DSA-65/Kyber      |   NumPy Integration    |   Key Management           |
|   SPHINCS+/NTT Ops     |   Math Engine          |   3R Monitoring            |
|                                                                              |
|                       Built for a civilized evolution.                       |
+==============================================================================+
```

**Copyright 2025–2026 Steel Security Advisors LLC**  
**Author/Inventor:** Andrew E. A.  
**License:** Apache License 2.0 | **Version:** 2.0

---

## Core Innovations

### 6-Layer Defense-in-Depth

AMA Cryptography applies six independent cryptographic layers sequentially, providing unprecedented defense-in-depth:

| Layer | Algorithm | Standard | Security |
|-------|-----------|----------|---------|
| 1 | Canonical Length-Prefixed Encoding | — | Anti-concatenation |
| 2 | **SHA3-256** Content Hash | NIST FIPS 202 | 128-bit collision resistance |
| 3 | **HMAC-SHA3-256** Authentication | RFC 2104 | Keyed message authentication |
| 4 | **Ed25519** Classical Signature | RFC 8032 | 128-bit classical security |
| 5 | **ML-DSA-65** Quantum-Resistant Signature | NIST FIPS 204 | 192-bit quantum security |
| 6 | **RFC 3161** Trusted Timestamp | RFC 3161 | Third-party attestation |

An attacker must defeat **all 6 independent layers** to forge a package. Most systems use only 1–2 layers.

### 3R Runtime Security Monitoring

The system's unique runtime monitoring framework provides real-time visibility into cryptographic operations with less than 2% performance overhead:

- **Resonance Engine** — FFT-based frequency-domain anomaly detection
- **Recursion Engine** — Multi-scale hierarchical pattern analysis
- **Refactoring Engine** — Code complexity metrics for security review

### Zero-Dependency Native C Library

All cryptographic primitives are implemented natively in C11 with no external cryptographic dependencies:

- SHA3-256, HMAC-SHA3-256, HKDF-SHA3-256
- Ed25519, AES-256-GCM, X25519
- ML-DSA-65 (FIPS 204), ML-KEM-1024 (FIPS 203), SPHINCS+-SHA2-256f (FIPS 205)
- ChaCha20-Poly1305, Argon2id, secp256k1

---

## Quick Navigation

### Getting Started
- [Installation](Installation) — System requirements, build instructions, pip install
- [Quick Start](Quick-Start) — 5-minute guide to creating and verifying your first crypto package
- [API Reference](API-Reference) — Complete Python API documentation

### Architecture & Design
- [Architecture](Architecture) — System design, component interactions, data flow
- [Cryptography Algorithms](Cryptography-Algorithms) — All algorithms, standards, key sizes, security levels
- [Post-Quantum Cryptography](Post-Quantum-Cryptography) — ML-DSA-65, Kyber-1024, SPHINCS+, hybrid schemes
- [Security Model](Security-Model) — Threat model, security properties, side-channel analysis

### Advanced Topics
- [Key Management](Key-Management) — HD key derivation, lifecycle, rotation, HSM support
- [Secure Memory](Secure-Memory) — SecureBuffer, memory zeroing, constant-time operations
- [Hybrid Cryptography](Hybrid-Cryptography) — Classical + PQC hybrid KEM, binding combiners
- [Adaptive Posture](Adaptive-Posture) — Runtime threat response, algorithm switching
- [C API Reference](C-API-Reference) — Native C library documentation

### Project Info
- [Performance Benchmarks](Performance-Benchmarks) — Throughput metrics, latency data, scalability
- [Contributing](Contributing) — How to contribute, coding standards, testing requirements

---

## Use Cases by Sector

| Sector | Use Case |
|--------|----------|
| **Government & Defense** | Classified data protection with quantum-safe guarantees |
| **Financial Services** | Transaction signing future-proofed against quantum threats |
| **Healthcare** | HIPAA-compliant data integrity with audit trails |
| **Critical Infrastructure** | SCADA/ICS systems requiring long-term security guarantees |
| **Humanitarian** | Crisis response, whistleblower protection, field data security |
| **Blockchain & Crypto** | Post-quantum secure digital signatures |

---

## Project Status

| Property | Value |
|----------|-------|
| Version | 2.0 |
| Python Support | 3.8+ (including 3.13) |
| Platforms | Linux, macOS, Windows |
| Audit Status | Community-tested; not externally audited |
| License | Apache 2.0 |
| Contact | steel.sa.llc@gmail.com |

> **Security Disclosure:** This is a self-assessed cryptographic implementation without third-party audit. Production use requires FIPS 140-2 Level 3+ HSM for master secrets, independent security review, and constant-time verification. See [Security Model](Security-Model) for details.

---

## Integration

AMA Cryptography serves as the cryptographic protection layer for [Mercury Agent](https://github.com/Steel-SecAdv-LLC/Mercury-Agent), providing quantum-resistant security for Mercury Agent's services.

---

*Wiki maintained by Steel Security Advisors LLC. Last updated: 2026-03-10.*
