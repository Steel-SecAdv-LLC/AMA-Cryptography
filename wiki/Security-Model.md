# Security Model

Documentation for AMA Cryptography's security properties, threat model, side-channel analysis, security guarantees, and production security requirements.

---

## Security Status

| Property | Value |
|----------|-------|
| Audit Status | Community-tested; **not externally audited** |
| Version | 2.1.2 |
| Last Updated | 2026-04-13 |
| Responsible Disclosure | steel.sa.llc@gmail.com |

> **Production Disclaimer:** This is a self-assessed cryptographic implementation without third-party audit. Production use **requires**:
> - FIPS 140-2 Level 3+ HSM for master secrets
> - Independent security review by qualified cryptographers
> - Constant-time implementation verification
> - Secure file permissions for key files (encrypted volumes, restricted access)

---

## Security Guarantees

### What AMA Cryptography Guarantees

| Property | Mechanism | Guarantee |
|----------|-----------|-----------|
| **Data Integrity** | SHA3-256 | Any modification to signed data detected |
| **Authentication** | HMAC-SHA3-256 + Ed25519 + ML-DSA-65 | Forged packages detected |
| **Quantum Resistance** | ML-DSA-65 (FIPS 204) | Secure against Shor's algorithm |
| **Non-repudiation** | RFC 3161 timestamps | Cryptographic proof of existence time |
| **Key Independence** | HKDF domain separation | Compromise of one key doesn't compromise others |
| **Memory Safety** | SecureBuffer, secure_memzero | Key material zeroed after use |

### What AMA Cryptography Does NOT Guarantee

- Not a general-purpose TLS/transport security library
- Not a replacement for HSM in high-security environments
- 3R monitoring flags statistical anomalies but does not prevent attacks
- AES-GCM default build is not constant-time with respect to cache (use `-DAMA_AES_CONSTTIME=ON` for shared-tenant environments)
- Not certified under FIPS 140-2/3

---

## Threat Model

### Adversary Assumptions

The system is designed to be secure against:

| Adversary | Capability | Protection |
|-----------|-----------|-----------|
| **Classical adversary** | Classical computing resources | Ed25519 + ML-DSA-65 + all layers |
| **Quantum adversary** | Cryptographically-relevant quantum computer (CRQC) | ML-DSA-65 + ML-KEM-1024 |
| **Network adversary** | Full network interception (MITM) | Signature verification, RFC 3161 timestamps |
| **Offline dictionary attacker** | GPU/ASIC password cracking | Argon2id memory-hard KDF |
| **Harvest Now, Decrypt Later** | Storing today's data to decrypt after quantum computers exist | Quantum-resistant encryption |

### Out-of-Scope Threats

The following are **not** in scope for AMA Cryptography's security model:

- **Compromised execution environment** (malware on the signing machine)
- **Physical access** to HSM or key material
- **Social engineering** attacks on key custodians
- **Zero-day vulnerabilities** in the operating system or hardware
- **Supply-chain attacks** on build toolchain

---

## Multi-Layer Security Analysis

Each layer provides independent protection from a different mathematical foundation:

**Core Cryptographic Operations:**

| Layer | Algorithm | Security Assumption | Failure Mode |
|-------|-----------|--------------------|----|
| 1 | SHA3-256 | Keccak collision resistance (NIST FIPS 202) | Only if SHA3 is broken |
| 2 | HMAC-SHA3-256 | PRF security, key secrecy (RFC 2104) | Only if HMAC key exposed |
| 3 | Hybrid Ed25519 + ML-DSA-65 | Discrete log (Curve25519) + Module-LWE lattice hardness (RFC 8032 + NIST FIPS 204) | Quantum computer (Shor) for Ed25519; unknown lattice breakthrough for ML-DSA-65 |
| 4 | HKDF-SHA3-256 | PRF security of HMAC-SHA3-256 (RFC 5869) | Only if underlying PRF is broken |

**Optional add-ons (not core layers):** SPHINCS+-256f, ML-KEM-1024, RFC 3161 timestamping.

**Combined security:** Package authenticity is protected by four independent cryptographic operations. An attacker must simultaneously break **all applicable layers**. No known attack accomplishes this.

---

## Side-Channel Analysis

### Constant-Time Operations

The following operations are implemented in constant time:

| Operation | Implementation | Status |
|-----------|---------------|--------|
| HMAC comparison | `ama_consttime_memcmp()` (C) / XOR accumulator (Python) | ✓ Constant-time |
| Ed25519 signing | `ama_ed25519.c` with `fe25519_sq()` | ✓ Constant-time |
| Ed25519 verification | Windowed scalar multiplication | ✓ Constant-time |
| AES-256-GCM (default) | Table-based S-box | ⚠ NOT constant-time |
| AES-256-GCM (consttime) | Bitsliced (`-DAMA_AES_CONSTTIME=ON`) | ✓ Constant-time |
| ML-DSA-65 | NTT operations | ✓ Constant-time |
| ML-KEM-1024 | NTT + Fujisaki-Okamoto | ✓ Constant-time |
| Key zeroing | `secure_memzero()` multi-pass | ✓ Compiler-resistant |

### AES Cache-Timing Warning

The default AES-256-GCM implementation uses a 256-byte lookup table S-box. In **shared-tenant environments** (cloud VMs, containers with shared L1/L2 caches), this can leak information through cache-timing side-channels.

**Remediation for shared-tenant environments:**
```bash
cmake -B build -DAMA_AES_CONSTTIME=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

This enables the bitsliced AES implementation (`ama_aes_bitsliced.c`) that eliminates table lookups.

### Memory Safety

Sensitive material handling:
- All key material is stored as `bytearray` for in-place zeroing
- `SecureBuffer` context manager ensures zeroing even on exception
- `secure_memzero()` performs multi-pass overwrite to resist compiler optimization
- Optional `secure_mlock()` prevents key material from reaching swap
- `SecureKeyStorage` uses AES-256-GCM encryption at rest

---

## Supported Versions

| Version | Security Support |
|---------|-----------------|
| 2.0.x | ✓ Active (security updates provided) |
| 1.0.x | ✗ End-of-life (superseded by 2.0) |

---

## Reporting Vulnerabilities

### Critical Security Issues

**DO NOT** open a public GitHub issue for security vulnerabilities.

**Report to:** steel.sa.llc@gmail.com  
**Subject:** `[SECURITY] AMA Cryptography Vulnerability Report`

**Include:**
- Detailed description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Proof-of-concept code (if applicable)
- Suggested remediation

### Severity Classification

| Severity | Examples |
|----------|---------|
| **Critical** | Signature forgery, key extraction, authentication bypass |
| **High** | Timing side-channel, DoS of cryptographic operations, key material exposure |
| **Medium** | Input validation issues, entropy weakness, standard deviation |
| **Low** | Documentation inconsistencies, missing security best practices |

---

## Production Deployment Checklist

Before deploying AMA Cryptography in production:

- [ ] Master secrets stored in FIPS 140-2 Level 3+ HSM
- [ ] Independent security review by qualified cryptographers
- [ ] Constant-time AES enabled (`-DAMA_AES_CONSTTIME=ON`) if using shared-tenant infrastructure
- [ ] Key file permissions restricted (mode 0600, encrypted volume)
- [ ] RFC 3161 timestamp configured with a trusted TSA
- [ ] Key rotation policy documented and automated
- [ ] 3R monitoring alerts reviewed by security team
- [ ] `PQCUnavailableError` handling tested (fallback behavior documented)
- [ ] Memory locking (`secure_mlock`) tested on target platform
- [ ] Penetration testing performed on integration points

---

## Security Comparison

AMA Cryptography vs. peer implementations:

| Feature | AMA Cryptography | libsodium | OpenSSL |
|---------|-----------------|-----------|---------|
| Quantum-resistant signatures | ✓ ML-DSA-65 (FIPS 204) | ✗ | ✗ (3.x preview) |
| Hybrid classical+PQC | ✓ | ✗ | ✗ |
| Runtime anomaly monitoring | ✓ 3R Framework | ✗ | ✗ |
| Defense layers | 4 core + 2 supporting | 1-2 | 1-2 |
| RFC 3161 timestamps | ✓ | ✗ | ✗ |
| Zero-downtime key rotation | ✓ | ✗ | ✗ |
| NIST FIPS 203/204/205 | ✓ | ✗ | Partial |
| Audit status | Self-assessed | ✓ Audited | ✓ Audited |

> **Note:** libsodium and OpenSSL are production-hardened, widely-audited libraries. AMA Cryptography provides additional PQC capabilities not yet available in those libraries, but has not undergone equivalent external audit.

---

## References

- [NIST FIPS 203](https://doi.org/10.6028/NIST.FIPS.203) — ML-KEM (Kyber)
- [NIST FIPS 204](https://doi.org/10.6028/NIST.FIPS.204) — ML-DSA (Dilithium)
- [NIST FIPS 205](https://doi.org/10.6028/NIST.FIPS.205) — SLH-DSA (SPHINCS+)
- [RFC 8032](https://tools.ietf.org/html/rfc8032) — Ed25519
- [RFC 5869](https://tools.ietf.org/html/rfc5869) — HKDF
- [RFC 3161](https://tools.ietf.org/html/rfc3161) — Trusted Timestamps
- [SECURITY.md](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/SECURITY.md) — Self-assessment
- [THREAT_MODEL.md](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/THREAT_MODEL.md) — Detailed threat classification

---

*See [Architecture](Architecture) for the defense-in-depth design, or [Cryptography Algorithms](Cryptography-Algorithms) for algorithm details.*
