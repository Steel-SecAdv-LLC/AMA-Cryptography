# Security Model

Documentation for AMA Cryptography's security properties, threat model, side-channel analysis, security guarantees, and production security requirements.

---

## Security Status

| Property | Value |
|----------|-------|
| Audit Status | Community-tested; **not externally audited** |
| Version | 5.0.0 |
| Last Updated | 2026-08-15 |
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
| **Non-repudiation** | Ed25519 + ML-DSA-65 signatures | Cryptographic proof of authorship. RFC 3161 contributes nothing: AMA verifies no TSA signature, so `genTime` is unauthenticated ([INVARIANT-37](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/INVARIANTS.md)) |
| **Key Independence** | HKDF domain separation | Compromise of one key doesn't compromise others |
| **Memory Safety** | SecureBuffer, secure_memzero | Key material zeroed after use |

### What AMA Cryptography Does NOT Guarantee

- Not a general-purpose TLS/transport security library
- Not a replacement for HSM in high-security environments
- 3R monitoring flags statistical anomalies but does not prevent attacks. Its timing component has a measured floor rather than an open-ended promise: a periodic probe quieter than roughly a third of the ambient jitter is not distinguishable from noise (envelope table in [`MONITORING.md`](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/MONITORING.md#resonancetimingmonitor-runtime-timing-anomaly-monitoring))
- AES-GCM default build uses constant-time bitsliced S-box (`AMA_AES_CONSTTIME=ON`); explicitly disabling it reverts to table-based AES which is cache-timing vulnerable
- Not certified under FIPS 140-2/3

---

## Threat Model

### Adversary Assumptions

The system is designed to be secure against:

| Adversary | Capability | Protection |
|-----------|-----------|-----------|
| **Classical adversary** | Classical computing resources | Ed25519 + ML-DSA-65 + all layers |
| **Quantum adversary** | Cryptographically-relevant quantum computer (CRQC) | ML-DSA-65 + ML-KEM-1024 |
| **Network adversary** | Full network interception (MITM) | Signature verification. **Not** RFC 3161: a MITM on the TSA path substitutes a self-built token with any `genTime` and the binding check still passes |
| **Offline dictionary attacker** | GPU/ASIC password cracking | Argon2id memory-hard KDF |
| **Harvest Now, Decrypt Later** | Storing today's data to decrypt after quantum computers exist | Quantum-resistant encryption |
| **Autonomous agent abusing the API** | An in-process agent driving the library to mint persistence material or successor-authorizing signatures ("notes for future versions") | Agent-instance binding (INVARIANT-30) refuses non-ephemeral / restricted derivations without an operator-held authority key; 3R volume-spike + note-artifact detectors surface the behaviour |

### Agent-Instance Binding (INVARIANT-30)

Modelled on the July 2026 autonomous-agent sandbox escape, where an evaluation
agent reached the open internet and left signed notes for future versions of
itself. A binding names an agent instance, the lifetime of material it may
derive (`EPHEMERAL` / `SESSION` / `PERSISTENT`), and the capabilities it may
exercise (`DATA_SIGN`, `KEY_EXCHANGE`, `PERSISTENCE`, `SELF_REPLICATE`,
`DELEGATE`). Any non-`EPHEMERAL` lifetime or restricted capability requires a
non-zero ethical-profile hash **and** an `HMAC-SHA3-256` authorization tag that
verifies under an operator-held authority key — a MAC check, not a flag test,
evaluated in constant time and fail-closed (no output, distinct error code, no
partial state). The binding is domain separation and policy over the existing
SHA3-256 / HMAC-SHA3-256 / HKDF primitives; it adds no new algorithm. Its limit
is stated plainly: it constrains derivations that *opt into* a binding, so its
value is realised when a deployment routes persistence-material derivation
through it. It is verified by a byte-KAT C test, an end-to-end adversarial
suite, a strict dudect constant-time lane, and a dedicated libFuzzer harness.

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

**Optional add-ons (not core layers):** SLH-DSA-SHA2-256f, ML-KEM-1024, RFC 3161 timestamping.

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
| AES-256-GCM (default) | Bitsliced S-box (`AMA_AES_CONSTTIME=ON`) | ✓ Constant-time |
| AES-256-GCM (opt-out) | Table-based S-box (`-DAMA_AES_CONSTTIME=OFF -DAMA_AES_TABLE_INSECURE=ON`) | ⚠ NOT constant-time |
| ML-DSA-65 | NTT operations | ✓ Constant-time |
| ML-KEM-1024 | NTT + Fujisaki-Okamoto | ✓ Constant-time |
| Key zeroing | `secure_memzero()` multi-pass | ✓ Compiler-resistant |

### AES Cache-Timing Warning

The default AES-256-GCM build uses the constant-time bitsliced AES S-box (`AMA_AES_CONSTTIME=ON` since v2.1.2). Disabling it takes two flags — `-DAMA_AES_CONSTTIME=OFF` alone is a CMake `FATAL_ERROR` unless `-DAMA_AES_TABLE_INSECURE=ON` is also passed to acknowledge the exposure (INVARIANT-20) — after which the build falls back to a 256-byte lookup table S-box that leaks information through cache-timing side-channels in **shared-tenant environments** (cloud VMs, containers with shared L1/L2 caches). A compile-time warning is emitted when the table-based path is selected.

**Verify constant-time AES is enabled (default):**
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
# Look for: "AES consttime: ON" in CMake output
```

### Memory Safety

Sensitive material handling:
- All key material is stored as `bytearray` for in-place zeroing
- `SecureBuffer` context manager ensures zeroing even on exception
- `secure_memzero()` performs multi-pass overwrite to resist compiler optimization
- Optional `secure_mlock()` prevents key material from reaching swap
- `SecureKeyStorage` uses AES-256-GCM encryption at rest

---

## Supported Versions

Mirrors [`SECURITY.md`](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/SECURITY.md),
which is authoritative.

| Version | Security Support |
|---------|-----------------|
| 5.0.x | ✓ Active (development and security updates) |
| 4.0.x | ✗ Superseded by v5.0 (four breaking changes — see CHANGELOG `[5.0.0]`, unreleased) |
| 3.5.x | ✗ Superseded by v4.0 (six breaking changes — see CHANGELOG `[4.0.0]`) |
| 3.4.x | ✗ Superseded by v3.5 (no public API removals) |
| 3.3.x | ✗ Superseded by v3.4 (no public API removals) |
| 3.2.x | ✗ Superseded by v3.3 (no public API removals) |
| 3.1.x | ✗ Superseded by v3.2 (no public API removals) |
| 3.0.x | ✗ Superseded by v3.1 (no public API removals) |
| 2.1.x | ✗ Superseded by v3.0 (`legacy_compat` Argon2id shim available for one-shot migration) |
| 2.0.x | ✗ Superseded by v2.1 |
| 1.0.x | ✗ Superseded by v2.0 |

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
- [ ] Constant-time AES confirmed enabled (default `AMA_AES_CONSTTIME=ON`; verify in CMake output)
- [ ] Key file permissions restricted (mode 0600, encrypted volume)
- [ ] If timestamps are relied upon: the token's issuer is established **outside AMA** (authenticated channel to the TSA, or out-of-band validation before storage). Configuring a reputable TSA alone has no verification consequence — AMA checks the §2.4.2 binding only and accepts a forged token identically
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
| Quantum-resistant signatures | ✓ ML-DSA-65 (FIPS 204) | ✗ | ✓ ML-DSA (native since 3.5; benchmarked here at 4.0.1) |
| Hybrid classical+PQC | ✓ Single-API signature + KEM binding | ✗ | ◐ TLS hybrid key-exchange groups (e.g. X25519MLKEM768); no hybrid signature binding API |
| Runtime anomaly monitoring | ✓ 3R Framework | ✗ | ✗ |
| Defense layers | 4 core + 2 supporting | 1-2 | 1-2 |
| RFC 3161 timestamps | ◐ Wire format + §2.4.2 binding; no TSA signature or chain verification | ✗ | ✓ Full verification (`openssl ts -verify`) |
| Zero-downtime key rotation | ✓ | ✗ | ✗ |
| NIST FIPS 203/204/205 | ✓ | ✗ | ✓ (3.5+: ML-KEM, ML-DSA, SLH-DSA) |
| Audit status | Self-assessed | ✓ Audited | ✓ Audited |

> **Note:** libsodium and OpenSSL are production-hardened, widely-audited libraries, and OpenSSL ships the NIST PQC standards (ML-KEM, ML-DSA, SLH-DSA) natively since 3.5. AMA's differentiators are hybrid classical+PQC binding in a single API, runtime anomaly monitoring (3R), and agent-instance binding — not PQC availability — and it has not undergone equivalent external audit.

---

## References

- [NIST FIPS 203](https://doi.org/10.6028/NIST.FIPS.203) — ML-KEM (Kyber)
- [NIST FIPS 204](https://doi.org/10.6028/NIST.FIPS.204) — ML-DSA (Dilithium)
- [NIST FIPS 205](https://doi.org/10.6028/NIST.FIPS.205) — SLH-DSA (SPHINCS+)
- [RFC 8032](https://tools.ietf.org/html/rfc8032) — Ed25519
- [RFC 5869](https://tools.ietf.org/html/rfc5869) — HKDF
- [RFC 3161](https://tools.ietf.org/html/rfc3161) — Time-Stamp Protocol (AMA implements the wire format and §2.4.2 binding; not TSA signature or chain verification)
- [SECURITY.md](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/SECURITY.md) — Self-assessment
- [THREAT_MODEL.md](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/THREAT_MODEL.md) — Detailed threat classification

---

*See [Architecture](Architecture) for the defense-in-depth design, or [Cryptography Algorithms](Cryptography-Algorithms) for algorithm details.*
