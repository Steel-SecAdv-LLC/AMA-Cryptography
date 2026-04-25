# Security Policy

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 3.0.0 |
| Last Updated | 2026-04-20 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Overview

AMA Cryptography is a quantum-resistant cryptographic protection system released under the Apache License 2.0 as free and open-source software. As of v2.0, all cryptographic primitives are implemented natively in C with zero core dependencies. Security is our highest priority. We take all vulnerabilities seriously and appreciate responsible disclosure from the security research community.

---

## Supported Versions

We actively maintain and provide security updates for the following versions:

| Version | Supported | Status |
|---------|-----------|--------|
| 2.1.x | Yes | Active development and security updates |
| 2.0.x | No | Superseded by v2.1 |
| 1.0.x | No | Superseded by v2.0 |

---

## Security Features

AMA Cryptography implements defense-in-depth with multiple independent security layers — four core cryptographic operations supported by key derivation and timestamping:

1. **SHA3-256 Content Hashing** (NIST FIPS 202)
2. **HMAC-SHA3-256 Authentication** (RFC 2104)
3. **Ed25519 Digital Signatures** (RFC 8032, C11 atomics hardened)
4. **ML-DSA-65 Quantum-Resistant Signatures** (NIST FIPS 204)
5. **HKDF-SHA3-256 Key Derivation** (RFC 5869, NIST SP 800-108)
6. **RFC 3161 Trusted Timestamps**

### Additional Cryptographic Capabilities

- **AES-256-GCM Authenticated Encryption** (NIST SP 800-38D)
- **ML-KEM-1024 Key Encapsulation** (NIST FIPS 203)
- **SPHINCS+-SHA2-256f Hash-Based Signatures** (NIST FIPS 205)
- **Adaptive Cryptographic Posture System** (runtime threat-level response)
- **Hybrid KEM Combiner** (IND-CCA2 binding construction per Bindel et al.)

### Performance — Framing

Throughput is a continuously-improving axis, not a ceiling.  On x86-64
AVX2 AMA's current ops/sec is within a factor of 2–5× of the
best-known public numbers for libsodium (Ed25519) and liboqs
(ML-DSA-65, ML-KEM-1024), and every release closes some of that gap;
recent work (see `CHANGELOG.md` from v2.1 onward) added 4-way Keccak
batching, Ed25519 signed-window combs, merged-layer ML-DSA NTT, and
Ed25519 verify via Shamir/Straus joint scalar multiplication with a
width-5 wNAF — roughly doubling verify throughput.

#### What "2× verify" means in practice

Ed25519 verify dominates wall-clock time in three protocol families
that AMA's downstream consumers run at scale:

- **X.509 certificate-chain validation** (TLS handshake, code-signing).
  A typical chain is 3–4 certificates deep; each certificate signature
  is one Ed25519 verify.  Doubling per-verify throughput halves the
  CPU budget per chain validation, which on a busy gateway is the
  difference between handling N and 2N concurrent handshakes per core.
- **Noise Protocol Framework handshakes** (WireGuard, Lightning,
  Nym).  The XX, IK and IKpsk2 patterns each do at least one Ed25519
  verify of the responder's static key per handshake; mixed-PQ
  patterns (e.g. `Noise_XXhfs_25519+ML-KEM-1024_*`) keep the same
  verify on the classical leg.  Faster verify shortens the
  Diffie-Hellman-bound handshake critical path.
- **MLS (RFC 9420) group operations.**  Each Welcome / Commit
  message carries one or more Ed25519 signatures over the GroupContext
  and KeyPackages.  In a 1000-member group an Add/Remove can require
  verifying O(log N) signatures along the ratchet-tree path; verify
  speed sets the floor on group-rekey latency.

The change is purely algorithmic — same group-element math, no new
external dependency, no new dispatch slot — and is gated behind
`AMA_ED25519_VERIFY_SHAMIR` (default ON) and `AMA_ED25519_VERIFY_WINDOW`
(default 5) so a single recompile reverts to the prior layout if a
downstream consumer needs the old throughput envelope for
deterministic regression purposes.

The deliberate choices that constitute AMA's security posture —
zero external cryptographic dependencies, in-tree constant-time
implementations audited under `INVARIANT-12`, and a vendored
build-from-source supply chain — auto-bound peak ops/sec against
libraries that lean on AVX-512 or hand-tuned assembly across 500 k+
LoC of audit surface.  Readers who value raw speed over supply-chain
minimalism are unlikely to be the target audience for this library;
readers who need auditable, small-surface post-quantum primitives
with headroom to keep improving should find the trade-off
acceptable.  Measured ops/sec numbers are in `benchmark-report.md`
and `benchmarks/README.md` — any claim to the contrary elsewhere in
the repository should be treated as aspirational and reported as a
documentation bug.

## Reporting a Vulnerability

### Critical Security Issues

If you discover a security vulnerability in AMA Cryptography, please report it responsibly:

**DO NOT** open a public GitHub issue for security vulnerabilities.

**Instead, please use one of the following private channels:**

1. **Preferred — GitHub Private Vulnerability Reporting:**
   [Open a private advisory](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/security/advisories/new).
   GitHub encrypts the report in transit and storage; no PGP key management
   is required on either side.
2. **Email fallback:** steel.sa.llc@gmail.com with subject `[SECURITY] AMA Cryptography Vulnerability Report`.

**Include in your report:**
   - Detailed description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Proof-of-concept code (if applicable)
   - Suggested remediation (if available)
   - Your contact information for follow-up

### What Constitutes a Security Vulnerability

We consider the following to be security vulnerabilities worthy of immediate attention:

**Critical:**
- Cryptographic primitive failures (hash collision, signature forgery)
- Key extraction or recovery attacks
- Authentication bypass
- Arbitrary code execution
- Privilege escalation
- Cryptographic oracle attacks

**High:**
- Side-channel attacks (timing, power analysis)
- Denial of service affecting cryptographic operations
- Information disclosure of sensitive cryptographic material
- Dependency vulnerabilities in cryptographic libraries

**Medium:**
- Input validation issues leading to unexpected behavior
- Insufficient entropy in key generation
- Weak random number generation
- Implementation deviations from cryptographic standards

**Low:**
- Documentation inconsistencies affecting security
- Missing security headers or best practices
- Informational security improvements

### Out of Scope

The following are generally **not** considered security vulnerabilities:

- Theoretical attacks requiring impractical computational resources (e.g., 2^128 operations)
- Issues in third-party dependencies (report to upstream maintainers)
- Social engineering attacks
- Physical access attacks on user systems
- Issues requiring user misconfiguration or ignoring documentation
- Performance or availability issues without security impact
- Missing features (use GitHub Issues instead)

## Response Timeline

We are committed to responding to security reports promptly:

| Severity | Initial Response | Status Update | Resolution Target |
|----------|-----------------|---------------|-------------------|
| Critical | 24 hours        | Every 48 hours | 7 days |
| High     | 48 hours        | Weekly | 30 days |
| Medium   | 5 business days | Bi-weekly | 60 days |
| Low      | 10 business days | Monthly | 90 days |

**Initial Response:** Acknowledgment of receipt and initial severity assessment
**Status Update:** Progress reports and estimated resolution timeline
**Resolution Target:** Expected timeframe for patch release (may vary based on complexity)

## Disclosure Policy

We follow **coordinated disclosure** principles:

1. **Report Received:** We acknowledge receipt within the timeframes above
2. **Validation:** We validate the vulnerability and assess severity
3. **Fix Development:** We develop and test a security patch
4. **Advisory Preparation:** We prepare a security advisory with CVE (if applicable)
5. **Coordinated Release:** We coordinate disclosure timing with the reporter
6. **Public Disclosure:** We publish the advisory and release the patch

**Typical disclosure timeline:** 90 days from initial report, or earlier if:
- A fix is available and tested
- The vulnerability is being actively exploited
- Other parties have independently discovered the issue
- The reporter and maintainers mutually agree

## Security Updates

Security updates are released as follows:

- **Critical vulnerabilities:** Emergency patch release within 7 days
- **High vulnerabilities:** Patch in next minor version (within 30 days)
- **Medium vulnerabilities:** Patch in next scheduled release
- **Low vulnerabilities:** Addressed in regular development cycle

Security advisories are published:
- GitHub Security Advisories (https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/security/advisories)
- Release notes with [SECURITY] tag
- Email notification to users who have starred the repository (when critical)

## Responsible Disclosure Recognition

We deeply appreciate security researchers who help keep AMA Cryptography secure. Reporters who follow responsible disclosure will be:

- **Credited** in the security advisory (unless anonymity is requested)
- **Acknowledged** in the CHANGELOG and release notes
- **Thanked** publicly on our GitHub repository
- **Recognized** in our Hall of Fame for significant contributions

We do not currently offer a bug bounty program but may consider recognition rewards for exceptional discoveries.

## Security Best Practices

Users deploying AMA Cryptography in production should:

### Key Management
- **REQUIRED:** Store master secrets in FIPS 140-2 Level 3+ HSMs for production
- **REQUIRED:** Implement key rotation every 90 days
- **REQUIRED:** Use hardware security modules (AWS CloudHSM, YubiKey, etc.)
- **NEVER:** Store private keys in plain text or version control
- **NEVER:** Reuse keys across different Omni-Code packages

### Zero-Dependency Architecture (v2.1)
- **REQUIRED:** Build native C library (`cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build`)
- All cryptographic primitives (SHA3, HKDF, Ed25519, AES-256-GCM, ML-DSA-65, Kyber-1024, SPHINCS+, X25519, ChaCha20-Poly1305, Argon2, secp256k1) are native C — no external cryptographic dependencies required
- Optional: numpy/scipy for 3R monitoring, PyKCS11 for HSM

### Cryptographic Operations
- **REQUIRED:** Build native PQC C library (`cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build`)
- **REQUIRED:** Enable all cryptographic layers (no fallbacks in production)
- **REQUIRED:** Use RFC 3161 trusted timestamp authorities
- **RECOMMENDED:** Use multiple TSAs for redundancy
- **RECOMMENDED:** Verify all signatures before trusting package contents

### Dependency Management
- **NOTE:** v2.0 has zero core cryptographic dependencies — all primitives are native C
- **REQUIRED:** Keep optional dependencies up to date (numpy, scipy, pynacl if used)
- **REQUIRED:** Enable Dependabot for automated security updates
- **RECOMMENDED:** Pin dependency versions for reproducible builds
- **RECOMMENDED:** Verify package signatures from PyPI

### Monitoring and Auditing
- **REQUIRED:** Log all cryptographic operations for audit trails
- **REQUIRED:** Monitor for signature verification failures
- **REQUIRED:** Alert on quantum library unavailability
- **RECOMMENDED:** Implement rate limiting for signature operations
- **RECOMMENDED:** Regular security audits of deployment configuration

## Cryptographic Algorithm Security

### Current Algorithms

| Algorithm | Classical Security | Quantum Security | Status |
|-----------|-------------------|------------------|--------|
| SHA3-256 | 2^128 | 2^128 | ✓ Secure |
| HMAC-SHA3-256 | 2^128 | 2^128 | ✓ Secure |
| Ed25519 | 2^126 | ~10^7 gates* | ⚠ Quantum-vulnerable |
| ML-DSA-65 (Dilithium-3) | 2^207 | 2^192 | ✓ Quantum-secure |
| ML-KEM-1024 (Kyber) | 2^256 | 2^128 | ✓ Quantum-secure |
| SPHINCS+-SHA2-256f | 2^256 | 2^128 | ✓ Quantum-secure |
| AES-256-GCM | 2^256 | 2^128 | ✓ Quantum-secure |
| HKDF | 2^128 | 2^128 | ✓ Secure |
| X25519 | 2^128 | ~10^7 gates* | ⚠ Quantum-vulnerable |
| ChaCha20-Poly1305 | 2^256 | 2^128 | ✓ Quantum-secure |
| Argon2id | Memory-hard | Memory-hard | ✓ Secure |

*Ed25519 and X25519 are vulnerable to sufficiently large quantum computers, but ML-DSA-65 provides quantum-resistant backup.

### Cryptographic Deprecation Policy

We will deprecate cryptographic algorithms when:
- Practical attacks reduce security below 112-bit classical security
- NIST or other authoritative bodies recommend deprecation
- Quantum computers pose imminent threat to classical algorithms
- More efficient quantum-resistant alternatives become available

**30 days notice** will be provided before deprecating any algorithm, with migration guides and backwards compatibility support.

### Performance note on the VAES AES-GCM dispatch path (x86-64)

The library ships an optional VAES + VPCLMULQDQ AES-256-GCM kernel
(PR A, 2026-04) behind runtime CPUID + XCR0 gating
(`ama_cpuid_has_vaes_aesgcm()`). The VAES + VPCLMULQDQ AES-GCM path
targets **YMM (256-bit), not ZMM**: Zen 3+ / Ice Lake+ CPUs execute
these without the AVX-512 ZMM frequency penalty documented for
Skylake-SP / Cascade Lake. Cloud VM variance on shared hosts is still
the dominant noise source; published throughput numbers are from
bare-metal runs, not CI. Hosts without VAES — or any non-x86-64
host — automatically route through the AVX2 AES-NI + PCLMULQDQ path
shipped in #253 / #254 / #260 / #261, which remains the regression
baseline tracked in `benchmarks/baseline.json`.

## Security Audits

AMA Cryptography has undergone internal security analysis documented in this file. We welcome:

- Independent security audits from qualified cryptographers
- Academic review of our mathematical proofs
- Penetration testing of the implementation
- Code reviews focusing on cryptographic correctness

Please contact us at steel.sa.llc@gmail.com to coordinate security audit efforts.

## Compliance and Standards

AMA Cryptography is designed to comply with:

- **NIST FIPS 202** - SHA-3 Standard (SHA3-256, SHAKE128, SHAKE256)
- **NIST FIPS 203** - Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM / Kyber)
- **NIST FIPS 204** - Module-Lattice-Based Digital Signature Standard (ML-DSA / Dilithium)
- **NIST FIPS 205** - Stateless Hash-Based Digital Signature Standard (SLH-DSA / SPHINCS+)
- **NIST SP 800-38D** - Recommendation for Block Cipher Modes: GCM (AES-256-GCM)
- **NIST SP 800-108** - Recommendation for Key Derivation Using Pseudorandom Functions
- **NIST SP 800-57** - Recommendation for Key Management
- **RFC 2104** - HMAC: Keyed-Hashing for Message Authentication
- **RFC 5869** - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- **RFC 8032** - Edwards-Curve Digital Signature Algorithm (EdDSA)
- **RFC 3161** - Internet X.509 Public Key Infrastructure Time-Stamp Protocol

Non-compliance with these standards should be reported as a high-severity security issue.

## Contact

**Preferred channel:** [GitHub Private Vulnerability Reporting](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/security/advisories/new)
**Email fallback:** steel.sa.llc@gmail.com
**security.txt:** [`.well-known/security.txt`](.well-known/security.txt) (RFC 9116)
**Response Time:** 24-48 hours for critical issues
**Organization:** Steel Security Advisors LLC

## See Also

- [`docs/DESIGN_NOTES.md`](docs/DESIGN_NOTES.md) — Security arguments for original constructions (double-helix engine, adaptive posture, composition protocol)
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — System threat model and risk assessment
- [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md) — Cryptographic algorithm overview
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — System architecture and invariants
- [`CONSTANT_TIME_VERIFICATION.md`](CONSTANT_TIME_VERIFICATION.md) — Timing-side-channel validation
- [`.github/INVARIANTS.md`](.github/INVARIANTS.md) — Library invariants (canonical)

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-11-26 | Initial professional release |
| 1.1.0 | 2026-01-09 | Version alignment, terminology updates |
| 2.0.0 | 2026-03-08 | Zero-dependency native C architecture, FIPS 203/204/205 compliance, AES-256-GCM, adaptive posture system, hybrid KEM combiner, Ed25519 atomics hardening, Phase 2 primitives, fuzzing harnesses, threat model documentation |
| 2.1.0 | 2026-03-25 | Hand-written AVX2/NEON/SVE2 SIMD for 8 algorithms, runtime dispatch, security fixes S1-S6, bitsliced constant-time AES default |
| 2.1.5 | 2026-04-17 | Security audit fixes (length-prefixed HKDF encoding, constant-time ops, finding C6/C7/H2), HSM support via PyKCS11, fd leak protection (CodeQL #297), secure channel protocol v2 with `rekey_epoch` AAD, INVARIANT-13 restoration |

---

Copyright 2025-2026 Steel Security Advisors LLC. Licensed under Apache License 2.0.
