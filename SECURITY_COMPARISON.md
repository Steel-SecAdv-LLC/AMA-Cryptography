# Security Comparison: AMA Cryptography vs OpenSSL+liboqs

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 2.1 |
| Last Updated | 2026-03-10 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Executive Summary

**Question:** Is AMA Cryptography safer or more secure than OpenSSL + liboqs?

**Short Answer:**
- **Theoretically:** YES (more defense layers)
- **Practically:** DEPENDS (lacks external audit vs battle-tested code)

**Nuanced Answer:** AMA Cryptography provides **architectural security advantages** through defense-in-depth, but OpenSSL+liboqs has **implementation maturity advantages** through extensive auditing.

---

## Security Feature Comparison

### Core Cryptographic Primitives

| Feature | OpenSSL+liboqs | AMA Cryptography | Security Implication |
|---------|----------------|--------------|----------------------|
| **Ed25519 Signatures** | ✅ OpenSSL (audited) | ✅ Native C (RFC 8032 KAT validated, C11 atomics) | Equivalent |
| **ML-DSA-65 Signatures** | ✅ liboqs (NIST-reviewed) | ✅ Native C (NIST KAT validated, 10/10 pass) | Equivalent |
| **ML-KEM-1024 (Kyber)** | ✅ liboqs (NIST-reviewed) | ✅ Native C (NIST KAT validated, 10/10 pass) | Equivalent |
| **SPHINCS+-SHA2-256f** | ✅ liboqs | ✅ Native C (FIPS 205) | Equivalent |
| **AES-256-GCM** | ✅ OpenSSL (audited) | ✅ Native C (SP 800-38D) | OpenSSL has AES-NI |
| **X25519 Key Exchange** | ✅ OpenSSL (audited) | ✅ Native C (RFC 7748) | Equivalent |
| **ChaCha20-Poly1305** | ✅ OpenSSL (audited) | ✅ Native C (RFC 8439, constant-time) | Equivalent |
| **Argon2id** | ⚠️ Not built-in | ✅ Native C (RFC 9106) | **AMA has built-in** |
| **Audit Status** | ✅ Extensively audited | ❌ **No external audit** | **OpenSSL+liboqs safer** |
| **FIPS 140-2** | ✅ Available | ❌ Not certified | **OpenSSL+liboqs safer** |

**Verdict:** For core cryptographic operations, **OpenSSL+liboqs is more trustworthy** due to extensive auditing.

---

### Defense-in-Depth Architecture

| Security Layer | OpenSSL+liboqs | AMA Cryptography | Security Value |
|----------------|----------------|--------------|----------------|
| **SHA3-256 Content Hash** | ❌ Not included | ✅ Layer 1 | Integrity verification |
| **HMAC-SHA3-256** | ❌ Not included | ✅ Layer 2 | Authentication |
| **Ed25519 Signature** | ✅ Yes | ✅ Layer 3 | Classical security |
| **ML-DSA-65 Signature** | ✅ Yes | ✅ Layer 4 | Quantum resistance |
| **HKDF Key Derivation** | ⚠️ Manual | ✅ Layer 5 (integrated) | Key independence |
| **RFC 3161 Timestamps** | ❌ Not included | ✅ Layer 6 (optional) | Non-repudiation |
| **Total Layers** | **2** | **6** | **AMA Cryptography has 3x more layers** |

**Verdict:** **AMA Cryptography provides significantly more defense-in-depth.**

---

### Runtime Security Features

| Feature | OpenSSL+liboqs | AMA Cryptography | Security Benefit |
|---------|----------------|--------------|------------------|
| **3R Monitoring** | ❌ None | ✅ Yes (<2% overhead) | Anomaly detection |
| **Adaptive Posture** | ❌ None | ✅ Yes (runtime threat response) | Automated key rotation, algorithm switching |
| **Hybrid KEM Combiner** | ❌ None | ✅ Yes (IND-CCA2 binding) | Classical + PQC key encapsulation |
| **Constant-time Verification** | ✅ (OpenSSL) | ✅ (with dudect tests, C11 atomics) | Side-channel resistance |
| **Memory Safety** | ✅ (C with sanitizers) | ⚠️ Python (GC) + C | Language-dependent |
| **Bounds Checking** | ⚠️ Manual | ✅ Automatic (Python) | Buffer overflow prevention |
| **Secure Memory Wiping** | ✅ Yes | ✅ Yes | Key material protection |

**Verdict:** **Mixed** - OpenSSL has proven constant-time impl, AMA Cryptography adds runtime monitoring.

---

## Security Analysis by Threat Model

### Threat: Cryptographic Algorithm Break

**Scenario:** Ed25519 is broken by quantum computer or cryptanalysis

| Implementation | Protection | Outcome |
|----------------|------------|---------|
| OpenSSL+liboqs | ML-DSA-65 still valid | ✅ Protected |
| AMA Cryptography | ML-DSA-65 + HMAC + SHA3 | ✅ **Better protected** (multiple fallbacks) |

**Winner:** **AMA Cryptography** - multiple independent layers mean attacker must break ALL of them.

---

### Threat: Implementation Vulnerability

**Scenario:** Bug in signature verification logic

| Implementation | Risk Assessment | Mitigation |
|----------------|-----------------|------------|
| OpenSSL+liboqs | Lower risk | ✅ Extensively audited, battle-tested |
| AMA Cryptography | Higher risk | ❌ **No external audit**, more complex codebase |

**Winner:** **OpenSSL+liboqs** - proven track record, fewer bugs likely.

---

### Threat: Side-Channel Attack

**Scenario:** Timing attack to extract private keys

| Implementation | Protection | Verification |
|----------------|------------|--------------|
| OpenSSL | Constant-time primitives | ✅ Extensively tested in production |
| liboqs | Constant-time ML-DSA-65 | ✅ NIST-reviewed |
| AMA Cryptography | Constant-time utils + dudect | ⚠️ **Self-tested only** |

**Winner:** **OpenSSL+liboqs** - proven constant-time implementations.

---

### Threat: Key Compromise

**Scenario:** Attacker steals private keys

| Implementation | Protection | Recovery |
|----------------|------------|----------|
| OpenSSL+liboqs | Key hygiene (user responsibility) | No additional protection |
| AMA Cryptography | HSM requirement + key derivation | Same ultimate vulnerability, but better practices |

**Tie:** Both equally vulnerable if keys are compromised. AMA Cryptography's architecture REQUIRES HSM, which is good practice.

---

### Threat: Supply Chain Attack

**Scenario:** Malicious code injected into dependencies

| Implementation | Risk | Attack Surface |
|----------------|------|----------------|
| OpenSSL+liboqs | 2 dependencies | Smaller attack surface |
| AMA Cryptography | Native C + Python (zero core deps) | **Comparable attack surface** |

**Winner:** **Mixed** - AMA Cryptography v2.0 has zero core cryptographic dependencies (all native C). Optional dependencies (numpy, scipy, pynacl) are only for monitoring and secure memory features. The core cryptographic path has a comparable attack surface to OpenSSL+liboqs.

---

### Threat: Zero-Day in Single Component

**Scenario:** Critical vulnerability discovered in Ed25519

| Implementation | Impact | Mitigation |
|----------------|--------|------------|
| OpenSSL+liboqs | Signatures may be forged | Relies on ML-DSA-65 |
| AMA Cryptography | Signatures may be forged | **Also has HMAC + SHA3 + HKDF layers** |

**Winner:** **AMA Cryptography** - defense-in-depth means attack requires breaking multiple independent systems.

---

## Security Properties Comparison

### Cryptographic Strength

| Property | OpenSSL+liboqs | AMA Cryptography | Analysis |
|----------|----------------|--------------|----------|
| **Classical Security** | 128-bit (Ed25519) | 128-bit (Ed25519) | **Equivalent** |
| **Quantum Security** | 192-bit (ML-DSA-65) | 192-bit (ML-DSA-65) | **Equivalent** |
| **Hash Security** | N/A | 128-bit (SHA3-256) | **AMA Cryptography adds integrity layer** |
| **MAC Security** | N/A | 256-bit (HMAC-SHA3-256) | **AMA Cryptography adds authentication** |
| **AEAD** | ✅ AES-256-GCM (AES-NI) | ✅ AES-256-GCM + ChaCha20-Poly1305 (native C) | AMA offers constant-time AEAD alternative |

**Overall:** Cryptographic strength is **equivalent** for signatures, but AMA Cryptography adds **additional security properties** through extra layers.

---

### Implementation Assurance

| Property | OpenSSL+liboqs | AMA Cryptography | Winner |
|----------|----------------|--------------|--------|
| **External Audit** | ✅ Multiple audits | ❌ None | **OpenSSL+liboqs** |
| **FIPS Certification** | ✅ Available | ❌ No | **OpenSSL+liboqs** |
| **Battle Testing** | ✅ Years in production | ⚠️ v2.0 (community-tested) | **OpenSSL+liboqs** |
| **Bug Bounty** | ✅ Active programs | ❌ None | **OpenSSL+liboqs** |
| **Code Review** | ✅ Public, extensive | ⚠️ Self-review | **OpenSSL+liboqs** |

**Verdict:** **OpenSSL+liboqs has significantly better implementation assurance.**

---

## Honest Security Assessment

### When AMA Cryptography is MORE Secure

1. ✅ **Against algorithm breaks** - Multiple independent layers mean breaking one doesn't compromise the system
2. ✅ **Against zero-days** - Defense-in-depth means attacker needs multiple exploits
3. ✅ **For integrity verification** - SHA3-256 + HMAC add layers not present in basic hybrid
4. ✅ **For anomaly detection** - 3R monitoring can detect attacks OpenSSL+liboqs would miss
5. ✅ **For key management** - Integrated HKDF with domain separation prevents key reuse
6. ✅ **For adaptive response** - Automated key rotation and algorithm switching on threat detection
7. ✅ **For hybrid KEM** - IND-CCA2 binding combiner ensures security if either component KEM holds

### When OpenSSL+liboqs is MORE Secure

1. ✅ **Against implementation bugs** - Extensively audited, battle-tested code
2. ✅ **Against side-channels** - Proven constant-time implementations
3. ✅ **For compliance** - FIPS 140-2 certification available
4. ✅ **For trust** - External audits by cryptography experts
5. ✅ **For simplicity** - Smaller codebase = fewer places for bugs

### The Nuanced Truth

**AMA Cryptography provides ARCHITECTURAL security advantages:**
- More security layers (6 vs 2)
- Runtime monitoring with adaptive posture response
- Better defense against multi-vector attacks
- Zero core dependencies (all native C implementations)
- Hybrid KEM combiner with IND-CCA2 binding
- Automated key rotation and algorithm switching

**OpenSSL+liboqs provides IMPLEMENTATION security advantages:**
- Proven correctness through audits
- Simpler, less code to analyze
- FIPS certification path
- Hardware-accelerated AES (AES-NI)

---

## Production Security Recommendations

### Use OpenSSL+liboqs when:
- ✓ You need FIPS 140-2 certification
- ✓ You require externally audited cryptography
- ✓ You want the simplest, most proven implementation
- ✓ You will implement your own defense-in-depth layers
- ✓ Regulatory compliance requires certified libraries

### Use AMA Cryptography when:
- ✓ You accept the **lack of external audit** risk
- ✓ You need integrated defense-in-depth (6 layers)
- ✓ You want runtime security monitoring (3R) with adaptive posture response
- ✓ You need a zero-dependency cryptographic stack (all native C)
- ✓ You value architectural security over implementation maturity
- ✓ You can wait for **future external audit** before production use

### CRITICAL Security Requirements for AMA Cryptography

Before using AMA Cryptography in production:

1. **MANDATORY External Audit**
   - Independent cryptographic review
   - Side-channel analysis
   - Penetration testing

2. **MANDATORY HSM Usage**
   - FIPS 140-2 Level 3+ for all private keys
   - No software-only key storage

3. **MANDATORY Constant-Time Verification**
   - Run dudect on target hardware
   - Verify no timing leakage

4. **RECOMMENDED Code Review**
   - Third-party security code review
   - Fuzzing and formal verification

---

## Bottom Line

**Is AMA Cryptography safer or more secure?**

**Architecturally:** YES
- 6 security layers vs 2
- Runtime monitoring
- Defense-in-depth design

**Implementation-wise:** NO (currently)
- Lacks external audit
- No FIPS certification
- Less battle-tested

**For Production Use:**
- **OpenSSL+liboqs:** Ready now (with caveats)
- **AMA Cryptography:** Ready **AFTER external audit + FIPS certification**

**The Honest Answer:**

AMA Cryptography **COULD BE more secure** if it receives proper external auditing. The architecture provides genuine security advantages. But **as it stands**, OpenSSL+liboqs is **more trustworthy** for production because it has been extensively audited and battle-tested.

**Security is not just about features - it's about proven correctness.**

---

## References

1. OpenSSL Security Audits: https://www.openssl.org/policies/secpolicy.html
2. liboqs NIST Submission: https://openquantumsafe.org/
3. AMA Cryptography Security Analysis: SECURITY_ANALYSIS.md
4. FIPS 140-2 Requirements: https://csrc.nist.gov/publications/detail/fips/140/2/final

---

**Generated:** 2026-03-10
**Copyright:** 2025-2026 Steel Security Advisors LLC
**License:** Apache License 2.0
