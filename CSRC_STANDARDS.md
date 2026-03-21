# CSRC Standards Mapping — AMA Cryptography Library

**Version:** 2.0
**Date:** 2026-03-18
**Organization:** Steel Security Advisors LLC
**Author:** Andrew E. A.

This document maps every cryptographic primitive implemented in AMA Cryptography
to its governing standard, parameter set, and authoritative source URL. Only
algorithms with shipping code are listed — no aspirational entries.

---

## Section 1 — Algorithm-to-Standard Mapping

### 1.1 NIST-Standardized Algorithms (FIPS / SP Publications)

| Algorithm | Standard | Parameter Set | Status | CSRC URL |
|-----------|----------|---------------|--------|----------|
| SHA3-256 | FIPS 202 | SHA3-256 (r=1088, c=512, d=256) | Final | https://csrc.nist.gov/pubs/fips/202/final |
| SHA3-512 | FIPS 202 | SHA3-512 (r=576, c=1024, d=512) | Final | https://csrc.nist.gov/pubs/fips/202/final |
| SHAKE128 | FIPS 202 | SHAKE128 (r=1344, c=256, XOF) | Final | https://csrc.nist.gov/pubs/fips/202/final |
| SHAKE256 | FIPS 202 | SHAKE256 (r=1088, c=512, XOF) | Final | https://csrc.nist.gov/pubs/fips/202/final |
| SHA-256 | FIPS 180-4 | SHA-256 (256-bit digest) | Final | https://csrc.nist.gov/pubs/fips/180-4/upd1/final |
| HMAC-SHA-256 | FIPS 198-1 | HMAC with SHA-256 (key ≤ block size 64 B) | Final | https://csrc.nist.gov/pubs/fips/198-1/final |
| AES-256-GCM | NIST SP 800-38D | AES-256 key (256-bit), 96-bit nonce, 128-bit tag | Final | https://csrc.nist.gov/pubs/sp/800/38/d/final |
| ML-KEM-1024 (Kyber-1024) | FIPS 203 | ML-KEM-1024 (k=4, n=256, q=3329) | Final | https://csrc.nist.gov/pubs/fips/203/final |
| ML-DSA-65 (Dilithium3) | FIPS 204 | ML-DSA-65 (k=6, l=5, η=4, γ₁=2¹⁹) | Final | https://csrc.nist.gov/pubs/fips/204/final |
| SLH-DSA-SHA2-256f (SPHINCS+-256f) | FIPS 205 | SLH-DSA-SHA2-256f (n=32, h=68, d=17, w=16, fast) | Final | https://csrc.nist.gov/pubs/fips/205/final |

### 1.2 RFC-Only Algorithms (Not NIST Publications)

The following algorithms are standardized via IETF RFCs and are **not** NIST
FIPS or SP publications. They are included for completeness.

| Algorithm | RFC | Parameter Set | Notes |
|-----------|-----|---------------|-------|
| ChaCha20-Poly1305 | RFC 8439 | 256-bit key, 96-bit nonce, 128-bit tag | IETF AEAD construction; not a NIST publication |
| Ed25519 | RFC 8032 | Curve25519, SHA-512, 256-bit keys, 512-bit signatures | Pure EdDSA (no prehash); not a NIST publication |
| X25519 | RFC 7748 | Curve25519, 256-bit keys | Diffie-Hellman key exchange; not a NIST publication |
| Argon2id | RFC 9106 | Configurable: t_cost, m_cost, parallelism, tag length | Memory-hard KDF; not a NIST publication |
| HKDF (with SHA3-256) | RFC 5869 | Extract-then-Expand with HMAC-SHA3-256, max output 8160 B | KDF construction; not a NIST publication. Uses SHA3-256 as the underlying hash |
| secp256k1 | SEC 2 v2 / BIP-32 | 256-bit prime field, compressed SEC1 public keys (33 B) | Certicom/Bitcoin curve; not a NIST publication. Used for BIP-32 HD key derivation |

---

## Section 2 — Hybrid Construction: NIST IR 8547 Alignment

### 2.1 Hybrid KEM: X25519 + ML-KEM-1024

AMA Cryptography implements a hybrid Key Encapsulation Mechanism combining a
classical Diffie-Hellman component with a post-quantum lattice-based KEM.

| Property | Value |
|----------|-------|
| **Classical component** | X25519 (RFC 7748) |
| **PQC component** | ML-KEM-1024 (FIPS 203) |
| **Combiner** | HKDF-SHA3-256 (RFC 5869 construction with SHA3-256) |
| **Ciphertext binding** | Yes — `salt = classical_ct \|\| pqc_ct` |
| **Public-key binding** | Yes — `info = label \|\| classical_pk \|\| pqc_pk` |
| **Security claim** | IND-CCA2 if **either** component KEM is IND-CCA2 secure |
| **Combined public key size** | 1600 bytes (32 B X25519 + 1568 B ML-KEM-1024) |
| **Combined ciphertext size** | 1600 bytes (32 B X25519 ephemeral + 1568 B ML-KEM-1024) |
| **Shared secret size** | 32 bytes |
| **Domain separation label** | `ama-hybrid-kem-v2` |
| **Implementation** | `ama_cryptography/hybrid_combiner.py` → `HybridCombiner` |

**NIST IR 8547 Reference:** NIST Internal Report 8547, "Transition to
Post-Quantum Cryptography Standards" (November 2024), Section 6, recommends
transitional hybrid combinations pairing a classical algorithm with a
NIST-approved PQC algorithm. The X25519 + ML-KEM-1024 construction follows
this guidance: the classical component provides backward compatibility and
established security assurance, while the PQC component provides quantum
resistance. The binding combiner ensures that compromise of one component does
not weaken the overall construction.

### 2.2 Hybrid Signature: Ed25519 + ML-DSA-65

AMA Cryptography implements a hybrid digital signature scheme combining a
classical EdDSA signature with a post-quantum lattice-based signature.

| Property | Value |
|----------|-------|
| **Classical component** | Ed25519 (RFC 8032) |
| **PQC component** | ML-DSA-65 (FIPS 204) |
| **Construction** | Concatenated dual signatures — both must verify for acceptance |
| **Security claim** | EUF-CMA if **either** component scheme is EUF-CMA secure |
| **Combined public key size** | 1984 bytes (32 B Ed25519 + 1952 B ML-DSA-65) |
| **Combined signature size** | 3373 bytes (64 B Ed25519 + 3309 B ML-DSA-65) |
| **Implementation** | `ama_cryptography/crypto_api.py` → `HybridSignatureProvider` |

**NIST IR 8547 Reference:** Section 6 of NIST IR 8547 similarly applies to
hybrid signature constructions. The concatenated dual-signature approach
ensures that an attacker must forge **both** signatures to break the scheme,
preserving security during the transition period when the classical algorithm
may become vulnerable to quantum cryptanalysis.

---

## Section 3 — What Is NOT Claimed (CAVP Disclaimer)

### 3.1 Statement of Compliance Scope

This library provides **algorithm-compliant implementations** of the
cryptographic primitives listed above. The implementations follow the
specifications in the referenced FIPS, SP, and RFC documents.

**The following is explicitly stated:**

**(a)** This is an algorithm-compliant implementation. It is **not**
CAVP-validated. The implementation has been tested against NIST-published
test vectors for self-attestation purposes only.

**(b)** **No CAVP certificate has been issued** for any algorithm in this
library. The library does not appear on the NIST Cryptographic Algorithm
Validation Program validated algorithms list.

**(c)** **No CMVP certificate has been issued.** This library has not been
submitted to or evaluated by the Cryptographic Module Validation Program.

**(d)** **Meets FIPS 140-3 Security Level 1 technical requirements**
(self-tests, integrity verification, error state machine).
**NOT formally CAVP/CMVP validated.** This library has not undergone
formal FIPS 140-3 evaluation by an accredited laboratory.

**(e)** **What CAVP/CMVP validation would require:**

1. **Accredited NVLAP CST Laboratory Engagement:** A laboratory accredited
   under the National Voluntary Laboratory Accreditation Program (NVLAP)
   for Cryptographic and Security Testing (CST) must perform the validation
   testing. The laboratory must hold current accreditation from NIST.

2. **Algorithm-Specific ACVP Test Vector Suites:** Each algorithm must be
   validated using the Automated Cryptographic Validation Protocol (ACVP)
   test vectors. This includes Algorithm Functional Tests (AFT), Monte
   Carlo Tests (MCT), and any algorithm-specific test types defined in
   the ACVP specification for that algorithm.

3. **Formal Cryptographic Module Boundary Definition:** A precise definition
   of the cryptographic module boundary must be established, delineating
   which software components, hardware interfaces, and data paths constitute
   the module. This includes identification of all critical security
   parameters (CSPs) and public security parameters (PSPs).

4. **Operational Environment Documentation:** Complete documentation of the
   operating environment(s) in which the module operates, including
   operating system, compiler, hardware platform, and any relevant
   configuration settings that affect cryptographic operation.

5. **Ongoing Compliance Obligations:** After initial validation, the module
   is subject to periodic review, sunset dates on algorithm approvals,
   and must be re-validated if the implementation or operational
   environment changes materially. CMVP validation certificates have a
   defined validity period and historical algorithm transitions (e.g.,
   3DES deprecation) require timely migration.
