# Cryptographic Algorithms - AMA Cryptography ♱

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 1.1 |
| Last Updated | 2026-01-09 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

This document provides an overview of the cryptographic algorithms used in AMA Cryptography ♱ (AG♱), their security properties, and references to official specifications.

## Algorithm Summary

| Algorithm | Type | Security Level | Standard | Status |
|-----------|------|----------------|----------|--------|
| ML-DSA-65 (Dilithium) | Digital Signature | NIST Level 3 (192-bit) | FIPS 204 | Primary PQC |
| Kyber-1024 | Key Encapsulation | NIST Level 5 (256-bit) | FIPS 203 | Backend Ready |
| SPHINCS+-SHA2-256f | Hash-Based Signature | NIST Level 5 (256-bit) | FIPS 205 | Backend Ready |
| Ed25519 | Digital Signature | 128-bit classical | RFC 8032 | Classical Fallback |
| SHA3-256 | Hash Function | 128-bit collision | FIPS 202 | Content Hashing |
| HMAC-SHA3-256 | MAC | 256-bit | RFC 2104 | Authentication |
| HKDF-SHA3-256 | Key Derivation | 256-bit | RFC 5869 | Key Management |

## Post-Quantum Cryptography (PQC)

### ML-DSA-65 (CRYSTALS-Dilithium)

ML-DSA-65 is the primary post-quantum signature algorithm, providing 192-bit quantum security based on the Module Learning With Errors (MLWE) problem.

**Key Sizes (FIPS 204):**
- Public Key: 1,952 bytes
- Private Key: 4,032 bytes
- Signature: 3,309 bytes

**Security Properties:**
- EUF-CMA secure in the Quantum Random Oracle Model (QROM)
- Based on MLWE hardness assumption
- Quantum attack cost: ~2^160 operations (Grover-accelerated BKZ)

**Standard:** NIST FIPS 204 (2024)

**Reference:**
> Ducas, L., et al. (2021). "CRYSTALS-Dilithium: Algorithm Specifications and Supporting Documentation (Version 3.1)." NIST PQC Round 3 Submission.

### Kyber-1024 (ML-KEM)

Kyber-1024 provides IND-CCA2 secure key encapsulation for establishing shared secrets.

**Key Sizes:**
- Public Key: 1,568 bytes
- Secret Key: 3,168 bytes
- Ciphertext: 1,568 bytes
- Shared Secret: 32 bytes

**Security Properties:**
- IND-CCA2 secure in the QROM
- Based on MLWE hardness assumption
- NIST Security Level 5 (256-bit quantum)

**Standard:** NIST FIPS 203 (2024)

**Integration Status:** Backend implemented in `ama_cryptography/pqc_backends.py`. Integration into main signing workflow pending.

### SPHINCS+-SHA2-256f-simple

SPHINCS+ provides stateless hash-based signatures with security based only on hash function properties.

**Key Sizes:**
- Public Key: 64 bytes
- Secret Key: 128 bytes
- Signature: 49,856 bytes

**Security Properties:**
- EUF-CMA secure based on hash function security
- No state management required (unlike XMSS/LMS)
- Conservative security assumptions

**Standard:** NIST FIPS 205 (2024)

**Integration Status:** Backend implemented in `ama_cryptography/pqc_backends.py`. Integration into main signing workflow pending.

## Classical Cryptography

### Ed25519

Ed25519 provides classical digital signatures as a fallback when PQC libraries are unavailable.

**Key Sizes:**
- Public Key: 32 bytes
- Private Key: 32 bytes (seed)
- Signature: 64 bytes

**Security Properties:**
- 128-bit classical security
- Deterministic signatures (no RNG needed for signing)
- NOT quantum-resistant (vulnerable to Shor's algorithm)

**Standard:** RFC 8032

**Usage:** Classical fallback and hybrid signatures (Ed25519 + ML-DSA-65).

### SHA3-256

SHA3-256 is used for content hashing throughout the system.

**Properties:**
- 256-bit output
- 128-bit collision resistance
- 256-bit preimage resistance
- Sponge construction (Keccak)

**Standard:** NIST FIPS 202

### HMAC-SHA3-256

HMAC with SHA3-256 provides message authentication.

**Properties:**
- 256-bit tag
- PRF security under key secrecy
- Forgery resistance: 2^256 operations

**Standard:** RFC 2104 (HMAC construction) with SHA3-256

### HKDF-SHA3-256

HKDF is used for key derivation from master secrets.

**Properties:**
- Extract-then-Expand paradigm
- Domain separation via `info` parameter
- Cryptographically independent derived keys

**Standard:** RFC 5869

## Hybrid Signature Scheme

AG♱ supports hybrid signatures combining Ed25519 and ML-DSA-65:

```
HybridSign(message, sk_ed25519, sk_dilithium):
    sig_ed25519 = Ed25519.Sign(message, sk_ed25519)
    sig_dilithium = ML-DSA-65.Sign(message, sk_dilithium)
    return sig_ed25519 || sig_dilithium

HybridVerify(message, signature, pk_ed25519, pk_dilithium):
    sig_ed25519, sig_dilithium = Split(signature)
    return Ed25519.Verify(message, sig_ed25519, pk_ed25519) AND
           ML-DSA-65.Verify(message, sig_dilithium, pk_dilithium)
```

**Security:** Secure against both classical and quantum adversaries. Both signatures must verify for acceptance.

## Defense-in-Depth Layers

AG♱ applies six independent cryptographic layers:

1. **Canonical Encoding** - Length-prefixed encoding prevents concatenation attacks
2. **SHA3-256 Hash** - Content integrity with collision resistance
3. **HMAC-SHA3-256** - Symmetric authentication with shared key
4. **Ed25519 Signature** - Classical asymmetric authentication
5. **ML-DSA-65 Signature** - Quantum-resistant asymmetric authentication
6. **RFC 3161 Timestamp** - Third-party proof of existence (optional)

**Security Bound:** Overall security is bounded by the weakest layer (~128-bit classical, ~192-bit quantum when Dilithium is enforced). Defense-in-depth ensures continued protection if any single layer is compromised. See [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) for detailed analysis.

### Hash Algorithm Note: RFC 3161 Timestamps

The RFC 3161 timestamp layer uses **SHA-256** instead of SHA3-256 for the TSA request. This is a deliberate design choice for interoperability:

- Most RFC 3161 TSA services (FreeTSA, DigiCert, GlobalSign) do not support SHA3-256
- The timestamp token provides proof-of-existence at a specific time
- The SHA-256 hash is only used for the TSA request, not for package integrity
- Package integrity is protected by SHA3-256 in layers 2-5

This does not weaken security because:
1. The timestamp proves when the package existed, not its integrity
2. Package integrity is independently verified by SHA3-256, HMAC, and signatures
3. SHA-256 remains secure for collision resistance (no practical attacks)

## Implementation Notes

### Constant-Time Operations

The C core (`src/c/ama_consttime.c`) provides constant-time utilities:
- `ava_ct_memcmp()` - Constant-time memory comparison
- `ava_ct_select()` - Constant-time conditional selection
- `ava_ct_is_zero()` - Constant-time zero check

These prevent timing side-channel attacks on sensitive comparisons.

### Key Zeroization

All key material is securely wiped after use via `secure_wipe()` which:
1. Overwrites memory with zeros
2. Uses memory barriers to prevent compiler optimization
3. Verifies the wipe completed

### Backend Selection

PQC is provided by the native C library:
1. **Native C library** - Full native implementations of ML-DSA-65, Kyber-1024, SPHINCS+-256f (NIST FIPS 203/204/205 KAT validated)

Check availability with:
```python
from ama_cryptography.pqc_backends import get_pqc_status
status = get_pqc_status()
print(f"Dilithium: {status.dilithium_available}")
print(f"Kyber: {status.kyber_available}")
```

## References

1. NIST FIPS 202 (2015). "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions."
2. NIST FIPS 203 (2024). "Module-Lattice-Based Key-Encapsulation Mechanism Standard."
3. NIST FIPS 204 (2024). "Module-Lattice-Based Digital Signature Standard."
4. NIST FIPS 205 (2024). "Stateless Hash-Based Digital Signature Standard."
5. RFC 2104 (1997). "HMAC: Keyed-Hashing for Message Authentication."
6. RFC 5869 (2010). "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)."
7. RFC 8032 (2017). "Edwards-Curve Digital Signature Algorithm (EdDSA)."
8. RFC 3161 (2001). "Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)."

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture and design
- [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) - Detailed security analysis and proofs
- [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) - Deployment and integration guide
