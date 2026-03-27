# Cryptographic Algorithms - AMA Cryptography

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 2.1 |
| Last Updated | 2026-03-10 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

This document provides an overview of the cryptographic algorithms used in AMA Cryptography, their security properties, and references to official specifications.

> **Design Note:** AMA Cryptography is built exclusively from standardized cryptographic primitives (NIST FIPS, IETF RFC) — no custom ciphers, hash functions, or signature schemes. The composition protocol (how primitives are combined into the multi-layer defense architecture, double-helix key evolution, and adaptive posture system) is an original design by Steel Security Advisors LLC. AMA Cryptography is a standalone cryptographic library for any Python project, AI agent, or AI system requiring quantum-resistant security. [Mercury Agent](https://github.com/Steel-SecAdv-LLC/Mercury-Agent) is one consumer, but the library is designed for general-purpose independent use.

## Algorithm Summary

| Algorithm | Type | Security Level | Standard | Implementation | Status |
|-----------|------|----------------|----------|----------------|--------|
| ML-DSA-65 (Dilithium) | Digital Signature | NIST Level 3 (192-bit) | FIPS 204 | Native C (`ama_dilithium.c`) | Primary PQC |
| ML-KEM-1024 (Kyber) | Key Encapsulation | NIST Level 5 (256-bit) | FIPS 203 | Native C (`ama_kyber.c`) | Backend Ready |
| SPHINCS+-SHA2-256f | Hash-Based Signature | NIST Level 5 (256-bit) | FIPS 205 | Native C (`ama_sphincs.c`) | Backend Ready |
| AES-256-GCM | Authenticated Encryption | 256-bit | SP 800-38D | Native C (`ama_aes_gcm.c`) | Full |
| Ed25519 | Digital Signature | 128-bit classical | RFC 8032 | Native C (`ama_ed25519.c`) | Classical + Hybrid |
| SHA3-256 | Hash Function | 128-bit collision | FIPS 202 | Native C (`ama_sha3.c`) | Content Hashing |
| HMAC-SHA3-256 | MAC | 256-bit | RFC 2104 | Native C | Authentication |
| HKDF-SHA3-256 | Key Derivation | 256-bit | RFC 5869 | Native C (`ama_hkdf.c`) | Key Management |
| X25519 | Key Exchange | 128-bit classical | RFC 7748 | Native C (`ama_x25519.c`) | Hybrid KEM |
| ChaCha20-Poly1305 | Authenticated Encryption | 256-bit | RFC 8439 | Native C (`ama_chacha20poly1305.c`) | Alternative AEAD |
| Argon2id | Password Hashing | Memory-hard | RFC 9106 | Native C (`ama_argon2.c`) | Key Derivation |
| secp256k1 | Elliptic Curve | 128-bit classical | SEC 2 | Native C (`ama_secp256k1.c`) | HD Key Derivation |

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
- Quantum attack cost: ~2^190 operations (Grover-accelerated BKZ)

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

Ed25519 provides classical digital signatures for hybrid mode (Ed25519 + ML-DSA-65).

**Key Sizes:**
- Public Key: 32 bytes
- Private Key: 32 bytes (seed)
- Signature: 64 bytes

**Security Properties:**
- 128-bit classical security
- Deterministic signatures (no RNG needed for signing)
- NOT quantum-resistant (vulnerable to Shor's algorithm)

**Standard:** RFC 8032

**Implementation (v2.0):** Native C (`ama_ed25519.c`) with:
- Dedicated `fe25519_sq()` field squaring (~55 muls vs ~100, based on SUPERCOP ref10)
- C11 `_Atomic` with `memory_order_acquire`/`memory_order_release` for thread-safe initialization
- Sign/verify roundtrip validated against RFC 8032 Test Vector 1 (12 tests)
- Fallback to volatile for pre-C11 compilers (MSVC compatibility)

**Usage:** Classical signatures and hybrid signatures (Ed25519 + ML-DSA-65).

### AES-256-GCM

AES-256-GCM provides authenticated encryption with associated data (AEAD).

**Parameters:**
- Key: 256 bits
- IV/Nonce: 96 bits
- Tag: 128 bits

**Security Properties:**
- IND-CPA confidentiality under AES-256 PRP assumption
- INT-CTXT authenticity with forgery probability ≤ 2^-128
- 128-bit quantum security (Grover's bound)

**Standard:** NIST SP 800-38D

**Implementation:** Native C (`ama_aes_gcm.c`). Uses 256-byte lookup table S-box — **not** constant-time with respect to cache-timing in shared-tenant environments. For such deployments, hardware AES-NI or bitsliced implementations are recommended.

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

## Hybrid Constructions

### Hybrid Signature Scheme

AMA Cryptography supports hybrid signatures combining Ed25519 and ML-DSA-65:

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

### Hybrid KEM Combiner

AMA Cryptography supports hybrid key encapsulation combining a classical KEM with a PQC KEM via a binding construction (Bindel et al., PQCrypto 2019):

```
combined_ss = HKDF-SHA3-256(
    salt = classical_ct || pqc_ct,         # Ciphertext binding
    ikm  = classical_ss || pqc_ss,         # Combined key material
    info = label || classical_pk || pqc_pk  # Context binding
)
```

**Security:** IND-CCA2 secure if **either** component KEM remains unbroken. Ciphertext binding prevents mix-and-match attacks.

**Implementation:** `ama_cryptography/hybrid_combiner.py` — uses native C HKDF-SHA3-256 with Python fallback.

## Defense-in-Depth Layers

AMA Cryptography applies multiple independent cryptographic layers. Core cryptographic operations (the defense layers an attacker must defeat) are distinguished from supporting infrastructure:

**Core Cryptographic Operations:**
1. **SHA3-256 Hash** - Content integrity with 128-bit collision resistance (FIPS 202)
2. **HMAC-SHA3-256** - Keyed message authentication using HKDF-derived key
3. **Ed25519 Signature** - Classical digital signature with 128-bit security (RFC 8032)
4. **ML-DSA-65 Signature** - Quantum-resistant digital signature with 192-bit security (FIPS 204)

**Supporting Infrastructure:**
- **Canonical Encoding** - Deterministic length-prefixed input normalization (prevents concatenation attacks)
- **HKDF-SHA3-256** - Key derivation ensuring cryptographic key independence (RFC 5869)
- **RFC 3161 Timestamp** - Third-party temporal proof of existence (optional)

**Security Bound:** Overall security is bounded by the weakest core layer (~128-bit classical, ~192-bit quantum when ML-DSA-65 is enforced). Defense-in-depth ensures continued protection if any single layer is compromised. See [SECURITY.md](SECURITY.md) for detailed analysis.

### Hash Algorithm Note: RFC 3161 Timestamps

The optional RFC 3161 timestamp add-on uses **SHA-256** instead of SHA3-256 for the TSA request. This is a deliberate design choice for interoperability:

- Most RFC 3161 TSA services (FreeTSA, DigiCert, GlobalSign) do not support SHA3-256
- The timestamp token provides proof-of-existence at a specific time
- The SHA-256 hash is only used for the TSA request, not for package integrity
- Package integrity is protected by SHA3-256 in layers 1-4

This does not weaken security because:
1. The timestamp proves when the package existed, not its integrity
2. Package integrity is independently verified by SHA3-256, HMAC, and signatures
3. SHA-256 remains secure for collision resistance (no practical attacks)

## Implementation Notes

### Zero-Dependency Architecture (v2.0)

All cryptographic primitives are implemented natively in C with zero external dependencies:

| Source File | Algorithm | Standard |
|-------------|-----------|----------|
| `ama_sha3.c` | SHA3-256, SHAKE128/256 | FIPS 202 |
| `ama_hkdf.c` | HKDF-SHA3-256 | RFC 5869 |
| `ama_ed25519.c` | Ed25519 (C11 atomics) | RFC 8032 |
| `ama_aes_gcm.c` | AES-256-GCM | SP 800-38D |
| `ama_dilithium.c` | ML-DSA-65 | FIPS 204 |
| `ama_kyber.c` | ML-KEM-1024 | FIPS 203 |
| `ama_sphincs.c` | SPHINCS+-SHA2-256f | FIPS 205 |
| `ama_consttime.c` | Constant-time utilities | — |
| `ama_platform_rand.c` | Platform CSPRNG | — |
| `ama_x25519.c` | X25519 key exchange | RFC 7748 |
| `ama_chacha20poly1305.c` | ChaCha20-Poly1305 AEAD | RFC 8439 |
| `ama_argon2.c` | Argon2id password hashing | RFC 9106 |
| `ama_secp256k1.c` | secp256k1 curve operations | SEC 2 |
| `ama_aes_bitsliced.c` | Bitsliced AES S-box | — (optional) |

### Constant-Time Operations

The C core (`src/c/ama_consttime.c`) provides constant-time utilities:
- `ama_consttime_memcmp()` - Constant-time memory comparison (XOR accumulation)
- `ama_consttime_swap()` - Conditional buffer swap (bitwise masking)
- `ama_consttime_lookup()` - Table lookup (full table scan)
- `ama_consttime_copy()` - Conditional copy (bitwise masking)
- `ama_secure_memzero()` - Compiler-proof memory scrubbing

All verified via dudect-style timing analysis (see [CONSTANT_TIME_VERIFICATION.md](CONSTANT_TIME_VERIFICATION.md)).

### Key Zeroization

All key material is securely wiped after use via `secure_wipe()` which:
1. Overwrites memory with zeros
2. Uses memory barriers to prevent compiler optimization
3. Verifies the wipe completed

### Backend Selection

PQC is provided by the native C library (`libama_cryptography.so`):
- **ML-DSA-65** - NIST KAT validated (10/10 pass, FIPS 204)
- **ML-KEM-1024** - NIST KAT validated (10/10 pass, FIPS 203)
- **SPHINCS+-SHA2-256f** - Native C (FIPS 205)

Check availability with:
```python
from ama_cryptography.pqc_backends import get_pqc_status
status = get_pqc_status()
print(f"Dilithium: {status.dilithium_available}")
print(f"Kyber: {status.kyber_available}")
print(f"SPHINCS+: {status.sphincs_available}")
```

### Adaptive Cryptographic Posture

The adaptive posture system (`ama_cryptography/adaptive_posture.py`) bridges the 3R monitor with runtime security responses:

| Threat Level | Score | Response |
|-------------|-------|----------|
| NOMINAL | 0.0-0.3 | No action |
| ELEVATED | 0.3-0.6 | Increase monitoring |
| HIGH | 0.6-0.8 | Rotate keys |
| CRITICAL | 0.8-1.0 | Rotate keys + switch algorithm + alert |

Algorithm strength ordering: ED25519 (0) → ML_DSA_65 (1) → SPHINCS_256F (2) → HYBRID_SIG (3)

## Phase 2 Cryptographic Primitives

### X25519 (Diffie-Hellman Key Exchange)

X25519 provides elliptic curve Diffie-Hellman key exchange on Curve25519.

**Parameters:**
- Public Key: 32 bytes
- Private Key: 32 bytes (clamped scalar)
- Shared Secret: 32 bytes

**Security Properties:**
- 128-bit classical security
- NOT quantum-resistant (vulnerable to Shor's algorithm)
- Used in hybrid KEM combiner (classical component alongside Kyber-1024)

**Standard:** RFC 7748

**Implementation:** Native C (`ama_x25519.c`)

### ChaCha20-Poly1305 (Alternative AEAD)

ChaCha20-Poly1305 provides authenticated encryption as an alternative to AES-256-GCM, particularly suitable for environments where AES hardware acceleration is unavailable or cache-timing resistance is required.

**Parameters:**
- Key: 256 bits
- Nonce: 96 bits
- Tag: 128 bits

**Security Properties:**
- IND-CPA confidentiality under ChaCha20 PRP assumption
- INT-CTXT authenticity
- Constant-time by design (no table lookups, no cache-timing concerns)
- 128-bit quantum security (Grover's bound)

**Standard:** RFC 8439

**Implementation:** Native C (`ama_chacha20poly1305.c`). Software-only, constant-time — recommended for shared-tenant environments where AES cache-timing is a concern.

### Argon2id (Password Hashing)

Argon2id provides memory-hard password hashing, combining data-dependent and data-independent memory access patterns for resistance against both GPU and side-channel attacks.

**Parameters:**
- Memory cost: Configurable (recommended: 64 MiB+)
- Time cost: Configurable (recommended: 3+ iterations)
- Parallelism: Configurable
- Output: Variable length (recommended: 32 bytes)

**Security Properties:**
- Memory-hard: Resists GPU/ASIC brute-force attacks
- Hybrid mode: Data-independent first pass + data-dependent second pass
- Winner of the Password Hashing Competition (2015)

**Standard:** RFC 9106

**Implementation:** Native C (`ama_argon2.c`)

### secp256k1 (Elliptic Curve Operations)

secp256k1 provides elliptic curve operations supporting BIP32-compliant hierarchical deterministic (HD) key derivation.

**Parameters:**
- Private Key: 32 bytes (scalar)
- Public Key: 33 bytes (compressed) or 65 bytes (uncompressed)
- Curve Order: 2^256 - 432420386565659656852420866394968145599

**Security Properties:**
- 128-bit classical security
- NOT quantum-resistant
- Used for HD key derivation (BIP32 compliance)

**Standard:** SEC 2 (Standards for Efficient Cryptography)

**Implementation:** Native C (`ama_secp256k1.c`)

## References

1. NIST FIPS 202 (2015). "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions."
2. NIST FIPS 203 (2024). "Module-Lattice-Based Key-Encapsulation Mechanism Standard."
3. NIST FIPS 204 (2024). "Module-Lattice-Based Digital Signature Standard."
4. NIST FIPS 205 (2024). "Stateless Hash-Based Digital Signature Standard."
5. RFC 2104 (1997). "HMAC: Keyed-Hashing for Message Authentication."
6. RFC 5869 (2010). "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)."
7. RFC 8032 (2017). "Edwards-Curve Digital Signature Algorithm (EdDSA)."
8. RFC 3161 (2001). "Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)."
9. RFC 7748 (2016). "Elliptic Curves for Security."
10. RFC 8439 (2018). "ChaCha20 and Poly1305 for IETF Protocols."
11. RFC 9106 (2021). "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications."

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture and design
- [SECURITY.md](SECURITY.md) - Detailed security analysis and proofs
- [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) - Deployment and integration guide
