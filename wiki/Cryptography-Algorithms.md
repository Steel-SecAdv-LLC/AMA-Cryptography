# Cryptography Algorithms

Complete reference for all cryptographic algorithms used in AMA Cryptography, their security properties, key sizes, standards, and native C implementations.

> **Design Principle:** AMA Cryptography is built exclusively from standardized cryptographic primitives (NIST FIPS, IETF RFC). No custom ciphers, hash functions, or signature schemes. The composition protocol is an original design by Steel Security Advisors LLC.

---

## Algorithm Summary

| Algorithm | Type | Security Level | Standard | C Source | Status |
|-----------|------|---------------|----------|----------|--------|
| ML-DSA-65 (Dilithium) | Digital Signature | NIST Level 3 (192-bit quantum) | FIPS 204 | `ama_dilithium.c` | Primary PQC |
| ML-KEM-1024 (Kyber) | Key Encapsulation | NIST Level 5 (256-bit quantum) | FIPS 203 | `ama_kyber.c` | Available |
| SPHINCS+-SHA2-256f | Hash-Based Signature | NIST Level 5 (256-bit quantum) | FIPS 205 | `ama_sphincs.c` | Available |
| Ed25519 | Digital Signature | 128-bit classical | RFC 8032 | `ama_ed25519.c` | Classical + Hybrid |
| AES-256-GCM | Authenticated Encryption | 256-bit key / 128-bit quantum | SP 800-38D | `ama_aes_gcm.c` | Full |
| ChaCha20-Poly1305 | Authenticated Encryption | 256-bit key / 128-bit security | RFC 8439 | `ama_chacha20poly1305.c` | Full |
| SHA3-256 | Hash Function | 128-bit collision | FIPS 202 | `ama_sha3.c` | Full |
| HMAC-SHA3-256 | MAC | 256-bit PRF security | RFC 2104 | `ama_hkdf.c` | Full |
| HKDF-SHA3-256 | Key Derivation | 256-bit derived keys | RFC 5869 | `ama_hkdf.c` | Full |
| X25519 | Key Exchange | 128-bit classical | RFC 7748 | `ama_x25519.c` | Full |
| Argon2id | Password Hashing | Memory-hard KDF | RFC 9106 | `ama_argon2.c` | Full |
| secp256k1 | Elliptic Curve Ops | 128-bit classical | SEC 2 | `ama_secp256k1.c` | HD key derivation |

---

## Post-Quantum Cryptography

### ML-DSA-65 (CRYSTALS-Dilithium)

The **primary post-quantum signature algorithm** in AMA Cryptography.

| Property | Value |
|----------|-------|
| Standard | NIST FIPS 204 (2024) |
| Security Level | NIST Level 3 |
| Classical Security | ~2^170 operations |
| Quantum Security | ~2^190 operations (Grover-BKZ) |
| Public Key | 1,952 bytes |
| Secret Key | 4,032 bytes |
| Signature | 3,309 bytes |
| Hardness | Module Learning With Errors (MLWE) |
| Security Model | EUF-CMA in QROM |

**Performance (native C, 2026-04-06):**
- Key generation: ~0.18 ms (5,536 ops/sec)
- Signing: ~0.27 ms (3,639 ops/sec)
- Verification: ~0.15 ms (6,490 ops/sec)

**Usage:**
```python
from ama_cryptography.pqc_backends import (
    generate_dilithium_keypair,
    dilithium_sign,
    dilithium_verify,
)

pk, sk = generate_dilithium_keypair()
sig = dilithium_sign(b"message", sk)
assert dilithium_verify(b"message", sig, pk)
```

---

### ML-KEM-1024 (Kyber)

**Post-quantum key encapsulation mechanism** for establishing shared secrets.

| Property | Value |
|----------|-------|
| Standard | NIST FIPS 203 (2024) |
| Security Level | NIST Level 5 |
| Quantum Security | ~2^256 operations |
| Public Key | 1,568 bytes |
| Secret Key | 3,168 bytes |
| Ciphertext | 1,568 bytes |
| Shared Secret | 32 bytes |
| Hardness | Module Learning With Errors (MLWE) |
| Security Model | IND-CCA2 in QROM |

**Usage:**
```python
from ama_cryptography.pqc_backends import (
    generate_kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
)

pk, sk = generate_kyber_keypair()
ciphertext, shared_secret = kyber_encapsulate(pk)
recovered = kyber_decapsulate(ciphertext, sk)
assert recovered == shared_secret
```

---

### SPHINCS+-SHA2-256f

**Stateless hash-based signature scheme** — security based only on hash function properties (no lattice assumptions).

| Property | Value |
|----------|-------|
| Standard | NIST FIPS 205 (2024) |
| Security Level | NIST Level 5 |
| Quantum Security | ~2^256 operations |
| Public Key | 64 bytes |
| Secret Key | 128 bytes |
| Signature | 49,856 bytes |
| Hardness | SHA-256 collision/preimage resistance |
| State | Stateless (no key state required) |

**Usage:**
```python
from ama_cryptography.pqc_backends import (
    generate_sphincs_keypair,
    sphincs_sign,
    sphincs_verify,
)

pk, sk = generate_sphincs_keypair()
sig = sphincs_sign(b"message", sk)
assert sphincs_verify(b"message", sig, pk)
```

> **Note:** SPHINCS+ signatures are large (≈49 KB). Use ML-DSA-65 for most applications; SPHINCS+ provides a conservative fallback with no lattice assumptions.

---

## Classical Cryptography

### Ed25519

**Classical digital signature** providing compact signatures for hybrid schemes.

| Property | Value |
|----------|-------|
| Standard | RFC 8032 |
| Curve | Edwards25519 (twisted Edwards form) |
| Security | 128-bit classical (NOT quantum-resistant) |
| Public Key | 32 bytes |
| Secret Key | 32 bytes (seed) |
| Signature | 64 bytes |
| Signing | Deterministic (RFC 8032) |

**C Implementation Features (`ama_ed25519.c`):**
- Dedicated `fe25519_sq()` field squaring (~55 multiplications vs ~100)
- C11 `_Atomic` with `memory_order_acquire`/`memory_order_release` for thread-safe initialization
- Validated against RFC 8032 Test Vector 1 (12 test vectors)
- MSVC compatibility via volatile fallback for pre-C11 compilers

**Performance:**
- Key generation: ~0.12 ms (8,354 ops/sec)
- Signing: ~0.24 ms (4,248 ops/sec)
- Verification: ~0.25 ms (4,070 ops/sec)

**Usage:**
```python
from ama_cryptography.crypto_api import AsymmetricCryptoAlgorithm

algo = AsymmetricCryptoAlgorithm()
pk, sk = algo.generate_keypair()
sig = algo.sign(b"message", sk)
assert algo.verify(b"message", sig, pk)
```

---

### AES-256-GCM

**Authenticated encryption with associated data (AEAD)**.

| Property | Value |
|----------|-------|
| Standard | NIST SP 800-38D |
| Key | 256 bits |
| Nonce/IV | 96 bits |
| Authentication Tag | 128 bits |
| Security | 256-bit key, 128-bit quantum (Grover) |
| Forgery Probability | ≤ 2^-128 |

> **Side-Channel Note:** The default implementation uses a 256-byte lookup table S-box. This is **not** constant-time with respect to cache-timing in shared-tenant environments (cloud VMs, containers). For such deployments, use the bitsliced implementation: `-DAMA_AES_CONSTTIME=ON`.

**Usage:**
```python
from ama_cryptography.crypto_api import SymmetricCryptoAlgorithm
import os

algo = SymmetricCryptoAlgorithm()
key = os.urandom(32)
ciphertext = algo.encrypt(b"plaintext", key)
plaintext = algo.decrypt(ciphertext, key)
```

---

### ChaCha20-Poly1305

**Stream cipher-based AEAD** — constant-time by design, suitable for all environments.

| Property | Value |
|----------|-------|
| Standard | RFC 8439 |
| Key | 256 bits |
| Nonce | 96 bits |
| Tag | 128 bits |
| Security | 256-bit key, 128-bit security |
| Timing | Constant-time (no table lookups) |

ChaCha20-Poly1305 is preferred over AES-GCM in environments without hardware AES-NI or when constant-time guarantees are required without building with `AMA_AES_CONSTTIME=ON`.

---

### X25519 (ECDH)

**Elliptic-curve Diffie-Hellman key exchange**.

| Property | Value |
|----------|-------|
| Standard | RFC 7748 |
| Curve | Curve25519 |
| Security | 128-bit classical |
| Public/Private Key | 32 bytes each |
| Shared Secret | 32 bytes |

Used in hybrid KEM constructions (paired with ML-KEM-1024 for post-quantum hybrid).

---

## Key Derivation

### HKDF-SHA3-256

**HMAC-based Key Derivation Function** — derive domain-separated subkeys from master secrets.

| Property | Value |
|----------|-------|
| Standard | RFC 5869 |
| Construction | Extract-then-Expand |
| Output Length | Variable (up to 255 × 32 bytes) |
| Domain Separation | Via `info` parameter |

**Usage:**
```python
# Used internally by key_management.py
# Direct access via C library binding
from ama_cryptography.key_management import KeyManager

manager = KeyManager(master_key)
key_id = manager.generate_master_key()
```

---

### Argon2id

**Memory-hard password hashing** — resistant to GPU and ASIC brute-force attacks.

| Property | Value |
|----------|-------|
| Standard | RFC 9106 |
| Mode | Argon2id (hybrid time/memory-hard) |
| Use Case | Password hashing, key derivation from passwords |
| Tuning | Memory cost, time cost, parallelism configurable |

---

### secp256k1

**Elliptic curve operations** for BIP32-compatible HD key derivation.

| Property | Value |
|----------|-------|
| Standard | SEC 2 |
| Curve | secp256k1 (Bitcoin curve) |
| Security | 128-bit classical |
| Use Case | HD key derivation path support |

---

## Hash Functions

### SHA3-256

| Property | Value |
|----------|-------|
| Standard | NIST FIPS 202 |
| Construction | Keccak sponge (Keccak-f[1600]) |
| Output | 256 bits |
| Collision Resistance | 128-bit |
| Preimage Resistance | 256-bit |

**Performance:** ~1,046,450 ops/sec (1 µs per hash).

---

## Hybrid Constructions

### Hybrid Signature Scheme

Combining Ed25519 (classical) with ML-DSA-65 (quantum-resistant):

```
HybridSign(message, sk_ed25519, sk_dilithium):
    sig_ed25519   = Ed25519.Sign(message, sk_ed25519)
    sig_dilithium = ML-DSA-65.Sign(message, sk_dilithium)
    return sig_ed25519 || sig_dilithium

HybridVerify(message, signature, pk_ed25519, pk_dilithium):
    sig_ed, sig_dil = Split(signature)
    return Ed25519.Verify(message, sig_ed, pk_ed25519) AND
           ML-DSA-65.Verify(message, sig_dil, pk_dilithium)
```

**Security:** Secure against both classical and quantum adversaries. Both signatures must verify for acceptance.

---

### Hybrid KEM Combiner

Combining X25519 (classical) with ML-KEM-1024 (post-quantum) using a binding construction per Bindel et al. (PQCrypto 2019):

```
combined_ss = HKDF-SHA3-256(
    salt = classical_ct || pqc_ct,           # Ciphertext binding
    ikm  = classical_ss || pqc_ss,           # Combined key material
    info = label || classical_pk || pqc_pk   # Context binding
)
```

**Security:** IND-CCA2 under assumption that at least one component KEM is IND-CCA2. Secure against both classical and quantum adversaries.

See [Hybrid Cryptography](Hybrid-Cryptography) for implementation details.

---

## Key Sizes Reference

| Component | Size |
|-----------|------|
| Master Secret | 32 bytes (256 bits) |
| HMAC Key | 32 bytes (256 bits) |
| Ed25519 Private Key | 32 bytes |
| Ed25519 Public Key | 32 bytes |
| Ed25519 Signature | 64 bytes |
| ML-DSA-65 Private Key | 4,032 bytes |
| ML-DSA-65 Public Key | 1,952 bytes |
| ML-DSA-65 Signature | 3,309 bytes |
| ML-KEM-1024 Public Key | 1,568 bytes |
| ML-KEM-1024 Secret Key | 3,168 bytes |
| ML-KEM-1024 Ciphertext | 1,568 bytes |
| ML-KEM-1024 Shared Secret | 32 bytes |
| SPHINCS+ Public Key | 64 bytes |
| SPHINCS+ Secret Key | 128 bytes |
| SPHINCS+ Signature | 49,856 bytes |
| AES-256-GCM Key | 32 bytes |
| AES-256-GCM Nonce | 12 bytes |
| AES-256-GCM Tag | 16 bytes |

---

*See [Post-Quantum Cryptography](Post-Quantum-Cryptography) for in-depth PQC details, or [Performance Benchmarks](Performance-Benchmarks) for timing data.*
