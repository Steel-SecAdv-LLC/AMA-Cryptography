# Post-Quantum Cryptography

In-depth documentation for the post-quantum cryptographic algorithms in AMA Cryptography, their NIST standardization, native implementations, and integration into the multi-layer defense architecture.

---

## Background: The Quantum Threat

Classical asymmetric cryptography (RSA, ECDSA, ECDH) relies on problems believed hard for classical computers — integer factorization and discrete logarithms. **Shor's algorithm** running on a large-scale quantum computer can solve these problems in polynomial time, rendering classical signatures and key exchange insecure.

**Timeline:** Large-scale quantum computers capable of breaking RSA-2048 or ECC-256 are projected within 5–15 years. "Harvest Now, Decrypt Later" (HNDL) attacks make it prudent to deploy quantum-resistant cryptography **today** to protect data with long-term sensitivity.

**AMA Cryptography's response:** Implement NIST-approved post-quantum algorithms natively in C11 alongside classical algorithms in a hybrid scheme, providing a 50+ year security horizon.

---

## NIST PQC Standardization

The U.S. National Institute of Standards and Technology (NIST) finalized three PQC standards in 2024:

| Standard | Algorithm | Basis | Type |
|----------|-----------|-------|------|
| FIPS 203 | ML-KEM (Kyber) | MLWE lattice | Key Encapsulation |
| FIPS 204 | ML-DSA (Dilithium) | MLWE lattice | Digital Signature |
| FIPS 205 | SLH-DSA (SPHINCS+) | Hash functions | Digital Signature |

All three are fully implemented natively in AMA Cryptography's C library.

---

## ML-DSA-65 (CRYSTALS-Dilithium) — Primary PQC Signature

### Overview

ML-DSA-65 is AMA Cryptography's **primary post-quantum signature algorithm**, implementing NIST FIPS 204 at security Level 3. It is based on the Module Learning With Errors (MLWE) hardness assumption over module lattices.

### Security Properties

| Property | Value |
|----------|-------|
| Standard | NIST FIPS 204 (August 2024) |
| Security Level | NIST Level 3 |
| Classical Security | ~2^170 bit operations |
| Quantum Security | ~2^190 operations (Grover-accelerated BKZ) |
| Hardness Assumption | Module-LWE (MLWE), Module-SIS |
| Security Model | EUF-CMA in the Quantum Random Oracle Model (QROM) |
| Quantum Attacks | Lattice sieving + Grover: ~2^190 |

### Key and Signature Sizes

| Component | Size |
|-----------|------|
| Public Key | 1,952 bytes |
| Secret Key | 4,032 bytes |
| Signature | 3,309 bytes |

### Native C Implementation

**File:** `src/c/ama_dilithium.c`

Features:
- NTT-based polynomial multiplication over the ring Zq[X]/(X^256 + 1), q = 8,380,417
- Rejection sampling for uniform distribution
- Deterministic signing (no per-signature randomness required)
- Full NIST KAT validation: 10/10 known-answer tests pass
- Zero external dependencies

### Python API

```python
from ama_cryptography.pqc_backends import (
    generate_dilithium_keypair,
    dilithium_sign,
    dilithium_verify,
    DILITHIUM_AVAILABLE,
)

# Check availability
if not DILITHIUM_AVAILABLE:
    raise RuntimeError("ML-DSA-65 not available")

# Generate key pair (DilithiumKeyPair dataclass)
kp = generate_dilithium_keypair()
print(f"Public key: {len(kp.public_key)} bytes")  # 1952
print(f"Secret key: {len(kp.secret_key)} bytes")  # 4032

# Sign
message   = b"Data to sign"
signature = dilithium_sign(message, kp.secret_key)
print(f"Signature: {len(signature)} bytes")       # 3309

# Verify
is_valid = dilithium_verify(message, signature, kp.public_key)
print(f"Valid: {is_valid}")  # True

# Tamper detection
tampered   = b"Tampered data"
is_tampered = dilithium_verify(tampered, signature, kp.public_key)
print(f"Tampered: {is_tampered}")  # False
```

### Performance

| Operation | Mean | Ops/sec |
|-----------|------|---------|
| Key generation | 0.22 ms | 4,554 |
| Signing | 1.02 ms | 981 |
| Verification | 0.21 ms | 4,809 |

---

## ML-KEM-1024 (Kyber) — Post-Quantum Key Encapsulation

### Overview

ML-KEM-1024 provides IND-CCA2 secure key encapsulation for establishing shared secrets. It is implemented at NIST Level 5 (highest security tier).

### Security Properties

| Property | Value |
|----------|-------|
| Standard | NIST FIPS 203 (August 2024) |
| Security Level | NIST Level 5 |
| Classical Security | ~2^256 operations |
| Quantum Security | ~2^256 operations |
| Hardness Assumption | Module-LWE (MLWE) |
| Security Model | IND-CCA2 in QROM |
| Transformation | Fujisaki-Okamoto (IND-CPA → IND-CCA2) |

### Key and Ciphertext Sizes

| Component | Size |
|-----------|------|
| Public Key | 1,568 bytes |
| Secret Key | 3,168 bytes |
| Ciphertext | 1,568 bytes |
| Shared Secret | 32 bytes |

### Native C Implementation

**File:** `src/c/ama_kyber.c`

Features:
- Full NTT-based polynomial arithmetic over Zq[X]/(X^256 + 1), q = 3,329
- Complete Fujisaki-Okamoto transform for IND-CCA2 security
- Full NIST KAT validation: 10/10 known-answer tests pass
- Zero external dependencies (all required PRFs natively implemented)

### Python API

```python
from ama_cryptography.pqc_backends import (
    generate_kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
    KYBER_AVAILABLE,
)

# Generate recipient key pair (KyberKeyPair dataclass)
kp = generate_kyber_keypair()

# Sender: encapsulate (returns KyberEncapsulation with ct + ss)
enc = kyber_encapsulate(kp.public_key)
print(f"Ciphertext: {len(enc.ciphertext)} bytes")      # 1568
print(f"Shared secret: {len(enc.shared_secret)} bytes")  # 32

# Recipient: decapsulate using secret key
recovered = kyber_decapsulate(enc.ciphertext, kp.secret_key)

# Shared secrets match
assert recovered == enc.shared_secret
print("Key agreement successful!")
```

---

## SPHINCS+-SHA2-256f — Hash-Based Signature

### Overview

SPHINCS+ is a **stateless hash-based signature scheme** whose security relies only on the collision and preimage resistance of SHA-256, with **no lattice assumptions**. It provides a conservative cryptographic backup with different security foundations than ML-DSA-65.

### Security Properties

| Property | Value |
|----------|-------|
| Standard | NIST FIPS 205 (August 2024) |
| Security Level | NIST Level 5 |
| Quantum Security | ~2^256 operations |
| Hardness Assumption | SHA-256 collision and preimage resistance |
| State | **Stateless** (unlike XMSS/LMS) |
| Assumptions | Minimal — only hash function security |

### Key and Signature Sizes

| Component | Size |
|-----------|------|
| Public Key | 64 bytes |
| Secret Key | 128 bytes |
| Signature | 49,856 bytes |

> **Signature Size Trade-off:** SPHINCS+ signatures are large (~49 KB) because the security proof requires including multiple authentication paths. Use ML-DSA-65 for performance-sensitive applications. SPHINCS+ provides a stateless, conservative alternative.

### Native C Implementation

**File:** `src/c/ama_sphincs.c`

Features:
- Full WOTS+ one-time signature scheme
- FORS few-time signature scheme
- Hypertree construction with multi-layer Merkle trees
- SHA2-256f variant (fast, 60-tree construction)
- Zero external dependencies

### Python API

```python
from ama_cryptography.pqc_backends import (
    generate_sphincs_keypair,
    sphincs_sign,
    sphincs_verify,
    SPHINCS_AVAILABLE,
)

kp  = generate_sphincs_keypair()                  # SphincsKeyPair
sig = sphincs_sign(b"message", kp.secret_key)
assert sphincs_verify(b"message", sig, kp.public_key)
print(f"Signature size: {len(sig)} bytes")        # 49856
```

---

## Checking PQC Availability

```python
from ama_cryptography.pqc_backends import (
    get_pqc_status,
    get_pqc_backend_info,
    PQCStatus,
    DILITHIUM_AVAILABLE,
    KYBER_AVAILABLE,
    SPHINCS_AVAILABLE,
)

# Per-backend top-level availability booleans (read directly)
assert DILITHIUM_AVAILABLE and KYBER_AVAILABLE and SPHINCS_AVAILABLE

# High-level status: PQCStatus.AVAILABLE if at least one PQC backend loaded
status = get_pqc_status()
assert status is PQCStatus.AVAILABLE

# Detailed backend info dict (per-algorithm availability, backend name,
# algorithm parameters, PQC and hash/HMAC status, etc.)
info = get_pqc_backend_info()
print(info["dilithium_available"],
      info["kyber_available"],
      info["sphincs_available"])
```

---

## Hybrid Classical + PQC Schemes

### Why Hybrid?

The hybrid approach provides:
1. **Classical security** — secure against today's computers if the PQC assumption fails
2. **Quantum security** — secure against future quantum computers
3. **Migration path** — interoperates with classical-only systems during transition

### Hybrid Signature Scheme

AMA Cryptography combines Ed25519 + ML-DSA-65 in a dual-signature scheme,
driven through the unified `AmaCryptography` dispatcher with
`AlgorithmType.HYBRID_SIG`:

```python
from ama_cryptography.crypto_api import AmaCryptography, AlgorithmType

crypto = AmaCryptography(algorithm=AlgorithmType.HYBRID_SIG)
kp = crypto.generate_keypair()             # KeyPair: pk = Ed25519_pk || ML-DSA_pk
sig = crypto.sign(message, kp.secret_key)  # Signature: Ed25519_sig || ML-DSA_sig
valid = crypto.verify(message, sig, kp.public_key)   # both layers must verify
```

For direct access to the provider (same inputs/outputs, no
`AlgorithmType` selection step), use `HybridSignatureProvider` from
`ama_cryptography.crypto_api`.

### Hybrid KEM

For key establishment, see [Hybrid Cryptography](Hybrid-Cryptography).

---

## NIST KAT Validation

All PQC algorithms pass NIST Known Answer Tests (KAT) from the official NIST PQC submissions:

| Algorithm | KAT Tests | Status |
|-----------|-----------|--------|
| ML-DSA-65 | 10/10 | ✓ Pass |
| ML-KEM-1024 | 10/10 | ✓ Pass |
| SPHINCS+-SHA2-256f | Available | ✓ Pass |

Test vectors are located in `tests/test_pqc_kat.py` and `tests/test_nist_kat.py`.

---

## Security Recommendations

| Scenario | Recommended Algorithm | Rationale |
|----------|----------------------|-----------|
| Primary signatures | ML-DSA-65 | Best performance at NIST Level 3 |
| Key exchange | ML-KEM-1024 + X25519 hybrid | Strongest hybrid security |
| Conservative fallback | SPHINCS+-SHA2-256f | No lattice assumptions |
| Short-term classical-only | Ed25519 | Compatible with legacy verifiers |

---

*See [Cryptography Algorithms](Cryptography-Algorithms) for the full algorithm table, or [Hybrid Cryptography](Hybrid-Cryptography) for hybrid KEM details.*
