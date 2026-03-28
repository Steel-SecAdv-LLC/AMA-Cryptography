# AMA Cryptography System Architecture

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 2.3 |
| Last Updated | 2026-03-19 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Executive Summary

AMA Cryptography is a cryptographic protection system designed to secure sensitive data structures using quantum-resistant cryptography. It serves as the cryptographic protection layer for [Mercury Agent](https://github.com/Steel-SecAdv-LLC/Mercury-Agent). The architecture implements defense-in-depth security through multiple independent cryptographic layers, with mathematical integration of ethical constraints into key derivation operations.

This document provides a comprehensive technical reference for system architects, security engineers, and developers working with or evaluating the AMA Cryptography system.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Architectural Principles](#architectural-principles)
3. [Cryptographic Architecture](#cryptographic-architecture)
4. [Ethical Integration Framework](#ethical-integration-framework)
5. [Component Architecture](#component-architecture)
6. [Data Flow and Processing Pipeline](#data-flow-and-processing-pipeline)
7. [Key Management Architecture](#key-management-architecture)
8. [Security Architecture](#security-architecture)
9. [Performance Architecture](#performance-architecture)
10. [Deployment Architecture](#deployment-architecture)
11. [Testing and Quality Assurance](#testing-and-quality-assurance)
12. [Standards Compliance](#standards-compliance)
13. [References](#references)

---

## System Overview

### Purpose

AMA Cryptography provides cryptographic protection for structured data (referred to as "Omni-Codes" within the system) using a hybrid classical/quantum-resistant signature scheme. The system is designed for long-term data integrity assurance (50+ years) in environments where quantum computing threats must be considered.

### Scope

This architecture covers the core cryptographic engine, key management system, ethical integration framework, and supporting infrastructure. Out of scope are application-specific integrations, network transport security, and external HSM implementations.

### Non-Goals

The following are explicitly not goals of this architecture:

- General-purpose encryption-as-a-service (the system provides AES-256-GCM and hybrid KEM for targeted use cases, not as a generic encryption service)
- Real-time streaming cryptographic operations
- Hardware-level cryptographic acceleration
- Certificate authority or PKI infrastructure

### High-Level Architecture

```
+------------------------------------------------------------------+
|                      AMA CRYPTOGRAPHY SYSTEM                          |
+------------------------------------------------------------------+
|                                                                   |
|  +--------------------+  +--------------------+  +---------------+|
|  | Cryptographic      |  | Ethical            |  | Key           ||
|  | Pipeline           |  | Integration        |  | Management    ||
|  |                    |  |                    |  |               ||
|  | - SHA3-256 Hash    |  | - 4 Ethical        |  | - HKDF        ||
|  | - HMAC-SHA3-256    |  |   Pillars          |  | - Key Rotation||
|  | - Ed25519          |  | - Constraint       |  | - HSM Support ||
|  | - ML-DSA-65        |  |   Validation       |  |               ||
|  | - RFC 3161 TSA     |  | - Signature Gen    |  |               ||
|  +--------------------+  +--------------------+  +---------------+|
|                                                                   |
|  +--------------------------------------------------------------+ |
|  |                    Application Interface                     | |
|  |                                                              | |
|  |  create_crypto_package()  |  verify_crypto_package()         | |
|  |  export_public_keys()     |  generate_key_management_system()| |
|  +--------------------------------------------------------------+ |
|                                                                   |
+------------------------------------------------------------------+
```

---

## Architectural Principles

### Design Philosophy

The AMA Cryptography architecture is built on the following foundational principles:

**Security Through Mathematical Rigor**: Security of individual cryptographic primitives (SHA3-256, Ed25519, ML-DSA-65, HMAC, HKDF) relies on published proofs and reduction arguments to well-studied cryptographic assumptions. The system's composition protocol and original components (key evolution, adaptive posture) have not undergone independent formal verification. No security-by-obscurity mechanisms are employed.

**Defense in Depth**: Multiple independent cryptographic layers — four core operations (SHA3-256, HMAC-SHA3-256, Ed25519, ML-DSA-65) supported by key derivation and optional timestamping — ensure that compromise of any single layer does not compromise the overall system security. Each layer provides distinct security properties.

**Quantum Readiness**: Primary signature algorithms are selected for resistance to known quantum attacks. The system is designed to remain secure against adversaries with access to large-scale quantum computers.

**Ethical Integration**: Ethical constraints are mathematically bound to cryptographic operations through the key derivation process, ensuring that ethical metadata cannot be separated from cryptographic proofs.

**Standards Compliance**: Built exclusively from standardized cryptographic primitives (NIST FIPS, IETF RFC) — no custom ciphers, hash functions, or signature schemes. The composition protocol (how primitives are combined into the multi-layer defense architecture, key evolution, and adaptive posture system) is an original design.

**Zero External Crypto Dependencies (INVARIANT-1)**: All cryptographic primitives are implemented natively in C. No third-party crypto packages are permitted. See [`.github/INVARIANTS.md`](.github/INVARIANTS.md).

**Performance Efficiency**: Cryptographic operations are optimized to maintain throughput exceeding 450 packages/second for full multi-layer operations.

### Architectural Constraints

The following constraints govern architectural decisions:

1. All cryptographic operations must use approved NIST or IETF algorithms
2. Key material must never be logged or exposed in error messages
3. Constant-time operations must be used for all security-critical comparisons
4. The system must degrade gracefully when optional components are unavailable
5. All public interfaces must validate inputs before processing

---

## Cryptographic Architecture

AMA Cryptography is designed as a standalone cryptographic library for all AI agents and AI systems, not exclusively Mercury Agent. Any Python or C project can integrate these primitives independently. The library provides a complete, self-contained suite of quantum-resistant cryptographic operations suitable for any application requiring post-quantum security.

### Cryptographic Primitive Selection

| Primitive | Algorithm | Standard | Security Level | C Implementation |
|-----------|-----------|----------|----------------|------------------|
| Hash Function | SHA3-256 | NIST FIPS 202 | 128-bit collision resistance | **Full** (ama_sha3.c) |
| Message Authentication | HMAC-SHA3-256 | RFC 2104 + FIPS 202 | 256-bit key, 128-bit security | **Full** (ama_hkdf.c) |
| Classical Signature | Ed25519 | RFC 8032 | 128-bit classical security | **Full** (ama_ed25519.c) |
| Quantum-Resistant Signature | ML-DSA-65 (Dilithium) | NIST FIPS 204 | 192-bit quantum security | **Full** (ama_dilithium.c) |
| Key Encapsulation | ML-KEM-1024 (Kyber) | NIST FIPS 203 | 256-bit quantum security | **Full** (ama_kyber.c) |
| Hash-Based Signature | SPHINCS+-SHA2-256f | NIST FIPS 205 | 256-bit quantum security | **Full** (ama_sphincs.c) |
| Authenticated Encryption | AES-256-GCM | NIST SP 800-38D | 256-bit key, 128-bit security | **Full** (ama_aes_gcm.c) |
| Key Derivation | HKDF-SHA3-256 | RFC 5869 | 256-bit derived keys | **Full** (ama_hkdf.c) |
| Timestamping | RFC 3161 TSA | RFC 3161 | Third-party attestation | Python API only |
| Key Exchange | X25519 | RFC 7748 | 128-bit classical security | **Full** (ama_x25519.c) |
| Alternative AEAD | ChaCha20-Poly1305 | RFC 8439 | 256-bit key, 128-bit security | **Full** (ama_chacha20poly1305.c) |
| Password Hashing | Argon2id | RFC 9106 | Memory-hard KDF | **Full** (ama_argon2.c) |
| EC Operations | secp256k1 | SEC 2 | HD key derivation support | **Full** (ama_secp256k1.c) |
| Constant-Time Utilities | memcmp, memzero, swap, lookup, copy | — | Side-channel resistance | **Full** (ama_consttime.c) |
| Platform CSPRNG | getrandom/getentropy/BCryptGenRandom | — | Entropy source | **Full** (ama_platform_rand.c) |

**C Library Source Files — 20 .c files + 1 internal header in `src/c/`:**

Core primitives:
- `src/c/ama_core.c` - Library initialization, version info, feature detection, shared utilities
- `src/c/ama_sha3.c` - SHA3-256, SHAKE128/256, streaming API (Keccak-f[1600])
- `src/c/ama_sha256.c` - Native SHA-256 (FIPS 180-4), used by SPHINCS+ internally
- `src/c/ama_hmac_sha256.c` - Native HMAC-SHA-256 (RFC 2104), used by SPHINCS+ PRF_msg
- `src/c/ama_platform_rand.c` - Platform-native CSPRNG (getrandom/getentropy/BCryptGenRandom)
- `src/c/ama_hkdf.c` - HKDF-SHA3-256 with HMAC-SHA3-256 (RFC 5869)
- `src/c/ama_consttime.c` - Constant-time utilities (memcmp, memzero, swap, lookup, copy)
- `src/c/internal/ama_sha2.h` - Extracted SHA-512 header-only implementation (deduplication for Ed25519/SPHINCS+)

Signature and key exchange:
- `src/c/ama_ed25519.c` - Ed25519 keygen/sign/verify with windowed scalar mult
- `src/c/ama_kyber.c` - ML-KEM-1024 full native implementation (NTT, IND-CCA2, Fujisaki-Okamoto)
- `src/c/ama_dilithium.c` - ML-DSA-65 full native implementation (NTT q=8380417, rejection sampling)
- `src/c/ama_sphincs.c` - SPHINCS+-SHA2-256f-simple full native implementation (WOTS+, FORS, hypertree)
- `src/c/ama_x25519.c` - X25519 Diffie-Hellman key exchange (RFC 7748)
- `src/c/ama_secp256k1.c` - secp256k1 elliptic curve operations (HD key derivation)

Encryption and KDF:
- `src/c/ama_aes_gcm.c` - AES-256-GCM authenticated encryption (NIST SP 800-38D)
- `src/c/ama_aes_bitsliced.c` - Bitsliced AES S-box (cache-timing hardened, optional via `-DAMA_AES_CONSTTIME=ON`). Augments `ama_aes_gcm.c` with constant-time S-box when enabled.
- `src/c/ama_chacha20poly1305.c` - ChaCha20-Poly1305 AEAD (RFC 8439)
- `src/c/ama_argon2.c` - Argon2id password hashing (RFC 9106)

Infrastructure:
- `src/c/ama_cpuid.c` - CPU feature detection (AES-NI, PCLMULQDQ, ARMv8-CE) for AEAD backend selection
- `src/c/ama_secure_memory.c` - Secure memory operations (mlock/munlock) via native platform APIs
- `src/c/ed25519_donna_shim.c` - Ed25519-donna assembly variant shim (optional via `-DAMA_ED25519_ASSEMBLY=ON`)

**Zero-Dependency PQC:** All three PQC algorithms (Kyber, Dilithium, SPHINCS+) operate without OpenSSL. SHA-256, HMAC-SHA-256, and random byte generation are provided by native implementations (`ama_sha256.c`, `ama_hmac_sha256.c`, `ama_platform_rand.c`), validated against NIST KAT vectors.

### Cryptographic Layer Stack

The system implements multiple independent security layers, applied sequentially. Core cryptographic operations (the defense layers an attacker must defeat) are distinguished from supporting infrastructure:

```
  Supporting: RFC 3161 Trusted Timestamp (optional)
              |
    Layer 4: ML-DSA-65 Quantum-Resistant Signature
              |
    Layer 3: Ed25519 Classical Digital Signature
              |                                       Supporting: HKDF-SHA3-256
    Layer 2: HMAC-SHA3-256 Message Authentication  <-- derives keys for Layers 2-4
              |
    Layer 1: SHA3-256 Content Hash
              |
  Input Normalization: Canonical Length-Prefixed Encoding
              |
          [Input Data]
```

**Core Cryptographic Operations:**

**Input Normalization - Canonical Encoding**: Input data is encoded using a deterministic length-prefixed format that prevents concatenation attacks and ensures identical inputs always produce identical encoded outputs. This is the input normalization step, not an independent defense layer.

**Layer 1 - Content Hashing**: SHA3-256 produces a 256-bit digest of the canonically encoded data. This digest serves as the binding commitment for all subsequent cryptographic operations. 128-bit collision resistance (NIST FIPS 202).

**Layer 2 - Message Authentication**: HMAC-SHA3-256 provides keyed message authentication using a key derived via HKDF. This layer enables efficient verification when the HMAC key is available.

**Layer 3 - Classical Signature**: Ed25519 provides a compact (64-byte) digital signature with 128-bit classical security. This layer ensures compatibility with existing verification infrastructure.

**Layer 4 - Quantum-Resistant Signature**: ML-DSA-65 (Dilithium Level 3) provides a lattice-based signature resistant to known quantum attacks. Signature size is approximately 3,309 bytes. 192-bit quantum security (NIST FIPS 204).

**Supporting Cryptographic Infrastructure:**

**HKDF-SHA3-256 Key Derivation**: Derives independent cryptographic keys from a single master secret, ensuring key independence across Layers 2-4. A supporting primitive, not an independent defense layer.

**RFC 3161 Trusted Timestamp**: Optional third-party timestamp providing temporal proof of existence at a specific time. Proves when a package was created, not who created it.

### Key Sizes and Parameters

| Component | Size | Notes |
|-----------|------|-------|
| Master Secret | 256 bits | CSPRNG-generated root key |
| HMAC Key | 256 bits | Derived via HKDF |
| Ed25519 Private Key | 256 bits | Seed for key generation |
| Ed25519 Public Key | 256 bits | Compressed Edwards point |
| Ed25519 Signature | 512 bits | (R, s) pair |
| ML-DSA-65 Private Key | 4,032 bytes | Lattice-based secret key |
| ML-DSA-65 Public Key | 1,952 bytes | Lattice-based public key |
| ML-DSA-65 Signature | 3,309 bytes | Lattice-based signature |
| SHA3-256 Output | 256 bits | Collision-resistant digest |
| HKDF Salt | 256 bits | Optional, zeros if not provided |

---

## Ethical Integration Framework

### Overview

The Ethical Integration Framework mathematically binds ethical metadata to cryptographic operations through the HKDF info parameter. This ensures that derived keys are cryptographically dependent on the ethical context, making it impossible to separate ethical constraints from the cryptographic proof.

### Ethical Pillar Structure

The system defines 4 ethical pillars, each governing a triad of three sub-properties. Each pillar has a weight of 3.0 (3 sub-properties × 1.0). The sum of all weights equals 12.0, ensuring balanced representation.

**Pillar 1: Omniscient — Triad of Wisdom (Verification Layer)**
- Complete verification: SHA3-256 coverage across all data inputs
- Multi-dimensional detection: Temporal, structural, cryptographic anomaly detection
- Complete data validation: Canonical encoding eliminates concatenation attacks

**Pillar 2: Omnipotent — Triad of Agency (Cryptographic Generation)**
- Maximum cryptographic strength: Defense-in-depth against all known attacks
- Secure key generation: CSPRNG + HKDF-SHA3-256 with proper entropy
- Real-time protection: >1,000 ops/sec with minimal latency

**Pillar 3: Omnidirectional — Triad of Geography (Defense-in-Depth)**
- Multi-layer defense: Security presence across all cryptographic layers
- Temporal integrity: Trusted timestamping via RFC 3161
- Attack surface coverage: Classical, quantum, concatenation, forgery defense

**Pillar 4: Omnibenevolent — Triad of Integrity (Ethical Constraints)**
- Ethical foundation: Cryptographic operations serve protective, non-malicious purposes
- Mathematical correctness: Provably correct implementation with formal verification
- Hybrid security: Classical + quantum resistance for long-term security

### Mathematical Integration

The ethical context is integrated into key derivation as follows:

```
ethical_vector = serialize(pillars, weights, symbols)
ethical_signature = SHA3-256(ethical_vector)[:16]  // 128-bit truncation
enhanced_info = application_context || ethical_signature
derived_key = HKDF-SHA3-256(master_secret, salt, enhanced_info, length=32)
```

This construction ensures that any modification to the ethical pillars produces a different derived key, cryptographically binding the ethical context to all subsequent operations.

### Constraint Validation

The system enforces the following constraints on ethical pillars:

1. Weight sum must equal 12.0 (tolerance: 1e-10)
2. All pillar symbols must be unique
3. All pillar names must be unique
4. Weight values must be positive real numbers
5. Triad structure must be preserved (4 triads, 3 pillars each)

---

## Component Architecture

### Python Package Structure

```
ama_cryptography/
├── __init__.py            # Package exports, lazy imports
├── crypto_api.py          # Core API: AmaCryptography, create/verify_crypto_package
├── key_management.py      # KeyManagementSystem, KeyRotationManager, HD derivation
├── pqc_backends.py        # Native C bindings (ctypes), PQC algorithm dispatch
├── adaptive_posture.py    # Adaptive security posture (3R → key rotation/algorithm escalation)
├── hybrid_combiner.py     # Hybrid KEM combiner (X25519 + ML-KEM-1024)
├── double_helix_engine.py # Bio-inspired helical data architecture
├── equations.py           # Mathematical framework (Lyapunov, golden ratio, etc.)
├── _numeric.py            # Pure-Python numerical utilities (NumPy-free fallback)
├── secure_memory.py       # Secure zeroing (backend cascade), SecureBytes, mlock
├── rfc3161_timestamp.py   # RFC 3161 TSA client (online/mock/disabled modes)
├── exceptions.py          # Custom exception hierarchy
├── hmac_binding.*.so      # Cython HMAC-SHA3-256 binding (compiled)
└── math_engine.*.so       # Cython math acceleration (compiled)

Root-level modules:
├── ama_cryptography/legacy_compat.py  # Legacy API compat (ported from code_guardian_secure.py)
├── ama_cryptography_monitor.py      # 3R runtime security monitor
└── ama_cryptography_monitor_demo.py # Monitor demonstration
```

### Core Components

#### ama_cryptography.legacy_compat

The primary cryptographic module implementing the complete security framework
via standalone functions (not a class).

**Responsibilities**:
- Cryptographic package creation and verification
- Key pair generation for all signature algorithms
- Security grade calculation and reporting
- Standards compliance validation

**Key Interfaces**:
- `create_crypto_package(codes, helix_params, kms, author, use_rfc3161=False, tsa_url=None, monitor=None) -> CryptoPackage`
- `verify_crypto_package(codes, helix_params, pkg, hmac_key=None, require_quantum_signatures=None) -> Dict[str, bool]`
- `generate_ed25519_keypair(seed=None) -> Ed25519KeyPair`
- `generate_dilithium_keypair() -> DilithiumKeyPair`

#### KeyManagementSystem

Centralized key management with support for key derivation, rotation, and export.

**Responsibilities**:
- Master secret generation and storage
- Key derivation using HKDF
- Key rotation scheduling and execution
- Public key export for distribution

**Data Structure**:
```python
@dataclass
class KeyManagementSystem:
    master_secret: bytes        # 256-bit root secret
    hmac_key: bytes            # Derived HMAC key
    ed25519_keypair: Ed25519KeyPair
    dilithium_keypair: DilithiumKeyPair
    creation_date: datetime
    rotation_schedule: str     # "quarterly", "monthly", "annually"
    version: str
```

#### CryptoPackage

Self-contained cryptographic package with embedded verification materials.

**Data Structure**:
```python
@dataclass
class CryptoPackage:
    content_hash: str          # SHA3-256 hex digest
    hmac_tag: str             # HMAC-SHA3-256 hex tag
    ed25519_signature: str    # Ed25519 signature hex
    dilithium_signature: str  # ML-DSA-65 signature hex
    timestamp: str            # ISO 8601 UTC timestamp
    timestamp_token: Optional[str]  # RFC 3161 token (base64)
    author: str               # Signer identifier
    ed25519_pubkey: str       # Embedded public key
    dilithium_pubkey: str     # Embedded public key
    version: str              # Package format version
    ethical_vector: Dict[str, float]  # 4 Ethical Pillar scores
    ethical_hash: str         # SHA3-256 hash of ethical vector
    quantum_signatures_enabled: bool  # Whether PQC signatures are present
    signature_format_version: str     # Signature format version tag
```

### Component Interactions

```
+-------------------+     +-------------------+     +-------------------+
|                   |     |                   |     |                   |
|  Application      |---->| ama_cryptography    |---->|  CryptoPackage    |
|  Interface        |     |                   |     |  (Output)         |
|                   |     +--------+----------+     |                   |
+-------------------+              |                +-------------------+
                                   |
                    +--------------+--------------+
                    |              |              |
                    v              v              v
          +----------------+ +----------+ +----------------+
          |                | |          | |                |
          | KeyManagement  | | Ethical  | | Timestamp      |
          | System         | | Framework| | Authority      |
          |                | |          | | (External)     |
          +----------------+ +----------+ +----------------+
```

### Adaptive Posture System (v2.0)

**Module:** `ama_cryptography/adaptive_posture.py`

The adaptive posture system bridges the 3R runtime anomaly monitor and the cryptographic API, enabling dynamic security responses based on real-time threat signals.

```
3R Monitor → PostureEvaluator → CryptoPostureController → KeyRotationManager
             (weighted scoring)  (cooldown enforcement)    (BIP32 derivation)
                                                         → AlgorithmType
                                                           (strength escalation)
```

**Components:**
- `PostureEvaluator`: Weighted scoring model consuming timing (50%), pattern (30%), and resonance (20%) signals. Exponential decay on accumulated score prevents stale anomalies from driving permanent escalation.
- `CryptoPostureController`: Orchestrates key rotation via existing `KeyRotationManager` and algorithm switching via existing `AlgorithmType` hierarchy (ED25519 → ML_DSA_65 → SPHINCS_256F → HYBRID_SIG).

### Hybrid Key Combiner (v2.0)

**Module:** `ama_cryptography/hybrid_combiner.py`

Binding construction for hybrid KEM (classical + PQC) shared secrets per Bindel et al. (PQCrypto 2019).

```
combined_ss = HKDF-SHA3-256(
    salt = classical_ct || pqc_ct,       # Ciphertext binding
    ikm  = classical_ss || pqc_ss,       # Combined key material
    info = label || classical_pk || pqc_pk  # Context binding
)
```

Security: IND-CCA2 secure if either component KEM remains unbroken. Uses native C `ama_hkdf` (HMAC-SHA3-256) with pure Python SHA3-256 fallback.

---

## Data Flow and Processing Pipeline

### Package Creation Flow

```
1. Input Validation
   - Validate data format and parameters
   - Verify KMS integrity and key availability
   
2. Canonical Encoding
   - Apply length-prefixed encoding to all fields
   - Ensure deterministic byte representation
   
3. Content Hashing
   - Compute SHA3-256 digest of encoded data
   - Store as content_hash in package
   
4. HMAC Generation
   - Compute HMAC-SHA3-256 using derived hmac_key
   - Store as hmac_tag in package
   
5. Classical Signature
   - Sign content_hash with Ed25519 private key
   - Store signature and public key in package
   
6. Quantum-Resistant Signature
   - Sign content_hash with ML-DSA-65 private key
   - Store signature and public key in package
   
7. Timestamp (Optional)
   - Request RFC 3161 timestamp from TSA
   - Store timestamp token in package
   
8. Package Assembly
   - Combine all components into CryptoPackage
   - Serialize to JSON format
```

### Package Verification Flow

```
1. Package Parsing
   - Deserialize JSON to CryptoPackage
   - Validate all required fields present
   
2. Content Hash Verification
   - Recompute SHA3-256 from provided data
   - Compare with stored content_hash
   
3. HMAC Verification (if key available)
   - Recompute HMAC-SHA3-256
   - Constant-time comparison with stored tag
   
4. Ed25519 Signature Verification
   - Extract public key from package
   - Verify signature over content_hash
   
5. ML-DSA-65 Signature Verification
   - Extract public key from package
   - Verify signature over content_hash
   
6. Timestamp Verification (if present)
   - Parse RFC 3161 timestamp token
   - Verify TSA signature and time bounds
   
7. Result Aggregation
   - Return verification status for each layer
   - Overall success requires all layers to pass
```

---

## Key Management Architecture

### Key Hierarchy

```
                    +------------------+
                    |  Master Secret   |
                    |  (256 bits)      |
                    +--------+---------+
                             |
              +--------------+--------------+
              |              |              |
              v              v              v
        +-----------+  +-----------+  +-----------+
        | HMAC Key  |  | Ed25519   |  | ML-DSA-65 |
        | (derived) |  | Seed      |  | Seed      |
        +-----------+  | (derived) |  | (derived) |
                       +-----+-----+  +-----+-----+
                             |              |
                             v              v
                       +-----------+  +-----------+
                       | Ed25519   |  | ML-DSA-65 |
                       | Key Pair  |  | Key Pair  |
                       +-----------+  +-----------+
```

### Key Derivation

All keys are derived from the master secret using HKDF-SHA3-256 with domain-separated info parameters:

```
hmac_key = HKDF(master_secret, info="ama-cryptography-hmac-key-v1")
ed25519_seed = HKDF(master_secret, info="ama-cryptography-ed25519-seed-v1")
dilithium_seed = HKDF(master_secret, info="ama-cryptography-dilithium-seed-v1")
```

### Key Rotation

The system supports configurable key rotation schedules:

| Schedule | Rotation Interval | Use Case |
|----------|------------------|----------|
| Monthly | 30 days | High-security environments |
| Quarterly | 90 days | Standard production (default) |
| Annually | 365 days | Low-risk applications |

Key rotation procedure:
1. Generate new master secret from CSPRNG
2. Derive new key hierarchy
3. Archive old public keys with timestamp
4. Securely zero old master secret
5. Update active key identifier
6. Log rotation event for audit

### HSM Integration Points

The architecture supports optional HSM integration for master secret storage:

- AWS CloudHSM (FIPS 140-2 Level 3)
- YubiKey PIV (FIPS 140-2 Level 2)
- Nitrokey HSM (Common Criteria EAL4+)
- Generic PKCS#11 interface

---

## Security Architecture

### Threat Model

**In-Scope Threats**:
- Quantum computer attacks on classical signatures (Shor's algorithm)
- Classical cryptanalytic attacks on hash functions and signatures
- Data tampering and forgery attempts
- Key compromise through side-channel attacks
- Replay attacks on signed packages

**Out-of-Scope Threats**:
- Physical access to execution environment
- Compromise of trusted timestamp authorities
- Denial of service attacks
- Social engineering attacks
- Implementation bugs in underlying cryptographic libraries

### Security Properties

| Property | Mechanism | Assurance Level |
|----------|-----------|-----------------|
| Integrity | SHA3-256 + HMAC | 128-bit |
| Authenticity | Ed25519 + ML-DSA-65 | 128-bit classical, 192-bit quantum |
| Non-repudiation | Digital signatures + RFC 3161 | Cryptographic proof |
| Forward secrecy | Key rotation | Configurable interval |
| Ethical binding | HKDF context integration | Cryptographic binding |

### Combined Security Analysis

**Security Bound:** Overall security is bounded by the weakest cryptographic layer, not the sum of all layers. The system provides approximately 128-bit classical security (from Ed25519/HMAC) and approximately 192-bit quantum security (from ML-DSA-65/Dilithium) when all layers are enforced.

**Defense-in-Depth Benefit:** While security is bounded by the weakest layer, the defense-in-depth architecture ensures that even if one layer is compromised (e.g., a future break in Ed25519), other layers continue to provide protection. Package authenticity is protected by four independent cryptographic operations — content hashing, keyed authentication, classical signature, and quantum-resistant signature — supported by independent key derivation and optional third-party timestamping.

See [SECURITY.md](SECURITY.md) for detailed security proofs and the formal security bound statement.

### Security Assumptions

The security analysis assumes:

1. SHA3-256 behaves as a random oracle
2. HMAC-SHA3-256 is a secure PRF (widely believed, not formally proven for sponge constructions)
3. Ed25519 discrete log problem is hard for classical computers
4. ML-DSA-65 lattice problems are hard for quantum computers
5. CSPRNG provides uniformly random output
6. Constant-time implementations prevent timing attacks

---

## Performance Architecture

### Performance Targets

| Operation | Target Latency | Measured Latency |
|-----------|---------------|------------------|
| KMS Generation | < 5 ms | ~2.12 ms |
| Package Creation (multi-layer) | < 5 ms | ~2.17 ms |
| Package Verification (multi-layer) | < 5 ms | ~2.04 ms |
| HMAC Computation | < 1 ms | ~0.032 ms |
| SHA3-256 Hash | < 1 ms | ~0.001 ms |

### Throughput Characteristics

- **Signing Throughput**: ~462 packages/second (single core, full multi-layer)
- **Verification Throughput**: ~489 packages/second (single core, full multi-layer)
- **Bottleneck**: ML-DSA-65 signing (4.20 ms, dominant signing cost)

### Optimization Strategies

**Cryptographic Optimization**:
- Pre-computed NTT tables for ML-DSA-65
- Efficient SHA3-256 implementation via hashlib
- Key caching to avoid repeated derivation

**Ethical Integration Efficiency**:
- Cached ethical signatures for repeated operations
- Optimized pillar validation with early termination
- ~15% overhead on HKDF derivation specifically; <2% impact on end-to-end package operations (ML-DSA-65 signing dominates pipeline at ~4.2ms)

**Memory Management**:
- Secure zeroing of key material after use
- Bounded buffer sizes for all operations
- Automatic cleanup via context managers

### Cython Acceleration Strategy

The system provides two Cython extension modules for performance-critical paths:

**`src/cython/hmac_binding.pyx`** — Direct binding to native `ama_hmac_sha3_256()`:
- Compiles to C, calls the native function directly with zero Python marshaling
- Throughput: ~262K ops/sec (vs ~182K ops/sec for ctypes fallback)
- Auto-selected when extension is built; ctypes fallback for environments without Cython

**`src/cython/math_engine.pyx`** — Optimized mathematical operations:
- Lyapunov stability computation (27.3x speedup)
- Matrix-vector multiplication (28.1x speedup)
- NTT operations (37.7x speedup)
- Helix evolution (18.9x speedup)
- NumPy integration for array operations

**`src/cython/helix_engine_complete.pyx`** — Complete helix engine with Cython optimization.

Both compiled `.so` modules are installed into the `ama_cryptography/` package directory. The Python API detects availability at import time and falls back to pure Python implementations when extensions are not built.

### HMAC-SHA3-256 Binding Architecture

`ama_hmac_sha3_256()` is exposed to Python through two binding layers:

**Primary path: Cython (`cy_hmac_sha3_256`)**
Compiles to C and calls `ama_hmac_sha3_256()` directly. Zero Python marshaling
overhead. Throughput: ~262K ops/sec.

**Fallback path: ctypes (`native_hmac_sha3_256`)**
Available when the Cython extension is not built. Incurs per-call Python
marshaling overhead. Throughput: ~182K ops/sec. Functionally correct; not for
high-frequency use.

The Cython path is selected automatically when the extension is built (standard
install). The ctypes fallback is available for environments where Cython cannot
be compiled.

### Build System Architecture

The C library uses CMake (`CMakeLists.txt`, ~270 lines) with the following key configuration:

| Option | Default | Effect |
|--------|---------|--------|
| `AMA_USE_NATIVE_PQC` | ON | Compile ML-DSA-65, ML-KEM-1024, SPHINCS+ from source |
| `AMA_AES_CONSTTIME` | ON | Add bitsliced AES S-box (`ama_aes_bitsliced.c`) for cache-timing hardening |
| `AMA_BUILD_TESTS` | ON | Build C test suite (9 test files in `tests/c/`) |
| `AMA_BUILD_EXAMPLES` | ON | Build C examples (`examples/c/`) |
| `AMA_TESTING_MODE` | OFF | Build test-only library with internal symbol visibility |
| `AMA_ENABLE_AVX2` | OFF | Auto-detect and enable AVX2 SIMD optimizations |

When `AMA_USE_NATIVE_PQC=OFF`, the PQC source files are excluded and the library provides only classical primitives (SHA3, Ed25519, HKDF, AES-GCM).

Fuzz harnesses are built separately via `fuzz/CMakeLists.txt` (12 targets covering all C implementations).

### Architectural Invariants

All PRs touching `ama_cryptography/`, `.github/workflows/`, or `tests/` must satisfy the four invariants defined in [`.github/INVARIANTS.md`](.github/INVARIANTS.md):

1. **INVARIANT-1 — Zero External Crypto Dependencies**: All cryptographic primitives are owned natively. No third-party crypto packages (`libsodium`, `pynacl`, `cryptography`, etc.). Python stdlib modules (`hashlib`, `os`, `secrets`) permitted for non-primitive operations only.
2. **INVARIANT-2 — Fail-Closed CI**: Security-critical CI steps must not use `continue-on-error: true`.
3. **INVARIANT-3 — Observable Failure States**: No bare `except: pass`, no silent `return`, no stderr suppression.
4. **INVARIANT-4 — Pinned Action References**: All third-party GitHub Actions pinned to full commit SHA.

Additionally, [`INVARIANTS.md`](INVARIANTS.md) (root) requires that all cryptographic primitives map to a non-deprecated entry in [`CSRC_STANDARDS.md`](CSRC_STANDARDS.md).

---

## Deployment Architecture

### System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| Operating System | Ubuntu 20.04+ | Ubuntu 22.04+ |
| Python Version | 3.9 | 3.11+ |
| Memory | 512 MB | 2 GB |
| Storage | 100 MB | 500 MB |
| CPU | 1 core | 4 cores |

### Deployment Models

**Library Integration**: Import directly into Python applications
```python
from ama_cryptography.crypto_api import create_crypto_package, verify_crypto_package
```

**Command-Line Interface**: Execute as standalone module
```bash
python -m ama_cryptography
```

**Containerized Deployment**: Docker images available
```bash
docker run ama-cryptography:latest
```

### Scalability Considerations

- **Horizontal Scaling**: Stateless design supports multiple instances
- **Load Balancing**: Any instance can process any request
- **Key Distribution**: Public keys can be distributed via CDN
- **Rate Limiting**: Recommended for public-facing deployments

---

## Testing and Quality Assurance

### Test Categories

| Category | Purpose | Coverage Target | Files |
|----------|---------|-----------------|-------|
| Unit Tests | Individual function validation | 80% line coverage | 30 Python test files |
| C Unit Tests | Native library validation | All C functions | 9 C test files (`tests/c/`) |
| Integration Tests | Cross-component workflows | All public APIs | `test_integration_e2e.py`, `test_comprehensive_system.py` |
| Performance Tests | Benchmark regression detection | All critical paths | `test_performance.py`, `benchmarks/` |
| Security Tests | Cryptographic correctness | 100% crypto functions | `test_crypto_core_penetration.py`, `test_memory_security.py` |
| Compliance Tests | Standards adherence | All claimed standards | `test_nist_kat.py`, `test_pqc_kat.py` |
| Fuzz Tests | Input mutation testing | 12 C targets | `fuzz/fuzz_*.c` |
| NIST ACVP Vectors | Official vector validation | 815 vectors, 12 algorithms | `nist_vectors/` |

**Total:** 866+ tests collected across 39 files (30 Python + 9 C).

### Continuous Integration Pipeline

```
1. Code Quality
   - black --check (formatting)
   - ruff check (linting + import sorting, replaces flake8 + isort)
   - mypy --strict (type checking, 0 errors)

2. Security Scanning
   - bandit (code security)
   - Semgrep (static security analysis, fail-closed)
   - safety (dependency vulnerabilities)
   - pip-audit (package audit)

3. Test Execution
   - pytest with coverage reporting
   - Performance benchmark validation

4. Build Verification
   - Package installation test
   - Docker image build
```

### Test Vector Validation

Cryptographic implementations are validated against:

- **NIST ACVP vectors** (`nist_vectors/`): 815 vectors tested, 815 passed across 12 algorithm functions and 7 NIST standards. See [CSRC_ALIGN_REPORT.md](CSRC_ALIGN_REPORT.md) for full breakdown.
- NIST FIPS 202 SHA3-256, SHA3-512, SHAKE-128, SHAKE-256 test vectors
- NIST FIPS 203 ML-KEM-1024 KAT vectors (10/10 pass — `tests/kat/fips203/`)
- NIST FIPS 204 ML-DSA-65 KAT vectors (10/10 pass — `tests/kat/fips204/`)
- NIST FIPS 205 SPHINCS+-SHA2-256f-simple SigVer vectors (`nist_vectors/SLH-DSA-sigVer-FIPS205.json`)
- NIST FIPS 180-4 SHA-256 reference vectors
- NIST SP 800-38D AES-256-GCM test vectors
- RFC 2104 HMAC-SHA-256 test vectors
- RFC 5869 HKDF test vectors (SHA-256 for structure validation)
- Project-specific golden vectors for HMAC-SHA3-256 and HKDF-SHA3-256
- Legacy .rsp format KAT vectors for ML-KEM (512/768/1024) and ML-DSA (44/65/87)

---

## Standards Compliance

### Cryptographic Standards

| Standard | Description | Implementation Status | KAT Validation |
|----------|-------------|---------------------|----------------|
| NIST FIPS 202 | SHA-3 Standard (SHA3-256, SHAKE128, SHAKE256) | Algorithm implemented | NIST test vectors |
| NIST FIPS 203 | ML-KEM (Kyber) Standard | Algorithm implemented | **10/10 KAT pass** |
| NIST FIPS 204 | ML-DSA (Dilithium) Standard | Algorithm implemented | **10/10 KAT pass** |
| NIST FIPS 205 | SLH-DSA (SPHINCS+) Standard | Algorithm implemented | Native implementation |
| NIST SP 800-108 | Key Derivation Functions | Algorithm implemented | — |
| RFC 2104 | HMAC Specification | Algorithm implemented | — |
| RFC 5869 | HKDF Specification | Algorithm implemented | — |
| RFC 8032 | Ed25519 Specification | Algorithm implemented | — |
| NIST SP 800-38D | AES-GCM Authenticated Encryption | Algorithm implemented | NIST test vectors |
| RFC 7748 | X25519 Key Exchange | Algorithm implemented | — |
| RFC 8439 | ChaCha20-Poly1305 AEAD | Algorithm implemented | — |
| RFC 9106 | Argon2 Password Hashing | Algorithm implemented | — |
| RFC 3161 | Time-Stamp Protocol | Optional, implemented when enabled | — |

> **Note:** "Algorithm implemented" means the library implements the algorithms as specified in the referenced standards and passes Known Answer Tests (KATs) against official NIST test vectors. This is NOT a CAVP/CMVP validation claim. This implementation has not been submitted for CMVP validation and is not FIPS 140-3 certified.

### Code Quality Standards

- PEP 8 style compliance (enforced via black)
- Type hints throughout (validated via mypy)
- Comprehensive docstrings (Google style)
- Maximum line length: 100 characters
- Maximum cyclomatic complexity: 15

---

## References

### Standards Documents

1. NIST FIPS 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions (August 2015)
2. NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (August 2024)
3. NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (August 2024)
4. NIST FIPS 205: Stateless Hash-Based Digital Signature Standard (August 2024)
5. NIST SP 800-108 Rev. 1: Recommendation for Key Derivation Using Pseudorandom Functions (August 2022)
6. RFC 2104: HMAC: Keyed-Hashing for Message Authentication (February 1997)
7. RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF) (May 2010)
8. RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA) (January 2017)
9. RFC 3161: Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP) (August 2001)
10. RFC 7748: Elliptic Curves for Security (January 2016)
11. RFC 8439: ChaCha20 and Poly1305 for IETF Protocols (June 2018)
12. RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications (September 2021)
13. NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC (November 2007)

### Implementation References

- `ama_cryptography/crypto_api.py`: Core cryptographic implementation
- `ama_cryptography/pqc_backends.py`: Native C library bindings and PQC dispatch
- `include/ama_cryptography.h`: Complete C API specification
- `SECURITY.md`: Detailed security proofs and analysis
- `THREAT_MODEL.md`: Threat model and risk assessment
- `BENCHMARKS.md`: Performance measurement methodology and results (generated by `benchmark_suite.py`)
- `CSRC_ALIGN_REPORT.md`: NIST ACVP vector validation results (815/815 pass)
- `CSRC_STANDARDS.md`: Governing standards registry
- `IMPLEMENTATION_GUIDE.md`: Deployment and integration guide
- `.github/INVARIANTS.md`: PR-level architectural invariants
- `INVARIANTS.md`: Library-level invariants (CSRC_STANDARDS.md mapping)

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2025-11-26 | Steel Security Advisors LLC | Initial professional release |
| 1.1.0 | 2026-01-09 | Steel Security Advisors LLC | Version alignment |
| 2.0.0 | 2026-03-08 | Steel Security Advisors LLC | Zero-dependency native C architecture, adaptive posture, hybrid KEM combiner, AES-256-GCM, FIPS 203/204/205 algorithm implementation, Phase 2 primitives, ethical pillar alignment, Mercury Agent integration |
| 2.2.0 | 2026-03-16 | Steel Security Advisors LLC | HMAC-SHA3-256 Cython binding, CSRC alignment report, SHA-512 deduplication |
| 2.3.0 | 2026-03-19 | Steel Security Advisors LLC | Comprehensive documentation update: Python package structure, Cython acceleration strategy, build system architecture, INVARIANTS reference, NIST ACVP validation (815 vectors), fuzz testing (12 targets), updated performance figures to match current benchmarks |

---

Copyright 2025-2026 Steel Security Advisors LLC. Licensed under Apache License 2.0.
