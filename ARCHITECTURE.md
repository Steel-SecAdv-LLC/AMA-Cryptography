# AMA Cryptography System Architecture

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 5.0.0 |
| Last Updated | 2026-08-24 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Executive Summary

AMA Cryptography is a cryptographic protection system designed to secure sensitive data structures using quantum-resistant cryptography. The architecture implements defense-in-depth security through multiple independent cryptographic layers, with mathematical integration of ethical constraints into key derivation operations.

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
- Dedicated accelerator-appliance or HSM firmware implementation
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

**Security Through Mathematical Rigor**: Security of individual cryptographic primitives (SHA3-256, Ed25519, ML-DSA-65, HMAC, HKDF) relies on published proofs and reduction arguments to well-studied cryptographic assumptions. The system's composition protocol and original components (key evolution, adaptive posture) have not undergone independent formal verification. Written security arguments for the original constructions are provided in [`docs/DESIGN_NOTES.md`](docs/DESIGN_NOTES.md). No security-by-obscurity mechanisms are employed.

**Defense in Depth**: Multiple independent cryptographic layers — four core operations (SHA3-256, HMAC-SHA3-256, Ed25519, ML-DSA-65) supported by key derivation and optional timestamping — ensure that compromise of any single layer does not compromise the overall system security. Each layer provides distinct security properties.

**Quantum Readiness**: Primary signature algorithms are selected for resistance to known quantum attacks. The system is designed to remain secure against adversaries with access to large-scale quantum computers.

**Ethical Integration**: Ethical constraints are mathematically bound to cryptographic operations through the key derivation process, ensuring that ethical metadata cannot be separated from cryptographic proofs. This is a **policy construct layered on top of the FIPS primitives** — the ethical vector enters the cryptographic stack only through the HKDF `info` parameter (RFC 5869) and does not modify the underlying FIPS 202/203/204/205 primitives, their security bounds, or their ACVP-validated behavior. See [`AMA_CRYPTOGRAPHY_ETHICAL_PILLARS.md`](AMA_CRYPTOGRAPHY_ETHICAL_PILLARS.md) — the document is structured into Part A (FIPS Primitive Layer, reference only) and Part B (Ethical Policy Layer, original work) with an explicit boundary between the two.

**Standards Compliance**: Built exclusively from standardized cryptographic primitives (NIST FIPS, IETF RFC) — no custom ciphers, hash functions, or signature schemes. The composition protocol (how primitives are combined into the multi-layer defense architecture, key evolution, and adaptive posture system) is an original design.

**Zero External Crypto Dependencies (INVARIANT-1)**: All cryptographic primitives are implemented natively in C, and every production hash/KDF call in the Python layer runs on those C kernels — stdlib `hashlib` (OpenSSL-backed) is confined to the gate-pinned pre-execution trust bootstrap. No third-party crypto packages are permitted. See [`.github/INVARIANTS.md`](.github/INVARIANTS.md).

**Performance Efficiency**: Cryptographic operations are optimized and measured through reproducible benchmark artifacts. Throughput claims must name the benchmark host, build flags, and generated artifact.

### Architectural Constraints

The following constraints govern architectural decisions:

1. All cryptographic operations must use approved NIST or IETF algorithms
2. Key material must never be logged or exposed in error messages
3. Constant-time operations must be used for all security-critical comparisons
4. The system must degrade gracefully when optional components are unavailable
5. All public interfaces must validate inputs before processing

---

## Cryptographic Architecture

AMA Cryptography is designed as a standalone cryptographic library. Any Python or C project can integrate these primitives independently. The library provides a self-contained suite of quantum-resistant cryptographic operations suitable for applications requiring post-quantum security after appropriate independent review.

### Cryptographic Primitive Selection

| Primitive | Algorithm | Standard | Security Level | C Implementation |
|-----------|-----------|----------|----------------|------------------|
| Hash Function | SHA3-256 | NIST FIPS 202 | 128-bit collision resistance | **Full** (ama_sha3.c) |
| Message Authentication | HMAC-SHA3-256 | RFC 2104 + FIPS 202 | 256-bit key, 128-bit security | **Full** (ama_hkdf.c) |
| Classical Signature | Ed25519 | RFC 8032 | 128-bit classical security | **Full** (ama_ed25519.c) |
| Quantum-Resistant Signature | ML-DSA-65 (Dilithium) | NIST FIPS 204 | 192-bit quantum security | **Full** (ama_dilithium.c) |
| Key Encapsulation | ML-KEM-1024 (Kyber) | NIST FIPS 203 | 256-bit quantum security | **Full** (ama_kyber.c) |
| Hash-Based Signature | SLH-DSA-SHA2-256f | NIST FIPS 205 | 256-bit quantum security | **Full** (ama_slhdsa.c) |
| Hash-Based Signature | SLH-DSA-SHAKE-128s | NIST FIPS 205 | NIST L1 | **Full** (ama_slhdsa.c) |
| Authenticated Encryption | AES-256-GCM | NIST SP 800-38D | 256-bit key, 128-bit security | **Full** (ama_aes_gcm.c) |
| Key Derivation | HKDF-SHA3-256 | RFC 5869 | 256-bit derived keys | **Full** (ama_hkdf.c) |
| Timestamping | RFC 3161 TSA | RFC 3161 | §2.4.2 message-imprint binding only — not attestation ([INVARIANT-37](INVARIANTS.md#invariant-37--a-verification-api-must-not-claim-a-check-it-does-not-perform)) | Python API only |
| Key Exchange | X25519 | RFC 7748 | 128-bit classical security | **Full** (ama_x25519.c) |
| Alternative AEAD | ChaCha20-Poly1305 | RFC 8439 | 256-bit key, 128-bit security | **Full** (ama_chacha20poly1305.c) |
| Password Hashing | Argon2id | RFC 9106 | Memory-hard KDF | **Full** (ama_argon2.c) |
| EC Operations | secp256k1 | SEC 2 | HD key derivation support | **Full** (ama_secp256k1.c) |
| Constant-Time Utilities | memcmp, memzero, swap, lookup, copy | — | Side-channel resistance | **Full** (ama_consttime.c) |
| Platform CSPRNG | getrandom/getentropy/BCryptGenRandom | — | Entropy source | **Full** (ama_platform_rand.c) |

**C Library Source Files — measured 2026-05-16: 22 top-level `.c` files, 2 internal headers, 1 internal `.c`, and 4 public headers across `src/c/` and `include/`:**

Core primitives:
- `src/c/ama_core.c` - Library initialization, version info, feature detection, shared utilities
- `src/c/ama_sha3.c` - SHA3-256, SHAKE128/256, streaming API (Keccak-f[1600])
- `src/c/ama_sha256.c` - Native SHA-256 (FIPS 180-4), used by SPHINCS+ internally
- `src/c/ama_hmac_sha256.c` - Native HMAC-SHA-256 (RFC 2104), used by SPHINCS+ PRF_msg
- `src/c/ama_platform_rand.c` - Platform-native CSPRNG (getrandom/getentropy/BCryptGenRandom)
- `src/c/ama_hkdf.c` - HKDF-SHA3-256 with HMAC-SHA3-256 (RFC 5869)
- `src/c/ama_consttime.c` - Constant-time utilities (memcmp, memzero, swap, lookup, copy)
- `src/c/internal/ama_sha2.h` - Extracted SHA-512 header-only implementation (deduplication for Ed25519/SLH-DSA/FROST)
- `src/c/internal/ama_sha3_x4.h` - 4-way Keccak-f[1600] interface shared by AVX2 and AVX-512 backends

Signature and key exchange:
- `src/c/ama_ed25519.c` - Ed25519 keygen/sign/verify with windowed scalar mult
- `src/c/ama_kyber.c` - ML-KEM-1024 full native implementation (NTT, IND-CCA2, Fujisaki-Okamoto)
- `src/c/ama_dilithium.c` - ML-DSA-65 full native implementation (NTT q=8380417, rejection sampling)
- `src/c/ama_slhdsa.c` - parameterized SLH-DSA implementation for SHA2-256f and SHAKE-128s (FIPS 205; WOTS+, FORS, hypertree); also provides the legacy SLH-DSA-SHA2-256f-compatible `ama_sphincs_*` API surface
- `src/c/ama_x25519.c` - X25519 Diffie-Hellman key exchange (RFC 7748)
- `src/c/ama_secp256k1.c` - secp256k1 elliptic curve operations (HD key derivation)

Encryption and KDF:
- `src/c/ama_aes_gcm.c` - AES-256-GCM authenticated encryption (NIST SP 800-38D)
- `src/c/ama_aes_bitsliced.c` - Bitsliced AES S-box (cache-timing hardened, **default**: `-DAMA_AES_CONSTTIME=ON`). Replaces `ama_aes_gcm.c` table-based S-box with constant-time algebraic decomposition.
- `src/c/ama_chacha20poly1305.c` - ChaCha20-Poly1305 AEAD (RFC 8439)
- `src/c/ama_argon2.c` - Argon2id password hashing (RFC 9106)

Infrastructure:
- `src/c/ama_cpuid.c` - CPU feature detection (AES-NI, PCLMULQDQ, AVX2, AVX-512F/VL, BMI2, ADX, VAES, VPCLMULQDQ, SHA-NI, NEON, SVE2) for runtime dispatch
- `src/c/ama_secure_memory.c` - Secure memory operations (mlock/munlock) via native platform APIs
- `src/c/ed25519_donna_shim.c` - Ed25519-donna assembly variant shim (optional via `-DAMA_ED25519_ASSEMBLY=ON`)

**Zero-Dependency PQC:** ML-KEM-1024, ML-DSA-65, and SLH-DSA parameter sets operate without OpenSSL, liboqs, PQClean, or external PQC libraries. SHA-256, HMAC-SHA-256, SHA-3/SHAKE, and random byte generation are provided by native implementations and validated against the repository's NIST-vector harness.

### Cryptographic Layer Stack

The system implements multiple independent security layers, applied sequentially. Core cryptographic operations (the defense layers an attacker must defeat) are distinguished from supporting infrastructure:

```
  Supporting: RFC 3161 timestamp binding, not attestation (optional)
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

**RFC 3161 Timestamp Binding**: Optional. AMA implements the RFC 3161 wire format on its own DER codec and verifies the §2.4.2 *message-imprint binding* — that a token refers to this data — plus the `PKIStatusInfo` verdict and the TSA's nonce echo.

It does **not** verify the TSA's CMS `SignerInfo` signature and does **not** validate the TSA certificate chain; neither is implemented anywhere in AMA. A token that binds your data is therefore not evidence that a trusted authority issued it — anyone who can hand you a token can construct one over your data bearing any `genTime` they choose, with no key and no privileged position — and `TSTInfo.genTime` is unauthenticated. This layer proves neither *when* a package was created nor *who* created it; it establishes only that a given token and a given payload go together.

The binding check is sound, and is the right check, when trust in the token's **origin** is established by a separate control: a token received over an authenticated channel, or one re-checked after being validated out of band. It establishes nothing on its own.

The authoritative machine-readable statement of this boundary is `ama_cryptography.rfc3161_timestamp.RFC3161_CAPABILITIES`; it is enforced against this and every other document by [INVARIANT-37](INVARIANTS.md#invariant-37--a-verification-api-must-not-claim-a-check-it-does-not-perform). See [Scope: RFC 3161 attestation](#scope-rfc-3161-attestation-is-not-implemented) for what closing the gap would require.

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
- Temporal binding: RFC 3161 tokens bound to content by the §2.4.2 message imprint (not temporal *integrity* — `genTime` is unauthenticated; see INVARIANT-37)
- Attack surface coverage: Classical, quantum, concatenation, forgery defense

**Pillar 4: Omnibenevolent — Triad of Integrity (Ethical Constraints)**
- Ethical foundation: Cryptographic operations serve protective, non-malicious purposes
- Mathematical correctness: primitives implemented from the published standards and pinned to their published test vectors, with sanitizer, fuzz and differential coverage of the C core — testing evidence, not proof. This library has not been formally verified; see [§Design Philosophy](#design-philosophy) and [`docs/DESIGN_NOTES.md`](docs/DESIGN_NOTES.md)
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
├── ama_cryptography_monitor.py        # Top-level monitor compatibility shim
└── tools/monitoring/                  # 3R runtime security monitor and demo
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

6. Timestamp Binding Check (if present)
   - Parse RFC 3161 timestamp token
   - Recompute the message imprint and compare in constant time (§2.4.2)
   - The TSA signature and certificate chain are NOT verified, and genTime
     is NOT evaluated: a passing check means the token refers to this data,
     not that a trusted authority issued it (INVARIANT-37)

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
- TSA compromise is not the relevant timestamp threat here: AMA verifies no TSA signature, so a forged token needs no compromise at all (THREAT_MODEL.md T3.7)
- Denial of service attacks
- Social engineering attacks
- Implementation bugs in underlying cryptographic libraries

### Security Properties

| Property | Mechanism | Assurance Level |
|----------|-----------|-----------------|
| Integrity | SHA3-256 + HMAC | 128-bit |
| Authenticity | Ed25519 + ML-DSA-65 | 128-bit classical, 192-bit quantum |
| Non-repudiation | Digital signatures (Ed25519 + ML-DSA-65) | Cryptographic proof. RFC 3161 contributes **nothing** here: no TSA signature is verified, so a token is not attributable to any authority ([INVARIANT-37](INVARIANTS.md#invariant-37--a-verification-api-must-not-claim-a-check-it-does-not-perform)) |
| Forward secrecy | Key rotation | Configurable interval |
| Ethical binding | HKDF context integration | Cryptographic binding |
| Agent-instance containment | Agent-instance binding (INVARIANT-30) | Operator-authorized; fail-closed, constant-time |

### Agent-Instance Binding (INVARIANT-30)

Extends the HKDF domain-separation and Omni-Code ethical-binding architecture
above to the *agent* dimension. Where the existing ethical binding ties material
to a package context, an agent-instance binding ties it to a named agent
instance, a declared lifetime, and a capability set:

```
enc(b) = 0x11 || "AMA-AGENT-BIND-v1"
       || version || lifetime || capabilities || reserved
       || 0x20 || instance_id[32] || 0x20 || ethical_profile[32]     (88 bytes)

HKDF info      := enc(b) || u32be(info_len) || info      (ama_hkdf_agent_bound)
signature ctx  := SHA3-256(0x02 || enc(b))               (ama_agent_binding_context)
authorization  := HMAC-SHA3-256(K_auth, 0x01 || enc(b))  (operator-held K_auth)
```

The two sub-domain tags (`0x01` authorization, `0x02` signature context) keep an
authorization tag from ever being replayable as a signature context. Because
`enc(b)` is folded into the KDF and the signature context, material derived
under one binding is cryptographically unrelated to the same input under any
other — an agent cannot relabel ephemeral material as persistent after the
fact; it would have to derive it again, which is the call the policy refuses.

Policy: any lifetime other than `EPHEMERAL`, or any capability in
`{PERSISTENCE, SELF_REPLICATE, DELEGATE}`, requires a non-zero ethical-profile
hash **and** an authorization tag verifying under the operator's key. The check
is fail-closed and constant-time (single arithmetic exit; the HMAC is computed
even when no key is supplied), so neither *whether* nor *which* clause refused
is observable by timing. No new algorithm is introduced — the layer is domain
separation and policy over SHA3-256 / HMAC-SHA3-256 / HKDF, preserving
INVARIANT-1.

**Layering:** `src/c/ama_agent_binding.c` (policy + encoding, native) →
`ama_cryptography/agent_binding.py` (thin ctypes surface, input validation) →
optional advisory detectors in `ama_cryptography/monitoring.py`. The native
layer depends only on SHA3/HMAC/HKDF, so it is present in both the default and
the `AMA_USE_NATIVE_PQC=OFF` build.

### Combined Security Analysis

**Security Bound:** Overall security is bounded by the weakest cryptographic layer, not the sum of all layers. The system provides approximately 128-bit classical security (from Ed25519/HMAC) and approximately 192-bit quantum security (from ML-DSA-65/Dilithium) when all layers are enforced.

**Defense-in-Depth Benefit:** While security is bounded by the weakest layer, the defense-in-depth architecture ensures that even if one layer is compromised (e.g., a future break in Ed25519), other layers continue to provide protection. Package authenticity is protected by four independent cryptographic operations — content hashing, keyed authentication, classical signature, and quantum-resistant signature — supported by independent key derivation. The optional RFC 3161 timestamp is **not** a fifth independent operation: it is a binding check an adversary satisfies unaided (see below), so it must not be counted toward this bound.

See [SECURITY.md](SECURITY.md) for detailed security proofs and the formal security bound statement.

### Scope: RFC 3161 attestation is not implemented

This is recorded as a scoped gap rather than described as a delivered property, because the difference is the whole of the layer's value.

**What is missing.** A timestamp exists to let a third party attest that data existed at a time. That attestation is carried entirely by the TSA's CMS `SignerInfo` signature over the `TSTInfo`, and by the validation of the certificate that signed it. AMA implements neither, so it implements the RFC 3161 *format* and the *binding*, and none of the *attestation*.

**What that costs, precisely.** Forging a token AMA accepts requires no key, no compromise and no privileged network position — only the ability to hand the verifier a token. An adversary builds a CMS `SignedData` offline whose `messageImprint` is the digest of your content and whose `genTime` is whatever they choose. `extract_tst_info` requires the structure to carry a signer, so the forgery must be well-formed; nothing checks that the signer is real. This is strictly weaker than the "TSA compromise" threat the threat model used to be written around, and it is why [THREAT_MODEL.md](THREAT_MODEL.md) now carries a separate row for it.

**Why it is not closed in this change.** It needs three things AMA does not have, and each is a component rather than a function: CMS `SignerInfo` processing (RFC 5652 §5.3, including the `signedAttrs` `messageDigest` and `contentType` binding, without which a signature over the wrong bytes verifies); X.509 path validation (RFC 5280 §6, the full algorithm — name chaining, validity windows, basic constraints, key usage, EKU `id-kp-timeStamping`, and revocation), which is a documented exclusion for this release; and a trust store with a policy for what anchors a deployment accepts. Shipping a partial version of any of them would produce something that passes a happy-path test and reports success against a certificate it never really validated — the same failure mode this section exists to retire.

**What closing it requires,** so it can be scheduled rather than guessed at:

- CMS `SignerInfo` verification: `signedAttrs` canonical re-encoding (RFC 5652 §5.4 — the SET OF must be re-encoded with its implicit tag replaced, a detail that silently invalidates otherwise-correct implementations), the `messageDigest` and `contentType` attribute bindings, and signature verification under the algorithms real TSAs use (RSASSA-PKCS1-v1_5, RSASSA-PSS and ECDSA over the NIST curves — the last of which this PR now provides).
- X.509 certificate parsing and RFC 5280 §6 path validation, including EKU `id-kp-timeStamping` (RFC 3161 §2.3 requires it, and a TSA certificate accepted without it is a general-purpose certificate being trusted for time).
- A trust-anchor store and an explicit policy surface, defaulting to refusal rather than to a bundled anchor set.
- Revocation (CRL or OCSP), or an explicit, documented refusal to check it — a timestamp verified against a revoked TSA certificate is the case the whole control exists for.
- Only then: `RFC3161_CAPABILITIES["tsa_signature"]` and `["tsa_certificate_chain"]` flip to `True`, which is the single edit that permits every claim this document currently withholds. [INVARIANT-37](INVARIANTS.md#invariant-37--a-verification-api-must-not-claim-a-check-it-does-not-perform)'s gate reads that table, so the documentation and the code cannot be updated out of step in either direction.

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
- Native C SHA3-256 (FIPS 202) with SIMD dispatch (AVX2 / AVX-512 / NEON / SVE2)
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

**`src/cython/helix_engine_complete.pyx`** — a complete-engine reference implementation of all 18+ variants. The default build does **not** compile it: `setup.py` builds `math_engine.pyx` and the FFI bindings, and this file is kept as a reference source rather than a shipped extension.

The compiled Cython `.so` modules — `math_engine` and the FFI bindings — are installed into the `ama_cryptography/` package directory. The Python API detects availability at import time and falls back to pure Python implementations when an extension is not built.

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
| `AMA_BUILD_TESTS` | ON | Build C test suite (`tests/c/`) |
| `AMA_BUILD_EXAMPLES` | ON | Build C examples (`examples/c/`) |
| `AMA_TESTING_MODE` | OFF | Build test-only library with internal symbol visibility |
| `AMA_ENABLE_AVX2` | OFF | Auto-detect and enable AVX2 SIMD optimizations |

When `AMA_USE_NATIVE_PQC=OFF`, the PQC source files are excluded and the library provides only classical primitives (SHA3, Ed25519, HKDF, AES-GCM).

Fuzz harnesses are built separately via `fuzz/CMakeLists.txt` (15 targets covering all C implementations).

### Architectural Invariants

All PRs touching `ama_cryptography/`, `.github/workflows/`, or `tests/` must satisfy the architectural invariants defined in [`INVARIANTS.md`](INVARIANTS.md) (canonical, INVARIANT-1 through INVARIANT-43). `.github/INVARIANTS.md` is a three-line pointer to it, kept that way by the version-consistency gate so a second divergent copy cannot reappear. Highlights:

1. **INVARIANT-1 — Zero External Crypto Dependencies**: All cryptographic primitives are owned natively. No third-party crypto packages (`libsodium`, `pynacl`, `cryptography`, etc.). Python stdlib `os`/`secrets` permitted for OS entropy; `hashlib` (OpenSSL-backed in every libcrypto-linked CPython) is confined to the pre-execution trust bootstrap, pinned with exact per-file counts by `tools/check_stdlib_hash_boundary.py` — all production hashing and key derivation runs on the native kernels. All primitives must map to a non-deprecated entry in [`CSRC_STANDARDS.md`](CSRC_STANDARDS.md); vendored public-domain source compiled in-tree is permitted.
2. **INVARIANT-2 — Fail-Closed CI**: Security-critical CI steps must not use `continue-on-error: true`.
3. **INVARIANT-3 — Observable Failure States**: No bare `except: pass`, no silent `return`, no stderr suppression.
4. **INVARIANT-4 — Pinned Action References**: All third-party GitHub Actions pinned to full commit SHA.
5. **INVARIANT-15 — Thread-Safe CPU Dispatch**: `ama_cpuid.c` one-time init must use `pthread_once` (POSIX) or `InitOnceExecuteOnce` (Windows — MSVC and MinGW-w64 alike, selected on `_WIN32` rather than `_MSC_VER`); lockless flag + plain-variable patterns are prohibited.

See [`INVARIANTS.md`](INVARIANTS.md) for the complete set (INVARIANT-1 through INVARIANT-43) and vendoring policy.

---

## Deployment Architecture

### System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| Operating System | Ubuntu 20.04+ | Ubuntu 22.04+ |
| Python Version | 3.10 | 3.11+ |
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
| Unit Tests | Individual function validation | 80% line coverage | Python test files under `tests/` (count enforced by `tools/check_documented_counts.py` — see the verified totals below) |
| C Unit Tests | Native library validation | All C functions | 65 `test_*.c` registered via ctest in `tests/c/` (+ 1 standalone `bench_*.c` + 2 standalone `x25519_equiv_*.c`) |
| Integration Tests | Cross-component workflows | All public APIs | `test_integration_e2e.py`, `test_comprehensive_system.py` |
| Performance Tests | Benchmark regression detection | All critical paths | `test_performance.py`, `benchmarks/` |
| Security Tests | Cryptographic correctness | 100% crypto functions | `test_crypto_core_penetration.py`, `test_memory_security.py` |
| Compliance Tests | Standards adherence | All claimed standards | `test_nist_kat.py`, `test_pqc_kat.py` |
| Fuzz Tests | Input mutation testing | 15 C targets | `fuzz/fuzz_*.c` (16 sources; `fuzz_rng.c` is a helper) |
| NIST ACVP Vectors | Official vector validation | 1,215 vectors, 12 algorithms (815 AFT + 400 SHA-3 MCT) | `nist_vectors/` |

**Total:** 4,701 Python test functions across 200 test files, plus the
ctest-registered C tests and standalone C benchmark under `tests/c/`
(the exact C-test count varies with build options — `AMA_USE_NATIVE_PQC`
gates `test_x25519`, `test_chacha20poly1305`, `test_argon2id`,
`test_kyber_debug`, `test_kyber_cpa`, and `test_kat`, which additionally
requires `AMA_AES_CONSTTIME` because it drives its KAT DRBG from AMA's own
constant-time AES-256; see `tests/c/CMakeLists.txt` for the canonical list).
See [`docs/METRICS_REPORT.md`](docs/METRICS_REPORT.md) for reproduction
instructions.

### Continuous Integration Pipeline

```
1. Code Quality
   - black --check (formatting)
   - ruff check (linting + import sorting, replaces flake8 + isort)
   - mypy --strict (type checking, 0 errors) over EVERY tracked `.py`
     file — package, tests, gate scripts, generators, benchmarks,
     examples, `setup.py`, `docs/conf.py`. That the run covered all of
     them is itself checked, by `tools/check_type_check_scope.py`
     against mypy's own coverage report, because an exit status says
     nothing about what was looked at.

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

- **NIST ACVP vectors** (`nist_vectors/`): 1,215 vectors tested, 1,215 passed across 12 algorithm functions and 7 NIST standards (815 AFT + 400 SHA-3 MCT). See [CSRC_ALIGN_REPORT.md](docs/compliance/CSRC_ALIGN_REPORT.md) for full breakdown.
- NIST FIPS 202 SHA3-256, SHA3-512, SHAKE-128, SHAKE-256 test vectors
- NIST FIPS 203 ML-KEM-1024 KAT vectors (10/10 pass — `tests/kat/fips203/`)
- NIST FIPS 204 ML-DSA-65 KAT vectors (10/10 pass — `tests/kat/fips204/`)
- NIST FIPS 205 SPHINCS+-SHA2-256f-simple SigVer vectors (`tests/kat/fips205/SLH-DSA-sigVer-FIPS205.json`)
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
| RFC 2104 | HMAC Specification | Algorithm implemented | — |
| RFC 5869 | HKDF Specification | Algorithm implemented | — |
| RFC 8032 | Ed25519 Specification | Algorithm implemented | — |
| NIST SP 800-38D | AES-GCM Authenticated Encryption | Algorithm implemented | NIST test vectors |
| RFC 7748 | X25519 Key Exchange | Algorithm implemented | — |
| RFC 8439 | ChaCha20-Poly1305 AEAD | Algorithm implemented | — |
| RFC 9106 | Argon2 Password Hashing | Algorithm implemented | — |
| RFC 3161 | Time-Stamp Protocol | **Partial** — §2.4.1/§2.4.2 wire format and message-imprint binding implemented; CMS `SignerInfo` signature verification and X.509 path validation **not** implemented | RFC 3161 §2.4.1/§2.4.2 wire-format tests |

> **Note:** "Algorithm implemented" means the library implements the algorithms as specified in the referenced standards and passes Known Answer Tests (KATs) against official NIST test vectors. This is NOT a CAVP/CMVP validation claim. This implementation has not been submitted for CMVP validation and is not FIPS 140-3 certified.

### Code Quality Standards

- PEP 8 style compliance (enforced via black)
- Type hints throughout (validated via `mypy --strict`, whole tree; scope enforced by `tools/check_type_check_scope.py`)
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
- `BENCHMARKS.md`: Performance measurement methodology and results (generated locally by running `python benchmarks/benchmark_suite.py`; not checked into version control)
- `docs/compliance/CSRC_ALIGN_REPORT.md`: NIST ACVP vector validation results (1,215/1,215 pass — 815 AFT + 400 SHA-3 MCT)
- `CSRC_STANDARDS.md`: Governing standards registry
- `IMPLEMENTATION_GUIDE.md`: Deployment and integration guide
- `INVARIANTS.md`: Canonical architectural invariants (INVARIANT-1 through INVARIANT-43), including vendoring policy and CSRC_STANDARDS.md mapping (`.github/INVARIANTS.md` is a pointer to it)

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2025-11-26 | Steel Security Advisors LLC | Initial professional release |
| 1.1.0 | 2026-01-09 | Steel Security Advisors LLC | Version alignment |
| 2.0.0 | 2026-03-08 | Steel Security Advisors LLC | Zero-dependency native C architecture, adaptive posture, hybrid KEM combiner, AES-256-GCM, FIPS 203/204/205 algorithm implementation, Phase 2 primitives, ethical pillar alignment, Mercury Agent integration |
| 2.1.0 | 2026-03-25 | Steel Security Advisors LLC | Hand-written AVX2/NEON/SVE2 SIMD for 8 algorithms, runtime dispatch, security fixes S1-S6, HMAC-SHA3-256 Cython binding, CSRC alignment report, SHA-512 deduplication, Python package structure, Cython acceleration strategy, build system architecture, INVARIANTS reference, NIST ACVP validation (815 vectors), fuzz testing (12 targets) |
| 2.1.5 | 2026-04-17 | Steel Security Advisors LLC | Security audit fixes (length-prefixed HKDF encoding, constant-time ops), HSM support via PyKCS11, fd leak protection, INVARIANT-13 restoration with 52 tracked suppressions, comprehensive test coverage for secure_memory/crypto_api/PQC backends, documentation version alignment |
| 3.0.0 | 2026-04-27 | Steel Security Advisors LLC | RFC 9106 Argon2id byte-identity fix (BREAKING — `ama_argon2id_legacy` / `native_argon2id_legacy` verify-only shim) and `out_len` cap at `AMA_ARGON2ID_MAX_TAG_LEN = 1024`; in-house AVX-512 4-way Keccak permutation kernel (opt-in `-DAMA_ENABLE_AVX512=ON`, EVEX YMM-width `vprolq` + `vpternlogq`, XCR0 5+6+7 gated) with `docs/AVX512_KECCAK_ADR.md` ADR; X25519 fe64 (radix-2⁶⁴) ladder + hand-written MULX+ADX inline-asm kernel (`fe64_mul512_mulx` / `fe64_sq512_mulx` / `fe64_reduce512_mulx`) under BMI2∧ADX bundle gate; X25519 4-way AVX2 Montgomery-ladder kernel + `ama_x25519_scalarmult_batch` API (opt-in `AMA_DISPATCH_USE_X25519_AVX2=1`); VAES + VPCLMULQDQ YMM AES-256-GCM clean replacement; Ed25519 verify-path SWE rectification + base-point comb table + merged NTT + AVX2 rejection (Tier-B PQC); batch ML-DSA-65 / ML-KEM-1024 sampling via 4-way SHAKE128/SHAKE256 + CBD2 AVX2; ChaCha20-Poly1305 8-way AVX2 (≥ 512 B) and Argon2 BlaMka G AVX2; SHA-3 auto-tune hysteresis (best-of-5, 10% revert threshold); NIST ACVP self-attestation (815/815 AFT, weekly continuous validation); D-1…D-10 distribution / tooling audit (wheel SONAME bundling with `$ORIGIN`/`@loader_path` runtime_library_dirs, CLI subprocess test self-contained, isolated `setup.py` CMake build dir, fatal Cython failures + `numpy>=1.24.0` / `Cython>=3.2.4` build pins, dudect AES-GCM tag-compare redesign, `.semgrep.yml` 341 FP → 0, X25519 dispatch-policy contract test, `setuptools>=78.1.1` / `wheel>=0.46.2` supply-chain pins, `setuptools<70` preflight, ed25519-donna fallthrough annotations) |
| 3.1.0 | 2026-05-14 | Steel Security Advisors LLC | Public documentation alignment, v3.1.0 release hygiene, INVARIANT-14 CVE-ignore review, and no public API changes since v3.0.0 |
| 3.2.0 | 2026-05-20 | Steel Security Advisors LLC | Mercury Agent v1.7.0 alignment; per-slot SIMD auto-tune with file-based cross-process dispatch cache (`AMA_DISPATCH_CACHE_FILE`) + dispatch cache safety; `ama_keypair_generate(AMA_ALG_ED25519)` wiring; NTT benchmark overflow guard; dudect CI hygiene; native `native_hmac_sha256` Python bindings |
| 3.3.0 | 2026-07-05 | Steel Security Advisors LLC | Native one-shot SHA-256 (`native_sha256`); documented public convenience + native MAC/KDF surface (`quick_hmac` / `quick_hkdf`, native HMAC/HKDF SHA-2/3, `AmaCryptographyError` exception root); consolidated the two SLH-DSA-SHA2-256f C signers into one; completed native-hashing purity in `crypto_api`; SLSA provenance permissions + CodeQL unused-static resolution |
| 4.0.0 | 2026-08-01 | Steel Security Advisors LLC | Trust-anchor enforcement end to end (anchor compiled into the native library, required for `verify_crypto_package`'s `all_valid`, and no longer bypassable by deleting the signature artefact); constant-time scalar GHASH with an optimizer value barrier and a callgrind instruction-invariance gate; Ed25519 canonical-`y` (INVARIANT-38) on single verify, batch verify and point decode; KDF policy floor on both cost and algorithm; per-epoch AEAD nonce budget (INVARIANT-22); package serialization and `SecureSession` no longer emit key material; RFC 8439 length limit on ChaCha20-Poly1305. BREAKING ×6 — see CHANGELOG `[4.0.0]`. (Rows for 3.4.0 and 3.5.0 were never added to this table; CHANGELOG.md is the complete record for those releases.) |
| 5.0.0 | 2026-08-14 | Steel Security Advisors LLC | Fail-closed FIPS 140-3 POST: `import ama_cryptography` raises on self-test failure and the ERROR state inhibits output on every surface (INVARIANT-39/-40); pairwise consistency test on every asymmetric keygen (INVARIANT-41); declared-ctypes-ABI cross-check with AST-discovered scope and a loaded-library major-version handshake (INVARIANT-42); pre-load SHA3-256 verification of the native library (hash-then-map via `/proc/self/fd`) with fail-closed unreadable-candidate handling; the six Cython binding extensions digest-bound into the v3 integrity artefact (BOTH signing callers bind — the wheel pipeline and the repair flow alike, since `integrity --update --sign` sets `--bind-extensions` unconditionally; anchored/developer severity split); repository-wide audit fixes — global `-mavx2` contamination removed from portable translation units, KyberSlash divisions replaced with exact Granlund–Montgomery reciprocal multiplies, SVE2 Keccak theta and Kyber NTT corrected and CI-built, dead CI gates made enforceable; one-shot AEAD wrapper throughput recovery (all-`bytes` fast path); benchmark floors recalibrated as measured medians with derived tolerances; pre-load refusal of a binding extension whose digest does not match the signed artefact (previously verified only after it had executed); the `AMA_BUILD_PIPELINE` carve-out that let an environment variable buy a mapping of an unverified native library replaced with an in-process signing-only scope; ML-KEM `Compress_d` applies its own `mod 2^d` with an exhaustive 16,645-pair proof; SoftHSM2, the semgrep end-to-end assertion, `test_dispatch_cache_file` on SIMD-off builds and `test_pq_parser_stack` under Valgrind all made executable; the dudect verdict rule distinguishes a directional leak from an unusable measurement. BREAKING ×10 — see CHANGELOG `[5.0.0]`. |

---

Copyright 2025-2026 Steel Security Advisors LLC. Licensed under Apache License 2.0.
