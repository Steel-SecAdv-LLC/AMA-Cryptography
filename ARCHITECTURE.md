# AMA Cryptography System Architecture

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 2.0 |
| Last Updated | 2026-03-06 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Executive Summary

AMA Cryptography is a production-grade cryptographic protection system designed to secure sensitive data structures using quantum-resistant cryptography. The architecture implements defense-in-depth security through six independent cryptographic layers, with mathematical integration of ethical constraints into key derivation operations.

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

- General-purpose encryption services (the system focuses on signing and integrity)
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
|  | - SHA3-256 Hash    |  | - 12 Ethical       |  | - HKDF        ||
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

**Security Through Mathematical Rigor**: All security claims are backed by formal proofs or reduction arguments to well-studied cryptographic assumptions. No security-by-obscurity mechanisms are employed.

**Defense in Depth**: Six independent cryptographic layers ensure that compromise of any single layer does not compromise the overall system security. Each layer provides distinct security properties.

**Quantum Readiness**: Primary signature algorithms are selected for resistance to known quantum attacks. The system is designed to remain secure against adversaries with access to large-scale quantum computers.

**Ethical Integration**: Ethical constraints are mathematically bound to cryptographic operations through the key derivation process, ensuring that ethical metadata cannot be separated from cryptographic proofs.

**Standards Compliance**: All cryptographic primitives conform to published NIST and IETF standards. No custom or non-standard cryptographic constructions are used.

**Performance Efficiency**: Cryptographic operations are optimized to maintain throughput exceeding 1,000 operations per second with less than 4% overhead for ethical integration.

### Architectural Constraints

The following constraints govern architectural decisions:

1. All cryptographic operations must use approved NIST or IETF algorithms
2. Key material must never be logged or exposed in error messages
3. Constant-time operations must be used for all security-critical comparisons
4. The system must degrade gracefully when optional components are unavailable
5. All public interfaces must validate inputs before processing

---

## Cryptographic Architecture

### Cryptographic Primitive Selection

| Primitive | Algorithm | Standard | Security Level | C Implementation |
|-----------|-----------|----------|----------------|------------------|
| Hash Function | SHA3-256 | NIST FIPS 202 | 128-bit collision resistance | **Full** (ama_sha3.c) |
| Message Authentication | HMAC-SHA3-256 | RFC 2104 + FIPS 202 | 256-bit key, 128-bit security | **Full** (ama_hkdf.c) |
| Classical Signature | Ed25519 | RFC 8032 | 128-bit classical security | **Full** (ama_ed25519.c) |
| Quantum-Resistant Signature | ML-DSA-65 (Dilithium) | NIST FIPS 204 | 192-bit quantum security | **Full** (ama_dilithium.c) |
| Key Encapsulation | ML-KEM-1024 (Kyber) | NIST FIPS 203 | 256-bit quantum security | **Full** (ama_kyber.c) |
| Hash-Based Signature | SPHINCS+-SHA2-256f | NIST FIPS 205 | 256-bit quantum security | **Full** (ama_sphincs.c) |
| Key Derivation | HKDF-SHA3-256 | RFC 5869 | 256-bit derived keys | **Full** (ama_hkdf.c) |
| Timestamping | RFC 3161 TSA | RFC 3161 | Third-party attestation | Python API only |

**C Library Source Files (v1.1):**
- `src/c/ama_sha3.c` - SHA3-256, SHAKE128/256, streaming API (Keccak-f[1600])
- `src/c/ama_hkdf.c` - HKDF-SHA3-256 with HMAC-SHA3-256 (RFC 5869)
- `src/c/ama_ed25519.c` - Ed25519 keygen/sign/verify with windowed scalar mult
- `src/c/ama_kyber.c` - ML-KEM-1024 full native implementation (NTT, IND-CCA2, Fujisaki-Okamoto)
- `src/c/ama_dilithium.c` - ML-DSA-65 full native implementation (NTT q=8380417, rejection sampling)
- `src/c/ama_sphincs.c` - SPHINCS+-SHA2-256f-simple full native implementation (WOTS+, FORS, hypertree)

### Cryptographic Layer Stack

The system implements six independent security layers, applied sequentially:

```
Layer 6: RFC 3161 Trusted Timestamp (optional)
         |
Layer 5: ML-DSA-65 Quantum-Resistant Signature
         |
Layer 4: Ed25519 Classical Digital Signature
         |
Layer 3: HMAC-SHA3-256 Message Authentication
         |
Layer 2: SHA3-256 Content Hash
         |
Layer 1: Canonical Length-Prefixed Encoding
         |
      [Input Data]
```

**Layer 1 - Canonical Encoding**: Input data is encoded using a deterministic length-prefixed format that prevents concatenation attacks and ensures identical inputs always produce identical encoded outputs.

**Layer 2 - Content Hashing**: SHA3-256 produces a 256-bit digest of the canonically encoded data. This digest serves as the binding commitment for all subsequent cryptographic operations.

**Layer 3 - Message Authentication**: HMAC-SHA3-256 provides symmetric authentication using a derived key. This layer enables efficient verification when the HMAC key is available.

**Layer 4 - Classical Signature**: Ed25519 provides a compact (64-byte) digital signature with 128-bit classical security. This layer ensures compatibility with existing verification infrastructure.

**Layer 5 - Quantum-Resistant Signature**: ML-DSA-65 (Dilithium Level 3) provides a lattice-based signature resistant to known quantum attacks. Signature size is approximately 3,293 bytes.

**Layer 6 - Trusted Timestamp**: Optional RFC 3161 timestamp from a trusted third-party authority provides non-repudiation and proof of existence at a specific time.

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
| ML-DSA-65 Signature | ~3,293 bytes | Lattice-based signature |
| SHA3-256 Output | 256 bits | Collision-resistant digest |
| HKDF Salt | 256 bits | Optional, zeros if not provided |

---

## Ethical Integration Framework

### Overview

The Ethical Integration Framework mathematically binds ethical metadata to cryptographic operations through the HKDF info parameter. This ensures that derived keys are cryptographically dependent on the ethical context, making it impossible to separate ethical constraints from the cryptographic proof.

### Ethical Pillar Structure

The system defines 12 ethical pillars organized into four triads. Each pillar has a symbolic identifier and a weight value. The sum of all weights equals 12.0, ensuring balanced representation.

**Triad 1 - Foundation**
- Eris: Balanced consideration of competing interests
- Eden ♱: Harmonious system growth and sustainability
- Veritas: Truth and validation in all operations

**Triad 2 - Expansion**
- X: Accommodation of unknown future requirements
- Caduceus: Balanced exchange and fair dealing
- Dev: Continuous development and improvement

**Triad 3 - Wisdom**
- Sophia: Integration of diverse knowledge sources
- Minerva: Strategic decision-making capability
- Athena: Practical application of wisdom

**Triad 4 - Transcendence**
- Isis: Regenerative and self-healing properties
- Thoth: Preservation and transmission of knowledge
- Hermes: Connectivity and communication

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

### Core Components

#### OmniGuardianSecure

The primary cryptographic engine implementing the complete security framework.

**Responsibilities**:
- Cryptographic package creation and verification
- Key pair generation for all signature algorithms
- Security grade calculation and reporting
- Standards compliance validation

**Key Interfaces**:
- `create_crypto_package(data, params, kms, author, use_rfc3161, tsa_url) -> CryptoPackage`
- `verify_crypto_package(data, params, pkg, hmac_key) -> Dict[str, bool]`
- `generate_ed25519_keypair(seed) -> Ed25519KeyPair`
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
```

### Component Interactions

```
+-------------------+     +-------------------+     +-------------------+
|                   |     |                   |     |                   |
|  Application      |---->|  OmniGuardianSecure|---->|  CryptoPackage    |
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

**Defense-in-Depth Benefit:** While security is bounded by the weakest layer, the defense-in-depth architecture ensures that even if one layer is compromised (e.g., a future break in Ed25519), other layers continue to provide protection. An attacker must defeat ALL layers to fully compromise the system.

See [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) for detailed security proofs and the formal security bound statement.

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
| Key Generation | < 50 ms | ~35 ms |
| Package Creation | < 200 ms | ~150 ms |
| Package Verification | < 150 ms | ~85 ms |
| HMAC Computation | < 1 ms | ~0.3 ms |
| SHA3-256 Hash | < 1 ms | ~0.2 ms |

### Throughput Characteristics

- **Signing Throughput**: ~1,116 packages/second (single core)
- **Verification Throughput**: ~4,717 packages/second (single core)
- **Bottleneck**: ML-DSA-65 signing (780 microseconds, 87% of signing time)

### Optimization Strategies

**Cryptographic Optimization**:
- Pre-computed NTT tables for ML-DSA-65
- Efficient SHA3-256 implementation via hashlib
- Key caching to avoid repeated derivation

**Ethical Integration Efficiency**:
- Cached ethical signatures for repeated operations
- Optimized pillar validation with early termination
- Minimal serialization overhead (< 4% total)

**Memory Management**:
- Secure zeroing of key material after use
- Bounded buffer sizes for all operations
- Automatic cleanup via context managers

---

## Deployment Architecture

### System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| Operating System | Ubuntu 20.04+ | Ubuntu 22.04+ |
| Python Version | 3.8 | 3.11+ |
| Memory | 512 MB | 2 GB |
| Storage | 100 MB | 500 MB |
| CPU | 1 core | 4 cores |

### Deployment Models

**Library Integration**: Import directly into Python applications
```python
from code_guardian_secure import create_crypto_package, verify_crypto_package
```

**Command-Line Interface**: Execute as standalone script
```bash
python code_guardian_secure.py
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

| Category | Purpose | Coverage Target |
|----------|---------|-----------------|
| Unit Tests | Individual function validation | 80% line coverage |
| Integration Tests | Cross-component workflows | All public APIs |
| Performance Tests | Benchmark validation | All critical paths |
| Security Tests | Cryptographic correctness | 100% crypto functions |
| Compliance Tests | Standards adherence | All claimed standards |

### Continuous Integration Pipeline

```
1. Code Quality
   - black --check (formatting)
   - isort --check-only (imports)
   - flake8 (linting)
   - mypy (type checking)

2. Security Scanning
   - bandit (code security)
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

- NIST FIPS 202 SHA3-256 test vectors
- NIST FIPS 203 ML-KEM-1024 KAT vectors (10/10 pass — `tests/kat/fips203/`)
- NIST FIPS 204 ML-DSA-65 KAT vectors (10/10 pass — `tests/kat/fips204/`)
- NIST FIPS 205 SPHINCS+-SHA2-256f-simple (native implementation)
- RFC 5869 HKDF test vectors (SHA-256 for structure validation)
- Project-specific golden vectors for HMAC-SHA3-256 and HKDF-SHA3-256
- Legacy .rsp format KAT vectors for ML-KEM (512/768/1024) and ML-DSA (44/65/87)

---

## Standards Compliance

### Cryptographic Standards

| Standard | Description | Compliance Status | KAT Validation |
|----------|-------------|-------------------|----------------|
| NIST FIPS 202 | SHA-3 Standard (SHA3-256, SHAKE128, SHAKE256) | Full compliance | NIST test vectors |
| NIST FIPS 203 | ML-KEM (Kyber) Standard | Full compliance | **10/10 KAT pass** |
| NIST FIPS 204 | ML-DSA (Dilithium) Standard | Full compliance | **10/10 KAT pass** |
| NIST FIPS 205 | SLH-DSA (SPHINCS+) Standard | Full compliance | Native implementation |
| NIST SP 800-108 | Key Derivation Functions | Full compliance | — |
| RFC 2104 | HMAC Specification | Full compliance | — |
| RFC 5869 | HKDF Specification | Full compliance | — |
| RFC 8032 | Ed25519 Specification | Full compliance | — |
| RFC 3161 | Time-Stamp Protocol | Optional, full compliance when enabled | — |

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

### Implementation References

- `code_guardian_secure.py`: Core cryptographic implementation
- `SECURITY_ANALYSIS.md`: Detailed security proofs and analysis
- `BENCHMARKS.md`: Performance measurement methodology and results
- `IMPLEMENTATION_GUIDE.md`: Deployment and integration guide

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2025-11-26 | Steel Security Advisors LLC | Initial professional release |

---

Copyright 2025 Steel Security Advisors LLC. Licensed under Apache License 2.0.
