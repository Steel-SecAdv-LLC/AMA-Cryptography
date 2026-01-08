# Changelog

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 1.3 |
| Last Updated | 2026-01-08 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Overview

All notable changes to Ava Guardian ♱ will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added - Native C Cryptographic Library

**Enhancement:** Implemented native C cryptographic primitives for high-performance operations.

#### Summary

Added native C implementations of core cryptographic primitives including SHA3-256, HKDF-SHA3-256, Ed25519 (experimental), and Kyber NTT operations. These provide significant performance improvements over Python implementations for applicable operations.

#### Changes

- **Native C Implementations (`src/c/`):**
  - `ava_sha3.c`: SHA3-256, SHAKE128, SHAKE256 with **streaming API** (init/update/final) (513 lines)
  - `ava_hkdf.c`: HKDF-SHA3-256 with HMAC-SHA3-256 per RFC 5869 (313 lines)
  - `ava_ed25519.c`: Ed25519 keygen/sign/verify with **windowed scalar multiplication** (1,244 lines, experimental)
  - `ava_kyber.c`: Extended with NTT, inverse NTT, Montgomery reduction, polynomial compression (611 lines)

- **Header Updates (`include/ava_guardian.h`):**
  - Added Ed25519 standalone API: `ava_ed25519_keypair()`, `ava_ed25519_sign()`, `ava_ed25519_verify()`
  - Added **Streaming SHA3 API**: `ava_sha3_init()`, `ava_sha3_update()`, `ava_sha3_final()`, `ava_sha3_ctx`
  - Updated documentation for SHA3-256 and HKDF functions
  - Removed "STUB" notes for implemented functions

- **Build System (`CMakeLists.txt`):**
  - Added new source files to AVA_SOURCES

- **Test Suite (`tests/c/`):**
  - `test_sha3.c`: SHA3-256 tests with NIST KAT vectors
  - `test_hkdf.c`: HKDF tests including edge cases (NULL salt/info, zero-length output)
  - `test_ed25519.c`: Ed25519 tests (note: verify roundtrip skipped pending field arithmetic fixes)
  - `test_benchmark.c`: Performance benchmarks for C implementations

- **Documentation:**
  - `ARCHITECTURE.md`: Updated cryptographic primitive table with C implementation status
  - `BENCHMARK_RESULTS.md`: Added C library performance benchmarks and C vs Python comparison
  - `README.md`: Updated implementation status matrix and C layer description

#### Performance Results

| Operation | C Library | Python API | C Speedup |
|-----------|-----------|------------|-----------|
| SHA3-256 (short) | 1,111,144 ops/sec | 292,790 ops/sec | **3.8x** |
| HKDF (32B) | 133,327 ops/sec | 21,443 ops/sec | **6.2x** |
| Ed25519 Sign | 8,131 ops/sec | 10,453 ops/sec | 0.78x (Python faster*) |

*Python Ed25519 uses the optimized cryptography/OpenSSL library. C implementation is experimental.

#### Bug Fixes

- **ava_sha3.c:** Fixed undefined behavior in `rotl64()` when rotation amount n=0. Shifting a 64-bit value by 64 bits is UB in C; this caused test failures on clang while passing on gcc. Fixed by masking n to [0,63] range and handling n=0 explicitly.
- **ava_ed25519.c:** Added missing `#include <stdlib.h>` which caused build failures on macOS with clang due to implicit function declarations for malloc/free being errors in C99+.

#### Security Notes

- SHA3-256 and HKDF implementations are production-ready with NIST KAT validation
- Ed25519 C implementation is marked **experimental** - field arithmetic requires further optimization
- For production Ed25519 operations, continue using the Python API with cryptography library
- All implementations include secure memory zeroing of sensitive data
- Cross-compiler compatibility verified (gcc and clang on Ubuntu and macOS)

---

### Added - Constant-Time Verification and NIST KAT Documentation

**Enhancement:** Added dudect-style timing analysis harness and documented NIST KAT coverage.

#### Summary

Addresses remaining security audit concerns by adding constant-time verification tooling and documenting existing NIST KAT test vector coverage.

#### Changes

- **Constant-Time Verification (`tools/constant_time/`):**
  - `dudect_harness.c`: Implements Welch's t-test timing analysis for all 5 constant-time functions
  - `Makefile`: Build system with `make test` (100K iterations) and `make test-full` (1M iterations)
  - Tests: `ava_consttime_memcmp`, `ava_consttime_swap`, `ava_secure_memzero`, `ava_consttime_lookup`, `ava_consttime_copy`
  - Threshold: |t| < 4.5 (dudect convention, ~10⁻⁵ false positive probability)

- **Documentation:**
  - `CONSTANT_TIME_VERIFICATION.md`: Methodology documentation with scope table
  - `README.md`: Added "Constant-Time Verification" and "NIST KAT Validation" sections
  - `IMPLEMENTATION_GUIDE.md`: Added NIST KAT and constant-time verification to pre-deployment checklist
  - `SECURITY_ANALYSIS.md`: Updated limitations section to reflect addressed concerns

- **Header Fix (`include/ava_guardian.h`):**
  - Fixed `ava_consttime_lookup` parameter order to match implementation (table_len, elem_size)

#### Security Analysis

The dudect-style harness provides statistical timing analysis, not formal verification. Results indicate no detectable timing leakage under tested conditions. Environment-sensitive; run on target hardware for production validation.

#### References

- Reparaz, O., Balasch, J., & Verbauwhede, I. (2017). "Dude, is my code constant time?" https://eprint.iacr.org/2016/1123.pdf

---

### Changed - HKDF Algorithm Unification

**BREAKING CHANGE:** Unified HKDF key derivation to use SHA3-256 instead of SHA-256.

#### Summary

The `derive_keys()` function now uses `HKDF-SHA3-256` instead of `HKDF-SHA256` for key derivation. This aligns the HKDF algorithm with the project's SHA3 emphasis and ensures consistency across all cryptographic primitives.

#### Changes

- **Code (`code_guardian_secure.py`):**
  - `derive_keys()`: Changed `algorithm=hashes.SHA256()` to `algorithm=hashes.SHA3_256()`
  - Updated docstring to reflect SHA3-256 usage
  - Added explanatory comment about RFC 5869 and HMAC-SHA3-256 as secure PRF

- **Documentation (`SECURITY_ANALYSIS.md`):**
  - Updated all HKDF references from SHA-256 to SHA3-256
  - Fixed HKDF security theorem to reference HMAC-SHA3-256
  - Updated compliance tables to show HKDF-SHA3-256
  - Corrected all numeric bounds and parameters

- **Tests (`tests/test_hkdf_sha3_256.py`):**
  - Added 16 comprehensive tests for HKDF-SHA3-256
  - Golden vector tests for reproducibility verification
  - Ethical context integration tests
  - Key independence and determinism tests

- **Configuration (`pytest.ini`):**
  - Added filter for liboqs version mismatch warning

#### Security Analysis

HMAC-SHA3-256 is a secure PRF, and HKDF-SHA3-256 maintains equivalent security to HKDF-SHA256:
- PRF security: 2^-128 (unchanged)
- Key derivation security: 2^-256 (unchanged)
- Collision resistance: 2^-128 (unchanged)

While RFC 5869 was written for HMAC with Merkle-Damgard hashes, HMAC-SHA3-256 provides the same PRF guarantees required by HKDF.

#### Breaking Change Impact

**⚠️ Keys derived with v1.0.0 will differ from keys derived with this version.**

- Applications using `derive_keys()` must regenerate all derived keys
- Existing `Code_CRYPTO_PACKAGE.json` files remain valid (signatures unchanged)
- Only key derivation is affected, not hashing or signatures

#### Migration Path

1. Regenerate all derived keys using updated `derive_keys()` function
2. Update any stored derived keys in your application
3. No changes needed for existing signed packages

---

---

## PLANNED FOR v2.0.0

> **⚠️ WARNING:** The features below are NOT included in v1.0.0. They are planned for future releases.

### Ethical Integration (Planned)

**Major Enhancement:** Mathematical integration of 12 Code Code Ethical Pillars into cryptographic framework.

#### New Features

- **Ethical Vector Integration:**
  - 12-dimensional ethical vector (4 triads × 3 pillars)
  - Balanced weighting constraint: Σw = 12.0
  - Cryptographic binding via SHA3-256 ethical signatures
  
- **Enhanced Key Derivation:**
  - `create_ethical_hkdf_context()`: Integrates ethical vector into HKDF
  - Enhanced HKDF with 128-bit ethical signature in context parameter
  - Maintains RFC 5869 compliance and security level (2^-128)
  
- **CryptoPackage Schema Extension:**
  - New field: `ethical_vector` (Dict[str, float]) - 12 Code Code Ethical Pillars
  - New field: `ethical_hash` (str) - SHA3-256 hash of ethical vector for verification
  
- **KeyManagementSystem Enhancement:**
  - New field: `ethical_vector` stored with KMS for consistency
  - Keys cryptographically bound to ethical constraints
  
- **Comprehensive Documentation:**
  - SECURITY_ANALYSIS.md: Added Section 5.1 "Ethically-Bound HKDF Context" with formal mathematical proofs
  - IMPLEMENTATION_GUIDE.md: Added complete migration guide for v1.0.0 → v2.0.0
  - ARCHITECTURE.md: Complete system architecture documentation (387 lines)
  
- **Performance Benchmarking:**
  - `benchmark_suite.py`: Comprehensive performance testing framework (400 lines)
  - `benchmark_results.json`: Live performance data
  - Validated <4% overhead for ethical integration in full package creation

#### Changed

- **HKDF Key Derivation:**
  - `derive_keys()` now accepts optional `ethical_vector` parameter
  - Enhanced context includes 128-bit ethical signature
  - Backward compatible: defaults to ETHICAL_VECTOR if not specified
  
- **Package Creation:**
  - `create_crypto_package()` now includes ethical vector and hash
  - `generate_key_management_system()` accepts optional `ethical_vector`
  
- **Test Suite:**
  - Updated `test_demonstration.py` for improved quantum library detection
  - Enhanced test robustness with subprocess-based validation

#### Security Analysis

**Mathematical Proof (Section 5.1 of SECURITY_ANALYSIS.md):**

Theorem: If SHA3-256 is collision-resistant and HMAC-SHA256 is a PRF, then HKDF with ethically-bound context remains a secure KDF with security level 2^-127 ≈ 2^-128.

**Security Properties:**
- Maintains HKDF collision resistance (2^-128)
- Provides cryptographic binding to ethical constraints
- Enhanced domain separation via ethical signature
- Non-repudiation of ethical configuration

**Standards Compliance:**
- ✓ RFC 5869 (HKDF): Fully compliant - uses standard context parameter
- ✓ NIST FIPS 202 (SHA3-256): Fully compliant
- ✓ NIST SP 800-108: Compliant with KDF best practices

**Performance Impact:**
- Ethical signature computation: <2 μs per key derivation
- Full package creation overhead: <4% (from 0.30ms baseline)
- Throughput maintained: >3,300 packages/second

#### Breaking Changes

**⚠️ BREAKING: CryptoPackage Schema**

The `CryptoPackage` dataclass now includes two new required fields:
- `ethical_vector: Dict[str, float]`
- `ethical_hash: str`

**Impact:**
- Code deserializing v1.0.0 `Code_CRYPTO_PACKAGE.json` files will fail
- Applications must migrate to v2.0.0 schema

**Migration Path:**
1. Regenerate all packages with v2.0.0 (recommended)
2. Use backward-compatible loader with default ethical vector
3. Batch migration script for multiple packages

See IMPLEMENTATION_GUIDE.md "Migration Guide" section for detailed instructions.

#### Security Assessment

The system maintains secure and tested defense-in-depth architecture. Ethical integration:
- Does not weaken cryptographic security (proven mathematically)
- Adds contextual binding and domain separation
- Provides additional security properties through ethical constraints

### Version Planning

These changes are planned for **v2.0.0** release due to breaking changes in `CryptoPackage` schema. Release date to be determined.

## [1.0.0] - 2025-11-22

**First Public Release - Apache License 2.0**

This release represents the first public open-source release of Ava Guardian ♱ (AG♱) under Apache License 2.0. The system provides secure, tested quantum-resistant cryptographic protection for helical mathematical Omni-Codes.

### Added
- **Apache License 2.0:** Full open-source licensing with proper headers
- **NOTICE file:** Copyright and attribution documentation
- **Code Quality Infrastructure:**
  - `pyproject.toml` with comprehensive project metadata
  - `setup.cfg` with Flake8 configuration
  - Black, isort, MyPy configuration
  - Dependency specifications with version constraints
- **Continuous Integration:**
  - GitHub Actions workflow for testing across Python 3.8-3.11
  - Security scanning workflow with CodeQL, Safety, Bandit
  - Dependabot configuration for automated dependency updates
- **Repository Governance:**
  - `SECURITY.md` with vulnerability disclosure policy
  - `CONTRIBUTING.md` with cryptographic contribution guidelines
  - `CODE_OF_CONDUCT.md` based on Contributor Covenant 2.1
  - Issue templates for bug reports and feature requests
  - Pull request template with security checklist
- **Testing Infrastructure:**
  - Minimal pytest test suite validating demonstration function
  - Test configuration in `pytest.ini`
  - `requirements.txt` and `requirements-dev.txt` for dependencies
- **Documentation Updates:**
  - `CHANGELOG.md` for version tracking
  - Corrected line count in DELIVERY_SUMMARY.md (1,515 lines)
  - Removed stale ARCHITECTURE.md reference from README.md

### Changed
- Updated Python source file with Apache License 2.0 header
- Updated license reference in `code_guardian_secure.py` docstring
- Enhanced README.md documentation references

### Security
- Established security scanning infrastructure
- Implemented vulnerability disclosure process
- Added security-focused code review requirements
- Configured automated security dependency updates

### Core Cryptographic Features

**Six Independent Security Layers:**
- SHA3-256 content hashing (NIST FIPS 202)
- HMAC-SHA3-256 authentication (RFC 2104)
- Ed25519 digital signatures (RFC 8032)
- CRYSTALS-Dilithium quantum-resistant signatures (NIST FIPS 204)
- HKDF key derivation (RFC 5869, NIST SP 800-108)
- RFC 3161 trusted timestamps

**Quantum Resistance:**
- Full Dilithium Level 3 implementation (192-bit quantum security)
- Support for liboqs-python and pqcrypto libraries
- Hybrid classical + post-quantum signature scheme

**Key Management:**
- HKDF-based key derivation
- HSM integration support (AWS CloudHSM, YubiKey, Nitrokey)
- Encrypted keystore fallback with PBKDF2

### Documentation

**Security Analysis (36,000+ words total):**
- SECURITY_ANALYSIS.md (9,000+ words) with mathematical proofs
- IMPLEMENTATION_GUIDE.md (5,000+ words) with deployment guides
- README.md with architecture diagrams and quick start
- 17 peer-reviewed academic citations
- 7 NIST/IETF standards compliance verification

### Previous Development Versions

This public v1.0.0 release is based on internal development version 4.0.0, which evolved through multiple iterations to achieve production readiness.

---

## Version History Summary

| Version | Date | Description |
|---------|------|-------------|
| 1.3 | 2026-01-08 | Version 1.3 release with comprehensive audit and version updates |
| 1.2 | 2025-12-04 | Version 1.2 release with code quality improvements |
| 1.1 | 2025-11-29 | Native C library, constant-time verification, HKDF unification |
| 1.0 | 2025-11-22 | First public open-source release (Apache 2.0) |

---

## Upgrade Guide

### Installation

**Requirements:**
- Python 3.8 or higher
- cryptography >= 41.0.0

**Basic Installation:**
```bash
pip install ava-guardian
```

**With Quantum Resistance (Recommended):**
```bash
pip install ava-guardian[quantum]
# or
pip install liboqs-python
```

**Development Installation:**
```bash
git clone https://github.com/Steel-SecAdv-LLC/Ava-Guardian.git
cd Ava-Guardian
pip install -r requirements-dev.txt
pytest  # Run tests
```

---

## Deprecation Notices

No features are currently deprecated.

Future deprecation notices will include:
- **Feature being deprecated**
- **Deprecation date**
- **Removal date**
- **Migration path**
- **Replacement feature**

---

## Security Advisories

No security advisories at this time.

Security advisories will be published at:
- GitHub Security Advisories: https://github.com/Steel-SecAdv-LLC/Ava-Guardian/security/advisories
- Release notes with [SECURITY] tag

---

Copyright 2025 Steel Security Advisors LLC. Licensed under Apache License 2.0.
