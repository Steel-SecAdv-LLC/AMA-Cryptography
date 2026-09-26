# AMA Cryptography System Architecture

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 5.0.0 |
| Last Updated | 2026-09-26 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Executive Summary

AMA Cryptography is a cryptographic library with a native C core and a Python application layer. Every primitive is implemented in this repository (INVARIANT-1): ML-KEM, ML-DSA, SLH-DSA, HSS/LMS verification, Ed25519, FROST(Ed25519), X25519, ECDSA and ECDH over P-256/384/521, secp256k1, AES-256-GCM, ChaCha20-Poly1305, Ascon, SHA-2, SHA-3/SHAKE, HMAC, HKDF, PBKDF2 and Argon2id. On these it builds a hybrid Ed25519 + ML-DSA-65 package-signing protocol, a hybrid X25519 + ML-KEM-1024 KEM combiner, key management, and a fail-closed power-on self-test. The deprecated legacy API (`ama_cryptography.legacy_compat`) additionally binds an ethical-metadata vector into HKDF key derivation.

This document describes the components, data flows and security boundaries of the 5.0.0 tree.

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
9. [Power-On Self-Test and Module Integrity](#power-on-self-test-and-module-integrity)
10. [Performance Architecture](#performance-architecture)
11. [Deployment Architecture](#deployment-architecture)
12. [Testing and Quality Assurance](#testing-and-quality-assurance)
13. [Standards Compliance](#standards-compliance)
14. [References](#references)

---

## System Overview

### Purpose

AMA Cryptography signs and authenticates arbitrary byte content with a hybrid classical/post-quantum signature (Ed25519 + ML-DSA-65), and exposes the underlying primitives for direct use. New code uses `ama_cryptography.crypto_api`; the deprecated `ama_cryptography.legacy_compat` signs structured "Omni-Code" records.

### Scope

This architecture covers the native C core, the Python package, key management, the ethical-binding construction and the supporting infrastructure. Application-specific integrations and external HSM implementations are out of scope.

### Non-Goals

- General-purpose encryption-as-a-service (the library provides AES-256-GCM, ChaCha20-Poly1305 and a hybrid KEM for targeted use, not as a generic service)
- A production transport protocol: `secure_channel` (a PQ-hybrid Noise-NK variant) is experimental and has not undergone independent security review
- Dedicated accelerator-appliance or HSM firmware
- Certificate authority or PKI infrastructure

### High-Level Architecture

```
+----------------------------------------------------------------------+
| Python layer (ama_cryptography/)                                      |
|  crypto_api: create/verify_crypto_package, providers, AlgorithmType   |
|  key_management | key_formats | hybrid_combiner | adaptive_posture    |
|  secure_channel + session | agent_binding | rfc3161_timestamp         |
|  legacy_compat (deprecated; ethical-vector HKDF binding)              |
|  _self_test + _module_state: POST, integrity, error-state guards      |
+-------------------------------+--------------------------------------+
                                | ctypes (pqc_backends) / Cython bindings
+-------------------------------v--------------------------------------+
| Native C core: src/c/, public ABI include/ama_cryptography.h         |
|  ML-KEM, ML-DSA, SLH-DSA | Ed25519, X25519, P-256/384/521, secp256k1, |
|  FROST | AES-256-GCM, ChaCha20-Poly1305, Ascon | SHA-2, SHA-3/SHAKE,  |
|  HMAC, HKDF, PBKDF2, Argon2id, HSS/LMS verify | platform CSPRNG,      |
|  constant-time utilities, secure memory                               |
|  dispatch/ + avx2/ avx512/ x86/ neon/ sve2/ kernels (CPUID-gated)     |
+----------------------------------------------------------------------+
```

---

## Architectural Principles

### Design Philosophy

**Security Basis**: Security of individual cryptographic primitives (SHA3-256, Ed25519, ML-DSA-65, HMAC, HKDF) relies on published proofs and reduction arguments to well-studied cryptographic assumptions. The system's composition protocol and original components (key evolution, adaptive posture) have not undergone independent formal verification. Written security arguments for the original constructions are provided in [`docs/DESIGN_NOTES.md`](docs/DESIGN_NOTES.md). No security-by-obscurity mechanisms are employed.

**Defense in Depth**: A package carries a SHA3-256 content digest, an HMAC-SHA3-256 tag and a hybrid Ed25519 + ML-DSA-65 signature over a transcript of the whole package (INVARIANT-52). Forging a `HYBRID_SIG` package against a trusted signing key requires forging both signatures. The layers are not independent of the hash functions: a practical SHA3-256 collision defeats the content digest, and through it the transcript both signatures cover.

**Quantum Readiness**: Post-quantum security rests on ML-DSA-65 (signatures) and ML-KEM (key establishment). It holds only for packages signed with `HYBRID_SIG` or `ML_DSA_65` whose verifier requires the ML-DSA layer; Ed25519 alone provides no security against a cryptographically relevant quantum computer.

**Ethical Integration**: In the legacy API (`legacy_compat`), ethical constraints are bound to cryptographic operations through the key derivation process. This is a **policy construct layered on top of the FIPS primitives** — the ethical vector enters the cryptographic stack only through the HKDF `info` parameter (RFC 5869) and does not modify the underlying FIPS 202/203/204/205 primitives, their security bounds, or their ACVP self-attested behaviour (no CAVP certificate). See [`AMA_CRYPTOGRAPHY_ETHICAL_PILLARS.md`](AMA_CRYPTOGRAPHY_ETHICAL_PILLARS.md) — the document is structured into Part A (FIPS Primitive Layer, reference only) and Part B (Ethical Policy Layer, original work) with an explicit boundary between the two.

**Standards Compliance**: Built exclusively from standardized cryptographic primitives (NIST FIPS and SP, IETF RFC, SECG SEC 2) — no custom ciphers, hash functions, or signature schemes. The composition protocol (how primitives are combined into the package, key evolution, and adaptive posture) is an original design.

**Zero External Crypto Dependencies (INVARIANT-1)**: All cryptographic primitives are implemented natively in C, and every production hash/KDF call in the Python layer runs on those C kernels — stdlib `hashlib` (OpenSSL-backed) is confined to the gate-pinned pre-execution trust bootstrap and two comparators whose output the library never emits: POST's hashlib cross-check of the SHA3-256 KAT and `hybrid_combiner`'s test-only HKDF reference, which raises unless a test opts in. No third-party crypto packages are permitted. See [INVARIANT-1](INVARIANTS.md#invariant-1--zero-external-crypto-dependencies).

**Performance Efficiency**: Throughput claims name the benchmark host, build flags, and generated artifact (AGENTS.md §8.7).

### Architectural Constraints

1. All cryptographic operations use approved NIST or IETF algorithms (or SECG SEC 2 for secp256k1)
2. Key material is never logged or exposed in error messages
3. Every secret-dependent operation executes in constant time (INVARIANT-12)
4. Optional, non-cryptographic components (Cython acceleration, monitoring, HSM) may be absent; a cryptographic operation never falls back to a weaker or non-native implementation — it raises (INVARIANT-7)
5. All public interfaces validate inputs before processing (INVARIANT-5)

---

## Cryptographic Architecture

AMA Cryptography is a standalone cryptographic library. Any Python or C project can use its primitives independently.

### Cryptographic Primitive Selection

| Primitive | Algorithm | Standard | Security Level | C Implementation |
|-----------|-----------|----------|----------------|------------------|
| Hash | SHA3-256/512, SHAKE128/256 | NIST FIPS 202 | 128-bit collision (SHA3-256) | `ama_sha3.c` |
| Hash | SHA-256, SHA-384, SHA-512 | NIST FIPS 180-4 | 128/192/256-bit collision | `ama_sha256.c` (+ `ama_sha256_ni.c`), `ama_sha512.c` |
| MAC | HMAC-SHA3-256; HMAC-SHA-256/384/512 | RFC 2104 / FIPS 198-1 | 256-bit key | `ama_hkdf.c`, `ama_hmac_sha256.c`, `ama_hmac_sha384.c` |
| KDF | HKDF-SHA3-256 (+ HKDF-SHA-256/384/512) | RFC 5869 | 256-bit derived keys | `ama_hkdf.c` |
| Password KDF | PBKDF2-HMAC-SHA-256/512; Argon2id | SP 800-132; RFC 9106 | Memory-hard (Argon2id) | `ama_pbkdf2.c`; `ama_argon2.c` |
| KEM | ML-KEM-512/768/1024 | NIST FIPS 203 | NIST categories 1/3/5 | `ama_kyber.c` |
| Signature | ML-DSA-44/65/87 | NIST FIPS 204 | NIST categories 2/3/5 | `ama_dilithium.c` |
| Signature | SLH-DSA-SHA2-256f, SLH-DSA-SHAKE-128s | NIST FIPS 205 | NIST categories 5 / 1 | `ama_slhdsa.c` |
| Signature (verify only) | HSS/LMS | RFC 8554 / SP 800-208 | Hash-based | `ama_lms.c` |
| Signature | Ed25519 | RFC 8032 | ~128-bit classical; none against a quantum adversary | `ama_ed25519.c` |
| Threshold signature | FROST(Ed25519, SHA-512), RFC 9591-style (not ciphersuite-interoperable) | RFC 9591 | As Ed25519 | `ama_frost.c` |
| Signature / key agreement | ECDSA, ECDH over P-256/384/521 | FIPS 186-5, SP 800-56A r3, RFC 6979 | ~128/192/256-bit classical | `ama_nistp.c` |
| Signature / HD keys | secp256k1 ECDSA; BIP32-style HD derivation (not BIP32-interoperable) | SEC 2 | ~128-bit classical | `ama_secp256k1.c` |
| Key agreement | X25519 | RFC 7748 | ~128-bit classical | `ama_x25519.c` |
| AEAD | AES-256-GCM | NIST SP 800-38D | 256-bit key, 128-bit tag | `ama_aes_gcm.c` (+ `ama_aes_bitsliced.c`) |
| AEAD | ChaCha20-Poly1305 | RFC 8439 | 256-bit key, 128-bit tag | `ama_chacha20poly1305.c` |
| AEAD / hash | Ascon-AEAD128, Ascon-Hash256 | NIST SP 800-232 | 128-bit | `ama_ascon.c` |
| Timestamping | RFC 3161 TSA | RFC 3161 | §2.4.2 message-imprint binding only — not attestation ([INVARIANT-37](INVARIANTS.md#invariant-37--a-verification-api-must-not-claim-a-check-it-does-not-perform)) | Python API only |
| Constant-Time Utilities | memcmp, memzero, swap, lookup, copy | — | Side-channel resistance | `ama_consttime.c` |
| Platform CSPRNG | getrandom / getentropy / `/dev/urandom` / BCryptGenRandom | — | Entropy source | `ama_platform_rand.c` |

[CSRC_STANDARDS.md](CSRC_STANDARDS.md) is the authoritative registry of algorithms and their governing standards.

**C Library Source Files.** The measured, gate-checked file inventory is README's [C library inventory](README.md#c-library-inventory-v500); this list does not repeat its counts. **Principal modules:**

Core primitives:
- `src/c/ama_core.c` - version API and the algorithm-agnostic `ama_context` API (keypair, sign, verify, KEM)
- `src/c/ama_sha3.c` - SHA3-256/512, SHAKE128/256, streaming API (Keccak-f[1600])
- `src/c/ama_sha256.c`, `src/c/ama_sha256_ni.c` - SHA-256 (FIPS 180-4), scalar and the x86 SHA-NI kernel selected on CPUID
- `src/c/ama_hmac_sha256.c`, `src/c/ama_hmac_sha384.c`, `src/c/ama_sha512.c`, `src/c/ama_pbkdf2.c` - HMAC-SHA-256/384, SHA-384/512 one-shots, PBKDF2 (SP 800-132)
- `src/c/ama_platform_rand.c` - Platform-native CSPRNG
- `src/c/ama_hkdf.c` - HKDF with HMAC-SHA3-256 (RFC 5869)
- `src/c/ama_consttime.c` - Constant-time utilities (memcmp, memzero, swap, lookup, copy)
- `src/c/internal/ama_sha2.h` - header-only SHA-512/384 core and HMAC shared by Ed25519, FROST, SLH-DSA, HKDF, HMAC-SHA-384, SHA-512 and PBKDF2
- `src/c/internal/ama_sha3_x4.h` - 4-way Keccak-f[1600] interface shared by the AVX2 and AVX-512 backends

Signature and key exchange:
- `src/c/ama_ed25519.c` - Ed25519 (RFC 8032), in-house backend. The group arithmetic is written once in `src/c/internal/ama_ed25519_ge.h` and instantiated over two fields: `fe51` (radix 2^51, `src/c/fe51.h`), the default on every host and the only path on AArch64 and MSVC; and fe64-MULX (radix 2^64, BMI2 + ADX, `src/c/x86/ama_ed25519_fe64_mulx.c`), compiled on x86-64 GCC/Clang and used only after `ama_ed25519_set_mulx_override(1)` on a BMI2 + ADX host. Signing uses a constant-time fixed-base comb; verification uses variable-time wNAF over public inputs only. The two instantiations are byte-identical (`tests/c/test_ed25519_fe51_mulx_equiv.c`). Canonical `S` and `y` are enforced and small-order keys and `R` halves are rejected (INVARIANT-26, -38, -48). No third-party Ed25519 code remains; `src/c/vendor/` must not exist.
- `src/c/ama_frost.c` - FROST(Ed25519) trusted-dealer keygen, two-round signing and aggregation; aggregation verifies every share (INVARIANT-49). `ama_frost_verify_share()` returns `AMA_ERROR_VERIFY_FAILED` for a participant's own non-canonical commitment, as its header states.
- `src/c/ama_kyber.c` - ML-KEM-512/768/1024 (NTT, Fujisaki-Okamoto transform, IND-CCA2)
- `src/c/ama_dilithium.c` - ML-DSA-44/65/87 (NTT q=8380417, rejection sampling, FIPS 204 external interface)
- `src/c/ama_slhdsa.c` - parameterized SLH-DSA for SHA2-256f and SHAKE-128s (FIPS 205; WOTS+, FORS, hypertree); also provides the legacy `ama_sphincs_*` API surface
- `src/c/ama_lms.c` - HSS/LMS verification (RFC 8554, SP 800-208)
- `src/c/ama_nistp.c` - P-256/384/521 ECDSA (RFC 6979 deterministic and hedged) and ECDH
- `src/c/ama_x25519.c` - X25519 (RFC 7748)
- `src/c/ama_secp256k1.c` - secp256k1 ECDSA and the point arithmetic behind BIP32-style HD derivation
- `src/c/fe51.h`, `src/c/fe64.h` - radix-2^51 and radix-2^64 field arithmetic for Curve25519

Encryption and KDF:
- `src/c/ama_aes_gcm.c` - AES-256-GCM (NIST SP 800-38D)
- `src/c/ama_aes_bitsliced.c` - constant-time bitsliced AES S-box used by the portable AES-GCM path; AES-NI, ARMv8 AES and VAES-AVX2 are selected at run time where present (`ama_aes_gcm_active_backend()`), and the table S-box is built only with `-DAMA_AES_CONSTTIME=OFF` plus `-DAMA_AES_TABLE_INSECURE=ON` (INVARIANT-20)
- `src/c/ama_chacha20poly1305.c` - ChaCha20-Poly1305 (RFC 8439)
- `src/c/ama_ascon.c` - Ascon-AEAD128 and Ascon-Hash256 (SP 800-232)
- `src/c/ama_argon2.c` - Argon2id (RFC 9106)
- `src/c/ama_agent_binding.c` - agent-instance binding (INVARIANT-30)

Infrastructure:
- `src/c/ama_cpuid.c` - CPU feature detection (AES-NI, PCLMULQDQ, SSSE3, SSE4.1/4.2, POPCNT, AVX/OSXSAVE, AVX2, AVX-512F/VL and XCR0 ZMM state, BMI1, BMI2, ADX, VAES, VPCLMULQDQ, SHA-NI; ARM NEON, AES, PMULL, SHA2 and SVE2) for runtime dispatch
- `src/c/ama_secure_memory.c` - Secure memory operations (mlock/munlock) via native platform APIs
- `src/c/dispatch/ama_dispatch.c` - runtime backend selection (below)

**Zero-Dependency PQC:** ML-KEM, ML-DSA and SLH-DSA operate without OpenSSL, liboqs, PQClean or any external PQC library.

### Native Backend Dispatch and SIMD Kernels

Runtime selection is in `src/c/dispatch/ama_dispatch.c`, on CPUID results initialised once through `src/c/internal/ama_once.h` (INVARIANT-15). Kernels:

- `avx2/`: AES-GCM (AES-NI and VAES), Argon2 G, ChaCha20-Poly1305 8-way, ML-DSA, ML-KEM, SHA3 4-way Keccak, X25519 4-way ladder (opt-in `AMA_DISPATCH_USE_X25519_AVX2`), the Ed25519 comb's table fold, and a documented SLH-DSA placeholder
- `avx512/`: 4-way Keccak (`-DAMA_ENABLE_AVX512=ON`, default OFF)
- `x86/`: BMI1/BMI2 Keccak-f[1600], Ed25519 fe64-MULX, P-256 Montgomery MULX
- `neon/`: AES-GCM, Argon2, ChaCha20-Poly1305, ML-DSA, ML-KEM, SHA3, and SHA-256 compression for SLH-DSA
- `sve2/`: ML-KEM and ML-DSA NTTs, a scalar Keccak unit, and five documented placeholders (AES-GCM, ChaCha20-Poly1305, Argon2, SLH-DSA, Ed25519)

Per-slot auto-tune and the cross-process cache are controlled by `AMA_DISPATCH_CACHE_FILE`, `AMA_DISPATCH_NO_AUTOTUNE` and `AMA_DISPATCH_ONLY`. Every SIMD kernel is pinned by an equivalence test (INVARIANT-45).

### Cryptographic Layer Stack

**Primary API (`crypto_api.create_crypto_package`)** — four layers:

1. SHA3-256 digest of the content.
2. HMAC-SHA3-256 of the content under a fresh 256-bit key. The key travels with the package result, so this layer detects corruption and proves nothing to a party that holds the package.
3. The primary signature — `HYBRID_SIG` by default: Ed25519 and ML-DSA-65 (the ML-DSA half under a FIPS 204 context, INVARIANT-50) — over `package_transcript()`, a canonical transcript of every other field (INVARIANT-52).
4. HKDF-SHA3-256 derivation of `num_derived_keys` keys from a fresh master secret and salt, committed in the signed metadata.

SLH-DSA-SHA2-256f, ML-KEM-1024 encapsulation and an RFC 3161 token are optional add-ons, all covered by the transcript.

**Legacy API (`legacy_compat`, deprecated)** — the Omni-Code content is canonically length-prefix encoded and hashed. HKDF derives the HMAC key and the Ed25519 seed from the KMS master secret, with the ethical-vector digest in `info`. HMAC-SHA3-256, Ed25519 and ML-DSA-65 are computed over `build_package_transcript()`.

**RFC 3161 Timestamp Binding**: Optional. AMA implements the RFC 3161 wire format on its own DER codec and verifies the §2.4.2 *message-imprint binding* — that a token refers to this data — plus the `PKIStatusInfo` verdict and the TSA's nonce echo.

It does **not** verify the TSA's CMS `SignerInfo` signature and does **not** validate the TSA certificate chain; neither is implemented anywhere in AMA. A token that binds your data is therefore not evidence that a trusted authority issued it — anyone who can hand you a token can construct one over your data bearing any `genTime` they choose, with no key and no privileged position — and `TSTInfo.genTime` is unauthenticated. This layer proves neither *when* a package was created nor *who* created it; it establishes only that a given token and a given payload go together.

The binding check is sound, and is the right check, when trust in the token's **origin** is established by a separate control: a token received over an authenticated channel, or one re-checked after being validated out of band. It establishes nothing on its own.

The authoritative machine-readable statement of this boundary is `ama_cryptography.rfc3161_timestamp.RFC3161_CAPABILITIES`; it is enforced against this and every other document by [INVARIANT-37](INVARIANTS.md#invariant-37--a-verification-api-must-not-claim-a-check-it-does-not-perform). See [Scope: RFC 3161 attestation](#scope-rfc-3161-attestation-is-not-implemented) for what closing the gap would require.

### Key Sizes and Parameters

| Component | Size | Notes |
|-----------|------|-------|
| Master Secret | 256 bits | CSPRNG-generated |
| HMAC Key | 256 bits | CSPRNG, carried with the package result (`crypto_api`); HKDF-derived (legacy) |
| Ed25519 Private Key | 256 bits | Seed for key generation |
| Ed25519 Public Key | 256 bits | Compressed Edwards point |
| Ed25519 Signature | 512 bits | (R, S) pair |
| ML-DSA-65 Private Key | 4,032 bytes | Lattice-based secret key |
| ML-DSA-65 Public Key | 1,952 bytes | Lattice-based public key |
| ML-DSA-65 Signature | 3,309 bytes | Lattice-based signature |
| SHA3-256 Output | 256 bits | Collision-resistant digest |
| HKDF Salt | 256 bits | CSPRNG-generated per KMS or per package, stored with it |

---

## Ethical Integration Framework

### Overview

In the legacy API only, the ethical vector is bound to the key hierarchy and to the package: its SHA3-256 digest enters the HKDF `info` of every derived key, and `ethical_hash` (recomputed by the verifier) is part of the signed and MACed transcript, so altering the vector changes the derived keys and invalidates the package's HMAC and signatures. `crypto_api` performs no ethical binding.

### Ethical Pillar Structure

The four pillar names and their equal weights (3.0 each, Σ = 12.0) are defined in `ama_cryptography/equations.py` (`ETHICAL_VECTOR`): Omniscient (Triad of Wisdom), Omnipotent (Triad of Agency), Omnidirectional (Triad of Geography) and Omnibenevolent (Triad of Integrity). Their descriptions are policy text in [`AMA_CRYPTOGRAPHY_ETHICAL_PILLARS.md`](AMA_CRYPTOGRAPHY_ETHICAL_PILLARS.md) Part B.

### Mathematical Integration

The construction (`legacy_compat.create_ethical_hkdf_context` and `derive_keys`):

```
ethical_signature = SHA3-256(json.dumps(ethical_vector, sort_keys=True))[:16]
info_i            = f"{context}:{i}" || ethical_signature
key_i             = HKDF-SHA3-256(ikm=master_secret, salt=hkdf_salt, info=info_i, L=32)
```

Any change to the vector produces different derived keys. This is domain separation; it adds no cryptographic strength.

### Constraint Validation

At import, `equations.py` refuses a module `ETHICAL_VECTOR` that is not four weights of exactly 3.0 (Σ = 12.0). A caller-supplied `ethical_vector` is not validated; it is serialized as given.

---

## Component Architecture

### Python Package Structure

```
ama_cryptography/
├── __init__.py            # Package exports, lazy imports; runs POST at import
├── __main__.py            # `python -m ama_cryptography`: the legacy demonstration
├── crypto_api.py          # Primary API: AmaCryptography, create/verify_crypto_package, providers
├── pqc_backends.py        # ctypes bindings to the native library; error-state gated
├── key_management.py      # HD derivation, KeyRotationManager, SecureKeyStorage, HSMKeyStorage
├── key_formats.py         # PKCS#8 / SPKI / PEM / JWK / COSE_Key
├── _asn1.py               # DER codec
├── hybrid_combiner.py     # Hybrid KEM combiner (X25519 + ML-KEM-1024)
├── adaptive_posture.py    # 3R signals → key rotation / algorithm escalation
├── agent_binding.py       # Agent-instance binding (INVARIANT-30)
├── ascon.py               # Ascon-AEAD128 / Ascon-Hash256
├── session.py             # Session state, sequence numbers, replay window
├── secure_channel.py      # Experimental PQ-hybrid Noise-NK channel
├── secure_memory.py       # Native secure zeroing, SecureBuffer, mlock
├── rfc3161_timestamp.py   # RFC 3161 client (online/mock/disabled), binding check only
├── integrity.py           # Integrity artefact CLI (--verify, --update --sign)
├── _build_sign.py         # Build-time signer
├── _artefact_source.py    # Integrity artefact sources
├── _self_test.py          # POST, integrity verification, module attestation
├── _module_state.py       # State machine, output guards, pairwise tests
├── _post_kats/            # POST known-answer vectors
├── _package_transcript.py # Canonical package transcript (INVARIANT-52)
├── equations.py           # 3R / helix mathematics, ETHICAL_VECTOR, OMNI_CODES
├── double_helix_engine.py # Double-helix key evolution
├── monitor.py, monitoring.py # 3R monitor and advisory detectors
├── legacy_compat.py       # Deprecated legacy API (ethical-vector HKDF binding)
├── exceptions.py          # Exception hierarchy
├── _numeric.py            # NumPy-free numerical utilities
├── _finalizer_health.py   # Finalizer health reporting
├── _owner_only.py         # Owner-only file and directory permissions
└── *.so                   # Six compiled extensions: math_engine and the
                           # sha3, hmac, hkdf, ed25519, dilithium bindings

Root-level:
├── ama_cryptography_monitor.py  # Monitor compatibility shim
└── tools/monitoring/            # 3R runtime monitor demo
```

### Core Components

#### ama_cryptography.crypto_api (primary)

- `create_crypto_package(content: bytes, config: Optional[CryptoPackageConfig] = None) -> CryptoPackageResult`
- `verify_crypto_package(content, package, expected_public_key=None) -> Dict[str, bool]`

`all_valid` is False unless `expected_public_key` is supplied and matches the package's signing key (since 4.0): without a trust anchor, verification proves integrity and internal consistency only. RFC 3161 tokens are not checked by this call.

#### ama_cryptography.legacy_compat (deprecated)

Standalone functions ported from the former `code_guardian_secure` module; `create_crypto_package` and `verify_crypto_package` emit `DeprecationWarning`.

- `create_crypto_package(codes, helix_params, kms, author, use_rfc3161=False, tsa_url=None, monitor=None) -> CryptoPackage`
- `verify_crypto_package(codes, helix_params, package, hmac_key, monitor=None, require_quantum_signatures=None) -> Dict[str, Optional[bool]]` — `hmac_key` is required and is the authenticity gate
- `generate_ed25519_keypair(seed=None) -> Ed25519KeyPair`
- `generate_dilithium_keypair() -> DilithiumKeyPair`

#### KeyManagementSystem (legacy)

Holds the master secret, the derived HMAC key and Ed25519 keypair, the ML-DSA-65 keypair and the ethical vector.

**Data Structure**:
<!-- example: python-names module=ama_cryptography.legacy_compat -->
```python
@dataclass
class KeyManagementSystem:
    master_secret: bytes        # 256-bit root secret
    hmac_key: bytes            # Derived HMAC key
    hkdf_salt: bytes           # Salt the derivation used
    ed25519_keypair: Ed25519KeyPair
    dilithium_keypair: Optional[DilithiumKeyPair]
    creation_date: str         # ISO 8601 UTC timestamp
    rotation_schedule: str     # "quarterly", "monthly", "annually"
    version: str
    ethical_vector: Dict[str, float]
    quantum_signatures_enabled: bool = True
```

#### CryptoPackage (legacy)

**Data Structure**:
<!-- example: python-names module=ama_cryptography.legacy_compat -->
```python
@dataclass
class CryptoPackage:
    content_hash: str          # SHA3-256 hex digest
    hmac_tag: str             # HMAC-SHA3-256 hex tag
    ed25519_signature: str    # Ed25519 signature hex
    dilithium_signature: Optional[str]  # ML-DSA-65 signature hex
    timestamp: str            # ISO 8601 UTC timestamp
    timestamp_token: Optional[str]  # RFC 3161 token (base64)
    author: str               # Signer identifier
    ed25519_pubkey: str       # Embedded public key
    dilithium_pubkey: Optional[str]  # Embedded public key
    version: str              # Package format version
    ethical_vector: Dict[str, float]  # 4 Ethical Pillar scores
    ethical_hash: str         # SHA3-256 hash of ethical vector
    quantum_signatures_enabled: bool  # Whether PQC signatures are present
    signature_format_version: str     # Signature format version tag
    hash_format_version: str          # Content-hash format version tag
```

### Adaptive Posture System

**Module:** `ama_cryptography/adaptive_posture.py`

The adaptive posture system connects the 3R runtime anomaly monitor to the cryptographic API.

```
3R Monitor → PostureEvaluator → CryptoPostureController → KeyRotationManager
             (weighted scoring)  (cooldown enforcement)    (rotation)
                                                         → AlgorithmType
                                                           (strength escalation)
```

**Components:**
- `PostureEvaluator`: Weighted scoring model consuming **four** signals — timing 0.45, pattern 0.25, resonance 0.15 and Lyapunov stability 0.15 (`PostureEvaluator` weights). Threat-level boundaries are 0.15 / 0.45 / 0.80 (`PostureEvaluator.DEFAULT_*_THRESHOLD`). The accumulated score is a decaying peak-hold (`max(score, acc × decay_rate)`, default 0.95); escalation requires `escalation_count` (3) consecutive evaluations, and de-escalation a hysteresis band.
- `CryptoPostureController`: Orchestrates key rotation via `KeyRotationManager` and algorithm escalation over per-family ladders (`ALGORITHM_FAMILIES`: signature ED25519 < ML_DSA_65 < SPHINCS_256F < HYBRID_SIG; KEM KYBER_1024 < HYBRID_KEM). An escalation never crosses families, and an algorithm in no family is refused at construction (INVARIANT-35).

### Hybrid Key Combiner

**Module:** `ama_cryptography/hybrid_combiner.py`

Binding construction for hybrid KEM (classical + PQC) shared secrets per Bindel et al. (PQCrypto 2019):

```
salt = u32be(len(classical_ct)) || classical_ct || u32be(len(pqc_ct)) || pqc_ct
ikm  = classical_ss || pqc_ss                        # both fixed 32 bytes
info = label || 0x02 || u32be(len(classical_pk)) || classical_pk
             || u32be(len(pqc_pk)) || pqc_pk          # label = b"ama-hybrid-kem-v2"
combined_ss = HKDF-SHA3-256(salt, ikm, info, 32)
```

Security: IND-CCA2 if either component KEM is IND-CCA2 (the Bindel et al. combiner argument). Uses native C `ama_hkdf` (HMAC-SHA3-256) and **nothing else** — with the native backend unavailable, `HybridCombiner.combine()` raises `RuntimeError` rather than deriving the combined secret in Python. That is INVARIANT-7: a pure-Python HKDF here would be a non-constant-time substitute in a secret-dependent path, chosen automatically and silently. The `_hkdf_python` reference implementation remains in the class for unit tests and refuses to run without an explicit keyword-only opt-in.

---

## Data Flow and Processing Pipeline

### Package Creation Flow

```
crypto_api.create_crypto_package(content, config):
1. Refuse unless OPERATIONAL; content must be non-empty bytes
2. content_hash = SHA3-256(content)
3. hmac_key = CSPRNG(32); hmac_tag = HMAC-SHA3-256(hmac_key, content)
4. Primary keypair: config.signing_keypair, else generated (pairwise-tested, INVARIANT-41)
5. Optional SLH-DSA-SHA2-256f signature over content
6. master_secret, hkdf_salt = CSPRNG(32) each; derived_keys[i] = HKDF(master, salt,
   b"ama_cryptography_crypto_package_v1:" || i)
7. Optional ML-KEM-1024 encapsulation (shared-secret commitment in metadata)
8. Optional RFC 3161 token (tsa_mode online | mock | disabled)
9. Metadata, including the derived-keys and KEM commitments
10. primary_signature = Sign(package_transcript(package, content_hash))  # HYBRID_SIG by default
Returns CryptoPackageResult (holds hmac_key and hkdf_master_secret; to_dict() strips them)

legacy_compat.create_crypto_package (deprecated):
canonical hash → ethical_hash → optional RFC 3161 token over content_hash (failure raises)
→ assemble package → ML-DSA-65 over transcript("signature") → HMAC over
transcript("hmac") → Ed25519 over transcript("signature")
```

### Package Verification Flow

```
crypto_api.verify_crypto_package(content, package, expected_public_key=None):
1. Content hash: recompute SHA3-256 and compare
2. HMAC: recompute with the key carried in the package; constant-time compare
3. Signature: rebuild package_transcript() over the supplied content and verify the
   primary signature against expected_public_key when supplied, else the embedded key
4. Derived keys: re-derive, compare, and check the signed commitment
5. Optional add-ons: SLH-DSA signature; KEM shared secret when a keypair is available
6. all_valid: every executed check passed AND expected_public_key was supplied and matched
   (the RFC 3161 token is not checked here)

legacy_compat.verify_crypto_package (deprecated):
returns a per-check map (content_hash, ethical_vector, hmac, ed25519, dilithium,
timestamp, rfc3161_binding) with no aggregate; hmac is the authenticity gate.
rfc3161_binding recomputes the message imprint and compares it in constant time
(§2.4.2). The TSA signature and certificate chain are NOT verified, and genTime is
NOT evaluated: a passing check means the token refers to this data, not that a
trusted authority issued it (INVARIANT-37).
```

---

## Key Management Architecture

### Key Hierarchy (legacy KMS)

```
                    +------------------+
                    |  Master Secret   |
                    |  (256 bits)      |
                    +--------+---------+
                             |
              +--------------+
              |              |
              v              v
        +-----------+  +-----------+        +-----------+
        | HMAC Key  |  | Ed25519   |        | ML-DSA-65 |
        | HKDF[0]   |  | Seed      |        | Key Pair  |
        +-----------+  | HKDF[1]   |        | (CSPRNG)  |
                       +-----+-----+        +-----------+
                             |
                             v
                       +-----------+
                       | Ed25519   |
                       | Key Pair  |
                       +-----------+
```

### Key Derivation

The legacy KMS derives its keys with the construction in [Mathematical Integration](#mathematical-integration): `HKDF-SHA3-256(master_secret, hkdf_salt, f"{context}:{i}" || ethical_signature)`. The ML-DSA-65 keypair comes from the CSPRNG, not from the master secret.

### Key Rotation

`KeyRotationManager` (`key_management.py`) records key lifecycle state (ACTIVE, ROTATING, DEPRECATED, REVOKED, COMPROMISED), expiry and usage limits, and reports `should_rotate()` on expiry, usage limit or `rotation_period` (default 90 days). Generating and installing the replacement key, and zeroing the old one, is the caller's responsibility (or `CryptoPostureController`'s, when adaptive posture triggers rotation).

### HSM Integration Points

`HSMKeyStorage` (`key_management.py`) stores master secrets through any PKCS#11 module via the optional PyKCS11 dependency. CI exercises it against SoftHSM2 only; other tokens (YubiKey, Nitrokey, AWS CloudHSM PKCS#11 libraries) use the same interface but are not tested here.

---

## Security Architecture

### Threat Model

**In-Scope Threats**:
- Quantum computer attacks on classical signatures (Shor's algorithm)
- Classical cryptanalytic attacks on hash functions and signatures
- Data tampering and forgery attempts
- Key compromise through timing and cache side channels (INVARIANT-12); power and EM analysis are out of scope

**Not mitigated by the package format**: a valid package re-presented verifies again; freshness and replay detection are the application's responsibility (`session` provides a replay window for `secure_channel` only).

**Out-of-Scope Threats**:
- Physical access to execution environment
- TSA compromise is not the relevant timestamp threat here: AMA verifies no TSA signature, so a forged token needs no compromise at all (THREAT_MODEL.md T3.7)
- Denial of service attacks
- Social engineering attacks
- Defects in the host platform: kernel CSPRNG, CPython interpreter, C toolchain

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full model.

### Security Properties

| Property | Mechanism | Assurance Level |
|----------|-----------|-----------------|
| Integrity | SHA3-256 + HMAC | 128-bit |
| Authenticity | Ed25519 + ML-DSA-65 against an out-of-band trusted public key (`expected_public_key`); without it, integrity only | ~128-bit classical; NIST category 3 (ML-DSA-65) |
| Non-repudiation | Digital signatures (Ed25519 + ML-DSA-65), relative to a signing key the verifier trusts out of band | Cryptographic proof. RFC 3161 contributes **nothing** here: no TSA signature is verified, so a token is not attributable to any authority ([INVARIANT-37](INVARIANTS.md#invariant-37--a-verification-api-must-not-claim-a-check-it-does-not-perform)) |
| Ethical binding (legacy API) | HKDF context integration | Domain separation |
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

HKDF info      := enc(b) || binder(0x03) || u32be(info_len) || info   (ama_hkdf_agent_bound)
signature ctx  := SHA3-256(0x02 || enc(b) || binder(0x04))            (ama_agent_binding_context)
authorization  := HMAC-SHA3-256(K_auth, 0x01 || enc(b))                (operator-held K_auth)

binder(s)      := HMAC-SHA3-256(K_auth, s || enc(b))   if the binding requires authorization
               := 0^32                                  otherwise (unrestricted)
```

The four sub-domain tags (`0x01` authorization, `0x02` signature context,
`0x03` / `0x04` the HKDF and context binders) keep any one of those values from
ever being replayable as another. Because `enc(b)` is folded into the KDF and
the signature context, material derived under one binding is cryptographically
unrelated to the same input under any other — an agent cannot relabel
ephemeral material as persistent after the fact; it would have to derive it
again, which is the call the policy refuses. The binder makes `K_auth` an input
to a restricted binding's derivations rather than only to the gate in front of
them (2026-09 audit, A-6). These are the 5.0.0 layouts: earlier releases had no
binder for any binding, so every derived key and signature context differs
from 4.x for the same inputs, unrestricted bindings included.
`tests/c/test_agent_binding.c` pins both layouts with byte KATs.

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

Against forgery of a `HYBRID_SIG` package verified with a trusted key, an adversary must forge both Ed25519 and ML-DSA-65 over the same transcript: about 2^128 classical work, and NIST category 3 against a quantum adversary (ML-DSA-65; Ed25519 contributes nothing against Shor's algorithm). Every layer depends on SHA-3 (and Ed25519 on SHA-512): a practical SHA3-256 collision defeats the content digest and with it the transcript that every signature covers. The `crypto_api` HMAC key travels with the package, so that layer adds nothing against an adversary who holds the package; in the legacy API it authenticates to holders of the caller-supplied key. The optional RFC 3161 timestamp is **not** an independent operation: it is a binding check an adversary satisfies unaided (see below), so it must not be counted toward the bound.

Written security arguments for the original constructions are in [`docs/DESIGN_NOTES.md`](docs/DESIGN_NOTES.md).

### Scope: RFC 3161 attestation is not implemented

This is recorded as a scoped gap rather than described as a delivered property, because the difference is the whole of the layer's value.

**What is missing.** A timestamp exists to let a third party attest that data existed at a time. That attestation is carried entirely by the TSA's CMS `SignerInfo` signature over the `TSTInfo`, and by the validation of the certificate that signed it. AMA implements neither, so it implements the RFC 3161 *format* and the *binding*, and none of the *attestation*.

**What that costs, precisely.** Forging a token AMA accepts requires no key, no compromise and no privileged network position — only the ability to hand the verifier a token. An adversary builds a CMS `SignedData` offline whose `messageImprint` is the digest of your content and whose `genTime` is whatever they choose. `extract_tst_info` requires the structure to carry a signer, so the forgery must be well-formed; nothing checks that the signer is real. This is strictly weaker than the "TSA compromise" threat, and [THREAT_MODEL.md](THREAT_MODEL.md) carries it as row T3.7.

**Why it is not closed in this change.** It needs three things AMA does not have, and each is a component rather than a function: CMS `SignerInfo` processing (RFC 5652 §5.3, including the `signedAttrs` `messageDigest` and `contentType` binding, without which a signature over the wrong bytes verifies); X.509 path validation (RFC 5280 §6, the full algorithm — name chaining, validity windows, basic constraints, key usage, EKU `id-kp-timeStamping`, and revocation), which is a documented exclusion for this release; and a trust store with a policy for what anchors a deployment accepts. Shipping a partial version of any of them would produce something that passes a happy-path test and reports success against a certificate it never really validated — the same failure mode this section exists to retire.

**What closing it requires,** so it can be scheduled rather than guessed at:

- CMS `SignerInfo` verification: `signedAttrs` canonical re-encoding (RFC 5652 §5.4 — the SET OF must be re-encoded with its implicit tag replaced, a detail that silently invalidates otherwise-correct implementations), the `messageDigest` and `contentType` attribute bindings, and signature verification under the algorithms real TSAs use (RSASSA-PKCS1-v1_5, RSASSA-PSS and ECDSA over the NIST curves, which `ama_nistp.c` implements).
- X.509 certificate parsing and RFC 5280 §6 path validation, including EKU `id-kp-timeStamping` (RFC 3161 §2.3 requires it, and a TSA certificate accepted without it is a general-purpose certificate being trusted for time).
- A trust-anchor store and an explicit policy surface, defaulting to refusal rather than to a bundled anchor set.
- Revocation (CRL or OCSP), or an explicit, documented refusal to check it — a timestamp verified against a revoked TSA certificate is the case the whole control exists for.
- Only then: `RFC3161_CAPABILITIES["tsa_signature"]` and `["tsa_certificate_chain"]` flip to `True`, which is the single edit that permits every claim this document currently withholds. [INVARIANT-37](INVARIANTS.md#invariant-37--a-verification-api-must-not-claim-a-check-it-does-not-perform)'s gate reads that table, so the documentation and the code cannot be updated out of step in either direction.

### Security Assumptions

The security analysis assumes:

1. SHA3-256 behaves as a random oracle
2. HMAC-SHA3-256 is a secure PRF (widely believed, not formally proven for sponge constructions)
3. The ECDLP on edwards25519, P-256/384/521 and secp256k1 is hard for classical computers, and SHA-512 is collision-resistant
4. Module-LWE and Module-SIS are hard for quantum and classical computers (ML-KEM, ML-DSA), and the SLH-DSA hash assumptions hold
5. The platform CSPRNG output is indistinguishable from uniform
6. The constant-time code has no secret-dependent timing on the deployment platform — checked by dudect and Valgrind lanes, not proven

---

## Power-On Self-Test and Module Integrity

`import ama_cryptography` runs POST (`_self_test._run_self_tests`) under `_POST_LOCK`, in this stage order:

1. `native-backend`: the library is present, loadable, and passes the ABI and major-version checks (INVARIANT-42).
2. `kat-pre-integrity`: SHA3-256 and Ed25519 KATs, the primitives integrity verification relies on.
3. `integrity`: SHA3-256 digests of the package sources and native library, with the Ed25519 signature of the build-time artefact (INVARIANT-17).
4. `execution-integrity`: the executed bytecode matches the signed source (INVARIANT-40).
5. `kat`: HMAC-SHA3-256, AES-256-GCM, ML-KEM-1024, ML-DSA-65, SLH-DSA-SHA2-256f, SLH-DSA-SHAKE-128s.
6. `oracle`: constant-time timing oracle on `ama_consttime_memcmp`.
7. `rng`: two OS CSPRNG draws must differ.

Behaviour:
- The first failure puts the module in ERROR and the import raises `CryptoModuleError` (INVARIANT-39). A stage that raises also enters ERROR with the stage and exception recorded, and the exception still propagates.
- In ERROR, every cryptographic entry point refuses through `check_crypto_permitted()` / `check_operational()` (enforced by `tools/check_error_state_gating.py`).
- Each stage's wall-clock is published as `module_attestation()["stage_durations_ms"]`; a failed run's timings and results are kept in `last_failure()`.
- `AMA_FIPS_STRICT=1` turns a skipped KAT or oracle into a failure. `AMA_POST_DIAGNOSTIC_IMPORT=1` completes the import in ERROR for triage; cryptography stays refused.
- The native library is digest-verified before it is mapped, and binding extensions before they execute.
- Asymmetric key generation runs a pairwise consistency test (INVARIANT-41), and the declared ctypes ABI is cross-checked against the header (`tools/check_ctypes_abi.py`, INVARIANT-42).

Detail: [SECURITY.md § Module Integrity Verification](SECURITY.md#module-integrity-verification).

---

## Performance Architecture

### Performance Targets and Measured Latency

Every number below is **derived from one record** —
`benchmarks/benchmark-results.json`, written by `benchmarks/benchmark_runner.py`
— and regenerated by `python tools/update_docs.py`. It is not typed by hand.

<!-- AUTO-PIPELINE-LATENCY-START -->
<!-- Generated by `python tools/update_docs.py` from benchmarks/benchmark-results.json. Do not edit by hand: every number below is 1000 / ops_per_second from that record, so the latency view and the throughput view in wiki/Performance-Benchmarks.md cannot disagree. -->

| Operation | Target latency | Measured latency (ms/op) | Measured throughput (ops/sec) |
|-----------|---------------:|-------------------------:|------------------------------:|
| Package Creation (multi-layer) | < 5 ms | 0.721 | 1,386.9 |
| Package Verification (multi-layer) | < 5 ms | 0.409 | 2,444.0 |
| ML-DSA-65 Sign (dominant package-creation cost) | < 5 ms | 0.460 | 2,172.4 |
| Ed25519 Sign | < 1 ms | 0.028 | 35,287 |
| HMAC-SHA3-256 (1 KB) | < 1 ms | 0.0049 | 205,641 |
| SHA3-256 Hash (1 KB) | < 1 ms | 0.0033 | 298,723 |
| HKDF-SHA3-256 (3-key derive) | < 1 ms | 0.0073 | 136,549 |

**Bottleneck.** ML-DSA-65 signing costs 0.460 ms against 0.721 ms for a whole multi-layer package creation — 64% of the pipeline, and the single dominant term. Both figures are rows of the table above, so the claim is arithmetic on one record rather than two independently typed constants.

**Provenance — everything needed to reproduce these numbers:**

- **Benchmark command:** `python benchmarks/benchmark_runner.py --verbose --baseline benchmarks/baseline.json --require-runner-class x86_64 --require-populated-baseline --output benchmarks/benchmark-results.json --markdown benchmark-report.md`
- **Source record:** `benchmarks/benchmark-results.json`, run 2026-09-22
- **Platform:** Linux-6.18.44-fc-v37-x86_64-with-glibc2.39 / x86_64 — 4 logical processor(s)
- **Build:** v5.0.0 · digest d95f5cc73e89c347… · libama_cryptography.so
- **Commit:** `4e4fa7fa7f25` — DIRTY (uncommitted changes: ama_cryptography/_integrity_digest.txt, ama_cryptography/_integrity_signature.py)
- **Python bindings:** 6 of 6 compiled bindings imported: dilithium_binding, ed25519_binding, hkdf_binding, hmac_binding, math_engine, sha3_binding
- **Scope:** one run on the host named above. CMake flags are not recorded by the runner. These are not the canonical-host figures (README, Performance Metrics) and not the CI regression floors.
- **Units:** milliseconds per operation, computed as `1000 / ops_per_second`; the throughput column is the record's own `ops_per_second` field.
- **Sampling:** batches grown (sized to the fastest rate observed) until a timed batch spans >= 0.15s of measured wall-clock; 3 full-window batches per call
- **Aggregation:** fastest observation (throughput noise is one-sided: interference can only make an operation look slower)
- **Tolerance:** none is enforced on this table — it is a measurement of one host. The enforced floors live in `benchmarks/baseline.json` (x86-64) and `benchmarks/arm-baseline.json` (aarch64), with each row's own `tolerance_percent`, and the `benchmark-regression` CI job fails a run that falls below them.
- **Drift detection:** `tools/check_benchmark_claims.py` (CI, `security-checks`) re-derives every cell here from the record and fails on a mismatch, so a hand-edited number cannot survive a push.

To refresh: re-run the command above on the host you want published, then `python tools/update_docs.py`.
<!-- AUTO-PIPELINE-LATENCY-END -->

### Optimization Strategies

**Cryptographic Optimization**:
- Pre-computed NTT tables for ML-KEM and ML-DSA
- Keccak-f[1600]: scalar single-state permutation (BMI1/BMI2 build on CPUID; NEON on AArch64); 4-way AVX2/AVX-512 kernels for batched SHAKE sampling in ML-KEM and ML-DSA
- `KeypairCache` (`crypto_api`) and the `signing_keypair` normalization memo avoid repeated key work

**Memory Management**:
- Secure zeroing of key material after use, including on every error path (INVARIANT-6)
- Automatic cleanup via context managers

### Cython Acceleration Strategy

**FFI bindings** (`sha3_binding.pyx`, `hmac_binding.pyx`, `hkdf_binding.pyx`, `ed25519_binding.pyx`, `dilithium_binding.pyx` under `src/cython/`) call the native entry points with no ctypes argument marshaling. `pqc_backends.hmac_sha3_256()` (used by `legacy_compat`) takes the Cython path when built; `crypto_api`'s HMAC layer calls `native_hmac_sha3_256` (ctypes) directly. No Cython-versus-ctypes ratio has been measured in this tree, so none is published.

**`src/cython/math_engine.pyx`** — the 3R monitor's math:
- Lyapunov stability computation
- Matrix-vector multiplication
- NTT (internal `cdef` helpers, not exported)
- Helix evolution

No speed-up ratio is published for these kernels (INVARIANT-36). `python benchmarks/performance_suite.py` measures the Lyapunov and matrix-vector kernels against their NumPy baselines on the host it runs on.

**`src/cython/helix_engine_complete.pyx`** — a reference source for the helix-equation engine; not compiled by `setup.py`.

A binding extension that is not built is replaced by the ctypes binding to the same native function; no cryptographic operation runs in Python (INVARIANT-7). A built extension whose digest does not match the signed artefact is refused before it executes. `math_engine` alone falls back to pure-Python numerics.

### Build System Architecture

The C library uses CMake (`CMakeLists.txt`):

| Option | Default | Effect |
|--------|---------|--------|
| `AMA_USE_NATIVE_PQC` | ON | Compile ML-KEM, ML-DSA, SLH-DSA, X25519, ChaCha20-Poly1305, Argon2id, secp256k1, the P-curves, FROST and the platform CSPRNG |
| `AMA_AES_CONSTTIME` | ON | Bitsliced AES S-box (`ama_aes_bitsliced.c`); OFF also requires `AMA_AES_TABLE_INSECURE=ON` (INVARIANT-20) |
| `AMA_AES_TABLE_INSECURE` | OFF | Acknowledges the cache-timing-unsafe table S-box |
| `AMA_BUILD_SHARED` / `AMA_BUILD_STATIC` | ON | Shared and static libraries |
| `AMA_BUILD_TESTS` | ON | C test suite (`tests/c/`) |
| `AMA_BUILD_EXAMPLES` | ON | C examples (`examples/c/`) |
| `AMA_BUILD_FUZZ` | OFF | libFuzzer harnesses |
| `AMA_ENABLE_SIMD` | ON | Master switch for SIMD paths |
| `AMA_ENABLE_AVX2` | ON | AVX2 kernels (x86-64) |
| `AMA_ENABLE_AVX512` | OFF | AVX-512 4-way Keccak |
| `AMA_ENABLE_NEON` | ON | NEON kernels (AArch64) |
| `AMA_ENABLE_SVE2` | OFF | SVE2 kernels (ARMv9) |
| `AMA_ENABLE_LTO` | ON | Link-time optimization |
| `AMA_ENABLE_SANITIZERS` | OFF | ASan / UBSan |
| `AMA_ENABLE_DUDECT` | OFF | dudect constant-time tests |
| `AMA_ENABLE_NATIVE_ARCH` | OFF | `-march=native` |
| `AMA_KYBER_BUILD_DIAGNOSTICS` | OFF | Kyber NTT/CPA debug block (test-only) |

`AMA_TESTING_MODE` is not a user-facing `option()`: when `AMA_BUILD_TESTS=ON`, it is applied as a private compile definition on the separate `ama_cryptography_test` static library, exposing internal symbols (e.g. `randombytes` hooks for deterministic KAT testing, the CSPRNG-failure hooks in ML-KEM, ML-DSA, SLH-DSA, X25519 and the P-curves, and the MakeHint test exports declared in `src/c/internal/ama_testing_exports.h`) without contaminating the installable production libraries.

When `AMA_USE_NATIVE_PQC=OFF`, the library keeps SHA-2, SHA-3, HMAC, HKDF, PBKDF2, Ed25519, AES-GCM, Ascon, HSS/LMS verification and agent binding, and drops the platform CSPRNG, ML-KEM, ML-DSA, SLH-DSA, X25519, ChaCha20-Poly1305, Argon2id, secp256k1, the P-curves and FROST.

Fuzz harnesses are built separately via `fuzz/CMakeLists.txt` (17 targets), one per primitive family, each driving that family's parsers and verifiers with attacker-supplied bytes. The RFC 8554 HSS/LMS verifier was the last parser without one, which `CRYPTO_REVIEW_CHECKLIST.md` requires; `fuzz_lms` closes that gap. The targets do not cover every C implementation. Measured 2026-09-24 on x86-64 by running each harness once over its seed corpus with coverage instrumentation, no harness executes: PBKDF2 (`ama_pbkdf2.c`), the SHA-384/512 one-shots (`ama_sha512.c`) and HMAC-SHA-384 (`ama_hmac_sha384.c`), which take no structured input and are pinned by `tests/c/test_sha512_kat.c`, `tests/test_sha2_pbkdf2_native.py` and `tests/test_public_hmac_hkdf_api.py`; the `ama_context` API in `ama_core.c`, whose `ama_verify` checks the hybrid signature's fixed length and splits it for its verifier (Ed25519, ML-DSA-65), both of which the harnesses do drive (pinned by `tests/c/test_core.c`); the kernels a host's dispatch does not select (on that host the bitsliced AES, the AVX2 X25519 and the MULX Ed25519 paths); and the NEON, SVE2 and AVX-512 kernels, which the x86-64 fuzz lane cannot execute.

### Architectural Invariants

Every change must satisfy the architectural invariants defined in [`INVARIANTS.md`](INVARIANTS.md) (canonical, INVARIANT-1 through INVARIANT-53). `.github/INVARIANTS.md` is a three-line pointer to it, kept that way by the version-consistency gate so a second divergent copy cannot reappear. Highlights:

1. **INVARIANT-1 — Zero External Crypto Dependencies**: All cryptographic primitives are owned natively. No third-party crypto packages (`libsodium`, `pynacl`, `cryptography`, etc.). Python stdlib `os`/`secrets` permitted for OS entropy; `hashlib` (OpenSSL-backed in every libcrypto-linked CPython) is confined to the pre-execution trust bootstrap and two comparators whose output the library never emits (POST's hashlib cross-check of the SHA3-256 KAT; `hybrid_combiner`'s test-only HKDF reference), pinned with exact per-file counts by `tools/check_stdlib_hash_boundary.py` — all production hashing and key derivation runs on the native kernels. All primitives must map to a non-deprecated entry in [`CSRC_STANDARDS.md`](CSRC_STANDARDS.md); no cryptographic source is vendored, and `src/c/vendor/` must not exist (the vendor-isolation gate fails the build if it reappears).
2. **INVARIANT-2 — Fail-Closed CI**: Security-critical CI steps must not use `continue-on-error: true`.
3. **INVARIANT-6 — Secret Key Zeroing on All Exit Paths**, including CSPRNG-failure exits.
4. **INVARIANT-7 — No Cryptographic Fallbacks, Ever**.
5. **INVARIANT-12 — Constant-Time for All Secret-Dependent Operations**.
6. **INVARIANT-15 — Thread-Safe CPU Dispatch**: `ama_cpuid.c` one-time init must use `pthread_once` (POSIX) or `InitOnceExecuteOnce` (Windows — MSVC and MinGW-w64 alike, selected on `_WIN32` rather than `_MSC_VER`); lockless flag + plain-variable patterns are prohibited.
7. **INVARIANT-39 / -40 — A Failed POST Fails the Import; Executed Bytecode Matches Signed Source**.
8. **INVARIANT-52 — A Package Signature Covers the Whole Package**.

See [`INVARIANTS.md`](INVARIANTS.md) for the complete set (INVARIANT-1 through INVARIANT-53) and vendoring policy.

---

## Deployment Architecture

### Supported Platforms

Tested in CI: `ubuntu-latest`, `macos-latest` (arm64), `macos-15-intel` and `windows-latest` × CPython 3.10–3.14 (`ci-build-test.yml`), plus AArch64 on `ubuntu-24.04-arm` and under QEMU (`arm-qemu.yml`). `python_requires >= 3.10`. No minimum memory or storage has been measured.

### Deployment Models

**Library Integration**: Import directly into Python applications
<!-- example: python-run -->
```python
from ama_cryptography.crypto_api import create_crypto_package, verify_crypto_package
```

**Demonstration**: `python -m ama_cryptography` runs the legacy demonstration; it is not a general CLI.
```bash
python -m ama_cryptography
```

**Containers**: CI builds `docker/Dockerfile` and `docker/Dockerfile.alpine`; no image is published.
```bash
docker build -f docker/Dockerfile -t ama-cryptography .
```

### State and Scaling

AEAD nonce state (INVARIANT-22) and session state are per-process or per-file and must not be shared between instances without the documented multi-process rules ([SECURITY.md § Multi-process AES-GCM nonce safety](SECURITY.md#multi-process-aes-gcm-nonce-safety)).

---

## Testing and Quality Assurance

### Test Categories

| Category | Purpose | Coverage Target | Files |
|----------|---------|-----------------|-------|
| Unit Tests | Individual function validation | `--cov` floor 75% (`pyproject.toml`) | Python test files under `tests/` (count enforced by `tools/check_documented_counts.py` — see the verified totals below) |
| C Unit Tests | Native library validation | Branch arcs no suite takes are inventoried by `tools/measure_branch_coverage.py --python-suite`; see AGENTS.md §11 for the dated figures | 94 `test_*.c` registered via ctest in `tests/c/` (+ 2 `x25519_equiv_*.c` helper translation units linked into `test_x25519_field_equiv`) |
| Integration Tests | Cross-component workflows | All public APIs | `test_integration_e2e.py`, `test_comprehensive_system.py` |
| Performance Tests | Benchmark regression detection | All critical paths | `benchmarks/` (instruction-count baselines, `check_baseline_justification.py`), `test_benchmark_baseline_infra.py`, `test_benchmark_baseline_freshness.py`, `test_published_benchmark_artefacts_are_current.py` |
| Security Tests | Cryptographic correctness | Adversarial and residue tests | `test_crypto_core_penetration.py`, `test_memory_security.py`, `tests/c/test_csprng_failure_residue.c` |
| Compliance Tests | Standards adherence | All claimed standards | `test_nist_kat.py`, `test_pqc_kat.py` |
| Fuzz Tests | Input mutation testing | 17 C targets | `fuzz/fuzz_*.c` (18 sources; `fuzz_rng.c` is a helper) |
| NIST ACVP Vectors | Official vector validation | 1,215 vectors, 12 algorithm functions (815 AFT + 400 SHA-3 MCT); self-attested, not CAVP | `nist_vectors/`; `acvp_validation.yml` fails if any of the 1,215 regresses (INVARIANT-18) |
| Wycheproof | Adversarial vectors | 15 vendored corpora | `wycheproof_vectors/run_wycheproof.py` |

**Total:** 6,560 Python test functions across 270 test files, plus the
ctest-registered C tests and the two `x25519_equiv_*.c` helper translation units under `tests/c/`,
which have no `main` of their own and are linked into `test_x25519_field_equiv`
(the set of C tests depends on `AMA_USE_NATIVE_PQC`, `AMA_AES_CONSTTIME`, the ISA
and the platform; `tests/c/CMakeLists.txt` is canonical).
See [`docs/METRICS_REPORT.md`](docs/METRICS_REPORT.md) for reproduction
instructions.

Tests are labelled PIN, RANGE or SMOKE by mutation (AGENTS.md §6.4). Among the 5.0.0 additions:

- `tests/c/test_csprng_failure_residue.c` drives every CSPRNG-failure exit in ML-KEM, ML-DSA, SLH-DSA and X25519 and scans the dead stack for the partial draw (INVARIANT-6).
- `tests/c/test_ml_dsa_hint_encoding.c` covers the FIPS 204 hint-ordering, padding and count rules (SUF-CMA) and MakeHint's boundary case.
- `tests/c/test_input_guards.c` covers NULL, short-buffer, context-length and range guards (RANGE).
- `tests/c/test_frost.c` Test 11 covers FROST CSPRNG failures, the non-canonical commitment verdict and the argument guards.

### Continuous Integration

| Workflow | Role |
|----------|------|
| `ci.yml` | Python test matrix, code quality (black, ruff, `mypy --strict` over every tracked `.py`, scope checked by `tools/check_type_check_scope.py`), the `tools/check_*.py` gates, Semgrep, benchmark regression, constant-time checks, AVX-512 lane, C-consumer build |
| `ci-build-test.yml` | C library across compilers and platforms, Python package matrix, instruction-count regression, Docker builds |
| `static-analysis.yml` | cppcheck, clang-analyzer, CodeQL, `-Werror` on x86-64 and AArch64, ASan, MSan, TSan, Valgrind, clang-tidy, reproducible build |
| `security.yml` | pip-audit, bandit, CycloneDX SBOM, TruffleHog |
| `dudect.yml` | dudect lanes and callgrind instruction-count invariance |
| `fuzzing.yml`, `clusterfuzzlite.yml` | libFuzzer on every PR; nightly ClusterFuzzLite campaigns |
| `acvp_validation.yml` | NIST ACVP vectors |
| `arm-qemu.yml` | AArch64 under QEMU (Crypto Extensions on and off, SVE2, UBSan) |
| `baseline-guard.yml`, `corpus-provenance.yml` | Benchmark-baseline justification; vendored corpus digests |
| `integrity-anchor-check.yml` | Release signing seed and trust anchor are a matching pair |
| `release.yml` | Wheels, sdist, reproducibility check, SLSA provenance, sigstore signing, GitHub Release |

### Test Vector Validation

Cryptographic implementations are validated against:

- **NIST ACVP vectors** (`nist_vectors/`): 1,215 vectors tested, 1,215 passed across 12 algorithm functions and 7 NIST standards (815 AFT + 400 SHA-3 MCT). See [CSRC_ALIGN_REPORT.md](docs/compliance/CSRC_ALIGN_REPORT.md) for full breakdown.
- NIST FIPS 202 SHA3-256, SHA3-512, SHAKE-128, SHAKE-256 test vectors
- FIPS 203 ML-KEM-1024 KAT vectors (10/10 pass — `tests/kat/fips203/`, regenerated from the pq-crystals reference generator)
- NIST FIPS 204 ML-DSA-65 KAT vectors (10/10 pass — `tests/kat/fips204/`)
- NIST FIPS 205 ACVP sigVer (the SLH-DSA-SHA2-256f and SHAKE-128s groups of `SLH-DSA-sigVer-FIPS205.json`) and sigGen vectors for both sets (`tests/kat/fips205/`)
- NIST FIPS 180-4 SHA-256 reference vectors
- NIST SP 800-38D AES-256-GCM test vectors
- RFC 2104 HMAC-SHA-256 and RFC 5869 HKDF test vectors
- Wycheproof (`wycheproof_vectors/`): AES-GCM, ChaCha20-Poly1305, ECDSA (P-256/384/521, secp256k1), Ed25519, X25519, HKDF-SHA-2, HMAC-SHA-2 and HMAC-SHA3-256
- RFC 6979 (`tests/kat/rfc6979/`), Ascon (`tests/kat/ascon/`), RFC 9500 key formats (`tests/kat/keyformats/`)
- Project-specific golden vectors for HMAC-SHA3-256 and HKDF-SHA3-256
- Pre-FIPS round-3 `.rsp` KATs for ML-KEM (512/768/1024) and ML-DSA (44/65/87), historical and parse-only

---

## Standards Compliance

### Cryptographic Standards

| Standard | Description | Implementation Status | Vector Validation |
|----------|-------------|---------------------|----------------|
| NIST FIPS 180-4 | SHA-2 | Algorithm implemented | ACVP / reference vectors |
| NIST FIPS 198-1 | HMAC | Algorithm implemented | ACVP (HMAC-SHA-256), Wycheproof |
| NIST FIPS 202 | SHA-3 Standard (SHA3-256, SHAKE128, SHAKE256) | Algorithm implemented | ACVP |
| NIST FIPS 203 | ML-KEM | Algorithm implemented | ACVP; **10/10 KAT pass** |
| NIST FIPS 204 | ML-DSA | Algorithm implemented | ACVP; **10/10 KAT pass** |
| NIST FIPS 205 | SLH-DSA | Algorithm implemented | ACVP sigVer/sigGen vectors |
| NIST FIPS 186-5, SP 800-56A r3, RFC 6979 | ECDSA and ECDH (P-256/384/521) | Algorithm implemented | Wycheproof, RFC 6979 |
| SEC 2 | secp256k1 (BIP32-style HD, not interoperable) | Algorithm implemented | Wycheproof |
| NIST SP 800-38D | AES-GCM | Algorithm implemented | ACVP, Wycheproof |
| NIST SP 800-132 | PBKDF2 | Algorithm implemented | — |
| NIST SP 800-208 / RFC 8554 | HSS/LMS | Verification only | — |
| NIST SP 800-232 | Ascon | Algorithm implemented | Ascon KATs |
| RFC 2104 / RFC 5869 | HMAC / HKDF | Algorithm implemented | RFC vectors, Wycheproof |
| RFC 8032 | Ed25519 | Algorithm implemented | Wycheproof |
| RFC 7748 | X25519 | Algorithm implemented | Wycheproof |
| RFC 8439 | ChaCha20-Poly1305 | Algorithm implemented | Wycheproof |
| RFC 9106 | Argon2 | Algorithm implemented | — |
| RFC 9591 | FROST(Ed25519, SHA-512) — RFC 9591-style; not ciphersuite-interoperable | Algorithm implemented | — |
| RFC 3161 | Time-Stamp Protocol | **Partial** — §2.4.1/§2.4.2 wire format and message-imprint binding implemented; CMS `SignerInfo` signature verification and X.509 path validation **not** implemented | RFC 3161 §2.4.1/§2.4.2 wire-format tests |

> **Note:** "Algorithm implemented" means the library implements the algorithm as specified and passes the NIST, RFC or Wycheproof vectors cited in its row. This is NOT a CAVP/CMVP validation claim. This implementation has not been submitted for CMVP validation and is not FIPS 140-3 certified.

### Code Quality Standards

- black formatting; ruff lint
- Type hints throughout (validated via `mypy --strict`, whole tree; scope enforced by `tools/check_type_check_scope.py`)
- Google-style docstrings (not linter-enforced)
- Maximum line length: 100 characters
- Maximum cyclomatic complexity: 15
- C: C11, clean under `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Werror` on gcc and clang (AGENTS.md §9)

---

## References

### Standards Documents

1. NIST FIPS 180-4: Secure Hash Standard (August 2015)
2. NIST FIPS 186-5: Digital Signature Standard (February 2023)
3. NIST FIPS 198-1: The Keyed-Hash Message Authentication Code (July 2008)
4. NIST FIPS 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions (August 2015)
5. NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (August 2024)
6. NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (August 2024)
7. NIST FIPS 205: Stateless Hash-Based Digital Signature Standard (August 2024)
8. NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC (November 2007)
9. NIST SP 800-56A Rev. 3: Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography (April 2018)
10. NIST SP 800-132: Recommendation for Password-Based Key Derivation (December 2010)
11. NIST SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes (October 2020)
12. NIST SP 800-232: Ascon-Based Lightweight Cryptography Standards for Constrained Devices (August 2025)
13. SEC 2: Recommended Elliptic Curve Domain Parameters, Version 2.0 (January 2010)
14. RFC 2104: HMAC: Keyed-Hashing for Message Authentication (February 1997)
15. RFC 3161: Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP) (August 2001)
16. RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF) (May 2010)
17. RFC 6979: Deterministic Usage of DSA and ECDSA (August 2013)
18. RFC 7748: Elliptic Curves for Security (January 2016)
19. RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA) (January 2017)
20. RFC 8439: ChaCha20 and Poly1305 for IETF Protocols (June 2018)
21. RFC 8554: Leighton-Micali Hash-Based Signatures (April 2019)
22. RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications (September 2021)
23. RFC 9500: Standard Public Key Cryptography (PKC) Test Keys (December 2023)
24. RFC 9591: The Flexible Round-Optimized Schnorr Threshold (FROST) Protocol for Two-Round Schnorr Signatures (June 2024)

### Implementation References

- `ama_cryptography/crypto_api.py`: Primary Python API
- `ama_cryptography/pqc_backends.py`: Native C library bindings
- `include/ama_cryptography.h`: Public C API (with `ama_cpuid.h`, `ama_dispatch.h`, `ama_uint128.h`)
- `SECURITY.md`: Security policy, module-integrity design, operational controls
- `docs/DESIGN_NOTES.md`: Written security arguments for original constructions
- `THREAT_MODEL.md`: Threat model and risk assessment
- `docs/BENCHMARK_HISTORY.md`: Published benchmark figures with host, method and per-run data
- `docs/compliance/CSRC_ALIGN_REPORT.md`: NIST ACVP vector validation results (1,215/1,215 pass — 815 AFT + 400 SHA-3 MCT)
- `CSRC_STANDARDS.md`: Governing standards registry
- `IMPLEMENTATION_GUIDE.md`: Deployment and integration guide
- `INVARIANTS.md`: Canonical architectural invariants (INVARIANT-1 through INVARIANT-53), including vendoring policy and CSRC_STANDARDS.md mapping (`.github/INVARIANTS.md` is a pointer to it)

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2025-11-26 | Steel Security Advisors LLC | Initial professional release |
| 1.1.0 | 2026-01-09 | Steel Security Advisors LLC | Version alignment |
| 2.0.0 | 2026-03-08 | Steel Security Advisors LLC | Zero-dependency native C architecture, adaptive posture, hybrid KEM combiner, AES-256-GCM, FIPS 203/204/205 algorithm implementation, Phase 2 primitives, ethical pillar alignment, Mercury Agent integration |
| 2.1.0 | 2026-03-25 | Steel Security Advisors LLC | Hand-written AVX2/NEON/SVE2 SIMD for 8 algorithms, runtime dispatch, security fixes S1-S6, HMAC-SHA3-256 Cython binding, CSRC alignment report, SHA-512 deduplication, Python package structure, Cython acceleration strategy, build system architecture, INVARIANTS reference, NIST ACVP validation (815 vectors), fuzz testing (12 targets) |
| 2.1.5 | 2026-04-17 | Steel Security Advisors LLC | Security audit fixes (length-prefixed HKDF encoding, constant-time ops), HSM support via PyKCS11, fd leak protection, INVARIANT-13 restoration with 52 tracked suppressions, comprehensive test coverage for secure_memory/crypto_api/PQC backends, documentation version alignment |
| 3.0.0 | 2026-04-27 | Steel Security Advisors LLC | RFC 9106 Argon2id byte-identity fix (BREAKING — `ama_argon2id_legacy` / `native_argon2id_legacy` verify-only shim) and `out_len` cap at `AMA_ARGON2ID_MAX_TAG_LEN = 1024`; in-house AVX-512 4-way Keccak permutation kernel (opt-in `-DAMA_ENABLE_AVX512=ON`, EVEX YMM-width `vprolq` + `vpternlogq`, XCR0 5+6+7 gated) with `docs/AVX512_KECCAK_ADR.md` ADR; X25519 fe64 (radix-2⁶⁴) ladder + hand-written MULX+ADX inline-asm kernel (`fe64_mul512_mulx` / `fe64_sq512_mulx` / `fe64_reduce512_mulx`) under BMI2∧ADX bundle gate; X25519 4-way AVX2 Montgomery-ladder kernel + `ama_x25519_scalarmult_batch` API (opt-in `AMA_DISPATCH_USE_X25519_AVX2=1`); VAES + VPCLMULQDQ YMM AES-256-GCM clean replacement; Ed25519 verify-path SWE rectification + base-point comb table + merged NTT + AVX2 rejection (Tier-B PQC); batch ML-DSA-65 / ML-KEM-1024 sampling via 4-way SHAKE128/SHAKE256 + CBD2 AVX2; ChaCha20-Poly1305 8-way AVX2 (≥ 512 B) and Argon2 BlaMka G AVX2; SHA-3 auto-tune hysteresis (best-of-5, 10% revert threshold); NIST ACVP self-attestation (815/815 AFT, weekly continuous validation); D-1…D-10 distribution / tooling audit (wheel SONAME bundling with `$ORIGIN`/`@loader_path` runtime_library_dirs, CLI subprocess test self-contained, isolated `setup.py` CMake build dir, fatal Cython failures + `numpy>=1.24.0` / `Cython>=3.2.4` build pins, dudect AES-GCM tag-compare redesign, `.semgrep.yml` 341 FP → 0, X25519 dispatch-policy contract test, `setuptools>=78.1.1` / `wheel>=0.46.2` supply-chain pins, `setuptools<70` preflight, fallthrough annotations in the formerly vendored Ed25519 x86-64 backend — since removed in 5.0.0, #394) |
| 3.1.0 | 2026-05-14 | Steel Security Advisors LLC | Public documentation alignment, v3.1.0 release hygiene, INVARIANT-14 CVE-ignore review, and no public API changes since v3.0.0 |
| 3.2.0 | 2026-05-20 | Steel Security Advisors LLC | Mercury Agent v1.7.0 alignment; per-slot SIMD auto-tune with file-based cross-process dispatch cache (`AMA_DISPATCH_CACHE_FILE`) + dispatch cache safety; `ama_keypair_generate(AMA_ALG_ED25519)` wiring; NTT benchmark overflow guard; dudect CI hygiene; native `native_hmac_sha256` Python bindings |
| 3.3.0 | 2026-07-05 | Steel Security Advisors LLC | Native one-shot SHA-256 (`native_sha256`); documented public convenience + native MAC/KDF surface (`quick_hmac` / `quick_hkdf`, native HMAC/HKDF SHA-2/3, `AmaCryptographyError` exception root); consolidated the two SLH-DSA-SHA2-256f C signers into one; completed native-hashing purity in `crypto_api`; SLSA provenance permissions + CodeQL unused-static resolution |
| 3.4.0 | 2026-07-25 | Steel Security Advisors LLC | Vendored Wycheproof gate; Ed25519 canonical-`S` (INVARIANT-26) and X25519 u-coordinate canonicalization (INVARIANT-27); agent-instance binding (INVARIANT-30) with 3R detectors; Ascon-AEAD128 / Ascon-Hash256 (SP 800-232) |
| 3.5.0 | 2026-07-30 | Steel Security Advisors LLC | NIST P-256/384/521 ECDSA and ECDH (FIPS 186-5, INVARIANT-34 low-`s` policy); ML-KEM-512/768 and ML-DSA-44/87 parameter sets; HSS/LMS verification (SP 800-208) |
| 4.0.0 | 2026-08-01 | Steel Security Advisors LLC | Trust-anchor enforcement end to end (anchor compiled into the native library, required for `verify_crypto_package`'s `all_valid`, and no longer bypassable by deleting the signature artefact); constant-time scalar GHASH with an optimizer value barrier and a callgrind instruction-invariance gate; Ed25519 canonical-`y` (INVARIANT-38) on single verify, batch verify and point decode; KDF policy floor on both cost and algorithm; per-epoch AEAD nonce budget (INVARIANT-22); package serialization and `SecureSession` no longer emit key material; RFC 8439 length limit on ChaCha20-Poly1305. BREAKING ×6 — see CHANGELOG `[4.0.0]`. |
| 5.0.0 | Unreleased | Steel Security Advisors LLC | Fail-closed FIPS 140-3 POST: `import ama_cryptography` raises on self-test failure and the ERROR state inhibits output on every surface (INVARIANT-39/-40); pairwise consistency test on every asymmetric keygen (INVARIANT-41); declared-ctypes-ABI cross-check with AST-discovered scope and a loaded-library major-version handshake (INVARIANT-42); pre-load SHA3-256 verification of the native library (hash-then-map via `/proc/self/fd`) with fail-closed unreadable-candidate handling; the six Cython binding extensions digest-bound into the v3 integrity artefact (BOTH signing callers bind — the wheel pipeline and the repair flow alike, since `integrity --update --sign` sets `--bind-extensions` unconditionally; anchored/developer severity split); repository-wide audit fixes — global `-mavx2` contamination removed from portable translation units, KyberSlash divisions replaced with exact Granlund–Montgomery reciprocal multiplies, SVE2 Keccak theta and Kyber NTT corrected and CI-built, dead CI gates made enforceable; one-shot AEAD wrapper throughput recovery (all-`bytes` fast path); benchmark floors recalibrated as measured medians with derived tolerances; pre-load refusal of a binding extension whose digest does not match the signed artefact (previously verified only after it had executed); the `AMA_BUILD_PIPELINE` carve-out that let an environment variable buy a mapping of an unverified native library replaced with an in-process signing-only scope; ML-KEM `Compress_d` applies its own `mod 2^d` with an exhaustive 16,645-pair proof; SoftHSM2, the semgrep end-to-end assertion, `test_dispatch_cache_file` on SIMD-off builds and `test_pq_parser_stack` under Valgrind all made executable; the dudect verdict rule distinguishes a directional leak from an unusable measurement.; in-house Ed25519 backend (fe51 by default, fe64-MULX by override) replacing ed25519-donna, which is removed (#394); ML-DSA-65 on the FIPS 204 external interface with context-separated hybrid signatures (INVARIANT-50); package signatures over a whole-package transcript (INVARIANT-52); INVARIANT-43 through INVARIANT-53; `ama_frost_verify_share` returns the verdict its header documents; CSPRNG-failure exits in ML-KEM, ML-DSA, SLH-DSA and X25519 scrub the partial draw (INVARIANT-6); POST records per-stage wall-clock, and a stage that raises enters ERROR with a recorded reason. BREAKING ×11 — see CHANGELOG `[5.0.0]`. |

---

Copyright 2025-2026 Steel Security Advisors LLC. Licensed under Apache License 2.0.
