<div align="center">

# AMA Cryptography

**Post-quantum + classical hybrid cryptographic library. Zero external crypto dependencies.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org)
[![C](https://img.shields.io/badge/C-C11-blue.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![PQC](https://img.shields.io/badge/PQC-ML--DSA--65%20%7C%20ML--KEM--1024-purple.svg)](CRYPTOGRAPHY.md)
[![Status](https://img.shields.io/badge/status-community--tested-orange.svg)](SECURITY.md)

</div>

---

## What AMA Cryptography Is

AMA Cryptography is a hybrid Ed25519 + ML-DSA-65 framework for quantum-resistant
integrity protection. Every cryptographic primitive — from SHA3-256 to ML-KEM-1024
— is implemented natively in C with zero external crypto library dependencies
([INVARIANT-1](#invariant-1--zero-external-crypto-dependencies)). The library is
NIST-validated against 815 ACVP test vectors with 0 failures.

Previously named **Ava Guardian** (renamed ~March 2026).

**Copyright 2025-2026 Steel Security Advisors LLC**
**Author/Inventor:** Andrew E. A.
**Status:** Community-tested | Not externally audited

---

## Performance

All numbers are measured medians from controlled benchmarks on the platform
listed below. No ranges, no approximations.

**Platform:** Intel Xeon @ 2.10GHz (AVX-512, SHA-NI, AES-NI, BMI2), GCC 13.3.0,
`-O3 -march=native -funroll-loops`, 4 CPU cores.

### Ed25519 (C library, direct)

Source: [`docs/ed25519_field_investigation_report.md`](docs/ed25519_field_investigation_report.md)
and assembly benchmark (this branch).

| Operation | fe51 (default) | donna assembly | Delta |
|---|---:|---:|---:|
| keygen | 22,189 ops/s | 85,715 ops/s | **+286%** |
| sign (240B) | 21,242 ops/s | 72,388 ops/s | **+241%** |
| verify (240B) | 10,082 ops/s | 25,823 ops/s | **+156%** |

donna assembly path: `cmake -DAMA_ED25519_ASSEMBLY=ON` (default OFF, x86-64 only).

### ML-DSA-65 (C library, via Python API)

Source: [`docs/performance_investigation_report.md`](docs/performance_investigation_report.md)

| Operation | ops/sec | Latency |
|---|---:|---:|
| KeyGen | 4,925 | 203 us |
| Sign | 4,315 | 232 us |
| Verify | 1,174,398 | 0.9 us |

### Core Primitives (C library, via Python API)

Source: [`docs/performance_investigation_report.md`](docs/performance_investigation_report.md)

| Operation | ops/sec |
|---|---:|
| SHA3-256 (1KB, ctypes) | 278,203 |
| SHA3-256 (1KB, Cython) | 332,447 |
| HMAC-SHA3-256 (1KB) | 185,874 |
| HKDF-SHA3-256 (96B) | 123,047 |

### Full 6-Layer Package

| Operation | ops/sec |
|---|---:|
| Package create | 1,939 |
| Package verify | 2,152 |

---

## Algorithm Support

| Algorithm | Standard | Implementation |
|---|---|---|
| ML-DSA-65 (Dilithium) | FIPS 204 | Native C |
| ML-KEM-1024 (Kyber) | FIPS 203 | Native C |
| SPHINCS+-SHA2-256f | FIPS 205 | Native C |
| Ed25519 | RFC 8032 | Native C (fe51 or donna) |
| X25519 | RFC 7748 | Native C |
| SHA3-256/512, SHAKE128/256 | FIPS 202 | Native C |
| HMAC-SHA3-256 | RFC 2104 / FIPS 202 | Native C |
| HKDF-SHA3-256 | RFC 5869 | Native C |
| Argon2id | RFC 9106 | Native C |
| ChaCha20-Poly1305 | RFC 8439 | Native C |
| AES-256-GCM | NIST SP 800-38D | Native C |

---

## Installation

### Build from Source

```bash
git clone https://github.com/Steel-SecAdv-LLC/AMA-Cryptography.git
cd AMA-Cryptography

# Install Python dependencies
pip install -r requirements.txt

# Build C library (all PQC algorithms included natively)
cmake -B build -DCMAKE_BUILD_TYPE=Release -DAMA_USE_NATIVE_PQC=ON
cmake --build build -j$(nproc)

# Run tests
cd build && ctest --output-on-failure
```

### Optional: ed25519-donna Assembly (x86-64)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release \
  -DAMA_USE_NATIVE_PQC=ON \
  -DAMA_ED25519_ASSEMBLY=ON \
  -DAMA_ENABLE_NATIVE_ARCH=ON
cmake --build build -j$(nproc)
```

### Optional: Cython Acceleration

```bash
python setup.py build_ext --inplace
```

### CMake Options

| Option | Default | Description |
|---|---|---|
| `AMA_USE_NATIVE_PQC` | ON | Native ML-DSA-65, ML-KEM-1024, SPHINCS+ |
| `AMA_ED25519_ASSEMBLY` | OFF | ed25519-donna x86-64 assembly scalar mult |
| `AMA_AES_CONSTTIME` | ON | Bitsliced AES S-box (cache-timing safe) |
| `AMA_ENABLE_NATIVE_ARCH` | OFF | `-march=native` for host-optimized builds |
| `AMA_ENABLE_AVX2` | ON | AVX2 SIMD optimizations |
| `AMA_ENABLE_LTO` | ON | Link-time optimization |
| `AMA_ENABLE_SANITIZERS` | OFF | AddressSanitizer/UBSan |

---

## Quickstart

### Sign and Verify (Python)

```python
from ama_cryptography.crypto_api import AmaCryptography, AlgorithmType

crypto = AmaCryptography(algorithm=AlgorithmType.HYBRID_SIG)
keypair = crypto.generate_keypair()

signature = crypto.sign(b"Hello, World!", keypair.secret_key)
valid = crypto.verify(b"Hello, World!", signature.signature, keypair.public_key)
print(f"Valid: {valid}")  # True
```

### KEM (Key Encapsulation)

```python
from ama_cryptography.crypto_api import AmaCryptography, AlgorithmType

kem = AmaCryptography(algorithm=AlgorithmType.ML_KEM_1024)
keypair = kem.generate_keypair()
ciphertext, shared_secret = kem.encapsulate(keypair.public_key)
decapsulated = kem.decapsulate(ciphertext, keypair.secret_key)
assert shared_secret == decapsulated
```

### Package Create and Verify

```python
from ama_cryptography.crypto_api import AmaCryptography, AlgorithmType

crypto = AmaCryptography(algorithm=AlgorithmType.HYBRID_SIG)
keypair = crypto.generate_keypair()

# Create 6-layer integrity package
package = crypto.create_package(b"Protected data", keypair.secret_key)

# Verify all 6 layers
valid = crypto.verify_package(package, keypair.public_key)
print(f"Package valid: {valid}")  # True
```

---

## Architecture

### INVARIANT-1 — Zero External Crypto Dependencies

AMA Cryptography owns all cryptographic primitives natively. No pre-built
external libraries (libsodium, OpenSSL, liboqs) are linked. Every algorithm is
implemented in C11 and compiled as part of AMA's build system.

**Why this matters:** Supply-chain attacks on cryptographic dependencies
(compromised packages, backdoored binaries, dependency confusion) are eliminated.
The attack surface is the auditable source in `src/c/` — nothing else.

**Vendoring policy:** Public-domain source vendored into `src/c/vendor/` and
compiled from source is permitted. Vendored source is AMA IP once integrated.
Currently vendored: [ed25519-donna](https://github.com/floodyberry/ed25519-donna)
(public domain, Andrew Moon) — see [INVARIANTS.md](INVARIANTS.md).

### Multi-Language Stack

| Layer | Role | Source |
|---|---|---|
| **C** (22 source files) | All cryptographic primitives, constant-time ops | `src/c/` |
| **Cython** (optional) | Accelerated Python-to-C bindings (18-37x vs pure Python) | `src/cython/` |
| **Python** | High-level API, key management, 3R monitoring | `ama_cryptography/` |

### 6-Layer Defense-in-Depth

| Layer | Protection |
|---|---|
| 1. SHA3-256 | Content integrity (128-bit collision resistance) |
| 2. HMAC-SHA3-256 | Keyed message authentication |
| 3. Ed25519 | Classical signatures (128-bit classical security) |
| 4. ML-DSA-65 | Quantum signatures (192-bit quantum security) |
| 5. HKDF | Key derivation (cryptographic key independence) |
| 6. RFC 3161 | Timestamping (third-party proof of existence) |

---

## NIST Validation

815 ACVP vectors tested across 12 algorithm functions. **815 passed, 0 failed.**

```bash
# C library KAT tests
cd build && ctest --output-on-failure

# Python NIST ACVP vectors
python3 nist_vectors/run_vectors.py
```

Algorithms validated: SHA3-256, SHAKE128/256, HMAC-SHA3-256, Ed25519,
AES-256-GCM, ML-DSA-65 (FIPS 204), ML-KEM-1024 (FIPS 203),
SPHINCS+-SHA2-256f (FIPS 205).

See [CSRC_ALIGN_REPORT.md](CSRC_ALIGN_REPORT.md) for the full validation matrix.

---

## Project History

AMA Cryptography was originally developed under the name **Ava Guardian**.
Renamed to AMA Cryptography ~March 2026 to reflect the project's broader scope
as a standalone cryptographic library. The cryptographic core, INVARIANT-1 policy,
and all algorithm implementations are unchanged from the Ava Guardian lineage.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
pip install -e ".[dev,all]"
make format   # clang-format, black
make lint     # ruff, mypy
make test     # all tests
```

## Security Disclosure

This is a self-assessed cryptographic implementation without third-party audit.
Production use requires independent security review by qualified cryptographers.
See [SECURITY.md](SECURITY.md) for responsible disclosure procedures.

---

## Contact

| Type | Contact |
|---|---|
| General | steel.sa.llc@gmail.com |
| Security Issues | [SECURITY.md](SECURITY.md) |
| GitHub Issues | [Issues](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/issues) |

---

## Legal

Copyright 2025-2026 Steel Security Advisors LLC. Apache License 2.0.

**Author/Inventor:** Andrew E. A.
**AI Co-Architects:** Eris, Eden, Devin, Claude

This project is a human/AI collaborative construct. The human architect does not
hold formal credentials in cryptography. All security analysis is self-assessed.
See the full disclaimer in [LICENSE](LICENSE).

*Last updated: 2026-03-20*
