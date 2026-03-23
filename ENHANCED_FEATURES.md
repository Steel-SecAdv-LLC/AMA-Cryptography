# AMA Cryptography Enhanced Features

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 2.1 |
| Last Updated | 2026-03-10 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Overview

AMA Cryptography v2.0 features a zero-dependency, multi-language architecture that combines the security of native C cryptographic primitives with the usability of Python. All cryptographic operations are implemented natively — no external cryptographic libraries required. This document describes the enhanced features available in the current release.

---

## Multi-Language Architecture

### Architecture Overview

```
+-------------------------------------------------------------+
|                     APPLICATION LAYER                       |
|                    (Python / CLI / Web)                     |
+------------------------------+------------------------------+
                               |
+------------------------------v------------------------------+
|                  PYTHON BINDINGS & API                      |
|            ama_cryptography/  (High-level interface)            |
+----+--------------------------------------------+------------+
     |                                            |
+----v----------------------------+   +-----------v-----------+
|   CYTHON OPTIMIZATION LAYER     |   |  PURE PYTHON FALLBACK |
|   src/cython/math_engine.pyx    |   |  (for portability)    |
|   - 18-37x math speedup         |   |                       |
|   - NTT O(n log n)              |   |                       |
|   - Matrix operations           |   |                       |
+----+----------------------------+   +-----------------------+
     |
+----v--------------------------------------------------------+
|              C CORE LIBRARY (libama_cryptography)               |
|                  src/c/  include/                           |
|  - Constant-time cryptographic primitives                   |
|  - ML-DSA-65, Kyber-1024, SPHINCS+-256f (FIPS 203/204/205)  |
|  - AES-256-GCM, Ed25519, SHA3-256, HKDF-SHA3-256            |
|  - C11 atomics for thread-safe initialization                |
|  - Memory-safe context management                           |
|  - SIMD optimizations (AVX2)                                |
+-------------------------------------------------------------+
```

## Performance Enhancements

### Cython Mathematical Engine

**Measured: 18–37x speedup over pure Python mathematical baseline**

Optimized operations:
- Polynomial arithmetic (add, sub, multiply)
- Number Theoretic Transform (NTT) - O(n log n)
- Matrix-vector multiplication
- Lyapunov function evaluation
- Helix evolution steps

Example speedup measurements:
```
Operation                  Python      Cython     Speedup
─────────────────────────────────────────────────────────
Lyapunov function         12.3 ms     0.45 ms    27.3x
Matrix-vector (500x500)   8.7 ms      0.31 ms    28.1x
NTT (degree 256)          45.2 ms     1.2 ms     37.7x
Helix evolution step      3.4 ms      0.18 ms    18.9x
```

### C Constant-Time Primitives

All cryptographic operations execute in constant time:

1. **ama_consttime_memcmp()**: Timing-attack resistant comparison
   - Volatile pointer usage prevents optimization
   - Data-independent control flow
   - Bitwise accumulation instead of branching

2. **ama_secure_memzero()**: Compiler-proof memory scrubbing
   - Memory barrier to prevent optimization
   - Guaranteed zeroing of sensitive data

3. **ama_consttime_swap()**: Conditional data-independent swap
   - XOR-based swap without branches
   - Mask-based selection

### SIMD Optimizations

AVX2 support for polynomial operations:
- 4x throughput on 64-bit operations
- Vectorized modular arithmetic
- Cache-friendly memory layouts

## Cryptographic Algorithms

### ML-DSA-65 (CRYSTALS-Dilithium)

**NIST FIPS 204 — Native C Implementation**

- Public key: 1,952 bytes
- Secret key: 4,032 bytes
- Signature: ~3,293 bytes
- Security: NIST Level 3 (~192-bit quantum)
- Constant-time implementation
- NIST KAT validated: **10/10 PASS**

### Kyber-1024 (ML-KEM)

**NIST FIPS 203 — Native C Implementation**

> **Integration Status:** Backend implemented in `ama_cryptography/pqc_backends.py`. Available via hybrid KEM combiner (`ama_cryptography/hybrid_combiner.py`).

- Public key: 1,568 bytes
- Secret key: 3,168 bytes
- Ciphertext: 1,568 bytes
- Shared secret: 32 bytes
- Security: NIST Level 5 (~256-bit quantum)
- IND-CCA2 secure (Fujisaki-Okamoto transform)
- NIST KAT validated: **10/10 PASS**

### SPHINCS+-SHA2-256f-simple

**NIST FIPS 205 — Native C Implementation**

> **Integration Status:** Backend implemented in `ama_cryptography/pqc_backends.py`. Available via adaptive posture system (`ama_cryptography/adaptive_posture.py`).

- Public key: 64 bytes
- Secret key: 128 bytes
- Signature: 49,856 bytes
- Security: 256-bit post-quantum (hash-based, no lattice assumptions)
- Stateless — no state management required (unlike XMSS/LMS)
- WOTS+ one-time signatures, FORS few-time signatures, hypertree (d=17)

### AES-256-GCM

**NIST SP 800-38D — Native C Implementation**

- Key: 256 bits
- IV/Nonce: 96 bits
- Tag: 128 bits
- Security: IND-CPA + INT-CTXT (128-bit quantum via Grover's bound)
- **Note:** Lookup-table S-box, not constant-time for cache-timing in shared-tenant environments

### X25519 (Key Exchange)

**RFC 7748 — Native C Implementation**

- Public key: 32 bytes
- Private key: 32 bytes (clamped scalar)
- Shared secret: 32 bytes
- Security: 128-bit classical (NOT quantum-resistant)
- Used as classical component in hybrid KEM combiner

### ChaCha20-Poly1305 (Alternative AEAD)

**RFC 8439 — Native C Implementation**

- Key: 256 bits
- Nonce: 96 bits
- Tag: 128 bits
- Security: IND-CPA + INT-CTXT (128-bit quantum via Grover's bound)
- **Constant-time by design** — no table lookups, no cache-timing concerns
- Recommended alternative to AES-256-GCM in shared-tenant environments

### Argon2id (Password Hashing)

**RFC 9106 — Native C Implementation**

- Memory cost: Configurable (recommended: 64 MiB+)
- Time cost: Configurable (recommended: 3+ iterations)
- Output: Variable length (recommended: 32 bytes)
- Memory-hard: Resists GPU/ASIC brute-force attacks
- Winner of Password Hashing Competition (2015)

### secp256k1 (HD Key Derivation)

**SEC 2 — Native C Implementation**

- Private key: 32 bytes
- Public key: 33 bytes (compressed) / 65 bytes (uncompressed)
- Security: 128-bit classical (NOT quantum-resistant)
- BIP32-compliant hierarchical deterministic key derivation

---

## Adaptive Cryptographic Posture System (v2.0)

**Module:** `ama_cryptography/adaptive_posture.py`

The adaptive posture system bridges the 3R runtime anomaly monitor with the cryptographic API for dynamic security responses.

**Components:**
- **PostureEvaluator** — Weighted scoring: timing (50%), pattern (30%), resonance (20%) with exponential decay
- **CryptoPostureController** — Key rotation, algorithm switching, cooldown enforcement (300s default)

**Threat Levels:**

| Level | Score | Automated Response |
|-------|-------|--------------------|
| NOMINAL | 0.0-0.3 | No action |
| ELEVATED | 0.3-0.6 | Increase monitoring frequency |
| HIGH | 0.6-0.8 | Rotate keys |
| CRITICAL | 0.8-1.0 | Rotate keys + switch algorithm + alert |

**Algorithm Strength Ordering:**
ED25519 (0) → ML_DSA_65 (1) → SPHINCS_256F (2) → HYBRID_SIG (3)

---

## Hybrid KEM Combiner (v2.0)

**Module:** `ama_cryptography/hybrid_combiner.py`

Binding construction for hybrid key encapsulation (classical + PQC) per Bindel et al. (PQCrypto 2019):

```
combined_ss = HKDF-SHA3-256(
    salt = classical_ct || pqc_ct,         # Ciphertext binding
    ikm  = classical_ss || pqc_ss,         # Combined key material
    info = label || classical_pk || pqc_pk  # Context binding
)
```

**Security Properties:**
- IND-CCA2 secure if **either** component KEM remains unbroken
- Ciphertext binding prevents mix-and-match attacks
- Uses native C HKDF-SHA3-256 with Python fallback

---

## Build System

### CMake (C Library)

Full-featured cross-platform build:

```bash
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DAMA_BUILD_SHARED=ON \
  -DAMA_BUILD_STATIC=ON \
  -DAMA_ENABLE_AVX2=ON \
  -DAMA_ENABLE_LTO=ON
```

Options:
- Shared/static library builds
- SIMD optimizations (AVX2, SSE4.2)
- Sanitizers (ASan, UBSan, MSan)
- Link-time optimization
- Custom install prefix

### Python setup.py

Integrated build system:

```bash
# Build with all optimizations
python setup.py build_ext --inplace

# Development mode
python setup.py develop

# Create distribution
python setup.py sdist bdist_wheel
```

Environment variables:
- `AMA_NO_CYTHON=1`: Disable Cython (pure Python)
- `AMA_NO_C_EXTENSIONS=1`: Disable C extensions
- `AMA_DEBUG=1`: Debug symbols and checks
- `AMA_COVERAGE=1`: Coverage instrumentation

### Makefile

Convenient targets:

```bash
make all          # Build everything
make c            # C library only
make python       # Python package
make test         # Run all tests
make benchmark    # Performance benchmarks
make docker       # Build Docker images
make docs         # Generate documentation
make install      # System-wide installation
```

## Testing Infrastructure

### C Test Suite

Location: `tests/c/`

Tests:
- `test_consttime.c`: Constant-time operation validation
- `test_core.c`: Context and lifecycle management
- `test_kyber.c`: Kyber-1024 algorithm tests
- `test_ml_dsa.c`: ML-DSA-65 signature tests

Run with:
```bash
cd build
ctest --output-on-failure
```

### Python Test Suite

Location: `tests/`

Tests:
- Algorithm correctness
- Mathematical framework verification
- Integration tests
- Performance benchmarks

Run with:
```bash
pytest tests/ -v --cov=ama_cryptography
```

## Docker Support

### Ubuntu-based Image

Full-featured production image:

```dockerfile
FROM ubuntu:22.04
# ~200MB final size
```

Build and run:
```bash
docker build -t ama-cryptography -f docker/Dockerfile .
docker run --rm ama-cryptography
```

### Alpine-based Image

Minimal production image:

```dockerfile
FROM alpine:3.18
# ~50MB final size
```

Build and run:
```bash
docker build -t ama-cryptography:alpine -f docker/Dockerfile.alpine .
docker run --rm ama-cryptography:alpine
```

### Docker Compose

Multi-service deployment:

```bash
docker-compose up -d        # Start all services
docker-compose down         # Stop all services
docker-compose ps           # Check status
```

Services:
- `ama-cryptography`: Main service
- `ama-monitor`: Monitoring service
- `ama-benchmark`: Periodic benchmarks

## Documentation

### C API Documentation (Doxygen)

Generate with:
```bash
cd build
doxygen ../docs/Doxyfile
```

Output: `build/docs/html/index.html`

Features:
- Complete API reference
- Call graphs and dependency diagrams
- Source code browser
- XML output for Sphinx integration

### Python API Documentation (Sphinx)

Generate with:
```bash
cd docs
sphinx-build -b html . _build/html
```

Output: `docs/_build/html/index.html`

Features:
- Automatic API documentation
- Type hints support
- Mathematical notation (MathJax)
- Interactive examples

## CI/CD Pipeline

GitHub Actions workflows:

### Build and Test (`ci-build-test.yml`)

Runs on:
- Ubuntu (GCC, Clang)
- macOS (GCC, Clang)
- Windows (MSVC)
- Python 3.9-3.13

Tests:
- C library compilation and tests
- Python package builds
- Cross-platform compatibility
- Code coverage

### Security (`security.yml`)

Checks:
- Dependency vulnerabilities (pip-audit)
- Code security (bandit)
- Static analysis
- License compliance

### Docker (`docker.yml`)

Builds:
- Ubuntu-based images
- Alpine-based images
- Multi-architecture (amd64, arm64)
- Security scanning

## Performance Benchmarking

Comprehensive benchmarking suite:

```bash
# Run all benchmarks
python benchmarks/performance_suite.py

# Run specific benchmarks
pytest tests/ --benchmark-only

# Profile with cProfile
make profile
```

Metrics tracked:
- Operations per second
- Memory usage
- Cache efficiency
- SIMD utilization
- Speedup ratios

Results saved to:
- `benchmarks/performance_results.json`
- `benchmark_results.json` (legacy)

## Cross-Platform Support

### Linux

Full support on:
- Ubuntu 18.04+
- Debian 10+
- CentOS 8+
- Fedora 32+
- Arch Linux

### macOS

Supported versions:
- macOS 10.15 (Catalina)+
- Apple Silicon (M1/M2) native
- Intel x86_64

### Windows

Supported compilers:
- MSVC 2019+
- MinGW-w64
- Clang on Windows

Note: C extensions may require additional setup on Windows.

## Security Guarantees

### Constant-Time Operations

All cryptographic comparisons and operations execute in constant time:

✓ Memory comparisons (ama_consttime_memcmp)
✓ Conditional swaps (ama_consttime_swap)
✓ Array lookups (ama_consttime_lookup)
✓ Signature verification
✓ Key generation

### Memory Safety

✓ Secure memory wiping (ama_secure_memzero)
✓ Magic number context validation
✓ Bounds checking in debug mode
✓ Sanitizer support (ASan, UBSan, MSan)
✓ No use-after-free vulnerabilities

### Side-Channel Resistance

✓ Data-independent control flow
✓ Constant-time conditional operations
✓ Cache-timing attack mitigation
✓ Power analysis resistance (algorithmic level)
✓ Fault injection detection

## Migration Guide

### From Pure Python

The new multi-language architecture is fully backward compatible:

```python
# Old code still works
from ama_cryptography import AmaEquationEngine
engine = AmaEquationEngine(state_dim=100)
```

No changes required! The system automatically uses:
1. C library (if available)
2. Cython optimizations (if compiled)
3. Pure Python (fallback)

### Enabling C/Cython

To get maximum performance:

```bash
# Install build tools
pip install Cython

# Build extensions
python setup.py build_ext --inplace

# Verify
python -c "from ama_cryptography.math_engine import benchmark_matrix_operations; print(benchmark_matrix_operations())"
```

## Version Compatibility

| Component | Version | Notes |
|-----------|---------|-------|
| Python | 3.9-3.13 | Type hints support |
| NumPy | 1.24+ | Optional (equations/monitoring) |
| Cython | 0.29.30+ | Optional (for speedup) |
| CMake | 3.15+ | C library build |
| GCC | 9+ | C11 support (required for atomics) |
| Clang | 10+ | C11 support |
| MSVC | 2019+ | Windows builds (volatile fallback for atomics) |

**Note:** OpenSSL is **no longer required** as of v2.0. All cryptographic primitives (SHA3, HKDF, Ed25519, AES-256-GCM, ML-DSA-65, Kyber-1024, SPHINCS+, X25519, ChaCha20-Poly1305, Argon2, secp256k1) are implemented natively in C.

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-11-26 | Initial professional release |
| 1.1.0 | 2026-01-09 | Version alignment |
| 2.0.0 | 2026-03-08 | Zero-dependency native C, AES-256-GCM, adaptive posture, hybrid KEM combiner, Ed25519 atomics, FIPS 203/204/205, KAT validation, Phase 2 primitives, fuzzing harnesses, threat model, Mercury Agent integration |

---

Copyright 2025-2026 Steel Security Advisors LLC. Licensed under Apache License 2.0.
