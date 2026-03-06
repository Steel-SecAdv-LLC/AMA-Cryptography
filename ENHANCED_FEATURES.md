# AMA Cryptography ♱ Enhanced Features

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 1.1 |
| Last Updated | 2026-01-09 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Overview

AMA Cryptography ♱ 1.0 introduces a multi-language architecture that combines the security of C, the performance of Cython, and the usability of Python. This document describes the enhanced features available in the current release.

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
|   - 10-50x speedup              |   |                       |
|   - NTT O(n log n)              |   |                       |
|   - Matrix operations           |   |                       |
+----+----------------------------+   +-----------------------+
     |
+----v--------------------------------------------------------+
|              C CORE LIBRARY (libama_cryptography)               |
|                  src/c/  include/                           |
|  - Constant-time cryptographic primitives                   |
|  - ML-DSA-65, Kyber-1024, SPHINCS+-256f                     |
|  - Memory-safe context management                           |
|  - SIMD optimizations (AVX2)                                |
+-------------------------------------------------------------+
```

## Performance Enhancements

### Cython Mathematical Engine

**Target: 10-50x speedup over pure Python**

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

2. **ava_secure_memzero()**: Compiler-proof memory scrubbing
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

**NIST PQC Selected Algorithm**

- Public key: 1952 bytes
- Secret key: 4016 bytes
- Signature: 3309 bytes
- Security: NIST Level 3 (~192-bit classical)
- Constant-time implementation

### Kyber-1024 (ML-KEM)

**Key Encapsulation Mechanism**

> **Integration Status:** Backend implemented in `ama_cryptography/pqc_backends.py`. Integration into main signing workflow pending.

- Public key: 1568 bytes
- Secret key: 3168 bytes
- Ciphertext: 1568 bytes
- Shared secret: 32 bytes
- Security: NIST Level 5 (~256-bit classical)
- IND-CCA2 secure

### SPHINCS+-256f

**Stateless Hash-Based Signatures**

> **Integration Status:** Backend implemented in `ama_cryptography/pqc_backends.py`. Integration into main signing workflow pending.

- Public key: 64 bytes
- Secret key: 128 bytes
- Signature: 49856 bytes
- Security: 256-bit post-quantum
- No quantum speedup possible

## Build System

### CMake (C Library)

Full-featured cross-platform build:

```bash
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DAVA_BUILD_SHARED=ON \
  -DAVA_BUILD_STATIC=ON \
  -DAVA_ENABLE_AVX2=ON \
  -DAVA_ENABLE_LTO=ON
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
- `AVA_NO_CYTHON=1`: Disable Cython (pure Python)
- `AVA_NO_C_EXTENSIONS=1`: Disable C extensions
- `AVA_DEBUG=1`: Debug symbols and checks
- `AVA_COVERAGE=1`: Coverage instrumentation

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
- `ava-monitor`: Monitoring service
- `ava-benchmark`: Periodic benchmarks

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
- Python 3.8-3.12

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

✓ Secure memory wiping (ava_secure_memzero)
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
| Python | 3.8+ | Type hints support |
| NumPy | 1.24+ | Array operations |
| Cython | 0.29.30+ | Optional (for speedup) |
| CMake | 3.15+ | C library build |
| OpenSSL | 1.1.1+ | Cryptographic primitives |
| GCC | 9+ | C11 support |
| Clang | 10+ | C11 support |
| MSVC | 2019+ | Windows builds |

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-11-26 | Initial professional release |

---

Copyright 2025 Steel Security Advisors LLC. Licensed under Apache License 2.0.
