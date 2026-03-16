# Installation

This page covers all supported ways to install and build AMA Cryptography.

---

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.9 | 3.11+ |
| C Compiler | GCC 7 / Clang 6 | GCC 12 / Clang 16 |
| CMake | 3.15 | 3.25+ |
| RAM | 512 MB | 2 GB |
| Platforms | Linux, macOS, Windows | Ubuntu 22.04+ / macOS 13+ |

---

## Installing System Dependencies

### Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install build-essential cmake python3-dev python3-pip
```

### macOS (Homebrew)

```bash
brew install cmake
# Xcode Command Line Tools (required for compiler)
xcode-select --install
```

### Windows

Install [Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) (includes MSVC C11 support), plus [CMake](https://cmake.org/download/).

---

## Step 1: Clone the Repository

```bash
git clone https://github.com/Steel-SecAdv-LLC/AMA-Cryptography.git
cd AMA-Cryptography
```

---

## Step 2: Build the Native C Library

The native C library provides all cryptographic primitives (SHA3-256, HKDF, Ed25519, AES-256-GCM, ML-DSA-65, Kyber-1024, SPHINCS+) with **zero external dependencies**.

### Standard Build (Recommended)

```bash
# Configure with post-quantum cryptography enabled
cmake -B build \
  -DAMA_USE_NATIVE_PQC=ON \
  -DCMAKE_BUILD_TYPE=Release

# Build the library
cmake --build build
```

### Build with All Features

```bash
cmake -B build \
  -DAMA_USE_NATIVE_PQC=ON \
  -DAMA_ENABLE_SIMD=ON \
  -DAMA_ENABLE_AVX2=ON \
  -DAMA_ENABLE_LTO=ON \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build
```

### CMake Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `AMA_BUILD_SHARED` | `ON` | Build shared library (`.so`/`.dll`) |
| `AMA_BUILD_STATIC` | `ON` | Build static library (`.a`/`.lib`) |
| `AMA_BUILD_TESTS` | `ON` | Build C test suite |
| `AMA_USE_NATIVE_PQC` | `ON` | Enable ML-DSA-65, Kyber-1024, SPHINCS+ |
| `AMA_ENABLE_SIMD` | `ON` | SIMD optimizations |
| `AMA_ENABLE_AVX2` | `ON` | AVX2 acceleration (x86_64 only) |
| `AMA_AES_CONSTTIME` | `OFF` | Bitsliced AES (cache-timing safe mode) |
| `AMA_ENABLE_LTO` | `ON` | Link-time optimization |
| `AMA_BUILD_FUZZ` | `OFF` | Build libFuzzer harnesses |

> **Constant-Time AES:** For deployments in shared-tenant environments (cloud VMs, containers), enable `-DAMA_AES_CONSTTIME=ON` to use the bitsliced AES implementation that is hardened against cache-timing side-channels.

---

## Step 3: Install the Python Package

### Development Install (Editable)

```bash
pip install -e .
```

### Standard Install

```bash
pip install .
```

### With Optional Extras

```bash
# Full monitoring stack (NumPy + SciPy for 3R engine)
pip install -e ".[monitoring]"

# Legacy classical cryptography fallback
pip install -e ".[legacy]"

# Hardware Security Module (HSM) support
pip install -e ".[hsm]"

# Libsodium secure memory bindings
pip install -e ".[secure-memory]"

# Development tools (pytest, black, ruff, mypy, coverage)
pip install -e ".[dev]"

# Documentation generation (Sphinx)
pip install -e ".[docs]"

# Everything at once
pip install -e ".[monitoring,legacy,hsm,secure-memory,dev]"
```

---

## Step 4: Verify Installation

### Check PQC Status

```python
from ama_cryptography.pqc_backends import get_pqc_status
print(get_pqc_status())
```

Expected output:
```
{
  "ml_dsa_65": "available",
  "ml_kem_1024": "available",
  "sphincs_sha2_256f": "available",
  "backend": "native"
}
```

### Run the Demo

```bash
python3 code_guardian_secure.py
```

Expected:
```
==================================================================
AMA Cryptography: SHA3-256 Security Hash
==================================================================

[1/5] Generating key management system...
  ✓ Master secret: 256 bits
  ✓ HMAC key: 256 bits
  ✓ Ed25519 keypair: 32 bytes
  ✓ Dilithium keypair: 1952 bytes

==================================================================
✓ ALL VERIFICATIONS PASSED
==================================================================
```

---

## Optional: Build with Cython Acceleration

Cython provides 18–37x speedup for mathematical operations:

```bash
# Install Cython first
pip install cython>=3.0

# Build with Cython extensions
python setup.py build_ext --inplace
```

> **Note:** Cython acceleration is optional. The pure Python API remains fully functional without it.

---

## Building C Tests

```bash
cmake -B build -DAMA_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build
cd build && ctest --output-on-failure
```

---

## Building Fuzzing Harnesses (Security Research)

```bash
cmake -B build \
  -DAMA_BUILD_FUZZ=ON \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo

cmake --build build
```

Fuzzing targets include: AES-GCM, Ed25519, HKDF, X25519, ChaCha20-Poly1305, SHA3, Kyber, Dilithium, SPHINCS+, Argon2id, secp256k1, constant-time operations.

---

## Makefile Shortcuts

The repository includes a `Makefile` for common operations:

```bash
make all      # Build C library + Python package
make test     # Run Python test suite
make clean    # Remove build artifacts
make install  # Install Python package
```

---

## Troubleshooting

### C Library Not Found

If the Python package cannot find the native C library at runtime:

```bash
# Ensure the library is built
cmake --build build

# On Linux: update the dynamic linker cache
sudo ldconfig

# Or set LD_LIBRARY_PATH explicitly
export LD_LIBRARY_PATH="$PWD/build:$LD_LIBRARY_PATH"
```

### CMake Version Too Old

```bash
# Ubuntu: install newer CMake from Kitware APT
wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc | sudo apt-key add -
sudo apt-add-repository 'deb https://apt.kitware.com/ubuntu/ focal main'
sudo apt-get update && sudo apt-get install cmake
```

### Missing Python Headers

```bash
# Ubuntu/Debian
sudo apt-get install python3-dev

# macOS (Homebrew Python)
brew install python
```

---

*See [Quick Start](Quick-Start) to begin using the library, or [Architecture](Architecture) for a system overview.*
