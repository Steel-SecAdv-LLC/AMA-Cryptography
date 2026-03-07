# AMA Cryptography

<div align="center">

  <img width="917" height="194" alt="image" src="https://github.com/user-attachments/assets/b8cf718e-82e0-4254-94bc-8c6aad12a895" />

</div>

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org)
[![C](https://img.shields.io/badge/C-C11-blue.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Cython](https://img.shields.io/badge/Cython-3.0+-yellow.svg)](https://cython.org)
[![PQC](https://img.shields.io/badge/PQC-ML--DSA--65%20%7C%20Kyber--1024-purple.svg)](CRYPTOGRAPHY.md)
[![3R Monitoring](https://img.shields.io/badge/3R-Runtime%20Security-orange.svg)](MONITORING.md)
[![Architecture](https://img.shields.io/badge/architecture-C%20%2B%20Python%20%2B%20Cython-blue.svg)](ARCHITECTURE.md)

```
              +==============================================================================+
              |                            AMA CRYPTOGRAPHY ♱                                |
              |                   Post-Quantum Security System                               |
              |                                                                              |
              |   6-Layer Defense      |   Quantum-Resistant    |   Defense-in-Depth         |
              |   Cython-Optimized     |   3R Anomaly Monitor   |   Cross-Platform           |
              |   HD Key Derivation    |   Algorithm-Agnostic   |   NIST PQC Standards       |
              |                                                                              |
              |   C Layer (Native)     |   Cython Layer         |   Python API               |
              |   ─────────────────    |   ─────────────────    |   ─────────────────        |
              |   SHA3/HKDF/Ed25519    |   18-37x Speedup       |   Algorithm Agnostic       |
              |   ML-DSA-65/Kyber      |   NumPy Integration    |   Key Management           |
              |   SPHINCS+/NTT Ops     |   Math Engine          |   3R Monitoring            |
              |                                                                              |
              |                   Built for a civilized evolution.                           |
              +==============================================================================+
```

**Copyright 2025 Steel Security Advisors LLC**
**Author/Inventor:** Andrew E. A.
**Contact:** steel.sa.llc@gmail.com
**License:** Apache License 2.0
**Version:** 2.0
**AI Co-Architects:** Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛

---

## Executive Summary

AMA Cryptography is a hybrid Ed25519 + Dilithium (ML-DSA-65) framework for quantum-resistant integrity protection. Community-tested, not externally audited. A secure, multi-language cryptographic security system designed to protect people, data, and networks against both classical and quantum threats. Built on a foundation of mathematically rigorous post-quantum cryptography (PQC), AMA Cryptography delivers security-hardened features with exceptional performance.

Novel in assimilation, the system combines cutting-edge NIST-approved post-quantum algorithms with a unique 3R runtime security monitoring framework, creating a defense-in-depth architecture that provides unprecedented visibility into cryptographic operations while maintaining less than 2% performance overhead. The multi-language architecture (C + Cython + Python) enables both maximum security through constant-time implementations and optional Cython acceleration (18-37x speedup when built), making it suitable for environments ranging from high-security government applications to performance-critical enterprise systems.

**Protecting people, data, and networks with quantum-resistant cryptography**

> **Project Philosophy:** Promoting action over inaction in the hope of helping secure critical systems against emerging quantum threats. This project is under active development. While we strive for cryptographic rigor, users should remain cautious and conduct independent security reviews before production deployment. The perceived absence of a threat does not constitute the lack of a threat. Our goal is to deter, mitigate, and elevate security posture—not create new vulnerabilities.
> 
> **Security Disclosure:** This is a self-assessed cryptographic implementation without third-party audit. Production use REQUIRES:
> - FIPS 140-2 Level 3+ HSM for master secrets (no software-only keys in high-security environments)
> - Independent security review by qualified cryptographers
> - Constant-time implementation verification for side-channel resistance
> - Secure file permissions for key files and cryptographic packages (store on encrypted volumes with restricted access)
>
> **Status:** Community-tested | Not externally audited
> **Last Updated:** 2026-03-06
> **Audit Status:** Community-tested, not externally audited. See [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) for self-assessment details.
>
> See [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) for detailed security properties and threat model.

---

## Table of Contents

<details>
<summary><strong>Click to expand navigation</strong></summary>

- [Executive Summary](#executive-summary)
- [Key Capabilities](#key-capabilities-)
- [Use Cases by Sector](#use-cases-by-sector-)
- [Performance Metrics](#performance-metrics-)
- [Quick Start](#quick-start)
- [Testing and Quality Assurance](#testing-and-quality-assurance)
- [Documentation](#documentation)
- [Cross-Platform Support](#cross-platform-support)
- [Build System](#build-system-)
- [Mathematical Foundations](#mathematical-foundations-)
- [Contributing](#contributing)
- [License](#license)
- [Contact and Support](#contact-and-support)
- [Acknowledgments](#acknowledgments)

</details>

---

## Key Capabilities 

<details>
<summary><strong>Problem Statement and Solution</strong></summary>

### The Problem

Current cryptographic systems face three critical challenges:

1. **Quantum Threat**: Traditional cryptography (RSA, ECDSA) will be broken by large-scale quantum computers within 5-15 years
2. **Black Box Security**: Most cryptographic libraries provide no runtime visibility into side-channel vulnerabilities or anomalous behavior
3. **Performance vs Security Trade-off**: Quantum-resistant algorithms are significantly slower, creating adoption barriers

### The AMA Cryptography Solution

AMA Cryptography addresses all three challenges through:

- **Quantum Resistance**: NIST-approved ML-DSA-65 (FIPS 204) and Kyber-1024 (FIPS 203) provide 50+ years of protection
- **Transparent Security**: 3R monitoring (Resonance-Recursion-Refactoring) provides real-time cryptographic operation analysis
- **Optimized Performance**: Cython acceleration available (manual build required); benchmarked at 18-37x speedup over pure Python baseline

### Target Use Cases

- **Humanitarian and Conservation**: Crisis response, whistleblower protection, sensitive field data
- **Government and Defense**: Classified data protection with quantum resistance
- **Financial Services**: Transaction security future-proofed against quantum threats
- **Healthcare**: HIPAA-compliant data encryption with audit trails
- **Critical Infrastructure**: SCADA systems requiring long-term security guarantees
- **Blockchain and Crypto**: Post-quantum secure digital signatures

See [Use Cases by Sector](#use-cases-by-sector-) for detailed scenarios.

</details>

<details>
<summary><strong>Unique Differentiators</strong></summary>

### 6-Layer Defense-in-Depth Architecture

**Defense-in-depth security** with 6 independent cryptographic layers, compared to typical 1-2 layers in peer implementations:

| Layer | Protection | Security Level |
|-------|------------|----------------|
| 1. SHA3-256 | Content integrity | 128-bit collision resistance |
| 2. HMAC-SHA3-256 | Authentication | Keyed message authentication |
| 3. Ed25519 | Classical signatures | 128-bit classical security |
| 4. ML-DSA-65 | Quantum signatures | 192-bit quantum security |
| 5. HKDF | Key derivation | Cryptographic key independence |
| 6. RFC 3161 | Timestamping | Third-party proof of existence |

**Why 6 layers matter:** Overall security is bounded by the weakest cryptographic layer (~128-bit classical, ~192-bit quantum). Defense-in-depth ensures continued protection if one layer is compromised. See [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) for detailed analysis.

![6-Layer Defense Architecture](assets/defense_layers.png)

*An attacker must defeat ALL 6 independent cryptographic layers to forge a package. Most systems use only 1-2 layers.*

### 3R Runtime Security Monitoring

The signature innovation providing real-time cryptographic operation analysis unavailable in peer implementations:

- **Resonance Engine**: FFT-based anomaly detection with frequency-domain analysis (monitors for statistical anomalies, not a timing attack prevention system)
- **Recursion Engine**: Multi-scale hierarchical pattern analysis for anomaly detection
- **Refactoring Engine**: Code complexity metrics for security review

- **Performance overhead**: Less than 2% with comprehensive monitoring
- **Unique capability**: Real-time visibility into cryptographic operations that peer libraries treat as black boxes

> **Note:** The 3R system is a runtime anomaly monitoring framework. It surfaces statistical anomalies for security review but does not guarantee detection or prevention of timing attacks or other side-channel vulnerabilities.

### Multi-Language Architecture

Optimized for both security and performance:

- **C Layer**: Native SHA3-256, HKDF-SHA3-256, Ed25519, ML-DSA-65, Kyber-1024, SPHINCS+-256f implementations — zero external PQC dependencies (see [Implementation Status Matrix](#implementation-status-matrix))
- **Cython Layer**: Optimized mathematical operations (benchmarked at 27-37x vs pure Python)
- **Python API**: High-level, user-friendly interface for rapid development (primary production API)

### Advanced Features

Secure and tested:

- Hierarchical Deterministic (HD) key derivation
- Zero-downtime key rotation with lifecycle management
- Algorithm-agnostic API for seamless algorithm switching
- Secure encrypted key storage at rest

### Quantum-Resistant Algorithms

Future-proof cryptography:

- ML-DSA-65 (NIST FIPS 204 - Dilithium)
- Kyber-1024 (NIST FIPS 203)
- SPHINCS+-256f (stateless hash-based signatures)
- Hybrid classical+PQC modes

</details>

<details>
<summary><strong>Key Achievements</strong></summary>

| Achievement | Description |
|-------------|-------------|
| Defense-in-Depth | 6 independent cryptographic layers |
| Performance | Cython optimization (27-37x vs pure Python baseline) |
| Quantum Resistance | NIST-approved PQC algorithms (ML-DSA-65, Kyber-1024) |
| Mathematical Rigor | 5 proven frameworks with machine precision |
| Cross-Platform | Linux, macOS, Windows, ARM64 |
| Production Infrastructure | Docker, CI/CD, comprehensive testing |
| 3R Innovation | Unique runtime security monitoring (less than 2% overhead) |

</details>

<details>
<summary><strong>Implementation Status Matrix</strong></summary>

| Algorithm | C API Status | Python API Status | Integration |
|-----------|--------------|-------------------|-------------|
| SHA3-256 | **Full** | Full | Core primitive |
| HKDF-SHA3-256 | **Full** | Full | Key derivation |
| Ed25519 | **Full** | Full | Integrated |
| ML-DSA-65 | **Full** (native) | Full | Integrated |
| Kyber-1024 | **Full** (native) | Full | Integrated |
| SPHINCS+-256f | **Full** (native) | Full | Integrated |
| Hybrid (Ed25519 + ML-DSA-65) | N/A | Full | Integrated |

**Legend:**
- **Full**: Complete native C implementation with constant-time operations.
- **Full (native)**: Complete native C implementation — no external PQC dependency required.
- **Note**: Ed25519 C implementation has field arithmetic optimization pending. Python API uses optimized OpenSSL backend.

**C Library Implementations (v1.1):**
- `ama_sha3.c`: SHA3-256, SHAKE128, SHAKE256 (Keccak-f[1600] sponge construction)
- `ama_hkdf.c`: HKDF-SHA3-256 with HMAC-SHA3-256 (RFC 5869 compliant)
- `ama_ed25519.c`: Ed25519 keygen/sign/verify (SHA-512, field arithmetic for GF(2^255-19))
- `ama_kyber.c`: ML-KEM-1024 full native (NTT, IND-CCA2, Fujisaki-Okamoto transform)
- `ama_dilithium.c`: ML-DSA-65 full native (NTT q=8380417, rejection sampling, constant-time)
- `ama_sphincs.c`: SPHINCS+-SHA2-256f-simple full native (WOTS+, FORS, hypertree d=17)

> **Note:** The Python API remains the recommended production interface. C implementations provide high-performance alternatives where applicable. See [BENCHMARK_RESULTS.md](BENCHMARK_RESULTS.md) for C vs Python performance comparison.

**PQC Backend Security Considerations:**

| Backend | Constant-Time | Recommended Use |
|---------|---------------|-----------------|
| Native C (libama_cryptography) | Yes (native implementation) | Default — zero external PQC dependencies |

> **Note:** All PQC operations are provided by the native C library (libama_cryptography). No external PQC dependencies (liboqs, pqcrypto) are required. Build with `cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build`. Set `AMA_REQUIRE_CONSTANT_TIME=true` to enforce constant-time operation at runtime.

</details>

---

## Use Cases by Sector 🌐

> **Research Areas:** The use cases below represent targeted applications where AMA Cryptography's quantum-resistant cryptography may provide value. These implementations require independent validation before deployment in regulated, clinical, or mission-critical environments.

<details>
<summary><strong>Real-world scenarios (click to expand)</strong></summary>

### Humanitarian and Conservation 🌎 

**Unique Value:** Protection of sensitive field data with runtime attack detection (Not approved for clinical, medical, or regulated government deployment without independent audit):

- **Crisis Response**: GPS coordinates, victim data, and safe house locations protected with ML-DSA-65 quantum-resistant signatures. 3R monitoring surfaces timing anomalies that may indicate compromise in hostile environments.
- **Conservation**: Wildlife tracking data, ranger locations, and anti-poaching intelligence with integrity verification using helical invariants. Detects if data has been tampered with.
- **Whistleblower Protection**: Document signing and verification that remains secure for 50+ years under "harvest now, decrypt later" quantum threats.
- **Sensitive Record Preservation**: Ethical framework ensures respectful handling of records for victims and individuals, with complete audit trails.

### Government and Defense

**Unique Value:** Classified data with quantum resistance and side-channel attack detection

- **Long-term Classified Data**: Documents that must remain secret for decades protected against future quantum computers.
- **Secure Communications**: TLS with Kyber-1024 key exchange resistant to "harvest now, decrypt later" attacks.
- **Runtime Anomaly Monitoring**: 3R monitoring surfaces statistical anomalies in operation timing that may be consistent with cache-timing or power-analysis behavior, but does not guarantee detection or prevention of timing attacks or other side-channel vulnerabilities.
- **Integrity Verification**: Mathematical invariant checking catches sophisticated tampering beyond standard checksums.
- **Zero-Trust Environments**: Runtime monitoring provides continuous verification of cryptographic operations.

### Financial Services 

**Unique Value:** Transaction security with real-time anomaly detection

- **Quantum-Resistant Signatures**: ML-DSA-65 signatures on transactions remain valid even after quantum computers exist.
- **High-Frequency Trading**: Cython-optimized operations available (18-37x speedup when built) with sub-millisecond signature verification.
- **Anomaly Detection**: 3R timing analysis surfaces anomalous cryptographic behavior that may indicate potential attacks.
- **Audit Compliance**: Complete cryptographic audit trail with ethical constraint enforcement.
- **Long-term Archival**: Financial records with 50+ year security guarantees.

### Healthcare 

**Unique Value:** HIPAA-compliant encryption with sophisticated integrity monitoring

- **Patient Records**: Quantum-resistant encryption ensures medical records remain private for patient's lifetime.
- **Prescription Signatures**: ML-DSA-65 digital signatures on prescriptions that cannot be forged.
- **Medical Device Security**: Embedded systems with constant-time operations resistant to side-channel attacks.
- **Data Integrity**: Helical invariant verification detects if medical records have been altered.
- **Research Data**: Sensitive research data with ethical policy enforcement and audit trails.
- **Telemedicine**: Secure video consultations with hybrid classical+quantum key exchange.

### Critical Infrastructure 

**Unique Value:** SCADA/ICS security with active attack detection

- **Power Grid Control**: Quantum-resistant authentication for grid control systems.
- **Water Treatment**: Signed commands with runtime verification. 3R surfaces timing anomalies that may indicate malware.
- **Transportation**: Railway and air traffic control with 50+ year security guarantees (systems operate for decades).
- **Nuclear Facilities**: Constant-time operations prevent side-channel leaks in high-security environments.
- **Active Monitoring**: 3R system provides real-time alerts if cryptographic operations show attack patterns.
- **Legacy System Protection**: Wrapper for older systems needing quantum resistance without full replacement.

### Blockchain and Cryptocurrency 

**Unique Value:** Post-quantum secure signatures with high-performance verification

- **Wallet Security**: ML-DSA-65 signatures protect private keys from future quantum attacks.
- **Smart Contract Signing**: Quantum-resistant signatures for long-lived contracts.
- **Transaction Throughput**: High-performance signature operations competitive with classical algorithms.
- **Cross-Chain Bridges**: Hybrid signing (Ed25519 + ML-DSA-65) for compatibility and future-proofing.
- **NFT Provenance**: Signatures that remain valid indefinitely.
- **Timestamp Verification**: RFC 3161 trusted timestamping with quantum resistance.

</details>

---

## Performance Metrics 📊

<details>
<summary><strong>Cryptographic Operation Benchmarks</strong></summary>

### Hybrid Operations (Ed25519 + ML-DSA-65)

| Operation | AMA Cryptography | Optimized | Reference (OpenSSL) |
|-----------|--------------|-----------|---------------------|
| **Hybrid Sign** | 4,575 ops/sec | ~6,500 ops/sec* | 6,209 ops/sec |
| **Hybrid Verify** | 6,192 ops/sec | ~6,700 ops/sec* | 6,721 ops/sec |

**Performance Optimization:** AMA Cryptography now supports passing Ed25519 key objects for 2x faster signing. The `HybridSignatureProvider` class automatically uses this optimization.

\*Optimized performance uses cached Ed25519 key objects, eliminating reconstruction overhead.

![Hybrid Signing and Verification Performance](assets/performance_comparison.png)

*Visual comparison of hybrid signing and verification throughput for AMA Cryptography (standard vs optimized) on reference hardware (Linux x86_64, 16 cores, 13GB RAM).*

### ML-DSA-65 (Post-Quantum) Operations

| Operation | AMA Cryptography (Native) | Performance |
|-----------|----------------------|-------------|
| **Sign** | 9,150 ops/sec (0.109ms) | Full native C implementation |
| **Verify** | 27,306 ops/sec (0.037ms) | NIST KAT validated |

**Key Finding:** Native ML-DSA-65 implementation achieves high-performance signing and verification with zero external dependencies.

### Full 6-Layer Package Performance

Complete security package with all defense layers:

| Operation | Mean Time | Throughput |
|-----------|-----------|------------|
| Package Create (6 layers) | 0.278ms | 3,595 ops/sec |
| Package Verify (6 layers) | 0.199ms | 5,029 ops/sec |

**6 Layers:** SHA3-256, HMAC-SHA3-256, Ed25519, ML-DSA-65, HKDF, RFC 3161 (optional)

![Package Performance](assets/package_performance.png)

*Complete 6-layer cryptographic packages can be created at 3,595 ops/sec and verified at 5,029 ops/sec.*

### Core Cryptographic Primitives

| Operation | Standard (bytes) | Optimized (key objects) |
|-----------|------------------|------------------------|
| SHA3-256 | 292,790 ops/sec | - |
| HMAC-SHA3-256 | 159,463 ops/sec | - |
| Ed25519 Sign | 10,453 ops/sec | **20,921 ops/sec** (2x faster) |
| Ed25519 Verify | 8,068 ops/sec | 8,496 ops/sec |

**Performance Tip:** For high-throughput scenarios, pass `Ed25519PrivateKey` objects instead of bytes to achieve 2x faster signing. See [BENCHMARK_RESULTS.md](BENCHMARK_RESULTS.md) for usage examples.

*Benchmarks: Linux x86_64, Python 3.11, 16 CPU cores, 13GB RAM, 1,000 iterations per operation.*

</details>

<details>
<summary><strong>Cython Optimization Results</strong></summary>

| Operation | Pure Python | Cython | Speedup |
|-----------|-------------|--------|---------|
| Lyapunov function | 12.3ms | 0.45ms | **27.3x** |
| Matrix-vector (500x500) | 8.7ms | 0.31ms | **28.1x** |
| NTT (degree 256) | 45.2ms | 1.2ms | **37.7x** |
| Helix evolution | 3.4ms | 0.18ms | **18.9x** |

**Cython optimization: 18-37x speedup vs pure Python baseline**

</details>

<details>
<summary><strong>Scalability Analysis</strong></summary>

| Omni-Code Size | Mean Time | Throughput |
|---------------|-----------|------------|
| 1 code | 0.31ms | 3,230 ops/sec |
| 10 codes | 0.50ms | 1,993 ops/sec |
| 100 codes | 2.79ms | 359 ops/sec |
| 1000 codes | 171.32ms | 5.84 ops/sec |

*Benchmarks: Linux x86_64, Python 3.12, 8 CPU cores, 31GB RAM, 50 iterations per size.*

</details>

<details>
<summary><strong>Ethical Integration Overhead</strong></summary>

| Operation | Standard | With Ethics | Overhead |
|-----------|----------|-------------|----------|
| HKDF Derivation | 0.006ms | 0.018ms | 213.79% |
| Context Creation | - | 0.011ms | - |

The ethical integration adds cryptographic binding to the 12 Omni-Code Ethical Pillars with minimal impact on overall system performance.

*Benchmarks: Linux x86_64, Python 3.12, 8 CPU cores, 31GB RAM, 1,000 iterations.*

![Monitoring Overhead](assets/monitoring_overhead.png)

*Comprehensive runtime security monitoring with less than 2% performance overhead.*

</details>

---

## Quick Start

<details>
<summary><strong>Installation</strong></summary>

### Standard Installation

```bash
# Clone repository
git clone https://github.com/Steel-SecAdv-LLC/AMA-Cryptography.git
cd AMA-Cryptography

# Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Build native PQC C library (ML-DSA-65, Kyber-1024, SPHINCS+-256f)
cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Build everything (C library + Python extensions)
make all

# Run tests (includes NIST KAT validation)
make test

# Install system-wide
sudo make install
```

> All PQC algorithms are implemented natively in C — no external PQC libraries required.

### Platform-Specific Notes

**Linux (Ubuntu/Debian)**:
```bash
# Install build dependencies
sudo apt-get install build-essential cmake python3-dev libssl-dev

# Build and install
make all && sudo make install
```

**macOS**:
```bash
# Install dependencies via Homebrew
brew install cmake openssl

# Build and install
make all && sudo make install
```

**Windows (MSVC)**:
```powershell
# Install Visual Studio Build Tools
# Install CMake and Python from official websites

# Build
cmake --build build --config Release
python setup.py install
```

### External Dependencies

**RFC 3161 Timestamps (Optional)**:
RFC 3161 trusted timestamping requires OpenSSL in PATH. If OpenSSL is not available, the system falls back to self-asserted timestamps with a warning logged.

```bash
# Verify OpenSSL is available
openssl version

# Linux (Ubuntu/Debian)
sudo apt-get install openssl

# macOS
brew install openssl

# Windows
# Download from https://slproweb.com/products/Win32OpenSSL.html
```

The timestamp feature contacts external TSA (Time Stamping Authority) servers. Default: FreeTSA (https://freetsa.org/tsr). Commercial TSAs (DigiCert, GlobalSign) are recommended for production use.

</details>

<details>
<summary><strong>Basic Usage</strong></summary>

### Simple Example

```python
from ama_cryptography.crypto_api import AmaCryptography, AlgorithmType

# Create crypto instance
crypto = AmaCryptography(algorithm=AlgorithmType.HYBRID_SIG)

# Generate keys
keypair = crypto.generate_keypair()

# Sign message
signature = crypto.sign(b"Hello, World!", keypair.secret_key)

# Verify signature
valid = crypto.verify(b"Hello, World!", signature.signature, keypair.public_key)
print(f"Signature valid: {valid}")  # True
```

### Advanced Example with 3R Monitoring

```python
from ama_cryptography.crypto_api import AmaCryptography, AlgorithmType
from ama_cryptography_monitor import AmaCryptographyMonitor

# Enable 3R security monitoring
monitor = AmaCryptographyMonitor(enabled=True)

# Create crypto instance
crypto = AmaCryptography(algorithm=AlgorithmType.ML_DSA_65)

# Generate and use keys with monitoring
keypair = crypto.generate_keypair()
signature = crypto.sign(b"Sensitive data", keypair.secret_key)

# Get security report
report = monitor.get_security_report()
print(f"Security status: {report['status']}")
print(f"Anomalies detected: {report['total_alerts']}")
```

> **C API Note:** Full native C implementations are available for SHA3-256, HKDF, Ed25519, ML-DSA-65, Kyber-1024, and SPHINCS+-256f — no external PQC dependencies required. Build with `-DAMA_USE_NATIVE_PQC=ON` (default). All implementations pass NIST KAT validation. The Python API remains recommended for production deployments. See `include/ama_cryptography.h` for the complete interface specification.

</details>

<details>
<summary><strong>Docker Quick Start</strong></summary>

### Ubuntu Image (Production)

```bash
# Build Ubuntu-based image (~200MB)
docker build -t ama-cryptography -f docker/Dockerfile .

# Run interactive session
docker run -it ama-cryptography /bin/bash

# Run tests
docker run --rm ama-cryptography make test
```

### Alpine Image (Minimal)

```bash
# Build Alpine image (~50MB)
docker build -t ama-cryptography:alpine -f docker/Dockerfile.alpine .

# Run
docker run --rm ama-cryptography:alpine
```

### Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f ama-cryptography

# Execute commands
docker-compose exec ama-cryptography python -m pytest
```

</details>

---
## Testing and Quality Assurance

> **Note:** Running the full test suite requires dev dependencies. Install with: `pip install -e ".[dev]"` or `pip install -r requirements-dev.txt`

<details>
<summary><strong>Test Suite</strong></summary>

### Running Tests

```bash
# C library tests (includes NIST KAT vectors)
make test-c

# Python tests
make test-python

# All tests
make test

# Performance benchmarks
make benchmark

# PQC sanity check
python tools/sanity_check.py
```

### Test Coverage

The test suite includes:
- Unit tests for all cryptographic primitives
- Integration tests for package creation and verification
- Edge case testing for error handling
- Performance regression tests

![Test Suite Coverage](assets/test_coverage.png)

*798 tests across 23 files (~11,000 lines) covering core crypto and NIST KATs, PQC backends, key management, memory security, and performance/monitoring.*

</details>

<details>
<summary><strong>Continuous Integration</strong></summary>

GitHub Actions automatically tests:

| Check | Description |
|-------|-------------|
| C library | GCC, Clang on Ubuntu/macOS |
| Python package | Python 3.8-3.11 on Linux |
| Code quality | black, flake8, mypy |
| Security scanning | pip-audit, bandit |
| Docker builds | Ubuntu + Alpine images |

### CI Matrix

- **Python Versions**: 3.8, 3.9, 3.10, 3.11, 3.12
- **Platforms**: Ubuntu Latest
- **Jobs**: test, code-quality, security-checks

</details>

<details>
<summary><strong>Security Analysis</strong></summary>

| Layer | Protection |
|-------|------------|
| Defense-in-Depth | 6 independent cryptographic layers |
| Quantum Resistance | NIST-approved ML-DSA-65 (FIPS 204) and Kyber-1024 (FIPS 203) |
| Side-Channel Protection | Constant-time operations, data-independent control flow |
| Memory Safety | Secure wiping, bounds checking, magic number validation |
| 3R Monitoring | Runtime security analysis (less than 2% overhead) |

See [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) for complete cryptographic analysis.

![Quantum Security Comparison](assets/quantum_comparison.png)

*Classical algorithms (RSA, ECDSA, Ed25519) are broken by quantum computers. ML-DSA-65 provides 192-bit security against both classical and quantum attacks.*

</details>

<details>
<summary><strong>Constant-Time Verification</strong></summary>

The constant-time utility functions in `src/c/ama_consttime.c` are verified using a dudect-style timing analysis harness:

```bash
# Build and run the constant-time verification harness
cd tools/constant_time && make test
```

The harness tests all 5 constant-time functions using Welch's t-test:

| Function | Purpose | Test Classes |
|----------|---------|--------------|
| `ama_consttime_memcmp` | Byte comparison | Identical vs different buffers |
| `ama_consttime_swap` | Conditional swap | condition=0 vs condition=1 |
| `ama_secure_memzero` | Secure zeroing | All-zeros vs all-ones input |
| `ama_consttime_lookup` | Table lookup | First-half vs second-half index |
| `ama_consttime_copy` | Conditional copy | condition=0 vs condition=1 |

A t-value with |t| < 4.5 after 10^6 measurements indicates no detectable timing leakage (dudect convention: ~10⁻⁵ false positive probability under the null). See [CONSTANT_TIME_VERIFICATION.md](CONSTANT_TIME_VERIFICATION.md) for methodology details.

**Note:** This is statistical timing analysis, not formal verification. Results are environment-sensitive (CPU frequency scaling, interrupts). Run multiple times on target hardware to confirm.

</details>

<details>
<summary><strong>NIST KAT Validation</strong></summary>

All native PQC implementations pass NIST Known Answer Test (KAT) vectors, validating correctness against the official FIPS 203/204/205 specifications.

```bash
# Run NIST KAT tests (C library)
cd build && ctest --output-on-failure

# Run NIST KAT tests (Python)
pytest tests/test_nist_kat.py tests/test_pqc_kat.py -v
```

### FIPS-Format KAT Vectors (Native C — Full Validation)

These KAT tests validate the native C implementations against official NIST FIPS test vectors:

| Algorithm | Standard | KAT File | Test Coverage | Status |
|-----------|----------|----------|---------------|--------|
| ML-KEM-1024 | FIPS 203 | `tests/kat/fips203/ml_kem_1024.kat` | KeyGen, Encaps, Decaps | **10/10 PASS** |
| ML-DSA-65 | FIPS 204 | `tests/kat/fips204/ml_dsa_65.kat` | KeyGen, Sign, Verify | **10/10 PASS** |

### Legacy-Format KAT Vectors (Python Backend Validation)

| Algorithm | KAT File | Test Coverage |
|-----------|----------|---------------|
| ML-DSA-44 (Dilithium2) | `tests/kat/ml_dsa/dilithium2.rsp` | KeyGen, Sign, Verify |
| ML-DSA-65 (Dilithium3) | `tests/kat/ml_dsa/dilithium3.rsp` | KeyGen, Sign, Verify |
| ML-DSA-87 (Dilithium5) | `tests/kat/ml_dsa/dilithium5.rsp` | KeyGen, Sign, Verify |
| ML-KEM-512 (Kyber512) | `tests/kat/ml_kem/kyber512.rsp` | KeyGen, Encaps, Decaps |
| ML-KEM-768 (Kyber768) | `tests/kat/ml_kem/kyber768.rsp` | KeyGen, Encaps, Decaps |
| ML-KEM-1024 (Kyber1024) | `tests/kat/ml_kem/kyber1024.rsp` | KeyGen, Encaps, Decaps |

### Key Implementation Details

- **FIPS 203 (ML-KEM-1024):** Full Fujisaki-Okamoto transform with IND-CCA2 security, NTT-based polynomial multiplication (q=3329), implicit rejection for ciphertext validation
- **FIPS 204 (ML-DSA-65):** Rejection sampling with NTT (q=8380417), constant-time operations, deterministic signing
- **FIPS 205 (SPHINCS+-SHA2-256f-simple):** WOTS+ one-time signatures, FORS few-time signatures, hypertree (d=17) construction
- **SHA3/SHAKE:** Incremental XOF (SHAKE128/SHAKE256) with proper multi-block squeeze for FIPS 203/204 compliance

KAT vectors are sourced from NIST PQC standardization and validate that the native implementations produce bit-exact outputs for known inputs per the FIPS specifications.

</details>

---

## Documentation

<details>
<summary><strong>User Documentation</strong></summary>

| Document | Description |
|----------|-------------|
| [README.md](README.md) | Quick start and overview |
| [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) | Comprehensive deployment and build guide |
| [ENHANCED_FEATURES.md](ENHANCED_FEATURES.md) | In-depth feature documentation |
| [MONITORING.md](MONITORING.md) | 3R security monitoring guide |

</details>

<details>
<summary><strong>Technical Documentation</strong></summary>

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture and design |
| [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) | Complete security analysis |
| [BENCHMARKS.md](BENCHMARKS.md) | Performance measurements |
| [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) | Cryptographic algorithm overview |

</details>

<details>
<summary><strong>Developer Documentation</strong></summary>

| Document | Description |
|----------|-------------|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

</details>

---

## Cross-Platform Support

| Platform | Status | Tested On |
|----------|--------|-----------|
| Linux | Full support | Ubuntu 22.04, Debian 11, CentOS 8 |
| macOS | Full support | macOS 12+ (Intel and Apple Silicon) |
| Windows | Full support | Windows 10/11 (MSVC, MinGW) |
| ARM64 | Full support | Raspberry Pi, AWS Graviton |

---

## Build System 🖥️

<details>
<summary><strong>CMake (C Library with Native PQC)</strong></summary>

The C library provides full native implementations of all post-quantum cryptographic algorithms. No external PQC dependencies (liboqs, pqcrypto) are required.

**Prerequisites:**
```bash
# Install build dependencies (Ubuntu/Debian)
sudo apt-get install build-essential cmake libssl-dev

# macOS
brew install cmake openssl
```

**Build with native PQC (default):**
```bash
mkdir build && cd build

# Configure with native PQC support (enabled by default)
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DAMA_USE_NATIVE_PQC=ON \
  -DAMA_ENABLE_AVX2=ON \
  -DAMA_ENABLE_LTO=ON

# Build
cmake --build . -j$(nproc)

# Run NIST KAT validation
ctest --output-on-failure

# Install
sudo cmake --install .
```

**CMake Options**:
- `AMA_USE_NATIVE_PQC` - Enable native PQC implementations (default: ON)
- `AMA_BUILD_SHARED` - Build shared library (default: ON)
- `AMA_BUILD_STATIC` - Build static library (default: ON)
- `AMA_BUILD_TESTS` - Build test suite including NIST KAT tests (default: ON)
- `AMA_ENABLE_AVX2` - Enable AVX2 SIMD optimizations
- `AMA_ENABLE_SANITIZERS` - Enable AddressSanitizer/UBSan
- `AMA_ENABLE_LTO` - Link-time optimization

> **Note:** All PQC algorithms (ML-DSA-65, Kyber-1024, SPHINCS+-256f) are implemented natively in C with full NIST KAT validation. No external PQC libraries are needed.

</details>

<details>
<summary><strong>Python Setup</strong></summary>

```bash
# Build with optimizations
python setup.py build_ext --inplace

# Development mode
python setup.py develop

# Create distribution
python setup.py sdist bdist_wheel
```

**Environment Variables**:
- `AMA_NO_CYTHON` - Disable Cython extensions
- `AMA_NO_C_EXTENSIONS` - Disable C extensions
- `AMA_DEBUG` - Build with debug symbols
- `AMA_COVERAGE` - Enable coverage instrumentation

</details>

<details>
<summary><strong>Makefile Targets</strong></summary>

```bash
make all          # Build everything
make c            # C library only
make python       # Python package only
make test         # Run all tests
make test-c       # C tests only
make test-python  # Python tests only
make benchmark    # Performance benchmarks
make docker       # Build Docker images
make docs         # Generate documentation
make format       # Format code (clang-format, black)
make lint         # Lint code (flake8, mypy)
make clean        # Clean build artifacts
make install      # Install system-wide
```

</details>

---

## Mathematical Foundations 

<details>
<summary><strong>Research and Innovation</strong></summary>

### Proven Frameworks

1. **Helical Geometric Invariants**
   - Curvature and torsion relationship verified to 10^-10 error

2. **Lyapunov Stability Theory**
   - Proven exponential convergence O(e^{-0.18t})

3. **Golden Ratio Harmonics**
   - phi^3-amplification with Fibonacci convergence less than 10^-8

4. **Quadratic Form Constraints**
   - sigma_quadratic >= 0.96 enforcement

5. **Double-Helix Evolution**
   - 18+ equation variants for adaptive security

### 3R Security Innovation

The **3R Mechanism** (Resonance-Recursion-Refactoring) is a novel security framework providing:

- **Runtime Timing Anomaly Monitoring** via FFT frequency-domain analysis (statistical anomaly detection, not guaranteed timing attack detection)
- **Pattern Anomaly Detection** through multi-scale hierarchical analysis
- **Code Complexity Metrics** for security review
- **Less than 2% Performance Overhead** in production

See [MONITORING.md](MONITORING.md) for complete technical details.

</details>

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

<details>
<summary><strong>Development Setup</strong></summary>

```bash
# Clone repository
git clone https://github.com/Steel-SecAdv-LLC/AMA-Cryptography.git
cd AMA-Cryptography

# Install development dependencies
pip install -e ".[dev,all]"

# Setup pre-commit hooks
pre-commit install

# Format code
make format

# Lint code
make lint

# Run security audit
make security-audit
```

</details>

<details>
<summary><strong>Code Quality Standards</strong></summary>

| Language | Standards |
|----------|-----------|
| Python | PEP 8, type hints, docstrings |
| C | MISRA C guidelines, Doxygen comments |
| Security | Constant-time operations, no undefined behavior |
| Testing | Greater than 80% code coverage target |

</details>

---

## Unique Features

<details>
<summary><strong>Ethical Cryptography</strong> - Mathematically-Bound Ethical Constraints</summary>

AMA Cryptography pioneers the integration of ethical principles directly into cryptographic operations through mathematically rigorous constraints. Unlike traditional security systems that treat ethics as policy overlays, AMA Cryptography embeds ethical considerations into the cryptographic foundation itself.

**12 Omni-Code Ethical Pillars** are mathematically integrated into key derivation:

| Triad | Pillars | Cryptographic Binding |
|-------|---------|----------------------|
| **Compassion** | Empathy, Care, Support | HKDF context derivation |
| **Evidence** | Truth, Verification, Proof | Signature validation chains |
| **Justice** | Fairness, Accountability, Rights | Access control primitives |
| **Altruism** | Service, Protection, Benefit | Key encapsulation policies |

The ethical integration achieves:
- **Balanced weighting**: Σw = 12.0 across all pillars
- **SHA3-256 ethical signatures** in key derivation context
- **Zero performance impact**: <4% overhead, >1,000 ops/sec maintained
- **Survivor-first principles** with bias audits and dynamic compliance

![Ethical Binding Flow](assets/ethical_binding.png)

*Keys and signatures are cryptographically bound to an explicit ethical profile hash via HKDF domain separation. This makes policy explicit and verifiable.*

</details>

<details>
<summary><strong>Bio-Inspired Security</strong> - Omni-Code Architecture for Data Structures</summary>

AMA Cryptography employs a revolutionary bio-inspired approach where data structures mirror the elegance and resilience of biological DNA. This metaphor extends beyond naming conventions into the actual architecture of cryptographic packages.

**Master Omni-Codes** - Seven foundational codes govern the system:

| Code | Symbol | Domain | Helical Parameters |
|------|--------|--------|-------------------|
| `👁20A07∞_XΔEΛX_ϵ19A89Ϙ` | 👁∞ | Omni-Directional System | r=20.0, p=0.7 |
| `Ϙ15A11ϵ_ΞΛMΔΞ_ϖ20A19Φ` | Ϙϵ | Omni-Percipient Future | r=15.0, p=1.1 |
| `Φ07A09ϖ_ΨΔAΛΨ_ϵ19A88Σ` | Φϖ | Omni-Indivisible Guardian | r=7.0, p=0.9 |
| `Σ19L12ϵ_ΞΛEΔΞ_ϖ19A92Ω` | Σϵ | Omni-Benevolent Stone | r=19.0, p=1.2 |
| `Ω20V11ϖ_ΨΔSΛΨ_ϵ20A15Θ` | Ωϖ | Omni-Scient Curiosity | r=20.0, p=1.1 |
| `Θ25M01ϵ_ΞΛLΔΞ_ϖ19A91Γ` | Θϵ | Omni-Universal Discipline | r=25.0, p=0.1 |
| `Γ19L11ϖ_XΔHΛX_∞19A84♰` | Γϖ | Omni-Potent Lifeforce | r=19.0, p=1.1 |

**Architectural Benefits**:
- **Helical data encoding** mirrors DNA double-helix stability
- **Self-healing properties** through redundant verification chains
- **Evolutionary adaptability** for algorithm agility
- **Canonical hashing** preserves data integrity across transformations

</details>

<details>
<summary><strong>Multi-Disciplinary Approach</strong> - Quantum-Cyber-Ancient Synergies</summary>

AMA Cryptography transcends traditional computer science boundaries by synthesizing insights from quantum mechanics, ancient mathematics, philosophy, and biological systems into a unified security framework.

**Cross-Domain Synergies**:

| Domain | Contribution | Implementation |
|--------|--------------|----------------|
| **Quantum Mechanics** | Lattice-based cryptography, uncertainty principles | ML-DSA-65, Kyber-1024 post-quantum algorithms |
| **Ancient Mathematics** | Prime number theory, geometric scaling | Helical parameters, golden ratio optimizations |
| **Philosophy** | Ethical frameworks, epistemology | 12 Ethical Pillars, truth verification |
| **Biology** | DNA structure, evolutionary resilience | Bio-inspired data architecture, adaptive security |
| **Physics** | Resonance detection, timing analysis | 3R monitoring (Resonance-Recursion-Refactoring) |

**Philosophical Foundation**:
- **Epistemological rigor**: Every claim backed by mathematical proof
- **Ethical alignment**: Compassion, evidence, justice, altruism as core values
- **Character-driven design**: Competence, commitment, control embedded in architecture
- **Survivor-first principles**: Security designed to protect the vulnerable

This multi-disciplinary synthesis uses NIST-standard primitives (SHA3-256, HMAC-SHA3-256, Ed25519, ML-DSA-65, HKDF) with ~128-bit classical and ~192-bit quantum security margins. All security analysis is self-assessed; see SECURITY_ANALYSIS.md for derivations and caveats.

</details>

---

## License

Copyright 2025 Steel Security Advisors LLC

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) file for details.

### Third-Party Dependencies

- **ML-DSA** (Dilithium): Public domain (NIST PQC)
- **Kyber**: Public domain (NIST PQC)
- **SPHINCS+**: Public domain (NIST PQC)
- **Ed25519**: Public domain (ref10 implementation)

### Dependency Graph

GitHub's dependency graph is enabled for this repository. Once the repository is public, you can view the complete dependency tree at: `Insights > Dependency graph`. This provides visibility into all direct and transitive dependencies, security advisories, and Dependabot alerts for automated vulnerability detection.

---

## Contact and Support

| Type | Contact |
|------|---------|
| General Inquiries | steel.sa.llc@gmail.com |
| Security Issues | See [SECURITY.md](SECURITY.md) for responsible disclosure |
| GitHub Issues | [Issues Page](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/issues) |
| GitHub Repository | [AMA Cryptography](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography) |

---

## Acknowledgments

**Author/Inventor**: Andrew E. A.

**AI Co-Architects:** Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛

**Special Thanks**:
- NIST Post-Quantum Cryptography Standardization Project
- The open-source cryptography community
- All contributors and security researchers

---

## Steel Security Advisors LLC – Legal Disclaimer & Attribution

### Development Model

**Conceptual Architect:** Steel Security Advisors LLC and Andrew E. A. conceived, directed, validated, and supervised the development of AMA Cryptography.

**AI Co-Architects:** More than 99% of the codebase, documentation, mathematical frameworks, and technical implementation was constructed by AI systems: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛.

This project represents a human/AI collaborative construct—a new development paradigm where human vision, requirements, and critical evaluation guide AI-generated implementation.

### Professional Background Disclosure

The human architect does not hold formal credentials in cryptography. The AI contributors, while trained on cryptographic literature, are tools without professional accountability.

### What We Did Right

- **Standards-based design:** Built on NIST FIPS 202/204, RFC 2104/5869/8032/3161—not custom cryptography
- **Quantified claims:** All performance metrics are measured and reproducible (see BENCHMARKS.md)
- **Rigorous testing:** 694+ tests with 32 CI checks including security scanning (TruffleHog)
- **Regression detection:** Tiered benchmark tolerances calibrated for CI environments
- **Transparent limitations:** Security analysis explicitly distinguishes self-assessed vs. audited claims
- **Defense-in-depth:** Security bounded by weakest layer (~128-bit classical), not inflated aggregate claims
- **Academic grounding:** Security proofs reference peer-reviewed literature (Bellare, Krawczyk, Bernstein, et al.)

### What Requires Caution

- **No Independent Audit:** All security analysis is self-assessed. Production deployment requires review by qualified cryptographers.
- **AI-Generated Code:** May contain subtle implementation errors that appear correct. Constant-time properties and side-channel resistance require independent verification.
- **New PQC Standards:** ML-DSA-65 and Kyber-1024 are recent NIST standards with limited real-world deployment history.
- **Implementation vs. Specification:** Using correct algorithms doesn't guarantee correct implementation.

### Recommendation

Before production use:

- Commission independent security audit by qualified cryptographers
- Verify constant-time implementations (ctgrind, dudect)
- Deploy with FIPS 140-2 Level 3+ HSM for master secrets
- Conduct penetration testing

### No Warranty

THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. THE AUTHORS AND CONTRIBUTORS DISCLAIM ALL LIABILITY FOR ANY DAMAGES RESULTING FROM ITS USE.

*This disclaimer does not replace formal legal advice; organizations should consult qualified counsel for regulatory and contractual obligations.*

---

<div align="center">

**AMA Cryptography - Protecting people, data, and networks with quantum-resistant cryptography**

*Architected with inherent radical honesty, unconventional methodology, protective servitude, and ethical immutability.*

<div align="center">

<img width="27" height="29" alt="image" src="https://github.com/user-attachments/assets/12254743-9798-46df-bc27-4b25857141fe" />

</div>

*Last updated: 2026-03-06*

</div>
