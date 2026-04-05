# AMA Cryptography — Developer Skills Reference

## Build Targets

| Target | Command | Description |
|--------|---------|-------------|
| `make all` | Build C library + Python extensions | Full build |
| `make c` | `cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build` | C library only |
| `make python` | `python3 setup.py build_ext --inplace` | Python extensions |
| `make test` | `make test-c test-python` | All tests |
| `make test-c` | `cd build && ctest --output-on-failure` | C tests via CTest |
| `make test-python` | `pytest tests/ -v --cov=ama_cryptography` | Python tests |
| `make benchmark` | `python3 benchmark_suite.py` | Performance benchmarks |
| `make lint` | `ruff check . && mypy ama_cryptography/` | Lint + type check |
| `make format` | `black . && ruff check --select I --fix .` | Auto-format |
| `make security-scan` | bandit + semgrep + pip-audit | Security audit |
| `make constant-time-check` | dudect harness (100K iterations) | Timing leak detection |
| `make fuzz` | libFuzzer + ASan harnesses | Fuzz testing |
| `make docker` | Docker image build | Container build |

## Test Patterns

```bash
# Full test suite
pytest tests/ -v

# Specific test categories
pytest tests/ -k "test_crypto"          # Crypto operations
pytest tests/ -k "test_pqc"            # Post-quantum tests
pytest tests/ -k "test_nist_kat"       # NIST Known Answer Tests (requires oqs)
pytest tests/ -k "test_memory"         # Secure memory tests
pytest tests/ -k "test_posture"        # Adaptive posture tests

# With coverage
pytest tests/ -v --cov=ama_cryptography --cov-report=term-missing

# Quick smoke test
python -m ama_cryptography            # Runs demo/POST
```

## Development Workflow

1. **Build C library first** (required for all PQC operations):
   ```bash
   cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release
   cmake --build build -j$(nproc)
   ```

2. **Install Python package in dev mode**:
   ```bash
   pip install -e ".[dev,all]"
   ```

3. **Run tests**:
   ```bash
   pytest tests/ -v --tb=short
   ```

4. **Lint before committing**:
   ```bash
   ruff check .
   black --check .
   mypy --strict ama_cryptography/ tests/
   ```

5. **Update integrity digest after modifying Python source**:
   ```bash
   python -m ama_cryptography.integrity --update
   ```

## CI Matrix

The CI pipeline (`.github/workflows/ci.yml`) runs a cross-platform matrix:

### Test Matrix (3 OS × 5 Python versions = 12 configurations)

| OS | Python Versions | Notes |
|----|----------------|-------|
| `ubuntu-latest` (x86-64) | 3.9, 3.10, 3.11, 3.12, 3.13 | Primary platform, full test suite |
| `windows-latest` | 3.9, 3.10, 3.11, 3.12, 3.13 | Windows compatibility (CMake via choco) |
| `ubuntu-24.04-arm` (AArch64) | 3.11, 3.13 | ARM64 with NEON/SVE2 dispatch testing |

### Quality & Security Jobs

| Job | Python | Description |
|-----|--------|-------------|
| `code-quality` | 3.11 | ruff + black + mypy --strict |
| `security-checks` | 3.11 | bandit + semgrep + pip-audit + invariant checks |
| `benchmark-regression` | 3.11 | Performance regression detection vs baseline.json |
| `constant-time-check` | N/A (C only) | dudect timing analysis (50K iterations) |
| `fuzz-*` | N/A (C only) | libFuzzer + ASan harnesses for core primitives |
| `cppcheck` / `scan-build` | N/A (C only) | Static analysis (gcc + clang) |
| `CodeQL` | N/A | GitHub security analysis |

## SIMD Tier Explanation

Runtime dispatch selects the best available SIMD path:

### ARM (AArch64)
```
Generic (C) → NEON (128-bit SIMD) → SVE2 (scalable vector, ARMv9+)
```

### x86-64
```
Generic (C) → AVX2 (256-bit SIMD)
```

The dispatch system (`src/c/dispatch/ama_dispatch.c`) detects CPU features
at initialization and sets function pointers to the optimal implementation.
SVE2 overrides NEON when available; AVX2 overrides generic on x86.

Dispatch covers: Keccak-f1600, Kyber NTT/invNTT/pointwise, Dilithium NTT/invNTT/pointwise.

## Key Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AMA_DISPATCH_VERBOSE` | `0` | Print dispatch decisions at init |
| `AMA_CRYPTO_LIB_PATH` | auto-detect | Override path to `libama_cryptography.so` |
| `AMA_CI_REQUIRE_BACKENDS` | `0` | Fail if any PQC backend is unavailable (CI) |
| `AMA_TESTING_MODE` | unset | Enable test-specific behavior |
| `AMA_REQUIRE_REAL_PQC` | unset | Enforce native PQC (production gate) |
| `AMA_REQUIRE_CONSTANT_TIME` | unset | Enforce constant-time crypto |

## Architecture Overview

```
Layer 0: Native C (src/c/)     — SHA3, AES-GCM, Dilithium, Kyber, SPHINCS+, Ed25519
Layer 1: Cython (src/cython/)  — High-performance math engine bindings
Layer 2: Python API             — crypto_api.py, key_management.py, secure_channel.py
Support: 3R Monitor + Posture  — Runtime timing anomaly detection + threat response
```

## Key Invariants

- **INVARIANT-7**: No pure-Python crypto fallbacks. All primitives delegate to native C.
- **INVARIANT-12**: Secret-dependent operations must be constant-time via native backend.
- **INVARIANT-13**: All suppression comments must have tracking identifiers.
- **FIPS POST**: Module integrity + KAT tests + timing oracle run at import time.
