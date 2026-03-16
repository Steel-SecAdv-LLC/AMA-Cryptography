# Contributing

Thank you for your interest in contributing to AMA Cryptography. This page covers how to set up a development environment, code standards, testing requirements, and the contribution workflow.

---

## Code of Conduct

All contributors are expected to follow the [Code of Conduct](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/CODE_OF_CONDUCT.md). We are committed to providing a welcoming and harassment-free environment.

---

## Development Setup

### 1. Fork and Clone

```bash
git clone https://github.com/YOUR_USERNAME/AMA-Cryptography.git
cd AMA-Cryptography
```

### 2. Build the Native Library

```bash
cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

### 3. Install in Development Mode

```bash
pip install -e ".[dev,monitoring]"
```

This installs all development dependencies:
- `pytest`, `pytest-cov`, `pytest-benchmark`
- `black`, `ruff`, `mypy`
- `hypothesis` (property-based testing)
- `numpy`, `scipy` (for 3R monitoring engine)

### 4. Install Pre-commit Hooks

```bash
pre-commit install
```

This runs formatting (Black), linting (ruff), and security scanning (Semgrep) automatically on each commit.

---

## Code Standards

### Python

| Tool | Standard | Config |
|------|---------|--------|
| Formatter | Black (line length 88) | `pyproject.toml` |
| Linter + imports | ruff (replaces flake8 + isort) | `pyproject.toml` |
| Type hints | mypy (strict) | `pyproject.toml` |
| Docstrings | Google style | — |

Run all checks:
```bash
black ama_cryptography tests
ruff check ama_cryptography tests
mypy ama_cryptography
```

### C

| Tool | Standard | Config |
|------|---------|--------|
| Formatter | clang-format | `.clang-format` |
| Standard | C11 (`-std=c11`) | `CMakeLists.txt` |
| Line width | 100 columns | `.clang-format` |
| Indent | 4 spaces | `.clang-format` |
| Include sort | Disabled | `.clang-format` |

Run C formatter:
```bash
clang-format -i src/c/*.c include/*.h
```

C source files include the public header as:
```c
#include "../include/ama_cryptography.h"
```

### Timestamps

All timestamps use `datetime.now(timezone.utc)` (not `datetime.now()`) to ensure timezone-aware UTC timestamps throughout.

---

## Testing Requirements

All contributions must include tests. The test suite uses `pytest` with custom markers:

| Marker | Description |
|--------|-------------|
| `@pytest.mark.slow` | Long-running tests (>10s) |
| `@pytest.mark.quantum` | Requires PQC library |
| `@pytest.mark.integration` | End-to-end integration tests |

### Running Tests

```bash
# All tests
pytest tests/

# Specific test file
pytest tests/test_pqc_backends.py -v

# Skip slow tests
pytest tests/ -m "not slow"

# With coverage report
pytest tests/ --cov=ama_cryptography --cov-report=html

# Run only integration tests
pytest tests/ -m integration
```

### Test Coverage Requirements

| Category | Minimum Coverage |
|----------|-----------------|
| Core cryptographic operations | 90% |
| Key management | 85% |
| Public API | 90% |
| Error handling | 80% |

### C Tests

```bash
cmake -B build -DAMA_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build
cd build && ctest --output-on-failure -V
```

---

## Types of Contributions

### Bug Reports

When reporting bugs:
1. Check existing issues to avoid duplicates
2. Include: Python version, OS, library version (`import ama_cryptography; print(ama_cryptography.__version__)`)
3. Provide a minimal reproducible example
4. Include full error traceback

### Security Vulnerabilities

**Do NOT** open public issues for security vulnerabilities. See [Security Model](Security-Model) for the responsible disclosure process.

### Feature Requests

Open an issue with:
- Problem statement
- Proposed solution
- Security implications (especially for cryptographic changes)
- References to relevant standards

### Pull Requests

1. **Fork** the repository
2. **Branch** from `main`: `git checkout -b feature/your-feature-name`
3. **Implement** your change with tests
4. **Run** the full test suite: `pytest tests/`
5. **Run** linters: `black`, `ruff check`, `mypy`
6. **Commit** with a clear message (see format below)
7. **Push** to your fork
8. **Open a PR** against `main`

### Commit Message Format

```
type(scope): Brief description (≤ 50 chars)

Longer explanation of what and why (not how).
Reference issues: Fixes #123
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `security`

Examples:
```
feat(pqc): add SPHINCS+-SHA2-192f variant
fix(key_management): use timezone.utc in rotate_key()
security(aes): document cache-timing limitation of default S-box
test(hybrid_combiner): add property-based tests with Hypothesis
docs(wiki): update performance benchmarks for v2.0
```

---

## Cryptographic Contribution Guidelines

Cryptographic code changes require extra scrutiny:

### For New Algorithms

1. Must be from a NIST/IETF approved standard (FIPS, RFC)
2. Must include NIST Known Answer Test (KAT) validation
3. Must include security analysis documenting assumptions and security level
4. Constant-time implementation required for secret-dependent operations
5. Required reviewer: someone with cryptographic expertise

### For Changes to Existing Algorithms

1. Justify the change with references to standards or security analysis
2. Maintain backward compatibility or provide migration path
3. All existing KAT tests must continue to pass
4. Run `tests/test_pqc_kat.py` and `tests/test_nist_kat.py`

### For Key Management Changes

1. Ensure `datetime.now(timezone.utc)` is used (not naive datetimes)
2. Verify hardened-only BIP32 derivation is maintained
3. Test all `KeyStatus` lifecycle transitions

---

## Project Structure

```
AMA-Cryptography/
├── ama_cryptography/     # Python package
│   ├── __init__.py       # Lazy imports (PEP 562)
│   ├── crypto_api.py     # Algorithm-agnostic API
│   ├── pqc_backends.py   # PQC backend
│   ├── key_management.py # HD keys, lifecycle
│   ├── secure_memory.py  # Memory safety
│   ├── hybrid_combiner.py# Hybrid KEM
│   ├── adaptive_posture.py # Threat response
│   ├── equations.py      # Math engine
│   ├── double_helix_engine.py # State evolution
│   ├── rfc3161_timestamp.py # RFC 3161
│   └── exceptions.py     # Exception hierarchy
├── src/c/                # Native C implementations
├── include/              # C API headers
├── tests/                # Python test suite (30 files)
├── tests/c/              # C test suite
├── fuzz/                 # libFuzzer harnesses
├── examples/             # Usage examples
├── benchmarks/           # Performance benchmarks
├── docs/                 # Sphinx documentation
└── wiki/                 # GitHub Wiki source
```

---

## Continuous Integration

The CI pipeline runs on every PR:

| Check | Description |
|-------|-------------|
| `ci.yml` | Python tests (matrix: 3.9, 3.10, 3.11, 3.12) |
| `ci-build-test.yml` | C library build + C tests |
| `static-analysis.yml` | Black, ruff, mypy --strict, Semgrep |
| `security.yml` | Security scanning |
| `fuzzing.yml` | libFuzzer regression tests |

All CI checks must pass before a PR is eligible for merge.

---

## Contact

- **Maintainer:** Andrew E. A. (Steel Security Advisors LLC)
- **Email:** steel.sa.llc@gmail.com
- **Issues:** [GitHub Issues](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/issues)

---

*See [Installation](Installation) for the full build setup, or [Security Model](Security-Model) for the responsible disclosure process.*
