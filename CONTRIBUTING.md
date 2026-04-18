# Contributing to AMA Cryptography

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 2.1.5 |
| Last Updated | 2026-04-17 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Overview

This document provides guidelines for contributing to the AMA Cryptography quantum-resistant cryptographic protection system. AMA Cryptography is released under the Apache License 2.0 as free and open-source software, accessible for universal use as a knowledge vault and bridge to cryptographic frontiers.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Contribution Guidelines](#contribution-guidelines)
5. [Cryptographic Standards](#cryptographic-standards)
6. [Code Quality Requirements](#code-quality-requirements)
7. [Testing Requirements](#testing-requirements)
8. [Pull Request Process](#pull-request-process)
9. [Security Considerations](#security-considerations)
10. [Documentation Standards](#documentation-standards)
11. [Community](#community)

---

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Git
- Basic understanding of cryptography
- Familiarity with NIST and IETF standards

### Ways to Contribute

We welcome contributions in the following areas:

- **Bug Reports:** Report issues with cryptographic operations, standards compliance, or implementation errors
- **Security Fixes:** Address security vulnerabilities (see [SECURITY.md](SECURITY.md))
- **Documentation:** Improve clarity, add examples, correct errors
- **Testing:** Add test coverage, improve test quality
- **Performance:** Optimize cryptographic operations without compromising security
- **Features:** Implement new cryptographic features (discuss first in an issue)
- **Standards Updates:** Update implementations to reflect new NIST/IETF standards

### What NOT to Contribute

Please **DO NOT** submit pull requests that:

- Weaken cryptographic security in any way
- Remove or bypass security layers
- Introduce unproven or non-standard cryptographic algorithms
- Break standards compliance (NIST FIPS 202, 203, 204, 205, SP 800-38D, RFC 2104, 5869, 8032, 3161)
- Add unnecessary dependencies
- Include proprietary or non-Apache 2.0 compatible code
- Lack specification references (NIST FIPS, RFC, or peer-reviewed paper) for cryptographic changes

## Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/AMA-Cryptography.git
cd AMA-Cryptography
```

### 2. Create Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies (zero core deps — all crypto is native C)
pip install --upgrade pip

# Build native C library (all cryptographic primitives)
cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release && cmake --build build

# Install development tools
pip install -e ".[dev]"  # Installs pytest, ruff, mypy, bandit (and black on Python 3.10+)
```

### 3. Verify Setup

```bash
# Run the demonstration
python -m ama_cryptography

# Expected output should include "ALL VERIFICATIONS PASSED"
```

### 4. Create Feature Branch

```bash
# Create a new branch for your contribution
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

## Contribution Guidelines

### General Principles

1. **Security First:** Never compromise security for convenience or performance
2. **Standards Compliance:** Adhere strictly to NIST and IETF specifications
3. **Standards Rigor:** All cryptographic claims must reference the relevant standard's security analysis
4. **Code Quality:** Follow PEP 8 and maintain type hints throughout
5. **Documentation:** Every change must be documented with academic citations where applicable
6. **Backwards Compatibility:** Maintain compatibility unless security requires breaking changes

### Critical Rules for Cryptographic Code

**ALWAYS:**
- Use cryptographically secure random number generation (`secrets` module)
- Validate all inputs to cryptographic functions
- Use constant-time operations for security-critical comparisons
- Follow NIST recommendations for key sizes and algorithm parameters
- Cite the specification being implemented (NIST FIPS, RFC, or peer-reviewed paper)
- Provide KAT validation against published test vectors
- Security claims must reference the relevant standard's security analysis, not original proofs
- Test against known test vectors from standards documents

**NEVER:**
- Introduce ad-hoc or unreviewed cryptographic constructions — all primitives must follow published NIST/IETF specifications and pass KAT validation
- Use deprecated algorithms (MD5, SHA-1, RSA < 2048 bits)
- Store secrets in logs, error messages, or debug output
- Use non-constant-time string comparisons for authentication
- Ignore error conditions in cryptographic operations
- Make security claims without referencing the relevant standard's security analysis
- Copy-paste cryptographic code without understanding it

## Cryptographic Standards

All contributions must maintain compliance with:

### Required Standards

| Standard | Version | Compliance Level | Documentation |
|----------|---------|------------------|---------------|
| NIST FIPS 202 | 2015 | Mandatory | SHA-3 Standard (SHA3-256, SHAKE128/256) |
| NIST FIPS 203 | 2024 | Mandatory | ML-KEM (Kyber) Key Encapsulation |
| NIST FIPS 204 | 2024 | Mandatory | ML-DSA (Dilithium) Digital Signatures |
| NIST FIPS 205 | 2024 | Mandatory | SLH-DSA (SPHINCS+) Hash-Based Signatures |
| NIST SP 800-38D | 2007 | Mandatory | AES-GCM Authenticated Encryption |
| NIST SP 800-108 | Rev. 1 | Mandatory | Key Derivation Using Pseudorandom Functions |
| RFC 2104 | 1997 | Mandatory | HMAC |
| RFC 5869 | 2010 | Mandatory | HKDF |
| RFC 8032 | 2017 | Mandatory | EdDSA (Ed25519) |
| RFC 3161 | 2001 | Mandatory | Time-Stamp Protocol |
| RFC 7748 | 2016 | Mandatory | Elliptic Curves for Security (X25519) |
| RFC 8439 | 2018 | Mandatory | ChaCha20-Poly1305 AEAD |
| RFC 9106 | 2021 | Mandatory | Argon2 Memory-Hard Function |

### Changes to Cryptographic Standards

If you need to update cryptographic standards:

1. Open an issue first to discuss the change
2. Provide references to the updated standard
3. Include migration guide for existing users
4. Maintain backwards compatibility when possible
5. Update all affected documentation
6. Add deprecation warnings before removing old standards

## Code Quality Requirements

### PEP 8 Compliance

All Python code must follow PEP 8 style guidelines:

```bash
# Check formatting and linting
black --check .
ruff check .
```

### Type Hints

All functions must include comprehensive type hints:

```python
from typing import List, Tuple, Optional

def create_signature(
    data: bytes,
    private_key: ed25519.Ed25519PrivateKey
) -> bytes:
    """
    Create Ed25519 signature for data.

    Args:
        data: Raw bytes to sign
        private_key: Ed25519 private key

    Returns:
        64-byte signature

    Raises:
        ValueError: If data is empty
    """
    if not data:
        raise ValueError("Cannot sign empty data")
    return private_key.sign(data)
```

### Documentation Requirements

All functions must have docstrings including:

- **Brief description:** One-line summary
- **Detailed description:** Cryptographic purpose and operation
- **Args:** Type and description of each parameter
- **Returns:** Type and description of return value
- **Raises:** All possible exceptions
- **Security:** Any security considerations or constraints
- **Standards:** Reference to relevant NIST/IETF standards
- **Examples:** Usage examples for non-trivial functions

### Code Review Checklist

Before submitting, verify:

- [ ] Code follows PEP 8 (run `black`, `ruff check`)
- [ ] All functions have type hints
- [ ] All functions have comprehensive docstrings
- [ ] No cryptographic security weaknesses introduced
- [ ] Standards compliance maintained
- [ ] Tests pass (run `pytest`)
- [ ] Documentation updated
- [ ] No secrets or credentials in code
- [ ] Error handling is comprehensive
- [ ] Performance impact is acceptable

## Testing Requirements

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=. --cov-report=term-missing

# Run specific test file
pytest tests/test_specific.py

# Run tests marked as slow
pytest -m slow
```

### Test Coverage Requirements

- **Minimum coverage:** 80% for new code
- **Cryptographic functions:** 100% coverage required
- **Error paths:** All error conditions must be tested
- **Edge cases:** Boundary conditions and corner cases

### Test Quality Standards

All tests must:

1. **Use Known Test Vectors:** Use published test vectors from NIST/IETF when available
2. **Test Success Paths:** Verify correct operation with valid inputs
3. **Test Failure Paths:** Verify proper error handling with invalid inputs
4. **Test Edge Cases:** Empty inputs, maximum sizes, boundary conditions
5. **Be Deterministic:** No random failures or race conditions
6. **Be Independent:** Tests should not depend on execution order
7. **Be Fast:** Unit tests should complete in milliseconds
8. **Be Documented:** Include docstrings explaining what is being tested

### Example Test Structure

```python
import pytest
from ama_cryptography.crypto_api import generate_ed25519_keypair, sign_data

class TestEd25519Signatures:
    """Test Ed25519 signature generation and verification."""

    def test_signature_generation_success(self):
        """Test successful signature generation with valid input."""
        # Arrange
        keypair = generate_ed25519_keypair()
        data = b"Test data for signing"

        # Act
        signature = sign_data(data, keypair.private_key)

        # Assert
        assert len(signature) == 64  # Ed25519 signatures are 64 bytes
        assert isinstance(signature, bytes)

    def test_signature_verification_success(self):
        """Test successful signature verification."""
        # Test implementation
        pass

    def test_signature_empty_data_raises_error(self):
        """Test that signing empty data raises ValueError."""
        keypair = generate_ed25519_keypair()

        with pytest.raises(ValueError, match="Cannot sign empty data"):
            sign_data(b"", keypair.private_key)
```

## Pull Request Process

### Before Submitting

1. **Update from main:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run all checks:**
   ```bash
   black .
   ruff check .
   mypy ama_cryptography/
   pytest
   ```

3. **Update documentation:**
   - Update README.md if adding features
   - Update SECURITY.md if affecting security
   - Update IMPLEMENTATION_GUIDE.md if changing deployment
   - Add entries to CHANGELOG.md

4. **Commit with clear messages:**
   ```bash
   git commit -m "feat: Add support for Kyber key encapsulation

   - Implement Kyber-768 key generation
   - Add encapsulation and decapsulation functions
   - Include NIST test vectors
   - Update documentation with Kyber details

   Refs: NIST FIPS 203
   Closes: #123"
   ```

### Commit Message Format

Follow conventional commits:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `security`: Security vulnerability fix
- `docs`: Documentation only
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `chore`: Maintenance tasks

**Examples:**
```
feat(crypto): Add Falcon signature support
fix(hmac): Correct constant-time comparison
security(keys): Fix timing attack in key derivation
docs(readme): Update installation instructions
test(dilithium): Add NIST test vectors
```

### Pull Request Template

When you open a PR, include:

1. **Description:** Clear description of changes
2. **Motivation:** Why is this change needed?
3. **Security Impact:** Does this affect security? How?
4. **Standards Compliance:** Which standards does this affect?
5. **Testing:** What tests were added/modified?
6. **Breaking Changes:** Any backwards-incompatible changes?
7. **Checklist:** Complete the PR checklist

### Review Process

1. **Automated Checks:** All CI checks must pass
2. **Code Review:** At least one maintainer approval required
3. **Security Review:** Cryptographic changes require additional review
4. **Documentation Review:** All docs must be accurate
5. **Testing:** All tests must pass on Python 3.9-3.13

### After Approval

Maintainers will:
1. Merge your PR into main branch
2. Update version numbers if needed
3. Add your contribution to CHANGELOG
4. Credit you in release notes

## Security Considerations

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for reporting process.

### Security Review Requirements

Changes affecting cryptographic operations require:

1. **Specification Citation:** Cite the specification being implemented (NIST FIPS, RFC, or peer-reviewed paper)
2. **KAT Validation:** Provide Known Answer Test validation against published test vectors from the cited specification
3. **Standards References:** Cite NIST/IETF specifications for all algorithm choices and parameter selections
4. **Threat Analysis:** Consider attack vectors
5. **Performance Analysis:** Ensure constant-time operations where required
6. **Security Claims:** Must reference the relevant standard's security analysis, not original proofs

### Common Security Pitfalls

Avoid these common mistakes:

- **Timing Attacks:** Use constant-time comparisons for MACs/signatures
- **Side Channels:** Be aware of cache timing and power analysis
- **Entropy Issues:** Always use `secrets` module for randomness
- **Error Information Leakage:** Don't reveal information in error messages
- **Integer Overflow:** Validate all length calculations
- **Memory Safety:** Be careful with buffer sizes

## Documentation Standards

### Academic Citations

When referencing cryptographic research:

```markdown
According to Bernstein et al. [1], Ed25519 provides 128-bit classical security...

**References:**

[1] Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., & Yang, B. Y. (2011).
    "High-speed high-security signatures."
    Journal of Cryptographic Engineering, 2(2), 77-89.
    DOI: 10.1007/s13389-012-0027-1
```

### Standards References

When citing standards:

```markdown
SHA3-256 provides 128-bit collision resistance and 256-bit preimage resistance
as specified in NIST FIPS 202 Section 6.1.

**Reference:** NIST FIPS 202 - SHA-3 Standard: Permutation-Based Hash and
Extendable-Output Functions (August 2015)
```

## Community

### Communication Channels

- **GitHub Issues:** Bug reports, feature requests
- **GitHub Discussions:** General questions, ideas
- **Email:** steel.sa.llc@gmail.com (security issues only)

### Getting Help

- Review [README.md](README.md) for project overview
- Check [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) for usage
- Read [SECURITY.md](SECURITY.md) for technical details
- Search existing issues before opening new ones
- Ask questions in GitHub Discussions

### Recognition

Contributors will be recognized in:
- CHANGELOG.md for their contributions
- Release notes
- GitHub contributors page

Significant contributors may be invited to join the project as maintainers.

## Questions

If you have questions about contributing:

1. Check this CONTRIBUTING.md file
2. Review existing issues and pull requests
3. Ask in GitHub Discussions
4. Contact maintainers at steel.sa.llc@gmail.com

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-11-26 | Initial professional release |
| 1.1.0 | 2026-01-09 | Version alignment, terminology updates |
| 2.0.0 | 2026-03-08 | Zero-dependency architecture, FIPS 203/204/205, updated module references |
| 2.1.0 | 2026-03-16 | Replace flake8/isort references with ruff, toolchain documentation update |
| 2.1.5 | 2026-04-17 | Documentation version alignment across repository |

---

Copyright 2025-2026 Steel Security Advisors LLC. Licensed under Apache License 2.0.
