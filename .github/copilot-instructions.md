# Copilot Instructions — AMA Cryptography

## Project Overview

AMA Cryptography is a quantum-resistant cryptography library with a three-tier
architecture: native C core (`src/c/`), Cython bindings (`src/cython/`), and
Python API (`ama_cryptography/`). All cryptographic primitives are implemented
in-house — zero external crypto dependencies.

## Critical Constraints

1. **INVARIANT-1:** Never introduce imports of `cryptography`, `pynacl`,
   `libsodium`, OpenSSL, or any external crypto library. Only
   `hmac.compare_digest()` is permitted from the `hmac` module.

2. **INVARIANT-7:** No pure-Python fallbacks for cryptographic operations.
   If the native C backend is unavailable, the library must raise
   `RuntimeError` at import time.

3. **INVARIANT-12:** All secret-dependent operations must be constant-time.
   Never use `==` to compare MACs, tags, or secret data. Python code must
   delegate all crypto to the native C backend.

## Standards Compliance

All cryptographic implementations must reference their governing standard:
- SHA-3: NIST FIPS 202
- ML-KEM (Kyber): NIST FIPS 203
- ML-DSA (Dilithium): NIST FIPS 204
- SLH-DSA (SPHINCS+): NIST FIPS 205
- AES-GCM: NIST SP 800-38D
- Ed25519: RFC 8032
- X25519: RFC 7748
- ChaCha20-Poly1305: RFC 8439
- HKDF: RFC 5869
- Argon2id: RFC 9106
- HMAC: RFC 2104

See `CSRC_STANDARDS.md` for the complete mapping.

## Code Style

- **Python:** PEP 8 via `black` (line length 100) and `ruff`. Type hints
  required on all functions. Docstrings with args, returns, raises, and
  standards references.
- **C:** C11 standard. No external crypto deps. Constant-time for all
  secret-dependent paths.
- **Imports:** Always at top of file. Use `ruff` for import sorting (not
  standalone `isort`).
- **Commits:** Conventional format: `<type>(<scope>): <subject>`

## After Modifying `ama_cryptography/` Source

Always regenerate the FIPS 140-3 integrity digest:
```bash
python -m ama_cryptography.integrity --update
```

Failure to do so will cause the Power-On Self-Test to fail, blocking all
cryptographic operations.

## Key Files

| File | Purpose |
|------|---------|
| `.github/INVARIANTS.md` | Canonical architectural invariants (INVARIANT-1 through INVARIANT-15) and vendoring policy |
| `CONTRIBUTING.md` | Contribution guidelines |
| `CSRC_STANDARDS.md` | Algorithm-to-standard mapping |

## Testing

```bash
pytest tests/ -v                      # Run test suite
python -m ama_cryptography            # Verify demo outputs "ALL VERIFICATIONS PASSED"
ruff check . && black --check .       # Lint and format
mypy --strict ama_cryptography/ tests/ # Type check
```
