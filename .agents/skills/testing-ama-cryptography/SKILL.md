# Testing AMA Cryptography

## Overview
Procedures for testing the AMA Cryptography system (formerly Ava Guardian),
a hybrid post-quantum security framework with FIPS 140-3 compliance.

## Environment Setup

```bash
cd ~/repos/Ava-Guardian
# Python 3.12+ required; native C library pre-built in build/lib/
```

## Running the Full Test Suite

```bash
python -m pytest tests/ -v --timeout=300
```

Expected: ~1260+ passed, ~8 skipped, 0 failures.
Skips are conditional on PQC backend availability (Kyber, SPHINCS+, Dilithium).

## Lint and Formatting

```bash
# Use ruff (NOT standalone isort) -- the project's ruff config handles import sorting
ruff check ama_cryptography/ tests/
black --check ama_cryptography/ tests/
```

**Important:** Do NOT run `isort` separately. The project's `pyproject.toml` configures
ruff with `I001` (isort) rules. Running standalone isort will conflict with ruff's
import ordering and produce false violations.

## FIPS 140-3 Integrity Digest

After ANY change to source files under `ama_cryptography/`, you MUST update the
integrity digest:

```bash
python -m ama_cryptography.integrity --update
```

Verify it:

```bash
python -m ama_cryptography.integrity --verify
```

The digest file is `ama_cryptography/_integrity_digest.txt`. If you forget to update
it, the module's Power-On Self-Test (POST) will fail integrity verification on import,
and `_MODULE_STATE` will be set to `"ERROR"`, blocking all cryptographic operations
via `_check_operational()`.

## Cryptographic Demo

```bash
python3 code_guardian_secure.py
```

Expected output includes "ALL VERIFICATIONS PASSED". Verify no legacy terminology
(e.g., "6-Layer") appears in output.

## Testing the FIPS 140-3 Operational Gate

All convenience functions (`quick_hash`, `quick_sign`, `quick_verify`, `quick_kem`)
call `_check_operational()` before executing. To test the gate:

```python
from ama_cryptography._self_test import _set_error, _set_operational
from ama_cryptography.exceptions import CryptoModuleError
from ama_cryptography.crypto_api import quick_hash

try:
    _set_error("test error reason")
    quick_hash(b"should fail")  # Raises CryptoModuleError
except CryptoModuleError as e:
    assert "test error reason" in str(e)
finally:
    _set_operational()  # Always restore to prevent cascading failures
```

**Critical:** Always wrap `_set_error()` in a `try/finally` with `_set_operational()`
to restore the module. Failure to do so leaves the module in ERROR state and all
subsequent crypto operations will fail.

## CI Configuration

CI workflows are in `.github/workflows/`:
- `ci.yml` -- main CI (lint, test, security)
- `ci-build-test.yml` -- build and NIST KAT tests
- `fuzzing.yml`, `security.yml`, `static-analysis.yml`

**Trigger rules:**
- `push` triggers on: `main`, `develop`, `claude/**`
- `pull_request` triggers on: `main`, `develop` ONLY

PRs must target `main` or `develop` for CI to run. PRs targeting other branches
(e.g., `claude/consolidate-*`) will NOT trigger CI workflows.

## Key Invariants

1. **INVARIANT-1:** Zero external crypto dependencies (no OpenSSL, no libsodium)
2. **INVARIANT-2:** Thread-safe CPU dispatch for SIMD operations
3. **FIPS 140-3:** All crypto ops gated by `_check_operational()`
4. **Terminology:** Use "Multi-Layer Defense-in-Depth" (not "6-Layer")
5. **Metadata key:** `multi_layer_defense` (not `six_layer_defense`)
