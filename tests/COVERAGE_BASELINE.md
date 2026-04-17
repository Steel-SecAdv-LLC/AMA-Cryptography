# Coverage Baseline Report

**Date:** 2026-04-17
**Branch:** `claude/improve-test-coverage-oJO79`
**Invocation:**

```
cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release \
      -DAMA_BUILD_TESTS=OFF -DAMA_BUILD_EXAMPLES=OFF
cmake --build build -j$(nproc)
pip install -e ".[dev]"
AMA_CI_REQUIRE_BACKENDS=1 coverage run --source=ama_cryptography -m pytest tests/
coverage report --precision=2
```

**Environment:**

- Python 3.11, Linux x86-64
- Native backends: `DILITHIUM_AVAILABLE=True`, `KYBER_AVAILABLE=True`,
  `SPHINCS_AVAILABLE=True`, `_ED25519_NATIVE_AVAILABLE=True`,
  `_AES_GCM_NATIVE_AVAILABLE=True`
- `AMA_CI_REQUIRE_BACKENDS=1` set; all backends verified present before pytest.
- Test suite: **1,945 passed, 11 skipped** in ~71 s.

All skips verified to be environmental (live TSA, cross-library differential
checks, Cython bindings not built, SoftHSM2 absent, `math_engine` Cython ext not
built). No skips mask missing backends.

## Why `coverage run`, not `pytest --cov`

`pytest-cov` installs its tracer in `pytest_configure`, which runs *after*
conftest imports `ama_cryptography`. That module performs non-trivial
import-time work that must be traced:

- `pqc_backends.py`: `ctypes` signature setup, `_find_native_library()`
  discovery, module-level class/enum construction.
- `_self_test.py`: FIPS 140-3 POST runs at import.
- `secure_memory.py`: backend-cascade selection runs at import.

`coverage run -m pytest` starts the tracer before any Python import, so these
import-time statements register correctly.

## Overall

| Metric | Value |
|---|---|
| Statements | 5,355 |
| Missed | 774 |
| **Overall coverage** | **85.55 %** |

## Per-module coverage (19 modules)

| Module | Stmts | Miss | Cover | Notes |
|---|---:|---:|---:|---|
| `__init__.py` | 26 | 0 | **100.00 %** | — |
| `__main__.py` | 1 | 1 | **0.00 %** | Entry point; only executed by `python -m ama_cryptography`. |
| `_finalizer_health.py` | 32 | 2 | **93.75 %** | `record_finalizer_error` interpreter-shutdown log path. |
| `_numeric.py` | 563 | 32 | **94.32 %** | NumPy-absent numerical fallbacks — mostly unreachable arms. |
| `_self_test.py` | 307 | 60 | **80.46 %** | POST failure branches, power-up-test timing edge cases, self-test rerun guards. |
| `adaptive_posture.py` | 320 | 43 | **86.56 %** | Lyapunov-instability branch, classify de-escalation path, history trimming, `__del__` / observer-disable paths. |
| `crypto_api.py` | 752 | 233 | **69.02 %** | Largest absolute gap (233 lines). Nonce-counter persist corruption handling (1029–1115), `create_crypto_package` SPHINCS/Kyber add-on branches, `verify_crypto_package` error catches, `AmaCryptography.sign/verify` error paths, hybrid KEM sign/verify edges, key-agreement / fork-detection branches (2173–2455). |
| `double_helix_engine.py` | 258 | 8 | **96.90 %** | Residual fallbacks when numpy unavailable. |
| `equations.py` | 125 | 11 | **91.20 %** | Validator error branches for malformed pillars. |
| `exceptions.py` | 21 | 0 | **100.00 %** | — |
| `hybrid_combiner.py` | 105 | 2 | **98.10 %** | Empty-input guards. |
| `integrity.py` | 21 | 0 | **100.00 %** | — |
| `key_management.py` | 484 | 26 | **94.63 %** | Export / persistence error paths; rotation edge cases. |
| `legacy_compat.py` | 509 | 41 | **91.94 %** | Legacy-API error messages, fd-leak fallbacks in `load_keys` / `save_keys`. |
| `pqc_backends.py` | 993 | 199 | **79.96 %** | 2nd-largest gap. Input validation rejection branches across Kyber/Dilithium/SPHINCS+ providers (349–1061), context-API error paths (904–1060), AES-GCM streaming edge cases, Argon2id parameter rejection, secp256k1 / X25519 / FROST error paths. |
| `rfc3161_timestamp.py` | 157 | 11 | **92.99 %** | Network error paths, malformed token branches. |
| `secure_channel.py` | 274 | 7 | **97.45 %** | Handshake-error paths. |
| `secure_memory.py` | 264 | 97 | **63.26 %** | Largest **percentage** gap. Module picks a single backend at import; other-backend arms (POSIX `mlock`/`munlock`, darwin `memset_s`, Python multi-pass memzero fallback, pure-Python constant-time compare) are dead code once native selection wins. `_detect_mlock_available` probe paths also unreachable. |
| `session.py` | 143 | 1 | **99.30 %** | Single cleanup-error branch. |
| **TOTAL** | **5,355** | **774** | **85.55 %** | — |

## Observations

1. **Three modules account for ~68 % of missed lines**: `crypto_api.py` (233),
   `pqc_backends.py` (199), `secure_memory.py` (97). Work here has the highest
   leverage.
2. **`secure_memory.py` is structurally capped on a single CI runner.** The
   module selects a single backend at import and renders the others unreachable.
   Genuine raises to ~85 % are feasible; above that requires either
   `importlib.reload` with mocked environment probes or multi-platform CI —
   both of which are out-of-scope for this effort and would risk violating the
   prohibition on reaching into private module state.
3. **`__main__.py` is a one-statement entry point** (`main()`). A subprocess
   smoke test hitting `python -m ama_cryptography` covers it at 100 % without
   introducing new dependencies.
4. **`_self_test.py` POST-failure paths** require injecting a simulated
   primitive failure; this can be done cleanly by patching the specific
   primitive the test targets (e.g. `ama_cryptography._self_test._HASH_FN`)
   rather than reaching into `_SELF_TEST_RESULTS`.
5. **`pqc_backends.py` gaps are overwhelmingly input-validation branches**
   (wrong key length, nonce length, message length, parameter range). These
   are the exact error paths INVARIANT-5 documents; they are public-API
   testable with simple value inputs.
6. **`crypto_api.py` gaps split three ways:**
   - AES-GCM counter persistence corruption / lock-failure branches
     (1029–1115). Testable end-to-end via a temp dir and corrupting the
     counter file.
   - `create_crypto_package` / `verify_crypto_package` optional add-on and
     error-catch branches (2173–2455). Testable by constructing packages with
     SPHINCS / Kyber enabled and by mutating the package to force verify
     failures.
   - Algorithm-dispatch and keypair-validation branches (179–625). Testable
     via explicit `AlgorithmType` selection and malformed keypair arguments.

## Skipped test audit

| File | Skip count | Reason | Action |
|---|---:|---|---|
| `test_crypto_import_paths.py` | 1 | Live TSA integration test | Keep; correct. |
| `test_differential.py` | 2 | Requires `pycryptodome` / `pynacl` (INVARIANT-1 would forbid as hard deps) | Keep; correct. |
| `test_ed25519_batch_verify_cython.py` | 4 | Cython `ed25519_binding` not compiled | Keep; correct. |
| `test_hsm_integration.py` | 1 | SoftHSM2 not installed | Keep; correct. |
| `test_smoke_import.py` | 3 | `math_engine` Cython extension not built | Keep; correct. |

All skips use `pytest.skip(reason=...)` or `pytest.mark.skipif(..., reason=...)`
and conform to INVARIANT-3.

## Inventory

- **63** `test_*.py` files in `tests/` (task description said "currently 62";
  counted at baseline).
- **19** Python modules in `ama_cryptography/` (matches task description).

---

*This document is a measurement snapshot. The plan for change lives in
`COVERAGE_PLAN.md`; the final before/after comparison will live in a separate
final report at the end of this effort.*
