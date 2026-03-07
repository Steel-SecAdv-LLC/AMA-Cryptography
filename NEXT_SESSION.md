# Next Session: Remaining Issues & Polish Roadmap

**Prepared:** 2026-03-07
**For:** Steel Security Advisors LLC
**Status:** Post-CI stabilization (64/64 checks passing)

---

## Priority 1: Security Hardening

### 1.1 AES S-box — Cache-Timing Side Channel

**File:** `src/c/ama_aes_gcm.c:44`
**Issue:** The file header claims "T-table free, bitsliced S-box," but the implementation uses a standard 256-byte lookup table (`aes_sbox[256]`). Table-based AES is vulnerable to cache-timing attacks (Bernstein 2005, Osvik et al. 2006).

**Fix options (pick one):**
- **Bitsliced AES** — Implement a true bitsliced S-box (Koenig & Lackey). Constant-time by construction.
- **AES-NI intrinsics** — Use hardware AES instructions where available (`_mm_aesenc_si128`), with bitsliced fallback on non-x86.
- **Honest documentation** — If the S-box lookup is intentional (e.g., performance tradeoff), remove the "bitsliced" claim from the header and document the tradeoff in `SECURITY_ANALYSIS.md`.

### 1.2 Ed25519 Base Point Initialization — Thread Safety

**File:** `src/c/ama_ed25519.c:552, 800`
**Issue:** `B_initialized` and `ge_base_table_ready` use `volatile int` with check-then-set pattern. This is a TOCTOU race — two threads can both see `0`, both compute, and one can read a partially-written `B`.

**Fix:**
- Use C11 `_Atomic int` with `atomic_load`/`atomic_store` and `atomic_thread_fence(memory_order_release)`.
- Or use `pthread_once` for one-time initialization.
- The comment at line 572 acknowledges this ("On x86 this is implicit") but the code must be correct on ARM/RISC-V too.

### 1.3 Ed25519 Field Arithmetic Performance

**File:** `src/c/ama_ed25519.c`
**Issue:** Per the CHANGELOG, Ed25519 sign in C (8,131 ops/sec) is slower than Python/OpenSSL (10,453 ops/sec). The field arithmetic needs optimization.

**Fix:**
- Implement radix-2^51 representation (like ref10/donna).
- Add platform-specific 128-bit multiplication where available.
- Benchmark after fix to confirm C is faster than Python.

---

## Priority 2: Documentation Overhaul

### 2.1 README.md Refresh

- Update implementation status matrix to reflect current state (all C primitives implemented).
- Add clear "Security Caveats" section listing known limitations (S-box, thread safety).
- Verify all badge links are current and accurate.
- Update performance comparison table with latest benchmark numbers.
- Simplify the quick-start instructions.

### 2.2 CHANGELOG.md Cleanup

- The `[Unreleased]` section is massive and reads like a development log. Consolidate it.
- There are two `[2.0.0]` headers (lines 20 and 223) — merge or restructure.
- Add a proper `[2.1.0]` (or `[3.0.0]`) section for the C native library work.

### 2.3 Stale/Redundant Documentation

Review and consolidate these files — some may overlap or be outdated:
- `SECURITY_ANALYSIS.md` vs `SECURITY_COMPARISON.md` vs `SECURITY.md` — three security docs.
- `BENCHMARKS.md` vs `BENCHMARK_RESULTS.md` — two benchmark docs.
- `ENHANCED_FEATURES.md` — verify it reflects current features.
- `CRYPTOGRAPHY.md` vs `ARCHITECTURE.md` — check for overlap.

### 2.4 Sphinx/Doxygen Docs

- `docs/` has `Doxyfile`, `conf.py`, `index.rst`. Verify they build cleanly.
- Add API reference generation from C header docstrings.
- Ensure Python API docstrings are complete and Sphinx-compatible.

### 2.5 Copyright/Date Audit

- Some files reference 2025, some 2026. Normalize copyright headers.
- Ensure all `Last Updated` fields in doc headers are current.

---

## Priority 3: Repo Polish

### 3.1 CI/Build Cleanup

- Review the CI churn that occurred during stabilization (black version mismatch, MSVC flags, test assertion mismatches). Add guardrails:
  - Pin `black` version in `requirements-dev.txt` and CI.
  - Add a CI step that verifies formatting matches before running tests.
- Ensure benchmark-regression CI job is stable and not flaky.

### 3.2 Test Coverage Gaps

- Ed25519 C verify roundtrip is currently skipped (`test_ed25519.c` — "pending field arithmetic fixes"). Un-skip after 1.3 is done.
- Add fuzz testing for C crypto primitives (AFL/libFuzzer).
- Add property-based tests for Python API (Hypothesis).

### 3.3 pyproject.toml / Package Metadata

- Verify classifiers, URLs, and description are current.
- Ensure `pip install ama-cryptography` instructions work end-to-end.
- Check that Cython build doesn't break on clean install.

### 3.4 Pre-commit Hooks

- Verify all pre-commit hooks are current and functioning.
- Consider adding `clang-format` for C code consistency.

---

## Priority 4: Future Considerations (Not Blocking)

| Item | Notes |
|------|-------|
| Formal security audit | Engage third-party firm for production validation |
| Fuzzing campaign | AFL++ / libFuzzer on all C primitives |
| FIPS 140-3 module boundary | If FIPS certification is a goal, define the module boundary now |
| PyPI publication | Package and publish once audit-ready |
| ARM/RISC-V testing | Thread safety fix (1.2) needs validation on weak memory models |

---

## Session Checklist

Use this as your task list for the next PR run:

- [ ] Fix AES S-box (bitslice or document the tradeoff)
- [ ] Fix Ed25519 thread safety (C11 atomics or pthread_once)
- [ ] Optimize Ed25519 field arithmetic
- [ ] Un-skip Ed25519 verify roundtrip test
- [ ] Consolidate CHANGELOG.md (fix dual 2.0.0 headers)
- [ ] Merge/deduplicate security docs
- [ ] Merge/deduplicate benchmark docs
- [ ] Refresh README.md status matrix and caveats
- [ ] Audit all doc dates and copyright years
- [ ] Verify Sphinx/Doxygen builds
- [ ] Pin tool versions in CI
- [ ] Add clang-format for C code
- [ ] Final full CI run — all green

---

*Prepared by Claude (Opus 4.6) for the next engineering session.*
