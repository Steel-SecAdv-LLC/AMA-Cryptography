# Audit and Update Directive — PR #376

**Version:** 1.0
**Organization:** Steel Security Advisors LLC
**Applies to:** [Steel-SecAdv-LLC/AMA-Cryptography#376](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/pull/376)
**Head branch:** `steel/autonomous-boundcont-vu2lxv`
**Base branch:** `main`

This directive assigns a comprehensive audit and update of the AMA Cryptography
repository. It is written to be executed directly by an engineer or by an
autonomous assistant with repository write access.

---

## 1. Scope and Authority

**Repository and PR.** All work continues on PR #376. No other pull request is
in scope.

**Branch policy.** Do not create branches. Take control of the PR head branch
`steel/autonomous-boundcont-vu2lxv` and push all approved changes directly to
it. Work that lands anywhere else is out of scope and will be discarded.

**Decision authority.** You are authorized to modify code, tests, CI workflows,
documentation, and build scripts as required to satisfy the acceptance criteria
in Section 5.

**Quality standard.** Every change must be correct, verifiable, secure,
performant, and maintainable. Changes that mask a symptom without resolving its
root cause do not satisfy this directive.

---

## 2. Constraints and Non-Negotiables

1. No new branches. All work is pushed to the PR head branch.
2. No bypassing, relaxing, or weakening of a security or correctness property to
   make a test pass. If a test and an implementation disagree, determine which
   is wrong and fix that one on the merits.
3. Every finding is either resolved in this PR or tracked as an issue carrying
   reproduction steps, a risk assessment, and a remediation plan. Critical
   findings are resolved, not tracked.
4. Every fix ships with automated verification — a test, a CI gate, or both —
   sufficient to fail on regression.
5. Portability is preserved. Platform-specific code paths are permitted only
   behind runtime dispatch with a portable C fallback that produces identical
   output.
6. INVARIANT-1 holds: no third-party cryptographic code and no new cryptographic
   primitives. Introducing a primitive is a separate, explicitly approved
   decision (see Section 5, *Preserve and evolve primitives*).

---

## 3. Repository Baseline

The following infrastructure is present. Extend it; do not duplicate it. Any
task below that reads as "add X" means "add the missing coverage to the existing
X" wherever an X already exists.

| Area | Existing assets |
|---|---|
| AEAD and symmetric | `src/c/ama_aes_gcm.c`, `ama_aes_bitsliced.c`, `ama_chacha20poly1305.c`, `ama_argon2.c` |
| Post-quantum | `src/c/ama_kyber.c` (ML-KEM-1024), `ama_dilithium.c` (ML-DSA-65), `ama_slhdsa.c` (SLH-DSA) |
| Classical asymmetric | `src/c/ama_ed25519.c`, `ama_x25519.c`, `ama_secp256k1.c`, `ama_frost.c` |
| Hashing and KDF | `src/c/ama_sha256.c`, `ama_sha256_ni.c`, `ama_sha3.c`, `ama_hmac_sha256.c`, `ama_hmac_sha384.c`, `ama_hkdf.c` |
| Constant-time support | `src/c/ama_consttime.c`, `CONSTANT_TIME_VERIFICATION.md`, `tools/run_dudect.sh`, `.github/workflows/dudect.yml`, `constant-time-check` job |
| SIMD kernels | `src/c/avx2/`, `src/c/avx512/`, `src/c/neon/`, `src/c/sve2/`, dispatch in `src/c/dispatch/` |
| Fuzzing | 15 targets in `fuzz/`, `fuzz/dictionaries/`, `fuzz/seed_corpus/`, `.github/workflows/fuzzing.yml`, `oss-fuzz/`, `validate-fuzz-dictionaries` gate job |
| Property tests | `tests/test_property_based_crypto.py`, `tests/test_property_based_lyapunov.py`, `hypothesis` in `requirements-dev.txt` |
| Vectors and interop | `nist_vectors/` (+ `run_vectors.py`), `wycheproof_vectors/` (+ `run_wycheproof.py`, `manifest.json`), `tests/kat/{fips203,fips204,fips205,ml_kem,ml_dsa}`, `.github/workflows/acvp_validation.yml` |
| Benchmarks | `benchmarks/` (suite, runner, `baseline.json`, `arm-baseline.json`, `comparative_benchmark.py`, `performance_comparison.py`), `benchmark-regression` job, `.github/workflows/arm-qemu.yml` |
| Quality checklists | `CRYPTO_REVIEW_CHECKLIST.md`, `CSRC_STANDARDS.md`, `INVARIANTS.md`, `tools/check_*.py` |
| CI aggregation | `ci-gate` in `.github/workflows/ci.yml` — the single required status context; per-workflow gates in `ci-build-test.yml` and `static-analysis.yml` |

### 3.1 Primitive Scope Correction

The source instruction set targeted **Ascon** for the security review,
interoperability, and cross-project comparison tasks. **Ascon is not implemented
in this repository** — it appears in no source, test, header, or document.

Those tasks are therefore retargeted to the AEAD primitives that ship:
**AES-256-GCM** and **ChaCha20-Poly1305**, with the associated-data,
nonce-handling, and tag-verification paths of each. All acceptance criteria
below reflect that retarget. The cross-project comparison becomes AES-256-GCM
vs. ChaCha20-Poly1305 vs. external reference implementations.

This retarget introduces no primitive, so INVARIANT-1 remains intact.

Ascon is out of scope for this directive. Auditing a primitive the repository
does not implement resolves to *implementing* it first — native C
implementation, known-answer vectors, constant-time proof, fuzz target, and
dispatch coverage. That is new-primitive work, which INVARIANT-1 prohibits
absent explicit approval and which the *Preserve and evolve primitives* rule in
Section 5 admits only on demonstrated merit over an incumbent. Adopting Ascon is
therefore a separate scoped decision requiring its own decision log — not a
finding of this audit. Do not add it under this directive.

---

## 4. Deliverables

1. An audit report covering security, correctness, performance,
   interoperability, and API ergonomics.
2. Code changes on the PR head branch implementing fixes, tests, and
   optimizations.
3. CI updates running unit tests, property tests, fuzzing, and interop checks
   under pass/fail gating.
4. A canonical test-vectors file with automated verification.
5. Benchmark results and profiling notes for the targeted platforms.
6. Documentation updated to the standard in Section 5.
7. Definitive algorithm and bindings matrices committed to the repository.

---

## 5. Tasks and Acceptance Criteria

| Task | Objective | Acceptance Criteria |
|---|---|---|
| **Security review** | Verify constant-time behavior and side-channel resistance across AES-256-GCM, ChaCha20-Poly1305, and the asymmetric and PQC primitives | Audit notes recorded in-repo; every primitive handling secret material carries a dudect measurement meeting the `\|t\| < 4.5` gate; any primitive lacking a measurement gains one; identified leaks fixed or mitigated with the mitigation documented |
| **Interoperability testing** | Validate cross-implementation compatibility using official and extended vectors | Interop harness committed; each AEAD and PQC family validates against at least two independent reference implementations or authoritative vector sets; harness runs in CI |
| **Fuzzing** | Find input-handling defects in encryption, decryption, and associated-data paths | Every public AEAD entry point — including AD and tag-verification paths — has a target under `fuzz/`; targets registered in `fuzzing.yml` and `oss-fuzz/`; no unresolved crash, leak, or UB under ASan+UBSan; every finding triaged with disposition recorded |
| **Property tests** | Establish invariants: round-trip, tag forgery rejection, nonce-misuse detection | Property tests added to the existing `hypothesis` suite covering round-trip fidelity, rejection of any tampered ciphertext/tag/AD, and nonce-reuse detection; executed by CI; failures fixed, or documented with an implemented mitigation |
| **Test vectors** | Publish canonical vectors and verify implementations against them | Dedicated canonical vectors file committed; automated verification test wired into CI that fails the build on any mismatch; vector provenance cited |
| **CI enhancements** | Gate merges on tests, fuzzing, and interop checks | New jobs added to the appropriate workflow and listed in that workflow's aggregating gate `needs:`; gate resolves definitively red or green; branch protection requires the gate contexts |
| **Performance benchmarks** | Measure throughput and latency on x86-64, ARMv8, and embedded targets | Benchmark coverage in `benchmarks/` for each targeted platform; results published in-repo with reproducible invocation scripts; C-core-only targets (for example Cortex-M, which does not host the CPython layer) benchmarked through the C harness and labeled as such |
| **Platform profiling** | Identify hot paths and optimization opportunities | Profiling report committed; prioritized optimization list with a measured baseline per entry |
| **Platform optimizations** | Add conditional kernels using intrinsics or assembly | Kernels added behind runtime dispatch and feature flags, each with a portable C fallback; differential tests prove byte-identical output between every kernel and the fallback; correctness tests pass on all targeted platforms |
| **Implementation quality checklist** | Enforce constant-time patterns, memory safety, and secure error handling | `CRYPTO_REVIEW_CHECKLIST.md` extended to cover these categories; every mechanically checkable item enforced by a `tools/check_*.py` script wired into CI |
| **Algorithm inventory** | Document supported algorithms and primitives definitively | `CSRC_STANDARDS.md` designated the canonical inventory and confirmed to list every shipping primitive with its standard, parameter set, and source; a CI check fails when a shipping primitive is absent from the inventory |
| **Language and bindings matrix** | Map existing bindings and gaps across ecosystems | Matrix file committed covering the C ABI, `pkg-config` integration, and the Python ctypes/Cython surface; gaps enumerated and target bindings prioritized |
| **Multi-language bindings and TLS integration** | Provide a mainstream binding and TLS usage examples | At least one mainstream-language binding implemented and tested; TLS integration example committed under `examples/` and exercised by CI |
| **Documentation standards** | Standardize headers and usage examples across modules | Documentation template committed; required header fields defined; every module updated under this directive carries the header and a working usage example |
| **API ergonomics** | Make APIs secure-by-default for nonce and key handling | API changes or wrappers implemented so that the default path cannot silently reuse a nonce or accept a mis-sized key; migration notes and examples committed; backwards compatibility preserved or the break documented in `CHANGELOG.md` |
| **Cross-project comparison** | Compare AES-256-GCM vs. ChaCha20-Poly1305 vs. external reference implementations | Comparative tests and a resource/performance summary committed covering both shipping AEADs against each other and against external references, extending `benchmarks/comparative_benchmark.py`; methodology and hardware recorded alongside results |
| **Release and changelog policy** | Define release rules and changelog format | Release policy and changelog template committed, specifying how security fixes and API changes are recorded and versioned; consistent with the existing release-safety invariants |
| **Preserve and evolve primitives** | Maintain current primitives; replace only on demonstrated merit | Decision log committed for any primitive addition, replacement, or removal, recording the compatibility impact, security rationale, and measured evidence supporting the change |

---

## 6. Execution Guidance

**Start from a reproducing test.** For each finding, commit a test that fails
against current behavior before committing the fix. The failing test is the
evidence the finding is real.

**Automate every verification.** A fix without a test or CI check that fails on
regression is incomplete.

**Document each non-trivial decision.** Record a short rationale and the test
evidence in the PR discussion or the relevant in-repo document.

**Measure performance claims.** Every performance change carries before/after
benchmarks produced by the committed scripts, plus the profiling artifact that
motivated it.

**Keep commits atomic.** Prefer small, reviewable commits, each with a single
clear purpose and its accompanying tests.

**Track what remains.** Any finding not fully resolved in this PR becomes a
tracked issue with reproduction steps, risk assessment, and remediation plan.

---

## 7. Definition of Done

- Every task in Section 5 meets its acceptance criteria, or has a tracked issue
  meeting the Section 6 standard.
- The audit report is committed.
- All CI gates pass on the PR head commit.
- No unresolved critical finding remains.
- All work is present on `steel/autonomous-boundcont-vu2lxv`.

---

Copyright (C) 2025-2026 Steel Security Advisors LLC
