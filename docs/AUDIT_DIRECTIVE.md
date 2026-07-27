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

Ascon is out of scope **for this directive** — which is a scheduling judgment,
not a rejection of Ascon. The two are worth separating explicitly, because the
first phrasing of this section read as the second.

**Why it is out of scope here.** Auditing a primitive the repository does not
implement resolves to *implementing* it first: native C permutation and modes,
known-answer vectors, a constant-time proof under the dudect gate, a fuzz
target, dispatch coverage, ABI additions, and a Python surface. That is
new-primitive work. INVARIANT-1 admits it only as an explicitly approved
decision, and the *Preserve and evolve primitives* rule requires a decision log
with measured evidence. Landing it inside an audit PR whose stated purpose is
removing theatre and closing findings would dilute both efforts and put a fresh
several-thousand-line primitive into a change set reviewers are reading for
regressions.

**Why it is nonetheless recommended, as its own scoped work.** Ascon is not a
speculative candidate. NIST published **SP 800-232**, *Ascon-Based Lightweight
Cryptography Standards for Constrained Devices*, as a final standard on
2025-08-13, specifying **Ascon-AEAD128**, **Ascon-Hash256**, **Ascon-XOF128**,
and **Ascon-CXOF128**. Four points make it a good fit for this library
specifically:

1. **It matches what this project already is.** AMA Cryptography's identity is
   native implementations of NIST standards — FIPS 202/203/204/205, SP 800-56C,
   SP 800-90A. Ascon is the only NIST-standardized lightweight AEAD. It belongs
   in `CSRC_STANDARDS.md` on exactly the same footing as the rest.
2. **It closes a real gap, and one this directive already trips over.** §5.2
   commits to Cortex-M as a benchmark tier while the library ships only
   AES-256-GCM and ChaCha20-Poly1305 — both designed for application
   processors. Ascon's 320-bit permutation, absence of lookup tables, and small
   code/RAM footprint are aimed precisely at that class of device. Adopting it
   resolves the inconsistency between the platforms claimed and the primitives
   offered.
3. **Its side-channel story is strong by construction.** No S-box tables, no
   data-dependent memory access, naturally bitsliceable — so it starts where
   `ama_aes_bitsliced.c` had to be engineered to arrive, and should clear the
   `|t| < 4.5` dudect gate without special handling.
4. **The engineering model is already in the repository.** Ascon is a
   sponge over a round-based permutation; `ama_sha3.c` is the same shape. The
   code is not shared and must not be, but the review patterns, KAT harness,
   and dispatch scaffolding transfer directly.

**What it is not.** Ascon does not replace anything. On x86-64 with AES-NI or
ARMv8 with crypto extensions it will lose to AES-256-GCM, and it will usually
lose to ChaCha20-Poly1305 in pure software on 64-bit machines. No mainstream
TLS deployment negotiates it. It is *additive* coverage for constrained
targets, and the decision log must record it as such rather than as a
performance or interoperability win.

**Disposition.** Recommended for adoption as a separate PR against a v3.5.0
milestone, carrying its own decision log per the *Preserve and evolve
primitives* rule, with Ascon-AEAD128 and Ascon-Hash256 as the minimum viable
scope and the XOF variants following. Do not add it under this directive.

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
| **CI enhancements** | Gate merges on tests, fuzzing, and interop checks | See §5.1 — every criterion for this row is stated there |
| **Performance benchmarks** | Measure throughput and latency on x86-64, ARMv8, and embedded targets | See §5.2 — every criterion for this row is stated there |
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

### 5.1 CI Enhancements — What "Gated" Means Here

A job that runs is not a job that gates. Branch protection on this repository
requires each workflow's **aggregating gate context** (`ci-gate`,
`static-analysis-gate`, `fuzzing-gate`, …) rather than the individual job
names. That is deliberate: it keeps the required-context list inside the
repository, under code review, instead of in the branch-protection UI where it
drifts silently as jobs are added and renamed (*required-context drift*).

The design has one failure mode, and it points the wrong way. A job omitted
from its gate's `needs:` **still runs and still shows a red X on the pull
request — and still cannot block the merge**, because branch protection never
evaluates its context. The pull request displays a failing check beside a green
required gate, and "all required checks passed" is true.

That was live in this repository, not hypothetical. `c-library-no-native-pqc`
in `ci-build-test.yml` guards the `AMA_USE_NATIVE_PQC=OFF` build — the
configuration used by consumers who take the library without native
post-quantum support. It was absent from `ci-gate`'s `needs:` while commit
`f3dd0c2` on this branch had to repair that exact configuration after it broke
undetected. The guard existed, ran, and gated nothing.

A CI change satisfies this row when all four hold:

1. The new job is defined in the workflow whose gate should own it. `needs:` is
   workflow-local; a job in `ci.yml` cannot be gated by `static-analysis.yml`.
2. The job id appears in that workflow's gate `needs:` list.
3. The gate carries a job-level `if: always()`. Without it the gate reports
   `skipped` when a dependency fails, and a required context that reports
   `skipped` never resolves — the pull request waits indefinitely on "Expected
   — waiting for status" instead of going red. A gate that cannot report red
   is not a gate.
4. Branch protection requires the gate context.

Items 1–3 are **no longer a matter of reviewer diligence**:
`tools/check_gate_coverage.py` (INVARIANT-31) enforces them mechanically and
fails the pull request that omits a job, drops `if: always()`, or adds a
multi-job pull-request workflow with no gate at all. Single-job workflows and
workflows that never trigger on `pull_request` are exempt by construction — the
first is its own status context, the second produces no context branch
protection could require. Item 4 is a repository setting and remains an
operator action.

### 5.2 Performance Benchmarks — Platform Tiers

"Embedded targets" in the objective column is not one tier, and conflating them
produced an unachievable criterion. Split them:

| Tier | Targets | Harness | Status |
|---|---|---|---|
| **Full stack** | x86-64, ARMv8/aarch64 | Python `benchmarks/` suite over the native library | Required. ARMv8 runs under `arm-qemu.yml`; `benchmarks/arm-baseline.json` is the recorded baseline |
| **C core only** | Cortex-M and any target without CPython | C harness against the static library | Required *as a C-core measurement*, explicitly labeled |

The distinction is a hard constraint, not a preference: **this library's Python
layer cannot run on Cortex-M.** There is no CPython on a microcontroller of
that class, so `benchmarks/` — which imports `ama_cryptography` — cannot
produce a number there at any effort level. Demanding "benchmark the Python
suite on Cortex-M" is demanding something impossible, and a criterion that
cannot be met is worse than no criterion: it either gets quietly dropped or
gets satisfied with a fabricated figure.

What is genuinely achievable, and therefore what this row requires:

- x86-64 and ARMv8 measured through the existing `benchmarks/` suite, with the
  recorded baselines and the `benchmark-regression` gate unchanged.
- Cortex-M measured through the **C harness only**, against the static library
  built for the target, reporting cycle counts and code/RAM footprint rather
  than Python-level throughput.
- Every published Cortex-M figure labeled **"C core only — no Python layer"**
  at the point of publication, so a reader cannot mistake it for a measurement
  of the shipped Python API.
- The invocation script for each tier committed, so every figure is
  reproducible from the repository.

A Cortex-M number that is absent is acceptable and must be stated as absent. A
Cortex-M number presented as if the full stack produced it is not.

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
