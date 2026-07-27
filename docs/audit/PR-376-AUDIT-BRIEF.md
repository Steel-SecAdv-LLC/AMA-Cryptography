# Engineering Brief — Audit and Update, PR #376

## Document Information

| Property | Value |
|----------|-------|
| Applies to | https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/pull/376 |
| PR head branch | `steel/autonomous-boundcont-vu2lxv` |
| PR base branch | `main` |
| Classification | Internal — engineering handoff |
| Maintainer | Steel Security Advisors LLC |

---

## 1. Purpose

This brief hands over execution of a comprehensive audit and update of the
AMA Cryptography repository to an engineer or coding assistant. It is written
to be executed directly: every task names its objective, the concrete actions
required, and the acceptance criteria that close it. Acceptance is decided by
committed evidence, not by assertion.

Read Section 2 before starting any task. It contains binding corrections to
the task register that determine whether several tasks are executable at all.

---

## 2. Binding premise corrections

These are established facts about the repository as it stands. They override
any conflicting instruction elsewhere in this brief or in its source draft.

### 2.1 Ascon is not implemented in this repository

A full-tree search returns no reference to Ascon in source, headers, build
files, tests, workflows, or documentation. The AEAD constructions actually
shipped are **AES-256-GCM** (`src/c/ama_aes_bitsliced.c`, plus AES-NI/VAES,
NEON and SVE2 kernels) and **ChaCha20-Poly1305** (`src/c/ama_chacha20poly1305.c`,
plus AVX2, NEON and SVE2 kernels).

Consequently:

- Every task phrased against Ascon is redirected to the shipping AEAD set and
  the wider primitive inventory. The security, interoperability, fuzzing and
  comparison objectives are preserved verbatim; only the target changes.
- Adding Ascon is **not** in scope as a side effect of this work. `INVARIANT-1`
  prohibits introducing new cryptographic primitives without governance
  sign-off. If Ascon adoption is desired, run the decision gate in
  **Appendix A** first and land it as its own change with its own review.

### 2.2 PR #376 already has a delivered subject

PR #376 is *Agent-instance key/signature binding (INVARIANT-30), 3R
agentic-abuse detectors, and security-tooling remediation*: 47 files,
+7,162 / −55, 8 commits. It is open, not a draft, and every check run on its
head commit is `success` or `skipped`. `mergeable_state` is `blocked`, which
reflects branch-protection review requirements rather than a failing gate.

Consequently:

- Confirm the current head SHA and check-run state before assuming any gate is
  red. Do not "fix" a gate that is passing.
- The repository's own standard requires small, atomic, individually reviewable
  changes. A repository-wide audit landed wholesale onto this PR head conflicts
  with that standard and with the PR's stated scope.
- **Default rule:** work that verifies, tests, documents or hardens what #376
  already touches lands on the PR head branch. Work that changes subsystems
  #376 does not touch — new bindings, new kernels, new comparison suites — is
  prepared as separately reviewable commits and requires the repository owner's
  explicit go-ahead before being pushed to this PR head. Section 5 marks each
  task accordingly.

### 2.3 Most infrastructure named in the task register already exists

The repository already carries fuzzing, constant-time measurement, ACVP
validation, a vendored Wycheproof corpus with provenance gating, ARM QEMU
testing, benchmark regression detection, and a cryptographic review checklist —
all wired into CI as blocking gates. Section 4 is the authoritative baseline.

Tasks that read "add X" are therefore to be executed as **"verify, extend and
close the gaps in the existing X at the named path."** Creating a parallel
second implementation of an existing capability is a defect, not a deliverable.

---

## 3. Scope, authority and standard

**Repository.** `Steel-SecAdv-LLC/AMA-Cryptography`.

**Branch policy.** Do not create new branches. Take control of the PR head
branch `steel/autonomous-boundcont-vu2lxv` and push approved changes directly
to it, subject to the scope boundary in §2.2.

**Decision authority.** You are authorized to modify source, tests, CI
workflows, build scripts and documentation as required to satisfy the
acceptance criteria in Section 5.

**Quality standard.** Changes must be correct, verifiable, secure, performant
and maintainable. A change that suppresses a symptom without resolving its
cause does not satisfy any acceptance criterion in this brief.

---

## 4. Repository baseline

Establish current state against this table before proposing any change. Each
row names what exists and where its enforcement lives.

| Capability | Implementation | Enforcement |
|---|---|---|
| Fuzzing | `fuzz/` — targets for AES-GCM, ChaCha20-Poly1305, Ed25519, X25519, secp256k1, ML-KEM, ML-DSA, SLH-DSA, FROST, HKDF, SHA-3, Argon2, constant-time helpers; `fuzz/dictionaries/`, `fuzz/seed_corpus/` | `.github/workflows/fuzzing.yml` — jobs `fuzz-core`, `fuzz-pqc`, `fuzz-consttime-aes`, `validate-fuzz-dictionaries` (fail-closed), `fuzzing-gate`; OSS-Fuzz under `oss-fuzz/`, `tools/test_oss_fuzz_build.sh` |
| Constant-time verification | `src/c/ama_consttime.c`, `tools/constant_time/` (dudect harness), `tools/run_dudect.sh` | `.github/workflows/dudect.yml`; `constant-time-check` job in `ci.yml`; documented in `CONSTANT_TIME_VERIFICATION.md`, `docs/constant-time-testing.md` |
| Known-answer vectors | `tests/kat/fips203`, `tests/kat/fips204`, `tests/kat/fips205`, `tests/kat/ml_kem`, `tests/kat/ml_dsa`, `nist_vectors/` | `tests/test_nist_kat.py`; `.github/workflows/acvp_validation.yml`; attestation in `docs/compliance/` |
| Third-party vector corpus | `wycheproof_vectors/` — vendored, pinned by `manifest.json` (upstream commit, per-file SHA-256, per-file vector count), verified before execution, nothing fetched at test time | `ci.yml` (fail-closed); `.github/workflows/corpus-provenance.yml`; refreshed via `tools/refresh_wycheproof_corpus.py` |
| Static analysis | `.clang-tidy`, `.semgrep.yml`, `.github/codeql/`, `tools/check_suppression_hygiene.py` | `.github/workflows/static-analysis.yml` — cppcheck, MemorySanitizer, ThreadSanitizer, Valgrind; `.github/workflows/security.yml`; `Static Analysis Gate` |
| Benchmarks | `benchmarks/` — `benchmark_suite.py`, `performance_suite.py`, `benchmark_c_raw.c`, `phase0_baseline.py`, `comparative_benchmark.py`, `performance_comparison.py`; `baseline.json` (regression tolerance), `arm-baseline.json` | `benchmark-regression` job in `ci.yml`; `.github/workflows/arm-qemu.yml`; provenance policy in `benchmarks/README.md`; history in `docs/BENCHMARK_HISTORY.md` |
| Review controls | `CRYPTO_REVIEW_CHECKLIST.md`, `INVARIANTS.md`, `THREAT_MODEL.md`, `SECURITY.md`, `CSRC_STANDARDS.md` | `.github/PULL_REQUEST_TEMPLATE.md`; `tools/check_workflow_commands.py`; `CI Gate` aggregation job in `ci.yml` |
| Algorithm-to-standard mapping | `CSRC_STANDARDS.md` — every shipping primitive mapped to its governing standard, parameter set and CSRC URL | `docs/compliance/CSRC_ALIGN_REPORT.md`, `docs/compliance/ACVP_SELF_ATTESTATION.md` |
| Release mechanics | `.github/workflows/release.yml`, `CHANGELOG.md` (Keep a Changelog + SemVer), signed wheels, SLSA provenance | `tools/check_version_consistency.py`; `tools/generate_sbom.py` |
| Language surfaces | C core `src/c/`; Python via ctypes and Cython `src/cython/*.pyx`; examples in `examples/c/` and `examples/python/` | `ci.yml` matrix — Python 3.10–3.13 on Linux, macOS, Windows; `Docker Build` |

**Confirmed gaps** — these are genuinely absent and are new work: a
language/bindings matrix, any non-Python binding, a TLS integration example, a
standalone release and changelog policy document, and a documentation header
template distinct from the license-header enforcement in `tools/check_headers.py`.

---

## 5. Task register

Each task states its objective, the required actions, and the acceptance
criteria that close it. **Scope** is `PR` (lands on the PR head branch) or
`Gated` (requires owner go-ahead per §2.2 before pushing to this PR head).

### T1 — Side-channel review of shipping AEAD and primitive set — *Scope: PR*

**Objective.** Establish and evidence constant-time behaviour for AES-256-GCM,
ChaCha20-Poly1305, and the primitives reachable from the PR's new code paths.

**Actions.**
1. Enumerate every secret-dependent branch, table lookup and memory access in
   the AEAD implementations and their SIMD variants, including the bitsliced
   AES fallback used where AES-NI is unavailable.
2. Extend the dudect harness in `tools/constant_time/` to cover any primitive
   or code path not already measured, rather than adding a second harness.
3. For each measured path, record the t-statistic, the execution count, and the
   pass threshold in effect.
4. Where a measurement fails or is inconclusive, fix the implementation or
   document the mitigation with its residual risk.

**Acceptance criteria.**
- Audit notes committed under `docs/audit/`, naming each primitive, each code
  path examined, and the verdict with its evidence.
- dudect coverage extended to every path identified as uncovered; results are
  reproducible from `tools/run_dudect.sh`.
- The constant-time gate remains blocking and passes on the head commit.
- Any implementation change carries a test that fails against the prior code.

### T2 — Cross-implementation interoperability — *Scope: PR*

**Objective.** Demonstrate that this library's outputs are accepted by, and
that it accepts outputs from, at least two independent implementations of each
shipping algorithm.

**Actions.**
1. Inventory current external-vector coverage: `tests/kat/`, `nist_vectors/`,
   `wycheproof_vectors/` (pinned by `manifest.json`).
2. Identify algorithms with no independent cross-check and extend the harness
   to cover them. Peer libraries belong in the `[benchmark]` extra in
   `pyproject.toml` and must not be imported by the core package at runtime —
   `INVARIANT-1` applies.
3. Cover both directions: vectors produced elsewhere and verified here, and
   vectors produced here and verified elsewhere.

**Acceptance criteria.**
- Interop harness committed with results for at least two independent
  implementations per algorithm covered.
- Any vector corpus added is vendored and pinned by digest with an upstream
  commit reference, matching the `wycheproof_vectors/manifest.json` pattern.
  No fetching at test time.
- The interop suite is wired into a blocking CI gate.

### T3 — Fuzzing coverage — *Scope: PR*

**Objective.** Close input-handling gaps in encryption, decryption and
associated-data paths.

**Actions.**
1. Audit each existing target in `fuzz/` for what it actually asserts.
   Targets that only assert absence of a crash are to be strengthened to assert
   security properties — a tampered tag never verifies, a refused operation
   writes no output, associated data is bound to the ciphertext.
2. Verify every dictionary parses and every seed corpus is reachable by the
   fuzzer; the `validate-fuzz-dictionaries` job exists precisely because a
   malformed line silently voids an entire dictionary.
3. Add targets for any input-accepting entry point not currently fuzzed.
4. Triage all findings to root cause. Add each reproducer to the seed corpus.

**Acceptance criteria.**
- No unresolved crash, leak, or undefined behaviour under ASan and UBSan.
- Every target asserts at least one security property beyond non-crashing.
- Execution counts per target recorded in the PR evidence.
- `fuzzing-gate` remains blocking.

### T4 — Property tests — *Scope: PR*

**Objective.** Encode invariants as executable properties.

**Actions.** Cover at minimum: encrypt/decrypt round-trip across message and
AD lengths including empty and boundary sizes; ciphertext or tag mutation
always fails authentication; associated-data mutation always fails
authentication; nonce misuse is detected or prevented at the API boundary; key
and nonce length validation; behaviour at length limits.

**Acceptance criteria.**
- Property tests committed and executed by CI.
- Every failure is fixed at root cause, or documented with its mitigation and
  residual risk in `THREAT_MODEL.md`.
- Generators are seeded reproducibly and failing cases are pinned as
  regression tests.

### T5 — Canonical test vectors — *Scope: PR*

**Objective.** Publish the canonical vectors that pin this library's wire
format and verify against them automatically.

**Actions.**
1. Publish a dedicated vectors file covering the constructions this library
   defines itself — including the 88-byte canonical binding record introduced
   by this PR, which is already pinned as a byte KAT in
   `tests/c/test_agent_binding.c`.
2. Verify every vector from both the C and Python surfaces.
3. State explicitly in the file header that a change to any vector re-keys
   deployed material.

**Acceptance criteria.**
- Vectors file committed with provenance for each vector.
- Automated verification fails CI on any mismatch.
- Both language surfaces are covered.

### T6 — CI gating — *Scope: PR*

**Objective.** Ensure every check added by this work blocks merge on failure.

**Actions.** Add each new job to the aggregating gate's `needs` list. Confirm
the gate fails when a dependency fails — an aggregation job that passes while a
dependency fails is a defect. Confirm no new check is `continue-on-error` or
soft-failing.

**Acceptance criteria.**
- Every new check is reachable from a blocking gate.
- Negative-path verification demonstrates the gate fails when a dependency
  fails, extending the existing pattern in `tests/test_ci_gate_negative.py`.
- Required-check configuration is consistent with the gates that exist.

### T7 — Performance benchmarks — *Scope: Gated*

**Objective.** Measure throughput and latency on ARM Cortex-M, ARMv8, x86-64
and embedded targets.

**Actions.** Extend `benchmarks/` and the ARM QEMU workflow rather than
introducing a parallel suite. Where a target cannot be measured in CI, state
the measurement method and the hardware used. Honour the provenance policy in
`benchmarks/README.md`: every published number traces to a committed artifact
or to live output regenerated from one.

**Acceptance criteria.**
- Reproducible scripts committed; a reader can regenerate every published
  number from the repository.
- Results committed with the platform, toolchain, build configuration and
  measurement methodology recorded alongside each number.
- Regression tolerances in `benchmarks/baseline.json` updated where measured
  performance changes.

### T8 — Platform profiling — *Scope: Gated*

**Objective.** Identify hot paths and rank optimization opportunities by
measured cost.

**Acceptance criteria.**
- Profiling report committed, naming the profiler, workload and platform for
  each measurement.
- Prioritized list where each entry carries a measured current cost and an
  estimated achievable gain.

### T9 — Platform-conditional kernels — *Scope: Gated*

**Objective.** Add optimized kernels where profiling shows measurable gain.

**Actions.** Follow the existing dispatch architecture in
`src/c/dispatch/ama_dispatch.c` and `src/c/ama_cpuid.c`. Every kernel is
selected at runtime behind a capability check and has a portable C fallback
that produces byte-identical output.

**Acceptance criteria.**
- Differential tests prove byte-identical output between each kernel and the
  portable fallback, extending the pattern in
  `tests/test_x25519_dispatch_policy.py` and the Ed25519 backend-parity check.
- Constant-time properties re-verified for every new kernel.
- Before/after benchmarks committed.
- The build succeeds and tests pass on targets lacking the instruction set.

### T10 — Implementation quality checklist — *Scope: PR*

**Objective.** Ensure the review checklist covers constant-time patterns,
memory safety and secure error handling, and that the code satisfies it.

**Actions.** Extend `CRYPTO_REVIEW_CHECKLIST.md` where this work exposes an
uncovered control. Keep every item phrased so a reviewer can answer it from the
diff and its tests, and name the automated gate that enforces it. Then apply
the checklist to the PR diff and record the result.

**Acceptance criteria.**
- Checklist covers each control class named above, each item citing its gate.
- The completed checklist for this PR is recorded in the PR evidence.

### T11 — Algorithm inventory — *Scope: PR*

**Objective.** Maintain a definitive inventory of supported algorithms and
primitives.

**Actions.** `CSRC_STANDARDS.md` is the inventory. Verify it against the
shipping code and correct any drift. Its stated rule — only algorithms with
shipping code are listed, no aspirational entries — is binding.

**Acceptance criteria.**
- Every shipping primitive appears with its standard, parameter set and source.
- No listed algorithm lacks shipping code; no shipping algorithm is unlisted.
- An automated check fails CI on drift between the inventory and the code.

### T12 — Language and bindings matrix — *Scope: Gated*

**Objective.** Publish the current binding surface and the gaps in it.

**Actions.** Record, per language: binding status, the mechanism, which API
surface is exposed, which is not, and the platforms covered. Current state is
a C core with Python bindings via ctypes and Cython; no other language binding
exists. Rank candidate targets by demand and by the effort the C ABI implies.

**Acceptance criteria.**
- Matrix file committed reflecting verified state, not intent.
- Prioritized target list with the rationale for each ranking.

### T13 — Additional binding and TLS integration example — *Scope: Gated*

**Objective.** Deliver one mainstream binding beyond Python and a TLS
integration example.

**Actions.** Implement the binding against the existing C ABI; do not fork the
core to accommodate it. The TLS example demonstrates integration and belongs
under `examples/`; it must not introduce a third-party cryptographic dependency
into the core package, per `INVARIANT-1`.

**Acceptance criteria.**
- Binding implemented with tests running in CI on every supported platform.
- The binding is verified against the canonical vectors from T5.
- TLS integration example committed, executable, and documented.

### T14 — Documentation standard — *Scope: PR*

**Objective.** Standardize module documentation headers and usage examples.

**Actions.** The repository already uses a consistent "Document Information"
table across top-level documents. Formalize it as a template and apply it.
Note that `tools/check_headers.py` enforces *license* headers and is a separate
control — extend it or add a companion check, but do not conflate the two.

**Acceptance criteria.**
- Template committed (see Appendix B).
- Every module touched by this work carries the required header and at least
  one executable usage example.
- An automated check enforces the template on documents in scope.

### T15 — API ergonomics — *Scope: Gated*

**Objective.** Make the public API secure by default, particularly for key and
nonce handling.

**Actions.** Identify every API where a caller can produce an insecure result
through ordinary use — nonce reuse, key reuse across contexts, silent
truncation, unchecked lengths. Prefer additive wrappers that make the safe path
the default path. Preserve backward compatibility; where an interface must
change, provide migration notes and a deprecation path.

**Acceptance criteria.**
- Changes or wrappers implemented with tests covering the misuse cases.
- Migration notes and examples committed.
- Backward compatibility preserved, or the break documented with its rationale
  and migration path.

### T16 — Comparative analysis — *Scope: Gated*

**Objective.** Compare the shipping AEADs against each other and against peer
implementations on performance and resource use.

**Actions.** Extend `benchmarks/comparative_benchmark.py` and
`benchmarks/performance_comparison.py`. Peer libraries are declared under the
`[benchmark]` extra and are never imported by the core package. Where the
original draft specified an Ascon comparison, that arm is contingent on
Appendix A; run the comparison across the shipping AEAD set regardless.

**Acceptance criteria.**
- Comparative tests committed and reproducible.
- Summary covering throughput, latency, memory footprint and code size, with
  the measurement methodology stated.

### T17 — Release and changelog policy — *Scope: Gated*

**Objective.** Document the release rules and changelog format, with explicit
handling of security-relevant and API-affecting changes.

**Actions.** The mechanics exist — `release.yml`, signed wheels, SLSA
provenance, `tools/check_version_consistency.py`, and a CHANGELOG following
Keep a Changelog and SemVer. What is absent is the stated policy: what
constitutes a security release, how advisories are coordinated with releases,
how API changes are classified against SemVer, and what evidence a release
requires.

**Acceptance criteria.**
- Release policy document committed covering version classification, security
  release handling, and required pre-release evidence.
- Changelog template committed with security and API-change sections.
- Policy is consistent with the automation that already exists.

### T18 — Primitive change control — *Scope: PR*

**Objective.** Ensure primitives are replaced only on demonstrated grounds.

**Actions.** Record every primitive change in a decision log entry stating the
motivation, the security rationale, the compatibility impact, the migration
path, and the evidence. This governs Appendix A and any future change.

**Acceptance criteria.**
- Decision log committed under `docs/audit/`.
- Every primitive change in scope has an entry; no primitive changes without
  one.

---

## 6. Execution protocol

1. **Establish the baseline first.** Confirm the current head SHA, the state of
   every check run, and the contents of Section 4 before changing anything.
   Report the baseline before the first commit.
2. **Reproduce before fixing.** Add a test that fails against current code and
   demonstrates the issue, then fix it. A fix without a failing-first test does
   not satisfy its acceptance criterion.
3. **Automate every verification.** Each fix ships with the test or gate that
   prevents its regression.
4. **Keep commits atomic.** One purpose per commit, with its tests. Match the
   repository's existing commit-message conventions.
5. **Measure performance claims.** Before and after, same machine, same build
   configuration, methodology stated. Unmeasured performance claims are not
   acceptable.
6. **Never weaken a control to make a gate pass.** If a gate fails, the finding
   is real until proven otherwise. Suppressions require a recorded
   justification and are subject to `tools/check_suppression_hygiene.py`.
7. **Respect the scope boundary.** `Gated` tasks require the owner's go-ahead
   before being pushed to the PR head branch (§2.2).
8. **Track what does not close.** Any finding not resolved in this PR gets a
   tracked issue with reproduction steps, a risk assessment and a remediation
   plan, referenced from the PR.

---

## 7. Evidence standard

Every claim in the audit report and the PR description must be traceable to a
committed artifact or to a command a reviewer can run. Specifically:

- Test results cite the suite, the count, and the environment.
- Constant-time claims cite the t-statistic, the execution count and the
  threshold.
- Fuzzing claims cite the target, the execution count and the sanitizer set.
- Performance claims cite the platform, toolchain, build configuration and the
  artifact the number came from, per `benchmarks/README.md`.
- Interoperability claims name the independent implementations and their
  versions.
- A claim that cannot be reproduced from the repository is removed rather than
  softened.

---

## 8. Definition of done

- Every task in Section 5 is either closed against its acceptance criteria or
  carries a tracked issue with reproduction steps, risk assessment and
  remediation plan.
- All CI gates pass on the head commit, with no gate weakened, skipped or
  soft-failed to achieve it.
- The audit report covering security, correctness, performance,
  interoperability and API ergonomics is committed.
- The PR description states what changed, why, and what evidence supports each
  claim.
- No unresolved critical finding is deferred.

---

## Appendix A — Ascon adoption decision gate

Ascon is not implemented in this repository (§2.1). Adopting it is a governance
decision under `INVARIANT-1`, not an audit task. Before any Ascon code is
written, produce a decision record answering:

1. **Requirement.** What use case do AES-256-GCM and ChaCha20-Poly1305 fail to
   serve? Ascon's standardized niche is constrained environments; state the
   target platform and its measured constraint.
2. **Standard.** Which specification and parameter set — NIST SP 800-232 —
   and which variants.
3. **Implementation.** `INVARIANT-1` forbids third-party crypto and requires
   in-house implementation with KAT validation. Scope the constant-time
   implementation, its SIMD variants and its portable fallback.
4. **Validation.** Which vector sources establish correctness, and how they are
   vendored and pinned.
5. **Maintenance.** The added surface across dispatch, fuzzing, dudect,
   benchmarks, bindings and documentation.
6. **Decision.** Adopt or decline, with the rationale recorded per T18.

If declined, record the decision so the question is settled rather than
recurring. Until this gate is passed, treat all Ascon references in the source
draft as redirected to the shipping AEAD set.

---

## Appendix B — Documentation header template

Apply to every document in scope, matching the convention already used across
the repository's top-level documents:

```markdown
# <Title>

## Document Information

| Property | Value |
|----------|-------|
| Document Version | <version, tracking the project version> |
| Last Updated | <ISO date> |
| Classification | <Public | Internal> |
| Maintainer | Steel Security Advisors LLC |

---

## Purpose

<What this document is for and who must read it.>

## Usage

<At least one executable example.>
```

This is distinct from the license header enforced by `tools/check_headers.py`,
which remains required on every tracked source file.

---

## Appendix C — Push and review hygiene

- Push to `steel/autonomous-boundcont-vu2lxv` only. Do not create branches.
- Rebase or merge `main` into the PR head when the base advances; resolve
  conflicts rather than forcing past them.
- Confirm check-run state after each push; a push that turns a gate red is
  yours to resolve before continuing.
- Update the PR description as scope changes so it always describes what the
  diff actually contains.
- Where a `Gated` task's work is prepared but not authorized, hold it as a
  separate commit series and state its readiness in the PR rather than pushing
  it into the PR head.
