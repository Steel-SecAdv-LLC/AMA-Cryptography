# Engineering Operations Directive

**Applies to:** every automated agent and every contributor operating on this
repository.
**Status:** binding. This directive is read before the first tool call of a
session, not after.
**Authority:** subordinate to `INVARIANTS.md`; superior to convenience,
convention, and individual preference.

---

## 1. Purpose and scope

This repository implements a cryptographic library with no third-party
cryptographic dependencies. Every primitive is native to this tree. There is no
upstream implementation to catch an error made here, and no downstream consumer
positioned to detect one. The correctness burden terminates in this repository.

This directive states what the repository requires of anyone modifying it: the
standard of evidence, the order of precedence when requirements conflict, the
classification of findings, and the enforcement model. It is written to remain
valid independent of who maintains the repository.

The repository requires confidence and fidelity. Work is complete when it is
proven, not when it is plausible.

---

## 2. Order of precedence

When requirements conflict, they resolve in this order. A lower item never
justifies compromising a higher one.

| Rank | Requirement |
|---|---|
| 1 | **Security invariants** — the 53 numbered invariants in `INVARIANTS.md` |
| 2 | **Correctness** — conformance to FIPS/RFC, ACVP and KAT agreement, ABI truth |
| 3 | **Reproducibility** — deterministic builds, byte-equal artifacts, pinned corpora |
| 4 | **Performance** — measured throughput and instruction counts against their floors |
| 5 | **Developer convenience** — build ergonomics, run time, tooling comfort |

A change that improves rank 4 by weakening rank 1 or 2 is rejected regardless of
the magnitude of the improvement. A change that cannot satisfy rank 1 is
escalated to the repository maintainer for a decision; it is not resolved by the
agent bending the invariant.

---

## 3. System architecture

Read `ARCHITECTURE.md` in full before substantive work. Summary:

Native C cryptographic core with a Python application layer and zero external
cryptographic dependencies. ML-KEM-1024, ML-DSA-65, SLH-DSA, Ed25519, X25519,
secp256k1, P-256/384/521, AES-256-GCM, ChaCha20-Poly1305, SHA-3, HKDF, Argon2id
and FROST are implemented under `src/c/`. The Python layer calls those kernels.
`hashlib` is confined to the gate-pinned pre-execution trust bootstrap.

| Path | Contents |
|---|---|
| `src/c/` | Cryptographic primitives. No vendored crypto. No suppressions. |
| `src/c/{avx2,avx512,neon,sve2}/` | SIMD kernels, CPUID-gated, each pinned by KAT |
| `src/c/dispatch/` | Runtime backend selection |
| `include/` | Public C ABI; every exported symbol is declared here |
| `ama_cryptography/` | Python package: crypto_api, key_management, posture, monitoring |
| `tests/c/`, `tests/` | 86 C test suites, 248 Python test modules |
| `tools/check_*.py` | Gate scripts that enforce the invariants |

Design constraints governing all changes:

1. Standardized primitives only — NIST FIPS and IETF RFC. The composition
   protocol is original work; the primitives are not.
2. Defense in depth: independent layers, so that a single failure is not total.
3. Constant-time execution for every secret-dependent operation.
4. Graceful degradation applies to optional components. It never applies to
   cryptography (INVARIANT-7).
5. Performance claims name the host, the build flags, and the artifact.

---

## 4. The invariant framework

`INVARIANTS.md` contains 53 numbered invariants. They are enforced by gate
scripts, not by convention, and they take precedence over any other guidance in
this repository. Before modifying an area, read the invariant governing it.

1. Zero External Crypto Dependencies
2. Fail-Closed CI
3. Observable Failure States
4. Pinned Action References
5. Input Validation at Python/C Boundary
6. Secret Key Zeroing on All Exit Paths
7. No Cryptographic Fallbacks, Ever
8. Deterministic Reproducible Builds
9. Maximum Exception Scope in Crypto Paths
10. Signed Commits on Protected Branches
11. SBOM as Release Gate
12. Constant-Time for All Secret-Dependent Operations
13. No Unjustified Static-Analysis Suppressions
14. CVE Ignore-List Hygiene
15. Thread-Safe CPU Dispatch via Platform Once-Primitive
16. Honest Compliance and Audit Claims
17. Module Integrity Signing Stays Build-Time and Ephemeral
18. ACVP Self-Attestation Coupled to CI Coverage Floors
19. Hybrid KEM Combiner Is Security-Critical
20. Constant-Time AES Remains the Default
21. X25519 Low-Order Outputs Rejected
22. AEAD Nonce Durability Fails Closed
23. No Credential Material in the Public Tree
24. Pinned Action SHAs Resolve Upstream
25. Workflow Runner Labels and Commands Valid
26. Ed25519 Signatures Have a Canonical S
27. X25519 u-Coordinates Reduced Before Use
28. ECDSA Signatures Low-s and Strictly Encoded
29. ECDSA Public-Key Coordinates Canonical
30. Agent-Instance Persistence Operator-Authorized
31. Every PR Job Reachable From Its Gate
32. Documented Install Commands Resolve
33. Every Fuzz Harness Registered Everywhere
34. Low-s Is a Property of the Sign/Verify Pair
35. A Selector Never Resolves Weaker Than Asked
36. AMA Is Not Measured Against Another Implementation
37. A Verification API Does Not Claim a Check It Does Not Perform
38. Ed25519 Compressed Points Have a Canonical y
39. A Failed POST Fails the Import and Inhibits Output
40. Executed Bytecode Matches Signed Source
41. No Keypair Released Without a Pairwise Consistency Test
42. Declared ctypes ABI Matches the C Header
43. Every Logged Literal Survives a cp1252 Handler
44. A Fetched Corpus Is Pinned by Bytes, Not by Name
45. Every SIMD Kernel Has a Pin, Vectors Run Under It
46. Fuzzing Must Be Able to Deepen
47. A Lane That Provisions a Resource Fails the Skip of It
48. Ed25519 Rejects Small-Order Public Keys and R Halves
49. A FROST Nonce Pair Is Single-Use; Aggregation Verifies Every Share
50. Approved-Mode Signing Is Context-Separated
51. An Ed25519 Signer Derives Its Own Public Half
52. A Package Signature Covers the Whole Package
53. A Documented Claim Must Resolve Against the Implementation

---

## 5. Primary directive: remediation at source

**A defect is resolved by changing the code. Documentation, annotation, and
suppression are not resolutions.**

This is the governing engineering principle of the repository and the most
frequent point of failure in practice.

Required responses:

| Condition | Required action | Not acceptable |
|---|---|---|
| Static-analysis finding | Change the code until the analyzer is satisfied | Suppression marker; disabling the check |
| Irreducible tool limitation | Narrow the exclusion to the exact demonstrated files, pinned by a gate | Tree-wide or directory-wide exclusion |
| Intermittent test | Make the test deterministic | `skip`, `xfail`, quarantine, deletion |
| Unprotected guard | Build the test that fails without the guard | A comment asserting the guard is correct |
| Unreproducible performance claim | Re-measure and publish the conditions | Softening the claim |
| Missing mechanism | Build the mechanism | Describing its absence |

*Historical corrective action:* repository-wide suppression mechanisms — a
`.cppcheck-suppressions` file and a tree-wide `clang-tidy` check exclusion —
were removed and the underlying code corrected, because they violated
INVARIANT-13. Both had been documented. Documentation did not make them
acceptable.

Suppressions are prohibited without exception in `src/c/` and `include/`.
Elsewhere they are governed by INVARIANT-13, which requires line scope, the
named rule, a justification, a tracking reference, and test coverage of the
suppressed line.

**Blocked work.** Where remediation genuinely requires hardware, a credential,
or an authority the agent does not hold, the agent states the blocker in one
sentence, names precisely what is required to clear it, and completes all
remaining work in full. A single blocked item does not license an incomplete
pass.

---

## 6. Evidence standard

Code review is not evidence. A passing test is not evidence that the test
constrains anything.

**6.1 Measure before asserting.** Execute the behavior and record the result.
Claims about what the system does are supported by observed output, not by
reading the implementation.

**6.2 Mutation is the test of a test.** For any test added, or any guard
claimed to be protected: deliberately break the guard, rebuild, and confirm the
test fails. A test that passes against a deliberately broken guard constrains
nothing and shall be reported as such and corrected.

**6.3 Identify what is load-bearing.** Guards are frequently redundant. A test
surviving removal of guard A may be protected by guard B. Remove each
independently, then both, and report the measured result. Where a property is
enforced redundantly, the test pins the property, not either implementation,
and the documentation says so.

**6.4 Classify assertions by demonstrated behavior.** This repository uses:

- **PIN** — fails when the fix is reverted. Established by mutation.
- **RANGE** — unit test of a predicate's domain.
- **SMOKE** — behavioral; holds with or without the change.

The label is earned by mutation, not assigned by intent.

**6.5 Measure what is never executed.** `tools/measure_branch_coverage.py`
reports branch arcs under `src/c` that no test reaches. A guard that no test
executes is unprotected: removing it breaks nothing observable. This instrument
aggregates across every translation unit, because a header instantiated in
several units is covered if any instantiation runs it.

**6.6 Correct the record.** Where measurement contradicts an earlier conclusion
— including one stated in a commit message, a comment, or this directive — the
correction is stated explicitly and the artifact is amended. An accurate
retraction is preferred to a consistent narrative.

---

## 7. Severity classification

Findings are classified on discovery. Classification determines urgency and
whether work may be deferred.

| Severity | Definition | Handling |
|---|---|---|
| **Critical** | Cryptographic incorrectness, key or secret exposure, invariant violation, silent acceptance of invalid input | Halt other work. Remediate before any further change is pushed. |
| **High** | Build- or verification-gate bypass, a gate that cannot detect what it claims, ABI or format divergence from the declared contract | Remediate in the current pass. |
| **Medium** | Coverage gap, an unprotected guard, an untested reachable path, a stale derived figure | Remediate in the current pass where scoped; otherwise record with the measurement. |
| **Low** | Documentation inaccuracy, comment drift, naming, formatting | Carry into the next change that already touches the file. |

A finding whose severity is uncertain is treated at the higher classification
until measurement establishes otherwise.

---

## 8. Prohibited actions

1. Weakening, disabling, or narrowing a gate to obtain a passing build.
2. Skipping, quarantining, or deleting a test to obtain a passing build.
3. Adding a suppression to `src/c/` or `include/` under any justification.
4. Committing `ama_cryptography/_integrity_signature.py` from a local build; it
   carries a per-build ephemeral key and local artifact digests.
5. Empty commits, or closing and reopening a pull request, to re-trigger CI.
6. Asserting that a CI lane passed without observing it complete.
7. Publishing a performance figure without its host, build flags, and run
   identifier.
8. Rewriting history on a branch the agent does not own.
9. Treating a red pull request as blocked on review. A failing or conflicted
   head is active work.
10. Expanding scope beyond the requested change without authorization.

**On infrastructure failures.** Treat every failing test as a product defect
until infrastructure has been positively ruled out. Infrastructure failure is a
conclusion reached by evidence — an error naming a service the change does not
touch and reproducing identically on re-run, or the same failure present on the
base branch — not an initial hypothesis. "Flake" is not a root cause.

---

## 9. Verification procedure

Establish the baseline before modifying it:

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DAMA_USE_NATIVE_PQC=ON
cmake --build build && ctest --test-dir build --output-on-failure
python -m pytest tests/ -q
```

Required before pushing:

```
black --check . && ruff check . && mypy --strict <scope>
python tools/check_headers.py
python tools/refresh_derived_docs.py      # must reach its fixpoint
ctest --test-dir build --output-on-failure
python -m pytest tests/ -q
```

Any modified C compiles clean under strict warnings on both toolchains:

```
gcc   -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Werror
clang -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Werror
```

**Commit composition.** A change and the derived figures it moves belong in the
same commit; the documented-counts gate reads them together, and splitting them
produces a failing intermediate state. Consecutive pushes cancel the superseded
CI run, and its roll-up gates then report failure for cancelled dependencies
rather than for any defect. One validated push is preferred to several
speculative ones.

---

## 10. Enforcement model

Invariants are enforced by gate scripts under `tools/` and by the CI workflows
that invoke them, fail-closed (INVARIANT-2). Enforcement is mechanical;
agreement with a rule is not required for it to bind.

A violation that reaches review indicates two defects: the change, and the gate
that failed to detect it. Both are remediated. Where no gate exists for a rule
this directive states, constructing that gate is in scope for the pass that
discovered the omission — subject to the constraint that a gate requiring a
standing exemption list is not a gate. Such a mechanism reproduces the
suppression pattern INVARIANT-13 prohibits and is rejected; where systematic
exemption would be unavoidable, the correct artifact is a measurement
instrument producing a reviewed inventory, not a build-blocking check.

Conflicts between this directive and `INVARIANTS.md` resolve in favor of
`INVARIANTS.md`. Conflicts this directive does not resolve are escalated to the
repository maintainer.

---

## 11. Current engineering state

Open item, carried forward and unassigned:

`tools/measure_branch_coverage.py` reports 1,741 of 11,315 instrumented
branch arcs under `src/c` never taken by the C suite (measured 2026-09-22 on
the tree just before `test_ed25519_stack_residue` was added: gcc 13.3.0, Debug
`--coverage -O0 -g`, 143 translation units, `ctest` 138 tests; the suite has
grown since, so this is a dated measurement, not a current count). The 839b66b4 commit message
reported 1,765 of 11,053; re-measuring that revision on this host gives
1,792 of 11,081 over 142 translation units, so the earlier figure belongs to
a different host and toolchain and is superseded here. The Ed25519 rows have been triaged
and two Medium findings closed. The dispatch and CPUID buckets (285 and 60
arcs) are structurally unreachable on any single host and require no action.
The following have not been examined: `ama_nistp.c` (152 arcs),
`ama_dilithium.c` (143), `ama_slhdsa.c` (116), `ama_kyber.c` (113),
`ama_frost.c` (67).

**What this inventory is, and what it is not.** Two corrections, per §6.6,
because the paragraph above has twice been read as a defect list and worked as
one.

First, the instrument measures one suite. Its own docstring says so — "the
branch arcs under `src/c` that the C suite never takes" — and its documented
procedure builds with `--coverage` and runs `ctest`, nothing else. The Python suite
never executes under it. An arc reached only from Python is
therefore counted here as never taken, so the number is an inventory of what
the C suite does not reach, which is not the same set as the guards no test
protects. Extending the measurement to cover both suites is open and unsolved;
until it is, a row in this inventory is a question, not a finding.

Second, `839b66b4` — the commit that produced this inventory — already
classified NULL-argument returns and allocation-failure returns among the arcs
that are legitimately never taken. Arc count recovered against that class is
not triage progress, and reporting it as such is a measurement error. `abde8640`
made exactly that error and its claim is withdrawn; the test it added is kept,
because it pins real INVARIANT-5 guards.

The required approach is unchanged in kind but not in target: identify guards
*no test in either suite* executes, construct tests that fail without them, and
remediate anything that proves to be more than a coverage gap. An arc is
triaged when its classification is established by mutation, not when it stops
appearing in a count. Per §10, a coverage gate carrying an exemption list is
not an acceptable substitute.

`ama_nistp.c` now also has exploratory coverage: `fuzz/fuzz_nistp.c` drives its
four parsers and asserts four properties across them. That is a standing check,
not a reduction in the figure above, which is a `ctest` measurement.

Release prerequisites are recorded in the pull request description. Each
requires hardware, a protected credential, or a workflow dispatch; none is
blocked by a defect in the tree. Re-measuring the "canonical host" is no
longer one of them, and the paragraph that stood here is corrected per §6.6:
it described a drift gate over the README's canonical-host tables as narrowing
that prerequisite, but those tables were 4.x-era measurements of code 5.0.0
changed, on hardware this project cannot reach, so pinning them kept figures
that described nothing current. They are removed rather than re-measured. The
README's throughput table now carries only CI-measured four-run medians,
pinned — with the host, build flags and run identifiers of every measurement
source — by
`tools/check_published_benchmarks.py` against
`benchmarks/published-benchmarks.json`. The policy for figures from other
hardware is stated once, in `benchmarks/README.md`.

---

## 12. Document control

This directive is maintained in the repository root and is subordinate to
`INVARIANTS.md`. It is amended by the same review process as any other change to
the tree, and its amendments are subject to the evidence standard in §6.

Related documents: `INVARIANTS.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`,
`CONTRIBUTING.md`, `CRYPTO_REVIEW_CHECKLIST.md`, `CHANGELOG.md`.

Copyright (C) 2025-2026 Steel Security Advisors LLC
SPDX-License-Identifier: Apache-2.0
