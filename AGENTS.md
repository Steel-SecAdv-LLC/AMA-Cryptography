# Standing Orders for Any AI Working on AMA Cryptography

**From:** Andrew E. A. — Steel Security Advisors LLC, owner of this repository
**Applies to:** every AI agent that touches this tree. Astra, Claude, whoever comes next.
**Read this before your first tool call. Not after.**

---

## 1. Why you are here

This is a cryptographic library that real systems will depend on. It has no
third-party crypto underneath it — if something is wrong here, nothing catches
it downstream. That is the whole premise of the project, and it is why I hold
the bar where I hold it.

I have spent months on this. I do not need enthusiasm. I need **confidence and
fidelity**. Those two words are the job.

What I want from you:

- Real strategy, engineering, and signal.
- Work that is **finished** — no gaps, no deferments, no suppressions, no
  silencing, no weakness left in place with a note attached.
- Awareness. Do not act unconsciously. Know what is around you in this tree
  before you change it.
- Your own verification. Check your work, then check it a second way. Tell me
  the truth about what you found, including when the truth is that you were
  wrong an hour ago.

What I do not want:

- Guessing presented as fact.
- Questions you could have answered by reading the repository.
- Scope you invented because it seemed interesting.
- Anything that increases my future work without paying for itself now.

Stay alert for genuine synergies, novel methods, or breakthroughs worth having.
They are welcome. They are not an excuse to wander.

---

## 2. What this system is

Read `ARCHITECTURE.md` in full before substantive work. The short version:

**Native C cryptographic core, Python application layer, zero external crypto
dependencies.** Every primitive — ML-KEM-1024, ML-DSA-65, SLH-DSA, Ed25519,
X25519, secp256k1, P-256/384/521, AES-256-GCM, ChaCha20-Poly1305, SHA-3, HKDF,
Argon2id, FROST — is implemented in this tree under `src/c/`. The Python layer
calls those kernels. `hashlib` is confined to the gate-pinned trust bootstrap
and nowhere else.

**The layers:**

| Layer | What lives there |
|---|---|
| `src/c/` | The primitives. No vendored crypto. No suppressions. Ever. |
| `src/c/{avx2,avx512,neon,sve2}/` | SIMD kernels, CPUID-gated, each pinned by KAT |
| `src/c/dispatch/` | Runtime backend selection |
| `include/` | The public C ABI — every exported symbol is declared here, no exceptions |
| `ama_cryptography/` | Python package: crypto_api, key_management, posture, monitoring |
| `tests/c/`, `tests/` | 83 C suites, 245 Python test modules |
| `tools/check_*.py` | The gates. These enforce the invariants. |

**The design principles I hold you to:**

1. Standardized primitives only — NIST FIPS, IETF RFC. No custom ciphers or
   hashes. The *composition* is original; the primitives are not.
2. Defense in depth. Independent layers, so one failure is not total failure.
3. Quantum readiness in the primary signature path.
4. Constant-time for everything secret-dependent.
5. Graceful degradation for optional components — **never** for cryptography
   itself. See INVARIANT-7.
6. Honest performance claims: name the host, the flags, the artifact.

---

## 3. The invariants are the constitution

`INVARIANTS.md` is 3,356 lines and carries **52 numbered invariants**. They are
not documentation. They are the rules the gates enforce, and most of them exist
because something went wrong once and I do not intend to repeat it.

Know them. When you touch an area, re-read the invariant that governs it.

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

If your change cannot live inside these, the answer is not to bend one. Bring
me the argument and I will decide.

---

## 4. Engineer it. Do not document around it.

**This is the rule I care about most, so read it twice.**

When you find a problem, the deliverable is a **fix in the code**. Not a note.
Not a caveat in the CHANGELOG. Not a suppression with a tracking ID. Not a
`skipif`. Not a comment explaining why the broken thing is acceptable.

I have watched this project accumulate exactly that failure mode and then spend
an entire maintenance pass deleting it — the `.cppcheck-suppressions` file, the
tree-wide dropped clang-tidy check. Both were "documented." Both were wrong.
The pass that removed them put it correctly: **a suppression and a dropped
check are not fixes.** INVARIANT-13 says the same thing with teeth.

So:

- A failing analyzer finding gets the **code** changed until the analyzer is
  satisfied, or the exclusion gets narrowed to the exact files with a
  demonstrated irreducible tool limitation — never the tree.
- A flaky test gets **made robust**. It does not get skipped, disabled, or
  quarantined. A failing test is never "infra."
- A gap in a guard gets the guard **built**, plus the test that fails without
  it.
- A performance claim you cannot reproduce gets **re-measured**, not softened.
- If a mechanism is missing — a gate, an instrument, a harness, a lever —
  **build the mechanism.** Fuses, breakers, plumbing, wiring. That is
  engineering. Writing a paragraph about the missing fuse is not.

The one honest exception: when the fix genuinely belongs to someone else or
needs hardware or a credential you do not have. Then say so in one plain
sentence, name exactly what is needed, and **finish everything else in full**.
Do not let one blocked item become cover for a half-done pass.

---

## 5. How to prove a change — the discipline I expect

Reading the code is not proof. Passing tests are not proof that a test is
*doing anything*. Here is the standard, and it is not optional:

**Measure before you claim.** Run the thing. Capture the number. If you are
asserting behavior, exercise the behavior first and read what actually comes
back.

**Kill the mutant.** For any test you add or any guard you claim is protected:
break the guard on purpose, rebuild, and confirm the test *fails*. If it still
passes, your test proves nothing and you must say so and fix it. This single
habit is what separates a real assertion from decoration.

**Find out what is actually load-bearing.** Guards are often redundant. A test
that passes when you remove guard A may be riding on guard B. Remove each, then
both. Report what you found, not what you assumed. I would rather have an
accurate "this pins the property, not the implementation" than a confident
label that is false.

**Label honestly.** This tree uses PIN (fails without the fix), RANGE (unit
test of a predicate) and SMOKE (behavioral, holds either way). Earn the label
by mutation. Do not guess it.

**Know what is never exercised.** `tools/measure_branch_coverage.py` reports
the branch arcs under `src/c` that no test reaches. A guard nothing executes is
invisible — deleting it breaks nothing and the suite stays green. Run it. Read
it. That is how two real gaps were found.

**Correct yourself out loud.** If mutation contradicts your earlier reasoning,
say so plainly and fix the artifact. I would much rather read "my first
reasoning was wrong, here is the measurement" than a clean story that is not
true. Confidence built on a wrong premise is worse than no confidence.

---

## 6. Never

- Never weaken a gate to get green.
- Never skip, disable, or quarantine a test.
- Never add a suppression to `src/c/` or `include/`. Not with a justification.
  Not with a tracking ID. Not ever.
- Never commit `ama_cryptography/_integrity_signature.py` from a local build —
  it carries a per-build ephemeral key and your local `.so` digests.
- Never push an empty commit or close/reopen a PR to kick CI.
- Never claim a lane passed that you did not watch finish.
- Never state a benchmark number without the host, the flags, and the run.
- Never rewrite history on a branch that is not yours.
- Never let a red PR sit because it is "waiting on review." Red is work.

---

## 7. The loop, every time

Before you touch anything:

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DAMA_USE_NATIVE_PQC=ON
cmake --build build && ctest --test-dir build --output-on-failure
python -m pytest tests/ -q
```

Know the baseline before you move it.

Before you push:

```
black --check . && ruff check . && mypy --strict <scope>
python tools/check_headers.py
python tools/refresh_derived_docs.py      # must reach its fixpoint
ctest --test-dir build --output-on-failure
python -m pytest tests/ -q
```

Strict warnings on both compilers for any C you touch:

```
gcc   -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Werror
clang -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Werror
```

Then squash your derived-docs refresh into the commit that caused it. Two
pushes a minute apart cancel the first CI run and produce a wall of red
roll-up gates that mean nothing. One validated push beats three speculative
ones.

---

## 8. Where things stand

PR 394 carries the 5.0.0 completion work. CI is green. The four release
prerequisites in the PR body each need hardware, a credential, or a workflow
dispatch — none is blocked by a defect in the branch.

The open engineering item, and it is real: **`tools/measure_branch_coverage.py`
reports ~1,765 of ~11,053 branch arcs under `src/c` are never taken.** The
Ed25519 rows have been triaged. The rest have not. The dispatch and CPUID
buckets are structurally unreachable on any single host and are fine.
`ama_nistp.c` (203), `ama_frost.c` (67), `ama_slhdsa.c` (116), `ama_kyber.c`
(111) and `ama_dilithium.c` (140) have not been examined by anyone.

That is where the next real pass goes. Not a coverage gate with an exemption
list — that is a suppression file wearing a different hat, and this project
already deleted one. Read the inventory, find the guards nothing executes,
build the tests that make them fail-visible, and fix anything that turns out to
be more than a test gap.

Finish it. Prove it. Tell me the truth about it.

— Andrew
