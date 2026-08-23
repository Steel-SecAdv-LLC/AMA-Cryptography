## Pull Request Description

> **Corrections at `6c40102`** — 5 defects fixed, 3 claims withdrawn, lanes re-run: [record](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/pull/394#issuecomment-5331588336). **Not merge-ready**: no human crypto review.

### Summary

A full-repository audit of AMA Cryptography at v4.0.0 (post-PR #391), run as fifteen parallel subsystem reviews — C symmetric / classical-asymmetric / PQC / SIMD-infra, the ctypes boundary, the Python API and security infrastructure, build system, CI and gate tooling, test quality, fuzz and benchmark infrastructure, docs-vs-code, the public C ABI, and a targeted re-review of PRs #391 and #386. Every finding was independently re-verified against the code before it was acted on; the ones that survived are fixed here, each with the evidence that established it.

The branch has since been carried through a **completion pass** covering the 55 commits it then had (the branch now carries 233) — the three open review threads closed at root cause, the four open decisions settled with implementation and tests, the fail-open security boundaries closed, and every mandatory verification lane executed against the final code rather than assumed. Those are described under *Completion pass* below; they are the reason the version moves to **5.0.0** and the reason this description now enumerates four breaking changes where the first revision said "None".

Two further passes followed, and both are described below. **Completion pass 2** re-examined the branch against its own measurements — including the detector-efficacy measurement an earlier revision of this description said did not exist yet, which did exist and was negative on every axis. **Completion pass 3** is the result of the full-effective-diff review that pass 2 established: running it over all 183 changed files found twenty-nine real defects, several of them in code the previous pass had just added, and they are fixed here rather than recorded as known issues.

The three most consequential findings of the original audit were all invisible to the existing test suite, for the same structural reason: nothing exercised the configuration in which they are reachable.

1. **Shipped wheels could SIGILL on pre-AVX2 x86-64.** `CMakeLists.txt` put `-mavx2` on `CMAKE_C_FLAGS` for every translation unit, so the compiler auto-vectorised ordinary C everywhere — measured before the fix: 34 YMM instructions inside `ama_kyber.c`'s portable keygen/encaps/decaps, 18 in the dispatcher, 2 in `ama_aes_bitsliced.c`, the constant-time AES fallback that exists *for* CPUs without AES-NI (which overwhelmingly also lack AVX2). Release wheels build with these defaults, so the crash lands inside the portable path the CPUID dispatcher correctly selected. The macro it defined (`AMA_HAS_AVX2`) was read by no source file.

2. **ML-KEM had the KyberSlash division pattern on secret operands** — the Compress_1 message decode in decapsulation (`mp = v − sᵀu`) and `poly_compress` inside the FO re-encryption. Replaced with an exact Granlund–Montgomery reciprocal multiply, proven byte-identical by exhaustive comparison over every coefficient in [0, q−1] for every width in {1, 4, 5, 10, 11}.

3. **The SVE2 backend was wired into dispatch but never built by any CI configuration.** `AMA_ENABLE_SVE2` defaults OFF and no workflow turned it on, so the tests documented as pinning those kernels could not reach them and the dudect sve2 lanes skipped unconditionally. Behind that gap: a Keccak theta step that read uninitialised stack on every shipping SVE2 CPU, and a Kyber NTT that disagreed with every other backend at all vector lengths.

### Type of Change

- [x] Bug fix (non-breaking change that fixes an issue)
- [x] Security fix (addresses a security vulnerability)
- [x] Performance improvement
- [x] Test enhancement (adds or improves tests)
- [x] Documentation update (changes to documentation only)
- [x] Breaking change (fix or feature that would cause existing functionality to change)

### Related Issues

Follows PR #391 (fail-closed POST, INVARIANT-39/40) and PR #386 (CSPRNG fail-closed, GHASH subkey, trust anchors). No issue numbers.

## Motivation and Context

### Why is this change required?

Each defect below is reachable in a configuration the project ships or documents, and none was caught by the existing suite. Several are cases where a control *stated* a property that its implementation did not deliver — an ERROR-severity semgrep rule that never scanned a C file, a cppcheck gate whose exit code was swallowed by `tee`, a build step whose `rc=$?` always read 0, a σ-threshold "enforcement" that was a provable no-op, a rotation-retry guarantee defeated by its own caller, a regression gate whose measurement noise exceeded its own threshold by 34x, and a SoftHSM2 suite that had never executed on any job this repository has ever run. (An ARM/QEMU workflow that "could not parse" was also claimed — **withdrawn**: introduced by this branch's `1e8bfb2`, fixed by `80103d7`; PR-local.) This repository's stated standard is that a gate which cannot fail is worse than no gate, so those are treated as defects of the same weight as the crypto bugs.

### What problem does it solve?

Removes a crash reachable on real hardware from published artifacts; removes a timing-oracle pattern from ML-KEM decapsulation; makes the SVE2 backend correct on the vector lengths real silicon implements; converts several decorative controls into ones that actually fail; and converts two post-hoc detections (native library, binding extensions) into pre-execution refusals that no environment variable can demote.

## Cryptographic Impact

### Security Impact Assessment

- [x] Modifies existing cryptographic operation (requires security analysis)

### Standards Compliance

- [x] NIST FIPS 202 (SHA-3)
- [x] NIST FIPS 204 (Dilithium)
- [x] RFC 5869 (HKDF)
- [x] RFC 8032 (Ed25519)

Also affected: FIPS 203 (ML-KEM compression), FIPS 205 (SLH-DSA ACVP corpora), RFC 8439 (Poly1305 key scrubbing and tag verify), RFC 9106 (Argon2 length binding), FIPS 140-3 §4.9.2 (continuous RNG test, output inhibition) and §4.9.1 (pairwise consistency test on every keygen).

### Academic References

- Bernstein, D. J., et al. (2024). "KyberSlash: Exploiting secret-dependent division timings in Kyber implementations." IACR ePrint 2024/1049 — the division pattern removed from `ama_kyber.c`.
- Granlund, T., and Montgomery, P. L. (1994). "Division by invariant integers using multiplication." PLDI '94, 61–72 — the exact reciprocal-multiply replacing it.
- Bos, J. W., and Carter, J. (as used in ed25519-donna's batch verification) — the randomizer soundness argument that the CSPRNG fail-open defeated.
- Reparaz, O., Balasch, J., and Verbauwhede, I. (2017). "Dude, is my code constant time?" DATE '17 — the Welch t-test procedure whose verdict rule is corrected here, and the method that found the ChaCha20-Poly1305 finding in C6.
- FIPS 197 §5.2 — the AES-256 key schedule, re-expressed in NEON registers (see *Self-review findings*).

### Security Analysis

**Classical Security:** The ML-KEM change removes a decapsulation timing oracle whose exploitation recovers the secret key. The Ed25519 batch-verify change removes a fail-open in which a failed CSPRNG draw caused every signature in the batch to be reported valid — with all-zero randomizers the aggregate collapses to the identity and the per-signature fallback is never taken. The FIPS 202 change converts a ctypes-reachable stack overflow (up to 95 bytes) into a clean error. The NEON AES-256 key schedule no longer writes round keys to the stack at all, which is a stronger guarantee than scrubbing them afterwards. Ed25519 public-key decode now rejects the last two non-canonical encodings (RFC 8032 §5.1.3, `x = 0` with the sign bit set) in both backends. ChaCha20-Poly1305 decrypt gets the unified post-verify control flow AES-GCM already had (C6).

**Quantum Security:** Unchanged. The ML-KEM compression replacement is byte-identical over its entire input domain, so ciphertexts, shared secrets and every FIPS 203 KAT are bit-for-bit unchanged.

**Security Impact:** Improves. No security property is weakened; the changes are removals of leaks, fail-opens and crashes, conversions of post-load detection into pre-load refusal, plus routing of key-material draws through the health-tested CSPRNG that INVARIANT-41 already claimed covered them.

## Implementation Details

### Changes Made

1. **Build — AVX2 no longer contaminates portable code.** Removed the global `-mavx2 -DAMA_HAS_AVX2`; per-file `set_source_files_properties` flags already give the AVX2 kernels what they need. Verified after: zero AVX/AVX2 opcodes outside `src/c/avx2` and `src/c/avx512` in the linked library, with the kernels' own YMM intact.
2. **ML-KEM — division-free `Compress_d`.** `M = ceil(2^40/q) = 330282857`, `S = 40`; exhaustively proven equal to the division form over all 16,645 (coefficient, width) pairs. The function now also applies its own documented `mod 2^d` — see *Completion pass* item C3.
3. **SVE2 Keccak theta** — the five-element column parity was stored through one `svwhilelt_b64(0,5)` predicate, which activates only `min(5, svcntd())` lanes. Modelled per vector length: VL=128 leaves 3 of 5 parity words uninitialised, VL=256 leaves 1, VL≥512 leaves none — which is exactly why QEMU's default 2048-bit `max` CPU hid it.
4. **SVE2 Kyber NTT** — `barrett_reduce_scalar` used the rounded form (`+ (1 << 25)`) where production, NEON and the test reference all use the truncating form (output differed by exactly one q), and neither NTT direction emitted the canonicalising Barrett sweep the AVX2/NEON kernels finish with.
5. **Ed25519 batch verify** — `ed25519_randombytes_unsafe` discarded `ama_randombytes`' status; the failure is now latched in a thread-local flag the wrapper inspects, marking every entry invalid and returning `AMA_ERROR_CRYPTO`.
6. **FIPS 202 streaming** — one exported `ama_sha3_ctx` is shared by four families with different rates and carries no tag; each entry point now validates `buffer_len` against its own rate.
7. **Zeroization and validation** — Poly1305's radix-2^26 init never scrubbed the clamped `r` key its radix-2^44 twin scrubs (the unfixed path is the one MSVC and every 32-bit target take); the 4-way Keccak sponge contexts in `kyber_gennoise`, `dil_polyvec_uniform_eta` and `dil_polyvecl_uniform_gamma1` were left seeded with sigma/rhoprime; `ama_hkdf` rejected a NULL `ikm` but not the NULL salt/info forms its SHA-2 sibling rejects (a NULL `info` with non-zero length reached a `memcpy` from NULL); Argon2id truncated `pwd_len`/`salt_len` into H0 above `UINT32_MAX`; the Windows RNG cast `len` to `ULONG` and reported success over an unwritten tail; the generic-POSIX RNG fallback used stdio (copying RNG output through a never-zeroized heap buffer) and lacked `O_CLOEXEC`.
8. **Python — INVARIANT-41 made true.** Nine key-material and nonce draws still used bare `secrets.token_bytes`. The GCM nonces are the sharpest: the counter machinery bounds how *many* nonces a key may see and never inspects their values, so a stuck DRBG repeating one was invisible to every control in place.
9. **Continuous RNG test** — unlocked read-compare-store, so two threads could both compare an identical stuck value against the same stale predecessor and both pass. Now compare-and-store under a lock, storing a SHA-256 digest rather than the sample (for a 32-byte draw the slice is the same object handed to the caller, so the old form pinned live key material in module state).
10. **CI gates that could not fail** — `rc=$?` after a failed `if` always read 0 (verified in a shell: old form `rc=0`, new form `rc=1`); cppcheck's `--error-exitcode=1` was swallowed by `tee` without pipefail; the ERROR-severity `bare-memset-zero-secret-named-buffer` rule is scoped to `src/c/**` while every semgrep invocation scans `ama_cryptography/` only. Widening the semgrep scope is not the fix — its C parser errors on every file using the `AMA_API` macro (15 files), which the severity gate correctly treats as a failed scan — so the property is now enforced by `tools/check_c_secret_zeroization.py`.
11. **Adaptive posture** — `_execute_action` armed the rotation cooldown unconditionally and *before* the attempt, so a rotation that was attempted and failed still suppressed every retry for the full window, making the whole attempted/succeeded distinction dead code. Separately, `ALGORITHM_STRENGTH.get(name, 0)` mapped unknown names onto the weakest rung (INVARIANT-35).
12. **Monitoring** — `_prune_alerts` rebound `self.alerts`, so alerts appended concurrently landed on the discarded list and vanished, and four of six writers took no lock; `_key_alerts` was an unbounded write-only list.
13. **`equations` — the σ_quadratic enforcement now enforces.** σ is a Rayleigh quotient, so scaling cannot change it; measured 0.1 before and after against a 0.96 threshold. Now rotates toward E's dominant eigenvector by the smallest blend reaching the threshold, and reports honestly when the threshold exceeds λ_max (unreachable by any state).
14. **Fuzzing** — the `--atheris` lane wrote `(target, data)` tuples to disk and died with `TypeError` before Setup; seeds also lacked the selector byte the entry point strips. Both `fuzz_ed25519` seeds were 32 bytes against a 33-byte harness minimum, so neither executed any library code. The fuzz build also instrumented only the harness translation unit, not the library it linked; a dedicated instrumented target now gives libFuzzer real coverage feedback (per-target block coverage measured at 115–10,237, previously none).
15. **Benchmarks (INVARIANT-36)** — `benchmark_suite.py` and `validation_suite.py` timed `hashlib.sha3_256` (OpenSSL on CPython) and published it as AMA's SHA3-256, with `validation_suite` "validating" the documented `sha3_256_hash` claim against it.
16. **Documentation honesty (INVARIANT-16)** — `ETHICAL_PILLARS` listed "NIST FIPS validation" and "formally verified implementations" as achieved methods and claimed ">95% coverage" and "confidence ≥ 99.9%", contradicting its own text 480 lines later and the canonical disclaimers in `CSRC_STANDARDS.md`/`README.md`. Also corrected: `THREAT_MODEL` said hardware AES-NI was "not in this library" (it ships AES-NI, VAES and ARMv8-CE kernels) and that disabling constant-time AES "emits a warning" (it fails the configure unless explicitly acknowledged); `CONSTANT_TIME_VERIFICATION` described the default S-box as "algebraic bitsliced — no table" when it is a masked full-table scan; the invariant range was stale at 1–38 in three files (42 exist); the v4.0.0 rows said "BREAKING ×4" where the CHANGELOG enumerates six.

### Self-review findings

Re-reviewing this branch against its own base surfaced four further items. Three were fixed; the fourth is a correction to an earlier claim in this description.

17. **A performance regression this PR introduced, in NEON AES-GCM.** Item 7 above added `ama_secure_memzero()` calls to `aes_key_assist_neon`/`aes_key_assist2_neon` to scrub round-key material those helpers staged through `uint8_t[16]` locals. The exposure was real — `out` is a complete AES-256 round key, its neighbours hold the adjacent one, and two consecutive AES-256 round keys invert to the master key — but the remedy was wrong. Each scrub carries a compiler barrier; six per helper across 13 helper calls per expansion defeated inlining and forced arrays into memory the compiler had kept in registers. Measured with `aarch64-linux-gnu-gcc 13 -O2 -march=armv8-a+crypto`, counting instructions in the branch-free expansion call tree, and running 200,000 expansions under `qemu-aarch64-static`:

    | version | instructions/expansion | 200k expansions |
    |---|---|---|
    | pre-PR | 880 (inlined) | 300.6 ms |
    | with the scrubs | 1,524 (13 out-of-line calls) | 1,574.9 ms |
    | after the fix | **137** (inlined) | **41.3 ms** |

    Key expansion runs once per GCM call, so that was a per-operation cost on every AArch64 AES-GCM encrypt and decrypt. The fix removes the memory round trip instead of cleaning up after it: SubWord via `AESE` on a broadcast word (ShiftRows is the identity on a vector whose four columns are equal, so the result is the broadcast of `SubWord(word)`), RotWord as a rotate-right-by-8, and the XOR cascade as a two-step vector prefix-XOR with `vextq_u8`. Nothing secret reaches the stack, so there is nothing left to scrub — the property the x86 kernels already had. Byte-identical to the pre-PR schedule over 300,000 keys × 15 round keys = 4,500,000 comparisons under QEMU.

18. **The benchmark job could not have reported that regression.** Each benchmark took a single timed run of a hard-coded iteration count (20–100, chosen per primitive across costs three orders of magnitude apart). Twenty ML-DSA-65 signatures is about 6 ms of measurement, and the whole 19-benchmark suite finished in roughly 0.4 s of wall clock on the CI runner. Three consecutive runs of one unchanged binary reported **917, 1845 and 3086 ops/sec** for `dilithium_sign` — a 3.4x spread with the code held constant, against a 10% regression threshold. Batches are now sized from the fastest rate observed so every primitive is measured over a comparable window (≥0.15 s), and the fastest of three full-window batches is reported. The target is recomputed after every batch, not from one calibration: the first version of this fix had a bug its own test caught, where a batch that is slow because it was *unlucky* satisfies an elapsed-time target with very few iterations and the undersized batch is then reused for every remaining round. Undersized batches inform sizing only and can never be reported, since these numbers become floors.
19. **Two apparent regressions that were not.** Comparing this branch's aarch64 benchmark job against the same job on the base commit also showed `dilithium_sign` at −65% and `full_package_create` at −67%. Both were noise from the harness in item 18. Re-measured deterministically with callgrind, the Dilithium sponge scrubs added in item 7 cost **4,200 instructions per signature out of 177 million (0.002%)**. Only findings backed by instruction counts are reported here.
20. **A ReDoS in this PR's own new gate.** CodeQL flagged `tools/check_c_secret_zeroization.py`; the finding was correct, and stress-testing the file found a second instance CodeQL did not report. `_MEMSET_RE` had two nullable quantifiers in sequence and a starred group whose alternatives each began with `\s*` (2,000 spaces 37 ms → 16,000 spaces 2,077 ms, a clean 4x per doubling); `_destination_name` stripped subscripts with `re.sub(r"\[[^\]]*\]", …)`, which is quadratic on unbalanced brackets (100k `[` took 5.5 s). Both rewritten to be linear and pinned by timing tests; every pattern in the file now grows ~2.0x per doubling.

### Completion pass

Everything above was the audit. What follows is the completion pass over the branch as it then stood — all 55 of its commits and every changed file, not only the files named in review threads.

#### C0 — What the full-branch review covered

Every commit on the branch and every changed source file was read against: cryptographic correctness, constant-time behaviour, memory safety, secret handling and zeroization, undefined behaviour, integer bounds and conversions, error propagation, fail-open behaviour, API and ABI compatibility, concurrency, platform portability, build and packaging behaviour, signing and provenance controls, test adequacy, benchmark validity, documentation accuracy and release consistency.

Excluding the regenerated fuzz seed corpora, the reviewed surface is ~110 files: 20 C sources and headers, 5 C tests, 18 package modules, 14 gate and generator tools, 8 benchmark files, 6 workflows, 3 Dockerfiles, `setup.py`, `CMakeLists.txt`, and the documentation set.

What the review found beyond the open threads is the substance of C1–C8 below — including defects no automated reviewer had reported: the `Compress_d` contract violation (C3), a ChaCha20-Poly1305 constant-time divergence (C6), a provenance flag that could never report clean (C6), a doc-sync tool that could not execute on Windows and would have corrupted line endings if it had (C6), a fifteen-month-stale SONAME in the ACVP harness (C6), and a fuzz job that could not import the package it fuzzes (C6). Differential checks were used where equivalence was the claim: the optimised MAD selection in `monitoring.py` was re-derived against the naive `sorted(abs(v - median))` form over 4,000 randomised windows (0 mismatches), as `Compress_d` was over all 16,645 (coefficient, width) pairs.

#### C1 — The two remaining fail-open security boundaries are closed

Both had the same shape: the check ran, decided correctly, and something short-circuited the consequence.

* **`AMA_BUILD_PIPELINE=1` demoted the pre-load native-library digest refusal to a warning and mapped the object anyway.** That variable is read from `os.environ` on every import, so anyone able to set one variable in the target process converted a pre-execution refusal into a post-hoc report — and a shared object runs its constructors the moment it is mapped, which is the entire event the check exists to prevent. No code execution was required to reach it. The need behind the carve-out is real (re-signing must map the library, because the signature is produced by the in-tree Ed25519 kernel and INVARIANT-1 forbids a PyCA dependency), so it is now met by **scope** rather than by severity: `pqc_backends.unverified_load_for_signing()` is an in-process context manager that `ama_cryptography._build_sign` enters around its own discovery call and leaves immediately. Setting a module attribute inside the victim's interpreter is not a capability an environment variable confers, and secure-execution mode (set-uid/set-gid) revokes it regardless.
* **The binding extensions were verified *after* the imports that pull them in.** A binding extension is an ordinary extension module, so importing it runs its module-init function; a tampered `sha3_binding` therefore executed and only then moved the module to the ERROR state. A gate at the top of package initialisation now hashes every extension the artefact signs and raises before any binding import can occur — verified end to end by flipping one byte in a signed binding, which refuses the import with the extension unimported. A digest **mismatch** is unambiguous tampering and is always fatal; inventory drift keeps its anchored/developer split inside POST, because deciding its severity needs the trust anchor from the library this gate deliberately runs ahead of.

Two consequences of making the refusal unconditional were fixed rather than worked around. The signer now selects the file to bind by **path** discovery and hashes it instead of deriving the path from a loaded handle (a loader-based signer walks past the very file it was asked to re-bless — its digest is stale by definition — and signs whichever later candidate still matched; a disagreement between the hashed and the loaded object is now an error, because signing the wrong file is worse than failing to sign). And the build-pipeline import escape widens from "the integrity stage failed" to "every failing stage is one a re-signing run repairs", decided structurally via `native_backend_refused_on_digest()` rather than by matching message text — so a release container, which carries the flag for its whole lifetime, still cannot smoke-test a broken wheel and report success.

#### C2 — Four verification lanes that could not execute, and the FROST excursion

Each was configured, named in the documentation, and incapable of running — and a check whose *availability probe* is wrong reports "not applicable" in exactly the words it would use if it had passed. SoftHSM2 was never installed by any workflow, so the only real PKCS#11 coverage in the tree skipped on every job this repository has ever run; the semgrep end-to-end assertion probed a deprecated entry point that exits 2 on a working installation, so it answered "not installed" everywhere semgrep *was* installed; `test_dispatch_cache_file` had been papered over with a whole-file skip whose root cause was `0 ns` meaning both "not measured" and "measured as zero"; and `test_pq_parser_stack` produced 32 invalid reads under Valgrind, now resolved by mapping the region twice from one shared object rather than by suppressing the reads. Each is described in full in `CHANGELOG.md`. (A fifth, `arm-qemu.yml`, is under C6 — it did not merely skip, it could not parse.)

**The `FROST scalar_negate (extremes)` excursion** was investigated rather than re-run until it passed. Re-measured at 2,000,000 operations per round × 5 rounds on a quiet host, at batch sizes 1, 8, 64 and 256, the lane reads |t| ≤ 1.62 with per-class means agreeing to within 0.6% (106.9 ns vs 107.5 ns unbatched); `scalar_negate`'s borrow loop and `sc_reduce` are branchless on inspection. What CI showed was the t-statistic **flipping sign** between rounds, which a systematic effect cannot do — and the verdict rule could not tell that apart from a finding. The rule now classifies rather than collapses: a majority of rounds over threshold *agreeing on a direction* is a leak; a majority over threshold *disagreeing* is `UNUSABLE`. Both still fail the run, so nothing is waved through; what changes is the diagnosis. Sensitivity is untouched, because a real leak's excursions share a sign. Eight new self-test cases pin the boundary, including the exact observed shape. **That classification then earned its keep in C6**, where it distinguished a real ChaCha20-Poly1305 finding from noise.

#### C3 — ML-KEM `Compress_d` applies its own `mod 2^d`

`kyber_compress_d`'s documented contract is `round(2^d·x/q) mod 2^d`; it returned the unmasked quotient. Not cosmetic: **832 of the 3,329 coefficients exceed `2^d` before the mask at d=1** — the width that decodes the ML-KEM message — along with 104 at d=4, 52 at d=5 and 1 at d=10. Every current caller happened to mask downstream, so no shipped output changes, but the helper's contract and its callers' assumptions had diverged. `tests/c/test_kyber_compress.c` now proves the equivalence against the specification's division form over all 16,645 (coefficient, width) pairs, through an `AMA_TESTING_MODE` export declared in `src/c/internal/ama_testing_exports.h` so the test exercises the shipped translation unit rather than a copy.

#### C4 — The four open decisions, settled with implementation and evidence

The first revision of this description asked reviewers four questions. All four are now resolved by analysis and code; none is left as a recommendation.

1. **ML-KEM derived constant vs pq-crystals per-width transcription** → **derived constant kept.** The single 64-bit form (`M = ceil(2^40/q)`, `S = 40`) is verified exhaustively over the entire input domain; the per-width transcription was attempted first and was wrong for d=10 and d=11 through 32-bit overflow. A construction whose correctness is *proved over its whole domain* preserves the repository's explicit guarantee better than one whose correctness rests on faithful copying. The exhaustive proof is now a committed test rather than a one-off.
2. **SVE2 theta scalar vs vector-length-agnostic vector** → **scalar kept, and the justification replaced with a measurement.** The old comment asserted the vector form "would cost more code". Measured instead: the VLA vector form is **15.9x slower at VL=128, 10.0x at VL=256 and 5.6x at VL=512** than the 20 scalar XORs it would replace, because a five-element reduction strip-mined across a vector-length-agnostic loop spends its time in predicate setup. The table is now in the source where the assertion was.
3. **`KYBER_1024` and `HYBRID_KEM` in `ALGORITHM_STRENGTH`** → **added, on a separate KEM ladder.** A single flat table cannot answer a KEM escalation with a KEM: it would have let a posture escalation cross families and offer a signature scheme in place of a KEM. `ALGORITHM_FAMILIES` now declares the signature and KEM ladders, `ALGORITHM_STRENGTH` is derived from them, and escalation is family-scoped. `AES_256_GCM` remains deliberately unrankable — an AEAD with nothing stronger to escalate to — and the `ValueError` for an unrankable name lists the valid names by family.
4. **`check_docker_pins` warn-versus-fail** → **fail, with the grace window documented.** Warning is the failure mode this PR exists to remove: a control that reports and does not stop is one nobody acts on. The 60-day window is now derived from a stated rationale (a base-image bump is a one-line change plus a CI cycle; 60 days is two release trains) and the finding taxonomy is explicit — `EOL_APPROACHING`, `EOL_PASSED`, `EOL_UNDECLARED`, `NOT_DIGEST_PINNED`, `UNDOCUMENTED_EXEMPTION` — so the diagnosis and the remedy are distinguishable.

#### C5 — The mandatory release dry run found three real blockers

The dry run was executed rather than assumed, and it failed three times before it passed. All three were genuine defects in this branch, none reachable from any other lane:

* **windows-latest**: the unconditional pre-load refusal from C1 starved `secure_memory` of a native handle, so `secure_memzero` refused, so the signer failed, so the job correctly refused to produce an unsigned release wheel. The fix is `_process_is_the_integrity_signer()` — the escape is keyed on the *identity of the running process* (`__main__.__spec__.name` being the signer module) and not on an environment variable, so it cannot be conferred from outside.
* **macos-15 and macos-15-intel**: `delocate-wheel` rewrites Mach-O load commands *after* signing, so all five binding digests mismatched in the produced wheel. `CIBW_REPAIR_WHEEL_COMMAND_MACOS` is now empty with the reasoning recorded in the workflow — the extensions link only against the library shipped in the same wheel, so there is nothing for delocate to vendor, and its rewrite can only invalidate the signature.
* A stale Windows comment in `release.yml` described behaviour the file no longer had; corrected in the same pass.

The dry run completes green end to end on the final head: preflight, trust-anchor verification, sdist, all five cibuildwheel platforms, SLSA subject hashing, Sigstore signing and SLSA provenance generation, with only the publish and GitHub-release steps skipped as a dry run requires.

#### C6 — Running the lanes against the final code found seven more defects

Each was found by executing a lane rather than trusting it, and each is fixed at root cause with the sweep for equivalents that follows from it. The first is the substantive cryptographic result; the other six are enumerated in `CHANGELOG.md` — `arm-qemu.yml` could not parse — PR-local (`1e8bfb2`, fixed `80103d7`); the Python key-parser fuzz job could not import the package it fuzzes; `tools/update_docs.py` could not execute on Windows at all and would have rewritten every line ending if it had; the ACVP harness pinned a SONAME three majors stale; the `Security Checks` job could not start pytest; and the benchmark provenance flag could never report a clean tree.

* **A ChaCha20-Poly1305 constant-time divergence in shipped C.** The dudect SIMD sweep's `chacha20-neon` slot on `ubuntu-24.04-arm` reported `ChaCha20-Poly1305 tag verify` at **|t| = 7.68 against a 4.5 threshold in 2 of 3 rounds with a consistent sign** — the shape C2's verdict rule separates from host noise. The lane runs only on dispatch and schedule, so per-PR CI had never exercised it. The compare itself was never the problem: `ama_consttime_memcmp` accumulates all 16 bytes with no early exit, so the *position* of a forgery — the oracle that lets an attacker build a tag byte by byte — was never observable. The divergence was structural: verify-pass and verify-fail were two separate straight lines, each arm of the `if` carrying its own `ama_secure_memzero()` call site, with only the pass arm going on to evaluate `if (ct_len > 0)`. `ama_aes_gcm.c:705` already carried the remedy — its comment records closing this very lane for AES-GCM — and of the five tag-compare sites in the tree (AES-GCM, Ascon, Argon2, agent-binding, ChaCha) this was the only one still branching directly on the comparison with duplicated cleanup. It now matches: compare hoisted to a value, one shared scrub call site, decrypt length bounded by a constant-time mask of `tag_match`. The fail-closed contract is unchanged and still pinned by the existing 0xA5 canary test. **The same sweep that found it now passes.**

#### C7 — Benchmark evidence is re-measured, not re-stated

Every published performance number in the tree is regenerated from the completed branch state on one host with nothing else running, and the records now carry the provenance needed to reproduce them: exact commit, working-tree cleanliness, host and CPU, Python build, the exact command, the sampling rule, the extra-repeat counts per primitive, and the aggregation method — in **both** the markdown report and the JSON record, which previously carried none of it. The five primitives whose cross-run disagreement exceeded 7% (`dilithium_sign`, `full_package_create`, `full_package_verify`, `aes_256_gcm_encrypt`, `hkdf_derive`) are sampled at 3–5 whole-run repeats rather than one.

The reports also now say plainly what the baseline column *is*: a regression **floor** measured on a named CI runner, not this host's expected throughput. Conflating the two is what let stale floors look like current performance.

**Stated as a limitation rather than papered over:** the canonical-host tables in `README.md` are 4.x-era measurements, labelled with the host and date they were taken on and with which rows this release superseded. Re-measuring them requires the canonical bench host (AVX-512 + VAES + VPCLMULQDQ, Sapphire Rapids / Zen 4 class), which is not reachable from CI or from this branch's build environment. That is a release-time action on hardware, listed under *Remaining actions*.

#### C8 — Release-state records now describe the branch that exists

- `CHANGELOG.md` carries a `## [5.0.0] - Unreleased` section with a breaking-changes glance table. It is **not** dated: under Keep a Changelog the date on a version heading is the release date, no `v5.0.0` tag exists, and `tests/test_update_docs_changelog_guard.py` fails if a date appears before the tag does.
- `tools/update_docs.py` was itself corrupting that file: its duplicate-section guard required `## [X.Y.Z] - YYYY-MM-DD`, so it could not see either undated heading, concluded 5.0.0 had no section, and inserted a second one above the hand-written one — which would then be the section `check_documented_counts` reads. Fixed and pinned by tests.
- The version moves to 5.0.0 at every declaration site and the integrity artefact is re-signed; the SONAME follows to `.so.5` and the loader's major-version handshake (INVARIANT-42) expects 5.
- `docs/METRICS_REPORT.md`, `README.md` and `ARCHITECTURE.md` are re-measured against the final tree, and the whole-project LoC reproduction command is replaced: the `find`-based form relied on a written instruction to measure on a clean checkout, and on a working tree with a virtualenv and two out-of-source build directories it reported 336,644 against the real 314,083. Enumerating tracked files with `git ls-files` makes the number independent of what the person running it happens to have built.


### Completion pass 2 — the branch re-examined against its own measurements

A post-completion audit raised fourteen findings against the completed branch, several of them defects in the completion pass's own claims. All are closed by implementation and measurement; `CHANGELOG.md` carries the full narrative.

* **The 3R timing detector was measurably non-functional, and this description had said the measurement did not exist.** The evaluation committed at `8d72b8c` was negative on every axis: the post-update robust z-score was provably capped below 3.0, so four of six sigma profiles and the `critical` severity were unreachable and sigma was inert (497 alarms at sigma 2, 3 and 5 alike); the Gaussian-calibrated MAD rule ran at a 12.52% clean false-alarm rate on heavy-tailed timing data; sustained-shift recall was 17.6%; and the harness "tied" trivial baselines only inside an unjustified F1 band of 0.02. The detector is rebuilt: point alarms score against the PRIOR window at max(profile sigma, an empirically calibrated (1 − alarm_budget) quantile of that operation's own score history); sustained shifts raise edge-triggered sign-CUSUM events against a reference locked at 200 samples, re-baselining after persistence; severity is capped at `warning` until calibration activates. The 1,807-line stale detector copy under `tools/monitoring/` is deleted.
* **CodeQL alert 620** (unreachable code) fixed at source with the file-local `_explode()` pattern the suite already uses — no dismissal, no suppression.
* **dudect gains two forgery-position lanes** (ChaCha20-Poly1305 and AES-GCM), each driving two forgeries over a 64-byte payload through the corrected masked control flow and differing only in which tag byte mismatches, so the byte-position oracle is measured rather than argued. Both lanes' stale `if (ct_len > 0)` comments are corrected to the `bounded_len` masking the implementations ship. 27 lanes.
* **The Kyber `-Wconversion` debt is zero and frozen** — `barrett_reduce` rewritten with `int32_t` intermediates and one cast proven exhaustively (65,536/65,536 bit-identical) across all five variants, clang's 42 packer findings fixed in the existing explicit-cast style, and the strict-warnings job failing on anything outside the two documented extension classes.
* **Windows runs the real SoftHSM2 token lifecycle** (see *Known limitations* for exactly what that covers); **Linux wheels are re-signed after `auditwheel repair`** so the artefact binds the bytes that ship; **`tools/verify_install_oob.py`** adds a standalone out-of-band verifier; and **the lines-of-code figures are gated on both columns and regenerable** from `git ls-files`, retiring the `find`-based commands that disagreed with the `git` form by 502 lines.

### Completion pass 3 — what the full-diff review actually found

Issue 2 asked for a credible, auditable review of the whole effective change set, because automated review had covered at most 123 of the branch's 183 changed files and its remaining attempts failed on a 300-file limit. Building that review was not the deliverable; running it was. Nine independent subsystem passes over all 183 files, each finding then verified against the code, surfaced **twenty-nine real defects** — several in code the previous pass had just added. All are fixed in this branch. The full record — scope manifest, method, coverage audit and dispositions — is posted as [a comment on this PR](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/pull/394#issuecomment-5308090417). The consequential findings:

| Severity | Finding | Resolution |
|---|---|---|
| critical | `tools/verify_install_oob.py` authenticated the artefact with the public key the artefact **itself carries**, so an attacker with write access to the installed tree — the threat the tool exists to answer — could rewrite the sources, mint a keypair, re-sign, and get `RESULT: PASS` | `--expected-pubkey`, supplied from outside the tree, is compared **before** the signature check; without an anchor the tool exits 2 unless `--allow-unanchored` is passed, which labels the verdict `PASS (UNANCHORED)` and states it establishes internal consistency, not authenticity |
| major | `ama_shake128_inc_squeeze` / `ama_shake256_inc_squeeze` escaped the cross-family guard: a SHAKE128-finalized context squeezed past byte 136 makes `available = 136 − buffer_len` underflow, and the extraction loop reads past the 200-byte Keccak state and off the end of the context into caller-visible output | `sha3_squeeze_pos_ok` on both squeeze paths (the legal squeeze position is `[0, rate]`, not `[0, rate)`), with three regression tests; without the guard the first aborts under UBSan with `index 25 out of bounds for type 'uint64_t [25]'` |
| major | the `AMA_BUILD_PIPELINE=1` repair carve-out excluded nothing — its condition was witnessed by the very row it filtered, so **every** integrity failure qualified, including "Ed25519 signature did NOT verify — module tampered", and a release container carrying the flag could smoke-test a tampered wheel and exit 0 | failures are classified structurally by `integrity_failure_was_stale_binding()`; verified end to end that a byte-flipped signature now exits 1 under the flag while the documented re-signing flow still imports |
| major | the binding-strength downgrade the code documents was never implemented — the `exact` flag was unpacked and discarded — so a developer tree with built-but-uncovered extensions reported `fully_verified: True` over code that had already executed unchecked | new `signed-bindings-unverified` strength, recorded as a SKIP and escalated by `AMA_FIPS_STRICT` |
| major | POST hard-failed on `.pyc` files the interpreter would never load: the validation header was read and discarded, so editing a lazily imported module and re-signing left the tree unimportable until `__pycache__` was cleared by hand — in a stage `AMA_BUILD_PIPELINE=1` does not repair | both the in-tree checker and the out-of-band verifier validate the header the way CPython does (PEP 552), including the unchecked-hash case that **is** always executed |
| major | the strict-warnings gate was red on **every** GitHub-hosted run: its allowlist matched ASCII apostrophes, but `LANG=C.UTF-8` makes GCC quote identifiers with U+2018/U+2019, so the job failed on the exact two classes it exists to permit — and it passed when its log was missing | `LC_ALL=C` pinned on the build step, quote-agnostic patterns (a bracket class does not work: a C-locale grep splits a multibyte quote into bytes), and a missing or empty log now fails the step |
| major | three detector gates measured the host rather than the detector — `shift-detection` failed 7 runs in 30 with nothing wrong, and `sigma-floor-is-live` drew all its separation from the uncalibrated warmup, so a detector that ignored sigma once calibration went live still passed | gates run on deterministic seeded streams (byte-identical across runs), each verified to **fail** under mutation of the property it names; the live-timing measurements are still taken and reported as the evidence |
| major | `benchmarks/baseline.json` asserted that no code the floors describe had changed since they were measured; the Kyber `barrett_reduce` rewrite landed in the very commit that carried that assertion | the claim is corrected, and `check_baseline_justification.py` now verifies it mechanically with `git diff` from the calibration commit; every drifted path is itemised with its reasoning in `metadata.floor_drift_acknowledged` |

Also fixed: a session ID minted outside the health-tested RNG; `ROTATE_AND_SWITCH` spinning the algorithm ladder whenever rotation failed; two silent bypasses of the C zeroization gate (a cast on the destination, an integer suffix on the zero) in the only enforcement INVARIANT-6 has; a `FROM --platform=…` form that skipped Docker pin enforcement; a Kyber test whose printed evidence did not measure the rationale it claimed; a test that tampered with a tracked vector in the working tree; and an HSM workflow assertion satisfiable by deleting the flag it keyed on.

**Documentation claims corrected against measurement, not restated.** The SoftHSM2 lane runs one real-token test, not 51. The C suite was 59 files / 62 translation units at that pass, not the 58 / 61 then published; it is 62 / 65 now. The gated `pqc_backends` surface is what `tools/check_error_state_gating.py` reports — 89 native plus 10 Cython entry points now, 85 at that pass — replacing two documents that disagreed at 80 and 81. The canonical-host tables understate 5.0.0 on the AEAD rows **and overstate it on every keygen row**, which now pay a pairwise consistency test. The published throughput table names the host that actually produced it instead of asserting a canonical bench host it never ran on. `ARCHITECTURE.md` no longer points at the three-line `.github/INVARIANTS.md` pointer as the canonical invariant register, nor says INVARIANT-38. `README.md` states that `v5.0.0` is not tagged yet, so its install commands cannot silently fail.

### Technical Approach

Every behavioural fix is pinned by a test that fails without it, and the negative direction is verified by mutation rather than asserted. The continuous-RNG test was mutation-checked (reverting the lock makes all 8 threads receive the stuck value); the four benchmark-window mutations and both error-state-gating mutations each fail the suite; reverting the `mod 2^d` mask fails `test_kyber_compress` at 989 of 16,645 pairs; reverting the pre-import binding gate lets a byte-flipped extension execute, which the new test catches.

Writing the tests found three defects in the new tooling itself, all fixed before the tools were wired in: the C-zeroization gate crashed rendering out-of-repo paths and tested the root identifier of `ctx->hmac_key` rather than the field; the Docker gate's "an exemption must explain itself" check searched the whole file for `oss-fuzz`/`base-builder`, both of which appear in `FROM gcr.io/oss-fuzz-base/base-builder`, so every exemption explained itself by existing.

Where a fix could not be validated on this hardware, the configuration was reproduced rather than assumed: the SVE2 and NEON work was verified with the same toolchain the CI job uses (aarch64-linux-gnu cross + qemu-user-static) at vq=1, vq=2 and vq=16.

### Breaking Changes

**Breaking Changes:**
- [x] Yes — **ten**, plus twelve behavioural changes

This checkbox said "four", and the paragraph under it said "All eight are
tabulated in `CHANGELOG.md`" while that glance table carried thirteen rows and
now carries twenty-two. Two records disagreeing about how many changes a release
makes is worse than any single row, so the enumeration is no longer duplicated
here. `CHANGELOG.md`'s glance table is the one list, each row with its migration;
this is its index.

**Breaking — rows 1, 2, 3, 7, 14, 15, 16, 17, 18, 21.** In order: POST failure
raises on `import`; Ed25519 rejects `x = 0` with the sign bit set; an unrankable
algorithm raises instead of mapping to the weakest rung; binding extensions are
digest-bound into the v3 artefact; **row 14, below**; `jwk_thumbprint` accepts
six digest names instead of everything `hashlib.new()` knows; `num_derived_keys
< 1` raises; an unrecognised `tsa_mode` raises instead of going ONLINE;
`ama_dispatch_table_t` loses its unread `sha3_256` member; and completing an
import through a repairable POST failure requires the process to BE the
integrity signer rather than to carry `AMA_BUILD_PIPELINE=1`.

**Row 14 is new in the debt-closure pass and is the one to read first — the only
row where the library was ACCEPTING something it should have rejected.**
`ama_ed25519_batch_verify` now rejects a signature whose R half is a
non-canonical point encoding (RFC 8032 §5.1.7 step 1 → §5.1.3), in both backends.
The donna batch path decoded R instead of re-encoding and comparing it, so at
`count >= 4` — where donna leaves its per-entry fallback for the multi-scalar
routine — it reported VALID for a signature `ama_ed25519_verify` REJECTS. Two
verifiers in one library disagreed on one input, and producing such a signature
needs the signer's own key and no forgery. Migration: none for conformant
callers; a caller that batch-verified attacker-supplied signatures should
re-check anything it accepted at `count >= 4`.

**Behavioural — rows 4, 5, 6, 8, 9, 10, 11, 12, 13, 19, 20, 22:** the same
answer, different work, timing or failure mode. Rows 19 and 20 are the install
fixes — `pip install .` now signs and binds the extensions it ships, and
`integrity --update --sign` binds what it repairs.
For C consumers of the installed shared library: the SONAME follows the major version, so it moves `.so.4` → `.so.5` and existing binaries must be relinked. No C API signature changed.

## Testing

### Test Coverage

- [x] Unit tests added/updated
- [x] Integration tests added/updated
- [x] Test coverage maintained or improved
- [x] All tests pass locally

Added, beyond the audit's own tests: `tests/c/test_kyber_compress.c` (exhaustive `Compress_d` equivalence, 16,645 pairs), `tests/test_update_docs_changelog_guard.py` (29 cases, including the platform-independent text-I/O gate), the `dudect_rounds.h` verdict-classification self-tests (10 new cases including the exact observed FROST shape), the pre-import binding-gate tests in `tests/test_preload_native_digest.py`, the family-ladder tests in `tests/test_adaptive_posture.py`, the expression-syntax gate tests in `tests/test_workflow_command_checks.py`, the SoftHSM2 availability and provisioning tests in `tests/test_hsm_integration.py`, the semgrep console-script probe tests in `tests/test_semgrep_severity_gate.py`, `tests/test_acvp_harness_library_discovery.py` (12 cases, none of which names a SONAME major), and the provenance/invocation tests in `tests/test_benchmark_baseline_infra.py`.

The suite is **4,542 static test functions across 189 files** at the current head, of which **6,125** execute in the default configuration. `docs/METRICS_REPORT.md`, `README.md` and `ARCHITECTURE.md` are re-measured to match, and the documented-counts gate checks all 66 claims, on both columns of every lines-of-code row as well as the counts.

### Testing Performed

**Environment:**
- Python version(s): 3.11.15
- Operating System: Ubuntu 24.04 (x86-64); aarch64 via cross-compile + QEMU user-mode; macOS 15 (arm64 + x86-64) and Windows Server via the release dry run
- PQC backend: [x] Native C library

**Executed against the final branch state:**

| Lane | Result |
|---|---|
| Python suite | 6,125 passed / 49 skipped / 0 failed at `c694bc5` (this environment — see note below the table) |
| C suite, x86-64 | 67/67 at `c694bc5`; 69/69 on the fe51 backend build |
| C suite, aarch64 + SVE2 at VL=128, 256, 2048 | 64/64 at each |
| C suite under ASan+UBSan (`-fno-sanitize-recover=all`) | 67/67 at `c694bc5`, instrumentation confirmed by `nm -D` |
| MemorySanitizer (clang-18) | 67/67, clean — re-run at `c694bc5` |
| ThreadSanitizer | 67/67, clean — re-run at `c694bc5` |
| Valgrind memcheck (CI subset) | 6/6, `ERROR SUMMARY: 0 errors` each — re-run at `c694bc5` |
| `static-analysis.yml` MSan/TSan/Valgrind matrix | last dispatch `75f2bbc` — **stale**; superseded by the `6c40102` re-runs. |
| `dudect.yml` SIMD sweep | last dispatch `75f2bbc` — **stale**; re-run at `6c40102` (27 lanes PASS). |
| dudect, 100K and 1M iterations | no leakage; 27 lanes, including the two new forgery-position lanes |
| Detector efficacy gates | green and **deterministic** — byte-identical across repeated runs, each verified to fail under mutation of the property it names |
| dudect SIMD sweep | green on every slot that **executed** — not "all slots": the two `sve2` slots never ran (sweep omitted `-DAMA_ENABLE_SVE2=ON`, so cells exited 77). Fixed; `chacha20-neon`, which surfaced C6, ran. |
| `mypy --strict` (full CI arg list) | clean — 234 files at `6c40102`, **303 at the current head** |
| black / ruff / documented counts (62 then, **66 now**) / hygiene gates | clean |
| libFuzzer, 15 entry points under ASan | clean against a genuinely instrumented library |
| Python key-parser fuzz campaign | executes (it could not import the package before this release) |
| SoftHSM2 / PKCS#11 | the suite's one real-token test (`test_full_lifecycle`) executes on Linux, macOS **and Windows**, instead of skipping everywhere; the other 53 tests in that file are mock-driven and always ran |
| Release dry run (`release.yml`) | green end to end: preflight, sdist, cibuildwheel on ubuntu-latest / ubuntu-24.04-arm / macos-15 / macos-15-intel / windows-latest, Sigstore signing, SLSA provenance |
| ARM QEMU cross-test | executes for the first time; SVE2 at each declared vector length |
| ACVP vector validation | 1,215/1,215 |
| Full PR check set | red at `7b6e2f2`: `mypy --strict` rejected `pb.sys` in this branch's new tests, failing Code Quality/Lint and five gates. Fixed in `6c40102`; Code Quality re-run on the pinned toolchain, exit 0. |

The skips in CI are the optional interop comparators and network-gated corpora (pycryptodome, pynacl, live TSA, a CI-only HSM assertion, network-gated Wycheproof); the suite was re-run with `AMA_CI_REQUIRE_BACKENDS=1` to confirm the imperative-skip escalation produces no false positives against them.

**On the environment for the pass-3 figures:** completion pass 3's verification ran in this branch's Linux build container, not on the CI matrix. Its 71 skips are the environment-gated lanes that container cannot run (HSM token, docker daemon, optional interop comparators, network corpora, and the tests requiring a native library inside the package directory rather than `build/lib`). Every number in this table that is attributed to that run is stated as measured there; the CI matrix is what exercises the platform lanes.

### Known Test Vectors

- [x] Tested against official NIST test vectors
- [x] Tested against IETF RFC test vectors

FIPS 203/204/205 KATs and the vendored ACVP and Wycheproof corpora all pass unchanged, which is the operative check on the ML-KEM compression rewrite and the NEON key-schedule rewrite.

## Code Quality

### Code Quality Checks

- [x] Code follows PEP 8 style guidelines
- [x] All functions have type hints
- [x] All functions have comprehensive docstrings
- [x] No security warnings from linters (Bandit, etc.)
- [x] Black formatting applied (`black .`)
- [x] Ruff linting passed (`ruff check .`)
- [x] Type checking passed (`mypy --strict`)

`mypy --strict` over the CI scope is **clean over 303 files** at the current head (the invocation adds `tools/` gate scripts and the gated `benchmarks/` entry points; `tools/verify_install_oob.py` and `tools/resign_wheel.py` were added to it in completion pass 3, since a security tool outside the type gate is a security tool nobody checks). The first revision of this description recorded 15 pre-existing errors; those were missing `types-PyYAML` stubs and `no-any-return` returns, and they are fixed here rather than carried — further strict errors introduced by this branch's own new code were fixed rather than suppressed.

### Documentation Updates

- [x] README.md updated
- [x] SECURITY.md updated
- [x] CHANGELOG.md updated
- [x] Inline code comments added for complex logic

`CHANGELOG.md` carries the full 5.0.0 section, including the breaking-changes glance table. (The first revision of this description said the file was "deliberately not touched"; that is no longer true and the statement is withdrawn.) `ARCHITECTURE.md`, `SECURITY.md`, `wiki/Security-Model.md`, `wiki/Performance-Benchmarks.md` and `docs/METRICS_REPORT.md` are updated to the final branch state.

## Backwards Compatibility

### Compatibility Assessment

- [x] Breaking changes documented (see the table above and `CHANGELOG.md`)

Every breaking change is a fail-closed correction: a silent weakness becomes a loud refusal. None is a capability removal, and none changes a wire format, a key format or a C API signature.

## Performance Impact

### Performance Analysis

**Impact:**
- [x] Performance improvement

The ML-KEM compression replaces a divide with a fixed-latency 64-bit multiply on every compression call. The NEON AES-256 key schedule drops from 880 to 137 instructions (7.3x faster than the pre-PR code, and 38x faster than the intermediate scrubbed version this PR briefly introduced), once per AES-GCM call on AArch64. The AVX2 change removes auto-vectorisation from generically-dispatched translation units — this is the intended trade: those paths run on CPUs that cannot execute the instructions at all, and the hand-written per-file kernels the dispatcher selects on capable hardware are untouched. The Python one-shot AEAD wrappers regain the throughput the buffer-borrow hardening had cost.

Both regression baselines were recalibrated from the repaired harness (floors are measured medians, tolerances derived), and `check_baseline_justification.py` now refuses to let a validity window move unless a floor was actually re-measured — closing the hole that made "declare the stale floors valid for longer" the cheapest way to satisfy the freshness test. Completion pass 3 closed the remaining half of that hole: the gate had accepted a second hand-edited metadata string as proof, so it now checks with `git diff` from the recorded calibration commit that no code the floors describe has changed, and requires any drift to be itemised with a reason.

## Deployment Considerations

### Deployment Impact

- [x] Relink required for C consumers (SONAME `.so.4` → `.so.5`)

Container images now build `FROM` digest-pinned bases, and the Alpine image moves from `alpine:3.18` (end-of-support 2025-05-09) to `alpine:3.23` (supported to 2027-11-01).

### New Dependencies

**Added Dependencies:**
- None at runtime. `softhsm2` and `PyKCS11` are installed by CI for the `[hsm]` extra, which already existed and was already declared.

**Justification:**
- `tools/check_c_secret_zeroization.py`, `tools/check_docker_pins.py` and the new `check_expression_syntax()` pass are hand-written and use only the standard library, consistent with the project's no-external-dependencies posture.

## Checklist

### Pre-Submission Checklist

- [x] I have read the Contributing Guidelines
- [x] I have read the Code of Conduct
- [x] My code follows the project's coding standards
- [x] I have performed a self-review of my own code
- [x] I have commented my code, particularly in hard-to-understand areas
- [x] I have updated the documentation accordingly
- [x] My changes generate no new warnings
- [x] I have added tests that prove my fix is effective
- [x] New and existing unit tests pass locally with my changes

### Cryptographic Changes Checklist

- [x] Cryptographic changes are backed by academic research
- [x] All cryptographic claims have mathematical proofs or citations
- [x] Standards compliance has been verified
- [x] Security analysis has been performed
- [x] Constant-time operations maintained where required
- [x] No timing side-channels introduced
- [x] Entropy sources are cryptographically secure

### Security Checklist

- [x] No secrets or credentials in code
- [x] No information leakage in error messages
- [x] Input validation is comprehensive
- [x] Error handling does not reveal implementation details
- [x] No integer overflow vulnerabilities
- [x] Memory safety verified for buffer operations

## Additional Context

### Items from earlier revisions of this description that are now resolved

The first revision listed six findings as "found but not fixed" and four questions for reviewers; the second listed the benchmark floors and the binding extensions as known remaining items. **All are now closed in this branch:**

- **Fuzz instrumentation** — a dedicated instrumented target gives libFuzzer real coverage feedback; per-target block coverage measured at 115–10,237, previously none.
- **SLH-DSA ACVP corpora could skip** — the three vector files are tracked in git, so a missing corpus means it was deleted or truncated, which is exactly when a skip is worst. Now failures.
- **Imperative skips bypassed CI backend escalation** — the hook now also reads the reason pytest recorded on the report.
- **`check_error_state_gating` ordering and aliasing** — both closed.
- **`check_ctypes_abi` scope** — discovered from the package's ASTs with the old list as a floor beneath it; coverage went from 89 to 131 signatures, all matching the header.
- **Docker base images** — digest-pinned, `alpine:3.18` replaced, enforced by a gate that fails 60 days before a declared end-of-support date.
- **The benchmark floors** — recalibrated from the repaired harness and re-measured against the completed branch state, with provenance recorded in both published records (C7).
- **The binding extensions** — digest-bound into the v3 artefact and refused before import (C1).
- **All four reviewer questions** — resolved by analysis and implementation (C4).
- **The 3R detector's missing baseline comparison** — measured, committed and gated (Completion pass 2); the result is reported as measured, including where a trivial baseline matches it.
- **Review coverage of the branch** — the full 183-file effective diff has been independently reviewed and the twenty-nine defects it found are fixed (Completion pass 3).

### Known limitations, stated rather than left implicit

- **The real-token PKCS#11 lane is one test, on three platforms.** The claim that SoftHSM2 "has no maintained package on any Windows runner manager" was checked and is false — Chocolatey's `softhsm.install` 2.5.0 (Disig MSI) — so Windows now provisions a real token alongside Linux and macOS. What that buys is precise and worth stating precisely: `TestSoftHSMIntegration::test_full_lifecycle` is the **one** test in the tree that drives a real token (keygen, sign, verify, delete), and it now executes on all three platforms instead of skipping everywhere. The other 53 tests in that file exercise the PKCS#11 wrapper against mocks and always ran. An earlier revision of this description said 51 tests execute against a real token; that was wrong and is withdrawn.
- **The canonical-host performance tables in `README.md` are 4.x-era measurements.** They carry the host and date they were taken on and state which rows 5.0.0 superseded. Re-measuring needs hardware not reachable from CI (see *Remaining actions*).
- **The 3R detector's measured envelope is published, including where a trivial baseline matches it.** The comparison against trivial baselines that an earlier revision said did not exist now exists, is committed (`benchmarks/detector_baseline_eval.py`), and gates in CI. Measured: at a matched alarm budget a top-N KNN oracle ranks isolated spikes about as well as the calibrated point path (mean F1 ratio 0.95–0.99 on the deterministic gate streams, 0.65–1.12 across runs on live host timings) — while needing the shipped detector's own alarm count as an oracle to run at all. What the machinery earns is the calibrated false-alarm budget, the two-stage severity contract and the sustained-shift event path; the shift-stream F1 gaps are inside the file's own tie band and are not claimed as an advantage. `MONITORING.md` carries the same numbers.

### Remaining actions, and why they cannot be performed here

Each requires the repository owner's protected identity, authorization, or hardware. Every prerequisite has been prepared and validated in this branch:

1. **A qualified human cryptographic review of this diff.** All commits machine-authored, all reviews to date bots. Blocking.
2. **Re-run the platform lanes at `c694bc5`** (AArch64/QEMU incl. SVE2 VLs, macOS, Windows, SVE2 dudect slots).
3. **Merge approval on this pull request.** Requires the owner's review.
4. **The signed annotated `v5.0.0` tag.** `release.yml`'s preflight requires an annotated, signed tag (INVARIANT-10) and validates that it matches `pyproject.toml`; the dry run exercised that job with tag verification skipped, and everything downstream of it — sdist, all five cibuildwheel platforms, Sigstore signing, SLSA provenance, and the binding-digest checks — passed. Creating the tag requires the owner's signing key. The `CHANGELOG.md` heading is deliberately `## [5.0.0] - Unreleased` and is replaced with the real date at tag time, which a test enforces.
5. **Publication to PyPI** and the associated attestation upload, which run under the protected `release` environment and the owner's publication permissions.
6. **Re-measuring the canonical-host performance tables** on the canonical bench host (AVX-512 + VAES + VPCLMULQDQ, Sapphire Rapids / Zen 4 class), which is not reachable from CI or this build environment. The README now states row by row that the published figures are 4.x-era, that the AEAD rows understate this release and the keygen rows overstate it, and that no 5.0.0 canonical measurement exists.
7. **Re-running the release dry run.** `release.yml` changed after the dry run recorded in C5 — the Linux repair step now chains `tools/resign_wheel.py` — so the run must be repeated to exercise that path before tagging. It needs only a workflow dispatch; everything it consumes is in the branch.
8. **Re-measuring the x86 and aarch64 regression floors on their canonical runner classes.** The floors carried into 5.0.0 were measured before the Kyber `barrett_reduce` rewrite, which is an NTT inner-loop function; the drift is now itemised in `metadata.floor_drift_acknowledged` and enforced by `check_baseline_justification.py`, and the benchmark-regression jobs on this PR are what actually exercise it. A floor breach there means re-measure, not extend the window.

Nothing in items 1–8 is blocked by a technical defect found in this branch.

---

**By submitting this pull request, I confirm that my contribution is made under the terms of the Apache License 2.0.**

Copyright (C) 2025-2026 Steel Security Advisors LLC

🤖 Generated with [Claude Code](https://claude.com/claude-code)