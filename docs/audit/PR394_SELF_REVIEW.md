<!-- Copyright (C) 2025-2026 Steel Security Advisors LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# PR #394 readiness falsification — §16 adversarial self-review

A second pass whose job is to defeat the first. Ledger ids refer to
`docs/audit/ledger.tsv`; logs are under `docs/audit/logs/`.

## 1. Ten highest-confidence "verified" claims, each attacked

| # | Claim I am most confident of | The case in which it is wrong | Outcome |
|---|---|---|---|
| 1 | The full C suite is clean under ASan+UBSan, MSan, TSan, and on AArch64 (FINDING-0001 closed) | The sanitizer lanes ran locally, not on the CI image; a CI-only environment difference (older clang, different libc) could reproduce the hang. Also: the scan now reads only *resident* pages, so a sentinel on a swapped-out page would be missed. | Local lanes replicate the CI recipes byte-for-byte (`PR394_CAPABILITIES.md`); CI runners have no swap; the negative mode proves detection on every lane. Residual: a future CI image change. **Stands, with the swap caveat recorded in FINDING-0001.** |
| 2 | `check_keygen_pct.py` now fails when any arm of a family dispatch loses its pairwise test (FINDING-0003) | An `if` without `else` whose fall-through releases the keypair untested is still invisible; so is a dispatch through a dictionary of callables or a two-hop delegation. | Both limits are stated in the gate's docstring and pinned as tests (`test_an_if_without_else_opens_no_comparison`, `test_two_levels_of_delegation_are_not_followed`). **Constructible — and therefore recorded as an explicit uncovered shape, not a verified one.** |
| 3 | The independence proof: the shipped library and bindings link nothing but libc (F-01..F-09, Linux x86-64 and the AArch64 cross build) | macOS and Windows wheels are built by cibuildwheel with delocate/delvewheel, which can graft a system library into the wheel; nothing here inspects those artefacts. | **Constructible.** Linux artefacts are proven; macOS/Windows are covered only by the release dry run's own checks (release.yml's MACOS block re-signs after delocate). Recorded as a subset in §2 below. |
| 4 | The dudect harness can return positive (D-DUDECT-POS-01b, -02b: FAIL verdicts at |t| 342 and 753) | A positive control that is *too* obvious proves little about a subtle leak; the harness's sensitivity floor was not measured with a small injected effect. | **Partly constructible.** The ML-DSA sign lane's INFO detection (|t| 1588 on a by-design dependency) and the 0.2 ns systematic-effect calibration in `check_dudect_class_staging.py`'s docstring are the only sensitivity evidence; a graded injection series (1, 5, 20 ns) was not run. Listed under §3 things most likely wrong. |
| 5 | No division instruction takes a secret operand at any shipped optimisation level (E-ASM census, 3 compilers x 5 levels) | The census attributes instructions to the nearest preceding label; an inlined callee's division is charged to the caller, and I read the source of each flagged function by hand. A misread of one dividend's provenance would pass a secret division. | Every non-trivial site was mapped to its source line (`.loc` of gcc -O2 -g: dilithium 1640, lms 190/191/207, nistp 1034) and each dividend is a counter, length, or table index. **Stands; the residual is the hand-reading.** |
| 6 | ACVP: 1,215/1,215 reproduced here, and the denominator is 6,608 fetched tcIds with 5,789 skips accounted (FINDING-0006) | The fetch pins an ACVP-Server ref; if that ref were a stale subset of NIST's current vectors, "complete corpus" would be false in a way this audit cannot see offline. | The ref is pinned by `acvp_validation.yml` with a runbook for bumping it; upstream drift is not checked here. **Constructible; recorded as unverifiable-offline in the claims ledger.** |
| 7 | Every negative control in `PR394_NEGATIVE_CONTROLS.tsv` shows its gate failing on a violation and passing clean | The driver's first full run reverted the auditor's own working-tree edits via `git checkout` (README, ci.yml) — a control that damages the thing under test. Fixed by snapshot/restore and proven on NC-18 with an uncommitted edit. A control can also pass for the wrong reason (the violation fails the gate on a *different* rule than intended). | The verdict logs are retained per control; the diagnostic text was read for each first-time failure. **The damage case happened and is recorded; the wrong-rule case was checked by reading, not by tooling.** |
| 8 | The 3R monitor's efficacy numbers (FINDING-0005) | One trace, one host, under load from concurrent sweeps; the monitor's `window_size`/threshold defaults may be tuned for a different operation cadence; the baseline's window (100) was chosen to match. | Rates will move on another host; the README states the conditions and the test pins prose to table, not to a floor. **Stands as a measurement with stated conditions; not as a universal rate.** |
| 9 | The fail-open sweep's 146 sites are all triaged fail-closed, documented-knob, degrade-logged, operational or not-security | The sweep is AST-shape based; a fail-open path written as `except X: result = default` (assignment rather than return/pass/log) is not in its classes. | **Constructible.** The sweep's class list is its scope; a broader dataflow sweep was not run. Recorded as a subset. |
| 10 | The mutation kill rates (keygen gate 92.7 %, dudect gate 84.2 %, workflow gate 62.7 %, error-state gate 60.9 %, hybrid combiner 68.8 %) | Kill counts include kills by the gate's *self-run* on the real tree, which is a CI-equivalent oracle but not a unit test; and the survivor disposition for the two largest runs (176 and 90 survivors) was classified by operator, not read one by one. | Self-run kills are reported in their own column (`self_run_rc`) so the reader can separate them. **Survivor reading is incomplete for two targets — stated in `PR394_MUTATION.tsv` and §3.** |

## 2. Subsets accepted as representative

| Where | The subset | The uncovered risk |
|---|---|---|
| Independence proof | Linux x86-64 shared library and bindings; AArch64 cross-built library | macOS and Windows wheels (delocate/delvewheel grafting) — release.yml's own artefact checks are the only control |
| Valgrind | 47 of 76 CTest cases executed; 29 skipped because Valgrind's synthetic CPU lacks the ISA the dispatch-only / equivalence tests force (`AMA_DISPATCH_ONLY` unsupported → exit 77) | Memory errors in the AVX2/AVX-512/NEON/SVE2 kernels are covered by ASan/MSan lanes only, not by Valgrind |
| Fuzz depth | a one-minute budget per target, one seed corpus, one host; four targets under 10k executions at CI's Debug build (sphincs 20, frost 515, dilithium 1,748, argon2 1,961) | Those four targets' fuzz coverage claim rests on the seed corpus, not on exploration. The -O2 -g build measured here (`PR394_FUZZ_DEPTH_O2G.tsv`) is the proposed remedy |
| Mutation testing | Five targets (three gates, the error-state gate, the hybrid combiner); `ama_cryptography/` beyond the combiner not mutated (each mutant needs a re-sign; the driver supports it, time did not) | Test strength for the rest of the Python package is unmeasured |
| Claims ledger | 1,815 claims extracted from 12 of 137 input chunks; 125 chunks not extracted (the sub-agent fan-out was withdrawn after it exhausted the account's session limit) | Claims in the un-extracted chunks were not reproduced; the attestation counts them as unverifiable, not as confirmed |
| dudect | 100,000 measurements on a loaded host; SVE2 lanes impossible here (no silicon); VAES lane impossible after the CPU change | Timing evidence for SVE2 and VAES kernels is CI-only or absent |
| Fail-open sweep | Five AST shapes | Dataflow-shaped fail-open paths |
| Coverage ledger | Execution evidence is derived by path class from ledger ids, not per-file instrumentation | A file inside a covered class that no lane actually compiles or imports would still read as executed |

## 3. Numbers in the report I did not produce this session

Removed or reproduced, per the rule: every figure in `PR394_ATTESTATION.md`,
`PR394_EXCEPTIONS.md`, `PR394_ACCEPTANCE.tsv` and this file is either a
ledger row from this session or an explicitly attributed quotation from the
pull request description (marked "PR description says"). The PR
description's own figures (67/67, 6,125 passed, 3,783 differential cases,
27 dudect lanes) are NOT restated as verified; where this session
re-measured (76 CTest cases, 26 dudect lanes PASS + 1 INFO, 3,912
Wycheproof, 1,215 ACVP) the re-measured number is the one used.

## 4. Coincidences found (each MAJOR at minimum by the mandate's rule)

| Coincidence | Where | Disposition |
|---|---|---|
| The scrub inspector's negative control held on x86-64 only because glibc placed the scanner's `FILE` buffer away from the freed sentinel | `tests/c/test_secure_free_scrub.c` | FINDING-0002, closed (allocation-free scanner, registered on every lane) |
| `check_keygen_pct.py` passed only because the polymorphic helper happened to call *some* pairwise test in *some* arm | `tools/check_keygen_pct.py` | FINDING-0003, closed |
| The VAES equivalence test ran natively during Phase A only because the VM happened to sit on a Sapphire Rapids host at the time | `test_aes_gcm_vaes_equiv`, A-23/A-25 | Recorded in `PR394_CAPABILITIES.md`; §10 row 4 (unconfigured, not unreachable) |
| The negative-control driver did not destroy committed work only because the auditor's edits had not yet been committed when they were reverted — and they were reverted | `docs/audit/negative_controls.py` | Fixed (snapshot/restore), proven on NC-18 |
| `_declared_length_fits` returns True for a raw pointer — correct today because every caller passes a sized ctypes array | `ama_cryptography/pqc_backends.py:3221` | Documented contract; triaged in `PR394_FAILOPEN_SWEEP.tsv`; not changed (a refusal would break the ctypes borrow policy). Listed here because it is the Compress_d shape: correct output, contract that depends on callers |

## 5. What a hostile reviewer with three days would look for next

1. The macOS/Windows wheel contents (§2 row 1) — `otool -L` / `dumpbin` on
   the dry-run artefacts, which this audit could not download.
2. A graded dudect injection series to put a number on the harness's
   detection floor (§1 row 4).
3. The 176 surviving workflow-gate mutants read one by one; the `continue ->
   break` class (27) is where a second offender in one file would go
   unreported.
4. Windows PKCS#11 (§10 row 5) — the lane this audit argued for and did not
   build.
5. The 125 un-extracted claim chunks.
