<!-- Copyright (C) 2025-2026 Steel Security Advisors LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# PR #394 readiness falsification — §10 exception adjudication

The mandate's rule: an item may remain unresolved only when resolution is
prevented by physics, non-existent hardware, absent authority, a non-existent
external system, or approved scope. Each row below records the claimed
blocker, the evidence gathered in this audit, the verdict, and — where the
exception stands — the residual risk, the exact closure condition, and the
owner action that closes it. Ledger ids refer to `docs/audit/ledger.tsv`;
every cited log is under `docs/audit/logs/`.

| # | Item | Claimed blocker | Verdict |
|---|---|---|---|
| 1 | Merge approval | Owner authority | **Valid exception** (absent authority), with the technical side cleared below |
| 2 | Signed v5.0.0 tag | Owner signing key | **Valid exception for creation**; verification is proven here |
| 3 | PyPI publication | Owner credentials | **Valid exception for publication**; the upstream steps are exercised by the release dry run, which is currently **stale** (see row) |
| 4 | Canonical-host benchmark tables | AVX-512/VAES/VPCLMULQDQ silicon unreachable | **Exception fails as stated**: the silicon is reachable in this cloud environment (it was present for Phase A of this very session); it is unconfigured, not unreachable |
| 5 | Windows PKCS#11 coverage | No maintained SoftHSM2 Windows package | **Exception fails as stated**: a Windows SoftHSM2 build path and pre-built packages exist; re-classified as approved scope (a new platform lane is not in this audit's change budget) |
| 6 | README 4.x-era performance tables | Same silicon | **Exception fails as stated** (same as row 4); the labelling and gate-independence halves are **verified** |
| 7 | 3R monitoring detection efficacy | none stated | **Measured** — FINDING-0005, closed by calibrating the claim |

## 1. Merge approval

*Blocker.* Only the repository owner can approve and merge; branch protection
reports `mergeable_state: blocked` on the pull request.

*Technical side: clear.* At the head this audit started from (`be1af0f`) the
Python test jobs were red on every platform (check runs of 2026-09-02
03:32–04:09 UTC: 24 `Python x.y on <os>` / `Test <os> / Python x.y`
failures; C, fuzz, dudect, ARM, static-analysis, security and provenance
gates green). The cause was the audit's own first commit (documented in
`PR394_CAPABILITIES.md`, session 1 defects) and was fixed in `ef0fcc8`.

At the attested head `d1800bf` **every repository workflow is green**:

| Workflow | Run | Conclusion |
|---|---|---|
| CI - Testing and Code Quality | 33667338639 | success |
| CI - Build and Test | 33667338515 | success |
| CI - Static Analysis (C Code) | 33667338514 | success |
| CI - Fuzzing (libFuzzer) | 33667338483 | success |
| CI - dudect Constant-Time Verification | 33667338323 | success |
| ARM (QEMU) Cross-Test | 33667338628 | success |
| ACVP Vector Validation | 33667338430 | success |
| Vendored Corpus Provenance | 33667338544 | success |
| Security Scanning | 33667338458 | success |
| Integrity anchor check | 33667338399 | success |
| Baseline Change Guard | 33667338394 | success |

The twelfth run on that head, "Running Copilot Code Review" (33667353537),
is GitHub's own reviewer app rather than a repository gate; it reports
`cancelled` here as it did on the pre-audit head.

Three genuine failures surfaced on the audit's own commits between the first
push and this state, each fixed with its evidence: the documented
line-of-code table going stale after a docs edit (`a8f15a1`), two CodeQL
alerts on the audit drivers (`da493ea`, alerts 654 and 655), and
`Test windows-latest / Python 3.14` cancelled at its 20-minute cap with no
test failure (`d1800bf`; the overrun is 4.2 minutes of Windows setup, and
the leg only reached the later steps once the suite stopped failing early).
Every other failure event on this branch during the audit was a run
superseded by a later push — `cancel-in-progress` — verified in each job log
by its `Dependency results: ... cancelled` line.

The pull request reports `mergeable_state: blocked` with those checks green,
which is the approving review, not a technical obstacle.

*Residual risk.* None beyond the owner's review.  *Closure.* Owner approves
and merges.  *Owner action.* Review and merge.

## 2. Signed v5.0.0 tag

*Blocker.* Creating the tag requires the owner's signing key — a valid
absent-authority exception for creation.

*What is testable here, and was tested.* The preflight's refusal of an
unsigned, lightweight or mismatched tag:

| Control | Evidence |
|---|---|
| `tools/check_release_tag.py` refuses a lightweight tag | negative control NC-35 (`phaseD/NC-35-violated.log`, exit 1; clean exit 0) |
| refuses an annotated but unsigned tag | NC-35b (`phaseD/NC-35b-violated.log`, exit 1) |
| refuses a tag whose version does not match `pyproject.toml` | release.yml preflight step "Resolve tag → version (must match pyproject.toml)", exercised by the 23 recorded dry-run dispatches (run 33338946996 at `32c3e0de`, success) |
| refuses an unanchored release from the canonical repository | preflight step H3; the trust-store gate `tools/check_release_state.py` (NC-21, exit 1 when docs flip to "released" without the anchor) |

*Residual risk.* A signed tag made with a key that is not the one the trust
store pins would be refused by the same preflight; a signed tag with the
pinned key on the wrong commit would pass the tag check and fail the
version/docs checks only if those differ.  *Closure.* The owner tags
`v5.0.0` with the pinned key.  *Owner action.* `git tag -s v5.0.0` on the
merged head, after the dry run in row 3 is green on the same file set.

## 3. PyPI publication

*Blocker.* Trusted Publishing runs under the `release` environment's
credentials — a valid absent-authority exception for the publish step
itself.

*Upstream of publication.* `release.yml` exercises, in a `workflow_dispatch`
dry run (`dry_run: true`), every job before `publish-pypi`: preflight
(tag/version/anchor/docs/SBOM), `verify-anchor`, `build-wheels`
(cibuildwheel on the five platforms, with the AMA_BUILD_PIPELINE post-build
signer and the wheel smoke test), `build-sdist` (install-from-source smoke
test), `hash-artefacts` (base64 subjects — the attestation upload shape),
`provenance`, and `sign` (sigstore bundle).  The last green dry run is run
33338946996 at `32c3e0de` (2026-08-30).

*Finding, and its closure.* The workflow's own runbook names the file set
whose change invalidates a recorded dry run (`setup.py`, `_build_sign.py`,
`tools/resign_wheel.py`, `tools/wheel_smoke_test.py`,
`tools/check_release_tag.py`, the workflow itself).  Three commits after
`32c3e0de` touch that set (`17e5d79`, `ce4930f`, `c0e0135`), so the recorded
dry run was stale for this head.

**A dry run was dispatched at the attested head and is green.**  Run
[33716963848](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/actions/runs/33716963848),
`workflow_dispatch` with `dry_run: true` on `steel/systempqc-maint1` at
`990a248`, 2026-09-03 04:57:55Z → 05:11:55Z, conclusion **success**.
Sixteen jobs: thirteen succeeded and three were skipped, and the three
skipped are exactly the ones that publish —

| Job | Result |
|---|---|
| Preflight (tag + version + SBOM coherence) | success |
| Verify the integrity trust anchor pair | success |
| Build sdist (install-from-source smoke test) | success |
| cibuildwheel ubuntu-latest / ubuntu-24.04-arm / macos-15 / macos-15-intel / windows-latest | success (5) |
| Hash artefacts for SLSA subject set | success |
| Sigstore sign (wheels + sdist) | success |
| SLSA v1 provenance — detect-env / generator / final | success (3) |
| SLSA provenance — upload-assets | skipped |
| **Publish to PyPI (Trusted Publishing)** | **skipped** |
| **Create GitHub Release** | **skipped** |

The two publishing jobs are structurally unreachable from a dispatch, not
merely flag-gated: each requires `github.event_name == 'push'` **and**
`startsWith(github.ref, 'refs/tags/v')`, and a `workflow_dispatch` on a
branch satisfies neither whatever `dry_run` is set to.  That is why the
dispatch was safe to make without the owner's credentials, and it is what
the skipped rows above show.  So release prerequisite 4 of the PR
description — "re-run of the release dry run", open because `setup.py` and
`tools/wheel_smoke_test.py` changed after run 31988592972 — is **closed at
this head**.

*Residual risk.* The dry run cannot exercise the `publish-pypi` job's
credential exchange; a Trusted Publishing misconfiguration would surface
only at the real release.  It also does not re-run automatically: a commit
after `990a248` touching the runbook's file set makes run 33716963848 stale
in exactly the way it made 33338946996 stale.  *Closure.* This run, plus a
re-dispatch at the tagged commit if that file set moves again, then the
owner's publish.  *Owner action.* Publish under the `release` environment.

## 4. Canonical-host benchmark tables

*Claimed blocker.* "AVX-512 / VAES / VPCLMULQDQ silicon unreachable".

*Evidence.* This session's own host had `vaes vpclmulqdq gfni sha_ni` in
`/proc/cpuinfo` during Phase A (ledger A-23, `phaseA/hw-flags.log`) and
lost them when the VM was moved to a different CPU model later in the
session (A-25, `phaseA/hw-flags-reprobe.log`; `PR394_CAPABILITIES.md`
"Hardware present and absent").  A third probe on the resumed session
(ledger R-01, `phaseR/hw-flags-reprobe-3.log`, 2026-09-03 04:58Z) reports
the same absence: `avx512f`, `avx512vl`, `avx512dq`, `avx512bw`, `aes` and
`pclmulqdq` present; `vaes`, `vpclmulqdq`, `gfni`, `sha_ni` and
`avx512ifma` absent.  Three observations, one with the silicon and two
without: the pool can place the VM on it, and nothing in this session's
control decides that it does.  GitHub's hosted x86-64 runners are
Cascade-Lake class (the CI benchmark job records `avx512f` but no `vaes`),
and the repository has no larger-runner or self-hosted configuration.  So
the silicon is reachable in the cloud (this session sat on it) but not by
any configured workflow: **unconfigured, not unreachable**.

*Verdict.* Not a hardware exception.  It is a **scope** item: configuring a
runner class that carries the silicon is a repository-settings decision
(a larger runner or a self-hosted label) with a cost, which is the owner's
to make.  *Residual risk.* The README's canonical-host tables stay 4.x-era
until then; the labelling is verified in row 6 so no reader is misled.
*Closure.* A benchmark run of `benchmarks/benchmark_suite.py` on a runner
with `vaes vpclmulqdq`, and the tables regenerated from it.  *Owner
action.* Provision the runner class (or pin the audit VM class that had the
silicon) and dispatch the benchmark workflow there.

## 5. Windows PKCS#11 coverage

*Claimed blocker.* "No maintained SoftHSM2 Windows package".

*Evidence.* Upstream SoftHSMv2 documents a Windows build with CMake and the
vcpkg toolchain (vcpkg is preinstalled on GitHub's Windows runners), and
pre-built Windows packages exist (disig/SoftHSM2-for-Windows releases; the
OpenDNSSEC installer).  `HSMKeyStorage` takes `library_path` as a
constructor argument, so a Windows lane needs no library change — only the
DLL path and a `SOFTHSM2_CONF`.  Sources:
https://github.com/softhsm/softHSMv2 ,
https://deepwiki.com/softhsm/SoftHSMv2/7.3-building-on-windows ,
https://github.com/disig/SoftHSM2-for-Windows/blob/master/BUILDING.md .

*Verdict.* The stated blocker is false: a PKCS#11 soft token exists for
Windows runners.  What remains is a new CI lane (a vcpkg build or a
pinned-package download of SoftHSM2 on `windows-latest`, then
`tests/test_hsm_integration.py` against it) — work this audit did not
undertake because it adds a platform lane rather than verifying an existing
control, and because it cannot be validated from this Linux host without a
dispatch-and-iterate cycle on the Windows runner.  Re-classified as
**approved scope**, not "no package exists".  *Residual risk.* The PKCS#11
code paths are exercised on Linux only (SoftHSM2 at
`/usr/lib/softhsm/libsofthsm2.so`, present on this host); a Windows-specific
PKCS#11 defect (path handling, DLL loading) would not be caught before
release.  *Closure.* A green `windows-latest` job running
`tests/test_hsm_integration.py` against a SoftHSM2 build.  *Owner action.*
Approve the lane; the build recipe is the upstream CMake+vcpkg one.

## 6. README 4.x-era performance tables

*Labelled?* Verified: `README.md` "Performance Metrics" opens with three
call-outs — "All ops/sec figures ... are from the canonical bench host ...
measured 2026-04-25 to 2026-04-27", "The canonical-host figures below were
measured against the 4.x code", and "**Every canonical-host row below is a
4.x-era measurement** ... No 5.0.0 measurement on AVX-512 + VAES +
VPCLMULQDQ silicon exists" — before any table.

*Does any gate read them as current?* Verified no: of the nine tools that
open `README.md` (`build_post_kats`, `check_documented_counts`,
`check_reference_integrity`, `check_release_state`, `check_release_tag`,
`check_vector_provenance`, `generate_dashboards`, `refresh_wycheproof_corpus`,
`update_docs`), none parses an ops/sec table; the benchmark regression
floors are read from `benchmarks/baseline.json` and
`benchmarks/arm-baseline.json` (their own measured medians), and
`generate_dashboards.py` reads the benchmark suite's JSON output, not the
README.  *Silicon.* As row 4.

## 7. 3R monitoring detection efficacy

*Measured*, not documented: `docs/audit/sweeps/r3_efficacy.py` (ledger
D-3R-01, `phaseD/r3-efficacy.log`, table `PR394_3R_EFFICACY.tsv`).  On
4,000 real ML-DSA-65 sign timings with injected anomalies, against a
trailing-window z-score baseline: isolated 10x outliers detected 30 % (3R)
vs 80 % (baseline) at 1.4 % vs 1.8 % false positives; 1.5x outliers 5 % vs
26 %; 20-sample bursts at 3x 41 % vs 15 %; a +10 % persistent shift
detected after 19 samples vs 47; +5 % after 182 vs 47.

*The argument for shipping it.* It ships as what its documentation now
says it is: an advisory regime-change monitor that never blocks an
operation, better than the trivial baseline on persistent shifts of 10 %
or more and worse on isolated outliers.  It is not evidence of
timing-attack detection, and the README no longer lets a reader infer
that.  FINDING-0005 records the before/after; `tests/test_3r_efficacy_calibration.py`
pins the prose to the table.  No exception remains on this row.
