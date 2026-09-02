# PR #394 readiness falsification — Phase A capability declaration

Mandate: attempt to falsify the proposition that PR #394 (`steel/systempqc-maint1`
→ `main`) is complete, and repair whatever the falsification succeeds against.
This declaration is committed before any diff is analysed. Anything absent from
it may not later be invoked as an excuse; anything listed as present must be used.

Every statement below is backed by a row in `docs/audit/ledger.tsv` (column
`id`) and by the retained raw log that row names under `docs/audit/logs/phaseA/`.
The probe script is `docs/audit/phaseA_probes.sh`; re-running it regenerates
the rows and logs. `docs/audit/run_logged.sh` is the recording runner every
row is written through.

## Session record

Two sessions have executed Phase A on this branch:

| Session | Host | Result |
|---|---|---|
| 1 (2026-09-02 03:29 UTC) | Xeon @ 2.80 GHz, Cascade Lake class, no VAES / VPCLMULQDQ / SHA-NI | Committed at `be1af0f`. Its ledger rows named 24 logs, none of which were committed (`*.log` is git-ignored), so no row was evidence. The declaration also cited a session-local scratch file by name, which no tracked file carries, which failed `tests/test_documented_source_paths_exist.py`, and the four added files moved the whole-project line count without re-measuring `docs/METRICS_REPORT.md`, which failed the documented-counts gate — every Python lane at `be1af0f` was red on those two tests. |
| 2 (this one, 2026-09-02 05:54 UTC) | Xeon @ 2.10 GHz, model 207 (Sapphire Rapids class), 4 vCPU under KVM | The ledger and logs were regenerated on this host and are committed. `.gitignore` now re-includes `docs/audit/logs/`, and `tools/check_secrets.py` allowlists that directory for the same reason it allowlists `verification/v5-audit/logs/`. |

Session 1's rows are superseded rather than kept: a row whose log is absent
from the tree cannot be checked, and the mandate's own rule (§14) is that a
reported exit code with no retained log is not evidence.

## Repository state

| Fact | Value | Ledger row |
|---|---|---|
| HEAD at probe time | `be1af0f0a225298e8ca0156492ae1b2a24d3994a`, branch `steel/systempqc-maint1` | A-01 |
| Clone completeness | `git fsck --connectivity-only` clean; 6 working-tree entries were pending at probe time — this directory's regenerated files, `.gitignore`, `tools/check_secrets.py`, and the editable-install re-sign of `ama_cryptography/_integrity_signature.py`, which is never staged | A-01 |
| Base | `origin/main` = `2dcef5c6ccf7aa95a00a460e525dfb500f59ea87` = merge-base (linear range) | A-02 |
| `git rev-list --count origin/main..HEAD` | 367 (1 merge commit, 366 non-merge) | A-02 |
| GitHub PR header (API, this session) | 367 commits, 1,243 changed files, +114,955 / −7,609 | `pull_request_read` |
| `git diff --stat origin/main...HEAD` | 1,243 files, +114,781 / −7,609. GitHub's +174 additions drift is not reproducible from git; git is ground truth and the drift is recorded, not explained | Phase B ledger |

## Toolchain that can be executed here

| Tool | Version / state | Ledger row |
|---|---|---|
| cmake (system) | 3.28.3 | A-04 |
| cmake (pip shim, required by the `cmake>=4.4.0` build floor in `pyproject.toml`) | 4.4.3 in `/opt/ama-venv` | A-04 |
| gcc | 13.3.0 (Ubuntu) | A-05 |
| clang | 18.1.3 (Ubuntu) | A-05 |
| AArch64 cross | `aarch64-linux-gnu-gcc-13` 13.3.0, binutils 2.42 | A-05 |
| 32-bit x86 | `gcc -m32` and `clang -m32` both build and run (`libc6-dev-i386`, `lib32gcc-13-dev`; `gcc-multilib` itself conflicts with the cross compiler on this distribution and is not installed) | A-05 |
| qemu-user | `qemu-aarch64-static` 8.2.2. `-cpu max,sve-max-vq=N` reaches VL = 128 / 256 / 512 bits for N = 1 / 2 / 4, **but the process default VL is capped at 512 bits for N = 8 and 16**; VL = 1024 and 2048 bits require `sve-default-vector-length=-1` (or an explicit byte length) in addition. `-cpu cortex-a53` faults SVE with SIGILL (exit 132), so feature masking is real | A-06 |
| valgrind | 3.22.0 | A-07 |
| ASan / MSan / TSan / UBSan | all four compile and run under clang 18 (`libclang-rt-18-dev`) | A-08 |
| libFuzzer | `clang -fsanitize=fuzzer` builds and runs | A-09 |
| atheris | present in the venv | A-10 |
| semgrep | 1.176.0 (CI pins 1.74.0; the difference is recorded) | A-11 |
| cppcheck | 2.13.0 | A-12 |
| clang-tidy | 18.1.3 | A-13 |
| CodeQL CLI | bundle 2.20.0 downloaded this session; `python` and `cpp` extractors resolve. Session-local path, supplied through `AUDIT_CODEQL` | A-14 |
| mypy / ruff / black / bandit | 2.3.1 / 0.16.5 / 26.5.1 / 1.9.4 (venv, resolved from `requirements-dev.txt` today) | A-15 |
| SoftHSM2 / PyKCS11 / OpenSC | softhsm2-util 2.6.1, `/usr/lib/softhsm/libsofthsm2.so`, PyKCS11 imports, `pkcs11-tool` present | A-16 |
| sigstore | python client 4.5.0; cosign v2.4.1 (downloaded this session, path through `AUDIT_COSIGN`) | A-17 |
| gh CLI | **absent** (exit 3). GitHub is reached through the session's GitHub MCP tools only | A-18 |
| mutmut | 3.7.0 | A-19 |
| Python | 3.11.15; pytest 9.1.1; hypothesis 6.167.1; Cython 3.3.0; numpy 2.4.6; scipy 1.17.1 | A-20 |
| docker | client and daemon up (`dockerd --iptables=false --bridge=none`, started in-session) | A-22 |

Python package: built and installed the way `ci.yml` does it (`pip install -e
".[dev,legacy,benchmark,hsm]" pycryptodome`, committed `.py` digest verified
current before the build, artefact re-signed under `AMA_BUILD_PIPELINE=1`
afterwards), so the suite runs against the native library. A test-enabled
Release build lives in `build-release/`: 75 ctest cases registered, 75/75
pass, 14 hardware-skipped (the NEON, SVE2 and AVX-512 4-way dispatch and
equivalence cases, which run in the cross and AVX-512 lanes instead) — row A-24.

## CI that can be dispatched and read

- Read: every workflow run, job, check run and log on the repository through
  the GitHub MCP tools, authenticated as the repository owner account
  (`get_me` → `Steel-SecAdv-LLC`).
- Dispatch: `actions_run_trigger` on `steel/systempqc-maint1`. Workflows
  carrying `workflow_dispatch`: `acvp_validation`, `arm-qemu`, `ci-build-test`,
  `ci`, `corpus-provenance`, `dudect` (`measurements` input), `fuzzing`
  (`fuzz_duration` input), `integrity-anchor-check`, `release` (`dry_run`,
  default true), `security`, `static-analysis`, `wiki-sync`. `auto-docs` and
  `baseline-guard` have no dispatch trigger.
- Not exercised under this mandate, by its own terms: `release.yml` with
  `dry_run=false`, tag signing, PyPI publication, the `release` environment's
  credentials.

## Hardware present and absent

| ISA / platform | State on this host | Consequence | Ledger row |
|---|---|---|---|
| AVX2, AVX-512F/VL/BW/IFMA | **present** (both hosts) | the AVX2 kernels and the AVX-512 Keccak 4-way kernel execute natively | A-23, A-25 |
| VAES, VPCLMULQDQ, GFNI | **present at Phase A, absent afterwards** | The VM was moved to a different CPU during this session: the Phase A probe (A-23, `phaseA/hw-flags.log`) lists `vaes vpclmulqdq gfni sha_ni`; the re-probe taken after the change (A-25, `phaseA/hw-flags-reprobe.log`) lists none of them and reports the model as "Intel(R) Xeon(R) Processor @ 2.80GHz". Every measurement whose ledger row is later than A-25's timestamp ran WITHOUT this silicon; in particular `test_aes_gcm_vaes_equiv` skips (row F-C-test_aes_gcm_vaes_equiv, exit 77, "dispatcher selected the AVX2 AES-NI reference") and no VAES-kernel result in this audit was produced after the change. The PR description's release prerequisite 3 ("Sapphire Rapids / Zen 4 silicon") is therefore reachable in this cloud environment but not stably: the §10 adjudication of the canonical-host benchmark treats it as reachable-but-unconfigured, with this row as the evidence that the same session saw both states. | A-23, A-25 |
| SHA-NI | **present at Phase A, absent afterwards** | as above: `ama_sha256_ni.c` executed natively only before the host change | A-23, A-25 |
| SVE / SVE2 silicon | absent | NEON and SVE2 run only under qemu-user (functional, not timing-faithful); dudect on SVE2 is impossible here | A-23 |
| Windows, macOS | absent | those platform lanes are CI-only evidence | A-23 |
| Real HSM | absent | SoftHSM2 only | A-16 |

## Network reachability

Reachable (HTTP 200): raw.githubusercontent.com (ACVP-Server, Wycheproof
corpora), csrc.nist.gov, pypi.org, files.pythonhosted.org,
rekor.sigstore.dev, tuf-repo-cdn.sigstore.dev, api.github.com (via the proxy;
unauthenticated), rfc-editor.org. github.com root returns 400 through the
proxy but release-asset downloads redirect and complete (CodeQL bundle,
cosign). registry-1.docker.io answers 401 (reachable, unauthenticated). Row A-21.

## Standing constraints of the mandate

- Authorized ref: `refs/heads/steel/systempqc-maint1` only. No other branch,
  tag, fork, remote, or PR is created, modified, or deleted; no force-push, no
  history rewrite. The session harness had created and checked out
  `claude/pr-394-readiness-verify-7khmup` at `origin/main` before this session
  began; that branch is untouched and nothing is pushed to it.
- Local scratch branches and worktrees for bisection are permitted and never pushed.
