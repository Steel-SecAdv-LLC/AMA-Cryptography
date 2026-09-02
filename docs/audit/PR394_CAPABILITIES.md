# PR #394 readiness falsification — Phase A capability declaration

Mandate: attempt to falsify the proposition that PR #394 (`steel/systempqc-maint1`
→ `main`) is complete, and repair whatever the falsification succeeds against.
This file is committed before any diff is read. Anything absent from it may not
later be invoked as an excuse; anything listed as present must be used.

Every statement below is backed by a row in `docs/audit/ledger.tsv` (column
`id`) and a retained log under `docs/audit/logs/phaseA/`. The probe script is
`docs/audit/phaseA_probes.sh`; re-running it regenerates the rows.

## Repository state

| Fact | Value | Ledger row |
|---|---|---|
| HEAD attested at start | `2cd50cbd45e4c90968c713a03ff9ecc3a86b9f85` | A-01 |
| Branch | `steel/systempqc-maint1`, tracking `origin/steel/systempqc-maint1` | A-01 |
| Clone completeness | `git fsck --connectivity-only` clean; working tree had 2 untracked/modified entries at probe time (this directory, and the build-time re-sign of `ama_cryptography/_integrity_signature.py`) | A-01 |
| Base | `origin/main` = `2dcef5c6ccf7aa95a00a460e525dfb500f59ea87` = merge-base (linear range) | A-02 |
| `git rev-list --count origin/main..HEAD` | 366 (1 merge commit, 365 non-merge) | A-02 |
| GitHub PR header | states 366 commits, 1,239 changed files, +114,711 / −7,609 | PR API `pull_request_read`, this session |
| `git diff --stat origin/main...HEAD` | 1,239 files, +114,537 / −7,609 (GitHub's +174 additions drift is not reproducible from git; git is ground truth) | scratch `bit0e1ciw.txt`, reproduced in Phase B |

## Toolchain that can be executed here

| Tool | Version / state | Ledger row |
|---|---|---|
| cmake (system) | 3.28.3 | A-04 |
| cmake (pip shim, required by `setup.py`'s ≥4.4.0 floor) | 4.4.3 in `/opt/ama-venv` | A-04 |
| gcc | 13.3.0 (Ubuntu) | A-05 |
| clang | 18.1.3 (Ubuntu) | A-05 |
| aarch64 cross | `aarch64-linux-gnu-gcc-13` 13.3.0, binutils 2.42 | A-05 |
| 32-bit x86 | `gcc -m32` builds and runs (`gcc-multilib`) | A-05 |
| qemu-user | `qemu-aarch64-static` 8.2.2; `-cpu max,sve-default-vector-length={16,32,64,128,256}` yields VL = 128/256/512/1024/2048 bits; `-cpu cortex-a53` faults SVE with SIGILL (exit 132), so feature masking is real | A-06 |
| valgrind | 3.22.0 | A-07 |
| ASan / MSan / TSan / UBSan | all four compile and run under clang 18 (`libclang-rt-18-dev`) | A-08 |
| libFuzzer | `clang -fsanitize=fuzzer` builds and runs | A-09 |
| atheris | 3.0.0 (venv) | A-10 |
| semgrep | 1.176.0 (CI pins 1.74.0; version difference recorded) | A-11 |
| cppcheck | 2.13.0 | A-12 |
| clang-tidy | 18.1.3 | A-13 |
| CodeQL CLI | bundle 2.20.0 downloaded and unpacked this session; `python` and `cpp` extractors resolve | A-14 |
| mypy / ruff / black / bandit | 1.19.1 / 0.15.8 / 26.3.1 / 1.9.4 (venv). CI pins mypy 2.3.0, ruff 0.16.0, black 26.5.1 (`ci.yml`); the venv versions are what `requirements-dev.txt` resolved to on this index today and are recorded as such | A-15 |
| SoftHSM2 / PyKCS11 / OpenSC | softhsm2-util 2.6.1, `/usr/lib/softhsm/libsofthsm2.so`, PyKCS11 imports, `pkcs11-tool` present | A-16 |
| sigstore | python client 4.5.0; cosign v2.4.1 (`cosign-linux-amd64` downloaded this session) | A-17 |
| gh CLI | **absent** (exit 3). GitHub is reached through the session's GitHub MCP tools only | A-18 |
| mutmut | 3.7.0 | A-19 |
| Python | 3.11.15; pytest 9.1.1; hypothesis 6.167.1; Cython 3.3.0; numpy 2.4.6; scipy 1.17.1 | A-20 |
| docker | client 29.3.1 present, **daemon down** at probe time (starting it in-session is possible, per the prior audit's record; not yet done) | A-22 |

Python package: built and installed the way `ci.yml` does it (`cmake -B build
… -DAMA_BUILD_TESTS=OFF`, `pip install -e ".[dev,legacy,benchmark,hsm]"
pycryptodome`, committed `.py` digest verified current), so the suite runs
against the native library with the integrity artefact re-signed for this
build. A second, test-enabled Release build lives in `build-release/`
(76 ctest binaries, 76/76 pass, 8 hardware-skipped — row A-24).

## CI that can be dispatched and read

- Read: every workflow run, job, check run and log on the repository through
  the GitHub MCP tools, authenticated as the repository owner account
  (`get_me` → `Steel-SecAdv-LLC`).
- Dispatch: `actions_run_trigger` on `steel/systempqc-maint1` works — a
  `static-analysis.yml` dispatch returned HTTP 204 this session and is the
  capability proof. Workflows carrying `workflow_dispatch`: `acvp_validation`,
  `arm-qemu`, `ci-build-test`, `ci`, `corpus-provenance`, `dudect`
  (`measurements` input), `fuzzing` (`fuzz_duration` input),
  `integrity-anchor-check`, `release` (`dry_run`, default true), `security`,
  `static-analysis`, `wiki-sync`. `auto-docs` and `baseline-guard` have no
  dispatch trigger.
- Not exercised under this mandate, by its own terms: `release.yml` with
  `dry_run=false`, tag signing, PyPI publication, the `release` environment's
  credentials.

## Hardware that is NOT here

| Absent | Consequence | Ledger row |
|---|---|---|
| VAES, VPCLMULQDQ | the AES-GCM VAES/AVX-512 kernel cannot execute on this host; it can be built, disassembled, and its dispatch gating proven, but not run | A-23 |
| SHA-NI | `ama_sha256_ni.c` cannot execute here; same treatment | A-23 |
| Real SVE2 / AArch64 silicon | NEON and SVE2 run only under qemu-user (functional, not timing-faithful); dudect on SVE2 is impossible here | A-23 |
| Windows, macOS | those platform lanes are CI-only evidence | A-23 |
| Real HSM | SoftHSM2 only | A-16 |
| AVX-512F/DQ/BW/VL/CD/VNNI | **present** — the AVX-512 Keccak 4-way kernel can execute here | A-23 |

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
  history rewrite. The harness had checked out `claude/pr394-readiness-verify-myuxz8`
  at session start; that branch is untouched and nothing is pushed to it.
- Local scratch branches/worktrees for bisection are permitted and never pushed.
