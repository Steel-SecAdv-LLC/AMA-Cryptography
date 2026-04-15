# AMA Cryptography — AI Agent Instructions

> **Scope:** This document governs all AI agent activity (Claude, Devin, Codex,
> Copilot, or any future agent) operating on the AMA Cryptography repository.
> Instructions are imperative and institutional. Compliance is mandatory.

---

## Table of Contents

1. [Governing Documents](#governing-documents)
2. [Phase 1 — Branch Consolidation](#phase-1--branch-consolidation)
3. [Phase 2 — CI/CD Repair](#phase-2--cicd-repair)
4. [Phase 3 — Technical Debt Resolution](#phase-3--technical-debt-resolution)
5. [Phase 4 — Production Readiness Checklist](#phase-4--production-readiness-checklist)
6. [Inviolable Constraints](#inviolable-constraints)
7. [Development Environment](#development-environment)
8. [Code Quality Standards](#code-quality-standards)
9. [Workflow Reference](#workflow-reference)

---

## Governing Documents

Before making any change, read and internalize these documents in order:

| Document | Purpose | Authority |
|----------|---------|-----------|
| `INVARIANTS.md` | Library-wide invariants and vendoring policy | **Binding** |
| `.github/INVARIANTS.md` | Architectural invariants enforced on every PR (INVARIANT-1 through INVARIANT-14) | **Binding** |
| `CONTRIBUTING.md` | Contribution guidelines, code quality, PR process | **Binding** |
| `CSRC_STANDARDS.md` | Algorithm-to-standard mapping — only algorithms with shipping code | **Binding** |
| `SECURITY.md` | Security policy and vulnerability reporting | **Binding** |
| `ARCHITECTURE.md` | Three-tier architecture (C core / Cython / Python API) | Reference |
| `IMPLEMENTATION_GUIDE.md` | Deployment and usage guide | Reference |
| `THREAT_MODEL.md` | Threat model and security analysis | Reference |
| `CONSTANT_TIME_VERIFICATION.md` | Constant-time verification methodology | Reference |

**Rule:** Every action must be justified with evidence from these documents or
from the codebase itself. No assumptions. No guesses. If uncertain, state the
uncertainty and propose a verification step.

---

## Phase 1 — Branch Consolidation

### Objective

Eliminate all stale branches and open PRs. Ensure `main` contains every valued
change. Leave the repository with zero open PRs and zero non-default branches
(except `develop` if it exists).

### Procedure

1. **Enumerate all remote branches and open PRs.**
   ```bash
   git branch -r
   gh pr list --state open --json number,title,headRefName,updatedAt
   ```

2. **For each branch, audit commits not in `main`.**
   ```bash
   git log main..<branch> --oneline --no-merges
   ```

3. **Classify each branch:**
   - **Valued:** Contains new features, bug fixes, documentation improvements,
     or test additions not yet in `main`. Cherry-pick or merge into `main` with
     proper attribution (`--author` preserved).
   - **Stale/Captured:** All meaningful commits already in `main`, or the
     branch is abandoned. Close the PR and delete the branch.
   - **Superseded:** A newer PR covers the same ground. Close with a comment
     referencing the superseding PR.

4. **Cherry-pick valued commits.**
   ```bash
   git cherry-pick --allow-empty -x <sha>
   ```
   Preserve the original author. Add `Cherry-picked from <branch>` in the
   commit message trailer.

5. **Close PRs and delete branches.**
   ```bash
   gh pr close <number> --comment "Captured in main via <commit-sha>. Branch deleted."
   gh api repos/{owner}/{repo}/git/refs/heads/<branch> -X DELETE
   ```

6. **Document the consolidation** in a summary table:

   | Branch | PR # | Disposition | Justification |
   |--------|------|-------------|---------------|
   | `auto-docs/update` | — | Delete | Auto-generated; superseded by main |
   | `claude/fix-*` | #183 | Captured | Merged via #183; remaining commits cherry-picked |
   | `dependabot/*` | — | Close | Already consolidated or superseded |

---

## Phase 2 — CI/CD Repair

### Auto-Documentation Workflow

**Workflow file:** `.github/workflows/auto-docs.yml`

**Known root cause:** `actions/checkout@v6` changed credential persistence
behavior. The workflow must:

1. Set `persist-credentials: false` on the checkout step.
2. Explicitly configure the push remote with a token-authenticated URL:
   ```yaml
   git remote set-url origin "https://x-access-token:${GH_TOKEN}@github.com/${{ github.repository }}.git"
   ```
3. Use `git push origin <branch> --force` (not `git push -u`).
4. Use `gh pr list` with `--jq '.[0].number // empty'` to safely detect
   existing PRs.

**Verification:** After fixing, trigger the workflow manually via
`workflow_dispatch` (if available) or by pushing a commit to `main`. The
workflow must:
- Run `tools/update_docs.py` successfully (exit 0).
- Detect changes and push to `auto-docs/update` branch.
- Create or update a PR without errors.
- Exit cleanly when no changes are detected.

### All CI Workflows

Audit every file in `.github/workflows/`:

| Workflow | File | Gate Type |
|----------|------|-----------|
| CI - Testing and Code Quality | `ci.yml` | **Blocking** |
| CI - Build and Test | `ci-build-test.yml` | **Blocking** (except Docker: `continue-on-error: true` per INVARIANT-2) |
| Security Scanning | `security.yml` | **Blocking** |
| Static Analysis (C Code) | `static-analysis.yml` | **Blocking** |
| Fuzzing (libFuzzer) | `fuzzing.yml` | **Blocking** |
| dudect Constant-Time | `dudect.yml` | **Blocking** |
| Auto-Documentation | `auto-docs.yml` | Advisory |
| Sync Wiki | `wiki-sync.yml` | Advisory |

**Checklist for each workflow:**

- [ ] All third-party Actions pinned to full commit SHA (INVARIANT-4)
- [ ] No hardcoded secrets — only `${{ secrets.* }}` or `${{ github.token }}`
- [ ] No deprecated Action versions
- [ ] No `continue-on-error: true` on security-critical steps (INVARIANT-2)
- [ ] No `2>/dev/null` or stderr suppression (INVARIANT-3)
- [ ] CVE ignores documented per INVARIANT-14
- [ ] Timeout set appropriately for each job

---

## Phase 3 — Technical Debt Resolution

### 3.1 TODO/FIXME/HACK/XXX Audit

```bash
rg -n '(TODO|FIXME|HACK|XXX)\b' --type py --type c --type-add 'cython:*.pyx' --type cython
```

For each marker found:
1. Determine if the issue is still relevant.
2. If resolvable, fix it and remove the marker.
3. If deferred, convert to a GitHub Issue with a tracking reference.
4. If obsolete, remove the marker with a commit message explaining why.

### 3.2 Invariant Compliance Audit

For each invariant in `.github/INVARIANTS.md` (INVARIANT-1 through INVARIANT-14):

1. **INVARIANT-1 (Zero External Crypto Dependencies):** Verify no imports of
   `cryptography`, `pynacl`, `libsodium`, OpenSSL bindings, etc. in
   `ama_cryptography/`. Verify `hmac.compare_digest()` is the only permitted
   `hmac` usage.
   ```bash
   rg 'import (cryptography|nacl|pynacl|libsodium)' ama_cryptography/
   rg 'hmac\.(new|HMAC)\b' ama_cryptography/
   ```

2. **INVARIANT-2 (Fail-Closed CI):** Verify no `continue-on-error: true` on
   security steps in workflow files (documented Docker exception is acceptable).

3. **INVARIANT-3 (Observable Failure States):** Verify no bare
   `except ...: pass` in crypto paths. Verify all `__del__` methods call
   `record_finalizer_error()`.

4. **INVARIANT-4 (Pinned Action References):** Verify all Actions use full SHA.
   ```bash
   rg 'uses:.*@[^0-9a-f]' .github/workflows/
   ```

5. **INVARIANT-5 (Input Validation):** Verify all ctypes dispatch functions
   validate fixed-size buffer lengths.

6. **INVARIANT-6 (Secret Key Zeroing):** Verify PQC KeyPair classes use
   `bytearray`, have `wipe()` and `__del__`.

7. **INVARIANT-7 (No Crypto Fallbacks):** Verify `RuntimeError` raised at
   import time when native C backend is missing.

8. **INVARIANT-12 (Constant-Time):** Verify no Python-level MAC/tag
   verification, no `==` comparisons on secret data.

### 3.3 CSRC_STANDARDS.md Consistency

Verify every algorithm listed in `CSRC_STANDARDS.md` has:
- Shipping code in `src/c/` or `ama_cryptography/`
- A test in `tests/`
- Correct parameter sets matching the implementation

Verify no algorithm exists in code without a `CSRC_STANDARDS.md` entry.

### 3.4 Dead Code and Unused Imports

```bash
ruff check --select F401,F811 .
```

Remove unused imports. Flag dead code for review.

### 3.5 Test Coverage

```bash
pytest tests/ -v --cov=ama_cryptography --cov-report=term-missing
```

Identify public API functions with zero coverage. Add tests for any gaps.

### 3.6 Documentation-Implementation Consistency

Cross-reference `README.md`, `ARCHITECTURE.md`, `IMPLEMENTATION_GUIDE.md`
against actual code. Flag any claims that do not match the implementation.

---

## Phase 4 — Production Readiness Checklist

All items must be verified before declaring the repository production-ready.

### CI/CD

- [ ] All CI workflows pass on `main` (green across all matrix entries)
- [ ] Auto-Documentation workflow creates PRs without errors
- [ ] Wiki sync workflow operates correctly
- [ ] Security scanning (Bandit, pip-audit, Semgrep, TruffleHog) all pass
- [ ] Fuzzing targets build and run without crashes
- [ ] Constant-time verification (dudect) passes

### Tests

- [ ] All unit tests pass: `pytest tests/ -v`
- [ ] NIST KAT tests pass (when oqs is available)
- [ ] Module integrity digest is current: `python -m ama_cryptography.integrity --verify`
- [ ] Demonstration passes: `python -m ama_cryptography` outputs "ALL VERIFICATIONS PASSED"
- [ ] Crypto backends verified available (Dilithium, Kyber, SPHINCS+, AES-GCM, Ed25519)

### Repository Hygiene

- [ ] No open PRs or stale branches remaining
- [ ] No unresolved TODO/FIXME/HACK/XXX comments (or all tracked in Issues)
- [ ] All invariants (INVARIANT-1 through INVARIANT-14) satisfied
- [ ] CSRC_STANDARDS.md matches implemented algorithms

### Documentation

- [ ] README.md accurate and up to date
- [ ] ARCHITECTURE.md reflects actual three-tier structure
- [ ] CHANGELOG.md current with recent changes
- [ ] CONTRIBUTING.md references correct toolchain (ruff, not flake8/isort)
- [ ] All wiki pages synchronized

### Security

- [ ] No hardcoded credentials anywhere in the repository
- [ ] No secrets in logs, error messages, or debug output
- [ ] All cryptographic operations use constant-time comparisons
- [ ] Input validation at all Python/C boundaries (INVARIANT-5)
- [ ] Secret key zeroing on all exit paths (INVARIANT-6)
- [ ] No cryptographic fallbacks (INVARIANT-7)
- [ ] All `--ignore-vuln` entries documented per INVARIANT-14

### Build System

- [ ] `cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build` succeeds on Linux
- [ ] Cross-platform build verified (Linux, macOS, Windows per CI matrix)
- [ ] Docker images build and pass smoke tests (Ubuntu and Alpine)
- [ ] `pip install -e ".[dev]"` succeeds
- [ ] Package metadata in `pyproject.toml` and `setup.py` is correct

---

## Inviolable Constraints

These constraints derive from `INVARIANTS.md` and `.github/INVARIANTS.md`.
Violation of any constraint is a hard stop — do not proceed.

### INVARIANT-1: Zero External Crypto Dependencies

**NEVER** link, import, or depend on `libsodium`, `OpenSSL`, `liboqs`,
`pynacl`, `cryptography`, or any pre-built cryptographic library at runtime.

Vendoring public-domain source into `src/c/vendor/` and compiling as part of
AMA's build system is permitted.

Python stdlib `hashlib`, `os`, `secrets` are permitted for non-primitive
operations. `hmac.compare_digest()` is the only permitted `hmac` function.

### INVARIANT-2: Thread-Safe CPU Dispatch

All one-time initialization in `ama_cpuid.c` must use platform once-primitives:
- **POSIX:** `pthread_once`
- **Windows:** `InitOnceExecuteOnce`

`volatile int` flag patterns are prohibited. C11 `call_once` is not used
(missing on macOS, buggy on MSVC).

### INVARIANT-7: No Cryptographic Fallbacks

When the native C backend is unavailable, the library raises `RuntimeError` at
import time. There is no pure-Python fallback for any cryptographic operation.
There is no development escape hatch.

### INVARIANT-12: Constant-Time Required

All secret-dependent operations must be constant-time. Python code must not
implement cryptographic primitives — it delegates to the native C backend.
No `==` comparisons on MACs, tags, or secret data.

### General Rules

- Every cryptographic claim must reference the relevant NIST/IETF standard
- All changes must be measurable and verifiable
- Security claims must reference the standard's security analysis, not original proofs
- No ad-hoc or unreviewed cryptographic constructions
- Follow conventional commit format: `<type>(<scope>): <subject>`

---

## Development Environment

### Setup

```bash
# Clone and enter
git clone https://github.com/Steel-SecAdv-LLC/AMA-Cryptography.git
cd AMA-Cryptography

# Create virtual environment
python -m venv venv && source venv/bin/activate

# Build native C library
cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release \
  -DAMA_BUILD_TESTS=OFF -DAMA_BUILD_EXAMPLES=OFF
cmake --build build -j$(nproc)

# Install Python package with dev dependencies
pip install --upgrade pip setuptools wheel
pip install "Cython>=3.0.0" "numpy>=1.24.0,<3.0.0"
pip install -e ".[dev]"

# Install pre-commit hooks
pip install pre-commit && pre-commit install

# Verify
python -m ama_cryptography  # Must output "ALL VERIFICATIONS PASSED"
```

### Lint and Format

```bash
ruff check .                          # Linting (replaces flake8 + isort)
black --check --diff .                # Formatting
mypy --strict ama_cryptography/ tests/ # Type checking
```

**Do NOT** run `isort` separately — ruff handles import sorting via `I001`.

### Testing

```bash
pytest tests/ -v --tb=short           # Full test suite
pytest tests/ -v --cov=ama_cryptography --cov-report=term-missing  # With coverage
```

### FIPS 140-3 Integrity Digest

After ANY change to source files under `ama_cryptography/`:

```bash
python -m ama_cryptography.integrity --update  # Regenerate digest
python -m ama_cryptography.integrity --verify   # Verify
```

The digest file is `ama_cryptography/_integrity_digest.txt`. Forgetting to
update it causes the Power-On Self-Test (POST) to fail, setting
`_MODULE_STATE = "ERROR"` and blocking all cryptographic operations.

---

## Code Quality Standards

### Python

- **PEP 8** compliance enforced by `black` (line length 100) and `ruff`
- **Type hints** required on all functions
- **Docstrings** required: summary, args, returns, raises, security notes, standards references
- **No `Any`** — understand the type and access attributes correctly
- **Imports at top** — never nested inside functions
- **Security first** — never log secrets, use constant-time comparisons

### C

- **C11 standard** (`-std=c11`)
- **Constant-time** for all secret-dependent operations
- **Memory safety** — validate all buffer sizes, use `secure_memzero`
- **No external crypto deps** — all primitives implemented in-tree

### Commit Messages

Follow conventional commits:
```
<type>(<scope>): <subject>

<body>

Refs: <standard>
```

Types: `feat`, `fix`, `security`, `docs`, `test`, `refactor`, `perf`, `chore`

---

## Workflow Reference

### CI Trigger Rules

| Event | Branches |
|-------|----------|
| `push` | `main`, `develop`, `claude/**` |
| `pull_request` | `main`, `develop` only |
| `workflow_dispatch` | Manual trigger (most workflows) |

PRs must target `main` or `develop` for CI to trigger.

### Key Commands

| Task | Command |
|------|---------|
| Build C library | `cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build` |
| Run tests | `pytest tests/ -v` |
| Lint | `ruff check . && black --check .` |
| Type check | `mypy --strict ama_cryptography/ tests/` |
| Security scan | `bandit -r ama_cryptography/ -l` |
| Update integrity digest | `python -m ama_cryptography.integrity --update` |
| Verify integrity | `python -m ama_cryptography.integrity --verify` |
| Run demo | `python -m ama_cryptography` |
| Benchmark regression | `python benchmarks/benchmark_runner.py --verbose` |

### Architecture Quick Reference

```
Three-Tier Architecture:

  Tier 1: Native C      src/c/          Cryptographic primitives (FIPS/RFC compliant)
                         include/        C header files (public API surface)
                         src/c/vendor/   Vendored source (ed25519-donna)

  Tier 2: Cython        src/cython/     High-performance bindings (C-to-Python bridge)

  Tier 3: Python API    ama_cryptography/  Public Python API, orchestration, monitoring
                         tests/            Test suite
                         tools/            Development and CI utilities
                         benchmarks/       Performance benchmarks
```

---

_Maintained by Steel Security Advisors LLC._
_Last updated: 2026-04-07_
