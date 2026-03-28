# AMA Cryptography — Architectural Invariants

> **Policy document.** Every PR that touches `ama_cryptography/`, `.github/workflows/`,
> or `tests/` **must** satisfy all invariants below.
> Reviewers: reject any PR that violates them.

---

## INVARIANT-1 — Zero External Crypto Dependencies

**NEVER:** Introduce ad-hoc or unreviewed cryptographic constructions. All primitives must follow published NIST/IETF specifications and pass KAT validation.

**Do NOT introduce or depend on third-party cryptographic packages**
(`libsodium`, `pynacl`, `cryptography`, OpenSSL bindings, etc.).
Optional extras declared in `pyproject.toml` (e.g., `[secure-memory]`) may list
such packages for future or interop use, but the core `ama_cryptography` package
**must not** import or call them at runtime.

Python stdlib modules (`hashlib`, `os`, `secrets`) are permitted for
non-primitive operations (OS entropy, hashing). They **must NOT** be used as a
substitute for AMA's own implementations of HMAC, memory zeroing, or core
cipher operations.

**`hmac` module policy:** `hmac.compare_digest()` is permitted for constant-time
comparison. `hmac.new()` / `hmac.HMAC()` are not permitted — use AMA's own HMAC
implementations.

## INVARIANT-2 — Fail-Closed CI

Security-critical CI steps (pip-audit, bandit, Semgrep, KAT tests when oqs is
present, secret scanning) **must not** use `continue-on-error: true`.
Failures in these steps **must** block the pipeline.

**Documented exception:** The Docker build job in `ci-build-test.yml` uses
`continue-on-error: true` because transient Docker Hub auth/rate-limit
failures must not gate PRs. This job is infrastructure (image build + smoke
test), not a primary security gate — the KAT test suite runs independently
in the test matrix.

## INVARIANT-3 — Observable Failure States

- No bare `except …: pass` that swallows security-relevant errors.
- No bare `return` that silently skips a test — use `pytest.skip(reason=…)`.
- No `2>/dev/null` or other stderr suppression in workflow scripts.
- Mock assertions must verify **call signatures**, not just call occurrence.

## INVARIANT-4 — Pinned Action References

All third-party GitHub Actions used in security workflows **must** be pinned
to a full commit SHA, not a mutable tag (`@main`, `@v1`, etc.).

## INVARIANT-5 — Input Size Validation at Python/C Boundary

All Python functions that dispatch to the native C library via `ctypes` **must**
validate the byte-length of every fixed-size buffer argument **before** the
`ctypes` call. This prevents malformed inputs from reaching C code before bounds
checking. Variable-length parameters (messages, plaintext, AAD) whose length is
passed alongside via `c_size_t(len(...))` are safe and do not require pre-checks.

## INVARIANT-6 — Secret Key Zeroing on All Exit Paths

PQC key-pair dataclasses (`DilithiumKeyPair`, `KyberKeyPair`, `SphincsKeyPair`)
**must** store secret key material in mutable `bytearray` objects (not immutable
`bytes`) so that it can be securely zeroed via `secure_memzero`. Key-pair
objects **must** provide a `wipe()` method and a `__del__` destructor that zeros
secret key material.

## INVARIANT-7 — No Silent Cryptographic Fallbacks

When a native constant-time C backend is unavailable and the library falls back
to a pure-Python implementation, it **must** emit a `logger.warning()` (or at
minimum `logger.debug()` for non-crypto-critical paths) so that the fallback is
observable in logs. Production deployments requiring constant-time guarantees
**must** set `AMA_REQUIRE_CONSTANT_TIME=true`.

## INVARIANT-8 — Deterministic Reproducible Builds

The C build system **must** document and enforce minimum compiler versions
(GCC >= 12, Clang >= 15) required for correct constant-time code generation
and SIMD intrinsics. The reference build environment is the pinned Docker
image (`ubuntu:22.04`) with the documented compiler toolchain.

## INVARIANT-9 — Maximum Exception Scope in Crypto Paths

Code under `ama_cryptography/` **should** use narrow exception types
(`ValueError`, `RuntimeError`, `OSError`) rather than broad `except Exception`
where possible. Exceptions: handlers that explicitly transition to FIPS ERROR
state (e.g., `_self_test.py` POST failure tuples) may catch `Exception`.
A Semgrep rule for flagging new broad catches is deferred pending Semgrep
pattern syntax support (see `.semgrep.yml` for details).

## INVARIANT-10 — Signed Commits on Protected Branches

All commits merged to `main` and `develop` **must** be GPG- or SSH-signed.
This is **REQUIRED** (not merely recommended) per the supply-chain threat
model (T4.3). Branch protection rules should enforce this.

> **Enforcement gap:** This invariant requires enabling "Require signed commits"
> in GitHub branch protection settings for `main` and `develop`. This cannot be
> configured via PR — a repository administrator must enable it.

## INVARIANT-11 — SBOM as Release Gate

CycloneDX SBOM generation (Python + C library) **must** succeed as a required
check on release tags. The C library SBOM should be generated from build-system
metadata rather than a static placeholder when build tooling supports it.

> **Enforcement gap:** Making the SBOM job a required status check on release
> tags requires configuring GitHub branch protection rules or tag protection
> rules. This cannot be configured via PR — a repository administrator must
> add the check to the required status checks list.

---

_Maintained by Steel Security Advisors LLC._
_Last updated: 2026-03-28_
