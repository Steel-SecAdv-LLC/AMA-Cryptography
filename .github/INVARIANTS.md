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

## INVARIANT-5 — Input Validation at Python/C Boundary

All Python functions that dispatch to the native C library via `ctypes` **must**
validate inputs **before** the `ctypes` call:

- **Fixed-size buffers:** Validate the byte-length of every fixed-size buffer
  argument (keys, public keys, nonces, tags). Variable-length parameters
  (messages, plaintext, AAD) whose length is passed alongside via
  `c_size_t(len(...))` are safe and do not require pre-checks.
  **Signature exemption:** ML-DSA-65 and SPHINCS+ signatures are
  variable-length (the `*_SIGNATURE_BYTES` constants are maximum buffer
  sizes, not exact output lengths). Their actual length is passed via
  `c_size_t(len(signature))`, so they fall under the variable-length
  exemption.

- **Fixed-width integer parameters:** Python integers passed to C functions
  expecting fixed-width types (`c_uint32`, `c_int32`, etc.) **must** be
  range-checked against the target type's bounds before dispatch. Python's
  arbitrary-precision `int` can silently overflow/wrap when ctypes converts
  to a fixed-width C integer. Example: Argon2id `t_cost`, `m_cost`, and
  `parallelism` are `c_uint32` — values above `2^32 - 1` must be rejected.

## INVARIANT-6 — Secret Key Zeroing on All Exit Paths

PQC key-pair dataclasses (`DilithiumKeyPair`, `KyberKeyPair`, `SphincsKeyPair`)
**must** store secret key material in mutable `bytearray` objects (not immutable
`bytes`) so that it can be securely zeroed via `secure_memzero`. Key-pair
objects **must** provide a `wipe()` method and a `__del__` destructor that zeros
secret key material. Consumers that extract secret keys from these objects
**must** copy the key via `bytes(kp.secret_key)` or `bytearray(kp.secret_key)`
to avoid use-after-wipe when the source KeyPair is garbage collected.

## INVARIANT-7 — No Silent Cryptographic Fallbacks

When a native constant-time C backend is unavailable and the library falls back
to a pure-Python implementation, it **must** emit a `logger.warning()` (or at
minimum `logger.debug()` for non-crypto-critical paths) so that the fallback is
observable in logs. Production deployments requiring constant-time guarantees
**must** set `AMA_REQUIRE_CONSTANT_TIME=true`, which raises `RuntimeError` at
module load if native backends are unavailable.

## INVARIANT-8 — Deterministic Reproducible Builds

The C build system **must** document and enforce minimum compiler versions
(GCC >= 12, Clang >= 15) required for correct constant-time code generation
and SIMD intrinsics. The reference build environment is the pinned Docker
image (`ubuntu:22.04`) with the documented compiler toolchain.

**Enforcement:** By default, CMake will `FATAL_ERROR` if the detected compiler
does not meet the minimum version. To build on an unverified toolchain (e.g.,
for development or CI on older hosts), pass `-DAMA_ALLOW_UNVERIFIED_TOOLCHAIN=ON`
to downgrade to a `WARNING`.

## INVARIANT-9 — Maximum Exception Scope in Crypto Paths

Code under `ama_cryptography/` **should** use narrow exception types
(`ValueError`, `RuntimeError`, `OSError`) rather than broad `except Exception`
where possible. Exceptions: handlers that explicitly transition to FIPS ERROR
state (e.g., `_self_test.py` POST failure tuples) and `__del__` destructors
(which must never raise) may catch `Exception`.
Semgrep 1.74.0 does not support `except Exception` pattern syntax; manual
review is required until Semgrep adds support.

## INVARIANT-10 — Signed Commits on Protected Branches

All commits merged to `main` and `develop` **must** be GPG- or SSH-signed.
This is **REQUIRED** (not merely recommended) per the supply-chain threat
model (T4.3). Branch protection rules should enforce this.

> **Status:** Signed commits are enabled via branch protection on `main` and
> `develop`.

## INVARIANT-11 — SBOM as Release Gate

CycloneDX SBOM generation (Python + C library) **must** succeed as a required
check on release tags.

The `security.yml` workflow triggers on `v*` tags so the SBOM job executes
automatically on every release. A repository administrator should add the
`SBOM Generation (CycloneDX)` job as a required status check on tag protection
rules to enforce the gate.

## INVARIANT-12 — CVE Ignore-List Hygiene

Every `--ignore-vuln` flag in CI workflows **must** have an accompanying comment
that states: (a) the CVE ID, (b) why the vulnerability is not exploitable in
this context, and (c) the condition under which the ignore should be removed.

Tracked ignores:

| CVE | Package | Reason | Remove when |
|-----|---------|--------|-------------|
| CVE-2026-4539 | Pygments (transitive via rich/bandit) | ReDoS in AdlLexer — dev-only, local access, not used at runtime | Pygments ships a fix (>2.20.0) or the transitive dependency is dropped |

> **Review cadence:** Re-evaluate all tracked CVE ignores on the first of each
> quarter or when Dependabot bumps the affected package, whichever comes first.

---

_Maintained by Steel Security Advisors LLC._
_Last updated: 2026-03-31_
