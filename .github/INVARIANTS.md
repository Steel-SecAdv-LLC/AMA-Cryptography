# AMA Cryptography — Architectural Invariants

> **Policy document.** Every PR that touches `ama_cryptography/`, `.github/workflows/`,
> or `tests/` **must** satisfy all invariants below.
> Reviewers: reject any PR that violates them.

---

## INVARIANT-1 — Zero External Crypto Dependencies

**NEVER:** Introduce ad-hoc or unreviewed cryptographic constructions. All primitives must follow published NIST/IETF specifications and pass KAT validation.

**Do NOT introduce or depend on third-party cryptographic packages**
(`libsodium`, `pynacl`, `cryptography`, OpenSSL bindings, etc.).
Optional extras declared in `pyproject.toml` (e.g., `[legacy]` for the PyCA
fallback, `[benchmark]` for peer libraries used only by `benchmarks/`) may list
such packages for opt-in interop or comparison use, but the core
`ama_cryptography` package **must not** import or call them at runtime.

No pre-built external cryptographic libraries (libsodium, OpenSSL, liboqs,
etc.) may be linked.

Python stdlib modules (`hashlib`, `os`, `secrets`) are permitted for
non-primitive operations (OS entropy, hashing). They **must NOT** be used as a
substitute for AMA's own implementations of HMAC, memory zeroing, or core
cipher operations.

**`hmac` module policy:** `hmac.compare_digest()` is permitted for constant-time
comparison. `hmac.new()` / `hmac.HMAC()` are not permitted — use AMA's own HMAC
implementations.

### INVARIANT-1 Addendum — Algorithm Registry

All cryptographic primitives implemented in this library **must** map to a
non-deprecated entry in [`CSRC_STANDARDS.md`](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/CSRC_STANDARDS.md). Adding any
new algorithm requires updating `CSRC_STANDARDS.md` with its governing
standard, parameter set, status, and source URL **before** implementation is
permitted. Algorithms whose governing standard has been deprecated or
withdrawn must be removed from the library or explicitly documented with a
migration timeline.

### INVARIANT-1 Addendum — Vendoring Policy

Vendoring public-domain source into `src/c/vendor/` and compiling it as part
of AMA's own build system is permitted. Vendored source is included in-tree
and compiled from source as part of AMA's build system; its original license
(documented per component) is unaffected by vendoring. Vendored source
**must not** be linked as a pre-built binary.

See the **Vendored Dependencies** appendix at the end of this document for
the current inventory.

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

### INVARIANT-3 Addendum — Finalizer Failures Must Be Observable

Finalizers and destructors **may** catch broad exceptions to prevent
propagation.  However, silence must **never** be the only outcome.  Each
finalizer that catches an exception **must** produce an observable failure
state by **one** of the following means:

1. Incrementing a thread-safe internal error counter.
2. Setting an internal "finalizer error" flag.
3. Recording a last-error code retrievable via a health or self-test call.

Logging is optional.  It is sometimes unsafe during interpreter shutdown and
**must not** be relied upon as the sole observable artifact.

**Implementation:** `ama_cryptography/_finalizer_health.py` provides the
canonical `record_finalizer_error()` function and `finalizer_health_check()`
query API.  All `__del__` methods in cryptographic classes must call
`record_finalizer_error()` on exception.

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

## INVARIANT-7 — No Cryptographic Fallbacks, Ever

When the native constant-time C backend is unavailable, the library **must**
refuse to operate.  It **must** raise at import time, load time, or during
initialization.

The following are **not** acceptable substitutes:

- A pure-Python fallback for any cryptographic primitive or secret-dependent
  operation.
- A warning without a hard stop.
- A runtime flag that defers the safety decision.

If portability requires a fallback path, that path **must** be non-cryptographic
— for example, the monitoring math engine — and **must not** touch secrets under
any circumstances.

There is **no** runtime or development escape hatch for cryptographic
operation.  The failure mode for a missing backend is always a hard refusal
to operate under any code path that could touch secrets.

The sole import-time exception is **documentation builds**: when
`AMA_SPHINX_BUILD=1` (or `SPHINX_BUILD=1`) is set, the import-time guards
in `crypto_api.py`, `key_management.py`, and `legacy_compat.py` stand down
so that Sphinx `autodoc` can introspect signatures and docstrings without
a native library.  This override **does not permit any cryptographic
operation to proceed** — every call-time code path still invokes
`_enforce_invariant7*()`, which raises `RuntimeError` exactly as it would
at import time on a regular (non-docs) run.  In other words: INVARIANT-7
is preserved by a hop from import-time enforcement to call-time
enforcement under the documented docs-only flag, never weakened.

**Enforcement:** Module-level guards in `crypto_api.py`, `key_management.py`,
`legacy_compat.py`, and `pqc_backends.py` raise `RuntimeError` at import
time when the native C backend is unavailable, except under the
documented Sphinx/docs-build override above; under that override,
call-time enforcement (`_enforce_invariant7*`) still refuses any
cryptographic work without the native backend.

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

## INVARIANT-12 — Constant-Time Required for All Secret-Dependent Operations

All code paths that process secret material **must** be constant-time with
respect to that secret.

**Secret material** includes: private keys, seeds, shared secrets, symmetric
keys, MAC keys, intermediate values derived from those secrets, the presence
or absence of any of the above, and pre-verification MAC/tag comparisons.
The length or mere presence of a secret is itself secret when it is
attacker-observable.

### Rules

1. **Python delegation:** Python code **must not** implement secret-dependent
   cryptographic primitives (HMAC, KDFs, signature math, KEM decapsulation,
   AEAD tag verification).  Python handles non-secret orchestration only and
   delegates all secret operations to the native constant-time backend.

2. **No Python MAC/tag verification:** Python code **must not** perform MAC
   or tag verification logic, including partial parsing, other than passing
   data to the native backend and checking a boolean result.

3. **Constant-time comparison:** Must use `hmac.compare_digest()` or the
   project's constant-time C helpers (`ama_consttime_memcmp`).  Ordinary
   `==`, `memcmp`, or early-exit comparisons are **prohibited** in all
   secret verification paths.

4. **No secret-dependent branching:** Branching, table indexing, loop counts,
   and memory access patterns dependent on secret data are **prohibited** in
   both C and Python cryptographic paths.

**Enforcement:** CI runs constant-time verification checks (dudect, ctgrind,
custom timing harnesses, static structural scans) and **must** fail on
detection of secret-dependent variable-time constructs.  The project's
`CONSTANT_TIME_VERIFICATION.md` is the authoritative artifact for
verification methodology.

## INVARIANT-13 — No Unjustified Static-Analysis Suppressions

Use of `# noqa`, `# nosec`, `# pylint: disable`, `# type: ignore`, or any
equivalent suppression marker is **prohibited** unless **all three** of the
following conditions are met:

1. The suppression is **line-scoped**, not file-scoped.
2. It includes a **human-readable justification** and a **tracking reference**,
   for example: `# nosec B110: __del__ must not raise (FIN-001)`.
3. The suppressed line is **covered by tests** or a deterministic runtime check.

The **only** permitted exception is finalizers and destructors that must not
raise, provided the reason is explicitly documented inline.

Suppressions are **absolutely forbidden** in the following locations regardless
of justification:

- `src/c/` (core cryptographic C primitives)
- `ama_cryptography/_primitive` (if present)
- `ama_cryptography/backend` (if present)
- `include/ama_*.h` (C header files)

**Enforcement:** CI scans the repository for suppression tokens and **must**
fail if a suppression is missing a justification, missing a tracking ID, or
appears in a forbidden directory.

## INVARIANT-14 — CVE Ignore-List Hygiene

Every `--ignore-vuln` flag in CI workflows **must** have an accompanying comment
that states: (a) the CVE ID, (b) why the vulnerability is not exploitable in
this context, and (c) the condition under which the ignore should be removed.

Tracked ignores:

| CVE | Package | Reason | Remove when |
|-----|---------|--------|-------------|
| CVE-2026-4539 | Pygments (transitive via rich/bandit) | ReDoS in AdlLexer — dev-only, local access, not used at runtime | Pygments ships a fix (>2.20.0) or the transitive dependency is dropped |
| CVE-2026-3219 | pip (build-time installer) | pip handles concatenated tar+ZIP archives as ZIP regardless of filename. Build-time installer bug; ama-cryptography ships ZERO Python runtime dependencies, so this CVE has no runtime attack surface against the cryptographic API. CI installs from a pinned `requirements-lock.txt` (no attacker-controlled archives). No fix version released upstream as of 2026-04-24. | pip ships a fix (track via https://github.com/pypa/pip issue tracker) |

> **Review cadence:** Re-evaluate all tracked CVE ignores on the first of each
> quarter or when Dependabot bumps the affected package, whichever comes first.

## INVARIANT-15 — Thread-Safe CPU Dispatch via Platform Once-Primitive

All one-time initialization in `ama_cpuid.c` (CPU feature detection, AEAD
backend selection) **must** use a platform once-primitive that guarantees
exactly-once execution with full memory visibility across threads. The
approved primitives are:

- **POSIX** (Linux, macOS, BSDs): `pthread_once` (IEEE Std 1003.1)
- **Windows** (MSVC): `InitOnceExecuteOnce` (`synchapi.h`, Vista+)

Lockless flag + plain-variable patterns (e.g., `volatile int done` guarding a
non-atomic shared variable) are **prohibited** — they constitute data races
on weakly-ordered architectures and are undefined behavior under the C11
memory model.

C11 `<threads.h>` (`call_once`) is **not** used because it is unavailable on
macOS (Apple SDK has never shipped `<threads.h>`) and unreliable on MSVC
(partially shipped starting VS 17.8, still buggy). `CMakeLists.txt` uses
`find_package(Threads REQUIRED)` and links `Threads::Threads` to all library
targets.

---

## Vendored Dependencies

### ed25519-donna

- **Source:** https://github.com/floodyberry/ed25519-donna
- **License:** Public domain (Andrew Moon)
- **Location:** `src/c/vendor/ed25519-donna/`
- **CMake flag:** `AMA_ED25519_ASSEMBLY` (default **ON** on x86-64 and
  MSVC x64; default **OFF** on ARM and other non-x86 targets, where donna
  has no assembly path. Opt out of donna on x86-64 with
  `-DAMA_ED25519_ASSEMBLY=OFF`, which forces the in-tree fe51 + signed
  4-bit window comb backend in `src/c/ama_ed25519.c` — useful for
  clean-room auditing of the AMA-authored Ed25519 path.)
- **Purpose:** Optimized x86-64 Ed25519 scalar multiplication with inline
  assembly for constant-time Niels basepoint table selection. Provides ~3x
  keygen/sign speedup and ~2.5x verify speedup over AMA's fe51 C
  implementation on x86-64. The in-tree backend also uses a signed 4-bit
  window comb (BDLSY 2012) that closes most of that gap on platforms where
  donna is not available.
- **INVARIANT-1 compliance:** The vendored source is public domain, compiled
  from source as part of AMA's build system, and never linked as a pre-built
  binary. It satisfies INVARIANT-1 under the vendoring policy: vendored
  public-domain source is included in-tree and compiled as part of AMA's
  build system; its original public-domain license is unaffected by
  vendoring.
- **MSVC ARM64 limitation:** The donna backend provides x86-64 assembly
  only. The fe51 backend requires `__uint128_t`, which MSVC does not provide
  on any architecture. Therefore MSVC on ARM64 (Windows on ARM) has no
  working Ed25519 path. `CMakeLists.txt` emits `FATAL_ERROR` at configure
  time for this combination. To build on ARM64 Windows, use GCC or Clang
  (e.g., via MSYS2 or clang-cl) which provide `__uint128_t` and enable the
  fe51 backend.

---

_Maintained by Steel Security Advisors LLC._
_Last updated: 2026-04-20_
