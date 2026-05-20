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

### INVARIANT-8 Addendum — Reproducible-build CI gate is strict on native artefacts

The `reproducible-build` job in `.github/workflows/static-analysis.yml`
builds the wheel twice from identical inputs and **must** see byte-equal
output across (a) `INTEGRITY_DIGEST_HEX`, (b) every shipped `.py` file
except `_integrity_signature.py` (which is legitimately ephemeral per
INVARIANT-17), and (c) every compiled native artefact (`.so` / `.pyd` /
Cython `_bin.so`). The "(c)" lane was promoted from advisory to strict
in the audit Issue 10 deferral close-out and stays strict.

Three controls hold (c) reachable:

- **Container pin:** the job runs inside a specific
  `quay.io/pypa/manylinux_2_28_x86_64:<dated-tag>` image, both passes
  on the same tag. `:latest` is prohibited — it re-introduces
  host-toolchain drift between passes. If the pinned tag is yanked
  upstream, refresh to the next dated tag in the same release line.
- **Compiler flags:** `CFLAGS` includes
  `-fdebug-prefix-map=${PWD}=. -ffile-prefix-map=${PWD}=.` so the host
  cwd is stripped from DWARF debug info and `__FILE__` macros.
- **Archiver flags:** `AR_FLAGS=Drcs` and `LDFLAGS=-Wl,--build-id=sha1`
  drop per-object mtime in archives and force a deterministic build-ID
  derived from input bits.

If a new non-determinism surfaces (e.g., a future Cython release embeds
a timestamp in generated C), the remediation is at the root cause, not
a per-path exemption in the diff. Adding `--exclude` clauses to weaken
the strict gate is prohibited.

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
check on release tags, and the rendered SBOM **must** be a deterministic
function of the canonical package version in `pyproject.toml`.

The `security.yml` workflow triggers on `v*` tags so the SBOM job executes
automatically on every release. A repository administrator should add the
`SBOM Generation (CycloneDX)` job as a required status check on tag protection
rules to enforce the gate.

### INVARIANT-11 Addendum — No Hardcoded SBOM Versions

The committed CycloneDX SBOM for the C-library components
(`docs/compliance/sbom-c-library.json`) **must** be rendered exclusively from
`tools/generate_sbom.py`, which reads the package version from
`pyproject.toml` as its single source of truth. Hardcoded `"version": "X.Y.Z"`
literals inside CI workflows, heredoc-emitted SBOM fragments, or inline
component lists are prohibited.

**Enforcement:** The `sbom` job in `.github/workflows/security.yml` runs
`python tools/generate_sbom.py --check` and fails the workflow if the
on-disk SBOM diverges from a fresh render against pyproject.toml — so a PR
that bumps the package version without regenerating the SBOM cannot ship.

The `release.yml` workflow runs the same check inside its preflight stage
so a tagged release that forgot to regenerate the SBOM is blocked before
any wheel build happens.

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

Active ignores:

| CVE | Package | Reason | Remove when | Last reviewed |
|-----|---------|--------|-------------|---------------|
| _None_ | _N/A_ | No active `--ignore-vuln` flags remain in CI as of the Q2 review. | _N/A_ | 2026-05-14 |

Historical Q2 2026 review:

| CVE | Package | Review result | Evidence | Last reviewed |
|-----|---------|---------------|----------|---------------|
| CVE-2026-4539 | Pygments | Removed from CI ignores. `requirements-lock.txt` pins Pygments 2.20.0, which contains the upstream AdlLexer ReDoS fix. | https://github.com/pygments/pygments/issues/3058 | 2026-05-14 |
| CVE-2026-3219 | pip | Removed from CI ignores. CI upgrades pip before audit; pip 26.1 includes the archive-unpacking fix, and fresh CI-shaped audit environments with pip 26.1.1 report no known vulnerabilities. The library still has zero Python runtime dependencies, so there is no runtime cryptographic API attack surface. | https://github.com/pypa/pip/pull/13870 | 2026-05-14 |

> **Review cadence:** Re-evaluate all tracked CVE ignores on the first of each
> quarter or when Dependabot bumps the affected package, whichever comes first.
> Next scheduled review: 2026-07-01.

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

## INVARIANT-16 — Honest Compliance and Audit Claims

AMA Cryptography **must not** overstate validation, certification, audit, or
compliance status. Documentation and metadata must preserve the distinction
between implementation conformance, self-attestation, formal validation, and
independent review.

Required posture:

- **Algorithm-compliant** means the implementation is intended to follow the
  cited NIST/IETF/SEC/BIP specification and is tested against the project's
  available vectors. It does **not** imply formal laboratory validation.
- **ACVP self-attested** means AMA's CI has run the documented vector harness
  and published the resulting artifacts. It does **not** imply a NIST-issued
  CAVP certificate.
- **CAVP validated** may be claimed only after a corresponding certificate has
  been issued and can be cited.
- **CMVP / FIPS 140-3 validated** may be claimed only after a corresponding
  module certificate has been issued and can be cited.
- **Externally audited** may be claimed only after an independent qualified
  reviewer has produced an audit report or equivalent written attestation that
  can be cited. Community testing, internal review, CI, fuzzing, and static
  analysis are valuable but are **not** substitutes for an external audit.

Any README, package metadata, badge, release note, website/wiki page,
compliance report, or customer-facing text that mentions FIPS, ACVP, CAVP,
CMVP, certification, validation, attestation, or audit status **must** preserve
this exact claims boundary.

## INVARIANT-17 — Module Integrity Signing Must Remain Build-Time and Ephemeral

The module-integrity signing path (`ama_cryptography/_build_sign.py` and any
successor) **must** remain a build-pipeline-only mechanism. Runtime package
code must verify integrity artifacts; it must never be able to mint a new
trusted integrity signature over modified package contents.

Required properties:

- The signing command must be gated to the wheel/release build pipeline.
- The private signing key must never ship in wheels, source distributions,
  repository files, generated runtime artifacts, logs, caches, test fixtures,
  or package data.
- Default local builds must use an ephemeral per-build keypair and discard the
  private key before the build completes.
- Release CI may derive or inject the signing key from a CI-controlled seed or
  trust-anchor mechanism only when the release pipeline explicitly opts in and
  verifies the resulting public key against the compiled trust anchor.
- The only shipped integrity artifact should contain public verification data
  such as digest, public key, and signature.
- Missing, mismatched, malformed, or untrusted integrity artifacts must produce
  an observable failure state and must not silently bless modified Python
  modules as trusted runtime code.

This invariant exists to preserve post-build tamper detection without turning
integrity signing into a local attacker-controlled resigning oracle.

## INVARIANT-18 — ACVP Self-Attestation Must Stay Coupled to CI Coverage Floors

The ACVP self-attestation documents and CI vector-validation workflow **must**
remain in lockstep. Coverage must not silently shrink, drift from published
attestation artifacts, or pass CI merely because an expected-count constant was
not updated.

Any change that adds, removes, renames, skips, reclassifies, or retargets ACVP
vectors **must** update all affected artifacts in the same commit:

1. `.github/workflows/acvp_validation.yml` vector floor and ACVP reference.
2. `nist_vectors/` fetch/run logic and default ACVP reference, if changed.
3. `docs/compliance/acvp_attestation.json` totals and per-algorithm counts.
4. Customer-facing compliance reports that cite vector counts, pass/fail totals,
   skipped-vector semantics, or upstream ACVP reference.

The workflow must fail if any of the following drift from the published
attestation artifacts:

- total vectors tested;
- total vectors passed or failed;
- per-algorithm vector counts;
- algorithm names;
- upstream ACVP reference;
- expected floor semantics; or
- all-zero coverage for a listed algorithm.

Expanding coverage is welcome, but it must move the attestation JSON, CI floor,
ACVP reference, and compliance prose together so the published claim always
matches the evidence CI just produced.

## INVARIANT-19 — Hybrid KEM Combiner Construction Is Security-Critical

The hybrid KEM combiner is security-critical and **must** preserve the current
binding construction unless a cryptographic review explicitly approves a new
construction and the transcript test vectors are updated in the same change.

The production combiner must retain all of the following properties:

- HKDF-SHA3-256 using the RFC 5869 Extract-then-Expand construction;
- native constant-time HKDF backend for production secret-dependent operation;
- domain-separation label bound into `info`;
- explicit two-component binding (`component_count = 2` or equivalent);
- length-prefixed classical ciphertext and PQC ciphertext bound into `salt`;
- concatenated classical and PQC shared secrets as the input keying material;
- length-prefixed classical public key and PQC public key bound into `info`;
- fixed transcript ordering that cannot be canonicalized ambiguously; and
- fail-closed behavior when the native HKDF backend is unavailable.

Do **not** refactor, simplify, reorder, remove length prefixes, remove public-key
binding, change labels, substitute a KDF, or introduce an experimental combiner
in production paths without documenting the security rationale and updating the
relevant tests and compliance/design notes. Research KDFs or alternate combiners
may live only in clearly non-production modules that cannot be reached by the
production hybrid KEM provider.

## INVARIANT-20 — Constant-Time AES Must Remain the Default

The default AES-GCM build **must** use the constant-time cache-safe AES path
(`AMA_AES_CONSTTIME=ON`, implemented by `ama_aes_bitsliced.c` or a reviewed
constant-time successor). Table-based AES must never become the default again.

Required properties:

- CMake's default configuration must enable the constant-time AES path.
- Build output must clearly identify whether constant-time AES is enabled.
- Disabling constant-time AES must require an explicit opt-out build flag and
  must emit a clear warning that the resulting table-based path is not suitable
  for shared-tenant or side-channel-sensitive deployments.
- CI timing harnesses and constant-time verification tools must compile and
  exercise the production-default constant-time AES path, not a faster
  non-default table path.
- Documentation must describe table-based AES, if present, as an opt-out or
  test/benchmark compatibility path rather than the recommended build.

This invariant protects the project from regressing from the bitsliced/cache-safe
AES default back to lookup-table behavior that can leak through cache timing on
shared hardware.

### INVARIANT-20 Addendum — Explicit Opt-In for Table-Based AES

Disabling the constant-time AES path with `-DAMA_AES_CONSTTIME=OFF` alone is
**prohibited**. Operators who explicitly require the table-based path
(legacy hardware compatibility benchmarks, etc.) **must** also pass
`-DAMA_AES_TABLE_INSECURE=ON` to acknowledge the cache-timing exposure. The
CMake build system fails configuration with `FATAL_ERROR` when
`AMA_AES_CONSTTIME=OFF` is requested without the matching acknowledgement
flag.

The runtime API `ama_aes_gcm_active_backend()` (declared in
`include/ama_dispatch.h`) returns a constant NUL-terminated string
identifying the kernel actually selected by the dispatcher
(`"vaes-avx2"`, `"aes-ni-pclmul"`, `"arm-aes-pmull"`,
`"bitsliced-software"`, or `"table-insecure"`). Downstream integration
tests **should** assert at startup that this label is never
`"table-insecure"` unless the deployment is explicitly cleared for that
path.

**Test:** `tests/c/test_aes_gcm_backend_introspect.c` asserts both
properties at build time when `AMA_AES_CONSTTIME` is defined.

## INVARIANT-21 — X25519 Low-Order Outputs Must Be Rejected

X25519 key exchange **must** reject all-zero shared secrets produced by low-order
or otherwise invalid peer public inputs.

Required behavior:

- `ama_x25519_key_exchange()` and any successor API must OR-reduce or otherwise
  constant-time check the full 32-byte shared-secret output for all-zero.
- On all-zero output, the shared-secret buffer must be securely zeroed before
  returning failure.
- The API must return a hard cryptographic error, not a warning, partial result,
  nullable success value, or caller-configurable soft failure.
- Batch APIs must preserve equivalent fail-closed semantics: if any lane
  produces an all-zero shared secret, all batch outputs must be scrubbed and the
  batch must fail rather than exposing partially successful lane outputs.
- Tests must cover single-shot low-order rejection and batch all-zero rejection
  so future ladder or SIMD refactors cannot silently remove the check.

## INVARIANT-22 — AEAD Nonce Durability Must Fail Closed

AEAD nonce/counter tracking in the Python orchestration layer **must** remain
durable across process restarts and safe across concurrent processes for every
production path that auto-generates or tracks nonces.

Required behavior:

- Per-key nonce counters must be persisted before or atomically with exposure of
  a nonce to encryption, so a crash or restart cannot forget a used counter slot.
- Multi-process access to the same counter state must use an inter-process lock
  or an equivalently strong atomic update mechanism.
- Multi-threaded access within one process must serialize counter mutation.
- Malformed persistence files, truncated entries, invalid hex, lock failures,
  fsync/write failures, permission errors, or counter-state corruption must
  raise a hard error rather than continuing with partial nonce history.
- Nonce reuse detection must not use probabilistic data structures that can
  produce false negatives.
- Ephemeral mode is permitted only as an explicit test/hermetic-mode opt-in and
  must not be silently enabled for production encryption.
- Exceeding the configured per-key nonce safety limit must force re-keying or
  hard failure; it must not wrap, reset, or continue with a warning.

This invariant treats forgotten nonce history as a cryptographic safety failure,
not as recoverable telemetry loss.

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
_Last updated: 2026-05-19_
