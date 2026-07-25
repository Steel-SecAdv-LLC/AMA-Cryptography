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

**No exceptions.** An earlier revision of this document recorded one, for
the Docker build job in `ci-build-test.yml`, on the grounds that it used
`continue-on-error: true`. It does not and never did, and the comment above
the job forbids adding one. The false exemption was an invitation to
"restore" it on the next flake.

That job mitigates Docker Hub flakiness without weakening the gate: it routes
`docker.io` through `mirror.gcr.io` (`buildkitd-config-inline`), so the
base-image pulls that happen inside the BuildKit container — which the
runner's local cache cannot serve — are off the unauthenticated Docker Hub
path; it pre-pulls the BuildKit image with 8 attempts and capped backoff,
mirror first; and it logs in to Docker Hub when both credentials are set. A
real build or smoke-test failure is still a red job.

`continue-on-error: true` does appear twice, on the `actions/setup-python`
step in `ci.yml` and `ci-build-test.yml`, each followed by a retry step gated
on `steps.setup-python.outcome == 'failure'`. Neither is a security gate and
a genuine failure still fails at the retry.

## INVARIANT-3 — Observable Failure States

- No bare `except …: pass` that swallows security-relevant errors.
- No bare `return` that silently skips a test — use `pytest.skip(reason=…)`.
- No `2>/dev/null` or other stderr suppression used to hide the failure of a
  *substantive* step. Suppressing stderr on a pure **capability probe** — a
  command run only to discover whether a feature is available, whose failure
  is the answer rather than an error — is permitted and is what the tree
  does: `nice -n -10 true 2>/dev/null` (can this runner raise scheduling
  priority?) and `file "$f" 2>/dev/null | grep -q ELF` (is this an ELF
  object?). The distinguishing test is whether the suppressed output could
  have reported a real problem; for a probe whose result is immediately
  branched on, it cannot.
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
and `legacy_compat.py` raise `RuntimeError` at import time when the native C
backend is unavailable, except under the documented Sphinx/docs-build
override above.  `pqc_backends.py` enforces the same guarantee at **call
time** rather than import time: it records the backend as unavailable at
import (`*_NATIVE_AVAILABLE = False`) and every wrapper raises `RuntimeError`
before performing any operation without the native backend — and
`crypto_api.py`, which imports `pqc_backends`, layers the import-time gate on
top.  Under the docs override, call-time enforcement (`_enforce_invariant7*`)
still refuses any cryptographic work without the native backend.

## INVARIANT-8 — Deterministic Reproducible Builds

The C build system **must** document and enforce minimum compiler versions
(GCC >= 12, Clang >= 15) required for correct constant-time code generation
and SIMD intrinsics. The reference build environment is the pinned Docker
image (`ubuntu:22.04`) with the documented compiler toolchain.

**Enforcement:** By default, CMake will `FATAL_ERROR` if the detected compiler
does not meet the minimum version. To build on an unverified toolchain (e.g.,
for development or CI on older hosts), pass `-DAMA_ALLOW_UNVERIFIED_TOOLCHAIN=ON`
to downgrade to a `WARNING`.

### INVARIANT-8 Addendum — Native-Artefact Byte Equality

The release wheel's native artefacts (`libama_cryptography.so` / `.pyd`
and Cython-built kernel `.so` files) **must** be byte-identical across
two independent rebuilds from the same source tree.  This is enforced
by the `reproducible-build` job in `.github/workflows/static-analysis.yml`,
which builds the wheel twice inside a date-pinned `manylinux_2_28`
container with the following invariants on both passes:

- `SOURCE_DATE_EPOCH` pinned to a fixed reference epoch.
- `PYTHONHASHSEED=0` for deterministic dict iteration.
- `PYTHONDONTWRITEBYTECODE=1` (no `.pyc` files in the wheel).
- `CFLAGS` carries three overlapping prefix-maps targeting the
  workspace tree: `-fdebug-prefix-map`, `-ffile-prefix-map`, and
  `-fmacro-prefix-map`, each `=${{ github.workspace }}=.` (the
  Actions-expanded workspace root; the POSIX `${GITHUB_WORKSPACE}`
  form is deliberately NOT used, because it is not expanded inside an
  `env:` map and would reach the compiler as a literal string,
  silently disabling all three flags).  Strips host paths from DWARF
  debug-info, from `__FILE__` macro expansions, and from `-D` macro
  values respectively.
- `LDFLAGS+=-Wl,--build-id=sha1` derives the linker build-id from
  the section contents instead of a fresh-per-invocation random value.
- `MAKEFLAGS=-j1` + `CMAKE_BUILD_PARALLEL_LEVEL=1` force sequential
  compilation so parallel-build write-order variation cannot leak
  into the `.so`.
- `python -m build --wheel --no-isolation` skips PEP 517 build
  isolation, which would otherwise stage build deps inside
  `/tmp/build-env-<random8>/` and let that random path leak into the
  Cython-built `.so` via `__FILE__` expansion from NumPy headers.
  Build deps are pre-installed into the container Python in the
  workflow's "Install build prerequisites" step.

`AR_FLAGS` / `ARFLAGS` are deliberately NOT set — CMake's archive
creation invokes `ar` directly and ignores both env vars, and modern
binutils (`>= 2.27`, March 2016) defaults to deterministic archives
without flags.  If a future toolchain regression brings back
non-deterministic `ar`, the strict diff below catches it and the
fix is `CMAKE_C_ARCHIVE_CREATE` overrides — not an env var the
build doesn't read.

The container image is pinned to a date-stamped tag in the manylinux
project's `YYYY.MM.DD-N` format (NOT `:latest`, NOT the floating
`:manylinux_2_28` rolling tag) so the gate stays stable across the
project's rolling updates.  A tag bump is auditable: it must be its
own commit so the reproducible-build delta is visible in the diff.
The tag MUST be verified against
`https://quay.io/api/v1/repository/pypa/manylinux_2_28_x86_64/tag/`
before being committed — a fabricated date will fail the docker pull
with "manifest not found" on the first CI run and block the strict
gate.  Promoting the pin from a date-stamped tag to a `@sha256:`
digest pin is the natural follow-up (the digest does not float at
all, where the date-stamped tag could theoretically be force-pushed
upstream).

The signature artefact `ama_cryptography/_integrity_signature.py` is
explicitly exempt — INVARIANT-17 keeps the per-build ephemeral
signing keypair non-byte-stable.  The `_integrity_signature.py` exemption
is in the workflow's `.py`-equality check (which compares every OTHER
`.py` file byte-for-byte) and not in the native-artefact diff (where
the file does not appear).

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

### INVARIANT-12 Addendum — Per-Slot SIMD Constant-Time Verification

The nightly SIMD dudect sweep in `.github/workflows/dudect.yml`
(`dudect-simd-sweep`) **must** measure each dispatch-table-routable
SIMD slot in isolation via `AMA_DISPATCH_ONLY=<slot>`.  A t-value
regression on any slot is a hard fail, not a "noise" excuse — the
per-slot isolation is exactly what makes the t-value attributable
to a single SIMD kernel rather than to the union of every SIMD
path that happens to be on the host.

The slot inventory (also enumerated in `include/ama_dispatch.h` and
in CHANGELOG `[Unreleased]`) is the authoritative list.  Adding a
new dispatchable SIMD kernel **must** also:

- Extend `apply_dispatch_only()` in
  `src/c/dispatch/ama_dispatch.c` with a recognition branch for
  the new slot.
- Extend `KNOWN_SLOTS[]` in
  `tests/c/test_dispatch_only_env.c`.
- Add the slot to the dudect-simd-sweep matrix in
  `.github/workflows/dudect.yml`.
- Document the slot in this list and in the
  `ama_dispatch_active_slot()` block-comment in
  `include/ama_dispatch.h`.

Skipping any of the four bullets above silently downgrades the
constant-time gate for the new kernel from "explicitly measured"
to "assumed to ride the all-default-dispatch lane" — exactly the
ambiguity the close-out exists to remove.

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

## INVARIANT-23 — No Credential Material in the Public Tree

**Statement.** No live credential material — private keys, provider tokens, or
high-entropy secrets assigned to secret-named identifiers — may be committed to
this repository, and the gate that enforces this must itself be tested in both
directions.

**Why.** AMA Cryptography is a public repository whose tracked content is
largely *published high-entropy material*: NIST KAT vectors, ACVP responses,
fuzz seed corpora, and the Ed25519 public key plus detached signature in
`ama_cryptography/_integrity_signature.py`. That combination is the worst case
for an off-the-shelf secret scanner — it produces so many false positives that
teams reach for a blanket ignore file, and the blanket is what lets a real key
through later.

**Enforcement.** `tools/check_secrets.py` is an in-house scanner written
against this repository's actual layout (no third-party dependency, consistent
with INVARIANT-1). It runs as a fail-closed CI gate and as a `pre-commit` hook
in `--staged` mode.

**Testing duty (the load-bearing half).** A scanner that is never tested against
real credential shapes silently degrades into a no-op. `tests/test_secret_scanner.py`
pins BOTH directions:

- **Detection** — PEM/OpenSSH private keys, AWS access-key ids, GitHub PATs,
  Slack tokens, Google API keys, `Authorization` headers, tracked `.env` files,
  and high-entropy assignments to secret-named identifiers are each caught.
- **Non-detection** — published KAT vectors, the integrity public key, and
  documentation placeholders do NOT fire.

This dual duty is not optional: the detection tests are what caught a real gap
in the scanner's own identifier regex (a `\b` anchor never matches inside
`db_password`, because `_` is a word character).

**Evasion resistance (learned the hard way).** The scanner folds concatenated
string literals before matching, so a credential split across adjacent literals
(`"ghp_" + "..."`) is caught like any other. This is not hypothetical: during
this control's own development, splitting the test fixtures was used to get
them past both this scanner and GitHub push protection. That workaround passed
the gate while proving the gate had a hole. The hole is now closed and pinned
by `TestCatchesSplitLiteralEvasion`; obfuscating a value to avoid a finding is
a violation of this invariant, not a fix for one.

**Allowlist discipline.** Every allowlist entry in `tools/check_secrets.py`
carries a written justification for why that path cannot contain a live secret.
Silencing the scanner globally, adding an unjustified entry, or spelling a
value so it evades detection all violate this invariant. Where an exception is
genuinely required — as for the scanner's own detection suite, which must
contain credential shapes — it is taken as a **visible, path-based allowlist
entry with a written reason**, never hidden in how the value is written.

---

## INVARIANT-24 — Pinned Action SHAs Must Resolve Upstream

**Statement.** Every SHA-pinned GitHub Action in `.github/workflows/**` must
reference a commit that actually exists in the upstream repository, and the
trailing version comment must name a tag that SHA really points at.

**Why.** SHA-pinning is a supply-chain control only if the SHA is real. A pin
to a commit that exists nowhere is not "secure by accident" — it is a latent
outage that fires at the worst possible moment. `release.yml` carried
`pypa/cibuildwheel@e9c4a96e…  # v3.2.0`, a SHA present neither as the `v3.2.0`
tag object nor its dereferenced commit. Every wheel job aborted with
"Unable to resolve action … unable to find version", which is why the v3.2.0
and v3.3.0 releases both published **zero binary artefacts**. Nothing caught
it because `release.yml` only runs on a tag push — the pin was never resolved
until release day, and by then the release had already failed.

**Enforcement.** `tools/check_action_pins.py --strict` resolves every pin with
`git ls-remote` (read-only, no clone, no auth) and fails on any SHA that
matches no advertised ref, or whose version comment names a tag the SHA is not
actually under. Run in CI on every PR, so a bad pin fails on the change that
introduces it rather than on a release.

**Unverifiable is not valid.** If upstream cannot be reached, the checker exits
2 and reports the pin as inconclusive. It never treats an unverifiable pin as
passing.

---

## INVARIANT-25 — Workflow Runner Labels and Command Strings Must Be Valid

**Statement.** Every runner label named in `.github/workflows/**` must be a
GitHub-hosted image that currently exists, every embedded `python -c` payload
must compile, and every command string destined for `cmd.exe` must use quoting
`cmd.exe` actually honours.

**Why.** `release.yml` triggers on `push: tags: ['v*']` and nothing else, so a
defect inside it is invisible until a release is attempted. Three shipped that
way, each independently sufficient to produce a release with no artefacts:

1. **A retired runner label.** The wheel matrix named `macos-13` after GitHub
   retired that image. The job did not fail fast — it queued for a runner that
   would never arrive until `timeout-minutes` expired, failing `build-wheels`
   and every stage downstream of it.
2. **An inline Python payload broken by YAML folding.** `CIBW_TEST_COMMAND` was
   a folded scalar (`>-`), which joins the block's lines with a space. The
   payload reached the interpreter with a leading space and raised
   `IndentationError: unexpected indent`. Every wheel on every platform built
   correctly and then failed this one command.
3. **POSIX quoting handed to `cmd.exe`.** `CIBW_BEFORE_BUILD_WINDOWS` used
   single quotes to shield `>=` from redirection. `cmd.exe` does not treat a
   single quote as a quoting operator, so pip received it literally and every
   Windows wheel job died on `Invalid requirement: "'cmake"`.

All three are decidable without running anything.

**Enforcement.** `tools/check_workflow_commands.py` runs in CI on every PR. It
resolves `runs-on:` through `strategy.matrix` (including `include:` entries),
compiles every extracted `python -c` payload after applying the shell's own
double-quote unescaping, and rejects POSIX single-quoting in `*_WINDOWS`
cibuildwheel variables and `shell: cmd` steps. Both directions are pinned by
`tests/test_workflow_command_checks.py`, which replays all three historical
defects and asserts the legitimate shapes do not false-positive.

**Unresolved is not verified.** A label the checker cannot resolve statically
(an `inputs.*` expression, a matrix it cannot expand) is reported separately
and excluded from the verified count. It is never quietly counted as passing.

**Stated limitation.** GitHub publishes no API enumerating available hosted
labels, so `SUPPORTED_LABELS` is a curated table carrying the date and source
it was verified against. It catches an already-retired label, a typo, and a
label that never existed — it cannot predict a *future* retirement. The
authoritative detector for that is a `workflow_dispatch` dry run of
`release.yml` before cutting a tag, which is a release-procedure obligation,
not something this checker can discharge.

---

## INVARIANT-26 — Ed25519 Signatures Must Have a Canonical S

**Statement.** Every Ed25519 verification path must reject a signature whose
scalar half `S` is not in the range `0 <= S < L`, where
`L = 2^252 + 27742317777372353535851937790883648493` is the order of the base
point. This applies to single verification, batch verification, and both
compiled backends.

**Why.** RFC 8032 §5.1.7 requires the verifier to decode `S` "in the range
`0 <= S < L`" and to treat the signature as invalid if that decoding fails.
Neither backend enforced it, and Wycheproof `eddsa_verify_schema_v1` found it:
`tc63` (*checking malleability*) and `tc85` (*Signature with S just above the
bound*) both verified as **valid**.

* The vendored **ed25519-donna** path (x86-64 default) tested only
  `RS[63] & 224`, rejecting `S >= 2^253`. `L` is just above `2^252`, so the
  band `L <= S < 2^253` passed — exactly where `S + L` lands.
* The portable **fe51** path (`ama_ed25519.c`) performed no range check, and
  its scalar-multiply reduces mod `L` internally, so `S` and `S + L` produce
  the identical point.

The defect is signature malleability. Given any valid `(R, S)`, anyone can
emit `(R, S + L)` — a distinct 64-byte string that also verifies — without the
private key. Systems treating signature bytes as an identity (deduplication
caches, replay windows, content addressing, transaction ids) can be shown two
"different" signatures for one authenticated message.

**Enforcement.** `src/c/internal/ama_ed25519_canonical.h` provides the range
check as a `static inline`, included by **both** backends. It is header-only
because CMakeLists.txt swaps one backend source for the other, so a shared `.c`
would compile into only one configuration and the check could regress silently
in the other. Applied at three sites: `ama_ed25519_verify` in each backend, and
the donna batch wrapper — donna's batch routine calls its own
`ed25519_sign_open` rather than `ama_ed25519_verify`, so without the third site
batch verification would accept what single verification rejects.

**Not claimed as constant time.** `S` arrives in the signature and is public, so
a data-dependent branch here leaks nothing secret. The check is written
branch-free because it costs nothing at this size, not because INVARIANT-12
requires it here.

**Verification.** `tests/test_ed25519_canonical_s.py` pins the behaviour from
Python, `tests/c/test_ed25519_canonical_s.c` pins it from C across the
single-verify and batch paths, and the vendored Wycheproof corpus
(`wycheproof_vectors/`) runs all 150 Ed25519 vectors on every PR.

Note that `tests/c/test_ed25519_verify_equiv.c` case D.3 — "s-half replaced
with the group order `l`" — is **not** coverage for this defect, though it
reads like it. It rejects because `[l]B = identity` makes the *group equation*
fail, which it did against the unpatched code too. Only `S = s + L`, which
satisfies the group equation, isolates the range check. That distinction is
now recorded at both sites. Measured against a deliberately
unpatched build: `S + L` verified as **True** before the fix and **False**
after, with honest signatures verifying in both. Both backends were built and
run separately — 150/150 Wycheproof Ed25519 vectors pass on each.

## INVARIANT-27 — X25519 u-Coordinates Must Be Reduced Before Use

**Statement.** Every X25519 field path must reduce the received u-coordinate
modulo `p = 2^255 - 19` after masking bit 255, so that a non-canonical
encoding and its canonical form produce the same shared secret.

**Why.** RFC 7748 §5 `decodeUCoordinate` masks bit 255 and stops, so a decoded
u can land anywhere in `[0, 2^255)`. Nineteen of those values — `[p, 2^255)` —
are representable but not canonical: each names a field element that also has
a smaller encoding. The RFC then performs arithmetic mod `p`, so the element
such an encoding denotes is unambiguously `u mod p`.

All three field paths in `src/c/ama_x25519.c` (fe64, fe51, gf16) masked the
top bit and never reduced, so a u in that band was consumed unreduced.
Wycheproof `x25519_test` **tc88** is exactly this case: its u is `p + 3`, and
AMA derived a shared secret that no other implementation computes.

RFC 7748 does not *require* the reduction and Wycheproof scores the case
`acceptable`, so this is an interoperability decision rather than a break. It
is decided in favour of reducing because the failure mode is silent and
undiagnosable: two peers that agree on a public key derive different shared
secrets, and the handshake simply fails. Every reference implementation
(ref10, curve25519-donna, libsodium) normalizes and therefore agrees with the
reduced interpretation.

**Enforcement.** `x25519_canonicalize_u()` in `src/c/ama_x25519.c` masks bit
255 and performs one conditional subtraction of `p` — one suffices, because
after masking the value is below `2^255 = p + 19`. All three ladders call it
before decoding. The subtraction is performed unconditionally and the result
selected with an arithmetic mask, so there is no branch and no value-dependent
memory access.

It is applied to the 32-byte encoding rather than inside `fe51_frombytes` /
`fe64_frombytes` because those helpers are shared with Ed25519, whose point
decoding has the opposite rule: RFC 8032 §5.1.3 requires a non-canonical `y`
to be **rejected**, not reduced. Changing them would silently alter signature
verification.

**Not a constant-time requirement.** The u-coordinate is a peer's public key
and is public. The implementation is constant time regardless.

**Verification.** `tests/test_x25519_canonical_u.py` pins tc88, the general
non-canonical/canonical agreement property, the full `[p, p+18]` band, and
the bit-255 masking rule. The Wycheproof gate runs all 518 X25519 vectors on
every PR; `wycheproof_vectors/run_wycheproof.py` additionally pins that
exactly 31 low-order public keys are rejected under RFC 7748 §6.1 rather than
returning an all-zero shared secret.

## INVARIANT-28 — ECDSA Signatures Must Be Low-s and Strictly Encoded

**Statement.** `ama_secp256k1_ecdsa_sign` must emit only the canonical low
representative (`s <= (n-1)/2`), and `ama_secp256k1_ecdsa_verify` must reject
a high `s`, an `r` or `s` outside `[1, n-1]`, and any signature that is not
minimal DER.

**Why.** ECDSA's verification equation is symmetric in the sign of `s`: for
every valid `(r, s)`, the pair `(r, n - s)` also verifies. That is signature
malleability — the same defect class as INVARIANT-26 — and it is reachable by
anyone holding a signature, with no private key. Range and encoding
permissiveness are the same problem by other means: an `r >= n` that is
silently reduced, or a non-minimal INTEGER, each yields a second distinct byte
string that verifies for one message.

Wycheproof's ECDSA suite is largely an encoding-abuse corpus; a permissive
parser fails it loudly, which is the point.

**Enforcement.** In `src/c/ama_secp256k1.c`: `sc_is_high()` decides the low-s
question against `(n-1)/2`; signing negates a high `s` before encoding;
verification rejects one. `der_parse_signature()` accepts only
`30 <len> 02 <rlen> <r> 02 <slen> <s>` with short-form lengths, minimal
INTEGERs, no superfluous leading zero, no negative value, and no trailing
bytes. `sc_from_bytes()` reports whether its input was already `< n`, so an
out-of-range `r`/`s` is rejected rather than reduced.

**Deliberate divergence from Wycheproof, declared.** The corpus scores
high-`s` signatures `valid`, because plain X9.62 accepts them. AMA rejects
them. All 72 such vectors are claimed by the named
`ecdsa/high-s-rejected` policy in `wycheproof_vectors/run_wycheproof.py`,
with the reason and an exact expected count, so the divergence is visible in
the gate's output rather than absorbed into a pass.

**Timing posture.** Signing is constant time with respect to the private key
and the RFC 6979 nonce: scalar arithmetic mod `n` is Montgomery form with no
data-dependent branch, and inversion uses a fixed chain over the public
exponent `n - 2`. Verification is variable time by design — every input is
public — matching what `ama_ed25519_batch_verify` states.

**Verification.** `tests/test_secp256k1_ecdsa.py` (32 tests) covers RFC 6979
determinism, nonce non-reuse across messages and across keys, rejection of the
high-`s` twin of a signature the library itself produced, and each strict-DER
rule. All 476 Wycheproof ECDSA vectors run on every PR; 308/308 of the
`invalid` (encoding-abuse) vectors reject correctly.

---

_Maintained by Steel Security Advisors LLC._
_Last updated: 2026-07-25_
