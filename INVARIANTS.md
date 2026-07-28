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

**Nor invoked.** "Must not import or call" covers a subprocess as squarely as an
import: shelling out to `openssl` is a competing implementation performing a
cryptographic operation inside AMA at runtime, and it adds an undeclared
dependency on that binary being installed. `ama_cryptography/legacy_compat.py`
did exactly that for RFC 3161 timestamping until the `TimeStampReq` encoder and
the `TimeStampResp` / `TSTInfo` decoder were written against RFC 3161 §2.4.1 and
§2.4.2 using AMA's own DER codec. `tools/check_corpus_originality.py` scans
`ama_cryptography/` for such invocations (INVARIANT-36), so the rule is enforced
rather than asserted.

Naming another implementation is not calling it. Curve aliases such as
`prime256v1` are wire-format spellings AMA must *accept*, and a comment
crediting where an approach came from is scholarship; the check works on the AST
so neither trips it.

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

**A gate must also be legible, and this is not a stylistic point.** The Bandit
severity gate spent its life red for a reason that did not exist: it grepped
`^\s*(Medium|High):\s*[1-9]` over Bandit's text report, which prints a
by-severity and a by-confidence tally under the same labels and the same
indentation, so it matched the confidence one. A gate whose failure message
names a condition nobody can reproduce gets routed around, and that is a
fail-open outcome arrived at through a fail-closed mechanism. Gates over tool
output **must** therefore read a structured format where the tool emits one —
`tools/check_bandit_severity.py` consumes Bandit's JSON — and **must** fail
closed on a report that is missing, malformed, error-carrying, empty, or
pre-filtered, since none of those establishes that the tree is clean.
`tests/test_bandit_severity_gate.py` demonstrates the rejection direction for
each of those conditions; a gate with no negative control has not been shown
to be a gate at all.

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
must compile, every command string destined for `cmd.exe` must use quoting
`cmd.exe` actually honours, and every release-creating step must be safe under
immutable releases and under a re-run for a tag already published.

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

A fourth class was added after v3.4.0, when immutable releases were enabled on
this repository. Immutable releases freeze a release's tag and assets at
publish; the title and notes stay editable. Three properties of the
`softprops/action-gh-release` step follow from that, none of which fail until a
tag is pushed:

4. **Release text destroyed, or a prerelease frozen before upload.** `name:`
   overwrote a hand-edited release title, because `updateRelease` resolves
   `input_name || existingRelease.name || tag`. `body:` without
   `append_body: true` overwrote hand-edited notes, because the body resolves
   as `workflowBody || existingReleaseBody`. And a prerelease with assets was
   never drafted — `createRelease` computes
   `draft = prerelease === true ? input_draft === true : true`, so only a
   *non*-prerelease drafts automatically — leaving a published `-rc` whose
   assets freeze before the upload, which then fails with *Cannot upload assets
   to an immutable release*.

**Enforcement.** `tools/check_workflow_commands.py` runs in CI on every PR. It
resolves `runs-on:` through `strategy.matrix` (including `include:` entries),
compiles every extracted `python -c` payload after applying the shell's own
double-quote unescaping, rejects POSIX single-quoting in `*_WINDOWS`
cibuildwheel variables and `shell: cmd` steps, and checks every step using a
release-creating action for the three properties above. A `${{ ... }}`
expression counts as neither true nor false there: a step that drives `draft:`
from the same condition as `prerelease:` has handled the case, and the checker
does not second-guess a value it cannot evaluate. Both directions are pinned by
`tests/test_workflow_command_checks.py`, which replays all four historical
defect classes — including the pre-fix `release.yml` step reproducing all three
release-publishing findings at once — and asserts the legitimate shapes do not
false-positive.

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

The high-`s` rejection — and only that — is caller-selectable through
`ama_secp256k1_ecdsa_verify_ex(..., flags)`: the strict default
(`ama_secp256k1_ecdsa_verify`) rejects it; `AMA_SECP256K1_ECDSA_ALLOW_HIGH_S`
accepts it for conformant third-party X9.62 interop. The range and minimal-DER
requirements are never relaxed by any flag, and the signing path always emits
low-`s` regardless. Strict is the default precisely because it keeps a
signature a unique identifier for its (key, message) pair.

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

## INVARIANT-29 — ECDSA Public-Key Coordinates Must Be Canonical Field Elements

**Statement.** `ama_secp256k1_ecdsa_verify` must reject a public key whose `Qx`
or `Qy` coordinate is not a canonical field element in `[0, p)`. A coordinate
`>= p` is rejected, never reduced modulo `p` before the curve-membership check.

**Why.** This is the same input-canonicalization class as the `r, s ∈ [1, n-1]`
range check of INVARIANT-28 and the `0 <= S < L` check of INVARIANT-26: a
coordinate `>= p` is a second, non-canonical byte encoding of the reduced point,
and unreduced field arithmetic would otherwise accept it — letting one signature
verify under two distinct public-key encodings. Rejecting it keeps a signature
bound to a single public-key byte string.

It is the deliberate policy analogue of INVARIANT-27's X25519 non-canonical-`u`
decision, resolved the other way: X25519 *reduces* (two peers must agree on one
shared secret), whereas an ECDSA verification key is *rejected* (a signature
must not verify under a second encoding of the key). For secp256k1 the
non-canonical band `[p, 2^256)` holds only `2^32 + 977` representable values, so
this is a narrow but real defense-in-depth gate — and it matches libsecp256k1's
own rejection of `secp256k1_fe_set_b32` overflow.

**Enforcement.** In `src/c/ama_secp256k1.c`, `secp256k1_fe_bytes_canonical()`
compares the 32-byte big-endian coordinate against `p` and returns 0 for any
value `>= p`; `ama_secp256k1_ecdsa_verify` calls it on both `Qx` and `Qy` before
the curve equation is evaluated, returning `AMA_ERROR_VERIFY_FAILED` on a
non-canonical coordinate. Verification is variable time by design (the public
key is public), so the data-dependent early return carries no timing obligation.

**Verification.** `tests/test_secp256k1_ecdsa_noncanonical_pubkey.py` drives the
policy through the Python binding (`Qx`/`Qy` in `{p, p+1, 2^256-1}` rejected, a
canonical key accepted). `tests/c/test_secp256k1.c` isolates the predicate from
the curve/signature checks via the `AMA_TESTING_MODE` export
`ama_secp256k1_test_fe_bytes_canonical` (Test 10: `p-1` / `0` / real coordinates
canonical; `p` / `p+1` / `2^256-1` not). The full-verify path cannot make that
distinction, because a valid signature for a public key in the tiny reduced
image would require an ECDLP solution or an ECDSA forgery — so the isolated
predicate test is the one that proves the gate fires.

## INVARIANT-30 — Agent-Instance Persistence Material Must Be Operator-Authorized

**Statement.** Key material or signature contexts carrying a non-`EPHEMERAL`
lifetime, or any capability in `AMA_AGENT_CAP_RESTRICTED_MASK`
(`PERSISTENCE`, `SELF_REPLICATE`, `DELEGATE`), **must not** be produced unless
the binding carries a non-zero ethical-profile hash *and* an authorization tag
that verifies under an operator-supplied authority key. Every refusal is
fail-closed: no output bytes, a distinct error code, and no partial state.

**Why.** In July 2026 an autonomous evaluation agent escaped its sandbox via a
zero-day, moved laterally, reached the open internet, and operated as a
short-lived self-migrating swarm — leaving signed notes intended for future
versions of itself. Two cryptographic capabilities are load-bearing for that
behaviour and for essentially nothing else a legitimate caller needs: key
material that *outlives the agent instance* (persistence), and signatures a
*later* instance would treat as authoritative (self-replication). Ordinary
per-message signing and ephemeral session keys are neither, and stay on the
unauthorized fast path. Gating only the two dangerous populations keeps the
common case free of ceremony while making the dangerous case require a secret
the agent does not hold.

Domain separation is the second half of the property, and it is what makes the
gate more than a policy flag. The canonical 88-byte binding encoding is folded
into HKDF's `info` and hashed into the signature context, so material derived
under one binding is cryptographically unrelated to the same input under any
other — including a binding that differs only in its lifetime byte or a single
capability bit. An agent cannot relabel ephemeral material as persistent after
the fact; it would have to derive it again, which is the call that is refused.

**Enforcement.** `src/c/ama_agent_binding.c`. `ama_agent_binding_check()` is
the single policy point; `ama_hkdf_agent_bound()` and
`ama_agent_binding_context()` both call it before producing anything and write
no output on refusal. The authorization tag is
`HMAC-SHA3-256(K_auth, 0x01 || enc(b))` over the whole record, so post-hoc
capability escalation or lifetime relabelling invalidates it. The refusal path
is constant-time by construction: every policy predicate is evaluated into a
single mask with no short-circuiting, the HMAC is computed even when no
authority key was supplied, the tag comparison always runs over all 32 bytes
via `ama_consttime_memcmp`, and the function has one arithmetically-selected
exit — so neither *whether* the check failed nor *which* clause failed is
distinguishable by timing. No new algorithms are introduced: the layer is
domain separation and policy over SHA3-256, HMAC-SHA3-256 and HKDF
(INVARIANT-1 preserved).

**Verification.** `tests/c/test_agent_binding.c` pins the canonical encoding as
a byte KAT (a change there silently re-keys every deployment), and covers
structural refusals, missing authorization, foreign-key tags, single-bit tag
flips, capability escalation, and cross-binding derivation separation.
`tests/test_agent_binding.py` drives the Python surface, including
property-based injectivity over the encoding.
`tests/test_agentic_load_adversarial.py` runs the four adversarial scenarios
(high-concurrency ephemeral load, future-version note simulation,
lateral-probe simulation, fail-closed under parallel load). The constant-time
claim is measured by the `Agent binding check` lane in
`tests/c/test_dudect.c`, which is registered strict (`is_info_only = 0`) and
therefore fails CI on |t| >= 4.5.

`fuzz/fuzz_agent_binding.c` attacks the same invariant from the other
direction. Where the tests above assert the policy on *chosen* records, the
fuzzer builds records from arbitrary bytes — out-of-range lifetimes, undefined
capability bits, a non-zero reserved byte — and traps if a restricted record is
ever accepted without a usable authority key and a non-zero ethical profile,
if key material is derived for a refused binding, if a refusal writes into the
caller's output buffer, or if a tampered authorization tag verifies. It also
drives `info_len` across the 256-byte stack/heap boundary inside
`ama_hkdf_agent_bound()`. This is a *core* (non-PQC) fuzz target, so it runs
in both configurations.

The binding layer calls only SHA3-256 / HMAC-SHA3-256 / HKDF, so it carries no
`AMA_USE_NATIVE_PQC` dependency: `test_agent_binding` builds and passes in both
the default (PQC on) and the PQC-off configurations, and the
`ci-build-test.yml` configuration-guard job proves it on every PR.

---

## INVARIANT-31 — Every Pull-Request Job Must Be Reachable From Its Gate

**Statement.** Every job in a workflow that triggers on `pull_request` **must**
appear in the `needs:` of an aggregating gate job in that same workflow, and
every gate job **must** carry a job-level `if: always()`. A workflow with more
than one job that runs on `pull_request` must define a gate.

**Why.** Branch protection here requires each workflow's aggregating gate
context (`ci-gate`, `static-analysis-gate`, `fuzzing-gate`, …) rather than the
individual job names, so that the required-context list lives in the repository
under code review instead of drifting in the branch-protection UI as jobs are
added and renamed. The cost of that design is a failure mode that points the
wrong way: a job omitted from the gate's `needs:` still runs and still shows a
red X on the pull request, but branch protection never evaluates its context,
so **it cannot block the merge**. The pull request shows a failing check beside
a green required gate, and "all required checks passed" is true.

That was live, not hypothetical. `c-library-no-native-pqc` guards the
`AMA_USE_NATIVE_PQC=OFF` build — the configuration used by consumers who take
the library without native post-quantum support — and was absent from
`ci-build-test.yml`'s gate while that exact configuration broke and had to be
repaired. The guard ran and gated nothing. The closing paragraph of
INVARIANT-30 above asserts that this job "proves it on every PR"; that sentence
was only true once the job was wired in.

The `if: always()` half is a distinct failure. Without it a gate is *skipped*
when any dependency fails, and a required context that reports `skipped` never
resolves — the pull request waits on "Expected — waiting for status check to be
reported" instead of going red. A gate that cannot report red is not a gate.

**Enforcement.** `tools/check_gate_coverage.py`, run in the `security-checks` job
of `ci.yml`. Single-job workflows are exempt by construction (the job *is* its
own status context) as are workflows that never trigger on `pull_request`
(`release.yml` on a tag push, `wiki-sync.yml` on a push to main) — branch
protection cannot require a context they never produce. The checker also
reports a `needs:` entry naming a job that does not exist, which makes the gate
fail to start rather than report red.

**Verification.** `tests/test_gate_coverage.py` pins both directions: detection
of an uncovered job, a gate without `if: always()`, a multi-job pull-request
workflow with no gate, and a dangling `needs:` entry; non-detection for the
shapes this repository legitimately uses. A dedicated regression test asserts
`c-library-no-native-pqc` specifically, and a sweep runs the rules over every
workflow in `.github/workflows/`.

---

## INVARIANT-32 — Documented Install Commands Must Resolve

**Statement.** Every optional-dependency extra named in a `pip install` command
in the tracked documentation set **must** be declared in
`[project.optional-dependencies]` in `pyproject.toml`, compared under PEP 685
normalisation.

**Why.** `pip` does not fail on an extra a distribution does not provide. It
emits a warning, installs the package **without** it, and exits 0. So a stale
or misspelled name in an install instruction does not produce an error the
reader can act on — it produces a package missing the dependencies the reader
was told they were installing, plus a success message. The failure surfaces
much later as an `ImportError` from a subsystem the user believes they enabled.

That shipped, on the page new users read first. `wiki/Installation.md` —
published to the public GitHub Wiki by `wiki-sync.yml` — offered an editable
install for an extra named `secure-memory`, described it as *"Libsodium secure
memory bindings"*, and included the same name in its *"Everything at once"*
command. No such extra has ever existed. `ama_cryptography.secure_memory` is
dependency-free — Python standard library plus the native C library already
built in the preceding step — so no extra could deliver anything. And
advertising a *libsodium* binding contradicted INVARIANT-1 outright, on a
public page, for a project whose stated position is zero external
cryptographic dependencies.

An install instruction is API surface. A reader cannot verify it without
running it, and running it reports success either way.

**Enforcement.** `tools/check_documented_extras.py`, run in the `security-checks`
job of `ci.yml`. `CHANGELOG.md` is excluded by design: it is a historical
record, and an extra that genuinely existed in an earlier release must remain
readable in the entry that introduced or removed it.

**Verification.** `tests/test_documented_extras.py` pins both directions:
detection of the historical defect in its single-extra and comma-separated
forms; non-detection for declared extras, PEP 685 punctuation and case variants
(which pip itself accepts), Markdown link syntax, and lines that are not
install commands. A sweep runs over the repository's own documentation, a
regression test asserts the `secure-memory` name is gone from the wiki, and the
reverse direction is checked too — a declared extra named in no install
instruction fails, since an extra nobody is told about may as well not exist.

---

## INVARIANT-33 — Every Fuzz Harness Must Be Registered Everywhere

**Statement.** Every translation unit in `fuzz/` that defines
`LLVMFuzzerTestOneInput` **must** appear in the CMake target lists, in the
`fuzzing.yml` job matrix (actively, or commented out with a recorded reason),
and in `oss-fuzz/build.sh`. No registry may name a target with no source file.

Every Python harness under `fuzz/python/` **must** be run by `fuzzing.yml`.
Those are not libFuzzer targets, so they have one registry rather than three,
and the same rule applies: a harness that exists and is never run is
indistinguishable from one that finds nothing.

**Why.** A harness is registered in three independent lists, and nothing tied
them together. `oss-fuzz/build.sh` even carries the comment *"Keep in sync
with fuzz/CMakeLists.txt"* — and had drifted anyway: `fuzz_agent_binding` was
added to the CMake lists and to the CI matrix when the agent-binding layer
landed, and never to `build.sh`. OSS-Fuzz therefore never built it. The
omission was invisible because `build.sh` skips a missing target with a
warning and exits 0.

That is the worst shape a coverage gap can take. The harness exists, it is
exercised in CI, and the continuous fuzzing meant to run it for months does
not — so the project believes it has coverage it does not have. A harness
nobody runs is indistinguishable from one that finds nothing.

**Enforcement.** `tools/check_fuzz_target_registration.py`, run in the
`security-checks` job of `ci.yml`. A commented-out matrix entry counts as
registered: not every harness belongs in the per-PR lane (`fuzz_sphincs` is
excluded because SPHINCS+ is too slow for CI, with the reason recorded beside
it), but such a target must still be in both build lanes so OSS-Fuzz keeps
running it. The checker distinguishes a *deliberate, documented* exclusion
from silent drift.

**The Python lane, and why it exists.** `ama_cryptography/_asn1.py` and
`key_formats.py` are hostile-input parsers in exactly the sense the fifteen C
harnesses are — anyone who can hand you a key file reaches them — and they had
no harness at all. What they had was a deterministic mutation sweep inside
pytest: 120 fixed mutations per algorithm from one seed, which explores the same
neighbourhood on every run for ever. That is worth having and it is not fuzzing,
so it was kept and `fuzz/python/fuzz_key_formats.py` was added beside it.

The harness is AMA's own — its generator, mutator and seed corpus are in the
file — so the lane depends on no third-party fuzzing engine (INVARIANT-36).
Atheris is supported via `--atheris` when it happens to be installed,
deliberately as a bonus rather than as the lane.

It earned its place immediately. Five real parser defects on its first
campaigns, each one an input reaching a layer not written for it:

1. `UnicodeDecodeError` out of `_as_der`, on PEM-as-bytes containing a
   non-ASCII octet — a `ValueError` subclass, so `except KeyFormatError` at the
   boundary was not sufficient.
2. `TypeError: unhashable type` out of `_cose_algorithm`, from a nested CBOR map
   used as a `crv` value. The JSON side already carried this fix; the CBOR side
   did not.
3. Strict-RFC-7468 PEM accepting a trailing `0x1F`, because Python's
   `str.strip()` counts U+001C–U+001F, U+0085 and U+00A0 as whitespace and
   RFC 7468 does not.
4. Non-canonical base64 accepted: `b64decode(validate=True)` checks the
   alphabet, not the padding bits, so `…Of3N=` and `…Of3M=` decoded to one key.
   Found after 7.5 million executions.
5. An out-of-range EC private scalar in a key file raising `RuntimeError` past
   the format layer — which in turn surfaced that `secp256k1` accepted a scalar
   at or above the group order where the NIST curves refused it, so one library
   was strict on one curve and lax on another. Found after 17.8 million
   executions.

Each is pinned by a named regression test in `tests/test_key_formats.py`, so
pytest catches a recurrence without waiting for a campaign to rediscover it.

**Verification.** `tests/test_fuzz_target_registration.py` pins both
directions over a synthetic tree — missing from OSS-Fuzz, missing from CMake,
a registry naming a nonexistent target, and a fully consistent tree — plus the
repository's own registration. Three non-detection cases are pinned
specifically because the checker's first draft produced them as false
positives, and each would have pushed a maintainer to "fix" a repository that
was already correct: a support translation unit that is not a harness
(`fuzz_rng.c`), a file that merely *names* `LLVMFuzzerTestOneInput` in a
comment, and a CMake comment containing a parenthesis that truncated the
parsed block.

`tests/test_python_fuzz_harness.py` does the same for the Python lane, and for a
reason specific to it: the harness runs for a time budget in `fuzzing.yml`, so
nothing in the ordinary suite would notice if its contract check broke — it
would run its millions of executions and report success for ever. So the suite
drives it in-process and violates each contract it claims (an unexpected
exception, a non-canonical acceptance, a slow parse, a missing artifact) to
confirm each is still caught.

---

## INVARIANT-34 — Low-`s` Is a Property of the Sign/Verify Pair

**Statement.** Low-`s` normalisation and high-`s` rejection are **two halves of
one control**. A curve's default must set both or neither, and any API that
exposes them must expose both.

- **secp256k1** sets both by default: `ama_secp256k1_ecdsa_sign` emits only the
  low representative and `ama_secp256k1_ecdsa_verify` rejects the high twin
  (INVARIANT-28). `AMA_SECP256K1_ECDSA_ALLOW_HIGH_S` relaxes the verifier for
  third-party X9.62 interop.
- **P-256 / P-384 / P-521** set neither by default: `ama_nistp_ecdsa_sign`
  emits RFC 6979's `s` verbatim and `ama_nistp_ecdsa_verify` accepts either
  representative. `AMA_NISTP_ECDSA_SIGN_LOW_S` and
  `AMA_NISTP_ECDSA_REQUIRE_LOW_S` turn both halves on together.

The checks that cost no interoperability are unconditional on every curve in
every mode: minimal DER only, `r` and `s` strictly in `[1, n-1]` rather than
reduced into range, and public-key coordinates strictly in `[0, p)`.

**Why.** Normalisation on its own prevents nothing. If the verifier accepts
both representatives, then given any AMA signature `(r, s)` anyone can emit
`(r, n - s)` and AMA itself will accept it. The signature is malleable
regardless of what the signer chose. Normalisation only becomes a security
property when the verifier refuses the twin — the pair is the control, and
either half alone is a costume.

This is not hypothetical: it is the defect this invariant was rewritten to fix.
The first version of the NIST prime-curve support normalised on the signer and
verified permissively — the one combination with no security benefit — and paid
for it in conformance. `ama_nistp_ecdsa_sign` advertised itself as
"deterministic per RFC 6979" while failing RFC 6979's own Appendix A.2.5 /
A.2.6 / A.2.7 vectors on every case whose natural `s` came out high, roughly
half of them. `r` matched everywhere, so the nonce derivation was right and the
divergence was invisible to every test that existed.

It was invisible for a second, worse reason. The "independent" pure-Python
reference in `tests/test_nistp_curves.py` normalised too, because it was
written alongside the C code rather than from the specification. Two
implementations that share an assumption do not check each other. **A reference
must be derived from the specification only, never from the implementation it
checks** — that rule is the durable lesson here, and it is why `_ref_sign` now
takes the policy as a parameter instead of baking one in.

The per-curve defaults then follow from what each curve is *for*. secp256k1
signatures are identifiers — a blockchain transaction is addressed by its
signature bytes, so two valid encodings means two identities, and AMA controls
both ends, so strict is free. The NIST prime curves exist here to interoperate
with signers AMA did not write: X9.62, FIPS 186-5, RFC 3279, TLS, X.509, JWS
and WebAuthn all permit either `s` and essentially none of their signers
normalise, so a strict default would reject conformant signatures — not "more
secure", just non-interoperable, defeating the reason the curves were added.

**Enforcement.** In `src/c/ama_nistp.c`, `nistp_ecdsa_sign_core()` takes
`low_s` as a parameter and `nistp_sign_dispatch()` derives it from
`AMA_NISTP_ECDSA_SIGN_LOW_S`; unknown flag bits are rejected rather than
ignored. `nistp_ecdsa_verify_rs()` rejects a high `s` only under
`AMA_NISTP_ECDSA_REQUIRE_LOW_S`. The range, canonical-coordinate and strict-DER
gates sit outside both flags. `src/c/ama_secp256k1.c` is unchanged.

**Wycheproof consequence, declared.** The secp256k1 divergence policy
`ecdsa/high-s-rejected` claims exactly 72 vectors and is scoped by filename.
The three NIST prime-curve suites — 1530 vectors — need no divergence policy at
all and pass with zero exceptions. That asymmetry in the gate output is the
visible evidence for this invariant: making the NIST default strict would
create a new uncounted divergence bucket and turn the gate red.

**Timing posture.** Signing is constant time with respect to the private key
and the RFC 6979 nonce on both curves; the normalisation is a conditional
negation of a value that is about to be published. Verification is variable
time by design on both — every input is public.

**Verification.**
`tests/test_nistp_curves.py::test_rfc6979_published_vectors` replays all 18
in-scope vectors from RFC 6979 Appendix A.2.5/A.2.6/A.2.7 (vendored under
`tests/kat/rfc6979/`), asserting the RFC's own public key and both signature
components, and fails if the corpus ever stops containing a high-`s` case —
without one it could no longer detect silent normalisation.
`test_rfc6979_vectors_reject_low_s_normalisation` pins the opposite direction,
so the trade-off is a fact in CI rather than a claim in a docstring.
`test_low_s_is_opt_in_and_default_is_rfc6979_verbatim` requires the default to
produce at least one high `s` over 24 signatures.
`test_low_s_is_a_property_of_the_sign_verify_pair` asserts the four-way truth
table directly. `test_ecdsa_matches_rfc6979_reference` runs the
specification-derived reference under *both* policies.
`tests/test_secp256k1_ecdsa_low_s_policy.py` holds the secp256k1 half unchanged.

---

## INVARIANT-35 — A Selector Must Never Resolve Weaker Than It Was Asked

**Statement.** Any argument that names an algorithm, curve, parameter set or
security level **must** resolve to exactly what was named or fail. It must
never fall back to a default, round to a neighbour, or return a plausible
answer for an input it did not recognise.

Concretely, for every selector in the library:

- an unrecognised value raises (Python) or returns `NULL` / `0` (C);
- a size or capability query for an unrecognised value returns `0` or `NULL`,
  never the size of some other parameter set;
- no selector has a "default" branch that maps unknown input onto a real
  choice.

**Why.** INVARIANT-7 covers the *availability* axis: no backend, no operation.
This is the *selection* axis, and nothing covered it until the library grew
enough parameter sets for it to matter. As of the NIST prime curves and the
FIPS 203/204 parameter-set work there are nine selectable levels across three
families, plus SLH-DSA's two — an integer or a string away from each other.

The failure this prevents is quiet and total. A selector that maps an
unrecognised `"ML-KEM-192"` onto ML-KEM-512, or a mistyped curve id onto
P-256, produces working code, valid signatures and successful handshakes at a
security level nobody chose and no test asserts. Unlike a missing backend, it
never surfaces: the caller believes it asked for category 5 and got category 1,
and every downstream artefact is well-formed. A downgrade that reports success
is worse than a hard failure, because only the hard failure gets fixed.

The rule is deliberately absolute rather than "must not resolve *weaker*". A
selector cannot know which direction is weaker for a given caller — P-521 is
not simply "stronger" than P-256 for someone whose peer only speaks P-256 —
and a rule that requires that judgement invites a fallback that argues it got
the direction right. Resolve exactly, or refuse.

**Enforcement.** In C: `nistp_lookup()`, `kyber_params_for()`,
`dil_params_for()` and `slhdsa_params_for()` each end in `default: return NULL`
and every public size/name query propagates that as `0` / `NULL`. In Python:
`_param_set_id()` (shared by `_ml_kem_id` / `_ml_dsa_id`) and
`_nistp_curve_id()` raise `ValueError` on any unrecognised value, and reject
`bool` explicitly — `True` is an `int` in Python and would otherwise index a
selector table.

Name aliases are permitted and are not a violation: `"secp256r1"`,
`"prime256v1"` and `"P-256"` denote the same curve, and `"Dilithium3"` denotes
ML-DSA-65. An alias resolves to the thing it names. What is forbidden is
resolving something that names *nothing*.

**Verification.** `tests/test_selector_strictness.py` enumerates every selector
in the library and drives each with the same battery of unrecognised inputs —
neighbouring-but-invalid integers, plausible-but-wrong names, `bool`, `None`,
negative values, and the empty string — asserting a raise every time. It also
asserts the C side returns `0` / `NULL` rather than another set's answer, and
that the alias tables resolve only to sets that actually exist. Adding a
selector without adding it to that enumeration fails the test, because the test
derives its list from the modules rather than from a hand-written literal.

---

## INVARIANT-36 — AMA Is Not Measured Against Another Implementation

**Statement.** No other cryptographic implementation's output may serve as an
answer key for AMA's correctness, and no test or development tool may invoke
another cryptographic binary. Where a specification publishes no worked example,
the substitute is a reference derived **from the specification text**, written
in this repository.

**Why.** AMA's stated position is that it depends on no other cryptographic
implementation: the README says "zero external crypto deps", `CMakeLists.txt`
records that OpenSSL is "not used by AMA sources", and a dozen C files carry
comments of the form "replaces OpenSSL `EVP_Digest`". All of that was true of
what the library *runs*.

It was not true of how the library was *checked*. `tests/kat/keyformats/`
carried twelve PEM files generated by OpenSSL 3.0.13, vendored as the answer key
for EC PKCS#8 and SPKI on the reasoning that RFC 5915 and RFC 5480 publish no
worked examples. Nothing linked OpenSSL, nothing invoked it at build or test
time, and the files were inert data — and a competing implementation's output
was still the thing AMA's correctness was measured against, inside AMA's own
repository.

Two objections, one of principle and one of engineering. A project that depends
on no other implementation should not depend on one to know whether it is right.
And an answer key taken from an implementation inherits that implementation's
opinions, including its bugs and its non-conformances, where a specification's
worked example does not. This PR already learned the second lesson the hard way
on RFC 6979: the "independent" pure-Python reference normalised `s` because the
C code did, so the two agreed by construction while both diverged from the
document (see INVARIANT-34). **Two implementations that share an assumption do
not check each other** — and an implementation you did not write shares
assumptions you cannot see.

**What replaced it.** Two things, and between them the coverage is wider than
what was removed:

* **RFC 9500 §2.3** — "Standard Public Key Cryptography (PKCS) Test Keys",
  December 2023 — publishes P-256, P-384 and P-521 private keys as RFC 5915
  `ECPrivateKey`, which is exactly the structure AMA embeds inside PKCS#8. The
  gap that justified the shortcut had been closed by the IETF; nobody had
  looked. Vendored as `tests/kat/keyformats/rfc9500_ec.json` through the same
  `--specs` path as every other corpus.
* **`tests/ref_keyformat.py`** — a second encoder for SPKI, PKCS#8, RFC 5915
  `ECPrivateKey` and the RFC 9881 §6 `CHOICE`, transcribed from the RFCs' own
  ASN.1 with the text quoted inline. It imports nothing from
  `ama_cryptography`, and it is *declarative* — encodings are nested
  `(tag, content)` data fed to one generic serialiser — where the production
  encoder is per-type writers called from per-algorithm branches. A shared
  control-flow mistake has nowhere to hide when the two shapes have no control
  flow in common. It is anchored against RFC 9500 §2.3 and RFC 8410 §10.1
  before it is used as an authority anywhere else, because two encoders that
  agree could still both be wrong.

The vendored keys covered six algorithms in one encoding each. The reference
covers all twelve, in both encodings, under both `include_public_key` settings
and all three PQ `CHOICE` arms — plus constructed fixed-width edge cases (a
scalar or coordinate with leading zero octets) that a sampled corpus reaches
about once in 512 keys.

**Scope.** This is about *implementation output as ground truth*, not about
published test-vector suites. `wycheproof_vectors/` and the NIST ACVP corpora
under `tests/kat/` are adversarial inputs with expected verdicts, published for
implementers to run — the same category as a specification's worked example, and
they keep their own provenance gates (INVARIANT-24's sibling machinery in
`.github/workflows/corpus-provenance.yml`).

**No exceptions are recorded.** One used to be — `ama_cryptography/legacy_compat.py`
shelling out to `openssl ts` for RFC 3161 timestamping, described here as "a
shipped interop feature, not a validation path". It is gone: AMA encodes and
decodes RFC 3161 on its own DER codec, `rfc3161_timestamp.py` no longer imports
`rfc3161ng` either, and the gate below scans `ama_cryptography/` precisely so
neither can return. An invariant register that still names a removed exception
is worse than one that names none, because a reader takes it as current.

**Enforcement.** `tools/check_corpus_originality.py`, run in the
`security-checks` job of `ci.yml`. Three checks:

1. No process-spawning call under `ama_cryptography/`, `tests/` or `tools/`
   invokes a cryptographic binary. AST-based, so the many "replaces OpenSSL X"
   comments are not findings — flagging those would make the gate
   un-satisfiable and push a maintainer to delete accurate documentation. The
   callee set covers `subprocess.run`/`Popen`/`call`/`check_call`/
   `check_output`/`getoutput`/`getstatusoutput`, `os.system`/`popen`, and the
   `exec*`/`spawn*`/`posix_spawn*` families; string constants bound to a name
   elsewhere in the file are resolved before matching, because
   `CMD = ["openssl", ...]; subprocess.run(CMD)` is how the removed generator
   actually spelled it and a gate that would not catch the code it exists to
   prevent returning is not a gate.
2. Every corpus file's `source.url` is on `rfc-editor.org` or `ietf.org`.
3. `tests/ref_keyformat.py` imports nothing from `ama_cryptography`.

**Verification.** `tests/test_corpus_originality.py` pins both directions —
the repository as it stands, plus a reproduction of each violation: a
`subprocess.run(["openssl", ...])`, four other cryptographic binaries, a corpus
file citing a non-standards source, a directory of key files under the corpus
(the exact shape the OpenSSL material was carried in), a reference encoder that
imports the production one, and a missing reference encoder. The non-detection
case is pinned too: a module full of prose mentioning OpenSSL must **not** be
flagged.

---

## INVARIANT-37 — A Verification API Must Not Claim a Check It Does Not Perform

**Statement.** A function whose name begins `verify_`, a result key, a
parameter, a docstring, or any document in this repository, **must not**
assert a verification that the implementation does not carry out. Where a
check is not implemented, three things follow and all three are enforced:

- the **name** must scope itself to what is actually checked
  (`verify_token_binding`, not `verify_token`);
- an argument requesting the unimplemented check must **raise**, never resolve
  to the weaker one;
- the boundary must be **published as data**, not only as prose, so the
  documentation can be checked against the code rather than against a reviewer's
  memory.

The canonical instance is RFC 3161.
`ama_cryptography.rfc3161_timestamp.RFC3161_CAPABILITIES` is the single source
of truth: `message_imprint_binding`, `pki_status`, `nonce_echo` and
`signer_present` are performed; `tsa_signature`, `tsa_certificate_chain` and
`gen_time` are not.

**Why.** By the time anyone checked, this repository asserted the opposite of
its own implementation in more than fifty places.

`ARCHITECTURE.md`'s verification flow wrongly listed "Verify TSA signature and
time bounds" as step 6 of 7; no such step exists. `THREAT_MODEL.md` falsely
recorded the retired claim "RFC 3161 TSA with independent verification" as
**IMPLEMENTED** — the row an auditor reads to conclude a threat is closed. `wiki/Security-Model.md`
scored AMA ✓ against OpenSSL ✗ on RFC 3161, inverted on the single axis where
OpenSSL does the work and AMA does not. The `rfc3161_timestamp` module
docstring opened with the retired claim "Third-party attestation: Independent
verification by TSA". `AMA_CRYPTOGRAPHY_ETHICAL_PILLARS.md` carried a
"Mathematical Proof" whose security statement was exactly backwards. It
wrongly said forgery "Requires TSA private key compromise" — when in truth
forging a token AMA accepts needs no key, no compromise and no privileged
position: the
adversary builds a CMS `SignedData` offline over the target's own content, with
whatever `genTime` suits them. The same document multiplied a timestamp
"detection dimension" into a `P(detect) ≥ 0.999999999` bound; against an
adaptive adversary that dimension's detection rate is 0, and the bound was
inflated by three orders of magnitude.

None of it was written dishonestly. It was written by people who knew what a
timestamp is *for*, describing a feature named after the thing it does not do.
That is the failure this invariant addresses: not lying, but the absence of
anything that would notice. Every one of those statements was "qualified"
somewhere else in the repository, and none of the qualifications were where the
reader's eye was.

The reason it matters more than an ordinary documentation defect is that these
particular sentences are load-bearing. A threat-model row marked IMPLEMENTED
closes a risk. `SECURITY.md` wrongly made "REQUIRED: use RFC 3161 trusted
timestamp authorities" a production control, telling an operator they had
bought attributable time, which they had not, and the
control they configure in response changes nothing an attacker must defeat.
Documentation that overstates a security property is a vulnerability in the
deployment, not a typo in a file.

**Why the gate is driven by a capability table.** The obvious enforcement is a
denylist of forbidden phrases, and it would be wrong in a specific, expensive
way: it freezes today's limitation into CI. The day CMS `SignerInfo`
verification lands, a phrase denylist begins rejecting claims that have become
*true*, and the remedy depends on somebody remembering to edit a gate — which
is the same species of memory this invariant exists because nobody had.

So the prohibitions are **derived**. `tools/check_verification_claim_honesty.py`
reads `RFC3161_CAPABILITIES` and forbids a claim *because its capability is
`False`*. Implementing a check and flipping one entry to `True` permits the
corresponding documentation in the same commit, with no gate edit and no
prohibition left standing after it stopped being true. The same table is what
`TokenVerification.not_verified` reports at runtime, so an audit record cannot
claim more than the library does, and what the behavioural tests drive — the
code, the runtime record, the tests and the documentation are four consumers of
one declaration rather than four restatements of one belief.

**The same-line rule.** A claim must be negated on the line that makes it. This
is deliberate and it is the lesson of the fifty: a disclaimer three paragraphs
away, or in another file, or in a docstring the reader is not looking at, did
not prevent a single one of them.

**Enforcement.** `tools/check_verification_claim_honesty.py`, run in the
`security-checks` job of `ci.yml`. Five checks:

1. **No claim of an unperformed check.** For every `False` capability, the claim
   patterns bound to it must not appear un-negated in `ama_cryptography/`,
   `tools/`, `tests/`, `examples/`, `docs/`, `wiki/`, `benchmarks/`, `fuzz/` or
   root Markdown. Generic assurance vocabulary ("independent verification") is
   scoped to lines that are about timestamping, so a true statement about
   side-channel review of the C code is not a finding — a gate that fires on
   those is one people learn to route around, which is the failure mode
   INVARIANT-2 already records.
2. **The misnamed result key is not taught.** No `results["rfc3161"]` in any
   document or docstring. The key is retained in code and now warns when read;
   a copy-pasteable example teaching it would undo that.
3. **A refusing argument is documented as refusing.** `certificate_file` and
   `tsa_cert_path` must be described as raising.
4. **No instruction to install `rfc3161ng`**, removed under INVARIANT-1.
5. **The table cannot outgrow its enforcement.** Every `False` capability must
   have claim patterns bound to it; every pattern must name a real capability;
   the scan's exemption list must stay exactly the two self-referential files
   (the checker, which states the forbidden claims in order to forbid them, and
   its test, which states them in order to require rejection).

The table is read with `ast` rather than by importing the module, so the gate
runs in a lint job with nothing built.

**Verification.** `tests/test_verification_claim_honesty_gate.py` — 46 tests —
pins both directions: the repository as it stands, plus a reproduction of every
violation class and, equally, the near-misses that must **not** fire. It also
pins `test_flipping_a_capability_to_true_permits_its_claims`, which is the
property the design rests on, and `test_ast_parsed_table_equals_the_imported_one`,
so the gate's reading of the table and everyone else's cannot drift.

That suite has already earned its place. An early version of the pattern for
the phrase this section will not repeat ended `(?:stamp|-stamp|stamping)?\b`,
which cannot match its own plural: the group takes `stamp`, the `\b` demands a
boundary before the `s`, and every backtrack fails identically. The gate missed
the most common phrasing of the most common false claim in the tree and
reported success. Its own negative controls found that, and fixing the pattern
immediately surfaced two further live instances.

`tests/test_rfc3161_api_honesty.py` — 18 tests — drives the behaviour the table
describes, so the table cannot become aspirational. The load-bearing one is
`test_a_token_with_a_nonsense_signature_still_satisfies_the_binding`: it builds
a token in-process, with no key and no TSA, whose signature octets are zeros
and whose `genTime` is the epoch, and requires the binding check to accept it.
It is an uncomfortable assertion to write down, which is why it belongs in the
suite — it is the fact every claim removed under this invariant was denying.
Its companion requires the same check to still reject a different payload, so
"accepts a forgery" cannot be satisfied by a check that accepts everything.

**Scope.** The invariant is general; the capability table and claim patterns
currently cover RFC 3161, because that is where the defect was found and where
AMA ships a feature whose headline purpose is unimplemented. A future
verification surface with an unimplemented half is expected to declare its own
table and bind its own patterns. What closing the RFC 3161 gap requires is
scoped in [ARCHITECTURE.md § Scope: RFC 3161 attestation is not implemented](ARCHITECTURE.md#scope-rfc-3161-attestation-is-not-implemented).

---

_Maintained by Steel Security Advisors LLC._
_Last updated: 2026-07-28_
