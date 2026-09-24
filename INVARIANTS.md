# AMA Cryptography — Architectural Invariants

> **Policy document.** Every PR that touches `ama_cryptography/`, `.github/workflows/`,
> or `tests/` **must** satisfy all invariants below.
> Reviewers: reject any PR that violates them.

Each invariant states the rule (**Statement**), the gate that enforces it
(**Enforcement**), the tests that show the gate can fail (**Verification**),
any recorded exception, and a short **Why**. The history behind a rule — the
defect that prompted it, earlier wording and its retraction, the pass that
found it — is in git history: `git show d8b1fca1:INVARIANTS.md` is the last
long form of this document, and `git show d8b1fca1:CHANGELOG.md` recovers the
pass-by-pass journal. Where a retraction changed what a rule requires, the text
below already states the current rule. A measured figure appears here only with
its date and host; otherwise the commit that holds the measurement is named.

---

## INVARIANT-1 — Zero External Crypto Dependencies

**Statement.** Introduce no ad-hoc or unreviewed cryptographic construction:
every primitive follows a published NIST/IETF specification and passes KAT
validation. Do **not** introduce or depend on third-party cryptographic
packages (`libsodium`, `pynacl`, `cryptography`, OpenSSL bindings, etc.), and
link no pre-built external cryptographic library (libsodium, OpenSSL, liboqs,
etc.). Optional extras in `pyproject.toml` (e.g. `[legacy]`, `[benchmark]`) may
list such packages for opt-in interop or comparison, but the core
`ama_cryptography` package **must not** import or call them at runtime — and
"call" includes a subprocess: shelling out to `openssl` is a competing
implementation running inside AMA. Naming another implementation (a curve alias
such as `prime256v1`, a comment crediting an approach) is not calling it.

- Python stdlib `os` and `secrets` are permitted for OS services (entropy is
  the operating system's to provide).
- **`hashlib`** resolves to OpenSSL on a libcrypto build, so it is confined to
  the pre-execution **trust bootstrap**: the pre-load shared-object digest, the
  pre-import binding-extension digest gate in `__init__.py`, the
  signed-integrity source digests, the build-time signer, the SHA3-256 KAT
  cross-check against fixed FIPS 202 vectors, and the RuntimeError-guarded
  test-only HKDF reference. All production hashing and key derivation runs on
  AMA's kernels (`native_sha256/384/512`, `native_sha3_256/384/512`,
  `native_pbkdf2_hmac_sha256/512`).
- **`hmac`**: `hmac.compare_digest()` is permitted for constant-time
  comparison; `hmac.new()` / `hmac.HMAC()` are not — use AMA's own HMAC.
- Stdlib modules **must NOT** substitute for AMA's own HMAC, memory zeroing or
  core cipher operations.

**Enforcement.** `tools/check_stdlib_hash_boundary.py` pins every `hashlib` /
`hmac` binding file by file with exact reference counts (aliases,
`from`-imports and dynamic imports included), so a new use anywhere fails CI.
`tools/check_corpus_originality.py` rejects any process-spawning call to a
cryptographic binary under `ama_cryptography/`, `tests/` and `tools/`
(INVARIANT-36). `tools/check_vendor_isolation.py` checks the built library's
linkage (ELF, Mach-O including fat binaries, PE), the modules resident after
import, source imports, container recipes and the CMake configuration.

**Verification.** `tests/test_vendor_isolation_gate.py`,
`tests/test_corpus_originality.py` and the stdlib-hash boundary tests pin both
directions.

**Why.** There is no upstream implementation positioned to catch an error
made here, and a vendor reached through a transitive import, a linker flag or
`hashlib` is a vendor performing AMA's cryptography in-process.

### INVARIANT-1 Addendum — Algorithm Registry

**Statement.** Every cryptographic primitive implemented in this library
**must** map to a non-deprecated entry in
[`CSRC_STANDARDS.md`](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/CSRC_STANDARDS.md).
Adding any new algorithm requires updating `CSRC_STANDARDS.md` with its
governing standard, parameter set, status and source URL **before**
implementation is permitted. An algorithm whose standard is deprecated or
withdrawn is removed or documented with a migration timeline.

**Enforcement.** `tools/check_algorithm_registry.py`, run in `ci.yml`, at two
levels, both *discovered* from `include/ama_cryptography.h`:

1. **Families** — every `AMA_API` prototype's `ama_<family>_` prefix must map
   to one or more registry tokens (a tuple where a family spans two
   publications, as `ama_nistp_*` spans FIPS 186-5 and SP 800-56A rev. 3), and
   each token must appear in the registry's tables.
2. **Parameter sets** — the enumerators of the parameter-set enums
   (`AMA_ML_DSA_*`, `AMA_ML_KEM_*`, `AMA_SLHDSA_*`, `AMA_NIST_CURVE_*`) and the
   `ama_hmac_<hash>` prototypes must each map to a token in the **Algorithm
   column** of a row of its own.

An identifier the mapping does not know fails. The gate fails closed on a
collapsed header scan, a header with no parameter sets, or a truncated
registry.

**Verification.** `tests/test_algorithm_registry_gate.py` pins every direction.

**Why.** The family level alone read `ama_hmac_*` as covered by the
HMAC-SHA-256 row while three further HMAC constructions had no row; when the
gate first ran it named 18 missing entries.

### INVARIANT-1 Addendum — Vendoring Policy

**Statement.** No cryptographic source is vendored. Every primitive the
library ships is written in this repository, and `src/c/vendor/` **must not
exist**. The only third-party code in the repository is the dudect timing
harness under `tests/c/dudect/`, which is test tooling outside `src/c/`.

**Enforcement.** `tools/check_vendor_isolation.py` fails the build if the
directory reappears or if any file under `src/c/` includes a forbidden vendor
header, in a fallback arm or anywhere else.

**Verification.** `tests/test_vendor_isolation_gate.py` pins both directions.

**Why.** The last vendored component (an x86-64 Ed25519 backend) was replaced
by the in-house backend and removed; the **Vendored Dependencies** appendix
records it.

## INVARIANT-2 — Fail-Closed CI

**Statement.** Security-critical CI steps (pip-audit, bandit, Semgrep, KAT
tests, secret scanning) **must not** use `continue-on-error: true`; their
failures **must** block the pipeline. A gate over tool output **must** read a
structured format where the tool emits one, and **must** fail closed on a
report that is missing, malformed, error-carrying, empty or pre-filtered.

**Exceptions.** None for security gates. `continue-on-error: true` appears only
on the `actions/setup-python` step in `ci.yml` and `ci-build-test.yml`, each
followed by a retry step gated on `steps.setup-python.outcome == 'failure'`; a
genuine failure still fails at the retry. The Docker build job in
`ci-build-test.yml` carries no exemption: it mitigates Docker Hub flakiness by
routing `docker.io` through `mirror.gcr.io`, pre-pulling BuildKit with capped
retries and logging in when credentials exist, and a real failure is still red.

**Enforcement.** Each severity gate parses the structured report:
`tools/check_bandit_severity.py` (Bandit JSON),
`tools/check_semgrep_severity.py`, `tools/check_codeql_severity.py` (SARIF,
blocking at `security-severity` 7.0 and above whatever the level).

**Verification.** `tests/test_bandit_severity_gate.py` and its siblings drive
the rejection direction for each missing, malformed, empty and pre-filtered
report shape.

**Why.** A gate whose failure message names a condition nobody can reproduce
gets routed around — the Bandit gate once matched its confidence tally instead
of its severity tally — and that is a fail-open outcome reached through a
fail-closed mechanism.

## INVARIANT-3 — Observable Failure States

**Statement.**

- No bare `except …: pass` that swallows security-relevant errors.
- No bare `return` that silently skips a test — use `pytest.skip(reason=…)`.
- No `2>/dev/null` or other stderr suppression hiding the failure of a
  *substantive* step. Suppressing stderr on a pure **capability probe** — a
  command whose failure is the answer, immediately branched on (`nice -n -10
  true 2>/dev/null`, `file "$f" 2>/dev/null | grep -q ELF`) — is permitted.
- Mock assertions verify **call signatures**, not just call occurrence.

**Why.** A failure that nobody can observe is indistinguishable from success,
and every consumer downstream acts on the success.

### INVARIANT-3 Addendum — Finalizer Failures Must Be Observable

**Statement.** Finalizers and destructors **may** catch broad exceptions to
prevent propagation, but silence must **never** be the only outcome. Each
finalizer that catches an exception **must** produce an observable failure
state by **one** of:

1. incrementing a thread-safe internal error counter;
2. setting an internal "finalizer error" flag;
3. recording a last-error code retrievable via a health or self-test call.

Logging is optional; it is sometimes unsafe during interpreter shutdown and
**must not** be the sole observable artifact.

**Enforcement.** `ama_cryptography/_finalizer_health.py` provides
`record_finalizer_error()` and the `finalizer_health_check()` query API; every
`__del__` in a cryptographic class calls `record_finalizer_error()` on
exception.

## INVARIANT-4 — Pinned Action References

**Statement.** All third-party GitHub Actions used in security workflows
**must** be pinned to a full commit SHA, not a mutable tag (`@main`, `@v1`,
etc.).

**Exception (one, named by path).**
`slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0`:
the generator verifies that its caller referenced it by a semantic-version tag
and fails otherwise, because the tag is what its provenance attests. Any
further exemption needs an entry in `_PIN_EXEMPT` with a written reason.

**Enforcement.** `tools/check_action_pins.py --strict` in `ci.yml`:
`find_unpinned()` rejects every `uses:` reference in a workflow or in a
composite action under `.github/actions/` (flow-style `- {uses: …}` included)
whose ref is not a 40-character SHA; local `./…` and `docker://` references are
out of scope (container images are `tools/check_docker_pins.py`'s). It fails
closed when it finds no pins at all. The resolution half is
INVARIANT-24.

**Verification.** `tests/test_action_pin_checks.py`.

**Why.** Whoever controls an upstream repository can move a tag, and the
workflow then runs different code with no diff in this repository.

## INVARIANT-5 — Input Validation at Python/C Boundary

**Statement.** Every Python function that dispatches to the native library via
`ctypes` **must** validate inputs **before** the call:

- **Fixed-size buffers** (keys, public keys, nonces, tags): validate the byte
  length. Variable-length parameters passed with `c_size_t(len(...))`
  (messages, plaintext, AAD) need no pre-check. ML-DSA-65 and SPHINCS+
  signatures are variable-length (`*_SIGNATURE_BYTES` are maxima) and fall
  under that exemption.
- **Fixed-width integers**: a Python `int` bound for `c_uint32`, `c_int32`,
  etc. is range-checked first (e.g. Argon2id `t_cost`, `m_cost`,
  `parallelism` above `2^32 - 1` are rejected), because ctypes wraps silently.
- **Borrowed buffers** go through one rule (`_byte_view`): 1-D, byte items,
  contiguous, else `TypeError`.

**Why.** Past the boundary a wrong length is an out-of-bounds read or write in
C, and a wrapped integer is a different parameter than the one the caller
passed.

## INVARIANT-6 — Secret Key Zeroing on All Exit Paths

**Statement.** Secret material is zeroed on every exit path, success and
failure alike. PQC key-pair dataclasses (`DilithiumKeyPair`, `KyberKeyPair`,
`SphincsKeyPair`) **must** store secret keys in mutable `bytearray` objects so
`secure_memzero` can clear them, and **must** provide `wipe()` and a `__del__`
that zeroes them. Consumers extracting a secret key copy it
(`bytes(kp.secret_key)` or `bytearray(kp.secret_key)`) to avoid use-after-wipe.
In C, secret buffers are cleared with `ama_secure_memzero`, and the dead stack
a secret-handling callee leaves is cleared with `ama_secure_stack_wipe()`
(every AEAD entry point; the Ed25519 secret entry points use a deeper internal
variant).

**Enforcement.** `tools/check_c_secret_zeroization.py` rejects a plain
`memset`/`bzero` zeroing of a secret-named object anywhere under `src/c/` and
`tests/c/`, following module-local helpers.

**Verification.** `tests/c/test_aead_stack_residue.c` and
`tests/c/test_ed25519_stack_residue.c` search the dead stack for key material
after each call, with positive controls that fail if the probe cannot see a
key left behind; `tests/c/test_secure_free_scrub.c` proves the post-free scrub
at the byte level.

**Why.** Compilers copy secrets into stack slots the source never names, so a
scrub that is reviewed rather than measured is an assumption.

## INVARIANT-7 — No Cryptographic Fallbacks, Ever

**Statement.** When the native constant-time C backend is unavailable, the
library **must** refuse to operate, raising at import, load or initialization.
Not acceptable substitutes:

- a pure-Python fallback for any cryptographic primitive or secret-dependent
  operation;
- a warning without a hard stop;
- a runtime flag that defers the safety decision.

A portability fallback is permitted only on a non-cryptographic path (for
example the monitoring math engine) and **must not** touch secrets. There is
**no** runtime or development escape hatch for cryptographic operation.

**Exception (documentation builds only).** With `AMA_SPHINX_BUILD=1` (or
`SPHINX_BUILD=1`) the import-time guards in `crypto_api.py`,
`key_management.py` and `legacy_compat.py` stand down so autodoc can read
signatures; every call-time path still invokes `_enforce_invariant7*()` and
`check_crypto_permitted()` and raises, the POST backend stage records a skip,
and `module_attestation()["fully_verified"]` stays `False`.

**Enforcement.** The POST stage `_self_test._run_backend_stage()` fails when no
native library loaded, so `import ama_cryptography` raises `CryptoModuleError`
(see [INVARIANT-39](#invariant-39--a-failed-post-must-fail-the-import-and-the-error-state-must-inhibit-output)).
Module-level guards in `crypto_api.py`, `key_management.py` and
`legacy_compat.py` raise when those modules are imported without a backend,
and every `pqc_backends.py` wrapper raises at call time.

**Why.** A fallback makes the non-constant-time path reachable exactly when
the constant-time one is missing, and POST is the one check that runs on every
import.

## INVARIANT-8 — Deterministic Reproducible Builds

**Statement.** The C build **must** enforce minimum compiler versions
(GCC >= 12, Clang >= 15) required for correct constant-time code generation and
SIMD intrinsics. The reference build environment is the pinned Docker image
(`ubuntu:22.04`) with the documented toolchain.

**Enforcement.** CMake raises `FATAL_ERROR` below the minimum;
`-DAMA_ALLOW_UNVERIFIED_TOOLCHAIN=ON` downgrades it to a `WARNING` for
development hosts.

### INVARIANT-8 Addendum — Native-Artefact Byte Equality

**Statement.** The release wheel's native artefacts (`libama_cryptography.so`
/ `.pyd` and the Cython-built `.so` files) **must** be byte-identical across two
independent rebuilds of the same tree, and no absolute build path may survive
in a shipped object.

**Enforcement.** The `reproducible-build` job in
`.github/workflows/static-analysis.yml` builds the wheel twice inside a
digest-pinned `manylinux_2_28` container (job-level `shell: bash`), with:

- `SOURCE_DATE_EPOCH` pinned; `PYTHONHASHSEED=0`; `PYTHONDONTWRITEBYTECODE=1`;
- `-fdebug-prefix-map`, `-ffile-prefix-map` and `-fmacro-prefix-map` taken
  from the in-container workspace path;
- `LDFLAGS+=-Wl,--build-id=sha1`;
- `MAKEFLAGS=-j1` and `CMAKE_BUILD_PARALLEL_LEVEL=1`;
- `python -m build --wheel --no-isolation`, with build dependencies
  pre-installed, so no random isolation path leaks into a Cython object.

The job diffs every native artefact (versioned `.so` names included), compares
every other `.py` byte for byte, and fails if an absolute build path survives
in any object it examined, or if it examined fewer objects than expected. `AR_FLAGS`/`ARFLAGS` are deliberately unset: CMake invokes `ar`
directly and binutils >= 2.27 is deterministic by default; a regression there
is fixed with `CMAKE_C_ARCHIVE_CREATE`. A container pin change is its own
commit, verified against the registry before it is committed. A release
requires the reproducible wheel.

**Exception.** `ama_cryptography/_integrity_signature.py` is excluded from the
`.py`-equality check: INVARIANT-17 makes it a per-build ephemeral artefact.

## INVARIANT-9 — Maximum Exception Scope in Crypto Paths

**Statement.** Code under `ama_cryptography/` **should** catch narrow
exception types (`ValueError`, `RuntimeError`, `OSError`) rather than
`except Exception` where possible.

**Exceptions.** Handlers that explicitly transition to the FIPS ERROR state
(e.g. `_self_test.py` POST failure tuples) and `__del__` destructors (which
must never raise) may catch `Exception`.

**Enforcement.** Manual review: Semgrep 1.74.0 has no `except Exception`
pattern syntax.

## INVARIANT-10 — Signed Commits on Protected Branches

**Statement.** All commits merged to `main` and `develop` **must** be GPG- or
SSH-signed. This is **REQUIRED** by the supply-chain threat model (T4.3).

**Enforcement.** Branch protection on `main` and `develop` requires signed
commits.

### INVARIANT-10 Addendum — Release Tags Must Be Annotated and Signed

**Statement.** A release tag **must** be an annotated tag object carrying a
signature. A lightweight `v*` tag is prohibited: it is a mutable pointer with no
object to sign.

**Enforcement.** `tools/check_release_tag.py`, run in `release.yml`'s
preflight before any wheel is built, checks *shape*: the ref resolves, names a
tag object, and the object contains an OpenPGP, SSH or X.509 signature block.
It states in its output that it does **not** verify the signature;
verification is the trust-store check below.

**Verification.** `tests/test_release_tag_gate.py` supplies the negative
controls for each rejected shape, including one asserting that a fabricated
signature block passes, so the gate's PASS cannot be mistaken for a
cryptographic result.

**Why.** Of the eleven tags the repository carried when the gate was written,
none was signed, although the operator runbook said `git tag -s`.

### INVARIANT-10 Addendum — The Trust Store, and a Correction

**Statement.** `.github/allowed_signers` publishes the binding between the
release signing key and its principal (`namespaces="git"`); it mirrors an
owner-established fact and is checked against signed bytes, never trusted on
its own.

**Enforcement.** `tests/test_release_tag_trust_store.py` verifies the v4.0.0
tag object — embedded in the test, because `actions/checkout` does not fetch
tags at its default depth — against the published key on every run, with
negative controls for a substituted key, a substituted principal, a tampered
payload and a wrong signature namespace. Its Ed25519 verification is
standard-library code pinned by the RFC 8032 §7.1 vector (INVARIANT-1).

Consumers verify a release tag offline with

```bash
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag v5.0.0
```

documented in `README.md` beside the Sigstore and SLSA commands.

**Why.** An earlier text said the repository must not ship a trust store; the
key had in fact been registered by the account owner, and an unverifiable claim
is not the same as a claim that must not be published.

## INVARIANT-11 — SBOM as Release Gate

**Statement.** CycloneDX SBOM generation (Python + C library) **must** succeed
as a required check on release tags, and the rendered SBOM **must** be a
deterministic function of the canonical package version in `pyproject.toml`.

**Enforcement.** `security.yml` triggers on `v*` tags so the SBOM job runs on
every release; an administrator adds `SBOM Generation (CycloneDX)` as a
required status check on tag protection.

### INVARIANT-11 Addendum — No Hardcoded SBOM Versions

**Statement.** `docs/compliance/sbom-c-library.json` **must** be rendered
exclusively by `tools/generate_sbom.py`, which reads the version from
`pyproject.toml`. Hardcoded `"version": "X.Y.Z"` literals in workflows, heredoc
SBOM fragments or inline component lists are prohibited.

**Enforcement.** The `sbom` job in `security.yml` and `release.yml`'s
preflight run `python tools/generate_sbom.py --check`, failing when the
committed SBOM diverges from a fresh render.

## INVARIANT-12 — Constant-Time Required for All Secret-Dependent Operations

**Statement.** Every code path that processes secret material **must** be
constant-time with respect to it. **Secret material** includes private keys,
seeds, shared secrets, symmetric and MAC keys, values derived from them, the
presence or absence of any of them, and pre-verification MAC/tag comparisons;
the length or presence of a secret is itself secret when attacker-observable.

### Rules

1. **Python delegation:** Python **must not** implement secret-dependent
   primitives (HMAC, KDFs, signature math, KEM decapsulation, AEAD tag
   verification); it orchestrates and delegates to the native backend.
2. **No Python MAC/tag verification:** Python passes data to the native
   backend and checks a boolean result, nothing more.
3. **Constant-time comparison:** `hmac.compare_digest()` or
   `ama_consttime_memcmp`; `==`, `memcmp` and early-exit comparisons are
   **prohibited** in secret verification paths.
4. **No secret-dependent branching:** branching, table indexing, loop counts and
   memory access patterns dependent on secrets are **prohibited** in C and
   Python, with one carve-out the standards mandate: the FIPS 204 (ML-DSA) and
   FIPS 205 (SLH-DSA) signing loops reject and resample by construction, so
   their iteration count is secret-dependent. `CONSTANT_TIME_VERIFICATION.md`
   §"ML-DSA / SLH-DSA signing" documents it; it leaks a timing signal on the
   rejection count, not key material.
5. **Masks survive the optimiser:** a secret-derived 0/~0 mask passes through
   `ama_ct_value_barrier_u64` (`src/c/internal/ama_ct_barrier.h`) so a compiler
   cannot turn it back into a branch; the remaining branches on public verdicts
   are declared with `AMA_CT_DECLASSIFY` (`src/c/internal/ama_ct_declassify.h`).

**Enforcement.** `tools/check_ghash_constant_time.py` runs every registered
target under callgrind and requires a zero cross-class delta in retired
instructions, data references and D1/LLd misses (pinned cache geometry), and
its `--taint` mode runs a Memcheck secret-taint sweep; it builds and refuses
an unoptimised library (`ama_build_optimization_probe()`), runs with
`AMA_DISPATCH_NO_AUTOTUNE=1` and prints the wiring it measured.
`.github/workflows/dudect.yml` runs the wall-clock lanes, and
`tools/check_dudect_class_staging.py` keeps their class preparation
branch-free. `tools/check_secret_division.py` rejects divisions on secret
operands (KyberSlash) in the built objects. `CONSTANT_TIME_VERIFICATION.md` is
the authoritative methodology.

**Verification.** Each callgrind target is verified to fail against a planted
secret-dependent branch; `tests/test_ghash_constant_time_gate.py` holds the
target tables to one set; the dudect self-tests pin the verdict rule.

**Why.** At `-O3` clang once rebuilt a secp256k1 masked select into a branch
on the RFC 6979 nonce, and the gates were then measuring an unoptimised build
in which that transformation cannot occur.

### INVARIANT-12 Addendum — Per-Slot SIMD Constant-Time Verification

**Statement.** The nightly SIMD dudect sweep (`dudect-simd-sweep` in
`.github/workflows/dudect.yml`) **must** measure each dispatch-routable SIMD
slot in isolation via `AMA_DISPATCH_ONLY=<slot>`. An excursion on any slot is
a hard fail — never excused as noise — when it meets the adjudication rule in
`tests/c/dudect/dudect_rounds.h`: |t| at or above `DUDECT_T_THRESHOLD` (5.0) in
a strict majority of rounds, with a consistently signed per-class difference of
at least `DUDECT_MIN_EFFECT_NS` (2 ns). Below that floor the lane reports
`SUB-FLOOR`, which records an abstention, not a clearance; the deterministic
callgrind targets own that range where a target covers the call.

The slot inventory is one list (`include/ama_dispatch.h` is authoritative).
Adding a dispatchable SIMD kernel **must** also:

- extend `apply_dispatch_only()` in `src/c/dispatch/ama_dispatch.c`;
- extend `KNOWN_SLOTS[]` in `tests/c/test_dispatch_only_env.c`;
- add the slot to the dudect-simd-sweep matrix in `.github/workflows/dudect.yml`;
- document the slot in the `ama_dispatch_active_slot()` block comment in
  `include/ama_dispatch.h`.

**Enforcement.** `tests/test_dudect_simd_sweep_gate.py` executes the sweep's
own classification logic against the real matrix; INVARIANT-45 holds the
inventories to one list.

**Why.** Per-slot isolation is what makes a t-value attributable to one SIMD
kernel rather than to whatever the host happened to wire.

## INVARIANT-13 — No Unjustified Static-Analysis Suppressions

**Statement.** `# noqa`, `# nosec`, `# pylint: disable`, `# type: ignore`, or
any equivalent suppression marker is **prohibited** unless **all four** hold:

1. The suppression is **line-scoped**, not file-scoped.
2. It **names the rule it silences** — `# nosec B110`, `# noqa: S310`,
   `# nosemgrep: <rule_id>` — never the bare marker. (`# type: ignore` is
   exempt from this condition: mypy's file-level form is legitimate and
   `warn_unused_ignores` reports an ignore that suppresses nothing.)
3. It includes a **human-readable justification** and a **tracking reference**,
   for example `# nosec B110: __del__ must not raise (FIN-001)`.
4. The suppressed line is **covered by tests** or a deterministic runtime check.

The **only** permitted exception is finalizers and destructors that must not
raise, with the reason documented inline.

Suppressions are **absolutely forbidden**, regardless of justification, in:

- `src/c/` (core cryptographic C primitives)
- `include/ama_*.h` (C header files)

No exception is recorded for either tree. A `# type: ignore` inside an
`except ImportError` whose `try` imports a **third-party** module is also
prohibited: it is required where the package is installed and an error where it
is not, so declare the name before the `try` (`np: Any`) instead.

**Enforcement.** CI scans the repository for suppression tokens and **must**
fail if a suppression is missing a justification, missing a tracking ID, or
appears in a forbidden directory. `tools/check_suppression_hygiene.py` runs
three passes:

- **Justified and tracked** over `ama_cryptography/`, `tests/` and `tools/`,
  reading only a *trailing* comment's own text (a full-line comment is prose
  and suppresses nothing; mypy's file-level `# type: ignore` stays in scope).
- **Absolutely forbidden** over every `.c` and `.h` under `src/c/` and
  `include/`: `NOLINT*`, `cppcheck-suppress`, `nosemgrep`, `coverity[`,
  `LINTED`, `#pragma GCC/clang diagnostic ignored` and its `_Pragma(...)` form,
  MSVC `#pragma warning(disable|suppress)`, `#pragma GCC optimize` / `clang
  optimize off`, `no_sanitize*`, `disable_sanitizer_instrumentation`, and
  `optnone` in any attribute position. It fails closed on an empty scope.
- **Portability** over every tracked Python file, for the third-party
  optional-import rule above.

`RUF100` is enforced, so an inert `noqa` naming a rule ruff does not run fails
too. The C static analysers run without suppressions: `cppcheck` with no
suppressions file, and `clang-tidy` with
`clang-analyzer-core.UndefinedBinaryOperatorResult` enabled everywhere except a
per-file exclusion for exactly the three files where it raises an irreducible
interprocedural false positive, pinned by
`tests/test_compiler_warning_gate.py`.

**Verification.** `tests/test_invariant_upgrades.py`
(`TestSuppressionScanPrecision`, `TestOptionalImportSuppressions`, and the
suppression-hygiene cases that drive the gate's own `check_source`) and
`tests/test_suppression_hygiene_gate.py` pin every pass in both directions.

**Why.** A bare marker blanket-suppresses its scanner — for `# nosec`, bandit
reads an unresolvable id list as "all tests" — and a suppression in `tools/`
silences an analyser inside the layer that enforces this invariant.

## INVARIANT-14 — CVE Ignore-List Hygiene

**Statement.** Every `--ignore-vuln` flag in CI workflows **must** carry a
comment stating (a) the CVE ID, (b) why the vulnerability is not exploitable
here, and (c) the condition under which the ignore is removed.

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

**Statement.** All one-time initialization in `ama_cpuid.c` (CPU feature
detection, AEAD backend selection) **must** use a platform once-primitive that
guarantees exactly-once execution with full memory visibility across threads:

- **POSIX** (Linux, macOS, BSDs): `pthread_once` (IEEE Std 1003.1)
- **Windows** (MSVC and MinGW-w64): `InitOnceExecuteOnce` (`synchapi.h`, Vista+)

The selection is made on `_WIN32`, not `_MSC_VER`: which primitive exists is a
property of the operating system, not the compiler. Lockless flag +
plain-variable patterns (e.g. `volatile int done` guarding a non-atomic shared
variable) are **prohibited** — they are data races, undefined behaviour under
the C11 memory model. A lazily cached value read on concurrent paths is
`_Atomic` (relaxed order suffices when it publishes nothing else). C11
`<threads.h>` `call_once` is **not** used: macOS has never shipped it and MSVC's
is unreliable. `CMakeLists.txt` uses `find_package(Threads REQUIRED)` and links
`Threads::Threads` to every library target.

**Enforcement.** `src/c/internal/ama_once.h` is the shared primitive (the
`AMA_CALL_ONCE` wrapper).

**Verification.** `tests/c/test_concurrent_init.c` releases eight threads
together into the dispatch table, the CPUID probes, the curve comb tables and
the P-256 decode/validate paths, so the ThreadSanitizer lane observes real
concurrency; the lane asserts the test is registered before trusting its own
green.

**Why.** An idempotent value does not make an unsynchronised read and write any
less of a race, and a sanitizer that watches a single-threaded program finds
none.

## INVARIANT-16 — Honest Compliance and Audit Claims

**Statement.** AMA Cryptography **must not** overstate validation,
certification, audit or compliance status. Documentation and metadata preserve
the distinction between implementation conformance, self-attestation, formal
validation and independent review:

- **Algorithm-compliant** means the implementation follows the cited
  NIST/IETF/SEC/BIP specification and is tested against the project's
  available vectors. It does **not** imply formal laboratory validation.
- **ACVP self-attested** means AMA's CI ran the documented vector harness and
  published the artifacts. It does **not** imply a NIST-issued CAVP
  certificate.
- **CAVP validated** may be claimed only after a corresponding certificate has
  been issued and can be cited.
- **CMVP / FIPS 140-3 validated** may be claimed only after a corresponding
  module certificate has been issued and can be cited.
- **Externally audited** may be claimed only after an independent qualified
  reviewer has produced a citable audit report or equivalent written
  attestation. Community testing, internal review, CI, fuzzing and static
  analysis are **not** substitutes for an external audit.

Any README, package metadata, badge, release note, website/wiki page,
compliance report or customer-facing text mentioning FIPS, ACVP, CAVP, CMVP,
certification, validation, attestation or audit status **must** preserve this
boundary. The FIPS 140-3 alignment claims are scoped to the Python API surface
(see INVARIANT-41).

**Enforcement.** `tools/check_verification_claim_honesty.py` (unqualified
formal-verification claims), `tools/check_hd_interop_honesty.py` (BIP32
compatibility claims), and review.

## INVARIANT-17 — Module Integrity Signing Must Remain Build-Time and Ephemeral

**Statement.** The module-integrity signing path (`ama_cryptography/_build_sign.py`
and any successor) **must** remain a build-pipeline-only mechanism. Runtime
package code verifies integrity artifacts; it must never be able to mint a
trusted integrity signature over modified package contents. Required:

- Signing is gated to the process that *is* the signer (the build pipeline or
  the documented repair command), never to an ambient environment variable.
- The private signing key never ships in wheels, sdists, repository files,
  generated runtime artifacts, logs, caches, test fixtures or package data.
- Default local builds use an ephemeral per-build keypair and discard the
  private key before the build completes.
- Release CI may derive or inject the signing key from a CI-controlled seed or
  trust anchor only when the release pipeline explicitly opts in and verifies
  the resulting public key against the compiled trust anchor.
- The only shipped integrity artifact contains public verification data:
  digests, public key and signature.
- The signed artefact (`ama_cryptography/_integrity_signature.py`) is a build
  output and is not tracked: every build signs its own over its own native and
  binding digests (AGENTS.md §8.4). `.gitignore` and `MANIFEST.in` exclude it;
  the tracked source-drift check is `_integrity_digest.txt`, a pure function of
  the `.py` sources.
- Missing, mismatched, malformed or untrusted integrity artifacts produce an
  observable failure state and never silently bless modified Python modules.

**Verification.** `tests/test_setup_signer_contract.py` fails if the artefact
becomes tracked, un-ignored or shipped in an sdist, or if the unbuilt-clone
remedy text regresses; `tests/test_build_sign.py` pins the signer, including
the atomic, mode-preserving artefact write and the `--require-trust-anchor`
flag.

**Why.** Post-build tamper detection is only worth having if integrity signing
cannot become a local, attacker-controlled re-signing oracle.

## INVARIANT-18 — ACVP Self-Attestation Must Stay Coupled to CI Coverage Floors

**Statement.** The ACVP self-attestation documents and the CI vector-validation
workflow **must** remain in lockstep: coverage must not silently shrink, drift
from the published artifacts, or pass because an expected-count constant was
not updated. A change that adds, removes, renames, skips, reclassifies or
retargets ACVP vectors updates, in the same commit:

1. `.github/workflows/acvp_validation.yml` vector floor and ACVP reference;
2. `nist_vectors/` fetch/run logic and default ACVP reference, if changed;
3. `docs/compliance/acvp_attestation.json` totals and per-algorithm counts;
4. customer-facing compliance reports citing vector counts, pass/fail totals,
   skipped-vector semantics or the upstream ACVP reference.

**Enforcement.** The workflow fails if any of these drift from the published
attestation: total vectors tested; totals passed or failed; per-algorithm
counts; algorithm names; upstream ACVP reference; expected floor semantics; or
all-zero coverage for a listed algorithm. The fetched projections themselves
are pinned by bytes (INVARIANT-44), and a fetch that acquires nothing fails
the step.

**Why.** The published claim must match the evidence CI just produced;
expanding coverage is welcome, but it moves the JSON, the floor, the reference
and the prose together.

## INVARIANT-19 — Hybrid KEM Combiner Construction Is Security-Critical

**Statement.** The hybrid KEM combiner **must** keep its current binding
construction unless a cryptographic review approves a new one and the
transcript test vectors are updated in the same change. It retains:

- HKDF-SHA3-256 using the RFC 5869 Extract-then-Expand construction;
- the native constant-time HKDF backend for production operation;
- a domain-separation label bound into `info`;
- explicit two-component binding (`component_count = 2` or equivalent);
- length-prefixed classical and PQC ciphertexts bound into `salt`;
- the concatenated classical and PQC shared secrets as input keying material;
- length-prefixed classical and PQC public keys bound into `info`;
- fixed transcript ordering that cannot be canonicalized ambiguously; and
- fail-closed behaviour when the native HKDF backend is unavailable.

Do **not** refactor, simplify, reorder, remove length prefixes, remove
public-key binding, change labels, substitute a KDF or introduce an
experimental combiner on production paths without documenting the security
rationale and updating the tests and compliance/design notes. Research KDFs or
alternate combiners live only in non-production modules the production hybrid
KEM provider cannot reach.

**Enforcement.** Cryptographic review of any change to the construction;
`tests/test_hybrid_combiner.py` and `tests/test_hybrid_combiner_edge_cases.py`
pin the fail-closed behaviour and ciphertext binding, and
`tools/check_crypto_construction_docs.py` derives the documented combiner
behaviour from `hybrid_combiner.py` (INVARIANT-53).

## INVARIANT-20 — Constant-Time AES Must Remain the Default

**Statement.** The default AES-GCM build **must** use the constant-time
cache-safe AES path (`AMA_AES_CONSTTIME=ON`, implemented by
`ama_aes_bitsliced.c` or a reviewed constant-time successor). Table-based AES
never becomes the default again:

- CMake's default configuration enables the constant-time path.
- Build output identifies whether constant-time AES is enabled.
- Disabling it requires an explicit opt-out flag and emits a warning that the
  table path is unsuitable for shared-tenant or side-channel-sensitive
  deployments.
- CI timing harnesses and constant-time tools exercise the production-default
  constant-time path, not a faster non-default table path.
- Documentation describes table-based AES, if present, as an opt-out or
  test/benchmark compatibility path.

**Why.** Lookup-table AES leaks through cache timing on shared hardware.

### INVARIANT-20 Addendum — Explicit Opt-In for Table-Based AES

**Statement.** `-DAMA_AES_CONSTTIME=OFF` alone is **prohibited**: an operator
who needs the table path **must** also pass `-DAMA_AES_TABLE_INSECURE=ON`, and
CMake fails configuration with `FATAL_ERROR` otherwise. The runtime API
`ama_aes_gcm_active_backend()` (`include/ama_dispatch.h`) returns the kernel
actually installed (`"vaes-avx2"`, `"aes-ni-pclmul"`, `"arm-aes-pmull"`,
`"bitsliced-software"` or `"table-insecure"`); integrations **should** assert at
startup that it is never `"table-insecure"` unless the deployment is cleared
for that path. The dispatch report prints this wired backend beside the
detected capability tier.

**Verification.** `tests/c/test_aes_gcm_backend_introspect.c` asserts both
properties when `AMA_AES_CONSTTIME` is defined, and forces the scalar slot to
show the label is not constant.

## INVARIANT-21 — X25519 Low-Order Outputs Must Be Rejected

**Statement.** X25519 key exchange **must** reject all-zero shared secrets
produced by low-order or otherwise invalid peer public inputs:

- `ama_x25519_key_exchange()` and any successor constant-time check the full
  32-byte output for all-zero (a mask over the output, no branch);
- on all-zero output the shared-secret buffer is securely zeroed before
  returning failure;
- the API returns a hard cryptographic error, not a warning, partial result,
  nullable success or caller-configurable soft failure;
- batch APIs fail the whole batch and scrub every output if any lane produces
  an all-zero secret;
- tests cover single-shot and batch rejection so a ladder or SIMD refactor
  cannot silently remove the check.

**Verification.** `wycheproof_vectors/run_wycheproof.py` pins that exactly 31
low-order public keys are rejected under RFC 7748 §6.1.

## INVARIANT-22 — AEAD Nonce Durability Must Fail Closed

**Statement.** AEAD nonce/counter tracking in the Python orchestration layer
**must** remain durable across process restarts and safe across concurrent
processes for every production path that auto-generates or tracks nonces:

- Per-key counters are persisted before or atomically with exposing a nonce,
  so a crash cannot forget a used slot.
- Multi-process access uses an inter-process lock or an equally strong atomic
  update; multi-threaded access serialises counter mutation.
- Malformed persistence files, truncated entries, invalid hex, lock failures,
  fsync/write failures, permission errors or counter-state corruption raise a
  hard error rather than continuing with partial history.
- Nonce reuse detection uses no probabilistic structure that can produce false
  negatives.
- Ephemeral mode is an explicit test/hermetic opt-in, never silently enabled for
  production encryption.
- Exceeding the per-key nonce safety limit forces re-keying or hard failure; it
  never wraps, resets or continues with a warning.
- The persistence file is writable only by the encrypting principal. A
  file-based counter cannot detect an offline rollback or deletion of its own
  state; that protection is a deployment responsibility.

The separate `NonceTracker` ledger is opt-in public API: no encrypt path in the
package consults it, it bounds capacity by refusal (never eviction), and its
file is created owner-only with `O_NOFOLLOW` (a protected DACL on Windows).

**Verification.** `tests/test_nonce_tracker_is_opt_in.py` pins that reading of
the ledger to the code.

**Why.** Forgotten nonce history is a cryptographic safety failure, not
recoverable telemetry loss.

---

## Vendored Dependencies

**None.** `src/c/vendor/` does not exist and the vendor-isolation gate fails
the build if it reappears (INVARIANT-1 Addendum — Vendoring Policy).

The tree once vendored a public-domain x86-64 Ed25519 implementation behind a
CMake option. The in-house backend replaced it — static base-point tables
(`tools/gen_ed25519_tables.py`), a signed 5-bit comb with constant-time masked
selection, Bernstein–Yang constant-time inversion and half-size-scalar
verification — and builds on MSVC through `_umul128` / `__umulh`. The removed
backend's verdicts over a 2,022-record corpus are frozen in
`tests/oracle/ed25519_frozen_oracle.txt` and replayed on every build.

---

## INVARIANT-23 — No Credential Material in the Public Tree

**Statement.** No live credential material — private keys, provider tokens, or
high-entropy secrets assigned to secret-named identifiers — may be committed,
and the gate that enforces this must itself be tested in both directions.
Obfuscating a value to avoid a finding (splitting a literal, encoding it) is a
violation, not a fix.

**Exceptions.** Every allowlist entry in `tools/check_secrets.py` carries a
written justification for why that path cannot hold a live secret. Where an
exception is genuinely required — the scanner's own detection suite must
contain credential shapes — it is a **visible, path-based allowlist entry with
a written reason**, never hidden in how the value is written. Silencing the
scanner globally or adding an unjustified entry violates this invariant.

**Enforcement.** `tools/check_secrets.py`, an in-house scanner written for this
repository's layout, runs as a fail-closed CI gate and as a `pre-commit` hook
in `--staged` mode. It folds concatenated string literals before matching,
enumerates tracked files through `tools/_repo.py` (`git ls-files -z`, so a
non-ASCII filename cannot slip past), and fails on an explicit path it cannot
read rather than reporting it clean.

**Verification.** `tests/test_secret_scanner.py` pins detection (PEM/OpenSSH
keys, AWS key ids, GitHub PATs, Slack tokens, Google API keys, `Authorization`
headers, tracked `.env` files, high-entropy secret-named assignments, and split
literals via `TestCatchesSplitLiteralEvasion`) and non-detection (published KAT
vectors, the integrity public key, documentation placeholders).

**Why.** This tree is largely published high-entropy material — KAT vectors,
ACVP responses, fuzz corpora — which is the worst case for an off-the-shelf
scanner, and the blanket ignore file that follows is what lets a real key
through.

---

## INVARIANT-24 — Pinned Action SHAs Must Resolve Upstream

**Statement.** Every SHA-pinned GitHub Action in `.github/workflows/**` must
reference a commit that exists upstream, resolve to a **release tag**, and its
trailing version comment must name a tag that SHA really carries.

**Enforcement.** `tools/check_action_pins.py --strict` resolves every pin with
`git ls-remote` (read-only, no clone, no auth) on every PR and fails on a SHA
matching no advertised release tag — a pin to an upstream pull-request or
branch head is refused — or whose comment names the wrong tag. If upstream
cannot be reached it exits 2 and reports the pin inconclusive; **unverifiable
is not valid**.

**Verification.** `tests/test_action_pin_checks.py`.

**Why.** `release.yml` once pinned `pypa/cibuildwheel` to a SHA that existed
nowhere, and two releases published zero binary artefacts because the pin was
first resolved on release day.

---

## INVARIANT-25 — Workflow Runner Labels and Command Strings Must Be Valid

**Statement.** Every runner label in `.github/workflows/**` must be a
GitHub-hosted image that currently exists; every embedded `python -c` payload
must compile; every command string bound for `cmd.exe` must use quoting
`cmd.exe` honours; every expression must be valid Actions syntax; every `cmake`
configure must state its optimisation level; a step that invokes pytest must
build the library first or set `AMA_POST_DIAGNOSTIC_IMPORT`; and every
release-creating step must be safe under immutable releases and under a re-run
for an already-published tag (it must not overwrite a hand-edited `name:` or
`body:` without `append_body: true`, and a prerelease with assets must be
drafted before upload).

**Enforcement.** `tools/check_workflow_commands.py` on every PR: it resolves
`runs-on:` through `strategy.matrix` (`include:` entries too), compiles each
extracted `python -c` payload after the shell's own unescaping, rejects POSIX
single-quoting in `*_WINDOWS` cibuildwheel variables and `shell: cmd` steps,
parses every `${{ }}` body and bare `if:` value as an expression (a lone `=`
is rejected), runs `check_cmake_build_type()` and
`check_pytest_prerequisites()`, and checks every release-creating step. A
`${{ ... }}` value it cannot evaluate counts as neither true nor false.

**Verification.** `tests/test_workflow_command_checks.py` replays every
historical defect class — a retired `macos-13` label, a folded `>-` payload
that raised `IndentationError`, single quotes handed to `cmd.exe`, the pre-fix
release step — and asserts the legitimate shapes do not false-positive.

**Exception (stated limitation).** GitHub publishes no API listing hosted
labels, so `SUPPORTED_LABELS` is a curated table carrying the date and source
it was verified against; it catches a retired label, a typo and a label that
never existed, but not a *future* retirement. A `workflow_dispatch` dry run of
`release.yml` before cutting a tag is the release-procedure obligation that
covers that. An unresolvable label is reported separately and never counted as
verified.

**Why.** `release.yml` runs only on a tag push, so each of these defects was
invisible until a release was attempted, and each alone produced a release
with no artefacts.

---

## INVARIANT-26 — Ed25519 Signatures Must Have a Canonical S

**Statement.** Every Ed25519 verification path must reject a signature whose
scalar half `S` is not in `0 <= S < L`, where
`L = 2^252 + 27742317777372353535851937790883648493`. This applies to single
and batch verification.

**Enforcement.** The range check is a `static inline` in
`src/c/internal/ama_ed25519_canonical.h`, applied in `ama_ed25519_verify`,
which batch verification calls per entry, so the two cannot disagree. It is the
first of three input rules kept together in that header: `0 <= S < L` here,
canonical point encodings in INVARIANT-38, small-order rejection in
INVARIANT-48. `S` is public, so the check carries no constant-time obligation;
it is branch-free because that costs nothing.

**Verification.** `tests/test_ed25519_canonical_s.py` and
`tests/c/test_ed25519_canonical_s.c` pin it from Python and C across single and
batch verify, and the vendored Wycheproof corpus runs all 150 Ed25519 vectors on
every PR (`tc63`, `tc85`). Only `S + L`, which still satisfies the group
equation, isolates this check; `tests/c/test_ed25519_verify_equiv.c` case D.3
(`S = L`) is not coverage for it, and both sites say so.

**Why.** RFC 8032 §5.1.7 requires the range; without it anyone can turn a valid
`(R, S)` into a second valid `(R, S + L)` with no private key, breaking every
system that treats signature bytes as an identity.

## INVARIANT-27 — X25519 u-Coordinates Must Be Reduced Before Use

**Statement.** Every X25519 field path must reduce the received u-coordinate
modulo `p = 2^255 - 19` after masking bit 255, so a non-canonical encoding and
its canonical form produce the same shared secret.

**Enforcement.** `x25519_canonicalize_u()` in `src/c/ama_x25519.c` masks bit 255
and performs one unconditional subtraction of `p` selected by an arithmetic
mask (one suffices: after masking the value is below `p + 19`); every ladder
calls it before decoding. It works on the 32-byte encoding, not inside
`fe51_frombytes` / `fe64_frombytes`, because those helpers are shared with
Ed25519, whose decoding must *reject* a non-canonical value (INVARIANT-38).

**Verification.** `tests/test_x25519_canonical_u.py` pins Wycheproof `tc88`
(u = `p + 3`), the whole `[p, p+18]` band and the bit-255 rule; the Wycheproof
gate runs all 518 X25519 vectors on every PR.

**Why.** RFC 7748 permits either reading, but a peer that does not reduce
derives a shared secret no other implementation computes, and the handshake
fails silently; every reference implementation reduces.

## INVARIANT-28 — ECDSA Signatures Must Be Low-s and Strictly Encoded

**Statement.** `ama_secp256k1_ecdsa_sign` **and
`ama_secp256k1_ecdsa_sign_raw`** must emit only the low representative
(`s <= (n-1)/2`), and `ama_secp256k1_ecdsa_verify` must reject a high `s`, an
`r` or `s` outside `[1, n-1]`, and any signature that is not minimal DER. Both
signers share `secp256k1_ecdsa_sign_scalars()` (including the `sc_cond_negate`
low-`s` selection) and differ only in DER-encoding versus fixed-width
`r || s`. Only the high-`s` rejection is caller-selectable, through
`ama_secp256k1_ecdsa_verify_ex(..., AMA_SECP256K1_ECDSA_ALLOW_HIGH_S)` for
third-party X9.62 interop; the range and minimal-DER rules never relax, and the
signers always emit low-`s`.

**Enforcement.** In `src/c/ama_secp256k1.c`: `sc_is_high()` decides low-`s`
against `(n-1)/2`; signing negates a high `s` by mask; verification rejects
one. `der_parse_signature()` accepts only `30 <len> 02 <rlen> <r> 02 <slen> <s>`
with short-form lengths, minimal INTEGERs, no superfluous leading zero, no
negative value and no trailing bytes. `sc_from_bytes()` reports whether its
input was already `< n`, so an out-of-range `r`/`s` is rejected, not reduced.
Signing is constant time with respect to the private key and the RFC 6979
nonce, measured by `tools/check_ghash_constant_time.py --target ecdsa`;
verification is variable time by design (every input is public).

**Exception (declared Wycheproof divergence).** The corpus scores high-`s`
signatures `valid` because plain X9.62 accepts them; AMA rejects them. The 72
such vectors are claimed by the named `ecdsa/high-s-rejected` policy in
`wycheproof_vectors/run_wycheproof.py` with an exact expected count.

**Verification.** `tests/test_secp256k1_ecdsa.py` (31 tests) covers RFC 6979
determinism, nonce non-reuse, rejection of the high-`s` twin of the library's
own signature, and each strict-DER rule; `tests/c/test_secp256k1.c` decodes the
DER form back to `(r, s)` and compares it with `r || s` over 512 keys; all 476
Wycheproof ECDSA vectors run on every PR.

**Why.** For every valid `(r, s)`, `(r, n - s)` also verifies; anyone holding a
signature can malleate it, as they can with a silently reduced `r` or a
non-minimal INTEGER.

---

## INVARIANT-29 — ECDSA Public-Key Coordinates Must Be Canonical Field Elements

**Statement.** `ama_secp256k1_ecdsa_verify` must reject a public key whose `Qx`
or `Qy` is not a canonical field element in `[0, p)`. A coordinate `>= p` is
rejected, never reduced before the curve-membership check.

**Enforcement.** `secp256k1_fe_bytes_canonical()` in `src/c/ama_secp256k1.c`
compares the big-endian coordinate against `p`; verification calls it on both
coordinates through `secp256k1_aff_from_bytes_checked()`, which
`ama_secp256k1_point_mul` shares, before evaluating the curve equation, and
`ama_secp256k1_pubkey_decompress` applies it to the compressed `x`. The public key is public, so the early return carries no timing
obligation.

**Verification.** `tests/test_secp256k1_ecdsa_noncanonical_pubkey.py` drives
the policy through Python (`Qx`/`Qy` in `{p, p+1, 2^256-1}` rejected, a
canonical key accepted); `tests/c/test_secp256k1.c` isolates the predicate via
`ama_secp256k1_test_fe_bytes_canonical`, and decompress is pinned with the
`x = 1` / `x = 1 + p` twin.

**Why.** A coordinate `>= p` is a second encoding of the reduced point; X25519
reduces (two peers must agree), but a verification key must not admit a second
encoding, matching libsecp256k1's own rejection.

## INVARIANT-30 — Agent-Instance Persistence Material Must Be Operator-Authorized

**Statement.** Key material or signature contexts carrying a non-`EPHEMERAL`
lifetime, or any capability in `AMA_AGENT_CAP_RESTRICTED_MASK` (`PERSISTENCE`,
`SELF_REPLICATE`, `DELEGATE`), **must not** be produced unless the binding
carries a non-zero ethical-profile hash *and* an authorization tag that
verifies under an operator-supplied authority key `K_auth`. The authority key
is an **input** to those derivations, not only to the gate beside them: a
restricted binding's HKDF output and signature context take the binder
`HMAC-SHA3-256(K_auth, 0x03 || enc(b))` (HKDF) or `… 0x04 || enc(b)`
(signature context), so the output is unobtainable without `K_auth`, not
merely unreachable through the guarded entry point. Unrestricted bindings take
a fixed zero binder. Every refusal is fail-closed: no output bytes, a distinct
error code, no partial state.

**Enforcement.** `src/c/ama_agent_binding.c`. `ama_agent_binding_check()` is
the single policy point; `ama_hkdf_agent_bound()` and
`ama_agent_binding_context()` call it before producing anything, and
`authority_binder()` mixes `K_auth` into both derivations under its own
sub-domain. The authorization tag is `HMAC-SHA3-256(K_auth, 0x01 || enc(b))`
over the whole canonical 88-byte record, so post-hoc capability escalation or
lifetime relabelling invalidates it. The refusal path is constant-time by
construction (every predicate folded into one mask, the HMAC computed even with
no key supplied, the tag compared over all 32 bytes, one arithmetically-selected
exit). No new algorithm is introduced (INVARIANT-1).

**Verification.** `tests/c/test_agent_binding.c` pins the canonical encoding as
a byte KAT and covers structural refusals, missing authorization, foreign-key
tags, single-bit tag flips, capability escalation and cross-binding separation;
`tests/test_agent_binding.py` drives the Python surface with property-based
injectivity; `tests/test_agentic_load_adversarial.py` runs four adversarial
scenarios; `fuzz/fuzz_agent_binding.c` builds records from arbitrary bytes and
traps on any restricted record accepted without authority, derivation for a
refused binding, or output written on refusal. The constant-time claim is
blocked by the deterministic `--target agent-binding` gate in
`.github/workflows/dudect.yml` (identical instruction counts on accept and
reject); the `Agent binding check` dudect lane is strict but abstains below its
2 ns floor (`tests/c/dudect/dudect_rounds.h`). The layer carries no
`AMA_USE_NATIVE_PQC` dependency, which the configuration-guard job in
`ci-build-test.yml` proves on every PR.

**Why.** An agent with in-process access (`THREAT_MODEL.md` T3.6) can call
`ama_hkdf` itself, so a policy gate beside a public derivation is a gate to step
around; persistence and self-replication are the two capabilities an escaped
agent needs and a legitimate caller rarely does.

---

## INVARIANT-31 — Every Pull-Request Job Must Be Reachable From Its Gate

**Statement.** Every job in a workflow that triggers on `pull_request` **must**
appear in the `needs:` of an aggregating gate job in that workflow, every gate
job **must** carry a job-level `if: always()`, and a gate **must** evaluate
the result of every need it lists (a wildcard `needs.*.result` test must cover
failure, cancelled and skipped). A workflow with more than one job that runs
on `pull_request` must define a gate. A path-filtered pull-request workflow
**must** have a no-op twin on the complementary paths, so its gate context is
reported on every pull request and can be a required check.

**Exceptions.** Single-job workflows (the job *is* its own context) and
workflows that never trigger on `pull_request` (`release.yml`,
`wiki-sync.yml`).

**Enforcement.** `tools/check_gate_coverage.py`, run in the `security-checks`
job of `ci.yml`, also reports a `needs:` entry naming a job that does not
exist, holds each twin's path list complementary to its workflow's, and keeps
non-vacuity floors equal to the live workflow and job counts.

**Verification.** `tests/test_gate_coverage.py` pins both directions —
uncovered job, gate without `if: always()`, multi-job workflow with no gate,
dangling `needs:`, an unevaluated need, a missing twin — plus a regression test
for `c-library-no-native-pqc` and a sweep over every workflow.

**Why.** Branch protection requires each workflow's gate context rather than
job names, so a job missing from `needs:` shows a red X that cannot block the
merge, a gate without `if: always()` reports `skipped` and never resolves, and
a skipped path-filtered workflow reports no check at all.

---

## INVARIANT-32 — Documented Install Commands Must Resolve

**Statement.** Every optional-dependency extra named in a `pip install`
command in the tracked documentation **must** be declared in
`[project.optional-dependencies]` in `pyproject.toml`, compared under PEP 685
normalisation, and every declared extra must be named by at least one install
instruction.

**Exception.** `CHANGELOG.md` is excluded by design: it is a historical
record, and an extra that existed in an earlier release must stay readable in
the entry that introduced or removed it.

**Enforcement.** `tools/check_documented_extras.py`, run in the
`security-checks` job of `ci.yml`.

**Verification.** `tests/test_documented_extras.py` pins detection (single and
comma-separated forms), non-detection (declared extras, PEP 685 punctuation
and case, Markdown link syntax, non-install lines), a sweep over the
repository's documentation, and the reverse direction.

**Why.** `pip` installs a package *without* an extra it does not provide and
exits 0, so a stale extra name produces a successful install missing the
dependencies the reader was told they were getting — as a wiki page once did
for a nonexistent `secure-memory` extra advertised as a libsodium binding.

---

## INVARIANT-33 — Every Fuzz Harness Must Be Registered Everywhere

**Statement.** Every translation unit in `fuzz/` that defines
`LLVMFuzzerTestOneInput` **must** appear in the CMake target lists, in the
`fuzzing.yml` job matrix (actively, or commented out with a recorded reason and
an allowlist entry naming the job that does run it), and in
`oss-fuzz/build.sh`, and must have a non-empty seed corpus. No registry may
name a target with no source file. Every Python harness under `fuzz/python/`
**must** be run by `fuzzing.yml`.

**Exception.** `fuzz_sphincs` is excluded from the per-PR matrix (SPHINCS+ is
too slow for that lane) with the reason recorded beside it; it stays in both
build lanes and runs in the job its allowlist entry names.

**Enforcement.** `tools/check_fuzz_target_registration.py`, run in the
`security-checks` job of `ci.yml`; `tools/check_fuzz_input_reachability.py`
derives each lane's `-max_len` from the harness's own guards so the deep
branches are reachable (INVARIANT-46).

**Verification.** `tests/test_fuzz_target_registration.py` pins both
directions over a synthetic tree plus the repository's own registration,
including three non-detection cases (a support unit such as `fuzz_rng.c`, a
file that merely names `LLVMFuzzerTestOneInput` in a comment, a CMake comment
with a parenthesis). `tests/test_python_fuzz_harness.py` drives
`fuzz/python/fuzz_key_formats.py` in-process and violates each contract it
claims (an unexpected exception, a non-canonical acceptance, a slow parse, a
missing artifact) to confirm each is still caught; the parser defects its
campaigns found are pinned by named regression tests in
`tests/test_key_formats.py`.

**Why.** A harness registered in some lists but not others — `fuzz_agent_binding`
was once never built by OSS-Fuzz, whose `build.sh` skips a missing target with
exit 0 — is indistinguishable from one that finds nothing.

---

## INVARIANT-34 — Low-`s` Is a Property of the Sign/Verify Pair

**Statement.** Low-`s` normalisation and high-`s` rejection are **two halves of
one control**. A curve's default sets both or neither, and any API that exposes
them exposes both.

- **secp256k1** sets both by default: `ama_secp256k1_ecdsa_sign` and
  `ama_secp256k1_ecdsa_sign_raw` emit only the low representative and
  `ama_secp256k1_ecdsa_verify` rejects the high twin (INVARIANT-28);
  `AMA_SECP256K1_ECDSA_ALLOW_HIGH_S` relaxes the verifier for third-party X9.62
  interop.
- **P-256 / P-384 / P-521** set neither by default: `ama_nistp_ecdsa_sign`
  emits RFC 6979's `s` verbatim and `ama_nistp_ecdsa_verify` accepts either
  representative. `AMA_NISTP_ECDSA_SIGN_LOW_S` and
  `AMA_NISTP_ECDSA_REQUIRE_LOW_S` turn both halves on together.

Unconditional on every curve in every mode: minimal DER only, `r` and `s`
strictly in `[1, n-1]` rather than reduced, and public-key coordinates strictly
in `[0, p)`. The normalisation predicate is selected by mask, never branched on
(whether `s` was negated is exactly what the published low `s` hides); the
caller's `low_s` flag is public and may be branched on.

**Enforcement.** In `src/c/ama_nistp.c`, `nistp_ecdsa_sign_core()` takes
`low_s` as a parameter derived from `AMA_NISTP_ECDSA_SIGN_LOW_S` by
`nistp_sign_dispatch()` (unknown flag bits are rejected), and
`nistp_ecdsa_verify_rs()` rejects a high `s` only under
`AMA_NISTP_ECDSA_REQUIRE_LOW_S`; the range, coordinate and strict-DER gates sit
outside both flags. The secp256k1 half is INVARIANT-28's. Signing is constant
time with respect to the private key and the nonce on both curves, including
the normalisation; verification is variable time by design.

**Exception (declared).** The secp256k1 Wycheproof divergence
`ecdsa/high-s-rejected` claims exactly 72 vectors, scoped by filename. The three
prime-curve suites need no divergence policy and pass with zero exceptions;
a strict prime-curve default would create an uncounted divergence and turn the
gate red.

**Verification.** `tests/test_nistp_curves.py::test_rfc6979_published_vectors`
replays all 18 in-scope vectors from RFC 6979 Appendix A.2.5/A.2.6/A.2.7
(vendored under `tests/kat/rfc6979/`) and fails if the corpus stops containing a
high-`s` case; `test_rfc6979_vectors_reject_low_s_normalisation`,
`test_low_s_is_opt_in_and_default_is_rfc6979_verbatim`,
`test_low_s_is_a_property_of_the_sign_verify_pair` (the four-way truth table)
and `test_ecdsa_matches_rfc6979_reference` (a specification-derived reference
under both policies) pin the rest; `tests/test_secp256k1_ecdsa_low_s_policy.py`
holds the secp256k1 half.

**Why.** Normalisation alone prevents nothing: if the verifier accepts both
representatives, anyone can emit `(r, n - s)` and AMA accepts it. A reference
must be derived from the specification only — the first prime-curve reference
normalised because the C code did, and the two agreed while both diverged from
RFC 6979. The prime curves default to verbatim because they exist to
interoperate with X9.62, FIPS 186-5, TLS, X.509, JWS and WebAuthn signers that
do not normalise.

---

## INVARIANT-35 — A Selector Must Never Resolve Weaker Than It Was Asked

**Statement.** Any argument that names an algorithm, curve, parameter set or
security level **must** resolve to exactly what was named or fail — never fall
back to a default, round to a neighbour, or answer for an input it did not
recognise:

- an unrecognised value raises (Python) or returns `NULL` / `0` (C);
- a size or capability query for an unrecognised value returns `0` or `NULL`,
  never another parameter set's size;
- no selector maps unknown input onto a real choice through a default branch;
- an escalation from an algorithm whose strength cannot be ranked is refused,
  and strength ladders are per algorithm family, so an escalation cannot cross
  families.

**Exception.** Name aliases resolve to the thing they name (`"secp256r1"`,
`"prime256v1"` and `"P-256"`; `"Dilithium3"` for ML-DSA-65). What is forbidden
is resolving something that names *nothing*.

**Enforcement.** In C, `nistp_lookup()`, `kyber_params_for()`,
`dil_params_for()` and `slh_lookup()` end in `default: return NULL`, and every
public size/name query propagates it. In Python, `_param_set_id()` and
`_nistp_curve_id()` raise `ValueError` on any unrecognised value and reject
`bool` explicitly; `CryptoPostureController` raises for an algorithm it
cannot rank.

**Verification.** `tests/test_selector_strictness.py` derives the list of
selectors from the modules, drives each with neighbouring-but-invalid
integers, plausible wrong names, `bool`, `None`, negatives and the empty
string, asserts a raise every time and a `0`/`NULL` from C, and checks that
aliases resolve only to real sets.

**Why.** A selector that maps an unknown name onto a real parameter set
produces working code, valid signatures and successful handshakes at a
security level nobody chose, and unlike a missing backend it never surfaces.
The rule is absolute rather than "not weaker" because a selector cannot know
which direction is weaker for its caller.

---

## INVARIANT-36 — AMA Is Not Measured Against Another Implementation

**Statement.** No other cryptographic implementation's output may serve as an
answer key for AMA's correctness, and no code under `ama_cryptography/`,
`tests/` or `tools/` may invoke another cryptographic binary. Where a
specification publishes no worked example, the substitute is a reference
derived **from the specification text**, written in this repository — for key
formats, `tests/ref_keyformat.py` (a declarative encoder transcribed from the
RFCs' ASN.1, anchored against RFC 9500 §2.3 and RFC 8410 §10.1) and the RFC 9500
§2.3 test keys in `tests/kat/keyformats/rfc9500_ec.json`. Published
test-vector suites (`wycheproof_vectors/`, the NIST ACVP corpora under
`tests/kat/`) are adversarial inputs with expected verdicts, not implementation
output, and keep their own provenance gates.

**Two exceptions are recorded.** The first is `benchmarks/` (audit M22): the
benchmark harness links and drives reference implementations (OpenSSL,
libsodium, wolfSSL, Botan, Nettle, libgcrypt, mbedTLS) **solely to measure AMA
against them**. It is on no correctness, runtime or release path, feeds no
answer key, and is outside the gate's scope by design.

The second is the interoperability oracles: the tests carrying
`@pytest.mark.requires_interop_oracle` in `tests/test_aes_gcm_native.py`,
`tests/test_hkdf_sha3_256.py`, `tests/test_ed25519_native.py`,
`tests/test_ed25519_expanded_key.py` and `tests/test_differential.py` import
PyCA cryptography, PyNaCl or pycryptodome
and check that AMA and a second implementation agree in both directions. That
is interoperability evidence, installed by the require-backends lane (audit
M18); it is not the answer key. A disagreement with an oracle is investigated
against the specification, never resolved in the other implementation's
favour. The register is complete: an exception omitted from it, or one named
here after removal, misleads a reader who takes it as current.

**Enforcement.** `tools/check_corpus_originality.py`, run in the
`security-checks` job of `ci.yml`:

1. No process-spawning call under `ama_cryptography/`, `tests/` or `tools/`
   invokes a cryptographic binary. AST-based (comments naming OpenSSL are not
   findings), covering the `subprocess`, `os.system`/`popen`, `exec*`,
   `spawn*` and `posix_spawn*` families, with string constants bound to names
   resolved first.
2. Every corpus file's `source.url` is on `rfc-editor.org` or `ietf.org`.
3. `tests/ref_keyformat.py` imports nothing from `ama_cryptography`.
4. No vector generator computes its expected values through a third-party
   provider instead of transcribing them (`scan_vector_generators`).

The gate cannot see a Python import, and its verdict says what it checked;
the oracle register above is kept complete by
`tests/test_interop_oracle_register.py`.

**Verification.** `tests/test_corpus_originality.py` reproduces each violation
(a `subprocess.run(["openssl", ...])`, four other binaries, a non-standards
corpus source, a directory of key files under the corpus, a reference encoder
importing the production one, a missing reference encoder) and pins the
non-detection of prose mentioning OpenSSL.

**Why.** An answer key taken from an implementation inherits its opinions,
bugs and non-conformances, and two implementations that share an assumption do
not check each other.

---

## INVARIANT-37 — A Verification API Must Not Claim a Check It Does Not Perform

**Statement.** A function whose name begins `verify_`, a result key, a
parameter, a docstring, or any document in this repository **must not** assert
a verification the implementation does not carry out. Where a check is not
implemented:

- the **name** scopes itself to what is checked (`verify_token_binding`, not
  `verify_token`);
- an argument requesting the unimplemented check **raises**, never resolves to
  the weaker one;
- the boundary is **published as data**, not only prose, so documentation can
  be checked against code.

The canonical instance is RFC 3161.
`ama_cryptography.rfc3161_timestamp.RFC3161_CAPABILITIES` is the single source
of truth: `message_imprint_binding`, `pki_status`, `nonce_echo` and
`signer_present` are performed; `tsa_signature`, `tsa_certificate_chain` and
`gen_time` are not. A claim must be negated on the line that makes it.

**Enforcement.** `tools/check_verification_claim_honesty.py`, run in the
`security-checks` job of `ci.yml`, reads `RFC3161_CAPABILITIES` with `ast` and
forbids a claim *because* its capability is `False`, so implementing a check
and flipping its entry permits the matching documentation with no gate edit.
Five checks:

1. No un-negated claim of an unperformed check in `ama_cryptography/`,
   `tools/`, `tests/`, `examples/`, `docs/`, `wiki/`, `benchmarks/`, `fuzz/`
   or root Markdown, negation scoped to the sentence that carries the claim;
   generic assurance vocabulary is scoped to timestamping lines.
2. No document or docstring teaches the misnamed `results["rfc3161"]` key
   (retained in code, warning when read).
3. `certificate_file` and `tsa_cert_path` are documented as raising.
4. No instruction to install `rfc3161ng` (removed under INVARIANT-1).
5. Every `False` capability has claim patterns bound to it, every pattern names
   a real capability, and the scan's exemption list is exactly the two
   self-referential files (the checker and its test).

The same gate also rejects unqualified formal-verification claims.
`TokenVerification.not_verified` reports the same table at runtime.

**Verification.** `tests/test_verification_claim_honesty_gate.py` — 71 tests —
pins every violation class and its near-misses, including
`test_flipping_a_capability_to_true_permits_its_claims` and
`test_ast_parsed_table_equals_the_imported_one`.
`tests/test_rfc3161_api_honesty.py` — 20 tests — drives the behaviour the
table describes;
`test_a_token_with_a_nonsense_signature_still_satisfies_the_binding` requires
the binding check to accept a keyless token with a zeroed signature and an
epoch `genTime`, and its companion requires a different payload to be rejected.

**Scope.** The invariant is general; the table and patterns cover RFC 3161,
where the defect was found. A future verification surface with an
unimplemented half declares its own table. What closing the RFC 3161 gap
requires is in [ARCHITECTURE.md § Scope: RFC 3161 attestation is not implemented](ARCHITECTURE.md#scope-rfc-3161-attestation-is-not-implemented).

**Why.** Documentation that overstates a security property is a vulnerability
in the deployment: before this invariant the repository contradicted its own
RFC 3161 implementation in more than fifty places, including a threat-model row
an auditor reads as closed.

---

## INVARIANT-38 — Ed25519 Compressed Points Must Have a Canonical `y`

**Statement.** Every Ed25519 point decode must reject a compressed encoding
whose `y`, after masking bit 255, is not in `[0, p)` with `p = 2^255 - 19`, and
an encoding with `x = 0` and the sign bit set (RFC 8032 §5.1.3). A `y >= p` is
rejected, never reduced before the curve equation is solved.

**Enforcement.** `ama_ed25519_point_y_is_canonical()` and
`ama_ed25519_point_x_sign_is_admissible()` in
`src/c/internal/ama_ed25519_canonical.h` (the branch-free comparator is shared
with the `S < L` check), enforced inside `ge_decode_prepare` in
`src/c/internal/ama_ed25519_ge.h`, which every decode funnels through, so both
field instantiations accept exactly the same encodings; `ge_decode_finish`
re-checks `x = 0` as deliberate defence in depth. The `y` is public; the check
is branch-free regardless.

**Verification.** `tests/c/test_ed25519_canonical_s.c` covers the full 19-value
band, the `p-1`/`p` boundary, sign-bit independence and single/batch
integration; `tests/test_ed25519_canonical_y.py` drives the policy through
Python; `tests/c/test_ed25519_decode_x_zero.c` pins the §5.1.3 rule on the
non-verify decoders (`scalarmult_public`, `double_scalarmult_public`,
`point_add`), where only removing *both* redundant guards changes a verdict;
the frozen oracle and the fe51/MULX differential pin the two instantiations.

**Why.** A verification key must not admit a second encoding, because
everything treating the key as an identity would see two names for one key;
X25519 resolves the same question the other way (INVARIANT-27) because two
peers must agree on one shared secret.

---

## INVARIANT-39 — A Failed POST Must Fail the Import, and the Error State Must Inhibit Output

**Statement.** FIPS 140-3 §4.9.2 requires a module whose power-on self-tests
fail to enter an error state in which **all** cryptographic output is
inhibited. For this package that is two rules:

- **A failed POST fails the import.** `import ama_cryptography` raises
  `CryptoModuleError` carrying the root cause and the full POST result table.
- **The error state inhibits output.** Every public entry point that reaches
  the native library or a Cython kernel calls `check_crypto_permitted()` before
  its first native call — `pqc_backends`, `ascon`, `agent_binding`,
  `secure_memory`, every `cy_*` function in the Cython bindings (whose import
  forces POST to run), `AmaContext`, and the `key_formats` secret-key exports
  (`to_pkcs8` / `to_pem` / `to_jwk` / `to_cose`).

`check_crypto_permitted()` permits `SELF_TEST` on the POST thread only, so the
KATs can call the primitives under test without opening the surface to other
threads. `module_attestation()["fully_verified"]` is true only when no
self-test was skipped; release gates assert it. The CASTs POST depends on run
first (NIST IG 10.3.A): the SHA3-256 and Ed25519 KATs — genuine known-answer
tests with negative cases — precede the integrity stage that uses them. The
integrity signature covers `SHA3-256(domain ‖ py_digest ‖ native_digest)` plus
the POST KAT vectors and the six binding extensions (v3 artefact), and the
native library is verified **before** it is mapped: candidates are hashed
first, loaded through `/proc/self/fd` on the hashed descriptor on Linux, and a
mismatch is refused before its constructors run. An `AMA_CRYPTO_LIB_PATH`
override relocates the signed library and never substitutes it: it passes the
same pre-load check, and a differing object is refused with no fallback.
Diagnostics describe what happened: signed-integrity verification is
verified / tampered / could-not-be-verified, and the last case carries the
loader's own error.

**Exceptions (the only two import completions; neither permits
cryptography).**

- `AMA_POST_DIAGNOSTIC_IMPORT=1` — triage: the module stays in `ERROR` and
  `check_crypto_permitted()` refuses every operation; the operator gains
  `module_attestation()`.
- A process that **is** the integrity signer (`_process_is_the_integrity_signer()`:
  `ama_cryptography._build_sign`, or `ama_cryptography.integrity` running a
  writing subcommand, by `__main__` and `sys.orig_argv`; revoked in
  secure-execution mode) completes the import when every failed stage is one a
  re-signing run repairs — a stale integrity binding or a native digest
  refusal. A bad signature, a wrong trust anchor, a malformed artefact, a
  failed KAT, a timing leak or an RNG fault hard-fails on every path. An
  environment variable alone (`AMA_BUILD_PIPELINE=1`) confers nothing.

**Enforcement.** `tools/check_error_state_gating.py` enumerates the gated
surface from the modules' ASTs — following one level of delegation to a
private helper whose first statement is the guard — requires the guard before
the first native call, line-scans the five binding `.pyx` files, discovers any
other module reaching the native library, and checks its declared exemptions for
staleness. Its output is the authoritative count: 107 native entry points
across `pqc_backends`, `ascon`, `agent_binding` and `secure_memory`, plus
10 Cython binding entry points, with 4 documented exemptions at the time of
writing; `tools/check_documented_counts.py` compares every published
occurrence of that figure against the tool.

**Verification.** `tests/test_post_failclosed.py` drives the import-level
behaviour in subprocesses, the binding and key-export refusals, and that a
broken KAT is not excused; `tests/test_error_state_gating_tool.py` pins the
gate in both directions; `tests/test_native_integrity.py`,
`tests/test_preload_native_digest.py` (including
`TestSigningScopeRequiresIntentNotJustIdentity`) and
`tests/test_native_lib_override_hardening.py` pin the tamper, forge,
refused-before-mapping and override cases;
`tests/test_native_library_never_mapped_unverified.py` requires a tampered copy
to be refused *and* absent from `/proc/self/maps`.

**Cost.** One state check per gated call, and one SHA3-256 over the shared
object per import.

**Why.** A self-test whose failure goes to the log while success goes to the
exit code fails nothing, and a shared object executes its constructors the
moment it is mapped, so a digest compared after load detects tampering the
tampered code has already acted on.

---

## INVARIANT-40 — The Executed Bytecode Must Match the Signed Source

**Statement.** The bytecode CPython executes must be a faithful compile of the
integrity-verified source. POST's `execution-integrity` stage, run right after
the source-integrity stage, recompiles every signed `.py` and refuses any
cached `.pyc` the interpreter would load whose bytecode differs, comparing the
executed surface (`co_code`, names, locals, argument and flag shape, and every
constant recursively, with a type guard) and ignoring `co_filename` and line
tables. It validates each `.pyc` header as CPython does (PEP 552, the
`--check-hash-based-pycs never` unchecked case included), covers the same file
set the digest signs (lazily imported modules too), records honestly where no
`.pyc` exists, and flags any loaded `ama_cryptography` module whose source
resolves outside the verified package directory.

**Exception (stated boundary).** A self-check written in Python cannot vouch
for its own module's bytecode if that was poisoned before it ran; OS and
package-manager code signing is the control that closes this, documented in
[`SECURITY.md`](SECURITY.md) under *Execution integrity*.
`tools/verify_install_oob.py` performs the same comparison out of band, from
the operator's interpreter, against an `--expected-pubkey` supplied from
outside the tree.

**Enforcement and verification.** `tests/test_execution_integrity.py` pins the
comparator (a changed instruction, a nested-function change and a
constant-type swap are caught; a filename-only difference is not), the
per-file check, the substitution guard, and the end-to-end path on a copied
tree; `tests/test_pyc_cache_liveness.py` pins the header rules under all three
`--check-hash-based-pycs` settings.

**Cost.** One `compile()` per signed source file, once per import.

**Why.** A timestamp-based `.pyc` is honoured whenever its stored
`(mtime, size)` match the source, so an attacker can leave every `.py` pristine
— signature verifying — and run different bytecode.

## INVARIANT-41 — No Asymmetric Keypair Is Released Without a Pairwise Consistency Test

**Statement.** Every asymmetric key-generation path runs the matching FIPS
140-3 pairwise consistency test before its keypair leaves the function:
sign-and-verify for the signature families (Ed25519, ML-DSA, SLH-DSA/SPHINCS+,
the FROST dealer via a full t-of-n round verified against the group key, ECDSA
per FIPS 186-5 §3.3 for the NIST-P curves and the BIP32 secp256k1 keys);
encapsulate-and-decapsulate for ML-KEM; and for X25519 the SP 800-56A rev. 3
§5.6.2.1.4 assurance in its strong form, a Diffie-Hellman roundtrip against a
fresh ephemeral peer. The rule is uniform across random and seed-derived
generation and across every surface (`native_*`, `generate_*`,
`AmaContext.keypair_generate` with the context's own operations, and the BIP32
master and child derivations). The test is **unconditional**; where a test's
counterpart operation is not built, keygen refuses with an availability error
rather than release an untested keypair. A failed test enters ERROR and
inhibits all further output (INVARIANT-39). Every Python-side entropy draw that
mints key material, nonces or session identifiers goes through the §4.9.2
health-tested, error-state-gated CSPRNG (`secure_token_bytes`), never a bare
`secrets` / `os.urandom` draw.

**Exception (scope).** These are properties of the `ama_cryptography`
**Python package**, not of `libama_cryptography.so` linked directly (audit M1):
a C consumer gets the constant-time primitives but not POST, the error-state
inhibition or the PCT (C-side PCT exists for ML-KEM only). This invariant and
the FIPS-140-3-alignment claims are scoped to the Python API surface until the
controls move into the C boundary or the boundary is formally defined as the
Python package (INVARIANT-16).

**Enforcement.** `tools/check_keygen_pct.py` discovers every keygen entry point
from `ama_cryptography/pqc_backends.py`'s AST and fails on any that does not
reach `pairwise_test_signature` / `_kem` / `_agreement`, directly or through
one level of delegation; every arm of a conditional whose sibling arm runs a
test must run one or raise, and a test under an `if` without an `else` does not
count as unconditional. Exemptions name a reason and are checked for
staleness. It runs in `ci.yml`. `tests/test_invariant41_rng_sweep.py`
enumerates every bare OS-entropy call site in the package against a reasoned
allowlist.

**Verification.** `tests/test_keygen_pct_gate.py` pins the gate in both
directions (including an unwired keygen appended to the module);
`tests/test_keygen_pct.py` pins the behaviour — a lying verify raises
`CryptoModuleError` and enters ERROR, ERROR refuses further keygen, and real
keypairs pass for every fast family.

**Cost.** Small beside key generation for every family except the hash-based
signatures, whose keygen visibly pauses; the user-facing statement of that cost
is row 4 of the CHANGELOG's 5.0.0 glance table (measured in `2dcef5c6`).

**Why.** A keypair whose halves do not correspond — a fault mid-generation, a
corrupted seed, a miscomputed BIP32 sum — otherwise fails later, far from the
event that caused it, and a flag-gated test would make the default
configuration the non-compliant one.

## INVARIANT-42 — The Declared ctypes ABI Must Match the C Header, and the Loaded Library Must Match the Package

**Statement.** Every `argtypes`/`restype` declaration in the package must agree
with the `AMA_API` prototype in the C headers — arity, and a coarse class per
position (pointer-like vs integer-like; pointer/integer/void for returns) — in
both directions: a symbol called without a declared signature fails, and a
signature for a symbol no header declares fails. At runtime the loader asks the
**loaded** object for its compiled-in version (`ama_version_number`) before
configuring any signature and rejects a library whose major version is not the
package's.

**Enforcement.** `tools/check_ctypes_abi.py` discovers its scope from the
package's ASTs, with `REQUIRED_MODULES` as a seven-module floor
(`pqc_backends`, `ascon`, `agent_binding`, `secure_memory`,
`hybrid_combiner`, `_build_sign`, `_self_test`) evaluated against discovery,
and prints both counts. `tools/check_version_consistency.py` pins the Python
transcription of the required major to the header macro.

**Verification.** `tests/test_ctypes_abi_gate.py` demonstrates an arity
change, a pointer/integer confusion, a void return read as a value and an
uncovered called symbol each failing; the handshake's reject branch is pinned
against a fake library reporting a foreign version.

**Cost.** The static gate is CI-only; the handshake is one call per import.

**Why.** A symbol probe proves a name is exported, not its arity or types, and
a stale prior-major library satisfies every `hasattr` and corrupts the call
frame at the first mismatched call.

## INVARIANT-43 — Every Logged Literal Must Survive a cp1252 Handler

**Statement.** Every literal emitted through a logger or `warnings.warn` in the
shipped package must be encodable in cp1252. Interpolated values are runtime
data and are not checked. The rule is cp1252-encodable, not ASCII: `—` and `§`
encode and are used widely.

**Enforcement.** `tools/check_log_message_encodability.py` walks every
module's AST for emission sites — bound-name loggers, `self.logger`, and the
inline `logging.getLogger(__name__).<level>(...)` idiom — and fails on a
literal a cp1252 handler would refuse, and on an explicit path it cannot read.
It runs in ci.yml's Security Checks job.

**Verification.** `tests/test_log_message_encodability_gate.py` pins both
directions, including the inline idiom.

**Why.** `logging.FileHandler` defaults to the locale encoding (cp1252 on
Windows) and silently discards a record it cannot encode; the key-rotation
audit records once carried a `→` and were exactly the records Windows dropped.

---

## INVARIANT-44 — A Fetched Conformance Corpus Is Pinned by Its Bytes, Not by a Name

**Statement.** Every conformance vector that is fetched rather than vendored is
pinned by SHA-256 and length in a committed manifest
(`docs/compliance/acvp_vector_digests.json`), and every consumer verifies
against it independently: the fetcher before it writes (refusing, not trusting,
a local file that does not match), the harness before it reads, and the
workflow between the two. The bytes written are the bytes published. The pin
is advanced only by `fetch_vectors.py --refresh-manifest`, which refuses to run
under GitHub Actions, in the same commit as the attestation it underwrites.

**Enforcement.** `tools/acvp_vector_pin.py` is the verifier and `--check` CLI;
`.github/workflows/acvp_validation.yml` runs it between the fetch and the run
and cross-checks the manifest's ref against the attestation's. Fetches go
through `tools/http_fetch.py` (HTTPS only, transport errors retried, a 404/403
or a wrong digest never retried). Vendored corpora are pinned the same way in
`tests/kat/PROVENANCE.json` by `tools/check_vector_provenance.py`.

**Verification.** `tests/test_acvp_vector_digests_gate.py` pins anchor digests
in its own source (so a regenerated manifest alone cannot make a corrupted
corpus verify), holds the manifest to the two independent records the tree
carries for three of the files, and drives every refusal with a negative
control; `tests/test_vector_provenance_gate.py` does the same for the vendored
corpora.

**Why.** A tag is a movable ref served through a CDN, so an attestation citing
`v1.1.0.42` described bytes nobody had identified, and a re-serialised local
copy could never be compared with upstream.

---

## INVARIANT-45 — Every SIMD Kernel Has a Pin, and the Published Vectors Run Under It

**Statement.** Every kernel the dispatch table can install has an
`AMA_DISPATCH_ONLY` name, and the inventory is one list across
`src/c/dispatch/ama_dispatch.c`, `tests/c/test_dispatch_only_env.c`,
`include/ama_dispatch.h`, `tests/c/CMakeLists.txt` and `dudect.yml`. For every
slot, the published-vector KATs whose primitive routes through it run with the
slot pinned and the auto-tune off, on every ctest lane including
MemorySanitizer (built with SIMD on). A KAT cannot pass under a pin the host
did not honour: `tests/c/kat_slot_guard.h`, the first statement of every swept
executable's `main()`, exits 77 (Skipped) when the pin was refused — or 1 when
the build's CI runner class mandates the slot. Mandated slots follow
`dudect.yml`: AVX2 and AES-NI+PCLMULQDQ on hosted x86-64 runners, NEON and the
Crypto Extensions on AArch64; AVX-512, VAES and SVE2 may skip. A pin resolves on
the probed tier even after auto-tune demotion or an opt-out.

**Enforcement.** The sweep is registered in `tests/c/CMakeLists.txt` with two
negative-control cells that pass only on the guard's own verdict line
(`PASS_REGULAR_EXPRESSION`), so deleting the guard fails them.
`tests/test_kat_slot_sweep_gate.py` holds the five inventories to one list,
requires a published-vector cell per slot, requires the guard as the first
statement of every swept `main()`, and requires both MSan lanes to build the
SIMD kernels.

**Why.** A pin that only proves it resolves executes no cryptography, and a
kernel checked against the standards only when a host's default wiring selects
it may never be checked at all.

---

## INVARIANT-46 — Fuzzing Must Be Able to Deepen

**Statement.** The fuzz corpus persists across runs: restored before fuzzing,
merged to its coverage-adding units after (after a crash too), and saved under
a run-unique key, so every run starts from the newest corpus and leaves a newer
one. A scheduled campaign runs an order of magnitude longer than a
pull-request run and saves what it finds on the default branch. The OSS-Fuzz
build integration is executed by OSS-Fuzz's own driver — `build_fuzzers`
inside `base-builder` with the checkout mounted, then `check_build` — on every
push, through the same script a developer runs, and ClusterFuzzLite runs nightly
from the same integration under three sanitizers.

**Enforcement.** `tests/test_fuzz_corpus_persistence_gate.py` pins the
restore → fuzz → merge → save order and keys in both matrix jobs, the merge
after a crash, the growth numbers in the step summary, the schedule and its
budgets, the OSS-Fuzz job in the fuzzing gate, the script mounting the checkout,
and the ClusterFuzzLite modes and pins. `tools/check_fuzz_target_registration.py`
holds `oss-fuzz/build.sh` to the harness set, and `.clusterfuzzlite/build.sh`
execs it so there is one build integration.

**Why.** A lane that starts from the seed corpus and discards what it found
every time never reaches the deep branches libFuzzer only grows into over many
executions.

---

## INVARIANT-47 — A Lane That Provisions a Resource Fails the Skip of It

**Statement.** When a lane is configured to provide what a test needs — the
native backends, the interoperability oracles, the full git history, an
example's third-party dependency, a tool the lane installs — a skip of that
test in that lane is a failure. The lane declares what it provides with a flag
(`AMA_CI_REQUIRE_BACKENDS`, `AMA_CI_REQUIRE_HISTORY`); a test declares what it
needs with a marker (`requires_interop_oracle`, `requires_git_history`,
`requires_example_deps`, `requires_host_isa`) or, for the native backends, by
naming the backend in its skip reason; `tests/conftest.py` turns the skip into a
failure only where the two meet. A flag never escalates outside its own promise,
and a history guard resolves its refs before comparing anything, so it cannot
pass silently either. Outside CI every one of these remains an ordinary skip.

**Enforcement.** `tests/conftest.py` escalates the markers and backend keywords
under their flags (`requires_host_isa` exempts only where the host genuinely
lacks the named ISA); `ci.yml` and `ci-build-test.yml` check out with
`fetch-depth: 0`, install `[examples]` and `clang-format`, and set both flags on
their pytest steps; `benchmarks/check_baseline_justification.py` refuses a ref
it cannot resolve and an empty base ref.

**Verification.** `tests/test_conftest_backend_skip_scoping.py` drives the
production hook through pytester for every marker in both directions, holds
every history skip and every `[examples]` import-skip under its marker, and holds
the backend-only modules' reasons to the keyword set.

**Why.** A skip is green, and guards that read git objects skipped on every
depth-1 CI run for as long as they existed; one compared nothing with nothing
and passed.

---

## INVARIANT-48 — Ed25519 Must Reject Small-Order Public Keys and R Halves

**Statement.** Every Ed25519 verification path must reject a signature whose
public key `A`, or whose signature half `R`, is one of the fourteen 32-byte
encodings of the eight points of the order-8 subgroup — the identity included,
the non-canonical spellings included, both settings of the x-sign bit included.
This applies to single and batch verification.

**Enforcement.** `ama_ed25519_point_is_small_order()` in
`src/c/internal/ama_ed25519_canonical.h` — a sign-bit-masked byte comparison
against seven stored `y` values, derived and exhaustively checked (the five
distinct `y` of `E[8]` plus `p` and `p+1`, the only band values that reduce into
the set) — applied to `public_key` and to `R` in `ama_ed25519_verify`, which
batch verification calls per entry, with deliberately no second copy. The
policy (cofactorless verification guarded by this rule) is stated at
`ama_ed25519_verify` in `include/ama_cryptography.h`, together with the
consequence that a cofactored verifier (ZIP-215, permissive libsodium) and a
cofactorless one can be split by torsion-carrying signatures, so a consensus
system fixes one rule across every participant. Six of the fourteen encodings
are also refused by INVARIANT-38; the overlap is kept so each predicate's
contract is independent of the order they are applied in. A blocklist is used
rather than a cofactor-clearing order check because both decide exactly the
same predicate and the blocklist needs no decode; the measurement that chose it
is in `9b860868`. Both inputs are public; the comparison is branch-free anyway.

**Verification.** `tests/c/test_ed25519_small_order.c` and
`tests/test_ed25519_small_order.py` carry the forgery vectors (generated by a
pure-Python RFC 8032 reference pinned by the §7.1 vectors), labelled FORGERY,
RANGE or SMOKE by mutation, and put every vector to single *and* batch verify
with the verdicts required to agree. The Wycheproof Ed25519 vectors pass with
no new divergence, and the frozen oracle replays clean.

**Why.** A cofactorless verifier accepts the identity as a public key unless
something rejects it, and then `(R = [s]B, S = s)` verifies for every message;
every small-order key admits a per-message forgery at the cost of at most eight
hashes. No legitimate signature is affected: an honest `R` is small-order with
probability about `2^-252`.

---

## INVARIANT-49 — A FROST Nonce Pair Is Single-Use and the Library Consumes It; Aggregation Verifies Every Share Before It Returns Success

**Statement.**

1. A nonce pair from `ama_frost_round1_commit` is good for **exactly one**
   `ama_frost_round2_sign` call, and **round 2 consumes it**: `nonce_pair` is
   non-`const`, it is `ama_secure_memzero`'d on every exit (success, argument
   refusal and internal error alike), and an all-zero (consumed) pair is
   refused on entry with `AMA_ERROR_INVALID_PARAM`, by a constant-time OR-fold.
2. `ama_frost_aggregate` verifies **every** signature share against the RFC 9591
   §5.3 relation before it contributes (a share must be canonical, `z < L`, and
   every commitment is admitted before `R` is built), reports the offending
   participant's 1-based index through `bad_participant_index` (written 0 on
   entry; 0 means "not attributable"), and verifies the assembled `(R, z)` with
   the RFC 8032 verifier before writing anything. A refusal writes no signature.

The header's FROST section is titled **RFC 9591-STYLE, NOT RFC 9591
CIPHERSUITE-INTEROPERABLE**: the hash derivations omit the
`"FROST-ED25519-SHA512-v1"` contextString and the H1–H5 separation, so every
participant must run this library; the aggregated signature's RFC 8032
conformance is unconditional.

**Enforcement.** `src/c/ama_frost.c`: every round-2 exit goes through one
`consume:` label; `verify_share_core` implements §5.3 and
`ama_frost_verify_share` exposes it. In `ama_cryptography/pqc_backends.py`,
`frost_round1_commit` returns the pair as a `bytearray`, `frost_round2_sign`
requires a writable buffer and scrubs it in `finally`, and `frost_aggregate`
raises `FrostShareRejected` with `participant_index`.
`tools/check_ctypes_abi.py` holds the arities against the header
(INVARIANT-42).

**Verification.** `tests/c/test_frost.c` Test 8 (scrub after success and
failure, refusal of a reused and of a supplied all-zero pair, and `ATTACK
BLOCKED`: three signings under one nonce, only the first succeeds) and Test 9
(honest shares accepted, corrupted ones rejected with the culprit's index for
two different culprits, the caller's buffer untouched, a `NULL` blame channel,
mismatched key shares, an honest ceremony still verifying);
`tests/test_frost.py` mirrors both (`TestFROSTNonceSingleUse`,
`TestFROSTShareVerification`).

**Cost.** Aggregation adds two share verifications per signer and one RFC 8032
verification, once per ceremony; round 2 is unchanged within noise. The
measurement is in `9b860868`.

**Why.** Reusing one nonce pair over three messages yields three linear
equations that recover the participant's long-term share from protocol outputs
alone, and an aggregator that checks nothing lets one faulty signer destroy
every ceremony anonymously.

---

## INVARIANT-50 — An Approved-Mode Signing API Is Context-Separated, and the Internal Interface Does Not Ship

**Statement.** Every signing and verification entry point in a shipped library
applies its scheme's domain separation before it reaches the core; a "legacy"
or "compatibility" name is not an exemption. The internal interface — FIPS 205
§9 `slh_sign_internal` / `slh_verify_internal`, FIPS 204 `ML-DSA.Sign_internal`
(Algorithm 7) — is compiled only under `AMA_TESTING_MODE`, so it is absent from
every shipped artefact by construction rather than by export control. Where a
test needs a knob the approved mode does not expose, the knob goes on the
context-separated entry point. An empty message is a message: `(NULL, 0)` is
read as empty for the message as it is for the context, and `(NULL, non-zero)`
is a caller bug.

**Enforcement.** `ama_sphincs_sign` / `ama_sphincs_verify` and the generic
`ama_sign` / `ama_verify` for SLH-DSA apply §10.2 with the empty context;
`ama_slhdsa_sign_addrnd` (taking `ctx` and `M` separately) replaced the public
`ama_slhdsa_sign_internal`. ML-DSA's internal functions are
`ama_ml_dsa_sign_internal` / `_verify_internal` in the test archive, and
`native_ml_dsa_sign` / `_verify` take the empty context by default.
`cmake/ama_exports.map` localises the internal names as defence in depth, and
`tools/check_ctypes_abi.py` refuses a declaration for a symbol the public
header no longer declares.

**Verification.** `tests/c/test_slhdsa_context_separation.c` asserts both
cross-verification probes as negative results and replays all 14 NIST ACVP
`signatureInterface == "internal"` SLH-DSA-SHA2-256f sigVer vectors through the
test archive; `tests/test_slhdsa_context_separation.py` holds the Python
surface and that `dlsym` finds neither §9 symbol; `tests/test_pqc_kat.py`
requires a shipped verifier to reject NIST's valid internal-interface
signatures. `tests/c/test_ml_dsa_context_separation.c` pins the ML-DSA §5.2
wrapper for empty, short and 255-byte contexts and replays the 30 internal and
30 external vendored records byte-exact; `tests/test_ml_dsa_interfaces.py`
asserts none of the four internal names is in the shipped library and repeats
the oracle probe against every shipped signer.

**Cost.** Negative: the §10.2 prefix is absorbed into the streaming hashes
rather than copied into a heap buffer, which made large-message signing faster
than the §9 path it replaced and removed the last allocation from
`src/c/ama_slhdsa.c`; the measurement is in `9b860868`.

**Why.** With both interpretations under one key the two cross-verified, so a
caller signing attacker-influenced bytes through the legacy or generic API was
a signing oracle for pure signatures on attacker-chosen `(ctx, M)`.

---

## INVARIANT-51 — An Ed25519 Signer Derives Its Own Public Half

**Statement.** No Ed25519 signing entry point hashes a public half into
`H(R ‖ A ‖ M)` that its own secret scalar did not generate.
`ama_ed25519_sign` must derive `A = [a]B` from the scalar it computed and refuse
any 64-byte secret key whose stored bytes 32..63 differ from it.
`ama_ed25519_expand_secret_key` must perform the same derivation and refusal
once, at load, and bind the scalar, the nonce prefix and `A` under a tag
(`SHA-512("AMA/Ed25519/expanded-key/v1" ‖ a ‖ prefix ‖ A)[0..31]`) that
`ama_ed25519_sign_expanded` must re-verify on every signature, refusing an
expanded key whose tag disagrees. Refusal on every path is
`AMA_ERROR_INVALID_PARAM` with the output written as zeros (64 signature
bytes, or the 128 expanded bytes), never left untouched. There is no opt-out.
The expanded form is not a storage format: it holds the scalar in the clear, is
documented as opaque, and its Python owner (`pqc_backends.Ed25519SigningKey`)
zeroes it on close and on collection.

**Enforcement.** `src/c/ama_ed25519.c`: both entry points share
`ed25519_sign_core`, which computes the signature unconditionally and applies
the verdict as a 0/~0 mask at a single exit (masking the 64 output bytes and
the return code); the comparisons are `ed25519_mismatch_mask32`, an
XOR-accumulate laundered through `ama_ct_value_barrier_u64`. The scalar,
`derived_a`, the recomputed tag and every buffer the core writes are scrubbed on
every exit (INVARIANT-6). The `ed25519-sign` and `ed25519-sign-expanded` targets
of `tools/check_ghash_constant_time.py` (instruction-count and secret-taint, on
the test archive and the shipped object) hold both to a zero delta.

**Verification.** `tests/test_ed25519_key_half_integrity.py` drives bit flips
across the public half, a half from another key and an all-zero half, and
asserts the two-signature transcript the attack needs cannot be produced.
`tests/c/test_ed25519_expanded.c` and `tests/test_ed25519_expanded_key.py`
replay the RFC 8032 §7.1 vectors through the expanded path, require
byte-equality with the per-call path, flip every expanded-key bit and require
refusal, and refuse at load, on both field backends. Every assertion is a
refusal or an inequality, with positive controls keeping them non-vacuous.

**Cost.** Measured on 2026-09-22 (`build/bin/benchmark_c_raw`, median of
1,000, 63-byte message, Intel Xeon @2.80GHz container, `taskset -c 0`):
`ama_ed25519_sign` 24,780 ns, `ama_ed25519_sign_expanded` 13,613 ns (0.55×),
`ama_ed25519_expand_secret_key` 12,632 ns once.

**Why.** `r = H(h[32..63] ‖ M)` depends only on the seed and the message, so two
signatures over one message under two different stored `A` halves share `R`
and give `s₁ − s₂ = (h₁ − h₂)·a (mod L)` — the private scalar — and ordinary
storage corruption produces that input with no fault injection.

---

## INVARIANT-52 — A Package Signature Covers the Whole Package

**Statement.** Every field a crypto package carries, and the *presence* of
every optional one, must be inside the signature the package presents as its
authenticity claim. The creator and the verifier derive the signed bytes from
the same function, and a field that cannot be encoded into those bytes fails
the signature rather than being silently omitted. Secrets are not in the
transcript; each is pinned through a signed public commitment (`hmac_tag`,
`derived_keys`, and `metadata["kem_shared_secret_commitment"]`, a
domain-separated SHA3-256 of the KEM secret). `derived_keys` itself is
included, because binding the salt, info and count alone lets a swapped
`hkdf_master_secret` with recomputed keys stay self-consistent.

**Enforcement.** `ama_cryptography/_package_transcript.py` is the type-tagged,
length-prefixed, domain-separated encoding; `crypto_api.package_transcript` is
the single extraction point (`create_crypto_package` assembles with a
placeholder signature, takes the transcript the verifier will compute, then
fills the real signature in). `legacy_compat.build_package_transcript` does the
same for `SIGNATURE_FORMAT_V3` under separate `"signature"` and `"hmac"`
purposes, and `legacy_compat.recompute_ethical_hash` derives the ethical digest
from the vector. `canonical()` raises `TypeError` for a type it cannot
represent.

**Verification.** `tests/test_crypto_package_transcript.py` runs the tamper
matrix on the modern and legacy packages against an untampered-clone control
(because `copy.deepcopy` strips secrets through `__getstate__`), plus the
substituted-KEM-key case; the encoder's injectivity is tested without a
backend.

**Why.** When only `content` was signed, *removing* an optional
post-quantum layer was undetectable: the 2026-09 audit found 7 of 17 tamper
cases on a fully layered package returning success, with no key material
needed.

---

## INVARIANT-53 — A Documented Claim Must Resolve Against the Implementation

**Statement.** Every claim the tracked documentation makes about this library
must be **derivable from the library**, and a gate must derive it:

1. **Examples.** Every fenced `python` or `c` block on a user-facing page
   runs, compiles and links, or carries an explicit `pseudocode: <reason>`
   marker.
2. **Constructions.** Every security-relevant description — a fallback, a
   weighting, a threshold, a zeroing strategy, a symbol's existence — matches
   what the source does, with the expected value **parsed out of the source**.
3. **Public API.** Every documented import, signature, return type, context
   manager and exported symbol matches what a user can reach.
4. **Measurements.** Every published performance figure is re-derivable from a
   record that states the command, host, units, sampling and aggregation behind
   it.

Do **not** weaken the implementation to make a document true: where claim and
code disagree, the code and the invariants are authoritative unless testing
shows the code defective.

**Exception.** A **correction note** may quote the wording it retires, but
only behind an explicit `<!-- claim-check: quoting-retired-wording -->` marker;
a waiver that can be inferred arrives by accident.

**Enforcement.** Five gates, run in `ci.yml`:

- `tools/check_doc_examples.py` — `security-checks` and `c-consumer` (C against
  an *installed* prefix under gcc and clang). Every covered block declares its
  mode; `c-run` blocks execute under `valgrind --track-origins=yes`.
- `tools/check_crypto_construction_docs.py` — `security-checks`. Derives its
  authority with `ast` from `hybrid_combiner.py`, `adaptive_posture.py`,
  `equations.py`, `legacy_compat.py`, `src/c/ama_consttime.c` and
  `src/c/ama_lms.c`, scans source comments and docstrings as well as prose,
  fails closed (exit 2) on a partial derivation, and checks its name-exempted
  gate files at startup.
- `tools/check_public_api_docs.py` — `security-checks`, `--require-library`:
  bare-import reachability in a fresh subprocess, signatures, return types,
  `__enter__` values, the version script against `nm --dynamic` in both
  directions, and the per-architecture SIMD inventory.
- `tools/check_benchmark_claims.py` — `security-checks`: re-derives every cell
  of the generated benchmark blocks, requires every floor cited in prose to
  exist in `baseline.json` or `arm-baseline.json` for that benchmark and
  architecture, requires reproduction provenance, and rejects a figure more
  than 8x its own floor as a units or identity error.
- `tools/check_published_benchmarks.py` — `security-checks`: every number
  between the `published-bench` markers in `README.md`, and every
  restatement on the pages the record lists under `documents`, is recorded in
  `benchmarks/published-benchmarks.json` and compared in both directions, keyed
  by page, row and position; every measurement source names its host, build
  flags, command, sampling, aggregation and CI runs.

`tests/test_documented_c_prototypes_match_headers.py` and
`tests/test_documented_source_paths_exist.py` hold C prototypes and cited
source paths to the tree, and `tools/check_hd_interop_honesty.py` keeps the
BIP32 correction (CHANGELOG KM-HD-001) from returning.

**Verification.** `tests/test_documentation_integrity_gates.py` pins all four
claim kinds in both directions; the negative controls are the literal text the
2026-09 documentation-integrity pass removed, and positive controls assert the
corrected wording passes.

**Why.** For an integrator the documentation *is* the specification: a wiki C
example once minted Ed25519 private keys from uninitialised stack memory,
compiled clean under `-Wall -Wextra -Werror` and printed `valid=1`. A claim
corrected once with no gate — the BIP32 case — came back in six places.

---

_Maintained by Steel Security Advisors LLC._
_Last updated: 2026-09-24_
