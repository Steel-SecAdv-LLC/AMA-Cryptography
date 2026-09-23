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

Python stdlib modules (`os`, `secrets`) are permitted for OS services —
entropy is the operating system's to provide, not a competing implementation.

**`hashlib` policy (tightened 2026-08):** CPython's `hashlib` is not a neutral
helper. In every build that links libcrypto its constructors resolve to
OpenSSL — `hashlib.sha3_256` *is* `_hashlib.openssl_sha3_256` — so a
production `hashlib` call inside the package is OpenSSL performing an AMA
cryptographic primitive in-process. An earlier revision of this invariant
permitted stdlib "hashing" as a non-primitive operation; that parenthetical
granted what the rule forbids, and roughly fifty call sites accumulated under
it. All production hashing and key derivation now runs on AMA's own kernels
(`native_sha256/384/512`, `native_sha3_256/384/512`,
`native_pbkdf2_hmac_sha256/512`). `hashlib` is confined to the pre-execution
**trust bootstrap** — the pre-load shared-object digest (which cannot be
computed by the library not yet loaded), the pre-import binding-extension
digest gate in `__init__.py` (which hashes each signed compiled extension
before its module-init code may execute), the signed-integrity source
digests, the build-time signer, the SHA3-256 KAT cross-check against fixed
FIPS 202 vectors, and the RuntimeError-guarded test-only HKDF reference —
pinned file-by-file with exact reference counts by
`tools/check_stdlib_hash_boundary.py`, so a new use anywhere fails CI.

They **must NOT** be used as a substitute for AMA's own implementations of
HMAC, memory zeroing, or core cipher operations.

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

**Enforcement.** `tools/check_algorithm_registry.py`, run in `ci.yml`, at two
levels.

1. **Families.** DISCOVERED from `include/ama_cryptography.h` — every `AMA_API`
   prototype contributes its `ama_<family>_` prefix. Each family must carry a
   mapping to one or more `CSRC_STANDARDS.md` tokens (a tuple where the family
   spans two publications, as `ama_nistp_*` does: FIPS 186-5 for ECDSA and
   SP 800-56A rev. 3 for ECDH), and each token must appear in that file's
   tables.
2. **Parameter sets.** Also discovered: the enumerators of the header's
   parameter-set enums (`AMA_ML_DSA_*`, `AMA_ML_KEM_*`, `AMA_SLHDSA_*`,
   `AMA_NIST_CURVE_*`) and the `ama_hmac_<hash>` prototypes. Each must map to a
   token that appears in the **Algorithm column** of a row — its own row, not a
   mention inside another algorithm's prose.

At both levels an identifier the mapping does not know fails, which is the
"before implementation is permitted" clause expressed as a check. The gate
fails closed on a collapsed header scan, a header with no parameter sets, or a
truncated registry, and every direction is pinned by
`tests/test_algorithm_registry_gate.py`.

The second level exists because the first is too coarse to see what the audit
found. `ama_hmac_*` maps to FIPS 198-1, which the HMAC-SHA-256 row satisfies,
so the family read as covered while three further HMAC constructions shipped
with no row at all; `ama_dilithium_*` maps to ML-DSA-65, which said nothing
about ML-DSA-44 or ML-DSA-87.

Until 5.0.0 nothing checked this, and the registry did not hold. Run against
`CSRC_STANDARDS.md` as it stood, the gate reports **18** violations by name:
FIPS 186-5 and SP 800-56A rev. 3 both uncited and P-256/P-384/P-521 each
without a row; SP 800-208 uncited for both LMS and HSS; ML-KEM-512, ML-KEM-768,
ML-DSA-44, ML-DSA-87 and SLH-DSA-SHAKE-128s each without a row; and
HMAC-SHA-384, HMAC-SHA-512 and HMAC-SHA3-256 the same — in a document whose
first paragraph says it maps *every* primitive implemented in the library and
lists no aspirational entries. The same pass that found this had itself added
five other rows, so the rule was known and still not met, which is what a rule
with no gate looks like.

### INVARIANT-1 Addendum — Vendoring Policy

No cryptographic source is vendored. Every primitive the library ships is
written in this repository, and `src/c/vendor/` **must not exist**:
`tools/check_vendor_isolation.py` fails the build if the directory reappears
or if any file under `src/c/` includes a forbidden vendor header, in a fallback
arm or anywhere else, and `tests/test_vendor_isolation_gate.py` pins both
directions.

This addendum used to permit vendoring public-domain source into
`src/c/vendor/`, compiled from source and never linked pre-built, and one
component lived under it: a public-domain x86-64 Ed25519 implementation
selected by a CMake option on x86-64 and MSVC builds. The twenty-first
maintenance pass replaced it with the in-house Ed25519 backend
(`src/c/ama_ed25519.c`, `src/c/internal/ama_ed25519_ge.h`), which is measured
faster than it was on every row, and removed the option, the shim, the
differential CI job and the tree itself. The only third-party code left in
the repository is the dudect timing harness under `tests/c/dudect/`, which is
test tooling, not a cryptographic primitive, and is outside `src/c/`. The
**Vendored Dependencies** appendix at the end of this document records the
history.

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
to a full commit SHA, not a mutable tag (`@main`, `@v1`, etc.). A tag is
mutable: whoever controls the upstream repository can move it, and the workflow
then runs different code with no diff in this repository.

**Enforcement:** `tools/check_action_pins.py`, run with `--strict` in
`ci.yml`. It performs two checks:

1. **`find_unpinned()`** — every `uses:` reference whose ref is not a
   40-character commit SHA is a violation. Local references (`./…`) and
   `docker://` images are out of scope; anything else needs an entry in
   `_PIN_EXEMPT` with a written reason.
2. **`find_pins()` + `list_remote_refs()`** — every SHA pin must still resolve
   upstream, and under `--strict` its trailing version comment must name a tag
   the SHA actually carries.

Check 1 did not exist until 5.0.0, and this invariant had **no enforcement
anywhere** until then. The pin checker matched `uses: <action>@[0-9a-f]{40}`
and nothing else, so a reference carrying no SHA was structurally invisible to
it — the rule's only checker could not see its violations, and
`tests/test_action_pin_checks.py` recorded that in a comment ("Non-detection:
`@v1` is a different violation") rather than closing it. The gate also exited
**0** when it found no pins at all; it now fails closed, like every other gate
in `tools/`.

**The one exemption**, named individually rather than by prefix:
`slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0`.
Upstream *refuses* a SHA reference — the generator verifies that its caller
referenced it by a semantic-version tag and fails the build otherwise, because
the tag is what its own provenance attests. Pinning it by SHA would not harden
the supply chain; it would break the attestation that workflow exists to
produce.

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

**Enforcement:** The primary gate is the POST stage
`_self_test._run_backend_stage()`, which fails the power-on self-tests when no
native library loaded, so `import ama_cryptography` raises
`CryptoModuleError` — see [INVARIANT-39](#invariant-39--a-failed-post-must-fail-the-import-and-the-error-state-must-inhibit-output).
That stage exists because the guards named below are **not** reached by a bare
`import ama_cryptography`: `crypto_api` is behind `__init__.__getattr__` and
`key_management` / `legacy_compat` are imported on demand, so for a long time a
checkout with no discoverable `libama_cryptography` imported cleanly, emitted a
`UserWarning`, skipped eight of its eleven self-tests and reached
`OPERATIONAL` — a warning without a hard stop, which is the substitute this
invariant explicitly rules out.  The claim in this section was true of the
modules it named and false of the package as a whole.  POST is the one thing
that always runs on import, so POST is where the invariant is now enforced.

The remaining layers are unchanged and still apply:

* Module-level guards in `crypto_api.py`, `key_management.py` and
  `legacy_compat.py` raise `RuntimeError` when those modules *are* imported
  without a native backend, except under the documented Sphinx/docs-build
  override above.
* `pqc_backends.py` enforces at **call time**: it records the backend as
  unavailable at import (`*_NATIVE_AVAILABLE = False`) and every wrapper
  raises before performing any operation without it.

Under the docs override the POST stage records a skip instead of a failure and
the import proceeds so autodoc can read signatures — call-time enforcement
(`_enforce_invariant7*`, and now `check_crypto_permitted()`) still refuses
every cryptographic operation, and `module_attestation()["fully_verified"]`
stays `False`.

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

### INVARIANT-10 Addendum — Release Tags Must Be Annotated and Signed

A release tag **must** be an annotated tag object carrying a signature. A
lightweight tag — a ref pointing straight at a commit — is prohibited for
`v*`, because it is a mutable pointer with no object to sign: anyone who can
push can move it, and there is no place a signature could later be added.

This addendum exists because the invariant above was, until 4.0.0, asserted
about commits and enforced about nothing else. Measured across the eleven tags
the repository carried when the gate was written, **six were lightweight and
the remaining five were annotated but unsigned — none was signed**, and every
one of those releases went out through a pipeline whose operator runbook said
`git tag -s`. A documented practice that nothing checks is a practice that has
not happened.

**Enforcement:** `tools/check_release_tag.py`, run from `release.yml`'s
preflight stage before any wheel is built. It checks *shape* — the ref
resolves, names a tag object rather than a commit, and the object contains an
OpenPGP, SSH, or X.509 signature block — and states in its own output that it
does **not** verify the signature. That is a division of labour rather than a
gap: preflight's job is the properties that were wrong on all eleven historical
tags, and it needs no key material, no `ssh-keygen` and no network to do it,
which is what lets it run first, before anything is built. Verification is a
separate check with a separate input, and it exists — see the addendum below.
GitHub's verified/unverified verdict is the third half; it is account-level
state, so preflight reports it rather than gating on it.
`tests/test_release_tag_gate.py` supplies the negative controls for each
rejected shape, including one asserting that a fabricated signature block
passes — so a future reader cannot mistake this gate's PASS for a
cryptographic result.

### INVARIANT-10 Addendum — The Trust Store, and a Correction

Until 5.0.0 the paragraph above ended differently. It said verification needs a
trust store "this repository deliberately does not ship", because "publishing an
`allowed_signers` file would assert a key binding only the account owner can
establish".

The reasoning was sound; the conclusion was false when it was written. The
account owner had already established the binding: the release signing key was
registered on the account the same day v4.0.0 was tagged, and v4.0.0 — tagged
twenty-eight minutes after that sentence was committed — is signed with it. What
got recorded as a property of the project was really the author's inability to
read account-level state. **An unverifiable claim and a claim that must not be
published are not the same thing**, and a repository that enforces INVARIANT-37
against its own APIs is the last place that confusion belongs. The sentence then
propagated into `tools/check_release_tag.py` and
`tests/test_release_tag_gate.py`, which is how a reasoned aside becomes a
project policy nobody re-examines.

**What ships instead.** `.github/allowed_signers` carries the binding, scoped
`namespaces="git"`. It is a mirror of an owner-established fact, not the
repository vouching for itself — and on its own it would still be worth exactly
as much as the repository carrying it, which is why it does not stand on its
own:

**Enforcement:** `tests/test_release_tag_trust_store.py` verifies the v4.0.0 tag
object against the published key on every run, with negative controls for a
substituted key, a substituted principal, a tampered payload and a wrong
signature namespace. The tag object is embedded in the test rather than read
through `git`, because `actions/checkout` does not fetch tags at its default
depth and a check that silently skips on the runners that matter is not a check.
Ed25519 verification is implemented there in the standard library alone, pinned
by the RFC 8032 §7.1 known-answer vector; INVARIANT-1's refusal of external
cryptographic dependencies is a poor thing to honour everywhere except in the
test that checks the release key. A fingerprint copied from a settings page
proves nothing. A signature checked against the bytes it covers does.

Consumers verify a release tag with

```bash
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag v5.0.0
```

documented in `README.md` beside the Sigstore and SLSA commands. That check is
offline: no GitHub account, no network, no trust in this repository's hosting.

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
   both C and Python cryptographic paths, with one carve-out mandated by the
   standards themselves: **the FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA)
   signing loops reject and resample by construction, so their iteration count
   is secret-dependent.** This is not a defect and not fixable without
   diverging from the standard; `CONSTANT_TIME_VERIFICATION.md` §"ML-DSA /
   SLH-DSA signing" documents it, the dudect lane measures it (info-only, with
   its deterministic counterpart gate), and it leaks no private-key material —
   only a timing signal on the number of rejections for a given message. Every
   *other* secret-dependent construct remains prohibited.

**Enforcement:** CI runs constant-time verification checks (dudect, ctgrind,
custom timing harnesses, static structural scans) and **must** fail on
detection of secret-dependent variable-time constructs.  The project's
`CONSTANT_TIME_VERIFICATION.md` is the authoritative artifact for
verification methodology.

### INVARIANT-12 Addendum — Per-Slot SIMD Constant-Time Verification

The nightly SIMD dudect sweep in `.github/workflows/dudect.yml`
(`dudect-simd-sweep`) **must** measure each dispatch-table-routable
SIMD slot in isolation via `AMA_DISPATCH_ONLY=<slot>`.  A t-value
excursion on any slot is a hard fail — never excused as noise — when it
meets the adjudication rule in `tests/c/dudect/dudect_rounds.h`: |t| at
or above `DUDECT_T_THRESHOLD` (5.0) in a strict majority of rounds, with
a consistently signed per-class difference of at least
`DUDECT_MIN_EFFECT_NS` (2 ns).  Below that measured floor the lane
reports `SUB-FLOOR` without failing, because on shared hardware the
apparatus cannot attribute a sub-2 ns difference to the code (the floor's
derivation and its limits are documented at the definition).  The
per-slot isolation is exactly what makes an adjudicable t-value
attributable to a single SIMD kernel rather than to the union of every
SIMD path that happens to be on the host.

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
equivalent suppression marker is **prohibited** unless **all four** of the
following conditions are met:

1. The suppression is **line-scoped**, not file-scoped.
2. It **names the rule it silences** — `# nosec B110`, `# noqa: S310`,
   `# nosemgrep: <rule_id>` — never the bare marker.
3. It includes a **human-readable justification** and a **tracking reference**,
   for example: `# nosec B110: __del__ must not raise (FIN-001)`.
4. The suppressed line is **covered by tests** or a deterministic runtime check.

The **only** permitted exception is finalizers and destructors that must not
raise, provided the reason is explicitly documented inline.

Suppressions are **absolutely forbidden** in the following locations regardless
of justification:

- `src/c/` (core cryptographic C primitives)
- `include/ama_*.h` (C header files)

**Enforcement:** CI scans the repository for suppression tokens and **must**
fail if a suppression is missing a justification, missing a tracking ID, or
appears in a forbidden directory.

**Scope.** `tools/check_suppression_hygiene.py` runs three passes, because this
invariant states more than one rule.

*The justified-and-tracked pass* covers `ama_cryptography/`, `tests/` **and
`tools/`**. `tools/` was outside it until someone noticed what lives there: the
gate scripts themselves. A suppression in that tree silences a static analyser
*inside the layer that enforces this invariant*, which is the last place an
unexplained one belongs. Widening the scan found two bare `# noqa: S310`
markers — no reason, no tracking ID — over `urllib` calls in the corpus fetchers
that accepted `file:` and `ftp:` URLs; both now check the scheme, so the
suppression states a fact rather than a hope.

*The absolutely-forbidden pass* covers every non-vendored `.c` and `.h` under
`src/c/` and `include/` — the same enumeration the fail-closed clang-tidy job
performs — and fails on the presence of `NOLINT*`, `cppcheck-suppress`,
`nosemgrep`, `coverity[` or `LINTED`, and, since the twenty-seventh pass, of
the compiler- and sanitizer-level forms too: `#pragma GCC/clang diagnostic
ignored` and its `_Pragma(...)` operator form, MSVC
`#pragma warning(disable|suppress)`, `#pragma GCC optimize`/`clang optimize
off`, `no_sanitize*` and `disable_sanitizer_instrumentation` attributes, and
`optnone` in any attribute position or as `[[clang::optnone]]`. It used to
recognise the analyser comment markers only, so the tree carried two `-Wpedantic` pragmas and a `no_sanitize_address` while the
gate reported that it carried none. The pragmas are gone, and so is the
warning they hid: every `__int128` declaration carries `__extension__`, and the
compiler-warning gate's `int128-extension` allowlist entry was deleted with
it. There is no justification escape
hatch, because that is what "regardless of justification" means. It fails
closed on an empty scope: a glob that matches nothing is a checker fault, not
a clean tree.

**No exception is recorded.** The twenty-seventh pass kept one —
`no_sanitize_address` on `ama_secure_stack_wipe` — on the stated ground that
AddressSanitizer would report the scrub as the fault it resembles. That
ground was never measured, and it is false: the function writes only its own
local array, which is always a valid access. With the attribute removed the
clang ASan+UBSan build passes all of `ctest` (140/140, including
`detect_stack_use_after_return=1`), so the attribute and the gate's exemption
register were both deleted.

*The portability pass* covers every tracked Python file and fails on a
`# type: ignore` sitting inside an `except ImportError` whose `try` imports a
THIRD-PARTY module. Such a marker cannot be correct in both environments this
project type-checks in: where the optional package is installed, the name bound
by the `try` carries the module's type and `name = None` in the fallback needs
the ignore; where it is not — the CI type-check image carries the pinned tools
and nothing else — the import resolves to `Any` through
`ignore_missing_imports`, the assignment is fine, and the same marker is an
error under `warn_unused_ignores`. One file, two verdicts, and the one CI sees
is the red one. The remedy is never another suppression: declare the name
before the `try` (`np: Any`) and import under an alias.

The third-party restriction is what makes the pass precise rather than noisy.
`crypto_api.py` guards `from ama_cryptography.rfc3161_timestamp import …` — an
in-tree module mypy resolves in every environment — so the three ignores in
that handler are needed unconditionally and are correctly left alone. Both
directions are pinned by `tests/test_invariant_upgrades.py`
::`TestOptionalImportSuppressions`.

Neither the C-tree pass nor the portability pass existed until 5.0.0, and the
enforcement sentence above was false without the first of them. The checker listed the forbidden directories and had a branch
that reported on them, but it only ever collected
`ama_cryptography/**/*.py`, `tests/**/*.py` and `tools/**/*.py`, so no path
under `src/c/` or `include/` could reach that branch — dead code for all four
entries, two of which (`ama_cryptography/_primitive`, `ama_cryptography/backend`)
name directories that do not exist. Meanwhile a live suppression sat in the
shim of the since-removed vendored Ed25519 backend: a next-line marker
silencing three clang-analyzer uninitialised-read checks on that backend's
macro-driven initialisation, while the gate printed "all suppressions are
properly justified" and exited 0. It went — not moved or re-justified, but
removed by making the analyzer's premise false, zero-initialising the two
locals at declaration, after which clang-tidy 18 reported the file clean (and
the file itself has since left the tree with the backend). The tree now
carries **zero** suppressions under either root, and the gate is the thing
that keeps it that way.

Widening it also required the scanner to become precise about what a
suppression *is*. It had been collecting the line numbers carrying a comment
and then matching over the whole raw line, which put string literals back in
scope, and it made no distinction between a marker and prose describing one —
so the checkers' own documentation of their subject matter was reported as
eight unjustified suppressions. It now reads the comment token's text, and only
where the comment is *trailing*: `bandit`, `ruff` and `mypy` all anchor a
suppression to the line of the finding, so a full-line comment suppresses
nothing. mypy's file-level `# type: ignore` is the one standalone form that is
real, and it is kept in scope explicitly. The set of suppressions policed in
`ama_cryptography/` and `tests/` is unchanged by this — 96 before and after —
so the precision gain removed false positives only. Both directions are pinned
by `tests/test_invariant_upgrades.py::TestSuppressionScanPrecision`.

**Naming the rule (condition 2) is not style.** A bare marker blanket-suppresses
its whole scanner on that line, and for `# nosec` the failure is worse than
that: bandit parses everything after the marker as test ids, warns for each word
it cannot resolve, and treats the resulting *empty* set as "no specific tests" —
i.e. blanket. So this repository's own justification style, `# nosec -- reason
(TAG-NNN)`, reads to a reviewer as targeted while silencing every bandit test on
the line. Measured against bandit 1.9.4 on two files differing only in the
marker: a `subprocess.call(..., shell=True)` line carrying `# nosec -- prose
(DEMO-002)` produces no finding, while the same line carrying `# nosec B105` — a
code that matches nothing there — still reports `B607`. `ruff` treats a bare
`# noqa` the same way. Both are now required to name a rule, alongside the
`nosemgrep` rule that already was; `# type: ignore` is deliberately exempt,
because mypy's file-level form on line 1 is a legitimate bare spelling and
`--strict`'s `warn_unused_ignores` already reports an ignore that suppresses
nothing. The tree satisfied the rule before it existed — zero bare markers in
`ama_cryptography/`, `tests/` and `tools/` — so this keeps the property rather
than repairing a violation, and
`TestSuppressionScanPrecision::test_no_marker_in_the_tree_is_written_bare`
asserts it directly against the tree as well as through the checker.

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
- **Windows** (MSVC and MinGW-w64): `InitOnceExecuteOnce` (`synchapi.h`, Vista+)

The selection is made on `_WIN32`, not on `_MSC_VER`: which primitive is
available is a property of the operating system, not of the compiler.
`src/c/internal/ama_once.h` and `src/c/dispatch/ama_dispatch.c` both asked
the compiler until this was corrected, which sent MinGW-w64 — Windows, but
not MSVC — down the POSIX branch to link `winpthreads` for a facility
Windows itself supplies.

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
- The persistence file must be writable only by the encrypting principal. The
  read-modify-write is atomic across concurrent processes, but a file-based
  counter cannot detect an offline rollback or deletion of its own state; that
  protection is a deployment responsibility, not something the mechanism
  self-enforces.

This invariant treats forgotten nonce history as a cryptographic safety failure,
not as recoverable telemetry loss.

---

## Vendored Dependencies

**None.** `src/c/vendor/` does not exist and the vendor-isolation gate fails
the build if it reappears (INVARIANT-1 Addendum — Vendoring Policy).

### History: the removed x86-64 Ed25519 backend

Until the twenty-first maintenance pass the tree vendored a public-domain
x86-64 Ed25519 implementation (Andrew Moon's), compiled from source through a
project shim and selected by a CMake option that defaulted on for x86-64 and
was auto-enabled on MSVC x64, because the in-tree radix-2^51 arithmetic
needed a 128-bit integer type MSVC does not have. It was the faster path on
x86-64 at the time.

It is gone. The in-house backend now carries static precomputed base-point
tables (`tools/gen_ed25519_tables.py`), a signed 5-bit comb with constant-time
masked selection, Bernstein–Yang constant-time inversion, and half-size-scalar
verification, and measures faster than the removed backend on every Ed25519
row of the benchmark on the reference x86-64 host (keygen 0.85x, sign 0.87x,
verify 0.74x, double-scalar-mult 0.67x of its time). MSVC builds the same
arithmetic through `_umul128` / `__shiftright128` (x64) and `__umulh` (ARM64),
so Windows on ARM, which had no Ed25519 path at all, now has the same one as
every other platform. The removed backend's answers over a 2,022-record corpus
are frozen in `tests/oracle/ed25519_frozen_oracle.txt` and replayed on every
build, so the code that replaced it is still held to the answers it gave.

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

* The vendored x86-64 path the tree then carried (since removed) tested only
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
check as a `static inline`. It was made header-only when CMakeLists.txt still
swapped one backend source for the other, so that a shared `.c` could not
compile into only one configuration; with one backend left it is applied at
`ama_ed25519_verify`, which batch verification calls per entry, so the two
cannot disagree. (The removed vendored backend's batch routine called its own
verifier, which is why a third site once existed.)

**Not claimed as constant time.** `S` arrives in the signature and is public, so
a data-dependent branch here leaks nothing secret. The check is written
branch-free because it costs nothing at this size, not because INVARIANT-12
requires it here.

**Family.** This is the first of three input rules applied at
`ama_ed25519_verify` and kept together in one header: `0 <= S < L` here,
canonical point encodings in INVARIANT-38, and small-order rejection in
INVARIANT-48.

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
(ref10, Andrew Moon's curve25519, libsodium) normalizes and therefore agrees
with the reduced interpretation.

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

**Statement.** `ama_secp256k1_ecdsa_sign` **and
`ama_secp256k1_ecdsa_sign_raw`** must emit only the canonical low
representative (`s <= (n-1)/2`), and `ama_secp256k1_ecdsa_verify` must reject
a high `s`, an `r` or `s` outside `[1, n-1]`, and any signature that is not
minimal DER.

Both signing entry points are named because they are one implementation:
`secp256k1_ecdsa_sign_scalars()` performs the arithmetic, including the
`sc_cond_negate` low-`s` selection, and the two public functions differ only
in whether they DER-encode the result or return it as fixed-width `r || s`.
`tests/c/test_secp256k1.c` decodes the DER form back to (r, s) and compares
it against `r || s` over 512 keys, so a divergence between them — which is
the only way one could satisfy this invariant while the other did not —
fails there.

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

That sentence was in this document before it was true of the code, and it is
worth recording how, because the shape recurs. Three sites in
`src/c/ama_secp256k1.c` branched on a secret and each was individually
plausible: `sc_mont_mul`'s Montgomery extra reduction (`if (t[SC_LIMBS])`),
`sc_add`'s carry fold (`if (carry)`, reached on the signing path as
`r*d mod n + z`), and `sc_is_high`'s short-circuited `memcmp`. The first was
found and fixed with a comment asserting it was the only one; the other two
were found by sweeping for the pattern rather than trusting that assertion.
All three are masked now — `sc_add` folds under an arithmetic mask,
`sc_is_high` is a single `sc_lt(SC_HALF_N, a->v)`, and the low-`s`
normalisation goes through `sc_cond_negate` — and
`tools/check_ghash_constant_time.py --target ecdsa` measures the property
rather than asserting it. On the AMA_TESTING_MODE static archive the workflow
actually builds, the pre-fix tree spreads **2,952** instructions across key
classes and the fixed tree spreads **80**. The gate's threshold was **3,000** —
forty-eight instructions above the defect it was measuring. It is now 200.

The general rule this yields: **finding one instance of a defect pattern is a
reason to sweep for the rest, and a gate calibrated between one known defect
and one assumed-clean baseline is only as good as the assumption.** Both
halves failed here at once — the "benign" 728-instruction spread the ECDSA
threshold was calibrated against was mostly two live leaks, and the threshold
derived from it landed just above the number it needed to be below.

**Verification.** `tests/test_secp256k1_ecdsa.py` (31 tests) covers RFC 6979
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

The authority key is an **input to those derivations**, not only to the gate
beside them. Until the 2026-09 audit it was not: `K_auth` authenticated the
binding record and the policy gate checked that tag, but the HKDF `info` was
`enc(b) || u32be(info_len) || info` and the signature context was
`SHA3-256(0x02 || enc(b))` — both computable from `enc(b)`, which is public
and which `ama_agent_binding_encode()` will produce for an *unauthorized*
binding. The adversary this invariant names is an agent with in-process
access (`THREAT_MODEL.md` T3.6), and that adversary can call `ama_hkdf`
itself, so the control was a gate to step around rather than a secret to be
without; the audit reproduced both outputs byte-for-byte holding no authority
key. A restricted binding's derivations now take a 32-byte binder
`HMAC-SHA3-256(K_auth, 0x03 || enc(b))` (HKDF) or `0x04 || enc(b)` (signature
context) as an input, so the *output* is unobtainable without `K_auth`, not
merely unreachable through the guarded entry point. Unrestricted bindings
have no operator secret and take a fixed zero binder: the scope of the
guarantee is exactly the population the statement above names.

**Enforcement.** `src/c/ama_agent_binding.c`. `ama_agent_binding_check()` is
the single policy point; `ama_hkdf_agent_bound()` and
`ama_agent_binding_context()` both call it before producing anything and write
no output on refusal. `authority_binder()` is the second point: it mixes
`K_auth` into each of those two derivations under its own sub-domain, which is
what makes the refusal above the *only* way to those bytes rather than the
only guarded way. The authorization tag is
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
claim is measured by two instruments. The `Agent binding check` lane in
`tests/c/test_dudect.c` is registered strict (`is_info_only = 0`), and a
strict lane fails CI only when |t| >= 5.0 (`DUDECT_T_THRESHOLD`) in a strict
majority of rounds with a consistently signed per-class difference of at
least `DUDECT_MIN_EFFECT_NS` (2 ns); below that floor the lane reports
`SUB-FLOOR` and exits 0 — as this lane did on a shared runner at
|t| = 41.72 in 3 of 3 rounds with a −1.141 ns difference
(`tests/c/dudect/dudect_rounds.h`). The blocking instrument for the
sub-floor range is therefore the deterministic `--target agent-binding`
gate in `.github/workflows/dudect.yml`, which measures 612,810,230 retired
instructions byte-identical whether the check accepts or rejects.

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

- **secp256k1** sets both by default: `ama_secp256k1_ecdsa_sign` and
  `ama_secp256k1_ecdsa_sign_raw` emit only the low representative and
  `ama_secp256k1_ecdsa_verify` rejects the high twin (INVARIANT-28). `AMA_SECP256K1_ECDSA_ALLOW_HIGH_S` relaxes the verifier for
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
and the RFC 6979 nonce on both curves, *including* the normalisation.
Verification is variable time by design on both — every input is public.

An earlier revision of this paragraph excused the normalisation as "a
conditional negation of a value that is about to be published", and that
reasoning is wrong in a way worth keeping on the record, because it is what
left a real leak in place on both curves. What gets published is the
*normalised* `s`. Whether the negation happened is precisely what the
published value does not reveal: given the low representative, an observer
cannot tell whether the signer computed it directly or by negating the high
twin. So `s_raw > (n-1)/2` is one bit per signature about `k` and `d`, and a
branch on it leaks that bit. Measured in isolation under callgrind, the
branched form cost 105 more instructions for a high `s` than a low one.

Both curves now select rather than branch: `sc_cond_negate` in
`ama_secp256k1.c`, and `nistp_select` under a mask in `ama_nistp.c`. The
`low_s` *flag* is still branched on — it is the caller's argument, it is
public, and branching on it keeps the default RFC-6979-verbatim path free.
"About to be published" is a sound argument for the flag and an unsound one
for the predicate; the distinction is which of the two the observer can
recover from the output.

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
`dil_params_for()` and `slh_lookup()` each end in `default: return NULL`
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
answer key for AMA's correctness, and no code under `ama_cryptography/`,
`tests/` or `tools/` — the runtime, correctness and gate surfaces the gate below
scans — may invoke another cryptographic binary. Where a specification publishes
no worked example, the substitute is a reference derived **from the specification
text**, written in this repository. The one recorded exception is `benchmarks/`,
which deliberately links and drives reference implementations (OpenSSL,
libsodium, wolfSSL, Botan, Nettle, libgcrypt, mbedTLS) **solely to measure AMA
against them**; it is on no correctness, runtime or release path, feeds no answer
key, and is outside the gate's scope by design (see the exception note below).

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

**Two exceptions are recorded.** The first is `benchmarks/` (audit M22): the
benchmark harness links and drives the reference implementations named in the
Statement to measure AMA's throughput against them. It is intentional — the
project benchmarks *against* these vendors, it does not use them in any
operation — it feeds no answer key, and it is deliberately outside the gate's
scope (the gate scans `ama_cryptography/`, `tests/` and `tools/`, not
`benchmarks/`).

The second is the interoperability oracles: the tests carrying
`@pytest.mark.requires_interop_oracle` in `tests/test_aes_gcm_native.py`,
`tests/test_hkdf_sha3_256.py`, `tests/test_ed25519_native.py`,
`tests/test_ed25519_expanded_key.py` and `tests/test_differential.py` import
PyCA cryptography, PyNaCl or pycryptodome
and check that AMA and a second implementation agree — PyCA encrypts and AMA
decrypts, libsodium signs and AMA verifies, and the reverse. That is
interoperability evidence, and it is what the require-backends lane installs
those packages for (audit M18); it is not the answer key. AMA's correctness is
established by the published vectors under `nist_vectors/` and `tests/kat/`
and by the specification-derived references in this repository, and a
disagreement with an oracle is investigated against the specification, never
resolved in the other implementation's favour. Until the twenty-seventh pass
this register said `benchmarks/` was the sole place external cryptographic
code is invoked anywhere in the tree, while a CI lane existed to require these
four modules to run; the gate (`tools/check_corpus_originality.py`) looks for
spawned binaries and vendored corpora and structurally cannot see a Python
import, and its verdict now says what it checked. Recording both is the
point: an absolute "no exceptions" that omits a live one is the converse of
the failure this register warns against below — as misleading as a named-but-
removed exception, because a reader takes the register as complete.

A former exception is gone: `ama_cryptography/legacy_compat.py` shelled out to
`openssl ts` for RFC 3161 timestamping, described here as "a shipped interop
feature, not a validation path". It is gone: AMA encodes and decodes RFC 3161 on
its own DER codec, `rfc3161_timestamp.py` no longer imports `rfc3161ng` either,
and the gate below scans `ama_cryptography/` precisely so neither can return. An
invariant register that still names a removed exception is worse than one that
names none, because a reader takes it as current.

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

**Verification.** `tests/test_verification_claim_honesty_gate.py` — 71 tests —
pins both directions: the repository as it stands, plus a reproduction of every
violation class and, equally, the near-misses that must **not** fire. It also
pins `test_flipping_a_capability_to_true_permits_its_claims`, which is the
property the design rests on, and `test_ast_parsed_table_equals_the_imported_one`,
so the gate's reading of the table and everyone else's cannot drift.  The ten
added last pin the two scoping defects found in the gate itself: the
formal-verification exemption was tested against the whole SENTENCE, so a
denial in one clause exempted a live claim in another, and a past-tense
attribution cue matched any of eight ordinary reporting verbs within eighty
characters of a `was`.

That suite has already earned its place. An early version of the pattern for
the phrase this section will not repeat ended `(?:stamp|-stamp|stamping)?\b`,
which cannot match its own plural: the group takes `stamp`, the `\b` demands a
boundary before the `s`, and every backtrack fails identically. The gate missed
the most common phrasing of the most common false claim in the tree and
reported success. Its own negative controls found that, and fixing the pattern
immediately surfaced two further live instances.

`tests/test_rfc3161_api_honesty.py` — 20 tests — drives the behaviour the table
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

## INVARIANT-38 — Ed25519 Compressed Points Must Have a Canonical `y`

**Statement.** Every Ed25519 point decode must reject a compressed encoding
whose `y` coordinate, after masking bit 255, is not in `[0, p)` with
`p = 2^255 - 19`. A `y >= p` is rejected, never reduced modulo `p` before the
curve equation is solved.

**Why.** RFC 8032 §5.1.3 requires exactly this: a non-canonical `y` is
rejected, not reduced. INVARIANT-27 already stated the rule as the reason
X25519's canonicalisation lives on the 32-byte encoding rather than inside the
shared `fe51_frombytes` / `fe64_frombytes` helpers — "those helpers are shared
with Ed25519, whose point decoding has the opposite rule". The statement was
true of the specification and of the document; it was not true of the code.
Both backends reduced. Nineteen values, `[p, 2^255)`, therefore decoded to the
same curve point as their reduced counterpart, and a public key had two
accepted byte encodings.

This is the same input-canonicalization class as INVARIANT-26 (`0 <= S < L`),
INVARIANT-28 (`r, s ∈ [1, n-1]`) and INVARIANT-29 (ECDSA `Qx`/`Qy` in
`[0, p)`), and it is resolved the same way and for the same reason: a
*verification key* must not admit a second encoding, because everything that
treats the key as an identity — a fingerprint, a map key, a bytewise
authorisation compare — is otherwise looking at two names for one key.

It is the deliberate policy counterpart of INVARIANT-27, resolved the other
way, and the split is the one the two RFCs draw. X25519 *reduces*, because two
peers must agree on one shared secret and the failure mode of disagreeing is
silent. Ed25519 *rejects*, because a signature must not verify under a second
encoding of its key.

**Not a forgery route on its own.** `S < L` (INVARIANT-26) is enforced and a
malleated `R` fails the re-encode comparison in verify, so both
signature-malleability paths were already closed. This closes the remaining
public-key encoding malleability.

A forgery route did exist alongside it, and this rule was not it:
INVARIANT-48 records that a small-order public key — the identity above all —
yields a universal forgery under AMA's cofactorless verifier, and that six of
the fourteen encodings it blocks are ones this rule already refused. The two
overlap without either being redundant; INVARIANT-48 states how they differ
in kind.

**Enforcement.** `ama_ed25519_point_y_is_canonical()` in
`src/c/internal/ama_ed25519_canonical.h` masks bit 255 and compares the 32-byte
little-endian value against `p` using the same branch-free comparator as the
`S < L` check (`ama_ed25519_lt_32`, factored out so the scalar and
field-element predicates cannot drift apart). It is enforced inside the
decoder every point in the in-house backend funnels through
(`ge_decode_prepare` in `src/c/internal/ama_ed25519_ge.h`), so both field
instantiations accept exactly the same set of encodings — which the fe51/MULX
differential and the frozen oracle both depend on. (The removed vendored
backend applied the same predicate at each of its call sites, because its
decoder stayed byte-for-byte unmodified.)

**Not a constant-time requirement.** The `y` coordinate arrives in a public
key and is public. The comparison is branch-free regardless.

**Verification.** The canonical-`y` coverage lives in
`tests/c/test_ed25519_canonical_s.c`, alongside the `S < L` cases: the full
19-value band, the `p-1` / `p` boundary, sign-bit independence in both
directions, and integration assertions through single and batch verify.
`tests/test_ed25519_canonical_y.py` drives the policy through the Python
binding — the whole `[p, p+18]` band rejected, canonical keys accepted, and the
sign bit shown not to affect the verdict — mirroring
`tests/test_secp256k1_ecdsa_noncanonical_pubkey.py` for INVARIANT-29. The
frozen oracle (`tests/oracle/ed25519_frozen_oracle.txt`) replays the removed
backend's verdicts on every case, and the fe51/MULX differential pins the two
field instantiations against each other.

---

## INVARIANT-39 — A Failed POST Must Fail the Import, and the Error State Must Inhibit Output

FIPS 140-3 §4.9.2 requires a module whose power-on self-tests have failed to
enter an error state in which **all** cryptographic output is inhibited.  This
invariant states the two halves that requirement decomposes into for a Python
package, because for a long time this repository satisfied neither.

**A failed POST must fail the import.** `ama_cryptography/__init__.py` discarded
the return value of `_run_self_tests()`.  POST would log
`CRITICAL: FIPS 140-3 POST FAILURE: <cause>`, set the module state to `ERROR` —
and then `import ama_cryptography` succeeded, with exit status 0.  Every build
script, CI smoke test and deployment health check that treats a clean import as
evidence of a working module therefore reported success over a module that had
just announced its own failure in the line above.  The failure went to the log
and the success went to the exit code, and the exit code is what tooling reads.
A self-test whose failure cannot fail anything is not a self-test.

Import now raises `CryptoModuleError` carrying the root cause and the full POST
result table, because a raising import leaves nothing behind to introspect: the
partially-initialised module is dropped from `sys.modules`, so the message is
the only artefact the operator gets.

Two narrow, documented completions of the import remain, and neither permits
cryptography:

* `AMA_POST_DIAGNOSTIC_IMPORT=1` — triage.  The module stays in `ERROR` and
  `check_crypto_permitted()` refuses every operation; the operator gains
  `module_attestation()`, nothing else.
* `AMA_BUILD_PIPELINE=1`, **and only for an integrity-stage failure** — the
  tools that repair a stale integrity artefact (`_build_sign`,
  `integrity --update`) live inside this package, so a hard raise would wall
  them off behind the fault they exist to clear.  That flag already confers the
  power to rewrite the artefacts outright, so honouring it grants no new
  capability.  A failed KAT, a timing leak or an RNG fault still hard-fails
  under it, so a release container — which carries the flag for its whole
  lifetime — cannot smoke-test a genuinely broken wheel and call it built.

**The error state must inhibit output.** The requirement was met only by
`crypto_api`, which calls `check_operational()` on its public methods.  Every
public entry point in `pqc_backends` — key generation, signing, KEM
encapsulation, AEAD, HMAC, KDF — called straight through to the C library with
no state check, so a module in `ERROR` kept producing keys and signatures for
any caller that reached past `crypto_api`, which is what this package's own
internal modules do.  Each now calls `check_crypto_permitted()` first.

The count is not written down here, because a number in prose is a number that
goes stale: `tools/check_error_state_gating.py` enumerates the surface from the
modules' own ASTs and fails when any entry point is ungated, and its output is
the authoritative figure (107 native entry points across `pqc_backends`, `ascon`,
`agent_binding` and `secure_memory`, plus 10 Cython binding entry points at the
time of writing, with 4 documented exemptions, and a discovery step that fails
if any other module reaches the native library while listed in neither the
audited nor the exempted set).

The parenthesis above is now checked rather than trusted: it said 85 while the
tool reported 86, having missed a commit that started tracking a native symbol
selected by a conditional expression.  `tools/check_documented_counts.py` reads
the figure from the tool and compares every published occurrence against it, so
the sentence that calls the tool authoritative is now enforced by the tool.

`ascon` joined the scanned modules once the gate learned to follow one level of
guard delegation.  Its public entry points call `lib.ama_ascon_*(...)` in their
own bodies, so the native reach was always visible; the guard was not, because
it lives in the private `_require_native()` choke point every one of them
passes through.  The module had been excluded on the stated grounds that "a
body-level scan cannot see the reach", which was true of `hybrid_combiner` and
not of this one.

`check_crypto_permitted()` is deliberately weaker than `check_operational()`:
it permits `SELF_TEST` **on the POST thread only**, because POST's Known Answer
Tests must be able to call the primitives under test, and widening that to any
thread would open the whole native surface for the duration of every
`reset_module()` — precisely the window an operator opens after a failure.

**A skip is not a pass.** In non-strict mode a KAT whose backend is absent is
recorded as a skip and POST still reaches `OPERATIONAL`.  That is a legitimate
source-checkout mode, but `module_status() == "OPERATIONAL"` answers "did
anything fail?", not "was everything tested?".  `module_attestation()` answers
the second question directly: `fully_verified` is true only when no self-test
was skipped, and release gates assert it rather than re-deriving it from the
tri-state result tuples.

**Diagnostics must describe what happened.** A native library that could not be
found was reported as `native Ed25519 not built — cannot verify signature`: a
claim about the C build, usually false, that sent operators to fix a build that
was fine.  `_verify_signed_integrity` now returns a tri-state —
verified / tampered / **could not be verified** — and the "could not" case
carries `native_backend_load_summary()`, which distinguishes a library that is
absent from one that is present and unloadable, and quotes the loader's own
error for the latter.  The dispatch is on the return value; it used to be a
substring test against the message, which made a security-critical branch a
function of prose.

**The integrity check must cover the code that does the cryptography.** The
signed artefact covered the package's `.py` files and nothing else. The shared
object that performs every cryptographic operation was signed by nothing and
verified at load by nothing, so a back-doored `libama_cryptography` left the
`.py` digest, the signature and the trust anchor all verifying while the actual
cryptography ran from unexamined bytes. The signature now covers the composite
`SHA3-256(domain ‖ py_digest ‖ native_digest)`, and the verifier re-hashes the
shared object it actually loaded and requires it to match. A one-byte change to
the `.so` fails POST and therefore the import; rewriting the embedded native
digest to match a tampered `.so` breaks the signature, which cannot be forged.
Because `_build_sign` can only sign by calling the native `ama_ed25519_sign`, a
working library is present at signing time by construction, so every signed
artefact binds it — there is no unsigned-native downgrade path. The one
non-full-strength outcome is an explicit `AMA_CRYPTO_LIB_PATH` override whose
bytes differ from the signed library's, which is recorded as *unverified* (a
skip, `fully_verified` `False`) rather than tampering; a byte-identical
override verifies in full, because verification binds the bytes, not the path.
Pinned by `tests/test_native_integrity.py`, including the tamper and
forge-attempt cases and the signer/verifier domain-constant agreement.

**The check runs before the object is mapped, not only after.** A shared
object executes its constructors at `dlopen` time, so a digest comparison
performed after load detects tampering the tampered code has already had a
chance to act on — the "raw discovery" boundary the 2026-08 audit recorded.
Discovery now hashes every candidate first and refuses to map an object whose
SHA3-256 does not match the artefact's signed native digest; on Linux the
mapping goes through `/proc/self/fd` on the descriptor that was hashed, so
the verified and mapped bytes cannot be split by a path swap, and the POST
stage compares the recorded digest of those mapped bytes rather than
re-reading the file. The pre-load comparison uses the artefact before its
signature can be verified (the verifier is inside the library being loaded),
so it defeats the `.so`-only attacker outright; the rewrites-both attacker is
caught post-load by the unforgeable signature or the trust anchor, with the
constructor residue that entails — that attacker remains the OS-code-signing
boundary `SECURITY.md` documents. The refusal is demoted to a
warning only for a process that IS the signer: `_SIGNING_LOAD_OVERRIDE`, a
module attribute `ama_cryptography._build_sign` sets around its own discovery
call, or `_process_is_the_integrity_signer()`, which keys on `__main__`'s
module name and `sys.orig_argv` — `ama_cryptography._build_sign`, or
`ama_cryptography.integrity` running a WRITING subcommand — and in both cases
only outside secure-execution mode.

`AMA_BUILD_PIPELINE=1` does NOT demote it, which this paragraph used to say it
did. The variable is read on every import, so any attacker who could set one
environment variable in the victim's process would have turned a pre-execution
refusal into a post-hoc report, with no code execution required. Setting a
module attribute inside the victim's interpreter is not a capability an
environment variable confers. Pinned by
`tests/test_preload_native_digest.py` (including
`TestSigningScopeRequiresIntentNotJustIdentity`, which drives the flag and a
signer-module argv together) and the refused-before-mapping tamper case in
`tests/test_native_integrity.py`.

**CASTs precede the integrity test that relies on them.** FIPS 140-3
(NIST IG 10.3.A) requires the algorithm self-test for any approved algorithm the
integrity test uses to run first. The signed-integrity check verifies an Ed25519
signature and computes SHA3-256 digests, so the SHA3-256 and Ed25519 KATs now
run before the integrity stage; the original single KAT stage ran them after,
so the module authenticated itself with an Ed25519 verifier it had not yet
self-tested. The Ed25519 KAT is also now a genuine RFC 8032 §7.1 known-answer
test with a negative case, not a self-consistency roundtrip an always-accept
verifier would pass — and that same verifier backs the integrity check.

**The gate covers the Cython bindings and secret-key export too.** Output
inhibition is not only about `pqc_backends`. The Cython binding modules
(`ama_cryptography.ed25519_binding` …) are public submodules whose `cy_*`
functions call the C kernel directly — a caller importing one reaches signing
and key generation without passing through `pqc_backends`' gated wrappers, and
if the package directory is on `sys.path`, without the package `__init__` (and
therefore POST) running at all. Each `cy_*` function now calls the guard, and
its module-level import of `check_crypto_permitted` forces POST to run even on
a top-level binding import. Separately, `key_formats` serialises secret keys
(`to_pkcs8` / `to_pem` / `to_jwk` / `to_cose`); those private-key output paths
now refuse in the error state rather than emitting a secret-key block from a
faulted module. (The v3 integrity artefact's module digest covers the
`.py` files, the vectors under `_post_kats/`, the native library **and** the
six compiled binding extensions — see the [5.0.0] glance row on
binding-extension digest signing. This paragraph previously said the binding
`.so` files were outside that coverage and called extending it "future work";
that stopped being true when the row landed, and the runtime guard closes the
error-state bypass independently either way.)

**Enforcement.** `tools/check_error_state_gating.py` parses the AST of
`pqc_backends.py` and requires `check_crypto_permitted()` on every public
function that reaches `_native_lib` or a `_cy_*` Cython callable, and
line-scans the five binding `.pyx` files to require the guard before the first
native call in every `cy_*` function. Exemptions must be declared with a stated
reason and are themselves checked for staleness, so the list cannot rot into a
blanket allowlist. It runs as a required CI step. Both directions — the gate
passing on the real tree, and the gate failing on an ungated function (Python
or `.pyx`) — are pinned by `tests/test_post_failclosed.py`, which also drives
the import-level behaviour in subprocesses (it cannot be observed from a
process that has already imported the package), exercises the binding and
key-export refusals, and checks that a broken KAT is not excused by
`AMA_BUILD_PIPELINE=1`.

**Measured cost.** The guard is ~37 ns per gated call (~9 ns of check, the rest
CPython call overhead), which is ~2 % of a 64-byte `native_sha3_256` and less on
everything larger.  The native-library digest adds one SHA3-256 over the shared
object (~800 KB → well under 1 ms) once per import.

---

## INVARIANT-40 — The Executed Bytecode Must Match the Signed Source

INVARIANT-39 binds the module's `.py` **source** and its native `.so`. But
CPython does not execute source: it executes the compiled bytecode in
`__pycache__/*.pyc`. A timestamp-based `.pyc` — the default — is honoured by
the interpreter whenever its stored `(mtime, size)` match the source file, and
an attacker with write access to the installed package sets exactly those. So
the gap is real and specific: leave every `.py` pristine, so the signed digest
and its Ed25519 signature still verify, and drop a `.pyc` whose bytecode
differs. The poisoned bytecode runs while every source-level check is green.

**The fix makes on-disk bytecode subordinate to the signed source.** A POST
stage (`execution-integrity`, run immediately after the source-integrity stage
that has just proven the `.py` files unmodified) recompiles each signed source
file and refuses any cached `.pyc` whose bytecode is not a faithful compile of
it. The comparison is by *executed surface* — `co_code`, the referenced
names/locals, the argument and flag shape, and every constant, descending
recursively into nested code objects — and deliberately ignores `co_filename`
and the line tables. Ignoring those is what keeps a legitimate `.pyc` built at a
different absolute path (a relocated wheel) from being a false positive, while a
single altered instruction, even inside a nested function, is still caught. A
constant swapped for an equal-valued one of another type (`1` for `1.0`, `1` for
`True`) is caught by a type guard, because `==` alone would pass it.

The stage covers the **same file set the digest signs** (every top-level
`*.py`), not merely the modules imported so far, so a poisoned `.pyc` for a
lazily-imported module is caught at POST rather than when that module is first
used. Where no `.pyc` exists (a source-only run, or `PYTHONDONTWRITEBYTECODE`),
there is nothing to poison — the interpreter compiled the signed source
directly — and the stage records that honestly rather than reporting a check it
did not perform. A `.pyc` from a different interpreter version (magic-number
mismatch) is skipped because the running interpreter will not load it either. A
complementary pass flags any loaded `ama_cryptography` module whose source
resolves outside the verified package directory — module substitution, whatever
its bytecode says.

**Bounded, and stated rather than implied.** A self-check written in Python
cannot vouch for the bytecode of *its own* module if that was already poisoned
before this code ran — the checker-poisoning boundary. This stage raises the
bar from "poison any `.pyc` freely" to "poison the checker's own `.pyc`, and do
so without tripping the source signature that the checker's source is bound by",
but it does not eliminate the class. The out-of-band control that does is OS /
package-manager code signing, which verifies files before the interpreter loads
them; this is documented in [`SECURITY.md`](SECURITY.md) under *Execution
integrity* alongside the trust-anchor boundary it shares.

**Enforcement.** `tests/test_execution_integrity.py` pins the bytecode
comparator (a changed instruction, a nested-function change and a
constant-type swap are caught; a filename-only difference is not), the
per-file check (a poisoned `.pyc` whose header still matches its pristine
source is a fault; a corrupt or foreign-magic `.pyc` is handled), the
substitution guard, and the end-to-end path: on a copied tree, a poisoned
but still-loadable `.pyc` fails POST and the import while the source digest
stays valid.

**Measured cost.** One `compile()` per signed source file, once per import —
tens of milliseconds over the package, on the same one-time POST path as the
digests above.

## INVARIANT-41 — No Asymmetric Keypair Is Released Without a Pairwise Consistency Test

FIPS 140-3 requires a conditional self-test on every asymmetric key
generation: the fresh keypair must demonstrate that its halves correspond
before the caller receives it. The helpers existed
(`pairwise_test_signature` / `pairwise_test_kem`) and were wired into **no**
key-generation path — the 2026-08 audit's finding #5. A keypair whose halves
do not correspond (a fault mid-generation, a corrupted caller-supplied seed,
a miscomputed BIP32 modular sum) was handed out and failed later, far from
the generation event that caused it.

**Every keygen path now runs the matching test before its keypair leaves the
function, and every family's test halves are independent.** Sign-and-verify
for the signature families (Ed25519, ML-DSA, SLH-DSA/SPHINCS+, the FROST
dealer via a full t-of-n round aggregated and verified against the group
key, ECDSA per FIPS 186-5 §3.3 for both the NIST-P curves and the BIP32
secp256k1 keys — the signer and verifier traverse genuinely independent
code); encapsulate-and-decapsulate for the KEM families (ML-KEM/Kyber); and
for X25519, the SP 800-56A rev. 3 §5.6.2.1.4 assurance in its strong form —
a Diffie-Hellman roundtrip against a fresh ephemeral peer,
``X25519(sk, eph_pk) == X25519(eph_sk, pk)``, which exercises the
scalar-multiplication kernel on two *different* scalar/point pairs and
demands the group law hold across them. An earlier revision recomputed the
public key and compared, which re-ran the same kernel on the same input and
could catch only a transient fault between the two computations; the
roundtrip closes that gap, and the ephemeral it needs is built without
re-entering keygen (a health-tested scalar draw plus one base-point
multiplication). The rule is uniform across random and seed-derived
generation — `*_from_seed` is publicly callable with arbitrary seeds, which
is precisely the path a corrupted input reaches — and across every surface:
the `native_*` entry points, the `generate_*` wrappers,
`AmaContext.keypair_generate` (tested with the context's *own* sign/verify
or encaps/decaps), and the BIP32 master and child derivations in
`key_management`. Every Python-side entropy draw that mints key material —
the Ed25519 seed, the BIP32 master seed, the Ascon key and nonce — now
routes through the §4.9.2 health-tested, error-state-gated CSPRNG draw
rather than a bare `secrets.token_bytes` / `os.urandom`.

**Scope — the Python API surface, not the bare `.so` (audit M1).** This
pairwise test, POST (INVARIANT-39) and the error-state output inhibition are
properties of the `ama_cryptography` **Python package**, which wraps every
approved operation behind `check_crypto_permitted()` and runs POST at import.
They are **not** properties of `libama_cryptography.so` linked directly:
`check_crypto_permitted` appears throughout `pqc_backends.py` and nowhere in
`src/c/`, and the C library's `ama_ed25519_keypair()` performs no pairwise test
(C-side PCT exists for ML-KEM only). `tools/check_keygen_pct.py` enforces this
over `pqc_backends.py`'s AST — the Python surface — alone. A C consumer that
links the shared object directly — the audience the SONAME, the pkg-config file
and `Dockerfile.c-api` serve — gets the constant-time primitives but **not**
POST, the error-state inhibition, or the PCT; those are supplied by the Python
wrapper. This invariant, and the FIPS-140-3-alignment claims in README and the
`CSRC_*` documents, are therefore scoped to the Python API surface until the
controls are either moved into the C boundary or the boundary is formally
defined as the Python package (INVARIANT-16, honest compliance claims).

The test is deliberately **unconditional**. Gating it behind an environment
flag would make the default configuration the non-compliant one; validation
applies to a configuration, not to a runtime toggle. Where a pairwise test's
counterpart operation is not built (a partial library with deterministic
keygen but no encapsulation), the keygen **refuses with an availability
error** rather than releasing an untested keypair — and rather than entering
the module ERROR state, which is reserved for a test that *ran and failed*. A
failed pairwise test enters ERROR through the shared helpers and inhibits all
further output (INVARIANT-39).

**Enforcement.** Two halves, and until 5.0.0 only one of them existed.

`tools/check_keygen_pct.py` is the coverage half: it DISCOVERS every keygen
entry point from `ama_cryptography/pqc_backends.py`'s own AST — 19 today — and
fails on any that does not reach `pairwise_test_signature` / `_kem` /
`_agreement`, directly or through one level of delegation. Exemptions must
name a reason and are checked for staleness. It runs in `ci.yml` and both
directions are pinned by `tests/test_keygen_pct_gate.py`.

`tests/test_keygen_pct.py` is the behaviour half: both failure directions (a
verify that lies → `CryptoModuleError` + ERROR state; the ERROR state then
refuses further keygen) and the positive path on real keypairs for every fast
family.

This paragraph used to credit the second file with the first file's job — "a
new keygen path that forgets the test fails the coverage assertion". It does
not, and could not: that test monkeypatches the three helpers into recorders,
calls a hand-written list of thirteen entry points, builds its `expected` list
alongside, and asserts the two match. A fourteenth keygen that omits its
pairwise test is never called by it, so both lists are unchanged and it passes.
Measured: an unwired `native_widget_keypair()` appended to `pqc_backends.py`
left that test at 17 passed / exit 0 while the new gate named the violation
and exited 1. This is the same gap INVARIANT-39 had before
`tools/check_error_state_gating.py`, closed the same way.

**Measured cost.** Sub-millisecond for every family except the hash-based
signatures: ~220 ms for SPHINCS+-SHA2-256f, ~1.0 s for SLH-DSA-SHAKE-128s —
paid at key generation, the rare, long-lived-key operation, and quantified
here rather than averaged away.

## INVARIANT-42 — The Declared ctypes ABI Must Match the C Header, and the Loaded Library Must Match the Package

A ctypes symbol probe proves a name is exported — not its arity, not its
parameter types, not its return convention. The 2026-08 audit's finding #7:
a stale major-version library, or any object exporting `ama_`-prefixed
names, satisfied every `hasattr` check and would corrupt the call frame at
the first mismatched invocation. A shared object carries no parameter
metadata, so the ABI cannot be interrogated at runtime; what the repository
does carry is the contract the library was compiled from.

**Two halves, static and runtime.** `tools/check_ctypes_abi.py` parses every
`AMA_API` prototype out of the C headers and every `argtypes`/`restype`
assignment out of every package module that declares one — the scope is
DISCOVERED from the package's ASTs rather than enumerated, with
`REQUIRED_MODULES` as a seven-module floor beneath it (`pqc_backends`,
`ascon`, `agent_binding`, `secure_memory`, `hybrid_combiner`, `_build_sign`,
`_self_test`; the gate prints both counts on every run) — and requires
agreement on
arity and on a coarse class per position (pointer-like vs. integer-like,
pointer/integer/void for returns) — the classes that decide call-frame
layout. Coverage is closed in both directions: a symbol called without a
declared signature fails, and a signature for a symbol no header declares
fails. At runtime, `pqc_backends` asks the **loaded** object for its
compiled-in version (`ama_version_number`) before configuring a single
signature against it, and rejects any library whose major version is not the
package's — extending `tools/check_version_consistency.py`'s static
version-consistency guarantee to the artefact the loader actually mapped.
The Python transcription of the required major is itself pinned to the
header macro by that same tool, so the two gates cannot drift apart
silently.

**Enforcement.** The gate runs in the test suite
(`tests/test_ctypes_abi_gate.py`), which also proves the negative
directions: an arity change, a pointer/integer confusion, a void return
read as a value, and an uncovered called symbol are each demonstrated to
fail on synthetic input. The handshake's reject branch is pinned by test
against a fake library object reporting a foreign version.

**Measured cost.** The static gate is CI-only. The handshake is one call
returning three compile-time constants, once per import.

## INVARIANT-43 — Every Logged Literal Must Survive a cp1252 Handler

`logging` fails closed and silent: when a handler cannot encode a record's
text, the encode raises inside `Handler.emit`, `logging` routes it to
`Handler.handleError`, prints a traceback to stderr, and **discards the
record** — the call site is told nothing. `logging.FileHandler` opens with
`encoding=None`, which resolves to the platform's preferred encoding —
cp1252 on a default Windows install. The 2026-08 audit found
`adaptive_posture` logging both the posture-triggered key rotation and the
algorithm switch with a `→` (U+2192) between the old and new identifiers,
so on Windows the two records stating that a signing key had changed were
exactly the two records a file handler dropped. An audit trail that
silently loses its key-rotation entries is worse than one never claimed:
the absence is indistinguishable from "no rotation happened".

**The rule is cp1252-encodable, not ASCII.** `—` and `§` encode in cp1252
and appear, correctly, in over a thousand POST and diagnostic strings;
cp1252 is precisely the line at which a record stops being written, so it
is the line this invariant draws. Only literal text is checked —
interpolated values are runtime data and cannot be decided statically.

**Enforcement.** `tools/check_log_message_encodability.py` walks every
module's AST for logger and `warnings.warn` emission sites — bound-name
loggers, `self.logger`, and the inline
`logging.getLogger(__name__).<level>(...)` idiom alike — and fails on any
literal a cp1252 handler would refuse. It runs in ci.yml's Security Checks
job; both directions, including the inline idiom the first version of the
gate could not see, are pinned by
`tests/test_log_message_encodability_gate.py`.

**Measured cost.** CI-only; one AST pass over the shipped package.

---

## INVARIANT-44 — A Fetched Conformance Corpus Is Pinned by Its Bytes, Not by a Name

`nist_vectors/fetch_vectors.py` downloads ten ACVP-Server projections and
`nist_vectors/run_vectors.py` validates the library against them; the
attestation in `docs/compliance/` publishes the result. The download was
pinned to a release tag and to nothing else. A tag names a snapshot; it does
not fix its bytes — it is a movable ref served through a CDN. A projection
already on disk was skipped and used as found, so an edited or truncated
local copy validated without a word. And the fetcher re-serialised what it
received, so nothing on disk could ever have been compared with upstream.
The attestation could say `v1.1.0.42` while the harness ran against bytes
nobody had identified.

**The rule.** Every conformance vector that is fetched rather than vendored
is pinned by SHA-256 and length in a committed manifest
(`docs/compliance/acvp_vector_digests.json`), and every consumer verifies
against it independently: the fetcher before it writes (and it refuses a
local file that does not match rather than trusting it), the harness before
it reads, and the workflow between the two. The bytes written are the bytes
published. The pin is advanced only by a deliberate command
(`fetch_vectors.py --refresh-manifest`) that refuses to run under GitHub
Actions, in the same commit as the attestation it underwrites.

**Enforcement.** `tools/acvp_vector_pin.py` is the verifier and the
`--check` CLI; `.github/workflows/acvp_validation.yml` runs it between the
fetch and the run and cross-checks the manifest's ref against the
attestation's. `tests/test_acvp_vector_digests_gate.py` pins anchor digests
in its own source (so a regenerated manifest alone cannot make a corrupted
corpus verify), holds the manifest to the two independent records this tree
already carries for three of the ten files (`tests/kat/PROVENANCE.json` and
the ML-KEM derivative's source block), and drives every refusal with a
negative control.

**Measured cost.** One streamed SHA-256 per projection per run; the largest
is 30 MB.

---

## INVARIANT-45 — Every SIMD Kernel Has a Pin, and the Published Vectors Run Under It

`AMA_DISPATCH_ONLY=<slot>` leaves every dispatch kernel at its scalar
fallback except one. `tests/c/test_dispatch_only_env.c` proved that the pin
resolves; it executes no cryptography. No CTest case ran a published-vector
KAT with a SIMD kernel pinned, so every AVX2, AVX-512, NEON and SVE2 kernel
was checked against the standards' answers only when a host's default wiring
happened to select it — and the auto-tune could, and on some hosts did,
revert a kernel before the KAT ran. Four wired kernels had no pin name at
all, and three of those (the AVX2 4-way Keccak that expands every ML-KEM and
ML-DSA matrix, and both x86 AES-GCM hardware kernels) were switched *off* by
every other pin. Both MemorySanitizer lanes built with `AMA_ENABLE_SIMD=OFF`,
so no SIMD kernel had ever run under the one sanitizer that sees
uninitialised reads.

**The rule.** Every kernel the dispatch table can install has an
`AMA_DISPATCH_ONLY` name, and the inventory is one list — in
`src/c/dispatch/ama_dispatch.c`, `tests/c/test_dispatch_only_env.c`,
`include/ama_dispatch.h`, `tests/c/CMakeLists.txt` and `dudect.yml`. For
every slot, the published-vector KATs whose primitive routes through it run
with the slot pinned and the auto-tune off, on every ctest lane including
MemorySanitizer. A KAT cannot pass under a pin the host did not honour:
`tests/c/kat_slot_guard.h`, the first statement of every swept executable's
`main()`, exits 77 (Skipped) when the pin was refused — or 1 when the build's
CI runner class mandates the slot, so a wiring regression is red rather than
a skip. Which slots are mandated follows `dudect.yml`: AVX2 and
AES-NI+PCLMULQDQ on every hosted x86-64 runner, NEON and the Crypto
Extensions on AArch64; AVX-512, VAES and SVE2 may skip.

**Enforcement.** The sweep is registered in `tests/c/CMakeLists.txt` with
two negative-control cells that pass only on the guard's own verdict line
(`PASS_REGULAR_EXPRESSION`), so deleting the guard fails them.
`tests/test_kat_slot_sweep_gate.py` holds the five inventories to one list,
requires a published-vector cell per slot, requires the guard to be the
first statement of every swept `main()`, and requires both MSan lanes to
build the SIMD kernels.

**Measured cost.** The sweep adds 37 cells to ctest; on the x86-64 Release
build they run in under two seconds in total, and the full suite under MSan
with SIMD on takes 85 s against the lane's 25-minute budget.

---

## INVARIANT-46 — Fuzzing Must Be Able to Deepen

Every run of the libFuzzer lane started from `fuzz/seed_corpus` and threw
away what it found after 60 seconds. No run stood on the previous one, so
the deep branches — the ML-DSA verify path at 5,262 bytes, SLH-DSA verify at
49,921 — were reachable in principle and reached by nobody; libFuzzer grows
its mutation length with executions, and measured 20-second runs of the
slow targets never mutated at their derived ceiling. The `oss-fuzz/`
submission files had never been built by anything.

**The rule.** The corpus persists across runs (restored before fuzzing,
merged to its coverage-adding units after, saved under a run-unique key so
every run starts from the newest corpus and leaves a newer one), a scheduled
campaign runs an order of magnitude longer than a pull-request run and saves
what it finds on the default branch where every branch can restore it, and
the OSS-Fuzz build integration is executed by OSS-Fuzz's own driver — build
inside `base-builder` with the checkout mounted, then `check_build` — on
every push, through the same script a developer runs. Continuous fuzzing on
OSS-Fuzz's infrastructure runs nightly through ClusterFuzzLite from the same
build integration, under three sanitizers, with the corpus kept between
runs.

**Enforcement.** `tests/test_fuzz_corpus_persistence_gate.py` pins the
restore → fuzz → merge → save order and keys in both matrix jobs, the merge
running after a crash, the growth numbers in the step summary, the nightly
schedule and its budgets, the OSS-Fuzz job in the fuzzing gate, the script
mounting the checkout, and the ClusterFuzzLite modes and pins.
`tools/check_fuzz_target_registration.py` continues to hold
`oss-fuzz/build.sh` to the harness set, and `.clusterfuzzlite/build.sh` execs
it so there is one build integration.

**Measured cost.** One cache restore and save per matrix cell (corpora are
tens of KB to a few MB); a merge of a few seconds; the OSS-Fuzz job pulls
`base-builder` and `base-runner` and builds fifteen fuzzers, roughly ten
minutes in parallel with the other lanes.

---

## INVARIANT-47 — A Lane That Provisions a Resource Fails the Skip of It

Both pytest lanes checked out at depth 1, so four guards that read git
objects — the baseline validity window against `origin/main`,
calibration-commit drift, the benchmark snapshot's provenance commit, the
embedded v4.0.0 tag bytes — skipped on every CI run for as long as they
existed; nothing installed Flask, so the six attack-surface pins on the Flask
demo never ran; twelve skip reasons gated on native features the CI build
produces and named none of the keywords the backend escalation matches; the
`.clang-format` validity test skipped everywhere for want of the tool. A skip
is green, and every one of these was green on every run. One was worse than
a skip: with `origin/main` absent the validity-window guard compared nothing
with nothing and passed.

**The rule.** When a lane is configured to provide what a test needs — the
native backends, the interoperability oracles, the full git history, an
example's third-party dependency, a tool the lane installs — a skip of that
test in that lane is a failure, not a skip. The lane says what it provides
with a flag (`AMA_CI_REQUIRE_BACKENDS`, `AMA_CI_REQUIRE_HISTORY`); a test says
what it needs with a marker (`requires_interop_oracle`,
`requires_git_history`, `requires_example_deps`) or, for the native backends,
by naming the backend in its skip reason; and `tests/conftest.py` turns the
skip into a failure only where the two meet. A flag never escalates a skip
outside its own promise: the history flag leaves backend skips alone and the
backends flag leaves history skips alone, so a lane that builds the C
library on a shallow checkout is still allowed to skip the history guards.
Outside CI, every one of these remains an ordinary skip.

**Why a marker and not a keyword, wherever possible.** A keyword match on the
reason text is a functional property of prose, and prose drifts; the markers
are the escalation for everything added after the backend keywords, and the
backend keywords themselves are held to their modules by a completeness guard
that reads `skipif` markers and `pytest.skip` calls alike and allowlists
host-OS reasons verbatim. A guard that cannot skip silently is only half the
rule; the other half is that it cannot pass silently either, which is why
the baseline guard resolves its refs before comparing anything.

**Enforcement.** `tests/conftest.py` escalates the three markers and the
backend keywords under their flags; `tests/test_conftest_backend_skip_scoping.py`
drives the production hook through pytester for every marker in both
directions, holds every history skip and every `[examples]` importorskip
under its marker, and holds the eight backend-only modules' reasons to the
keyword set; `ci.yml` and `ci-build-test.yml` check out with
`fetch-depth: 0`, install `[examples]` and `clang-format`, and set both
flags on their pytest steps; `benchmarks/check_baseline_justification.py`
refuses a ref it cannot resolve and an empty base ref, with tests against
real git.

---

## INVARIANT-48 — Ed25519 Must Reject Small-Order Public Keys and R Halves

**Statement.** Every Ed25519 verification path must reject a signature whose
public key `A`, or whose signature half `R`, is one of the fourteen 32-byte
encodings of the eight points of the order-8 subgroup — the identity
included, the non-canonical spellings included, both settings of the x-sign
bit included. This applies to single verification and to batch verification.

**Why.** AMA's verifier is **cofactorless**: it decides
`[S]B - R - [h]A = O`, not the cofactored `8([S]B - R - [h]A) = O`. RFC 8032
§5.1.7 permits either, and AMA's choice was recorded nowhere but an
implementation comment. The choice has a consequence that the RFC does not
spell out and that this library did not act on: a cofactorless verifier
accepts the identity as a public key unless something else rejects it, and an
identity public key makes the `[h]A` term vanish for **every** `h`. The
equation collapses to `[S]B = R`, so the pair `(R = [s]B, S = s)` verifies
against **every message**.

Measured in the 2026-09 audit against a pure-Python RFC 8032 reference at
`s ∈ {1, 5, 12345}` — all below `L`, so INVARIANT-26 does not intercept
them — all three were **accepted** for all four messages tried: 12 of 12,
through single verify and through batch verify alike. One 64-byte string,
produced with no secret of any kind, authenticating anything. It reached the
package layer, where `crypto_api` embeds the public key inside the package it
verifies: swapping that embedded key to the identity and the signature to the
forgery reported `primary_signature: True`, `primary: True`,
`core_valid: True`. Only `key_pinned` — which is optional, while `core_valid`
and `primary_signature` are offered as verdicts — kept `all_valid` false.

**The finding is wider than the identity**, and the fix is stated for the
wider case. For a small-order `A` of order `n`, `[h]A = [h mod n]A`, so an
attacker holding no secret picks any `S`, walks `j` over `[0, n)`, sets
`R = [S]B - [j]A` and keeps the first candidate whose `h = H(R ‖ A ‖ M)`
satisfies `h ≡ j (mod n)`. One in `n` candidates lands and `n ≤ 8`, so this
costs at most eight hash evaluations. Constructed for all **eight**
canonically encoded small-order points: 8 of 8 accepted before the fix, 0 of
8 after. The identity is the only one of them for which a single signature
works for every message; the other seven forge per message, which is not a
meaningful mitigation.

**What was NOT the gap.** A sub-review measured that cofactorless
verification already **rejects** the torsion-shifted key `A + T8` — 0 of 400
accepted — so the "one signature valid under several public keys" trick that
cofactored verifiers admit does not work here and never did. Stating the fix
as "reject small-order inputs" rather than as the cofactored-verifier repair
it resembles is deliberate.

**The third member of the input-canonicalisation family.** INVARIANT-26
requires `0 ≤ S < L`; INVARIANT-38 requires a canonical point encoding
(`y < p`, and an admissible x-sign bit) for `R` and for `A`; this requires the
point that encoding names not to be small-order. The three now live together
in `src/c/internal/ama_ed25519_canonical.h` as pure byte predicates over
public input, and they are applied together at one call site, because the
rules are read together and drift apart when they are stored apart. They are
not redundant with each other: six of the fourteen encodings here are already
refused by INVARIANT-38 (`y = p` and `y = p+1` under either sign fail the
`y < p` rule; `y = 1` and `y = p-1` with the sign bit **set** fail the `x = 0`
sign rule), and the remaining eight are canonical encodings of genuine curve
points that INVARIANT-38 has no quarrel with at all. The overlap is kept
rather than trimmed so that each predicate's contract is independent of the
order the call site applies them in.

They differ from each other in kind, and the difference is worth stating.
INVARIANT-26 and INVARIANT-38 are **encoding-uniqueness** rules: their defect
is that one key or one signature had two accepted byte spellings, which
breaks anything treating those bytes as an identity. This one is not about
spelling. Every one of the eight canonical encodings it blocks is the unique,
correct spelling of a real point on the curve. It is a **semantic** rule about
which points may be presented as a verification key at all, and its defect was
a working universal forgery, not a second name for one thing.

**It is a policy, and the policy is now published.** RFC 8032 does not mandate
small-order rejection, so this is AMA's choice twice over — once in taking the
cofactorless equation, once in guarding it. Both are stated at
`ama_ed25519_verify` in `include/ama_cryptography.h`, together with the
interoperability consequence: a cofactored verifier (ZIP-215, libsodium's
permissive mode) and a cofactorless one disagree on torsion-carrying
signatures, so a consensus system whose participants run a mixture of the two
can be shown an input that **splits** it. Fix one rule across every
participant; do not mix implementations and assume they agree. The rule itself
is also a narrowing, never a widening: no legitimate signature is affected,
because an honest `R` is `[r]B` with `r = H(prefix ‖ M) mod L` and is
small-order only when `r ≡ 0 (mod L)` — probability about `2^-252`.

**Enforcement.** `ama_ed25519_point_is_small_order()` in
`src/c/internal/ama_ed25519_canonical.h`, applied to `public_key` and to the
signature's `R` half in `ama_ed25519_verify` (`src/c/ama_ed25519.c`), which
batch verification calls per entry — so the two cannot disagree, the same
construction INVARIANT-26 and INVARIANT-38 rely on, and there is deliberately
no second copy of the check in the batch path. The predicate is a
sign-bit-masked byte comparison against seven stored `y` values, which is what
turns seven rows into fourteen blocked encodings. The table is derived and
exhaustively checked rather than copied: the eight points of `E[8]` have five
distinct `y` values, and a sweep of the whole nineteen-value band `[p, 2^255)`
found exactly two more (`p` and `p+1`) reducing into the set.

**A blocklist rather than a cofactor-clearing order check**, and the
measurement is the reason. Both decide exactly the same predicate — the table
is the complete set of encodings any decoder maps into `E[8]`, not a
heuristic. Measured on this tree (Release, gcc `-O2`, x86-64, min of three
runs): the byte predicate costs **127 ns**; a cofactor-clearing `[8]A == O`
built from the library's own `ama_ed25519_scalarmult_public` costs **9,065
ns**; a bare point decode alone costs **10,927 ns**; a whole
`ama_ed25519_verify` costs **34,951 ns**. That is 71× per call — the two
calls this rule adds cost 0.25 µs against 18.1 µs, `+0.7%` on a verify rather
than `+52%`. The gap is structural rather than an artefact of that ladder: an
order check must decode first, and a decode is a field square root. The
second reason is placement: `ama_ed25519_canonical.h` carries no field
arithmetic, so an order check could not live beside its two sibling rules at
all — it would have to go inside the `GE_SYM`-templated
`internal/ama_ed25519_ge.h` and be instantiated once per field, which is more
code in the one place the two instantiations can diverge.

**Not a constant-time requirement.** `A` arrives in a public key and `R` in a
signature; both are public. The comparison is branch-free anyway, for the same
reason as its two siblings — it costs nothing at this size, not because
INVARIANT-12 reaches here.

**Verification.** `tests/c/test_ed25519_small_order.c` (140 checks) and
`tests/test_ed25519_small_order.py` (68 checks) carry the forgery vectors
themselves — the library's signer cannot produce them, so they are fixed data
generated by a pure-Python RFC 8032 reference whose own correctness is pinned
by the §7.1 vectors it regenerates. Every assertion is labelled FORGERY (the
signature satisfies the group equation under its small-order input, so only
this rule can reject it), RANGE (a direct unit test of the predicate,
including the near-misses that must *not* be blocked) or SMOKE (behavioural,
rejected either way). The labels are measured, not asserted: with the
predicate neutered to `return 0`, the C file reports 102 passed / 38 failed,
and the 38 are exactly the 15 RANGE, 21 FORGERY and 2 mixed-batch assertions,
with every SMOKE line still green. Every vector in both files is put to
single verify *and* batch verify with the two verdicts required to agree, so
the inheritance through the per-entry loop is asserted rather than assumed.

Nothing else moved. The 150 vendored Wycheproof Ed25519 vectors still pass
with **no new divergence to declare**: the sixteen that carry a small-order
`R` (`tc10`–`tc19`, `tc25`–`tc29`, `tc60`) are all scored `invalid` upstream,
and no vector in that corpus uses a small-order public key. The frozen oracle
(`tests/oracle/ed25519_frozen_oracle.txt`) replays clean at all 2,022 records:
the only eleven that touch a small-order `A` or `R` are batch records whose
recorded verdict is already `0`.

**One piece of existing coverage was weakened by this, and is relabelled
rather than quietly left.** `tests/c/test_ed25519_canonical_s.c` proved its
INVARIANT-38 forgery pins non-vacuous with a control asserting that the
canonical identity encoding *accepts* the forgery — justified at the time by
"RFC 8032 does not require rejecting it", which was true of the RFC and wrong
as a policy. That control now asserts the opposite and is the PIN; the four
assertions it was supporting are SMOKE. Measured with the §5.1.3 guard
neutered and this rule in place: 6 failed / 44 passed, and all four of those
lines printed `[ OK ]`. INVARIANT-38's live coverage is what those 6 failures
were — the RANGE band and the decode-path `y = 0` / `y = p` pair, which this
rule does not touch, because the predicate is applied at
`ama_ed25519_verify` and not inside the decoder.

---

## INVARIANT-49 — A FROST Nonce Pair Is Single-Use and the Library Consumes It; Aggregation Verifies Every Share Before It Returns Success

Two properties of the threshold-signing API, stated together because the
2026-09 independent audit found both absent and because a coordinator that
can induce the first failure is exactly the party positioned to exploit the
second.

**The rule, part 1.** A nonce pair produced by `ama_frost_round1_commit` is
good for **exactly one** `ama_frost_round2_sign` call, over exactly one
message, and **round 2 consumes it**: `nonce_pair` is non-`const`, it is
`ama_secure_memzero`'d on every exit from round 2 — success, argument
refusal, internal error alike — and an all-zero (already-consumed) pair is
refused on entry with `AMA_ERROR_INVALID_PARAM`. Not "callers must not reuse
it". The library makes a second use unobtainable through the API.

**The rule, part 2.** `ama_frost_aggregate` verifies **every** signature
share against the RFC 9591 §5.3 relation before that share contributes to the
sum, reports the offending participant's 1-based index to the caller, and
then verifies the assembled `(R, z)` against the group public key with the
ordinary RFC 8032 verifier before writing anything to the caller's buffer. A
refusal writes no signature.

**Why part 1 — measured.** Until this change `ama_frost_round2_sign` took
`nonce_pair` as `const uint8_t *`, held no state, and neither marked,
consumed nor zeroized it, so calling it repeatedly with one pair over
different messages returned `AMA_SUCCESS` every time. Each call emits
`z = d + e·rho + (λ·s)·c` with `rho` and `c` varying per message and
`(d, e, λ·s)` fixed, so three calls are three independent linear equations in
three unknowns mod `l`. The audit's sub-review solved that system:

```
recovered d == hiding nonce  : True
recovered e == binding nonce : True
recovered secret share s_1   : True
```

Full recovery of the participant's long-term share, from the protocol outputs
alone, with no host access; with `t` shares so recovered the group secret is
reconstructible. Nothing exotic reaches it — a cached round-1 result, a retry
of a failed round 2 against a different message, or a coordinator that asks
for a re-sign. `SECURITY.md` documented the *repeating-CSPRNG* hazard as a
deployment obligation, and `nonce_generate`'s SCOPE note documented the
stateless hedge's limits, but neither said that the API **itself** permitted
reuse inside one healthy process. It is not fixable by documentation: a
`const` pointer plus a warning is exactly what was already there.

Scrubbing on **every** exit rather than only where a share was emitted is
deliberate. The weaker rule — "dead unless it returned `INVALID_PARAM`" —
must be re-derived at every call site and is not one testable property;
"round 2 consumes the nonce, whatever the outcome" is. A caller whose
arguments were malformed re-runs round 1, which costs 23 µs.

The consumed-nonce check is **constant-time** (`frost_is_all_zero`, an
OR-fold over all 64 bytes with a single branch on the aggregate). The
tempting argument against is that the buffer belongs to the caller and the
answer — "has this been consumed?" — is published by the return code anyway.
Both halves are true and neither is the point: what a short-circuiting scan
leaks is not the answer but the *shape* of a nonce that is **not** all-zero,
because an early-exit loop runs for as many iterations as the hiding nonce
has leading zero bytes. That is a repeatable per-round measurement of a
secret scalar's high-order structure, available to any observer co-resident
with the signer, and the caller owning the buffer does not licence the
library to leak it to a third party in the same address space. The fold costs
64 byte-ORs against round 2's eight scalar multiplications.

**Why part 2 — measured.** Aggregation summed `z_i` mod `l`, concatenated
with `R`, and returned `AMA_SUCCESS` unconditionally: it checked nothing.
Flipping one bit of one share gave `aggregate rc=0` followed by
`ed25519_verify -> -4`, with no indication of which participant was at fault,
and there was **no share-verification entry point in the API at all**. So one
faulty or malicious signer could destroy every ceremony it joined,
anonymously, and a caller trusting the return code would publish an invalid
signature. Identifiable abort is the robustness property FROST's two-round
structure exists to buy, and it was the property that was missing.

Verifying a share requires that signer's PUBLIC key share `PK_i`, which the
old parameter list did not carry and which cannot be recovered from what it
did carry — the commitments are nonce points, not key shares. Hence the
breaking signature change (`signer_public_shares`), and hence the attribution
out-parameter (`bad_participant_index`): the single `ama_error_t` return
cannot carry both a verdict and an identity, and the alternatives — one error
code per participant, or a new public struct for one byte — are worse than an
optional out-parameter a caller who does not want blame may pass `NULL`. It
is written to 0 **on entry**, so it is never stale, and 0 means "not
attributable to one participant" unambiguously because participant indices
are 1-based and validated non-zero. `AMA_ERROR_VERIFY_FAILED` is reused
rather than given a new `ama_error_t` enumerator: `ama_frost_aggregate` could
not previously return it at all, so within that entry point it means
"verification failed" and nothing else, and one family does not get to widen
an enum every family shares.

**Measured cost**, 2-of-3 over a 30-byte message, medians of 1000 iterations,
old and new code built from the same tree and timed in the same process on
one host: `ama_frost_aggregate` 120.8 µs → 470.0 µs. Of the ~349 µs added,
~35 µs is the defence-in-depth RFC 8032 verify and the rest is two per-share
verifications; it scales linearly in the number of signers. Round 2 is
unchanged — 165.2 µs → 163.7 µs, i.e. within noise: the OR-fold and the extra
`ama_secure_memzero` do not register. Aggregation is the once-per-ceremony
operation and the one whose result is published, so ~4x on it to buy
identifiable abort and a verified output is the right side of that trade.

**The header now says what the implementation does.** The same change
retitled the public header's section from "FROST THRESHOLD ED25519 SIGNATURES
(RFC 9591)" to "**RFC 9591-STYLE, NOT RFC 9591 CIPHERSUITE-INTEROPERABLE**"
and moved the caveat `src/c/ama_frost.c` had always carried into the section
banner and into every function's doc block. The protocol structure follows
RFC 9591; the hash derivations do not prefix the `"FROST-ED25519-SHA512-v1"`
contextString and do not use the per-role H1–H5 domain separation, so partial
signatures, commitments and binding factors are **not** interoperable with an
RFC 9591 ciphersuite implementation and every participant in a ceremony must
run this library. The aggregated signature's RFC 8032 conformance is
unconditional. This was **not** "fixed" by quietly adding the contextString:
that changes every derivation and breaks every deployed ceremony's wire
format, and is a separate decision with its own migration. The standard the
register holds elsewhere — the claim must match the artefact — is met by
correcting the claim, not by silently changing the artefact.

**Enforcement.** `src/c/ama_frost.c`. `ama_frost_round2_sign` takes
`uint8_t *nonce_pair`, routes every exit through a single `consume:` label
that scrubs it, and gates entry on `frost_is_all_zero`. `verify_share_core`
implements the §5.3 relation; `ama_frost_verify_share` is the new public
entry point over it; `ama_frost_aggregate` calls it per share with the
session values computed once, sets `*bad_participant_index` on rejection, and
runs `ama_ed25519_verify` on the assembled signature before copying it out.
The Python surface enforces the same contract in
`ama_cryptography/pqc_backends.py`: `frost_round1_commit` returns the nonce
pair as a `bytearray` (an immutable `bytes` cannot be consumed, and writing
through a pointer into one is undefined behaviour in CPython),
`frost_round2_sign` requires a writable buffer and scrubs it in a `finally`
so the Python-side argument refusals consume it too, and `frost_aggregate`
raises `FrostShareRejected` carrying `participant_index`. Callers updated in
the same change: the dealer's pairwise-consistency round trip in
`frost_keygen_trusted_dealer` (INVARIANT-41), `benchmarks/benchmark_c_raw.c`
— which now re-runs round 1 outside the timed window, because a benchmark
loop cannot reuse a consumed nonce — and `fuzz/fuzz_frost.c`, which fuzzes
the public key shares and the new entry point as well.

**Verification.** `tests/c/test_frost.c` Test 8 pins part 1 at the C
boundary: the buffer is zeroed after a successful round 2 **and** after a
failed one, a second call with it is refused, an all-zero pair supplied
directly is refused without a prior round 2 (so the entry check is pinned
independently of the scrub), and `ATTACK BLOCKED` runs the audit's
three-signings-under-one-nonce sequence and asserts only the first succeeds.
Test 9 pins part 2: `ama_frost_verify_share` accepts honest shares and
rejects a corrupted one, aggregation rejects a corrupted share with the
culprit's index — asserted for two different culprits, so a constant cannot
pass — leaves the caller's signature buffer untouched, accepts a `NULL` blame
channel, rejects mismatched public key shares, and an honest ceremony still
aggregates to a signature `ama_ed25519_verify` accepts.
`tests/test_frost.py` mirrors both on the Python surface
(`TestFROSTNonceSingleUse`, including
`test_attack_three_signings_under_one_nonce` and the `TypeError` on an
immutable nonce pair; `TestFROSTShareVerification`, including the
parametrised attribution test and the end-to-end RFC 8032 check).
`tools/check_ctypes_abi.py` holds the new arities against the header
(INVARIANT-42).

---

## INVARIANT-50 — An Approved-Mode Signing API Is Context-Separated, and the Internal Interface Does Not Ship

FIPS 205 §9 specifies `slh_sign_internal` / `slh_verify_internal` over the raw
byte string and states that the internal functions shall not be exposed to
applications other than for testing. §10.2 wraps them:
`M' = 0x00 || IntegerToBytes(|ctx|, 1) || ctx || M`. Three production entry
points signed and verified the raw message instead —
`ama_sphincs_sign` / `ama_sphincs_verify`, the generic context API
(`ama_sign` / `ama_verify` with `AMA_ALG_SPHINCS_256F`, which delegates to
them), and `ama_slhdsa_sign_internal`, which carried `AMA_API` and was present
in the shipped shared object by name (`nm -D` found it).

That is not merely a missing wrapper. Both interpretations of a signature
lived under ONE key, so they cross-verified. Measured on this tree before the
fix, in both directions:

```
slhdsa_sign(M, ctx=b"")          accepted by sphincs_verify(b"\x00\x00" + M)   -> True
sphincs_sign(b"\x00\x01x" + M)   accepted by slhdsa_verify(M, ctx=b"x")        -> True
```

The second line is the one that matters. A caller who signs any
attacker-influenced bytes through the legacy or the generic API — the API a
consumer reaches with no algorithm-specific knowledge — is a signing oracle
for FIPS 205 pure signatures on attacker-chosen `(ctx, M)` pairs under that
key. The context string is the mechanism the standard provides for keeping one
key's uses apart, and it separated nothing as long as a second entry point
would hash whatever it was handed.

**The rule.** Every signing and verification entry point in a shipped library
applies its scheme's domain separation before it reaches the core, and a
"legacy" or "compatibility" name is not an exemption — it is the name most
likely to be called by code that has not read the specification. The internal
interface is compiled only under `AMA_TESTING_MODE`, so it is absent from
every shipped artefact by construction rather than by export control: not
compiled is the only construction the ELF version script and the Mach-O
exported-symbols list cannot disagree about (the reasoning
`ama_ascon_permutation_for_test` established, INVARIANT-1's vendoring addendum
aside). Where a test genuinely needs a knob the approved mode does not expose,
the knob goes on the CONTEXT-SEPARATED entry point, not on a raw one.

**What that cost, and what it bought.** `ama_sphincs_sign` / `ama_sphincs_verify`
are now §10.2 with the empty context; this is a wire-format break, taken
deliberately because v5.0.0 was never tagged and the alternative is shipping
the oracle as a compatibility guarantee. `ama_slhdsa_sign_internal` left the
public surface and `ama_slhdsa_sign_addrnd` took its place: same
caller-supplied `addrnd`, but it takes `ctx` and `M` separately and builds `M'`
itself, so it cannot produce a signature over an unprefixed string. One export
out, one strictly narrower export in. NIST ACVP's hedged sigGen replay moved
onto it and got stronger in the move — the test used to build `M'` in Python,
which left the wrapper outside the vector.

**Enforcement.** `tests/c/test_slhdsa_context_separation.c` asserts both probes
above as negative results, that a §9 signature is rejected by every shipped
verifier and vice versa, that `sign_addrnd` is byte-identical to
`sign_internal` over the wrapper it builds, and replays all 14 NIST ACVP
`signatureInterface == "internal"` sigVer vectors for SLH-DSA-SHA2-256f
against `ama_slhdsa_verify_internal` — it links `ama_cryptography_test`,
because those vectors can only be replayed through the interface that no
longer ships. `tests/test_slhdsa_context_separation.py` holds the Python
surface: the same two probes, the generic API through `crypto_api`, that
`dlsym` finds neither §9 symbol in the loaded library, and that the C replay
still requires all fourteen — dropping coverage is the cheapest way to make a
conformance fix look clean. `tests/test_pqc_kat.py` asserts the other half:
that a shipped verifier rejects every one of NIST's VALID internal-interface
signatures. `cmake/ama_exports.map` localises both §9 names as defence in
depth, and `tools/check_ctypes_abi.py` refuses a ctypes declaration for a
symbol the public header no longer declares.

**ML-DSA, the same finding one scheme over (2026-09-23).** FIPS 204 §5.2
restricts `ML-DSA.Sign_internal` (Algorithm 7) the same way, and the library
still shipped it as `ama_ml_dsa_sign` / `ama_ml_dsa_verify`, with the Python
wrappers defaulting to it (`ctx=None`). The oracle reproduced: a signature from
`ama_ml_dsa_sign(0x00 || 0x01 || "x" || M)` was accepted by
`ama_ml_dsa_verify_ctx(M, ctx = "x")`. Both are now `ama_ml_dsa_sign_internal`
/ `_verify_internal` in the `AMA_TESTING_MODE` archive only, localised in
`cmake/ama_exports.map`, and `native_ml_dsa_sign` / `_verify` take the empty
context by default. The header's justification for shipping them — "the ACVP
internal-interface vectors replay through it" — was false for the C side and
true only of `tests/test_pqc_param_sets.py`'s Python replay of the vendored
`tests/kat/fips204` corpus; those 30 records now replay byte-exact in
`tests/c/test_ml_dsa_context_separation.c`, which also pins that the context
API is the §5.2 wrapper over Algorithm 7 for empty, short and 255-byte
contexts. `tests/test_ml_dsa_interfaces.py` asserts none of the four names is
in the shipped library and repeats the oracle probe against every shipped
signer.

**The empty message is a message.** The same entry points rejected
`message == NULL` outright, so whether a zero-length message could be signed
depended on whether the caller's allocator returned a non-NULL pointer for a
zero-byte request — a property of the caller's `malloc`, not of FIPS 205,
which is defined over `M ∈ B*`. These functions already read
`ctx = NULL, ctx_len = 0` as the empty context; message and ctx are now read
the same way, and `(NULL, non-zero)` is still a caller bug.

**Measured cost: negative.** The wrapper used to be materialised by `calloc`ing
`2 + |ctx| + |M|` bytes, copying the whole message in, scrubbing it and
freeing it — three extra passes over the message and a heap allocation of
caller-controlled size on the signing path, in three entry points. Routing the
legacy API through §10.2 would have added that copy to a path that did not
have it: signing 64 MiB through `ama_slhdsa_sign` cost **59.8 ms (+10.7 %)**
more than signing the same bytes raw, and 6.6 ms (+2.2 %) at 16 MiB. So the
wrapper became a separate absorbed segment instead. `PRF_msg` and `H_msg`
already stream, and the prefix is at most 257 bytes; it now rides in
`ama_hmac_sha512_3`'s third message slot (previously passed `NULL`) and in one
more `SHAKE-256` absorb. After the change the §10.2 path at 64 MiB runs in
560.8 ms against the old 618.9 ms — the conformance fix made signing large
messages **9.4 % faster** than the interface it replaced, and the legacy path
pays nothing measurable. It also removes an `AMA_ERROR_MEMORY` failure mode
and an attacker influence over allocator state from the signing path, which is
the reasoning `sha2_HT`'s fixed stack buffer already recorded one level down.
That was the last heap use in `src/c/ama_slhdsa.c`: the file no longer includes
`<stdlib.h>`, so SLH-DSA keygen, signing and verification run entirely on fixed
stack buffers and adding an allocation back has to be a deliberate edit.

---

## INVARIANT-51 — An Ed25519 Signer Derives Its Own Public Half

**Statement.** No Ed25519 signing entry point in this library hashes a public
half into `H(R ‖ A ‖ M)` that its own secret scalar did not generate.
`ama_ed25519_sign` must derive `A = [a]B` from the scalar it computed and
refuse any 64-byte secret key whose stored bytes 32..63 differ from it.
`ama_ed25519_expand_secret_key` must perform the same derivation and refusal
once, at load, and bind the scalar, the nonce prefix and `A` under a tag that
`ama_ed25519_sign_expanded` must re-verify on every signature, refusing an
expanded key whose tag disagrees. Refusal on every path is
`AMA_ERROR_INVALID_PARAM` with the output written as zeros (64 signature
bytes, or the 128 expanded bytes), never left untouched.

**Why.** The 64-byte layout `seed ‖ A` carries `A` so that a signer can skip a
scalar multiplication, and implementations that trust it do exactly that; this
one treats it as a layout, not a cache. Trusting it is a private-key recovery hazard,
not a hygiene issue. `r = H(h[32..63] ‖ M)` depends on the seed and the message
alone, so two signatures over **one** message under two different `A` halves
share `R`, and

    s₁ − s₂ = (h₁ − h₂)·a  (mod L)

yields the private scalar outright. This is the "Taming the many EdDSAs" fault
hazard, shared with Go and libsodium. What made it worse here is that the
header documented the key layout in detail and said nothing about the integrity
requirement on bytes 32..63 (2026-09 audit, B-2) — so a caller storing the two
halves separately, rebuilding a key from a corrupted record, or copying 32
bytes from the wrong buffer produced exactly this input with no reason to think
it mattered. No fault injection is needed; ordinary storage corruption suffices.

**Two paths, one property.** The per-call path pays the derivation on every
signature and needs no state. The expanded path (2026-09-22) pays it once:
`ama_ed25519_expand_secret_key` derives `A`, refuses a disagreeing half by the
same masked comparison, and writes `a ‖ prefix ‖ A ‖ tag` with
`tag = SHA-512("AMA/Ed25519/expanded-key/v1" ‖ a ‖ prefix ‖ A)[0..31]`. The
tag is what lets the signer skip the derivation without re-opening the
hazard: `A` cannot change in that form — nor can `a` or `prefix` — without
the tag failing to verify, and the tag is a preimage-bound function of all
three, so a fault or a mis-copy that alters any bit of the 128 is refused.
A party able to rewrite the tag consistently can read `a` from the same
bytes and needs no fault. The expanded form is not a storage format: it holds
the scalar in the clear (the same secrecy class as the seed it is one SHA-512
from), it is documented as opaque, and its Python owner
(`pqc_backends.Ed25519SigningKey`) zeroes it on close and on collection.
There is still no opt-out: neither path can be asked to trust a stored half.

**Cost, measured rather than asserted.** The per-call check is one fixed-base
scalar multiplication — the same operation that computes `R` — so that path
does roughly twice the curve work. The tag check is two SHA-512 compressions.
Measured on 2026-09-22 (`build/bin/benchmark_c_raw`, median of 1,000, 63-byte
message, Intel Xeon @2.80GHz container, `taskset -c 0`):
`ama_ed25519_sign` **24,780 ns**, `ama_ed25519_sign_expanded` **13,613 ns**
(0.55×), `ama_ed25519_expand_secret_key` 12,632 ns once. Through the Python
API on the same host and harness as the regression floors: `ed25519_sign`
34,566–34,977 ops/s, `ed25519_sign_expanded` 55,524–55,728 ops/s (three runs),
0.62× the per-call time — the C ratio plus the ctypes call both paths share.
The earlier figures for this invariant (13,189 ns before the check, 23,915 ns
after, median over 3,000) were taken on a different host and are superseded
by the above as the record for the per-call cost. Verification is untouched.

**Enforcement.** `src/c/ama_ed25519.c`. Both entry points share
`ed25519_sign_core`, which takes the caller's verdict as a 0/~0 mask and
applies it at a single exit by masking the 64 output bytes and the return
code; the signature is computed unconditionally, so the instruction-count and
secret-taint lanes see one path whatever the key. The comparisons — the
derived `A` against the stored half, and the recomputed tag against the
stored one — are `ed25519_mismatch_mask32`: an XOR-accumulate with no
relational operator, laundered through `ama_ct_value_barrier_u64`. An earlier
revision of this paragraph said the comparison was `ama_consttime_memcmp`
placed before any buffer was allocated, and that refusal wrote no signature;
the shipped code has never done either — the first version branched and was
caught by the secret-taint lane, and the mask form that replaced it runs the
full computation and zeroes the output — so that text is withdrawn (§6.6).
The scalar, `derived_a`, the recomputed tag and every buffer the core writes
are scrubbed on every exit (INVARIANT-6).

**Verification.** `tests/test_ed25519_key_half_integrity.py` drives single-bit
flips at five positions across the public half, a half taken from a different
key, and an all-zero half, and asserts the two-signature transcript the attack
needs cannot be produced. `tests/c/test_ed25519_expanded.c` and
`tests/test_ed25519_expanded_key.py` do the same for the expanded path. The C
suite replays the RFC 8032 §7.1 vectors through it, checks byte-equality with
the per-call path over 32 keys and 20 message lengths that cross the 4 KiB
stack threshold, flips every one of the 1,024 expanded-key bits and requires
each to be refused, and drives refusal at load, all on both field backends. The
Python suite does the same through `Ed25519SigningKey`: the RFC vectors, four
fresh keys over an 18-length sweep, one bit flipped in each of the 128 bytes of
the buffer the object owns, the frozen oracle's 24 sign records, PyCA
cross-verification, and refusal at load with nothing retained.
Every assertion is a refusal or an inequality rather than a pinned signature:
a pinned value would also pass against a signer that had started returning a
constant. The positive controls — a well-formed key still signs and verifies,
and the RFC vectors reproduce — are what keep the rest non-vacuous. The
`ed25519-sign-expanded` targets of `tools/check_ghash_constant_time.py`
(instruction-count and secret-taint, on the test archive and on the shipped
shared object) hold the expanded entry point to the same 0/0 standard as
`ed25519-sign`.

---

## INVARIANT-52 — A Package Signature Covers the Whole Package

**Statement.** Every field a crypto package carries, and the *presence* of every
optional one, must be inside the signature that package presents as its
authenticity claim. The creator and the verifier must derive the signed bytes
from the same function, and a field that cannot be encoded into those bytes
must fail the signature rather than be silently omitted.

**Why.** `create_crypto_package` signed the `content` bytes. Everything around
the content — the add-on signatures, the KEM ciphertext, the timestamp token,
the metadata — was therefore outside the signature. *Corrupting* an add-on was
caught, because the verifier re-checks it; **removing** one was not, because
nothing said it had been there. The 2026-09 audit (A-2) measured the
consequence on a package built with every layer enabled and verified with
`expected_public_key` pinned: stripping the SLH-DSA signature, stripping the
ML-KEM ciphertext, replacing the timestamp token and rewriting the metadata all
returned `all_valid: True`. Ten of seventeen tamper cases were detected; seven
were not, and no key material was needed for any of them. That is a downgrade
attack on the project's central claim — the post-quantum layers could be
removed from an artefact and it still verified as fully valid.

The audit also observed that **no invariant governed what the package signature
must cover**, and that A-2 sat precisely in that hole. This invariant is the
hole filled.

The same defect class held on the legacy surface, where the HMAC covered
`content_hash` alone: `author`, `timestamp`, `version` and `ethical_vector`
were forgeable under a package whose every reported check passed — which
contradicted `ARCHITECTURE.md`'s claim that ethical metadata "cannot be
separated from cryptographic proofs".

**Enforcement.** `ama_cryptography/_package_transcript.py` is the encoding: a
type-tagged, length-prefixed, domain-separated form in which two different
packages cannot produce the same bytes. `crypto_api.package_transcript` is the
single extraction point — `create_crypto_package` assembles the package with a
placeholder signature, takes the transcript from the function the verifier will
call, and fills the real signature in, so the two views cannot drift apart.
`legacy_compat.build_package_transcript` does the same for `SIGNATURE_FORMAT_V3`
under separate `"signature"` and `"hmac"` purposes, and
`legacy_compat.recompute_ethical_hash` derives the ethical digest from the
vector rather than trusting the stored hex. `canonical()` raises `TypeError`
for a type it cannot represent: a value the transcript cannot bind is the exact
hole this closes, so it is refused at signing time rather than discovered by an
auditor.

Secrets are deliberately *not* in the transcript — `hmac_key`,
`hkdf_master_secret` and `kem_shared_secret` are each pinned through a public
commitment that is signed (`hmac_tag`, `derived_keys`, and
`metadata["kem_shared_secret_commitment"]`, a domain-separated SHA3-256 of the
KEM secret), and including them would make the transcript uncomputable from
the redacted form `to_dict()` emits. The KEM commitment was missing until
2026-09-23: the Kyber secret key and the shared secret were both unsigned, so
a substituted key together with the secret it decapsulates to left the KEM
layer passing. `derived_keys`
*is* included, and the reason is worth stating because binding the salt, info
and count alone looks sufficient and is not: an attacker who swaps
`hkdf_master_secret` and recomputes the derived keys to match leaves Layer 4
self-consistent and salt, info and count unchanged.

**Verification.** `tests/test_crypto_package_transcript.py` runs the audit's
tamper matrix as a parametrised test — eighteen cases on the modern package,
seven on the legacy one — with an untampered-clone control, because a clone that
quietly lost a field would make the whole matrix pass while proving nothing
(`copy.deepcopy` does exactly that here: `__getstate__` strips secrets). The
encoder's injectivity is tested separately and without a backend. Measured
against the code as it stood, seven of the seventeen and four of the six
returned success.

---

## INVARIANT-53 — A Documented Claim Must Resolve Against the Implementation

**Statement.** Every claim the tracked documentation makes about this library
must be **derivable from the library**, and a gate must derive it. That covers
four kinds of claim, each with its own oracle:

1. **Examples.** Every fenced `python` or `c` block on a user-facing page runs,
   compiles and links — or carries an explicit `pseudocode: <reason>` marker.
2. **Constructions.** Every security-relevant description — a fallback, a
   weighting, a threshold, a zeroing strategy, a symbol's existence — matches
   what the source does, with the expected value **parsed out of the source**
   rather than written into the gate.
3. **Public API.** Every documented import, signature, return type, context
   manager and exported symbol matches what a user can actually reach.
4. **Measurements.** Every published performance figure is re-derivable from a
   record that states the command, host, units, sampling and aggregation behind
   it.

**Why.** Documentation is not commentary on this library; for an integrator it
*is* the specification. When it disagrees with the code, either they build
against something that does not exist or they trust a property the code does
not provide — and both are defects in the deployment, not typos in a file.

The 2026-09 documentation-integrity pass found every one of those four kinds,
and the worst of them was an example:

```c
uint8_t sk[AMA_ED25519_SECRET_KEY_BYTES];   /* 64 */
ama_ed25519_keypair(pk, sk);
```

`ama_ed25519_keypair` does not generate the seed. The caller must place 32
bytes of CSPRNG output in `secret_key[0..31]` before the call — the header says
so in the `ama_ed25519_keypair` contract of [`include/ama_cryptography.h`](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/include/ama_cryptography.h),
and the first statement of `ama_ed25519_keypair` in `src/c/ama_ed25519.c` is
the line that reads them (`sha512(secret_key, 32, hash)`). That example, on the page a C consumer is
pointed at, minted an Ed25519 private key from uninitialised stack memory. It
compiled clean under `-Wall -Wextra -Werror` and printed `valid=1`.

<!-- claim-check: quoting-retired-wording -->
The rest were the same shape, smaller: `create_crypto_package(codes, helix,
kms)` raising `TypeError` because `author` has always been required;
`package['package_id']` subscripting a dataclass; `buf.data` inside
`with SecureBuffer(...) as buf`, where `__enter__` yields the bytearray;
`get_pqc_status()` documented as a dict with a worked JSON example, returning a
`PQCStatus` enum; `locked: bool = secure_mlock(...)` against a function that
returns `None` and raises on failure; `MASTER_OMNI_CODES`, a name that has
never existed, used thirteen times; an `extern` link recipe for
`ama_randombytes`, which `cmake/ama_exports.map` localises and which exports no
symbol; eight "always available" submodules of which five raise
`AttributeError`; a "pure Python HKDF fallback" for a combiner that raises
(INVARIANT-7); posture thresholds of 0.3/0.6/0.8 against 0.15/0.45/0.80, and a
three-signal weighting against a four-signal one; "AMA does not implement
HSS/LMS" while `ama_lms_verify` and `ama_hss_verify` were exported; and
"ML-DSA-65 signing (4.20 ms)" three lines below a table putting a whole package
creation at 2.17 ms.

**Do not weaken the implementation to make a document true.** Where a claim and
the code disagree, the code and the invariants are authoritative unless testing
shows the code defective. `secure_wipe()` is the one case in this pass where it
was: `CRYPTOGRAPHY.md` described memory barriers the three Python `for` loops
did not have, so the function now delegates to the native barrier-backed
`secure_memzero` — the claim was right about what the library should do, and
the code was what moved.

**Enforcement.** Four gates, run in `ci.yml`:

* `tools/check_doc_examples.py` — `security-checks` (Python and C against the
  build tree) and `c-consumer` (C against an *installed* prefix, under gcc and
  clang, which is the only place the documented `#include <ama_cryptography.h>`
  and pkg-config flags are the ones a downstream consumer gets). Every
  `python`/`c` block on a covered page must declare its mode; an unmarked block
  fails, which is what stops coverage decaying as pages grow. `c-run` blocks
  execute under `valgrind --track-origins=yes`, because compiling is not enough
  — the uninitialised-seed example compiles and succeeds, and only a memory
  checker can see it.
* `tools/check_crypto_construction_docs.py` — `security-checks`. Derives its
  authority with `ast` from `hybrid_combiner.py`, `adaptive_posture.py`,
  `equations.py`, `legacy_compat.py`, `src/c/ama_consttime.c` and
  `src/c/ama_lms.c`, so implementing a fallback stops the fallback rule firing
  on its own and changing a weight changes the weight the gate demands. It
  fails closed (exit 2) on a partial derivation: a gate that silently learns
  nothing reports green on everything. Its scan covers source comments and
  docstrings as well as prose — they drift identically and are read by the
  same people — and the four gate scripts and their test module are exempt by
  name, because a gate cannot be written without quoting what it rejects. That
  exemption list is checked at startup, so an entry outliving its file fails
  rather than quietly widening.
* `tools/check_public_api_docs.py` — `security-checks`, with
  `--require-library`. Bare-import reachability (measured in a fresh
  subprocess, because Python binds a submodule as a package attribute the
  moment anything in the process imports it), signatures, return types asserted
  from real calls, `__enter__` return values, the version script against
  `nm --dynamic` in both directions, and the per-architecture SIMD inventory.
* `tools/check_benchmark_claims.py` — `security-checks`. Re-derives every cell
  of the generated benchmark blocks, requires every floor cited in prose to
  exist in `baseline.json` or `arm-baseline.json`, requires the results record
  to carry reproduction provenance, and rejects a measured figure more than 8x
  its own floor as a units or identity error.

A **correction note** may quote the wording it retires — a reader cannot
otherwise tell what changed — but only behind an explicit
`<!-- claim-check: quoting-retired-wording -->` marker. A waiver that can be
inferred is a waiver that arrives by accident.

**Verification.** `tests/test_documentation_integrity_gates.py` pins all four
in both directions. The negative controls are not invented: each is the literal
text this pass removed, so a regression to any of them fails a named test.
Positive controls assert that the *corrected* wording passes, because a gate
nobody can satisfy is a gate that gets disabled.

**Why a gate and not just a correction.** INVARIANT-16's BIP32 case is the
precedent recorded in this document: that claim was corrected once
(CHANGELOG KM-HD-001), shipped with no gate, and came back in six places.
`tools/check_hd_interop_honesty.py` exists because of it.

---

_Maintained by Steel Security Advisors LLC._
_Last updated: 2026-09-19_
