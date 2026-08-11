# Security Policy

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 4.0.0 |
| Last Updated | 2026-08-01 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Overview

AMA Cryptography is a quantum-resistant cryptographic protection system released under the Apache License 2.0 as free and open-source software. As of v2.0, all production cryptographic primitives are implemented natively in C with zero runtime cryptographic dependencies. Security is our highest priority. We take all vulnerabilities seriously and appreciate responsible disclosure from the security research community.

---

## Supported Versions

We actively maintain and provide security updates for the following versions:

| Version | Supported | Status |
|---------|-----------|--------|
| 4.0.x | Yes | Active development and security updates |
| 3.5.x | No | Superseded by v4.0 (six breaking changes — see CHANGELOG `[4.0.0]`) |
| 3.4.x | No | Superseded by v3.5; no public API removals |
| 3.3.x | No | Superseded by v3.4; no public API removals |
| 3.2.x | No | Superseded by v3.3; no public API removals |
| 3.1.x | No | Superseded by v3.2; no public API removals |
| 3.0.x | No | Superseded by v3.1; no public API removals |
| 2.1.x | No | Superseded by v3.0 (legacy_compat Argon2id shim available for one-shot migration; see CHANGELOG `[3.0.0] → ### BREAKING`) |
| 2.0.x | No | Superseded by v2.1 |
| 1.0.x | No | Superseded by v2.0 |

---

## Security Features

AMA Cryptography implements defense-in-depth with multiple independent security layers — four core cryptographic operations supported by key derivation, plus an optional timestamp binding that is **not** an independent security layer (see item 6):

1. **SHA3-256 Content Hashing** (NIST FIPS 202)
2. **HMAC-SHA3-256 Authentication** (RFC 2104)
3. **Ed25519 Digital Signatures** (RFC 8032, C11 atomics hardened)
4. **ML-DSA-65 Quantum-Resistant Signatures** (NIST FIPS 204)
5. **HKDF-SHA3-256 Key Derivation** (RFC 5869, NIST SP 800-108)
6. **RFC 3161 Timestamp Binding** — *not an independent layer.* AMA verifies the §2.4.2 message-imprint binding only. It does not verify the TSA's CMS `SignerInfo` signature or validate its certificate chain, so an adversary who can supply a token satisfies this check unaided, with any `genTime` they choose, using no key. It contributes no adversarial resistance and must not be counted toward the security bound. See [INVARIANT-37](INVARIANTS.md#invariant-37--a-verification-api-must-not-claim-a-check-it-does-not-perform) and [ARCHITECTURE.md § Scope: RFC 3161 attestation is not implemented](ARCHITECTURE.md#scope-rfc-3161-attestation-is-not-implemented).

### Additional Cryptographic Capabilities

- **AES-256-GCM Authenticated Encryption** (NIST SP 800-38D)
- **ML-KEM-1024 Key Encapsulation** (NIST FIPS 203)
- **SLH-DSA-SHA2-256f and SLH-DSA-SHAKE-128s Hash-Based Signatures** (NIST FIPS 205)
- **Adaptive Cryptographic Posture System** (runtime threat-level response)
- **Hybrid KEM Combiner** (IND-CCA2 binding construction per Bindel et al.)
- **Agent-Instance Key/Signature Binding** (INVARIANT-30) — see below

### Agent-Instance Binding (INVARIANT-30)

An autonomous agent driving this library needs two cryptographic capabilities
to outlive its own instance: key material that persists, and signatures a later
instance would treat as authoritative. Ordinary per-message signing and
ephemeral session keys are neither.

A binding names an agent instance, the lifetime of the material it may derive
(`EPHEMERAL` / `SESSION` / `PERSISTENT`), and the capabilities it may exercise
(`DATA_SIGN`, `KEY_EXCHANGE`, `PERSISTENCE`, `SELF_REPLICATE`, `DELEGATE`). Any
non-`EPHEMERAL` lifetime or restricted capability requires a non-zero
ethical-profile hash **and** an `HMAC-SHA3-256` authorization tag verifying
under an operator-held authority key. The canonical 88-byte encoding is folded
into HKDF's `info` and into the ML-DSA / SLH-DSA signature context, so material
derived under one binding is cryptographically unrelated to the same input under
any other — including one differing in a single capability bit.

This is domain separation and policy over the existing SHA3-256 /
HMAC-SHA3-256 / HKDF primitives; **no new algorithm is introduced**
(INVARIANT-1 intact). Refusal is fail-closed: no output bytes, a distinct error
code (`AMA_ERROR_ETHICAL_BINDING` / `EthicalBindingError`), and no partial
state. The policy check is constant-time — verified by a strict dudect lane —
so neither *whether* nor *which* clause refused is observable by timing.

**Operational guidance.** Hold the authority key outside the reach of any agent
that calls the library (an HSM, a separate supervisor process, or an operator
workstation). The binding constrains derivations made *through* it: route
persistence-material derivation through a binding to realise the protection. It
is not a sandbox and does not restrain code that never calls this library.

Two advisory 3R detectors (`VolumeSpikeDetector`, `NoteArtifactDetector`, both
on by default) surface the corresponding runtime behaviour — operation bursts
and signed payloads shaped like instructions for a successor — for human
review. They never block an operation, and a negative result is not a statement
that a payload is benign.

### Performance — Framing

Throughput is a continuously-improving axis, not a ceiling.  On x86-64
AVX2 AMA's checked-in benchmark artifacts and generated reports provide the
only supported throughput claims; avoid quoting relative speedups unless the
source artifact and host class are named. Recent work (see `CHANGELOG.md` from v2.1 onward) added 4-way Keccak
batching, Ed25519 signed-window combs, merged-layer ML-DSA NTT, and
Ed25519 verify via Shamir/Straus joint scalar multiplication with a
width-5 wNAF — roughly doubling verify throughput.

#### What "2× verify" means in practice

Ed25519 verify dominates wall-clock time in three protocol families
that AMA consumers run at scale:

- **X.509 certificate-chain validation** (TLS handshake, code-signing).
  A typical chain is 3–4 certificates deep; each certificate signature
  is one Ed25519 verify.  Doubling per-verify throughput halves the
  CPU budget per chain validation, which on a busy gateway is the
  difference between handling N and 2N concurrent handshakes per core.
- **Noise Protocol Framework handshakes** (WireGuard, Lightning,
  Nym).  The XX, IK and IKpsk2 patterns each do at least one Ed25519
  verify of the responder's static key per handshake; mixed-PQ
  patterns (e.g. `Noise_XXhfs_25519+ML-KEM-1024_*`) keep the same
  verify on the classical leg.  Faster verify shortens the
  Diffie-Hellman-bound handshake critical path.
- **MLS (RFC 9420) group operations.**  Each Welcome / Commit
  message carries one or more Ed25519 signatures over the GroupContext
  and KeyPackages.  In a 1000-member group an Add/Remove can require
  verifying O(log N) signatures along the ratchet-tree path; verify
  speed sets the floor on group-rekey latency.

The change is purely algorithmic — same group-element math, no new
external dependency, no new dispatch slot — and is gated behind
`AMA_ED25519_VERIFY_SHAMIR` (default ON) and `AMA_ED25519_VERIFY_WINDOW`
(default 5) so a single recompile reverts to the prior layout if a
consumer needs the old throughput envelope for
deterministic regression purposes.

The deliberate choices that constitute AMA's security posture —
zero external cryptographic dependencies, in-tree constant-time
implementations audited under `INVARIANT-12`, and a vendored
build-from-source supply chain — auto-bound peak ops/sec against
libraries that lean on AVX-512 or hand-tuned assembly across 500 k+
LoC of audit surface.  Readers who value raw speed over supply-chain
minimalism are unlikely to be the target audience for this library;
readers who need auditable, small-surface post-quantum primitives
with headroom to keep improving should find the trade-off
acceptable.  Measured ops/sec numbers are in `benchmark-report.md`
and `benchmarks/README.md` — any claim to the contrary elsewhere in
the repository should be treated as aspirational and reported as a
documentation bug.

## Reporting a Vulnerability

### Critical Security Issues

If you discover a security vulnerability in AMA Cryptography, please report it responsibly:

**DO NOT** open a public GitHub issue for security vulnerabilities.

**Instead, please use one of the following private channels:**

1. **Preferred — GitHub Private Vulnerability Reporting:**
   [Open a private advisory](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/security/advisories/new).
   GitHub encrypts the report in transit and storage; no PGP key management
   is required on either side.
2. **Email fallback:** steel.sa.llc@gmail.com with subject `[SECURITY] AMA Cryptography Vulnerability Report`.

**Include in your report:**
   - Detailed description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Proof-of-concept code (if applicable)
   - Suggested remediation (if available)
   - Your contact information for follow-up

### What Constitutes a Security Vulnerability

We consider the following to be security vulnerabilities worthy of immediate attention:

**Critical:**
- Cryptographic primitive failures (hash collision, signature forgery)
- Key extraction or recovery attacks
- Authentication bypass
- Arbitrary code execution
- Privilege escalation
- Cryptographic oracle attacks

**High:**
- Side-channel attacks (timing, power analysis)
- Denial of service affecting cryptographic operations
- Information disclosure of sensitive cryptographic material
- Dependency vulnerabilities in cryptographic libraries

**Medium:**
- Input validation issues leading to unexpected behavior
- Insufficient entropy in key generation
- Weak random number generation
- Implementation deviations from cryptographic standards

**Low:**
- Documentation inconsistencies affecting security
- Missing security headers or best practices
- Informational security improvements

### Out of Scope

The following are generally **not** considered security vulnerabilities:

- Theoretical attacks requiring impractical computational resources (e.g., 2^128 operations)
- Issues in third-party dependencies (report to upstream maintainers)
- Social engineering attacks
- Physical access attacks on user systems
- Issues requiring user misconfiguration or ignoring documentation
- Performance or availability issues without security impact
- Missing features (use GitHub Issues instead)

## Response Timeline

We are committed to responding to security reports promptly:

| Severity | Initial Response | Status Update | Resolution Target |
|----------|-----------------|---------------|-------------------|
| Critical | 24 hours        | Every 48 hours | 7 days |
| High     | 48 hours        | Weekly | 30 days |
| Medium   | 5 business days | Bi-weekly | 60 days |
| Low      | 10 business days | Monthly | 90 days |

**Initial Response:** Acknowledgment of receipt and initial severity assessment
**Status Update:** Progress reports and estimated resolution timeline
**Resolution Target:** Expected timeframe for patch release (may vary based on complexity)

## Disclosure Policy

We follow **coordinated disclosure** principles:

1. **Report Received:** We acknowledge receipt within the timeframes above
2. **Validation:** We validate the vulnerability and assess severity
3. **Fix Development:** We develop and test a security patch
4. **Advisory Preparation:** We prepare a security advisory with CVE (if applicable)
5. **Coordinated Release:** We coordinate disclosure timing with the reporter
6. **Public Disclosure:** We publish the advisory and release the patch

**Typical disclosure timeline:** 90 days from initial report, or earlier if:
- A fix is available and tested
- The vulnerability is being actively exploited
- Other parties have independently discovered the issue
- The reporter and maintainers mutually agree

## Security Updates

Security updates are released as follows:

- **Critical vulnerabilities:** Emergency patch release within 7 days
- **High vulnerabilities:** Patch in next minor version (within 30 days)
- **Medium vulnerabilities:** Patch in next scheduled release
- **Low vulnerabilities:** Addressed in regular development cycle

Security advisories are published:
- GitHub Security Advisories (https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/security/advisories)
- Release notes with [SECURITY] tag
- Email notification to users who have starred the repository (when critical)

## Responsible Disclosure Recognition

We deeply appreciate security researchers who help keep AMA Cryptography secure. Reporters who follow responsible disclosure will be:

- **Credited** in the security advisory (unless anonymity is requested)
- **Acknowledged** in the CHANGELOG and release notes
- **Thanked** publicly on our GitHub repository
- **Recognized** in our Hall of Fame for significant contributions

We do not currently offer a bug bounty program but may consider recognition rewards for exceptional discoveries.

## Security Best Practices

Users deploying AMA Cryptography in production should:

### Key Management
- **REQUIRED:** Store master secrets in FIPS 140-2 Level 3+ HSMs for production
- **REQUIRED:** Implement key rotation every 90 days
- **REQUIRED:** Use hardware security modules (AWS CloudHSM, YubiKey, etc.)
- **NEVER:** Store private keys in plain text or version control
- **NEVER:** Reuse keys across different Omni-Code packages

### Zero-Dependency Architecture (v2.1)
- **REQUIRED:** Build native C library (`cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build`)
- All production cryptographic primitives (SHA3, HKDF, Ed25519, AES-256-GCM, ML-DSA-65, ML-KEM-1024, SLH-DSA, X25519, ChaCha20-Poly1305, Argon2id, secp256k1) are native C — no external cryptographic dependencies required
- Optional: numpy/scipy for 3R monitoring, PyKCS11 for HSM

### Cryptographic Operations
- **REQUIRED:** Build native PQC C library (`cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build`)
- **REQUIRED:** Enable all cryptographic layers (no fallbacks in production)
- **REQUIRED (if timestamps are relied upon):** Establish the token's issuer through a control *outside* AMA — an authenticated channel to the TSA, or out-of-band validation of the token before it is stored. AMA verifies the RFC 3161 §2.4.2 message-imprint binding only; configuring a reputable TSA has no verification consequence here, because no TSA signature is checked and a forged token is accepted identically (INVARIANT-37).
- **RECOMMENDED:** Use multiple TSAs for redundancy of *availability*. This is not redundancy of trust: AMA does not verify any of them.
- **RECOMMENDED:** Verify all signatures before trusting package contents

### Dependency Management
- **NOTE:** v2.0 has zero core cryptographic dependencies — all primitives are native C
- **REQUIRED:** Keep optional dependencies up to date (numpy, scipy, pynacl if used)
- **REQUIRED:** Enable Dependabot for automated security updates
- **RECOMMENDED:** Pin dependency versions for reproducible builds
- **RECOMMENDED:** Verify package signatures from PyPI

### Monitoring and Auditing
- **REQUIRED:** Log all cryptographic operations for audit trails
- **REQUIRED:** Monitor for signature verification failures
- **REQUIRED:** Alert on quantum library unavailability
- **RECOMMENDED:** Implement rate limiting for signature operations
- **RECOMMENDED:** Regular security audits of deployment configuration

## Module Integrity Verification (FIPS 140-3 §4.9.1)

### Threat model

The integrity check verifies that an installed wheel's `.py` files
**and its native library** have not been tampered with after build.  It
is **not** a supply-chain identity check (PyPI's existing PGP / sigstore
mechanisms cover that) and it does **not** prove anything about a
malicious build pipeline — both the digest and the signing key are
produced by the same build that produced the code being signed.  The
contract is:

1. The wheel build computes SHA3-256 over the package's `.py` files
   **and a second SHA3-256 over the native library
   (`libama_cryptography`) it is about to ship**, generates an
   **ephemeral, per-build Ed25519 key** by default (or uses
   `AMA_INTEGRITY_SIGNING_SEED_HEX` in release CI), and signs the
   **composite** `SHA3-256(domain ‖ py_digest ‖ native_digest)` — so the
   two digests are inseparable.  It embeds **the signature, the public
   verification key, and both digests** as Python literals in
   `ama_cryptography/_integrity_signature.py`, then **discards the
   private key** before publishing the wheel.
2. At import, `_self_test._verify_signed_integrity()` re-hashes the
   `.py` files, loads the embedded `(pubkey, signature)` pair, verifies
   the signature over the recomputed composite with `ama_ed25519_verify`
   from the in-tree C kernel (via ctypes — INVARIANT-1 forbids a PyCA
   dependency), and then **re-hashes the shared object it actually
   loaded and requires it to match the signed native digest**.  Any
   mismatch — edited `.py` file, edited `.so`, or a swapped signature —
   transitions the module to the ERROR state and refuses every
   cryptographic operation.

   Binding the native library closes the gap where the Python wrapper
   was tamper-evident but the code doing the cryptography was not: a
   back-doored `libama_cryptography` used to leave the `.py` digest, the
   signature and the trust anchor all verifying.  Because `_build_sign`
   can only produce a signature by calling the native `ama_ed25519_sign`,
   a working native library is present at signing time by construction,
   so every signed artefact carries the native digest — there is no
   unsigned-native downgrade path.  The one exception is an explicit
   `AMA_CRYPTO_LIB_PATH` override (see below): the operator has
   deliberately substituted the backend, so the loaded object is
   recorded as **unverified** (a warning, and `fully_verified` is
   `False`) rather than treated as tampering.

There is **no long-lived signing key in developer builds**.  Each
default build generates, signs once, and discards.  Release CI may
compile the expected public key into the native library with CMake's
`AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX` option and set
`AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR=1`; then the build signer refuses
to emit an artefact whose derived public key does not match the native
anchor, and the import-time verifier fails closed if the embedded
public key is not that anchor.  This gives release packaging a stable
trust-anchor gate without adding any external crypto dependency or
trusting mutable Python source for the anchor.

### `--update` is build-pipeline-only

`python -m ama_cryptography.integrity --update` is gated behind
`AMA_BUILD_PIPELINE=1`.  Users who modify `.py` files after install
must rebuild the wheel — running `--update` locally would silently
re-bless tampered code and defeat the tamper-detection contract.

### Implementation status

Both halves ship together in the AArch64-completeness PR (2026-05):

1. **`--update` gate** — `python -m ama_cryptography.integrity --update`
   requires `AMA_BUILD_PIPELINE=1` in the environment.  Outside that
   gate the command exits 2 with a remediation message.  See
   `ama_cryptography/integrity.py`.
2. **Signing pipeline** — `python -m ama_cryptography._build_sign`
    (invoked by the build pipeline, e.g. `setup.py` post-build hook /
    CMake post-install step / wheel CI workflow) generates an ephemeral
    Ed25519 keypair (or uses `AMA_INTEGRITY_SIGNING_SEED_HEX` in
    release CI) via the in-tree `ama_ed25519_keypair` C symbol
    (INVARIANT-1: no PyCA dependency), checks the resulting public key
    against the C-compiled trust anchor when one is present, signs the
    SHA3-256 digest with `ama_ed25519_sign`, writes
    `ama_cryptography/_integrity_signature.py` with the embedded pubkey
    + signature + digest, and discards the private key before exit.
    See `ama_cryptography/_build_sign.py`.
3. **Import-time verifier** — `_self_test._verify_integrity()` calls
    `_verify_signed_integrity()` first.  When the signature artefact is
    present (the normal post-wheel-build state), it recomputes the
    digest, reads any native trust anchor via
    `ama_integrity_trust_anchor_pubkey_hex()`, calls
    `ama_ed25519_verify` via ctypes with the embedded pubkey and
    signature, and accepts only on a positive verify plus trust-anchor
    match when configured.  When the artefact is absent (editable
    installs, source checkouts, wheels built without
    `AMA_BUILD_PIPELINE=1`), the behaviour depends on
    `AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR`:
    - **Unset (developer / editable / source-checkout path):** the
      module falls back to digest-only verification against
      `_integrity_digest.txt` with a logged WARNING.  Developer
      ergonomics do not require a full wheel build on every edit;
      packagers still see the missing signature in CI logs.
    - **`=1` (release path):** the module refuses to fall back and
      transitions to ERROR state — release wheels MUST ship the
      Ed25519-signed artefact or every crypto call is rejected.  This
      makes a forgotten `AMA_BUILD_PIPELINE=1` in the release pipeline
      a hard failure instead of a silent posture downgrade.

#### What the integrity check does and does not defend against

State this plainly, because the distinction decides whether the mechanism
is load-bearing for your deployment:

- **Detected:** accidental corruption, partial or interrupted installs,
  drift between the built wheel and the files on disk, and a tampered
  `.py` file when the attacker cannot also rewrite the signature
  artefact.
- **NOT detected without a compiled trust anchor:** deliberate tampering
  by anyone who can write to the installed package directory. The
  verifying public key is read from
  `ama_cryptography/_integrity_signature.py`, which sits beside the code
  it attests. An attacker who edits a module can regenerate the digest,
  sign it with a keypair of their own, and overwrite that artefact; the
  check then passes. Deleting the artefact instead falls back to
  `_integrity_digest.txt`, a plaintext file with no signature at all.
  This is inherent to any self-contained self-check — the anchor is what
  breaks the circularity.
- **NOT covered at all:** the native shared library. The digest is
  computed over the package's `.py` files only
  (`_self_test._compute_module_digest`), so a substituted or patched
  `libama_cryptography` is invisible to it. See the
  `AMA_CRYPTO_LIB_PATH` note below.

A build is only tamper-evident against a write-capable adversary when
`AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX` is compiled into the native
library (`CMakeLists.txt`) so the embedded pubkey must match an anchor
the attacker cannot rewrite by editing Python, and
`AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR=1` forbids the unsigned fallback.
**Neither is set by default**, so a stock developer build is in the
unanchored state described above.

#### Installing the signing key (anchored releases)

Generate the keypair with AMA's own Ed25519 kernel — no third-party
crypto tool is needed, and using one would contradict INVARIANT-1:

    umask 077
    python3 -c "
    from ama_cryptography.pqc_backends import native_ed25519_keypair
    pk, sk = native_ed25519_keypair()
    open('seed.txt','w').write(sk[:32].hex())
    print('PUBLIC KEY:', pk.hex())
    "

`native_ed25519_keypair()` returns a 64-byte secret key that is
`seed || public_key`; only the **32-byte seed** (`sk[:32]`) is the value
to store. Both stored values are exactly 64 hex characters.

Store them on the repository (Settings → Secrets and variables → Actions):

| Value | Kind | Name |
|---|---|---|
| the seed | **Secret** | `AMA_INTEGRITY_SIGNING_SEED_HEX` |
| the public key | **Variable** | `AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX` |

Then delete `seed.txt` and keep a copy of the seed somewhere durable: the
public half is compiled into published binaries, so the key cannot be
rotated without invalidating the anchor those releases expect.

Run the **Integrity anchor check** workflow (manual trigger) to confirm
the two are a matching pair before tagging a release; a mismatch is
otherwise only surfaced by a failing release build. `release.yml` picks
both up automatically and sets `AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR=1`
only when the anchor variable is non-empty, so forks and
not-yet-configured repositories continue to build unanchored wheels
rather than failing on a missing secret.

#### `AMA_CRYPTO_LIB_PATH`

This environment variable overrides the search for the native library and
loads the named shared object directly. It is a developer convenience for
pointing at an out-of-tree build, and it is a code-execution boundary: a
shared object runs its constructors the moment it is mapped, before the
power-on self-test executes. Because the override is by definition not the
signed, shipped object, the integrity check records the loaded library as
**unverified** (the signature over the artefact still verifies, but the
loaded bytes are not bound to it) — `module_attestation()["fully_verified"]`
is `False` and a warning names the override. Treat the ability to set it as
equivalent to the ability to run code in the process.

It is ignored, with a warning, when the process is running set-uid or
set-gid, matching the dynamic loader's refusal to honour `LD_PRELOAD` and
`LD_LIBRARY_PATH` in secure-execution mode. When it is honoured, the
override is logged at WARNING so a substituted backend is visible in
operational logs.

#### `LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH`

The native-library search also consults `LD_LIBRARY_PATH` /
`DYLD_LIBRARY_PATH`, which are caller-controlled and steer backend
selection with the same power as `AMA_CRYPTO_LIB_PATH`. The dynamic loader
strips these from a set-uid/set-gid or file-capability process before it
maps anything, but this module reads them directly with `os.getenv`, which
bypasses that stripping — so on a privileged binary a less-privileged
caller's `LD_LIBRARY_PATH` could otherwise steer the cryptographic backend
the loader had already protected. Under secure-execution mode these
variables are therefore ignored for backend discovery, with a WARNING,
matching the loader's own rule. On Windows the concept has no referent and
`PATH`-based DLL resolution is unaffected.

#### Partial or mismatched native builds

A shared object can export some primitives and not others — a build with
`AMA_USE_NATIVE_PQC=OFF`, a stale library from a previous major version, or
a cross-architecture mismatch. Such a library now surfaces the families it
does **not** provide in `native_backend_diagnostics()["missing_families"]`
and a one-time WARNING at import, rather than presenting as a clean load
with a scattering of unrelated failures at first use. The POST known-answer
tests additionally *call* each covered primitive (ML-KEM, ML-DSA, SLH-DSA,
Ed25519, SHA3-256, HMAC-SHA3-256, AES-256-GCM) on a fixed input, so a
mismatched ABI there produces a wrong answer the KAT catches — the check a
bare symbol-presence probe cannot perform. Under `AMA_FIPS_STRICT=1` a
missing covered family hard-fails POST via its skipped KAT.

End-to-end smoke test (from the AArch64-completeness PR's CI):

    AMA_BUILD_PIPELINE=1 python -m ama_cryptography.integrity --update --sign
    python -m ama_cryptography.integrity --verify   # → "OK (signed integrity verified, ...)"
    # Now edit a .py file and re-import WITHOUT re-running the signer:
    python -c "import ama_cryptography; ama_cryptography._self_test._run_self_tests()"
    # → ERROR state, all crypto operations refused
    # (Re-running the signer over the edited tree makes the check pass again —
    #  see "What the integrity check does and does not defend against" above.)

Release-anchor smoke test:

    export AMA_BUILD_PIPELINE=1
    export AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR=1
    export AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX=<32-byte expected Ed25519 pubkey hex>
    export AMA_INTEGRITY_SIGNING_SEED_HEX=<32-byte release signing seed hex>
    python -m ama_cryptography.integrity --update --sign
    AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR=1 python -m ama_cryptography.integrity --verify

The release job normally supplies the trust anchor via the compiled
`AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX` CMake option; the environment
form above is a reproducible local equivalent used by tests to prove
the strict path rejects unanchored artefacts.

### `AMA_FIPS_STRICT` — escalate skipped KATs to POST failure

Released wheels and FIPS-validated deployments should set
`AMA_FIPS_STRICT=1` so a missing backend cannot silently degrade the
approved-algorithm self-test set:

  * **Unset (default, developer / docs / CI matrix builds):** when a
    KAT cannot run because its backend is unavailable (e.g. SPHINCS+
    was not built into the C library), the POST runner logs a WARNING,
    records the skip with `passed=None` in
    `module_self_test_results()`, and continues.  Skip is NOT a pass —
    consumers filtering for "everything passed" must compare
    `passed is True`.
  * **`=1` (release / FIPS-validated path):** a skipped KAT is
    escalated to a hard POST failure.  The module enters ERROR state
    and refuses every cryptographic operation until the missing
    backend is built and the process restarted.  This makes a
    forgotten `cmake -DAMA_USE_NATIVE_PQC=ON` in the release build a
    visible failure rather than a silent posture downgrade.

The strict-mode flag applies uniformly to every KAT (SHA3-256,
HMAC-SHA3-256, AES-256-GCM, ML-KEM-1024, ML-DSA-65, SLH-DSA,
SLH-DSA-SHAKE-128s, Ed25519) and the constant-time timing oracle.

### `AMA_ALLOW_PYTHON_MEMZERO` — opt into best-effort Python memzero

`secure_memzero` refuses to operate when the native C
zero-on-erase backend is unavailable; the Python multi-pass loop is
opt-in via `AMA_ALLOW_PYTHON_MEMZERO=1` (development / test) or
`AMA_SPHINX_BUILD=1` / `SPHINX_BUILD=1` (docs builds).  Production
deployments should never need the opt-in because INVARIANT-7 already
refuses to import the library without the native HMAC/HKDF backend,
so the native memzero is also present.  The gate is defence-in-depth
against a partial-build state where the constant-time primitives are
linked but the secure-memzero symbol is not.

### Multi-process AES-GCM nonce safety

`AESGCMProvider.encrypt()` reserves its per-key counter slot
atomically via an inter-process file lock before any nonce is
generated or AEAD is invoked.  Concurrent processes sharing the
same AES-GCM key reserve disjoint slots — a previous race window
where two processes could load the same baseline and write back
`max(N+a, N+b)` instead of `N+a+b` is closed.  Ephemeral mode
(`configure_ephemeral(True)` or `ephemeral=True` in the constructor)
bypasses disk I/O for hermetic test runs; in that mode the
multi-process race surface is the same as the historical
single-process design and callers MUST partition keys per-process.
If the host cannot provide a working `fcntl.flock` (POSIX) or
`msvcrt.locking` (Windows) primitive, encryption fails closed instead
of logging and continuing with degraded nonce safety.

The persisted counter path no longer keeps a dirty counter or batching
interval: every successful reservation writes the `slot+1` high-water
mark atomically, so there is no deferred flush state to lose on crash.

### Secure-channel nonce budget per rekey epoch (INVARIANT-22)

INVARIANT-22 requires that exceeding a per-key nonce safety limit force
re-keying or hard failure, never a wrap, reset, or warn-and-continue.
`SecureSession` auto-generates a nonce per message and is therefore in scope.

`SecureSession.encrypt()` draws a fresh random 96-bit nonce for every
message, so nonce reuse within one `(key, rekey_epoch)` pair is a birthday
problem rather than a counter overflow: after n encryptions the collision
probability is about n² / 2⁹⁷.

`MAX_ENCRYPTIONS_PER_EPOCH` (2²⁰) bounds it, checked *before* the nonce is
drawn, and `encrypt()` raises `RekeyRequiredError` on reaching it. Recovery is
the caller's: call `rekey()` on **both** peers, or close the session. The
library deliberately does not rekey for you — the AEAD associated data binds
`rekey_epoch`, so a unilateral rekey desynchronises the pair and every
subsequent message fails authentication at the far end.

Crossing the advisory `REKEY_INTERVAL` (1000 messages, counting both
directions) logs one WARNING per epoch. The ceiling binds the sender only:
`decrypt()` generates no nonces, so enforcing it on receive would break a peer
running an older build without improving this side's margin.

### FROST nonce hedging — what it covers, and what it does not

Round-1 nonces are derived as
`SHA-512(label || random(32) || share_secret(32)) mod l`, so nonce secrecy does
not rest on the CSPRNG alone: an adversary who can *predict* the RNG output
still cannot compute the nonce without the participant's secret share. The two
nonces in a pair use distinct domain-separation labels and therefore cannot
collide with each other.

**It does not protect against an RNG that repeats.** The derivation is a pure
function of its three inputs and holds no state, so a participant handed the
same random bytes twice emits the identical nonce — a VM restored from a
snapshot, a fork inheriting a buffered pool, several hosts re-seeded from one
image. Two partial signatures over different messages under one Schnorr nonce
disclose that participant's secret share by subtraction, so an RNG replay is a
full compromise of the share, and no amount of hashing inside the derivation
can prevent it.

RFC 9591's own `nonce_generate` has the same property. Only per-signature state
would change it — a counter, or binding the message in — and neither is
available to a round-1 API that runs before the message is known. **Preventing
RNG-state rollback is therefore a deployment obligation**, not a property this
library provides: do not snapshot-and-restore a signing host, and do not clone
a VM image that has already signed. `tests/c/test_frost.c` pins the repeat
behaviour as a known limit so it cannot be mistaken for a defect later, or
quietly assumed away.

### Key-store KDF parameters are untrusted input

`.kdf_metadata.json` names the algorithm and cost that turn the master
password into the storage key, and it is an unauthenticated file in the key
directory. Anyone who can write it can name a cheaper derivation.

This does **not** expose keys already stored — those were encrypted under a key
derived with the old parameters, so a swapped file simply fails to decrypt
them. What it governs is every key written *afterwards*, and on a store that is
initialised but not yet populated the downgrade leaves no trace at all.

`SecureKeyStorage` therefore clamps the parameters from below on read and
raises `KDFPolicyError` rather than deriving a weak key:

| Parameter | Floor | Source |
|---|---|---|
| Algorithm | Argon2id, where the build provides it | this section |
| PBKDF2-HMAC-SHA256 iterations | 600,000 | OWASP 2024 |
| Argon2id `t_cost` | 3 | RFC 9106 §4 |
| Argon2id `m_cost` | 65536 KiB (64 MiB) | RFC 9106 §4 |
| Argon2id `parallelism` | 1 | RFC 9106 §4 |

The algorithm row is load-bearing and not a formality. Clamping costs *within*
an algorithm leaves the cheapest attack intact: name a different one. The
metadata's `version` field selects the Argon2id branch, so deleting that single
field re-routes derivation to PBKDF2 — and PBKDF2 at exactly 600,000 iterations
satisfies every cost floor above while discarding memory-hardness entirely,
which is the property Argon2id is chosen for and the one that costs a GPU or
ASIC attacker real money. On a build with native Argon2id, metadata naming
PBKDF2 is therefore refused. Builds without native Argon2id are unaffected,
because PBKDF2 is what such a build legitimately creates stores with.

Storage format v3 also binds the KDF parameters into the AEAD associated data
and records them in each key file. The parameters already influence the derived
key, so this adds *provenance*, not confidentiality: the recorded cost cannot
be edited without invalidating the tag, and a mismatch is reported as a named
`KDFPolicyError` rather than an unexplained authentication failure. Format v2
records (which bound `key_id` alone) are still read.

To open a genuine legacy store, pass `allow_legacy_kdf=True` — which warns
instead of raising — then call `migrate_kdf(password)` to re-encrypt at current
strength and reopen without the flag.

## Cryptographic Algorithm Security

### Current Algorithms

| Algorithm | Classical Security | Quantum Security | Status |
|-----------|-------------------|------------------|--------|
| SHA3-256 | 2^128 | 2^128 | ✓ Secure |
| HMAC-SHA3-256 | 2^128 | 2^128 | ✓ Secure |
| Ed25519 | 2^126 | ~10^7 gates* | ⚠ Quantum-vulnerable |
| ML-DSA-65 (Dilithium-3) | 2^207 | 2^192 | ✓ Quantum-secure |
| ML-KEM-1024 (Kyber) | 2^256 | 2^128 | ✓ Quantum-secure |
| SPHINCS+-SHA2-256f | 2^256 | 2^128 | ✓ Quantum-secure |
| AES-256-GCM | 2^256 | 2^128 | ✓ Quantum-secure |
| HKDF | 2^128 | 2^128 | ✓ Secure |
| X25519 | 2^128 | ~10^7 gates* | ⚠ Quantum-vulnerable |
| ChaCha20-Poly1305 | 2^256 | 2^128 | ✓ Quantum-secure |
| Argon2id | Memory-hard | Memory-hard | ✓ Secure |

*Ed25519 and X25519 are vulnerable to sufficiently large quantum computers, but ML-DSA-65 provides quantum-resistant backup.

### Cryptographic Deprecation Policy

We will deprecate cryptographic algorithms when:
- Practical attacks reduce security below 112-bit classical security
- NIST or other authoritative bodies recommend deprecation
- Quantum computers pose imminent threat to classical algorithms
- More efficient quantum-resistant alternatives become available

**30 days notice** will be provided before deprecating any algorithm, with migration guides and backwards compatibility support.

### Performance note on the VAES AES-GCM dispatch path (x86-64)

The library ships an optional VAES + VPCLMULQDQ AES-256-GCM kernel
(PR A, 2026-04) behind runtime CPUID + XCR0 gating
(`ama_cpuid_has_vaes_aesgcm()`). The VAES + VPCLMULQDQ AES-GCM path
targets **YMM (256-bit), not ZMM**: Zen 3+ / Ice Lake+ CPUs execute
these without the AVX-512 ZMM frequency penalty documented for
Skylake-SP / Cascade Lake. Cloud VM variance on shared hosts is still
the dominant noise source; published throughput numbers are from
bare-metal runs, not CI. Hosts without VAES — or any non-x86-64
host — automatically route through the AVX2 AES-NI + PCLMULQDQ path
shipped in #253 / #254 / #260 / #261, which remains the regression
baseline tracked in `benchmarks/baseline.json`.

## Security Audits

AMA Cryptography has undergone internal security analysis documented in this file. We welcome:

- Independent security audits from qualified cryptographers
- Academic review of our mathematical proofs
- Penetration testing of the implementation
- Code reviews focusing on cryptographic correctness

Please contact us at steel.sa.llc@gmail.com to coordinate security audit efforts.

## Compliance and Standards

AMA Cryptography is designed to comply with:

- **NIST FIPS 202** - SHA-3 Standard (SHA3-256, SHAKE128, SHAKE256)
- **NIST FIPS 203** - Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM / Kyber)
- **NIST FIPS 204** - Module-Lattice-Based Digital Signature Standard (ML-DSA / Dilithium)
- **NIST FIPS 205** - Stateless Hash-Based Digital Signature Standard (SLH-DSA / SPHINCS+)
- **NIST SP 800-38D** - Recommendation for Block Cipher Modes: GCM (AES-256-GCM)
- **NIST SP 800-108** - Recommendation for Key Derivation Using Pseudorandom Functions
- **NIST SP 800-57** - Recommendation for Key Management
- **RFC 2104** - HMAC: Keyed-Hashing for Message Authentication
- **RFC 5869** - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- **RFC 8032** - Edwards-Curve Digital Signature Algorithm (EdDSA)
- **RFC 3161** - Internet X.509 Public Key Infrastructure Time-Stamp Protocol

Non-compliance with these standards should be reported as a high-severity security issue.

## Contact

**Preferred channel:** [GitHub Private Vulnerability Reporting](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/security/advisories/new)
**Email fallback:** steel.sa.llc@gmail.com
**security.txt:** [`.well-known/security.txt`](.well-known/security.txt) (RFC 9116)
**Response Time:** 24-48 hours for critical issues
**Organization:** Steel Security Advisors LLC

## See Also

- [`docs/DESIGN_NOTES.md`](docs/DESIGN_NOTES.md) — Security arguments for original constructions (double-helix engine, adaptive posture, composition protocol)
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — System threat model and risk assessment
- [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md) — Cryptographic algorithm overview
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — System architecture and invariants
- [`CONSTANT_TIME_VERIFICATION.md`](CONSTANT_TIME_VERIFICATION.md) — Timing-side-channel validation
- [`.github/INVARIANTS.md`](.github/INVARIANTS.md) — Library invariants (canonical)

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-11-26 | Initial professional release |
| 1.1.0 | 2026-01-09 | Version alignment, terminology updates |
| 2.0.0 | 2026-03-08 | Zero-dependency native C architecture, FIPS 203/204/205 compliance, AES-256-GCM, adaptive posture system, hybrid KEM combiner, Ed25519 atomics hardening, Phase 2 primitives, fuzzing harnesses, threat model documentation |
| 2.1.0 | 2026-03-25 | Hand-written AVX2/NEON/SVE2 SIMD for 8 algorithms, runtime dispatch, security fixes S1-S6, bitsliced constant-time AES default |
| 2.1.5 | 2026-04-17 | Security audit fixes (length-prefixed HKDF encoding, constant-time ops, finding C6/C7/H2), HSM support via PyKCS11, fd leak protection (CodeQL #297), secure channel protocol v2 with `rekey_epoch` AAD, INVARIANT-13 restoration |
| 3.0.0 | 2026-04-27 | RFC 9106 Argon2id byte-identity fix (BREAKING — legacy verify-only shim provided) and `out_len` cap at `AMA_ARGON2ID_MAX_TAG_LEN = 1024`; in-house AVX-512 4-way Keccak permutation kernel (opt-in via `-DAMA_ENABLE_AVX512=ON`, XCR0 5+6+7 gated) with `docs/AVX512_KECCAK_ADR.md` ADR; X25519 fe64 (radix-2⁶⁴) ladder + hand-written MULX+ADX inline-asm kernel under BMI2∧ADX bundle gate; X25519 4-way AVX2 batch API (`ama_x25519_scalarmult_batch`, opt-in); VAES YMM AES-256-GCM; Ed25519 verify-path SWE rectification + base-point comb + merged NTT + AVX2 rejection; batch ML-DSA-65 / ML-KEM-1024 sampling via 4-way SHAKE; ChaCha20-Poly1305 AVX2 (≥ 512 B) and Argon2 BlaMka G AVX2; SHA-3 auto-tune hysteresis; NIST ACVP self-attestation (815/815 AFT) under continuous validation; D-1…D-10 distribution / tooling audit (wheel SONAME bundling, Cython/numpy build pins, `setuptools≥78.1.1` / `wheel≥0.46.2`, dudect AES-GCM tag-compare redesign, `.semgrep.yml` 341 FP → 0, X25519 dispatch-policy contract test, ed25519-donna fallthrough annotations) |
| 3.1.0 | 2026-05-14 | Security hygiene release documentation alignment for current consumers, v3.1.0 tag legitimacy, INVARIANT-14 CVE-ignore review, and no public API changes since v3.0.0 |
| 3.2.0 | 2026-05-20 | Mercury Agent v1.7.0 alignment; per-slot SIMD auto-tune + file-based cross-process dispatch cache with dispatch-cache safety; NTT benchmark overflow guard; dudect CI hygiene; native HMAC-SHA-256 Python bindings; no breaking public API changes |
| 3.3.0 | 2026-07-05 | Native one-shot SHA-256; documented public MAC/KDF surface (`quick_hmac` / `quick_hkdf`, native HMAC/HKDF SHA-2/3, `AmaCryptographyError` exception root); SLH-DSA-SHA2-256f signer consolidation; native-hashing purity in `crypto_api`; SLSA provenance permissions + CodeQL unused-static resolution |
| 3.4.0 | 2026-07-25 | Support matrix rolled (3.4.x active); vendored Wycheproof gate; Ed25519 canonical-`S` enforcement (INVARIANT-26) and X25519 u-coordinate canonicalization (INVARIANT-27); agent-instance binding (INVARIANT-30) with 3R detectors; Ascon-AEAD128/Hash256 (SP 800-232) |
| 3.5.0 | 2026-07-30 | Support matrix rolled (3.5.x active, 3.4.x superseded — no public API removals); INVARIANT-22 nonce-counter rollback residual risk documented; NIST P-256/384/521 ECDSA (FIPS 186-5, INVARIANT-34 low-`s` policy), ML-KEM/ML-DSA parameter sets, HSS/LMS verification enter the supported surface |

---

Copyright 2025-2026 Steel Security Advisors LLC. Licensed under Apache License 2.0.
