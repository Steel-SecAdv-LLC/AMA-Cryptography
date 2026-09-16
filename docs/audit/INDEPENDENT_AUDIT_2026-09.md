# AMA Cryptography — Independent Engineering and Cryptographic Audit

| Property | Value |
|---|---|
| Subject | AMA Cryptography, branch `steel/systempqc-maint1` |
| Commit audited | `594bea4` |
| Declared version | 5.0.0 |
| Audit date | 2026-09-16 |
| Method | Static review plus build, execution and adversarial testing in an isolated sandbox |
| Classification | Public |

---

## 0. Scope, method and evidence standard

The repository was cloned, configured, built and executed. Nothing here rests on reading alone
unless it says so.

### What was built and run

| Activity | Result |
|---|---|
| CMake Release build, `AMA_USE_NATIVE_PQC=ON` | Clean; 17 warnings, all `-Wpedantic __int128` |
| `ctest` | 134 / 134 passed |
| `pytest` (full suite, 4 workers) | 7,700 passed, 1 failed, 47 skipped, 283 s |
| Cython extensions | 6 built and active |
| Gate scripts under `tools/` | 13 run by me, all pass; ~40 more run across the reviews |
| Differential harness vs Python standard library | 3,780 comparisons, 0 mismatches |
| Wycheproof corpus | 4,263 vectors, 0 failures |
| Adversarial probes written for this audit | 31 property checks plus five targeted exploit constructions |

### Evidence standard

Every finding carries one of three labels.

- **VERIFIED (this audit)** — reproduced by the author of this report, with the command output
  quoted or summarised.
- **VERIFIED (sub-review)** — reproduced by one of eleven parallel specialist reviews, with file
  and line evidence, consistent with what I checked independently.
- **REPORTED** — established by reading only, with the reasoning given.

Where evidence is insufficient, the report says so rather than guessing.

### Coverage

Eleven specialist reviews, all of which returned: symmetric primitives; Curve25519 and FROST;
Weierstrass ECDSA; ML-KEM and ML-DSA; SLH-DSA and LMS; C infrastructure, dispatch and build; the
high-level Python API and key management; Python parsers and protocol modules; the ctypes binding
layer; monitoring and adaptive posture; and test, CI and supply-chain infrastructure. Their
empirical work included independent oracle comparison (pycryptodome, hand-written Python
references), disassembly of the shipped Release object, Callgrind constant-time gates, ASan and
UBSan rebuilds, differential fuzzing of both DER parsers over 16,000 mutated encodings, and
exhaustive enumeration of several stated arithmetic bounds.

---

## 1. Executive summary

### Overall assessment

AMA Cryptography is a large, unusually disciplined and genuinely self-critical piece of
engineering — roughly 142,000 lines of C and headers, 40,000 of Python package code, 129,000 of
tests, 32,000 of gate tooling and 32,000 of documentation. It is not a typical self-published
cryptography project, and it should not be read as one.

The **primitive layer is in good shape**. Four specialist reviews covering the symmetric
primitives, the Weierstrass curves, the lattice schemes and the hash-based signatures each
reported **no Critical, High or Medium defect**, against substantial empirical work: byte-exact
replay of every available NIST vector, exhaustive enumeration of stated reduction bounds,
independent re-derivation of the Montgomery and zeta tables, disassembly confirming the ML-KEM
implicit-rejection path is branch-free in emitted code, and zero-drift Callgrind results across
eight key classes. The KyberSlash class is genuinely eliminated. The FIPS 204 hint-encoding
strictness rules — including the strictly-increasing rule most implementations omit — are all
present and enforced.

The **composition layer is where security is lost**, and the pattern is consistent enough to
state as the audit's central observation:

> **A control is established rigorously at one surface and assumed at a sibling surface that
> shares no code.**

This produced the majority of serious findings, independently, in five subsystems. A
buffer-capacity guard was written for one method of a four-method class, with a comment
explaining exactly why it was needed, and the three siblings with the identical argument shape got
nothing — a confirmed heap overflow. A signature covers the payload but not the metadata beside
it. `repr` was made secret-safe but `asdict` was not. A mock-mode fail-open was closed while the
disabled-mode fail-open one branch above it was not. A policy-flag hardening was applied to one
curve file and not its twin.

### Project maturity

**High, with a specific structural immaturity.** Build, test, CI, provenance and
documentation-honesty machinery are mature. The API surface is not: two incompatible package
formats with different trust models, ~9,000 lines of ctypes bindings in one module, and an
~8,000-line anomaly-detection and "ethical mathematics" layer inside a cryptographic library that
no cryptographic operation depends on.

### Security posture

**Good at the primitive layer; weak at the composition layer.** The places where security is
actually lost are the package format, the agent-binding policy layer, the FROST threshold
protocol, the session protocol, and the Python-to-C boundary.

### Cryptographic posture

**Sound algorithm selection, and — on unusually broad evidence — sound primitive implementation.**
The canonicalisation work (non-canonical `S`, non-canonical `y`, non-canonical ECDSA coordinates,
non-minimal DER, non-canonical `u`) is more thorough than most libraries attempt.

The cryptographic weaknesses are in the protocol and policy layers: a FROST implementation that
permits nonce reuse and never verifies signature shares; an Ed25519 verifier that accepts the
identity point as a public key, which I confirmed yields a universal forgery; a FIPS 205
conformance defect exposing the internal interface as production API; and an agent-binding feature
whose security claim does not match its construction.

### Production readiness

**Not yet, for the Python API surface or for FROST.** Seven findings must be fixed before any
deployment. None is deep or architectural; all are small, local changes.

---

## 2. Findings

Severity reflects impact on a deploying user, not effort to fix.

### 2.1 High

---

#### A-1 · Out-of-bounds heap write reachable from pure Python

**`AmaContext.sign`, `kem_encapsulate`, `kem_decapsulate` · VERIFIED (this audit), reproduced with SIGSEGV.**

`AmaContext.keypair_generate` validates that a caller-declared output length actually fits the
supplied buffer via `_declared_length_fits()`, with a comment stating that without it "a caller
passing a 100-byte array with `public_key_len=1952` gets 1952 bytes written past it — heap
corruption reachable from pure Python". The three sibling methods take the same
`(buffer, declared_length)` shape and perform **no such check**.

With `AmaContext(AmaContext.ALG_ML_DSA_65)`, a 64-byte buffer and `signature_len = 3309`:

```
keygen rc: 0
signing into a 64-byte buffer, declaring 3309 ...
sign rc: 0 | siglen now: 3309
PROCESS EXIT=139   (SIGSEGV)
```

The call reported **success** and the process died. The C side (`src/c/ama_core.c` ~353) checks
only `*signature_len < AMA_ML_DSA_65_SIGNATURE_BYTES`, which a caller-declared 3309 satisfies
regardless of the real allocation.

**Impact.** Out-of-bounds heap write of up to ~3.2 KB (ML-DSA-65) or ~49 KB (SLH-DSA). Memory
corruption; potentially exploitable. **Exploitability.** Requires a caller deriving buffer size
and length argument from different sources. Not directly attacker-triggered, but the project's own
policy — written in the comment on the one guarded method — is that Python must refuse this.
**Root cause.** A guard applied to one method of a class, with nothing enforcing it class-wide.

**Remediation.** Apply `_declared_length_fits` in all three, returning `-1` as `keypair_generate`
does; better, factor one `_check_out_buffer()` helper. Add a gate asserting every
`(buffer, length)` pair passed to a native call is size-checked — the AST-gate machinery already
exists, and this is the one gate family that checks guard presence but not buffer sizing.

---

#### A-2 · Optional post-quantum layers can be silently removed from a signed package

**VERIFIED (this audit).**

`create_crypto_package` signs the `content` bytes, not a canonical encoding of the package.
Several fields beside the signature are unauthenticated, and — the serious part — an optional
layer that is present can be set to `None` and verification still reports total success.

Package with `use_sphincs=True, use_kyber=True, include_kem=True`, verified with
`expected_public_key` pinned. Baseline `all_valid=True`.

| Tamper | `all_valid` | Detected |
|---|---|---|
| `content` or `content_hash` altered | `False` | yes |
| `metadata["signature_algorithm"]` changed | `False` | yes (indirect — it selects the verifier) |
| all other `metadata` rewritten | **`True`** | **no** |
| `timestamp` replaced | **`True`** | **no** |
| `sphincs_signature` **stripped** (`None`) | **`True`** | **no** |
| `sphincs_signature` corrupted | `False` | yes |
| `kem_ciphertext` **stripped** (`None`) | **`True`** | **no** |
| `kem_shared_secret` replaced | `False` | yes |

Corrupting an add-on is caught. **Removing it is not.**

**Impact.** A downgrade attack on the project's central claim. An attacker who can modify a package
removes the SLH-DSA and ML-KEM layers and it still verifies as fully valid. Consumers acting on
`timestamp`, `metadata`, or the presence of the post-quantum add-ons can be fed attacker-chosen
values under an `all_valid` verdict. **Exploitability.** Anyone who can modify a stored or
transmitted package; no key material.

**Remediation.** Sign a canonical, length-prefixed transcript covering the content hash, algorithm
identifiers, embedded public keys, every add-on signature and ciphertext, the HKDF salt and info,
the timestamp token and the metadata. Until then, have the verifier take the expected layer set as
a caller parameter and fail when a promised layer is absent.

*Two independent sub-reviews found the same class in `legacy_compat`, where the HMAC covers only
`content_hash`, leaving `author`, `timestamp`, `version` and `ethical_vector` forgeable under a
valid HMAC, and `verify_crypto_package` never recomputes `ethical_hash` from `ethical_vector`.
That contradicts `ARCHITECTURE.md`'s claim that ethical metadata "cannot be separated from
cryptographic proofs".*

---

#### A-3 · Ed25519 accepts the identity point as a public key, yielding a universal forgery

**VERIFIED (this audit).**

Verification is cofactorless (`[s]B − R − [h]A = O`) and performs no order check on `A` or `R`.
With `A` = the identity encoding, the `h` term vanishes, so `(R = [s]B, S = s)` satisfies the
equation **for every message**. I constructed this with a pure-Python reference for
`s ∈ {1, 5, 12345}` — all below `L`, so the canonical-`S` check does not block them:

```
s=1, 5, 12345 -> ACCEPTED for all four test messages, under A = identity
```

One key-free signature, no secret, valid for every message.

**It reaches the package layer.** With `crypto_api` configured for `ED25519`, swapping the
package's embedded public key to the identity point and the signature to the forgery gives:

```
primary_signature: True, primary: True, core_valid: True
all_valid: False   <- only because key_pinned is False
```

**Impact.** "A signature verifies" no longer implies "the signer holds a secret" for any system
that accepts an attacker-supplied or attacker-registered public key — which is exactly what the
package format does, since it embeds its own public keys. `all_valid` saves the default path only
because it also requires `key_pinned`, and pinning is optional while `core_valid` and
`primary_signature` are offered as verdicts.

**Exploitability.** Requires the relying party to accept an attacker-chosen public key.
**Root cause.** RFC 8032 does not mandate small-order rejection, so this is a defensible policy —
but it is undocumented, and the surrounding API hands attacker-supplied keys to it.

A sub-review additionally measured that cofactorless verification **rejects** the torsion-shifted
key `A+T8` (0 of 400 accepted), so the "one signature valid under several public keys" trick that
cofactored verifiers admit does not work here. The identity case is the gap.

**Remediation.** Reject small-order `A` and `R` — an order check, or a byte-blocklist of the 14
small-order encodings. Document the cofactorless choice and its interoperability consequence in
`INVARIANTS.md` and the public header. Correct `tests/c/test_ed25519_verify_equiv.c`, which
describes the verifier as "cofactored". Make `expected_public_key` mandatory, or stop reporting
`core_valid` as a verdict when the key is unpinned.

---

#### A-4 · FROST: nonce reuse recovers the participant's secret share, and the API permits it

**VERIFIED (sub-review), with a working algebraic recovery.**

`ama_frost_round2_sign` takes `nonce_pair` as `const uint8_t *`, holds no state, and does not
consume, mark or zeroize it. Calling it repeatedly with the same nonce pair on different messages
returns `AMA_SUCCESS` every time. Each call emits `z = d + e·rho + (λ·s)·c` with `rho` and `c`
varying per message and `(d, e, λ·s)` fixed — three calls give three independent linear equations
in three unknowns mod `l`. The sub-review solved the system and reported:

```
recovered d == hiding nonce  : True
recovered e == binding nonce : True
recovered secret share s_1   : True
```

**Impact.** Full recovery of the participant's long-term secret share. With `t` shares recovered
this way the group secret is reconstructible. **Exploitability.** Requires a participant to sign
three messages under one nonce pair — reachable through ordinary API misuse: a cached round-1
result, a retry of a failed round 2 against a different message, or a coordinator that requests
re-signing. The partial signatures are protocol outputs, so no host access is needed.
**Root cause.** A stateless API with a caller-owned `const` nonce pair. `SECURITY.md` documents
the *repeating-CSPRNG* hazard as a deployment obligation; neither it nor the header warns that the
API itself permits reuse in a single healthy process.

**Remediation.** Make the nonce pair single-use inside the library: take it non-`const`, zeroize
on every exit from round 2, and fail closed on an all-zero pair. Document the one-shot contract.

---

#### A-5 · FROST: `ama_frost_aggregate` never verifies signature shares

**VERIFIED (sub-review).**

Aggregation sums `z_i` mod `l`, concatenates with `R`, and returns `AMA_SUCCESS` unconditionally.
RFC 9591 §5.3 requires the coordinator to verify each share so a bad one is rejected *and
attributed*. There is no share-verification entry point in the API at all. Flipping one bit of a
share gives `aggregate rc=0` and then `ed25519_verify -> -4`.

**Impact.** A single malicious or faulty participant silently produces a garbage aggregate with no
attribution — identifiable abort, the main robustness property FROST's round structure buys, is
lost. A caller trusting the return code emits an invalid signature. Combined with A-4, a
coordinator that can induce repeated signing has both the means to break the ceremony and to
harvest the partials. **Exploitability.** Trivial for any participant.

**Remediation.** Implement per-share verification, return an error naming the offending index, and
export a standalone share-verification function. At minimum, verify the aggregate against the
group key before returning success.

---

#### A-6 · Agent-instance binding: the authority key gates policy but does not key the derivation

**VERIFIED (this audit).**

INVARIANT-30 and `README.md` state that the layer "cryptographically forbids long-lived
persistence material and successor-authorizing signatures unless a human-held operator key
authorizes them". `K_auth` authenticates the binding *record* via an HMAC tag checked by the
policy gate. It is **not** an input to the key derivation, the canonical encoding is public, and
`encode()` is callable on an unauthorized binding.

Restricted binding (`PERSISTENT` + `PERSISTENCE`), `K_auth` withheld:

```
unauthorized derive_key                                    -> EthicalBindingError  (gate works)
authorized derive_key                                      -> K
native_hkdf(ikm, 32, salt, encode() + u32be(len) + info)   ==  K     True   <- no K_auth
signing_context()  ==  SHA3-256(0x02 || encode())                    True
encode() on an unauthorized binding == authorized encoding           True
```

**Impact.** The threat model for this feature (`THREAT_MODEL.md` T3.6) is an autonomous agent with
**in-process access**. Against precisely that adversary the control is a policy gate that can be
stepped around, not a cryptographic one. **Exploitability.** Requires the ability to call
`native_hkdf` — the capability the agent this feature exists to constrain already has.

**Remediation.** Either mix `K_auth` into the HKDF salt or IKM so the derivation is genuinely
gated, or correct INVARIANT-30, `README.md`, `SECURITY.md` and `THREAT_MODEL.md` to say
"policy-gated at the C boundary". The second is a one-day change and restores the honesty standard
the project holds elsewhere; the first is the stronger fix.

*The C-side policy check itself is well built: a sub-review disassembled the shipped object and
confirmed the HMAC is computed on both the key-present and key-absent paths, the verdict is formed
with `sbb`/`neg`/`or`/`and` with no branch on the mask, and refusal writes no output. The defect is
in what the key is used **for**.*

---

#### A-7 · The long-lived release signing seed is exposed to unpinned PyPI build dependencies

**VERIFIED (sub-review).**

`release.yml` places `AMA_INTEGRITY_SIGNING_SEED_HEX` in the `cibuildwheel` step environment.
Three lines later that step runs `pip install 'cmake>=4.4.0' 'cython>=3.2.8' 'numpy>=1.24.0'` —
no hashes, no upper bounds, resolved fresh from PyPI at release time. `setup.py` spawns the signer
with `env = os.environ.copy()`, so the seed is in scope for CMake and every `setup.py` hook of
every build dependency and their transitive dependencies. `requirements-lock.txt` contains **zero**
hashes.

**Impact.** A single compromised release of `cmake`, `Cython`, `numpy` or anything they pull in
executes code in a process holding the **long-lived** release signing key — the private half of the
trust anchor compiled into every shipped shared object. Disclosure collapses INVARIANT-17: an
attacker could re-sign an arbitrarily modified tree and the import-time anchor check would accept
it. **Exploitability.** Requires compromising an upstream PyPI project, a demonstrated attack
class. No repository access needed. The window is every tag push.

**Remediation.** Move signing into a dedicated job consuming the wheel artefacts —
`tools/resign_wheel.py` already proves the shape. Regenerate the lock with `--generate-hashes` and
install with `--require-hashes`. The project's own INVARIANT-4 reasoning about mutable references
applies verbatim; it was applied exhaustively to GitHub Actions and not at all to PyPI.

---

#### A-8 · The integrity trust anchor is rooted in GitHub account control, with both approval gates documented as unconfigured

**VERIFIED (sub-review).**

The anchor is a repository variable compiled into the native library; its private half is a
repository secret. Anyone who can push a `v*` tag, add a workflow, or holds org-owner or admin
rights can exfiltrate it in one run and mint signatures indefinitely. `release.yml` relies on two
environment approval gates and says, in its own comments, that neither enforces:

> "referencing an environment does NOT by itself require approval … Until it is, the block
> documents the intended gate rather than enforcing it"

**Impact.** For the integrity system, "GitHub organisation compromise" and "forge any release that
verifies as authentic" are the same event. No offline key; no rotation path preserving
verifiability of prior releases.

**What genuinely survives** is the release *tag* signature: preflight runs `git verify-tag` against
the committed `allowed_signers` store and blocks on failure, and a test verifies the v4.0.0 tag on
every run with four negative controls. That is the strongest control in the pipeline and is
correctly separated from the anchor.

**Remediation.** Configure required reviewers on both environments — the workflow names this as the
fix. State in `SECURITY.md` that the anchor's security bound is GitHub organisation control, and
that the tag signature is what survives a compromise.

---

### 2.2 Medium

**B-1 · FIPS 205 internal interface is production API and cross-verifies with the external one.**
*VERIFIED (this audit).* `ama_sphincs_sign`/`_verify`, the generic `ama_sign`/`ama_verify` for
`AMA_ALG_SPHINCS_256F`, and `ama_slhdsa_sign_internal` sign the raw message with no
`0x00 ‖ len(ctx) ‖ ctx` prefix — FIPS 205 §9 internal functions, which the standard says shall not
be exposed to applications other than for testing. `ama_slhdsa_sign_internal` is exported from the
production object (`nm -D`). Both cross-directions verified under one key:

```
slhdsa_sign(M, ctx=b"")        accepted by sphincs_verify(b"\x00\x00" + M)   -> True
sphincs_sign(b"\x00\x01x" + M) accepted by slhdsa_verify(M, ctx=b"x")        -> True
```

Any component signing caller-influenced bytes through the legacy or generic API is a signing oracle
for FIPS 205 pure signatures on attacker-chosen `(ctx, M)` pairs under the same key. *Remediation:*
route the legacy and generic entry points through the §10.2 wrapper with empty context (a versioned
break); compile the internal signer only under `AMA_TESTING_MODE`, as the randombytes hook already
is.

**B-2 · Ed25519 signing trusts the caller-supplied public-key half.** *VERIFIED (sub-review).*
Signing recomputes the scalar and nonce from `secret_key[0..31]` but takes `A` verbatim from
`secret_key[32..63]` for `H(R‖A‖M)`, never checking `A = [a]B`. Since `r` depends only on the seed
and message, two signatures over one message with two different `A` halves share `R` and give
`s1 − s2 = (h1 − h2)·a mod l` — full private-scalar recovery. This is the classic "Taming the many
EdDSAs" fault hazard, shared with Go and libsodium, which is why it is Medium; the aggravating
factor is that the header documents the key layout in detail and says nothing about the integrity
requirement on bytes 32–63.

**B-3 · The production ML-DSA-65 signer is never byte-exact known-answer tested.**
*VERIFIED (sub-review).* No test compares a produced ML-DSA-65 signature to a NIST answer; the ACVP
attestation has keyGen and sigVer but no sigGen. `tests/kat/README.md` says "only the deterministic
ACVP groups are vendored", which is false for this file. ML-DSA-44 and -87 do have byte-exact
sigGen; 65 — the set shipped in `AMA_ALG_HYBRID`, in POST and as the Python default — does not.
*Note:* the lattice review subsequently replayed all 100 hedged records successfully using the
supplied `rnd`, so the implementation is correct today; the gap is that **nothing in CI does this**.

**B-4 · Posture-triggered key rotation is driven by unauthenticated, attacker-sized input.**
*VERIFIED (sub-review).* `verify_crypto_package` times the verify call and feeds it to the monitor
under a profile with `normalize_by_size: False`, so duration scales with attacker-chosen content
length. One oversized package produces a critical alert scoring exactly the HIGH threshold; three
evaluations later the controller rotates keys — one forced rotation per cooldown for as long as the
attacker submits. Not wired by default, which bounds it.

**B-5 · `CryptoPostureController` is not thread-safe.** *VERIFIED (sub-review).* No lock; eight
concurrent `evaluate_and_respond()` calls with a 300-second cooldown produced eight rotations.
Every documented throttle is bypassable under the concurrency the monitoring documentation
describes.

**B-6 · Session key hygiene: TTL expiry never wipes, and `asdict` emits both keys.**
*VERIFIED (sub-review).* Expiry sets `CLOSED` and raises without `_wipe_keys()`, and `close()`
early-returns on `CLOSED` — so after the first post-expiry call the AES-256 keys stay live for the
process lifetime and no later `close()` can scrub them. Separately, `repr=False` suppresses only
`__repr__`; `asdict()` serialises both keys and `__eq__` compares key material non-constant-time.

**B-7 · RFC 3161 "disabled" mode is a fail-open on the verification path.**
*VERIFIED (sub-review).* `verify_timestamp_binding` keys its disabled-mode branch off two fields of
the caller-supplied, unauthenticated `TimestampResult`, then checks only that the data hashes to a
value also taken from that result. An adversary controlling a stored result downgrades a real token
to `disabled` and still gets `True`. The module deliberately closed the same shape for mock tokens
one branch above.

**B-8 · `extract_tst_info` accepts trailing bytes at three nesting levels.**
*VERIFIED (sub-review).* The outer reader, the `[0] EXPLICIT` wrapper and the `SignedData` sequence
are never `finish()`ed, so one timestamp has an unbounded family of byte-distinct encodings that
all verify. The module argues this exact point for `parse_timestamp_response`, and the legacy
package stores tokens verbatim.

**B-9 · RFC 9881 `both`-arm round trip silently substitutes a different key.**
*VERIFIED (sub-review).* With consistency checks disabled an unvalidated seed is retained and then
preferred on export, so import → export → import replaces the key. RFC 9881 §8.2 requires rejecting
an inconsistent key.

**B-10 · PKCS#8 version INTEGER escapes the `KeyFormatError` boundary.** *VERIFIED (sub-review).*
The rejected version is formatted into the message before the range check, so a ~1.9 KB INTEGER
makes the error path raise `ValueError` past the documented narrow-exception contract. The same
class was fixed in three sibling call sites.

**B-11 · Unauthenticated dispatch cache and production-reachable `AMA_DISPATCH_ONLY`.**
*VERIFIED (sub-review).* `AMA_DISPATCH_CACHE_FILE` is validated only by a fingerprint derived from
public data, so anyone who can write the file pins every SIMD slot to its scalar fallback
persistently. `AMA_DISPATCH_ONLY` is compiled into the production library and zeroes the whole
dispatch table, moving AES-GCM off the hardware kernel — in an acknowledged table-S-box build that
is a genuine cache-timing exposure. Both are correctly disabled under `AT_SECURE`. *Remediation:*
check the cache file's owner on read, as the writer already does; compile `AMA_DISPATCH_ONLY` under
`AMA_TESTING_MODE`.

**B-12 · `_FORTIFY_SOURCE` downgraded from the toolchain default.** *VERIFIED (sub-review).*
`-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2` while GCC 13.3 defaults to 3. Level 3 extends checking to
runtime-sized allocations, which is most of this library's AEAD and parsing surface.

**B-13 · Handshake message 1 is replayable.** *VERIFIED (sub-review).* The responder is stateless:
a captured message 1 mints a fresh session indefinitely, each replay costing an ML-KEM
decapsulation plus an ML-DSA-65 signature from one recorded 3.2 KB frame. Key separation is
preserved, so this is resource exhaustion and absence of liveness proof, not key compromise.
Relatedly, the initiator's "ephemeral keypair" is generated, transmitted (1,600 bytes) and
discarded without contributing to key agreement, while the protocol name says `Noise_NK`.

**B-14 · `AmaContext.verify` returns an integer whose truthiness is inverted.**
*VERIFIED (sub-review).* It returns the raw error code: `0` valid, `-4` invalid. `if ctx.verify(...)`
accepts every forgery and rejects every genuine signature. It is the only `verify` in the ~9,000-line
module not returning `bool`.

**B-15 · The Cython fast path reintroduces the un-wipeable secret copy `_borrow` exists to
eliminate.** *VERIFIED (sub-review).* `dilithium_sign` and `native_ed25519_sign` call
`bytes(secret_key)` on the Cython path — the active path in the shipped build — leaving the
`_borrow` branch below it dead. A full 4,032-byte ML-DSA secret key is materialised as an immutable
object that cannot be zeroized.

**B-16 · Fuzzing and constant-time coverage have not kept pace with the primitive set.**
*VERIFIED (sub-review).* No fuzz harness reaches the NIST P-curve ECDSA and point parsers, the
LMS/HSS length-walker, ML-KEM 512/768, ML-DSA 44/87, or the RFC 3161 DER parser — the largest
attacker-controlled surfaces after secp256k1. On the constant-time side, ML-KEM keygen and
encapsulation, ML-DSA keygen, NIST-P ECDH, AEAD encryption and HKDF/HMAC-SHA3 have no deterministic
instrument and either no lane or an informational-only one.

**B-17 · Unpinned interop oracles and hashless dependency lock.** *VERIFIED (sub-review).*
`requirements-lock.txt` has no hashes; merge-critical lanes install `cryptography`, `pynacl` and
`pycryptodome` unpinned. These are the reference implementations AMA's differential correctness is
measured against. The linters, by contrast, are pinned exactly with a written rationale.

**B-18 · Required status checks cannot be verified from the repository.**
*VERIFIED (sub-review).* Nine aggregating gates and an entire invariant exist to make branch
protection tractable, and every gate carries a comment saying branch protection "should require only
this context". Nothing in-tree records what is actually required; `check_gate_coverage.py` proves
reachability, not requiredness. If `ci-gate` is not in the required list, all 84 jobs are advisory.
*Remediation:* commit the ruleset as JSON and gate on it — the repository already does exactly this
for `allowed_signers`.

### 2.3 Low

- **C-1 · A documented workflow turns the test suite red.** *VERIFIED (this audit).*
  `test_documented_source_paths_exist.py::test_the_allowlist_has_no_stale_entry` asserts that a
  run-produced path must **not exist on disk**. Running `nist_vectors/run_vectors.py` — the
  documented ACVP harness — writes the gitignored `nist_vectors/results.json`, and the suite then
  fails. This was the single pytest failure in my run, caused by following the documented procedure.
  CI never sees it because the ACVP job runs no pytest. The assertion should test tracked-ness
  (`git ls-files`), not existence.
- **C-2 · ACVP attestation version drift.** *VERIFIED (this audit).*
  `acvp_attestation.json` declares `"version": "3.0.0"`, `"date": "2026-04-25"` while the library is
  5.0.0. Vector totals (1,215 / 1,215 over 12 algorithms) do match every documented claim, and
  `check_version_consistency.py` passes — it does not cover this artefact. The attestation prose
  also still says ML-KEM-512 and -768 "are not implemented"; they are.
- **C-3 · secp256k1 silently ignores unknown policy flag bits** where its NIST-curve twin rejects
  them and names this exact defect in a comment. Not presently exploitable, because secp256k1's
  default is the strict policy — the hazard is forward-looking. *VERIFIED (sub-review).*
- **C-4 · secp256k1's RFC 6979 loop has no failure signal.** `rfc6979_nonce` returns `void` and
  writes `k_out` only on success, over an uninitialised caller buffer; the NIST twin returns `int`
  and is checked. Exhaustion is at ~2^-128 per candidate over 1,024 candidates, so unreachable —
  but it is a two-line fix. *VERIFIED (sub-review).*
- **C-5 · `ama_hmac_sha256` performs no parameter validation and cannot report an error.**
  `void`-returning; `key == NULL` with `key_len > 64` dereferences NULL. Both symbols are exported
  and ctypes-facing, so a marshalling bug reaches this directly. *VERIFIED (sub-review) — SIGSEGV.*
- **C-6 · The AVX2 Poly1305 helpers are dead code and arithmetically wrong** (a 10-bit mask where 42
  is needed, and a fold constant of 5 where the 44-bit limb split requires 20). Unreachable as
  shipped; the file header still advertises them as used. *VERIFIED (sub-review).*
- **C-7 · `ama_consttime_copy` is lowered to CMOV, not the mask arithmetic the source writes.**
  This is the primitive selecting between the true shared secret and `J(z‖c)` in ML-KEM
  decapsulation. CMOV is branch-free and data-independent on current hardware, so no impact is
  observed; the guarantee now rests on a micro-architectural convention rather than the ALU-only
  sequence the author wrote. *VERIFIED (sub-review), by disassembly.*
- **C-8 · `dil_polyveck_make_hint` retains a secret-dependent branch and a secret-indexed store**,
  where `PROVENANCE.md` states the scans "no longer carry that index". The channel is weak
  (`hint[]` is 88 bytes) and applies to rejected attempts only. *VERIFIED (sub-review) at source
  level.*
- **C-9 · `fe64_add`/`fe64_sub` are not total**; correctness depends on `u`-canonicalisation, which
  the shipped X25519 path always performs. The comment's claim that "no attacker steers them there"
  is false for non-canonical `u`, which an attacker fully controls. Latent only. *VERIFIED
  (sub-review), with a concrete failing pair.*
- **C-10 · `HybridEncapsulation` renders the combined shared secret in its `repr`**, where both
  sibling types carry `repr=False`. *VERIFIED (sub-review).*
- **C-11 · `bool` passes integer range checks** everywhere except the two selectors that exclude it,
  so `native_hkdf(b"k", True)` returns one byte of key material. *VERIFIED (sub-review).*
- **C-12 · Wipeable `bytearray` storage is refused by several secret-bearing wrappers** with a raw
  `ctypes.ArgumentError`, forcing callers into the un-wipeable `bytes` copy INVARIANT-6 forbids.
  *VERIFIED (sub-review).*
- **C-13 · SHAKE and PBKDF2 place no upper bound on caller-controlled output length**, where Argon2
  and both HKDF families do. A 256 MiB PBKDF2 output was produced. *VERIFIED (sub-review).*
- **C-14 · Four symbols are exported but declared in no installed header**, including an AVX2 Keccak
  kernel with no CPUID gate at its own entry — resolving it by name on a non-AVX2 host yields
  SIGILL. `include/ama_cpuid.h` is not installed yet its twenty functions are exported.
  *VERIFIED (sub-review).*
- **C-15 · Benchmark hooks, backend override setters and the ACVP-internal signers are public ABI.**
  The override setters are unsynchronised writes to process-global state selecting the field
  backend. *VERIFIED (sub-review).*
- **C-16 · Docker images self-sign their own integrity artefact** with a per-build ephemeral key and
  no trust anchor, so a container consumer sees `OPERATIONAL` with a strictly weaker guarantee than
  a wheel's; and there is **no `.dockerignore`** while both images `COPY . .`.
  *VERIFIED (sub-review).*
- **C-17 · HD child-key derivation performs secret big-integer arithmetic in Python**
  (`(il_int + parent_key_int) % SECP256K1_N`), which INVARIANT-12 rule 1 prohibits. Path parsing
  also accepts `"m/2147483648"` as hardened and tolerates `"mfoo/1"`. *VERIFIED (sub-review).*
- **C-18 · `canonical_hash_code` float canonicalisation collides.** `f"{r:.10f}"` makes
  `(0.0, 1.0)` and `(1e-11, 1.0)` hash identically — a package created for one verifies for the
  other — while `-0.0` and `0.0` differ and `nan` is accepted. *VERIFIED (sub-review).*
- **C-19 · Finalizers record ordinary `AttributeError`s from a failed `__init__` into the
  finalizer-error counter**, devaluing a health signal. *VERIFIED (sub-review).*
- **C-20 · FROST is advertised as RFC 9591 in the public header** without the non-interoperability
  caveat the `.c` file states accurately (no ciphersuite contextString, no H1–H5 domain separation).
  *VERIFIED (sub-review).*

### 2.4 Informational

- **D-1 · The "ethical pillars" / double-helix / σ-quadratic / Lyapunov layer is cryptographically
  inert.** *VERIFIED (sub-review).* It enters cryptography in one place, the deprecated
  `legacy_compat` path, where a **constant** 16-byte label is appended to HKDF `info` — no more
  domain separation than any fixed string. `crypto_api` and `key_management` never reference it.
  `lyapunov_stability_proof` returned `stable=True` for 200 of 200 arbitrary states because
  `V̇ = −2λV` is asserted rather than derived; the σ-quadratic threshold never triggers. The
  runnable examples in `AMA_CRYPTOGRAPHY_ETHICAL_PILLARS.md` do not run — they use dataclass fields
  that do not exist. Its `P(detect) ≥ 0.999999` and `P(system_fail) ≤ 2^-512` are not sound
  derivations. The layer is neutral to security and positive to complexity, and its "proof"
  vocabulary sits uneasily beside INVARIANT-16's honesty standard.
- **D-2 · Measured 3R detection efficacy is below the trivial baseline for most cases.** The
  project's own `benchmarks/r3_efficacy.tsv` shows point-anomaly true-positive rates of 0.05–0.30
  against a z-score baseline of 0.255–0.80. `README.md` and `MONITORING.md` disclose this honestly;
  `ENHANCED_FEATURES.md` and the ethical-pillars document do not.
- **D-3 · Documentation drift.** `ENHANCED_FEATURES.md` states posture weights 50/30/20 and
  thresholds 0.3/0.6/0.8 where the code uses 45/25/15/15 and 0.15/0.45/0.80, and claims an "18–37×
  speedup … for cryptographic primitives" for Cython code no primitive executes. `README.md`'s
  legacy KAT table claims KeyGen/Sign/Verify coverage for six Round-3 corpora that are parsed and
  length-checked only. `PROVENANCE.md`'s clean-room claim does not accommodate several constructs
  that are structurally identical to the pq-crystals reference (the `dil_decompose` fixed-point
  reciprocals, the mod-5 folding, the Montgomery zeta tables) — these are the canonical instantiation
  and are re-derivable from the parameters, but "the text of the algorithm is the only shared
  artifact" is stronger than the code supports.
- **D-4 · `tools/verify_install_oob.py` is exercised by nothing in CI.** A 1,325-line stdlib-only
  verifier with hand-written SHA3-256, SHA-512 and Ed25519 plus startup known-answer tests including
  a negative control. It is the correct architectural answer to the checker-poisoning boundary and
  deserves a CI lane.
- **D-5 · Two parallel implementations of one replay window** (`session.py::ReplayWindow` and
  `SecureSession._replay_window`); the comprehensively tested one is the unused one.
- **D-6 · `AMA_KYBER_BUILD_DIAGNOSTICS` is a build-configuration invariant with no automated
  check.** ~780 lines of `printf` diagnostics are correctly gated off for production targets, and
  the threat-model note says production builds must not define it — nothing verifies that a release
  artefact does not.

---

## 3. Architecture assessment

### Strengths

1. **The gate culture is real and is the project's best asset.** Non-vacuity floors derived from
   measured values appear on nearly every gate, so a gate that stops seeing its subject fails rather
   than passing. Forty-two `*_gate*.py` modules supply negative controls. The stated principle — "a
   gate with no negative control has not been shown to be a gate at all" — is implemented.
2. **Fail-closed behaviour at the module boundary is genuine.** I verified that with no native
   library the import raises; that a corrupted power-on self-test vector fails the import because the
   signature covers those vectors; and that in the error state every native entry point, the Cython
   bindings and the health-tested random draw all refuse.
3. **The primitive implementations withstand scrutiny.** Four specialist reviews found no
   Critical/High/Medium defect between them, against exhaustive enumeration of stated bounds,
   independent table re-derivation, disassembly of constant-time claims, differential fuzzing of both
   DER parsers over 16,000 encodings, and byte-exact replay of every available NIST vector.
4. **Input canonicalisation is pursued relentlessly and correctly**, with the reject-or-reduce
   choice argued from the governing RFC in each case.
5. **Documentation self-correction is unusual and valuable.** Multiple comments and invariants
   retract a prior conclusion and explain why the reasoning was sound while the conclusion was false.
6. **Supply-chain controls on the GitHub side are complete**: 142 action pins, every one resolved
   upstream with its version comment verified; container bases digest-pinned with end-of-life dates.

### Weaknesses

1. **The composition layer is materially weaker than the primitive layer.** Every High finding
   except A-7 and A-8 lives in a composition: the package format, the binding policy layer, the FROST
   protocol, the Python-to-C boundary.
2. **Protocol-level constructions have not had the same scrutiny as the primitives.** FROST is
   missing share verification and nonce-reuse protection — properties RFC 9591 specifies. The secure
   channel generates an ephemeral keypair that contributes nothing.
3. **Two incompatible package formats with different trust models** both ship, both are exported,
   and the deprecated one is the `python -m ama_cryptography` entry point.
4. **The module boundary is not defined.** FIPS-style controls are properties of the Python package,
   not the shared object. The project documents this accurately in INVARIANT-41, but a C consumer
   taking the SONAME, pkg-config file and `Dockerfile.c-api` the project ships gets constant-time
   primitives and none of the rest.
5. **Cohesion.** ~8,000 lines of anomaly detection and "equation engine" mathematics sit inside a
   cryptographic library, are eagerly imported by `__init__`, create a directory under `$HOME` at
   import, and are needed by no cryptographic operation.
6. **Single-module sprawl.** `pqc_backends.py` is ~9,000 lines with ~150 public wrappers. Several
   findings are "a sweep applied to N−1 of N siblings", and siblings 3,000 lines apart do not get
   swept together.

### Long-term risks

1. **Hand-maintained inventories are the principal drift risk** — dispatch slot lists in five places,
   constant-time lane counts by hand, a frozen fuzz harness set. The project has been bitten here
   before and responded with a gate; the remaining lists are owed the same.
2. **Comment volume.** The prose-to-code ratio approaches 2:1 in the largest files. Mostly earned,
   but it raises the cost of every review, and a few comments have drifted from the code (the safegcd
   "defence in depth" section, the `fe64` probability claim, the `make_hint` side-channel claim).
3. **The trust anchor cannot be rotated** without invalidating verifiability of prior releases, and
   `SECURITY.md` records the tension without resolving it.

---

## 4. Invariant assessment

**Method.** All forty-seven invariants read. Every `tools/check_*.py`, `tests/test_*.py` and
`tests/c/test_*.c` path cited anywhere in the register was checked for existence; thirteen gate
scripts executed by me, ~40 more across the reviews.

**Headline: there is not one dangling enforcement reference across all forty-seven invariants.**
Every artefact the register names exists, and every gate run passes. That is a materially better
result than the register's own history would predict.

### Valid and enforced

Thirty-two invariants name a gate or test that exists and passes. INVARIANT-1 (the `hashlib`
boundary, pinned with exact per-file counts), -13 (suppression hygiene), -23 (the in-house secret
scanner with evasion resistance), -31 (gate reachability), -35 (selector strictness), -36 (corpus
originality), -37 (verification-claim honesty driven by a machine-readable capability table), -39
(error-state gating over 105 native plus 10 Cython entry points), -41 (pairwise consistency over 19
keygen paths) and -42 (declared ctypes ABI) are the strongest. INVARIANT-20 I verified directly:
configuring with `-DAMA_AES_CONSTTIME=OFF` alone fails at CMake configure with a `FATAL_ERROR`
naming the acknowledgement flag.

### Weak

- **INVARIANT-19 (hybrid KEM combiner) — security-critical by its own text, pinned by no transcript
  test.** *VERIFIED (this audit).* It lists nine must-preserve properties and references no gate and
  no test; `grep` finds **zero** references in `tests/`, `tools/` or `.github/workflows/`. No
  combiner known-answer vector exists anywhere in the test tree. A refactor reordering the salt
  components or dropping a length prefix would silently change every derived key. *Mitigating:* a
  sub-review re-derived the transcript from the RFCs and found the implementation byte-for-byte
  correct today. A regression-risk gap, not a present defect.
- **INVARIANT-30 (agent-instance binding).** Claims a cryptographic prohibition; provides a policy
  gate (A-6).
- **INVARIANT-16 (honest compliance claims).** Largely upheld and unusually well policed, but the
  ACVP attestation still declares version 3.0.0 (C-2), `README.md`'s legacy KAT table overstates
  coverage, and `PROVENANCE.md`'s clean-room claim is stronger than the code supports (D-3).
- **INVARIANT-12 (constant-time for secret-dependent operations).** Rule 1 forbids Python from
  implementing secret-dependent primitives; HD child-key derivation does modular arithmetic on the
  secret scalar in Python big integers (C-17).
- **INVARIANT-6 (secret zeroing on all exit paths).** Well enforced in C and the ctypes wrappers,
  undermined on the two hottest signing paths by the Cython `bytes(secret_key)` (B-15).
- **INVARIANT-35 (a selector must never resolve weaker than it was asked).** Enforced thoroughly for
  algorithm and curve selectors, and violated in spirit twice: secp256k1's ignored flag bits (C-3)
  and `nistp_hmac`'s `default:` arm mapping an unrecognised digest width onto SHA-512 — unreachable
  today because callers gate first, but literally the construct the invariant prohibits.

### Traceability gaps (enforced, but the register does not say where)

**INVARIANT-18** and **INVARIANT-21** have zero references in `tests/`, `tools/` or
`.github/workflows/`. Both are in fact enforced — INVARIANT-18 by `acvp_validation.yml`, which
cross-checks totals and per-algorithm counts against the attestation, and INVARIANT-21 in C, which I
confirmed at runtime by having all four low-order X25519 inputs rejected. Neither names its
invariant, so a reviewer cannot follow the register to the mechanism. Fifteen invariants cite
neither a tool nor a test file.

### Missing

1. **No invariant governs what the package signature must cover.** A-2 sits precisely in that hole.
2. **No invariant requires buffer-capacity validation at the Python/C boundary.** INVARIANT-5 covers
   fixed-size *input* buffers and integer ranges; nothing covers caller-declared *output* lengths.
   A-1 sits precisely in that hole.
3. **No invariant governs the threshold-signature protocol.** FROST has no invariant at all, and
   A-4 and A-5 are both properties RFC 9591 specifies.
4. **No invariant defines the cryptographic module boundary.** INVARIANT-41 notes the Python/C
   asymmetry in passing; it deserves to be its own stated invariant.
5. **No invariant requires a fuzz harness or a constant-time instrument per attacker-facing parser
   or secret-consuming entry point.** INVARIANT-33 requires a harness to be registered everywhere
   once it exists; neither it nor INVARIANT-12's addendum requires one to exist.

### Contradictory

None. No invariant contradicts another and none is impossible to satisfy. Two are **overly narrow**:
INVARIANT-33 governs registration but not existence, and INVARIANT-12's addendum governs SIMD slots
but not primitives.

---

## 5. Cryptographic assessment

### Approved decisions

- **Algorithm selection.** Every primitive maps to a current NIST or IETF specification, and the
  registry gate enforces that mapping before implementation is permitted.
- **Hash, MAC and KDF implementations.** *VERIFIED (this audit).* 3,780 differential comparisons
  against the Python standard library — **zero mismatches**. All three HKDF entry points correctly
  reject `L > 255·HashLen`. A sub-review independently confirmed AEAD correctness against
  pycryptodome across four build variants (AES-NI, bitsliced, table S-box, radix-2^26 Poly1305),
  all producing byte-identical output.
- **Known-pitfall coverage.** *VERIFIED (this audit).* Ed25519 rejects `S+L` malleated and 65-byte
  signatures; X25519 rejects all four low-order inputs; ML-KEM performs implicit rejection returning
  a deterministic value different from the true shared secret, rejects a wrong ciphertext length,
  rejects a decapsulation key with corrupted `H(ek)`, and applies the FIPS 203 §7.2 modulus check on
  all three parameter sets and every `ek` entry point; ML-DSA rejects a trailing byte, a context
  longer than 255, and a mismatched context.
- **Reduction-bound discipline.** A sub-review enumerated `dil_reduce32`'s image exhaustively and
  found it exactly as the comment claims, and confirmed `kyber_compress_d`'s Granlund–Montgomery
  reciprocal matches the FIPS 203 definition over all 16,645 `(x, d)` pairs. These are bounds that
  are proven rather than asserted.
- **The ECDSA low-`s` policy split.** INVARIANT-34's reasoning — normalisation without verifier
  rejection is "a costume" — is correct, and the per-curve defaults follow from what each curve is
  for. I confirmed the four-way truth table on P-256 at runtime; a sub-review confirmed it
  independently by observing which RFC 6979 vectors `REQUIRE_LOW_S` rejects.
- **Complete group-law formulas.** Both Weierstrass adders compute the general case, an
  unconditional doubling and an infinity, then mask-select — verified on all four curves including
  projectively-disguised `P == Q`.
- **The hybrid KEM combiner construction**, confirmed byte-for-byte against an independent RFC-derived
  reference.
- **Fail-closed CSPRNG handling and the continuous health test**, including hashing the health sample
  so live key material is not retained in module state.

### Questionable decisions

- **Accepting the identity point as an Ed25519 verification key** (A-3) — permitted by RFC 8032,
  undocumented, and reachable through an API that carries public keys inside the artefact.
- **A stateless FROST round-2 API with a `const` nonce pair** (A-4), and aggregation without share
  verification (A-5).
- **Exposing the FIPS 205 internal interface as production API** (B-1).
- **Signing `content` rather than a transcript** (A-2).
- **Deriving key material without the authority key in a construction documented as
  cryptographically gated** (A-6).
- **The `AMA_CRYPTO_LIB_PATH` override loading without digest verification.** Defensible as operator
  intent, correctly recorded as unverified with `fully_verified=False`, and correctly hard-failed
  under `AMA_FIPS_STRICT=1` — all verified. But the default posture lets a substituted backend run
  while the module reports `OPERATIONAL`.
- **The ethical-vector-in-HKDF-info construction** (D-1): a constant label presented as cryptographic
  binding.

### Required changes before release

1. Output-buffer validation in `AmaContext.sign`, `kem_encapsulate`, `kem_decapsulate` (A-1).
2. A canonical authenticated transcript for the package, or at minimum failure on a stripped
   promised layer (A-2).
3. Small-order rejection for Ed25519 `A` and `R`, or mandatory key pinning at the package layer
   (A-3).
4. Single-use nonce enforcement and share verification in FROST (A-4, A-5).
5. Key the agent-binding derivation with `K_auth`, or correct the claim (A-6).
6. Move the release signing seed out of the wheel-build environment; hash-pin the lock (A-7).
7. Route the legacy and generic SLH-DSA entry points through the §10.2 wrapper; restrict the
   internal signer to testing builds (B-1).

### Future hardening opportunities

- Deterministic constant-time instruments for ML-KEM encapsulation and keygen, ML-DSA keygen,
  NIST-P ECDH and AEAD encryption; an object-level gate asserting no CMOV on a secret verdict (C-7).
- Fuzz harnesses for the NIST P-curve parsers, LMS/HSS, ML-KEM 512/768, ML-DSA 44/87 and RFC 3161.
- A transcript known-answer vector for the hybrid combiner (INVARIANT-19), and a byte-exact ML-DSA-65
  sigGen KAT in CI (B-3).
- Running the vendored Wycheproof AEAD/HMAC/HKDF corpora through the C API — they are present and
  largely undriven from C.
- An approved SP 800-90A DRBG inside the module boundary with SP 800-90B health tests, which
  `CSRC_STANDARDS.md` §3.1(e) already identifies as a CMVP prerequisite and honestly records as
  absent.
- Forward secrecy in the secure channel: the ephemeral keypair is generated, transmitted and
  discarded without contributing to key agreement.

---

## 6. Completion assessment

The standard posed: *has the project reached the point where only future cryptographic advances,
hardware evolution, dependency changes, or newly discovered vulnerabilities would necessitate
further modification?*

**It has not, and the gap is smaller than the length of this report suggests.**

### 6.1 What prevents this project from being considered complete?

1. **Confirmed defects that are not theoretical.** A heap overflow reproducible from pure Python with
   a SIGSEGV; a post-quantum layer removable from a signed package without detection; a universal
   Ed25519 forgery under an attacker-chosen public key that reaches the package layer; a FROST
   implementation whose secret share falls out of three signatures under one nonce pair. I reproduced
   the first three personally; the fourth came with a working algebraic recovery.
2. **The composition layer has not received the rigour the primitive layer has.** The package
   format — the artefact the library exists to produce — has no canonical authenticated transcript
   and no invariant governing one. FROST lacks two properties RFC 9591 specifies.
3. **Coverage asymmetry.** The newest primitives received vectors and negatives but no fuzz harnesses
   and no constant-time instruments, and the production ML-DSA-65 signer has no byte-exact test in CI.
4. **Scope not closed or removed.** RFC 3161 attestation is scoped, documented and unimplemented —
   handled with exemplary honesty, but unfinished by the project's own account. The monitoring and
   ethical-mathematics layer is neither load-bearing nor removed.

### 6.2 What prevents production deployment?

For the **Python API**: A-1, A-2, A-3, A-6. Memory corruption; a defeated defence-in-depth claim; a
forgery under an unpinned key; a containment control that does not hold against its named adversary.

For **FROST**: A-4 and A-5. Neither should be deployed in a threshold ceremony as it stands.

For the **release pipeline**: A-7 and A-8. The long-lived signing key is exposed to unpinned
third-party code on every tag push, and both approval barriers are documented in the workflow as not
configured.

For a **C consumer** linking the shared object directly: the primitives are in good shape, but the
consumer must understand that power-on self-tests, error-state inhibition and pairwise consistency
are not properties of the object they linked. The project documents this correctly; deployment
requires acting on it.

### 6.3 What unresolved risks remain?

- **Trust-root concentration.** The integrity anchor's security bound is GitHub organisation control,
  with no offline key and no rotation path (A-8).
- **Unverifiable branch protection.** The entire gate architecture terminates in account-level state
  no in-tree check can confirm (B-18).
- **Constant-time evidence is partial.** The apparatus is statistically sound and self-tested, but its
  effect-size floor applies to the per-class mean, so a large but rare secret-dependent event reads as
  sub-floor; most lanes contrast two fixed inputs rather than fixed-vs-random; and several
  secret-consuming paths have no deterministic instrument at all (B-16).
- **No external audit.** The project states this plainly, and this review does not substitute for one.
- **PQC maturity.** Correctly recorded as a residual risk in the threat model.

### 6.4 What changes are mandatory before release?

1. A-1 — output-buffer validation on the three unguarded `AmaContext` methods.
2. A-2 — authenticated transcript, or fail on a missing promised layer.
3. A-3 — small-order rejection, or mandatory key pinning.
4. A-4, A-5 — FROST single-use nonces and share verification.
5. A-6 — key the derivation, or correct the claim in four documents.
6. A-7 — remove the signing seed from the wheel-build environment; hash-pin the lock file.
7. A-8 — configure the two environment approvals; state the anchor's true security bound.
8. B-1 — stop exposing the FIPS 205 internal interface as production API.
9. B-2, B-6, B-7, B-14 — the Ed25519 key-half integrity check, session key wiping and serialisation,
   the timestamp disabled-mode fail-open, and the inverted `verify` return convention. Each is a
   handful of lines and each produces silent failure.

### 6.5 What changes are merely optional improvements?

- Splitting `pqc_backends.py` into a package and extracting the monitoring layer into a separate
  distribution. Both would materially reduce the "swept N−1 of N siblings" defect class; neither is
  required for correctness.
- The `_FORTIFY_SOURCE` level, the dispatch-cache ownership check, `.dockerignore`, the export-map
  additions, and the `__extension__` keyword that would make the build warning-clean.
- Deleting the broken dead AVX2 Poly1305 helpers and correcting the file header (C-6).
- Documentation drift in `ENHANCED_FEATURES.md`, the ethical-pillars document, the legacy KAT table
  and `PROVENANCE.md`'s clean-room wording.
- Relabelling the "proofs" in the ethical-mathematics documentation as design rationale.
- A CI lane for `tools/verify_install_oob.py`.

---

## 7. Answer to the maturity question

AMA Cryptography is **closer to the described standard than most self-assessed cryptographic projects
ever get, and is not there.**

What it has achieved is rarer than the standard being asked about: a repository where claims are
mechanically checked, where gates fail closed and carry floors against vacuity, where documentation
records its own prior errors with the measurement that exposed them, and where an auditor can run
thirteen enforcement tools and have all thirteen pass. Four specialist reviews of the primitive layer
returned no finding above Informational, against work that included exhaustive bound enumeration and
disassembly of the shipped object. Most projects claiming this level of rigour do not survive the
first hour of the checking this one invites.

What it has not achieved is the property in the question. That property requires that no present
defect remains to be found by ordinary review — and ordinary review, over a single session, found a
reproducible heap overflow, a downgrade attack on the central architectural claim, a universal
signature forgery under an attacker-chosen key, a threshold-signature scheme that leaks its secret
share on nonce reuse, and a headline security feature whose documented guarantee its construction
does not provide.

The encouraging part is where those defects are. Not one is in the cryptographic arithmetic, which is
the hard part and which held up under sustained attack. They are in the seams: the boundary between
Python and C, the shape of a signed artefact, the policy layer over a sound primitive, a protocol
wrapper around a correct signature scheme. Every one is small, local, and already understood in
principle by the codebase that contains it — the guard exists one method away, the honesty standard
one document away, the pinning discipline one ecosystem away.

The work remaining is not research. It is finishing sweeps the project already started.

---

## 8. Limitations of this audit

- **One auditor, one session, with eleven delegated specialist reviews.** Not a substitute for a
  funded multi-week review by qualified cryptographers, which the project's own documentation
  correctly says production deployment requires.
- **The sub-reviews are model-generated.** Where their findings are load-bearing I reproduced them
  myself, and those carry "VERIFIED (this audit)". Findings labelled "VERIFIED (sub-review)" rest on
  that review's cited evidence and reported reproduction, which I read but did not re-execute in
  every case. In one instance a sub-review's claim was **too strong** and I corrected it: metadata is
  not wholly unauthenticated, because `signature_algorithm` selects the verifier and changing it is
  caught.
- **One platform.** x86-64 Linux, GCC 13.3, 4 cores. No ARM, no NEON, no SVE2, no AVX-512, no VAES,
  no macOS, no Windows, no MSVC. Fourteen ctest cases and 33 more in the symmetric review skipped for
  absent hardware. The SVE2 and NEON tiers rest on one QEMU workflow.
- **No timing measurement of substance by me.** I ran the import-time oracle under contention (eight
  runs, zero false positives) and read the apparatus. Sub-reviews ran the Callgrind gates; nobody ran
  the dudect campaign.
- **No network-dependent validation.** ACVP projections are fetched only in CI; ten of twelve
  algorithms ran zero vectors locally, and the harness correctly failed closed.
- **No review of released artefacts.** Everything here concerns source at commit `594bea4`. No
  published wheel, tag signature or container image was examined.
- **Not examined at all:** the Doxygen and Sphinx documentation builds, the benchmark suite's own
  correctness, the wiki, and the several thousand lines of test code not sampled.

---

*Prepared as an independent engineering and cryptographic assessment. No repository file outside
`docs/audit/` was modified in the course of this review.*
