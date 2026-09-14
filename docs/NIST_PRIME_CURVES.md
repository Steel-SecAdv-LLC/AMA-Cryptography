# NIST prime curves — P-256, P-384, P-521

ECDSA (FIPS 186-5) and ECDH (SP 800-56A §5.7.1.2) over the three NIST prime
curves, implemented from specification in `src/c/ama_nistp.c` with zero external
crypto dependencies (INVARIANT-1).

## Why these curves are here

AMA already shipped Curve25519 (X25519, Ed25519) and secp256k1. Neither reaches
the ecosystems that gate adoption:

| Ecosystem | What it requires |
|---|---|
| TLS 1.2 / 1.3 | `secp256r1`, `secp384r1`, `secp521r1` key exchange and certificates |
| X.509 / PKIX | `id-ecPublicKey` with a NIST named curve (RFC 5480) |
| JOSE / JWT | `ES256`, `ES384`, `ES512` (RFC 7518 §3.4) |
| COSE / CBOR | `ES256`/`ES384`/`ES512`, EC2 key type (RFC 9053) |
| WebAuthn / FIDO2 | `ES256` over P-256, effectively universally |
| CNSA 1.0 | ECDSA and ECDH over P-384 |
| PKCS#11 HSM fleets | NIST curves are the common denominator |

Ed25519 covers a growing but disjoint slice (SSH, Sigstore, some of TLS 1.3);
secp256k1 covers blockchain and nothing else. The NIST prime curves were the
single largest interoperability gap in the library.

## Public surface

C: `include/ama_cryptography.h`, the `ama_nistp_*` family.
Python: `ama_cryptography.pqc_backends`, the `native_nistp_*` family.

```python
from ama_cryptography.pqc_backends import (
    native_nistp_keypair, native_nistp_ecdsa_sign, native_nistp_ecdsa_verify,
    native_nistp_ecdh, native_nistp_point_encode, native_nistp_point_decode,
)
import hashlib

pub, priv = native_nistp_keypair("P-256")   # public FIRST, as everywhere in AMA
digest = hashlib.sha256(b"message").digest()

der = native_nistp_ecdsa_sign("P-256", digest, priv)              # X.509 / TLS
raw = native_nistp_ecdsa_sign("P-256", digest, priv, raw=True)    # JWS / COSE
assert native_nistp_ecdsa_verify("P-256", der, digest, pub)

peer_pub, _peer_priv = native_nistp_keypair("P-256")
z = native_nistp_ecdh("P-256", priv, peer_pub)   # raw x-coordinate: feed to a KDF
```

Curve selectors accept `"P-256"`, `"secp256r1"` and `"prime256v1"` (and the
analogues for the other two), because callers arrive from ASN.1 OIDs, JWK `crv`
values and config files. An unrecognised name raises — silently defaulting to
P-256 would be the worst possible failure mode.

### Conventions

* A private key is `field_bytes` big-endian octets in `[1, n-1]`:
  32 (P-256), 48 (P-384), 66 (P-521).
* A public key is `2 * field_bytes` octets, `X || Y`, with **no** SEC 1 prefix —
  the same shape as the existing secp256k1 surface. Use
  `native_nistp_point_encode` / `_decode` to move to and from prefixed SEC 1
  (`0x04` uncompressed, `0x02`/`0x03` compressed).
* A signature is either DER or fixed-width `r || s`. Both are first class;
  `native_nistp_sig_der_to_raw` and `_raw_to_der` convert, re-validating range
  and encoding in both directions so a conversion cannot launder a malformed
  component into a well-formed one.
* Keypair functions return `(public, secret)` — public first, matching every
  other keypair function in AMA. `tests/test_keypair_conventions.py` asserts
  that ordering behaviourally across the whole library, by re-deriving the
  public key from the secret; an earlier revision of `native_nistp_keypair`
  had it reversed, which is one copy-paste away from publishing a private key.
* These functions never hash. Pass a digest of 32, 48 or 64 octets. The width
  also selects the RFC 6979 HMAC, as the RFC prescribes. A digest wider than the
  group order is truncated per FIPS 186-5, so signing a SHA-512 digest under
  P-256 is well defined and interoperable.

## Malleability posture (INVARIANT-34)

Low-`s` is a property of the **sign/verify pair**, and both halves are off by
default here.

Signing emits RFC 6979's `s` verbatim, so `ama_nistp_ecdsa_sign` reproduces the
RFC's own Appendix A.2.5/A.2.6/A.2.7 vectors byte-for-byte. Verification accepts
either representative, because X9.62, FIPS 186-5, TLS, X.509, JWS and WebAuthn
all permit either `s` and essentially none of their signers normalise — a
strict-by-default verifier would reject conformant third-party signatures,
which is precisely the adoption blocker this work exists to remove.

`AMA_NISTP_ECDSA_SIGN_LOW_S` and `AMA_NISTP_ECDSA_REQUIRE_LOW_S` turn both
halves on together. Setting only one is incoherent, and the first version of
this file did exactly that: it normalised on the signer while verifying
permissively. That combination prevents nothing — the twin of an AMA signature
still verified under AMA — and cost RFC 6979 conformance on roughly half of all
signatures while the header still claimed the RFC's name. See INVARIANT-34 for
the full account.

Everything that costs no interoperability stays unconditional in both modes:

* minimal DER only (short form, or the single long-form octet where a P-521 body
  genuinely exceeds 127 octets), minimal INTEGERs, no trailing bytes;
* `r` and `s` strictly in `[1, n-1]` — an out-of-range value is rejected, never
  reduced into range;
* public-key coordinates strictly in `[0, p)` — the INVARIANT-29 rule;
* the point on the curve and not the identity.

Callers who control both ends set `low_s=True` on the signer **and**
`require_low_s=True` on the verifier.

## Implementation

### One file, three curves

All three are short Weierstrass curves `y² = x³ − 3x + b` over a prime field
with cofactor 1. Only the modulus, group order, `b`, generator and operand width
differ, so the arithmetic is generic over a limb count and the curve is a `const`
parameter block. Three near-identical files would triple the audit surface for
zero capability. `ama_secp256k1.c` stays separate because it is a different curve
shape (`a = 0`, plus a Solinas prime that admits a curve-specific reduction a
generic path cannot express).

### Arithmetic

Montgomery form over 64-bit limbs with CIOS multiplication, rather than per-curve
Solinas reduction. The reduction chains for P-256/384/521 are three separate
bodies of subtle carry code; one generic, uniformly constant-time kernel is the
defensible trade at this stage. The cost is measured below and stated honestly
rather than hidden.

### Fixed-base comb for the generator

The generator is a public constant, so the doublings its scalar multiplication
performs can be done once at start-up instead of on every call — and doublings
are where the time went: the variable-base multiplier runs 132 windows × 4
doublings on P-521, and 528 doublings is most of a 2 ms operation.

`nistp_scalar_mul_generator` splits the scalar into four blocks and precomputes
every subset sum of the block-aligned multiples `2^(e·j)·G`. One pass over `e`
bit positions then does *one* doubling and *one* addition each: 131 and 131 on
P-521, against 528 and 132.

**Four blocks, not eight.** A comb's table has `2^blocks` entries and must be
read with a full linear scan to keep the access trace independent of the
scalar — the same requirement, for the same reason, as the variable-base
window. Doubling the block count halves the iterations and doubles the
per-iteration scan, so the win flattens while the constant-time cost grows.
Sixteen entries also keeps the scan *identical in shape* to the one already
reviewed, and the table at 3.5 KB per curve stays in L1 where a 56 KB one would
not.

**The generator only.** ECDH multiplies a peer-supplied point and keeps the
variable-base multiplier: precomputing for a base that changes every call buys
nothing, and a table built from attacker-supplied input is a surface this does
not need. The measurements below show exactly that split — every fixed-base
operation moves, ECDH and verification do not.

The comb is checked against the same naive double-and-add reference as the
windowed path, over the same boundary lattice, in `tests/c/test_nistp.c` — not
against the multiplier it replaced. A divergence would produce a public key that
is internally consistent and wrong: every self-round-trip would pass, and the
first thing to notice would be a peer.

Point arithmetic is Jacobian with the `a = −3` doubling formula. The addition
resolves **every** exceptional case branchlessly — either operand at infinity,
`P == Q`, `P == −Q` — by computing all candidates and selecting with masks. That
unconditional extra doubling is what lets the fixed-window scalar multiplier keep
the point at infinity in table slot 0 with no scalar-dependent special-casing.

### Timing posture

Constant time on every secret-dependent path: no secret-dependent branch and no
secret-dependent memory index in key generation, ECDSA signing, or ECDH. The
scalar multiplier is a fixed 4-bit window whose table is read with a full linear
scan — every one of the 16 entries is loaded and masked on every window, so the
memory-access trace is independent of the scalar. Field and scalar inversion use
Fermat exponentiation over the public exponents `p−2` / `n−2`.

The one data-dependent branch is RFC 6979's own nonce-rejection loop (§3.2 step
h.3), which every conformant signer shares. It fires with probability below
2⁻³² on these curves, and when it does the only fact it exposes is that one
discarded DRBG block landed above `n`. Reducing instead of rejecting would be a
silent divergence producing signatures no reference implementation matches.

Verification is variable time by design — every input is public. This matches
`ama_secp256k1_ecdsa_verify` and `ama_ed25519_batch_verify`.

### Measured cost

Single core, x86-64, `-O3 -flto`, generic Montgomery path. Median of 60 runs,
measured before and after the fixed-base comb on the same machine in the same
session:

| Curve | Operation | Before | After | Change |
|---|---|---:|---:|---:|
| P-256 | keygen | 0.334 ms | 0.183 ms | **1.83×** |
| P-256 | public key from private | 0.335 ms | 0.178 ms | **1.88×** |
| P-256 | sign | 0.377 ms | 0.217 ms | **1.74×** |
| P-256 | verify | 0.559 ms | 0.545 ms | — |
| P-256 | ECDH | 0.340 ms | 0.338 ms | — |
| P-384 | keygen | 0.811 ms | 0.467 ms | **1.74×** |
| P-384 | sign | 0.874 ms | 0.537 ms | **1.63×** |
| P-384 | verify | 1.360 ms | 1.376 ms | — |
| P-384 | ECDH | 0.798 ms | 0.803 ms | — |
| P-521 | keygen | 2.014 ms | 1.189 ms | **1.69×** |
| P-521 | sign | 2.244 ms | 1.398 ms | **1.61×** |
| P-521 | verify | 3.570 ms | 3.661 ms | — |
| P-521 | ECDH | 2.047 ms | 2.038 ms | — |

The shape of that table is the point. Every operation whose base is the fixed
generator — key generation, public-key derivation, the `k·G` in signing — moves
by 1.6–1.9×. Verification (Shamir's trick over two public points) and ECDH
(a peer-supplied base) do not move at all, which is what confirms the change is
scoped where it was meant to be rather than perturbing the field arithmetic.

Still slower than a curve-specialised implementation, and still stated rather
than elided. What remains, with an honest note on each:

* **Per-curve Solinas reduction.** The largest remaining win and the largest
  remaining audit surface: three separate bodies of subtle carry code against
  one generic kernel that is uniformly constant-time today. It needs its own
  differential campaign against the Montgomery path, which the existing
  `test_nistp` harness is the right place for.
* **Scalar blinding and coordinate randomisation.** Both consume entropy, and
  `ama_nistp_pubkey_from_privkey` is reachable from the *key-file parser* — the
  same path where `ama_ml_kem_privkey_check` was made deterministic in this
  branch precisely because a validation predicate must not draw from the CSPRNG.
  So these belong on the signing path, where a per-signature draw is already
  happening, and not on derivation. That is a design decision to make
  deliberately rather than a line to add.

## Validation

| Gate | What it proves |
|---|---|
| `wycheproof_vectors/` — 1530 vectors across `ecdsa_secp256r1_sha256`, `ecdsa_secp384r1_sha384`, `ecdsa_secp521r1_sha512` | adversarial verification: encoding abuse, edge-case signatures, invalid points. **0 failures, 0 policy exceptions** |
| `tests/kat/rfc6979/ecdsa_prime_curves.kat` | all 18 in-scope vectors from RFC 6979 Appendix A.2.5/A.2.6/A.2.7 — the specification's own answer key, replayed including its printed public keys |
| `tests/test_nistp_curves.py` — 97 tests | signing agrees byte-for-byte with a pure-Python reference derived **from the specification only**, under both signing policies; the four-way low-`s` truth table; nonce non-repetition; ECDH against the reference; invalid-curve rejection; the full negative space, including coordinates that are non-canonical *and* reduce onto a real curve point, which is the only form that tells rejection apart from silent reduction; the curve/hash pairing `nistp_default_hash` publishes |
| `tests/test_selector_strictness.py` — 41 tests | INVARIANT-35: every selector refuses every unrecognised value rather than resolving a neighbour |
| `tests/c/test_nistp.c` | the hardcoded Montgomery constants re-derived from `p` and `n` alone; the windowed scalar multiplier against a naive double-and-add reference over the boundary lattice |

The Wycheproof suites cover *verification* only; RFC 6979's vectors and the
Python reference are what pin *signing*.

A note on how that reference must be written, learned the hard way: the first
version of it normalised `s` because the C code did, so the two agreed by
construction and neither was checked against the RFC. **A reference must be
derived from the specification only, never from the implementation it checks.**
`_ref_sign` now takes the signing policy as a parameter rather than baking one
in, and the RFC's own vectors sit behind it as the thing neither implementation
can talk its way out of.

## Deliberately not implemented

* **P-224, P-192 and the binary/Koblitz curves.** Deprecated or below the
  128-bit floor; adding them would grow the attack surface for no adoption.
* **Non-deterministic (purely random) nonces.** The deterministic RFC 6979
  signer plus the §3.6 hedged variant (`hedged=True`, 32 fresh CSPRNG octets
  mixed into the DRBG) covers both the reproducibility and the fault-resistance
  requirement. A raw random-nonce entry point is a footgun with no upside.
* **Cofactor ECDH.** All three curves have cofactor 1, so cofactor and plain
  ECDH coincide. There is nothing to select.
* **Hashing inside sign/verify.** The API takes a digest. Hiding the hash choice
  is how implementations end up signing under the wrong one.
