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

priv, pub = native_nistp_keypair("P-256")
digest = hashlib.sha256(b"message").digest()

der = native_nistp_ecdsa_sign("P-256", digest, priv)              # X.509 / TLS
raw = native_nistp_ecdsa_sign("P-256", digest, priv, raw=True)    # JWS / COSE
assert native_nistp_ecdsa_verify("P-256", der, digest, pub)

peer_priv, peer_pub = native_nistp_keypair("P-256")
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
* These functions never hash. Pass a digest of 32, 48 or 64 octets. The width
  also selects the RFC 6979 HMAC, as the RFC prescribes. A digest wider than the
  group order is truncated per FIPS 186-5, so signing a SHA-512 digest under
  P-256 is well defined and interoperable.

## Malleability posture (INVARIANT-34)

Signing **always** emits the low-`s` representative, so an AMA-produced
signature is never malleable.

Verification accepts **either** representative by default. That is a deliberate
divergence from the secp256k1 default (INVARIANT-28), and it is the whole point:
X9.62, FIPS 186-5, TLS, X.509, JWS and WebAuthn all permit either `s`, and none
of their signers normalise. A strict-by-default verifier here would reject
conformant third-party signatures — which is precisely the adoption blocker this
work exists to remove.

Everything that costs no interoperability stays unconditional in both modes:

* minimal DER only (short form, or the single long-form octet where a P-521 body
  genuinely exceeds 127 octets), minimal INTEGERs, no trailing bytes;
* `r` and `s` strictly in `[1, n-1]` — an out-of-range value is rejected, never
  reduced into range;
* public-key coordinates strictly in `[0, p)` — the INVARIANT-29 rule;
* the point on the curve and not the identity.

Callers who control both ends can demand the canonical form with
`require_low_s=True` (`AMA_NISTP_ECDSA_REQUIRE_LOW_S` in C).

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

Single core, x86-64, `-O3 -flto`, generic Montgomery path:

| Curve | Sign | Verify |
|---|---|---|
| P-256 | ~0.37 ms | ~0.54 ms |
| P-384 | ~0.90 ms | ~1.38 ms |
| P-521 | ~2.24 ms | ~3.57 ms |

This is several times slower than a curve-specialised implementation with a
precomputed generator table and Solinas reduction. It is stated rather than
elided: the correctness and constant-time properties came first, and the two
obvious next steps — a precomputed comb for the fixed generator, and per-curve
Solinas reduction for P-256 — are additive optimisations that change no
behaviour and can be added under the existing differential test.

## Validation

| Gate | What it proves |
|---|---|
| `wycheproof_vectors/` — 1530 vectors across `ecdsa_secp256r1_sha256`, `ecdsa_secp384r1_sha384`, `ecdsa_secp521r1_sha512` | adversarial verification: encoding abuse, edge-case signatures, invalid points. **0 failures, 0 policy exceptions** |
| `tests/test_nistp_curves.py` — 85 tests | signing agrees byte-for-byte with an independent pure-Python RFC 6979 reference built from the SP 800-186 parameters; low-`s`/X9.62 policy in both directions; nonce non-repetition; ECDH against the reference; invalid-curve rejection; the full negative space |
| `tests/c/test_nistp.c` | the hardcoded Montgomery constants re-derived from `p` and `n` alone; the windowed scalar multiplier against a naive double-and-add reference over the boundary lattice |

The Wycheproof suites cover *verification* only. The Python reference is what
pins *signing* — including the nonce, which is re-derived from RFC 6979's own
HMAC_DRBG construction rather than from this implementation.

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
