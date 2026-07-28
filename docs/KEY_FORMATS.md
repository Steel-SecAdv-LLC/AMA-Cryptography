# Key interoperability formats — PKCS#8, SPKI, PEM, JWK, COSE_Key

`ama_cryptography.key_formats` is the boundary layer that lets an AMA key leave
the library and come back: into an X.509 certificate request, a TLS stack, a
JOSE token, a COSE message, a WebAuthn credential, or an HSM's PKCS#11 object.

Implemented from specification with zero external crypto dependencies
(INVARIANT-1); the ASN.1 and CBOR codecs are `ama_cryptography._asn1`.

## Why this exists

AMA's key handling was in-house only — opaque octet strings with AMA-defined
layouts. That is fine inside AMA and useless everywhere else. A library whose
keys cannot be written to a file another tool reads is a library nothing adopts,
however good its primitives are. This was the second-largest interoperability
gap after the NIST prime curves, and it gates the same ecosystems.

## Support matrix

| Algorithm | SPKI | PKCS#8 | PEM | JWK | COSE_Key |
|---|:--:|:--:|:--:|:--:|:--:|
| Ed25519 | yes | yes | yes | yes | yes |
| X25519 | yes | yes | yes | yes | yes |
| P-256 / P-384 / P-521 | yes | yes | yes | yes | yes |
| secp256k1 | yes | yes | yes | yes | yes |
| ML-DSA-44 / 65 / 87 | yes | yes | yes | — | — |
| ML-KEM-512 / 768 / 1024 | yes | yes | yes | — | — |

The two dashes are not gaps in the implementation — see
[Deliberately not implemented](#deliberately-not-implemented).

## Using it

```python
from pathlib import Path

from ama_cryptography.key_formats import (
    PrivateKey,
    PublicKey,
    jwk_thumbprint,
    load_pkcs8,
    load_spki,
)
from ama_cryptography.pqc_backends import native_nistp_keypair

pub, priv = native_nistp_keypair("P-256")
private = PrivateKey("P-256", priv, pub)
public = PublicKey("P-256", pub)

Path("key.pem").write_text(private.to_pem())      # PKCS#8, RFC 5958
Path("key.pub").write_text(public.to_pem())       # SPKI

jwk = public.to_jwk()                             # RFC 7518 / 8037
thumbprint = jwk_thumbprint(jwk)                  # RFC 7638
cose = public.to_cose()                           # RFC 9052, deterministic CBOR

reloaded = load_pkcs8(Path("key.pem").read_text())   # DER or strict PEM
assert reloaded.public().key == public.key
assert load_spki(Path("key.pub").read_text()).key == public.key
```

Every name above is also re-exported from the package itself
(`from ama_cryptography import load_pkcs8`), lazily, so importing
`ama_cryptography` does not pull the native backend in for callers who never
touch a key file.

`tests/test_documented_examples.py` runs this block verbatim, so a snippet that
has drifted is a failing test rather than a new user's first error.

`load_spki` and `load_pkcs8` accept DER bytes, a PEM string, or bytes holding
PEM text — a file read in binary mode is the common case and works.

## Standards

| Format | Documents |
|---|---|
| SPKI | RFC 5280 §4.1.2.7; RFC 5480 (EC); RFC 8410 (Ed25519/X25519) |
| PKCS#8 | RFC 5958 `OneAsymmetricKey`; RFC 5915 `ECPrivateKey`; RFC 8410 `CurvePrivateKey`; RFC 9881 §6 (ML-DSA); draft-ietf-lamps-kyber-certificates (ML-KEM) |
| PEM | RFC 7468, strict |
| JWK | RFC 7517/7518; RFC 8037 (OKP); RFC 8812 (secp256k1); RFC 7638 (thumbprints) |
| COSE_Key | RFC 9052/9053; RFC 8812; RFC 8949 §4.2.1 (deterministic encoding) |

## Design commitments

### Public and private material never share a code path

`PublicKey` and `PrivateKey` are separate types with separate encoders. There is
no `encode(key)` that decides which one it got, because the failure that design
permits — a private key serialised into the slot the caller is about to
publish — is silent and unrecoverable.

Separate types are not by themselves enough, and this is worth stating because
the first version of this module got it wrong. Both classes carry `.algorithm`
and `.key`, so a `PrivateKey` duck-types straight through a public encoder — and
for Ed25519 and X25519, where the two halves are the same width, it comes out
the other side as a *well-formed public encoding of the secret seed*. Nothing
about the result looks wrong. So the public encoders now refuse anything that is
not a `PublicKey` explicitly, and `test_a_private_key_cannot_be_encoded_as_a_public_one`
asserts it for all three shapes.

### Parsing is strict

DER only, never BER: definite lengths, minimal lengths, minimal INTEGERs, no
trailing data, no high-tag-number form. CBOR must be deterministic per RFC 8949
§4.2.1: sorted map keys, no duplicates, no indefinite lengths. PEM is strict
RFC 7468 — exact labels, no explanatory text, no whitespace inside the base64.

A permissive parser means two byte strings decode to the same key. That is the
same defect class as signature malleability, it is reachable by anyone who can
hand you a key file, and it breaks anything that identifies a key by the hash of
its encoding.

### Defaults are the conventional encoding, not a house style

`to_pkcs8()` takes `include_public_key`, and its default (`None`) means "the
form this algorithm's ecosystem actually emits":

| Kind | Default | Matches |
|---|---|---|
| EC | public key inside `ECPrivateKey` | RFC 5915 §3; RFC 9500 §2.3 |
| Ed25519 / X25519 | no public key, v1 | RFC 8410 §10.3 first example |
| ML-DSA / ML-KEM | no public key, v1 | RFC 9881 Appendix C |

`True` and `False` override it in either direction and both are tested. The
point of the default is that AMA's output is byte-identical to what a reference
encoder produces, which is verified against the vendored corpus and against
`tests/ref_keyformat.py` rather than asserted here.

Because `None` therefore means different things for different algorithms, the
resolved answer is published rather than left to be inferred:
`key_formats.CONVENTIONAL_PUBLIC_KEY` is the table, and
`conventional_include_public_key(algorithm)` answers for one algorithm.
`test_none_encodes_exactly_as_the_conventional_explicit_value` asserts, for
every algorithm, that `None` produces bytes identical to the explicit setting it
stands for — and *different* bytes from the other one, so the flag is never a
no-op.

Note the two families put the public half in different fields. EC uses
RFC 5915's `[1]` inside `ECPrivateKey`, which RFC 5958 never sees, so the
version stays v1. Everything else uses RFC 5958's own `[1] publicKey` on the
outer `SEQUENCE`, which raises the version to v2 — and RFC 5958 §2 ties those
together in both directions ("if publicKey is present, then version is set to v2
else version is set to v1"), which this parser now enforces. Accepting a v2 with
no public key gave one key two valid encodings.

### The cost of importing a key

PQ consistency checking on import is a documented policy, `enabled` by default,
switchable per call (`load_pkcs8(..., verify_pq_consistency=False)`), per block
(`with key_formats.pq_import_consistency(False):`) or per process
(`AMA_KEY_IMPORT_PQ_CONSISTENCY=0`). It defaults to enabled because the checks
are what reject the RFC 9881 §8.2 and lamps-kyber §C.4.1 negative vectors, and
because an ML-KEM inconsistency is *designed* to fail silently.

It is a policy rather than a constant because the checks are not free and the
import path is reachable by whoever supplies a key file. Measured on one core,
x86-64, `-O3 -flto`, by `benchmarks/keyformat_import.py` — the same standard as
the curve measurements in `docs/NIST_PRIME_CURVES.md`:

| Algorithm | Form | Parse only | Checked (default) | Ratio | Keygen, for scale |
|---|---|---:|---:|---:|---:|
| ML-DSA-44 | `expandedKey` | 0.011 ms | 0.099 ms | 8.9× | 0.118 ms |
| ML-DSA-65 | `expandedKey` | 0.011 ms | 0.155 ms | 13.7× | 0.192 ms |
| ML-DSA-87 | `expandedKey` | 0.011 ms | 0.287 ms | 26.0× | 0.274 ms |
| ML-KEM-512 | `expandedKey` | 0.018 ms | 0.127 ms | 7.0× | 0.044 ms |
| ML-KEM-768 | `expandedKey` | 0.019 ms | 0.204 ms | 10.9× | 0.077 ms |
| ML-KEM-1024 | `expandedKey` | 0.022 ms | 0.291 ms | 13.3× | 0.116 ms |
| ML-DSA-87 | `seed` | 0.266 ms | 0.262 ms | 1.0× | 0.274 ms |
| ML-KEM-1024 | `both` | 0.021 ms | 0.127 ms | 6.0× | 0.116 ms |

Read the ratio column as the denial-of-service lever: an `expandedKey`-only
ML-DSA-87 import costs about what *generating* a key costs, and 26× what parsing
the DER around it costs. The `seed` form shows a ratio of 1.0 because expanding
a seed is how the key is decoded at all — not a check, and so not governed by
the policy.

Two things stay true with the checks off, both free:

* ML-KEM still recovers its encapsulation key, because FIPS 203 §7.1 embeds `ek`
  verbatim in `dk`; extracting it is a slice, and it is still validated against
  the §7.2 modulus check. If the file also carries a public key, the two are
  still required to be equal.
* Every structural check still runs — DER strictness, the `CHOICE` arm, lengths,
  the OID. The policy governs *cryptographic* consistency only.

What is given up is stated plainly: ML-DSA no longer derives a public key at
import (the cost moves to first use, where `PrivateKey.public()` runs the full
check), and the specifications' negative vectors are no longer rejected at
import. RFC 9881 §8.2 requires an inconsistent key to be rejected as malformed,
so disabling this is a conformance decision, not a tuning one.

For scale, note what the table does *not* show: the EC curves cost far more on
this path than the PQ ones, because deriving a public key from a scalar is a
scalar multiplication. P-521 import is 1.23 ms against ML-DSA-87's 0.287 ms, and
that cost is not governed by this policy because for EC the derivation *is* the
key. It is the reason the fixed-base comb described in
`docs/NIST_PRIME_CURVES.md` was worth doing.

### Every algorithm is real

Nothing in the table is a placeholder. Where a format has no finished standard
for an algorithm, the call raises `UnsupportedKeyFormatError` naming the reason.

## Post-quantum private keys

RFC 9881 §6 gives ML-DSA (and the LAMPS ML-KEM draft gives ML-KEM) a three-arm
`CHOICE`: `seed [0]`, `expandedKey`, and `both`. All three are read and written,
and all three are real.

**The seed arm is functional.** It is expanded through
`ML-DSA.KeyGen_internal` / `ML-KEM.KeyGen_internal`, so importing a 54-octet
seed file yields a key that signs and verifies — not an opaque blob.

**A seed that arrives is kept.** RFC 9881 §8.1 is explicit that expansion is
one-way: "once a full key is expanded from seed and the seed discarded, the seed
cannot be recreated, even if the full expanded private key is available."
A layer that dropped the seed on import would irreversibly turn a 54-octet key
file into a multi-kilobyte one on the next write. `PrivateKey.seed` carries it,
and `pq_format="auto"` re-emits the form the key arrived in.

**Inconsistent keys are rejected — including the hard case.** Three checks:

| Arm | Check |
|---|---|
| `both` | the seed must expand to the supplied `expandedKey` (RFC 9881 §8.2) |
| `expandedKey` (ML-DSA) | `rho`, `s1`, `s2` determine `t`, hence `t0` and the public key, hence `tr = H(pk)`. Both `t0` and `tr` must agree with what the key carries. |
| `expandedKey` (ML-KEM) | `H(ek)` must be SHA3-256 of the embedded `ek`, **and** an encapsulate/decapsulate round trip must agree |

The last two are the ones implementations usually skip. RFC 9881 §8.2 says so in
as many words — implementations that "neglect to check consistency of tr and
t_0" detect neither of its Appendix C.4 examples 2 and 3.

The ML-KEM pairwise check is not redundant with the digest check. FIPS 203's
implicit rejection (Algorithm 18 line 8) is *designed* to fail silently, so a
decapsulation key with a mutated `dk_PKE` and a correct `H(ek)` raises nothing
anywhere downstream: the two parties simply hold different shared secrets and
the failure surfaces as an unexplained protocol error much later. Import time is
the only place it is visible.

Both checks are exposed on the backend as well:

```python
# doc-example: not runnable — a signature sketch, not a program. `sk` stands
# for a key the reader already has, and tests/test_documented_examples.py skips
# blocks carrying this marker rather than pretending to execute them.
from ama_cryptography.pqc_backends import (
    native_ml_dsa_privkey_check,
    native_ml_dsa_pubkey_from_privkey,
    native_ml_kem_privkey_check,
    native_ml_kem_pubkey_from_privkey,
)

native_ml_dsa_pubkey_from_privkey(65, sk)   # public key, or ValueError
native_ml_dsa_privkey_check(65, sk)         # the verdict alone
native_ml_kem_pubkey_from_privkey(768, sk)
native_ml_kem_privkey_check(768, sk)
```

### A related fix this surfaced

Adding the ML-DSA check exposed a missing FIPS 204 conformance gate in the
signer itself. `skDecode` (Algorithm 25) requires every `s1`/`s2` coefficient to
be in `[-eta, eta]` and the key to be rejected otherwise — but the packing is
not surjective onto its bit width (eta = 2 stores a five-value range in three
bits), so a malformed key decoded to coefficients the specification forbids and
was accepted. `ama_ml_dsa_sign` now refuses such a key rather than producing
signatures nothing verifies and driving the rejection loop off its calibrated
bounds.

## Validation

| Gate | What it proves |
|---|---|
| RFC 9881 Appendix C — 15 vectors | ML-DSA PKCS#8 in all three arms and SPKI, parsed and re-encoded byte-for-byte; three deliberately inconsistent keys rejected |
| draft-ietf-lamps-kyber-certificates-11 Appendix C — 16 vectors | the same for ML-KEM, with four inconsistent keys |
| RFC 8410 §10 — 3 vectors | Ed25519 SPKI and both PKCS#8 forms, including the one with a PKCS#8 attribute and a primitive `[1] publicKey` |
| RFC 8037 Appendix A / RFC 8152 Appendix C.7.1 | Ed25519 JWK, the RFC 7638 thumbprint *and its canonical input string*, P-256 and P-521 `COSE_Key` |
| `tests/kat/keyformats/rfc9500_ec.json` — 3 records | the IETF's own P-256/P-384/P-521 `ECPrivateKey`, the structure RFC 5915 defines without an example |
| `tests/ref_keyformat.py` | a second encoder transcribed from the RFCs' ASN.1 — AMA's own, importing nothing from `ama_cryptography` — covering every algorithm and option, anchored against RFC 9500 §2.3 and RFC 8410 §10.1 |
| `tests/test_key_formats.py` — 568 tests | the above in both directions, plus the negative space |
| `fuzz/python/fuzz_key_formats.py` | continuous hostile input across all ten parser entry points, run per PR by `fuzzing.yml` (INVARIANT-33) |

The counts above are not decoration and they are not taken on trust:
`tools/check_documented_counts.py` re-derives each one — pytest's own collection
count, the corpus files' `records` arrays, the Wycheproof manifest — and fails
CI when a documented number stops being true. A number nobody checks is worse
than no number, because a reader takes it as evidence.

Two things about that table are deliberate.

**Both directions, always.** Parsing the vendored bytes and re-encoding to them
are separate assertions. Checking only the first would miss a decoder and
encoder that are wrong in the same way — which is exactly what a self-round-trip
test cannot see.

**The PQ vectors double as keygen KATs.** RFC 9881 derives all of its examples
from one seed, so parsing a `seed` record runs AMA's `KeyGen_internal` and
compares against the RFC's own expanded key. A single mis-sampled coefficient in
ML-DSA-44 or ML-KEM-512 fails the `both` records outright.

The corpus is vendored and consumed offline; see
`tests/kat/keyformats/README.md` for provenance and
`tools/build_keyformat_corpus.py` to re-derive it. Nothing AMA ships reads those
files or links anything that produced them.

## Deliberately not implemented

* **JWK and COSE for ML-DSA and ML-KEM.** The JOSE and COSE registrations were
  still drafts when this was written. A guessed encoding produces keys that
  interoperate with nothing and that a future revision has to break, so the call
  raises `UnsupportedKeyFormatError` naming the reason. Use SPKI or PKCS#8,
  which *are* standardised for these algorithms (RFC 9881).
* **Encrypted PKCS#8** (`EncryptedPrivateKeyInfo`, RFC 5958 §3). Only the
  unencrypted form is read and written. A password-wrapped PKCS#8 needs a
  KDF-and-cipher policy decision that belongs with
  `ama_cryptography.key_management.SecureKeyStorage`, not with the encoding
  layer.
* **X.509 certificates.** This module handles keys, not the structures that
  contain them.
* **The lax RFC 7468 parsing rules.** §3 permits a parser to accept explanatory
  text around a block and whitespace inside the base64. A key file with
  unexplained bytes around it is one a caller should look at, not one this layer
  should quietly salvage — the salvaged part may not be the part they meant.
* **Round-tripping PKCS#8 attributes.** They are parsed and discarded so that
  third-party keys carrying them import cleanly, but nothing in AMA consumes
  them and they are not re-emitted. Claiming to preserve them would mean
  claiming to understand them.
