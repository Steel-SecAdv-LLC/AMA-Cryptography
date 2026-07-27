# Key-format conformance corpus

Everything here is consumed offline by `tests/test_key_formats.py`. Nothing is
fetched at test time, and nothing AMA ships reads these files or links anything
that produced them — this is checked-in data for CI, exactly as
`wycheproof_vectors/` is.

Rebuild or re-verify with `tools/build_keyformat_corpus.py`.

## Why a corpus at all

A round trip through AMA's own encoder proves only that AMA agrees with itself.
An encoder with the wrong OID, an absent-versus-NULL `parameters` mistake, or a
misidentified private-key `CHOICE` arm round-trips perfectly and interoperates
with nothing. These files are the only evidence that AMA's encodings are the
ecosystem's, so a missing file **fails** the suite rather than skipping it.

Every record is checked in both directions: the vendored bytes must parse to the
right key, and re-encoding that key must reproduce the vendored bytes exactly.
One direction alone would miss a decoder and encoder that are wrong in the same
way.

## Provenance

| File | Upstream | Revision |
|---|---|---|
| `rfc9881_ml_dsa.json` | [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.txt) Appendix C | RFC 9881, October 2025 |
| `lamps_ml_kem.json` | [draft-ietf-lamps-kyber-certificates-11](https://www.ietf.org/archive/id/draft-ietf-lamps-kyber-certificates-11.txt) Appendix C | draft -11, 22 July 2025 |
| `rfc8410_okp.json` | [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.txt) §10 | RFC 8410, August 2018 |
| `jose_cose.json` | [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.txt) Appendix A; [RFC 8152](https://www.rfc-editor.org/rfc/rfc8152.txt) Appendix C.7.1 | RFC 8037, January 2017; RFC 8152, July 2017 |
| `openssl/` | OpenSSL 3.0.13 (30 Jan 2024) | generated once; see `openssl/PROVENANCE.txt` |

The first four are **the specifications' own answer keys** — published by the
standards bodies precisely so an implementer needs no second party to check
against. `openssl/` is different in kind and is there for one reason: RFC 5915
and RFC 5480 publish no worked examples for EC PKCS#8 or SPKI, so for those
curves a second implementation's output is the only available cross-check.

`jose_cose.json` is transcribed from running text rather than parsed, because
those two appendices publish their examples as a JSON object and as CBOR
diagnostic notation, not as PEM. Its values are copied verbatim; the tests
re-derive everything else (the public key from the private one, the thumbprint
from the members) rather than trusting a second transcription.

## What each file pins

### `rfc9881_ml_dsa.json` — 15 records

Nine valid ML-DSA private keys (three parameter sets × the `seed`,
`expandedKey` and `both` arms of the RFC 9881 §6 `CHOICE`), three SPKI public
keys, and **three deliberately inconsistent private keys** from Appendix C.4.

The nine valid ones are more than an encoding test. RFC 9881 derives all of its
examples from the same seed `000102...1e1f`, so parsing a `seed` record runs it
through `ML-DSA.KeyGen_internal` and compares the result against the RFC's own
expanded key — which makes this a FIPS 204 key-generation KAT for
ML-DSA-44/65/87 as a side effect. A single mis-sampled coefficient would make
the `both` records fail outright.

The three bad ones cover three different failures, and each needs its own check:

1. `both`, where the seed does not expand to the supplied `expandedKey`.
2. `expandedKey`-only, where `tr` does not match the public key.
3. `expandedKey`-only, where `s1`/`s2` imply a `t` whose low bits are not the
   stored `t0`.

RFC 9881 §8.2 observes that implementations which "neglect to check consistency
of tr and t_0" detect neither of the last two. AMA recomputes both — see
`ama_ml_dsa_pubkey_from_privkey` in `src/c/ama_dilithium.c`.

### `lamps_ml_kem.json` — 16 records

The same shape for ML-KEM-512/768/1024, with **four** inconsistent keys:
`both`-mismatch, a mutated `dk_PKE` with a still-valid digest, a mutated
`H(ek)`, and a `both` pair differing only in the implicit-rejection secret `z`.

The mutated-`dk_PKE` case is the one that matters most. FIPS 203's implicit
rejection is *designed* to fail silently, so decapsulating with that key raises
nothing anywhere — the two parties simply hold different shared secrets and the
failure surfaces as an unexplained protocol error much later. Catching it needs
a pairwise encapsulate/decapsulate round trip at import time, which is why
`ama_ml_kem_privkey_check` does both that and the digest check.

### `rfc8410_okp.json` — 3 records

The Ed25519 SPKI from §10.1 and both PKCS#8 forms from §10.3. The second
private-key form is the valuable one: it is version 1, it carries a PKCS#8
*attribute* (a "Curdle Chairs" friendly name) that AMA does not consume, and its
`[1] publicKey` uses the primitive `0x81` tag rather than the constructed
`0xA1`. A parser that rejects unknown attributes, or that assumes the
constructed form, fails on it — and third-party key files carry both.

### `jose_cose.json` — 4 records

RFC 8037's Ed25519 JWK in both halves, the RFC 7638 thumbprint of it *including
the exact canonical input string the RFC prints*, and two RFC 8152 `COSE_Key`
maps (P-256 and P-521).

The thumbprint's canonical input is asserted rather than only its digest,
because the thing two implementations have to agree on is the
canonicalisation — required members only, lexicographic order, no whitespace —
and a wrong canonical form could otherwise slip through.

The P-521 COSE key is there because its `x` begins with a zero octet. Any
implementation that routes a coordinate through a big integer instead of
fixed-width octets silently drops it and produces a 65-byte value that is a
different key.

### `openssl/` — 12 files

PKCS#8 and SPKI for each of P-256, P-384, P-521, secp256k1, Ed25519 and X25519.
`test_openssl_corpus_covers_every_classical_algorithm` asserts the set matches
the library's, so a curve cannot be added without a cross-check.

## Refreshing

```
python3 tools/build_keyformat_corpus.py --specs    # re-derive from the RFCs
python3 tools/build_keyformat_corpus.py --verify   # offline re-parse
```

`--openssl` regenerates the independent sample, but note that key generation is
random: it **replaces** the corpus rather than reproducing it. Only run it if
you intend to swap the sample, and record the new OpenSSL version in the table
above in the same commit.
