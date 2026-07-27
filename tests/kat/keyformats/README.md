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
| `rfc9500_ec.json` | [RFC 9500](https://www.rfc-editor.org/rfc/rfc9500.txt) §2.3 | RFC 9500, December 2023 |

Every one of these is **a specification's own answer key** — published by a
standards body precisely so an implementer needs no second party to check
against. Nothing in this corpus is the output of another cryptographic product,
and nothing is meant to be.

RFC 9500 is the newest arrival and closed the one real gap. RFC 5915 defines
`ECPrivateKey` and publishes no example of it; RFC 5480 does the same for the
SPKI side. RFC 9500 — "Standard Public Key Cryptography (PKCS) Test Keys",
December 2023 — exists to supply exactly that kind of missing vector, and its
§2.3 prints P-256, P-384 and P-521 keys in the RFC 5915 `ECPrivateKey` form AMA
embeds inside PKCS#8.

Where a document still publishes nothing, the substitute is
[`tests/ref_keyformat.py`](../../ref_keyformat.py): a second encoder for these
structures, transcribed from the RFCs' own ASN.1 with the text quoted inline. It
is AMA's work, it imports nothing from `ama_cryptography`, and it is built
declaratively so it shares no control flow with the production encoder — because
two implementations that share an assumption do not check each other. It is
itself anchored against RFC 9500 §2.3 and RFC 8410 §10.1 before it is used as an
authority anywhere else.

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

### `rfc9500_ec.json` — 3 records

The IETF's own P-256, P-384 and P-521 private keys, as RFC 5915 `ECPrivateKey`.

Each carries `[0] parameters` and `[1] publicKey`, which makes it three vectors
in one. The `[0]` must be *accepted* — a standalone EC key file carries the
curve OID, and third-party files do too — and must then be *omitted* on
re-encoding, because RFC 5915 §3 says the field should not be repeated where the
enclosing structure already names the curve. Re-emitting it would produce a file
naming the curve twice, which is the shape that lets two parsers disagree about
which name wins.

The P-521 record doubles as a width vector: its scalar begins `0x01` in a
66-octet field, so an encoder that routed it through a big integer would emit a
shorter `OCTET STRING` that is still valid DER and is a different key.

### Coverage beyond the published vectors

The vendored records cover the keys the documents happened to print. Every
algorithm, in both directions and under both `include_public_key` settings, is
covered against `tests/ref_keyformat.py` instead — including the three RFC 9881
§6 `CHOICE` arms and the fixed-width edge cases (a scalar or coordinate with
leading zero octets), which are *constructed* rather than waited for.

## Refreshing

```
python3 tools/build_keyformat_corpus.py --specs    # re-derive from the RFCs
python3 tools/build_keyformat_corpus.py --verify   # offline re-parse
```

Both are reproducible: every record is extracted from a published document, so
`--specs` re-derives byte-identical files. `--verify-upstream` re-extracts from
the documents and compares record for record; it runs on a monthly schedule and
on any pull request touching this corpus (`.github/workflows/corpus-provenance.yml`).
