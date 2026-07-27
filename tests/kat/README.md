# Vendored known-answer test vectors

Every file under this directory is upstream NIST or Project Wycheproof material,
vendored so the conformance gates run **offline** and **version-pinned**. Nothing
is fetched at test time.

A round trip proves an implementation is self-consistent. It does not prove it is
the *right* algorithm — an implementation with a mistyped parameter signs,
verifies, and interoperates with nothing. These vectors are the only evidence
that distinguishes the two, so a missing file fails the suite rather than
skipping it.

## Provenance

| Directory | Files | Upstream | Ref |
|---|---|---|---|
| `fips203/` | `ml_kem_1024.kat` | NIST ACVP-Server, ML-KEM-keyGen/encapDecap-FIPS203 | `v1.1.0.42` |
| `fips203/` | `ml_kem_512.kat`, `ml_kem_768.kat` | [C2SP/wycheproof](https://github.com/C2SP/wycheproof) `testvectors_v1/mlkem_{512,768}_test.json` | `b61843a9a5115bb758134b6a1f5d5e502d445342` |
| `fips204/` | `ml_dsa_65.kat` | NIST ACVP-Server, ML-DSA-keyGen/sigGen-FIPS204 | `v1.1.0.42` |
| `fips204/` | `ml_dsa_44.kat`, `ml_dsa_87.kat` | [NIST ACVP-Server](https://github.com/usnistgov/ACVP-Server) `gen-val/json-files/ML-DSA-{keyGen,sigGen}-FIPS204/internalProjection.json` | `master` @ 2026-07-27 |
| `fips205/` | see `fips205/README.md` | NIST ACVP-Server, SLH-DSA-FIPS205 | `v1.1.0.42` |
| `ascon/` | see `ascon/README.md` | NIST SP 800-232 | — |
| `ml_dsa/`, `ml_kem/` | `*.rsp` | Round-3 CRYSTALS reference KATs (pre-FIPS) | — |

The `.rsp` files under `ml_dsa/` and `ml_kem/` predate FIPS 203/204 and are kept
for historical comparison only; they are **not** the conformance gate. The
`.kat` files under `fips203/` and `fips204/` are.

## Format

The `.kat` files use the repository's `key = hexvalue` line format, one field per
line, records separated by a blank line. Parsed by
`tests/test_pqc_param_sets.py::_parse_records` (Python) and `rsp_read_entry`
(C, `tests/c/test_kat.c`).

### `fips203/ml_kem_{512,768,1024}.kat`

| Field | Meaning |
|---|---|
| `d`, `z` | the 32-octet seed halves; `d \|\| z` is FIPS 203's 64-octet keygen seed |
| `pk` | expected public key (encapsulation key) — present when the source carried one |
| `ct` | ciphertext to decapsulate |
| `ss` | expected shared secret |
| `result` | `valid`, or `invalid` for an adversarial record |

An `invalid` record asserts that decapsulation does **not** produce the listed
secret. There are two shapes and both are exercised: a well-formed-length
ciphertext that must trigger FIPS 203 implicit rejection (silently, with no
error), and a wrong-length ciphertext that must be refused outright. Conflating
them would let the length check disappear unnoticed.

### `fips204/ml_dsa_{44,65,87}.kat`

Key-generation records carry `seed` / `pkey` / `skey`. Signature records carry
`skey` / `mlen` / `msg` / `ctx_len` / `ctx` / `sig`, plus — for the two files
added with the 44/87 parameter sets — a `sigmode` field:

| `sigmode` | Interface |
|---|---|
| `internal` | ML-DSA.Sign_internal: the message is signed directly |
| `external` | FIPS 204 §5.2 external/pure: `0x00 \|\| len(ctx) \|\| ctx \|\| M` |

Only the **deterministic** ACVP groups (`rnd = 0^256`) are vendored, because that
is the variant `ama_ml_dsa_sign` implements; the hedged and pre-hash (HashML-DSA)
groups are deliberately absent rather than silently unrun. `externalMu` groups are
also absent — that is a separate interface AMA does not expose.

## Refreshing

These files are derived from upstream JSON, not copied verbatim, so
`tools/refresh_wycheproof_corpus.py` (which verifies byte-for-byte against
upstream) does not cover them — it covers `wycheproof_vectors/` only. To refresh
a `.kat` file, re-derive it from the upstream JSON named in the table above at
the recorded ref, and record the new ref here in the same commit.
