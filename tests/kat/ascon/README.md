# Ascon Known-Answer Test Vectors

Vendored known-answer vectors for the two Ascon functions this library
implements, per **NIST SP 800-232** (final, 2025-08-13).

## Files

| File | Vectors | Function |
|---|---|---|
| `ascon_aead128.kat` | 1089 | Ascon-AEAD128 (SP 800-232 §4, Algorithms 3–4) |
| `ascon_hash256.kat` | 1025 | Ascon-Hash256 (SP 800-232 §5.1, Algorithm 5) |

## Provenance

Both files are the published Known-Answer Test corpora from the Ascon
designers' reference repository, which is the corpus NIST's Lightweight
Cryptography process used and the one every SP 800-232 implementation is
expected to reproduce byte for byte:

| File | Source |
|---|---|
| `ascon_aead128.kat` | `crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt` from <https://github.com/ascon/ascon-c> |
| `ascon_hash256.kat` | `crypto_hash/asconhash256/LWC_HASH_KAT_128_256.txt` from <https://github.com/ascon/ascon-c> |

Retrieved 2026-07-27, unmodified apart from the filename.

```
SHA-256 (ascon_aead128.kat) = bbbc34692fe05e5fda0a3b025585622ab3e3747495e5e3655b29aae8c2a4bd33
SHA-256 (ascon_hash256.kat) = b7d6fbc51362f0d62bc7e57b21f3e83242983434a7c92320a4956d915749df17
```

**These are test vectors, not code.** Vendoring them introduces no
third-party cryptographic implementation and therefore does not touch
INVARIANT-1, exactly as with the vendored NIST ACVP and Wycheproof corpora
already in this tree. Nothing under `src/` derives from the reference
implementation; `src/c/ama_ascon.c` was written from the specification text.

## Coverage

Both corpora enumerate the same shape: every input length from 0 to 32 bytes,
and for the AEAD every plaintext length 0..32 crossed with every
associated-data length 0..32. That covers the four boundaries where a sponge
implementation actually breaks:

- **empty input** — the AEAD absorbs no associated-data block at all when
  `|A| = 0` (an implementation that absorbs a padding block here round-trips
  against itself and produces non-standard tags forever);
- **sub-rate** — a partial block shorter than the rate;
- **exact rate** — a full block followed by an empty padded block;
- **rate + 1** — the first multi-block case.

They are exercised at both the 128-bit AEAD rate and the 64-bit hash rate.

## Format

The NIST Lightweight Cryptography KAT format: blank-line-separated records of
`Name = HEXVALUE` lines. An empty value is written as the field name followed
by ` = ` and nothing else.

```
Count = 34
Key = 000102030405060708090A0B0C0D0E0F
Nonce = 101112131415161718191A1B1C1D1E1F
PT = 20
AD =
CT = E8DD576ABA1CD3E6FC704DE02AEDB79588
```

`CT` is the concatenation `ciphertext || tag`, so `|CT| = |PT| + 16`.

> **Parser note, learned the hard way.** The empty-value line carries a
> *trailing space* (`AD = `). A parser that matches on the literal prefix
> `"AD = "` fails to match it and silently leaves the previous record's value
> in place — so every empty-AD vector tests the wrong thing while still being
> counted as passing. Both the C and Python readers in this repository match
> the field name and then skip whitespace, and both carry a comment saying
> why.

## Independent checks beyond these files

The corpora validate the modes. Two further checks, taken from SP 800-232
itself rather than from any implementation, validate the layers underneath —
so that a fault in the permutation cannot be cancelled by a compensating fault
in a mode:

- **Table 6** — the S-box lookup representation, checked against the shipped
  bitsliced expression for all 32 inputs.
- **Appendix A.3** — the precomputed Ascon-Hash256 initialization state
  (`Ascon-p[12](IV || 0^256)`), checked word for word. This library computes
  that state rather than pasting the published constants, which is what lets
  the published value serve as an independent witness.

Both live in `tests/c/test_ascon.c`.

---

Copyright (C) 2025-2026 Steel Security Advisors LLC
