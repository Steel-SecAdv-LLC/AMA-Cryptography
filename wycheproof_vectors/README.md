# Vendored Project Wycheproof corpus

Adversarial cryptographic test vectors from
[C2SP/wycheproof](https://github.com/C2SP/wycheproof), vendored into this
repository so the gate runs **offline and version-pinned**. Nothing is
fetched at test time.

Run it:

```sh
python wycheproof_vectors/run_wycheproof.py
```

## Why this is here

Wycheproof is a corpus of the cases that *break* implementations rather
than the cases that exercise them. Running it against this library for
the first time found a real defect in the first primitive tested —
Ed25519 signature malleability, RFC 8032 §5.1.7 — within a minute. The
fix landed in `src/c/internal/ama_ed25519_canonical.h`; this harness is
what stops that finding from being a one-off. It is a standing gate over
every vendored vector, run on every pull request, fail-closed.

It has since paid for itself twice more:

- **X25519 tc88** — a non-canonical u-coordinate (`u = p + 3`) was
  consumed unreduced, producing a shared secret no other implementation
  computes. Fixed in `src/c/ama_x25519.c::x25519_canonicalize_u`.
- **ECDSA secp256k1** — 476 vectors that had no runnable implementation
  at all until `ama_secp256k1_ecdsa_sign` / `_verify` were written.

## Provenance

`manifest.json` records, for every vendored file:

- the upstream repository and the **exact commit** the bytes came from,
- the **SHA-256** of the file as vendored, and
- the **number of vectors** it contains.

The runner verifies all three before running anything, so an edited,
truncated, or swapped corpus file fails loudly rather than silently
reducing coverage. The vector counts are asserted individually and in
total, so vectors disappearing from the corpus is itself a build failure.

| Source | Value |
|---|---|
| Repository | https://github.com/C2SP/wycheproof |
| Commit | `b61843a9a5115bb758134b6a1f5d5e502d445342` |
| Path | `testvectors_v1/` |
| Retrieved | 2026-07-25 |
| Upstream license | Apache-2.0 |

## Verifying provenance and refreshing the pin

`tools/refresh_wycheproof_corpus.py` is the other half of the manifest
contract — it re-derives the recorded provenance from upstream so the
pin can be *checked*, not just *trusted*, and regenerates the manifest
when the pin is advanced.

```sh
# Offline: every vendored file's SHA-256 + vector count matches the
# manifest (deterministic, no network). This is the check the CI test
# tests/test_wycheproof_corpus_provenance.py runs on every build.
python tools/refresh_wycheproof_corpus.py --offline

# Full: also fetch each file from C2SP/wycheproof at the pinned commit
# and confirm the vendored bytes are byte-identical to upstream.
python tools/refresh_wycheproof_corpus.py --verify

# Advance the pin: re-vendor from a new upstream commit and rewrite
# manifest.json (digests, counts, totals, the upstream block).
python tools/refresh_wycheproof_corpus.py --refresh --commit <sha>
```

A refresh deliberately does **not** touch this README's counts or the
runner's policy `expected` counts — those are re-reviewed by hand and
then re-verified with `--verify`, so a corpus change can never silently
absorb a behaviour change. The offline provenance check is automated and
fail-closed in CI; the upstream-bytes check is also exposed as an opt-in
test (`AMA_WYCHEPROOF_ONLINE=1 pytest tests/test_wycheproof_corpus_provenance.py`).

The vendored JSON under `vectors/` is upstream's work, redistributed
under Apache-2.0 — the same license this repository uses. It carries no
AMA copyright header (JSON has no comment syntax, and the files are kept
byte-identical to upstream so the recorded digests remain checkable);
`tools/check_headers.py` does not select `.json`.

## What is covered

| File | Vectors |
|---|---|
| `aes_gcm_test.json` | 316 |
| `chacha20_poly1305_test.json` | 325 |
| `ecdsa_secp256k1_sha256_test.json` | 476 |
| `ecdsa_secp256r1_sha256_test.json` | 484 |
| `ecdsa_secp384r1_sha384_test.json` | 504 |
| `ecdsa_secp521r1_sha512_test.json` | 542 |
| `ed25519_test.json` | 150 |
| `hkdf_sha256_test.json` | 86 |
| `hkdf_sha384_test.json` | 83 |
| `hkdf_sha512_test.json` | 83 |
| `hmac_sha256_test.json` | 174 |
| `hmac_sha384_test.json` | 174 |
| `hmac_sha3_256_test.json` | 174 |
| `hmac_sha512_test.json` | 174 |
| `x25519_test.json` | 518 |
| **Total** | **4,263** |

The three NIST P-curve ECDSA files were vendored at 451ffea (2026-07-28) and
this table was not updated, so it claimed 2,733 vectors over a corpus of
4,263 — under-reporting by 1,530, every one of which the harness was in fact
running. Recounted from the harness's own per-file output rather than by hand:

    python wycheproof_vectors/run_wycheproof.py

Wycheproof publishes no ML-KEM, ML-DSA or SLH-DSA vectors, so the
post-quantum surface is not covered here; that remains ACVP's job
(`nist_vectors/`).

## How a vector can end up not passing

Every vector lands in exactly one bucket, and the counts are pinned:

- **pass** — behaviour matches the vector.
- **acceptable** — the vector's own result is `acceptable` and a named
  policy in the runner explains which behaviour this library chose.
- **out-of-scope** — the vector addresses an algorithm variant that is
  not implemented (AES-128/192-GCM in an AES-256-only library).
- **policy-divergence** — this library deliberately disagrees with the
  corpus. There is exactly one: high-`s` ECDSA signatures, which
  Wycheproof scores `valid` and this library rejects as malleable.
- **fail** — anything else. Fails the build, named by tcId.

There is no silent skip. Each of the three policy tables carries a
written reason and an exact expected count, so a corpus refresh or a
behaviour change surfaces as a red build instead of being absorbed.
