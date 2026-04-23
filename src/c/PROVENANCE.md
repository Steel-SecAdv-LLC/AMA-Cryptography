# PQC Implementation Provenance

**Repository:** `steel-secadv-llc/ama-cryptography`
**Scope:** Native-C post-quantum primitives in `src/c/`
**Date:** 2026-04-21
**Maintainer:** Steel Security Advisors LLC

This document records, per primitive, whether the AMA Cryptography native-C
implementation was **derived from** an upstream reference (pq-crystals,
PQClean, liboqs, …) or **written from the FIPS specification directly**.
The aim is explicit provenance: readers can audit what code was copied,
what was transcribed from the standard, and where the two diverge.

It is the companion for file-level `Provenance:` comments added to
[`ama_kyber.c`](ama_kyber.c), [`ama_dilithium.c`](ama_dilithium.c), and
[`ama_sphincs.c`](ama_sphincs.c). When provenance claims here and in a
source file conflict, **the source file is authoritative** — this document
must be updated to match.

Every claim of "clean-room from FIPS" is backed by ACVP Known Answer Test
results published in [`../../CSRC_ALIGN_REPORT.md`](../../CSRC_ALIGN_REPORT.md)
and continuously enforced in
[`.github/workflows/acvp_validation.yml`](../../.github/workflows/acvp_validation.yml).

---

## Summary Table

| Primitive | Source file | Provenance | Upstream ref | License | ACVP KAT |
|-----------|-------------|------------|--------------|---------|----------|
| ML-KEM-1024 (FIPS 203) | `ama_kyber.c` | Written from FIPS 203 spec | None (no upstream code copied) | N/A (clean-room) | 25/25 KeyGen, 25/25 EncapDecap |
| ML-DSA-65 (FIPS 204) | `ama_dilithium.c` | Written from FIPS 204 spec | None (no upstream code copied) | N/A (clean-room) | 25/25 KeyGen, 15/15 SigVer (TG3) |
| SLH-DSA-SHA2-256f (FIPS 205) | `ama_sphincs.c` | Written from FIPS 205 spec | None (no upstream code copied) | N/A (clean-room) | 14/14 SigVer (TG5) |
| Ed25519 | `ama_ed25519.c` + `vendor/ed25519-donna/` | Vendored | [floodyberry/ed25519-donna](https://github.com/floodyberry/ed25519-donna) | Public domain (see `vendor/ed25519-donna/LICENSE`) | Sign/verify round-trip |
| SHA3-256 / SHA3-512 / SHAKE | `ama_sha3.c` | Written from FIPS 202 spec | None | N/A (clean-room) | 554 AFT + 400 MCT (151/86/174/143 AFT + 100 MCT per algo) |
| SHA-256 | `ama_sha256.c` | Written from FIPS 180-4 spec | None | N/A (clean-room) | FIPS 180-4 §B.1 refs |
| HMAC-SHA-256 | `ama_hmac_sha256.c` | Written from RFC 2104 + FIPS 198-1 | None | N/A (clean-room) | 150/150 AFT |

"Clean-room" means the AMA source file was written against the published
normative document (FIPS / RFC), not copied from another implementation.
It is **not** a claim of independent formal proof of correctness — that
bar is higher and is called out separately in `ARCHITECTURE.md §Design
Philosophy` and `docs/DESIGN_NOTES.md §Limitations`. Clean-room means
the text of the algorithm is the only shared artifact with third-party
implementations; it does not mean the algorithm is uniquely ours.

---

## ML-KEM-1024 — `ama_kyber.c`

**Standard:** NIST FIPS 203 (ML-KEM, August 2024 final).
**Parameter set:** ML-KEM-1024 (k=4, eta1=2, eta2=2, du=11, dv=5).

**Provenance:** Written from the FIPS 203 specification directly. No
source-level code was derived from pq-crystals/kyber, PQClean, liboqs, or
any other third-party implementation. All inner procedures
(`K-PKE.KeyGen`, `K-PKE.Encrypt`, `K-PKE.Decrypt`, `ML-KEM.KeyGen`,
`ML-KEM.Encaps`, `ML-KEM.Decaps`, and the NTT / CBD / ByteEncode /
ByteDecode helpers) were implemented by transcribing the pseudocode in
FIPS 203 §5–§7 into C.

**Randomness:** FIPS 203 §3.3 requires 32 bytes of fresh entropy for the
`d` seed in KeyGen and 32 bytes for the `m` parameter in Encaps. AMA
sources both through `ama_platform_rand.c` (getrandom / arc4random /
BCryptGenRandom depending on OS). The deterministic API
`ama_kyber_keypair_from_seed(d, z, …)` used for KAT validation bypasses
the RNG as required by ACVP.

**SIMD:** The NTT in `src/c/avx2/` is hand-written x86 assembly using the
AVX2 instruction set, developed in-house. It is not derived from the
pq-crystals AVX2 implementation. Correctness is established by the same
KAT vectors used for the generic C path (the AVX2 and generic NTT must
produce byte-identical outputs to pass the full ACVP run).

**Known divergences from the FIPS 203 pseudocode:** None in the
algorithmic sense. AMA's implementation matches FIPS 203 byte-for-byte on
all 50 applicable ACVP vectors. Non-normative differences:
- Rejection sampling in `SampleNTT` is implemented with a loop counter
  bound (to avoid infinite loops on pathological RNG behavior) rather
  than relying on the unbounded FIPS 203 loop. The bound is set high
  enough that a correct RNG will never hit it (~2^-128 probability).
- Secret key serialization uses the FIPS 203 layout
  (`dk = dk_PKE || ek_PKE || H(ek_PKE) || z`); no extra fields.

**Side-channel posture:** All secret-dependent operations use the
constant-time helpers in `ama_consttime.c`. dudect regression tests are
run under `tests/test_constant_time.py`.

---

## ML-DSA-65 — `ama_dilithium.c`

**Standard:** NIST FIPS 204 (ML-DSA, August 2024 final).
**Parameter set:** ML-DSA-65 (k=6, l=5, η=4, τ=49, β=196, γ₁=2^19,
γ₂=(q−1)/32, ω=55).

**Provenance:** Written from the FIPS 204 specification directly. No
source-level code was derived from pq-crystals/dilithium, PQClean,
liboqs, or any other third-party implementation. All procedures
(`ML-DSA.KeyGen`, `ML-DSA.Sign_internal`, `ML-DSA.Verify_internal`,
`Power2Round`, `Decompose`, `MakeHint`, `UseHint`, sampling from η / γ₁,
and the polynomial / NTT layer) were implemented by transcribing the
pseudocode in FIPS 204 §5–§8 into C.

**Domain separation wrapper:** The external/pure signature variant
(`ama_dilithium_sign_ctx`, `ama_dilithium_verify_ctx`) applies the
FIPS 204 §5.4 transform `M' = 0x00 || len(ctx) || ctx || M` before
delegating to the internal verify. This was added to resolve the 3
initial ACVP TG 3 failures documented in
[`CSRC_ALIGN_REPORT.md §2.2`](../../CSRC_ALIGN_REPORT.md) — the internal
verify function was correct all along; only the wrapper was missing.

**Randomness:** KeyGen consumes 32 bytes through `ama_platform_rand.c`;
Sign uses the hedged-randomness mode (ξ || rnd, where rnd is fresh per
signature) per FIPS 204 §5.3. The deterministic API
`ama_dilithium_keypair_from_seed(xi, …)` bypasses the RNG for KAT
validation as required by ACVP.

**SIMD:** The NTT / invNTT in `src/c/avx2/` and `src/c/neon/` are
hand-written and were developed in-house. The SVE2 path in
`src/c/sve2/` is also in-house (no external SVE2 Dilithium
implementation was publicly available at the time of writing).

**Known divergences from the FIPS 204 pseudocode:** None in the
algorithmic sense. All 25 KeyGen and 15 SigVer TG 3 vectors pass
byte-exact. Non-normative differences:
- `Sign_internal`'s rejection-sampling loop is bounded (maximum attempts
  = 2^16); a correct implementation will never hit the bound. This
  avoids a theoretical infinite loop on broken RNG.
- Public key hash `tr = H(ρ || t₁)` is computed once at KeyGen and
  stored in the secret key bytes, matching FIPS 204 §5.1.

**Side-channel posture:** Rejection-sampling rate depends on the secret
vector `s1`, which is a published vulnerability class for Dilithium;
AMA mitigates via hedged randomness (the `rnd` byte per FIPS 204 §5.3).

---

## SLH-DSA-SHA2-256f — `ama_sphincs.c`

**Standard:** NIST FIPS 205 (SLH-DSA, August 2024 final).
**Parameter set:** SLH-DSA-SHA2-256f (n=32, h=68, d=17, h'=4, a=9, k=35,
w=16, security category 5 — `f` = fast variant).

**Provenance:** Written from the FIPS 205 specification directly. No
source-level code was derived from sphincs/sphincsplus, PQClean,
liboqs, or any other third-party implementation. The 10 FIPS 205
algorithms (`slh_keygen`, `slh_sign`, `slh_verify`, WOTS+ 8/9/10, FORS
14/15/16/17, and the hypertree driver 11/12/13) were implemented by
transcribing FIPS 205 §9–§11 into C.

**Hash instantiation (FIPS 205 §11.2, security categories {3,5}):**
`ama_sphincs.c` uses:
- `H_msg` = MGF1-SHA-512 (with `toByte(0, 64 − n)` padding) — full
  resolution is documented in [`CSRC_ALIGN_REPORT.md §2.3`](../../CSRC_ALIGN_REPORT.md).
- `PRF_msg` = `Trunc_n(HMAC-SHA-512(SK.prf, opt_rand || M))` — see
  [`CSRC_ALIGN_REPORT.md §2.4`](../../CSRC_ALIGN_REPORT.md).
- `H` and `T_l` (multi-block thash) = SHA-512 with `toByte(0, 128 − n)`.
- `F` (single-block thash) = SHA-256 with `toByte(0, 64 − n)`.

The shared SHA-512 implementation lives in `src/c/internal/ama_sha2.h`
(extracted in v2.2 after SLH-DSA and Ed25519 were both shipped with
redundant copies — see [`CSRC_ALIGN_REPORT.md §2.5`](../../CSRC_ALIGN_REPORT.md)).

**ADRS compression:** The 22-byte compressed address used as the SHA-2
MGF1/PRF input follows the FIPS 205 §11.2 mapping (1-byte layer address
LSB, 8-byte tree address LSB, 1-byte type, 12-byte "rest" field). The
initial implementation used a different layout — see
[`CSRC_ALIGN_REPORT.md §2.3`](../../CSRC_ALIGN_REPORT.md) for the fix.

**Known divergences from the FIPS 205 pseudocode:** None in the
algorithmic sense. All 14 TG 5 SigVer vectors pass byte-exact. Non-
normative differences:
- The FORS and WOTS+ loops preserve the keypair-address field across
  `setTreeHeight` / `setTreeIndex` / `setType` calls (FIPS 205
  Algorithms 7, 16, 18). A bug that zeroed the keypair address too
  early was caught by ACVP and is documented in
  [`CSRC_ALIGN_REPORT.md §2.3`](../../CSRC_ALIGN_REPORT.md).

**Side-channel posture:** SLH-DSA is by construction hash-only; there
is no secret scalar, no rejection sampling, and no number-theoretic
operation that could leak timing. The implementation is constant-time
at the hash layer (the SHA-2 core is straight-line).

---

## Ed25519 — `ama_ed25519.c` + `vendor/ed25519-donna/`

**Provenance:** Mixed. The default x86-64 build uses the vendored
[floodyberry/ed25519-donna](https://github.com/floodyberry/ed25519-donna)
public-domain assembly backend (enabled by `AMA_ED25519_ASSEMBLY=ON`,
which is the CMake default on x86-64 / MSVC x64); the vendored copy
lives under `src/c/vendor/ed25519-donna/` with the upstream `LICENSE`
preserved verbatim. When the donna backend is not selected (the default
on ARM / other non-x86 targets, or on any platform with
`-DAMA_ED25519_ASSEMBLY=OFF`), the in-tree path in `src/c/ama_ed25519.c`
is used instead. It consists of:
- Radix 2^51 field arithmetic (`fe51.h`) — written from the
  [Ed25519 paper](https://ed25519.cr.yp.to/ed25519-20110926.pdf) and
  the ref10 SUPERCOP reference, in-tree.
- Fixed-base scalar multiplication via a **signed 4-bit window comb**
  (Bernstein–Duif–Lange–Schwabe–Yang 2012, §4) — 32 subtables × 8
  Edwards-extended points precomputed at first use from the RFC 8032
  base point, using the same in-tree group arithmetic as sign/verify.
  Constant-time (INVARIANT-12): digit extraction is branchless; table
  select is a linear cmov over all 8 entries; sign negation is a
  branchless cmov on the coordinate negations. No external data — the
  table is derived from ed_B by in-tree math, making every byte
  auditable. See `ge25519_scalarmult_base_comb_signed` in
  `ama_ed25519.c`.
- Variable-base scalar multiplication via width-4 wNAF (vartime, used
  only for verification where the scalar is public).

The AMA-level wrapper (`ama_ed25519.c`) adds:
- API surface matching AMA's `ama_ed25519_sign` / `_verify` contract.
- Integration with the AMA ctypes bindings and the FROST threshold layer.
- Expanded-key fast path used by `generate_ed25519_keypair` — see
  [`CSRC_ALIGN_REPORT.md §2.8`](../../CSRC_ALIGN_REPORT.md).
- `ama_ed25519_scalarmult_public` with explicit naming to prevent
  misuse of vartime scalar multiplication on secret scalars (audit
  finding C7).

Equivalence between the two fixed-base paths (comb vs. the wNAF
variable-base reference) is continuously verified by
`tests/c/test_ed25519_comb_equiv.c` on 1024 randomized scalars plus
five edge-case vectors (identity, scalar=1, all-nibbles-+7,
all-nibbles-+8, alternating bytes).

**Vendored-code patches** (applied in-tree on top of upstream
floodyberry/ed25519-donna; searchable by grepping `AMA-PATCH:`):

| File | Change | Reason |
|------|--------|--------|
| `vendor/ed25519-donna/ed25519-hash.h` | `ed25519_hash_update` early-return when `inlen == 0` | Upstream unconditionally calls `memcpy(dst, in, want)` even when `want` can be zero.  Passing a NULL `in` with `inlen == 0` is strict-C UB ("null pointer passed as argument 2, which is declared to never be null") and is flagged by UBSan; AMA's API permits `ama_ed25519_sign(..., NULL, 0, ...)` for empty-message signing (RFC 8032 Test Vector 1).  The early-return is a pure no-op for all real behaviour but satisfies the non-null-attribute contract. |

No AES-NI-like hardware instructions exist for Ed25519; all speedups
are algorithmic (precomputed tables, Karatsuba / fe51 field layout,
signed-digit comb).

---

## Clean-room statement

For the three PQC primitives (`ama_kyber.c`, `ama_dilithium.c`,
`ama_sphincs.c`), the maintainer (Andrew E. A., Steel Security Advisors
LLC) attests that:

1. The C source was written directly against the FIPS 203 / 204 / 205
   specification text.
2. Neither pq-crystals, PQClean, liboqs, nor any other third-party
   PQC source tree was used as a copy source during development. Such
   trees were consulted at the specification layer only (to understand
   ambiguous FIPS wording) and never at the code layer.
3. Algorithmic correctness is validated by the ACVP vectors in
   [`CSRC_ALIGN_REPORT.md`](../../CSRC_ALIGN_REPORT.md). A clean-room
   implementation that matches byte-for-byte against the upstream KAT
   vectors is — by definition — interoperable with any conformant
   implementation.

This attestation does **not** claim:
- Formal proof of correctness. See `docs/DESIGN_NOTES.md §Limitations`.
- Immunity from implementation bugs. Two such bugs have already been
  found and fixed (the SLH-DSA hash-instantiation and address-zeroing
  bugs in [`CSRC_ALIGN_REPORT.md §2.3`](../../CSRC_ALIGN_REPORT.md)).
  Readers should expect more over the life of the project and are
  encouraged to file issues via the `SECURITY.md` disclosure process.
- FIPS 140-3 certification. See
  [`CSRC_ALIGN_REPORT.md §3.3`](../../CSRC_ALIGN_REPORT.md).

---

## Why this document exists

Post-quantum cryptographic libraries ship with heavy inheritance:
liboqs, AWS-LC, BoringSSL, OpenSSL 3.5+, and CIRCL all derive from
pq-crystals or PQClean and say so explicitly in their source trees.
Without a comparable provenance statement, readers of AMA Cryptography
have no way to tell whether the PQC code is a clean-room FIPS transcription,
a PQClean fork with the identifiers renamed, or something in between.

The file-level `Provenance:` comments in the three PQC sources plus
this document make the answer auditable: everything in `ama_kyber.c`,
`ama_dilithium.c`, and `ama_sphincs.c` was written here, against the
NIST standards, and is held to the same ACVP bar any FIPS-aspiring
implementation must clear.
