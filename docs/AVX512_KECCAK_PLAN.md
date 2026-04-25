# AVX-512 Keccak 4-way — Decision Record

**Status:** Decided + shipped. Build flag `AMA_ENABLE_AVX512` (default OFF), in-house implementation.
**Date:** 2026-04-25
**Merged in:** PR #269 (commit 6a86668).
**Owner:** Steel Security Advisors LLC.

This is the Architecture Decision Record (ADR) for the AVX-512 4-way Keccak
permutation kernel. The earlier revision of this file framed the work as
*deferred pending two unblock gates*, with a sketch that pointed at vendoring
XKCP's `KeccakP-1600-AVX512.s`. Both gates have since been satisfied
(`/proc/cpuinfo`-probed runner job in `.github/workflows/ci.yml`; +20–40%
SHA3-256 1 KB win cleared the priority bar against other queued work) and the
implementation has shipped. This revision records **the decision that was
taken when both gates cleared**, the rationale for that decision, and what
landed.

---

## 1. Decision

**Use an in-house, hand-written AVX-512VL Keccak-f[1600] 4-way kernel.**
**Do not vendor XKCP.**

The kernel lives at `src/c/avx512/ama_sha3_x4_avx512.c` (228 lines,
hand-written intrinsics). It exposes the same `void (uint64_t states[4][25])`
ABI as `ama_keccak_f1600_x4_avx2` (`src/c/avx2/ama_sha3_avx2.c`), which is
the contract every existing 4-way SHAKE/SHA3 caller already targets through
`dispatch_table.keccak_f1600_x4`. The dispatcher promotes only the SHA3
slot (`src/c/dispatch/ama_dispatch.c` line ~276) to `AMA_IMPL_AVX512`; every
other slot keeps the existing effective-level downgrade until it grows its
own ZMM/EVEX kernel.

## 2. Why in-house, not vendored XKCP

Five reasons, in priority order:

1. **INVARIANT-1 vendor-crypto surface.** The repo already carves out exactly
   one external crypto dependency — `src/c/vendor/ed25519-donna/`, kept under
   the INVARIANT-1 carve-out for ed25519's hand-tuned amd64 scalarmult.
   Adding a second carve-out (`src/c/vendor/XKCP/`) widens the audit surface
   permanently for a single permutation. The in-house option costs us a
   one-time review of 228 lines of intrinsics; the vendor option costs us a
   running carve-out plus periodic upstream tracking.

2. **The wins that matter are single-instruction wins.** Branch B's kernel is
   228 lines of auditable AVX-512VL intrinsics emitted at YMM width — exactly
   the two single-instruction levers that move the needle over the AVX2
   reference:

   * `vprolq` (`_mm256_rol_epi64`) replaces the AVX2 kernel's synthesised
     `(x << n) | (x >> 64-n)` rotate (`rotl64_avx2` in
     `src/c/avx2/ama_sha3_avx2.c`).
   * `vpternlogq` (`_mm256_ternarylogic_epi64`) collapses theta's 5-way XOR
     to two ternlog-`0x96` ops, and the chi step `B[i] ^ (~B[i+1] & B[i+2])`
     to one ternlog-`0xD2` op.

   ZMM 8-way (true 64-byte lane packing) is a future concern. We deliberately
   stayed at YMM width for this kernel — the lanes already fit, and the
   Skylake-SP / Cascade Lake ZMM downclock curve is real-world hostile to
   short Keccak invocations. Vendoring XKCP would buy us the 8-way kernel
   along with the 4-way kernel, but only the 4-way kernel maps onto the
   existing 4-way SHAKE call sites; the 8-way kernel would require a separate
   ABI plus a separate dispatch slot that no caller currently uses.

3. **ABI continuity with the AVX2 4-way kernel.** Branch B's kernel matches
   the AVX2 4-way contract (`uint64_t states[4][25]`, lane-packed
   `__m256i`-style across the four states) byte-for-byte. The dispatcher
   wires either kernel through the same function-pointer slot, so the absorb
   / squeeze wrappers in `src/c/ama_sha3.c` are unchanged. XKCP's
   `KeccakP-1600-AVX512.s` uses an interleaved per-lane layout that would
   force an ABI shim and dispatcher surgery — a strictly larger change for a
   strictly smaller win.

4. **Constant-time / KAT byte-identity is easier to argue.** Keccak-f is
   data-independent by construction (FIPS 202 §3.2 — no secret-dependent
   branches or memory addressing), and INVARIANT-12 holds for our scalar and
   AVX2 4-way kernels. Because Branch B's kernel is structurally a
   straightforward EVEX rewrite of the AVX2 4-way kernel — same lane packing,
   same round-loop structure, same store / unpack pattern — the constant-time
   argument transfers from the AVX2 kernel verbatim. The KAT harness in
   `tests/c/test_sha3_avx512_kat.c` exercises that argument empirically by
   asserting byte-identity vs both the scalar reference (`src/c/ama_sha3.c::
   ama_keccak_f1600_generic`) and the AVX2 4-way kernel across SHAKE128,
   SHAKE256, and SHA3-256, including the FIPS 202 KAT vectors and edge-case
   absorb/squeeze lengths.

5. **The earlier revision of this file was a plan; the implementation is the
   record.** The original ADR sketched a vendoring path because that was the
   lowest-risk path *if no in-house alternative existed*. Branch B
   (`copilot/claudeavx512-keccak-4-way-kernel`) demonstrated the in-house
   alternative exists, audits cleanly, and matches the AVX2 4-way ABI
   exactly. We update the record to reflect the actual decision.

## 3. What shipped

* `src/c/avx512/ama_sha3_x4_avx512.c` — the kernel (228 lines).
* `src/c/ama_cpuid.c` — adds `xcr0_has_avx512_state()` (XCR0 bits 5+6+7 —
  opmask + ZMM Hi256 + Hi16 ZMM), surfaces `ama_has_avx512vl()` and the
  bundle helper `ama_cpuid_has_avx512_keccak()`, and tightens
  `ama_has_avx512f()` to AND its previous AVX-state gate with the new
  ZMM-state gate. Without that, the first EVEX-encoded YMM op would `#UD`
  on a host whose hypervisor advertised CPUID bits but masked the XCR0
  bits — same SIGILL category Devin Review #3136221784 covered for AVX2
  in PR A. INVARIANT-15 unchanged: every new cache field is populated from
  the same one-shot `detect_x86_features()` invocation as the legacy
  fields, gated by the existing `cpuid_once` once-primitive.
* `src/c/dispatch/ama_dispatch.c` — adds the SHA3-only AVX-512 promotion
  guarded by `#ifdef AMA_HAVE_AVX512_IMPL && ama_cpuid_has_avx512_keccak()`.
  All other slots keep the per-slot effective→AVX2 downgrade. The
  belt-and-suspenders `(has_avx512f && has_avx2)` AVX-512 promotion gate
  noted in §3 of the previous revision is preserved verbatim.
* `include/ama_cpuid.h` — public declarations for `ama_has_avx512vl()` and
  `ama_cpuid_has_avx512_keccak()` (the latter is the predicate the
  dispatcher consults).
* `CMakeLists.txt` — adds `option(AMA_ENABLE_AVX512 ... OFF)`. When ON,
  compiles `src/c/avx512/ama_sha3_x4_avx512.c` with per-file
  `-mavx512f -mavx512vl` (mirrors the AVX2 per-file pattern in the same
  file) and defines `AMA_HAVE_AVX512_IMPL` on the library targets.
  Default OFF — does not perturb the existing matrix builds.
* `tests/c/test_sha3_avx512_kat.c` — KAT byte-identity harness. Skips with
  CTest exit code 77 (INVARIANT-3 — observable skip, never silent pass) when
  `ama_cpuid_has_avx512_keccak()` returns 0.
* `.github/workflows/ci.yml` — `test-avx512` job. Probes `/proc/cpuinfo`
  for `avx512f` and `avx512vl`; when present, configures with
  `-DAMA_ENABLE_AVX512=ON`, builds and runs the KAT. The build/test body
  itself never uses `continue-on-error` (INVARIANT-2 — fail-closed CI).
  Skip-honest when the runner's host silicon doesn't advertise AVX-512.

## 4. Validation ladder

1. **Local SDE** — `sde64 -spr -- ./build/bin/test_sha3_avx512_kat`. Runs
   on every developer workstation regardless of host silicon. (Same gate the
   pre-shipping decision sketch named, retained.)
2. **CPUID-gated CI job** — `test-avx512` in `.github/workflows/ci.yml`.
   Best-effort: GitHub-hosted `ubuntu-latest` rotates among Cascade Lake /
   Ice Lake / Sapphire Rapids host CPUs, so AVX-512 hits some fraction of
   runs. The `/proc/cpuinfo` probe makes the skip honest.
3. **Quarterly bare-metal benchmark** on real Sapphire Rapids / Zen 4
   hardware to confirm the modeled +20–40% holds and to detect any thermal
   / downclock anomaly. Not on this PR's critical path.

## 5. Out of scope (no scope creep here)

* **ZMM 8-way Keccak.** A future kernel concern; would require a new
  dispatch slot and new ABI. No 4-way caller is left waiting for it.
* **Any other primitive's AVX-512 path** — Kyber NTT, Dilithium NTT,
  AES-GCM ZMM, ChaCha20 ZMM, Argon2, SPHINCS+. Each will get its own ADR
  if and when its own win clears the priority bar. The whole point of
  promoting one slot is to keep the kernel-level review surface small.
* **Removing `AMA_IMPL_AVX2` as a fallback.** Even when `AMA_ENABLE_AVX512`
  is ON, the AVX2 4-way kernel remains the fallback whenever
  `ama_cpuid_has_avx512_keccak()` returns 0 at runtime. Stripping the
  fallback would defeat the whole CPUID-gated dispatch model.

## 6. INVARIANT crosswalk

| INVARIANT | Effect |
|-----------|--------|
| INVARIANT-1  | **Held.** No new vendor crypto dependency. Existing carve-out (`src/c/vendor/ed25519-donna/`) remains the only one. |
| INVARIANT-2  | **Held.** `test-avx512` CI job's build/test body never uses `continue-on-error`; the only conditional is the `/proc/cpuinfo`-driven skip on the steps themselves. |
| INVARIANT-3  | **Held.** KAT skip surfaces as CTest exit code 77 (observable "Skipped"), not a silent pass. |
| INVARIANT-12 | **Held.** Keccak-f is data-independent; new kernel mirrors AVX2 4-way structure exactly. |
| INVARIANT-15 | **Held.** All new CPUID cache fields populated from the same one-shot `detect_x86_features()` invocation; no new once-primitive. |

## 7. What this document does *not* do

* It does not vendor any AVX-512 source.
* It does not add the ZMM 8-way kernel.
* It does not change the AVX2 4-way kernel.
* It does not promote any non-SHA3 dispatch slot.

The next material change to `main` on this subject — if any — will be a
new ADR for one of the items in §5.
