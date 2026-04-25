# AVX-512 Keccak 4-way — Decision Record

**Status:** Parked. Two unblock gates, both required.
**Date:** 2026-04-25
**Last x86-64 SIMD work shipped to `main`:** PR #266 (commit `30f7a0f`).
**Owner:** Steel Security Advisors LLC.

This is the terminal record for the AVX-512 Keccak 4-way work. It freezes the
decision to defer, fixes the unblock gates, and documents the existing
AVX-512 *safety* code in `main` so a future contributor does not strip it as
"leftover scaffolding." When the gates clear, the implementation PR (referred
to here as **PR C**) follows the sketch in §5 — no further planning step.

---

## 1. Work shipped since PR #261

PR #261 (`a57a3d6`, *Tier B — base-point comb + merged NTT + AVX2 rejection +
doc honesty*) is the last point at which this branch agreed with `main`. Two
PRs have landed since:

| PR    | SHA       | Subject                                                                      |
|-------|-----------|------------------------------------------------------------------------------|
| #265  | `7af9654` | `refactor(ed25519): rectify verify-path SWE inequities on top of AVX2 work`  |
| #266  | `30f7a0f` | `perf(aes-gcm): VAES + VPCLMULQDQ YMM AES-256-GCM — clean replacement for #264` |

PR #265 widens the variable-base wNAF window from 4 to 5 (≈18% fewer
additions in the verify scalar-mult loop) and applies Shamir's trick to
`[s]B + [h]A`. INVARIANT-12 unchanged: the routine remains variable-time by
contract, called only on public scalars.

PR #266 is the substantive x86-64 SIMD lever that landed: a 4-block-parallel
VAES + VPCLMULQDQ AES-256-GCM kernel, **YMM only**, gated on
`ama_cpuid_has_vaes_aesgcm()` = AVX2 ∧ VAES ∧ VPCLMULQDQ ∧ AES-NI ∧
PCLMULQDQ ∧ AVX-OSXSAVE. No `-mvaes -mvpclmulqdq` ZMM opcodes. No
`AMA_ENABLE_AVX512` build option. No new pthread_once. INVARIANT-15
unchanged.

PRs **#262, #263, #264** — earlier WIP and intermediate revisions of the
VAES dispatch work — are all **closed** and superseded by #266. Their head
branches are eligible for deletion at merge time of this doc; see §6.

## 2. Net x86-64 SIMD state on `main` today

* **Live:** AES-256-GCM bulk-throughput win via VAES + VPCLMULQDQ YMM.
* **Live (AVX2):** SHA3 / Keccak 4-way (`ama_keccak_f1600_x4_avx2` in
  `src/c/avx2/ama_sha3_avx2.c`, driven from
  `src/c/internal/ama_sha3_x4.h`), Kyber, Dilithium, SPHINCS+, ChaCha20-
  Poly1305, Argon2.
* **Parked:** the AVX-512 (ZMM-packed) Keccak 4-way kernel — the only
  remaining x86-64 SIMD lever. SHAKE drives sampling/expansion across
  ML-KEM-1024, ML-DSA-65, SPHINCS+, FROST, HMAC, and HKDF, so the gain
  compounds. Modeled at +20–40% on SHA3-256 1 KB.

## 3. Existing AVX-512 references in `main` are SAFETY code, not scaffolding

The lines below already exist in `main` because PR #266 hardened the
pre-existing `ama_has_avx512f()` stub from PR #213 against a latent SIGILL
on restricted-XCR0 VMs — hypervisors that expose AVX-512F in CPUID but mask
the AVX state bits in XCR0. They are load-bearing. **PR C must keep them.**

* `src/c/ama_cpuid.c`
  * `has_avx512f_cached` static (line ~88).
  * `xcr0_has_avx_state()` helper (lines ~117–158): XGETBV via the compiler
    intrinsic when `__XSAVE__` is defined, raw `.byte 0f 01 d0` fallback
    otherwise. Reads XCR0 bits 1+2 (SSE + AVX YMM Hi128). **Does not**
    read bits 5/6/7 (opmask / ZMM Hi256 / Hi16 ZMM); those are PR C's job.
  * `detect_x86_features()` populates `has_avx512f_cached` from leaf-7
    EBX[16] and `has_avx_osxsave_cached` from OSXSAVE + XCR0 (lines
    ~160–200).
  * `ama_has_avx512f()` returns
    `has_avx512f_cached && has_avx_osxsave_cached` (lines ~228–245).
    Without this gate, a VM that advertises AVX-512F in CPUID but masks
    AVX state in XCR0 would cause the dispatcher to wire the
    AMA_IMPL_AVX512 → AMA_IMPL_AVX2 fallback path, whose VEX-encoded
    YMM opcodes #UD on that host (Devin Review #3136221784).
  * Stub `ama_has_avx512f() { return 0; }` on AArch64 (line ~377) and on
    unsupported architectures (line ~411).

* `include/ama_cpuid.h`
  * `ama_has_avx512f()` declaration with the OSXSAVE/XCR0 docstring
    (lines ~134–150). The docstring explicitly notes that callers must
    *also* verify XCR0 bits 5/6/7 when the first AVX-512 kernel lands —
    PR C will tighten the gate when it ships ZMM code, **not** by
    relaxing this header.

* `src/c/dispatch/ama_dispatch.c`
  * `int has_avx512f = ama_has_avx512f();` (line ~226).
  * Belt-and-suspenders `if (has_avx512f && has_avx2) best = AMA_IMPL_AVX512;`
    (line ~235). The redundant `has_avx2` term prevents promotion to the
    AVX-512 tier on a CPU whose AVX2 XCR0 gate already failed. Do not
    remove on the grounds that AVX-512F implies AVX2 — the gate is about
    OS save-area state, not CPUID supersetting.
  * `effective = (best == AMA_IMPL_AVX512) ? AMA_IMPL_AVX2 : best;`
    (line ~240). This downgrade exists *because* there is no AVX-512
    kernel code yet; PR C is what removes the downgrade for the SHA3
    slot specifically.
  * Verbose dispatch log (line ~261) and human-readable name
    (`case AMA_IMPL_AVX512: return "AVX-512";` line ~576).

* `include/ama_dispatch.h`
  * `AMA_IMPL_AVX512 = 2` enum value (line ~28).

Total: ~28 lines of AVX-512 references in `main`. Every one of them is
either (a) a CPUID/XCR0 safety gate, (b) the dispatch downgrade that
keeps the safety gate from selecting non-existent code, or (c) the
already-public enum value. **None of it is implementation scaffolding.**

## 4. Unblock gates (both required)

PR C will only be opened when **both** of:

1. **CI runner with AVX-512 access** is declared in
   `.github/workflows/ci.yml`. Acceptable forms:
   * `ubuntu-latest` plus a `/proc/cpuinfo` capability gate that skips
     the AVX-512 job when the runner host lacks `avx512f`, **or**
   * a paid Sapphire Rapids / Zen 4 runner pool with a stable label.

   Today the CI matrix is `ubuntu-latest`, `windows-latest`, and
   `ubuntu-24.04-arm` — none of which guarantee AVX-512 host silicon —
   so this gate is open.

2. **The +20–40% SHA3-256 1 KB gain** clears the priority bar against
   other queued work. The win compounds across every primitive that
   uses SHAKE for sampling or expansion (ML-KEM-1024, ML-DSA-65,
   SPHINCS+, FROST, HMAC-SHA3-256, HKDF-SHA3-256), so the bar is not
   high — but it is non-zero, and "queued work" is reviewed per
   release, not on this branch.

These gates are conjunctive. Neither alone is sufficient.

## 5. PR C implementation sketch (follow this when both gates clear)

* **Vendor** XKCP's `KeccakP-1600-AVX512.s` plus the C glue into
  `src/c/vendor/XKCP/`. License is **CC0-1.0** — matches the
  INVARIANT-1 carve-out exactly (same pattern as
  `src/c/vendor/ed25519-donna/`). **No original Keccak AVX-512 writing.**
* **Build option** `AMA_ENABLE_AVX512` (CMake), default OFF. Compiles
  the vendored translation units in-tree with `-mavx512f -mavx512vl`
  (and any extension flags XKCP requires) under per-file
  `COMPILE_FLAGS`, identical to the AVX2 pattern in
  `src/c/avx2/CMakeLists.txt`.
* **Dispatcher**: drop the `AMA_IMPL_AVX512 → AMA_IMPL_AVX2` downgrade
  for `dispatch_info.sha3` only (line ~240 of
  `src/c/dispatch/ama_dispatch.c`). All other slots keep the downgrade
  until they grow ZMM kernels of their own.
* **CPUID gate tighten**: add an XCR0 bits 5+6+7 check
  (opmask / ZMM Hi256 / Hi16 ZMM) inside `ama_has_avx512f()`. The
  existing AVX-state gate stays — it is the AVX2-tier requirement and
  is independent of the ZMM-tier requirement.
* **KAT harness** validates byte-identity of the new permutation
  against:
  * the existing AVX2 4-way `ama_keccak_f1600_x4_avx2`, and
  * the scalar reference `ama_keccak_f1600` in `src/c/ama_sha3.c`,
  across the FIPS 202 SHAKE128 / SHAKE256 / SHA3-256 KAT vectors
  already wired into `tests/`.
* **Validation ladder**:
  1. Local SDE (`sde64 -spr -- ./test_sha3_kat`) — every developer
     workstation can run this regardless of host silicon.
  2. CPUID-gated CI job using whichever runner satisfies gate (1).
  3. Quarterly bare-metal benchmark on real Sapphire Rapids / Zen 4
     hardware to confirm the modeled +20–40% holds, and to detect any
     thermal / downclock anomaly.
* **Out of scope for PR C**: any other primitive's AVX-512 path
  (Kyber NTT, Dilithium NTT, AES-GCM ZMM, ChaCha20 ZMM, …). The
  whole point of opening one gate is to keep the kernel-level review
  surface small.

## 6. Closed-PR / branch cleanup

* PRs **#262, #263, #264** are closed; #266 supersedes them. The only
  remaining remote head from that cluster is
  `claude/fix-cryptography-pr-264-ZGpWu`, which can be deleted at the
  merge of this doc. The local branch list is otherwise clean.

## 7. What this document does *not* do

* It does not vendor any AVX-512 source.
* It does not add the `AMA_ENABLE_AVX512` build option.
* It does not change any CPUID gate, dispatch wiring, or
  enum value.
* It does not change CI.

It is text only, in `docs/`. Merging it is the act of closing the
topic — the next change to `main` on this subject is PR C itself.
