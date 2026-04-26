/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 */

/**
 * @file ama_cpuid.h
 * @brief CPU feature detection for AEAD backend selection
 * @author Andrew E. A., Steel Security Advisors LLC
 *
 * Detects hardware cryptographic acceleration:
 * - x86: AES-NI (CPUID leaf 1, ECX bit 25), PCLMULQDQ (ECX bit 1)
 * - ARM: AES + PMULL via ARMv8 Crypto Extensions
 *
 * Results are cached after first call for zero-overhead subsequent queries.
 *
 * AI Co-Architects: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
 */

#ifndef AMA_CPUID_H
#define AMA_CPUID_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Check for x86 AES-NI support.
 * @return 1 if AES-NI is available, 0 otherwise. Cached after first call.
 */
int ama_has_aes_ni(void);

/**
 * @brief Check for x86 PCLMULQDQ (carry-less multiply) support.
 * @return 1 if PCLMULQDQ is available, 0 otherwise. Cached after first call.
 */
int ama_has_pclmulqdq(void);

/* ============================================================================
 * VAES + VPCLMULQDQ probes (PR A — VAES AES-GCM YMM dispatch, 2026-04).
 *
 * VAES (CPUID.(EAX=7,ECX=0):ECX[9]) and VPCLMULQDQ (ECX[10]) are
 * *independent* of AVX-512.  Their VEX-encoded YMM forms only require
 * AVX OS save-area state (XCR0 bits 1 + 2 — SSE + AVX), not the AVX-512
 * opmask / ZMM bits.  Targeting YMM keeps the kernel off the pre-Ice-Lake
 * ZMM downclock curve entirely while still covering every Intel
 * Ice Lake+ / Alder Lake+ and AMD Zen 3+ host.
 *
 * All probes share the same pthread_once / InitOnceExecuteOnce primitive
 * that guards the rest of ama_cpuid.c (INVARIANT-15 unchanged — no new
 * once-primitive, no reordering of detect_x86_features()).  Non-x86
 * builds return 0 unconditionally, matching the existing ARM / generic
 * stubs above.
 * ============================================================================ */

/**
 * @brief Check for VAES (vectorized AES-NI) on YMM.
 *
 * CPUID.(EAX=7,ECX=0):ECX[9].  Lets a single AESENC / AESENCLAST act on
 * two 128-bit blocks packed in a YMM register.  Combined with the
 * 4-block-parallel inner loop in src/c/avx2/ama_aes_gcm_vaes_avx2.c,
 * this is the bulk-throughput primitive for the AVX2 VAES AES-GCM
 * path.  Returns 1 only when CPUID reports VAES *and* the OS has
 * enabled AVX state in XCR0 (bits 1 + 2).  AVX-512 state is
 * intentionally *not* required.
 */
int ama_has_vaes(void);

/**
 * @brief Check for VPCLMULQDQ (vectorized carry-less multiply) on YMM.
 *
 * CPUID.(EAX=7,ECX=0):ECX[10].  Carry-less multiply acting on two
 * 128-bit lanes of a YMM register simultaneously
 * (_mm256_clmulepi64_epi128) — emitted by the 4-block GHASH fold in
 * src/c/avx2/ama_aes_gcm_vaes_avx2.c (8 YMM CLMULs per 4-block
 * iteration, replacing the 16 XMM CLMULs of a per-lane Karatsuba).
 * GHASH must remain constant-time (INVARIANT-12), so this is paired
 * with a carry-less-multiply implementation rather than a table
 * lookup.  Returns 1 only when CPUID reports VPCLMULQDQ *and* the OS
 * has enabled AVX state in XCR0.
 */
int ama_has_vpclmulqdq(void);

/**
 * @brief Bundle check: AVX2 + VAES + VPCLMULQDQ + PCLMULQDQ + AES-NI.
 *
 * The VAES AES-GCM dispatch gate checks all five:
 *   - AVX2          — base ISA for YMM register set + integer ops
 *   - VAES          — 2-blocks-per-YMM AES rounds, emitted by the
 *                     4-block inner loop via _mm256_aesenc_epi128 /
 *                     _mm256_aesenclast_epi128
 *   - VPCLMULQDQ    — 2-lane carry-less multiply for the 4-lane
 *                     Karatsuba GHASH fold, emitted by the 4-block
 *                     inner loop via _mm256_clmulepi64_epi128
 *                     (8 YMM CLMULs per 4 blocks, vs 16 XMM in the
 *                     per-lane form)
 *   - PCLMULQDQ     — baseline 128-bit CLMUL (CPUID.(EAX=1):ECX[1]),
 *                     architecturally independent of VPCLMULQDQ
 *                     (CPUID.(EAX=7,ECX=0):ECX[10]).  The kernel calls
 *                     _mm_clmulepi64_si128 directly on every
 *                     single-block edge path (AAD blocks, H power
 *                     precompute, trailing-partial-block tail, and
 *                     the final length block), so the bundle must
 *                     gate PCLMULQDQ explicitly — every shipped CPU
 *                     with VPCLMULQDQ also has PCLMULQDQ but the ISA
 *                     does not document this as a strict superset
 *                     relationship (Devin Review #3140732664).
 *   - AES-NI        — 128-bit AESKEYGENASSIST runs the AES-256 key
 *                     schedule (VAES provides only the rounds);
 *                     _mm_aesenc_si128 / _mm_aesenclast_si128 are
 *                     also called on the single-block edge paths.
 *
 * Returns 1 only when every component passes; otherwise the dispatcher
 * falls back to the AVX2 AES-NI + PCLMULQDQ path shipped in #253 / #254.
 */
int ama_cpuid_has_vaes_aesgcm(void);

/**
 * @brief Check for x86 AVX2 runtime capability.
 *
 * CPUID.(EAX=7,ECX=0):EBX[5] AND OSXSAVE AND XCR0 bits 1+2 (SSE+AVX).
 * The OSXSAVE/XCR0 gate is essential: on a VM whose host kernel has
 * not enabled AVX state, VEX-encoded 128-bit or 256-bit AVX opcodes
 * will #UD, so the runtime dispatcher must refuse to select the AVX2
 * path there.  A caller who needs the raw CPUID feature-flag bit
 * (e.g. capability advertisement divorced from execution safety)
 * should not use this function.
 *
 * @return 1 if AVX2 is available AND the OS has enabled AVX state,
 *         0 otherwise.  Cached after first call.
 */
int ama_has_avx2(void);

/**
 * @brief Check for x86 AVX-512F CPUID feature bit + full AVX-512 OS state.
 *
 * CPUID.(EAX=7,ECX=0):EBX[16] AND OSXSAVE AND XCR0 bits 1+2 (SSE+AVX)
 * AND XCR0 bits 5+6+7 (opmask, ZMM Hi256, Hi16 ZMM).  AVX-512F is a
 * strict superset of AVX2, but the AVX OS-state gate alone is *not*
 * sufficient — *any* EVEX-encoded opcode (including the EVEX-encoded
 * YMM forms emitted by the in-house AVX-512 4-way Keccak kernel:
 * vprolq, vpternlogq) requires the AVX-512 save area enabled in XCR0.
 * Without that gate, the first EVEX op would #UD on a host whose
 * hypervisor advertises the CPUID bits but masks the XCR0 bits — the
 * same SIGILL category Devin Review #3136221784 covers for AVX2.
 *
 * @return 1 if AVX-512F is reported by CPUID AND the OS has enabled
 *         both the AVX state and the AVX-512 ZMM/opmask state,
 *         0 otherwise.  Cached after first call.
 */
int ama_has_avx512f(void);

/**
 * @brief Check for x86 AVX-512VL CPUID feature bit + full AVX-512 OS state.
 *
 * CPUID.(EAX=7,ECX=0):EBX[31] AND the same XCR0 contract as
 * ama_has_avx512f().  AVX-512VL ("Vector Length") is what allows
 * EVEX-encoded AVX-512 instructions (vprolq, vpternlogq, …) to act on
 * 256-bit YMM (and 128-bit XMM) registers instead of requiring full
 * 512-bit ZMM operands.  The 4-way Keccak kernel uses YMM-width EVEX
 * ops exclusively, so AVX-512VL — not just AVX-512F — is part of its
 * runtime gate.
 *
 * @return 1 if AVX-512VL is reported by CPUID AND the OS has enabled
 *         the AVX-512 save area, 0 otherwise.  Cached after first call.
 */
int ama_has_avx512vl(void);

/**
 * @brief Bundle check: AVX-512F + AVX-512VL + full AVX/AVX-512 OS state.
 *
 * The AVX-512 4-way Keccak dispatch gate.  Returns 1 only when every
 * component required by the in-house kernel
 * (src/c/avx512/ama_sha3_x4_avx512.c) passes:
 *   - AVX-512F  — base ISA enabling EVEX encoding
 *   - AVX-512VL — EVEX-encoded vprolq / vpternlogq on YMM (__m256i)
 *   - AVX OS state (XCR0 bits 1+2)        — checked transitively
 *   - AVX-512 OS state (XCR0 bits 5+6+7)  — checked transitively
 *
 * Otherwise the dispatcher leaves the SHA3 4-way slot wired to the
 * AVX2 kernel (ama_keccak_f1600_x4_avx2) — never to a generic-only
 * fallback when AVX2 is itself available.
 */
int ama_cpuid_has_avx512_keccak(void);

/* ============================================================================
 * BMI2 + ADX probes (PR D — MULX+ADX X25519 fe64 kernel, 2026-04).
 *
 * BMI2 (CPUID.(EAX=7,ECX=0):EBX[8]) supplies MULX — an unsigned 64×64→128
 * multiplication that writes the high half to one register and the low
 * half to another *without touching the carry flag*.  ADX (EBX[19])
 * supplies ADCX / ADOX — two independent 64-bit add-with-carry chains
 * that consume CF and OF respectively, so the kernel can interleave two
 * carry chains across the 4×4 schoolbook without serialising on CF.
 *
 * Together they let a hand-tuned X25519 fe64 multiply emit the entire
 * inner loop without GCC's spilled-flag overhead — the exact pattern
 * the OpenSSL "x25519-x86_64.pl" and BoringSSL "fiat" generators use to
 * outrun the pure-C radix-2^64 schoolbook by ~1.8–2.2× on Skylake+.
 *
 * Both bits are read at the same detect_x86_features() probe as the
 * legacy AES-NI / AVX2 / AVX-512 / VAES fields above (INVARIANT-15
 * unchanged: same once-primitive, no reordering, no new call sites in
 * dispatch_init_internal()).  Neither requires any XCR0 gate — MULX
 * targets general-purpose registers, ADCX/ADOX target rFLAGS and
 * general-purpose registers, no SIMD save area is touched.
 * ============================================================================ */

/**
 * @brief Check for x86 BMI2 (MULX, et al.) support.
 *
 * CPUID.(EAX=7,ECX=0):EBX[8].  MULX is the single-instruction
 * 64×64→128-bit unsigned multiply that writes the high half into one
 * destination register and the low half into another *without altering
 * the CF / OF flags*.  This is the prerequisite for interleaving with
 * ADX (ADCX/ADOX) in the X25519 fe64 multiply — without MULX, every
 * 64×64 product would spill the high half through RDX and clobber the
 * carry chain.
 *
 * No XCR0 gate is required: MULX is a general-purpose instruction with
 * no SIMD save-area dependency.
 *
 * @return 1 if BMI2 is reported by CPUID, 0 otherwise.  Cached after
 *         first call.
 */
int ama_has_bmi2(void);

/**
 * @brief Check for x86 ADX (ADCX, ADOX) support.
 *
 * CPUID.(EAX=7,ECX=0):EBX[19].  ADCX consumes/produces CF; ADOX
 * consumes/produces OF.  Pairing them lets the X25519 fe64 multiply
 * carry two independent reduction chains across the 4×4 schoolbook in
 * parallel, eliminating the carry-flag bottleneck that limits the
 * pure-C radix-2^64 schoolbook on x86-64.
 *
 * No XCR0 gate is required: ADCX/ADOX are general-purpose instructions
 * that touch only rFLAGS and the named general-purpose registers.
 *
 * @return 1 if ADX is reported by CPUID, 0 otherwise.  Cached after
 *         first call.
 */
int ama_has_adx(void);

/**
 * @brief Bundle check: BMI2 + ADX gate for the X25519 fe64 MULX+ADX kernel.
 *
 * Returns 1 only when both BMI2 (MULX) and ADX (ADCX/ADOX) are reported
 * by CPUID.  Both feature bits ship together on every Intel Broadwell+
 * and AMD Zen+ part — but the ISA documents them as architecturally
 * independent, so the bundle gates each one explicitly rather than
 * relying on the empirical "every shipped CPU with one has the other"
 * observation (same defensive contract used by
 * `ama_cpuid_has_vaes_aesgcm()` for VPCLMULQDQ vs PCLMULQDQ).
 *
 * The hand-tuned MULX+ADX inner loop in
 * `src/c/internal/ama_x25519_fe64_mulx.c` emits both opcode families
 * unconditionally — without this bundle gate, the dispatcher must
 * leave the X25519 entry point on the pure-C fe64 schoolbook
 * (or fe51, on a host where fe64 was forced off).
 *
 * Otherwise the dispatcher falls back to the pure-C fe64 multiply
 * emitted by `fe64_mul` / `fe64_sq` in `src/c/fe64.h` — the same
 * radix-2^64 schoolbook the in-tree ladder already uses, just without
 * the MULX+ADCX/ADOX micro-optimisation.
 */
int ama_cpuid_has_x25519_mulx(void);

/**
 * @brief Check for ARMv8 AES Crypto Extension support.
 * @return 1 if ARM AES is available, 0 otherwise. Cached after first call.
 */
int ama_has_arm_aes(void);

/**
 * @brief Check for ARMv8 PMULL (polynomial multiply) support.
 * @return 1 if ARM PMULL is available, 0 otherwise. Cached after first call.
 */
int ama_has_arm_pmull(void);

/**
 * @brief Check for ARMv8 NEON advanced-SIMD support.
 * @return 1 if NEON is available, 0 otherwise. Cached after first call.
 */
int ama_has_arm_neon(void);

/**
 * @brief Check for ARMv9 SVE2 advanced-SIMD support.
 * @return 1 if SVE2 is available, 0 otherwise. Cached after first call.
 */
int ama_has_arm_sve2(void);

/**
 * AEAD backend identifiers for runtime dispatch.
 */
typedef enum {
    AMA_AEAD_HW_AES_GCM = 0,      /**< Hardware-accelerated AES-256-GCM (AES-NI/ARMv8-CE) */
    AMA_AEAD_CHACHA20_POLY1305 = 1, /**< ChaCha20-Poly1305 (constant-time by design) */
    AMA_AEAD_SW_AES_GCM = 2         /**< Software AES-256-GCM (bitsliced constant-time) */
} ama_aead_backend_t;

/**
 * @brief Select the best available AEAD backend at runtime.
 *
 * Selection logic:
 *   - If AES-NI + PCLMULQDQ (x86) or AES + PMULL (ARM): AMA_AEAD_HW_AES_GCM
 *   - Otherwise: AMA_AEAD_CHACHA20_POLY1305 (constant-time by design)
 *
 * Never uses software table-based AES-GCM on secret data at runtime.
 * The bitsliced path remains as a compile-time option via AMA_AES_CONSTTIME.
 *
 * @return Selected AEAD backend identifier
 */
ama_aead_backend_t ama_select_aead(void);

/**
 * @brief Get human-readable name of the selected AEAD backend.
 * @param backend The backend identifier
 * @return Static string describing the backend
 */
const char *ama_aead_backend_name(ama_aead_backend_t backend);

#ifdef __cplusplus
}
#endif

#endif /* AMA_CPUID_H */
