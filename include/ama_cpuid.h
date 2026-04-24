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
 * @brief Bundle check: AVX2 + VAES + VPCLMULQDQ + AES-NI.
 *
 * The VAES AES-GCM dispatch gate checks all four:
 *   - AVX2          — base ISA for YMM register set + integer ops
 *   - VAES          — 2-blocks-per-YMM AES rounds, emitted by the
 *                     4-block inner loop via _mm256_aesenc_epi128 /
 *                     _mm256_aesenclast_epi128
 *   - VPCLMULQDQ    — 2-lane carry-less multiply for the 4-lane
 *                     Karatsuba GHASH fold, emitted by the 4-block
 *                     inner loop via _mm256_clmulepi64_epi128
 *                     (8 YMM CLMULs per 4 blocks, vs 16 XMM in the
 *                     per-lane form)
 *   - AES-NI        — 128-bit AESKEYGENASSIST runs the AES-256 key
 *                     schedule (VAES provides only the rounds; the
 *                     single-block edge paths — AAD, trailing
 *                     partial, length block — also stay on
 *                     _mm_clmulepi64_si128 since vectorising a
 *                     single-block multiply does not pay back the
 *                     pack/fold overhead).
 *
 * Returns 1 only when every component passes; otherwise the dispatcher
 * falls back to the AVX2 AES-NI + PCLMULQDQ path shipped in #253 / #254.
 */
int ama_cpuid_has_vaes_aesgcm(void);

/**
 * @brief Check for x86 AVX2 (CPUID.(EAX=7,ECX=0):EBX[5]).
 * @return 1 if AVX2 is available, 0 otherwise. Cached after first call.
 */
int ama_has_avx2(void);

/**
 * @brief Check for x86 AVX-512F (CPUID.(EAX=7,ECX=0):EBX[16]).
 * @return 1 if AVX-512F is available, 0 otherwise. Cached after first call.
 */
int ama_has_avx512f(void);

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
