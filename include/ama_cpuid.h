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

/* ========================================================================
 * AVX-512 bundle probes (PR A — VAES / VPCLMULQDQ dispatch, 2026-04).
 *
 * CPUID probes run once and are memoized behind the same pthread_once /
 * InitOnceExecuteOnce primitive that guards the rest of ama_cpuid.c.  All
 * helpers below include an OSXSAVE + XCR0 check (bits 1, 2, 5, 6, 7) so
 * we never emit a ZMM / opmask instruction on a host whose OS has not
 * enabled the AVX-512 state-save area — that gate is non-negotiable,
 * otherwise the dispatched path would #UD inside a VM with AVX-512
 * bits visible via CPUID but disabled in XCR0.
 *
 * On any non-x86-64 architecture these helpers unconditionally return 0,
 * mirroring the AArch64 / generic stubs already used for AES-NI below.
 * ======================================================================== */

/**
 * @brief Check for AVX-512 Foundation (AVX-512F).
 *
 * Returns 1 only when the CPU reports CPUID.(EAX=7,ECX=0):EBX[16] AND the
 * OS has enabled the AVX-512 opmask + ZMM state in XCR0 (bits 5, 6, 7)
 * alongside the AVX state (bits 1, 2).  Zero on non-x86-64 hosts.
 */
int ama_has_avx512f(void);

/**
 * @brief Check for AVX-512 Vector Length Extensions (AVX-512VL).
 *
 * CPUID.(EAX=7,ECX=0):EBX[31].  Enables 512-bit opcodes to target XMM/YMM
 * registers — required for the VAES AES-GCM path, which uses 256-bit
 * VAES rather than full-width ZMM in order to avoid the downclock
 * penalty that some Xeon SKUs still apply to sustained ZMM traffic.
 */
int ama_has_avx512vl(void);

/**
 * @brief Check for VAES (vectorized AES-NI).
 *
 * CPUID.(EAX=7,ECX=0):ECX[9].  Lets a single AESENC / AESENCLAST act on
 * four 128-bit blocks packed in a ZMM (or two in a YMM under AVX-512VL).
 * Core building block of the 4-block-parallel AES round used in the
 * PR A AES-GCM path.
 */
int ama_has_vaes(void);

/**
 * @brief Check for VPCLMULQDQ (vectorized carry-less multiply).
 *
 * CPUID.(EAX=7,ECX=0):ECX[10].  Carry-less multiply acting on four 128-bit
 * lanes of a ZMM simultaneously — used for 4-lane Karatsuba GHASH and
 * Montgomery reduction in the PR A AES-GCM path.  Must be paired with
 * VPCLMULQDQ *not* a table-lookup GHASH to preserve INVARIANT-12.
 */
int ama_has_vpclmulqdq(void);

/**
 * @brief Bundle check: AVX-512F + AVX-512VL + VAES + VPCLMULQDQ + AES-NI.
 *
 * The PR A AES-GCM path requires all four AVX-512 bits plus the legacy
 * AES-NI key-expansion opcodes.  Returns 1 only when every component
 * passes; otherwise the dispatcher falls back to the AVX2 AES-NI +
 * PCLMULQDQ path shipped in #253 / #254.
 */
int ama_cpuid_has_avx512_aesgcm_bundle(void);

/**
 * @brief Bundle check: AVX-512F (Keccak-f[1600] 4-way path).
 *
 * The AVX-512 Keccak kernel packs four independent 25 × uint64_t states
 * one-lane-per-ZMM and needs only AVX-512F for the permutation itself;
 * VL / VBMI / VAES are not required.  Exists as a named helper so the
 * dispatcher (and tests) never have to duplicate the OSXSAVE gate.
 */
int ama_cpuid_has_avx512_keccak(void);

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
