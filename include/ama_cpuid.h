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
