/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_sve2_internal.h
 * @brief Internal prototypes for the hand-written AArch64 SVE2 SIMD kernels.
 *
 * PRIVATE to src/c/sve2/, the dispatch layer and the C tests that pin
 * individual kernels; not installed, never exposed to consumers.  The SVE2
 * counterpart of src/c/avx2/ama_avx2_internal.h and
 * src/c/neon/ama_neon_internal.h, created for the same reason: the ten
 * SVE2 entry points were defined with no visible prototype, which
 * `-Wmissing-prototypes` reports at every definition and which the
 * strict-warnings gate makes fatal.
 *
 * These kernels are doubly invisible to the gate as it stood: the gate runs
 * on x86-64, and `AMA_ENABLE_SVE2` defaults OFF even on AArch64, so the only
 * configuration that compiles them is the ARM-QEMU SVE2 job — which does not
 * apply the strict flag set.
 *
 * The vector length is not part of any signature here.  These are
 * vector-length-agnostic kernels operating on fixed-size scalar arrays; the
 * SVE registers live entirely inside the definitions.
 */

#ifndef AMA_SVE2_INTERNAL_H
#define AMA_SVE2_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "ama_cryptography.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Two predicates, because the definition site and the consumer site do not
 * see the same macros.
 *
 *   __ARM_FEATURE_SVE2  is predefined by the compiler only for translation
 *                       units built with `-march=armv9-a+sve2`, which
 *                       CMakeLists.txt applies PER FILE to the sources in
 *                       src/c/sve2/.  This is the guard the TUs use,
 *                       so it is what makes a prototype visible at each
 *                       definition (the point of this header).
 *   AMA_HAVE_SVE2_IMPL  is a whole-project definition added when the SVE2
 *                       sources are in the build.  src/c/dispatch/
 *                       ama_dispatch.c is compiled WITHOUT the +sve2 flags,
 *                       so it sees only this one — and it is the consumer
 *                       that stores these kernels into the dispatch table.
 *
 * Declaring under either keeps one source of truth for both sides; on any
 * build without SVE2 neither macro is defined and the header is empty. */
#if defined(__ARM_FEATURE_SVE2) || defined(AMA_HAVE_SVE2_IMPL)

/* ============================================================================
 * SHA-3 / Keccak
 * ============================================================================ */
void        ama_keccak_f1600_sve2(uint64_t state[25]);

/* ============================================================================
 * Kyber (ML-KEM)
 * ============================================================================ */
void ama_kyber_ntt_sve2(int16_t poly[256], const int16_t zetas[128]);
void ama_kyber_invntt_sve2(int16_t poly[256], const int16_t zetas[128]);
void ama_kyber_poly_pointwise_sve2(int16_t r[256],
                                   const int16_t a[256],
                                   const int16_t b[256],
                                   const int16_t zetas[128]);
void ama_kyber_poly_add_sve2(int16_t r[256],
                             const int16_t a[256],
                             const int16_t b[256]);
void ama_kyber_poly_sub_sve2(int16_t r[256],
                             const int16_t a[256],
                             const int16_t b[256]);
void ama_kyber_poly_reduce_sve2(int16_t poly[256]);

/* ============================================================================
 * Dilithium (ML-DSA)
 * ============================================================================ */
void ama_dilithium_ntt_sve2(int32_t poly[256], const int32_t zetas[256]);
void ama_dilithium_invntt_sve2(int32_t poly[256], const int32_t zetas[256]);
void ama_dilithium_poly_pointwise_sve2(int32_t r[256],
                                       const int32_t a[256],
                                       const int32_t b[256]);

#endif /* __ARM_FEATURE_SVE2 || AMA_HAVE_SVE2_IMPL */

#ifdef __cplusplus
}
#endif

#endif /* AMA_SVE2_INTERNAL_H */
