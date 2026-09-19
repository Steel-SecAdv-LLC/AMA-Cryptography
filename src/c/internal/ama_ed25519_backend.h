/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_ed25519_backend.h
 * @brief Entry points of the MULX+ADX instantiation of the Ed25519 group
 *        arithmetic (src/c/x86/ama_ed25519_fe64_mulx.c).
 *
 * src/c/ama_ed25519.c dispatches to these when ama_ed25519_set_mulx_override(1)
 * has selected the instantiation and ama_cpuid_has_x25519_mulx() reports
 * BMI2 and ADX; by default (a measured choice, see BACKEND DISPATCH there)
 * it calls its own fe51 instantiation.  One declaration, included by the definitions and
 * by the dispatcher, so the two cannot drift — the reason
 * src/c/internal/ama_x25519_fe64_mulx.h exists, applied here.
 *
 * Declared unconditionally (like ama_testing_exports.h): CMake defines
 * AMA_HAVE_ED25519_FE64_MULX_IMPL on the library targets only when the unit
 * is compiled, and the dispatcher references these names only under that
 * macro, so on every other build they are declarations of nothing and the
 * linker never looks for them.  Hidden visibility: internal to the library,
 * not ABI.
 *
 * Scalars arrive pre-recoded by the dispatcher (comb digits for the
 * constant-time base multiplication, wNAF digits for the variable-time
 * ladders); points arrive and leave as compressed 32-byte encodings.  The
 * int-returning entry points return 0 on success and -1 when an encoding is
 * refused (non-canonical or not a point); the verify check returns 1 for a
 * valid signature, 0 for an invalid one, -1 for a refused encoding.
 */
#ifndef AMA_ED25519_BACKEND_H
#define AMA_ED25519_BACKEND_H

#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define AMA_ED25519_BACKEND_HIDDEN __attribute__((visibility("hidden")))
#else
#define AMA_ED25519_BACKEND_HIDDEN
#endif

AMA_ED25519_BACKEND_HIDDEN
void ama_ed25519_ge_scalarmult_base_mulx(uint8_t out[32], const int8_t *comb_digits);
AMA_ED25519_BACKEND_HIDDEN
int ama_ed25519_ge_verify_half_mulx(const uint8_t R[32], const uint8_t A[32],
                                    const int8_t *w_v0, const int8_t *w_v1, int v1_negative,
                                    const int8_t *w_k0, const int8_t *w_k1, int top);
AMA_ED25519_BACKEND_HIDDEN
int ama_ed25519_ge_point_add_mulx(uint8_t out[32], const uint8_t p[32], const uint8_t q[32]);
AMA_ED25519_BACKEND_HIDDEN
int ama_ed25519_ge_scalarmult_vartime_mulx(uint8_t out[32], const int8_t *wnaf,
                                           const uint8_t p[32]);
AMA_ED25519_BACKEND_HIDDEN
int ama_ed25519_ge_double_scalarmult_vartime_mulx(uint8_t out[32], const int8_t *w1,
                                                  const uint8_t p1[32], const int8_t *w2,
                                                  const uint8_t p2[32]);
/* Test-only (defined under AMA_TESTING_MODE in the MULX unit). */
AMA_ED25519_BACKEND_HIDDEN
int ama_ed25519_ge_table_entry_mulx(int which, int i, int j, uint8_t out[32]);

/* Constant-time comb row fold on 256-bit registers
 * (src/c/avx2/ama_ed25519_select_avx2.c, compiled with -mavx2; linked when
 * CMake defines AMA_HAVE_AVX2_IMPL).  out receives the entry whose 1-based
 * index equals mag, or all zero for mag == 0; row is `entries` consecutive
 * Niels points of 12 (fe64) or 15 (fe51) words.  Callers gate on
 * ama_has_avx2(). */
AMA_ED25519_BACKEND_HIDDEN
void ama_ed25519_select12_avx2(uint64_t *out, const uint64_t *row, uint32_t mag, int entries);
AMA_ED25519_BACKEND_HIDDEN
void ama_ed25519_select15_avx2(uint64_t *out, const uint64_t *row, uint32_t mag, int entries);

#endif /* AMA_ED25519_BACKEND_H */
