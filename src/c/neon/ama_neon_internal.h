/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_neon_internal.h
 * @brief Internal prototypes for the hand-written AArch64 NEON SIMD kernels.
 *
 * This header is PRIVATE to src/c/neon/, to the dispatch layer and to the
 * C tests that pin individual kernels.  It is NOT installed and is never
 * exposed to library consumers; every symbol declared here is a
 * runtime-dispatch implementation detail.
 *
 * It is the NEON counterpart of src/c/avx2/ama_avx2_internal.h and exists
 * for the same two reasons.
 *
 * 1. `-Wmissing-prototypes` is a project-wide flag (CMakeLists.txt) and
 *    `-Werror=missing-prototypes` in the strict-warnings gate.  Every NEON
 *    entry point was defined without a prior declaration, so each one
 *    produced a warning at its definition — 25 of them across the eight
 *    files here.  None was ever reported, because the strict-warnings gate
 *    runs on x86-64 only, where these translation units compile to an empty
 *    `#else` typedef.  The gate's claim ("no warnings outside src/c/vendor/
 *    beyond the two documented extension classes") was true of the one
 *    architecture it built, and the AArch64 build it never ran was carrying
 *    the exact class the gate makes fatal.
 *
 * 2. The prototypes were being re-transcribed by hand at each consumer:
 *    `src/c/dispatch/ama_dispatch.c` declared its own `extern` block,
 *    `src/c/ama_sha256.c` declared `ama_sha256_compress_neon` again, and
 *    `tests/c/test_sha256_neon_kat.c` a third time.  These are raw
 *    `uint8_t[]` / `uint32_t[]` buffer signatures whose addresses are then
 *    stored in a dispatch table: a signature that drifts between the
 *    definition and one of its transcriptions is not a compile error, it is
 *    undefined behaviour at the indirect call.  One declaration, included by
 *    both the definition and every consumer, makes that drift impossible.
 *
 * Symbols with no in-tree caller today are declared here too rather than
 * being made `static`: they are dispatch-graph material kept in-tree (the
 * lane-local add/sub/carry/compress routines), and turning them static
 * would remove symbols from the shipped shared library — an ABI change made
 * for a lint's convenience.  Declaring them is the fix for the missing
 * prototype; whether to wire them into dispatch is a separate question.
 */

#ifndef AMA_NEON_INTERNAL_H
#define AMA_NEON_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "ama_cryptography.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Every kernel below exists only on AArch64; on other targets the defining
 * translation units collapse to a placeholder typedef and the dispatcher
 * never references these names.  Declaring them unconditionally would be
 * harmless but misleading, and `fe51_neon` genuinely needs <arm_neon.h>'s
 * target to be meaningful. */
#if defined(__aarch64__) || defined(_M_ARM64)

/* ============================================================================
 * SHA-3 / Keccak — dispatch-facing
 * ============================================================================ */
void        ama_keccak_f1600_neon(uint64_t state[25]);

/* ============================================================================
 * Kyber (ML-KEM)
 *
 * ntt / invntt / poly_pointwise are dispatch-facing.  There is no NEON
 * kyber_poly_add / kyber_poly_sub: the dispatch table's kyber_poly_* slots are
 * wired for SVE2 only (see src/c/dispatch/ama_dispatch.c), and the NEON tier
 * reaches the same arithmetic through the compiler's auto-vectorisation of the
 * scalar int16 loops in src/c/ama_kyber.c.  The unwired NEON helpers that used
 * to sit here were removed as unexercised dead code (audit Low).
 * ============================================================================ */
void ama_kyber_ntt_neon(int16_t poly[256], const int16_t zetas[128]);
void ama_kyber_invntt_neon(int16_t poly[256], const int16_t zetas[128]);
void ama_kyber_poly_pointwise_neon(int16_t r[256],
                                   const int16_t a[256],
                                   const int16_t b[256],
                                   const int16_t zetas[128]);

/* ============================================================================
 * Dilithium (ML-DSA)
 *
 * ntt / invntt / poly_pointwise are dispatch-facing.  The unwired poly_add,
 * poly_sub and power2round helpers that used to sit here were removed: dead
 * code (no caller/test), and the power2round one was additionally incorrect —
 * it failed the FIPS 204 reconstruction and did not match the production
 * scalar dil_power2round (audit Low).  A future dispatch-graph extension must
 * add a correct, tested slot rather than resurrect them.
 * ============================================================================ */
void ama_dilithium_ntt_neon(int32_t poly[256], const int32_t zetas[256]);
void ama_dilithium_invntt_neon(int32_t poly[256], const int32_t zetas[256]);
void ama_dilithium_poly_pointwise_neon(int32_t r[256],
                                       const int32_t a[256],
                                       const int32_t b[256]);

/* ============================================================================
 * AES-256-GCM — ARMv8 Crypto Extensions kernel
 * ============================================================================ */
/* Defined only when the ARM Crypto Extensions are available to the compiler
 * (see the AMA_HAVE_NEON_CRYPTO_EXT_IMPL block in CMakeLists.txt).  Declared
 * under the same condition so a build that cannot define them cannot
 * accidentally reference them either — that mismatch is what made every MSVC
 * ARM64 build fail to link. */
#ifdef AMA_HAVE_NEON_CRYPTO_EXT_IMPL
void ama_aes256_gcm_encrypt_neon(const uint8_t *plaintext, size_t plaintext_len,
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t key[32], const uint8_t nonce[12],
                                 uint8_t *ciphertext, uint8_t tag[16]);
ama_error_t ama_aes256_gcm_decrypt_neon(const uint8_t *ciphertext,
                                        size_t ciphertext_len,
                                        const uint8_t *aad, size_t aad_len,
                                        const uint8_t key[32],
                                        const uint8_t nonce[12],
                                        const uint8_t tag[16],
                                        uint8_t *plaintext);
#endif /* AMA_HAVE_NEON_CRYPTO_EXT_IMPL */

/* ============================================================================
 * ChaCha20
 *
 * The x8 form is dispatch-facing.  The x4 form is the two-block building
 * block kept beside it; nothing calls it today.
 * ============================================================================ */
void ama_chacha20_block_x4_neon(const uint8_t key[32],
                                const uint8_t nonce[12],
                                uint32_t counter,
                                uint8_t out[256]);
void ama_chacha20_block_x8_neon(const uint8_t key[32],
                                const uint8_t nonce[12],
                                uint32_t counter,
                                uint8_t out[512]);

/* ============================================================================
 * Argon2 BlaMka G function (and the BLAKE2b compression it is built on)
 * ============================================================================ */
void ama_blake2b_compress_neon(uint64_t h[8], const uint64_t m[16],
                               uint64_t t0, uint64_t t1, int is_final);
void ama_argon2_g_neon(uint64_t out[128],
                       const uint64_t x[128],
                       const uint64_t y[128]);

/* ============================================================================
 * SHA-256 / SPHINCS+ (SLH-DSA)
 *
 * ama_sha256_compress_neon is consumed by src/c/ama_sha256.c and pinned by
 * tests/c/test_sha256_neon_kat.c; both used to re-declare it by hand.
 * ============================================================================ */
void ama_sha256_compress_neon(uint32_t state[8], const uint8_t block[64]);
void ama_sphincs_wots_chain_neon(uint8_t *out, const uint8_t *in,
                                 uint32_t start, uint32_t steps,
                                 const uint8_t *pub_seed,
                                 uint32_t addr[8], size_t n);

/* ============================================================================
 * Ed25519 field arithmetic (radix 2^51, two lanes at a time)
 *
 * The `fe51_neon` limb layout lives here rather than in the defining
 * translation unit so the prototypes below can name it.  No caller outside
 * src/c/neon/ama_ed25519_neon.c uses these today; they are the 2-way field
 * primitives a future NEON Ed25519 ladder would be built from.
 * ============================================================================ */
typedef struct {
    uint64_t v[5];
} fe51_neon;

void ama_fe51_add_x2_neon(fe51_neon r[2],
                          const fe51_neon a[2],
                          const fe51_neon b[2]);
void ama_fe51_sub_x2_neon(fe51_neon r[2],
                          const fe51_neon a[2],
                          const fe51_neon b[2]);
void ama_fe51_carry_x2_neon(fe51_neon r[2]);
void ama_fe51_mul_neon(fe51_neon *r, const fe51_neon *a, const fe51_neon *b);

#endif /* __aarch64__ || _M_ARM64 */

#ifdef __cplusplus
}
#endif

#endif /* AMA_NEON_INTERNAL_H */
