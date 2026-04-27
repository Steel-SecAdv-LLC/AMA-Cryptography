/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_avx2_internal.h
 * @brief Internal prototypes for the hand-written AVX2 SIMD kernels.
 *
 * This header is PRIVATE to src/c/avx2/ and to the dispatch layer.  It
 * is NOT installed and is never exposed to library consumers; every
 * symbol declared here is a runtime-dispatch implementation detail.
 *
 * The header exists to give each AVX2 translation unit a visible
 * prototype for its public (non-static) entry points, so that the
 * project-wide -Wmissing-prototypes lint has something to match at
 * the point of definition.  Previously each AVX2 TU defined its
 * externs without a prior declaration, producing a warning per
 * symbol on every build.
 *
 * The same prototypes were historically re-declared inline inside
 * src/c/dispatch/ama_dispatch.c; the dispatch TU should include this
 * header instead so the single source of truth lives in one place.
 */

#ifndef AMA_AVX2_INTERNAL_H
#define AMA_AVX2_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include "ama_cryptography.h"

/* All translation units that include this header are AVX2 SIMD
 * kernels or the dispatch layer reading their prototypes; pulling in
 * the Intel intrinsic types here lets the AES-256 key-expansion
 * signature be declared as `__m128i rk[15]` (which is how it is
 * defined) rather than type-erased to `void *`.
 *
 * <immintrin.h> is the correct header on MSVC as well: it pulls in
 * the full SSE/AVX/AVX2 intrinsic type set (including __m128i / __m256i).
 * The previous MSVC branch used <intrin.h>, which exposes compiler
 * intrinsics like __cpuid / _xgetbv but does NOT reliably provide
 * the SIMD vector types these prototypes need. */
#include <immintrin.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Portable "may be unused" marker for helper functions that are
 * defined for completeness / future-wiring but currently have no
 * caller in-tree.  Semantically equivalent to C++17 / C23
 * [[maybe_unused]] on a function: it grants the compiler permission
 * to emit the symbol without triggering -Wunused-function, without
 * claiming the function IS unused (which would be wrong — a future
 * dispatch-graph extension may well wire it up).
 *
 * Lane-local add/sub/compress/chain routines are kept in-tree so
 * they don't have to be re-derived next time the dispatch graph
 * grows; dispatch-facing entry points carry no marker and reaching
 * -Wunused-function on one of those is a real "this SIMD kernel
 * is compiled but nothing calls it" bug. */
#if defined(__GNUC__) || defined(__clang__)
#define AMA_MAYBE_UNUSED __attribute__((unused))
#else
#define AMA_MAYBE_UNUSED
#endif

/* ============================================================================
 * SHA-3 / Keccak
 * ============================================================================ */
void         ama_keccak_f1600_avx2(uint64_t state[25]);
void         ama_keccak_f1600_x4_avx2(uint64_t states[4][25]);
ama_error_t  ama_sha3_256_avx2(const uint8_t *input, size_t input_len,
                                uint8_t output[32]);

/* ============================================================================
 * Kyber (ML-KEM) — dispatch-facing entry points
 * ============================================================================ */
void ama_kyber_ntt_avx2(int16_t poly[256], const int16_t zetas[128]);
void ama_kyber_invntt_avx2(int16_t poly[256], const int16_t zetas[128]);
void ama_kyber_poly_pointwise_avx2(int16_t r[256],
                                    const int16_t a[256],
                                    const int16_t b[256],
                                    const int16_t zetas[128]);
void ama_kyber_cbd2_avx2(int16_t poly[256], const uint8_t buf[128]);

/* ============================================================================
 * Dilithium (ML-DSA) — dispatch-facing entry points
 * ============================================================================ */
void ama_dilithium_ntt_avx2(int32_t poly[256], const int32_t zetas[256]);
void ama_dilithium_invntt_avx2(int32_t poly[256], const int32_t zetas[256]);
void ama_dilithium_poly_pointwise_avx2(int32_t r[256],
                                        const int32_t a[256],
                                        const int32_t b[256]);
int  ama_dilithium_rej_uniform_avx2(int32_t *out, size_t outlen,
                                     const uint8_t *buf, size_t buflen);

/* ============================================================================
 * AES-256-GCM — AES-NI reference (reused by the VAES kernel)
 * ============================================================================ */
void ama_aes256_expand_key_avx2(const uint8_t key[32], __m128i rk[15]);
void ama_aes256_gcm_encrypt_avx2(const uint8_t *plaintext, size_t plaintext_len,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t key[32], const uint8_t nonce[12],
                                  uint8_t *ciphertext, uint8_t tag[16]);
ama_error_t ama_aes256_gcm_decrypt_avx2(const uint8_t *ciphertext, size_t ciphertext_len,
                                         const uint8_t *aad, size_t aad_len,
                                         const uint8_t key[32], const uint8_t nonce[12],
                                         const uint8_t tag[16], uint8_t *plaintext);

/* ============================================================================
 * AES-256-GCM — VAES + VPCLMULQDQ YMM kernel (this PR)
 *
 * Not declared on _MSC_VER: the MSVC build compiles the VAES source
 * file to a no-op typedef and the dispatcher falls back to the AES-NI
 * entries above.
 * ============================================================================ */
#if !defined(_MSC_VER)
void ama_aes256_gcm_encrypt_vaes_avx2(const uint8_t *plaintext, size_t plaintext_len,
                                       const uint8_t *aad, size_t aad_len,
                                       const uint8_t key[32], const uint8_t nonce[12],
                                       uint8_t *ciphertext, uint8_t tag[16]);
ama_error_t ama_aes256_gcm_decrypt_vaes_avx2(const uint8_t *ciphertext, size_t ciphertext_len,
                                              const uint8_t *aad, size_t aad_len,
                                              const uint8_t key[32], const uint8_t nonce[12],
                                              const uint8_t tag[16], uint8_t *plaintext);
#endif

/* ============================================================================
 * ChaCha20 — dispatch-facing entry point.
 *
 * Poly1305 SIMD helpers stay `static` in the defining TU because they
 * are internal to ama_chacha20poly1305_avx2.c and have no cross-TU
 * callers.  Dispatch reaches them transparently via the enclosing
 * ChaCha/Poly1305 AEAD API, not by name.
 * ============================================================================ */
void ama_chacha20_block_x8_avx2(const uint8_t key[32],
                                 const uint8_t nonce[12],
                                 uint32_t counter,
                                 uint8_t out[512]);

/* ============================================================================
 * Argon2 BlaMka G function
 * ============================================================================ */
void ama_argon2_g_avx2(uint64_t out[128],
                        const uint64_t x[128],
                        const uint64_t y[128]);

/* ============================================================================
 * X25519 — 4-way Montgomery ladder (RFC 7748)
 *
 * Processes four independent X25519 scalar multiplications in
 * parallel.  Invoked by the additive batch API
 * `ama_x25519_scalarmult_batch` only for full 4-lane chunks
 * (count / 4 of them) — short batches of 1, 2, or 3 and the (count
 * % 4) tail of longer batches stay on the scalar single-shot path
 * and are NOT padded into this kernel.  Each scalar is clamped per
 * RFC 7748 §5 inside the kernel; callers pass the raw 32-byte
 * secret keys.
 * ============================================================================ */
void ama_x25519_scalarmult_x4_avx2(uint8_t out[4][32],
                                    const uint8_t scalar[4][32],
                                    const uint8_t point[4][32]);

#ifdef __cplusplus
}
#endif

#endif /* AMA_AVX2_INTERNAL_H */
