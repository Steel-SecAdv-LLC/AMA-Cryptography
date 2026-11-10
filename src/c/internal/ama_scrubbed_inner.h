/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file internal/ama_scrubbed_inner.h
 * @brief The library's own way into primitives whose public entry point
 *        clears the stack (internal/ama_stack_wipe.h).
 *
 * THE RULE.  Code under src/c does not call a scrubbed entry point.  It calls
 * the function declared here, which is the same work without the clearing:
 *
 *     ama_shake256()         exported; runs the work, then clears its depth
 *     ama_shake256_inner()   the work; what ML-KEM, ML-DSA and HMAC call
 *
 * WHY.  A caller inside the library is one of two things.  It runs under an
 * entry point that clears a depth measured over everything it calls, this
 * function included, so a second wipe underneath clears nothing that would
 * otherwise be left.  Or it is verification, or another export that holds
 * nothing secret, and there is nothing to clear.  The public entry points
 * were called from both at first, because that is what the code already
 * did, and every inner hash paid for a wipe.  Measured 2026-11-10, retired
 * instructions under callgrind (gcc 14.2 -O3, LTO, x86-64 with AVX2 and
 * BMI2): the tree before the hash entry points cleared their stacks, then
 * with the library calling the public names, then with this header.
 *
 *     SLH-DSA-SHAKE-128s key generation
 *                 1,671,969,251     2,077,690,027     1,637,443,236
 *     SLH-DSA-SHAKE-128s verification
 *                    12,296,127        15,256,243        12,044,167
 *     HKDF-SHA3-256, 32 bytes out
 *                        40,678            44,900            41,280
 *
 * A quarter more for the first two while the public names were called, the
 * second of which handles no secret at all, and thirteen wipes for one key
 * derivation where there is now one.  Nothing in CI counts instructions for
 * SLH-DSA, so no gate would have said so.
 *
 * WHAT HOLDS IT.  tests/test_stack_scrub_surface.py fails on a call of a
 * scrubbed entry point from src/c that is not one of the forwarders
 * ama_stack_wipe.h names, on an inner function this header does not declare,
 * and on one the version script would export.  Each name here is listed
 * `local:` in cmake/ama_exports.map; none carries the export attribute, so
 * none reaches a Windows export table.
 *
 * An inner function is an ordinary function: it may be inlined into its
 * caller, which is how these calls were compiled before.  Only the
 * implementation half an entry point calls must stay out of line, and that
 * half is a `static` function beside the entry point which does nothing but
 * call this one.
 */

#ifndef AMA_INTERNAL_SCRUBBED_INNER_H
#define AMA_INTERNAL_SCRUBBED_INNER_H

#include <stddef.h>
#include <stdint.h>

#include "ama_cryptography.h"

/* SHA-3 and SHAKE (src/c/ama_sha3.c). */
ama_error_t ama_sha3_256_inner(const uint8_t* input, size_t input_len, uint8_t* output);
ama_error_t ama_sha3_512_inner(const uint8_t* input, size_t input_len, uint8_t* output);
ama_error_t ama_shake256_inner(const uint8_t* input, size_t input_len, uint8_t* output,
                               size_t output_len);
ama_error_t ama_sha3_update_inner(ama_sha3_ctx* ctx, const uint8_t* data, size_t len);
ama_error_t ama_sha3_final_inner(ama_sha3_ctx* ctx, uint8_t* output);
ama_error_t ama_shake128_inc_absorb_inner(ama_sha3_ctx* ctx, const uint8_t* data, size_t len);
ama_error_t ama_shake128_inc_finalize_inner(ama_sha3_ctx* ctx);
ama_error_t ama_shake128_inc_squeeze_inner(ama_sha3_ctx* ctx, uint8_t* output, size_t outlen);
ama_error_t ama_shake256_inc_absorb_inner(ama_sha3_ctx* ctx, const uint8_t* data, size_t len);
ama_error_t ama_shake256_inc_finalize_inner(ama_sha3_ctx* ctx);
ama_error_t ama_shake256_inc_squeeze_inner(ama_sha3_ctx* ctx, uint8_t* output, size_t outlen);

/* SHA-256 (src/c/ama_sha256.c) and the HMACs over SHA-2 and SHA-3
 * (src/c/ama_hmac_sha256.c, src/c/ama_hmac_sha384.c, src/c/ama_hkdf.c). */
void ama_sha256_inner(uint8_t *out, const uint8_t *in, size_t inlen);
void ama_hmac_sha256_inner(const uint8_t *key, size_t key_len, const uint8_t *data,
                           size_t data_len, uint8_t out[32]);
ama_error_t ama_hmac_sha384_inner(const uint8_t *key, size_t key_len, const uint8_t *msg,
                                  size_t msg_len, uint8_t out[48]);
ama_error_t ama_hmac_sha512_inner(const uint8_t *key, size_t key_len, const uint8_t *msg,
                                  size_t msg_len, uint8_t out[64]);
ama_error_t ama_hmac_sha3_256_inner(const uint8_t *key, size_t key_len, const uint8_t *msg,
                                    size_t msg_len, uint8_t out[32]);

/* HKDF-SHA3-256 (src/c/ama_hkdf.c). */
ama_error_t ama_hkdf_inner(const uint8_t* salt, size_t salt_len, const uint8_t* ikm,
                           size_t ikm_len, const uint8_t* info, size_t info_len, uint8_t* okm,
                           size_t okm_len);

/* Ed25519's SHA-512, scalar arithmetic and fixed-base multiplication, which
 * FROST is built from (src/c/ama_ed25519.c). */
void ama_ed25519_sha512_inner(const uint8_t *data, size_t len, uint8_t out[64]);
ama_error_t ama_ed25519_point_from_scalar_inner(uint8_t point[32], const uint8_t scalar[32]);
void ama_ed25519_sc_reduce_inner(uint8_t s[64]);
void ama_ed25519_sc_muladd_inner(uint8_t s[32], const uint8_t a[32], const uint8_t b[32],
                                 const uint8_t c[32]);

/* The constant-time AES-256 key schedule and block function AES-GCM's
 * portable path is built from (src/c/ama_aes_bitsliced.c). */
void ama_aes256_key_expansion_consttime_inner(const uint8_t key[32], uint8_t round_keys[240]);
void ama_aes256_encrypt_block_consttime_inner(const uint8_t round_keys[240], const uint8_t in[16],
                                              uint8_t out[16]);

#endif /* AMA_INTERNAL_SCRUBBED_INNER_H */
