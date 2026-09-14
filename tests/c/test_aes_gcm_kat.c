/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_aes_gcm_kat.c
 * @brief AES-256-GCM against NIST SP 800-38D Appendix B through the public
 *        API, with whichever kernel the dispatcher installed.
 *
 * test_aes_gcm_scalar_kat.c runs Test Cases 13 and 14 with the dispatch slots
 * FORCED to the scalar reference — deliberately, since its subject is the
 * table-free GHASH.  Until this file existed, that meant no C test ever ran a
 * published AES-GCM vector with a hardware kernel installed: the AES-NI+PCLMUL,
 * VAES+VPCLMULQDQ and ARMv8 AES+PMULL kernels were checked only for
 * equivalence with the scalar path on random inputs, never against the
 * standard's own answers.  The published vectors are the only evidence that
 * distinguishes "agrees with our scalar code" from "is AES-GCM".
 *
 * Test Cases 13-16 are the AES-256 / 96-bit-IV cases (this API takes a
 * 96-bit nonce only).  Case 15 is 64 bytes of plaintext, exactly four blocks,
 * so it drives the AES-NI kernel's four-block pipeline once; the SIMD-vs-scalar
 * lattice in test_aes_gcm_scalar_kat.c covers the longer inputs.
 *
 * Under the per-slot sweep this runs with AMA_DISPATCH_ONLY=aes-gcm-aesni,
 * aes-gcm-vaes or aes-gcm-neon, and then ALSO requires
 * ama_aes_gcm_active_backend() to name the pinned kernel, so the label the
 * dispatcher resolved and the pointer it installed cannot disagree.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ama_cryptography.h"
#include "ama_dispatch.h"
#include "kat_slot_guard.h"

static int passed = 0, failed = 0;

#define CHECK(cond, msg) do {                                   \
    if (!(cond)) { printf("  FAIL: %s\n", msg); failed++; }     \
    else         { passed++; }                                  \
} while (0)

typedef struct {
    const char *name;
    const uint8_t *key;     /* 32 bytes */
    const uint8_t *iv;      /* 12 bytes */
    const uint8_t *pt;      size_t pt_len;
    const uint8_t *aad;     size_t aad_len;
    const uint8_t *ct;      /* pt_len bytes */
    const uint8_t *tag;     /* 16 bytes */
} gcm_vector;

/* Transcribed from NIST SP 800-38D Appendix B (McGrew & Viega test cases),
 * AES-256 with 96-bit IV: Test Cases 13, 14, 15, 16. */
static const uint8_t zero_key[32] = {0};
static const uint8_t zero_iv[12]  = {0};
static const uint8_t tc13_tag[16] = {
    0x53,0x0f,0x8a,0xfb,0xc7,0x45,0x36,0xb9, 0xa9,0x63,0xb4,0xf1,0xc4,0xcb,0x73,0x8b };

static const uint8_t tc14_pt[16]  = {0};
static const uint8_t tc14_ct[16]  = {
    0xce,0xa7,0x40,0x3d,0x4d,0x60,0x6b,0x6e, 0x07,0x4e,0xc5,0xd3,0xba,0xf3,0x9d,0x18 };
static const uint8_t tc14_tag[16] = {
    0xd0,0xd1,0xc8,0xa7,0x99,0x99,0x6b,0xf0, 0x26,0x5b,0x98,0xb5,0xd4,0x8a,0xb9,0x19 };

static const uint8_t tc15_key[32] = {
    0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c, 0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08,
    0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c, 0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08 };
static const uint8_t tc15_iv[12] = {
    0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad, 0xde,0xca,0xf8,0x88 };
static const uint8_t tc15_pt[64] = {
    0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5, 0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
    0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda, 0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
    0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53, 0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
    0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57, 0xba,0x63,0x7b,0x39,0x1a,0xaf,0xd2,0x55 };
static const uint8_t tc15_ct[64] = {
    0x52,0x2d,0xc1,0xf0,0x99,0x56,0x7d,0x07, 0xf4,0x7f,0x37,0xa3,0x2a,0x84,0x42,0x7d,
    0x64,0x3a,0x8c,0xdc,0xbf,0xe5,0xc0,0xc9, 0x75,0x98,0xa2,0xbd,0x25,0x55,0xd1,0xaa,
    0x8c,0xb0,0x8e,0x48,0x59,0x0d,0xbb,0x3d, 0xa7,0xb0,0x8b,0x10,0x56,0x82,0x88,0x38,
    0xc5,0xf6,0x1e,0x63,0x93,0xba,0x7a,0x0a, 0xbc,0xc9,0xf6,0x62,0x89,0x80,0x15,0xad };
static const uint8_t tc15_tag[16] = {
    0xb0,0x94,0xda,0xc5,0xd9,0x34,0x71,0xbd, 0xec,0x1a,0x50,0x22,0x70,0xe3,0xcc,0x6c };

static const uint8_t tc16_aad[20] = {
    0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef, 0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
    0xab,0xad,0xda,0xd2 };
static const uint8_t tc16_tag[16] = {
    0x76,0xfc,0x6e,0xce,0x0f,0x4e,0x17,0x68, 0xcd,0xdf,0x88,0x53,0xbb,0x2d,0x55,0x1b };
/* TC16's plaintext and ciphertext are the first 60 bytes of TC15's. */

static const gcm_vector VECTORS[] = {
    { "SP 800-38D B.13", zero_key, zero_iv, NULL, 0, NULL, 0, NULL, tc13_tag },
    { "SP 800-38D B.14", zero_key, zero_iv, tc14_pt, 16, NULL, 0, tc14_ct, tc14_tag },
    { "SP 800-38D B.15", tc15_key, tc15_iv, tc15_pt, 64, NULL, 0, tc15_ct, tc15_tag },
    { "SP 800-38D B.16", tc15_key, tc15_iv, tc15_pt, 60, tc16_aad, 20, tc15_ct, tc16_tag },
};

static void run_vector(const gcm_vector *v) {
    uint8_t ct[64], tag[16], pt_back[64];
    char msg[96];

    ama_error_t rc = ama_aes256_gcm_encrypt(v->key, v->iv, v->pt, v->pt_len,
                                            v->aad, v->aad_len,
                                            v->pt_len ? ct : NULL, tag);
    snprintf(msg, sizeof msg, "%s: encrypt returns SUCCESS", v->name);
    CHECK(rc == AMA_SUCCESS, msg);
    if (v->pt_len) {
        snprintf(msg, sizeof msg, "%s: ciphertext matches the standard", v->name);
        CHECK(memcmp(ct, v->ct, v->pt_len) == 0, msg);
    }
    snprintf(msg, sizeof msg, "%s: tag matches the standard", v->name);
    CHECK(memcmp(tag, v->tag, 16) == 0, msg);

    memset(pt_back, 0xAA, sizeof pt_back);
    rc = ama_aes256_gcm_decrypt(v->key, v->iv, v->pt_len ? v->ct : NULL, v->pt_len,
                                v->aad, v->aad_len, v->tag, v->pt_len ? pt_back : NULL);
    snprintf(msg, sizeof msg, "%s: decrypt of the standard's ciphertext returns SUCCESS", v->name);
    CHECK(rc == AMA_SUCCESS, msg);
    if (v->pt_len) {
        snprintf(msg, sizeof msg, "%s: decrypted plaintext matches", v->name);
        CHECK(memcmp(pt_back, v->pt, v->pt_len) == 0, msg);
    }

    /* A flipped tag bit must be rejected by this kernel too. */
    uint8_t bad_tag[16];
    memcpy(bad_tag, v->tag, 16);
    bad_tag[15] ^= 0x01;
    rc = ama_aes256_gcm_decrypt(v->key, v->iv, v->pt_len ? v->ct : NULL, v->pt_len,
                                v->aad, v->aad_len, bad_tag, v->pt_len ? pt_back : NULL);
    snprintf(msg, sizeof msg, "%s: tampered tag rejected", v->name);
    CHECK(rc != AMA_SUCCESS, msg);
}

/* The backend a pinned AES-GCM slot must have installed.  Any other pin (or
 * no pin) leaves the choice to the dispatcher and only reports it. */
static const char *expected_backend_for_pin(const char *slot) {
    if (!slot) return NULL;
    if (strcmp(slot, "aes-gcm-aesni") == 0) return "aes-ni-pclmul";
    if (strcmp(slot, "aes-gcm-vaes") == 0)  return "vaes-avx2";
    if (strcmp(slot, "aes-gcm-neon") == 0)  return "arm-aes-pmull";
    return NULL;
}

int main(void) {
    KAT_SLOT_GUARD_OR_EXIT();  /* per-slot KAT sweep: refuse a pin the host did not honour */

    printf("==================================================\n");
    printf("AES-256-GCM NIST SP 800-38D Appendix B KAT\n");
    printf("through the public API, dispatched kernel installed\n");
    printf("==================================================\n\n");

    ama_dispatch_init();
    const char *backend = ama_aes_gcm_active_backend();
    printf("  active AES-GCM backend: %s\n", backend ? backend : "(null)");
    CHECK(backend != NULL, "ama_aes_gcm_active_backend() names a backend");

    const char *expected = expected_backend_for_pin(getenv("AMA_DISPATCH_ONLY"));
    if (expected) {
        printf("  pinned slot requires backend: %s\n", expected);
        CHECK(backend && strcmp(backend, expected) == 0,
              "the pinned AES-GCM slot installed the kernel its label names");
    }

    for (size_t i = 0; i < sizeof VECTORS / sizeof VECTORS[0]; i++)
        run_vector(&VECTORS[i]);

    printf("\n%d checks, %d failures\n", passed + failed, failed);
    return failed ? 1 : 0;
}
