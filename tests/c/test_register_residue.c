/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_register_residue.c
 * @brief No secret a public entry point produces is left in a vector
 *        register, or in its dead stack, when the call returns (INVARIANT-6).
 *
 * WHY A REGISTER, AND WHY THIS IS A MEMORY DEFECT.  The System V x86-64 ABI
 * makes every vector register call-clobbered, so a secret a callee leaves in
 * one is the caller's to overwrite, and nothing makes the caller do it soon.
 * The next save of the register file writes it to memory nobody scrubs: the
 * dynamic linker's lazy-binding trampoline (_dl_runtime_resolve_xsavec saves
 * every vector register onto the stack), a signal frame, a ucontext switch.
 * Measured 2026-11-08: once ama_sha3.c's store64_le became a whole-word
 * memcpy, gcc 13 -O2 merged ama_sha3_final's four digest stores into two
 * MOVDQU copies through %xmm8/%xmm9, and tools/measure_secret_residue.py
 * found one whole live copy of the HKDF-SHA3-256 output on [stack] under
 * CPython 3.12 (CI job 128658717231; reproduced locally, and gone under
 * LD_BIND_NOW=1, which binds every PLT slot before the call so that no
 * trampoline runs after it).
 *
 * That Python-level instrument sees such a copy only when a trampoline runs
 * before the interpreter overwrites the registers: under CPython 3.13 here it
 * did not, on the same library, and a signal raised from Python to force the
 * save came too late as well.  So it is no pin for the property.  This
 * harness is: it calls each entry point through the shared library and
 * stores %xmm0-%xmm15 (%ymm0-%ymm15 with AVX, and %zmm16-%zmm31 with
 * AVX-512F) in the instructions right after the call returns.  Nothing runs
 * in between that could clear them, and the compiler cannot keep a value of
 * its own in them across the call, because all of them are caller-saved.
 * Any 8-byte word of the secret found in the dump is a failure.
 *
 * WHAT HOLDS THE PROPERTY.  The measured surface leaked, before the
 * 2026-11-08 change, on main as well as on this branch: PBKDF2-SHA512,
 * Argon2id and the plaintext of all three AEADs (and two AES-256 key words
 * from AES-GCM decrypt on main); this branch added the SHA-3 digest and the
 * X25519 shared secret.  Every exported function is now compiled with
 * zero_call_used_regs("all") (AMA_API in include/ama_cryptography.h), so it
 * clears every call-clobbered register on return whatever its callees,
 * kernels and libc left there.  That attribute is the PIN for the PBKDF2,
 * Argon2id and AEAD rows: without it they fail.
 *
 * It cannot reach %zmm16-31 from a baseline x86-64 translation unit, and
 * glibc's EVEX memcpy copies through exactly those on every AVX-512 CPU:
 * under clang 18.1, which calls glibc for variable-length copies, the HKDF,
 * HKDF-SHA256, PBKDF2 and Argon2id rows failed with the output in %zmm16 and
 * %zmm17.  src/c/internal/ama_string_ops.h expands every library copy inline
 * instead (REP MOVSB under clang), and is the PIN for those rows on clang
 * (redundant on gcc, whose string-op pin already inlined them);
 * tests/test_no_libc_string_calls.py holds the import table.
 *
 * THE DEAD-STACK ROWS.  fe64_tobytes spilled the X25519 shared secret to its
 * own frame on the way to the MOVDQU copies, and nothing scrubs a returned
 * frame.  The register attribute cannot reach memory, so the value barrier
 * in fe64_store64_le / fe51_store64_le (each word stored from a general
 * register) is what keeps that copy from being made; the probe of
 * residue_probe.h pins it (poison, call below a gap, scan).
 *
 * CONTROLS: a word the harness itself loads into %xmm8 must be found in the
 * dump, and the stack probe's sentinel must be found in its window, or the
 * instrument is broken and every verdict is void.
 *
 * x86-64 System V with GNU C inline assembly only; elsewhere, and under a
 * sanitizer that moves locals off the real frame, it skips (77).
 */
#include "ama_cryptography.h"
#include "residue_probe.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !(defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))) || \
    defined(_WIN32) || AMA_PROBE_IS_INSTRUMENTED
int main(void) {
    printf("SKIP: x86-64 System V with GNU C inline assembly, uninstrumented, only\n");
    return 77;
}
#else

#define REG_STRIDE 32
static uint8_t g_regs[16 * REG_STRIDE];
static uint8_t g_hi[16 * 64];
static int g_have_avx;
static int g_have_avx512;

/* Every register stored to its own slot; the YMM form also stores the upper
 * halves, which the trampoline's XSAVEC saves too. */
#define DUMP_XMM()                                                                \
    __asm__ volatile("movdqu %%xmm0,    0(%0)\n\tmovdqu %%xmm1,   32(%0)\n\t"     \
                     "movdqu %%xmm2,   64(%0)\n\tmovdqu %%xmm3,   96(%0)\n\t"     \
                     "movdqu %%xmm4,  128(%0)\n\tmovdqu %%xmm5,  160(%0)\n\t"     \
                     "movdqu %%xmm6,  192(%0)\n\tmovdqu %%xmm7,  224(%0)\n\t"     \
                     "movdqu %%xmm8,  256(%0)\n\tmovdqu %%xmm9,  288(%0)\n\t"     \
                     "movdqu %%xmm10, 320(%0)\n\tmovdqu %%xmm11, 352(%0)\n\t"     \
                     "movdqu %%xmm12, 384(%0)\n\tmovdqu %%xmm13, 416(%0)\n\t"     \
                     "movdqu %%xmm14, 448(%0)\n\tmovdqu %%xmm15, 480(%0)"         \
                     : : "r"(g_regs) : "memory")
#define DUMP_YMM()                                                                \
    __asm__ volatile("vmovdqu %%ymm0,    0(%0)\n\tvmovdqu %%ymm1,   32(%0)\n\t"   \
                     "vmovdqu %%ymm2,   64(%0)\n\tvmovdqu %%ymm3,   96(%0)\n\t"   \
                     "vmovdqu %%ymm4,  128(%0)\n\tvmovdqu %%ymm5,  160(%0)\n\t"   \
                     "vmovdqu %%ymm6,  192(%0)\n\tvmovdqu %%ymm7,  224(%0)\n\t"   \
                     "vmovdqu %%ymm8,  256(%0)\n\tvmovdqu %%ymm9,  288(%0)\n\t"   \
                     "vmovdqu %%ymm10, 320(%0)\n\tvmovdqu %%ymm11, 352(%0)\n\t"   \
                     "vmovdqu %%ymm12, 384(%0)\n\tvmovdqu %%ymm13, 416(%0)\n\t"   \
                     "vmovdqu %%ymm14, 448(%0)\n\tvmovdqu %%ymm15, 480(%0)"       \
                     : : "r"(g_regs) : "memory")
/* The registers AVX-512 adds, which neither VZEROUPPER nor a legacy-SSE
 * epilogue touches. */
#define DUMP_ZMM_HI()                                                             \
    __asm__ volatile("vmovdqu64 %%zmm16,   0(%0)\n\tvmovdqu64 %%zmm17,  64(%0)\n\t" \
                     "vmovdqu64 %%zmm18, 128(%0)\n\tvmovdqu64 %%zmm19, 192(%0)\n\t" \
                     "vmovdqu64 %%zmm20, 256(%0)\n\tvmovdqu64 %%zmm21, 320(%0)\n\t" \
                     "vmovdqu64 %%zmm22, 384(%0)\n\tvmovdqu64 %%zmm23, 448(%0)\n\t" \
                     "vmovdqu64 %%zmm24, 512(%0)\n\tvmovdqu64 %%zmm25, 576(%0)\n\t" \
                     "vmovdqu64 %%zmm26, 640(%0)\n\tvmovdqu64 %%zmm27, 704(%0)\n\t" \
                     "vmovdqu64 %%zmm28, 768(%0)\n\tvmovdqu64 %%zmm29, 832(%0)\n\t" \
                     "vmovdqu64 %%zmm30, 896(%0)\n\tvmovdqu64 %%zmm31, 960(%0)"     \
                     : : "r"(g_hi) : "memory")

/* The call, then the dump as the very next statements. */
#define CALL_THEN_DUMP(rc, call)                \
    do {                                        \
        memset(g_regs, 0, sizeof(g_regs));      \
        memset(g_hi, 0, sizeof(g_hi));          \
        if (g_have_avx512) {                    \
            (rc) = (call);                      \
            DUMP_YMM();                         \
            DUMP_ZMM_HI();                      \
        } else if (g_have_avx) {                \
            (rc) = (call);                      \
            DUMP_YMM();                         \
        } else {                                \
            (rc) = (call);                      \
            DUMP_XMM();                         \
        }                                       \
    } while (0)

static int count_in(const uint8_t *dump, size_t dump_len, const uint8_t *s, size_t len) {
    int hits = 0;
    for (size_t w = 0; w + 8 <= len; w += 8) {
        for (size_t off = 0; off + 8 <= dump_len; off++) {
            if (memcmp(dump + off, s + w, 8) == 0) {
                hits++;
            }
        }
    }
    return hits;
}

/* Occurrences of any 8-byte word of s[0..len) at any offset of the dump. */
static int words_in_dump(const uint8_t *s, size_t len) {
    return count_in(g_regs, sizeof(g_regs), s, len) + count_in(g_hi, sizeof(g_hi), s, len);
}

static int g_failures;

static void verdict(const char *name, int rc, const uint8_t *s, size_t len) {
    int hits = words_in_dump(s, len);
    if (rc != AMA_SUCCESS) {
        printf("FAIL %-40s rc=%d\n", name, rc);
        g_failures++;
    } else if (hits != 0) {
        printf("FAIL %-40s %d secret word(s) left in vector registers\n", name, hits);
        g_failures++;
    } else {
        printf("ok   %-40s 0 secret words in vector registers\n", name);
    }
}

static const uint8_t g_key[32] = {
    0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x83, 0x94, 0xa5,
    0xb6, 0xc7, 0xd8, 0xe9, 0xfa, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
    0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0};
static const uint8_t g_salt[12] = {'s', 'a', 'l', 't', 's', 'a', 'l', 't', 's', 'a', 'l', 't'};
static const uint8_t g_info[7] = {'r', 'e', 's', 'i', 'd', 'u', 'e'};
static const uint8_t g_nonce[16] = {7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8};
static uint8_t g_pt[64], g_ct[64], g_tag[16], g_out[64];
static uint8_t g_pk1[32], g_sk1[32], g_pk2[32], g_sk2[32], g_ss[32];

/* --- dead stack: the X25519 shared secret and the HKDF-SHA3-256 output. */

RESIDUE_NOINLINE static ama_error_t probe_x25519_key_exchange(void) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_x25519_key_exchange(g_ss, g_sk1, g_pk2));
    return rc;
}

RESIDUE_NOINLINE static ama_error_t probe_hkdf(void) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_hkdf(g_salt, 1, g_key, sizeof(g_key), g_info, sizeof(g_info), g_out, 32));
    return rc;
}

static void stack_verdict(const char *name, ama_error_t (*probe)(void), const uint8_t *secret,
                          size_t len) {
    uint8_t needle[32];
    ama_error_t rc;
    int hits;
    memcpy(needle, secret, len); /* the output of an identical earlier call */
    poison_stack();
    rc = probe();
    hits = residue_count(needle, len);
    if (rc != AMA_SUCCESS || hits != 0 || memcmp(needle, secret, len) != 0) {
        printf("FAIL %-40s rc=%d, %d copy(ies) in its dead stack\n", name, (int)rc, hits);
        g_failures++;
    } else {
        printf("ok   %-40s 0 copies in its dead stack\n", name);
    }
}

int main(void) {
    int rc;
    uint8_t sentinel[32];

    __builtin_cpu_init();
    g_have_avx = __builtin_cpu_supports("avx");
    g_have_avx512 = __builtin_cpu_supports("avx512f");
    printf("register dump: %s\n", g_have_avx512 ? "ymm0-15, zmm16-31"
                                  : g_have_avx  ? "ymm0-15"
                                                : "xmm0-15");
    for (size_t i = 0; i < sizeof(g_pt); i++) {
        g_pt[i] = (uint8_t)(0x3cu ^ (i * 41u));
    }

    /* CONTROL (registers): sixteen bytes the harness loads into %xmm8 are in
     * slot 8 and are counted (the scan may count more: the compiler is free
     * to have built the array in another register as well). */
    memset(g_regs, 0, sizeof(g_regs));
    if (g_have_avx) {
        __asm__ volatile("vmovdqu (%0), %%xmm8" : : "r"(g_pt) : "xmm8");
        DUMP_YMM();
    } else {
        __asm__ volatile("movdqu (%0), %%xmm8" : : "r"(g_pt) : "xmm8");
        DUMP_XMM();
    }
    if (memcmp(g_regs + 8 * REG_STRIDE, g_pt, 16) != 0 || words_in_dump(g_pt, 16) < 2) {
        printf("FAIL control: the dump did not see a planted %%xmm8\n");
        return 1;
    }
    printf("ok   control: a planted %%xmm8 is seen\n");

    /* CONTROL (stack): a sentinel left in a frame at the probed depth is
     * seen, and the window reads what the poison wrote. */
    for (size_t i = 0; i < sizeof(sentinel); i++) {
        sentinel[i] = (uint8_t)(0xA7u ^ (i * 13u + 3u));
    }
    poison_stack();
    residue_probe_control(sentinel, sizeof(sentinel));
    if (residue_count(sentinel, sizeof(sentinel)) <= 0 || !residue_window_covers_poison()) {
        printf("FAIL control: the stack probe did not see its sentinel\n");
        return 1;
    }
    printf("ok   control: a sentinel left on the stack is seen\n");

    if (ama_x25519_keypair(g_pk1, g_sk1) != AMA_SUCCESS ||
        ama_x25519_keypair(g_pk2, g_sk2) != AMA_SUCCESS) {
        printf("FAIL x25519 keypairs\n");
        return 1;
    }

    /* --- SHA-3 family: the row CI named, and what it is built from. */
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_hkdf(g_salt, 1, g_key, sizeof(g_key), g_info, sizeof(g_info),
                                g_out, 32));
    verdict("ama_hkdf (32)", rc, g_out, 32);
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_hkdf(g_salt, 1, g_key, sizeof(g_key), g_info, sizeof(g_info),
                                g_out, 64));
    verdict("ama_hkdf (64)", rc, g_out, 64);
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_hmac_sha3_256(g_key, sizeof(g_key), g_info, sizeof(g_info), g_out));
    verdict("ama_hmac_sha3_256", rc, g_out, 32);
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_sha3_256(g_key, sizeof(g_key), g_out));
    verdict("ama_sha3_256", rc, g_out, 32);
    {
        ama_sha3_ctx ctx;
        if (ama_sha3_init(&ctx) != AMA_SUCCESS ||
            ama_sha3_update(&ctx, g_key, sizeof(g_key)) != AMA_SUCCESS) {
            printf("FAIL ama_sha3_init/update\n");
            return 1;
        }
        memset(g_out, 0, sizeof(g_out));
        CALL_THEN_DUMP(rc, ama_sha3_final(&ctx, g_out));
        verdict("ama_sha3_final", rc, g_out, 32);
    }

    /* --- key agreement and key generation. */
    memset(g_ss, 0, sizeof(g_ss));
    CALL_THEN_DUMP(rc, ama_x25519_key_exchange(g_ss, g_sk1, g_pk2));
    verdict("ama_x25519_key_exchange", rc, g_ss, 32);
    CALL_THEN_DUMP(rc, ama_x25519_keypair(g_pk1, g_sk1));
    verdict("ama_x25519_keypair (secret key)", rc, g_sk1, 32);
    memset(g_ss, 0, sizeof(g_ss));
    if (ama_x25519_key_exchange(g_ss, g_sk1, g_pk2) != AMA_SUCCESS) {
        printf("FAIL x25519 key exchange\n");
        return 1;
    }

    /* --- the other KDFs. */
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_hkdf_sha256(g_salt, 1, g_key, sizeof(g_key), g_info,
                                       sizeof(g_info), g_out, 32));
    verdict("ama_hkdf_sha256", rc, g_out, 32);
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_pbkdf2_hmac_sha512(g_key, 13, g_salt, 8, 2, g_out, 64));
    verdict("ama_pbkdf2_hmac_sha512", rc, g_out, 64);
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_argon2id(g_key, 13, g_salt, sizeof(g_salt), 1, 64, 1, g_out, 32));
    verdict("ama_argon2id", rc, g_out, 32);

    /* --- AEAD decryption: the plaintext, and the key. */
    if (ama_aes256_gcm_encrypt(g_key, g_nonce, g_pt, sizeof(g_pt), NULL, 0, g_ct, g_tag) !=
        AMA_SUCCESS) {
        printf("FAIL ama_aes256_gcm_encrypt\n");
        return 1;
    }
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_aes256_gcm_decrypt(g_key, g_nonce, g_ct, sizeof(g_ct), NULL, 0,
                                              g_tag, g_out));
    verdict("ama_aes256_gcm_decrypt (plaintext)", rc, g_out, sizeof(g_pt));
    verdict("ama_aes256_gcm_decrypt (key)", rc, g_key, sizeof(g_key));
    if (ama_chacha20poly1305_encrypt(g_key, g_nonce, g_pt, sizeof(g_pt), NULL, 0, g_ct,
                                     g_tag) != AMA_SUCCESS) {
        printf("FAIL ama_chacha20poly1305_encrypt\n");
        return 1;
    }
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_chacha20poly1305_decrypt(g_key, g_nonce, g_ct, sizeof(g_ct), NULL,
                                                    0, g_tag, g_out));
    verdict("ama_chacha20poly1305_decrypt (plaintext)", rc, g_out, sizeof(g_pt));
    verdict("ama_chacha20poly1305_decrypt (key)", rc, g_key, sizeof(g_key));
    if (ama_ascon_aead128_encrypt(g_key, g_nonce, g_pt, sizeof(g_pt), NULL, 0, g_ct, g_tag) !=
        AMA_SUCCESS) {
        printf("FAIL ama_ascon_aead128_encrypt\n");
        return 1;
    }
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_ascon_aead128_decrypt(g_key, g_nonce, g_ct, sizeof(g_ct), NULL, 0,
                                                 g_tag, g_out));
    verdict("ama_ascon_aead128_decrypt (plaintext)", rc, g_out, sizeof(g_pt));
    verdict("ama_ascon_aead128_decrypt (key)", rc, g_key, 16);

    /* --- dead stack. */
    memset(g_out, 0, sizeof(g_out));
    if (ama_hkdf(g_salt, 1, g_key, sizeof(g_key), g_info, sizeof(g_info), g_out, 32) !=
        AMA_SUCCESS) {
        printf("FAIL ama_hkdf\n");
        return 1;
    }
    stack_verdict("ama_x25519_key_exchange (dead stack)", probe_x25519_key_exchange, g_ss, 32);
    stack_verdict("ama_hkdf (dead stack)", probe_hkdf, g_out, 32);

    memset(g_regs, 0, sizeof(g_regs));
    memset(g_hi, 0, sizeof(g_hi));
    if (g_failures) {
        printf("%d verdict(s) failed\n", g_failures);
        return 1;
    }
    return 0;
}
#endif
