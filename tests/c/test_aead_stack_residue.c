/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_aead_stack_residue.c
 * @brief No AEAD key material survives on the dead stack (INVARIANT-6).
 *
 * `ama_secure_memzero` scrubs the buffers a function names.  It cannot reach
 * the copies an optimizing compiler spills of them, and both hardware AES-GCM
 * kernels had exactly that defect: they scrub their `rk[15]` key schedule at
 * exit while gcc 13 -O3 had already hoisted the round keys into separate
 * stack slots used as AES memory operands.  A probe of this shape found all
 * fifteen round keys after every encrypt and decrypt — `rk[0]` and `rk[1]`
 * among them, which for AES-256 are the raw 32-byte key.  ChaCha20-Poly1305
 * left its key likewise, there because `chacha20_block` scrubbed neither its
 * `state` nor its `working` array.
 *
 * The probe: fill a stack region with a pattern, call the AEAD entry point at
 * the same depth, then read that region back and count occurrences of the
 * secret.  A public entry point that has returned owns none of it.
 *
 * CONTROL.  A vacuous version of this test — one whose scan window misses the
 * frame — passes for the wrong reason, so `probe_control()` deliberately
 * leaves the key in its own frame and the test FAILS if the probe cannot see
 * that.  Both directions are checked before any AEAD verdict is trusted.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "ama_cryptography.h"

#define SCAN_BYTES 32768u
#define MSG_BYTES  256u

static int checks = 0;
static int failures = 0;

#define CHECK(cond, msg) do {                                    \
    checks++;                                                    \
    if (!(cond)) {                                               \
        failures++;                                              \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); \
    }                                                            \
} while (0)

static uint8_t g_key[32];
static uint8_t g_nonce[12];
static uint8_t g_msg[MSG_BYTES];

/* Poison the region a later call will use, so a hit is residue rather than a
 * leftover from process start. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void poison_stack(void) {
    volatile uint8_t pad[SCAN_BYTES];
    memset((void *)pad, 0x5A, sizeof pad);
    (void)pad[0];
}

/* Occurrences of `needle` in the SCAN_BYTES below this frame. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static int residue_count(const uint8_t *needle, size_t len) {
    volatile uint8_t anchor = 0;
    const uint8_t *base = (const uint8_t *)&anchor - SCAN_BYTES;
    size_t i;
    int hits = 0;
    for (i = 0; i + len <= SCAN_BYTES; i++) {
        if (memcmp(base + i, needle, len) == 0) {
            hits++;
        }
    }
    return hits;
}

/* Positive control: leaves the key in a frame the probe must be able to see. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void probe_control(void) {
    volatile uint8_t copy[512];
    memset((void *)copy, 0, sizeof copy);
    memcpy((void *)(copy + 128), g_key, sizeof g_key);
    /* Keep the copy alive to the end of the frame, then return without a
     * scrub — the exact shape the AEAD kernels used to exhibit. */
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(copy) : "memory");
#endif
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void run_gcm_encrypt(uint8_t *ct, uint8_t *tag) {
    CHECK(ama_aes256_gcm_encrypt(g_key, g_nonce, g_msg, MSG_BYTES, NULL, 0,
                                 ct, tag) == AMA_SUCCESS,
          "AES-256-GCM encrypt succeeds");
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void run_gcm_decrypt(const uint8_t *ct, const uint8_t *tag, uint8_t *pt) {
    CHECK(ama_aes256_gcm_decrypt(g_key, g_nonce, ct, MSG_BYTES, NULL, 0,
                                 tag, pt) == AMA_SUCCESS,
          "AES-256-GCM decrypt succeeds");
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void run_chacha_encrypt(uint8_t *ct, uint8_t *tag) {
    CHECK(ama_chacha20poly1305_encrypt(g_key, g_nonce, g_msg, MSG_BYTES, NULL, 0,
                                       ct, tag) == AMA_SUCCESS,
          "ChaCha20-Poly1305 encrypt succeeds");
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void run_chacha_decrypt(const uint8_t *ct, const uint8_t *tag, uint8_t *pt) {
    CHECK(ama_chacha20poly1305_decrypt(g_key, g_nonce, ct, MSG_BYTES, NULL, 0,
                                       tag, pt) == AMA_SUCCESS,
          "ChaCha20-Poly1305 decrypt succeeds");
}

int main(void) {
    static uint8_t ct[MSG_BYTES], pt[MSG_BYTES];
    uint8_t tag[16];
    unsigned i;
    int control_hits;

    for (i = 0; i < sizeof g_key; i++) {
        g_key[i] = (uint8_t)(0xC3u ^ (i * 7u + 11u));
    }
    memset(g_nonce, 0x24, sizeof g_nonce);
    memset(g_msg, 0x11, sizeof g_msg);

    printf("AEAD dead-stack key residue (INVARIANT-6)\n");
    printf("=========================================\n");

    /* --- control: the probe must be able to see a key that IS left behind. */
    poison_stack();
    probe_control();
    control_hits = residue_count(g_key, sizeof g_key);
    printf("  control (key deliberately left): %d hit(s)\n", control_hits);
    CHECK(control_hits > 0,
          "probe control: a key left on the stack IS detected "
          "(a zero here means the scan window missed the frame and every "
          "verdict below would be vacuous)");

    /* --- AES-256-GCM, both directions. */
    poison_stack();
    run_gcm_encrypt(ct, tag);
    CHECK(residue_count(g_key, sizeof g_key) == 0,
          "AES-256-GCM encrypt leaves no raw key on the dead stack");

    poison_stack();
    run_gcm_decrypt(ct, tag, pt);
    CHECK(residue_count(g_key, sizeof g_key) == 0,
          "AES-256-GCM decrypt leaves no raw key on the dead stack");
    CHECK(memcmp(pt, g_msg, MSG_BYTES) == 0, "AES-256-GCM round trip");

    /* Searching for the raw key is sufficient to cover the schedule: for
     * AES-256 the first two round keys ARE the key, so a build that leaks any
     * of the fifteen leaks these two — the pre-fix library failed exactly
     * here, with all fifteen present. */

    /* --- ChaCha20-Poly1305, both directions. */
    poison_stack();
    run_chacha_encrypt(ct, tag);
    CHECK(residue_count(g_key, sizeof g_key) == 0,
          "ChaCha20-Poly1305 encrypt leaves no raw key on the dead stack");

    poison_stack();
    run_chacha_decrypt(ct, tag, pt);
    CHECK(residue_count(g_key, sizeof g_key) == 0,
          "ChaCha20-Poly1305 decrypt leaves no raw key on the dead stack");
    CHECK(memcmp(pt, g_msg, MSG_BYTES) == 0, "ChaCha20-Poly1305 round trip");

    /* --- a failed verification must not leave the key either. */
    {
        uint8_t bad_tag[16];
        memcpy(bad_tag, tag, sizeof bad_tag);
        bad_tag[0] ^= 0x01u;
        poison_stack();
        CHECK(ama_chacha20poly1305_decrypt(g_key, g_nonce, ct, MSG_BYTES, NULL, 0,
                                           bad_tag, pt) == AMA_ERROR_VERIFY_FAILED,
              "ChaCha20-Poly1305 rejects a bad tag");
        CHECK(residue_count(g_key, sizeof g_key) == 0,
              "ChaCha20-Poly1305 reject path leaves no raw key");
    }

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
