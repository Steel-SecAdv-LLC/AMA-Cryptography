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
 * The probe — poison, call at the same depth, scan the poisoned bytes for
 * the needle — is `residue_probe.h`, shared with the Ed25519 harness.  Its
 * control, baseline and coverage checks, the sentinel that is not the key,
 * the barrier in `poison_stack()`, the integer address arithmetic, the GAP
 * every probed call runs below, and the sanitizer skip are all reasoned and
 * measured there, once, for both harnesses.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "ama_cryptography.h"

#include "residue_probe.h"

#if !AMA_PROBE_IS_INSTRUMENTED

#define MSG_BYTES 256u

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
static uint8_t g_nonce16[16];
static uint8_t g_msg[MSG_BYTES];

/* What the control plants, and what the control searches for.  NEVER the
 * key: see THE SENTINEL in residue_probe.h for the false positive that
 * planting the key manufactured. */
static uint8_t g_sentinel[32];

/* Any AES-256 key half left behind, not only a contiguous 32-byte copy.
 *
 * A compiler does not have to spill a key as one object, and the shipped one
 * does not.  Disassembled from the built library, the AVX2 kernel stores
 * key[0:16] with `movdqa %xmm2,(%rsp)` and key[16:32] with
 * `movdqa %xmm4,0x70(%rsp)` -- 112 bytes apart, in slots its own exit scrub
 * does not cover.  A contiguous 32-byte needle cannot see that shape at all,
 * so the probe was blind to the exact defect class it exists for; what saves
 * the library there is `ama_secure_stack_wipe()`, and nothing here was
 * measuring whether it did.
 *
 * Each 16-byte half is therefore searched independently (a whole-key copy
 * contains both).  For AES-256 either half is 128 bits of the key, so a hit
 * on one is a disclosure on its own. */
RESIDUE_NOINLINE static int key_residue_count(void) {
    return residue_count(g_key, 16) + residue_count(g_key + 16, 16);
}

/* Ascon-AEAD128's 16-byte key is g_key[0:16], held by the permutation as two
 * 64-bit words in host order, so a spill is an 8-byte word rather than a
 * 16-byte copy; each word is 64 bits of key. */
RESIDUE_NOINLINE static int ascon_key_residue_count(void) {
    return residue_count(g_key, 8) + residue_count(g_key + 8, 8);
}

#define NOINLINE RESIDUE_NOINLINE

NOINLINE static ama_error_t run_gcm_encrypt(uint8_t *ct, uint8_t *tag) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_aes256_gcm_encrypt(g_key, g_nonce, g_msg, MSG_BYTES,
                                         NULL, 0, ct, tag));
    return rc;
}

NOINLINE static ama_error_t run_gcm_decrypt(const uint8_t *ct,
                                            const uint8_t *tag, uint8_t *pt) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_aes256_gcm_decrypt(g_key, g_nonce, ct, MSG_BYTES,
                                         NULL, 0, tag, pt));
    return rc;
}

NOINLINE static ama_error_t run_chacha_encrypt(uint8_t *ct, uint8_t *tag) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_chacha20poly1305_encrypt(g_key, g_nonce, g_msg,
                                               MSG_BYTES, NULL, 0, ct, tag));
    return rc;
}

NOINLINE static ama_error_t run_chacha_decrypt(const uint8_t *ct,
                                               const uint8_t *tag,
                                               uint8_t *pt) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_chacha20poly1305_decrypt(g_key, g_nonce, ct, MSG_BYTES,
                                               NULL, 0, tag, pt));
    return rc;
}

NOINLINE static ama_error_t run_ascon_encrypt(uint8_t *ct, uint8_t *tag) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_ascon_aead128_encrypt(g_key, g_nonce16, g_msg,
                                            MSG_BYTES, NULL, 0, ct, tag));
    return rc;
}

NOINLINE static ama_error_t run_ascon_decrypt(const uint8_t *ct,
                                              const uint8_t *tag,
                                              uint8_t *pt) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_ascon_aead128_decrypt(g_key, g_nonce16, ct, MSG_BYTES,
                                            NULL, 0, tag, pt));
    return rc;
}

#endif /* !AMA_PROBE_IS_INSTRUMENTED */

int main(void) {
#if AMA_PROBE_IS_INSTRUMENTED
    /* Skipped, not suppressed.  This probe measures dead stack BELOW its own
     * frame -- that read IS the measurement, and it is precisely what an
     * ASan redzone and an MSan shadow exist to object to.  Keeping the
     * measurement and satisfying either is mutually exclusive: with the frame
     * exempted the probe would read redzone or shadow-poisoned bytes rather
     * than real residue.  So these lanes decline the test rather than
     * weakening it; the uninstrumented lanes run it, and they are where the
     * finding is gated.  See the AMA_PROBE_IS_INSTRUMENTED block above. */
    printf("SKIP: dead-stack residue cannot be measured under a sanitizer "
           "that relocates locals or instruments the read\n");
    return 77;
#else
    static uint8_t ct[MSG_BYTES], pt[MSG_BYTES];
    uint8_t tag[16];
    unsigned i;
    int control_hits;

    for (i = 0; i < sizeof g_key; i++) {
        g_key[i] = (uint8_t)(0xC3u ^ (i * 7u + 11u));
        /* Distinct from the key in every byte, and from the 0x5A poison. */
        g_sentinel[i] = (uint8_t)(0xA7u ^ (i * 13u + 3u));
    }
    memset(g_nonce, 0x24, sizeof g_nonce);
    memset(g_nonce16, 0x24, sizeof g_nonce16);
    memset(g_msg, 0x11, sizeof g_msg);

    printf("AEAD dead-stack key residue (INVARIANT-6)\n");
    printf("=========================================\n");

    /* --- control: the probe must be able to see a secret that IS left behind. */
    poison_stack();
    residue_probe_control(g_sentinel, sizeof g_sentinel);
    control_hits = residue_count(g_sentinel, sizeof g_sentinel);
    printf("  control (sentinel deliberately left): %d hit(s)\n", control_hits);
    CHECK(control_hits > 0,
          "probe control: a value left on the stack IS detected "
          "(a zero here means the scan window missed the frame and every "
          "verdict below would be vacuous)");
    CHECK(residue_window_covers_poison(),
          "probe coverage: the bytes the scan reads are the bytes the poison "
          "wrote (a failure here is a frame layout the probe was not written "
          "for, and every verdict below would be reading unpoisoned memory)");

    /* --- baseline: and it must hold NO copy of the key yet.
     *
     * The counterpart to the control, and the check that would have caught
     * the harness bug the control itself used to cause.  Every verdict below
     * reads `key_residue_count()`; if the window already holds the key, or
     * either half of it, before any AEAD has run, those verdicts are measuring
     * the harness rather than the library.  Assert the window is clean of the
     * needle first. */
    poison_stack();
    CHECK(key_residue_count() == 0,
          "probe baseline: no copy of the key is in the scan window before "
          "any AEAD call (a hit here means the harness contaminated the "
          "window and every verdict below would be measuring itself)");

    /* --- AES-256-GCM, both directions. */
    poison_stack();
    CHECK(run_gcm_encrypt(ct, tag) == AMA_SUCCESS, "AES-256-GCM encrypt succeeds");
    CHECK(key_residue_count() == 0,
          "AES-256-GCM encrypt leaves no raw key on the dead stack");

    poison_stack();
    CHECK(run_gcm_decrypt(ct, tag, pt) == AMA_SUCCESS, "AES-256-GCM decrypt succeeds");
    CHECK(key_residue_count() == 0,
          "AES-256-GCM decrypt leaves no raw key on the dead stack");
    CHECK(memcmp(pt, g_msg, MSG_BYTES) == 0, "AES-256-GCM round trip");

    /* Searching for the raw key is sufficient to cover the schedule: for
     * AES-256 the first two round keys ARE the key, so a build that leaks any
     * of the fifteen leaks these two — the pre-fix library failed exactly
     * here, with all fifteen present.  `key_residue_count()` searches each
     * 16-byte half separately, because the shipped AVX2
     * kernel spills those two round keys 112 bytes apart rather than
     * contiguously; see its comment. */

    /* --- ChaCha20-Poly1305, both directions. */
    poison_stack();
    CHECK(run_chacha_encrypt(ct, tag) == AMA_SUCCESS,
          "ChaCha20-Poly1305 encrypt succeeds");
    CHECK(key_residue_count() == 0,
          "ChaCha20-Poly1305 encrypt leaves no raw key on the dead stack");

    poison_stack();
    CHECK(run_chacha_decrypt(ct, tag, pt) == AMA_SUCCESS,
          "ChaCha20-Poly1305 decrypt succeeds");
    CHECK(key_residue_count() == 0,
          "ChaCha20-Poly1305 decrypt leaves no raw key on the dead stack");
    CHECK(memcmp(pt, g_msg, MSG_BYTES) == 0, "ChaCha20-Poly1305 round trip");

    /* --- a failed verification must not leave the key either. */
    tag[0] ^= 0x01u;
    poison_stack();
    CHECK(run_chacha_decrypt(ct, tag, pt) == AMA_ERROR_VERIFY_FAILED,
          "ChaCha20-Poly1305 rejects a bad tag");
    CHECK(key_residue_count() == 0,
          "ChaCha20-Poly1305 reject path leaves no raw key");

    /* --- Ascon-AEAD128, both directions and the reject path.  Pre-fix, gcc
     * left one key word after an encrypt and one to two after a rejected
     * decrypt, in the entry point's own frame. */
    poison_stack();
    CHECK(ascon_key_residue_count() == 0,
          "probe baseline: no Ascon key word in the window before any call");

    poison_stack();
    CHECK(run_ascon_encrypt(ct, tag) == AMA_SUCCESS,
          "Ascon-AEAD128 encrypt succeeds");
    CHECK(ascon_key_residue_count() == 0,
          "Ascon-AEAD128 encrypt leaves no key word on the dead stack");

    poison_stack();
    CHECK(run_ascon_decrypt(ct, tag, pt) == AMA_SUCCESS,
          "Ascon-AEAD128 decrypt succeeds");
    CHECK(ascon_key_residue_count() == 0,
          "Ascon-AEAD128 decrypt leaves no key word on the dead stack");
    CHECK(memcmp(pt, g_msg, MSG_BYTES) == 0, "Ascon-AEAD128 round trip");

    tag[0] ^= 0x01u;
    poison_stack();
    CHECK(run_ascon_decrypt(ct, tag, pt) == AMA_ERROR_VERIFY_FAILED,
          "Ascon-AEAD128 rejects a bad tag");
    CHECK(ascon_key_residue_count() == 0,
          "Ascon-AEAD128 reject path leaves no key word");

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
#endif
}
