/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ed25519_unaligned_input.c
 * @brief Ed25519 accepts caller buffers at any alignment, because it promises to
 *
 * `include/ama_cryptography.h` states exactly one requirement of
 * `ama_ed25519_verify`'s `signature` and `public_key`: "exactly 64 readable
 * bytes" and "exactly 32 readable bytes".  It says nothing about alignment,
 * and `const uint8_t *` imposes none, so `verify(sig, msg, len, packet + 3)`
 * is a legal call and must work.
 *
 * It did not.  On x86-64 the default backend is ed25519-donna
 * (`AMA_ED25519_ASSEMBLY` defaults ON there), and donna's `curve25519_expand`
 * read the public key with `*(uint64_t *)(in + 0)` — a load that requires
 * 8-byte alignment from a pointer that has none.  That is undefined behaviour
 * under C11 6.3.2.3p7, and UBSan reports it:
 *
 *   curve25519-donna-64bit.h:293:8: runtime error: load of misaligned address
 *   ... for type 'uint64_t', which requires 8 byte alignment
 *       #0 curve25519_expand
 *       #1 ge25519_unpack_negative_vartime
 *       #2 ed25519_sign_open
 *       #3 ama_ed25519_verify
 *
 * The `AddressSanitizer + UBSan` job runs `halt_on_error=1`, so for a caller
 * with an unaligned buffer this was not a warning — a signature check became
 * an abort.  The whole suite passed anyway, because every existing test hands
 * the library a `uint8_t[32]` local or static, which every compiler in use
 * aligns to at least 8.  Nothing exercised the contract as written.
 *
 * This test does.  It walks every offset in a byte slab, so at least one call
 * per loop is misaligned for 2, 4 and 8 bytes at once, and it asserts the
 * *verdict* as well — a good signature must still verify and a corrupted one
 * must still fail — so it is a real behavioural check in an ordinary build
 * and the UB tripwire in the sanitizer lanes.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "ama_cryptography.h"

/* Big enough for a 64-byte signature and a 32-byte key at any offset. */
#define SLAB 128
#define OFFSETS 16

static int failures = 0;

static void check(int cond, const char *what, int off) {
    if (!cond) {
        ++failures;
        fprintf(stderr, "  FAIL: %s at offset %d\n", what, off);
    }
}

int main(void) {
    uint8_t pk[32], sk[64], sig[64];
    static uint8_t key_slab[SLAB], sig_slab[SLAB];
    const char msg[] = "the header promises nothing about alignment";
    const size_t msg_len = sizeof(msg) - 1u;
    int off;

    printf("Ed25519 unaligned-caller-buffer test (%d offsets)\n", OFFSETS);

    /* ama_ed25519_keypair does NOT generate the seed: its contract is
     * "caller provides the 32-byte seed in secret_key[0..31] ... We must NOT
     * overwrite secret_key[0..31] here" (src/c/ed25519_donna_shim.c).  The
     * first revision of this file passed `sk` uninitialised and every
     * ordinary configuration passed — garbage is still a usable seed — which
     * is the exact defect test_ed25519_canonical_r.c documents MemorySanitizer
     * catching (use-of-uninitialized-value in sha512_LOAD64_BE under
     * ed25519_extsk).  A fixed seed also makes every offset's verdict
     * deterministic, which matters for a test that asserts both directions. */
    memset(sk, 0x42, 32);
    if (ama_ed25519_keypair(pk, sk) != AMA_SUCCESS) {
        fprintf(stderr, "FAILED: ama_ed25519_keypair\n");
        return 1;
    }
    if (ama_ed25519_sign(sig, (const uint8_t *)msg, msg_len, sk) != AMA_SUCCESS) {
        fprintf(stderr, "FAILED: ama_ed25519_sign\n");
        return 1;
    }

    /* Control: the aligned call every other test makes.  Without it a build
     * where verify always failed would pass the loop below vacuously. */
    check(ama_ed25519_verify(sig, (const uint8_t *)msg, msg_len, pk) == AMA_SUCCESS,
          "aligned control did not verify", -1);

    for (off = 0; off < OFFSETS; ++off) {
        uint8_t *upk = key_slab + off;
        uint8_t *usig = sig_slab + off;
        uint8_t saved;

        memcpy(upk, pk, sizeof(pk));
        memcpy(usig, sig, sizeof(sig));

        check(ama_ed25519_verify(usig, (const uint8_t *)msg, msg_len, upk) == AMA_SUCCESS,
              "a valid signature was rejected", off);

        /* And the other direction, so "always succeeds" cannot pass either. */
        saved = usig[0];
        usig[0] = (uint8_t)(saved ^ 0x01u);
        check(ama_ed25519_verify(usig, (const uint8_t *)msg, msg_len, upk) != AMA_SUCCESS,
              "a corrupted signature was accepted", off);
        usig[0] = saved;

        saved = upk[0];
        upk[0] = (uint8_t)(saved ^ 0x01u);
        check(ama_ed25519_verify(usig, (const uint8_t *)msg, msg_len, upk) != AMA_SUCCESS,
              "a signature verified under a corrupted key", off);
        upk[0] = saved;
    }

    if (failures != 0) {
        fprintf(stderr, "FAILED: %d error(s)\n", failures);
        return 1;
    }
    printf("PASS: %d offsets, valid and invalid verdicts both correct\n", OFFSETS);
    return 0;
}
