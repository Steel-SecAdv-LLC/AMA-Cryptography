/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ed25519_stack_residue.c
 * @brief No Ed25519 signing secret survives on the dead stack (INVARIANT-6).
 *
 * The signing path names three secrets it scrubs at exit: the SHA-512 of the
 * seed (whose clamped low half is the private scalar `a` and whose high half
 * is the nonce prefix), the per-message nonce `r`, and the hash buffer the
 * prefix is copied into.  `ama_ed25519_expand_secret_key` writes `a` and the
 * prefix into the caller's 128-byte expanded form and scrubs its own copy;
 * `ama_ed25519_sign_expanded` reads them from that form and copies the
 * prefix into a stack buffer it scrubs.  Each scrub was reviewed and none was
 * measured: `tests/c/test_aead_stack_residue.c` records that the AEAD
 * kernels' reviewed scrubs left all fifteen round keys behind, and the same
 * probe is applied here to the signing path.
 *
 * The probe: fill a stack region with a pattern, call the entry point at the
 * same depth, then read that region back and count occurrences of the
 * scalar and of the prefix.  Either one recovers signing capability on its
 * own — the scalar signs directly, and the prefix makes every nonce
 * predictable — so each is a needle in its own right.
 *
 * WHAT IS LOAD-BEARING (measured by mutation, AGENTS.md section 6.3).
 * Removing the `hash` scrub in `ama_ed25519_expand_secret_key` fails the
 * expand verdict (1 hit); removing the `hash` scrub in `ama_ed25519_sign`
 * fails the sign verdict (2 hits).  Removing the sign core's scrub of its
 * message buffer fails nothing here: the prefix it copies into that buffer
 * is overwritten by R || A for the second hash before the function returns,
 * so on this needle that scrub is redundant with the overwrite.  This test
 * pins the property -- no scalar or prefix on the dead stack -- and not any
 * one of the scrubs that together produce it.
 *
 * ONE SCAN PER POISON.  The scanning function is not exempt from the
 * defect it measures: a compiler may spill the needle it is comparing
 * against into the scanner's own frame, below the anchor, inside the window
 * the next scan at the same depth will read.  Measured: aarch64 gcc 13.3.0
 * at -O2 with -fsanitize=undefined (the arm-qemu UBSan lane) leaves
 * scalar[16..32] at anchor-95 and prefix[0..16] at anchor-143 after one
 * scan, so a second evaluation of `secret_residue_count()` before the next
 * `poison_stack()` reported the first evaluation's spill as library residue
 * and failed the expand verdict; x86-64 gcc and clang keep the needle in
 * registers and never showed it.  Each verdict below therefore evaluates the
 * count exactly once per poison and prints that value; `poison_stack()`'s
 * 32 KiB frame at this same depth is what clears the previous scan's spill
 * before the next probed call.
 *
 * CONTROL and BASELINE follow the AEAD harness exactly: a sentinel the probe
 * MUST see, then a window that MUST hold no copy of either needle before any
 * signing call, so a verdict is trusted only after both directions are
 * established.  The reasoning behind every construction here — the barrier
 * in `poison_stack`, the integer address arithmetic in `residue_count`, the
 * sentinel that is not the secret, and the sanitizer skip — is recorded in
 * that file and is not repeated.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "ama_cryptography.h"

#if defined(__has_feature)
#  if __has_feature(address_sanitizer) || __has_feature(memory_sanitizer) \
      || __has_feature(thread_sanitizer)
#    define AMA_PROBE_IS_INSTRUMENTED 1
#  endif
#endif
#if !defined(AMA_PROBE_IS_INSTRUMENTED) && (defined(__SANITIZE_ADDRESS__) \
    || defined(__SANITIZE_MEMORY__) || defined(__SANITIZE_THREAD__))
#  define AMA_PROBE_IS_INSTRUMENTED 1
#endif
#if !defined(AMA_PROBE_IS_INSTRUMENTED)
#  define AMA_PROBE_IS_INSTRUMENTED 0
#endif

/* Everything up to main() is the probe itself, compiled only where it runs:
 * an instrumented build returns 77 before calling any of it, and would
 * otherwise carry every helper as an unused function. */
#if !AMA_PROBE_IS_INSTRUMENTED

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

/* Inputs and outputs live in globals, never in the probing frame, so the only
 * copies the scan can find are the ones the library left. */
static uint8_t g_sk[64];
static uint8_t g_pk[32];
static uint8_t g_expanded[AMA_ED25519_EXPANDED_KEY_BYTES];
static uint8_t g_msg[MSG_BYTES];
static uint8_t g_sig[64];
static uint8_t g_sentinel[32];

/* The needles.  Bytes 0..31 of the expanded form are the clamped scalar and
 * bytes 32..63 are the prefix; both are what SHA-512(seed) produced and are
 * copied here once so the expanded form itself can be re-derived later. */
static uint8_t g_scalar[32];
static uint8_t g_prefix[32];

/* The scalar again, in the form the scalar arithmetic holds it: twelve signed
 * 64-bit limbs of 21 bits (sc25519_muladd / sc25519_reduce).  A spilled limb
 * is not a byte-form copy, so the 16-byte needles above cannot see it — and
 * one was left behind: limb 8 after sign and keypair under LTO, limb 9 after
 * sign and sign_expanded without.  Limbs whose value fits in 16 bits are
 * skipped as needles; they are too likely to occur by chance. */
static int64_t g_limbs[12];

static void scalar_limbs(const uint8_t s[32], int64_t out[12]) {
    int i;
    for (i = 0; i < 12; i++) {
        const int bit = 21 * i;
        uint64_t v = 0;
        int k;
        for (k = 0; k < 5 && bit / 8 + k < 32; k++) {
            v |= (uint64_t)s[bit / 8 + k] << (8 * k);
        }
        v >>= (unsigned)(bit & 7);
        out[i] = (i == 11) ? (int64_t)v : (int64_t)(v & 0x1FFFFFu);
    }
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void poison_stack(void) {
    volatile uint8_t pad[SCAN_BYTES];
    memset((void *)pad, 0x5A, sizeof pad);
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(pad) : "memory");
#else
    (void)pad[0];
#endif
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static int residue_count(const uint8_t *needle, size_t len) {
    volatile uint8_t anchor = 0;
    const uintptr_t anchor_addr = (uintptr_t)(const void *)&anchor;
    const uint8_t *base = (const uint8_t *)(anchor_addr - (uintptr_t)SCAN_BYTES);
    size_t i;
    int hits = 0;
    for (i = 0; i + len <= SCAN_BYTES; i++) {
        if (memcmp(base + i, needle, len) == 0) {
            hits++;
        }
    }
    return hits;
}

/* Either secret, in either 16-byte half: a compiler need not spill a value as
 * one object, and the AVX2 AES kernel demonstrably does not (see the AEAD
 * harness).  Half a scalar or half a prefix is 128 bits of secret. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static int secret_residue_count(void) {
    int hits = residue_count(g_scalar, 16) + residue_count(g_scalar + 16, 16)
             + residue_count(g_prefix, 16) + residue_count(g_prefix + 16, 16);
    int i;
    for (i = 0; i < 12; i++) {
        if (g_limbs[i] > 0xFFFF) {
            hits += residue_count((const uint8_t *)&g_limbs[i], sizeof g_limbs[i]);
        }
    }
    return hits;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void probe_control(void) {
    volatile uint8_t copy[512];
    memset((void *)copy, 0, sizeof copy);
    memcpy((void *)(copy + 128), g_sentinel, sizeof g_sentinel);
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(copy) : "memory");
#endif
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void run_expand(void) {
    CHECK(ama_ed25519_expand_secret_key(g_expanded, g_sk) == AMA_SUCCESS,
          "expand_secret_key succeeds");
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void run_sign_expanded(void) {
    CHECK(ama_ed25519_sign_expanded(g_sig, g_msg, MSG_BYTES, g_expanded) == AMA_SUCCESS,
          "sign_expanded succeeds");
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void run_keypair(void) {
    static uint8_t pk[32];
    CHECK(ama_ed25519_keypair(pk, g_sk) == AMA_SUCCESS && memcmp(pk, g_pk, 32) == 0,
          "keypair succeeds and is deterministic");
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void run_sign(void) {
    CHECK(ama_ed25519_sign(g_sig, g_msg, MSG_BYTES, g_sk) == AMA_SUCCESS,
          "sign succeeds");
}

/* A message above the 4 KiB stack threshold takes the heap path of the sign
 * core, whose scrub covers a different buffer than the small-message path. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void run_sign_expanded_large(const uint8_t *big, size_t big_len) {
    CHECK(ama_ed25519_sign_expanded(g_sig, big, big_len, g_expanded) == AMA_SUCCESS,
          "sign_expanded (heap path) succeeds");
}

#endif /* !AMA_PROBE_IS_INSTRUMENTED */

int main(void) {
#if AMA_PROBE_IS_INSTRUMENTED
    printf("SKIP: dead-stack residue cannot be measured under a sanitizer "
           "that relocates locals or instruments the read\n");
    return 77;
#else
    unsigned i;
    int control_hits;
    int hits;
    uint8_t *big;
    const size_t big_len = 8192u;

    for (i = 0; i < 32u; i++) {
        g_sk[i] = (uint8_t)(0xC3u ^ (i * 7u + 11u));
        g_sentinel[i] = (uint8_t)(0xA7u ^ (i * 13u + 3u));
    }
    memset(g_msg, 0x11, sizeof g_msg);
    big = (uint8_t *)malloc(big_len);
    if (!big) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }
    memset(big, 0x22, big_len);

    printf("Ed25519 dead-stack signing-secret residue (INVARIANT-6)\n");
    printf("=======================================================\n");

    /* Derive the needles once, off the probed depth: keypair, then expand.
     * The expanded form's first 64 bytes ARE the scalar and prefix. */
    CHECK(ama_ed25519_keypair(g_pk, g_sk) == AMA_SUCCESS, "keypair succeeds");
    CHECK(ama_ed25519_expand_secret_key(g_expanded, g_sk) == AMA_SUCCESS,
          "expand_secret_key (needle derivation) succeeds");
    memcpy(g_scalar, g_expanded, 32);
    memcpy(g_prefix, g_expanded + 32, 32);
    scalar_limbs(g_scalar, g_limbs);
    CHECK((g_scalar[0] & 7u) == 0u && (g_scalar[31] & 0xC0u) == 0x40u,
          "needle is the clamped scalar");

    /* --- control: the probe must be able to see a value left behind. */
    poison_stack();
    probe_control();
    control_hits = residue_count(g_sentinel, sizeof g_sentinel);
    printf("  control (sentinel deliberately left): %d hit(s)\n", control_hits);
    CHECK(control_hits > 0,
          "probe control: a value left on the stack IS detected "
          "(a zero here means the scan window missed the frame and every "
          "verdict below would be vacuous)");

    /* --- baseline: the window holds neither needle before any probed call.
     * The derivation above ran at this depth too, so this is also the first
     * verdict on expand_secret_key's scrub; it is asserted again below
     * against a fresh poison so the two cannot be confused. */
    poison_stack();
    CHECK(secret_residue_count() == 0,
          "probe baseline: no copy of the scalar or prefix is in the scan "
          "window before any probed call");

    /* --- expand_secret_key: its `hash` holds both needles and is scrubbed. */
    poison_stack();
    run_expand();
    hits = secret_residue_count();
    printf("  expand_secret_key: %d hit(s)\n", hits);
    CHECK(hits == 0,
          "expand_secret_key leaves neither the scalar nor the prefix on the "
          "dead stack");
    CHECK(memcmp(g_expanded, g_scalar, 32) == 0 &&
          memcmp(g_expanded + 32, g_prefix, 32) == 0,
          "expand_secret_key is deterministic");

    /* --- sign_expanded, stack path: the prefix is copied into `stack_buf`. */
    poison_stack();
    run_sign_expanded();
    hits = secret_residue_count();
    printf("  sign_expanded (stack path): %d hit(s)\n", hits);
    CHECK(hits == 0,
          "sign_expanded (stack path) leaves neither the scalar nor the "
          "prefix on the dead stack");
    CHECK(ama_ed25519_verify(g_sig, g_msg, MSG_BYTES, g_pk) == AMA_SUCCESS,
          "sign_expanded signature verifies");

    /* --- sign_expanded, heap path. */
    poison_stack();
    run_sign_expanded_large(big, big_len);
    hits = secret_residue_count();
    printf("  sign_expanded (heap path): %d hit(s)\n", hits);
    CHECK(hits == 0,
          "sign_expanded (heap path) leaves neither the scalar nor the "
          "prefix on the dead stack");
    CHECK(ama_ed25519_verify(g_sig, big, big_len, g_pk) == AMA_SUCCESS,
          "sign_expanded (heap path) signature verifies");

    /* --- keypair: the comb multiplies by the scalar it derives. */
    poison_stack();
    run_keypair();
    hits = secret_residue_count();
    printf("  keypair: %d hit(s)\n", hits);
    CHECK(hits == 0, "keypair leaves neither the scalar nor the prefix on the dead stack");

    /* --- sign from the 64-byte key: derives `hash` itself, then signs. */
    poison_stack();
    run_sign();
    hits = secret_residue_count();
    printf("  sign: %d hit(s)\n", hits);
    CHECK(hits == 0,
          "sign leaves neither the scalar nor the prefix on the dead stack");
    CHECK(ama_ed25519_verify(g_sig, g_msg, MSG_BYTES, g_pk) == AMA_SUCCESS,
          "sign signature verifies");

    free(big);
    ama_secure_memzero(g_scalar, sizeof g_scalar);
    ama_secure_memzero(g_prefix, sizeof g_prefix);
    ama_secure_memzero(g_expanded, sizeof g_expanded);
    ama_secure_memzero(g_sk, sizeof g_sk);

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
#endif
}
