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
 * scalar, of the prefix and of the per-message nonce `r`.  Each recovers
 * signing capability on its own — the scalar signs directly, the prefix
 * makes every nonce predictable, and `r` with the public signature gives the
 * scalar back as a = (S - r) * h^-1 mod l — so each is a needle in its own
 * right.  `r` is derived here from public data and the prefix, exactly as
 * the signer derives it (SHA-512(prefix || M) reduced mod l), once for each
 * message the probe signs.
 *
 * WHAT IS LOAD-BEARING (measured by mutation, AGENTS.md section 6.3).
 * Removing the `hash` scrub in `ama_ed25519_expand_secret_key` fails the
 * expand verdict (1 hit); removing the `hash` scrub in `ama_ed25519_sign`
 * fails the sign verdict (2 hits).  Removing the sign core's scrub of its
 * message buffer fails nothing here: the prefix it copies into that buffer
 * is overwritten by R || A for the second hash before the function returns,
 * so on this needle that scrub is redundant with the overwrite.  The nonce
 * needle is held the same way (gcc 13.3.0, Release, LTO, x86-64, against the
 * shared library): removing the sign core's `r` scrub alone fails nothing,
 * and removing the `ama_stack_wipe_below` backstop from ama_ed25519_sign and
 * ama_ed25519_sign_expanded alone fails no nonce verdict either (it fails
 * the sign verdict on a scalar limb, as before); removing both leaves `r` in
 * the dead core frame and fails the sign and both sign_expanded verdicts
 * with 2 nonce hits each.  This test pins the property -- no scalar, prefix
 * or nonce on the dead stack -- and not any one of the scrubs that together
 * produce it.
 *
 * `ama_ed25519_point_from_scalar` is probed too.  It is the raw [s]B
 * primitive FROST calls with secrets -- the group secret, each dealt share,
 * and both round-1 nonces -- and it runs the same reduce-then-comb path as
 * keypair, so it leaves the same spilled limbs.  It is probed twice: with the
 * clamped scalar (the keypair-equivalent input, whose reduction mod l is not
 * the identity) and with that scalar reduced mod l, the shape every FROST
 * secret has.  Measured 2026-09-24, x86-64 gcc 13.3 Release with LTO, against
 * the shared library: before point_from_scalar called `ama_stack_wipe_below`
 * each probe found 1 hit, limb 8 (bits 168..188, which the scalar and its
 * reduction share), and removing that one call restores exactly that.
 *
 * THE PROBE is `residue_probe.h`, shared with the AEAD harness: poison, run
 * the entry point below a GAP at the same depth, scan the poisoned bytes.
 * Its control, baseline and coverage checks are what make a verdict below
 * evidence, and the reasoning behind every construction — the barrier in
 * `poison_stack`, the mark taken in a leaf below the scanner, the window
 * clipped to the poison, the sentinel that is not the secret, the GAP, and
 * the sanitizer skip — is recorded there once.
 *
 * ONE SCAN PER POISON.  Each verdict evaluates `secret_residue_count()`
 * exactly once per poison and prints that value.  The discipline dates from
 * a measurement on aarch64 gcc 13.3.0 -O2 -fsanitize=undefined (the
 * arm-qemu UBSan lane), where the scanner spilled scalar[16..32] at
 * anchor-95 and prefix[0..16] at anchor-143 into its own frame, and a
 * second evaluation before the next poison reported the first one's spill
 * as library residue.  That frame is no longer inside the window (the mark
 * is taken below the scanner; see residue_probe.h, defect (a)), so the
 * discipline is now defensive rather than load-bearing; it is kept because
 * it costs nothing.  The record it replaces claimed the scanner's spill was
 * the only way the harness could see its own needle.  It was not: on the
 * uninstrumented AArch64 lanes the caller kept each limb needle live in a
 * callee-saved register across the scan, the scanner's prologue saved that
 * register inside the window, and every verdict — baseline included —
 * reported all twelve scalar limbs, once each (2026-09-25, RelWithDebInfo,
 * the arm-qemu-ctest, no-crypto-ext and both SVE2 lanes).  The window is
 * fixed at the construction, not the symptom.
 *
 * CONTROL and BASELINE: a sentinel the probe MUST see, then a window that
 * MUST hold no copy of any needle before any signing call, then the
 * coverage check that the window read is the poison written; a verdict is
 * trusted only after all three are established.
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

/* The per-message nonce r = SHA-512(prefix || M) mod l, for the two
 * messages the probe signs (the MSG_BYTES stack-path message and the 8 KiB
 * heap-path one).  Bytes 32..63 of each are the reducer's scratch. */
static uint8_t g_r[2][64];

/* The scalar again, in the form the scalar arithmetic holds it: twelve signed
 * 64-bit limbs of 21 bits (sc25519_muladd / sc25519_reduce).  A spilled limb
 * is not a byte-form copy, so the 16-byte needles above cannot see it — and
 * one was left behind: limb 8 after sign and keypair under LTO, limb 9 after
 * sign and sign_expanded without.  Limbs whose value fits in 16 bits are
 * skipped as needles; they are too likely to occur by chance.  The nonces
 * are held the same way by the same two routines, so their limbs are
 * needles too. */
static int64_t g_limbs[12];
static int64_t g_r_limbs[2][12];

/* The scalar reduced mod l, and its limbs: the form every FROST secret takes
 * (a nonce, a share, the group secret), fed to point_from_scalar below.  The
 * reduction inside the comb path of keypair and sign produces this value as
 * well, so every verdict counts it. */
static uint8_t g_reduced[32];
static int64_t g_reduced_limbs[12];

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

/* The last count, by needle: the scalar (bytes and limbs), the prefix, and
 * the two nonces (bytes and limbs).  Printed with each verdict so a failure
 * names what survived; written by the one evaluation per poison. */
static int g_hits_scalar, g_hits_prefix, g_hits_nonce;

/* Every secret, in either 16-byte half: a compiler need not spill a value as
 * one object, and the AVX2 AES kernel demonstrably does not (see the AEAD
 * harness).  Half a scalar, half a prefix or half a nonce is 128 bits of
 * secret. */
RESIDUE_NOINLINE
static int secret_residue_count(void) {
    int i, m;
    g_hits_scalar = residue_count(g_scalar, 16) + residue_count(g_scalar + 16, 16)
                  + residue_count(g_reduced, 16) + residue_count(g_reduced + 16, 16);
    for (i = 0; i < 12; i++) {
        if (g_limbs[i] > 0xFFFF) {
            g_hits_scalar += residue_count((const uint8_t *)&g_limbs[i], sizeof g_limbs[i]);
        }
        /* The reduction subtracts a small multiple of l, so the upper limbs
         * of the two forms coincide; a shared limb is counted once. */
        if (g_reduced_limbs[i] > 0xFFFF && g_reduced_limbs[i] != g_limbs[i]) {
            g_hits_scalar += residue_count((const uint8_t *)&g_reduced_limbs[i],
                                           sizeof g_reduced_limbs[i]);
        }
    }
    g_hits_prefix = residue_count(g_prefix, 16) + residue_count(g_prefix + 16, 16);
    g_hits_nonce = 0;
    for (m = 0; m < 2; m++) {
        g_hits_nonce += residue_count(g_r[m], 16) + residue_count(g_r[m] + 16, 16);
        for (i = 0; i < 12; i++) {
            if (g_r_limbs[m][i] > 0xFFFF) {
                g_hits_nonce += residue_count((const uint8_t *)&g_r_limbs[m][i],
                                              sizeof g_r_limbs[m][i]);
            }
        }
    }
    return g_hits_scalar + g_hits_prefix + g_hits_nonce;
}

static void print_verdict(const char *what, int hits) {
    printf("  %s: %d hit(s) (scalar %d, prefix %d, nonce %d)\n", what, hits,
           g_hits_scalar, g_hits_prefix, g_hits_nonce);
}

/* r = SHA-512(prefix || msg) mod l, as the signer computes it, through the
 * library's exported hash and reducer. */
static int derive_nonce(uint8_t out[64], const uint8_t *msg, size_t msg_len) {
    uint8_t *buf = (uint8_t *)malloc(32 + msg_len);
    if (!buf) {
        return -1;
    }
    memcpy(buf, g_prefix, 32);
    memcpy(buf + 32, msg, msg_len);
    ama_ed25519_sha512(buf, 32 + msg_len, out);
    ama_ed25519_sc_reduce(out);
    ama_secure_memzero(buf, 32 + msg_len);
    free(buf);
    return 0;
}

/* Every probed entry point runs below the GAP (residue_probe.h), so its
 * frame lies wholly under the bytes the scanner's frames occupy when they are
 * called at this same depth.  Until 2026-09-25 these wrappers had no gap and
 * the top ~176 bytes of each entry point's frame were clobbered by the
 * scanner before they were read. */
RESIDUE_NOINLINE
static void run_expand(void) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_ed25519_expand_secret_key(g_expanded, g_sk));
    CHECK(rc == AMA_SUCCESS, "expand_secret_key succeeds");
}

RESIDUE_NOINLINE
static void run_sign_expanded(void) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_ed25519_sign_expanded(g_sig, g_msg, MSG_BYTES, g_expanded));
    CHECK(rc == AMA_SUCCESS, "sign_expanded succeeds");
}

RESIDUE_NOINLINE
static void run_keypair(void) {
    static uint8_t pk[32];
    ama_error_t rc;
    RUN_BELOW_GAP(ama_ed25519_keypair(pk, g_sk));
    CHECK(rc == AMA_SUCCESS && memcmp(pk, g_pk, 32) == 0,
          "keypair succeeds and is deterministic");
}

RESIDUE_NOINLINE
static void run_sign(void) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_ed25519_sign(g_sig, g_msg, MSG_BYTES, g_sk));
    CHECK(rc == AMA_SUCCESS, "sign succeeds");
}

/* The raw FROST primitive, on a scalar whose [s]B is known: the clamped
 * scalar gives the public key, and so does its reduction mod l. */
RESIDUE_NOINLINE
static void run_point_from_scalar(const uint8_t *scalar) {
    static uint8_t point[32];
    ama_error_t rc;
    RUN_BELOW_GAP(ama_ed25519_point_from_scalar(point, scalar));
    CHECK(rc == AMA_SUCCESS && memcmp(point, g_pk, 32) == 0,
          "point_from_scalar succeeds and [s]B is the public key");
}

/* A message above the 4 KiB stack threshold takes the heap path of the sign
 * core, whose scrub covers a different buffer than the small-message path. */
RESIDUE_NOINLINE
static void run_sign_expanded_large(const uint8_t *big, size_t big_len) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_ed25519_sign_expanded(g_sig, big, big_len, g_expanded));
    CHECK(rc == AMA_SUCCESS, "sign_expanded (heap path) succeeds");
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
    {
        static uint8_t wide[64];
        memcpy(wide, g_scalar, 32);
        memset(wide + 32, 0, 32);
        ama_ed25519_sc_reduce(wide);
        memcpy(g_reduced, wide, 32);
        ama_secure_memzero(wide, sizeof wide);
    }
    scalar_limbs(g_reduced, g_reduced_limbs);
    CHECK(memcmp(g_reduced, g_scalar, 32) != 0,
          "the clamped scalar exceeds l, so its reduction is a distinct needle");
    CHECK((g_scalar[0] & 7u) == 0u && (g_scalar[31] & 0xC0u) == 0x40u,
          "needle is the clamped scalar");
    CHECK(derive_nonce(g_r[0], g_msg, MSG_BYTES) == 0 &&
          derive_nonce(g_r[1], big, big_len) == 0,
          "the per-message nonces are derived");
    scalar_limbs(g_r[0], g_r_limbs[0]);
    scalar_limbs(g_r[1], g_r_limbs[1]);
    /* The nonce needle must be the one the signer used: R = [r]B is the
     * first half of the signature it produces. */
    {
        uint8_t R[32];
        CHECK(ama_ed25519_sign(g_sig, g_msg, MSG_BYTES, g_sk) == AMA_SUCCESS &&
              ama_ed25519_point_from_scalar(R, g_r[0]) == AMA_SUCCESS &&
              memcmp(R, g_sig, 32) == 0,
              "needle is the signer's nonce: [r]B equals the signature's R");
        CHECK(ama_ed25519_sign_expanded(g_sig, big, big_len, g_expanded) == AMA_SUCCESS &&
              ama_ed25519_point_from_scalar(R, g_r[1]) == AMA_SUCCESS &&
              memcmp(R, g_sig, 32) == 0,
              "needle is the heap-path signer's nonce: [r]B equals R");
    }

    /* --- control: the probe must be able to see a value left behind. */
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

    /* --- baseline: the window holds neither needle before any probed call.
     * The derivation above ran at this depth too, so this is also the first
     * verdict on expand_secret_key's scrub; it is asserted again below
     * against a fresh poison so the two cannot be confused. */
    poison_stack();
    CHECK(secret_residue_count() == 0,
          "probe baseline: no copy of the scalar, prefix or nonce is in the "
          "scan window before any probed call");

    /* --- expand_secret_key: its `hash` holds both needles and is scrubbed. */
    poison_stack();
    run_expand();
    hits = secret_residue_count();
    print_verdict("expand_secret_key", hits);
    CHECK(hits == 0,
          "expand_secret_key leaves no scalar, prefix or nonce on the dead "
          "stack");
    CHECK(memcmp(g_expanded, g_scalar, 32) == 0 &&
          memcmp(g_expanded + 32, g_prefix, 32) == 0,
          "expand_secret_key is deterministic");

    /* --- sign_expanded, stack path: the prefix is copied into `stack_buf`. */
    poison_stack();
    run_sign_expanded();
    hits = secret_residue_count();
    print_verdict("sign_expanded (stack path)", hits);
    CHECK(hits == 0,
          "sign_expanded (stack path) leaves no scalar, prefix or nonce on "
          "the dead stack");
    CHECK(ama_ed25519_verify(g_sig, g_msg, MSG_BYTES, g_pk) == AMA_SUCCESS,
          "sign_expanded signature verifies");

    /* --- sign_expanded, heap path. */
    poison_stack();
    run_sign_expanded_large(big, big_len);
    hits = secret_residue_count();
    print_verdict("sign_expanded (heap path)", hits);
    CHECK(hits == 0,
          "sign_expanded (heap path) leaves no scalar, prefix or nonce on "
          "the dead stack");
    CHECK(ama_ed25519_verify(g_sig, big, big_len, g_pk) == AMA_SUCCESS,
          "sign_expanded (heap path) signature verifies");

    /* --- keypair: the comb multiplies by the scalar it derives. */
    poison_stack();
    run_keypair();
    hits = secret_residue_count();
    print_verdict("keypair", hits);
    CHECK(hits == 0, "keypair leaves no scalar, prefix or nonce on the dead stack");

    /* --- sign from the 64-byte key: derives `hash` itself, then signs. */
    poison_stack();
    run_sign();
    hits = secret_residue_count();
    print_verdict("sign", hits);
    CHECK(hits == 0,
          "sign leaves no scalar, prefix or nonce on the dead stack");
    CHECK(ama_ed25519_verify(g_sig, g_msg, MSG_BYTES, g_pk) == AMA_SUCCESS,
          "sign signature verifies");

    /* --- point_from_scalar: the FROST secret-scalar primitive, first on the
     * keypair-equivalent input, then on a scalar already reduced mod l. */
    poison_stack();
    run_point_from_scalar(g_scalar);
    hits = secret_residue_count();
    printf("  point_from_scalar (clamped scalar): %d hit(s)\n", hits);
    CHECK(hits == 0,
          "point_from_scalar (clamped scalar) leaves no copy of the scalar on "
          "the dead stack");

    poison_stack();
    run_point_from_scalar(g_reduced);
    hits = secret_residue_count();
    printf("  point_from_scalar (reduced scalar): %d hit(s)\n", hits);
    CHECK(hits == 0,
          "point_from_scalar (scalar < l, the FROST shape) leaves no copy of "
          "the scalar on the dead stack");

    free(big);
    ama_secure_memzero(g_reduced, sizeof g_reduced);
    ama_secure_memzero(g_scalar, sizeof g_scalar);
    ama_secure_memzero(g_prefix, sizeof g_prefix);
    ama_secure_memzero(g_r, sizeof g_r);
    ama_secure_memzero(g_r_limbs, sizeof g_r_limbs);
    ama_secure_memzero(g_expanded, sizeof g_expanded);
    ama_secure_memzero(g_sk, sizeof g_sk);

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
#endif
}
