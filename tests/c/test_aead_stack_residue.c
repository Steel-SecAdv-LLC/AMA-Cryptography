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
 * leaves a 32-byte SENTINEL in its own frame and the test FAILS if the probe
 * cannot see that.  A BASELINE check then asserts the window holds no copy of
 * the key before any AEAD runs.  Both directions are checked before any AEAD
 * verdict is trusted.
 *
 * The sentinel is not a detail: the control planted the KEY until this pass,
 * which contaminated the window with the very needle every later check
 * searches for, and turned the control into a false positive for the AEAD
 * verdicts under any frame layout that did not clear it.  See `g_sentinel`.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "ama_cryptography.h"

/* Sanitizers under which this probe cannot measure what it claims to.
 *
 * The premise of the whole file is that a function's locals live in ITS stack
 * frame, at a predictable depth below the caller's.  Every sanitizer here
 * breaks that premise or the read that tests it, each in its own way, so each
 * is named with the observation that established it:
 *
 *   - AddressSanitizer reports "stack-buffer-underflow ... 'anchor' ...
 *     underflows this variable" -- the probe reads past a one-byte object into
 *     its redzone, which is precisely what a redzone is for.
 *   - MemorySanitizer reports use-of-uninitialised-value -- dead stack the AEAD
 *     frame never wrote is exactly that.  Measured: the MSan lane reported
 *     `test_aead_stack_residue (Subprocess aborted)` while only ASan was named
 *     here, so MSan fell through and ran the probe.
 *   - ThreadSanitizer neither faults nor aborts.  It relocates locals off the
 *     real frame, so the probe simply stops seeing them, and the run is
 *     vacuous rather than loud.  The CONTROL is what caught it, which is why
 *     the control exists:
 *
 *         FAIL: probe control: a value left on the stack IS detected
 *           control (sentinel deliberately left): 0 hit(s)
 *         14 checks, 1 failures
 *
 *     Every AEAD verdict "passed" in that same run -- on a window that could
 *     not see a value deliberately planted in it.  Reporting those as evidence
 *     of no residue is the vacuous pass this test is built to refuse, so the
 *     lane declines instead.
 *
 * Enumerating sanitizers is a shape that fails again on the next one added,
 * and this file has now been caught by that twice.  What stands behind the
 * list is the control: an unanticipated sanitizer that breaks the premise
 * fails the control loudly rather than passing quietly, and the fix is to add
 * it here with its observation, never to relax the control. */
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
static uint8_t g_nonce16[16];
static uint8_t g_msg[MSG_BYTES];

/* What `probe_control()` plants, and what the control searches for.
 *
 * NEVER the key.  The control used to plant `g_key` itself, which made it
 * manufacture a false positive for every check that ran after it: the planted
 * copy landed 391 bytes below the probe's anchor, the `poison_stack()` before
 * the next check did not clear it, and the AES-256-GCM check then found the
 * CONTROL's key and reported it as an AEAD leak.  gcc's frame layout happened
 * to place the two out of each other's way and clang's did not, so the lane
 * split by compiler rather than by library behaviour -- exactly the shape of
 * a harness bug wearing a finding's clothes.  Proven by planting this
 * distinct value instead and re-running unchanged: the AEAD checks go to zero
 * hits under clang 18 -O2 -flto=thin, the configuration that failed.
 *
 * A control only has to establish that the scan window covers a frame at this
 * depth.  Any 32-byte value does that, and one that is not the secret cannot
 * be mistaken for it. */
static uint8_t g_sentinel[32];

/* Poison the region a later call will use, so a hit is residue rather than a
 * leftover from process start.
 *
 * The barrier below is load-bearing, not decoration.  `pad` is local, never
 * escapes and is dead at return, so the `memset` is a dead store and clang
 * deletes the whole 32 KiB of it: measured on the shipped flags, clang 18.1.3
 * emitted this entire function as
 *
 *     movb   $0x5a,-0x8(%rsp)      ; ONE byte
 *     movzbl -0x8(%rsp),%eax       ; satisfying the volatile read
 *     ret
 *
 * -- the 32 KiB frame is never even allocated -- while gcc 13.3.0 emitted the
 * real stack probe and memset.  That is the whole of the compiler split this
 * test showed: with no poison, whatever was on the stack from an earlier call
 * survives into the next scan, and "a hit is residue rather than a leftover"
 * is simply false.  It is also why the control's planted key used to reappear
 * in the AES-GCM verdict.
 *
 * The `"r"(pad)` operand makes the address escape and the `"memory"` clobber
 * makes the stores observable, so the memset must happen -- the same
 * construction `ama_secure_stack_wipe()` uses for the same reason. */
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

/* Occurrences of `needle` in the SCAN_BYTES below this frame. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static int residue_count(const uint8_t *needle, size_t len) {
    volatile uint8_t anchor = 0;
    /* Reach BELOW the anchor through uintptr_t rather than by subtracting
     * from `&anchor`.  Pointer arithmetic on a one-byte object is what the
     * probe means, but it is also, formally, out of that object's bounds,
     * and gcc says so: "array subscript -32768 is outside array bounds of
     * volatile uint8_t[1]" (-Warray-bounds).  The warning is correct about
     * the C, and reading dead stack IS the measurement, so the address is
     * computed as an integer -- which is exactly the operation intended --
     * instead of the diagnostic being suppressed. */
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
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static int key_residue_count(void) {
    return residue_count(g_key, 16) + residue_count(g_key + 16, 16);
}

/* Ascon-AEAD128's 16-byte key is g_key[0:16], held by the permutation as two
 * 64-bit words in host order, so a spill is an 8-byte word rather than a
 * 16-byte copy; each word is 64 bits of key. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static int ascon_key_residue_count(void) {
    return residue_count(g_key, 8) + residue_count(g_key + 8, 8);
}

/* Positive control: leaves the SENTINEL in a frame the probe must be able to
 * see.  See `g_sentinel` for why this must not be the key. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void probe_control(void) {
    volatile uint8_t copy[512];
    memset((void *)copy, 0, sizeof copy);
    memcpy((void *)(copy + 128), g_sentinel, sizeof g_sentinel);
    /* Keep the copy alive to the end of the frame, then return without a
     * scrub — the exact shape the AEAD kernels used to exhibit. */
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(copy) : "memory");
#endif
}

/* Every AEAD call runs below a GAP_BYTES buffer the caller keeps live, so the
 * primitive's frame lies wholly below the region `residue_count()`'s own
 * frame overwrites when it is called at the same depth.  Without the gap the
 * top of the primitive's frame is clobbered by the probe before it is read,
 * and whether a spill survives to be counted depends on frame layout:
 * measured, the unfixed Ascon-AEAD128 left a key word 87 bytes below the
 * anchor under gcc -O2 and in the clobbered bytes under the build's -O3,
 * where the probe passed against it. */
#define GAP_BYTES 512u

#if defined(__GNUC__) || defined(__clang__)
#  define NOINLINE __attribute__((noinline))
#  define KEEP_LIVE(buf) __asm__ __volatile__("" : : "r"(buf) : "memory")
#else
#  define NOINLINE
#  define KEEP_LIVE(buf) ((void)(buf)[0])
#endif

#define RUN_BELOW_GAP(call) do {                                 \
    volatile uint8_t gap[GAP_BYTES];                             \
    gap[0] = 0;                                                  \
    KEEP_LIVE(gap);                                              \
    rc = (call);                                                 \
    KEEP_LIVE(gap);                                              \
} while (0)

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
    probe_control();
    control_hits = residue_count(g_sentinel, sizeof g_sentinel);
    printf("  control (sentinel deliberately left): %d hit(s)\n", control_hits);
    CHECK(control_hits > 0,
          "probe control: a value left on the stack IS detected "
          "(a zero here means the scan window missed the frame and every "
          "verdict below would be vacuous)");

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
