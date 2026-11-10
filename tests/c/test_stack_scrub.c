/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_stack_scrub.c
 * @brief A secret-handling public entry point returns with the stack it used
 *        cleared, and with nothing input-dependent in its own frame
 *        (INVARIANT-6).
 *
 * WHAT IS MEASURED, AND WHY NOT A NEEDLE.  The residue harnesses that came
 * first (residue_probe.h, test_aead_stack_residue.c, test_ed25519_stack_
 * residue.c, test_register_residue.c) search a dead frame for a value they
 * name: a key, a limb, the whole output.  A harness of that kind sees only
 * the forms it thought of.  Measured 2026-11-10 on the shipped build (gcc
 * 13.3 -O3, LTO), with one 8-byte word of the secret as the needle instead
 * of the whole of it: three of the four words of the HKDF-SHA3-256 output,
 * seven of eight of a SHA3-512 digest and two of ML-KEM's implicit-rejection
 * seed z were in the dead stack after the call, in rows the whole-value
 * search reported clean.  The Keccak kernels are where most of it was (the
 * scalar permutation spills eight of its twenty-five final lanes, the AVX2
 * four-way one sixty-nine of a hundred); the rest were copies the compiler
 * made in the calling function's own frame, beside a buffer that function
 * does wipe.
 *
 * So this harness names no secret.  It asks two things of what an entry
 * point leaves behind, and both hold for any representation:
 *
 *   CLEARED.  Below the entry point's own frame, every byte the call wrote
 *   is zero.  The stack is filled with a pattern first; afterwards each
 *   byte under the frame that made the call is the pattern (never written)
 *   or zero (cleared), apart from the SCRUB_TOP_BYTES nearest the caller:
 *   the entry point's own frame and the first words of the wipe routine's.
 *   The lowest byte that is not the pattern must lie at least as deep as
 *   the depth the row names, or the wipe is not that deep.  An
 *   implementation that reached past its wipe fails the first half of
 *   this: what it wrote there is still there.
 *
 *   INPUT-INDEPENDENT.  Those nearest bytes are the same whatever the
 *   inputs were.  Every row runs twice, on two sets of keys, messages and
 *   seeds, from the same frame; they are compared byte for byte.  A return
 *   address, a saved register, a stack canary and a pointer to the same
 *   buffer do not differ.  A word of a key does.  So does the address of an
 *   allocation the call made, because the heap is moved between the two
 *   passes: such an address is no secret, but it is not the caller's
 *   pointer either, and an entry point's own frame holds nothing else.
 *
 * WHAT HOLDS IT.  Each of these entry points is two functions
 * (src/c/internal/ama_stack_wipe.h): the implementation, never inlined, and
 * the exported function, which calls it and then clears the stack below
 * itself to a depth measured for its family.  The exported function handles
 * pointers and lengths only, so nothing of the secret is ever in its frame
 * or in a register it saves.  A wipe issued from the implementation's own
 * frame cannot do this: that frame is still live, and any callee it calls
 * afterwards pushes the registers it was holding.
 *
 * THE LIBRARY'S BUILD, NOT THIS FILE'S.  A depth is chosen where the library
 * is compiled, by whether that compilation optimises (ama_stack_wipe.h).
 * This file cannot ask its own preprocessor: a residue probe is always
 * compiled -O2, and against a CMAKE_BUILD_TYPE=None library it named 2,048
 * bytes for SHA-3 where the library cleared 8,192 (measured 2026-11-10).
 * stack_scrub_build.c is compiled with the library's flags and carries the
 * depths and the answer as data.
 *
 * THE LEAF HELPERS IN AN UNOPTIMISED BUILD.  ama_consttime_memcmp, _copy,
 * _swap and _lookup, ama_secure_memzero and ama_aes_sbox_consttime make no
 * call and are not wrapped: wrapped, every call of a helper this small would
 * pay for a stack wipe.  Optimised, they keep no frame at all, and their rows
 * hold them to that.  Unoptimised, a compiler gives every parameter and every
 * named local a slot in the function's own frame, three of the six take
 * their secret by value (the swap condition, the lookup index, the S-box
 * input), and a wrapper would home the same argument in its own frame.
 * Measured 2026-11-10, gcc 13.3 with no -O: one to three input-dependent
 * bytes after _swap, _lookup and the S-box.  These rows are therefore judged
 * in an optimised library only.  In an unoptimised one each must show the
 * frame that is the reason, so that a library wrongly described as
 * unoptimised cannot take the exemption.
 *
 * CONTROLS, each of which must fail its own check or the harness is void:
 * a frame that keeps a value and returns without clearing it (CLEARED), a
 * frame that returns with eight bytes of its input in a local, and a frame
 * that returns with the address of a block it allocated and freed (both
 * INPUT-INDEPENDENT).
 *
 * WHERE IT RUNS.  x86-64 and AArch64 with GNU C inline assembly: Linux, and
 * Windows x64 built with MinGW, which CI runs under Wine.  That build has a
 * convention of its own (a home area above every return address, a stack
 * probe that pushes a call-clobbered register), and the first run of this
 * file on it failed 29 verdicts (2026-11-10; src/c/ama_consttime.c,
 * ama_stack_wipe_cap, says what each was).  MSVC has no inline assembly on
 * x64 and cannot compile this file, so nothing here says anything about a
 * library MSVC built.  Elsewhere, and under a sanitizer that moves locals
 * off the real frame, it skips (77), as the other residue probes do.
 */
#include "ama_cryptography.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "residue_frame.h"
#include "stack_scrub_build.h"

#if defined(__x86_64__)
#define SCRUB_X86_64 1
#elif defined(__aarch64__)
#define SCRUB_AARCH64 1
#endif

#if !(defined(__GNUC__) || defined(__clang__)) || AMA_PROBE_IS_INSTRUMENTED || \
    !(defined(SCRUB_X86_64) || defined(SCRUB_AARCH64)) || (defined(_WIN32) && !defined(SCRUB_X86_64))
int main(void) {
    printf("SKIP: x86-64 or AArch64 with GNU C inline assembly, uninstrumented, only\n");
    return 77;
}
#else

/* An entry point saves the callee-saved registers it uses, so what its
 * caller holds in them lands in its frame.  That is the caller's business
 * and not the library's, but here the caller is this harness, and what it
 * happens to hold differs between the two passes (measured, gcc 14.2 -O3:
 * two bytes of every SHA-3 row's frame).  Each row therefore zeroes them
 * just before the call.  The frame pointer is left alone: this file is
 * compiled with -fno-omit-frame-pointer, so it holds a stack address, the
 * same one in both passes. */
#if defined(SCRUB_X86_64) && defined(_WIN32)
/* The Windows x64 convention keeps %rdi, %rsi and %xmm6 to %xmm15 across a
 * call as well.  Measured 2026-11-10 (MinGW gcc 13.2 -O3, under Wine 9.0)
 * before the vector registers were zeroed here: ama_aes_sbox_consttime(),
 * whose table scan the compiler vectorises, saved ten of them in a 168-byte
 * frame, and sixteen bytes of what this harness had left in them differed
 * between the passes. */
#define SCRUB_NORMALISE_REGISTERS()                                                        \
    __asm__ volatile("xor %%ebx, %%ebx\n\txor %%r12d, %%r12d\n\txor %%r13d, %%r13d\n\t" \
                     "xor %%r14d, %%r14d\n\txor %%r15d, %%r15d\n\txor %%edi, %%edi\n\t"   \
                     "xor %%esi, %%esi\n\t"                                                \
                     "pxor %%xmm6, %%xmm6\n\tpxor %%xmm7, %%xmm7\n\tpxor %%xmm8, %%xmm8\n\t" \
                     "pxor %%xmm9, %%xmm9\n\tpxor %%xmm10, %%xmm10\n\t"                     \
                     "pxor %%xmm11, %%xmm11\n\tpxor %%xmm12, %%xmm12\n\t"                   \
                     "pxor %%xmm13, %%xmm13\n\tpxor %%xmm14, %%xmm14\n\t"                   \
                     "pxor %%xmm15, %%xmm15"                                               \
                     : : : "rbx", "r12", "r13", "r14", "r15", "rdi", "rsi", "cc",          \
                           "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12",      \
                           "xmm13", "xmm14", "xmm15")
#elif defined(SCRUB_X86_64)
#define SCRUB_NORMALISE_REGISTERS()                                                        \
    __asm__ volatile("xor %%ebx, %%ebx\n\txor %%r12d, %%r12d\n\txor %%r13d, %%r13d\n\t" \
                     "xor %%r14d, %%r14d\n\txor %%r15d, %%r15d"                            \
                     : : : "rbx", "r12", "r13", "r14", "r15", "cc")
#else
#define SCRUB_NORMALISE_REGISTERS()                                                     \
    __asm__ volatile("mov x19, #0\n\tmov x20, #0\n\tmov x21, #0\n\tmov x22, #0\n\t" \
                     "mov x23, #0\n\tmov x24, #0\n\tmov x25, #0\n\tmov x26, #0\n\t" \
                     "mov x27, #0\n\tmov x28, #0"                                       \
                     : : : "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28")
#endif

/* Deeper than the deepest row (ML-DSA signing) by a wide margin. */
#define SCRUB_SPAN_BYTES (640u * 1024u)
/* Every probed call runs below a buffer this large that its row keeps live,
 * so the scanner's own frames, which start at the row's depth, end above
 * the region they read (residue_probe.h, THE GAP). */
#define SCRUB_GAP_BYTES 2048u
/* The bytes nearest the caller, which CLEARED leaves to INPUT-INDEPENDENT:
 * the entry point's own frame, and the wipe routine's return address and
 * canary.  The largest measured is 182 (the generic entry points, aarch64
 * gcc 13.3 with no -O).  A fixed bound, not the end of a run: such bytes are
 * not contiguous (ama_consttime_lookup under gcc 13.3 -fsanitize=undefined
 * kept one 103 down and nothing between it and the 30 nearest). */
#define SCRUB_TOP_BYTES 512u
/* The mark sits a few bytes under the calling frame's stack pointer, and the
 * wipe's own frame begins a few bytes under that. */
#define SCRUB_DEPTH_SLACK 96u
#define SCRUB_MAX_ROWS 192u

static uintptr_t g_lo, g_mark;
static int g_phase;                 /* 0: first inputs, 1: second inputs */
static unsigned g_row;
static unsigned g_unjudged;         /* leaf helpers, in an unoptimised library */
static int g_failures;
static ama_error_t g_rc;
static uint8_t g_top[SCRUB_MAX_ROWS][SCRUB_TOP_BYTES];
static uint8_t g_top_now[SCRUB_TOP_BYTES];

/* THE HEAP MOVES BETWEEN THE PASSES.  An allocator hands a freed block back
 * to the next request of its size, so a call that allocates and frees gets
 * the same address every time it is made, and an address it left in a dead
 * frame would compare equal across the two passes.  Before the second pass
 * this takes, and keeps, one block of every size from sixteen bytes to a
 * megabyte: the blocks the first pass freed go to these, and what the second
 * pass allocates is somewhere else.  Measured 2026-11-10 without it: with
 * hybrid signing's own stack wipe removed, and then with its implementation
 * half merged back into ama_sign()'s helper as well, every row passed on
 * five builds (x86-64, AArch64 and Windows x64, optimised and not), although
 * the helper's frame keeps the address of the wrapped message. */
#define SCRUB_HEAP_HOLDS 80u
static void *g_heap_hold[SCRUB_HEAP_HOLDS];

static int scrub_move_heap(void) {
    size_t size = 16;
    for (unsigned i = 0; i < SCRUB_HEAP_HOLDS; i++) {
        g_heap_hold[i] = malloc(size);
        if (!g_heap_hold[i]) {
            return 1;
        }
        memset(g_heap_hold[i], 0x5c, size);
        size = i < 63u ? size + 16u : size * 2u;
    }
    return 0;
}

static void scrub_release_heap(void) {
    for (unsigned i = 0; i < SCRUB_HEAP_HOLDS; i++) {
        free(g_heap_hold[i]);
        g_heap_hold[i] = NULL;
    }
}

RESIDUE_NOINLINE static void scrub_poison(void) {
    volatile uint8_t pad[SCRUB_SPAN_BYTES];
    memset((void *)pad, RESIDUE_POISON_BYTE, sizeof pad);
    g_lo = (uintptr_t)(const void *)pad;
    RESIDUE_KEEP_LIVE(pad);
}

typedef struct {
    long used;   /* the lowest byte the call wrote, below the mark */
    long kept;   /* the lowest byte that is neither zero nor the pattern */
    long stray;  /* how many such bytes lie below SCRUB_TOP_BYTES */
} scrub_scan_t;

/* Reads [g_lo, g_mark) and copies its top SCRUB_TOP_BYTES; calls nothing
 * that could write there before it has. */
RESIDUE_NOINLINE static scrub_scan_t scrub_scan(void) {
    scrub_scan_t r = { 0, 0, 0 };
    const uint8_t *top = (const uint8_t *)g_mark;
    long n = (long)(g_mark - g_lo);
    long i;

    for (i = 1; i <= (long)SCRUB_TOP_BYTES; i++) {
        g_top_now[i - 1] = top[-i];
    }
    for (i = 1; i <= n; i++) {
        uint8_t b = top[-i];
        if (b != RESIDUE_POISON_BYTE) {
            r.used = i;
        }
        if (b != 0x00 && b != RESIDUE_POISON_BYTE) {
            r.kept = i;
            r.stray += i > (long)SCRUB_TOP_BYTES;
        }
    }
    return r;
}

/* depth == 0: an entry point that makes no call and keeps no frame to
 * speak of (the constant-time helpers); it must simply write nothing. */
static void scrub_verdict(const char *name, size_t depth) {
    scrub_scan_t s = scrub_scan();
    unsigned row = g_row++;
    long differ = 0;
    int cleared, reached;

    if (row >= SCRUB_MAX_ROWS) {
        printf("FAIL %s: more rows than SCRUB_MAX_ROWS\n", name);
        g_failures++;
        return;
    }
    cleared = s.stray == 0;
    if (depth == 0 && !scrub_library_is_optimised) {
        /* THE LEAF HELPERS IN AN UNOPTIMISED BUILD, above. */
        if (s.used == 0 || s.used > (long)SCRUB_TOP_BYTES) {
            printf("FAIL %-36s the library's flags do not optimise, and this helper %s "
                   "(used %ld)\n",
                   name, s.used == 0 ? "kept no frame: one of the two is wrong"
                                     : "wrote more than a frame of its own",
                   s.used);
            g_failures++;
        } else if (g_phase == 1) {
            g_unjudged++;
            printf("n/a  %-36s unoptimised library: a leaf's locals stay in its frame "
                   "(%ld byte(s)); judged in optimised builds\n",
                   name, s.used);
        }
        return;
    }
    /* The wipe must have reached the depth the row names.  It may reach
     * further: an implementation that calls another scrubbed entry point
     * leaves that one's (deeper, cleared) wipe below its own. */
    if (depth == 0) {
        reached = s.used <= (long)SCRUB_TOP_BYTES;
    } else {
        reached = s.used + (long)SCRUB_DEPTH_SLACK >= (long)depth;
    }
    if (g_phase == 0) {
        memcpy(g_top[row], g_top_now, sizeof g_top_now);
    } else {
        for (size_t i = 0; i < sizeof g_top_now; i++) {
            differ += g_top[row][i] != g_top_now[i];
        }
    }
    if (g_rc != AMA_SUCCESS || !cleared || !reached || differ) {
        printf("FAIL %-36s rc=%d used %ld (wipe %lu), %ld byte(s) kept below the top %lu "
               "(lowest %ld down), input-dependent %ld\n",
               name, (int)g_rc, s.used, (unsigned long)depth, s.stray,
               (unsigned long)SCRUB_TOP_BYTES, s.kept, differ);
        g_failures++;
    } else if (g_phase == 1) {
        printf("ok   %-36s used %7ld of %7lu  own frame %3ld byte(s), input-independent\n", name,
               s.used, (unsigned long)depth, s.kept);
    }
}

/* --- inputs ------------------------------------------------------------- */
static uint8_t g_key[32], g_key2[32], g_msg[200], g_out[256], g_out2[256];
static uint8_t g_salt[16], g_info[8], g_nonce[16], g_tag[16], g_pt[96], g_ct[96];
static ama_sha3_ctx g_ctx;
static uint8_t g_rk[240], g_blk[16];
static uint8_t g_ed_pk[32], g_ed_sk[64], g_ed_exp[AMA_ED25519_EXPANDED_KEY_BYTES], g_sig[64];
static uint8_t g_wide[64], g_s32[32];
static ama_agent_binding_t g_binding;
static char g_b64[64];
static size_t g_len;

static void pattern(uint8_t *p, size_t n, unsigned seed) {
    unsigned x = seed * 2654435761u + (g_phase ? 0x9E3779B9u : 0x1F123BB5u);
    for (size_t i = 0; i < n; i++) {
        x = x * 1664525u + 1013904223u;
        p[i] = (uint8_t)(x >> 24);
    }
}

/* A row: PREP runs at the row's own depth and sets up what the call
 * consumes; the call itself runs below the gap, from below the mark.  The
 * first phase also runs the call once unmeasured, so that lazy binding and
 * the one-time dispatch set-up are done before anything is judged. */
#define SCRUB_ROW_BODY(name, statement)                          \
    RESIDUE_NOINLINE static void row_##name(void) {              \
        volatile uint8_t gap[SCRUB_GAP_BYTES];                   \
        gap[0] = 0;                                              \
        RESIDUE_KEEP_LIVE(gap);                                  \
        residue_stack_mark(&g_mark);                             \
        SCRUB_NORMALISE_REGISTERS();                             \
        statement;                                               \
        RESIDUE_KEEP_LIVE(gap);                                  \
    }
#define SCRUB_ROW_RUN(name, depth, prep)                         \
    static void run_##name(void) {                               \
        if (g_phase == 0) {                                      \
            prep;                                                \
            row_##name();                                        \
        }                                                        \
        prep;                                                    \
        scrub_poison();                                          \
        row_##name();                                            \
        scrub_verdict(#name, (depth));                           \
    }
#define ROW(name, depth, prep, call)                             \
    SCRUB_ROW_BODY(name, g_rc = (call))                          \
    SCRUB_ROW_RUN(name, depth, prep)
#define VROW(name, depth, prep, call)                            \
    SCRUB_ROW_BODY(name, (g_rc = AMA_SUCCESS, (void)(call)))     \
    SCRUB_ROW_RUN(name, depth, prep)
#define NOPREP ((void)0)

/* Hashes and XOFs. */
ROW(ama_sha3_256, scrub_depth_SHA3, NOPREP, ama_sha3_256(g_key, 32, g_out))
ROW(ama_sha3_384, scrub_depth_SHA3, NOPREP, ama_sha3_384(g_key, 32, g_out))
ROW(ama_sha3_512, scrub_depth_SHA3, NOPREP, ama_sha3_512(g_key, 32, g_out))
ROW(ama_shake128, scrub_depth_SHA3, NOPREP, ama_shake128(g_key, 32, g_out, 200))
ROW(ama_shake256, scrub_depth_SHA3, NOPREP, ama_shake256(g_key, 32, g_out, 200))
ROW(ama_sha3_update, scrub_depth_SHA3, (void)ama_sha3_init(&g_ctx),
    ama_sha3_update(&g_ctx, g_msg, 200))
ROW(ama_sha3_final, scrub_depth_SHA3,
    ((void)ama_sha3_init(&g_ctx), (void)ama_sha3_update(&g_ctx, g_msg, 200)),
    ama_sha3_final(&g_ctx, g_out))
ROW(ama_sha3_512_update, scrub_depth_SHA3, (void)ama_sha3_512_init(&g_ctx),
    ama_sha3_512_update(&g_ctx, g_msg, 200))
ROW(ama_sha3_512_final, scrub_depth_SHA3,
    ((void)ama_sha3_512_init(&g_ctx), (void)ama_sha3_512_update(&g_ctx, g_msg, 200)),
    ama_sha3_512_final(&g_ctx, g_out))
ROW(ama_shake256_inc_absorb, scrub_depth_SHA3, (void)ama_shake256_inc_init(&g_ctx),
    ama_shake256_inc_absorb(&g_ctx, g_msg, 200))
ROW(ama_shake256_inc_finalize, scrub_depth_SHA3,
    ((void)ama_shake256_inc_init(&g_ctx), (void)ama_shake256_inc_absorb(&g_ctx, g_msg, 200)),
    ama_shake256_inc_finalize(&g_ctx))
ROW(ama_shake256_inc_squeeze, scrub_depth_SHA3,
    ((void)ama_shake256_inc_init(&g_ctx), (void)ama_shake256_inc_absorb(&g_ctx, g_msg, 200),
     (void)ama_shake256_inc_finalize(&g_ctx)),
    ama_shake256_inc_squeeze(&g_ctx, g_out, 200))
ROW(ama_shake128_inc_absorb, scrub_depth_SHA3, (void)ama_shake128_inc_init(&g_ctx),
    ama_shake128_inc_absorb(&g_ctx, g_msg, 200))
ROW(ama_shake128_inc_finalize, scrub_depth_SHA3,
    ((void)ama_shake128_inc_init(&g_ctx), (void)ama_shake128_inc_absorb(&g_ctx, g_msg, 200)),
    ama_shake128_inc_finalize(&g_ctx))
ROW(ama_shake128_inc_squeeze, scrub_depth_SHA3,
    ((void)ama_shake128_inc_init(&g_ctx), (void)ama_shake128_inc_absorb(&g_ctx, g_msg, 200),
     (void)ama_shake128_inc_finalize(&g_ctx)),
    ama_shake128_inc_squeeze(&g_ctx, g_out, 200))
VROW(ama_sha256, scrub_depth_SHA256, NOPREP, ama_sha256(g_out, g_key, 32))
ROW(ama_sha384, scrub_depth_SHA512, NOPREP, ama_sha384(g_key, 32, g_out))
ROW(ama_sha512, scrub_depth_SHA512, NOPREP, ama_sha512(g_key, 32, g_out))
VROW(ama_ed25519_sha512, scrub_depth_SHA512, NOPREP, ama_ed25519_sha512(g_key, 32, g_out))
ROW(ama_ascon_hash256, scrub_depth_ASCON, NOPREP, ama_ascon_hash256(g_key, 32, g_out))

/* MACs and KDFs. */
VROW(ama_hmac_sha256, scrub_depth_HMAC_SHA256, NOPREP,
     ama_hmac_sha256(g_key, 32, g_msg, 64, g_out))
VROW(ama_hmac_sha256_2, scrub_depth_HMAC_SHA256, NOPREP,
     ama_hmac_sha256_2(g_key, 32, g_msg, 32, g_msg + 32, 32, g_out))
ROW(ama_hmac_sha384, scrub_depth_HMAC, NOPREP, ama_hmac_sha384(g_key, 32, g_msg, 64, g_out))
ROW(ama_hmac_sha512, scrub_depth_HMAC, NOPREP, ama_hmac_sha512(g_key, 32, g_msg, 64, g_out))
ROW(ama_hmac_sha3_256, scrub_depth_HMAC, NOPREP,
    ama_hmac_sha3_256(g_key, 32, g_msg, 64, g_out))
ROW(ama_hkdf, scrub_depth_KDF, NOPREP,
    ama_hkdf(g_salt, 16, g_key, 32, g_info, 8, g_out, 64))
ROW(ama_hkdf_sha256, scrub_depth_KDF, NOPREP,
    ama_hkdf_sha256(g_salt, 16, g_key, 32, g_info, 8, g_out, 64))
ROW(ama_hkdf_sha384, scrub_depth_KDF, NOPREP,
    ama_hkdf_sha384(g_salt, 16, g_key, 32, g_info, 8, g_out, 64))
ROW(ama_hkdf_sha512, scrub_depth_KDF, NOPREP,
    ama_hkdf_sha512(g_salt, 16, g_key, 32, g_info, 8, g_out, 64))
ROW(ama_pbkdf2_hmac_sha256, scrub_depth_KDF, NOPREP,
    ama_pbkdf2_hmac_sha256(g_key, 32, g_salt, 16, 3, g_out, 48))
ROW(ama_pbkdf2_hmac_sha512, scrub_depth_KDF, NOPREP,
    ama_pbkdf2_hmac_sha512(g_key, 32, g_salt, 16, 3, g_out, 96))
ROW(ama_agent_binding_authorize, scrub_depth_KDF,
    (void)ama_agent_binding_init(&g_binding, AMA_AGENT_LIFETIME_PERSISTENT,
                                 AMA_AGENT_CAP_DATA_SIGN | AMA_AGENT_CAP_PERSISTENCE, g_key2,
                                 g_msg),
    ama_agent_binding_authorize(&g_binding, g_key, 32))
ROW(ama_agent_binding_check, scrub_depth_KDF, NOPREP,
    ama_agent_binding_check(&g_binding, g_key, 32))
ROW(ama_agent_binding_context, scrub_depth_KDF, NOPREP,
    ama_agent_binding_context(&g_binding, g_key, 32, g_out))
ROW(ama_hkdf_agent_bound, scrub_depth_KDF, NOPREP,
    ama_hkdf_agent_bound(&g_binding, g_key, 32, g_salt, 16, g_key2, 32, g_info, 8, g_out, 64))

/* AES and the always-built AEADs. */
ROW(ama_aes256_gcm_encrypt, scrub_depth_AEAD, NOPREP,
    ama_aes256_gcm_encrypt(g_key, g_nonce, g_pt, sizeof g_pt, g_msg, 20, g_ct, g_tag))
ROW(ama_aes256_gcm_decrypt, scrub_depth_AEAD,
    (void)ama_aes256_gcm_encrypt(g_key, g_nonce, g_pt, sizeof g_pt, g_msg, 20, g_ct, g_tag),
    ama_aes256_gcm_decrypt(g_key, g_nonce, g_ct, sizeof g_ct, g_msg, 20, g_tag, g_out))
ROW(ama_ascon_aead128_encrypt, scrub_depth_AEAD, NOPREP,
    ama_ascon_aead128_encrypt(g_key, g_nonce, g_pt, sizeof g_pt, g_msg, 20, g_ct, g_tag))
ROW(ama_ascon_aead128_decrypt, scrub_depth_AEAD,
    (void)ama_ascon_aead128_encrypt(g_key, g_nonce, g_pt, sizeof g_pt, g_msg, 20, g_ct, g_tag),
    ama_ascon_aead128_decrypt(g_key, g_nonce, g_ct, sizeof g_ct, g_msg, 20, g_tag, g_out))
#if defined(AMA_STACK_SCRUB_AES_CONSTTIME)
VROW(ama_aes256_key_expansion_consttime, scrub_depth_AES, NOPREP,
     ama_aes256_key_expansion_consttime(g_key, g_rk))
VROW(ama_aes256_encrypt_block_consttime, scrub_depth_AES,
     ama_aes256_key_expansion_consttime(g_key, g_rk),
     ama_aes256_encrypt_block_consttime(g_rk, g_pt, g_blk))
#endif

/* Ed25519. */
ROW(ama_ed25519_keypair, scrub_depth_ED25519, memcpy(g_ed_sk, g_key, 32),
    ama_ed25519_keypair(g_ed_pk, g_ed_sk))
ROW(ama_ed25519_sign, scrub_depth_ED25519, NOPREP,
    ama_ed25519_sign(g_sig, g_msg, 64, g_ed_sk))
ROW(ama_ed25519_expand_secret_key, scrub_depth_ED25519, NOPREP,
    ama_ed25519_expand_secret_key(g_ed_exp, g_ed_sk))
ROW(ama_ed25519_sign_expanded, scrub_depth_ED25519, NOPREP,
    ama_ed25519_sign_expanded(g_sig, g_msg, 64, g_ed_exp))
ROW(ama_ed25519_point_from_scalar, scrub_depth_ED25519, NOPREP,
    ama_ed25519_point_from_scalar(g_out, g_s32))
VROW(ama_ed25519_sc_reduce, scrub_depth_ED25519, pattern(g_wide, sizeof g_wide, 21),
     ama_ed25519_sc_reduce(g_wide))
VROW(ama_ed25519_sc_muladd, scrub_depth_ED25519, NOPREP,
     ama_ed25519_sc_muladd(g_out, g_s32, g_key2, g_s32))

/* Base64 of key material. */
ROW(ama_base64_encode, scrub_depth_BASE64, NOPREP,
    ama_base64_encode(g_b64, sizeof g_b64, g_key, 32, AMA_BASE64_STANDARD_PADDED, &g_len))
ROW(ama_base64_decode, scrub_depth_BASE64,
    (void)ama_base64_encode(g_b64, sizeof g_b64, g_key, 32, AMA_BASE64_STANDARD_PADDED, &g_len),
    ama_base64_decode(g_out, 64, g_b64, 44, AMA_BASE64_STANDARD_PADDED, &g_len))

/* The constant-time helpers make no call and are not wrapped: they must
 * simply write nothing but their own few words. */
static volatile int g_sink;
VROW(ama_consttime_memcmp, 0, NOPREP, g_sink = ama_consttime_memcmp(g_key, g_key2, 32))
VROW(ama_consttime_copy, 0, NOPREP, ama_consttime_copy(1, g_out, g_key, 32))
VROW(ama_consttime_swap, 0, NOPREP, ama_consttime_swap(1, g_out, g_out2, 32))
VROW(ama_consttime_lookup, 0, NOPREP, ama_consttime_lookup(g_msg, 8, 16, g_key[0] & 7u, g_out))
VROW(ama_secure_memzero, 0, NOPREP, ama_secure_memzero(g_out2, 64))
#if defined(AMA_STACK_SCRUB_AES_CONSTTIME)
VROW(ama_aes_sbox_consttime, 0, NOPREP, g_sink = ama_aes_sbox_consttime(g_key[1]))
#endif

#if defined(AMA_STACK_SCRUB_PQC_GROUP)
static uint8_t g_x_pk[32], g_x_sk[32], g_x_pk2[32], g_x_sk2[32];
static uint8_t g_bs[4][32], g_bp[4][32], g_bo[4][32];
static uint8_t g_priv[32], g_dig[32], g_der[AMA_NISTP_MAX_SIG_LEN + 8];
static uint8_t g_raw[2 * AMA_NISTP_MAX_FIELD_BYTES];
static uint8_t g_ppriv[3][AMA_NISTP_MAX_FIELD_BYTES], g_ppub[3][AMA_NISTP_MAX_PUBKEY_BYTES + 1];
static uint8_t g_ppeer_priv[3][AMA_NISTP_MAX_FIELD_BYTES];
static uint8_t g_ppeer[3][AMA_NISTP_MAX_PUBKEY_BYTES + 1];
static uint8_t g_gx[32], g_gy[32];
static uint8_t g_fgroup[32], g_fshares[3 * AMA_FROST_SHARE_BYTES];
static uint8_t g_fnonce[2 * AMA_FROST_NONCE_BYTES], g_fcommit[2 * AMA_FROST_COMMITMENT_BYTES];
static uint8_t g_fidx[2] = { 1, 2 };
static uint8_t g_kpk[AMA_KYBER_1024_PUBLIC_KEY_BYTES], g_ksk[AMA_KYBER_1024_SECRET_KEY_BYTES];
static uint8_t g_kct[AMA_KYBER_1024_CIPHERTEXT_BYTES], g_kss[32];
static uint8_t g_dpk[AMA_ML_DSA_87_PUBLIC_KEY_BYTES], g_dsk[AMA_ML_DSA_87_SECRET_KEY_BYTES];
static uint8_t g_dsig[AMA_ML_DSA_87_SIGNATURE_BYTES];
static uint8_t g_dpk65[AMA_ML_DSA_65_PUBLIC_KEY_BYTES], g_dsk65[AMA_ML_DSA_65_SECRET_KEY_BYTES];
static uint8_t g_spk[AMA_SLHDSA_SHA2_256F_PUBLIC_KEY_BYTES];
static uint8_t g_ssk[AMA_SLHDSA_SHA2_256F_SECRET_KEY_BYTES];
static uint8_t g_spk2[AMA_SLHDSA_SHAKE_128S_PUBLIC_KEY_BYTES];
static uint8_t g_ssk2[AMA_SLHDSA_SHAKE_128S_SECRET_KEY_BYTES];
static uint8_t g_ssig[AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES];
static uint8_t g_hpk[AMA_HYBRID_PUBLIC_KEY_BYTES], g_hsk[AMA_HYBRID_SECRET_KEY_BYTES];
static uint8_t g_hsig[AMA_HYBRID_SIGNATURE_BYTES];
static uint8_t g_scratch_pk[AMA_ML_DSA_87_PUBLIC_KEY_BYTES], g_scratch_sk[AMA_ML_DSA_87_SECRET_KEY_BYTES];
static size_t g_siglen, g_ctlen;
static ama_context_t *g_cx_hybrid, *g_cx_kem;

ROW(ama_argon2id, scrub_depth_ARGON2, NOPREP,
    ama_argon2id(g_key, 32, g_salt, 16, 1, 64, 1, g_out, 32))
ROW(ama_argon2id_legacy, scrub_depth_ARGON2, NOPREP,
    ama_argon2id_legacy(g_key, 32, g_salt, 16, 1, 64, 1, g_out2, 32))
ROW(ama_argon2id_legacy_verify, scrub_depth_ARGON2,
    (void)ama_argon2id_legacy(g_key, 32, g_salt, 16, 1, 64, 1, g_out2, 32),
    ama_argon2id_legacy_verify(g_key, 32, g_salt, 16, 1, 64, 1, g_out2, 32))
ROW(ama_chacha20poly1305_encrypt, scrub_depth_AEAD, NOPREP,
    ama_chacha20poly1305_encrypt(g_key, g_nonce, g_pt, sizeof g_pt, g_msg, 20, g_ct, g_tag))
ROW(ama_chacha20poly1305_decrypt, scrub_depth_AEAD,
    (void)ama_chacha20poly1305_encrypt(g_key, g_nonce, g_pt, sizeof g_pt, g_msg, 20, g_ct,
                                       g_tag),
    ama_chacha20poly1305_decrypt(g_key, g_nonce, g_ct, sizeof g_ct, g_msg, 20, g_tag, g_out))

ROW(ama_x25519_keypair, scrub_depth_X25519, NOPREP, ama_x25519_keypair(g_x_pk, g_x_sk))
ROW(ama_x25519_key_exchange, scrub_depth_X25519, NOPREP,
    ama_x25519_key_exchange(g_out, g_x_sk, g_x_pk2))
ROW(ama_x25519_scalarmult_batch, scrub_depth_X25519, NOPREP,
    ama_x25519_scalarmult_batch(g_bo, (const uint8_t (*)[32])g_bs, (const uint8_t (*)[32])g_bp,
                                4))

ROW(ama_secp256k1_pubkey_from_privkey, scrub_depth_SECP256K1, NOPREP,
    ama_secp256k1_pubkey_from_privkey(g_priv, g_out))
ROW(ama_secp256k1_seckey_verify, scrub_depth_SECP256K1, NOPREP,
    ama_secp256k1_seckey_verify(g_priv))
ROW(ama_secp256k1_seckey_tweak_add, scrub_depth_SECP256K1, NOPREP,
    ama_secp256k1_seckey_tweak_add(g_out, g_priv, g_dig))
ROW(ama_secp256k1_point_mul, scrub_depth_SECP256K1, NOPREP,
    ama_secp256k1_point_mul(g_priv, g_gx, g_gy, g_out, g_out2))
ROW(ama_secp256k1_ecdsa_sign_raw, scrub_depth_SECP256K1, NOPREP,
    ama_secp256k1_ecdsa_sign_raw(g_raw, g_dig, g_priv))
ROW(ama_secp256k1_ecdsa_sign, scrub_depth_SECP256K1, g_siglen = sizeof g_der,
    ama_secp256k1_ecdsa_sign(g_der, &g_siglen, g_dig, g_priv))

#define NISTP_ROWS(tag, curve, i)                                                             \
    ROW(ama_nistp_keypair_##tag, scrub_depth_NISTP, NOPREP,                               \
        ama_nistp_keypair(curve, g_out, g_out2))                                              \
    ROW(ama_nistp_pubkey_from_privkey_##tag, scrub_depth_NISTP, NOPREP,                   \
        ama_nistp_pubkey_from_privkey(curve, g_ppriv[i], g_out))                              \
    ROW(ama_nistp_ecdh_##tag, scrub_depth_NISTP, NOPREP,                                  \
        ama_nistp_ecdh(curve, g_ppriv[i], g_ppeer[i], g_out))                                 \
    ROW(ama_nistp_ecdsa_sign_raw_##tag, scrub_depth_NISTP, NOPREP,                        \
        ama_nistp_ecdsa_sign_raw(curve, g_dig, 32, g_ppriv[i], g_raw))                        \
    ROW(ama_nistp_ecdsa_sign_raw_ex_##tag, scrub_depth_NISTP, NOPREP,                     \
        ama_nistp_ecdsa_sign_raw_ex(curve, g_dig, 32, g_ppriv[i], g_raw,                      \
                                    AMA_NISTP_ECDSA_SIGN_LOW_S | AMA_NISTP_ECDSA_SIGN_HEDGED)) \
    ROW(ama_nistp_ecdsa_sign_##tag, scrub_depth_NISTP, g_siglen = sizeof g_der,           \
        ama_nistp_ecdsa_sign(curve, g_dig, 32, g_ppriv[i], g_der, &g_siglen))                 \
    ROW(ama_nistp_ecdsa_sign_ex_##tag, scrub_depth_NISTP, g_siglen = sizeof g_der,        \
        ama_nistp_ecdsa_sign_ex(curve, g_dig, 32, g_ppriv[i], g_der, &g_siglen,               \
                                AMA_NISTP_ECDSA_SIGN_LOW_S))                                  \
    ROW(ama_nistp_ecdsa_sign_hedged_##tag, scrub_depth_NISTP, g_siglen = sizeof g_der,    \
        ama_nistp_ecdsa_sign_hedged(curve, g_dig, 32, g_ppriv[i], g_der, &g_siglen))
NISTP_ROWS(p256, AMA_NIST_CURVE_P256, 0)
NISTP_ROWS(p384, AMA_NIST_CURVE_P384, 1)
NISTP_ROWS(p521, AMA_NIST_CURVE_P521, 2)

ROW(ama_frost_keygen_trusted_dealer, scrub_depth_FROST, NOPREP,
    ama_frost_keygen_trusted_dealer(2, 3, g_fgroup, g_fshares, g_priv))
ROW(ama_frost_round1_commit, scrub_depth_FROST, NOPREP,
    ama_frost_round1_commit(g_fnonce, g_fcommit, g_fshares))
/* A nonce pair is single-use and round 2 consumes it, so each call gets a
 * fresh commitment for signer 1; signer 2's is made once per phase. */
ROW(ama_frost_round2_sign, scrub_depth_FROST,
    (void)ama_frost_round1_commit(g_fnonce, g_fcommit, g_fshares),
    ama_frost_round2_sign(g_out, g_msg, 64, g_fshares, 1, g_fnonce, g_fcommit, g_fidx, 2,
                          g_fgroup))

ROW(ama_slhdsa_keygen_sha2, scrub_depth_SLH_DSA, NOPREP,
    ama_slhdsa_keygen(AMA_SLHDSA_SHA2_256F, g_scratch_pk, g_scratch_sk))
ROW(ama_slhdsa_keygen_shake, scrub_depth_SLH_DSA, NOPREP,
    ama_slhdsa_keygen(AMA_SLHDSA_SHAKE_128S, g_scratch_pk, g_scratch_sk))
ROW(ama_slhdsa_keygen_from_seed, scrub_depth_SLH_DSA, NOPREP,
    ama_slhdsa_keygen_from_seed(AMA_SLHDSA_SHA2_256F, g_key, g_key2, g_msg, g_spk, g_ssk))
ROW(ama_slhdsa_sign_sha2, scrub_depth_SLH_DSA, g_siglen = sizeof g_ssig,
    ama_slhdsa_sign(AMA_SLHDSA_SHA2_256F, g_ssig, &g_siglen, g_msg, 64, NULL, 0, g_ssk))
ROW(ama_slhdsa_sign_shake, scrub_depth_SLH_DSA, g_siglen = sizeof g_ssig,
    ama_slhdsa_sign(AMA_SLHDSA_SHAKE_128S, g_ssig, &g_siglen, g_msg, 64, NULL, 0, g_ssk2))
ROW(ama_slhdsa_sign_addrnd, scrub_depth_SLH_DSA, g_siglen = sizeof g_ssig,
    ama_slhdsa_sign_addrnd(AMA_SLHDSA_SHA2_256F, g_ssig, &g_siglen, g_msg, 64, NULL, 0, g_key2,
                           g_ssk))
ROW(ama_slhdsa_sign_deterministic, scrub_depth_SLH_DSA, g_siglen = sizeof g_ssig,
    ama_slhdsa_sign_deterministic(AMA_SLHDSA_SHA2_256F, g_ssig, &g_siglen, g_msg, 64, NULL, 0,
                                  g_ssk))
ROW(ama_sphincs_keypair, scrub_depth_SLH_DSA, NOPREP,
    ama_sphincs_keypair(g_scratch_pk, g_scratch_sk))
ROW(ama_sphincs_sign, scrub_depth_SLH_DSA, g_siglen = sizeof g_ssig,
    ama_sphincs_sign(g_ssig, &g_siglen, g_msg, 64, g_ssk))

/* The ama_kyber_* and ama_dilithium_* names below, and
 * ama_nistp_ecdsa_sign(), _sign_raw() and _sign_hedged() above, are one call
 * of the entry point beside them and nothing else (ama_stack_wipe.h, NOT
 * WRAPPED).  They clear nothing themselves.  The depth a row of theirs names
 * is the one its callee clears, and the row holds the forwarder to what it
 * holds everything else to: nothing of the inputs in the bytes it leaves. */
ROW(ama_kyber_keypair, scrub_depth_ML_KEM, NOPREP,
    ama_kyber_keypair(g_scratch_pk, AMA_KYBER_1024_PUBLIC_KEY_BYTES, g_scratch_sk,
                      AMA_KYBER_1024_SECRET_KEY_BYTES))
ROW(ama_kyber_keypair_from_seed, scrub_depth_ML_KEM, NOPREP,
    ama_kyber_keypair_from_seed(g_key, g_key2, g_kpk, g_ksk))
ROW(ama_kyber_encapsulate, scrub_depth_ML_KEM, g_ctlen = sizeof g_kct,
    ama_kyber_encapsulate(g_kpk, sizeof g_kpk, g_kct, &g_ctlen, g_kss, 32))
ROW(ama_kyber_decapsulate, scrub_depth_ML_KEM, NOPREP,
    ama_kyber_decapsulate(g_kct, sizeof g_kct, g_ksk, sizeof g_ksk, g_out, 32))
ROW(ama_ml_kem_keypair, scrub_depth_ML_KEM, NOPREP,
    ama_ml_kem_keypair(AMA_ML_KEM_1024, g_scratch_pk, AMA_KYBER_1024_PUBLIC_KEY_BYTES,
                       g_scratch_sk, AMA_KYBER_1024_SECRET_KEY_BYTES))
ROW(ama_ml_kem_keypair_from_seed, scrub_depth_ML_KEM, NOPREP,
    ama_ml_kem_keypair_from_seed(AMA_ML_KEM_1024, g_key, g_key2, g_kpk, sizeof g_kpk, g_ksk,
                                 sizeof g_ksk))
ROW(ama_ml_kem_encapsulate, scrub_depth_ML_KEM, g_ctlen = sizeof g_kct,
    ama_ml_kem_encapsulate(AMA_ML_KEM_1024, g_kpk, sizeof g_kpk, g_kct, &g_ctlen, g_kss, 32))
ROW(ama_ml_kem_decapsulate, scrub_depth_ML_KEM, NOPREP,
    ama_ml_kem_decapsulate(AMA_ML_KEM_1024, g_kct, sizeof g_kct, g_ksk, sizeof g_ksk, g_out, 32))
ROW(ama_ml_kem_privkey_check, scrub_depth_ML_KEM, NOPREP,
    ama_ml_kem_privkey_check(AMA_ML_KEM_1024, g_ksk, sizeof g_ksk))
ROW(ama_ml_kem_pubkey_from_privkey, scrub_depth_ML_KEM, NOPREP,
    ama_ml_kem_pubkey_from_privkey(AMA_ML_KEM_1024, g_ksk, sizeof g_ksk, g_scratch_pk,
                                   AMA_KYBER_1024_PUBLIC_KEY_BYTES))

ROW(ama_dilithium_keypair, scrub_depth_ML_DSA_KEYGEN, NOPREP,
    ama_dilithium_keypair(g_scratch_pk, g_scratch_sk))
ROW(ama_dilithium_keypair_from_seed, scrub_depth_ML_DSA_KEYGEN, NOPREP,
    ama_dilithium_keypair_from_seed(g_key, g_dpk65, g_dsk65))
ROW(ama_dilithium_sign, scrub_depth_ML_DSA_SIGN, g_siglen = sizeof g_dsig,
    ama_dilithium_sign(g_dsig, &g_siglen, g_msg, 64, g_dsk65))
ROW(ama_dilithium_sign_ctx, scrub_depth_ML_DSA_SIGN, g_siglen = sizeof g_dsig,
    ama_dilithium_sign_ctx(g_dsig, &g_siglen, g_msg, 64, g_info, 8, g_dsk65))
ROW(ama_ml_dsa_keypair, scrub_depth_ML_DSA_KEYGEN, NOPREP,
    ama_ml_dsa_keypair(AMA_ML_DSA_87, g_scratch_pk, g_scratch_sk))
ROW(ama_ml_dsa_keypair_from_seed, scrub_depth_ML_DSA_KEYGEN, NOPREP,
    ama_ml_dsa_keypair_from_seed(AMA_ML_DSA_87, g_key2, g_dpk, g_dsk))
ROW(ama_ml_dsa_sign_ctx, scrub_depth_ML_DSA_SIGN, g_siglen = sizeof g_dsig,
    ama_ml_dsa_sign_ctx(AMA_ML_DSA_87, g_dsig, &g_siglen, g_msg, 64, g_info, 8, g_dsk))
ROW(ama_ml_dsa_sign_hedged, scrub_depth_ML_DSA_SIGN, g_siglen = sizeof g_dsig,
    ama_ml_dsa_sign_hedged(AMA_ML_DSA_87, g_dsig, &g_siglen, g_msg, 64, g_info, 8, g_dsk))
ROW(ama_ml_dsa_privkey_check, scrub_depth_ML_DSA_CHECK, NOPREP,
    ama_ml_dsa_privkey_check(AMA_ML_DSA_87, g_dsk))
ROW(ama_ml_dsa_pubkey_from_privkey, scrub_depth_ML_DSA_CHECK, NOPREP,
    ama_ml_dsa_pubkey_from_privkey(AMA_ML_DSA_87, g_dsk, g_scratch_pk))

/* The generic entry points forward pointers to the rows above, and three of
 * the four keep nothing of their own: the depth is that of the entry point
 * they reach last.  Hybrid signing is the fourth.  Its helper keeps the
 * address of an allocation, so it is a pair of its own inside ama_sign()
 * (src/c/ama_core.c, hybrid_sign), with its own depth. */
ROW(ama_keypair_generate_hybrid, scrub_depth_ML_DSA_KEYGEN, NOPREP,
    ama_keypair_generate(g_cx_hybrid, g_hpk, sizeof g_hpk, g_hsk, sizeof g_hsk))
ROW(ama_sign_hybrid, scrub_depth_HYBRID, g_siglen = sizeof g_hsig,
    ama_sign(g_cx_hybrid, g_msg, 64, g_hsk, sizeof g_hsk, g_hsig, &g_siglen))
ROW(ama_kem_encapsulate, scrub_depth_ML_KEM, g_ctlen = sizeof g_kct,
    ama_kem_encapsulate(g_cx_kem, g_kpk, sizeof g_kpk, g_kct, &g_ctlen, g_kss, 32))
ROW(ama_kem_decapsulate, scrub_depth_ML_KEM, NOPREP,
    ama_kem_decapsulate(g_cx_kem, g_kct, sizeof g_kct, g_ksk, sizeof g_ksk, g_out, 32))
#endif /* AMA_STACK_SCRUB_PQC_GROUP */

/* CONTROL (CLEARED): a frame that keeps a value and returns without
 * clearing it.  Two functions, so that the value lies below the run at the
 * top by construction: a callee's frame is under its caller's on every
 * target, while the order of two locals in one frame is the compiler's
 * choice (clang 18.1 with a frame pointer put the copy above the gap, inside
 * the run, and the control saw nothing). */
RESIDUE_NOINLINE static void control_keeps_copy(const uint8_t *v) {
    volatile uint8_t copy[64];
    memcpy((void *)copy, v, 32);
    RESIDUE_KEEP_LIVE(copy);
}
RESIDUE_NOINLINE static void control_leaves(const uint8_t *v) {
    volatile uint8_t gap[SCRUB_TOP_BYTES + 256u];
    gap[0] = 0;
    RESIDUE_KEEP_LIVE(gap);
    control_keeps_copy(v);
    RESIDUE_KEEP_LIVE(gap);
}
SCRUB_ROW_BODY(control_cleared, control_leaves(g_key))

/* CONTROL (INPUT-INDEPENDENT): a frame that clears nothing below it because
 * it calls nothing, and returns with eight bytes of its input in a local. */
RESIDUE_NOINLINE static void control_keeps_word(const uint8_t *v) {
    volatile uint64_t word;
    uint64_t w;
    memcpy(&w, v, sizeof w);
    word = w | 0x0101010101010101ull;
    (void)word;
}
SCRUB_ROW_BODY(control_input, control_keeps_word(g_key))

/* CONTROL (INPUT-INDEPENDENT, an allocation): a frame that returns with the
 * address of a block it allocated and freed in a local. */
RESIDUE_NOINLINE static void control_keeps_address(void) {
    volatile uintptr_t address;
    void *block = malloc(96);
    address = (uintptr_t)block;
    (void)address;
    free(block);
}
SCRUB_ROW_BODY(control_address, control_keeps_address())

#define MUST(expr)                                              \
    do {                                                        \
        if ((expr) != AMA_SUCCESS) {                            \
            printf("FAIL set-up: %s\n", #expr);                 \
            return 1;                                           \
        }                                                       \
    } while (0)

static int set_up(void) {
    pattern(g_key, sizeof g_key, 1);
    pattern(g_key2, sizeof g_key2, 2);
    pattern(g_msg, sizeof g_msg, 3);
    pattern(g_pt, sizeof g_pt, 4);
    pattern(g_salt, sizeof g_salt, 5);
    pattern(g_info, sizeof g_info, 6);
    pattern(g_nonce, sizeof g_nonce, 7);
    pattern(g_s32, sizeof g_s32, 8);
    g_s32[31] &= 0x0F; /* below the group order */
    memcpy(g_ed_sk, g_key, 32);
    MUST(ama_ed25519_keypair(g_ed_pk, g_ed_sk));
    MUST(ama_ed25519_expand_secret_key(g_ed_exp, g_ed_sk));
    MUST(ama_agent_binding_init(&g_binding, AMA_AGENT_LIFETIME_PERSISTENT,
                                AMA_AGENT_CAP_DATA_SIGN | AMA_AGENT_CAP_PERSISTENCE, g_key2,
                                g_msg));
    MUST(ama_agent_binding_authorize(&g_binding, g_key, 32));
#if defined(AMA_STACK_SCRUB_PQC_GROUP)
    {
        /* The secp256k1 base point, as affine big-endian coordinates. */
        static const uint8_t gx[32] = {
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98 };
        static const uint8_t gy[32] = {
            0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11,
            0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F,
            0xFB, 0x10, 0xD4, 0xB8 };
        static const ama_nist_curve_t curves[3] = { AMA_NIST_CURVE_P256, AMA_NIST_CURVE_P384,
                                                    AMA_NIST_CURVE_P521 };
        memcpy(g_gx, gx, 32);
        memcpy(g_gy, gy, 32);
        pattern(g_priv, sizeof g_priv, 9);
        g_priv[0] &= 0x7F; /* below both group orders */
        g_priv[0] |= 0x01;
        pattern(g_dig, sizeof g_dig, 10);
        g_dig[0] &= 0x7F;
        MUST(ama_x25519_keypair(g_x_pk, g_x_sk));
        MUST(ama_x25519_keypair(g_x_pk2, g_x_sk2));
        for (int i = 0; i < 4; i++) {
            pattern(g_bs[i], 32, 11u + (unsigned)i);
            memcpy(g_bp[i], g_x_pk2, 32);
        }
        for (int i = 0; i < 3; i++) {
            MUST(ama_nistp_keypair(curves[i], g_ppriv[i], g_ppub[i]));
            MUST(ama_nistp_keypair(curves[i], g_ppeer_priv[i], g_ppeer[i]));
        }
        MUST(ama_frost_keygen_trusted_dealer(2, 3, g_fgroup, g_fshares, g_priv));
        MUST(ama_frost_round1_commit(g_fnonce + AMA_FROST_NONCE_BYTES,
                                     g_fcommit + AMA_FROST_COMMITMENT_BYTES,
                                     g_fshares + AMA_FROST_SHARE_BYTES));
        MUST(ama_slhdsa_keygen_from_seed(AMA_SLHDSA_SHA2_256F, g_key, g_key2, g_msg, g_spk,
                                         g_ssk));
        MUST(ama_slhdsa_keygen_from_seed(AMA_SLHDSA_SHAKE_128S, g_key, g_key2, g_msg, g_spk2,
                                         g_ssk2));
        MUST(ama_kyber_keypair_from_seed(g_key, g_key2, g_kpk, g_ksk));
        g_ctlen = sizeof g_kct;
        MUST(ama_kyber_encapsulate(g_kpk, sizeof g_kpk, g_kct, &g_ctlen, g_kss, 32));
        MUST(ama_dilithium_keypair_from_seed(g_key, g_dpk65, g_dsk65));
        MUST(ama_ml_dsa_keypair_from_seed(AMA_ML_DSA_87, g_key2, g_dpk, g_dsk));
        MUST(ama_keypair_generate(g_cx_hybrid, g_hpk, sizeof g_hpk, g_hsk, sizeof g_hsk));
    }
#endif
    return 0;
}

static void all_rows(void) {
    run_ama_sha3_256(); run_ama_sha3_384(); run_ama_sha3_512();
    run_ama_shake128(); run_ama_shake256();
    run_ama_sha3_update(); run_ama_sha3_final();
    run_ama_sha3_512_update(); run_ama_sha3_512_final();
    run_ama_shake256_inc_absorb(); run_ama_shake256_inc_finalize(); run_ama_shake256_inc_squeeze();
    run_ama_shake128_inc_absorb(); run_ama_shake128_inc_finalize(); run_ama_shake128_inc_squeeze();
    run_ama_sha256(); run_ama_sha384(); run_ama_sha512(); run_ama_ed25519_sha512();
    run_ama_ascon_hash256();

    run_ama_hmac_sha256(); run_ama_hmac_sha256_2(); run_ama_hmac_sha384(); run_ama_hmac_sha512();
    run_ama_hmac_sha3_256(); run_ama_hkdf(); run_ama_hkdf_sha256(); run_ama_hkdf_sha384();
    run_ama_hkdf_sha512(); run_ama_pbkdf2_hmac_sha256(); run_ama_pbkdf2_hmac_sha512();
    run_ama_agent_binding_authorize(); run_ama_agent_binding_check();
    run_ama_agent_binding_context(); run_ama_hkdf_agent_bound();

    run_ama_aes256_gcm_encrypt(); run_ama_aes256_gcm_decrypt();
    run_ama_ascon_aead128_encrypt(); run_ama_ascon_aead128_decrypt();
#if defined(AMA_STACK_SCRUB_AES_CONSTTIME)
    run_ama_aes256_key_expansion_consttime(); run_ama_aes256_encrypt_block_consttime();
#endif

    run_ama_ed25519_keypair(); run_ama_ed25519_sign(); run_ama_ed25519_expand_secret_key();
    run_ama_ed25519_sign_expanded(); run_ama_ed25519_point_from_scalar();
    run_ama_ed25519_sc_reduce(); run_ama_ed25519_sc_muladd();
    run_ama_base64_encode(); run_ama_base64_decode();

    run_ama_consttime_memcmp(); run_ama_consttime_copy(); run_ama_consttime_swap();
    run_ama_consttime_lookup(); run_ama_secure_memzero();
#if defined(AMA_STACK_SCRUB_AES_CONSTTIME)
    run_ama_aes_sbox_consttime();
#endif

#if defined(AMA_STACK_SCRUB_PQC_GROUP)
    run_ama_argon2id(); run_ama_argon2id_legacy(); run_ama_argon2id_legacy_verify();
    run_ama_chacha20poly1305_encrypt(); run_ama_chacha20poly1305_decrypt();
    run_ama_x25519_keypair(); run_ama_x25519_key_exchange(); run_ama_x25519_scalarmult_batch();
    run_ama_secp256k1_pubkey_from_privkey(); run_ama_secp256k1_seckey_verify();
    run_ama_secp256k1_seckey_tweak_add(); run_ama_secp256k1_point_mul();
    run_ama_secp256k1_ecdsa_sign_raw(); run_ama_secp256k1_ecdsa_sign();
#define RUN_NISTP(tag)                                                                   \
    run_ama_nistp_keypair_##tag(); run_ama_nistp_pubkey_from_privkey_##tag();            \
    run_ama_nistp_ecdh_##tag(); run_ama_nistp_ecdsa_sign_raw_##tag();                    \
    run_ama_nistp_ecdsa_sign_raw_ex_##tag(); run_ama_nistp_ecdsa_sign_##tag();           \
    run_ama_nistp_ecdsa_sign_ex_##tag(); run_ama_nistp_ecdsa_sign_hedged_##tag()
    RUN_NISTP(p256); RUN_NISTP(p384); RUN_NISTP(p521);
    run_ama_frost_keygen_trusted_dealer(); run_ama_frost_round1_commit();
    run_ama_frost_round2_sign();
    run_ama_slhdsa_keygen_sha2(); run_ama_slhdsa_keygen_shake(); run_ama_slhdsa_keygen_from_seed();
    run_ama_slhdsa_sign_sha2(); run_ama_slhdsa_sign_shake(); run_ama_slhdsa_sign_addrnd();
    run_ama_slhdsa_sign_deterministic(); run_ama_sphincs_keypair(); run_ama_sphincs_sign();
    run_ama_kyber_keypair(); run_ama_kyber_keypair_from_seed(); run_ama_kyber_encapsulate();
    run_ama_kyber_decapsulate(); run_ama_ml_kem_keypair(); run_ama_ml_kem_keypair_from_seed();
    run_ama_ml_kem_encapsulate(); run_ama_ml_kem_decapsulate(); run_ama_ml_kem_privkey_check();
    run_ama_ml_kem_pubkey_from_privkey();
    run_ama_dilithium_keypair(); run_ama_dilithium_keypair_from_seed(); run_ama_dilithium_sign();
    run_ama_dilithium_sign_ctx(); run_ama_ml_dsa_keypair(); run_ama_ml_dsa_keypair_from_seed();
    run_ama_ml_dsa_sign_ctx(); run_ama_ml_dsa_sign_hedged(); run_ama_ml_dsa_privkey_check();
    run_ama_ml_dsa_pubkey_from_privkey();
    run_ama_keypair_generate_hybrid(); run_ama_sign_hybrid();
    run_ama_kem_encapsulate(); run_ama_kem_decapsulate();
#endif
}

int main(void) {
    scrub_scan_t s;
    long differ = 0;

#if defined(AMA_STACK_SCRUB_PQC_GROUP)
    g_cx_hybrid = ama_context_init(AMA_ALG_HYBRID);
    g_cx_kem = ama_context_init(AMA_ALG_KYBER_1024);
    if (!g_cx_hybrid || !g_cx_kem) {
        printf("FAIL set-up: ama_context_init\n");
        return 1;
    }
#endif

    printf("library flags: %s\n", scrub_library_is_optimised ? "optimised" : "not optimised");

    /* CONTROL (CLEARED). */
    g_phase = 0;
    if (set_up()) {
        return 1;
    }
    scrub_poison();
    row_control_cleared();
    s = scrub_scan();
    if (s.stray == 0) {
        printf("FAIL control: an uncleared frame is not seen\n");
        return 1;
    }
    printf("ok   control: an uncleared frame is seen (%ld byte(s), to %ld down)\n", s.stray,
           s.kept);

    /* CONTROL (INPUT-INDEPENDENT): the same frame on the two input sets. */
    scrub_poison();
    row_control_input();
    (void)scrub_scan();
    memcpy(g_top[0], g_top_now, sizeof g_top_now);
    g_phase = 1;
    if (set_up()) {
        return 1;
    }
    scrub_poison();
    row_control_input();
    (void)scrub_scan();
    for (size_t i = 0; i < sizeof g_top_now; i++) {
        differ += g_top[0][i] != g_top_now[i];
    }
    if (differ == 0) {
        printf("FAIL control: a word of the input left in a frame is not seen\n");
        return 1;
    }
    printf("ok   control: a word of the input left in a frame is seen (%ld byte(s) differ)\n",
           differ);

    /* CONTROL (INPUT-INDEPENDENT, an allocation): the same frame before and
     * after the heap is moved, as it is between the two passes below. */
    scrub_poison();
    row_control_address();
    (void)scrub_scan();
    memcpy(g_top[0], g_top_now, sizeof g_top_now);
    if (scrub_move_heap()) {
        printf("FAIL set-up: no memory to move the heap with\n");
        return 1;
    }
    scrub_poison();
    row_control_address();
    (void)scrub_scan();
    differ = 0;
    for (size_t i = 0; i < sizeof g_top_now; i++) {
        differ += g_top[0][i] != g_top_now[i];
    }
    scrub_release_heap();
    if (differ == 0) {
        printf("FAIL control: the address of an allocation left in a frame is not seen\n");
        return 1;
    }
    printf("ok   control: the address of an allocation left in a frame is seen "
           "(%ld byte(s) differ)\n",
           differ);

    for (g_phase = 0; g_phase < 2; g_phase++) {
        g_row = 0;
        if (g_phase == 1 && scrub_move_heap()) {
            printf("FAIL set-up: no memory to move the heap with\n");
            return 1;
        }
        if (set_up()) {
            return 1;
        }
        all_rows();
    }
    scrub_release_heap();

#if defined(AMA_STACK_SCRUB_PQC_GROUP)
    ama_context_free(g_cx_hybrid);
    ama_context_free(g_cx_kem);
#endif
    if (g_failures) {
        printf("%d verdict(s) failed\n", g_failures);
        return 1;
    }
    printf("%u entry point(s): cleared, and input-independent", g_row - g_unjudged);
    if (g_unjudged) {
        printf("; %u leaf helper(s) not judged in an unoptimised library", g_unjudged);
    }
    printf("\n");
    return 0;
}
#endif
