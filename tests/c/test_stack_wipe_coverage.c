/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_stack_wipe_coverage.c
 * @brief The stack wipe overwrites every byte of the depth it is asked to
 *        clear, reaches no further, and leaves nothing of its own below it
 *        (INVARIANT-6).
 *
 * WHY A TEST OF ITS OWN.  tests/c/test_stack_scrub.c holds every entry point
 * to a cleared stack by looking at what a call leaves behind.  It cannot see
 * a byte the wipe skips if the primitive did not happen to write there, in
 * that build, on those inputs.  This file measures the wipe alone, by a
 * method that does not depend on what the stack held:
 *
 *   COVERED.  The stack is filled with one value and wiped, then filled with
 *   another and wiped again, from the same frame.  A byte that holds the
 *   first value after the first wipe and the second after the second was
 *   written by neither.  Within the depth asked for there must be none.
 *
 *   EXACT.  The lowest byte a wipe wrote lies no more than
 *   WIPE_HEADER_BYTES past the depth.  A frame larger than the request
 *   reserves, and under -fstack-clash-protection touches, stack the
 *   primitive never needed.
 *
 *   NOTHING OF ITS OWN.  Under the WIPE_HEADER_BYTES at the very top (the
 *   wipe frame's return address and stack-protector canary), every byte is
 *   zero or still the fill.  A wipe that calls a helper, or homes a parameter,
 *   leaves a return address or the parameter below the array it zeroed, and
 *   test_stack_scrub.c then reads the routine's bookkeeping as a primitive's
 *   residue.
 *
 * WHAT IT FAILED while the routine was being written (2026-11-10, each on
 * the shape named):
 *   - a chain of 8 KiB frames, one calling the next: sixteen unwritten bytes
 *     at every link, the padding beside each frame's return address and
 *     canary (COVERED);
 *   - the top of the region cleared by a struct of words instead of
 *     scalars: eight to sixteen bytes of the struct's alignment unwritten
 *     (COVERED);
 *   - the two calls made by a dispatching function instead of by the frame
 *     that is clearing its stack: the dispatcher's alignment word, eight
 *     bytes, unwritten (COVERED);
 *   - a helper that held the `memset`, in an unoptimised build, where it is
 *     a real call: 36 bytes (gcc 13.3 -O0) and 60 (clang 18.1 -O0) of its
 *     frame left below the array (NOTHING OF ITS OWN);
 *   - ama_secure_stack_wipe() on AArch64 under -fomit-frame-pointer, which
 *     the Release build sets: the link register saved alone in a
 *     sixteen-byte slot, the other eight bytes unwritten (COVERED);
 *   - the same function built for Windows x64 (MinGW gcc 13.2, under Wine
 *     9.0): the 32 bytes its caller's convention reserves above each return
 *     address, inside its own frame, unwritten (COVERED, and THE HOME AREA
 *     below).
 *
 * WHERE IT READS FROM.  The calling frame's stack pointer, taken in that
 * frame (residue_frame.h).  Until 2026-11-10 it was the address of a local
 * in a leaf the frame called, one to twenty-eight bytes lower depending on
 * the build; COVERED was not asked of the bytes in between, and both it and
 * EXACT were held to the depth less sixty-four.  On the Windows build that
 * hid the word ama_secure_stack_wipe() leaves unwritten when it does not
 * take its frame address, and on the macOS lane, where the local sat lowest,
 * the bytes directly under the stack pointer had never been read.  Both are
 * now held to the depth itself: every byte of it, from the stack pointer
 * down.
 *
 * It links the static test archive: the parts of the wipe are not exported
 * from the shared library (cmake/ama_exports.map).  The call sites are
 * AMA_STACK_WIPE_BELOW() itself, a macro, so what is measured is what every
 * scrubbed entry point expands to.  x86-64 and AArch64 with GNU C,
 * uninstrumented: CI runs it on Linux, on macOS arm64, and on the Windows
 * x64 build MinGW makes.  Elsewhere it skips (77); MSVC cannot be asked (no
 * inline assembly on x64).
 */
#include "ama_cryptography.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "residue_frame.h"
#include "../../src/c/internal/ama_stack_wipe.h"

#if !(defined(__GNUC__) || defined(__clang__)) || AMA_PROBE_IS_INSTRUMENTED || \
    !(defined(__x86_64__) || defined(__aarch64__)) || (defined(_WIN32) && !defined(__x86_64__))
int main(void) {
    printf("SKIP: x86-64 or AArch64 with GNU C, uninstrumented, only\n");
    return 77;
}
#else

/* Deeper than the deepest wipe by a wide margin. */
#define WIPE_SPAN_BYTES (640u * 1024u)
/* What a wipe frame holds besides its array: its return address, frame
 * record, canary and alignment, all above the array.  It is the most a wipe
 * may write past its depth, and the only place it may leave a byte that is
 * not zero. */
#define WIPE_HEADER_BYTES 128u
#define WIPE_FILL_A 0xA5u
#define WIPE_FILL_B 0x3Cu

#define WIPE_DEPTHS(X) \
    X(1024) X(2048) X(4096) X(8192) X(16384) X(24576) X(45056) X(49152) X(77824) X(176128) \
    X(196608)

static uintptr_t g_lo, g_mark;
static uint8_t *g_first;

RESIDUE_NOINLINE static void wipe_fill(uint8_t value) {
    volatile uint8_t pad[WIPE_SPAN_BYTES];
    memset((void *)pad, value, sizeof pad);
    g_lo = (uintptr_t)(const void *)pad;
    RESIDUE_KEEP_LIVE(pad);
}

/* The statement under test, from below a gap the harness's own frames stay
 * above (residue_probe.h, THE GAP). */
#define WIPE_SITE(name, statement)                  \
    RESIDUE_NOINLINE static void site_##name(void) { \
        volatile uint8_t gap[GAP_BYTES];            \
        gap[0] = 0;                                 \
        RESIDUE_KEEP_LIVE(gap);                     \
        RESIDUE_STACK_POINTER(g_mark);              \
        statement;                                  \
        RESIDUE_KEEP_LIVE(gap);                     \
    }
#define WIPE_DEPTH_SITE(bytes) WIPE_SITE(bytes, AMA_STACK_WIPE_BELOW(bytes))
WIPE_DEPTHS(WIPE_DEPTH_SITE)
/* The exported function is measured as its callers get it: out of line.
 * Called by name from here, a link-time-optimised build inlines it into this
 * site, and the frame it would have had, which is the thing being measured,
 * does not exist (measured 2026-11-10, gcc 13.3 -O3 -flto: the row passed
 * against a function whose alignment word nothing writes). */
static void (*volatile g_exported_wipe)(void) = ama_secure_stack_wipe;
WIPE_SITE(exported, g_exported_wipe())

#if defined(_WIN32)
/* THE HOME AREA (Windows x64).  A caller reserves 32 bytes above the return
 * address of every function it calls, and they are the callee's to use.  A
 * primitive may leave anything there, the bytes are inside the frame that
 * then clears its stack, and nothing laid below that frame reaches them: the
 * rows above cannot see them either, because they lie above the mark.  So
 * one function writes a pattern into its own home area as a callee would,
 * and another reads it back, around the statement under test.  Assembly,
 * because only a callee knows where its home area is. */
void wipe_home_poison(void);
void wipe_home_read(uint64_t out[4]);
__asm__("\t.text\n"
        "\t.globl\twipe_home_poison\n"
        "\t.def\twipe_home_poison;\t.scl\t2;\t.type\t32;\t.endef\n"
        "wipe_home_poison:\n"
        "\tmovabsq\t$0xa5a5a5a5a5a5a5a5, %rax\n"
        "\tmovq\t%rax, 8(%rsp)\n"
        "\tmovq\t%rax, 16(%rsp)\n"
        "\tmovq\t%rax, 24(%rsp)\n"
        "\tmovq\t%rax, 32(%rsp)\n"
        "\tret\n"
        "\t.globl\twipe_home_read\n"
        "\t.def\twipe_home_read;\t.scl\t2;\t.type\t32;\t.endef\n"
        "wipe_home_read:\n"
        "\tmovq\t8(%rsp), %rax\n"
        "\tmovq\t%rax, (%rcx)\n"
        "\tmovq\t16(%rsp), %rax\n"
        "\tmovq\t%rax, 8(%rcx)\n"
        "\tmovq\t24(%rsp), %rax\n"
        "\tmovq\t%rax, 16(%rcx)\n"
        "\tmovq\t32(%rsp), %rax\n"
        "\tmovq\t%rax, 24(%rcx)\n"
        "\tret\n");

/* The four words of this function's home area, after a callee has written
 * the pattern there and, if asked, the statement under test has run. */
RESIDUE_NOINLINE static void home_words(int wipe, uint64_t seen[4]) {
    wipe_home_poison();
    if (wipe) {
        AMA_STACK_WIPE_BELOW(1024);
    }
    wipe_home_read(seen);
}

/* Zero after a wipe, all four: a word that is no longer the pattern and not
 * zero either is something the wipe itself left there.  The pattern without
 * one, or the two helpers are not reading what a callee writes and the
 * first half shows nothing. */
static int home_check(void) {
    uint64_t control[4] = { 0, 0, 0, 0 }, wiped[4] = { 1, 1, 1, 1 };
    int kept = 0, poisoned = 0, ok;

    home_words(0, control);
    home_words(1, wiped);
    for (int i = 0; i < 4; i++) {
        poisoned += control[i] == 0xa5a5a5a5a5a5a5a5ull;
        kept += wiped[i] != 0;
    }
    ok = poisoned == 4 && kept == 0;
    printf("%s the home area: %d of 4 word(s) not zero after a wipe (%d of 4 written, the control)\n",
           ok ? "ok  " : "FAIL", kept, poisoned);
    return ok ? 0 : 1;
}
#endif

typedef struct {
    long used;  /* the lowest byte that is not the fill */
    long kept;  /* the lowest byte that is neither zero nor the fill */
} wipe_scan_t;

/* Reads [g_lo, g_mark) and nothing else; calls nothing. */
RESIDUE_NOINLINE static wipe_scan_t wipe_scan(uint8_t fill, uint8_t *copy) {
    wipe_scan_t r = { 0, 0 };
    const uint8_t *top = (const uint8_t *)g_mark;
    long n = (long)(g_mark - g_lo);
    long i;

    for (i = 1; i <= n; i++) {
        uint8_t b = top[-i];
        if (copy) {
            copy[i] = b;
        }
        if (b != fill) {
            r.used = i;
        }
        if (b != 0x00 && b != fill) {
            r.kept = i;
        }
    }
    return r;
}

static int wipe_check(const char *name, size_t depth, size_t header, void (*site)(void)) {
    wipe_scan_t a, b;
    const uint8_t *top;
    long unwritten = 0, first_at = 0, last_at = 0, kept;
    long held = (long)depth;
    int ok;

    wipe_fill((uint8_t)WIPE_FILL_A);
    site();
    a = wipe_scan((uint8_t)WIPE_FILL_A, g_first);
    wipe_fill((uint8_t)WIPE_FILL_B);
    site();
    b = wipe_scan((uint8_t)WIPE_FILL_B, NULL);
    top = (const uint8_t *)g_mark;
    for (long i = 1; i <= held; i++) {
        if (g_first[i] == (uint8_t)WIPE_FILL_A && top[-i] == (uint8_t)WIPE_FILL_B) {
            unwritten++;
            if (!first_at) {
                first_at = i;
            }
            last_at = i;
        }
    }
    kept = a.kept > b.kept ? a.kept : b.kept;
    ok = unwritten == 0 && kept <= (long)header && a.used >= held && b.used >= held &&
         a.used <= (long)(depth + header) && b.used <= (long)(depth + header);
    printf("%s %-28s wrote %7ld of %7lu, %ld unwritten", ok ? "ok  " : "FAIL", name, a.used,
           (unsigned long)depth, unwritten);
    if (unwritten) {
        printf(" (%ld..%ld down)", first_at, last_at);
    }
    printf(", its own to %ld down (%lu allowed)\n", kept, (unsigned long)header);
    return ok ? 0 : 1;
}

int main(void) {
    int failures = 0;

    g_first = malloc(WIPE_SPAN_BYTES + 1u);
    if (!g_first) {
        printf("FAIL: no memory for the first run's copy\n");
        return 1;
    }
#define WIPE_DEPTH_CHECK(bytes) \
    failures += wipe_check("AMA_STACK_WIPE_BELOW(" #bytes ")", bytes, WIPE_HEADER_BYTES, site_##bytes);
    WIPE_DEPTHS(WIPE_DEPTH_CHECK)
    /* The exported function's own frame lies between its caller and what it
     * clears, so it reaches that much further. */
    failures += wipe_check("ama_secure_stack_wipe()", AMA_STACK_WIPE_BYTES, 2u * WIPE_HEADER_BYTES,
                           site_exported);
#if defined(_WIN32)
    failures += home_check();
#endif
    free(g_first);
    if (failures) {
        printf("%d wipe(s) failed\n", failures);
        return 1;
    }
    printf("every wipe covers its depth, exactly, and leaves nothing of its own\n");
    return 0;
}
#endif
