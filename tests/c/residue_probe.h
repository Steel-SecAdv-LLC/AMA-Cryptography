/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file residue_probe.h
 * @brief The dead-stack residue probe shared by test_aead_stack_residue.c and
 *        test_ed25519_stack_residue.c (INVARIANT-6).
 *
 * `ama_secure_memzero` scrubs the buffers a function names.  It cannot reach
 * the copies an optimizing compiler spills of them, and the probe here is how
 * the repository measures whether a public entry point that has returned
 * still owns any of its secret: fill a stack region with a pattern, call the
 * entry point at the same depth, then read that region back and count
 * occurrences of the secret.
 *
 * The two harnesses that include this header differ only in their needles
 * (an AEAD key and its halves; an Ed25519 scalar, prefix and nonce in byte
 * and limb form).  The probe machinery below was duplicated between them
 * until 2026-09-25, and the duplication is how the Ed25519 copy drifted from
 * the AEAD copy on the GAP construction and how a defect in the shared
 * construction was fixed in neither.  One copy, included by both.
 *
 * WHAT A VERDICT MEANS.  Three facts are established before any verdict is
 * trusted, each by a check that can fail:
 *
 *   1. CONTROL: `residue_probe_control()` plants a SENTINEL in a frame at the
 *      probed depth and the harness FAILS if `residue_count()` cannot see it.
 *      A window that misses the frame passes every verdict for the wrong
 *      reason (ThreadSanitizer relocates locals and did exactly that).
 *   2. BASELINE: after a fresh poison the window holds no copy of the needle
 *      before the probed call.  A hit here means the harness contaminated the
 *      window and every verdict would be measuring itself.
 *   3. COVERAGE: `residue_window_covers_poison()` — the bytes the last scan
 *      read are the bytes the last poison wrote, less a bounded slack.  A
 *      frame layout that leaves the window reading unpoisoned memory, or a
 *      poison that stops short of the window, is reported as a harness
 *      defect rather than as residue.  This is the check that was missing.
 *
 * THE WINDOW, AND THE TWO DEFECTS IT USED TO HAVE (both measured 2026-09-25,
 * aarch64-linux-gnu gcc 13.3.0, RelWithDebInfo, the arm-qemu lanes, and
 * corrected per AGENTS.md section 6.6).  The scanner used to take the address
 * of a local in its own frame and read the SCAN_BYTES below it.
 *
 *   (a) The scanner's own frame was INSIDE the window.  AArch64 GCC lays a
 *       frame out with the callee-saved registers at its bottom
 *       (`stp x29, x30, [sp, #-80]!`, then x19..x24 at sp+16..), and the
 *       only local — the anchor — at its top (sp+79).  The caller loading a
 *       needle into a callee-saved register (`ldr x22, [x20]`: the limb it
 *       is about to compare, kept live across the call because it is read
 *       again afterwards) therefore put that needle at sp+40 of the
 *       scanner's frame, forty bytes below the anchor, and the scan found
 *       it: every one of the twelve scalar limbs, exactly once each,
 *       BASELINE included, on every AArch64 lane.  x86-64 GCC and clang
 *       place saved registers above the locals, so the same window excluded
 *       them there and the harness passed by layout rather than by
 *       construction.  `residue_stack_mark()` now takes the mark in a leaf
 *       BELOW the scanner: every byte of the scanner's frame, its saved
 *       registers included, is above the mark and outside the window.
 *
 *   (b) The window reached BELOW the poison.  The poison frame and the
 *       scanner are called from the same depth, but the scanner sits under
 *       its caller's frame (96 bytes here) and takes its mark from its own,
 *       so the lowest bytes of a window measured from the mark lay under the
 *       lowest byte the poison wrote, and whatever an earlier, deeper call
 *       had left there was reported as residue of the probed call (the
 *       heap-path nonce, 33 bytes under the poison's floor, in one build).
 *       The window is now the intersection of the SCAN_BYTES below the mark
 *       with the span the last `poison_stack()` recorded, so by construction
 *       every byte it reads was poisoned first.
 *
 * ONE SCAN PER POISON.  The Ed25519 harness evaluates its count exactly once
 * per poison because a scanner may spill the needle it is comparing into its
 * own frame (aarch64 gcc 13.3.0 -O2 -fsanitize=undefined did, at anchor-95
 * and anchor-143), and a second scan at the same depth then reported the
 * first scan's spill.  With the scanner's frame outside the window that
 * spill is no longer read; the discipline is kept because it costs nothing
 * and because a needle spilled by `residue_stack_mark()` itself — a leaf that
 * touches no needle — would be the next place to look.
 *
 * THE GAP.  Every probed call runs below a GAP_BYTES buffer its wrapper keeps
 * live, so the primitive's frame lies wholly below the region the scanner's
 * frames occupy when they are called at the same depth.  Without the gap
 * the top of the primitive's frame is clobbered by the probe before it is
 * read, and whether a spill survives to be counted depends on frame layout:
 * measured, the unfixed Ascon-AEAD128 left a key word 87 bytes below the
 * anchor under gcc -O2 and in the clobbered bytes under -O3, where the probe
 * passed against it.  The Ed25519 harness had no gap until this header.
 *
 * THE BARRIER in `poison_stack()` is load-bearing, not decoration.  `pad` is
 * local, never escapes and is dead at return, so the `memset` is a dead
 * store and clang deletes the whole 32 KiB of it: measured on the shipped
 * flags, clang 18.1.3 emitted the entire function as
 *
 *     movb   $0x5a,-0x8(%rsp)      ; ONE byte
 *     movzbl -0x8(%rsp),%eax       ; satisfying the volatile read
 *     ret
 *
 * — the 32 KiB frame was never even allocated — while gcc 13.3.0 emitted the
 * real stack probe and memset.  With no poison, whatever was on the stack
 * from an earlier call survives into the next scan, and "a hit is residue
 * rather than a leftover" is simply false.  The `"r"(pad)` operand makes the
 * address escape and the `"memory"` clobber makes the stores observable, so
 * the memset must happen — the same construction `ama_secure_stack_wipe()`
 * uses for the same reason.
 *
 * THE SENTINEL is never the needle.  The control used to plant the key
 * itself, which contaminated the window with the very needle every later
 * check searches for, and turned the control into a false positive for the
 * verdicts under any frame layout that did not clear it (gcc's layout
 * happened to; clang's did not, so the lane split by compiler rather than by
 * library behaviour).  A control only has to establish that the window
 * covers a frame at this depth; any 32-byte value does that, and one that is
 * not the secret cannot be mistaken for it.
 *
 * ADDRESS ARITHMETIC is done on `uintptr_t`, never on the pointer to a
 * one-byte object.  Reading below that object is what the probe means, but
 * it is also, formally, out of that object's bounds, and gcc says so
 * ("array subscript -32768 is outside array bounds of volatile uint8_t[1]",
 * -Warray-bounds).  The warning is correct about the C, and reading dead
 * stack IS the measurement, so the address is computed as an integer —
 * exactly the operation intended — instead of the diagnostic being
 * suppressed.
 *
 * SANITIZERS.  The premise of the whole probe is that a function's locals
 * live in ITS stack frame, at a predictable depth below the caller's.  Every
 * sanitizer named in AMA_PROBE_IS_INSTRUMENTED breaks that premise or the
 * read that tests it, each in its own way, and each was added with the
 * observation that established it:
 *
 *   - AddressSanitizer reports "stack-buffer-underflow ... 'anchor' ...
 *     underflows this variable" — the probe reads past a one-byte object
 *     into its redzone, which is precisely what a redzone is for.
 *   - MemorySanitizer reports use-of-uninitialised-value — dead stack the
 *     probed frame never wrote is exactly that.  Measured: the MSan lane
 *     reported `test_aead_stack_residue (Subprocess aborted)` while only
 *     ASan was named, so MSan fell through and ran the probe.
 *   - ThreadSanitizer neither faults nor aborts.  It relocates locals off
 *     the real frame, so the probe simply stops seeing them, and the run is
 *     vacuous rather than loud.  The CONTROL is what caught it:
 *
 *         FAIL: probe control: a value left on the stack IS detected
 *           control (sentinel deliberately left): 0 hit(s)
 *
 *     Every verdict "passed" in that same run — on a window that could not
 *     see a value deliberately planted in it.  Reporting those as evidence
 *     of no residue is the vacuous pass this probe is built to refuse, so
 *     the lane declines instead (exit 77, CTest: Skipped).
 *
 * Enumerating sanitizers is a shape that fails again on the next one added,
 * and this probe has been caught by that twice.  What stands behind the list
 * is the control: an unanticipated sanitizer that breaks the premise fails
 * the control loudly rather than passing quietly, and the fix is to add it
 * here with its observation, never to relax the control.  UBSan is NOT on
 * the list: it instruments arithmetic, not memory, the probe runs under it
 * unchanged, and the arm-qemu UBSan lane is one of the lanes that measure
 * it.
 */
#ifndef AMA_RESIDUE_PROBE_H
#define AMA_RESIDUE_PROBE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

/* Everything below is the probe itself, compiled only where it runs: an
 * instrumented build returns 77 before calling any of it, and would
 * otherwise carry every helper as an unused function. */
#if !AMA_PROBE_IS_INSTRUMENTED

#if defined(__GNUC__) || defined(__clang__)
#  define RESIDUE_NOINLINE __attribute__((noinline))
#  define RESIDUE_KEEP_LIVE(buf) __asm__ __volatile__("" : : "r"(buf) : "memory")
#elif defined(_MSC_VER)
#  define RESIDUE_NOINLINE __declspec(noinline)
#  define RESIDUE_KEEP_LIVE(buf) ((void)(buf)[0])
#else
#  define RESIDUE_NOINLINE
#  define RESIDUE_KEEP_LIVE(buf) ((void)(buf)[0])
#endif

/* The depth the probe covers below the probed call's entry frame. */
#define SCAN_BYTES 32768u

/* The pattern the poison writes.  Distinct from every needle byte the two
 * harnesses derive and from the sentinel. */
#define RESIDUE_POISON_BYTE 0x5Au

/* The most the window may fall short of SCAN_BYTES before the harness calls
 * itself defective: the caller's frame, the scanner's frame and the mark
 * leaf together take a few hundred bytes off the top of the poison span,
 * never anything like 4 KiB.  A shortfall past this means a layout the
 * probe was not written for. */
#define RESIDUE_WINDOW_SLACK_BYTES 4096u

/* Every probed call runs below a buffer of this size its wrapper keeps live
 * (see THE GAP above). */
#define GAP_BYTES 512u

/* The span the last poison_stack() wrote, and the span the last scan read;
 * integers, because both name dead frames. */
static uintptr_t residue_poison_lo, residue_poison_hi;
static uintptr_t residue_window_lo, residue_window_hi;

/* Fill the SCAN_BYTES below the caller's frame with the pattern, so that a
 * later hit at this depth is residue of a later call rather than a leftover
 * from process start or from an earlier probe. */
RESIDUE_NOINLINE static void poison_stack(void) {
    volatile uint8_t pad[SCAN_BYTES];
    memset((void *)pad, RESIDUE_POISON_BYTE, sizeof pad);
    residue_poison_lo = (uintptr_t)(const void *)pad;
    residue_poison_hi = residue_poison_lo + (uintptr_t)SCAN_BYTES;
    RESIDUE_KEEP_LIVE(pad);
}

/* The mark the window ends at: the address of a local in a leaf BELOW the
 * scanner.  Everything the scanner's own frame holds — its saved registers
 * above all, which on AArch64 carry whatever needle the caller had live —
 * lies above this address and outside the window (defect (a) above).  The
 * leaf touches no needle, so nothing it spills can be one. */
RESIDUE_NOINLINE static void residue_stack_mark(uintptr_t *out) {
    volatile uint8_t mark = 0;
    *out = (uintptr_t)(const void *)&mark;
}

/* Occurrences of `needle` in the poisoned bytes below the scanner.
 *
 * The window is [max(poison_lo, mark - SCAN_BYTES), min(poison_hi, mark)):
 * the SCAN_BYTES under the mark, clipped to the span the last poison wrote,
 * so every byte read was poisoned first (defect (b) above).  Recorded in
 * residue_window_lo/hi for residue_window_covers_poison(). */
RESIDUE_NOINLINE static int residue_count(const uint8_t *needle, size_t len) {
    uintptr_t mark = 0;
    uintptr_t lo, hi;
    const uint8_t *base;
    size_t n, i;
    int hits = 0;

    residue_stack_mark(&mark);
    lo = mark - (uintptr_t)SCAN_BYTES;
    if (lo < residue_poison_lo) {
        lo = residue_poison_lo;
    }
    hi = mark;
    if (hi > residue_poison_hi) {
        hi = residue_poison_hi;
    }
    residue_window_lo = lo;
    residue_window_hi = hi;
    if (hi <= lo) {
        return 0;
    }
    base = (const uint8_t *)lo;
    n = (size_t)(hi - lo);
    for (i = 0; i + len <= n; i++) {
        if (memcmp(base + i, needle, len) == 0) {
            hits++;
        }
    }
    return hits;
}

/* Whether the last scan read the last poison, less at most the slack: the
 * COVERAGE fact above.  False means the window and the poison have come
 * apart — the harness, not the library, is what failed. */
static int residue_window_covers_poison(void) {
    if (residue_window_hi <= residue_window_lo) {
        return 0;
    }
    if (residue_window_lo < residue_poison_lo || residue_window_hi > residue_poison_hi) {
        return 0;
    }
    return (residue_window_hi - residue_window_lo)
           + (uintptr_t)RESIDUE_WINDOW_SLACK_BYTES >= (uintptr_t)SCAN_BYTES;
}

/* Positive control: leaves `sentinel` in a frame at the probed depth, below
 * a GAP so it lands where a probed call's frame would, and returns without a
 * scrub — the exact shape the AEAD kernels used to exhibit.  See THE
 * SENTINEL above for why the caller must not pass the needle. */
RESIDUE_NOINLINE static void residue_probe_control(const uint8_t *sentinel, size_t len) {
    volatile uint8_t gap[GAP_BYTES];
    volatile uint8_t copy[512];
    gap[0] = 0;
    RESIDUE_KEEP_LIVE(gap);
    memset((void *)copy, 0, sizeof copy);
    memcpy((void *)(copy + 128), sentinel, len);
    RESIDUE_KEEP_LIVE(copy);
}

/* Run `call` below a GAP_BYTES buffer kept live across it.  `rc` is the
 * enclosing function's result variable. */
#define RUN_BELOW_GAP(call) do {                                 \
    volatile uint8_t gap[GAP_BYTES];                             \
    gap[0] = 0;                                                  \
    RESIDUE_KEEP_LIVE(gap);                                      \
    rc = (call);                                                 \
    RESIDUE_KEEP_LIVE(gap);                                      \
} while (0)

#endif /* !AMA_PROBE_IS_INSTRUMENTED */

#endif /* AMA_RESIDUE_PROBE_H */
