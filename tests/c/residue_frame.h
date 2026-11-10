/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file residue_frame.h
 * @brief The frame tools every dead-stack harness shares: whether the build
 *        is one a harness can read a frame in, the mark a read ends at, and
 *        the gap a probed call runs below.
 *
 * residue_probe.h includes this and adds the needle search built on it; its
 * header says why each of these is the shape it is (THE WINDOW, THE GAP,
 * SANITIZERS).  test_stack_scrub.c and test_stack_wipe_coverage.c search for
 * no needle and include this alone: the search's helpers are `static`, and a
 * file that used none of them would carry each as an unused function.
 */
#ifndef AMA_RESIDUE_FRAME_H
#define AMA_RESIDUE_FRAME_H

#include <stddef.h>
#include <stdint.h>

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

/* Compiled only where a harness runs: an instrumented build returns 77
 * before using any of it. */
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

/* The pattern the poison writes.  Distinct from every needle byte the needle
 * harnesses derive and from the sentinel. */
#define RESIDUE_POISON_BYTE 0x5Au

/* Every probed call runs below a buffer of this size its wrapper keeps live
 * (residue_probe.h, THE GAP). */
#define GAP_BYTES 512u

/* The mark the window ends at: the address of a local in a leaf BELOW the
 * scanner.  Everything the scanner's own frame holds — its saved registers
 * above all, which on AArch64 carry whatever needle the caller had live —
 * lies above this address and outside the window (residue_probe.h, defect
 * (a)).  The leaf touches no needle, so nothing it spills can be one. */
#if defined(_WIN64) && defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
/* Windows x64.  That convention has no red zone, so the leaf below would get
 * a frame: the local sat seventeen bytes under the caller's stack pointer
 * (MinGW gcc 13.2), where System V puts it nine under, and the word directly
 * below the return address of whatever is called next was above the mark and
 * never read.  Measured 2026-11-10: with the frame address no longer taken
 * in ama_secure_stack_wipe(), which leaves exactly that word unwritten, the
 * coverage test passed on Windows and failed on Linux and AArch64.  So the
 * mark is taken without a frame, at the same nine bytes: no prologue, no
 * local, the argument where the convention passes it. */
__attribute__((naked, noinline)) static void residue_stack_mark(
    __attribute__((unused)) uintptr_t *out) {
    __asm__("leaq -1(%rsp), %rax\n\tmovq %rax, (%rcx)\n\tret");
}
#else
RESIDUE_NOINLINE static void residue_stack_mark(uintptr_t *out) {
    volatile uint8_t mark = 0;
    *out = (uintptr_t)(const void *)&mark;
}
#endif

#endif /* !AMA_PROBE_IS_INSTRUMENTED */

#endif /* AMA_RESIDUE_FRAME_H */
