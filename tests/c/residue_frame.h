/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file residue_frame.h
 * @brief The frame tools every dead-stack harness shares: whether the build
 *        is one a harness can read a frame in, the gap a probed call runs
 *        below, and the stack pointer of the frame that makes the call.
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

/* THE CALLING FRAME'S STACK POINTER, read in that frame.
 *
 * test_stack_scrub.c and test_stack_wipe_coverage.c judge what a call leaves
 * below the frame that made it, so the address they read down from has to be
 * that frame's stack pointer, not something near it.  It used to be the
 * address of a local in a leaf they called (residue_probe.h,
 * residue_stack_mark), which is wherever a compiler lays that leaf's frame
 * out.  Measured 2026-11-10 in the builds of test_stack_scrub.c, in bytes
 * under the caller's stack pointer: 1 (AArch64, gcc 13.3), 4 (AArch64, clang
 * 18.1), 17 (x86-64, gcc 13.3 and clang 18.1, which push a frame pointer
 * first; 9 without one), 28 (AArch64, clang 18.1 under
 * -fstack-protector-strong).  Whatever lay between the two was not read, and
 * twice it was the thing being looked for:
 *
 *   - Windows x64, MinGW gcc 13.2.  That convention has no red zone, so the
 *     leaf had a frame where System V gives it none, and its local sat
 *     seventeen bytes under the caller's stack pointer in a file where Linux
 *     had it nine under.  The word directly below the return address of
 *     whatever was called next was never read: with the frame address no
 *     longer taken in ama_secure_stack_wipe(), which leaves exactly that
 *     word unwritten, the coverage test passed on Windows and failed on
 *     Linux and AArch64.
 *   - macOS arm64, AppleClang 21, the first run of test_stack_scrub.c there.
 *     That lane compiled the leaf under -fstack-protector-strong, which gives
 *     a function whose local has its address taken a canary and a frame
 *     record.  The control that returns with a word of its input in a local
 *     keeps it in the eight bytes directly under the caller's stack pointer;
 *     the leaf's local was below them, the control was not seen, and the run
 *     stopped there.  Had it not, every row would have been judged with the
 *     top of the entry point's own frame unread.  AppleClang's listing was
 *     not available to read.  clang 18.1 lays the leaf out the same way for
 *     that target and those flags, the local twenty-five bytes under, and on
 *     Linux AArch64 under QEMU it gives the verdict the macOS lane gave.
 *
 * Inline assembly in the frame itself has no frame of its own to be laid
 * out, on any convention or under any flag.  What it reads is that frame's
 * stack pointer as its body has it.  A call made from the frame begins
 * there: on AArch64 exactly, and on x86-64 at the return address the call
 * pushes, below any argument the frame pushed for it first. */
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#  define RESIDUE_STACK_POINTER(lvalue) __asm__ __volatile__("movq %%rsp, %0" : "=r"(lvalue))
#elif defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
#  define RESIDUE_STACK_POINTER(lvalue) __asm__ __volatile__("mov %0, sp" : "=r"(lvalue))
#endif

#endif /* !AMA_PROBE_IS_INSTRUMENTED */

#endif /* AMA_RESIDUE_FRAME_H */
