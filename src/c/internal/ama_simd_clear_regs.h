/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_simd_clear_regs.h
 * @brief AMA_SIMD_CLEAR_REGS: an AArch64 SIMD kernel clears every
 *        call-clobbered register on return (INVARIANT-6).
 *
 * WHY.  On AArch64 the portable sources compile with -mgeneral-regs-only
 * (CMakeLists.txt), so the public entry points' zero_call_used_regs("all")
 * (AMA_API, include/ama_cryptography.h) clears x0-x18 there and no SIMD
 * register.  A NEON or SVE2 kernel is the only code in the library that
 * writes one (src/c/internal/ama_string_ops.h keeps every copy out of libc's
 * SIMD memcpy), so a kernel that returns with a secret in v0-v31, z0-z31 or
 * p0-p15 leaves it there for the rest of the public call and after it.
 * Measured 2026-11-08 (gcc 13.3, qemu-aarch64 8.2 as Cortex-A72, Neoverse N2
 * and max): AES-256-GCM, ChaCha20-Poly1305 and Ascon decryption returned
 * with key words in q21/q28-q30 and plaintext in q4/q25
 * (tests/c/test_register_residue.c).
 *
 * WHAT.  Every kernel entry point declared in src/c/neon/ama_neon_internal.h
 * and src/c/sve2/ama_sve2_internal.h carries this attribute, and its
 * definition inherits it from that declaration.  "all", not "used": the
 * clearing must hold whatever the kernel's own callees wrote, and under LTO
 * the compiler decides which of them it inlines.  A per-file
 * -fzero-call-used-regs=used was tried first and measured ineffective in the
 * default LTO build: GCC applies that option at link time, not per
 * function.  An attribute is per function.
 *
 * SCOPE.  AArch64 with GCC or Clang.  A GNU-C compiler without the attribute
 * (GCC < 11, Clang < 15) is rejected rather than built without the clearing.
 * MSVC is not analysed (docs/constant-time-testing.md) and gets nothing.  On
 * every other target the kernels are not compiled and this defines nothing.
 */
#ifndef AMA_SIMD_CLEAR_REGS_H
#define AMA_SIMD_CLEAR_REGS_H

#if (defined(__aarch64__) || defined(_M_ARM64)) && \
    (defined(__GNUC__) || defined(__clang__)) && !defined(_MSC_VER)
#if defined(__has_attribute)
#if __has_attribute(zero_call_used_regs)
#define AMA_SIMD_CLEAR_REGS __attribute__((zero_call_used_regs("all")))
#endif
#endif
#ifndef AMA_SIMD_CLEAR_REGS
#error "ama_simd_clear_regs.h: zero_call_used_regs is required (GCC 11+, Clang 15+): without it the NEON and SVE2 kernels return with secrets in SIMD registers"
#endif
#else
#define AMA_SIMD_CLEAR_REGS
#endif

#endif /* AMA_SIMD_CLEAR_REGS_H */
