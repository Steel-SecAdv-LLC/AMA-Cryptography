/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_x25519_fe64_mulx.h
 * @brief Declarations for the MULX+ADX X25519 field kernels.
 *
 * WHY THIS HEADER EXISTS
 *
 * The four entry points defined in ama_x25519_fe64_mulx.c had no prototype
 * in scope at their definitions, and each consumer carried its own `extern`
 * declaration instead — one in src/c/ama_x25519.c, another in
 * tests/c/test_x25519_fe64_mulx_equiv.c.  That is three independent
 * transcriptions of the same signature with nothing tying them together, for
 * hand-written assembly kernels whose arguments are raw `uint64_t[4]`
 * buffers.  A change to one that missed the others would not be a compile
 * error; it would be a silent mismatch between what the caller pushes and
 * what the asm block reads.
 *
 * `-Wmissing-prototypes` was reporting exactly that, and the CI job named
 * "Strict Compiler Warnings (Werror)" passed anyway because it never actually
 * passed `-Werror`.  One declaration, included by the definitions and by
 * every consumer, is the fix; the compiler now checks the definition against
 * the same text the callers use.
 *
 * Hidden visibility: these are internal to libama_cryptography and are not
 * part of any public ABI.  They are built only when the MULX+ADX kernel
 * translation unit is compiled (AMA_HAVE_X25519_FE64_MULX_IMPL) on the fe64
 * field path (AMA_FE64_AVAILABLE); dispatch is additionally gated at runtime
 * on `ama_cpuid_has_x25519_mulx()`.
 */
#ifndef AMA_X25519_FE64_MULX_H
#define AMA_X25519_FE64_MULX_H

#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define AMA_X25519_MULX_HIDDEN __attribute__((visibility("hidden")))
#else
#define AMA_X25519_MULX_HIDDEN
#endif

/** h = f * g mod (2^255 - 19). Multiply and reduction fused into one asm block. */
AMA_X25519_MULX_HIDDEN
void ama_x25519_fe64_mul_mulx(uint64_t h[4], const uint64_t f[4], const uint64_t g[4]);

/** h = f^2 mod (2^255 - 19). Square and reduction fused into one asm block. */
AMA_X25519_MULX_HIDDEN
void ama_x25519_fe64_sq_mulx(uint64_t h[4], const uint64_t f[4]);

/* Two-stage compositions of the same building blocks, exported only to test
 * builds.  They keep the multiply/square and the reduction in separate asm
 * blocks where the production entry points fuse them, so they serve as a
 * second oracle: a divergence introduced while editing either block shows up
 * as fused-vs-two-stage disagreement even if both somehow agreed with a
 * mis-tabulated pure-C expectation.  See tests/c/test_x25519_fe64_mulx_equiv.c.
 *
 * Not wrapped in `#ifdef AMA_TESTING_MODE`: CMake sets that macro PRIVATE on
 * the test *library* target, so the test executables that link it do not carry
 * it.  A guarded declaration would disappear precisely where it is included
 * and the caller would fall back to an implicit declaration — silent under
 * gcc, an error under clang 16+.  An undefined symbol fails at link, loudly,
 * in the one configuration that calls it. */
void ama_x25519_fe64_mul_mulx_twostage(uint64_t h[4], const uint64_t f[4],
                                       const uint64_t g[4]);
void ama_x25519_fe64_sq_mulx_twostage(uint64_t h[4], const uint64_t f[4]);

#endif /* AMA_X25519_FE64_MULX_H */
