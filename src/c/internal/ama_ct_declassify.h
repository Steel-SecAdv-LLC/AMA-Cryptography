/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_ct_declassify.h
 * @brief Explicit declassification points for the secret-taint gate.
 *
 * tools/check_ghash_constant_time.py --taint marks a secret as undefined
 * under Valgrind Memcheck and reports every conditional jump, conditional
 * move and memory address that depends on it.  Most secret-dependent
 * decisions in this tree are written as masks and never reach a branch.  A
 * few are branches by necessity, on a value that is PUBLIC BY CONTRACT:
 *
 *   - an input-validity verdict the function returns to the caller anyway
 *     (a private key outside [1, n-1]);
 *   - a "cannot happen" guard on a value the API emits (r == 0 or s == 0 in
 *     ECDSA, a fixed-base multiple landing at infinity), where the standard
 *     mandates a retry or an error and the event has probability ~2^-256;
 *   - the RFC 6979 Sec 3.2 step h.3 candidate-rejection loop, which every
 *     conforming signer shares and which exposes only that a discarded
 *     DRBG block was out of range (~2^-32 on the NIST curves, ~2^-128 on
 *     secp256k1).
 *
 * AMA_CT_DECLASSIFY(ptr, len) marks such a value as public.  In production
 * builds it expands to nothing.  In AMA_TESTING_MODE builds on a host with
 * the Valgrind client-request header it tells Memcheck the bytes are
 * defined, so the gate does not report the branch that follows.  This is
 * the construction libsecp256k1 (secp256k1_declassify) and BoringSSL
 * (CONSTTIME_DECLASSIFY) use for the same purpose.
 *
 * Every use is an assertion that the value leaks nothing beyond what the
 * function's output already reveals.  State that argument in a comment at
 * the call site.  `grep -rn AMA_CT_DECLASSIFY src/c` is the complete,
 * reviewable list; a new site is a review item, not a convenience.
 */
#ifndef AMA_CT_DECLASSIFY_H
#define AMA_CT_DECLASSIFY_H

/* No __has_include here.
 *
 * The natural spelling is `#if defined(__has_include) && __has_include(...)`,
 * but cppcheck's preprocessor does not implement __has_include in any form --
 * joined or nested -- and rejects the directive outright
 * ("failed to evaluate #if condition, division/modulo by zero"), failing the
 * static-analysis gate.  INVARIANT-13 forbids an inline suppression under
 * src/c, and rightly: the construct is the problem, not the message.
 *
 * So availability is decided by the build system, which is where it belongs.
 * CMake probes for the header with check_include_file() and defines
 * AMA_HAVE_VALGRIND_MEMCHECK on the AMA_TESTING_MODE target only.  A
 * standalone compile that defines neither macro gets the production no-op,
 * which is the correct default for anything that is not the taint lane.
 */
#if defined(AMA_TESTING_MODE) && defined(AMA_HAVE_VALGRIND_MEMCHECK)
#  include <valgrind/memcheck.h>
#  define AMA_CT_DECLASSIFY(ptr, len) ((void)VALGRIND_MAKE_MEM_DEFINED((ptr), (len)))
#endif

#ifndef AMA_CT_DECLASSIFY
#  define AMA_CT_DECLASSIFY(ptr, len) ((void)(ptr), (void)(len))
#endif

#endif /* AMA_CT_DECLASSIFY_H */
