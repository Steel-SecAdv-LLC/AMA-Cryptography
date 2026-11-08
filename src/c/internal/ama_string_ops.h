/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_string_ops.h
 * @brief memcpy / memmove / memset for the library's own translation units
 *        on x86-64: no vector register holds the bytes, so none is left
 *        holding a secret after the call.
 *
 * WHY.  AMA_API clears every call-clobbered register a public call returns
 * through (zero_call_used_regs("all"), include/ama_cryptography.h), but a
 * baseline x86-64 translation unit only knows %xmm0-15.  glibc's EVEX string
 * routines, which it selects on every AVX-512 CPU, copy through %ymm16-31
 * precisely because those need no VZEROUPPER, and nothing in the library's
 * epilogue can reach them.  Measured 2026-11-08 (clang 18.1, x86-64 with
 * AVX-512F, glibc 2.39): ama_hkdf, ama_hkdf_sha256, ama_pbkdf2_hmac_sha512
 * and ama_argon2id returned with their whole output in %zmm16 and %zmm17,
 * left there by the memcpy that delivered it (tests/c/test_register_residue.c).
 * GCC inlines bounded memcpy/memset already (the string-op pin in
 * CMakeLists.txt) but calls glibc for memmove.
 *
 * WHAT.  Every memcpy, memmove and memset a library source writes becomes
 * one of the inline forms below, never a call into libc.
 *   - Under GCC: the compiler's own expansion, which the CMakeLists.txt
 *     strategy pin makes general-register MOV loops up to 256 bytes and
 *     REP MOVSB / REP STOSB beyond.  This also removes the fortified
 *     __memcpy_chk / __memset_chk calls GCC emitted for variable lengths.
 *   - Under Clang: a small copy of constant length stays the compiler's
 *     inline expansion, in general registers or %xmm0-15, which the epilogue
 *     clears.  Anything else is REP MOVSB / REP STOSB.
 *   - REP MOVSB and REP STOSB use no vector register.  Their latency depends
 *     only on the count, which is public at every call site, and both are on
 *     Intel's DOIT list.
 *   - memmove copies backwards (STD ... CLD) when the regions overlap with
 *     the destination above the source.
 *   - _FORTIFY_SOURCE's object-size check is kept: a length larger than
 *     __builtin_object_size reports for the destination traps, as
 *     __memcpy_chk would abort.
 *
 * SCOPE.  Force-included (-include) into the library's own sources by
 * CMakeLists.txt, on x86-64 with GCC or Clang only.  It is never part of the
 * public headers, so a consumer's string functions are not touched.  On
 * every other target it defines nothing.
 */
#ifndef AMA_STRING_OPS_H
#define AMA_STRING_OPS_H

/* __clang_analyzer__: the static analyzer (clang-tidy's clang-analyzer-*
 * checks) cannot model REP MOVSB / REP STOSB in inline assembly, so through
 * this header every copied buffer reads to it as uninitialised.  Under
 * analysis the calls stay libc's memcpy/memmove/memset, whose semantics are
 * the ones implemented here; nothing is compiled differently. */
/* Sanitizers: MemorySanitizer cannot see the stores REP MOVSB makes in inline
 * assembly, and so reports every copied buffer as uninitialised (measured: the
 * per-PR MSan lane aborted test_kat on fbefa4c).  AddressSanitizer and
 * ThreadSanitizer would silently miss the accesses.  All of them intercept
 * libc's memcpy/memmove/memset, so under any of them the calls stay libc's,
 * and the instrumented build checks every copy.  No shipped build is
 * sanitized; tests/test_no_libc_string_calls.py reads the release library. */
#if defined(__has_feature)
#if __has_feature(memory_sanitizer) || __has_feature(address_sanitizer) || \
    __has_feature(thread_sanitizer) || __has_feature(hwaddress_sanitizer)
#define AMA_STRING_OPS_SANITIZED 1
#endif
#endif
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__) || \
    defined(__SANITIZE_HWADDRESS__)
#define AMA_STRING_OPS_SANITIZED 1
#endif

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && \
    !defined(_MSC_VER) && !defined(__clang_analyzer__) && \
    !defined(AMA_STRING_OPS_SANITIZED) && !defined(AMA_STRING_OPS_DISABLE)

/* <string.h> first, so that its declarations are seen before the macros
 * below and every later #include of it is a no-op. */
#include <stddef.h>
#include <string.h>

/* Which copies are left to the compiler's own inline expansion.  GCC: all
 * of them -- CMakeLists.txt pins its strategy to unrolled MOV loops up to
 * 256 bytes and REP MOVSB / REP STOSB beyond, for every length, so a plain
 * __builtin_memcpy never becomes a call.  (Without this header the fortified
 * __builtin___memcpy_chk did: 39 __memcpy_chk and 8 __memset_chk calls into
 * glibc's EVEX routines, measured on the gcc 13.3 .so.)  Clang has no such
 * pin and lowers a variable-length builtin to a call, so only a constant
 * length up to 64 bytes stays inline there. */
#define AMA_STRING_OPS_INLINE_MAX 64u
#if defined(__clang__)
#define AMA_STRING_OPS_SMALL(n) (__builtin_constant_p(n) && (n) <= AMA_STRING_OPS_INLINE_MAX)
#else
#define AMA_STRING_OPS_SMALL(n) 1
#endif

#define AMA_STRING_OPS_FN static inline __attribute__((always_inline, unused))

/* Object-size check, as _FORTIFY_SOURCE=2 applies it to memcpy/memset. */
#define AMA_STRING_OPS_CHECK(dst, n)                                       \
    do {                                                                   \
        size_t ama_bos_ = __builtin_object_size((dst), 0);                 \
        if (ama_bos_ != (size_t)-1 && (n) > ama_bos_) {                    \
            __builtin_trap();                                              \
        }                                                                  \
    } while (0)

AMA_STRING_OPS_FN void *ama_rep_movsb(void *dst, const void *src, size_t n) {
    void *d = dst;
    __asm__ volatile("rep movsb" : "+D"(d), "+S"(src), "+c"(n) : : "memory");
    return dst;
}

AMA_STRING_OPS_FN void *ama_rep_movsb_backward(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst + n - 1;
    const unsigned char *s = (const unsigned char *)src + n - 1;
    __asm__ volatile("std\n\trep movsb\n\tcld" : "+D"(d), "+S"(s), "+c"(n) : : "memory");
    return dst;
}

AMA_STRING_OPS_FN void *ama_rep_stosb(void *dst, int c, size_t n) {
    void *d = dst;
    __asm__ volatile("rep stosb" : "+D"(d), "+c"(n) : "a"(c) : "memory");
    return dst;
}

#define memcpy(dst, src, n) ama_string_ops_memcpy((dst), (src), (n))
#define memmove(dst, src, n) ama_string_ops_memmove((dst), (src), (n))
#define memset(dst, c, n) ama_string_ops_memset((dst), (c), (n))

/* Function-like macros so that __builtin_object_size sees the caller's
 * destination expression (it does not evaluate it) and __builtin_constant_p
 * the folded length; every argument is evaluated exactly once. */
#define ama_string_ops_memcpy(dst, src, n)                                       \
    (__extension__({                                                             \
        void *ama_d_ = (dst);                                                    \
        const void *ama_s_ = (src);                                              \
        size_t ama_n_ = (size_t)(n);                                             \
        AMA_STRING_OPS_CHECK((dst), ama_n_);                                     \
        AMA_STRING_OPS_SMALL(ama_n_)                                             \
            ? __builtin_memcpy(ama_d_, ama_s_, ama_n_)                           \
            : ama_rep_movsb(ama_d_, ama_s_, ama_n_);                             \
    }))

#define ama_string_ops_memmove(dst, src, n)                                      \
    (__extension__({                                                             \
        void *ama_d_ = (dst);                                                    \
        const void *ama_s_ = (src);                                              \
        size_t ama_n_ = (size_t)(n);                                             \
        AMA_STRING_OPS_CHECK((dst), ama_n_);                                     \
        ((const unsigned char *)ama_d_ > (const unsigned char *)ama_s_ &&        \
         (const unsigned char *)ama_d_ < (const unsigned char *)ama_s_ + ama_n_) \
            ? ama_rep_movsb_backward(ama_d_, ama_s_, ama_n_)                     \
            : ama_rep_movsb(ama_d_, ama_s_, ama_n_);                             \
    }))

#define ama_string_ops_memset(dst, c, n)                                         \
    (__extension__({                                                             \
        void *ama_d_ = (dst);                                                    \
        int ama_c_ = (int)(c);                                                   \
        size_t ama_n_ = (size_t)(n);                                             \
        AMA_STRING_OPS_CHECK((dst), ama_n_);                                     \
        AMA_STRING_OPS_SMALL(ama_n_)                                             \
            ? __builtin_memset(ama_d_, ama_c_, ama_n_)                           \
            : ama_rep_stosb(ama_d_, ama_c_, ama_n_);                             \
    }))

#endif /* x86-64 GNU C */

#endif /* AMA_STRING_OPS_H */
