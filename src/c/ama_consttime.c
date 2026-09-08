/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_consttime.c
 * @brief Constant-time cryptographic operations
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * Timing-attack resistant implementations of critical cryptographic primitives.
 * All operations execute in constant time regardless of input values.
 */

#include "../include/ama_cryptography.h"
#include "internal/ama_testing_exports.h"
#include <string.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h>
#endif

/**
 * Constant-time memory comparison
 *
 * Compares two memory regions in constant time to prevent timing attacks.
 * Uses bitwise OR to accumulate differences without branching.
 *
 * @param a First buffer
 * @param b Second buffer
 * @param len Number of bytes to compare
 * @return 0 if equal, 1 if different (constant time)
 */
int ama_consttime_memcmp(const void* a, const void* b, size_t len) {
    const volatile uint8_t* va = (const volatile uint8_t*)a;
    const volatile uint8_t* vb = (const volatile uint8_t*)b;
    uint8_t diff = 0;
    size_t i;

    /* Accumulate differences without branching */
    for (i = 0; i < len; i++) {
        diff |= va[i] ^ vb[i];
    }

    /* Convert any non-zero to 1.  Stay in unsigned arithmetic the whole
     * way: right-shifting a negative signed value is implementation-
     * defined under C11 §6.5.7p5, which the original `(diff | -diff)
     * >> 7` form triggered after the usual integer promotion of diff
     * to int.  Two's-complement negation of an unsigned value is
     * ~x + 1; the result is 0 only when diff == 0, otherwise bit 7
     * (or higher) is set, so the >> 7 mask yields {0, 1}. */
    uint32_t d = diff;
    return (int)(((d | (~d + 1u)) >> 7) & 1u);
}

/**
 * Secure memory zeroing
 *
 * Scrubs memory to zero in a way that cannot be optimized away by the compiler:
 * every store goes through a volatile pointer, and a compiler barrier follows.
 *
 * Whole 64-bit words are stored when the buffer is 8-byte aligned, which every
 * caller's field element, hash state and key buffer is, then the byte tail.
 * The previous byte-at-a-time loop was correct but cost three instructions per
 * byte, and the callers scrub a lot: one SHA-512 compression scrubs its
 * 640-byte message schedule, so the loop was 40% of every hashed block and a
 * tenth of an Ed25519 signature.  A memset-plus-barrier rendering was measured
 * too and rejected: the X25519 ladder's dozen small scrubs became library
 * calls and its exchange slowed by 2-3%, while the word loop stays inline.
 *
 * @param ptr Memory to zero
 * @param len Number of bytes to zero
 */
/**
 * @brief Zero the stack the last call left behind (INVARIANT-6, dead frames).
 *
 * `ama_secure_memzero` scrubs the buffers a function NAMES.  It cannot reach
 * the copies an optimizing compiler makes of them.  Measured on the shipped
 * build (gcc 13 -O3, LTO): the AES-GCM AES-NI and VAES kernels expand the key
 * into a local `rk[15]`, scrub that array at exit as the source says — and
 * gcc has already hoisted the loop-invariant round keys into separate stack
 * slots that the AES rounds use as memory operands (`aesenc 0x10(%rsp)` …)
 * and that nothing scrubs.  A residue probe found all fifteen round keys
 * after every encrypt and decrypt, `rk[0]` and `rk[1]` among them — and for
 * AES-256 those two ARE the raw 32-byte key.  ChaCha20-Poly1305 left its key
 * likewise (that one was also a missing scrub, fixed at source).
 *
 * The compiler's copies have no names, so the only way to reach them is by
 * address: this function extends the stack over the region a just-returned
 * callee used and zeroes it.  Called from a public entry point right after
 * the primitive returns, its frame lands exactly where the primitive's frame
 * was.
 *
 * `AMA_STACK_WIPE_BYTES` (4096) comfortably covers the deepest AEAD kernel
 * frame measured here (0x680 = 1664 bytes); the residue probe found nothing
 * below 2,167 bytes of the caller's own anchor.  `memset` plus a compiler
 * barrier is deliberate and measured: the barrier makes the write observable
 * so it cannot be elided, while `memset` keeps the fast wide-store path — the
 * volatile-word loop `ama_secure_memzero` uses cost 90-127 ns per call here
 * against 29 ns for this form, which on a 16-byte AEAD call is the difference
 * between +50% and +17%; at 1 KiB and above it is not measurable.
 *
 * This is a backstop, not a substitute for scrubbing named buffers.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline, no_sanitize_address))
#elif defined(_MSC_VER)
__declspec(noinline)
#endif
AMA_API void ama_secure_stack_wipe(void) {
    unsigned char frame[AMA_STACK_WIPE_BYTES];
    memset(frame, 0, sizeof frame);  // SCRUB-BARRIER: frame — dead stack, possibly secret; the barrier below makes the write non-elidable, and memset keeps the wide-store path (29 ns here against 90-127 ns for the volatile word loop)
    /* Make the write observable so it survives dead-store elimination, and
     * keep the array's address escaping so the frame is really allocated. */
#ifdef _MSC_VER
    _ReadWriteBarrier();
#else
    __asm__ __volatile__("" : : "r"(frame) : "memory");
#endif
}

void ama_secure_memzero(void* ptr, size_t len) {
    volatile uint8_t* vptr = (volatile uint8_t*)ptr;
    size_t i = 0;

    if (((uintptr_t)ptr & 7u) == 0) {
        /* Type-puns the aligned buffer as volatile 64-bit words to scrub eight
         * bytes per store.  Formally a strict-aliasing deviation, but benign:
         * the stores are volatile (never elided or reordered away) and the
         * object is dead after this call.  The branch is on the public pointer
         * alignment and length only. */
        volatile uint64_t* vwords = (volatile uint64_t*)ptr;
        size_t words = len / 8;
        size_t w;
        for (w = 0; w < words; w++) {
            vwords[w] = 0;
        }
        i = words * 8;
    }
    for (; i < len; i++) {
        vptr[i] = 0;
    }

    /* Additional barrier to prevent optimization */
#ifdef _MSC_VER
    _ReadWriteBarrier();
#else
    __asm__ __volatile__("" ::: "memory");
#endif
}

/**
 * Constant-time conditional swap
 *
 * Swaps two buffers if condition is non-zero, in constant time.
 * Uses XOR swap to avoid branching.
 *
 * @param condition Swap if non-zero (constant time in condition value)
 * @param a First buffer
 * @param b Second buffer
 * @param len Number of bytes to swap
 */
void ama_consttime_swap(int condition, void* a, void* b, size_t len) {
    volatile uint8_t* va = (volatile uint8_t*)a;
    volatile uint8_t* vb = (volatile uint8_t*)b;
    size_t i;
    uint8_t mask;
    uint8_t tmp;

    /* Convert condition to mask: 0x00 or 0xFF */
    mask = (uint8_t)(-(int8_t)(condition != 0));

    /* XOR-based conditional swap */
    for (i = 0; i < len; i++) {
        tmp = mask & (va[i] ^ vb[i]);
        va[i] ^= tmp;
        vb[i] ^= tmp;
    }
}

/**
 * Constant-time equality check for size_t values
 *
 * Returns 1 if a == b, 0 otherwise, in constant time.
 * Uses the standard BoringSSL/libsodium pattern for branchless equality.
 *
 * @param a First value
 * @param b Second value
 * @return 1 if equal, 0 otherwise
 */
static inline int consttime_eq_size(size_t a, size_t b) {
    size_t diff = a ^ b;
    /* diff == 0  -> (diff | -diff) == 0, high bit 0, eq = 1
     * diff != 0  -> high bit of (diff | -diff) is 1, eq = 0 */
    diff |= (size_t)0 - diff;
    diff >>= (sizeof(size_t) * 8 - 1);
    return (int)(diff ^ 1);
}

/**
 * Constant-time array lookup
 *
 * Looks up an element in an array in constant time.
 * Always scans entire array to prevent timing leaks.
 *
 * SECURITY NOTE: This function uses constant-time comparison to avoid
 * timing side-channels. The equality check uses arithmetic operations
 * that do not branch on the secret index value. Volatile pointers prevent
 * compiler optimizations that could introduce timing variations.
 *
 * @param table Array to search
 * @param table_len Number of elements
 * @param elem_size Size of each element in bytes
 * @param index Index to retrieve (may be secret)
 * @param output Output buffer for element
 */
void ama_consttime_lookup(
    const void* table,
    size_t table_len,
    size_t elem_size,
    size_t index,
    void* output
) {
    const volatile uint8_t* tbl = (const volatile uint8_t*)table;
    volatile uint8_t* out = (volatile uint8_t*)output;
    size_t i, j;

    /* Initialize output to zero using volatile pointer */
    for (j = 0; j < elem_size; j++) {
        out[j] = 0;
    }

    /* Scan entire table using constant-time comparison */
    for (i = 0; i < table_len; i++) {
        /* Use constant-time equality check */
        int match = consttime_eq_size(i, index);
        /* Convert match (0 or 1) to full mask (0x00 or 0xFF) without casts */
        size_t full_mask = (size_t)0 - (size_t)match;

        /* Conditionally OR in this element */
        for (j = 0; j < elem_size; j++) {
            size_t v = tbl[i * elem_size + j];
            out[j] |= (uint8_t)(full_mask & v);
        }
    }
}

/**
 * Constant-time conditional copy
 *
 * Copies src to dst if condition is non-zero, in constant time.
 *
 * @param condition Copy if non-zero
 * @param dst Destination buffer
 * @param src Source buffer
 * @param len Number of bytes
 */
void ama_consttime_copy(int condition, void* dst, const void* src, size_t len) {
    volatile uint8_t* vdst = (volatile uint8_t*)dst;
    const volatile uint8_t* vsrc = (const volatile uint8_t*)src;
    size_t i;
    uint8_t mask;

    /* Convert condition to mask */
    mask = (uint8_t)(-(int8_t)(condition != 0));

    /* Conditional copy */
    for (i = 0; i < len; i++) {
        vdst[i] = (vdst[i] & ~mask) | (vsrc[i] & mask);
    }
}

#ifdef AMA_TESTING_MODE
/**
 * Whether THIS translation unit — and therefore the library it is part of —
 * was compiled with optimization enabled.
 *
 * See internal/ama_testing_exports.h for why this exists and what the return
 * values mean.  It is deliberately in ama_consttime.c: the caller is the
 * constant-time instruction-count gate, and this file is the one every such
 * build must contain.
 */
int ama_build_optimization_probe(void) {
#if defined(__GNUC__) || defined(__clang__)
    /* Defined by gcc and clang at -O1 and above; absent at -O0. */
#  if defined(__OPTIMIZE__)
    return 1;
#  else
    return 0;
#  endif
#else
    return -1;
#endif
}
#endif /* AMA_TESTING_MODE */
