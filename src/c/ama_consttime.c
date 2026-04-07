/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

    /* Convert any non-zero to 1 */
    return (int)((diff | -diff) >> 7) & 1;
}

/**
 * Secure memory zeroing
 *
 * Scrubs memory to zero in a way that cannot be optimized away by the compiler.
 * Uses volatile pointer to prevent optimization.
 *
 * @param ptr Memory to zero
 * @param len Number of bytes to zero
 */
void ama_secure_memzero(void* ptr, size_t len) {
    volatile uint8_t* vptr = (volatile uint8_t*)ptr;
    size_t i;

    for (i = 0; i < len; i++) {
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
