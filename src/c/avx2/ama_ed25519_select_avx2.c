/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_ed25519_select_avx2.c
 * @brief Constant-time row fold for the Ed25519 fixed-base comb on 256-bit
 *        registers (x86-64 with AVX2).
 *
 * The comb in src/c/internal/ama_ed25519_ge.h picks one of the sixteen
 * precomputed Niels points of a table row by a secret 5-bit digit.  Every
 * entry of the row is read and masked (`entry & m`, m all-ones only for the
 * wanted index) and the masked entries are OR-ed together, so the memory
 * trace and the instruction stream are the same for every digit.  This
 * unit does that fold three field elements (twelve or fifteen 64-bit words)
 * at a time on YMM registers; the 128-bit SSE2 fold in the template is the
 * same operation on half-width registers and runs where the CPUID gate
 * (ama_has_avx2(): AVX2 with OS-enabled AVX state) is closed.
 *
 * The output is the selected entry, or all zero for a digit of 0; the
 * caller supplies the identity for that case and applies the sign
 * afterwards, exactly as after its own fold.
 *
 * Compiled per-file with -mavx2 (CMakeLists.txt, AMA_AVX2_SOURCES) and named
 * for it, as tools/check_avx_scoping.py requires of any symbol that carries
 * YMM instructions.  Nothing here depends on the field radix: the fe51
 * instantiation passes fifteen-word entries, the fe64 one twelve-word
 * entries, both as plain uint64_t arrays.
 */

#if defined(__x86_64__) || defined(_M_X64)

#include <immintrin.h>
#include <stdint.h>

#include "../internal/ama_ed25519_backend.h"

#define LOAD256(p) _mm256_loadu_si256((const __m256i *)(p))
#define STORE256(p, v) _mm256_storeu_si256((__m256i *)(p), (v))

/* Two masks per compare: the 32-bit lanes of idx carry the 1-based index of
 * entry k (low half) and k+1 (high half); one VPCMPEQD gives both, and a
 * permute broadcasts each 128-bit half to a full-width mask. */
void ama_ed25519_select12_avx2(uint64_t *out, const uint64_t *row, uint32_t mag, int entries) {
    const __m256i vmag = _mm256_set1_epi32((int)mag);
    const __m256i two = _mm256_set1_epi32(2);
    __m256i idx = _mm256_set_epi32(2, 2, 2, 2, 1, 1, 1, 1);
    __m256i a0 = _mm256_setzero_si256(), a1 = a0, a2 = a0;
    __m256i b0 = a0, b1 = a0, b2 = a0;
    int k;

    for (k = 0; k < entries; k += 2) {
        const __m256i eq = _mm256_cmpeq_epi32(vmag, idx);
        const __m256i m0 = _mm256_permute2x128_si256(eq, eq, 0x00);
        const __m256i m1 = _mm256_permute2x128_si256(eq, eq, 0x11);
        const uint64_t *e0 = row + 12 * k;
        const uint64_t *e1 = row + 12 * (k + 1);
        idx = _mm256_add_epi32(idx, two);
        a0 = _mm256_or_si256(a0, _mm256_and_si256(m0, LOAD256(e0 + 0)));
        a1 = _mm256_or_si256(a1, _mm256_and_si256(m0, LOAD256(e0 + 4)));
        a2 = _mm256_or_si256(a2, _mm256_and_si256(m0, LOAD256(e0 + 8)));
        b0 = _mm256_or_si256(b0, _mm256_and_si256(m1, LOAD256(e1 + 0)));
        b1 = _mm256_or_si256(b1, _mm256_and_si256(m1, LOAD256(e1 + 4)));
        b2 = _mm256_or_si256(b2, _mm256_and_si256(m1, LOAD256(e1 + 8)));
    }
    STORE256(out + 0, _mm256_or_si256(a0, b0));
    STORE256(out + 4, _mm256_or_si256(a1, b1));
    STORE256(out + 8, _mm256_or_si256(a2, b2));
}

void ama_ed25519_select15_avx2(uint64_t *out, const uint64_t *row, uint32_t mag, int entries) {
    const __m256i vmag = _mm256_set1_epi32((int)mag);
    const __m256i two = _mm256_set1_epi32(2);
    __m256i idx = _mm256_set_epi32(2, 2, 2, 2, 1, 1, 1, 1);
    __m256i a0 = _mm256_setzero_si256(), a1 = a0, a2 = a0;
    __m256i b0 = a0, b1 = a0, b2 = a0;
    __m128i a3 = _mm_setzero_si128(), b3 = a3;
    uint64_t a4 = 0, b4 = 0;
    int k;

    for (k = 0; k < entries; k += 2) {
        const __m256i eq = _mm256_cmpeq_epi32(vmag, idx);
        const __m256i m0 = _mm256_permute2x128_si256(eq, eq, 0x00);
        const __m256i m1 = _mm256_permute2x128_si256(eq, eq, 0x11);
        const uint64_t *e0 = row + 15 * k;
        const uint64_t *e1 = row + 15 * (k + 1);
        idx = _mm256_add_epi32(idx, two);
        a0 = _mm256_or_si256(a0, _mm256_and_si256(m0, LOAD256(e0 + 0)));
        a1 = _mm256_or_si256(a1, _mm256_and_si256(m0, LOAD256(e0 + 4)));
        a2 = _mm256_or_si256(a2, _mm256_and_si256(m0, LOAD256(e0 + 8)));
        a3 = _mm_or_si128(a3, _mm_and_si128(_mm256_castsi256_si128(m0),
                                            _mm_loadu_si128((const __m128i *)(e0 + 12))));
        a4 |= e0[14] & (uint64_t)_mm256_extract_epi64(m0, 0);
        b0 = _mm256_or_si256(b0, _mm256_and_si256(m1, LOAD256(e1 + 0)));
        b1 = _mm256_or_si256(b1, _mm256_and_si256(m1, LOAD256(e1 + 4)));
        b2 = _mm256_or_si256(b2, _mm256_and_si256(m1, LOAD256(e1 + 8)));
        b3 = _mm_or_si128(b3, _mm_and_si128(_mm256_castsi256_si128(m1),
                                            _mm_loadu_si128((const __m128i *)(e1 + 12))));
        b4 |= e1[14] & (uint64_t)_mm256_extract_epi64(m1, 0);
    }
    STORE256(out + 0, _mm256_or_si256(a0, b0));
    STORE256(out + 4, _mm256_or_si256(a1, b1));
    STORE256(out + 8, _mm256_or_si256(a2, b2));
    _mm_storeu_si128((__m128i *)(out + 12), _mm_or_si128(a3, b3));
    out[14] = a4 | b4;
}

#else /* not x86-64: nothing to build; the template's SSE2/scalar fold is used */

/* ISO C forbids an empty translation unit. */
int ama_ed25519_select_avx2_unavailable_marker(void);
int ama_ed25519_select_avx2_unavailable_marker(void) { return 0; }

#endif
