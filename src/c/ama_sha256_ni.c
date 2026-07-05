/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_sha256_ni.c
 * @brief x86 SHA-NI (Intel SHA Extensions) SHA-256 compression kernel.
 *
 * Single-block SHA-256 compression using the SHA-NI instruction set
 * (_mm_sha256rnds2_epu32 / _mm_sha256msg1_epu32 / _mm_sha256msg2_epu32,
 * CPUID.(EAX=7,ECX=0):EBX[29]).  Drop-in replacement for the scalar
 * sha256_compress in ama_sha256.c, selected at runtime by ama_has_sha_ni()
 * so binaries stay portable across CPUs without the extension.
 *
 * This translation unit is compiled with -msha -mssse3 -msse4.1 per-file on
 * x86 only (see CMakeLists.txt), mirroring how the AVX2/NEON kernels receive
 * their ISA flags.  It is empty on non-x86 targets.
 *
 * Byte-identity to the FIPS 180-4 scalar compression is pinned by
 * tests/c/test_sha256_dispatch_equiv.c on every SHA-NI-capable CI host.
 *
 * Round structure follows the canonical public-domain Intel SHA Extensions
 * reference (Gulley/Walton); correctness is asserted, not assumed — the
 * equivalence KAT fails hard on any divergence from the scalar core.
 */

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)

#include <immintrin.h>
#include <stdint.h>

/* Self-prototype: this internal kernel is declared (extern) at its call site
 * in ama_sha256.c rather than in a shared header, so provide the prototype
 * here to satisfy -Wmissing-prototypes. */
void ama_sha256_compress_x86_shani(uint32_t state[8], const uint8_t block[64]);

void ama_sha256_compress_x86_shani(uint32_t state[8], const uint8_t block[64]) {
    __m128i STATE0, STATE1;
    __m128i MSG, TMP;
    __m128i MSG0, MSG1, MSG2, MSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;
    const __m128i MASK =
        _mm_set_epi64x((long long)0x0c0d0e0f08090a0bULL, (long long)0x0405060700010203ULL);

    /* Load state: state[0..3]=a,b,c,d  state[4..7]=e,f,g,h.
     * SHA-NI operates on the packed forms ABEF / CDGH. */
    TMP    = _mm_loadu_si128((const __m128i *)&state[0]);   /* DCBA */
    STATE1 = _mm_loadu_si128((const __m128i *)&state[4]);   /* HGFE */

    TMP    = _mm_shuffle_epi32(TMP, 0xB1);                  /* CDAB */
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);              /* EFGH */
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);              /* ABEF */
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);           /* CDGH */

    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    /* Rounds 0-3 */
    MSG0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(block + 0)), MASK);
    MSG  = _mm_add_epi32(MSG0, _mm_set_epi64x((long long)0xE9B5DBA5B5C0FBCFULL,
                                              (long long)0x71374491428A2F98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 4-7 */
    MSG1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(block + 16)), MASK);
    MSG  = _mm_add_epi32(MSG1, _mm_set_epi64x((long long)0xAB1C5ED5923F82A4ULL,
                                              (long long)0x59F111F13956C25BULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 8-11 */
    MSG2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(block + 32)), MASK);
    MSG  = _mm_add_epi32(MSG2, _mm_set_epi64x((long long)0x550C7DC3243185BEULL,
                                              (long long)0x12835B01D807AA98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 12-15 */
    MSG3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(block + 48)), MASK);
    MSG  = _mm_add_epi32(MSG3, _mm_set_epi64x((long long)0xC19BF1749BDC06A7ULL,
                                              (long long)0x80DEB1FE72BE5D74ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0   = _mm_add_epi32(MSG0, TMP);
    MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 16-19 */
    MSG  = _mm_add_epi32(MSG0, _mm_set_epi64x((long long)0x240CA1CC0FC19DC6ULL,
                                              (long long)0xEFBE4786E49B69C1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1   = _mm_add_epi32(MSG1, TMP);
    MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    /* Rounds 20-23 */
    MSG  = _mm_add_epi32(MSG1, _mm_set_epi64x((long long)0x76F988DA5CB0A9DCULL,
                                              (long long)0x4A7484AA2DE92C6FULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2   = _mm_add_epi32(MSG2, TMP);
    MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 24-27 */
    MSG  = _mm_add_epi32(MSG2, _mm_set_epi64x((long long)0xBF597FC7B00327C8ULL,
                                              (long long)0xA831C66D983E5152ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3   = _mm_add_epi32(MSG3, TMP);
    MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 28-31 */
    MSG  = _mm_add_epi32(MSG3, _mm_set_epi64x((long long)0x1429296706CA6351ULL,
                                              (long long)0xD5A79147C6E00BF3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0   = _mm_add_epi32(MSG0, TMP);
    MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 32-35 */
    MSG  = _mm_add_epi32(MSG0, _mm_set_epi64x((long long)0x53380D134D2C6DFCULL,
                                              (long long)0x2E1B213827B70A85ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1   = _mm_add_epi32(MSG1, TMP);
    MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    /* Rounds 36-39 */
    MSG  = _mm_add_epi32(MSG1, _mm_set_epi64x((long long)0x92722C8581C2C92EULL,
                                              (long long)0x766A0ABB650A7354ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2   = _mm_add_epi32(MSG2, TMP);
    MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 40-43 */
    MSG  = _mm_add_epi32(MSG2, _mm_set_epi64x((long long)0xC76C51A3C24B8B70ULL,
                                              (long long)0xA81A664BA2BFE8A1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3   = _mm_add_epi32(MSG3, TMP);
    MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 44-47 */
    MSG  = _mm_add_epi32(MSG3, _mm_set_epi64x((long long)0x106AA070F40E3585ULL,
                                              (long long)0xD6990624D192E819ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0   = _mm_add_epi32(MSG0, TMP);
    MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 48-51 */
    MSG  = _mm_add_epi32(MSG0, _mm_set_epi64x((long long)0x34B0BCB52748774CULL,
                                              (long long)0x1E376C0819A4C116ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1   = _mm_add_epi32(MSG1, TMP);
    MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    /* Rounds 52-55 */
    MSG  = _mm_add_epi32(MSG1, _mm_set_epi64x((long long)0x682E6FF35B9CCA4FULL,
                                              (long long)0x4ED8AA4A391C0CB3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2   = _mm_add_epi32(MSG2, TMP);
    MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 56-59 */
    MSG  = _mm_add_epi32(MSG2, _mm_set_epi64x((long long)0x8CC7020884C87814ULL,
                                              (long long)0x78A5636F748F82EEULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3   = _mm_add_epi32(MSG3, TMP);
    MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 60-63 */
    MSG  = _mm_add_epi32(MSG3, _mm_set_epi64x((long long)0xC67178F2BEF9A3F7ULL,
                                              (long long)0xA4506CEB90BEFFFAULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Accumulate into the saved state */
    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    /* Unpack ABEF / CDGH back to a,b,c,d,e,f,g,h */
    TMP    = _mm_shuffle_epi32(STATE0, 0x1B);      /* FEBA */
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);      /* DCHG */
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);   /* DCBA */
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);      /* HGFE */

    _mm_storeu_si128((__m128i *)&state[0], STATE0);
    _mm_storeu_si128((__m128i *)&state[4], STATE1);
}

#endif /* x86 */
