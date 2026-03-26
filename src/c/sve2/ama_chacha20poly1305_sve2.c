/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_chacha20poly1305_sve2.c
 * @brief ARM SVE2-optimized ChaCha20-Poly1305
 *
 * SVE2 scalable-vector intrinsics for ChaCha20 quarter-rounds.
 * The scalable vector length allows processing more parallel states
 * on wider hardware implementations.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__ARM_FEATURE_SVE2)
#include <arm_sve.h>

#define CHACHA_C0 0x61707865
#define CHACHA_C1 0x3320646e
#define CHACHA_C2 0x79622d32
#define CHACHA_C3 0x6b206574

/* ============================================================================
 * SVE2 ChaCha20 quarter-round on scalable-width vectors
 * ============================================================================ */
static inline void chacha_qr_sve2(svbool_t pg,
                                   svuint32_t *a, svuint32_t *b,
                                   svuint32_t *c, svuint32_t *d) {
    *a = svadd_u32_x(pg, *a, *b);
    *d = sveor_u32_x(pg, *d, *a);
    /* Rotate left by 16 = (x << 16) | (x >> 16) */
    *d = svorr_u32_x(pg, svlsl_n_u32_x(pg, *d, 16), svlsr_n_u32_x(pg, *d, 16));

    *c = svadd_u32_x(pg, *c, *d);
    *b = sveor_u32_x(pg, *b, *c);
    *b = svorr_u32_x(pg, svlsl_n_u32_x(pg, *b, 12), svlsr_n_u32_x(pg, *b, 20));

    *a = svadd_u32_x(pg, *a, *b);
    *d = sveor_u32_x(pg, *d, *a);
    *d = svorr_u32_x(pg, svlsl_n_u32_x(pg, *d, 8), svlsr_n_u32_x(pg, *d, 24));

    *c = svadd_u32_x(pg, *c, *d);
    *b = sveor_u32_x(pg, *b, *c);
    *b = svorr_u32_x(pg, svlsl_n_u32_x(pg, *b, 7), svlsr_n_u32_x(pg, *b, 25));
}

/* ============================================================================
 * ChaCha20 block: N-way parallel using SVE2 scalable vectors
 *
 * The number of parallel instances adapts to hardware VL.
 * With VL=128: 4 instances, VL=256: 8, VL=512: 16, VL=2048: 64.
 * ============================================================================ */
void ama_chacha20_block_sve2(const uint8_t key[32],
                              const uint8_t nonce[12],
                              uint32_t counter,
                              uint8_t *out, size_t *out_blocks) {
    uint32_t k[8], n[3];
    for (int i = 0; i < 8; i++) {
        k[i] = ((uint32_t)key[i*4]) | ((uint32_t)key[i*4+1] << 8) |
               ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    }
    for (int i = 0; i < 3; i++) {
        n[i] = ((uint32_t)nonce[i*4]) | ((uint32_t)nonce[i*4+1] << 8) |
               ((uint32_t)nonce[i*4+2] << 16) | ((uint32_t)nonce[i*4+3] << 24);
    }

    size_t vl_words = svcntw(); /* Number of 32-bit lanes in SVE vector */
    *out_blocks = vl_words;

    svbool_t pg = svptrue_b32();

    /* Broadcast state rows to all lanes */
    svuint32_t s0 = svdup_n_u32(CHACHA_C0);
    svuint32_t s1 = svdup_n_u32(CHACHA_C1);
    svuint32_t s2 = svdup_n_u32(CHACHA_C2);
    svuint32_t s3 = svdup_n_u32(CHACHA_C3);
    svuint32_t s4 = svdup_n_u32(k[0]);
    svuint32_t s5 = svdup_n_u32(k[1]);
    svuint32_t s6 = svdup_n_u32(k[2]);
    svuint32_t s7 = svdup_n_u32(k[3]);
    svuint32_t s8 = svdup_n_u32(k[4]);
    svuint32_t s9 = svdup_n_u32(k[5]);
    svuint32_t s10 = svdup_n_u32(k[6]);
    svuint32_t s11 = svdup_n_u32(k[7]);

    /* Counter: each lane gets counter+lane_index */
    svuint32_t s12 = svadd_u32_x(pg, svdup_n_u32(counter), svindex_u32(0, 1));
    svuint32_t s13 = svdup_n_u32(n[0]);
    svuint32_t s14 = svdup_n_u32(n[1]);
    svuint32_t s15 = svdup_n_u32(n[2]);

    /* Save initial state */
    svuint32_t i0=s0,i1=s1,i2=s2,i3=s3;
    svuint32_t i4=s4,i5=s5,i6=s6,i7=s7;
    svuint32_t i8=s8,i9=s9,i10=s10,i11=s11;
    svuint32_t i12=s12,i13=s13,i14=s14,i15=s15;

    /* 20 rounds */
    for (int round = 0; round < 10; round++) {
        chacha_qr_sve2(pg, &s0, &s4, &s8, &s12);
        chacha_qr_sve2(pg, &s1, &s5, &s9, &s13);
        chacha_qr_sve2(pg, &s2, &s6, &s10, &s14);
        chacha_qr_sve2(pg, &s3, &s7, &s11, &s15);
        chacha_qr_sve2(pg, &s0, &s5, &s10, &s15);
        chacha_qr_sve2(pg, &s1, &s6, &s11, &s12);
        chacha_qr_sve2(pg, &s2, &s7, &s8, &s13);
        chacha_qr_sve2(pg, &s3, &s4, &s9, &s14);
    }

    /* Add initial state */
    s0=svadd_u32_x(pg,s0,i0); s1=svadd_u32_x(pg,s1,i1);
    s2=svadd_u32_x(pg,s2,i2); s3=svadd_u32_x(pg,s3,i3);
    s4=svadd_u32_x(pg,s4,i4); s5=svadd_u32_x(pg,s5,i5);
    s6=svadd_u32_x(pg,s6,i6); s7=svadd_u32_x(pg,s7,i7);
    s8=svadd_u32_x(pg,s8,i8); s9=svadd_u32_x(pg,s9,i9);
    s10=svadd_u32_x(pg,s10,i10); s11=svadd_u32_x(pg,s11,i11);
    s12=svadd_u32_x(pg,s12,i12); s13=svadd_u32_x(pg,s13,i13);
    s14=svadd_u32_x(pg,s14,i14); s15=svadd_u32_x(pg,s15,i15);

    /* Store results - extract per-instance blocks */
    svuint32_t rows[16] = {s0,s1,s2,s3,s4,s5,s6,s7,
                           s8,s9,s10,s11,s12,s13,s14,s15};
    uint32_t tmp[64]; /* up to 64 lanes with VL=2048 */
    for (size_t inst = 0; inst < vl_words; inst++) {
        uint32_t block[16];
        for (int row = 0; row < 16; row++) {
            svst1_u32(pg, tmp, rows[row]);
            block[row] = tmp[inst];
        }
        memcpy(out + inst * 64, block, 64);
    }
}

#else
typedef int ama_chacha20poly1305_sve2_not_available;
#endif /* __ARM_FEATURE_SVE2 */
