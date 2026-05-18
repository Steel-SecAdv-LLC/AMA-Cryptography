/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_sphincs_neon.c
 * @brief ARM NEON-optimized SPHINCS+/SLH-DSA SHA-256 building blocks
 *
 * NEON intrinsics for SPHINCS+ (FIPS 205) SHA-256-family inner loop:
 *   - Single-block SHA-256 compression via ARM SHA2 Crypto Extensions
 *     (`vsha256hq_u32`, `vsha256h2q_u32`, `vsha256su0q_u32`,
 *     `vsha256su1q_u32`) when `__ARM_FEATURE_SHA2` is defined;
 *     scalar fallback otherwise.
 *   - Per-call WOTS+ chain helper (currently dead code: production
 *     `slh_wots_chain` in src/c/ama_slhdsa.c uses the scalar SHA-256
 *     pipeline through `ama_sha256_init/update/final`).  The helpers
 *     remain because the SHA-256 compression primitive itself is
 *     pinned by `tests/c/test_sha256_neon_kat.c` (FIPS 180-4 KAT) on
 *     `__ARM_FEATURE_SHA2` hosts and represents real work any future
 *     dispatched-SHA-256 SVE2/NEON wiring will consume.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>

/* SHA-256 round constants */
static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const uint32_t H256[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

/* NEON rotate right for 32-bit lanes */
static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

/* ============================================================================
 * NEON-assisted SHA-256 compression (single block)
 *
 * Uses ARM Crypto Extensions (vsha256hq_u32, etc.) if available,
 * otherwise falls back to NEON-vectorized computation.
 * ============================================================================ */
#if defined(__ARM_FEATURE_SHA2)
/* ARM SHA2 Crypto Extensions path — single-block SHA-256 compression.
 *
 * Algorithm: standard ARM Crypto Extension idiom (cf. Arm Architecture
 * Reference Manual SHA256H / SHA256H2 / SHA256SU0 / SHA256SU1 entries,
 * and the canonical patterns in OpenSSL `crypto/sha/asm/sha256-armv8.pl`
 * and Linux `arch/arm64/crypto/sha2-ce-core.S`).
 *
 * ABCD/EFGH assignment contract (ACLE):
 *   vsha256hq_u32(hash_abcd, hash_efgh, wk)  → next ABCD
 *   vsha256h2q_u32(hash_efgh, hash_abcd, wk) → next EFGH
 *
 * Both intrinsics consume the OLD ABCD; we therefore save ABCD into
 * tmp2 BEFORE the sha256h call so sha256h2 has the same value to feed
 * the EFGH update.
 *
 * At every 4-round quartet R (R = 0, 4, 8, ..., 60):
 *
 *   1. K-add: tmp = msg[(R/4) & 3] + K256[R..R+3].
 *   2. Hash:
 *        tmp2 = abcd
 *        abcd = sha256h (abcd, efgh, tmp)
 *        efgh = sha256h2(efgh, tmp2, tmp)
 *   3. Schedule (only while we still need future w-words, i.e. R < 48):
 *        msg[(R/4) & 3] = sha256su1(sha256su0(msg[(R/4) & 3], msg[((R/4)+1) & 3]),
 *                                   msg[((R/4)+2) & 3], msg[((R/4)+3) & 3])
 *      The slot whose contents just fed the K-add (and will no longer
 *      be needed for any of the remaining rounds) is reused to hold
 *      the freshly-scheduled w[R+16..R+19].
 *
 * Bug history:
 *   - The earliest rotation-based implementation (commit 4f877bc, PR
 *     #305 SIMD wiring) had two correlated message-schedule bugs in
 *     the rounds-12+ loop: the schedule step passed `msg0` to both
 *     arguments of vsha256su0q_u32, and the K-add unconditionally
 *     indexed `msg3` while the rotation moved the next round's
 *     message to a different slot.
 *   - The faf2e8d rewrite replaced the rotation with explicit array
 *     indexing, fixing those two but preserving an inherited
 *     ABCD/EFGH argument/assignment swap (the original wrote
 *     `efgh = vsha256hq_u32(efgh, abcd, ...)` which is "compute next
 *     ABCD treating EFGH as ABCD" — wrong since the two intrinsics
 *     are not symmetric in their first two arguments).
 *
 * The current revision is the canonical ABCD/EFGH pattern.  Pinned by
 * `tests/c/test_sha256_neon_kat.c` against FIPS 180-4 §B.1/§B.2 digests
 * on every AArch64 CI run. */
void ama_sha256_compress_neon(uint32_t state[8], const uint8_t block[64]) {
    uint32x4_t abcd = vld1q_u32(state);
    uint32x4_t efgh = vld1q_u32(state + 4);
    uint32x4_t abcd_save = abcd;
    uint32x4_t efgh_save = efgh;

    /* Load and byte-swap message words (block is big-endian per FIPS 180-4). */
    uint32x4_t msg[4];
    msg[0] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block)));
    msg[1] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 16)));
    msg[2] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 32)));
    msg[3] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 48)));

    /* Rounds 0..47 (R/4 = 0..11): hash quartet + schedule next w-block.
     * After iteration r, msg[r & 3] holds w[(r+4)*4..(r+4)*4+3]. */
    for (int r = 0; r < 12; r++) {
        int s0 = r & 3;
        int s1 = (r + 1) & 3;
        int s2 = (r + 2) & 3;
        int s3 = (r + 3) & 3;
        uint32x4_t tmp  = vaddq_u32(msg[s0], vld1q_u32(&K256[r * 4]));
        uint32x4_t tmp2 = abcd;
        abcd = vsha256hq_u32 (abcd, efgh, tmp);
        efgh = vsha256h2q_u32(efgh, tmp2, tmp);
        msg[s0] = vsha256su1q_u32(vsha256su0q_u32(msg[s0], msg[s1]),
                                  msg[s2], msg[s3]);
    }

    /* Rounds 48..63 (R/4 = 12..15): hash only — no more w-words needed.
     * At entry msg[] holds {w[48..51], w[52..55], w[56..59], w[60..63]}
     * in cyclic order; msg[r & 3] selects the right slot at each step. */
    for (int r = 12; r < 16; r++) {
        uint32x4_t tmp  = vaddq_u32(msg[r & 3], vld1q_u32(&K256[r * 4]));
        uint32x4_t tmp2 = abcd;
        abcd = vsha256hq_u32 (abcd, efgh, tmp);
        efgh = vsha256h2q_u32(efgh, tmp2, tmp);
    }

    /* Add saved state (Merkle-Damgård feed-forward). */
    abcd = vaddq_u32(abcd, abcd_save);
    efgh = vaddq_u32(efgh, efgh_save);

    vst1q_u32(state, abcd);
    vst1q_u32(state + 4, efgh);
}
#else
/* Fallback path: pure scalar SHA-256 compression for AArch64 builds
 * without `__ARM_FEATURE_SHA2` (e.g., ARMv8 cores without the optional
 * Crypto Extensions, or compilers that don't set the feature macro).
 * No NEON intrinsics are used here; the function keeps its
 * `_neon`-suffixed name solely so the caller (`wots_chain_neon`) can
 * use a single symbol regardless of feature availability. */
void ama_sha256_compress_neon(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24) |
               ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) |
               ((uint32_t)block[i*4+3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint32_t a=state[0], b=state[1], c=state[2], d=state[3];
    uint32_t e=state[4], f=state[5], g=state[6], h=state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h=g; g=f; f=e; e=d+temp1;
        d=c; c=b; b=a; a=temp1+temp2;
    }

    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}
#endif /* __ARM_FEATURE_SHA2 */

/* ============================================================================
 * WOTS+ chain computation (NEON-assisted)
 * ============================================================================ */
void ama_sphincs_wots_chain_neon(uint8_t *out, const uint8_t *in,
                                  uint32_t start, uint32_t steps,
                                  const uint8_t *pub_seed,
                                  uint32_t addr[8], size_t n) {
    if (steps == 0) {
        memcpy(out, in, n);
        return;
    }
    memcpy(out, in, n);

    for (uint32_t i = start; i < start + steps && i < 256; i++) {
        addr[6] = i;
        uint8_t block[64];
        memset(block, 0, 64);
        memcpy(block, out, n < 32 ? n : 32);
        block[32] = (uint8_t)(addr[0] >> 24);
        block[33] = (uint8_t)(addr[0] >> 16);
        block[34] = (uint8_t)(addr[0] >> 8);
        block[35] = (uint8_t)(addr[0]);

        uint32_t h_state[8];
        memcpy(h_state, H256, sizeof(H256));
        ama_sha256_compress_neon(h_state, block);

        for (int j = 0; j < 8 && j * 4 < (int)n; j++) {
            out[j*4+0] = (uint8_t)(h_state[j] >> 24);
            out[j*4+1] = (uint8_t)(h_state[j] >> 16);
            out[j*4+2] = (uint8_t)(h_state[j] >> 8);
            out[j*4+3] = (uint8_t)(h_state[j]);
        }
    }
    (void)pub_seed;
}

#else
typedef int ama_sphincs_neon_not_available;
#endif /* __aarch64__ */
