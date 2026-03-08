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
 * @file ama_ed25519.c
 * @brief Ed25519 digital signature implementation (RFC 8032)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2025-12-06
 *
 * Implements Ed25519 signatures per RFC 8032 using the twisted Edwards curve:
 *   -x^2 + y^2 = 1 + d*x^2*y^2  where d = -121665/121666 (mod p)
 *   p = 2^255 - 19
 *   Base point order: L = 2^252 + 27742317777372353535851937790883648493
 *
 * Security properties:
 * - Constant-time field arithmetic (fe25519 operations)
 * - Constant-time base point scalar multiplication (windowed with cmov)
 * - Constant-time table lookups (linear scan, no secret-dependent indexing)
 * - Thread-safe lazy initialization via CAS tri-state protocol
 * - Proper scalar clamping
 * - Cofactor handling per RFC 8032
 *
 * Note: ge25519_scalarmult() (variable-base) uses double-and-add and is
 * NOT constant-time. It is used only for verification where the scalar
 * (derived from the hash of the signature) is public.
 */

#include "../include/ama_cryptography.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* C11 atomics for thread-safe lazy initialization of base point tables.
 * Uses a tri-state CAS protocol: 0 = uninitialized, 1 = initializing, 2 = ready.
 * Falls back to volatile on pre-C11 compilers (MSVC, older GCC). */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
  #include <stdatomic.h>
  #define AMA_ATOMIC_INT            _Atomic int
  #define AMA_ATOMIC_LOAD(p)        atomic_load_explicit(&(p), memory_order_acquire)
  #define AMA_ATOMIC_STORE(p, v)    atomic_store_explicit(&(p), (v), memory_order_release)
  /* CAS: atomically set *p from expected to desired; returns 1 on success */
  #define AMA_ATOMIC_CAS(p, expected, desired) \
      atomic_compare_exchange_strong_explicit(&(p), &(expected), (desired), \
          memory_order_acq_rel, memory_order_acquire)
#else
  /* Pre-C11 fallback: volatile provides compiler ordering but not hardware
   * fence guarantees. Acceptable on x86 (TSO) but not on ARM/POWER. */
  #define AMA_ATOMIC_INT            volatile int
  #define AMA_ATOMIC_LOAD(p)        (p)
  #define AMA_ATOMIC_STORE(p, v)    ((p) = (v))
  /* Fallback CAS: NOT truly atomic — safe only on single-core or x86 TSO. */
  #define AMA_ATOMIC_CAS(p, expected, desired) \
      ((p) == (expected) ? ((p) = (desired), 1) : ((expected) = (p), 0))
#endif

/* Tri-state constants for lazy initialization protocol */
#define AMA_INIT_UNINIT       0
#define AMA_INIT_IN_PROGRESS  1
#define AMA_INIT_READY        2

/* ============================================================================
 * SHA-512 IMPLEMENTATION (Required by Ed25519)
 * ============================================================================ */

#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_SIZE 64

/* SHA-512 round constants */
static const uint64_t sha512_k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static inline uint64_t rotr64(uint64_t x, unsigned int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t load64_be(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

static inline void store64_be(uint8_t *p, uint64_t x) {
    p[0] = (uint8_t)(x >> 56); p[1] = (uint8_t)(x >> 48);
    p[2] = (uint8_t)(x >> 40); p[3] = (uint8_t)(x >> 32);
    p[4] = (uint8_t)(x >> 24); p[5] = (uint8_t)(x >> 16);
    p[6] = (uint8_t)(x >> 8);  p[7] = (uint8_t)(x);
}

static void sha512_transform(uint64_t state[8], const uint8_t block[128]) {
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t W[80];
    uint64_t t1, t2;
    int i;

    /* Load message block */
    for (i = 0; i < 16; i++) {
        W[i] = load64_be(block + i * 8);
    }

    /* Extend message */
    for (i = 16; i < 80; i++) {
        uint64_t s0 = rotr64(W[i-15], 1) ^ rotr64(W[i-15], 8) ^ (W[i-15] >> 7);
        uint64_t s1 = rotr64(W[i-2], 19) ^ rotr64(W[i-2], 61) ^ (W[i-2] >> 6);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* Compression */
    for (i = 0; i < 80; i++) {
        uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + sha512_k[i] + W[i];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha512(const uint8_t *data, size_t len, uint8_t out[64]) {
    uint64_t state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    uint8_t block[128];
    size_t i;
    uint64_t bit_len = len * 8;

    /* Process full blocks */
    while (len >= 128) {
        sha512_transform(state, data);
        data += 128;
        len -= 128;
    }

    /* Pad final block */
    memset(block, 0, sizeof(block));
    memcpy(block, data, len);
    block[len] = 0x80;

    if (len >= 112) {
        sha512_transform(state, block);
        memset(block, 0, sizeof(block));
    }

    /* Append length (big-endian, 128-bit, but we only use low 64 bits) */
    store64_be(block + 120, bit_len);
    sha512_transform(state, block);

    /* Output */
    for (i = 0; i < 8; i++) {
        store64_be(out + i * 8, state[i]);
    }
}

/* ============================================================================
 * FIELD ARITHMETIC: GF(2^255 - 19)
 * ============================================================================ */

typedef int64_t fe25519[10];  /* Radix 2^25.5 representation */

/* Helper: load 3 bytes little-endian */
static int64_t load_3(const uint8_t *in) {
    int64_t result;
    result  = (int64_t)in[0];
    result |= ((int64_t)in[1]) << 8;
    result |= ((int64_t)in[2]) << 16;
    return result;
}

/* Helper: load 4 bytes little-endian */
static int64_t load_4(const uint8_t *in) {
    int64_t result;
    result  = (int64_t)in[0];
    result |= ((int64_t)in[1]) << 8;
    result |= ((int64_t)in[2]) << 16;
    result |= ((int64_t)in[3]) << 24;
    return result;
}

/*
 * Load 32 bytes as field element (little-endian).
 * Uses radix 2^25.5: limbs alternate 26 and 25 bits.
 * Based on the SUPERCOP ref10 fe_frombytes implementation.
 */
static void fe25519_frombytes(fe25519 h, const uint8_t *s) {
    int64_t h0 = load_4(s);
    int64_t h1 = load_3(s + 4) << 6;
    int64_t h2 = load_3(s + 7) << 5;
    int64_t h3 = load_3(s + 10) << 3;
    int64_t h4 = load_3(s + 13) << 2;
    int64_t h5 = load_4(s + 16);
    int64_t h6 = load_3(s + 20) << 7;
    int64_t h7 = load_3(s + 23) << 5;
    int64_t h8 = load_3(s + 26) << 4;
    int64_t h9 = (load_3(s + 29) & 8388607) << 2;

    int64_t carry0, carry1, carry2, carry3, carry4;
    int64_t carry5, carry6, carry7, carry8, carry9;

    carry9 = (h9 + ((int64_t)1 << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 * ((int64_t)1 << 25);
    carry1 = (h1 + ((int64_t)1 << 24)) >> 25; h2 += carry1; h1 -= carry1 * ((int64_t)1 << 25);
    carry3 = (h3 + ((int64_t)1 << 24)) >> 25; h4 += carry3; h3 -= carry3 * ((int64_t)1 << 25);
    carry5 = (h5 + ((int64_t)1 << 24)) >> 25; h6 += carry5; h5 -= carry5 * ((int64_t)1 << 25);
    carry7 = (h7 + ((int64_t)1 << 24)) >> 25; h8 += carry7; h7 -= carry7 * ((int64_t)1 << 25);

    carry0 = (h0 + ((int64_t)1 << 25)) >> 26; h1 += carry0; h0 -= carry0 * ((int64_t)1 << 26);
    carry2 = (h2 + ((int64_t)1 << 25)) >> 26; h3 += carry2; h2 -= carry2 * ((int64_t)1 << 26);
    carry4 = (h4 + ((int64_t)1 << 25)) >> 26; h5 += carry4; h4 -= carry4 * ((int64_t)1 << 26);
    carry6 = (h6 + ((int64_t)1 << 25)) >> 26; h7 += carry6; h6 -= carry6 * ((int64_t)1 << 26);
    carry8 = (h8 + ((int64_t)1 << 25)) >> 26; h9 += carry8; h8 -= carry8 * ((int64_t)1 << 26);

    h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3; h[4] = h4;
    h[5] = h5; h[6] = h6; h[7] = h7; h[8] = h8; h[9] = h9;
}

/*
 * Reduce and store field element to 32 bytes (little-endian).
 * Based on the SUPERCOP ref10 fe_tobytes implementation.
 * Limb layout: h[0]=26, h[1]=25, h[2]=26, ..., h[9]=25 bits.
 */
static void fe25519_tobytes(uint8_t *s, const fe25519 h) {
    int64_t t[10];
    int64_t q, carry;
    int i;

    for (i = 0; i < 10; i++) t[i] = h[i];

    /* Compute q = floor((h + 19) / (2^255 - 19)) to determine if we need final reduction */
    q = (19 * t[9] + ((int64_t)1 << 24)) >> 25;
    q = (t[0] + q) >> 26;
    q = (t[1] + q) >> 25;
    q = (t[2] + q) >> 26;
    q = (t[3] + q) >> 25;
    q = (t[4] + q) >> 26;
    q = (t[5] + q) >> 25;
    q = (t[6] + q) >> 26;
    q = (t[7] + q) >> 25;
    q = (t[8] + q) >> 26;
    q = (t[9] + q) >> 25;

    /* If q=1, h >= p, so subtract p by adding 19 */
    t[0] += 19 * q;

    /* Propagate carries to get canonical form */
    carry = t[0] >> 26; t[1] += carry; t[0] -= carry * ((int64_t)1 << 26);
    carry = t[1] >> 25; t[2] += carry; t[1] -= carry * ((int64_t)1 << 25);
    carry = t[2] >> 26; t[3] += carry; t[2] -= carry * ((int64_t)1 << 26);
    carry = t[3] >> 25; t[4] += carry; t[3] -= carry * ((int64_t)1 << 25);
    carry = t[4] >> 26; t[5] += carry; t[4] -= carry * ((int64_t)1 << 26);
    carry = t[5] >> 25; t[6] += carry; t[5] -= carry * ((int64_t)1 << 25);
    carry = t[6] >> 26; t[7] += carry; t[6] -= carry * ((int64_t)1 << 26);
    carry = t[7] >> 25; t[8] += carry; t[7] -= carry * ((int64_t)1 << 25);
    carry = t[8] >> 26; t[9] += carry; t[8] -= carry * ((int64_t)1 << 26);
    carry = t[9] >> 25;               t[9] -= carry * ((int64_t)1 << 25);

    /* Pack into 32 bytes (matching 26/25-bit limb boundaries) */
    s[ 0] = (uint8_t)(t[0] >> 0);
    s[ 1] = (uint8_t)(t[0] >> 8);
    s[ 2] = (uint8_t)(t[0] >> 16);
    s[ 3] = (uint8_t)((t[0] >> 24) | (t[1] * ((int64_t)1 << 2)));
    s[ 4] = (uint8_t)(t[1] >> 6);
    s[ 5] = (uint8_t)(t[1] >> 14);
    s[ 6] = (uint8_t)((t[1] >> 22) | (t[2] * ((int64_t)1 << 3)));
    s[ 7] = (uint8_t)(t[2] >> 5);
    s[ 8] = (uint8_t)(t[2] >> 13);
    s[ 9] = (uint8_t)((t[2] >> 21) | (t[3] * ((int64_t)1 << 5)));
    s[10] = (uint8_t)(t[3] >> 3);
    s[11] = (uint8_t)(t[3] >> 11);
    s[12] = (uint8_t)((t[3] >> 19) | (t[4] * ((int64_t)1 << 6)));
    s[13] = (uint8_t)(t[4] >> 2);
    s[14] = (uint8_t)(t[4] >> 10);
    s[15] = (uint8_t)(t[4] >> 18);
    s[16] = (uint8_t)(t[5] >> 0);
    s[17] = (uint8_t)(t[5] >> 8);
    s[18] = (uint8_t)(t[5] >> 16);
    s[19] = (uint8_t)((t[5] >> 24) | (t[6] * ((int64_t)1 << 1)));
    s[20] = (uint8_t)(t[6] >> 7);
    s[21] = (uint8_t)(t[6] >> 15);
    s[22] = (uint8_t)((t[6] >> 23) | (t[7] * ((int64_t)1 << 3)));
    s[23] = (uint8_t)(t[7] >> 5);
    s[24] = (uint8_t)(t[7] >> 13);
    s[25] = (uint8_t)((t[7] >> 21) | (t[8] * ((int64_t)1 << 4)));
    s[26] = (uint8_t)(t[8] >> 4);
    s[27] = (uint8_t)(t[8] >> 12);
    s[28] = (uint8_t)((t[8] >> 20) | (t[9] * ((int64_t)1 << 6)));
    s[29] = (uint8_t)(t[9] >> 2);
    s[30] = (uint8_t)(t[9] >> 10);
    s[31] = (uint8_t)(t[9] >> 18);
}

static void fe25519_0(fe25519 h) {
    memset(h, 0, sizeof(fe25519));
}

static void fe25519_1(fe25519 h) {
    memset(h, 0, sizeof(fe25519));
    h[0] = 1;
}

static void fe25519_copy(fe25519 h, const fe25519 f) {
    memcpy(h, f, sizeof(fe25519));
}

static void fe25519_add(fe25519 h, const fe25519 f, const fe25519 g) {
    for (int i = 0; i < 10; i++) h[i] = f[i] + g[i];
}

static void fe25519_sub(fe25519 h, const fe25519 f, const fe25519 g) {
    for (int i = 0; i < 10; i++) h[i] = f[i] - g[i];
}

static void fe25519_neg(fe25519 h, const fe25519 f) {
    for (int i = 0; i < 10; i++) h[i] = -f[i];
}

/* Carry and reduce */
static void fe25519_carry(fe25519 h) {
    int64_t carry;
    for (int i = 0; i < 10; i++) {
        carry = h[i] >> ((i & 1) ? 25 : 26);
        h[i] -= carry << ((i & 1) ? 25 : 26);
        if (i < 9) h[i + 1] += carry;
        else h[0] += 19 * carry;
    }
}

/*
 * Multiplication with proper ref10 carry propagation.
 * The carry pattern is critical: it uses biased rounding and an interleaved
 * order (0,4,1,5,2,6,3,7,4,8,9,0) to keep limbs bounded within [-2^25, 2^26).
 * A naive single-pass carry allows limbs to grow, eventually causing int64_t
 * overflow in subsequent multiplications.
 * Based on the SUPERCOP ref10 fe_mul implementation.
 */
static void fe25519_mul(fe25519 h, const fe25519 f, const fe25519 g) {
    int64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    int64_t f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];
    int64_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
    int64_t g5 = g[5], g6 = g[6], g7 = g[7], g8 = g[8], g9 = g[9];
    int64_t g1_19 = 19 * g1, g2_19 = 19 * g2, g3_19 = 19 * g3, g4_19 = 19 * g4;
    int64_t g5_19 = 19 * g5, g6_19 = 19 * g6, g7_19 = 19 * g7, g8_19 = 19 * g8, g9_19 = 19 * g9;
    int64_t f1_2 = 2 * f1, f3_2 = 2 * f3, f5_2 = 2 * f5, f7_2 = 2 * f7, f9_2 = 2 * f9;

    int64_t h0 = f0*g0 + f1_2*g9_19 + f2*g8_19 + f3_2*g7_19 + f4*g6_19 + f5_2*g5_19 + f6*g4_19 + f7_2*g3_19 + f8*g2_19 + f9_2*g1_19;
    int64_t h1 = f0*g1 + f1*g0 + f2*g9_19 + f3*g8_19 + f4*g7_19 + f5*g6_19 + f6*g5_19 + f7*g4_19 + f8*g3_19 + f9*g2_19;
    int64_t h2 = f0*g2 + f1_2*g1 + f2*g0 + f3_2*g9_19 + f4*g8_19 + f5_2*g7_19 + f6*g6_19 + f7_2*g5_19 + f8*g4_19 + f9_2*g3_19;
    int64_t h3 = f0*g3 + f1*g2 + f2*g1 + f3*g0 + f4*g9_19 + f5*g8_19 + f6*g7_19 + f7*g6_19 + f8*g5_19 + f9*g4_19;
    int64_t h4 = f0*g4 + f1_2*g3 + f2*g2 + f3_2*g1 + f4*g0 + f5_2*g9_19 + f6*g8_19 + f7_2*g7_19 + f8*g6_19 + f9_2*g5_19;
    int64_t h5 = f0*g5 + f1*g4 + f2*g3 + f3*g2 + f4*g1 + f5*g0 + f6*g9_19 + f7*g8_19 + f8*g7_19 + f9*g6_19;
    int64_t h6 = f0*g6 + f1_2*g5 + f2*g4 + f3_2*g3 + f4*g2 + f5_2*g1 + f6*g0 + f7_2*g9_19 + f8*g8_19 + f9_2*g7_19;
    int64_t h7 = f0*g7 + f1*g6 + f2*g5 + f3*g4 + f4*g3 + f5*g2 + f6*g1 + f7*g0 + f8*g9_19 + f9*g8_19;
    int64_t h8 = f0*g8 + f1_2*g7 + f2*g6 + f3_2*g5 + f4*g4 + f5_2*g3 + f6*g2 + f7_2*g1 + f8*g0 + f9_2*g9_19;
    int64_t h9 = f0*g9 + f1*g8 + f2*g7 + f3*g6 + f4*g5 + f5*g4 + f6*g3 + f7*g2 + f8*g1 + f9*g0;

    int64_t carry0, carry1, carry2, carry3, carry4;
    int64_t carry5, carry6, carry7, carry8, carry9;

    /*
     * Ref10 interleaved carry propagation.
     * The order (0,4,1,5,2,6,3,7,4,8,9,0) ensures each limb receives at most
     * one incoming carry before its own carry is extracted, keeping all limbs
     * within the range needed to prevent overflow in subsequent multiplications.
     */
    carry0 = (h0 + ((int64_t)1 << 25)) >> 26; h1 += carry0; h0 -= carry0 * ((int64_t)1 << 26);
    carry4 = (h4 + ((int64_t)1 << 25)) >> 26; h5 += carry4; h4 -= carry4 * ((int64_t)1 << 26);
    carry1 = (h1 + ((int64_t)1 << 24)) >> 25; h2 += carry1; h1 -= carry1 * ((int64_t)1 << 25);
    carry5 = (h5 + ((int64_t)1 << 24)) >> 25; h6 += carry5; h5 -= carry5 * ((int64_t)1 << 25);
    carry2 = (h2 + ((int64_t)1 << 25)) >> 26; h3 += carry2; h2 -= carry2 * ((int64_t)1 << 26);
    carry6 = (h6 + ((int64_t)1 << 25)) >> 26; h7 += carry6; h6 -= carry6 * ((int64_t)1 << 26);
    carry3 = (h3 + ((int64_t)1 << 24)) >> 25; h4 += carry3; h3 -= carry3 * ((int64_t)1 << 25);
    carry7 = (h7 + ((int64_t)1 << 24)) >> 25; h8 += carry7; h7 -= carry7 * ((int64_t)1 << 25);
    carry4 = (h4 + ((int64_t)1 << 25)) >> 26; h5 += carry4; h4 -= carry4 * ((int64_t)1 << 26);
    carry8 = (h8 + ((int64_t)1 << 25)) >> 26; h9 += carry8; h8 -= carry8 * ((int64_t)1 << 26);
    carry9 = (h9 + ((int64_t)1 << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 * ((int64_t)1 << 25);
    carry0 = (h0 + ((int64_t)1 << 25)) >> 26; h1 += carry0; h0 -= carry0 * ((int64_t)1 << 26);

    h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3; h[4] = h4;
    h[5] = h5; h[6] = h6; h[7] = h7; h[8] = h8; h[9] = h9;
}

/*
 * Optimized squaring exploiting f[j]*f[k] = f[k]*f[j] symmetry.
 * Reduces ~100 multiplications (generic mul) to ~55 (dedicated sq).
 * Based on the SUPERCOP ref10 fe_sq implementation.
 * Uses the same interleaved carry propagation as fe25519_mul.
 */
static void fe25519_sq(fe25519 h, const fe25519 f) {
    int64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    int64_t f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];
    int64_t f0_2 = 2 * f0, f1_2 = 2 * f1, f2_2 = 2 * f2, f3_2 = 2 * f3;
    int64_t f4_2 = 2 * f4, f5_2 = 2 * f5, f6_2 = 2 * f6, f7_2 = 2 * f7;
    int64_t f5_38 = 38 * f5, f6_19 = 19 * f6, f7_38 = 38 * f7;
    int64_t f8_19 = 19 * f8, f9_38 = 38 * f9;

    int64_t h0 = f0*f0    + f1_2*f9_38 + f2_2*f8_19 + f3_2*f7_38 + f4_2*f6_19 + f5*f5_38;
    int64_t h1 = f0_2*f1  + f2*f9_38   + f3_2*f8_19 + f4*f7_38   + f5_2*f6_19;
    int64_t h2 = f0_2*f2  + f1_2*f1    + f3_2*f9_38 + f4_2*f8_19 + f5_2*f7_38 + f6*f6_19;
    int64_t h3 = f0_2*f3  + f1_2*f2    + f4*f9_38   + f5_2*f8_19 + f6*f7_38;
    int64_t h4 = f0_2*f4  + f1_2*f3_2  + f2*f2      + f5_2*f9_38 + f6_2*f8_19 + f7*f7_38;
    int64_t h5 = f0_2*f5  + f1_2*f4    + f2_2*f3    + f6*f9_38   + f7_2*f8_19;
    int64_t h6 = f0_2*f6  + f1_2*f5_2  + f2_2*f4    + f3_2*f3    + f7_2*f9_38 + f8*f8_19;
    int64_t h7 = f0_2*f7  + f1_2*f6    + f2_2*f5    + f3_2*f4    + f8*f9_38;
    int64_t h8 = f0_2*f8  + f1_2*f7_2  + f2_2*f6    + f3_2*f5_2  + f4*f4     + f9*f9_38;
    int64_t h9 = f0_2*f9  + f1_2*f8    + f2_2*f7    + f3_2*f6    + f4_2*f5;

    int64_t carry0, carry1, carry2, carry3, carry4;
    int64_t carry5, carry6, carry7, carry8, carry9;

    carry0 = (h0 + ((int64_t)1 << 25)) >> 26; h1 += carry0; h0 -= carry0 * ((int64_t)1 << 26);
    carry4 = (h4 + ((int64_t)1 << 25)) >> 26; h5 += carry4; h4 -= carry4 * ((int64_t)1 << 26);
    carry1 = (h1 + ((int64_t)1 << 24)) >> 25; h2 += carry1; h1 -= carry1 * ((int64_t)1 << 25);
    carry5 = (h5 + ((int64_t)1 << 24)) >> 25; h6 += carry5; h5 -= carry5 * ((int64_t)1 << 25);
    carry2 = (h2 + ((int64_t)1 << 25)) >> 26; h3 += carry2; h2 -= carry2 * ((int64_t)1 << 26);
    carry6 = (h6 + ((int64_t)1 << 25)) >> 26; h7 += carry6; h6 -= carry6 * ((int64_t)1 << 26);
    carry3 = (h3 + ((int64_t)1 << 24)) >> 25; h4 += carry3; h3 -= carry3 * ((int64_t)1 << 25);
    carry7 = (h7 + ((int64_t)1 << 24)) >> 25; h8 += carry7; h7 -= carry7 * ((int64_t)1 << 25);
    carry4 = (h4 + ((int64_t)1 << 25)) >> 26; h5 += carry4; h4 -= carry4 * ((int64_t)1 << 26);
    carry8 = (h8 + ((int64_t)1 << 25)) >> 26; h9 += carry8; h8 -= carry8 * ((int64_t)1 << 26);
    carry9 = (h9 + ((int64_t)1 << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 * ((int64_t)1 << 25);
    carry0 = (h0 + ((int64_t)1 << 25)) >> 26; h1 += carry0; h0 -= carry0 * ((int64_t)1 << 26);

    h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3; h[4] = h4;
    h[5] = h5; h[6] = h6; h[7] = h7; h[8] = h8; h[9] = h9;
}

/* Inversion via Fermat's little theorem: a^(-1) = a^(p-2) mod p */
static void fe25519_invert(fe25519 out, const fe25519 z) {
    fe25519 t0, t1, t2, t3;
    int i;

    fe25519_sq(t0, z);
    fe25519_sq(t1, t0);
    fe25519_sq(t1, t1);
    fe25519_mul(t1, z, t1);
    fe25519_mul(t0, t0, t1);
    fe25519_sq(t2, t0);
    fe25519_mul(t1, t1, t2);
    fe25519_sq(t2, t1);
    for (i = 0; i < 4; i++) fe25519_sq(t2, t2);
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t2, t1);
    for (i = 0; i < 9; i++) fe25519_sq(t2, t2);
    fe25519_mul(t2, t2, t1);
    fe25519_sq(t3, t2);
    for (i = 0; i < 19; i++) fe25519_sq(t3, t3);
    fe25519_mul(t2, t3, t2);
    fe25519_sq(t2, t2);
    for (i = 0; i < 9; i++) fe25519_sq(t2, t2);
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t2, t1);
    for (i = 0; i < 49; i++) fe25519_sq(t2, t2);
    fe25519_mul(t2, t2, t1);
    fe25519_sq(t3, t2);
    for (i = 0; i < 99; i++) fe25519_sq(t3, t3);
    fe25519_mul(t2, t3, t2);
    fe25519_sq(t2, t2);
    for (i = 0; i < 49; i++) fe25519_sq(t2, t2);
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t1, t1);
    for (i = 0; i < 4; i++) fe25519_sq(t1, t1);
    fe25519_mul(out, t1, t0);
}

/*
 * Compute z^(2^252 - 3), used for point decompression (sqrt of u/v).
 * Same addition chain as fe25519_invert up to z^(2^250-1), then:
 *   z^(2^252 - 4) * z = z^(2^252 - 3)
 * Based on the SUPERCOP ref10 pow22523 implementation.
 */
static void fe25519_pow22523(fe25519 out, const fe25519 z) {
    fe25519 t0, t1, t2, t3;
    int i;

    fe25519_sq(t0, z);
    fe25519_sq(t1, t0);
    fe25519_sq(t1, t1);
    fe25519_mul(t1, z, t1);
    fe25519_mul(t0, t0, t1);
    fe25519_sq(t2, t0);
    fe25519_mul(t1, t1, t2);
    fe25519_sq(t2, t1);
    for (i = 0; i < 4; i++) fe25519_sq(t2, t2);
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t2, t1);
    for (i = 0; i < 9; i++) fe25519_sq(t2, t2);
    fe25519_mul(t2, t2, t1);
    fe25519_sq(t3, t2);
    for (i = 0; i < 19; i++) fe25519_sq(t3, t3);
    fe25519_mul(t2, t3, t2);
    fe25519_sq(t2, t2);
    for (i = 0; i < 9; i++) fe25519_sq(t2, t2);
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t2, t1);
    for (i = 0; i < 49; i++) fe25519_sq(t2, t2);
    fe25519_mul(t2, t2, t1);
    fe25519_sq(t3, t2);
    for (i = 0; i < 99; i++) fe25519_sq(t3, t3);
    fe25519_mul(t2, t3, t2);
    fe25519_sq(t2, t2);
    for (i = 0; i < 49; i++) fe25519_sq(t2, t2);
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t1, t1);
    fe25519_sq(t1, t1);
    fe25519_mul(out, t1, z);
}

/* Conditional swap (constant time) */
static void fe25519_cswap(fe25519 f, fe25519 g, int b) {
    int64_t mask = -(int64_t)b;
    for (int i = 0; i < 10; i++) {
        int64_t x = mask & (f[i] ^ g[i]);
        f[i] ^= x;
        g[i] ^= x;
    }
}

/* Check if negative (LSB of reduced value) */
static int fe25519_isnegative(const fe25519 f) {
    uint8_t s[32];
    fe25519_tobytes(s, f);
    return s[0] & 1;
}

/* Check if zero */
static int fe25519_iszero(const fe25519 f) {
    uint8_t s[32];
    fe25519_tobytes(s, f);
    int ret = 0;
    for (int i = 0; i < 32; i++) ret |= s[i];
    return ret == 0;
}

/* ============================================================================
 * GROUP OPERATIONS: Extended Twisted Edwards
 * ============================================================================ */

/* Point in extended coordinates (X:Y:Z:T) where x=X/Z, y=Y/Z, xy=T/Z */
typedef struct {
    fe25519 X, Y, Z, T;
} ge25519_p3;

/* Point in projective coordinates (X:Y:Z) */
typedef struct {
    fe25519 X, Y, Z;
} ge25519_p2;

/* Point in completed coordinates for addition */
typedef struct {
    fe25519 X, Y, Z, T;
} ge25519_p1p1;

/* Precomputed point (y+x, y-x, 2dxy) */
typedef struct {
    fe25519 yplusx, yminusx, xy2d;
} ge25519_precomp;

/* d = -121665/121666 */
static const fe25519 d = {
    -10913610, 13857413, -15372611, 6949391, 114729,
    -8787816, -6275908, -3247719, -18696448, -12055116
};

/* 2*d */
static const fe25519 d2 = {
    -21827239, -5839606, -30745221, 13898782, 229458,
    15978800, -12551817, -6495438, 29715968, 9444199
};

/* Forward declaration — needed by ensure_base_point() below */
static int ge25519_frombytes(ge25519_p3 *h, const uint8_t *s);

/*
 * Base point B — lazily initialized from the Ed25519 compressed base point.
 * The compressed form is the y-coordinate (4/5 mod p) in little-endian with
 * the sign bit of x in the high bit of the last byte.
 * This avoids hardcoding limb values that depend on the radix representation.
 */
static ge25519_p3 B;
static AMA_ATOMIC_INT B_initialized = 0;

static void ensure_base_point(void) {
    int state = AMA_ATOMIC_LOAD(B_initialized);

    if (state == AMA_INIT_READY) return;

    /* Try to claim the initializer role via CAS: UNINIT -> IN_PROGRESS.
     * Exactly one thread wins; all others spin-wait below. */
    if (state == AMA_INIT_UNINIT) {
        int expected = AMA_INIT_UNINIT;
        if (AMA_ATOMIC_CAS(B_initialized, expected, AMA_INIT_IN_PROGRESS)) {
            /* We are the sole initializer. Decompress into a local first,
             * then publish via memcpy + release store. */
            static const uint8_t base_compressed[32] = {
                0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            };
            ge25519_p3 B_local;
            int rc = ge25519_frombytes(&B_local, base_compressed);
            if (rc != 0) {
                /* Decompression failed (should never happen). Reset to UNINIT
                 * so another thread can retry. */
                AMA_ATOMIC_STORE(B_initialized, AMA_INIT_UNINIT);
                return;
            }
            memcpy(&B, &B_local, sizeof(ge25519_p3));

            /* Release store: B is fully written before flag becomes READY. */
            AMA_ATOMIC_STORE(B_initialized, AMA_INIT_READY);
            return;
        }
        /* CAS failed — another thread is initializing. Fall through to spin. */
    }

    /* Spin-wait until the initializer thread publishes READY. */
    while (AMA_ATOMIC_LOAD(B_initialized) != AMA_INIT_READY) {
        /* Busy-wait. This path is extremely short-lived (one-time init). */
    }
}

static void ge25519_p3_0(ge25519_p3 *h) {
    fe25519_0(h->X);
    fe25519_1(h->Y);
    fe25519_1(h->Z);
    fe25519_0(h->T);
}

static void ge25519_p3_tobytes(uint8_t *s, const ge25519_p3 *h) {
    fe25519 recip, x, y;
    fe25519_invert(recip, h->Z);
    fe25519_mul(x, h->X, recip);
    fe25519_mul(y, h->Y, recip);
    fe25519_tobytes(s, y);
    s[31] ^= fe25519_isnegative(x) << 7;
}

/*
 * Decompress a point from 32-byte compressed Edwards form.
 * Based on the SUPERCOP ref10 ge_frombytes_negate_vartime (without negation).
 *
 * Algorithm: given y (with sign bit for x), compute:
 *   u = y^2 - 1,  v = d*y^2 + 1
 *   x = (u*v^3) * (u*v^7)^((p-5)/8)
 * Then verify and adjust sign.
 */
static int ge25519_frombytes(ge25519_p3 *h, const uint8_t *s) {
    fe25519 u, v, v3, vxx, check;
    int x_sign = s[31] >> 7;

    fe25519_frombytes(h->Y, s);
    fe25519_1(h->Z);

    /* u = y^2 - 1, v = dy^2 + 1 */
    fe25519_sq(u, h->Y);
    fe25519_mul(v, u, d);
    fe25519_sub(u, u, h->Z);
    fe25519_add(v, v, h->Z);

    /* Compute v^3 = v*v*v and uv^7 = u*v^3*v^3*v */
    fe25519_sq(v3, v);
    fe25519_mul(v3, v3, v);       /* v3 = v^3 */

    fe25519_sq(h->X, v3);
    fe25519_mul(h->X, h->X, v);  /* X = v^7 */
    fe25519_mul(h->X, h->X, u);  /* X = u*v^7 */

    /* x = (u*v^7)^((p-5)/8) * u * v^3 */
    fe25519_pow22523(h->X, h->X); /* X = (u*v^7)^((p-5)/8) */
    fe25519_mul(h->X, h->X, v3); /* X *= v^3 */
    fe25519_mul(h->X, h->X, u);  /* X *= u => candidate x */

    /* Verify: check if v*x^2 == u */
    fe25519_sq(vxx, h->X);
    fe25519_mul(vxx, vxx, v);
    fe25519_sub(check, vxx, u);
    fe25519_carry(check);

    if (!fe25519_iszero(check)) {
        /* Check if v*x^2 == -u (need to multiply x by sqrt(-1)) */
        fe25519_add(check, vxx, u);
        fe25519_carry(check);
        if (!fe25519_iszero(check)) return -1;
        static const fe25519 sqrt_m1 = {
            -32595792, -7943725, 9377950, 3500415, 12389472,
            -272473, -25146209, -2005654, 326686, 11406482
        };
        fe25519_mul(h->X, h->X, sqrt_m1);
    }

    /* Adjust sign of x to match the sign bit */
    if (fe25519_isnegative(h->X) != x_sign) {
        fe25519_neg(h->X, h->X);
    }

    /* Compute T = X*Y for extended coordinates */
    fe25519_mul(h->T, h->X, h->Y);
    return 0;
}

/* p1p1 -> p2 */
static void ge25519_p1p1_to_p2(ge25519_p2 *r, const ge25519_p1p1 *p) {
    fe25519_mul(r->X, p->X, p->T);
    fe25519_mul(r->Y, p->Y, p->Z);
    fe25519_mul(r->Z, p->Z, p->T);
}

/* p1p1 -> p3 */
static void ge25519_p1p1_to_p3(ge25519_p3 *r, const ge25519_p1p1 *p) {
    fe25519_mul(r->X, p->X, p->T);
    fe25519_mul(r->Y, p->Y, p->Z);
    fe25519_mul(r->Z, p->Z, p->T);
    fe25519_mul(r->T, p->X, p->Y);
}

/* p2 -> p3 (extend) */
static void ge25519_p2_to_p3(ge25519_p3 *r, const ge25519_p2 *p) {
    fe25519_copy(r->X, p->X);
    fe25519_copy(r->Y, p->Y);
    fe25519_copy(r->Z, p->Z);
    fe25519_mul(r->T, p->X, p->Y);
}

/* Double: p2 -> p1p1 */
static void ge25519_p2_dbl(ge25519_p1p1 *r, const ge25519_p2 *p) {
    fe25519 t0;
    fe25519_sq(r->X, p->X);
    fe25519_sq(r->Z, p->Y);
    fe25519_sq(r->T, p->Z);
    fe25519_add(r->T, r->T, r->T);
    fe25519_add(r->Y, p->X, p->Y);
    fe25519_sq(t0, r->Y);
    fe25519_add(r->Y, r->Z, r->X);
    fe25519_sub(r->Z, r->Z, r->X);
    fe25519_sub(r->X, t0, r->Y);
    fe25519_sub(r->T, r->T, r->Z);
}

/* Add: p3 + precomp -> p1p1 */
static void ge25519_madd(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_precomp *q) {
    fe25519 t0;
    fe25519_add(r->X, p->Y, p->X);
    fe25519_sub(r->Y, p->Y, p->X);
    fe25519_mul(r->Z, r->X, q->yplusx);
    fe25519_mul(r->Y, r->Y, q->yminusx);
    fe25519_mul(r->T, q->xy2d, p->T);
    fe25519_add(t0, p->Z, p->Z);
    fe25519_sub(r->X, r->Z, r->Y);
    fe25519_add(r->Y, r->Z, r->Y);
    fe25519_add(r->Z, t0, r->T);
    fe25519_sub(r->T, t0, r->T);
}

/* Sub: p3 - precomp -> p1p1 */
static void ge25519_msub(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_precomp *q) {
    fe25519 t0;
    fe25519_add(r->X, p->Y, p->X);
    fe25519_sub(r->Y, p->Y, p->X);
    fe25519_mul(r->Z, r->X, q->yminusx);
    fe25519_mul(r->Y, r->Y, q->yplusx);
    fe25519_mul(r->T, q->xy2d, p->T);
    fe25519_add(t0, p->Z, p->Z);
    fe25519_sub(r->X, r->Z, r->Y);
    fe25519_add(r->Y, r->Z, r->Y);
    fe25519_sub(r->Z, t0, r->T);
    fe25519_add(r->T, t0, r->T);
}

/*
 * Add: p3 + p3 -> p1p1 (completed/factored form).
 *
 * Outputs the "completed" representation (E, H, G, F) that is converted
 * to extended coordinates by ge25519_p1p1_to_p3 via:
 *   X_ext = r->X * r->T = E*F
 *   Y_ext = r->Y * r->Z = H*G
 *   Z_ext = r->Z * r->T = G*F
 *   T_ext = r->X * r->Y = E*H
 *
 * Based on the SUPERCOP ref10 unified addition formula.
 */
static void ge25519_add(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_p3 *q) {
    fe25519 A, B, C, D, E, F, G, H;
    fe25519_sub(A, p->Y, p->X);
    fe25519_sub(B, q->Y, q->X);
    fe25519_mul(A, A, B);
    fe25519_add(B, p->Y, p->X);
    fe25519_add(C, q->Y, q->X);
    fe25519_mul(B, B, C);
    fe25519_mul(C, p->T, q->T);
    fe25519_mul(C, C, d2);
    fe25519_mul(D, p->Z, q->Z);
    fe25519_add(D, D, D);
    fe25519_sub(E, B, A);
    fe25519_sub(F, D, C);
    fe25519_add(G, D, C);
    fe25519_add(H, B, A);
    /* Output completed form: (E, H, G, F) — NOT the multiplied-out form */
    fe25519_copy(r->X, E);
    fe25519_copy(r->Y, H);
    fe25519_copy(r->Z, G);
    fe25519_copy(r->T, F);
}

/* Helper: p3 -> p2 projection (drops T coordinate) */
static inline void ge25519_p3_to_p2(ge25519_p2 *r, const ge25519_p3 *p) {
    fe25519_copy(r->X, p->X);
    fe25519_copy(r->Y, p->Y);
    fe25519_copy(r->Z, p->Z);
}

/* Scalar multiplication using double-and-add */
static void ge25519_scalarmult(ge25519_p3 *r, const uint8_t *scalar, const ge25519_p3 *p) {
    ge25519_p3 Q;
    ge25519_p1p1 t;
    ge25519_p2 p2;
    int i;

    ge25519_p3_0(&Q);

    for (i = 255; i >= 0; i--) {
        int bit = (scalar[i >> 3] >> (i & 7)) & 1;

        /* Q = 2*Q */
        ge25519_p3_to_p2(&p2, &Q);
        ge25519_p2_dbl(&t, &p2);
        ge25519_p1p1_to_p3(&Q, &t);

        /* Q = Q + P if bit is set */
        if (bit) {
            ge25519_add(&t, &Q, p);
            ge25519_p1p1_to_p3(&Q, &t);
        }
    }

    memcpy(r, &Q, sizeof(ge25519_p3));
}

/* ============================================================================
 * OPTIMIZED BASE POINT MULTIPLICATION
 * Uses 4-bit windowed method with precomputed table for 2-3x speedup
 * ============================================================================ */

/* Precomputed table: table[i] = (i+1)*B for i in [0,15] */
static ge25519_p3 ge_base_table[16];
static AMA_ATOMIC_INT ge_base_table_ready = 0;

/* Initialize precomputed basepoint table.
 * Thread-safe via CAS tri-state: only one thread computes, others spin-wait. */
static void ge25519_init_base_table(void) {
    int state = AMA_ATOMIC_LOAD(ge_base_table_ready);

    if (state == AMA_INIT_READY) return;

    if (state == AMA_INIT_UNINIT) {
        int expected = AMA_INIT_UNINIT;
        if (AMA_ATOMIC_CAS(ge_base_table_ready, expected, AMA_INIT_IN_PROGRESS)) {
            /* Sole initializer thread. */
            ensure_base_point();

            /* Compute into local table first, then publish */
            ge25519_p3 local_table[16];
            ge25519_p1p1 t;

            /* table[0] = 1*B */
            memcpy(&local_table[0], &B, sizeof(ge25519_p3));

            /* table[i] = (i+1)*B = table[i-1] + B */
            for (int i = 1; i < 16; i++) {
                ge25519_add(&t, &local_table[i-1], &B);
                ge25519_p1p1_to_p3(&local_table[i], &t);
            }

            memcpy(ge_base_table, local_table, sizeof(ge_base_table));
            AMA_ATOMIC_STORE(ge_base_table_ready, AMA_INIT_READY);
            return;
        }
    }

    /* Spin-wait until the initializer thread publishes READY. */
    while (AMA_ATOMIC_LOAD(ge_base_table_ready) != AMA_INIT_READY) {
        /* Busy-wait. One-time cost during first use. */
    }
}

/* Constant-time conditional move: r = (flag ? p : r).
 * flag MUST be 0 or 1. No branching on flag. */
static void ge25519_cmov(ge25519_p3 *r, const ge25519_p3 *p, int flag) {
    int64_t mask = -(int64_t)flag;
    for (int j = 0; j < 10; j++) {
        r->X[j] ^= mask & (r->X[j] ^ p->X[j]);
        r->Y[j] ^= mask & (r->Y[j] ^ p->Y[j]);
        r->Z[j] ^= mask & (r->Z[j] ^ p->Z[j]);
        r->T[j] ^= mask & (r->T[j] ^ p->T[j]);
    }
}

/* Optimized base point multiplication using 4-bit windows (constant-time)
 *
 * Algorithm:
 * 1. Write scalar s in radix-16: s = sum(s_i * 16^i) where s_i in [0,15]
 * 2. Result = sum(s_i * 16^i * B) = sum(table[s_i-1] * 16^i) for s_i > 0
 * 3. Use Horner's method: (((...)*16 + s_63)*16 + s_62)*16 + ...
 *
 * Constant-time properties:
 * - Table lookup is always performed (constant-time scan of all 16 entries)
 * - Addition is always performed; when nibble == 0, the identity is selected
 *   from the table and the result is conditionally discarded via cmov
 * - No secret-dependent branches: work per nibble is identical regardless
 *   of scalar value
 *
 * This reduces 256 doublings + ~128 additions to 252 doublings + 64 additions
 */
static void ge25519_scalarmult_base_windowed(ge25519_p3 *r, const uint8_t *scalar) {
    ge25519_p3 Q, P, Q_after_add;
    ge25519_p1p1 t;
    ge25519_p2 p2;
    int i;

    /* Ensure table is initialized */
    ge25519_init_base_table();

    /* Start with identity */
    ge25519_p3_0(&Q);

    /* Process from most significant nibble */
    for (i = 63; i >= 0; i--) {
        /* Q = 16*Q (4 doublings) */
        for (int j = 0; j < 4; j++) {
            ge25519_p3_to_p2(&p2, &Q);
            ge25519_p2_dbl(&t, &p2);
            ge25519_p1p1_to_p3(&Q, &t);
        }

        /* Get 4-bit nibble (big-endian nibble order) */
        int byte_idx = i / 2;
        int nibble = (i & 1) ? (scalar[byte_idx] >> 4) : (scalar[byte_idx] & 0x0F);

        /* Constant-time: always look up and always add.
         * When nibble == 0, ge25519_table_lookup selects the identity
         * (since no table entry matches, r stays as identity from ge25519_p3_0).
         * We compute Q + P unconditionally, then use cmov to select the
         * result only when nibble != 0. This eliminates the secret-dependent
         * branch that would leak scalar nibble values via timing. */

        /* Select table[nibble-1] when nibble > 0, identity when nibble == 0 */
        int lookup_idx = nibble - 1;  /* -1 when nibble==0; no table entry matches */
        ge25519_p3_0(&P);
        for (int k = 0; k < 16; k++) {
            /* Branchless equality: mask = all-ones when k == lookup_idx, else 0.
             * Uses arithmetic to avoid compiler-generated branches on secret data. */
            unsigned int diff = (unsigned int)(k ^ lookup_idx);
            int64_t mask = -(int64_t)(1 & ((diff - 1) >> 31));
            for (int j = 0; j < 10; j++) {
                P.X[j] ^= mask & (P.X[j] ^ ge_base_table[k].X[j]);
                P.Y[j] ^= mask & (P.Y[j] ^ ge_base_table[k].Y[j]);
                P.Z[j] ^= mask & (P.Z[j] ^ ge_base_table[k].Z[j]);
                P.T[j] ^= mask & (P.T[j] ^ ge_base_table[k].T[j]);
            }
        }
        /* When nibble==0, P is the identity (0,1,1,0). Adding identity is
         * not free in extended coordinates, so we always compute the addition
         * but conditionally keep the result. */
        ge25519_add(&t, &Q, &P);
        ge25519_p1p1_to_p3(&Q_after_add, &t);

        /* Constant-time select: Q = (nibble != 0) ? Q_after_add : Q
         * The scalar nibble is secret (derived from SHA-512 of private seed),
         * so we must avoid any branch on its value. */
        int select = (int)(((unsigned int)(-nibble) | (unsigned int)nibble) >> 31);
        ge25519_cmov(&Q, &Q_after_add, select);
    }

    memcpy(r, &Q, sizeof(ge25519_p3));
}

/* Base point multiplication - use optimized windowed version */
static void ge25519_scalarmult_base(ge25519_p3 *r, const uint8_t *scalar) {
    ge25519_scalarmult_base_windowed(r, scalar);
}

/* ============================================================================
 * SCALAR ARITHMETIC: mod L where L is the group order
 * ============================================================================ */

/*
 * Reduce a 64-byte (512-bit) scalar mod L.
 * L = 2^252 + 27742317777372353535851937790883648493
 * Based on the SUPERCOP ref10 sc_reduce implementation.
 * Input: 64-byte SHA-512 hash. Output: 32-byte reduced scalar (in-place).
 */
static void sc25519_reduce(uint8_t *s) {
    /*
     * Load all 64 bytes into 24 limbs of 21 bits each.
     * Uses load_3/load_4 helpers with ref10 byte offsets.
     * Each limb starts at bit position i*21, which falls at byte floor(i*21/8)
     * with bit offset (i*21) mod 8.
     */
    int64_t s0 = 2097151 & load_3(s + 0);
    int64_t s1 = 2097151 & (load_4(s + 2) >> 5);
    int64_t s2 = 2097151 & (load_3(s + 5) >> 2);
    int64_t s3 = 2097151 & (load_4(s + 7) >> 7);
    int64_t s4 = 2097151 & (load_4(s + 10) >> 4);
    int64_t s5 = 2097151 & (load_3(s + 13) >> 1);
    int64_t s6 = 2097151 & (load_4(s + 15) >> 6);
    int64_t s7 = 2097151 & (load_4(s + 18) >> 3);
    int64_t s8 = 2097151 & load_3(s + 21);
    int64_t s9 = 2097151 & (load_4(s + 23) >> 5);
    int64_t s10 = 2097151 & (load_3(s + 26) >> 2);
    int64_t s11 = 2097151 & (load_4(s + 28) >> 7);
    int64_t s12 = 2097151 & (load_4(s + 31) >> 4);
    int64_t s13 = 2097151 & (load_3(s + 34) >> 1);
    int64_t s14 = 2097151 & (load_4(s + 36) >> 6);
    int64_t s15 = 2097151 & (load_4(s + 39) >> 3);
    int64_t s16 = 2097151 & load_3(s + 42);
    int64_t s17 = 2097151 & (load_4(s + 44) >> 5);
    int64_t s18 = 2097151 & (load_3(s + 47) >> 2);
    int64_t s19 = 2097151 & (load_4(s + 49) >> 7);
    int64_t s20 = 2097151 & (load_4(s + 52) >> 4);
    int64_t s21 = 2097151 & (load_3(s + 55) >> 1);
    int64_t s22 = 2097151 & (load_4(s + 57) >> 6);
    int64_t s23 = (load_4(s + 60) >> 3);

    int64_t carry;

    /* First pass: reduce s23..s18 into s11..s16 range */
    s11 += s23 * 666643; s12 += s23 * 470296; s13 += s23 * 654183;
    s14 -= s23 * 997805; s15 += s23 * 136657; s16 -= s23 * 683901;
    s23 = 0;

    s10 += s22 * 666643; s11 += s22 * 470296; s12 += s22 * 654183;
    s13 -= s22 * 997805; s14 += s22 * 136657; s15 -= s22 * 683901;
    s22 = 0;

    s9 += s21 * 666643; s10 += s21 * 470296; s11 += s21 * 654183;
    s12 -= s21 * 997805; s13 += s21 * 136657; s14 -= s21 * 683901;
    s21 = 0;

    s8 += s20 * 666643; s9 += s20 * 470296; s10 += s20 * 654183;
    s11 -= s20 * 997805; s12 += s20 * 136657; s13 -= s20 * 683901;
    s20 = 0;

    s7 += s19 * 666643; s8 += s19 * 470296; s9 += s19 * 654183;
    s10 -= s19 * 997805; s11 += s19 * 136657; s12 -= s19 * 683901;
    s19 = 0;

    s6 += s18 * 666643; s7 += s18 * 470296; s8 += s18 * 654183;
    s9 -= s18 * 997805; s10 += s18 * 136657; s11 -= s18 * 683901;
    s18 = 0;

    /* Carry propagation (first round) */
    carry = (s6 + (1 << 20)) >> 21; s7 += carry; s6 -= carry << 21;
    carry = (s8 + (1 << 20)) >> 21; s9 += carry; s8 -= carry << 21;
    carry = (s10 + (1 << 20)) >> 21; s11 += carry; s10 -= carry << 21;
    carry = (s12 + (1 << 20)) >> 21; s13 += carry; s12 -= carry << 21;
    carry = (s14 + (1 << 20)) >> 21; s15 += carry; s14 -= carry << 21;
    carry = (s16 + (1 << 20)) >> 21; s17 += carry; s16 -= carry << 21;

    carry = (s7 + (1 << 20)) >> 21; s8 += carry; s7 -= carry << 21;
    carry = (s9 + (1 << 20)) >> 21; s10 += carry; s9 -= carry << 21;
    carry = (s11 + (1 << 20)) >> 21; s12 += carry; s11 -= carry << 21;
    carry = (s13 + (1 << 20)) >> 21; s14 += carry; s13 -= carry << 21;
    carry = (s15 + (1 << 20)) >> 21; s16 += carry; s15 -= carry << 21;

    /* Second pass: reduce s17..s12 into s5..s10 range */
    s5 += s17 * 666643; s6 += s17 * 470296; s7 += s17 * 654183;
    s8 -= s17 * 997805; s9 += s17 * 136657; s10 -= s17 * 683901;
    s17 = 0;

    s4 += s16 * 666643; s5 += s16 * 470296; s6 += s16 * 654183;
    s7 -= s16 * 997805; s8 += s16 * 136657; s9 -= s16 * 683901;
    s16 = 0;

    s3 += s15 * 666643; s4 += s15 * 470296; s5 += s15 * 654183;
    s6 -= s15 * 997805; s7 += s15 * 136657; s8 -= s15 * 683901;
    s15 = 0;

    s2 += s14 * 666643; s3 += s14 * 470296; s4 += s14 * 654183;
    s5 -= s14 * 997805; s6 += s14 * 136657; s7 -= s14 * 683901;
    s14 = 0;

    s1 += s13 * 666643; s2 += s13 * 470296; s3 += s13 * 654183;
    s4 -= s13 * 997805; s5 += s13 * 136657; s6 -= s13 * 683901;
    s13 = 0;

    s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183;
    s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
    s12 = 0;

    /* Carry propagation — interleaved evens then odds (ref10 pattern) */
    carry = (s0 + (1 << 20)) >> 21; s1 += carry; s0 -= carry << 21;
    carry = (s2 + (1 << 20)) >> 21; s3 += carry; s2 -= carry << 21;
    carry = (s4 + (1 << 20)) >> 21; s5 += carry; s4 -= carry << 21;
    carry = (s6 + (1 << 20)) >> 21; s7 += carry; s6 -= carry << 21;
    carry = (s8 + (1 << 20)) >> 21; s9 += carry; s8 -= carry << 21;
    carry = (s10 + (1 << 20)) >> 21; s11 += carry; s10 -= carry << 21;

    carry = (s1 + (1 << 20)) >> 21; s2 += carry; s1 -= carry << 21;
    carry = (s3 + (1 << 20)) >> 21; s4 += carry; s3 -= carry << 21;
    carry = (s5 + (1 << 20)) >> 21; s6 += carry; s5 -= carry << 21;
    carry = (s7 + (1 << 20)) >> 21; s8 += carry; s7 -= carry << 21;
    carry = (s9 + (1 << 20)) >> 21; s10 += carry; s9 -= carry << 21;
    carry = (s11 + (1 << 20)) >> 21; s12 += carry; s11 -= carry << 21;

    /* Reduce s12 overflow via L coefficients */
    s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183;
    s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
    s12 = 0;

    /* Sequential carry using floor division (>> 21) */
    carry = s0 >> 21; s1 += carry; s0 -= carry << 21;
    carry = s1 >> 21; s2 += carry; s1 -= carry << 21;
    carry = s2 >> 21; s3 += carry; s2 -= carry << 21;
    carry = s3 >> 21; s4 += carry; s3 -= carry << 21;
    carry = s4 >> 21; s5 += carry; s4 -= carry << 21;
    carry = s5 >> 21; s6 += carry; s5 -= carry << 21;
    carry = s6 >> 21; s7 += carry; s6 -= carry << 21;
    carry = s7 >> 21; s8 += carry; s7 -= carry << 21;
    carry = s8 >> 21; s9 += carry; s8 -= carry << 21;
    carry = s9 >> 21; s10 += carry; s9 -= carry << 21;
    carry = s10 >> 21; s11 += carry; s10 -= carry << 21;
    carry = s11 >> 21; s12 += carry; s11 -= carry << 21;

    /* Second s12 wrap-around */
    s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183;
    s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
    s12 = 0;

    /* Final sequential carry */
    carry = s0 >> 21; s1 += carry; s0 -= carry << 21;
    carry = s1 >> 21; s2 += carry; s1 -= carry << 21;
    carry = s2 >> 21; s3 += carry; s2 -= carry << 21;
    carry = s3 >> 21; s4 += carry; s3 -= carry << 21;
    carry = s4 >> 21; s5 += carry; s4 -= carry << 21;
    carry = s5 >> 21; s6 += carry; s5 -= carry << 21;
    carry = s6 >> 21; s7 += carry; s6 -= carry << 21;
    carry = s7 >> 21; s8 += carry; s7 -= carry << 21;
    carry = s8 >> 21; s9 += carry; s8 -= carry << 21;
    carry = s9 >> 21; s10 += carry; s9 -= carry << 21;
    carry = s10 >> 21; s11 += carry; s10 -= carry << 21;

    /* Pack 12 limbs into 32 bytes */
    s[0] = (uint8_t)(s0 >> 0);
    s[1] = (uint8_t)(s0 >> 8);
    s[2] = (uint8_t)((s0 >> 16) | (s1 << 5));
    s[3] = (uint8_t)(s1 >> 3);
    s[4] = (uint8_t)(s1 >> 11);
    s[5] = (uint8_t)((s1 >> 19) | (s2 << 2));
    s[6] = (uint8_t)(s2 >> 6);
    s[7] = (uint8_t)((s2 >> 14) | (s3 << 7));
    s[8] = (uint8_t)(s3 >> 1);
    s[9] = (uint8_t)(s3 >> 9);
    s[10] = (uint8_t)((s3 >> 17) | (s4 << 4));
    s[11] = (uint8_t)(s4 >> 4);
    s[12] = (uint8_t)(s4 >> 12);
    s[13] = (uint8_t)((s4 >> 20) | (s5 << 1));
    s[14] = (uint8_t)(s5 >> 7);
    s[15] = (uint8_t)((s5 >> 15) | (s6 << 6));
    s[16] = (uint8_t)(s6 >> 2);
    s[17] = (uint8_t)(s6 >> 10);
    s[18] = (uint8_t)((s6 >> 18) | (s7 << 3));
    s[19] = (uint8_t)(s7 >> 5);
    s[20] = (uint8_t)(s7 >> 13);
    s[21] = (uint8_t)(s8 >> 0);
    s[22] = (uint8_t)(s8 >> 8);
    s[23] = (uint8_t)((s8 >> 16) | (s9 << 5));
    s[24] = (uint8_t)(s9 >> 3);
    s[25] = (uint8_t)(s9 >> 11);
    s[26] = (uint8_t)((s9 >> 19) | (s10 << 2));
    s[27] = (uint8_t)(s10 >> 6);
    s[28] = (uint8_t)((s10 >> 14) | (s11 << 7));
    s[29] = (uint8_t)(s11 >> 1);
    s[30] = (uint8_t)(s11 >> 9);
    s[31] = (uint8_t)(s11 >> 17);
}

/* Compute s = a + b*c mod L */
static void sc25519_muladd(uint8_t *s, const uint8_t *a, const uint8_t *b, const uint8_t *c) {
    /* Load 32-byte inputs into 12 limbs of 21 bits each using ref10 byte offsets */
    int64_t a0 = 2097151 & load_3(a + 0);
    int64_t a1 = 2097151 & (load_4(a + 2) >> 5);
    int64_t a2 = 2097151 & (load_3(a + 5) >> 2);
    int64_t a3 = 2097151 & (load_4(a + 7) >> 7);
    int64_t a4 = 2097151 & (load_4(a + 10) >> 4);
    int64_t a5 = 2097151 & (load_3(a + 13) >> 1);
    int64_t a6 = 2097151 & (load_4(a + 15) >> 6);
    int64_t a7 = 2097151 & (load_4(a + 18) >> 3);
    int64_t a8 = 2097151 & load_3(a + 21);
    int64_t a9 = 2097151 & (load_4(a + 23) >> 5);
    int64_t a10 = 2097151 & (load_3(a + 26) >> 2);
    int64_t a11 = (load_4(a + 28) >> 7);

    int64_t b0 = 2097151 & load_3(b + 0);
    int64_t b1 = 2097151 & (load_4(b + 2) >> 5);
    int64_t b2 = 2097151 & (load_3(b + 5) >> 2);
    int64_t b3 = 2097151 & (load_4(b + 7) >> 7);
    int64_t b4 = 2097151 & (load_4(b + 10) >> 4);
    int64_t b5 = 2097151 & (load_3(b + 13) >> 1);
    int64_t b6 = 2097151 & (load_4(b + 15) >> 6);
    int64_t b7 = 2097151 & (load_4(b + 18) >> 3);
    int64_t b8 = 2097151 & load_3(b + 21);
    int64_t b9 = 2097151 & (load_4(b + 23) >> 5);
    int64_t b10 = 2097151 & (load_3(b + 26) >> 2);
    int64_t b11 = (load_4(b + 28) >> 7);

    int64_t c0 = 2097151 & load_3(c + 0);
    int64_t c1 = 2097151 & (load_4(c + 2) >> 5);
    int64_t c2 = 2097151 & (load_3(c + 5) >> 2);
    int64_t c3 = 2097151 & (load_4(c + 7) >> 7);
    int64_t c4 = 2097151 & (load_4(c + 10) >> 4);
    int64_t c5 = 2097151 & (load_3(c + 13) >> 1);
    int64_t c6 = 2097151 & (load_4(c + 15) >> 6);
    int64_t c7 = 2097151 & (load_4(c + 18) >> 3);
    int64_t c8 = 2097151 & load_3(c + 21);
    int64_t c9 = 2097151 & (load_4(c + 23) >> 5);
    int64_t c10 = 2097151 & (load_3(c + 26) >> 2);
    int64_t c11 = (load_4(c + 28) >> 7);

    /* s = a + b*c */
    int64_t s0 = a0 + b0*c0;
    int64_t s1 = a1 + b0*c1 + b1*c0;
    int64_t s2 = a2 + b0*c2 + b1*c1 + b2*c0;
    int64_t s3 = a3 + b0*c3 + b1*c2 + b2*c1 + b3*c0;
    int64_t s4 = a4 + b0*c4 + b1*c3 + b2*c2 + b3*c1 + b4*c0;
    int64_t s5 = a5 + b0*c5 + b1*c4 + b2*c3 + b3*c2 + b4*c1 + b5*c0;
    int64_t s6 = a6 + b0*c6 + b1*c5 + b2*c4 + b3*c3 + b4*c2 + b5*c1 + b6*c0;
    int64_t s7 = a7 + b0*c7 + b1*c6 + b2*c5 + b3*c4 + b4*c3 + b5*c2 + b6*c1 + b7*c0;
    int64_t s8 = a8 + b0*c8 + b1*c7 + b2*c6 + b3*c5 + b4*c4 + b5*c3 + b6*c2 + b7*c1 + b8*c0;
    int64_t s9 = a9 + b0*c9 + b1*c8 + b2*c7 + b3*c6 + b4*c5 + b5*c4 + b6*c3 + b7*c2 + b8*c1 + b9*c0;
    int64_t s10 = a10 + b0*c10 + b1*c9 + b2*c8 + b3*c7 + b4*c6 + b5*c5 + b6*c4 + b7*c3 + b8*c2 + b9*c1 + b10*c0;
    int64_t s11 = a11 + b0*c11 + b1*c10 + b2*c9 + b3*c8 + b4*c7 + b5*c6 + b6*c5 + b7*c4 + b8*c3 + b9*c2 + b10*c1 + b11*c0;
    int64_t s12 = b1*c11 + b2*c10 + b3*c9 + b4*c8 + b5*c7 + b6*c6 + b7*c5 + b8*c4 + b9*c3 + b10*c2 + b11*c1;
    int64_t s13 = b2*c11 + b3*c10 + b4*c9 + b5*c8 + b6*c7 + b7*c6 + b8*c5 + b9*c4 + b10*c3 + b11*c2;
    int64_t s14 = b3*c11 + b4*c10 + b5*c9 + b6*c8 + b7*c7 + b8*c6 + b9*c5 + b10*c4 + b11*c3;
    int64_t s15 = b4*c11 + b5*c10 + b6*c9 + b7*c8 + b8*c7 + b9*c6 + b10*c5 + b11*c4;
    int64_t s16 = b5*c11 + b6*c10 + b7*c9 + b8*c8 + b9*c7 + b10*c6 + b11*c5;
    int64_t s17 = b6*c11 + b7*c10 + b8*c9 + b9*c8 + b10*c7 + b11*c6;
    int64_t s18 = b7*c11 + b8*c10 + b9*c9 + b10*c8 + b11*c7;
    int64_t s19 = b8*c11 + b9*c10 + b10*c9 + b11*c8;
    int64_t s20 = b9*c11 + b10*c10 + b11*c9;
    int64_t s21 = b10*c11 + b11*c10;
    int64_t s22 = b11*c11;
    int64_t s23 = 0;

    int64_t carry;

    /* Reduce mod L */
    carry = (s0 + (1 << 20)) >> 21; s1 += carry; s0 -= carry << 21;
    carry = (s2 + (1 << 20)) >> 21; s3 += carry; s2 -= carry << 21;
    carry = (s4 + (1 << 20)) >> 21; s5 += carry; s4 -= carry << 21;
    carry = (s6 + (1 << 20)) >> 21; s7 += carry; s6 -= carry << 21;
    carry = (s8 + (1 << 20)) >> 21; s9 += carry; s8 -= carry << 21;
    carry = (s10 + (1 << 20)) >> 21; s11 += carry; s10 -= carry << 21;
    carry = (s12 + (1 << 20)) >> 21; s13 += carry; s12 -= carry << 21;
    carry = (s14 + (1 << 20)) >> 21; s15 += carry; s14 -= carry << 21;
    carry = (s16 + (1 << 20)) >> 21; s17 += carry; s16 -= carry << 21;
    carry = (s18 + (1 << 20)) >> 21; s19 += carry; s18 -= carry << 21;
    carry = (s20 + (1 << 20)) >> 21; s21 += carry; s20 -= carry << 21;
    carry = (s22 + (1 << 20)) >> 21; s23 += carry; s22 -= carry << 21;

    carry = (s1 + (1 << 20)) >> 21; s2 += carry; s1 -= carry << 21;
    carry = (s3 + (1 << 20)) >> 21; s4 += carry; s3 -= carry << 21;
    carry = (s5 + (1 << 20)) >> 21; s6 += carry; s5 -= carry << 21;
    carry = (s7 + (1 << 20)) >> 21; s8 += carry; s7 -= carry << 21;
    carry = (s9 + (1 << 20)) >> 21; s10 += carry; s9 -= carry << 21;
    carry = (s11 + (1 << 20)) >> 21; s12 += carry; s11 -= carry << 21;
    carry = (s13 + (1 << 20)) >> 21; s14 += carry; s13 -= carry << 21;
    carry = (s15 + (1 << 20)) >> 21; s16 += carry; s15 -= carry << 21;
    carry = (s17 + (1 << 20)) >> 21; s18 += carry; s17 -= carry << 21;
    carry = (s19 + (1 << 20)) >> 21; s20 += carry; s19 -= carry << 21;
    carry = (s21 + (1 << 20)) >> 21; s22 += carry; s21 -= carry << 21;

    /* Reduce high limbs */
    s11 += s23 * 666643; s12 += s23 * 470296; s13 += s23 * 654183;
    s14 -= s23 * 997805; s15 += s23 * 136657; s16 -= s23 * 683901;
    s23 = 0;

    s10 += s22 * 666643; s11 += s22 * 470296; s12 += s22 * 654183;
    s13 -= s22 * 997805; s14 += s22 * 136657; s15 -= s22 * 683901;
    s22 = 0;

    s9 += s21 * 666643; s10 += s21 * 470296; s11 += s21 * 654183;
    s12 -= s21 * 997805; s13 += s21 * 136657; s14 -= s21 * 683901;
    s21 = 0;

    s8 += s20 * 666643; s9 += s20 * 470296; s10 += s20 * 654183;
    s11 -= s20 * 997805; s12 += s20 * 136657; s13 -= s20 * 683901;
    s20 = 0;

    s7 += s19 * 666643; s8 += s19 * 470296; s9 += s19 * 654183;
    s10 -= s19 * 997805; s11 += s19 * 136657; s12 -= s19 * 683901;
    s19 = 0;

    s6 += s18 * 666643; s7 += s18 * 470296; s8 += s18 * 654183;
    s9 -= s18 * 997805; s10 += s18 * 136657; s11 -= s18 * 683901;
    s18 = 0;

    carry = (s6 + (1 << 20)) >> 21; s7 += carry; s6 -= carry << 21;
    carry = (s8 + (1 << 20)) >> 21; s9 += carry; s8 -= carry << 21;
    carry = (s10 + (1 << 20)) >> 21; s11 += carry; s10 -= carry << 21;
    carry = (s12 + (1 << 20)) >> 21; s13 += carry; s12 -= carry << 21;
    carry = (s14 + (1 << 20)) >> 21; s15 += carry; s14 -= carry << 21;
    carry = (s16 + (1 << 20)) >> 21; s17 += carry; s16 -= carry << 21;

    carry = (s7 + (1 << 20)) >> 21; s8 += carry; s7 -= carry << 21;
    carry = (s9 + (1 << 20)) >> 21; s10 += carry; s9 -= carry << 21;
    carry = (s11 + (1 << 20)) >> 21; s12 += carry; s11 -= carry << 21;
    carry = (s13 + (1 << 20)) >> 21; s14 += carry; s13 -= carry << 21;
    carry = (s15 + (1 << 20)) >> 21; s16 += carry; s15 -= carry << 21;

    s5 += s17 * 666643; s6 += s17 * 470296; s7 += s17 * 654183;
    s8 -= s17 * 997805; s9 += s17 * 136657; s10 -= s17 * 683901;
    s17 = 0;

    s4 += s16 * 666643; s5 += s16 * 470296; s6 += s16 * 654183;
    s7 -= s16 * 997805; s8 += s16 * 136657; s9 -= s16 * 683901;
    s16 = 0;

    s3 += s15 * 666643; s4 += s15 * 470296; s5 += s15 * 654183;
    s6 -= s15 * 997805; s7 += s15 * 136657; s8 -= s15 * 683901;
    s15 = 0;

    s2 += s14 * 666643; s3 += s14 * 470296; s4 += s14 * 654183;
    s5 -= s14 * 997805; s6 += s14 * 136657; s7 -= s14 * 683901;
    s14 = 0;

    s1 += s13 * 666643; s2 += s13 * 470296; s3 += s13 * 654183;
    s4 -= s13 * 997805; s5 += s13 * 136657; s6 -= s13 * 683901;
    s13 = 0;

    s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183;
    s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
    s12 = 0;

    /* Carry propagation — interleaved evens then odds (ref10 pattern) */
    carry = (s0 + (1 << 20)) >> 21; s1 += carry; s0 -= carry << 21;
    carry = (s2 + (1 << 20)) >> 21; s3 += carry; s2 -= carry << 21;
    carry = (s4 + (1 << 20)) >> 21; s5 += carry; s4 -= carry << 21;
    carry = (s6 + (1 << 20)) >> 21; s7 += carry; s6 -= carry << 21;
    carry = (s8 + (1 << 20)) >> 21; s9 += carry; s8 -= carry << 21;
    carry = (s10 + (1 << 20)) >> 21; s11 += carry; s10 -= carry << 21;

    carry = (s1 + (1 << 20)) >> 21; s2 += carry; s1 -= carry << 21;
    carry = (s3 + (1 << 20)) >> 21; s4 += carry; s3 -= carry << 21;
    carry = (s5 + (1 << 20)) >> 21; s6 += carry; s5 -= carry << 21;
    carry = (s7 + (1 << 20)) >> 21; s8 += carry; s7 -= carry << 21;
    carry = (s9 + (1 << 20)) >> 21; s10 += carry; s9 -= carry << 21;
    carry = (s11 + (1 << 20)) >> 21; s12 += carry; s11 -= carry << 21;

    /* Reduce s12 overflow via L coefficients */
    s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183;
    s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
    s12 = 0;

    /* Sequential carry using floor division (>> 21) */
    carry = s0 >> 21; s1 += carry; s0 -= carry << 21;
    carry = s1 >> 21; s2 += carry; s1 -= carry << 21;
    carry = s2 >> 21; s3 += carry; s2 -= carry << 21;
    carry = s3 >> 21; s4 += carry; s3 -= carry << 21;
    carry = s4 >> 21; s5 += carry; s4 -= carry << 21;
    carry = s5 >> 21; s6 += carry; s5 -= carry << 21;
    carry = s6 >> 21; s7 += carry; s6 -= carry << 21;
    carry = s7 >> 21; s8 += carry; s7 -= carry << 21;
    carry = s8 >> 21; s9 += carry; s8 -= carry << 21;
    carry = s9 >> 21; s10 += carry; s9 -= carry << 21;
    carry = s10 >> 21; s11 += carry; s10 -= carry << 21;
    carry = s11 >> 21; s12 += carry; s11 -= carry << 21;

    /* Second s12 wrap-around */
    s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183;
    s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
    s12 = 0;

    /* Final sequential carry */
    carry = s0 >> 21; s1 += carry; s0 -= carry << 21;
    carry = s1 >> 21; s2 += carry; s1 -= carry << 21;
    carry = s2 >> 21; s3 += carry; s2 -= carry << 21;
    carry = s3 >> 21; s4 += carry; s3 -= carry << 21;
    carry = s4 >> 21; s5 += carry; s4 -= carry << 21;
    carry = s5 >> 21; s6 += carry; s5 -= carry << 21;
    carry = s6 >> 21; s7 += carry; s6 -= carry << 21;
    carry = s7 >> 21; s8 += carry; s7 -= carry << 21;
    carry = s8 >> 21; s9 += carry; s8 -= carry << 21;
    carry = s9 >> 21; s10 += carry; s9 -= carry << 21;
    carry = s10 >> 21; s11 += carry; s10 -= carry << 21;

    /* Pack 12 limbs into 32 bytes */
    s[0] = (uint8_t)(s0 >> 0);
    s[1] = (uint8_t)(s0 >> 8);
    s[2] = (uint8_t)((s0 >> 16) | (s1 << 5));
    s[3] = (uint8_t)(s1 >> 3);
    s[4] = (uint8_t)(s1 >> 11);
    s[5] = (uint8_t)((s1 >> 19) | (s2 << 2));
    s[6] = (uint8_t)(s2 >> 6);
    s[7] = (uint8_t)((s2 >> 14) | (s3 << 7));
    s[8] = (uint8_t)(s3 >> 1);
    s[9] = (uint8_t)(s3 >> 9);
    s[10] = (uint8_t)((s3 >> 17) | (s4 << 4));
    s[11] = (uint8_t)(s4 >> 4);
    s[12] = (uint8_t)(s4 >> 12);
    s[13] = (uint8_t)((s4 >> 20) | (s5 << 1));
    s[14] = (uint8_t)(s5 >> 7);
    s[15] = (uint8_t)((s5 >> 15) | (s6 << 6));
    s[16] = (uint8_t)(s6 >> 2);
    s[17] = (uint8_t)(s6 >> 10);
    s[18] = (uint8_t)((s6 >> 18) | (s7 << 3));
    s[19] = (uint8_t)(s7 >> 5);
    s[20] = (uint8_t)(s7 >> 13);
    s[21] = (uint8_t)(s8 >> 0);
    s[22] = (uint8_t)(s8 >> 8);
    s[23] = (uint8_t)((s8 >> 16) | (s9 << 5));
    s[24] = (uint8_t)(s9 >> 3);
    s[25] = (uint8_t)(s9 >> 11);
    s[26] = (uint8_t)((s9 >> 19) | (s10 << 2));
    s[27] = (uint8_t)(s10 >> 6);
    s[28] = (uint8_t)((s10 >> 14) | (s11 << 7));
    s[29] = (uint8_t)(s11 >> 1);
    s[30] = (uint8_t)(s11 >> 9);
    s[31] = (uint8_t)(s11 >> 17);
}

/* ============================================================================
 * ED25519 API FUNCTIONS
 * ============================================================================ */

/**
 * Generate Ed25519 keypair
 *
 * @param public_key Output: 32-byte public key
 * @param secret_key Output: 64-byte secret key (seed || public_key)
 * @return AMA_SUCCESS or error code
 */
ama_error_t ama_ed25519_keypair(uint8_t public_key[32], uint8_t secret_key[64]) {
    uint8_t hash[64];
    ge25519_p3 A;

    if (!public_key || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Generate random seed (first 32 bytes of secret_key) */
    /* NOTE: In production, use a cryptographic RNG */
    /* For now, we require the caller to provide entropy in secret_key[0..31] */

    /* Hash the seed */
    sha512(secret_key, 32, hash);

    /* Clamp the scalar */
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;

    /* Compute public key: A = s*B */
    ge25519_scalarmult_base(&A, hash);
    ge25519_p3_tobytes(public_key, &A);

    /* Store public key in secret_key[32..63] */
    memcpy(secret_key + 32, public_key, 32);

    /* Scrub intermediate values */
    ama_secure_memzero(hash, sizeof(hash));

    return AMA_SUCCESS;
}

/**
 * Sign a message with Ed25519
 *
 * @param signature Output: 64-byte signature
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key 64-byte secret key
 * @return AMA_SUCCESS or error code
 */
ama_error_t ama_ed25519_sign(
    uint8_t signature[64],
    const uint8_t *message,
    size_t message_len,
    const uint8_t secret_key[64]
) {
    uint8_t hash[64];
    uint8_t r[64];
    uint8_t hram[64];
    uint8_t *buf;
    ge25519_p3 R;

    if (!signature || !secret_key || (!message && message_len > 0)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Hash the secret key */
    sha512(secret_key, 32, hash);
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;

    /* r = H(h[32..63] || message) mod L */
    buf = (uint8_t *)malloc(32 + message_len);
    if (!buf) {
        return AMA_ERROR_MEMORY;
    }
    memcpy(buf, hash + 32, 32);
    if (message_len > 0) {
        memcpy(buf + 32, message, message_len);
    }
    sha512(buf, 32 + message_len, r);
    sc25519_reduce(r);

    /* R = r*B */
    ge25519_scalarmult_base(&R, r);
    ge25519_p3_tobytes(signature, &R);

    /* H(R || A || message) */
    free(buf);
    buf = (uint8_t *)malloc(64 + message_len);
    if (!buf) {
        return AMA_ERROR_MEMORY;
    }
    memcpy(buf, signature, 32);
    memcpy(buf + 32, secret_key + 32, 32);
    if (message_len > 0) {
        memcpy(buf + 64, message, message_len);
    }
    sha512(buf, 64 + message_len, hram);
    sc25519_reduce(hram);

    /* s = r + H(R||A||M) * a mod L */
    sc25519_muladd(signature + 32, r, hram, hash);

    /* Cleanup */
    ama_secure_memzero(hash, sizeof(hash));
    ama_secure_memzero(r, sizeof(r));
    ama_secure_memzero(hram, sizeof(hram));
    free(buf);

    return AMA_SUCCESS;
}

/**
 * Verify an Ed25519 signature
 *
 * @param signature 64-byte signature
 * @param message Message to verify
 * @param message_len Length of message
 * @param public_key 32-byte public key
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
ama_error_t ama_ed25519_verify(
    const uint8_t signature[64],
    const uint8_t *message,
    size_t message_len,
    const uint8_t public_key[32]
) {
    uint8_t h[64];
    uint8_t *buf;
    ge25519_p3 A, R_check;
    ge25519_p1p1 t;
    ge25519_p2 p2;
    uint8_t R_bytes[32];
    int i;

    if (!signature || !public_key || (!message && message_len > 0)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Decode public key */
    if (ge25519_frombytes(&A, public_key) != 0) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    /* Negate A for later subtraction */
    fe25519_neg(A.X, A.X);
    fe25519_neg(A.T, A.T);

    /* H(R || A || message) */
    buf = (uint8_t *)malloc(64 + message_len);
    if (!buf) {
        return AMA_ERROR_MEMORY;
    }
    memcpy(buf, signature, 32);
    memcpy(buf + 32, public_key, 32);
    if (message_len > 0) {
        memcpy(buf + 64, message, message_len);
    }
    sha512(buf, 64 + message_len, h);
    sc25519_reduce(h);
    free(buf);

    /* Check: [s]B - [h]A == R */
    /* Compute [s]B */
    ge25519_scalarmult_base(&R_check, signature + 32);

    /* Compute [h]A (A is already negated) */
    ge25519_p3 hA;
    ge25519_scalarmult(&hA, h, &A);

    /* R_check = [s]B + (-[h]A) = [s]B - [h]A */
    ge25519_add(&t, &R_check, &hA);
    ge25519_p1p1_to_p3(&R_check, &t);

    /* Encode and compare */
    ge25519_p3_tobytes(R_bytes, &R_check);

    int diff = 0;
    for (i = 0; i < 32; i++) {
        diff |= R_bytes[i] ^ signature[i];
    }

    return (diff == 0) ? AMA_SUCCESS : AMA_ERROR_VERIFY_FAILED;
}
