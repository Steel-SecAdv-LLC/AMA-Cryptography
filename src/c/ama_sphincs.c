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
 * @file ama_sphincs.c
 * @brief SPHINCS+-SHA2-256f-simple Hash-Based Signatures - Native C Implementation
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-03-08
 *
 * Full native implementation of SPHINCS+-SHA2-256f-simple (NIST FIPS 205).
 * Implements stateless hash-based signatures using the SPHINCS+ framework
 * with SHA-256 as the underlying hash function.
 *
 * Parameters (SPHINCS+-SHA2-256f-simple):
 * - Security level: NIST Level 5 (~256-bit classical, ~128-bit quantum)
 * - Public key: 64 bytes
 * - Secret key: 128 bytes
 * - Signature: 49856 bytes
 * - n = 32 (security parameter)
 * - h = 68 (total tree height)
 * - d = 17 (layers)
 * - a = 9 (FORS trees)
 * - k = 35 (FORS leaves per tree)
 * - w = 16 (Winternitz parameter)
 *
 * Standards:
 * - NIST FIPS 205 (SLH-DSA)
 * - Stateless hash-based signatures
 *
 * Security notes:
 * - Security relies solely on hash function properties
 * - No number-theoretic assumptions
 * - Constant-time hash computations
 *
 * Note: Uses SHA-256 internally (native implementation) as specified by the
 * "SHA2" variant. The existing ama_sha3.c provides SHA3/SHAKE which
 * is used for domain separation and message hashing.
 *
 * Zero external dependencies: SHA-256 and HMAC-SHA-256 provided by
 * ama_sha256.c and ama_hmac_sha256.c respectively. Random bytes
 * provided by ama_platform_rand.c.
 */

#include "../include/ama_cryptography.h"
#include "ama_sha256.h"
#include "ama_hmac_sha256.h"
#include "ama_platform_rand.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* ============================================================================
 * SPHINCS+-SHA2-256f-simple PARAMETERS
 * ============================================================================ */

#define SPX_N 32            /* Security parameter (bytes) */
#define SPX_FULL_HEIGHT 68  /* Total tree height */
#define SPX_D 17            /* Number of layers (hypertree) */
#define SPX_TREE_HEIGHT 4   /* Height of each subtree = FULL_HEIGHT/D */
#define SPX_FORS_HEIGHT 9   /* Height of FORS trees */
#define SPX_FORS_TREES 35   /* Number of FORS trees */
#define SPX_WOTS_W 16       /* Winternitz parameter */
#define SPX_WOTS_LOGW 4     /* log2(w) */
#define SPX_WOTS_LEN1 64    /* n*8/log2(w) = 32*8/4 */
#define SPX_WOTS_LEN2 3     /* floor(log(len1 * (w-1)) / log(w)) + 1 */
#define SPX_WOTS_LEN (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)  /* 67 */
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)  /* 67 * 32 = 2144 */

/* Address types */
#define SPX_ADDR_TYPE_WOTS 0
#define SPX_ADDR_TYPE_WOTSPK 1
#define SPX_ADDR_TYPE_HASHTREE 2
#define SPX_ADDR_TYPE_FORSTREE 3
#define SPX_ADDR_TYPE_FORSPK 4

/* Signature sizes */
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_WOTS_SIG_BYTES (SPX_WOTS_LEN * SPX_N)

/* ============================================================================
 * ADDRESS MANIPULATION
 * ============================================================================ */

typedef uint32_t spx_addr[8];

static void spx_set_layer_addr(spx_addr addr, uint32_t layer) {
    addr[0] = layer;
}

static void spx_set_tree_addr(spx_addr addr, uint64_t tree) {
    addr[1] = (uint32_t)(tree >> 32);
    addr[2] = (uint32_t)tree;
}

static void spx_set_type(spx_addr addr, uint32_t type) {
    addr[3] = type;
    /* Clear remaining fields when type changes */
    addr[4] = 0;
    addr[5] = 0;
    addr[6] = 0;
    addr[7] = 0;
}

static void spx_set_keypair_addr(spx_addr addr, uint32_t keypair) {
    addr[5] = keypair;
}

static void spx_set_chain_addr(spx_addr addr, uint32_t chain) {
    addr[6] = chain;
}

static void spx_set_hash_addr(spx_addr addr, uint32_t hash) {
    addr[7] = hash;
}

static void spx_set_tree_height(spx_addr addr, uint32_t height) {
    addr[6] = height;
}

static void spx_set_tree_index(spx_addr addr, uint32_t index) {
    addr[7] = index;
}

static void spx_copy_keypair_addr(spx_addr out, const spx_addr in) {
    memcpy(out, in, sizeof(spx_addr));
    out[3] = SPX_ADDR_TYPE_WOTSPK;
    out[4] = 0;
    /* out[5] preserved: keypair address from input (FIPS 205 Alg 7/18) */
    out[6] = 0;
    out[7] = 0;
}

/**
 * Compress address to 22-byte ADRSc per FIPS 205 Section 11.1.
 * ADRSc = ADRS[3] || ADRS[8:16] || ADRS[19] || ADRS[20:32]
 *
 * Drops high bytes of layer (bytes 0-2), tree_high (bytes 4-7),
 * and high bytes of keypair/padding word (bytes 16-18).
 */
static void spx_addr_compress(uint8_t *out, const spx_addr addr) {
    /*
     * FIPS 205 Section 11.1: ADRSc = ADRS[3] || ADRS[8:16] || ADRS[19] || ADRS[20:32]
     *
     * FIPS 205 32-byte ADRS layout (Section 4):
     *   [0:4]   layer        = addr[0]
     *   [4:8]   tree (high)  = 0 (unused top 4 bytes of 12-byte tree field)
     *   [8:12]  tree (mid)   = addr[1]
     *   [12:16] tree (low)   = addr[2]
     *   [16:20] type         = addr[3]
     *   [20:24] keypair      = addr[5]
     *   [24:28] chain/height = addr[6]
     *   [28:32] hash/index   = addr[7]
     */

    /* ADRS[3]: low byte of layer address */
    out[0] = (uint8_t)(addr[0]);

    /* ADRS[8:16]: addr[1] (tree mid) || addr[2] (tree low) */
    out[1] = (uint8_t)(addr[1] >> 24);
    out[2] = (uint8_t)(addr[1] >> 16);
    out[3] = (uint8_t)(addr[1] >> 8);
    out[4] = (uint8_t)(addr[1]);
    out[5] = (uint8_t)(addr[2] >> 24);
    out[6] = (uint8_t)(addr[2] >> 16);
    out[7] = (uint8_t)(addr[2] >> 8);
    out[8] = (uint8_t)(addr[2]);

    /* ADRS[19]: low byte of type */
    out[9] = (uint8_t)(addr[3]);

    /* ADRS[20:32]: addr[5] (keypair), addr[6] (chain/height), addr[7] (hash/index) */
    out[10] = (uint8_t)(addr[5] >> 24);
    out[11] = (uint8_t)(addr[5] >> 16);
    out[12] = (uint8_t)(addr[5] >> 8);
    out[13] = (uint8_t)(addr[5]);
    out[14] = (uint8_t)(addr[6] >> 24);
    out[15] = (uint8_t)(addr[6] >> 16);
    out[16] = (uint8_t)(addr[6] >> 8);
    out[17] = (uint8_t)(addr[6]);
    out[18] = (uint8_t)(addr[7] >> 24);
    out[19] = (uint8_t)(addr[7] >> 16);
    out[20] = (uint8_t)(addr[7] >> 8);
    out[21] = (uint8_t)(addr[7]);
}

/* ============================================================================
 * HASH FUNCTIONS (SHA-256 based, "simple" variant)
 * ============================================================================ */

/* ============================================================================
 * SHA-512 (required for FIPS 205 H_msg in security categories {3, 5})
 * ============================================================================ */

static const uint64_t spx_sha512_k[80] = {
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

static inline uint64_t spx_rotr64(uint64_t x, unsigned int n) {
    return (x >> n) | (x << (64 - n));
}

static void spx_sha512_transform(uint64_t state[8], const uint8_t block[128]) {
    uint64_t a, b, c, d, e, f, g, h, t1, t2;
    uint64_t W[80];
    int i;
    for (i = 0; i < 16; i++) {
        W[i] = ((uint64_t)block[i*8] << 56) | ((uint64_t)block[i*8+1] << 48) |
               ((uint64_t)block[i*8+2] << 40) | ((uint64_t)block[i*8+3] << 32) |
               ((uint64_t)block[i*8+4] << 24) | ((uint64_t)block[i*8+5] << 16) |
               ((uint64_t)block[i*8+6] << 8) | ((uint64_t)block[i*8+7]);
    }
    for (i = 16; i < 80; i++) {
        uint64_t s0 = spx_rotr64(W[i-15], 1) ^ spx_rotr64(W[i-15], 8) ^ (W[i-15] >> 7);
        uint64_t s1 = spx_rotr64(W[i-2], 19) ^ spx_rotr64(W[i-2], 61) ^ (W[i-2] >> 6);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (i = 0; i < 80; i++) {
        uint64_t S1 = spx_rotr64(e, 14) ^ spx_rotr64(e, 18) ^ spx_rotr64(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + spx_sha512_k[i] + W[i];
        uint64_t S0 = spx_rotr64(a, 28) ^ spx_rotr64(a, 34) ^ spx_rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/**
 * SHA-512 one-shot hash (used only for FIPS 205 H_msg in security category 5)
 */
static void spx_sha512(const uint8_t *data, size_t len, uint8_t out[64]) {
    uint64_t state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    uint8_t block[128];
    size_t orig_len = len;
    unsigned int i;
    while (len >= 128) {
        spx_sha512_transform(state, data);
        data += 128;
        len -= 128;
    }
    memset(block, 0, sizeof(block));
    memcpy(block, data, len);
    block[len] = 0x80;
    if (len >= 112) {
        spx_sha512_transform(state, block);
        memset(block, 0, sizeof(block));
    }
    {
        uint64_t bit_len = orig_len * 8;
        block[120] = (uint8_t)(bit_len >> 56); block[121] = (uint8_t)(bit_len >> 48);
        block[122] = (uint8_t)(bit_len >> 40); block[123] = (uint8_t)(bit_len >> 32);
        block[124] = (uint8_t)(bit_len >> 24); block[125] = (uint8_t)(bit_len >> 16);
        block[126] = (uint8_t)(bit_len >> 8);  block[127] = (uint8_t)(bit_len);
    }
    spx_sha512_transform(state, block);
    for (i = 0; i < 8; i++) {
        out[i*8]   = (uint8_t)(state[i] >> 56); out[i*8+1] = (uint8_t)(state[i] >> 48);
        out[i*8+2] = (uint8_t)(state[i] >> 40); out[i*8+3] = (uint8_t)(state[i] >> 32);
        out[i*8+4] = (uint8_t)(state[i] >> 24); out[i*8+5] = (uint8_t)(state[i] >> 16);
        out[i*8+6] = (uint8_t)(state[i] >> 8);  out[i*8+7] = (uint8_t)(state[i]);
    }
    ama_secure_memzero(block, sizeof(block));
    ama_secure_memzero(state, sizeof(state));
}

/**
 * MGF1-SHA-512 — used for FIPS 205 H_msg in security categories {3, 5}
 */
static void mgf1_sha512(uint8_t *out, size_t outlen,
                          const uint8_t *seed, size_t seedlen) {
    uint8_t buf[64];
    uint8_t counter[4] = {0, 0, 0, 0};
    size_t i, blocks;
    /* Build seed||counter in a temporary buffer for hashing */
    uint8_t hashbuf[SPX_N + SPX_N + 64 + 4];  /* max seed: 128 + 4 */
    if (seedlen > sizeof(hashbuf) - 4) {
        return;  /* safety check */
    }
    memcpy(hashbuf, seed, seedlen);

    blocks = (outlen + 63) / 64;
    for (i = 0; i < blocks; ++i) {
        hashbuf[seedlen]     = (uint8_t)(i >> 24);
        hashbuf[seedlen + 1] = (uint8_t)(i >> 16);
        hashbuf[seedlen + 2] = (uint8_t)(i >> 8);
        hashbuf[seedlen + 3] = (uint8_t)i;
        spx_sha512(hashbuf, seedlen + 4, buf);
        size_t tocopy = (outlen - i * 64 < 64) ? outlen - i * 64 : 64;
        memcpy(out + i * 64, buf, tocopy);
    }
    ama_secure_memzero(buf, sizeof(buf));
    ama_secure_memzero(hashbuf, sizeof(hashbuf));
}

/**
 * MGF1-SHA-256 mask generation function — native SHA-256
 */
static void mgf1_sha256(uint8_t *out, size_t outlen,
                          const uint8_t *seed, size_t seedlen) {
    uint8_t buf[32];
    uint8_t counter[4] = {0, 0, 0, 0};
    size_t i, blocks;

    blocks = (outlen + 31) / 32;
    for (i = 0; i < blocks; ++i) {
        counter[0] = (uint8_t)(i >> 24);
        counter[1] = (uint8_t)(i >> 16);
        counter[2] = (uint8_t)(i >> 8);
        counter[3] = (uint8_t)i;

        ama_sha256_ctx ctx;
        ama_sha256_init(&ctx);
        ama_sha256_update(&ctx, seed, seedlen);
        ama_sha256_update(&ctx, counter, 4);
        ama_sha256_final(&ctx, buf);

        size_t tocopy = (outlen - i * 32 < 32) ? outlen - i * 32 : 32;
        memcpy(out + i * 32, buf, tocopy);
    }
    ama_secure_memzero(buf, sizeof(buf));
}

/**
 * SPHINCS+ tweakable hash (F, H, T_l) — FIPS 205 Section 11.2 Table 5.
 *
 * For security categories {3,5} (n ∈ {24, 32}):
 *   F (inblocks == 1):  Trunc_n(SHA-256(PK.seed || toByte(0, 64-n) || ADRSc || M))
 *   H, T_l (inblocks > 1): Trunc_n(SHA-512(PK.seed || toByte(0, 128-n) || ADRSc || M))
 */
static void spx_thash(uint8_t *out, const uint8_t *in, unsigned int inblocks,
                       const uint8_t *pub_seed, const spx_addr addr) {
    uint8_t addr_c[22];

    spx_addr_compress(addr_c, addr);

    if (inblocks == 1) {
        /* F: SHA-256 with toByte(0, 64-n) padding */
        static const uint8_t padding[64 - SPX_N] = {0};
        uint8_t hash[32];

        ama_sha256_ctx ctx;
        ama_sha256_init(&ctx);
        ama_sha256_update(&ctx, pub_seed, SPX_N);
        ama_sha256_update(&ctx, padding, sizeof(padding));
        ama_sha256_update(&ctx, addr_c, sizeof(addr_c));
        ama_sha256_update(&ctx, in, SPX_N);
        ama_sha256_final(&ctx, hash);

        memcpy(out, hash, SPX_N);
    } else {
        /* H / T_l: SHA-512 with toByte(0, 128-n) padding */
        static const uint8_t padding[128 - SPX_N] = {0};  /* 96 zero bytes */
        uint8_t hash[64];

        /* Build input: PK.seed || toByte(0, 128-n) || ADRSc || M */
        size_t msg_len = (size_t)inblocks * SPX_N;
        size_t total = SPX_N + (128 - SPX_N) + 22 + msg_len;
        uint8_t *buf = (uint8_t *)calloc(1, total);
        if (!buf) {
            memset(out, 0, SPX_N);
            return;
        }
        memcpy(buf, pub_seed, SPX_N);
        memcpy(buf + SPX_N, padding, 128 - SPX_N);
        memcpy(buf + 128, addr_c, 22);
        memcpy(buf + 150, in, msg_len);

        spx_sha512(buf, total, hash);
        memcpy(out, hash, SPX_N);

        ama_secure_memzero(buf, total);
        free(buf);
    }
}

/**
 * PRF: keyed hash for secret value generation
 * FIPS 205 Section 11.1:
 * PRF(PK.seed, SK.seed, ADRS) = Trunc_n(SHA-256(PK.seed || toByte(0, 64-n) || ADRSc || SK.seed))
 */
static void spx_prf(uint8_t *out, const uint8_t *pub_seed,
                     const uint8_t *sk_seed, const spx_addr addr) {
    uint8_t addr_c[22];
    static const uint8_t padding[64 - SPX_N] = {0};  /* toByte(0, 64-n) */
    uint8_t hash[32];

    spx_addr_compress(addr_c, addr);

    ama_sha256_ctx ctx;
    ama_sha256_init(&ctx);
    ama_sha256_update(&ctx, pub_seed, SPX_N);          /* PK.seed (32 bytes) */
    ama_sha256_update(&ctx, padding, sizeof(padding));  /* toByte(0, 32) */
    ama_sha256_update(&ctx, addr_c, sizeof(addr_c));    /* ADRSc (22 bytes) */
    ama_sha256_update(&ctx, sk_seed, SPX_N);            /* SK.seed (32 bytes) */
    ama_sha256_final(&ctx, hash);

    memcpy(out, hash, SPX_N);
}

/**
 * PRF_msg: message-dependent randomness
 */
static void spx_prf_msg(uint8_t *out, const uint8_t *sk_prf,
                          const uint8_t *opt_rand,
                          const uint8_t *msg, size_t msglen) {
    /* HMAC-SHA256(sk_prf, opt_rand || msg) via native implementation */
    ama_hmac_sha256_2(sk_prf, SPX_N, opt_rand, SPX_N, msg, msglen, out);
}

/**
 * H_msg: hash message to obtain FORS message and tree/leaf indices
 */
static void spx_hash_message(uint8_t *digest, uint64_t *tree, uint32_t *leaf_idx,
                               const uint8_t *R, const uint8_t *pk,
                               const uint8_t *msg, size_t msglen) {
    uint8_t buf[SPX_FORS_MSG_BYTES + 8 + 4];  /* message hash output */
    size_t buflen = SPX_FORS_MSG_BYTES + 8 + 4;

    /* H_msg per FIPS 205 Sec 11.2 Table 5, security categories {3,5} (n=32):
     * MGF1-SHA-512(R || PK.seed || SHA-512(R || PK.seed || PK.root || M), m)
     *
     * Note: categories {3,5} use SHA-512 for H_msg (not SHA-256), and the
     * MGF1 seed has NO toByte(0, 128-n) padding — just R || PK.seed || inner. */
    {
        uint8_t hash[64];   /* SHA-512 output = 64 bytes */
        /* MGF1 seed: R(32) + PK.seed(32) + SHA-512_hash(64) = 128 bytes */
        uint8_t mgf_seed[SPX_N + SPX_N + 64];

        /* Inner hash: SHA-512(R || PK.seed || PK.root || M) */
        {
            /* Build input: R || PK.seed || PK.root || M */
            size_t inner_len = SPX_N + 2 * SPX_N + msglen;
            uint8_t *inner_buf = (uint8_t *)calloc(1, inner_len);
            if (!inner_buf) {
                memset(buf, 0, buflen);
                goto hmsg_extract;
            }
            memcpy(inner_buf, R, SPX_N);
            memcpy(inner_buf + SPX_N, pk, 2 * SPX_N);
            memcpy(inner_buf + 3 * SPX_N, msg, msglen);
            spx_sha512(inner_buf, inner_len, hash);
            ama_secure_memzero(inner_buf, inner_len);
            free(inner_buf);
        }

        /* Build MGF1 seed: R || PK.seed || SHA-512(inner) */
        memcpy(mgf_seed, R, SPX_N);
        memcpy(mgf_seed + SPX_N, pk, SPX_N);  /* PK.seed only */
        memcpy(mgf_seed + 2 * SPX_N, hash, 64);
        mgf1_sha512(buf, buflen, mgf_seed, sizeof(mgf_seed));

        ama_secure_memzero(hash, sizeof(hash));
        ama_secure_memzero(mgf_seed, sizeof(mgf_seed));
    }
    hmsg_extract:

    /* Extract FORS message digest */
    memcpy(digest, buf, SPX_FORS_MSG_BYTES);

    /* Extract tree index (8 bytes) */
    *tree = 0;
    {
        unsigned int i;
        for (i = 0; i < 8; ++i) {
            *tree |= (uint64_t)buf[SPX_FORS_MSG_BYTES + i] << (56 - 8 * i);
        }
    }
    /* Mask tree index to valid range */
    *tree &= (~(uint64_t)0) >> (64 - (SPX_FULL_HEIGHT - SPX_TREE_HEIGHT));

    /* Extract leaf index: ceil(h'/8) = 1 byte for h'=SPX_TREE_HEIGHT=4 */
    *leaf_idx = (uint32_t)buf[SPX_FORS_MSG_BYTES + 8];
    *leaf_idx &= ((uint32_t)1 << SPX_TREE_HEIGHT) - 1;
}

/* ============================================================================
 * WOTS+ (Winternitz One-Time Signature)
 * ============================================================================ */

/**
 * Compute base-w representation
 */
static void spx_base_w(unsigned int *output, int outlen,
                        const uint8_t *input) {
    int in_idx = 0;
    int out_idx = 0;
    int bits = 0;
    uint8_t total = 0;

    for (out_idx = 0; out_idx < outlen; ++out_idx) {
        if (bits == 0) {
            total = input[in_idx++];
            bits = 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out_idx] = (total >> bits) & (SPX_WOTS_W - 1);
    }
}

/**
 * Compute WOTS+ checksum
 */
static void spx_wots_checksum(unsigned int *csum_basew,
                                const unsigned int *msg_basew) {
    unsigned int csum = 0;
    int i;
    uint8_t csum_bytes[2];

    for (i = 0; i < SPX_WOTS_LEN1; ++i) {
        csum += SPX_WOTS_W - 1 - msg_basew[i];
    }

    /* Shift left to fill complete bytes */
    csum <<= (8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8;
    csum_bytes[0] = (uint8_t)(csum >> 8);
    csum_bytes[1] = (uint8_t)csum;

    spx_base_w(csum_basew, SPX_WOTS_LEN2, csum_bytes);
}

/**
 * WOTS+ chain computation
 * Applies the hash function 'steps' times starting from 'start'
 */
static void spx_wots_gen_chain(uint8_t *out, const uint8_t *in,
                                 unsigned int start, unsigned int steps,
                                 const uint8_t *pub_seed, spx_addr addr) {
    unsigned int i;
    memcpy(out, in, SPX_N);

    for (i = start; i < start + steps && i < SPX_WOTS_W; ++i) {
        spx_set_hash_addr(addr, i);
        spx_thash(out, out, 1, pub_seed, addr);
    }
}

/**
 * Generate WOTS+ public key from secret key
 */
static void spx_wots_gen_pk(uint8_t *pk, const uint8_t *sk_seed,
                              const uint8_t *pub_seed, spx_addr addr) {
    unsigned int i;
    uint8_t chain_in[SPX_N];

    for (i = 0; i < SPX_WOTS_LEN; ++i) {
        spx_set_chain_addr(addr, i);
        spx_set_hash_addr(addr, 0);
        spx_prf(chain_in, pub_seed, sk_seed, addr);
        spx_wots_gen_chain(pk + i * SPX_N, chain_in, 0, SPX_WOTS_W - 1,
                           pub_seed, addr);
    }
}

/**
 * Generate WOTS+ signature
 */
static void spx_wots_sign(uint8_t *sig, const uint8_t *msg,
                            const uint8_t *sk_seed, const uint8_t *pub_seed,
                            spx_addr addr) {
    unsigned int basew[SPX_WOTS_LEN];
    unsigned int csum_basew[SPX_WOTS_LEN2];
    unsigned int i;
    uint8_t chain_in[SPX_N];

    spx_base_w(basew, SPX_WOTS_LEN1, msg);
    spx_wots_checksum(csum_basew, basew);
    for (i = 0; i < SPX_WOTS_LEN2; ++i) {
        basew[SPX_WOTS_LEN1 + i] = csum_basew[i];
    }

    for (i = 0; i < SPX_WOTS_LEN; ++i) {
        spx_set_chain_addr(addr, i);
        spx_set_hash_addr(addr, 0);
        spx_prf(chain_in, pub_seed, sk_seed, addr);
        spx_wots_gen_chain(sig + i * SPX_N, chain_in, 0, basew[i],
                           pub_seed, addr);
    }
}

/**
 * Compute WOTS+ public key from signature
 */
static void spx_wots_pk_from_sig(uint8_t *pk, const uint8_t *sig,
                                   const uint8_t *msg,
                                   const uint8_t *pub_seed, spx_addr addr) {
    unsigned int basew[SPX_WOTS_LEN];
    unsigned int csum_basew[SPX_WOTS_LEN2];
    unsigned int i;

    spx_base_w(basew, SPX_WOTS_LEN1, msg);
    spx_wots_checksum(csum_basew, basew);
    for (i = 0; i < SPX_WOTS_LEN2; ++i) {
        basew[SPX_WOTS_LEN1 + i] = csum_basew[i];
    }

    for (i = 0; i < SPX_WOTS_LEN; ++i) {
        spx_set_chain_addr(addr, i);
        spx_wots_gen_chain(pk + i * SPX_N, sig + i * SPX_N,
                           basew[i], SPX_WOTS_W - 1 - basew[i],
                           pub_seed, addr);
    }
}

/* ============================================================================
 * FORS (Forest of Random Subsets)
 * ============================================================================ */

/**
 * Generate FORS secret value
 */
static void spx_fors_gen_sk(uint8_t *sk, const uint8_t *sk_seed,
                              const uint8_t *pub_seed, spx_addr addr) {
    spx_prf(sk, pub_seed, sk_seed, addr);
}

/**
 * Compute leaf of FORS tree
 */
static void spx_fors_gen_leaf(uint8_t *leaf, const uint8_t *sk_seed,
                                const uint8_t *pub_seed, uint32_t idx,
                                spx_addr addr) {
    uint8_t sk[SPX_N];

    spx_set_tree_height(addr, 0);
    spx_set_tree_index(addr, idx);
    spx_fors_gen_sk(sk, sk_seed, pub_seed, addr);
    spx_thash(leaf, sk, 1, pub_seed, addr);

    ama_secure_memzero(sk, sizeof(sk));
}

/**
 * Build authentication path and compute root for FORS tree
 */
static void spx_fors_treehash(uint8_t *root, uint8_t *auth_path,
                                const uint8_t *sk_seed, const uint8_t *pub_seed,
                                uint32_t leaf_idx, uint32_t tree_idx,
                                spx_addr addr) {
    uint8_t stack[(SPX_FORS_HEIGHT + 1) * SPX_N];
    unsigned int heights[SPX_FORS_HEIGHT + 1];
    unsigned int offset = tree_idx * (1u << SPX_FORS_HEIGHT);
    unsigned int sp = 0;
    uint32_t i;

    for (i = 0; i < (1u << SPX_FORS_HEIGHT); ++i) {
        /* Generate leaf directly onto the stack */
        spx_fors_gen_leaf(stack + sp * SPX_N, sk_seed, pub_seed, offset + i, addr);
        heights[sp] = 0;
        sp++;

        /* Save height-0 auth path sibling */
        if ((leaf_idx ^ 1u) == i) {
            memcpy(auth_path, stack + (sp - 1) * SPX_N, SPX_N);
        }

        /* Treehash: merge nodes up the tree */
        while (sp >= 2 && heights[sp - 1] == heights[sp - 2]) {
            uint32_t tree_node_idx = i >> (heights[sp - 1] + 1);

            spx_set_tree_height(addr, heights[sp - 1] + 1);
            spx_set_tree_index(addr, (offset + i) >> (heights[sp - 1] + 1));

            /* Merge in place: hash stack[sp-2..sp-1] into stack[sp-2] */
            spx_thash(stack + (sp - 2) * SPX_N,
                      stack + (sp - 2) * SPX_N, 2, pub_seed, addr);
            sp--;
            heights[sp - 1]++;

            /* Save auth path sibling at this height (after merge) */
            if (((leaf_idx >> heights[sp - 1]) ^ 1u) == tree_node_idx) {
                memcpy(auth_path + heights[sp - 1] * SPX_N,
                       stack + (sp - 1) * SPX_N, SPX_N);
            }
        }
    }

    memcpy(root, stack, SPX_N);
}

/**
 * FORS signing: generate FORS signature
 */
static void spx_fors_sign(uint8_t *sig, uint8_t *pk,
                            const uint8_t *msg_digest, const uint8_t *sk_seed,
                            const uint8_t *pub_seed, spx_addr fors_addr) {
    unsigned int i;
    uint8_t roots[SPX_FORS_TREES * SPX_N];
    unsigned int indices[SPX_FORS_TREES];

    /* Extract indices from message digest (MSB-first per FIPS 205) */
    {
        unsigned int byte_idx = 0;
        unsigned int bit_offset = 0;

        for (i = 0; i < SPX_FORS_TREES; ++i) {
            indices[i] = 0;
            unsigned int bits_left = SPX_FORS_HEIGHT;

            while (bits_left > 0) {
                unsigned int avail = 8 - bit_offset;
                unsigned int take = (bits_left < avail) ? bits_left : avail;
                unsigned int mask = (1u << take) - 1;

                indices[i] |= ((msg_digest[byte_idx] >> (8 - bit_offset - take)) & mask)
                              << (bits_left - take);

                bit_offset += take;
                bits_left -= take;
                if (bit_offset >= 8) {
                    bit_offset = 0;
                    byte_idx++;
                }
            }
        }
    }

    /* Generate FORS signatures for each tree */
    for (i = 0; i < SPX_FORS_TREES; ++i) {
        /* Generate leaf secret key value */
        spx_set_tree_height(fors_addr, 0);
        spx_set_tree_index(fors_addr, i * (1u << SPX_FORS_HEIGHT) + indices[i]);
        spx_fors_gen_sk(sig + i * (SPX_FORS_HEIGHT + 1) * SPX_N,
                        sk_seed, pub_seed, fors_addr);

        /* Compute authentication path */
        spx_fors_treehash(roots + i * SPX_N,
                          sig + i * (SPX_FORS_HEIGHT + 1) * SPX_N + SPX_N,
                          sk_seed, pub_seed, indices[i], i, fors_addr);
    }

    /* Compute FORS public key by hashing all roots */
    {
        uint32_t saved_keypair = fors_addr[5];
        spx_set_type(fors_addr, SPX_ADDR_TYPE_FORSPK);
        fors_addr[5] = saved_keypair;  /* FIPS 205: preserve keypair for FORS_ROOTS */
    }
    spx_thash(pk, roots, SPX_FORS_TREES, pub_seed, fors_addr);
}

/**
 * FORS verification: compute FORS public key from signature
 */
static void spx_fors_pk_from_sig(uint8_t *pk, const uint8_t *sig,
                                   const uint8_t *msg_digest,
                                   const uint8_t *pub_seed,
                                   spx_addr fors_addr) {
    unsigned int i, j;
    uint8_t roots[SPX_FORS_TREES * SPX_N];
    unsigned int indices[SPX_FORS_TREES];

    /* Extract indices from message digest (MSB-first per FIPS 205) */
    {
        unsigned int byte_idx = 0;
        unsigned int bit_offset = 0;

        for (i = 0; i < SPX_FORS_TREES; ++i) {
            indices[i] = 0;
            unsigned int bits_left = SPX_FORS_HEIGHT;

            while (bits_left > 0) {
                unsigned int avail = 8 - bit_offset;
                unsigned int take = (bits_left < avail) ? bits_left : avail;
                unsigned int mask = (1u << take) - 1;

                indices[i] |= ((msg_digest[byte_idx] >> (8 - bit_offset - take)) & mask)
                              << (bits_left - take);

                bit_offset += take;
                bits_left -= take;
                if (bit_offset >= 8) {
                    bit_offset = 0;
                    byte_idx++;
                }
            }
        }
    }

    /* Reconstruct roots from signatures */
    for (i = 0; i < SPX_FORS_TREES; ++i) {
        const uint8_t *sk_val = sig + i * (SPX_FORS_HEIGHT + 1) * SPX_N;
        const uint8_t *auth = sk_val + SPX_N;
        uint8_t node[2 * SPX_N];
        uint32_t idx = indices[i];
        uint32_t offset = i * (1u << SPX_FORS_HEIGHT);

        spx_set_tree_height(fors_addr, 0);
        spx_set_tree_index(fors_addr, offset + idx);

        /* Hash leaf value */
        spx_thash(node, sk_val, 1, pub_seed, fors_addr);

        /* Walk up the tree using authentication path */
        for (j = 0; j < SPX_FORS_HEIGHT; ++j) {
            spx_set_tree_height(fors_addr, j + 1);
            spx_set_tree_index(fors_addr, (offset + idx) >> (j + 1));

            if ((idx >> j) & 1) {
                memcpy(node + SPX_N, node, SPX_N);
                memcpy(node, auth + j * SPX_N, SPX_N);
            } else {
                memcpy(node + SPX_N, auth + j * SPX_N, SPX_N);
            }
            spx_thash(node, node, 2, pub_seed, fors_addr);
        }

        memcpy(roots + i * SPX_N, node, SPX_N);
    }

    /* Compute FORS public key */
    {
        uint32_t saved_keypair = fors_addr[5];
        spx_set_type(fors_addr, SPX_ADDR_TYPE_FORSPK);
        fors_addr[5] = saved_keypair;  /* FIPS 205: preserve keypair for FORS_ROOTS */
    }
    spx_thash(pk, roots, SPX_FORS_TREES, pub_seed, fors_addr);
}

/* ============================================================================
 * HYPERTREE
 * ============================================================================ */

/**
 * Compute leaf node of the XMSS tree (WOTS+ compressed public key)
 */
static void spx_xmss_gen_leaf(uint8_t *leaf, const uint8_t *sk_seed,
                                const uint8_t *pub_seed, uint32_t idx,
                                spx_addr addr) {
    uint8_t wots_pk[SPX_WOTS_BYTES];
    spx_addr wots_pk_addr;

    spx_set_type(addr, SPX_ADDR_TYPE_WOTS);
    spx_set_keypair_addr(addr, idx);

    spx_wots_gen_pk(wots_pk, sk_seed, pub_seed, addr);

    spx_copy_keypair_addr(wots_pk_addr, addr);
    spx_thash(leaf, wots_pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);
}

/**
 * Build XMSS tree and compute authentication path
 */
static void spx_xmss_treehash(uint8_t *root, uint8_t *auth_path,
                                const uint8_t *sk_seed,
                                const uint8_t *pub_seed,
                                uint32_t leaf_idx, spx_addr addr) {
    uint8_t stack[(SPX_TREE_HEIGHT + 1) * SPX_N];
    unsigned int heights[SPX_TREE_HEIGHT + 1];
    unsigned int sp = 0;
    uint32_t i;

    for (i = 0; i < (1u << SPX_TREE_HEIGHT); ++i) {
        /* Generate leaf directly onto the stack */
        spx_xmss_gen_leaf(stack + sp * SPX_N, sk_seed, pub_seed, i, addr);
        heights[sp] = 0;
        sp++;

        /* Save height-0 auth path sibling */
        if ((leaf_idx ^ 1u) == i) {
            memcpy(auth_path, stack + (sp - 1) * SPX_N, SPX_N);
        }

        /* Treehash: merge nodes up the tree */
        while (sp >= 2 && heights[sp - 1] == heights[sp - 2]) {
            uint32_t tree_node_idx = i >> (heights[sp - 1] + 1);

            spx_set_type(addr, SPX_ADDR_TYPE_HASHTREE);
            spx_set_tree_height(addr, heights[sp - 1] + 1);
            spx_set_tree_index(addr, tree_node_idx);

            /* Merge in place: hash stack[sp-2..sp-1] into stack[sp-2] */
            spx_thash(stack + (sp - 2) * SPX_N,
                      stack + (sp - 2) * SPX_N, 2, pub_seed, addr);
            sp--;
            heights[sp - 1]++;

            /* Save auth path sibling at this height (after merge) */
            if (((leaf_idx >> heights[sp - 1]) ^ 1u) == tree_node_idx) {
                memcpy(auth_path + heights[sp - 1] * SPX_N,
                       stack + (sp - 1) * SPX_N, SPX_N);
            }
        }
    }

    memcpy(root, stack, SPX_N);
}

/**
 * Hypertree signing: sign message across all tree layers
 */
static void spx_ht_sign(uint8_t *sig, const uint8_t *msg,
                          uint64_t tree, uint32_t leaf_idx,
                          const uint8_t *sk_seed, const uint8_t *pub_seed) {
    spx_addr addr;
    uint8_t root[SPX_N];
    unsigned int layer;

    memset(addr, 0, sizeof(addr));

    /* Sign at bottom layer */
    spx_set_layer_addr(addr, 0);
    spx_set_tree_addr(addr, tree);

    /* WOTS+ signature + auth path at bottom layer */
    spx_set_type(addr, SPX_ADDR_TYPE_WOTS);
    spx_set_keypair_addr(addr, leaf_idx);
    spx_wots_sign(sig, msg, sk_seed, pub_seed, addr);
    sig += SPX_WOTS_SIG_BYTES;

    /* Authentication path */
    spx_set_type(addr, SPX_ADDR_TYPE_HASHTREE);
    spx_xmss_treehash(root, sig, sk_seed, pub_seed, leaf_idx, addr);
    sig += SPX_TREE_HEIGHT * SPX_N;

    /* Sign at remaining layers */
    for (layer = 1; layer < SPX_D; ++layer) {
        leaf_idx = (uint32_t)(tree & ((1u << SPX_TREE_HEIGHT) - 1));
        tree >>= SPX_TREE_HEIGHT;

        spx_set_layer_addr(addr, layer);
        spx_set_tree_addr(addr, tree);

        spx_set_type(addr, SPX_ADDR_TYPE_WOTS);
        spx_set_keypair_addr(addr, leaf_idx);
        spx_wots_sign(sig, root, sk_seed, pub_seed, addr);
        sig += SPX_WOTS_SIG_BYTES;

        spx_set_type(addr, SPX_ADDR_TYPE_HASHTREE);
        spx_xmss_treehash(root, sig, sk_seed, pub_seed, leaf_idx, addr);
        sig += SPX_TREE_HEIGHT * SPX_N;
    }
}

/**
 * Hypertree verification: verify signature across all layers
 */
static int spx_ht_verify(const uint8_t *msg, const uint8_t *sig,
                           uint64_t tree, uint32_t leaf_idx,
                           const uint8_t *pub_seed, const uint8_t *root) {
    spx_addr addr;
    spx_addr wots_pk_addr;
    uint8_t node[SPX_N];
    uint8_t wots_pk[SPX_WOTS_BYTES];
    unsigned int layer;

    memset(addr, 0, sizeof(addr));

    /* Verify at bottom layer */
    spx_set_layer_addr(addr, 0);
    spx_set_tree_addr(addr, tree);

    spx_set_type(addr, SPX_ADDR_TYPE_WOTS);
    spx_set_keypair_addr(addr, leaf_idx);
    spx_wots_pk_from_sig(wots_pk, sig, msg, pub_seed, addr);
    sig += SPX_WOTS_SIG_BYTES;

    /* Compress WOTS+ public key */
    spx_copy_keypair_addr(wots_pk_addr, addr);
    spx_thash(node, wots_pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);

    /* Walk up tree using auth path */
    {
        unsigned int h;
        for (h = 0; h < SPX_TREE_HEIGHT; ++h) {
            spx_set_type(addr, SPX_ADDR_TYPE_HASHTREE);
            spx_set_tree_height(addr, h + 1);
            spx_set_tree_index(addr, leaf_idx >> (h + 1));

            uint8_t combined[2 * SPX_N];
            if ((leaf_idx >> h) & 1) {
                memcpy(combined, sig + h * SPX_N, SPX_N);
                memcpy(combined + SPX_N, node, SPX_N);
            } else {
                memcpy(combined, node, SPX_N);
                memcpy(combined + SPX_N, sig + h * SPX_N, SPX_N);
            }
            spx_thash(node, combined, 2, pub_seed, addr);
        }
    }
    sig += SPX_TREE_HEIGHT * SPX_N;

    /* Verify remaining layers */
    for (layer = 1; layer < SPX_D; ++layer) {
        leaf_idx = (uint32_t)(tree & ((1u << SPX_TREE_HEIGHT) - 1));
        tree >>= SPX_TREE_HEIGHT;

        spx_set_layer_addr(addr, layer);
        spx_set_tree_addr(addr, tree);

        spx_set_type(addr, SPX_ADDR_TYPE_WOTS);
        spx_set_keypair_addr(addr, leaf_idx);
        spx_wots_pk_from_sig(wots_pk, sig, node, pub_seed, addr);
        sig += SPX_WOTS_SIG_BYTES;

        spx_copy_keypair_addr(wots_pk_addr, addr);
        spx_thash(node, wots_pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);

        unsigned int h;
        for (h = 0; h < SPX_TREE_HEIGHT; ++h) {
            spx_set_type(addr, SPX_ADDR_TYPE_HASHTREE);
            spx_set_tree_height(addr, h + 1);
            spx_set_tree_index(addr, leaf_idx >> (h + 1));

            uint8_t combined[2 * SPX_N];
            if ((leaf_idx >> h) & 1) {
                memcpy(combined, sig + h * SPX_N, SPX_N);
                memcpy(combined + SPX_N, node, SPX_N);
            } else {
                memcpy(combined, node, SPX_N);
                memcpy(combined + SPX_N, sig + h * SPX_N, SPX_N);
            }
            spx_thash(node, combined, 2, pub_seed, addr);
        }
        sig += SPX_TREE_HEIGHT * SPX_N;
    }

    /* Compare computed root with expected root */
    return ama_consttime_memcmp(node, root, SPX_N);
}

/* ============================================================================
 * TOP-LEVEL API: KEY GENERATION, SIGNING, VERIFICATION
 * ============================================================================ */

/**
 * Random bytes hook for KAT testing.
 * When non-NULL, replaces /dev/urandom for deterministic output.
 * Only available in test builds (AMA_TESTING_MODE).
 */
#ifdef AMA_TESTING_MODE
ama_error_t (*ama_sphincs_randombytes_hook)(uint8_t* buf, size_t len) = NULL;
#endif

/* Get random bytes from OS (or from test hook if set) */
static ama_error_t spx_randombytes(uint8_t *buf, size_t len) {
#ifdef AMA_TESTING_MODE
    if (ama_sphincs_randombytes_hook) {
        return ama_sphincs_randombytes_hook(buf, len);
    }
#endif
    return ama_randombytes(buf, len);
}

/**
 * SPHINCS+-SHA2-256f-simple Key Pair Generation
 *
 * Generates a keypair for SPHINCS+-SHA2-256f-simple.
 *
 * @param public_key Output buffer for public key (64 bytes)
 * @param secret_key Output buffer for secret key (128 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sphincs_keypair(uint8_t *public_key, uint8_t *secret_key) {
    spx_addr addr;
    uint8_t root[SPX_N];
    ama_error_t rc;

    if (!public_key || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    memset(addr, 0, sizeof(addr));

    /* Generate random seeds: sk_seed, sk_prf, pub_seed */
    rc = spx_randombytes(secret_key, 3 * SPX_N);
    if (rc != AMA_SUCCESS) {
        return rc;
    }

    /* pub_seed is also stored in public key */
    memcpy(public_key, secret_key + 2 * SPX_N, SPX_N);

    /* Compute root of the top-level XMSS tree */
    spx_set_layer_addr(addr, SPX_D - 1);
    spx_set_tree_addr(addr, 0);

    {
        uint8_t auth_path[SPX_TREE_HEIGHT * SPX_N];
        spx_xmss_treehash(root, auth_path, secret_key, public_key, 0, addr);
    }

    /* Public key = pub_seed || root */
    memcpy(public_key + SPX_N, root, SPX_N);

    /* Secret key = sk_seed || sk_prf || pub_seed || root */
    memcpy(secret_key + 3 * SPX_N, root, SPX_N);

    return AMA_SUCCESS;
}

/**
 * SPHINCS+-SHA2-256f-simple Signing
 *
 * Signs a message using SPHINCS+-SHA2-256f-simple.
 *
 * @param signature Output buffer for signature (49856 bytes max)
 * @param signature_len Pointer to signature length (in/out)
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Secret key (128 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sphincs_sign(uint8_t *signature, size_t *signature_len,
                              const uint8_t *message, size_t message_len,
                              const uint8_t *secret_key) {
    const uint8_t *sk_seed = secret_key;
    const uint8_t *sk_prf = secret_key + SPX_N;
    const uint8_t *pub_seed = secret_key + 2 * SPX_N;
    const uint8_t *pk_root = secret_key + 3 * SPX_N;
    uint8_t pk[2 * SPX_N];
    uint8_t opt_rand[SPX_N];
    uint8_t R[SPX_N];
    uint8_t fors_msg[SPX_FORS_MSG_BYTES];
    uint64_t tree;
    uint32_t leaf_idx;
    uint8_t fors_pk[SPX_N];
    spx_addr fors_addr;
    ama_error_t rc;
    uint8_t *sig_ptr;

    if (!signature || !signature_len || !message || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    if (*signature_len < AMA_SPHINCS_256F_SIGNATURE_BYTES) {
        *signature_len = AMA_SPHINCS_256F_SIGNATURE_BYTES;
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Construct public key for message hashing */
    memcpy(pk, pub_seed, SPX_N);
    memcpy(pk + SPX_N, pk_root, SPX_N);

    /* Generate randomizer (for randomized signing) */
    rc = spx_randombytes(opt_rand, SPX_N);
    if (rc != AMA_SUCCESS) {
        return rc;
    }

    /* Compute R = PRF_msg(sk_prf, opt_rand, msg) */
    spx_prf_msg(R, sk_prf, opt_rand, message, message_len);

    /* Write R to signature */
    sig_ptr = signature;
    memcpy(sig_ptr, R, SPX_N);
    sig_ptr += SPX_N;

    /* Compute message hash to get FORS message and indices */
    spx_hash_message(fors_msg, &tree, &leaf_idx, R, pk, message, message_len);

    /* FORS signature */
    memset(fors_addr, 0, sizeof(fors_addr));
    spx_set_tree_addr(fors_addr, tree);
    spx_set_type(fors_addr, SPX_ADDR_TYPE_FORSTREE);
    spx_set_keypair_addr(fors_addr, leaf_idx);

    spx_fors_sign(sig_ptr, fors_pk, fors_msg, sk_seed, pub_seed, fors_addr);
    sig_ptr += SPX_FORS_BYTES;

    /* Hypertree signature over FORS public key */
    spx_ht_sign(sig_ptr, fors_pk, tree, leaf_idx, sk_seed, pub_seed);

    *signature_len = AMA_SPHINCS_256F_SIGNATURE_BYTES;
    return AMA_SUCCESS;
}

/**
 * SPHINCS+-SHA2-256f-simple Verification
 *
 * Verifies a SPHINCS+ signature on a message.
 *
 * @param message Message to verify
 * @param message_len Length of message
 * @param signature Signature (49856 bytes)
 * @param signature_len Length of signature
 * @param public_key Public key (64 bytes)
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_sphincs_verify(const uint8_t *message, size_t message_len,
                                const uint8_t *signature, size_t signature_len,
                                const uint8_t *public_key) {
    const uint8_t *pub_seed = public_key;
    const uint8_t *pk_root = public_key + SPX_N;
    const uint8_t *R;
    const uint8_t *fors_sig;
    const uint8_t *ht_sig;
    uint8_t fors_msg[SPX_FORS_MSG_BYTES];
    uint64_t tree;
    uint32_t leaf_idx;
    uint8_t fors_pk[SPX_N];
    spx_addr fors_addr;

    if (!message || !signature || !public_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    if (signature_len != AMA_SPHINCS_256F_SIGNATURE_BYTES) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    /* Parse signature: R || FORS sig || HT sig */
    R = signature;
    fors_sig = R + SPX_N;
    ht_sig = fors_sig + SPX_FORS_BYTES;

    /* Compute message hash */
    spx_hash_message(fors_msg, &tree, &leaf_idx, R, public_key,
                     message, message_len);

    /* Reconstruct FORS public key from signature */
    memset(fors_addr, 0, sizeof(fors_addr));
    spx_set_tree_addr(fors_addr, tree);
    spx_set_type(fors_addr, SPX_ADDR_TYPE_FORSTREE);
    spx_set_keypair_addr(fors_addr, leaf_idx);

    spx_fors_pk_from_sig(fors_pk, fors_sig, fors_msg, pub_seed, fors_addr);

    /* Verify hypertree signature */
    if (spx_ht_verify(fors_pk, ht_sig, tree, leaf_idx,
                       pub_seed, pk_root) != 0) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    return AMA_SUCCESS;
}

/**
 * SLH-DSA-SHA2-256f Verification with context (FIPS 205, Section 9.2 — external/pure)
 *
 * Applies the domain-separation wrapper M' = 0x00 || len(ctx) || ctx || M
 * defined in FIPS 205 Section 9.2, then delegates to ama_sphincs_verify().
 *
 * @param message       Raw message to verify
 * @param message_len   Length of message
 * @param ctx           Context string (0–255 bytes)
 * @param ctx_len       Length of context (must be <= 255)
 * @param signature     Signature to verify (49856 bytes)
 * @param signature_len Length of signature
 * @param public_key    Public key (64 bytes)
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_sphincs_verify_ctx(
    const uint8_t *message, size_t message_len,
    const uint8_t *ctx, size_t ctx_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key) {

    uint8_t *wrapped;
    size_t wrapped_len;
    ama_error_t result;

    /* Context must be at most 255 bytes */
    if (ctx_len > 255) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Overflow guard: wrapped_len = 2 + ctx_len + message_len */
    if (message_len > SIZE_MAX - 2 - ctx_len) {
        return AMA_ERROR_INVALID_PARAM;
    }
    wrapped_len = 2 + ctx_len + message_len;

    wrapped = (uint8_t *)calloc(1, wrapped_len);
    if (!wrapped) {
        return AMA_ERROR_MEMORY;
    }

    /* M' = 0x00 || IntegerToBytes(|ctx|, 1) || ctx || M */
    wrapped[0] = 0x00;
    wrapped[1] = (uint8_t)ctx_len;
    if (ctx_len > 0 && ctx != NULL) {
        memcpy(wrapped + 2, ctx, ctx_len);
    }
    memcpy(wrapped + 2 + ctx_len, message, message_len);

    result = ama_sphincs_verify(wrapped, wrapped_len, signature,
                                signature_len, public_key);

    ama_secure_memzero(wrapped, wrapped_len);
    free(wrapped);
    return result;
}
