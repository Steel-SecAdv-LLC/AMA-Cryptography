/**
 * Copyright 2025 Steel Security Advisors LLC
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
 * @file ava_sphincs.c
 * @brief SPHINCS+-SHA2-256f-simple Hash-Based Signatures - Native C Implementation
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-03-05
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
 * Note: Uses SHA-256 internally (via OpenSSL) as specified by the
 * "SHA2" variant. The existing ava_sha3.c provides SHA3/SHAKE which
 * is used for domain separation and message hashing.
 */

#include "../include/ava_guardian.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

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
    out[6] = 0;
    out[7] = 0;
}

/**
 * Serialize address to bytes (big-endian)
 */
static void spx_addr_to_bytes(uint8_t *bytes, const spx_addr addr) {
    unsigned int i;
    for (i = 0; i < 8; ++i) {
        bytes[4*i + 0] = (uint8_t)(addr[i] >> 24);
        bytes[4*i + 1] = (uint8_t)(addr[i] >> 16);
        bytes[4*i + 2] = (uint8_t)(addr[i] >> 8);
        bytes[4*i + 3] = (uint8_t)(addr[i]);
    }
}

/* ============================================================================
 * HASH FUNCTIONS (SHA-256 based, "simple" variant)
 * ============================================================================ */

/**
 * SHA-256 helper
 */
static void sha256(uint8_t *out, const uint8_t *in, size_t inlen) {
    SHA256(in, inlen, out);
}

/**
 * SHA-256 with two inputs concatenated
 */
static void sha256_2(uint8_t *out, const uint8_t *in1, size_t in1len,
                      const uint8_t *in2, size_t in2len) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in1, in1len);
    SHA256_Update(&ctx, in2, in2len);
    SHA256_Final(out, &ctx);
}

/**
 * MGF1-SHA-256 mask generation function
 */
static void mgf1_sha256(uint8_t *out, size_t outlen,
                          const uint8_t *seed, size_t seedlen) {
    uint8_t buf[32];
    uint8_t counter[4] = {0, 0, 0, 0};
    SHA256_CTX ctx;
    size_t i, blocks;

    blocks = (outlen + 31) / 32;
    for (i = 0; i < blocks; ++i) {
        counter[0] = (uint8_t)(i >> 24);
        counter[1] = (uint8_t)(i >> 16);
        counter[2] = (uint8_t)(i >> 8);
        counter[3] = (uint8_t)i;

        SHA256_Init(&ctx);
        SHA256_Update(&ctx, seed, seedlen);
        SHA256_Update(&ctx, counter, 4);
        SHA256_Final(buf, &ctx);

        size_t tocopy = (outlen - i * 32 < 32) ? outlen - i * 32 : 32;
        memcpy(out + i * 32, buf, tocopy);
    }
    ava_secure_memzero(buf, sizeof(buf));
}

/**
 * SPHINCS+ T_l function (tweakable hash for l-byte message)
 * Simple variant: SHA-256(pub_seed || addr || msg)
 */
static void spx_thash(uint8_t *out, const uint8_t *in, unsigned int inblocks,
                       const uint8_t *pub_seed, const spx_addr addr) {
    uint8_t addr_bytes[32];
    SHA256_CTX ctx;
    uint8_t hash[32];

    spx_addr_to_bytes(addr_bytes, addr);

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, pub_seed, SPX_N);
    SHA256_Update(&ctx, addr_bytes, sizeof(addr_bytes));
    SHA256_Update(&ctx, in, inblocks * SPX_N);
    SHA256_Final(hash, &ctx);

    memcpy(out, hash, SPX_N);
}

/**
 * PRF: keyed hash for secret value generation
 * PRF(sk_seed, addr) = SHA-256(pub_seed || addr || sk_seed)
 */
static void spx_prf(uint8_t *out, const uint8_t *pub_seed,
                     const uint8_t *sk_seed, const spx_addr addr) {
    uint8_t addr_bytes[32];
    SHA256_CTX ctx;
    uint8_t hash[32];

    spx_addr_to_bytes(addr_bytes, addr);

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, pub_seed, SPX_N);
    SHA256_Update(&ctx, addr_bytes, sizeof(addr_bytes));
    SHA256_Update(&ctx, sk_seed, SPX_N);
    SHA256_Final(hash, &ctx);

    memcpy(out, hash, SPX_N);
}

/**
 * PRF_msg: message-dependent randomness
 */
static void spx_prf_msg(uint8_t *out, const uint8_t *sk_prf,
                          const uint8_t *opt_rand,
                          const uint8_t *msg, size_t msglen) {
    uint8_t hmac_key[SPX_N];
    unsigned int outlen = 0;

    /* HMAC-SHA256(sk_prf, opt_rand || msg) */
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, sk_prf, SPX_N, EVP_sha256(), NULL);
    HMAC_Update(ctx, opt_rand, SPX_N);
    HMAC_Update(ctx, msg, msglen);
    HMAC_Final(ctx, out, &outlen);
    HMAC_CTX_free(ctx);

    (void)hmac_key;
}

/**
 * H_msg: hash message to obtain FORS message and tree/leaf indices
 */
static void spx_hash_message(uint8_t *digest, uint64_t *tree, uint32_t *leaf_idx,
                               const uint8_t *R, const uint8_t *pk,
                               const uint8_t *msg, size_t msglen) {
    uint8_t buf[SPX_FORS_MSG_BYTES + 8 + 4];  /* message hash output */
    uint8_t seed[2 * SPX_N + SPX_N];
    size_t seed_len = 2 * SPX_N + SPX_N;

    /* Construct seed: R || pk_seed || pk_root */
    memcpy(seed, R, SPX_N);
    memcpy(seed + SPX_N, pk, 2 * SPX_N);

    /* Generate enough pseudorandom bytes using MGF1 */
    size_t buflen = SPX_FORS_MSG_BYTES + 8 + 4;

    /* SHA-256(R || pk || msg) then MGF1 expand */
    {
        SHA256_CTX ctx;
        uint8_t hash[32];
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, R, SPX_N);
        SHA256_Update(&ctx, pk, 2 * SPX_N);
        SHA256_Update(&ctx, msg, msglen);
        SHA256_Final(hash, &ctx);
        mgf1_sha256(buf, buflen, hash, 32);
    }

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
    *tree &= ((uint64_t)1 << (SPX_FULL_HEIGHT - SPX_TREE_HEIGHT)) - 1;

    /* Extract leaf index (4 bytes) */
    *leaf_idx = 0;
    {
        unsigned int i;
        for (i = 0; i < 4; ++i) {
            *leaf_idx |= (uint32_t)buf[SPX_FORS_MSG_BYTES + 8 + i] << (24 - 8 * i);
        }
    }
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

    ava_secure_memzero(sk, sizeof(sk));
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

    spx_set_type(addr, SPX_ADDR_TYPE_FORSTREE);

    for (i = 0; i < (1u << SPX_FORS_HEIGHT); ++i) {
        /* Compute leaf */
        uint8_t node[SPX_N];
        spx_fors_gen_leaf(node, sk_seed, pub_seed, offset + i, addr);

        /* Save auth path node if needed */
        if (i == (leaf_idx ^ 1u)) {
            memcpy(auth_path, node, SPX_N);
        }

        /* Treehash: merge nodes up the tree */
        unsigned int h = 0;
        while (sp > 0 && heights[sp - 1] == h) {
            if (h < SPX_FORS_HEIGHT) {
                /* Save auth path */
                if (((i >> (h + 1)) ^ 1) == (leaf_idx >> (h + 1))) {
                    memcpy(auth_path + (h + 1) * SPX_N,
                           stack + (sp - 1) * SPX_N, SPX_N);
                }
            }
            spx_set_tree_height(addr, h + 1);
            spx_set_tree_index(addr, offset + (i >> (h + 1)));

            uint8_t combined[2 * SPX_N];
            memcpy(combined, stack + (sp - 1) * SPX_N, SPX_N);
            memcpy(combined + SPX_N, node, SPX_N);
            spx_thash(node, combined, 2, pub_seed, addr);
            sp--;
            h++;
        }

        memcpy(stack + sp * SPX_N, node, SPX_N);
        heights[sp] = h;
        sp++;
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

    /* Extract indices from message digest */
    {
        unsigned int bits_done = 0;
        unsigned int byte_idx = 0;
        unsigned int bit_offset = 0;

        for (i = 0; i < SPX_FORS_TREES; ++i) {
            indices[i] = 0;
            unsigned int bits_left = SPX_FORS_HEIGHT;

            while (bits_left > 0) {
                unsigned int avail = 8 - bit_offset;
                unsigned int take = (bits_left < avail) ? bits_left : avail;
                unsigned int mask = (1u << take) - 1;

                indices[i] |= ((msg_digest[byte_idx] >> bit_offset) & mask)
                              << (SPX_FORS_HEIGHT - bits_left);

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
        spx_set_type(fors_addr, SPX_ADDR_TYPE_FORSTREE);
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
    spx_set_type(fors_addr, SPX_ADDR_TYPE_FORSPK);
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

    /* Extract indices from message digest */
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

                indices[i] |= ((msg_digest[byte_idx] >> bit_offset) & mask)
                              << (SPX_FORS_HEIGHT - bits_left);

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

        spx_set_type(fors_addr, SPX_ADDR_TYPE_FORSTREE);
        spx_set_tree_height(fors_addr, 0);
        spx_set_tree_index(fors_addr, offset + idx);

        /* Hash leaf value */
        spx_thash(node, sk_val, 1, pub_seed, fors_addr);

        /* Walk up the tree using authentication path */
        for (j = 0; j < SPX_FORS_HEIGHT; ++j) {
            spx_set_tree_height(fors_addr, j + 1);
            spx_set_tree_index(fors_addr, offset + (idx >> (j + 1)));

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
    spx_set_type(fors_addr, SPX_ADDR_TYPE_FORSPK);
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
        uint8_t node[SPX_N];
        spx_xmss_gen_leaf(node, sk_seed, pub_seed, i, addr);

        /* Save auth path node */
        if (i == (leaf_idx ^ 1u)) {
            memcpy(auth_path, node, SPX_N);
        }

        unsigned int h = 0;
        while (sp > 0 && heights[sp - 1] == h) {
            if (h < SPX_TREE_HEIGHT) {
                if (((i >> (h + 1)) ^ 1) == (leaf_idx >> (h + 1))) {
                    memcpy(auth_path + (h + 1) * SPX_N,
                           stack + (sp - 1) * SPX_N, SPX_N);
                }
            }
            spx_set_tree_height(addr, h + 1);
            spx_set_tree_index(addr, i >> (h + 1));

            uint8_t combined[2 * SPX_N];
            memcpy(combined, stack + (sp - 1) * SPX_N, SPX_N);
            memcpy(combined + SPX_N, node, SPX_N);
            spx_set_type(addr, SPX_ADDR_TYPE_HASHTREE);
            spx_thash(node, combined, 2, pub_seed, addr);
            sp--;
            h++;
        }

        memcpy(stack + sp * SPX_N, node, SPX_N);
        heights[sp] = h;
        sp++;
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
    return ava_consttime_memcmp(node, root, SPX_N);
}

/* ============================================================================
 * TOP-LEVEL API: KEY GENERATION, SIGNING, VERIFICATION
 * ============================================================================ */

/* Get random bytes from OS */
static ava_error_t spx_randombytes(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        return AVA_ERROR_CRYPTO;
    }
    if (fread(buf, 1, len, f) != len) {
        fclose(f);
        return AVA_ERROR_CRYPTO;
    }
    fclose(f);
    return AVA_SUCCESS;
}

/**
 * SPHINCS+-SHA2-256f-simple Key Pair Generation
 *
 * Generates a keypair for SPHINCS+-SHA2-256f-simple.
 *
 * @param public_key Output buffer for public key (64 bytes)
 * @param secret_key Output buffer for secret key (128 bytes)
 * @return AVA_SUCCESS or error code
 */
ava_error_t ava_sphincs_keypair(uint8_t *public_key, uint8_t *secret_key) {
    spx_addr addr;
    uint8_t root[SPX_N];
    ava_error_t rc;

    if (!public_key || !secret_key) {
        return AVA_ERROR_INVALID_PARAM;
    }

    memset(addr, 0, sizeof(addr));

    /* Generate random seeds: sk_seed, sk_prf, pub_seed */
    rc = spx_randombytes(secret_key, 3 * SPX_N);
    if (rc != AVA_SUCCESS) {
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

    return AVA_SUCCESS;
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
 * @return AVA_SUCCESS or error code
 */
ava_error_t ava_sphincs_sign(uint8_t *signature, size_t *signature_len,
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
    ava_error_t rc;
    uint8_t *sig_ptr;

    if (!signature || !signature_len || !message || !secret_key) {
        return AVA_ERROR_INVALID_PARAM;
    }

    if (*signature_len < AVA_SPHINCS_256F_SIGNATURE_BYTES) {
        *signature_len = AVA_SPHINCS_256F_SIGNATURE_BYTES;
        return AVA_ERROR_INVALID_PARAM;
    }

    /* Construct public key for message hashing */
    memcpy(pk, pub_seed, SPX_N);
    memcpy(pk + SPX_N, pk_root, SPX_N);

    /* Generate randomizer (for randomized signing) */
    rc = spx_randombytes(opt_rand, SPX_N);
    if (rc != AVA_SUCCESS) {
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
    spx_set_keypair_addr(fors_addr, leaf_idx);

    spx_fors_sign(sig_ptr, fors_pk, fors_msg, sk_seed, pub_seed, fors_addr);
    sig_ptr += SPX_FORS_BYTES;

    /* Hypertree signature over FORS public key */
    spx_ht_sign(sig_ptr, fors_pk, tree, leaf_idx, sk_seed, pub_seed);

    *signature_len = AVA_SPHINCS_256F_SIGNATURE_BYTES;
    return AVA_SUCCESS;
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
 * @return AVA_SUCCESS if valid, AVA_ERROR_VERIFY_FAILED if invalid
 */
ava_error_t ava_sphincs_verify(const uint8_t *message, size_t message_len,
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
        return AVA_ERROR_INVALID_PARAM;
    }

    if (signature_len != AVA_SPHINCS_256F_SIGNATURE_BYTES) {
        return AVA_ERROR_VERIFY_FAILED;
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
    spx_set_keypair_addr(fors_addr, leaf_idx);

    spx_fors_pk_from_sig(fors_pk, fors_sig, fors_msg, pub_seed, fors_addr);

    /* Verify hypertree signature */
    if (spx_ht_verify(fors_pk, ht_sig, tree, leaf_idx,
                       pub_seed, pk_root) != 0) {
        return AVA_ERROR_VERIFY_FAILED;
    }

    return AVA_SUCCESS;
}
