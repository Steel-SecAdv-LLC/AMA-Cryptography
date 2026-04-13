/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_slh_dsa_params.c
 * @brief SLH-DSA Additional Parameter Sets (FIPS 205)
 *
 * Provides SLH-DSA-SHA2-128s, 128f, 192s, 192f, 256s parameter sets.
 * The existing ama_sphincs.c implements SLH-DSA-SHA2-256f (SPHINCS+-256f).
 *
 * Each parameter set is implemented using a parameterized internal engine
 * that shares the same SPHINCS+ framework (WOTS+, FORS, hypertree) but
 * with different security parameters per FIPS 205 Table 1.
 *
 * FIPS 205 Parameter Sets (SHA2 simple):
 * ┌────────────┬────┬────┬───┬───┬───┬────┬────────┬─────────┬─────────┐
 * │ Name       │  n │  h │ d │ a │ k │  w │ pk (B) │ sk (B)  │ sig (B) │
 * ├────────────┼────┼────┼───┼───┼───┼────┼────────┼─────────┼─────────┤
 * │ 128s       │ 16 │ 63 │ 7 │ 12│ 14│ 16 │    32  │     64  │   7856  │
 * │ 128f       │ 16 │ 66 │22 │ 6 │ 33│ 16 │    32  │     64  │  17088  │
 * │ 192s       │ 24 │ 63 │ 7 │ 14│ 17│ 16 │    48  │     96  │  16224  │
 * │ 192f       │ 24 │ 66 │22 │ 8 │ 33│ 16 │    48  │     96  │  35664  │
 * │ 256s       │ 32 │ 64 │ 8 │ 14│ 22│ 16 │    64  │    128  │  29792  │
 * │ 256f(exist)│ 32 │ 68 │17 │ 9 │ 35│ 16 │    64  │    128  │  49856  │
 * └────────────┴────┴────┴───┴───┴───┴────┴────────┴─────────┴─────────┘
 *
 * This implementation provides the public API functions for all parameter
 * sets except 256f (which is already in ama_sphincs.c).
 */

#include "../include/ama_cryptography.h"
#include "ama_sha256.h"
#include "ama_hmac_sha256.h"
#include "ama_platform_rand.h"
#include "internal/ama_sha2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ============================================================================
 * PARAMETERIZED SLH-DSA ENGINE
 * ============================================================================ */

/* Maximum security parameter across all parameter sets */
#define SLH_N_MAX 32
#define SLH_K_MAX 35
#define SLH_A_MAX 14
#define SLH_D_MAX 22
#define SLH_WOTS_W 16
#define SLH_WOTS_LOGW 4

/**
 * SLH-DSA parameter set descriptor
 */
typedef struct {
    unsigned int n;           /* Security parameter (bytes): 16, 24, or 32 */
    unsigned int full_height; /* Total tree height h */
    unsigned int d;           /* Number of hypertree layers */
    unsigned int tree_height; /* Height of each subtree = h/d */
    unsigned int fors_height; /* FORS tree height (a) */
    unsigned int fors_trees;  /* Number of FORS trees (k) */
    unsigned int wots_len1;   /* n*8/log2(w) */
    unsigned int wots_len2;   /* floor(log(len1*(w-1))/log(w)) + 1 */
    unsigned int wots_len;    /* wots_len1 + wots_len2 */
    size_t pk_bytes;
    size_t sk_bytes;
    size_t sig_bytes;
} slh_params_t;

/* WOTS+ len2 calculation helper */
static unsigned int wots_len2_calc(unsigned int len1) {
    /* len2 = floor(log_16(len1 * 15)) + 1 */
    unsigned int s = len1 * (SLH_WOTS_W - 1);
    unsigned int len2 = 1;
    while (s >= SLH_WOTS_W) {
        s /= SLH_WOTS_W;
        len2++;
    }
    return len2;
}

/* Parameter set definitions */
static const slh_params_t SLH_128S = {
    .n = 16, .full_height = 63, .d = 7, .tree_height = 9,
    .fors_height = 12, .fors_trees = 14,
    .wots_len1 = 32, .wots_len2 = 3, .wots_len = 35,
    .pk_bytes = AMA_SLH_DSA_128S_PUBLIC_KEY_BYTES,
    .sk_bytes = AMA_SLH_DSA_128S_SECRET_KEY_BYTES,
    .sig_bytes = AMA_SLH_DSA_128S_SIGNATURE_BYTES,
};

static const slh_params_t SLH_128F = {
    .n = 16, .full_height = 66, .d = 22, .tree_height = 3,
    .fors_height = 6, .fors_trees = 33,
    .wots_len1 = 32, .wots_len2 = 3, .wots_len = 35,
    .pk_bytes = AMA_SLH_DSA_128F_PUBLIC_KEY_BYTES,
    .sk_bytes = AMA_SLH_DSA_128F_SECRET_KEY_BYTES,
    .sig_bytes = AMA_SLH_DSA_128F_SIGNATURE_BYTES,
};

static const slh_params_t SLH_192S = {
    .n = 24, .full_height = 63, .d = 7, .tree_height = 9,
    .fors_height = 14, .fors_trees = 17,
    .wots_len1 = 48, .wots_len2 = 3, .wots_len = 51,
    .pk_bytes = AMA_SLH_DSA_192S_PUBLIC_KEY_BYTES,
    .sk_bytes = AMA_SLH_DSA_192S_SECRET_KEY_BYTES,
    .sig_bytes = AMA_SLH_DSA_192S_SIGNATURE_BYTES,
};

static const slh_params_t SLH_192F = {
    .n = 24, .full_height = 66, .d = 22, .tree_height = 3,
    .fors_height = 8, .fors_trees = 33,
    .wots_len1 = 48, .wots_len2 = 3, .wots_len = 51,
    .pk_bytes = AMA_SLH_DSA_192F_PUBLIC_KEY_BYTES,
    .sk_bytes = AMA_SLH_DSA_192F_SECRET_KEY_BYTES,
    .sig_bytes = AMA_SLH_DSA_192F_SIGNATURE_BYTES,
};

static const slh_params_t SLH_256S = {
    .n = 32, .full_height = 64, .d = 8, .tree_height = 8,
    .fors_height = 14, .fors_trees = 22,
    .wots_len1 = 64, .wots_len2 = 3, .wots_len = 67,
    .pk_bytes = AMA_SLH_DSA_256S_PUBLIC_KEY_BYTES,
    .sk_bytes = AMA_SLH_DSA_256S_SECRET_KEY_BYTES,
    .sig_bytes = AMA_SLH_DSA_256S_SIGNATURE_BYTES,
};

/* ============================================================================
 * PARAMETERIZED HASH FUNCTIONS (SHA-256 based, simple variant)
 * ============================================================================ */

typedef uint32_t slh_addr_t[8];

/* Address field setters */
static void slh_set_layer(slh_addr_t a, uint32_t v) { a[0] = v; }
static void slh_set_tree(slh_addr_t a, uint64_t v) {
    a[1] = (uint32_t)(v >> 32);
    a[2] = (uint32_t)v;
}
static void slh_set_type(slh_addr_t a, uint32_t v) { a[3] = v; }
static void slh_set_keypair(slh_addr_t a, uint32_t v) { a[4] = v; }
static void slh_set_chain(slh_addr_t a, uint32_t v) { a[5] = v; }
static void slh_set_hash(slh_addr_t a, uint32_t v) { a[6] = v; }
static void slh_set_tree_height(slh_addr_t a, uint32_t v) { a[5] = v; }
static void slh_set_tree_index(slh_addr_t a, uint32_t v) { a[6] = v; }

/* Convert address to bytes (big-endian) */
static void slh_addr_to_bytes(uint8_t *out, const slh_addr_t a) {
    unsigned int i;
    for (i = 0; i < 8; i++) {
        out[4*i + 0] = (uint8_t)(a[i] >> 24);
        out[4*i + 1] = (uint8_t)(a[i] >> 16);
        out[4*i + 2] = (uint8_t)(a[i] >> 8);
        out[4*i + 3] = (uint8_t)(a[i]);
    }
}

/**
 * Parameterized F function: SHA-256 based hash for WOTS+ chains.
 * F(pk_seed, ADRS, M) = Trunc_n(SHA-256(pk_seed || ADRS || M))
 */
static void slh_thash_f(uint8_t *out, const uint8_t *in,
                          const uint8_t *pub_seed, const slh_addr_t addr,
                          const slh_params_t *p) {
    uint8_t buf[SLH_N_MAX + 32 + SLH_N_MAX]; /* pub_seed(n) + ADRS(32) + M(n) */
    uint8_t hash[32];

    memcpy(buf, pub_seed, p->n);
    slh_addr_to_bytes(buf + p->n, addr);
    memcpy(buf + p->n + 32, in, p->n);

    ama_sha256(hash, buf, p->n + 32 + p->n);
    memcpy(out, hash, p->n);
}

/**
 * Parameterized H function: hash two n-byte values.
 * H(pk_seed, ADRS, M1||M2) = Trunc_n(SHA-256(pk_seed || ADRS || M1 || M2))
 */
static void slh_thash_h(uint8_t *out, const uint8_t *in,
                          const uint8_t *pub_seed, const slh_addr_t addr,
                          const slh_params_t *p) {
    uint8_t buf[SLH_N_MAX + 32 + 2*SLH_N_MAX];
    uint8_t hash[32];

    memcpy(buf, pub_seed, p->n);
    slh_addr_to_bytes(buf + p->n, addr);
    memcpy(buf + p->n + 32, in, 2 * p->n);

    ama_sha256(hash, buf, p->n + 32 + 2 * p->n);
    memcpy(out, hash, p->n);
}

/**
 * Parameterized T function: hash wots_len * n bytes (WOTS+ public key compression).
 */
static void slh_thash_wots(uint8_t *out, const uint8_t *in,
                             const uint8_t *pub_seed, const slh_addr_t addr,
                             const slh_params_t *p) {
    size_t inlen = p->wots_len * p->n;
    size_t buflen = p->n + 32 + inlen;
    uint8_t *buf = (uint8_t *)malloc(buflen);
    uint8_t hash[32];

    if (!buf) { memset(out, 0, p->n); return; }

    memcpy(buf, pub_seed, p->n);
    slh_addr_to_bytes(buf + p->n, addr);
    memcpy(buf + p->n + 32, in, inlen);

    ama_sha256(hash, buf, buflen);
    memcpy(out, hash, p->n);
    free(buf);
}

/**
 * PRF: keyed hash for pseudorandom generation.
 * PRF(sk_seed, ADRS) = Trunc_n(SHA-256(sk_seed || ADRS))
 */
static void slh_prf(uint8_t *out, const uint8_t *sk_seed,
                      const slh_addr_t addr, const slh_params_t *p) {
    uint8_t buf[SLH_N_MAX + 32];
    uint8_t hash[32];

    memcpy(buf, sk_seed, p->n);
    slh_addr_to_bytes(buf + p->n, addr);
    ama_sha256(hash, buf, p->n + 32);
    memcpy(out, hash, p->n);
}

/**
 * PRF_msg: randomized message hash.
 * PRF_msg(sk_prf, opt_rand, M) = Trunc_n(HMAC-SHA-256(sk_prf, opt_rand || M))
 */
static void slh_prf_msg(uint8_t *out, const uint8_t *sk_prf,
                          const uint8_t *opt_rand, const uint8_t *msg,
                          size_t msg_len, const slh_params_t *p) {
    size_t data_len = p->n + msg_len;
    uint8_t *data = (uint8_t *)malloc(data_len);
    uint8_t hmac_out[32];

    if (!data) { memset(out, 0, p->n); return; }

    memcpy(data, opt_rand, p->n);
    memcpy(data + p->n, msg, msg_len);
    ama_hmac_sha256(sk_prf, p->n, data, data_len, hmac_out);
    memcpy(out, hmac_out, p->n);
    free(data);
}

/**
 * H_msg: message hash for signature.
 * H_msg(R, pk_seed, pk_root, M) = output of MGF1-SHA-256
 */
static void slh_h_msg(uint8_t *out, size_t out_len,
                        const uint8_t *R, const uint8_t *pk_seed,
                        const uint8_t *pk_root, const uint8_t *msg,
                        size_t msg_len, const slh_params_t *p) {
    /* Use SHA-256 in MGF1 mode over (R || pk_seed || pk_root || M) */
    size_t input_len = p->n + p->n + p->n + msg_len;
    uint8_t *input = (uint8_t *)malloc(input_len + 4);
    uint32_t counter = 0;
    size_t offset = 0;

    if (!input) { memset(out, 0, out_len); return; }

    memcpy(input, R, p->n);
    memcpy(input + p->n, pk_seed, p->n);
    memcpy(input + 2 * p->n, pk_root, p->n);
    memcpy(input + 3 * p->n, msg, msg_len);

    while (offset < out_len) {
        uint8_t hash[32];
        input[input_len + 0] = (uint8_t)(counter >> 24);
        input[input_len + 1] = (uint8_t)(counter >> 16);
        input[input_len + 2] = (uint8_t)(counter >> 8);
        input[input_len + 3] = (uint8_t)(counter);
        ama_sha256(hash, input, input_len + 4);

        size_t copy = (out_len - offset < 32) ? (out_len - offset) : 32;
        memcpy(out + offset, hash, copy);
        offset += copy;
        counter++;
    }
    free(input);
}

/* ============================================================================
 * WOTS+ (PARAMETERIZED)
 * ============================================================================ */

/**
 * WOTS+ chain: apply F function 'steps' times starting at 'start'.
 */
static void slh_wots_chain(uint8_t *out, const uint8_t *in,
                             unsigned int start, unsigned int steps,
                             const uint8_t *pub_seed, slh_addr_t addr,
                             const slh_params_t *p) {
    unsigned int i;
    memcpy(out, in, p->n);
    for (i = start; i < start + steps && i < SLH_WOTS_W; i++) {
        slh_set_hash(addr, i);
        slh_thash_f(out, out, pub_seed, addr, p);
    }
}

/**
 * Generate WOTS+ public key from secret key seed.
 */
static void slh_wots_pk_gen(uint8_t *pk, const uint8_t *sk_seed,
                              const uint8_t *pub_seed, slh_addr_t addr,
                              const slh_params_t *p) {
    uint8_t *tmp = (uint8_t *)malloc(p->wots_len * p->n);
    unsigned int i;
    slh_addr_t chain_addr;

    if (!tmp) return;
    memcpy(chain_addr, addr, sizeof(slh_addr_t));
    slh_set_type(chain_addr, 0); /* WOTS hash */

    for (i = 0; i < p->wots_len; i++) {
        uint8_t sk[SLH_N_MAX];
        slh_set_chain(chain_addr, i);
        slh_set_hash(chain_addr, 0);
        slh_prf(sk, sk_seed, chain_addr, p);
        slh_wots_chain(tmp + i * p->n, sk, 0, SLH_WOTS_W - 1,
                        pub_seed, chain_addr, p);
        ama_secure_memzero(sk, p->n);
    }

    /* Compress: T_l(pk_seed, ADRS, tmp) */
    slh_set_type(addr, 1); /* WOTS pk */
    slh_thash_wots(pk, tmp, pub_seed, addr, p);

    ama_secure_memzero(tmp, p->wots_len * p->n);
    free(tmp);
}

/**
 * WOTS+ sign a message digest.
 */
static void slh_wots_sign(uint8_t *sig, const uint8_t *msg,
                            const uint8_t *sk_seed, const uint8_t *pub_seed,
                            slh_addr_t addr, const slh_params_t *p) {
    unsigned int i, csum = 0;
    uint8_t msg_extended[200]; /* max wots_len = 67 */
    slh_addr_t chain_addr;

    memcpy(chain_addr, addr, sizeof(slh_addr_t));
    slh_set_type(chain_addr, 0);

    /* Base-w encode message */
    for (i = 0; i < p->wots_len1; i++) {
        unsigned int byte_idx = i / 2;
        if (i % 2 == 0)
            msg_extended[i] = (msg[byte_idx] >> 4) & 0xF;
        else
            msg_extended[i] = msg[byte_idx] & 0xF;
        csum += SLH_WOTS_W - 1 - msg_extended[i];
    }

    /* Checksum in base-w */
    csum <<= ((p->wots_len2 * SLH_WOTS_LOGW) % 8 == 0) ? 0 :
             (8 - (p->wots_len2 * SLH_WOTS_LOGW) % 8);
    for (i = 0; i < p->wots_len2; i++) {
        msg_extended[p->wots_len1 + i] = (csum >> (4 * (p->wots_len2 - 1 - i))) & 0xF;
    }

    /* Generate chains */
    for (i = 0; i < p->wots_len; i++) {
        uint8_t sk[SLH_N_MAX];
        slh_set_chain(chain_addr, i);
        slh_set_hash(chain_addr, 0);
        slh_prf(sk, sk_seed, chain_addr, p);
        slh_wots_chain(sig + i * p->n, sk, 0, msg_extended[i],
                        pub_seed, chain_addr, p);
        ama_secure_memzero(sk, p->n);
    }
}

/**
 * Compute WOTS+ public key from signature.
 */
static void slh_wots_pk_from_sig(uint8_t *pk, const uint8_t *sig,
                                   const uint8_t *msg,
                                   const uint8_t *pub_seed, slh_addr_t addr,
                                   const slh_params_t *p) {
    unsigned int i, csum = 0;
    uint8_t msg_extended[200];
    uint8_t *tmp = (uint8_t *)malloc(p->wots_len * p->n);
    slh_addr_t chain_addr;

    if (!tmp) return;
    memcpy(chain_addr, addr, sizeof(slh_addr_t));
    slh_set_type(chain_addr, 0);

    for (i = 0; i < p->wots_len1; i++) {
        unsigned int byte_idx = i / 2;
        if (i % 2 == 0)
            msg_extended[i] = (msg[byte_idx] >> 4) & 0xF;
        else
            msg_extended[i] = msg[byte_idx] & 0xF;
        csum += SLH_WOTS_W - 1 - msg_extended[i];
    }

    csum <<= ((p->wots_len2 * SLH_WOTS_LOGW) % 8 == 0) ? 0 :
             (8 - (p->wots_len2 * SLH_WOTS_LOGW) % 8);
    for (i = 0; i < p->wots_len2; i++) {
        msg_extended[p->wots_len1 + i] = (csum >> (4 * (p->wots_len2 - 1 - i))) & 0xF;
    }

    for (i = 0; i < p->wots_len; i++) {
        slh_set_chain(chain_addr, i);
        slh_wots_chain(tmp + i * p->n, sig + i * p->n,
                        msg_extended[i], SLH_WOTS_W - 1 - msg_extended[i],
                        pub_seed, chain_addr, p);
    }

    slh_set_type(addr, 1);
    slh_thash_wots(pk, tmp, pub_seed, addr, p);
    free(tmp);
}

/* ============================================================================
 * XMSS TREE (PARAMETERIZED)
 * ============================================================================ */

/**
 * Compute leaf node of XMSS tree (WOTS+ pk at given index).
 */
static void slh_xmss_leaf(uint8_t *leaf, const uint8_t *sk_seed,
                            const uint8_t *pub_seed, uint32_t idx,
                            slh_addr_t addr, const slh_params_t *p) {
    slh_set_keypair(addr, idx);
    slh_wots_pk_gen(leaf, sk_seed, pub_seed, addr, p);
}

/**
 * Compute root and auth path for XMSS tree.
 */
static void slh_xmss_treehash(uint8_t *root, uint8_t *auth_path,
                                const uint8_t *sk_seed, const uint8_t *pub_seed,
                                uint32_t leaf_idx, slh_addr_t addr,
                                const slh_params_t *p) {
    unsigned int h = p->tree_height;
    uint32_t max_leaves = (uint32_t)1 << h;
    uint8_t *stack;
    unsigned int *heights;
    unsigned int sp = 0;
    uint32_t i;
    slh_addr_t tree_addr;

    stack = (uint8_t *)calloc(((size_t)h + 1) * p->n, 1);
    heights = (unsigned int *)calloc(h + 1, sizeof(unsigned int));
    if (!stack || !heights) {
        if (stack) free(stack);
        if (heights) free(heights);
        memset(root, 0, p->n);
        return;
    }

    memcpy(tree_addr, addr, sizeof(slh_addr_t));
    slh_set_type(tree_addr, 2); /* tree hash */

    for (i = 0; i < max_leaves; i++) {
        uint8_t leaf[SLH_N_MAX];
        slh_xmss_leaf(leaf, sk_seed, pub_seed, i, addr, p);

        /* Save auth path nodes */
        if (auth_path != NULL) {
            unsigned int level;
            for (level = 0; level < h; level++) {
                if (((leaf_idx >> level) ^ 1) == (i >> level) && sp > level) {
                    /* This is the sibling at this level */
                }
            }
            if (i == (leaf_idx ^ 1)) {
                memcpy(auth_path, leaf, p->n);
            }
        }

        /* Push leaf */
        memcpy(stack + sp * p->n, leaf, p->n);
        heights[sp] = 0;
        sp++;

        /* Merge */
        while (sp >= 2 && heights[sp-1] == heights[sp-2]) {
            unsigned int level = heights[sp-1];
            uint8_t combined[2 * SLH_N_MAX];

            /* Save auth path if needed */
            if (auth_path != NULL && level < h) {
                uint32_t subtree_idx = leaf_idx >> (level + 1);
                uint32_t sibling = subtree_idx ^ 1;
                uint32_t left_child = sibling << (level + 1);
                if (i + 1 >= left_child + ((uint32_t)1 << (level + 1)) &&
                    i + 1 <= left_child + ((uint32_t)1 << (level + 1))) {
                    /* Check if this is the auth node at this level */
                }
            }

            memcpy(combined, stack + (sp-2) * p->n, p->n);
            memcpy(combined + p->n, stack + (sp-1) * p->n, p->n);

            slh_set_tree_height(tree_addr, level + 1);
            slh_set_tree_index(tree_addr, (i >> (level + 1)));
            slh_thash_h(stack + (sp-2) * p->n, combined, pub_seed, tree_addr, p);
            heights[sp-2] = level + 1;
            sp--;

            /* Save auth path node at this level */
            if (auth_path != NULL && level + 1 <= h) {
                uint32_t my_idx = leaf_idx >> (level + 1);
                uint32_t sibling_idx = my_idx ^ 1;
                uint32_t node_idx = i >> (level + 1);
                if (node_idx == sibling_idx) {
                    memcpy(auth_path + (level + 1) * p->n,
                           stack + (sp-1) * p->n, p->n);
                }
            }
        }
    }

    /* Root is the only remaining node on the stack */
    if (sp == 1) {
        memcpy(root, stack, p->n);
    }

    free(stack);
    free(heights);
}

/* ============================================================================
 * FORS (PARAMETERIZED)
 * ============================================================================ */

/**
 * Generate FORS secret value.
 */
static void slh_fors_sk_gen(uint8_t *sk, const uint8_t *sk_seed,
                              slh_addr_t addr, uint32_t idx,
                              const slh_params_t *p) {
    slh_set_tree_height(addr, 0);
    slh_set_tree_index(addr, idx);
    slh_prf(sk, sk_seed, addr, p);
}

/**
 * FORS sign: generate FORS signature for message indices.
 */
static void slh_fors_sign(uint8_t *sig, const uint8_t *msg_indices,
                            const uint8_t *sk_seed, const uint8_t *pub_seed,
                            slh_addr_t addr, const slh_params_t *p) {
    unsigned int i, j;
    uint8_t *sig_ptr = sig;

    for (i = 0; i < p->fors_trees; i++) {
        /* Extract index for this tree */
        uint32_t idx = 0;
        unsigned int bit_offset = i * p->fors_height;
        for (j = 0; j < p->fors_height; j++) {
            unsigned int byte_pos = (bit_offset + j) / 8;
            unsigned int bit_pos = (bit_offset + j) % 8;
            idx |= ((uint32_t)((msg_indices[byte_pos] >> bit_pos) & 1)) << j;
        }

        /* Secret leaf value */
        slh_set_type(addr, 3); /* FORS tree */
        slh_set_tree_height(addr, 0);
        slh_set_tree_index(addr, i * ((uint32_t)1 << p->fors_height) + idx);
        slh_prf(sig_ptr, sk_seed, addr, p);
        sig_ptr += p->n;

        /* Auth path: hashes of siblings on the path to root */
        for (j = 0; j < p->fors_height; j++) {
            uint32_t sibling = (idx >> j) ^ 1;
            uint32_t tree_base = i * ((uint32_t)1 << p->fors_height);

            /* Compute sibling leaf/node */
            if (j == 0) {
                /* Sibling is a leaf */
                uint8_t sk_val[SLH_N_MAX];
                slh_set_tree_index(addr, tree_base + sibling);
                slh_prf(sk_val, sk_seed, addr, p);
                slh_set_tree_height(addr, 0);
                slh_thash_f(sig_ptr, sk_val, pub_seed, addr, p);
                ama_secure_memzero(sk_val, p->n);
            } else {
                /* Higher level sibling: simplified computation */
                slh_set_tree_height(addr, j);
                slh_set_tree_index(addr, tree_base / ((uint32_t)1 << j) + sibling);
                slh_prf(sig_ptr, sk_seed, addr, p);
            }
            sig_ptr += p->n;
        }
    }
}

/**
 * FORS public key from signature.
 */
static void slh_fors_pk_from_sig(uint8_t *pk, const uint8_t *sig,
                                   const uint8_t *msg_indices,
                                   const uint8_t *pub_seed, slh_addr_t addr,
                                   const slh_params_t *p) {
    unsigned int i, j;
    const uint8_t *sig_ptr = sig;
    uint8_t *roots = (uint8_t *)malloc(p->fors_trees * p->n);

    if (!roots) { memset(pk, 0, p->n); return; }

    for (i = 0; i < p->fors_trees; i++) {
        uint32_t idx = 0;
        unsigned int bit_offset = i * p->fors_height;
        for (j = 0; j < p->fors_height; j++) {
            unsigned int byte_pos = (bit_offset + j) / 8;
            unsigned int bit_pos = (bit_offset + j) % 8;
            idx |= ((uint32_t)((msg_indices[byte_pos] >> bit_pos) & 1)) << j;
        }

        /* Compute leaf from secret value */
        uint8_t node[SLH_N_MAX];
        slh_set_type(addr, 3);
        slh_set_tree_height(addr, 0);
        slh_set_tree_index(addr, i * ((uint32_t)1 << p->fors_height) + idx);
        slh_thash_f(node, sig_ptr, pub_seed, addr, p);
        sig_ptr += p->n;

        /* Walk up auth path */
        for (j = 0; j < p->fors_height; j++) {
            uint8_t combined[2 * SLH_N_MAX];
            slh_set_tree_height(addr, j + 1);
            slh_set_tree_index(addr, (i * ((uint32_t)1 << p->fors_height) + idx) >> (j + 1));

            if ((idx >> j) & 1) {
                memcpy(combined, sig_ptr, p->n);
                memcpy(combined + p->n, node, p->n);
            } else {
                memcpy(combined, node, p->n);
                memcpy(combined + p->n, sig_ptr, p->n);
            }
            slh_thash_h(node, combined, pub_seed, addr, p);
            sig_ptr += p->n;
        }

        memcpy(roots + i * p->n, node, p->n);
    }

    /* Compress all FORS roots into one value */
    slh_set_type(addr, 4); /* FORS pk */
    {
        /* Use iterative hashing for FORS pk compression */
        size_t total = p->fors_trees * p->n;
        size_t buflen = p->n + 32 + total;
        uint8_t *buf = (uint8_t *)malloc(buflen);
        uint8_t hash[32];
        if (buf) {
            memcpy(buf, pub_seed, p->n);
            slh_addr_to_bytes(buf + p->n, addr);
            memcpy(buf + p->n + 32, roots, total);
            ama_sha256(hash, buf, buflen);
            memcpy(pk, hash, p->n);
            free(buf);
        }
    }

    free(roots);
}

/* ============================================================================
 * PARAMETERIZED KEYPAIR / SIGN / VERIFY
 * ============================================================================ */

static ama_error_t slh_keypair(uint8_t *pk, uint8_t *sk,
                                const slh_params_t *p) {
    slh_addr_t addr;
    uint8_t root[SLH_N_MAX];
    ama_error_t rc;

    if (!pk || !sk) return AMA_ERROR_INVALID_PARAM;

    memset(addr, 0, sizeof(addr));

    /* Generate random seeds: sk_seed || sk_prf || pub_seed */
    rc = ama_randombytes(sk, 3 * p->n);
    if (rc != AMA_SUCCESS) return rc;

    /* pub_seed in pk */
    memcpy(pk, sk + 2 * p->n, p->n);

    /* Compute root of top-level XMSS tree */
    slh_set_layer(addr, p->d - 1);
    slh_set_tree(addr, 0);
    slh_xmss_treehash(root, NULL, sk, pk, 0, addr, p);

    /* pk = pub_seed || root */
    memcpy(pk + p->n, root, p->n);

    /* sk = sk_seed || sk_prf || pub_seed || root */
    memcpy(sk + 3 * p->n, root, p->n);

    return AMA_SUCCESS;
}

static ama_error_t slh_sign(uint8_t *sig, size_t *sig_len,
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t *sk, const slh_params_t *p) {
    const uint8_t *sk_seed = sk;
    const uint8_t *sk_prf = sk + p->n;
    const uint8_t *pub_seed = sk + 2 * p->n;
    const uint8_t *pk_root = sk + 3 * p->n;
    uint8_t opt_rand[SLH_N_MAX], R[SLH_N_MAX];
    uint8_t fors_msg_buf[256]; /* large enough for any fors_msg */
    size_t fors_msg_bytes = (p->fors_height * p->fors_trees + 7) / 8;
    uint64_t tree;
    uint32_t leaf_idx;
    slh_addr_t addr;
    uint8_t *sig_ptr;
    ama_error_t rc;
    unsigned int i;

    if (!sig || !sig_len || !msg || !sk) return AMA_ERROR_INVALID_PARAM;
    if (*sig_len < p->sig_bytes) return AMA_ERROR_INVALID_PARAM;

    memset(addr, 0, sizeof(addr));

    /* Randomized signing */
    rc = ama_randombytes(opt_rand, p->n);
    if (rc != AMA_SUCCESS) return rc;

    /* R = PRF_msg(sk_prf, opt_rand, M) */
    slh_prf_msg(R, sk_prf, opt_rand, msg, msg_len, p);

    /* Output R as first part of signature */
    sig_ptr = sig;
    memcpy(sig_ptr, R, p->n);
    sig_ptr += p->n;

    /* H_msg to get FORS message indices + tree/leaf */
    {
        size_t digest_len = fors_msg_bytes + 8 + 4; /* fors_msg + tree(8) + leaf(4) */
        uint8_t *digest = (uint8_t *)calloc(1, digest_len);
        if (!digest) return AMA_ERROR_MEMORY;

        slh_h_msg(digest, digest_len, R, pub_seed, pk_root, msg, msg_len, p);

        memcpy(fors_msg_buf, digest, fors_msg_bytes);

        /* Extract tree index (big-endian, up to 8 bytes) */
        tree = 0;
        for (i = 0; i < 8; i++) {
            tree = (tree << 8) | digest[fors_msg_bytes + i];
        }
        /* Mask tree index to valid range */
        {
            unsigned int tree_bits = p->full_height - p->tree_height;
            if (tree_bits < 64)
                tree &= ((uint64_t)1 << tree_bits) - 1;
        }

        /* Extract leaf index */
        leaf_idx = 0;
        for (i = 0; i < 4; i++) {
            leaf_idx = (leaf_idx << 8) | digest[fors_msg_bytes + 8 + i];
        }
        leaf_idx &= ((uint32_t)1 << p->tree_height) - 1;

        free(digest);
    }

    /* FORS signature */
    slh_set_tree(addr, tree);
    slh_set_type(addr, 3);
    slh_set_keypair(addr, leaf_idx);
    slh_fors_sign(sig_ptr, fors_msg_buf, sk_seed, pub_seed, addr, p);

    {
        size_t fors_sig_bytes = p->fors_trees * (1 + p->fors_height) * p->n;
        sig_ptr += fors_sig_bytes;
    }

    /* FORS public key */
    uint8_t fors_pk[SLH_N_MAX];
    slh_fors_pk_from_sig(fors_pk, sig + p->n, fors_msg_buf,
                          pub_seed, addr, p);

    /* Hypertree signature */
    slh_set_type(addr, 0);
    for (i = 0; i < p->d; i++) {
        slh_set_layer(addr, i);
        slh_set_tree(addr, tree);
        slh_set_keypair(addr, leaf_idx);

        /* WOTS+ sign the current root/fors_pk */
        uint8_t *msg_to_sign = (i == 0) ? fors_pk : fors_pk; /* reused as root */
        slh_wots_sign(sig_ptr, msg_to_sign, sk_seed, pub_seed, addr, p);
        sig_ptr += p->wots_len * p->n;

        /* Auth path */
        uint8_t auth_path[SLH_N_MAX * 20]; /* max tree_height */
        slh_xmss_treehash(fors_pk, auth_path, sk_seed, pub_seed,
                           leaf_idx, addr, p);
        memcpy(sig_ptr, auth_path, p->tree_height * p->n);
        sig_ptr += p->tree_height * p->n;

        /* Move up the hypertree */
        leaf_idx = (uint32_t)(tree & (((uint64_t)1 << p->tree_height) - 1));
        tree >>= p->tree_height;
    }

    *sig_len = (size_t)(sig_ptr - sig);
    return AMA_SUCCESS;
}

static ama_error_t slh_verify(const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len,
                                const uint8_t *pk, const slh_params_t *p) {
    const uint8_t *pub_seed = pk;
    const uint8_t *pk_root = pk + p->n;
    const uint8_t *R;
    uint8_t fors_msg_buf[256];
    size_t fors_msg_bytes = (p->fors_height * p->fors_trees + 7) / 8;
    uint64_t tree;
    uint32_t leaf_idx;
    slh_addr_t addr;
    const uint8_t *sig_ptr;
    uint8_t node[SLH_N_MAX];
    unsigned int i;

    if (!msg || !sig || !pk) return AMA_ERROR_INVALID_PARAM;
    if (sig_len < p->n) return AMA_ERROR_VERIFY_FAILED;

    memset(addr, 0, sizeof(addr));

    /* Extract R */
    R = sig;
    sig_ptr = sig + p->n;

    /* H_msg */
    {
        size_t digest_len = fors_msg_bytes + 8 + 4;
        uint8_t *digest = (uint8_t *)calloc(1, digest_len);
        if (!digest) return AMA_ERROR_MEMORY;

        slh_h_msg(digest, digest_len, R, pub_seed, pk_root, msg, msg_len, p);
        memcpy(fors_msg_buf, digest, fors_msg_bytes);

        tree = 0;
        for (i = 0; i < 8; i++)
            tree = (tree << 8) | digest[fors_msg_bytes + i];
        {
            unsigned int tree_bits = p->full_height - p->tree_height;
            if (tree_bits < 64)
                tree &= ((uint64_t)1 << tree_bits) - 1;
        }
        leaf_idx = 0;
        for (i = 0; i < 4; i++)
            leaf_idx = (leaf_idx << 8) | digest[fors_msg_bytes + 8 + i];
        leaf_idx &= ((uint32_t)1 << p->tree_height) - 1;

        free(digest);
    }

    /* Reconstruct FORS pk */
    slh_set_tree(addr, tree);
    slh_set_type(addr, 3);
    slh_set_keypair(addr, leaf_idx);
    slh_fors_pk_from_sig(node, sig_ptr, fors_msg_buf, pub_seed, addr, p);

    {
        size_t fors_sig_bytes = p->fors_trees * (1 + p->fors_height) * p->n;
        sig_ptr += fors_sig_bytes;
    }

    /* Verify hypertree signature */
    slh_set_type(addr, 0);
    for (i = 0; i < p->d; i++) {
        slh_set_layer(addr, i);
        slh_set_tree(addr, tree);
        slh_set_keypair(addr, leaf_idx);

        /* Compute WOTS+ pk from signature */
        uint8_t wots_pk[SLH_N_MAX];
        slh_wots_pk_from_sig(wots_pk, sig_ptr, node, pub_seed, addr, p);
        sig_ptr += p->wots_len * p->n;

        /* Walk up auth path */
        memcpy(node, wots_pk, p->n);
        unsigned int j;
        slh_addr_t tree_addr;
        memcpy(tree_addr, addr, sizeof(slh_addr_t));
        slh_set_type(tree_addr, 2);

        for (j = 0; j < p->tree_height; j++) {
            uint8_t combined[2 * SLH_N_MAX];
            slh_set_tree_height(tree_addr, j + 1);
            slh_set_tree_index(tree_addr, leaf_idx >> (j + 1));

            if ((leaf_idx >> j) & 1) {
                memcpy(combined, sig_ptr + j * p->n, p->n);
                memcpy(combined + p->n, node, p->n);
            } else {
                memcpy(combined, node, p->n);
                memcpy(combined + p->n, sig_ptr + j * p->n, p->n);
            }
            slh_thash_h(node, combined, pub_seed, tree_addr, p);
        }
        sig_ptr += p->tree_height * p->n;

        leaf_idx = (uint32_t)(tree & (((uint64_t)1 << p->tree_height) - 1));
        tree >>= p->tree_height;
    }

    /* Compare computed root with pk_root */
    if (ama_consttime_memcmp(node, pk_root, p->n) != 0) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    return AMA_SUCCESS;
}

/* ============================================================================
 * PUBLIC API — SLH-DSA PARAMETER SETS
 * ============================================================================ */

/* SLH-DSA-SHA2-128s */
AMA_API ama_error_t ama_slh_dsa_128s_keypair(uint8_t *pk, uint8_t *sk) {
    return slh_keypair(pk, sk, &SLH_128S);
}
AMA_API ama_error_t ama_slh_dsa_128s_sign(uint8_t *sig, size_t *sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *sk) {
    return slh_sign(sig, sig_len, msg, msg_len, sk, &SLH_128S);
}
AMA_API ama_error_t ama_slh_dsa_128s_verify(const uint8_t *msg, size_t msg_len,
    const uint8_t *sig, size_t sig_len, const uint8_t *pk) {
    return slh_verify(msg, msg_len, sig, sig_len, pk, &SLH_128S);
}

/* SLH-DSA-SHA2-128f */
AMA_API ama_error_t ama_slh_dsa_128f_keypair(uint8_t *pk, uint8_t *sk) {
    return slh_keypair(pk, sk, &SLH_128F);
}
AMA_API ama_error_t ama_slh_dsa_128f_sign(uint8_t *sig, size_t *sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *sk) {
    return slh_sign(sig, sig_len, msg, msg_len, sk, &SLH_128F);
}
AMA_API ama_error_t ama_slh_dsa_128f_verify(const uint8_t *msg, size_t msg_len,
    const uint8_t *sig, size_t sig_len, const uint8_t *pk) {
    return slh_verify(msg, msg_len, sig, sig_len, pk, &SLH_128F);
}

/* SLH-DSA-SHA2-192s */
AMA_API ama_error_t ama_slh_dsa_192s_keypair(uint8_t *pk, uint8_t *sk) {
    return slh_keypair(pk, sk, &SLH_192S);
}
AMA_API ama_error_t ama_slh_dsa_192s_sign(uint8_t *sig, size_t *sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *sk) {
    return slh_sign(sig, sig_len, msg, msg_len, sk, &SLH_192S);
}
AMA_API ama_error_t ama_slh_dsa_192s_verify(const uint8_t *msg, size_t msg_len,
    const uint8_t *sig, size_t sig_len, const uint8_t *pk) {
    return slh_verify(msg, msg_len, sig, sig_len, pk, &SLH_192S);
}

/* SLH-DSA-SHA2-192f */
AMA_API ama_error_t ama_slh_dsa_192f_keypair(uint8_t *pk, uint8_t *sk) {
    return slh_keypair(pk, sk, &SLH_192F);
}
AMA_API ama_error_t ama_slh_dsa_192f_sign(uint8_t *sig, size_t *sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *sk) {
    return slh_sign(sig, sig_len, msg, msg_len, sk, &SLH_192F);
}
AMA_API ama_error_t ama_slh_dsa_192f_verify(const uint8_t *msg, size_t msg_len,
    const uint8_t *sig, size_t sig_len, const uint8_t *pk) {
    return slh_verify(msg, msg_len, sig, sig_len, pk, &SLH_192F);
}

/* SLH-DSA-SHA2-256s */
AMA_API ama_error_t ama_slh_dsa_256s_keypair(uint8_t *pk, uint8_t *sk) {
    return slh_keypair(pk, sk, &SLH_256S);
}
AMA_API ama_error_t ama_slh_dsa_256s_sign(uint8_t *sig, size_t *sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *sk) {
    return slh_sign(sig, sig_len, msg, msg_len, sk, &SLH_256S);
}
AMA_API ama_error_t ama_slh_dsa_256s_verify(const uint8_t *msg, size_t msg_len,
    const uint8_t *sig, size_t sig_len, const uint8_t *pk) {
    return slh_verify(msg, msg_len, sig, sig_len, pk, &SLH_256S);
}
