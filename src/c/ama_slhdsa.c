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
 * @file ama_slhdsa.c
 * @brief NIST FIPS 205 SLH-DSA — parameter-driven native implementation.
 * @author Andrew E. A., Steel Security Advisors LLC
 *
 * Implements two FIPS 205 parameter sets in a single parameter-driven core:
 *
 *   - SLH-DSA-SHA2-256f-simple  (NIST category 5; pk=64, sk=128, sig=49856)
 *       Hash family: SHA-256 (F) + SHA-512 (H/T_l) + MGF1-SHA-512 (H_msg)
 *                  + HMAC-SHA-512 (PRF_msg) + SHA-256 (PRF), per FIPS 205 §11.2.
 *       Address: 22-byte compressed ADRSc per FIPS 205 §11.2.
 *
 *   - SLH-DSA-SHAKE-128s         (NIST category 1; pk=32, sk=64,  sig=7856)
 *       Hash family: SHAKE-256 for every primitive (H_msg, PRF, PRF_msg,
 *                  F, H, T_l) per FIPS 205 §11.1.
 *       Address: full 32-byte uncompressed ADRS per FIPS 205 §4.3.
 *
 * Provenance:
 *   In-house implementation derived solely from NIST FIPS 205 (August 2024
 *   final) §4–§11 pseudocode plus the SHA-2 / SHAKE-256 primitives in
 *   src/c/ama_sha256.c, src/c/internal/ama_sha2.h, and src/c/ama_sha3.c.
 *   No code derived from sphincs/sphincsplus, PQClean, liboqs, or any
 *   other third-party PQC implementation. See src/c/PROVENANCE.md.
 *
 * Validation:
 *   - SHA2-256f path: byte-exact against NIST ACVP SLH-DSA-sigVer-FIPS205
 *     (existing tests/kat/fips205/SLH-DSA-sigVer-FIPS205.json), reused via
 *     the legacy ama_sphincs_* shim.
 *   - SHAKE-128s path: byte-exact against NIST ACVP SLH-DSA-sigGen-FIPS205
 *     deterministic external/pure vectors (tcIds 214–220). See
 *     tests/kat/fips205/slhdsa_shake_128s_siggen_acvp.json.
 *
 * Backward compatibility:
 *   ama_sphincs_keypair / ama_sphincs_sign / ama_sphincs_verify and the
 *   legacy AMA_SPHINCS_256F_*_BYTES constants are preserved; the legacy
 *   entry points thin-wrap into this file's parameter-driven core with
 *   AMA_SLHDSA_SHA2_256F.
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
 * Parameter table (FIPS 205 Table 2)
 * ============================================================================ */

typedef struct slhdsa_params {
    ama_slhdsa_param_set_t id;
    /* core params */
    size_t n;             /* security parameter (bytes) */
    size_t full_height;   /* h: total tree height */
    size_t d;             /* number of hypertree layers */
    size_t tree_height;   /* h' = h/d */
    size_t fors_height;   /* a */
    size_t fors_trees;    /* k */
    size_t wots_w;        /* Winternitz w */
    size_t wots_logw;     /* lg(w) */
    size_t wots_len1;     /* 8n / lg(w) */
    size_t wots_len2;     /* see FIPS 205 §6.1 */
    size_t wots_len;      /* len1 + len2 */
    size_t md_bytes;      /* digest length m for H_msg, in bytes */
    size_t pk_bytes;      /* 2n */
    size_t sk_bytes;      /* 4n */
    size_t sig_bytes;     /* full signature length */
    size_t fors_msg_bytes;/* ceil((a*k + 8 + h - h/d ... ) / 8) — see compute */
    size_t fors_bytes;    /* k * (a+1) * n */
    size_t wots_sig_bytes;/* len * n */
    int    use_compressed_adrs; /* 1 for SHA2 family, 0 for SHAKE family */
    /* Address type codes used when calling PRF.
     * SHA2 family: same as the surrounding chain/tree type (the existing
     *   -256f path passes NIST ACVP using WOTS_HASH/FORS_TREE for PRF).
     * SHAKE family: FIPS 205 §6 Algorithms 5/16 use separate WOTS_PRF=5
     *   and FORS_PRF=6 type codes for the PRF input ADRS. */
    uint32_t wots_prf_type;
    uint32_t fors_prf_type;

    /* hash chain — function pointers parameterized over n / wide-output */
    void (*hash_F)(const struct slhdsa_params *p, uint8_t *out,
                   const uint8_t *pub_seed, const uint32_t adrs[8],
                   const uint8_t *m);
    void (*hash_HT)(const struct slhdsa_params *p, uint8_t *out,
                    const uint8_t *pub_seed, const uint32_t adrs[8],
                    const uint8_t *m, size_t inblocks);
    void (*prf)(const struct slhdsa_params *p, uint8_t *out,
                const uint8_t *pub_seed, const uint32_t adrs[8],
                const uint8_t *sk_seed);
    int  (*prf_msg)(const struct slhdsa_params *p, uint8_t *out,
                    const uint8_t *sk_prf, const uint8_t *opt_rand,
                    const uint8_t *msg, size_t msglen);
    int  (*hash_msg)(const struct slhdsa_params *p, uint8_t *out,
                     const uint8_t *R, const uint8_t *pk,
                     const uint8_t *msg, size_t msglen);
} slhdsa_params_t;

/* ----------------------------------------------------------------------------
 * Address helpers — we use a uniform uint32_t[8] in-memory representation and
 * serialize to either 22-byte compressed (SHA2) or 32-byte uncompressed
 * (SHAKE) form at hashing time, per FIPS 205 §4.2 / §4.3 / §11.2.
 *
 * Layout matches ama_sphincs.c:
 *   adrs[0]   = layer            (1 byte effective in compressed form)
 *   adrs[1]   = tree (high 32 bits)
 *   adrs[2]   = tree (low  32 bits)
 *   adrs[3]   = type
 *   adrs[5]   = keypair address
 *   adrs[6]   = chain / tree height
 *   adrs[7]   = hash addr / tree index
 * ---------------------------------------------------------------------------- */

#define SLH_ADDR_TYPE_WOTS     0
#define SLH_ADDR_TYPE_WOTSPK   1
#define SLH_ADDR_TYPE_HASHTREE 2
#define SLH_ADDR_TYPE_FORSTREE 3
#define SLH_ADDR_TYPE_FORSPK   4
/* SHAKE family uses separate PRF address types (FIPS 205 §6 / §8). For the
 * SHA2 family ama_sphincs.c proves byte-exact NIST ACVP compliance with the
 * surrounding chain/tree type left in place; the per-family wots_prf_type /
 * fors_prf_type fields in slhdsa_params_t encode this distinction. */
#define SLH_ADDR_TYPE_WOTS_PRF 5
#define SLH_ADDR_TYPE_FORS_PRF 6

static void slh_set_layer(uint32_t a[8], uint32_t v)   { a[0] = v; }
static void slh_set_tree(uint32_t a[8], uint64_t v)    {
    a[1] = (uint32_t)(v >> 32);
    a[2] = (uint32_t)v;
}
static void slh_set_type(uint32_t a[8], uint32_t v) {
    a[3] = v;
    a[4] = 0; a[5] = 0; a[6] = 0; a[7] = 0;
}
static void slh_set_keypair(uint32_t a[8], uint32_t v) { a[5] = v; }
static void slh_set_chain(uint32_t a[8], uint32_t v)   { a[6] = v; }
static void slh_set_hash(uint32_t a[8], uint32_t v)    { a[7] = v; }
static void slh_set_tree_height(uint32_t a[8], uint32_t v) { a[6] = v; }
static void slh_set_tree_index(uint32_t a[8], uint32_t v)  { a[7] = v; }
static void slh_copy_keypair_for_wotspk(uint32_t out[8], const uint32_t in[8]) {
    /* FIPS 205 Algorithms 7/18: copy (layer, tree, keypair), set type=WOTSPK,
     * zero (chain/height, hash/index). */
    out[0] = in[0];
    out[1] = in[1];
    out[2] = in[2];
    out[3] = SLH_ADDR_TYPE_WOTSPK;
    out[4] = 0;
    out[5] = in[5];
    out[6] = 0;
    out[7] = 0;
}

/* Serialize ADRS into compressed (22 B) or uncompressed (32 B) form. */
static void slh_addr_serialize(const slhdsa_params_t *p, uint8_t *out,
                               const uint32_t a[8]) {
    if (p->use_compressed_adrs) {
        /* 22-byte ADRSc per FIPS 205 §11.2:
         *   ADRS[3] || ADRS[8:16] || ADRS[19] || ADRS[20:32]
         * Mirrors spx_addr_compress() in ama_sphincs.c byte-for-byte. */
        out[0]  = (uint8_t)a[0];
        out[1]  = (uint8_t)(a[1] >> 24); out[2]  = (uint8_t)(a[1] >> 16);
        out[3]  = (uint8_t)(a[1] >> 8);  out[4]  = (uint8_t)a[1];
        out[5]  = (uint8_t)(a[2] >> 24); out[6]  = (uint8_t)(a[2] >> 16);
        out[7]  = (uint8_t)(a[2] >> 8);  out[8]  = (uint8_t)a[2];
        out[9]  = (uint8_t)a[3];
        out[10] = (uint8_t)(a[5] >> 24); out[11] = (uint8_t)(a[5] >> 16);
        out[12] = (uint8_t)(a[5] >> 8);  out[13] = (uint8_t)a[5];
        out[14] = (uint8_t)(a[6] >> 24); out[15] = (uint8_t)(a[6] >> 16);
        out[16] = (uint8_t)(a[6] >> 8);  out[17] = (uint8_t)a[6];
        out[18] = (uint8_t)(a[7] >> 24); out[19] = (uint8_t)(a[7] >> 16);
        out[20] = (uint8_t)(a[7] >> 8);  out[21] = (uint8_t)a[7];
    } else {
        /* 32-byte uncompressed ADRS per FIPS 205 §4.2:
         *   layer(4) || tree(12 = high32 || mid32 || low32) || type(4) ||
         *   keypair(4) || chain/height(4) || hash/index(4)
         * Tree's high 32 bits sit in bytes [4:8] and are zero in our 64-bit
         * tree usage (FIPS 205 caps tree at 2^(h-h'); both 256f and 128s fit
         * in 64 bits, so the top 4 bytes are always zero). */
        out[0]  = (uint8_t)(a[0] >> 24); out[1]  = (uint8_t)(a[0] >> 16);
        out[2]  = (uint8_t)(a[0] >> 8);  out[3]  = (uint8_t)a[0];
        out[4]  = 0; out[5] = 0; out[6] = 0; out[7] = 0;
        out[8]  = (uint8_t)(a[1] >> 24); out[9]  = (uint8_t)(a[1] >> 16);
        out[10] = (uint8_t)(a[1] >> 8);  out[11] = (uint8_t)a[1];
        out[12] = (uint8_t)(a[2] >> 24); out[13] = (uint8_t)(a[2] >> 16);
        out[14] = (uint8_t)(a[2] >> 8);  out[15] = (uint8_t)a[2];
        out[16] = (uint8_t)(a[3] >> 24); out[17] = (uint8_t)(a[3] >> 16);
        out[18] = (uint8_t)(a[3] >> 8);  out[19] = (uint8_t)a[3];
        out[20] = (uint8_t)(a[5] >> 24); out[21] = (uint8_t)(a[5] >> 16);
        out[22] = (uint8_t)(a[5] >> 8);  out[23] = (uint8_t)a[5];
        out[24] = (uint8_t)(a[6] >> 24); out[25] = (uint8_t)(a[6] >> 16);
        out[26] = (uint8_t)(a[6] >> 8);  out[27] = (uint8_t)a[6];
        out[28] = (uint8_t)(a[7] >> 24); out[29] = (uint8_t)(a[7] >> 16);
        out[30] = (uint8_t)(a[7] >> 8);  out[31] = (uint8_t)a[7];
    }
}

/* ============================================================================
 * SHA2-256f-simple hash chain (FIPS 205 §11.2, NIST category 5)
 * ============================================================================ */

/* MGF1-SHA-512 used for H_msg in NIST categories 3/5. */
static void sha2_mgf1_sha512(uint8_t *out, size_t outlen,
                             const uint8_t *seed, size_t seedlen) {
    uint8_t buf[64];
    /* Max seed in our use: R(n) + PK.seed(n) + SHA-512(64) = 32+32+64 = 128. */
    uint8_t hashbuf[160 + 4];
    size_t i, blocks, tocopy;
    if (seedlen > sizeof(hashbuf) - 4) {
        return;
    }
    memcpy(hashbuf, seed, seedlen);
    blocks = (outlen + 63) / 64;
    for (i = 0; i < blocks; ++i) {
        hashbuf[seedlen]     = (uint8_t)(i >> 24);
        hashbuf[seedlen + 1] = (uint8_t)(i >> 16);
        hashbuf[seedlen + 2] = (uint8_t)(i >> 8);
        hashbuf[seedlen + 3] = (uint8_t)i;
        ama_sha512(hashbuf, seedlen + 4, buf);
        tocopy = (outlen - i * 64 < 64) ? outlen - i * 64 : 64;
        memcpy(out + i * 64, buf, tocopy);
    }
    ama_secure_memzero(buf, sizeof(buf));
    ama_secure_memzero(hashbuf, sizeof(hashbuf));
}

static void sha2_F(const slhdsa_params_t *p, uint8_t *out,
                   const uint8_t *pub_seed, const uint32_t adrs[8],
                   const uint8_t *m) {
    /* F = Trunc_n(SHA-256(PK.seed || toByte(0, 64-n) || ADRSc || M_1)) */
    uint8_t addr_c[22];
    uint8_t padding[64];
    uint8_t hash[32];
    ama_sha256_ctx ctx;

    slh_addr_serialize(p, addr_c, adrs);
    memset(padding, 0, sizeof(padding));

    ama_sha256_init(&ctx);
    ama_sha256_update(&ctx, pub_seed, p->n);
    ama_sha256_update(&ctx, padding, 64 - p->n);
    ama_sha256_update(&ctx, addr_c, 22);
    ama_sha256_update(&ctx, m, p->n);
    ama_sha256_final(&ctx, hash);
    memcpy(out, hash, p->n);
    ama_secure_memzero(hash, sizeof(hash));
}

/* sha2_HT input bound: header (128 bytes: PK.seed || toByte(0,128-n)) +
 * compressed ADRSc (22 bytes) + msglen, where msglen = inblocks * n. The
 * largest caller is the WOTS public-key compression in slh_xmss_gen_leaf,
 * which uses inblocks = wots_len. For the SHA2 family parameter sets we
 * actually ship — currently SLH-DSA-SHA2-256f-simple, with n=32 and
 * wots_len=67 — that yields msglen ≤ 67*32 = 2144 and a total ≤ 2294.
 *
 * The bound below covers every NIST FIPS 205 SHA2 parameter set (the
 * worst case is SLH-DSA-SHA2-256s/f with n=32, wots_len=67); using a
 * fixed stack buffer here removes a silent OOM-on-calloc corruption
 * path on the hot signing/verification loop and removes an attacker
 * influence over heap allocator state during signing. */
#define AMA_SLHDSA_SHA2_HT_BUF_BYTES 2304u

static void sha2_HT(const slhdsa_params_t *p, uint8_t *out,
                    const uint8_t *pub_seed, const uint32_t adrs[8],
                    const uint8_t *m, size_t inblocks) {
    /* H / T_l = Trunc_n(SHA-512(PK.seed || toByte(0, 128-n) || ADRSc || M)) */
    uint8_t addr_c[22];
    uint8_t hash[64];
    uint8_t buf[AMA_SLHDSA_SHA2_HT_BUF_BYTES];
    size_t total, msglen;

    slh_addr_serialize(p, addr_c, adrs);
    msglen = inblocks * p->n;
    total = p->n + (128 - p->n) + 22 + msglen;
    /* Defensive bound check: any future parameter set exceeding the static
     * envelope is a programming error, not a runtime input. Refuse to write
     * a half-formed digest rather than corrupting the chain silently. */
    if (total > sizeof(buf)) {
        ama_secure_memzero(out, p->n);
        return;
    }
    memset(buf, 0, total);
    memcpy(buf, pub_seed, p->n);
    /* toByte(0, 128-n) is left as zeros from the memset above. */
    memcpy(buf + 128, addr_c, 22);
    if (msglen > 0) memcpy(buf + 150, m, msglen);
    ama_sha512(buf, total, hash);
    memcpy(out, hash, p->n);
    ama_secure_memzero(hash, sizeof(hash));
    ama_secure_memzero(buf, total);
}

static void sha2_PRF(const slhdsa_params_t *p, uint8_t *out,
                     const uint8_t *pub_seed, const uint32_t adrs[8],
                     const uint8_t *sk_seed) {
    /* PRF = Trunc_n(SHA-256(PK.seed || toByte(0, 64-n) || ADRSc || SK.seed)) */
    uint8_t addr_c[22];
    uint8_t padding[64];
    uint8_t hash[32];
    ama_sha256_ctx ctx;

    slh_addr_serialize(p, addr_c, adrs);
    memset(padding, 0, sizeof(padding));

    ama_sha256_init(&ctx);
    ama_sha256_update(&ctx, pub_seed, p->n);
    ama_sha256_update(&ctx, padding, 64 - p->n);
    ama_sha256_update(&ctx, addr_c, 22);
    ama_sha256_update(&ctx, sk_seed, p->n);
    ama_sha256_final(&ctx, hash);
    memcpy(out, hash, p->n);
    ama_secure_memzero(hash, sizeof(hash));
}

static int sha2_PRF_msg(const slhdsa_params_t *p, uint8_t *out,
                        const uint8_t *sk_prf, const uint8_t *opt_rand,
                        const uint8_t *msg, size_t msglen) {
    /* PRF_msg = Trunc_n(HMAC-SHA-512(SK.prf, opt_rand || M)) */
    uint8_t hmac_out[64];
    if (ama_hmac_sha512_3(sk_prf, p->n, opt_rand, p->n, msg, msglen,
                          NULL, 0, hmac_out) != 0) {
        return -1;
    }
    memcpy(out, hmac_out, p->n);
    ama_secure_memzero(hmac_out, sizeof(hmac_out));
    return 0;
}

static int sha2_H_msg(const slhdsa_params_t *p, uint8_t *out,
                      const uint8_t *R, const uint8_t *pk,
                      const uint8_t *msg, size_t msglen) {
    /* H_msg = MGF1-SHA-512(R || PK.seed || SHA-512(R || PK.seed || PK.root || M), m)
     * Categories 3/5 only — see FIPS 205 §11.2 Table 5. */
    uint8_t hash[64];
    uint8_t mgf_seed[160];   /* n + n + 64, ≤ 32+32+64 = 128 */
    uint8_t *inner_buf;
    size_t inner_len;
    size_t mgf_seed_len = p->n + p->n + 64;

    inner_len = p->n + 2 * p->n + msglen;
    inner_buf = (uint8_t *)calloc((size_t)1, inner_len);
    if (!inner_buf) {
        return -1;
    }
    memcpy(inner_buf, R, p->n);
    memcpy(inner_buf + p->n, pk, 2 * p->n);
    memcpy(inner_buf + 3 * p->n, msg, msglen);
    ama_sha512(inner_buf, inner_len, hash);
    ama_secure_memzero(inner_buf, inner_len);
    free(inner_buf);

    memcpy(mgf_seed, R, p->n);
    memcpy(mgf_seed + p->n, pk, p->n);   /* PK.seed only */
    memcpy(mgf_seed + 2 * p->n, hash, 64);
    sha2_mgf1_sha512(out, p->md_bytes, mgf_seed, mgf_seed_len);

    ama_secure_memzero(hash, sizeof(hash));
    ama_secure_memzero(mgf_seed, sizeof(mgf_seed));
    return 0;
}

/* ============================================================================
 * SHAKE family hash chain (FIPS 205 §11.1) — used by SHAKE-128s
 *
 * All five hashes are built on SHAKE-256 with the full uncompressed 32-byte
 * ADRS. Reuses the streaming SHAKE-256 API in ama_sha3.c to absorb multiple
 * input segments without an intermediate concatenation buffer.
 * ============================================================================ */

static int shake_absorb_three(const uint8_t *a, size_t alen,
                              const uint8_t *b, size_t blen,
                              const uint8_t *c, size_t clen,
                              uint8_t *out, size_t outlen) {
    ama_sha3_ctx ctx;
    if (ama_shake256_inc_init(&ctx) != AMA_SUCCESS) return -1;
    if (alen && ama_shake256_inc_absorb(&ctx, a, alen) != AMA_SUCCESS) return -1;
    if (blen && ama_shake256_inc_absorb(&ctx, b, blen) != AMA_SUCCESS) return -1;
    if (clen && ama_shake256_inc_absorb(&ctx, c, clen) != AMA_SUCCESS) return -1;
    if (ama_shake256_inc_finalize(&ctx) != AMA_SUCCESS) return -1;
    if (ama_shake256_inc_squeeze(&ctx, out, outlen) != AMA_SUCCESS) return -1;
    ama_secure_memzero(&ctx, sizeof(ctx));
    return 0;
}

static int shake_absorb_four(const uint8_t *a, size_t alen,
                             const uint8_t *b, size_t blen,
                             const uint8_t *c, size_t clen,
                             const uint8_t *d, size_t dlen,
                             uint8_t *out, size_t outlen) {
    ama_sha3_ctx ctx;
    if (ama_shake256_inc_init(&ctx) != AMA_SUCCESS) return -1;
    if (alen && ama_shake256_inc_absorb(&ctx, a, alen) != AMA_SUCCESS) return -1;
    if (blen && ama_shake256_inc_absorb(&ctx, b, blen) != AMA_SUCCESS) return -1;
    if (clen && ama_shake256_inc_absorb(&ctx, c, clen) != AMA_SUCCESS) return -1;
    if (dlen && ama_shake256_inc_absorb(&ctx, d, dlen) != AMA_SUCCESS) return -1;
    if (ama_shake256_inc_finalize(&ctx) != AMA_SUCCESS) return -1;
    if (ama_shake256_inc_squeeze(&ctx, out, outlen) != AMA_SUCCESS) return -1;
    ama_secure_memzero(&ctx, sizeof(ctx));
    return 0;
}

static void shake_F(const slhdsa_params_t *p, uint8_t *out,
                    const uint8_t *pub_seed, const uint32_t adrs[8],
                    const uint8_t *m) {
    /* F(PK.seed, ADRS, M_1) = SHAKE-256(PK.seed || ADRS || M_1, 8n) */
    uint8_t addr_full[32];
    slh_addr_serialize(p, addr_full, adrs);
    (void)shake_absorb_three(pub_seed, p->n, addr_full, 32, m, p->n, out, p->n);
    ama_secure_memzero(addr_full, sizeof(addr_full));
}

static void shake_HT(const slhdsa_params_t *p, uint8_t *out,
                     const uint8_t *pub_seed, const uint32_t adrs[8],
                     const uint8_t *m, size_t inblocks) {
    /* H(PK.seed, ADRS, M_2) = T_l(...) = SHAKE-256(PK.seed || ADRS || M, 8n) */
    uint8_t addr_full[32];
    slh_addr_serialize(p, addr_full, adrs);
    (void)shake_absorb_three(pub_seed, p->n, addr_full, 32,
                             m, inblocks * p->n, out, p->n);
    ama_secure_memzero(addr_full, sizeof(addr_full));
}

static void shake_PRF(const slhdsa_params_t *p, uint8_t *out,
                      const uint8_t *pub_seed, const uint32_t adrs[8],
                      const uint8_t *sk_seed) {
    /* PRF(PK.seed, SK.seed, ADRS) = SHAKE-256(PK.seed || ADRS || SK.seed, 8n) */
    uint8_t addr_full[32];
    slh_addr_serialize(p, addr_full, adrs);
    (void)shake_absorb_three(pub_seed, p->n, addr_full, 32,
                             sk_seed, p->n, out, p->n);
    ama_secure_memzero(addr_full, sizeof(addr_full));
}

static int shake_PRF_msg(const slhdsa_params_t *p, uint8_t *out,
                         const uint8_t *sk_prf, const uint8_t *opt_rand,
                         const uint8_t *msg, size_t msglen) {
    /* PRF_msg(SK.prf, opt_rand, M) = SHAKE-256(SK.prf || opt_rand || M, 8n) */
    return shake_absorb_three(sk_prf, p->n, opt_rand, p->n,
                              msg, msglen, out, p->n);
}

static int shake_H_msg(const slhdsa_params_t *p, uint8_t *out,
                       const uint8_t *R, const uint8_t *pk,
                       const uint8_t *msg, size_t msglen) {
    /* H_msg(R, PK.seed, PK.root, M) = SHAKE-256(R || PK.seed || PK.root || M, 8m) */
    return shake_absorb_four(R, p->n, pk, p->n, pk + p->n, p->n,
                             msg, msglen, out, p->md_bytes);
}

/* ============================================================================
 * Parameter set tables
 * ============================================================================ */

/* SLH-DSA-SHA2-256f-simple constants (FIPS 205 Table 2):
 *   n=32, h=68, d=17, h'=4, a=9, k=35, lg(w)=4 → w=16
 *   len1 = 64, len2 = 3, len = 67, m = 49 (FIPS 205 §11.2)
 *   FORS_BYTES = k*(a+1)*n = 35*10*32 = 11200
 *   WOTS_SIG  = len*n     = 67*32     = 2144
 *   HT_SIG    = d*(WOTS_SIG + h'*n)   = 17*(2144 + 128) = 38624
 *   sig_bytes = n + FORS_BYTES + HT_SIG = 32 + 11200 + 38624 = 49856 ✓
 *   fors_msg_bytes = ceil((a*k + h - h/d + h/d) / 8 ... ) — split:
 *     k*a bits for FORS indices (= 35*9 = 315 bits → 40 bytes)
 *     ceil((h - h/d) / 8) = ceil(64/8) = 8 bytes for tree index
 *     ceil((h/d) / 8) = ceil(4/8) = 1 byte for leaf index
 *     => 40 + 8 + 1 = 49 ✓ (matches existing SPX_FORS_MSG_BYTES + 8 + 4 logic)
 * Mirrors ama_sphincs.c byte-for-byte.
 */
static const slhdsa_params_t SLHDSA_PARAMS_SHA2_256F = {
    AMA_SLHDSA_SHA2_256F,
    32, 68, 17, 4, 9, 35, 16, 4, 64, 3, 67,
    49, /* m = 49 bytes (40+8+1) */
    64, 128, 49856,
    40,            /* fors_msg_bytes = ceil(k*a/8) */
    11200,
    2144,
    1,
    /* SHA2 path PRF call sites leave the type at WOTS_HASH/FORS_TREE — the
     * existing -256f code is byte-exact against NIST ACVP that way. */
    SLH_ADDR_TYPE_WOTS, SLH_ADDR_TYPE_FORSTREE,
    sha2_F, sha2_HT, sha2_PRF, sha2_PRF_msg, sha2_H_msg
};

/* SLH-DSA-SHAKE-128s constants (FIPS 205 Table 2):
 *   n=16, h=63, d=7, h'=9, a=12, k=14, lg(w)=4 → w=16
 *   len1 = 32, len2 = 3, len = 35, m = 30 (FIPS 205 §11.1)
 *   FORS_BYTES = 14*13*16 = 2912
 *   WOTS_SIG  = 35*16     = 560
 *   HT_SIG    = 7*(560 + 9*16) = 7*704 = 4928
 *   sig_bytes = 16 + 2912 + 4928 = 7856 ✓
 *   fors_msg_bytes_indices = ceil(k*a/8) = ceil(168/8) = 21 bytes (FORS digest)
 *   tree-index bits = h - h/d = 63 - 9 = 54 → ceil(54/8) = 7 bytes
 *   leaf-index bits = h/d = 9 → ceil(9/8) = 2 bytes
 *   total m = 21 + 7 + 2 = 30 ✓
 */
static const slhdsa_params_t SLHDSA_PARAMS_SHAKE_128S = {
    AMA_SLHDSA_SHAKE_128S,
    16, 63, 7, 9, 12, 14, 16, 4, 32, 3, 35,
    30, /* m = 30 bytes (21+7+2) */
    32, 64, 7856,
    21,            /* fors_msg_bytes = ceil(k*a/8) = 21 */
    2912,
    560,
    0,
    /* SHAKE family follows FIPS 205 §6 / §8 verbatim: PRF input ADRS uses
     * separate WOTS_PRF=5 / FORS_PRF=6 type codes. */
    SLH_ADDR_TYPE_WOTS_PRF, SLH_ADDR_TYPE_FORS_PRF,
    shake_F, shake_HT, shake_PRF, shake_PRF_msg, shake_H_msg
};

static const slhdsa_params_t *slh_lookup(ama_slhdsa_param_set_t ps) {
    switch (ps) {
        case AMA_SLHDSA_SHA2_256F:  return &SLHDSA_PARAMS_SHA2_256F;
        case AMA_SLHDSA_SHAKE_128S: return &SLHDSA_PARAMS_SHAKE_128S;
        default: return NULL;
    }
}

/* ============================================================================
 * H_msg index extraction (FIPS 205 Algorithms 19/20)
 *
 * The m-byte digest is split into three big-endian fields:
 *   bytes [0 : ceil(k*a/8)]                   → FORS message (k indices)
 *   next  ceil((h - h/d)/8)  bytes            → tree address (uint64_t)
 *   next  ceil((h/d)/8)      bytes            → leaf index (uint32_t)
 * High bits of tree/leaf are masked off to (h - h/d) and h/d respectively.
 * ============================================================================ */
static void slh_split_digest(const slhdsa_params_t *p, const uint8_t *digest,
                             uint64_t *tree, uint32_t *leaf_idx) {
    size_t fors_bytes = p->fors_msg_bytes;
    size_t tree_bits  = p->full_height - p->tree_height;
    size_t tree_bytes = (tree_bits + 7) / 8;
    size_t leaf_bytes = (p->tree_height + 7) / 8;
    uint64_t t = 0;
    uint32_t l = 0;
    size_t i;

    for (i = 0; i < tree_bytes; ++i) {
        t = (t << 8) | digest[fors_bytes + i];
    }
    if (tree_bits < 64) {
        t &= (~(uint64_t)0) >> (64 - tree_bits);
    }
    *tree = t;

    for (i = 0; i < leaf_bytes; ++i) {
        l = (l << 8) | digest[fors_bytes + tree_bytes + i];
    }
    if (p->tree_height < 32) {
        l &= ((uint32_t)1 << p->tree_height) - 1;
    }
    *leaf_idx = l;
}

/* Extract k FORS indices, each `a` bits wide, MSB-first from the digest's
 * first ceil(k*a/8) bytes. */
static void slh_extract_fors_indices(const slhdsa_params_t *p,
                                     const uint8_t *digest,
                                     unsigned int *indices) {
    size_t i;
    unsigned int byte_idx = 0;
    unsigned int bit_offset = 0;

    for (i = 0; i < p->fors_trees; ++i) {
        unsigned int bits_left = (unsigned int)p->fors_height;
        indices[i] = 0;
        while (bits_left > 0) {
            unsigned int avail = 8 - bit_offset;
            unsigned int take = (bits_left < avail) ? bits_left : avail;
            unsigned int mask = (1u << take) - 1u;
            indices[i] |= ((digest[byte_idx] >> (8 - bit_offset - take)) & mask)
                          << (bits_left - take);
            bit_offset += take;
            bits_left -= take;
            if (bit_offset >= 8) { bit_offset = 0; ++byte_idx; }
        }
    }
}

/* ============================================================================
 * WOTS+ — parameter-driven (FIPS 205 §6)
 * ============================================================================ */

static void slh_base_w(const slhdsa_params_t *p, unsigned int *out,
                       size_t outlen, const uint8_t *in) {
    /* For lg(w)=4 (both supported parameter sets) base_w = nibble extraction. */
    size_t in_idx = 0, out_idx;
    int bits = 0;
    uint8_t total = 0;
    unsigned int w_minus_1 = (unsigned int)(p->wots_w - 1);
    unsigned int logw = (unsigned int)p->wots_logw;
    for (out_idx = 0; out_idx < outlen; ++out_idx) {
        if (bits == 0) { total = in[in_idx++]; bits = 8; }
        bits -= (int)logw;
        out[out_idx] = (total >> bits) & w_minus_1;
    }
}

static void slh_wots_checksum(const slhdsa_params_t *p, unsigned int *csum_out,
                              const unsigned int *msg) {
    unsigned int csum = 0;
    size_t i;
    uint8_t csum_bytes[2];
    for (i = 0; i < p->wots_len1; ++i) {
        csum += (unsigned int)(p->wots_w - 1) - msg[i];
    }
    /* Shift left to fill complete bytes — for both supported sets:
     *   len2*logw = 3*4 = 12 bits, so shift = (8 - 12 % 8) % 8 = 4. */
    csum <<= (8 - ((p->wots_len2 * p->wots_logw) % 8)) % 8;
    csum_bytes[0] = (uint8_t)(csum >> 8);
    csum_bytes[1] = (uint8_t)csum;
    slh_base_w(p, csum_out, p->wots_len2, csum_bytes);
}

static void slh_wots_chain(const slhdsa_params_t *p, uint8_t *out,
                           const uint8_t *in, unsigned int start,
                           unsigned int steps, const uint8_t *pub_seed,
                           uint32_t addr[8]) {
    unsigned int i;
    memcpy(out, in, p->n);
    for (i = start; i < start + steps && i < p->wots_w; ++i) {
        slh_set_hash(addr, i);
        p->hash_F(p, out, pub_seed, addr, out);
    }
}

static void slh_wots_gen_pk(const slhdsa_params_t *p, uint8_t *pk,
                            const uint8_t *sk_seed, const uint8_t *pub_seed,
                            uint32_t addr[8]) {
    size_t i;
    uint8_t chain_in[32];
    uint32_t saved_type = addr[3];
    for (i = 0; i < p->wots_len; ++i) {
        slh_set_chain(addr, (uint32_t)i);
        slh_set_hash(addr, 0);
        addr[3] = p->wots_prf_type;            /* WOTS_PRF for SHAKE family */
        p->prf(p, chain_in, pub_seed, addr, sk_seed);
        addr[3] = saved_type;                  /* restore for chain hashing */
        slh_wots_chain(p, pk + i * p->n, chain_in, 0,
                       (unsigned int)(p->wots_w - 1), pub_seed, addr);
    }
    ama_secure_memzero(chain_in, sizeof(chain_in));
}

static void slh_wots_sign(const slhdsa_params_t *p, uint8_t *sig,
                          const uint8_t *msg, const uint8_t *sk_seed,
                          const uint8_t *pub_seed, uint32_t addr[8]) {
    unsigned int basew[80];   /* len ≤ 67 for either set */
    unsigned int csum[8];
    size_t i;
    uint8_t chain_in[32];
    uint32_t saved_type = addr[3];
    slh_base_w(p, basew, p->wots_len1, msg);
    slh_wots_checksum(p, csum, basew);
    for (i = 0; i < p->wots_len2; ++i) basew[p->wots_len1 + i] = csum[i];
    for (i = 0; i < p->wots_len; ++i) {
        slh_set_chain(addr, (uint32_t)i);
        slh_set_hash(addr, 0);
        addr[3] = p->wots_prf_type;
        p->prf(p, chain_in, pub_seed, addr, sk_seed);
        addr[3] = saved_type;
        slh_wots_chain(p, sig + i * p->n, chain_in, 0, basew[i],
                       pub_seed, addr);
    }
    ama_secure_memzero(chain_in, sizeof(chain_in));
}

static void slh_wots_pk_from_sig(const slhdsa_params_t *p, uint8_t *pk,
                                 const uint8_t *sig, const uint8_t *msg,
                                 const uint8_t *pub_seed, uint32_t addr[8]) {
    unsigned int basew[80];
    unsigned int csum[8];
    size_t i;
    slh_base_w(p, basew, p->wots_len1, msg);
    slh_wots_checksum(p, csum, basew);
    for (i = 0; i < p->wots_len2; ++i) basew[p->wots_len1 + i] = csum[i];
    for (i = 0; i < p->wots_len; ++i) {
        slh_set_chain(addr, (uint32_t)i);
        slh_wots_chain(p, pk + i * p->n, sig + i * p->n, basew[i],
                       (unsigned int)(p->wots_w - 1) - basew[i],
                       pub_seed, addr);
    }
}

/* ============================================================================
 * FORS — parameter-driven (FIPS 205 §8)
 * ============================================================================ */

static void slh_fors_gen_sk(const slhdsa_params_t *p, uint8_t *sk,
                            const uint8_t *sk_seed, const uint8_t *pub_seed,
                            uint32_t addr[8]) {
    /* Save the surrounding type (FORS_TREE), switch to FORS_PRF for SHAKE
     * family, call PRF, restore. SHA2 family's wots_prf_type/fors_prf_type
     * equal the surrounding type so this is a no-op there. */
    uint32_t saved_type = addr[3];
    addr[3] = p->fors_prf_type;
    p->prf(p, sk, pub_seed, addr, sk_seed);
    addr[3] = saved_type;
}

static void slh_fors_gen_leaf(const slhdsa_params_t *p, uint8_t *leaf,
                              const uint8_t *sk_seed, const uint8_t *pub_seed,
                              uint32_t idx, uint32_t addr[8]) {
    uint8_t sk[32];
    slh_set_tree_height(addr, 0);
    slh_set_tree_index(addr, idx);
    slh_fors_gen_sk(p, sk, sk_seed, pub_seed, addr);
    p->hash_F(p, leaf, pub_seed, addr, sk);
    ama_secure_memzero(sk, sizeof(sk));
}

static void slh_fors_treehash(const slhdsa_params_t *p, uint8_t *root,
                              uint8_t *auth_path, const uint8_t *sk_seed,
                              const uint8_t *pub_seed, uint32_t leaf_idx,
                              uint32_t tree_idx, uint32_t addr[8]) {
    /* Stack big enough for both parameter sets: max fors_height is 12 (SHAKE-128s)
     * and max n is 32 (SHA2-256f). 13 entries × 32 B = 416 B. */
    uint8_t  stack[(12 + 1) * 32];
    unsigned int heights[12 + 1];
    unsigned int sp = 0;
    uint32_t leaves = (uint32_t)1u << p->fors_height;
    uint32_t offset = tree_idx * leaves;
    uint32_t i;

    for (i = 0; i < leaves; ++i) {
        slh_fors_gen_leaf(p, stack + sp * p->n, sk_seed, pub_seed,
                          offset + i, addr);
        heights[sp] = 0; sp++;
        if ((leaf_idx ^ 1u) == i) {
            memcpy(auth_path, stack + (sp - 1) * p->n, p->n);
        }
        while (sp >= 2 && heights[sp - 1] == heights[sp - 2]) {
            uint32_t tree_node_idx = i >> (heights[sp - 1] + 1);
            slh_set_tree_height(addr, heights[sp - 1] + 1);
            slh_set_tree_index(addr, (offset + i) >> (heights[sp - 1] + 1));
            p->hash_HT(p, stack + (sp - 2) * p->n, pub_seed, addr,
                       stack + (sp - 2) * p->n, 2);
            sp--; heights[sp - 1]++;
            if (((leaf_idx >> heights[sp - 1]) ^ 1u) == tree_node_idx) {
                memcpy(auth_path + heights[sp - 1] * p->n,
                       stack + (sp - 1) * p->n, p->n);
            }
        }
    }
    memcpy(root, stack, p->n);
    ama_secure_memzero(stack, sizeof(stack));
}

static void slh_fors_sign(const slhdsa_params_t *p, uint8_t *sig, uint8_t *pk,
                          const uint8_t *msg_digest, const uint8_t *sk_seed,
                          const uint8_t *pub_seed, uint32_t fors_addr[8]) {
    /* Caller-provided indices buffer would be cleaner, but k≤35 across both
     * sets so we use a stack array. */
    unsigned int indices[35];
    uint8_t roots[35 * 32];
    size_t i;
    uint32_t saved_keypair;

    slh_extract_fors_indices(p, msg_digest, indices);
    for (i = 0; i < p->fors_trees; ++i) {
        slh_set_tree_height(fors_addr, 0);
        slh_set_tree_index(fors_addr,
                           (uint32_t)(i * (1u << p->fors_height) + indices[i]));
        slh_fors_gen_sk(p, sig + i * (p->fors_height + 1) * p->n,
                        sk_seed, pub_seed, fors_addr);
        slh_fors_treehash(p, roots + i * p->n,
                          sig + i * (p->fors_height + 1) * p->n + p->n,
                          sk_seed, pub_seed, indices[i], (uint32_t)i,
                          fors_addr);
    }
    saved_keypair = fors_addr[5];
    slh_set_type(fors_addr, SLH_ADDR_TYPE_FORSPK);
    fors_addr[5] = saved_keypair;
    p->hash_HT(p, pk, pub_seed, fors_addr, roots, p->fors_trees);
    ama_secure_memzero(roots, sizeof(roots));
}

static void slh_fors_pk_from_sig(const slhdsa_params_t *p, uint8_t *pk,
                                 const uint8_t *sig, const uint8_t *msg_digest,
                                 const uint8_t *pub_seed,
                                 uint32_t fors_addr[8]) {
    unsigned int indices[35];
    uint8_t roots[35 * 32];
    uint8_t node[2 * 32];
    size_t i, j;
    uint32_t saved_keypair;

    slh_extract_fors_indices(p, msg_digest, indices);
    for (i = 0; i < p->fors_trees; ++i) {
        const uint8_t *sk_val = sig + i * (p->fors_height + 1) * p->n;
        const uint8_t *auth = sk_val + p->n;
        uint32_t idx = indices[i];
        uint32_t offset = (uint32_t)(i * (1u << p->fors_height));

        slh_set_tree_height(fors_addr, 0);
        slh_set_tree_index(fors_addr, offset + idx);
        p->hash_F(p, node, pub_seed, fors_addr, sk_val);

        for (j = 0; j < p->fors_height; ++j) {
            slh_set_tree_height(fors_addr, (uint32_t)(j + 1));
            slh_set_tree_index(fors_addr, (offset + idx) >> (j + 1));
            if ((idx >> j) & 1u) {
                memcpy(node + p->n, node, p->n);
                memcpy(node, auth + j * p->n, p->n);
            } else {
                memcpy(node + p->n, auth + j * p->n, p->n);
            }
            p->hash_HT(p, node, pub_seed, fors_addr, node, 2);
        }
        memcpy(roots + i * p->n, node, p->n);
    }
    saved_keypair = fors_addr[5];
    slh_set_type(fors_addr, SLH_ADDR_TYPE_FORSPK);
    fors_addr[5] = saved_keypair;
    p->hash_HT(p, pk, pub_seed, fors_addr, roots, p->fors_trees);
    ama_secure_memzero(roots, sizeof(roots));
    ama_secure_memzero(node, sizeof(node));
}

/* ============================================================================
 * Hypertree (XMSS) — parameter-driven (FIPS 205 §9 / §10)
 * ============================================================================ */

static void slh_xmss_gen_leaf(const slhdsa_params_t *p, uint8_t *leaf,
                              const uint8_t *sk_seed, const uint8_t *pub_seed,
                              uint32_t idx, uint32_t addr[8]) {
    uint8_t wots_pk[80 * 32];   /* len*n max: 67*32 = 2144 < 80*32 */
    uint32_t wots_pk_addr[8];

    slh_set_type(addr, SLH_ADDR_TYPE_WOTS);
    slh_set_keypair(addr, idx);
    slh_wots_gen_pk(p, wots_pk, sk_seed, pub_seed, addr);

    slh_copy_keypair_for_wotspk(wots_pk_addr, addr);
    p->hash_HT(p, leaf, pub_seed, wots_pk_addr, wots_pk, p->wots_len);
    ama_secure_memzero(wots_pk, sizeof(wots_pk));
}

static void slh_xmss_treehash(const slhdsa_params_t *p, uint8_t *root,
                              uint8_t *auth_path, const uint8_t *sk_seed,
                              const uint8_t *pub_seed, uint32_t leaf_idx,
                              uint32_t addr[8]) {
    /* Max h' is 9 (SHAKE-128s), n max 32 → 10 × 32 = 320 B */
    uint8_t stack[(9 + 1) * 32];
    unsigned int heights[9 + 1];
    unsigned int sp = 0;
    uint32_t leaves = (uint32_t)1u << p->tree_height;
    uint32_t i;

    for (i = 0; i < leaves; ++i) {
        slh_xmss_gen_leaf(p, stack + sp * p->n, sk_seed, pub_seed, i, addr);
        heights[sp] = 0; sp++;
        if ((leaf_idx ^ 1u) == i) {
            memcpy(auth_path, stack + (sp - 1) * p->n, p->n);
        }
        while (sp >= 2 && heights[sp - 1] == heights[sp - 2]) {
            uint32_t tree_node_idx = i >> (heights[sp - 1] + 1);
            slh_set_type(addr, SLH_ADDR_TYPE_HASHTREE);
            slh_set_tree_height(addr, heights[sp - 1] + 1);
            slh_set_tree_index(addr, tree_node_idx);
            p->hash_HT(p, stack + (sp - 2) * p->n, pub_seed, addr,
                       stack + (sp - 2) * p->n, 2);
            sp--; heights[sp - 1]++;
            if (((leaf_idx >> heights[sp - 1]) ^ 1u) == tree_node_idx) {
                memcpy(auth_path + heights[sp - 1] * p->n,
                       stack + (sp - 1) * p->n, p->n);
            }
        }
    }
    memcpy(root, stack, p->n);
    ama_secure_memzero(stack, sizeof(stack));
}

static void slh_ht_sign(const slhdsa_params_t *p, uint8_t *sig,
                        const uint8_t *msg, uint64_t tree, uint32_t leaf_idx,
                        const uint8_t *sk_seed, const uint8_t *pub_seed) {
    uint32_t addr[8];
    uint8_t root[32];
    size_t layer;
    memset(addr, 0, sizeof(addr));

    slh_set_layer(addr, 0);
    slh_set_tree(addr, tree);

    slh_set_type(addr, SLH_ADDR_TYPE_WOTS);
    slh_set_keypair(addr, leaf_idx);
    slh_wots_sign(p, sig, msg, sk_seed, pub_seed, addr);
    sig += p->wots_sig_bytes;

    slh_set_type(addr, SLH_ADDR_TYPE_HASHTREE);
    slh_xmss_treehash(p, root, sig, sk_seed, pub_seed, leaf_idx, addr);
    sig += p->tree_height * p->n;

    for (layer = 1; layer < p->d; ++layer) {
        leaf_idx = (uint32_t)(tree & (((uint64_t)1u << p->tree_height) - 1u));
        tree >>= p->tree_height;

        slh_set_layer(addr, (uint32_t)layer);
        slh_set_tree(addr, tree);

        slh_set_type(addr, SLH_ADDR_TYPE_WOTS);
        slh_set_keypair(addr, leaf_idx);
        slh_wots_sign(p, sig, root, sk_seed, pub_seed, addr);
        sig += p->wots_sig_bytes;

        slh_set_type(addr, SLH_ADDR_TYPE_HASHTREE);
        slh_xmss_treehash(p, root, sig, sk_seed, pub_seed, leaf_idx, addr);
        sig += p->tree_height * p->n;
    }
    ama_secure_memzero(root, sizeof(root));
}

static int slh_ht_verify(const slhdsa_params_t *p, const uint8_t *msg,
                         const uint8_t *sig, uint64_t tree, uint32_t leaf_idx,
                         const uint8_t *pub_seed, const uint8_t *root_expected) {
    uint32_t addr[8];
    uint32_t wots_pk_addr[8];
    uint8_t node[32];
    uint8_t wots_pk[80 * 32];
    uint8_t combined[2 * 32];
    size_t layer;
    unsigned int h;

    memset(addr, 0, sizeof(addr));
    slh_set_layer(addr, 0);
    slh_set_tree(addr, tree);

    slh_set_type(addr, SLH_ADDR_TYPE_WOTS);
    slh_set_keypair(addr, leaf_idx);
    slh_wots_pk_from_sig(p, wots_pk, sig, msg, pub_seed, addr);
    sig += p->wots_sig_bytes;

    slh_copy_keypair_for_wotspk(wots_pk_addr, addr);
    p->hash_HT(p, node, pub_seed, wots_pk_addr, wots_pk, p->wots_len);

    for (h = 0; h < p->tree_height; ++h) {
        slh_set_type(addr, SLH_ADDR_TYPE_HASHTREE);
        slh_set_tree_height(addr, h + 1);
        slh_set_tree_index(addr, leaf_idx >> (h + 1));
        if ((leaf_idx >> h) & 1u) {
            memcpy(combined, sig + h * p->n, p->n);
            memcpy(combined + p->n, node, p->n);
        } else {
            memcpy(combined, node, p->n);
            memcpy(combined + p->n, sig + h * p->n, p->n);
        }
        p->hash_HT(p, node, pub_seed, addr, combined, 2);
    }
    sig += p->tree_height * p->n;

    for (layer = 1; layer < p->d; ++layer) {
        leaf_idx = (uint32_t)(tree & (((uint64_t)1u << p->tree_height) - 1u));
        tree >>= p->tree_height;

        slh_set_layer(addr, (uint32_t)layer);
        slh_set_tree(addr, tree);

        slh_set_type(addr, SLH_ADDR_TYPE_WOTS);
        slh_set_keypair(addr, leaf_idx);
        slh_wots_pk_from_sig(p, wots_pk, sig, node, pub_seed, addr);
        sig += p->wots_sig_bytes;

        slh_copy_keypair_for_wotspk(wots_pk_addr, addr);
        p->hash_HT(p, node, pub_seed, wots_pk_addr, wots_pk, p->wots_len);

        for (h = 0; h < p->tree_height; ++h) {
            slh_set_type(addr, SLH_ADDR_TYPE_HASHTREE);
            slh_set_tree_height(addr, h + 1);
            slh_set_tree_index(addr, leaf_idx >> (h + 1));
            if ((leaf_idx >> h) & 1u) {
                memcpy(combined, sig + h * p->n, p->n);
                memcpy(combined + p->n, node, p->n);
            } else {
                memcpy(combined, node, p->n);
                memcpy(combined + p->n, sig + h * p->n, p->n);
            }
            p->hash_HT(p, node, pub_seed, addr, combined, 2);
        }
        sig += p->tree_height * p->n;
    }

    return ama_consttime_memcmp(node, root_expected, p->n);
}

/* ============================================================================
 * Top-level keygen / sign / verify (parameter-driven, exposed C API)
 * ============================================================================ */

#ifdef AMA_TESTING_MODE
ama_error_t (*ama_slhdsa_randombytes_hook)(uint8_t *buf, size_t len) = NULL;
#endif

static ama_error_t slh_randombytes(uint8_t *buf, size_t len) {
#ifdef AMA_TESTING_MODE
    if (ama_slhdsa_randombytes_hook) {
        return ama_slhdsa_randombytes_hook(buf, len);
    }
#endif
    return ama_randombytes(buf, len);
}

/* keygen_internal: given (sk_seed, sk_prf, pk_seed) all of length n, fill pk
 * (= pk_seed || pk_root) and sk (= sk_seed || sk_prf || pk_seed || pk_root). */
static ama_error_t slh_keygen_internal(const slhdsa_params_t *p,
                                       const uint8_t *sk_seed,
                                       const uint8_t *sk_prf,
                                       const uint8_t *pk_seed,
                                       uint8_t *pk, uint8_t *sk) {
    uint32_t addr[8];
    uint8_t root[32];
    uint8_t auth_path[9 * 32];   /* h' ≤ 9 → ≤ 9*32 = 288 B */

    memset(addr, 0, sizeof(addr));
    slh_set_layer(addr, (uint32_t)(p->d - 1));
    slh_set_tree(addr, 0);

    /* Compute root of top XMSS tree from sk_seed/pk_seed. */
    slh_xmss_treehash(p, root, auth_path, sk_seed, pk_seed, 0, addr);

    /* Assemble pk = pk_seed || pk_root */
    memcpy(pk, pk_seed, p->n);
    memcpy(pk + p->n, root, p->n);

    /* Assemble sk = sk_seed || sk_prf || pk_seed || pk_root */
    memcpy(sk + 0 * p->n, sk_seed, p->n);
    memcpy(sk + 1 * p->n, sk_prf, p->n);
    memcpy(sk + 2 * p->n, pk_seed, p->n);
    memcpy(sk + 3 * p->n, root, p->n);

    ama_secure_memzero(root, sizeof(root));
    ama_secure_memzero(auth_path, sizeof(auth_path));
    return AMA_SUCCESS;
}

AMA_API ama_error_t ama_slhdsa_keygen(ama_slhdsa_param_set_t ps,
                                      uint8_t *pk, uint8_t *sk) {
    const slhdsa_params_t *p = slh_lookup(ps);
    uint8_t seeds[3 * 32];
    ama_error_t rc;
    if (!p || !pk || !sk) return AMA_ERROR_INVALID_PARAM;
    rc = slh_randombytes(seeds, 3 * p->n);
    if (rc != AMA_SUCCESS) return rc;
    rc = slh_keygen_internal(p, seeds, seeds + p->n, seeds + 2 * p->n, pk, sk);
    ama_secure_memzero(seeds, sizeof(seeds));
    return rc;
}

AMA_API ama_error_t ama_slhdsa_keygen_from_seed(ama_slhdsa_param_set_t ps,
                                                const uint8_t *sk_seed,
                                                const uint8_t *sk_prf,
                                                const uint8_t *pk_seed,
                                                uint8_t *pk, uint8_t *sk) {
    const slhdsa_params_t *p = slh_lookup(ps);
    if (!p || !sk_seed || !sk_prf || !pk_seed || !pk || !sk) {
        return AMA_ERROR_INVALID_PARAM;
    }
    return slh_keygen_internal(p, sk_seed, sk_prf, pk_seed, pk, sk);
}

/* slh_sign_internal: writes p->sig_bytes into signature given a fully-formed
 * secret key (sk = sk_seed || sk_prf || pk_seed || pk_root), randomizer
 * `opt_rand` (n bytes), and a (already context-wrapped) message. */
static ama_error_t slh_sign_internal(const slhdsa_params_t *p,
                                     uint8_t *signature,
                                     const uint8_t *opt_rand,
                                     const uint8_t *message, size_t message_len,
                                     const uint8_t *sk) {
    uint8_t pk[2 * 32];
    uint8_t R[32];
    uint8_t fors_msg[64];   /* m ≤ 49 (SHA2-256f) */
    uint64_t tree;
    uint32_t leaf_idx;
    uint8_t fors_pk[32];
    uint32_t fors_addr[8];
    uint8_t *sig_ptr = signature;

    const uint8_t *sk_seed  = sk;
    const uint8_t *sk_prf   = sk + p->n;
    const uint8_t *pub_seed = sk + 2 * p->n;
    const uint8_t *pk_root  = sk + 3 * p->n;

    memcpy(pk, pub_seed, p->n);
    memcpy(pk + p->n, pk_root, p->n);

    /* R = PRF_msg(SK.prf, opt_rand, M) */
    if (p->prf_msg(p, R, sk_prf, opt_rand, message, message_len) != 0) {
        return AMA_ERROR_MEMORY;
    }
    memcpy(sig_ptr, R, p->n);
    sig_ptr += p->n;

    /* digest = H_msg(R, PK.seed, PK.root, M); split into FORS msg + tree + leaf. */
    if (p->hash_msg(p, fors_msg, R, pk, message, message_len) != 0) {
        return AMA_ERROR_MEMORY;
    }
    slh_split_digest(p, fors_msg, &tree, &leaf_idx);

    /* FORS sign at (tree, leaf_idx). */
    memset(fors_addr, 0, sizeof(fors_addr));
    slh_set_tree(fors_addr, tree);
    slh_set_type(fors_addr, SLH_ADDR_TYPE_FORSTREE);
    slh_set_keypair(fors_addr, leaf_idx);
    slh_fors_sign(p, sig_ptr, fors_pk, fors_msg, sk_seed, pub_seed, fors_addr);
    sig_ptr += p->fors_bytes;

    /* HT sign over FORS pk. */
    slh_ht_sign(p, sig_ptr, fors_pk, tree, leaf_idx, sk_seed, pub_seed);

    ama_secure_memzero(R, sizeof(R));
    ama_secure_memzero(fors_msg, sizeof(fors_msg));
    ama_secure_memzero(fors_pk, sizeof(fors_pk));
    return AMA_SUCCESS;
}

/* ama_slhdsa_sign / verify use the FIPS 205 §10.2 external context wrapper. */
AMA_API ama_error_t ama_slhdsa_sign(ama_slhdsa_param_set_t ps,
                                    uint8_t *signature, size_t *signature_len,
                                    const uint8_t *message, size_t message_len,
                                    const uint8_t *ctx, size_t ctx_len,
                                    const uint8_t *sk) {
    const slhdsa_params_t *p = slh_lookup(ps);
    uint8_t opt_rand[32];
    uint8_t *wrapped = NULL;
    size_t wrapped_len;
    ama_error_t rc;

    if (!p || !signature || !signature_len || !message || !sk) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (ctx_len > 0 && ctx == NULL) return AMA_ERROR_INVALID_PARAM;
    if (ctx_len > 255) return AMA_ERROR_INVALID_PARAM;
    if (*signature_len < p->sig_bytes) {
        *signature_len = p->sig_bytes;
        return AMA_ERROR_INVALID_PARAM;
    }
    if (message_len > SIZE_MAX - 2 - ctx_len) return AMA_ERROR_INVALID_PARAM;

    /* opt_rand: per FIPS 205 §10.2 the hedged variant draws addrnd <- $;
     * deterministic mode uses addrnd = PK.seed (pub_seed of the secret key,
     * which equals sk[2n:3n]). NIST ACVP's deterministic vectors are the
     * latter, so we must support both. We expose the hedged form here; the
     * deterministic form is reachable via ama_slhdsa_sign_internal_det
     * for KAT validation. */
    rc = slh_randombytes(opt_rand, p->n);
    if (rc != AMA_SUCCESS) return rc;

    /* M' = 0x00 || len(ctx) || ctx || M */
    wrapped_len = 2 + ctx_len + message_len;
    wrapped = (uint8_t *)calloc((size_t)1, wrapped_len);
    if (!wrapped) {
        ama_secure_memzero(opt_rand, sizeof(opt_rand));
        return AMA_ERROR_MEMORY;
    }
    wrapped[0] = 0x00;
    wrapped[1] = (uint8_t)ctx_len;
    if (ctx_len) memcpy(wrapped + 2, ctx, ctx_len);
    memcpy(wrapped + 2 + ctx_len, message, message_len);

    rc = slh_sign_internal(p, signature, opt_rand, wrapped, wrapped_len, sk);
    if (rc == AMA_SUCCESS) *signature_len = p->sig_bytes;

    ama_secure_memzero(opt_rand, sizeof(opt_rand));
    ama_secure_memzero(wrapped, wrapped_len);
    free(wrapped);
    return rc;
}

/* slh_verify_internal: verifies (already context-wrapped) message against pk. */
static ama_error_t slh_verify_internal(const slhdsa_params_t *p,
                                       const uint8_t *signature,
                                       size_t signature_len,
                                       const uint8_t *message,
                                       size_t message_len,
                                       const uint8_t *pk) {
    const uint8_t *R, *fors_sig, *ht_sig;
    uint8_t fors_msg[64];
    uint64_t tree;
    uint32_t leaf_idx;
    uint8_t fors_pk[32];
    uint32_t fors_addr[8];
    int ok;

    if (signature_len != p->sig_bytes) return AMA_ERROR_VERIFY_FAILED;

    R = signature;
    fors_sig = R + p->n;
    ht_sig = fors_sig + p->fors_bytes;

    if (p->hash_msg(p, fors_msg, R, pk, message, message_len) != 0) {
        return AMA_ERROR_MEMORY;
    }
    slh_split_digest(p, fors_msg, &tree, &leaf_idx);

    memset(fors_addr, 0, sizeof(fors_addr));
    slh_set_tree(fors_addr, tree);
    slh_set_type(fors_addr, SLH_ADDR_TYPE_FORSTREE);
    slh_set_keypair(fors_addr, leaf_idx);
    slh_fors_pk_from_sig(p, fors_pk, fors_sig, fors_msg,
                         pk /* pub_seed = first n bytes */, fors_addr);

    ok = slh_ht_verify(p, fors_pk, ht_sig, tree, leaf_idx,
                       pk /* pub_seed */, pk + p->n /* pk_root */);
    ama_secure_memzero(fors_msg, sizeof(fors_msg));
    ama_secure_memzero(fors_pk, sizeof(fors_pk));
    return (ok == 0) ? AMA_SUCCESS : AMA_ERROR_VERIFY_FAILED;
}

AMA_API ama_error_t ama_slhdsa_verify(ama_slhdsa_param_set_t ps,
                                      const uint8_t *signature,
                                      size_t signature_len,
                                      const uint8_t *message, size_t message_len,
                                      const uint8_t *ctx, size_t ctx_len,
                                      const uint8_t *pk) {
    const slhdsa_params_t *p = slh_lookup(ps);
    uint8_t *wrapped;
    size_t wrapped_len;
    ama_error_t rc;

    if (!p || !signature || !message || !pk) return AMA_ERROR_INVALID_PARAM;
    if (ctx_len > 0 && ctx == NULL) return AMA_ERROR_INVALID_PARAM;
    if (ctx_len > 255) return AMA_ERROR_INVALID_PARAM;
    if (message_len > SIZE_MAX - 2 - ctx_len) return AMA_ERROR_INVALID_PARAM;

    wrapped_len = 2 + ctx_len + message_len;
    wrapped = (uint8_t *)calloc((size_t)1, wrapped_len);
    if (!wrapped) return AMA_ERROR_MEMORY;
    wrapped[0] = 0x00;
    wrapped[1] = (uint8_t)ctx_len;
    if (ctx_len) memcpy(wrapped + 2, ctx, ctx_len);
    memcpy(wrapped + 2 + ctx_len, message, message_len);

    rc = slh_verify_internal(p, signature, signature_len,
                             wrapped, wrapped_len, pk);
    ama_secure_memzero(wrapped, wrapped_len);
    free(wrapped);
    return rc;
}

/* ============================================================================
 * Internal "deterministic" + "internal interface" sign for KAT validation.
 *
 * The NIST ACVP SLH-DSA-sigGen-FIPS205 deterministic external/pure vectors
 * are produced with addrnd = PK.seed (FIPS 205 §10.2 line 6 sets opt_rand =
 * PK.seed when the deterministic variant is selected). Expose this as a
 * separate symbol so KAT tests can pin byte-exact signatures without
 * smuggling test-only code paths into the public hedged API.
 * ============================================================================ */
AMA_API ama_error_t ama_slhdsa_sign_deterministic(ama_slhdsa_param_set_t ps,
                                                  uint8_t *signature,
                                                  size_t *signature_len,
                                                  const uint8_t *message,
                                                  size_t message_len,
                                                  const uint8_t *ctx,
                                                  size_t ctx_len,
                                                  const uint8_t *sk) {
    const slhdsa_params_t *p = slh_lookup(ps);
    uint8_t *wrapped;
    size_t wrapped_len;
    ama_error_t rc;

    if (!p || !signature || !signature_len || !message || !sk) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (ctx_len > 0 && ctx == NULL) return AMA_ERROR_INVALID_PARAM;
    if (ctx_len > 255) return AMA_ERROR_INVALID_PARAM;
    if (*signature_len < p->sig_bytes) {
        *signature_len = p->sig_bytes;
        return AMA_ERROR_INVALID_PARAM;
    }
    if (message_len > SIZE_MAX - 2 - ctx_len) return AMA_ERROR_INVALID_PARAM;

    wrapped_len = 2 + ctx_len + message_len;
    wrapped = (uint8_t *)calloc((size_t)1, wrapped_len);
    if (!wrapped) return AMA_ERROR_MEMORY;
    wrapped[0] = 0x00;
    wrapped[1] = (uint8_t)ctx_len;
    if (ctx_len) memcpy(wrapped + 2, ctx, ctx_len);
    memcpy(wrapped + 2 + ctx_len, message, message_len);

    /* Deterministic addrnd = PK.seed (sk[2n .. 3n)). */
    rc = slh_sign_internal(p, signature, sk + 2 * p->n,
                           wrapped, wrapped_len, sk);
    if (rc == AMA_SUCCESS) *signature_len = p->sig_bytes;

    ama_secure_memzero(wrapped, wrapped_len);
    free(wrapped);
    return rc;
}

/* For ACVP "internal interface" (signatureInterface == "internal") tests we
 * need to sign the raw message with no §10.2 wrapper and an explicit
 * addrnd. Expose this as ama_slhdsa_sign_internal so KATs can call it
 * without having the public API leak addrnd injection. */
AMA_API ama_error_t ama_slhdsa_sign_internal(ama_slhdsa_param_set_t ps,
                                             uint8_t *signature,
                                             size_t *signature_len,
                                             const uint8_t *message,
                                             size_t message_len,
                                             const uint8_t *addrnd,
                                             const uint8_t *sk) {
    const slhdsa_params_t *p = slh_lookup(ps);
    ama_error_t rc;
    if (!p || !signature || !signature_len || !message || !addrnd || !sk) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (*signature_len < p->sig_bytes) {
        *signature_len = p->sig_bytes;
        return AMA_ERROR_INVALID_PARAM;
    }
    rc = slh_sign_internal(p, signature, addrnd, message, message_len, sk);
    if (rc == AMA_SUCCESS) *signature_len = p->sig_bytes;
    return rc;
}
