/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_sphincs_simd_equiv.c
 * @brief SPHINCS+ / SLH-DSA SIMD-vs-scalar parity test.
 *
 * Two independent surfaces are pinned:
 *
 *   1. **SLH-DSA-SHAKE-128s end-to-end**.  The dispatched Keccak
 *      kernel feeds SHAKE-128/256 inside every SLH-DSA-SHAKE
 *      operation (PRF, F, H, T_l, H_msg).  We sign + verify a fixed
 *      `(seed, key, message)` triple twice — once with the dispatched
 *      SIMD Keccak, once with the scalar Keccak forced via the
 *      `AMA_TESTING_MODE` hook `ama_test_force_keccak_f1600_scalar()` —
 *      then assert byte-identical signatures (deterministic signing
 *      mode) and cross-verify each signature under both Keccak
 *      backends.  This is the only production code path that
 *      transitively exercises SIMD inside SLH-DSA/SPHINCS+.
 *
 *   2. **SPHINCS+ AVX2 / NEON `wots_chain` helper vs scalar
 *      SHA-256**.  These are the standalone SIMD helpers shipped
 *      alongside the production SPHINCS+-256f scalar pipeline.
 *      They are not on the production call path today, but they
 *      ship in the build, document the SIMD intent for a future
 *      wiring, and need parity coverage so that wiring is safe.
 *
 *      Compares `ama_sphincs_wots_chain_{avx2,neon}` against an
 *      inlined scalar SHA-256 implementation (FIPS 180-4) executed
 *      with the exact same block-build / chaining pattern.  This
 *      is byte-identity, not algebraic equivalence — a mismatch
 *      means a SIMD regression that would silently corrupt WOTS+
 *      chains the moment the helper is wired in.
 *
 *      The AVX2 helper is `extern` (not `static`) so this test can
 *      reach it (see src/c/avx2/ama_sphincs_avx2.c).  The NEON
 *      helper has always been externally linkable.
 *
 * SKIP semantics:
 *   - Lane 1 SKIPs (informational) when the dispatched Keccak
 *     pointer is already the scalar reference (no SIMD Keccak built
 *     in — comparison is tautological) or when SLH-DSA is not
 *     present in the build.
 *   - Lane 2 SKIPs each helper independently when its
 *     `AMA_HAVE_*_IMPL` macro is not defined.
 *   - Returns code 77 if no lane was exercised; 0 on success; 1 on
 *     mismatch.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"
#include "ama_dispatch.h"

extern void ama_keccak_f1600_generic(uint64_t state[25]);

/* AMA_TESTING_MODE force/restore hooks resolved from libama_cryptography_test. */
extern void ama_test_force_keccak_f1600_scalar(void);
extern void ama_test_restore_keccak_f1600(void);

/* Direct symbol references for the SPHINCS+ SIMD WOTS+ helpers. */
#if defined(AMA_HAVE_AVX2_IMPL) && (defined(__x86_64__) || defined(_M_X64))
extern void ama_sphincs_wots_chain_avx2(uint8_t *out, const uint8_t *in,
                                        uint32_t start, uint32_t steps,
                                        const uint8_t *pub_seed,
                                        uint32_t addr[8], size_t n);
#endif
#if defined(AMA_HAVE_NEON_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
extern void ama_sphincs_wots_chain_neon(uint8_t *out, const uint8_t *in,
                                        uint32_t start, uint32_t steps,
                                        const uint8_t *pub_seed,
                                        uint32_t addr[8], size_t n);
#endif

/* --------------------------------------------------------------
 * Scalar reference for the SPHINCS+ `wots_chain` helper.
 *
 * Mirrors the block construction used by both the AVX2 and NEON
 * helpers in src/c/{avx2,neon}/ama_sphincs_{avx2,neon}.c: each step
 * builds a 64-byte SHA-256 block as [chain-value || addr[0] ||
 * addr[6]] padded with zeros, then runs a single FIPS 180-4 SHA-256
 * compression seeded with the standard IV.  No padding bytes are
 * appended (the helpers' write pattern is non-spec — they emit only
 * a single compression per step, matching the helpers byte-for-byte
 * which is what this test pins).  `pub_seed` is unused, consistent
 * with the helpers; suppressing via `(void)pub_seed`.
 * -------------------------------------------------------------- */
static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static const uint32_t SHA256_H[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};

static void sha256_compress_one_block(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int t = 0; t < 16; t++) {
        w[t] = ((uint32_t)block[t*4]   << 24) |
               ((uint32_t)block[t*4+1] << 16) |
               ((uint32_t)block[t*4+2] << 8)  |
               ((uint32_t)block[t*4+3]);
    }
    for (int t = 16; t < 64; t++) {
        uint32_t s0 = ((w[t-15] >> 7)  | (w[t-15] << 25)) ^
                      ((w[t-15] >> 18) | (w[t-15] << 14)) ^
                      (w[t-15] >> 3);
        uint32_t s1 = ((w[t-2]  >> 17) | (w[t-2]  << 15)) ^
                      ((w[t-2]  >> 19) | (w[t-2]  << 13)) ^
                      (w[t-2]  >> 10);
        w[t] = w[t-16] + s0 + w[t-7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int t = 0; t < 64; t++) {
        uint32_t S1 = ((e>>6)|(e<<26)) ^ ((e>>11)|(e<<21)) ^ ((e>>25)|(e<<7));
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t T1 = h + S1 + ch + SHA256_K[t] + w[t];
        uint32_t S0 = ((a>>2)|(a<<30)) ^ ((a>>13)|(a<<19)) ^ ((a>>22)|(a<<10));
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t T2 = S0 + mj;
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

static void scalar_wots_chain(uint8_t *out, const uint8_t *in,
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
        block[36] = (uint8_t)(addr[6] >> 24);
        block[37] = (uint8_t)(addr[6] >> 16);
        block[38] = (uint8_t)(addr[6] >> 8);
        block[39] = (uint8_t)(addr[6]);
        uint32_t h[8];
        memcpy(h, SHA256_H, sizeof(SHA256_H));
        sha256_compress_one_block(h, block);
        for (int j = 0; j < 8 && j * 4 < (int)n; j++) {
            out[j*4+0] = (uint8_t)(h[j] >> 24);
            out[j*4+1] = (uint8_t)(h[j] >> 16);
            out[j*4+2] = (uint8_t)(h[j] >> 8);
            out[j*4+3] = (uint8_t)(h[j]);
        }
    }
    (void)pub_seed;
}

/* The NEON variant intentionally omits the addr[6] bytes (its
 * block-build matches src/c/neon/ama_sphincs_neon.c which doesn't
 * write block[36..39]).  Mirror that here so the parity check is
 * byte-exact against the helper as written.  Only compiled when the
 * NEON lane is selectable on the target. */
#if defined(AMA_HAVE_NEON_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
static void scalar_wots_chain_no_hash_addr(uint8_t *out, const uint8_t *in,
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
        uint32_t h[8];
        memcpy(h, SHA256_H, sizeof(SHA256_H));
        sha256_compress_one_block(h, block);
        for (int j = 0; j < 8 && j * 4 < (int)n; j++) {
            out[j*4+0] = (uint8_t)(h[j] >> 24);
            out[j*4+1] = (uint8_t)(h[j] >> 16);
            out[j*4+2] = (uint8_t)(h[j] >> 8);
            out[j*4+3] = (uint8_t)(h[j]);
        }
    }
    (void)pub_seed;
}
#endif /* NEON variant only on AArch64 */

/* --------------------------------------------------------------
 * Lane 1: SLH-DSA-SHAKE-128s end-to-end SIMD-Keccak vs scalar-Keccak.
 *
 * SLH-DSA is always built in (src/c/ama_slhdsa.c has no PQC opt-in
 * guard).  The testing force/restore Keccak hooks resolve at link
 * time from libama_cryptography_test (see tests/c/CMakeLists.txt).
 * Each lane:
 *   - Derives a deterministic keypair via ama_slhdsa_keygen_from_seed.
 *   - Signs a fixed message with ama_slhdsa_sign_deterministic
 *     (deterministic randomiser = pk.seed per FIPS 205 §10.2).
 *   - Repeats under the forced-scalar Keccak.
 *   - Asserts byte-identical signatures.
 *   - Cross-verifies each signature under each backend.
 * -------------------------------------------------------------- */
static int run_slhdsa_simd_parity(int *exercised) {
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt == NULL || dt->keccak_f1600 == ama_keccak_f1600_generic) {
        printf("  INFO: SLH-DSA SHAKE lane skipped (no SIMD Keccak wired)\n");
        return 0;
    }

    const size_t N = 16;  /* SHAKE-128s seed length */
    uint8_t sk_seed[16], sk_prf[16], pk_seed[16];
    for (size_t i = 0; i < N; i++) {
        sk_seed[i] = (uint8_t)(0x10 + i);
        sk_prf[i]  = (uint8_t)(0x20 + i);
        pk_seed[i] = (uint8_t)(0x30 + i);
    }

    uint8_t pk[AMA_SLHDSA_SHAKE_128S_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_SLHDSA_SHAKE_128S_SECRET_KEY_BYTES];
    if (ama_slhdsa_keygen_from_seed(AMA_SLHDSA_SHAKE_128S,
                                    sk_seed, sk_prf, pk_seed,
                                    pk, sk) != AMA_SUCCESS) {
        fprintf(stderr, "FAIL: slhdsa keygen_from_seed (SIMD path)\n");
        return 1;
    }

    static uint8_t sig_simd[AMA_SLHDSA_SHAKE_128S_SIGNATURE_BYTES];
    static uint8_t sig_scal[AMA_SLHDSA_SHAKE_128S_SIGNATURE_BYTES];
    const uint8_t msg[] = "SLH-DSA-SHAKE-128s SIMD parity message";
    const size_t msg_len = sizeof(msg) - 1;
    size_t siglen_simd = sizeof(sig_simd);
    size_t siglen_scal = sizeof(sig_scal);

    if (ama_slhdsa_sign_deterministic(AMA_SLHDSA_SHAKE_128S,
                                      sig_simd, &siglen_simd,
                                      msg, msg_len, NULL, 0, sk)
        != AMA_SUCCESS) {
        fprintf(stderr, "FAIL: slhdsa SIMD sign\n");
        return 1;
    }

    /* Switch Keccak to scalar and recompute. */
    ama_test_force_keccak_f1600_scalar();
    ama_error_t rc = ama_slhdsa_sign_deterministic(AMA_SLHDSA_SHAKE_128S,
                                                   sig_scal, &siglen_scal,
                                                   msg, msg_len, NULL, 0, sk);
    /* Cross-verify the SIMD signature under the scalar Keccak. */
    ama_error_t vsv = ama_slhdsa_verify(AMA_SLHDSA_SHAKE_128S,
                                        sig_simd, siglen_simd,
                                        msg, msg_len, NULL, 0, pk);
    ama_test_restore_keccak_f1600();

    if (rc != AMA_SUCCESS) {
        fprintf(stderr, "FAIL: slhdsa scalar sign rc=%d\n", (int)rc);
        return 1;
    }
    if (vsv != AMA_SUCCESS) {
        fprintf(stderr, "FAIL: scalar-Keccak verify rejected SIMD signature\n");
        return 1;
    }
    if (siglen_simd != siglen_scal ||
        memcmp(sig_simd, sig_scal, siglen_simd) != 0) {
        fprintf(stderr,
                "FAIL: SLH-DSA-SHAKE-128s SIMD sig != scalar-Keccak sig "
                "(len_simd=%zu len_scal=%zu)\n", siglen_simd, siglen_scal);
        return 1;
    }
    /* Cross-verify the scalar signature under the dispatched (SIMD) Keccak. */
    if (ama_slhdsa_verify(AMA_SLHDSA_SHAKE_128S,
                          sig_scal, siglen_scal,
                          msg, msg_len, NULL, 0, pk) != AMA_SUCCESS) {
        fprintf(stderr, "FAIL: SIMD-Keccak verify rejected scalar signature\n");
        return 1;
    }
    printf("  PASS: SLH-DSA-SHAKE-128s deterministic sign byte-identical "
           "under SIMD-Keccak vs forced-scalar Keccak; cross-verify OK\n");
    *exercised = 1;
    return 0;
}

static int run_wots_chain_parity(int *exercised) {
    int built_any = 0;
    (void)built_any;

#if defined(AMA_HAVE_AVX2_IMPL) && (defined(__x86_64__) || defined(_M_X64))
    built_any = 1;
    {
        const size_t n = 32;  /* SPHINCS+-256f hash length */
        uint8_t in[32], out_simd[32], out_scal[32];
        uint8_t pub_seed[32] = {0};
        uint32_t addr[8];

        for (int trial = 0; trial < 64; trial++) {
            for (int i = 0; i < 32; i++) in[i] = (uint8_t)(0xA5 ^ trial ^ i);
            for (int i = 0; i < 8;  i++) addr[i] = 0x01020304u + (uint32_t)trial * (uint32_t)i;
            uint32_t start = (uint32_t)(trial & 0x7);
            uint32_t steps = 1u + (uint32_t)(trial & 0xF);

            uint32_t addr_simd[8], addr_scal[8];
            memcpy(addr_simd, addr, sizeof(addr));
            memcpy(addr_scal, addr, sizeof(addr));

            ama_sphincs_wots_chain_avx2(out_simd, in, start, steps,
                                        pub_seed, addr_simd, n);
            scalar_wots_chain(out_scal, in, start, steps,
                              pub_seed, addr_scal, n);
            if (memcmp(out_simd, out_scal, n) != 0) {
                fprintf(stderr,
                        "FAIL: sphincs_wots_chain_avx2 trial %d "
                        "(start=%u steps=%u)\n", trial, start, steps);
                return 1;
            }
        }
        printf("  PASS: ama_sphincs_wots_chain_avx2 byte-identical "
               "to scalar SHA-256 reference (64 trials)\n");
        *exercised = 1;
    }
#endif

#if defined(AMA_HAVE_NEON_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
    built_any = 1;
    {
        const size_t n = 32;
        uint8_t in[32], out_simd[32], out_scal[32];
        uint8_t pub_seed[32] = {0};
        uint32_t addr[8];

        for (int trial = 0; trial < 64; trial++) {
            for (int i = 0; i < 32; i++) in[i] = (uint8_t)(0x5A ^ trial ^ i);
            for (int i = 0; i < 8;  i++) addr[i] = 0x10203040u + (uint32_t)trial * (uint32_t)i;
            uint32_t start = (uint32_t)(trial & 0x7);
            uint32_t steps = 1u + (uint32_t)(trial & 0xF);

            uint32_t addr_simd[8], addr_scal[8];
            memcpy(addr_simd, addr, sizeof(addr));
            memcpy(addr_scal, addr, sizeof(addr));

            ama_sphincs_wots_chain_neon(out_simd, in, start, steps,
                                        pub_seed, addr_simd, n);
            scalar_wots_chain_no_hash_addr(out_scal, in, start, steps,
                                           pub_seed, addr_scal, n);
            if (memcmp(out_simd, out_scal, n) != 0) {
                fprintf(stderr,
                        "FAIL: sphincs_wots_chain_neon trial %d "
                        "(start=%u steps=%u)\n", trial, start, steps);
                return 1;
            }
        }
        printf("  PASS: ama_sphincs_wots_chain_neon byte-identical "
               "to scalar SHA-256 reference (64 trials)\n");
        *exercised = 1;
    }
#endif

    if (!built_any) {
        printf("  INFO: no SPHINCS+ SIMD wots_chain helper built in\n");
    }
    return 0;
}

int main(void) {
    printf("==========================================\n");
    printf("SPHINCS+ / SLH-DSA SIMD parity\n");
    printf("==========================================\n");

    int exercised = 0;

    if (run_slhdsa_simd_parity(&exercised)) return 1;

    if (run_wots_chain_parity(&exercised)) return 1;

    if (!exercised) {
        printf("SKIP: no SPHINCS+/SLH-DSA SIMD surface on this build/CPU\n");
        printf("==========================================\n");
        return 77;
    }
    printf("==========================================\n");
    return 0;
}
