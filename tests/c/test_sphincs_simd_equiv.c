/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_sphincs_simd_equiv.c
 * @brief SPHINCS+ / SLH-DSA SIMD-vs-scalar parity test.
 *
 * One surface is pinned; the second lane this file used to carry is retired
 * and runs nothing:
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
 *   2. **Retired: the `wots_chain` helper lanes.**  This lane used to
 *      compare `ama_sphincs_wots_chain_avx2` (and, earlier, the NEON
 *      helper) against a scalar SHA-256 transcription of the same
 *      algorithm.  Neither helper exists any more:
 *      `src/c/avx2/ama_sphincs_avx2.c` is a placeholder TU shipping no
 *      kernel, and the NEON helper was deleted in the twenty-seventh
 *      maintenance pass as compiled, uncalled, untested code whose
 *      block layout differed from the scalar reference.  The lane body
 *      records why the comparison proved nothing; `run_wots_chain_parity`
 *      stays so the retirement is visible where the lane was, and this
 *      header no longer describes a comparison that does not run.
 *
 * SKIP semantics:
 *   - Lane 1 is the only lane that runs.  It SKIPs (informational) when
 *     the dispatched Keccak pointer is already the scalar reference (no
 *     SIMD Keccak built in — comparison is tautological).
 *   - Returns code 77 when lane 1 skipped, because then no SPHINCS+ /
 *     SLH-DSA SIMD surface was exercised at all; 0 on success; 1 on
 *     mismatch.  No AVX2 or NEON SPHINCS+ helper is pinned on any host:
 *     none exists.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"
#include "ama_cpuid.h"
#include "ama_dispatch.h"

extern void ama_keccak_f1600_generic(uint64_t state[25]);

/* AMA_TESTING_MODE force/restore hooks resolved from libama_cryptography_test. */
extern void ama_test_force_keccak_f1600_scalar(void);
extern void ama_test_restore_keccak_f1600(void);

/* The scalar SHA-256 reference (`SHA256_K`, `SHA256_H`,
 * `sha256_compress_one_block`), the `wots_chain` references built on it and
 * the extern declarations of the AVX2 and NEON `wots_chain` helpers lived
 * here to drive lane 2.  Both helpers are deleted and lane 2 is retired —
 * see run_wots_chain_parity() below — so nothing of it is left compiled.
 */

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
    /* Lane retired.  It compared `ama_sphincs_wots_chain_avx2` against
     * `scalar_wots_chain`, a verbatim transcription of the same algorithm:
     * the two agreed by construction, the comparison executed no vector
     * instruction, and it would have passed for any implementation at all.
     * The helper it drove was scalar C that did not compute FIPS 205 `F`
     * (no `pub_seed`, no compressed ADRS, no `toByte(0, 64 - n)` padding)
     * and that no production path called; `src/c/avx2/ama_sphincs_avx2.c` is
     * now a placeholder TU shipping no kernel, and its header records why.
     * The earlier NEON sub-lane had already been retired for the same
     * reason.
     *
     * SLH-DSA's real SIMD path is the dispatched Keccak permutation under
     * SHAKE, which lane 1 above exercises end to end. */
    (void)exercised;
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
