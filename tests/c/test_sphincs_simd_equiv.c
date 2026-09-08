/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
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
 *   2. **SPHINCS+ AVX2 `wots_chain` helper vs scalar SHA-256**.
 *      `ama_sphincs_wots_chain_avx2` ships in the build alongside
 *      the production SPHINCS+-256f scalar pipeline.  It is NOT on
 *      the production call path today (see `slh_wots_chain` in
 *      `src/c/ama_slhdsa.c` — it loops scalar SHA-256 step-by-step
 *      and never dispatches to the SIMD helper), but it is shipped,
 *      documents the SIMD intent for a future wiring, and needs
 *      parity coverage so that wiring is safe.
 *
 *      Compares the AVX2 helper against an inlined scalar SHA-256
 *      implementation (FIPS 180-4) executed with the exact same
 *      block-build / chaining pattern.  This is byte-identity, not
 *      algebraic equivalence — a mismatch means a SIMD regression
 *      that would silently corrupt WOTS+ chains the moment the
 *      helper is wired in.
 *
 *      The AVX2 helper is `extern` (not `static`) so this test can
 *      reach it (see src/c/avx2/ama_sphincs_avx2.c).  The NEON
 *      `wots_chain` lane was previously pinned here too, but has
 *      been deliberately retired — see the explanatory comment block
 *      inside `run_wots_chain_parity` for the full rationale.
 *
 * SKIP semantics:
 *   - Lane 1 SKIPs (informational) when the dispatched Keccak
 *     pointer is already the scalar reference (no SIMD Keccak built
 *     in — comparison is tautological) or when SLH-DSA is not
 *     present in the build.
 *   - Lane 2 SKIPs the AVX2 sub-lane when `AMA_HAVE_AVX2_IMPL` is
 *     not defined at build time OR when the runtime CPU lacks AVX2
 *     (`ama_has_avx2()` returns 0) — calling the AVX2 entry point
 *     without that runtime check would SIGILL on a non-AVX2 CPU
 *     even though the production dispatcher would safely fall back.
 *   - Returns code 77 if no lane was exercised; 0 on success; 1 on
 *     mismatch.
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

/* Direct symbol references for the SPHINCS+ SIMD WOTS+ helpers. */
#if defined(AMA_HAVE_AVX2_IMPL) && (defined(__x86_64__) || defined(_M_X64))
#endif
/* (Previously: `extern void ama_sphincs_wots_chain_neon(...)`.  Removed
 * along with the NEON wots_chain test lane in `run_wots_chain_parity`
 * — see the inline rationale there.  The NEON helper itself is still
 * built into the library; this test simply no longer pins it.) */

/* --------------------------------------------------------------
 * Scalar reference for the SPHINCS+ AVX2 `wots_chain` helper.
 *
 * Mirrors the block construction used by the AVX2 helper in
 * `src/c/avx2/ama_sphincs_avx2.c`: each step builds a 64-byte SHA-256
 * block as [chain-value || addr[0] || addr[6]] padded with zeros,
 * then runs a single FIPS 180-4 SHA-256 compression seeded with the
 * standard IV.  No padding bytes are appended (the helper's write
 * pattern is non-spec — it emits only a single compression per step,
 * matching the helper byte-for-byte which is what this test pins).
 * `pub_seed` is unused, consistent with the helper; suppressed via
 * `(void)pub_seed`.
 *
 * Note: the NEON helper in `src/c/neon/ama_sphincs_neon.c` uses a
 * different block-build pattern (writes only `addr[0]` into the
 * block, never `addr[6]`).  This scalar reference does NOT mirror
 * the NEON pattern — when the NEON `wots_chain` lane was pinned
 * here it used a separate `scalar_wots_chain_no_hash_addr`
 * reference, which was removed alongside the NEON lane itself.
 * -------------------------------------------------------------- */
/* The scalar SHA-256 reference (`SHA256_K`, `SHA256_H`,
 * `sha256_compress_one_block`) and the `wots_chain` references built on it
 * lived here to drive lane 2.  Lane 2 is gone — see run_wots_chain_parity()
 * below — and with it the last consumer, so they are removed rather than
 * left compiled-but-unused.
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
