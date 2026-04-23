/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_dispatch.c
 * @brief Runtime SIMD dispatch system for AMA Cryptography
 *
 * Detects CPU features at initialization and selects the optimal
 * implementation for each cryptographic algorithm:
 *   x86-64: AVX-512 > AVX2 > generic
 *   AArch64: SVE2 > NEON > generic
 *
 * Function pointers are set once at init time via pthread_once /
 * InitOnceExecuteOnce (thread-safe, INVARIANT-15 compliant).
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

/* Expose POSIX clock_gettime / CLOCK_MONOTONIC on glibc.
 * Must precede all system headers.  Harmless on non-glibc platforms. */
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 199309L
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif

#include "ama_dispatch.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * Platform once-primitive (mirrors ama_cpuid.c — INVARIANT-15 compliant)
 * ============================================================================ */
#if defined(_MSC_VER)
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #define AMA_ONCE_FLAG          INIT_ONCE
    #define AMA_ONCE_FLAG_INIT     INIT_ONCE_STATIC_INIT
    typedef void (*ama_dispatch_once_fn)(void);
    static BOOL CALLBACK ama_dispatch_once_trampoline(PINIT_ONCE once, PVOID param, PVOID *ctx) {
        (void)once; (void)ctx;
        ((ama_dispatch_once_fn)param)();
        return TRUE;
    }
    #define AMA_DISPATCH_CALL_ONCE(flag, fn) \
        InitOnceExecuteOnce(&(flag), ama_dispatch_once_trampoline, (PVOID)(fn), NULL)
#else
    #include <pthread.h>
    #define AMA_ONCE_FLAG          pthread_once_t
    #define AMA_ONCE_FLAG_INIT     PTHREAD_ONCE_INIT
    #define AMA_DISPATCH_CALL_ONCE(flag, fn) \
        pthread_once(&(flag), (fn))
#endif

/* ============================================================================
 * Static dispatch state
 * ============================================================================ */

static ama_dispatch_info_t dispatch_info;
static ama_dispatch_table_t dispatch_table;
static AMA_ONCE_FLAG dispatch_once_flag = AMA_ONCE_FLAG_INIT;

#ifdef AMA_TESTING_MODE
/* Snapshot of dispatch_table immediately after dispatch_init_internal
 * completes. Used by ama_test_restore_*_avx2() so "restore" returns to
 * the dispatcher's actual post-init choice — including any opt-outs
 * applied via AMA_DISPATCH_NO_*_AVX2 env vars — rather than blindly
 * re-enabling the AVX2 pointer.  Test-only.
 */
static ama_dispatch_table_t dispatch_table_post_init;
#endif

/* ============================================================================
 * CPU feature detection helpers
 * ============================================================================ */

#if defined(__x86_64__) || defined(_M_X64)

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif

static int detect_avx2(void) {
#ifdef _MSC_VER
    int info[4];
    __cpuidex(info, 7, 0);
    return (info[1] >> 5) & 1; /* EBX bit 5 */
#else
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return (ebx >> 5) & 1; /* EBX bit 5 = AVX2 */
    }
    return 0;
#endif
}

static int detect_avx512f(void) {
#ifdef _MSC_VER
    int info[4];
    __cpuidex(info, 7, 0);
    return (info[1] >> 16) & 1; /* EBX bit 16 */
#else
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return (ebx >> 16) & 1; /* EBX bit 16 = AVX-512F */
    }
    return 0;
#endif
}

#elif defined(__aarch64__) || defined(_M_ARM64)

#if defined(__linux__)
#include <sys/auxv.h>

#ifndef HWCAP_NEON
/* NEON is always available on AArch64, but define for completeness */
#define HWCAP_NEON (1 << 1)
#endif

#ifndef HWCAP2_SVE2
#define HWCAP2_SVE2 (1 << 1)
#endif

static int detect_neon(void) {
    /* NEON is mandatory on AArch64 */
    return 1;
}

static int detect_sve2(void) {
    unsigned long hwcap2 = getauxval(AT_HWCAP2);
    return (hwcap2 & HWCAP2_SVE2) ? 1 : 0;
}

#elif defined(__APPLE__)

static int detect_neon(void) {
    /* Apple Silicon always has NEON */
    return 1;
}

static int detect_sve2(void) {
    /* Apple Silicon does not support SVE2 as of M4 */
    return 0;
}

#else

static int detect_neon(void) { return 0; }
static int detect_sve2(void) { return 0; }

#endif /* __linux__ / __APPLE__ */

#endif /* __x86_64__ / __aarch64__ */

/* ============================================================================
 * Generic fallback implementations (always available)
 * ============================================================================ */

/* Forward declaration: generic keccak_f1600 from ama_sha3.c */
extern void ama_keccak_f1600_generic(uint64_t state[25]);

/* Forward declaration: generic 4-way keccak_f1600 from ama_sha3.c.
 * Invokes the single-state dispatch pointer four times, so it
 * automatically benefits from AVX2/NEON single-state acceleration
 * on builds where the interleaved x4 kernel is unavailable. */
extern void ama_keccak_f1600_x4_generic(uint64_t states[4][25]);

/* ============================================================================
 * SIMD implementations (conditionally available at link time)
 * ============================================================================ */

#ifdef AMA_HAVE_AVX2_IMPL
extern void ama_keccak_f1600_avx2(uint64_t state[25]);
extern void ama_keccak_f1600_x4_avx2(uint64_t states[4][25]);
extern ama_error_t ama_sha3_256_avx2(const uint8_t *input, size_t input_len,
                                      uint8_t output[32]);
extern void ama_kyber_ntt_avx2(int16_t poly[256], const int16_t zetas[128]);
extern void ama_kyber_invntt_avx2(int16_t poly[256], const int16_t zetas[128]);
extern void ama_kyber_poly_pointwise_avx2(int16_t r[256],
                                           const int16_t a[256],
                                           const int16_t b[256],
                                           const int16_t zetas[128]);
extern void ama_dilithium_ntt_avx2(int32_t poly[256],
                                    const int32_t zetas[256]);
extern void ama_dilithium_invntt_avx2(int32_t poly[256],
                                       const int32_t zetas[256]);
extern void ama_dilithium_poly_pointwise_avx2(int32_t r[256],
                                               const int32_t a[256],
                                               const int32_t b[256]);
extern void ama_aes256_gcm_encrypt_avx2(const uint8_t *plaintext, size_t plaintext_len,
                                         const uint8_t *aad, size_t aad_len,
                                         const uint8_t key[32], const uint8_t nonce[12],
                                         uint8_t *ciphertext, uint8_t tag[16]);
extern ama_error_t ama_aes256_gcm_decrypt_avx2(const uint8_t *ciphertext, size_t ciphertext_len,
                                                const uint8_t *aad, size_t aad_len,
                                                const uint8_t key[32], const uint8_t nonce[12],
                                                const uint8_t tag[16], uint8_t *plaintext);
extern void ama_chacha20_block_x8_avx2(const uint8_t key[32],
                                        const uint8_t nonce[12],
                                        uint32_t counter,
                                        uint8_t out[512]);
extern void ama_argon2_g_avx2(uint64_t out[128],
                               const uint64_t x[128],
                               const uint64_t y[128]);
#endif

#ifdef AMA_HAVE_NEON_IMPL
extern void ama_keccak_f1600_neon(uint64_t state[25]);
extern ama_error_t ama_sha3_256_neon(const uint8_t *input, size_t input_len,
                                      uint8_t output[32]);
extern void ama_kyber_ntt_neon(int16_t poly[256], const int16_t zetas[128]);
extern void ama_kyber_invntt_neon(int16_t poly[256], const int16_t zetas[128]);
extern void ama_kyber_poly_pointwise_neon(int16_t r[256],
                                           const int16_t a[256],
                                           const int16_t b[256],
                                           const int16_t zetas[128]);
extern void ama_dilithium_ntt_neon(int32_t poly[256],
                                    const int32_t zetas[256]);
extern void ama_dilithium_invntt_neon(int32_t poly[256],
                                       const int32_t zetas[256]);
extern void ama_dilithium_poly_pointwise_neon(int32_t r[256],
                                               const int32_t a[256],
                                               const int32_t b[256]);
#endif

#ifdef AMA_HAVE_SVE2_IMPL
extern void ama_keccak_f1600_sve2(uint64_t state[25]);
extern void ama_kyber_ntt_sve2(int16_t poly[256], const int16_t zetas[128]);
extern void ama_kyber_invntt_sve2(int16_t poly[256], const int16_t zetas[128]);
extern void ama_kyber_poly_pointwise_sve2(int16_t r[256],
                                           const int16_t a[256],
                                           const int16_t b[256],
                                           const int16_t zetas[128]);
extern void ama_dilithium_ntt_sve2(int32_t poly[256],
                                    const int32_t zetas[256]);
extern void ama_dilithium_invntt_sve2(int32_t poly[256],
                                       const int32_t zetas[256]);
extern void ama_dilithium_poly_pointwise_sve2(int32_t r[256],
                                               const int32_t a[256],
                                               const int32_t b[256]);
#endif


/* Check if AMA_DISPATCH_VERBOSE=1 is set at runtime. */
static int dispatch_verbose(void) {
    static int v = -1;
    if (v < 0) {
        const char *env = getenv("AMA_DISPATCH_VERBOSE");
        v = (env && env[0] == '1') ? 1 : 0;
    }
    return v;
}

/* ============================================================================
 * Dispatch initialization
 *
 * Sets the implementation level for each algorithm based on detected
 * CPU features.  Called once via ama_dispatch_init().
 * ============================================================================ */
static void dispatch_init_internal(void) {
    memset(&dispatch_info, 0, sizeof(dispatch_info));

#if defined(__x86_64__) || defined(_M_X64)
    dispatch_info.arch_name = "x86-64";

    int has_avx2 = detect_avx2();
    int has_avx512f = detect_avx512f();

    ama_impl_level_t best = AMA_IMPL_GENERIC;
    if (has_avx2)   best = AMA_IMPL_AVX2;
    if (has_avx512f) best = AMA_IMPL_AVX512;

    /* All algorithms use the best available level.
     * AVX-512 implementations fall back to AVX2 where AVX-512
     * specific code isn't yet available. */
    ama_impl_level_t effective = (best == AMA_IMPL_AVX512 && 1)
                                 ? AMA_IMPL_AVX2  /* AVX-512 files are stretch */
                                 : best;

    dispatch_info.sha3             = effective;
    dispatch_info.kyber            = effective;
    dispatch_info.dilithium        = effective;
    dispatch_info.sphincs          = effective;
    dispatch_info.aes_gcm          = effective;
    /* Ed25519: no vector-wide AVX2/AVX-512 path is wired in this
     * dispatcher. Report as GENERIC; the concrete non-vector backend
     * (fe51 scalar, or the donna shim when AMA_ED25519_ASSEMBLY is
     * enabled) is selected by the build configuration, not at
     * runtime. */
    dispatch_info.ed25519          = AMA_IMPL_GENERIC;
    dispatch_info.chacha20poly1305 = effective;
    dispatch_info.argon2           = effective;

    if (dispatch_verbose())
        fprintf(stderr,
            "[AMA Dispatch] x86-64: AVX2=%d AVX-512F=%d => level=%d\n",
            has_avx2, has_avx512f, (int)effective);

#elif defined(__aarch64__) || defined(_M_ARM64)
    dispatch_info.arch_name = "AArch64";

    int has_neon = detect_neon();
    int has_sve2 = detect_sve2();

    ama_impl_level_t best = AMA_IMPL_GENERIC;
    if (has_neon) best = AMA_IMPL_NEON;
    if (has_sve2) best = AMA_IMPL_SVE2;

    dispatch_info.sha3             = best;
    dispatch_info.kyber            = best;
    dispatch_info.dilithium        = best;
    dispatch_info.sphincs          = best;
    dispatch_info.aes_gcm          = has_neon ? AMA_IMPL_NEON : AMA_IMPL_GENERIC;
    /* Ed25519: no vector-wide NEON/SVE2 path is wired in this
     * dispatcher. Report as GENERIC; the concrete backend (fe51
     * scalar) is selected at build time. */
    dispatch_info.ed25519          = AMA_IMPL_GENERIC;
    dispatch_info.chacha20poly1305 = best;
    dispatch_info.argon2           = best;

    if (dispatch_verbose())
        fprintf(stderr,
            "[AMA Dispatch] AArch64: NEON=%d SVE2=%d => level=%d\n",
            has_neon, has_sve2, (int)best);

#else
    dispatch_info.arch_name = "generic";
    if (dispatch_verbose())
        fprintf(stderr, "[AMA Dispatch] Unknown architecture — using generic C\n");
#endif

    /* ====================================================================
     * Phase 2: Wire function pointers to optimal implementations.
     *
     * Start with generic fallbacks, then override with SIMD where
     * detected.  NULL entries mean "caller uses its own inline generic"
     * (used for Kyber/Dilithium NTT where the generic path uses a
     * different internal zetas layout).
     * ==================================================================== */

    dispatch_table.keccak_f1600      = ama_keccak_f1600_generic;
    dispatch_table.keccak_f1600_x4   = ama_keccak_f1600_x4_generic;
    dispatch_table.sha3_256          = NULL;  /* dispatched via keccak_f1600 */
    dispatch_table.kyber_ntt         = NULL;  /* NULL = caller uses inline generic */
    dispatch_table.kyber_invntt      = NULL;
    dispatch_table.kyber_pointwise   = NULL;
    dispatch_table.dilithium_ntt     = NULL;
    dispatch_table.dilithium_invntt  = NULL;
    dispatch_table.dilithium_pointwise = NULL;
    dispatch_table.aes_gcm_encrypt     = NULL;  /* NULL = caller uses schoolbook GHASH */
    dispatch_table.aes_gcm_decrypt     = NULL;
    dispatch_table.chacha20_block_x8   = NULL;  /* NULL = caller uses scalar 1-block loop */
    dispatch_table.argon2_g            = NULL;  /* NULL = caller uses scalar BlaMka G */

#ifdef AMA_HAVE_AVX2_IMPL
    if (dispatch_info.sha3 >= AMA_IMPL_AVX2) {
        dispatch_table.keccak_f1600    = ama_keccak_f1600_avx2;
        dispatch_table.keccak_f1600_x4 = ama_keccak_f1600_x4_avx2;
        dispatch_table.sha3_256        = ama_sha3_256_avx2;
    }
    if (dispatch_info.kyber >= AMA_IMPL_AVX2) {
        dispatch_table.kyber_ntt       = ama_kyber_ntt_avx2;
        dispatch_table.kyber_invntt    = ama_kyber_invntt_avx2;
        dispatch_table.kyber_pointwise = ama_kyber_poly_pointwise_avx2;
    }
    if (dispatch_info.dilithium >= AMA_IMPL_AVX2) {
        dispatch_table.dilithium_ntt       = ama_dilithium_ntt_avx2;
        dispatch_table.dilithium_invntt    = ama_dilithium_invntt_avx2;
        dispatch_table.dilithium_pointwise = ama_dilithium_poly_pointwise_avx2;
    }
    if (dispatch_info.aes_gcm >= AMA_IMPL_AVX2) {
        dispatch_table.aes_gcm_encrypt = ama_aes256_gcm_encrypt_avx2;
        dispatch_table.aes_gcm_decrypt = ama_aes256_gcm_decrypt_avx2;
    }
    if (dispatch_info.chacha20poly1305 >= AMA_IMPL_AVX2) {
        /* Env override honored for A/B benchmarking and smoke-testing
         * the scalar fallback in production builds without a rebuild. */
        const char *no_chacha = getenv("AMA_DISPATCH_NO_CHACHA_AVX2");
        if (!(no_chacha && no_chacha[0] == '1'))
            dispatch_table.chacha20_block_x8 = ama_chacha20_block_x8_avx2;
    }
    if (dispatch_info.argon2 >= AMA_IMPL_AVX2) {
        const char *no_argon = getenv("AMA_DISPATCH_NO_ARGON2_AVX2");
        if (!(no_argon && no_argon[0] == '1'))
            dispatch_table.argon2_g = ama_argon2_g_avx2;
    }
#endif

#ifdef AMA_HAVE_NEON_IMPL
    if (dispatch_info.sha3 >= AMA_IMPL_NEON) {
        dispatch_table.keccak_f1600 = ama_keccak_f1600_neon;
        dispatch_table.sha3_256     = ama_sha3_256_neon;
    }
    if (dispatch_info.kyber >= AMA_IMPL_NEON) {
        dispatch_table.kyber_ntt       = ama_kyber_ntt_neon;
        dispatch_table.kyber_invntt    = ama_kyber_invntt_neon;
        dispatch_table.kyber_pointwise = ama_kyber_poly_pointwise_neon;
    }
    if (dispatch_info.dilithium >= AMA_IMPL_NEON) {
        dispatch_table.dilithium_ntt       = ama_dilithium_ntt_neon;
        dispatch_table.dilithium_invntt    = ama_dilithium_invntt_neon;
        dispatch_table.dilithium_pointwise = ama_dilithium_poly_pointwise_neon;
    }
#endif

    /* Save the pre-SVE2 keccak pointer (could be NEON or generic) so
     * the auto-tuning fallback reverts to this rather than always
     * falling back to generic C — which would skip the NEON tier. */
    ama_keccak_f1600_fn pre_sve2_keccak = dispatch_table.keccak_f1600;

#ifdef AMA_HAVE_SVE2_IMPL
    if (dispatch_info.sha3 >= AMA_IMPL_SVE2) {
        dispatch_table.keccak_f1600 = ama_keccak_f1600_sve2;
    }
    if (dispatch_info.kyber >= AMA_IMPL_SVE2) {
        dispatch_table.kyber_ntt       = ama_kyber_ntt_sve2;
        dispatch_table.kyber_invntt    = ama_kyber_invntt_sve2;
        dispatch_table.kyber_pointwise = ama_kyber_poly_pointwise_sve2;
    }
    if (dispatch_info.dilithium >= AMA_IMPL_SVE2) {
        dispatch_table.dilithium_ntt       = ama_dilithium_ntt_sve2;
        dispatch_table.dilithium_invntt    = ama_dilithium_invntt_sve2;
        dispatch_table.dilithium_pointwise = ama_dilithium_poly_pointwise_sve2;
    }
#endif

    /* ====================================================================
     * Phase 3: SIMD auto-tuning microbenchmark — hysteresis variant.
     *
     * Prior versions compared a ~10 ms SIMD vs generic run and reverted
     * the pointer whenever `simd_ns > generic_ns`. On noisy shared CI
     * runners that comparison is within timing jitter of equality, so
     * the hand-tuned AVX2 / NEON Keccak paths were being demoted to the
     * scalar tier despite being structurally faster.
     *
     * Fix: apply a 10 % hysteresis band and take the *best-of-N* trial
     * (min_ns) rather than the total, which is dominated by stalls on
     * contended hosts. The SIMD pointer is only reverted when the SIMD
     * tier is clearly slower — more than 10 % over generic's best time
     * — which is well outside the jitter of a modern clock_gettime()
     * microbench. Set AMA_DISPATCH_NO_AUTOTUNE=1 in the environment to
     * bypass entirely.
     *
     * Opt-out is respected on all platforms; the microbench itself is
     * still skipped on MSVC (no POSIX clock_gettime).
     * ==================================================================== */
#if !defined(_MSC_VER)
    const char *no_autotune = getenv("AMA_DISPATCH_NO_AUTOTUNE");
    int autotune_disabled = (no_autotune && no_autotune[0] == '1');

    if (!autotune_disabled &&
        dispatch_table.keccak_f1600 != ama_keccak_f1600_generic) {
        uint64_t state[25];
        memset(state, 0x42, sizeof(state));

        /* Warm-up: 200 iterations each to fill caches / branch predictors */
        for (int w = 0; w < 200; w++) {
            ama_keccak_f1600_generic(state);
        }
        for (int w = 0; w < 200; w++) {
            dispatch_table.keccak_f1600(state);
        }

        /* Run 5 trials of 2000 iterations each; take the minimum (best
         * run) which is the most resistant to scheduling jitter.
         *
         * Use int64_t (not long) for nanosecond accumulators: on ILP32
         * platforms long is 32-bit, and (tv_sec * 1000000000) overflows
         * after ~2.1 s — easily reachable on a contended CI runner —
         * which would silently flip the regression decision. */
        const int TRIALS = 5;
        const int ITERS  = 2000;
        int64_t generic_best = -1;
        int64_t simd_best    = -1;
        ama_keccak_f1600_fn simd_fn = dispatch_table.keccak_f1600;

        for (int trial = 0; trial < TRIALS; trial++) {
            struct timespec t0, t1;

            clock_gettime(CLOCK_MONOTONIC, &t0);
            for (int i = 0; i < ITERS; i++) {
                ama_keccak_f1600_generic(state);
            }
            clock_gettime(CLOCK_MONOTONIC, &t1);
            int64_t g = (int64_t)(t1.tv_sec - t0.tv_sec) * INT64_C(1000000000)
                      + (int64_t)(t1.tv_nsec - t0.tv_nsec);
            if (generic_best < 0 || g < generic_best) generic_best = g;

            clock_gettime(CLOCK_MONOTONIC, &t0);
            for (int i = 0; i < ITERS; i++) {
                simd_fn(state);
            }
            clock_gettime(CLOCK_MONOTONIC, &t1);
            int64_t s = (int64_t)(t1.tv_sec - t0.tv_sec) * INT64_C(1000000000)
                      + (int64_t)(t1.tv_nsec - t0.tv_nsec);
            if (simd_best < 0 || s < simd_best) simd_best = s;
        }

        /* Revert only if SIMD is more than 10 % slower than generic's
         * best — i.e., clearly and repeatably regressed. Within-band
         * results are treated as "SIMD wins" since SIMD has lower peak
         * latency even when averages overlap on noisy hosts. */
        int simd_regressed = (simd_best > (generic_best + generic_best / 10));

        if (simd_regressed) {
            if (pre_sve2_keccak != dispatch_table.keccak_f1600) {
                dispatch_table.keccak_f1600 = pre_sve2_keccak;
            } else {
                dispatch_table.keccak_f1600 = ama_keccak_f1600_generic;
            }
            /* Revert the batched x4 kernel in lockstep: if the single-state
             * AVX2/NEON kernel is slower than scalar on this host, the
             * interleaved 4-way kernel almost certainly is too.  The generic
             * x4_fn falls through to the (now-reverted) single-state pointer. */
            dispatch_table.keccak_f1600_x4 = ama_keccak_f1600_x4_generic;
            if (dispatch_verbose())
                fprintf(stderr,
                    "[AMA Dispatch] Auto-tune: SIMD keccak regressed >10%% "
                    "(best %lld ns vs %lld ns generic) — reverted to %s\n",
                    (long long)simd_best, (long long)generic_best,
                    dispatch_table.keccak_f1600 == ama_keccak_f1600_generic
                        ? "generic" : "previous tier");
        } else if (dispatch_verbose()) {
            fprintf(stderr,
                "[AMA Dispatch] Auto-tune: SIMD keccak kept "
                "(best %lld ns vs %lld ns generic, within 10%% band)\n",
                (long long)simd_best, (long long)generic_best);
        }
    } else if (autotune_disabled && dispatch_verbose()) {
        fprintf(stderr,
            "[AMA Dispatch] Auto-tune: disabled via AMA_DISPATCH_NO_AUTOTUNE=1\n");
    }
#endif /* !_MSC_VER */

    if (dispatch_verbose()) {
        fprintf(stderr, "[AMA Dispatch] keccak_f1600 -> %s\n",
                dispatch_table.keccak_f1600 == ama_keccak_f1600_generic
                    ? "generic" : "SIMD");
        fprintf(stderr, "[AMA Dispatch] kyber_ntt    -> %s\n",
                dispatch_table.kyber_ntt ? "SIMD" : "generic (inline)");
        fprintf(stderr, "[AMA Dispatch] dil_ntt      -> %s\n",
                dispatch_table.dilithium_ntt ? "SIMD" : "generic (inline)");
        fprintf(stderr, "[AMA Dispatch] chacha20_x8 -> %s\n",
                dispatch_table.chacha20_block_x8 ? "SIMD" : "scalar");
        fprintf(stderr, "[AMA Dispatch] argon2_g     -> %s\n",
                dispatch_table.argon2_g ? "SIMD" : "scalar");
        fprintf(stderr, "[AMA Dispatch] ed25519      -> scalar (no SIMD wired; backend chosen at build time)\n");
    }

#ifdef AMA_TESTING_MODE
    /* Snapshot post-init dispatch state for ama_test_restore_*_avx2().
     * Captures the actual choices the dispatcher made — including any
     * env-var opt-outs (AMA_DISPATCH_NO_*_AVX2) and the auto-tune
     * verdict — so that "restore" returns to that state rather than
     * blindly re-enabling AVX2. */
    dispatch_table_post_init = dispatch_table;
#endif
}

/* ============================================================================
 * Public API
 * ============================================================================ */

void ama_dispatch_init(void) {
    AMA_DISPATCH_CALL_ONCE(dispatch_once_flag, dispatch_init_internal);
}

const char *ama_impl_level_name(ama_impl_level_t level) {
    switch (level) {
        case AMA_IMPL_GENERIC: return "Generic C";
        case AMA_IMPL_AVX2:    return "AVX2";
        case AMA_IMPL_AVX512:  return "AVX-512";
        case AMA_IMPL_NEON:    return "ARM NEON";
        case AMA_IMPL_SVE2:    return "ARM SVE2";
        default:               return "Unknown";
    }
}

/**
 * Returns dispatch info for logging and benchmarking.
 * Caller must call ama_dispatch_init() first (or this does it lazily).
 */
const ama_dispatch_info_t *ama_get_dispatch_info(void) {
    ama_dispatch_init();
    return &dispatch_info;
}

/**
 * Returns the dispatch function pointer table.
 * Calls ama_dispatch_init() internally if not already initialized.
 */
const ama_dispatch_table_t *ama_get_dispatch_table(void) {
    ama_dispatch_init();
    return &dispatch_table;
}

#ifdef AMA_TESTING_MODE
/* ============================================================================
 * Test-only dispatch overrides.
 *
 * These symbols are compiled ONLY for the ama_cryptography_test library
 * (see CMakeLists.txt). They allow the C test harness to force the
 * scalar fallback path for a specific algorithm, enabling byte-for-byte
 * cross-verification between the SIMD and scalar implementations in a
 * single test process.
 *
 * NEVER expose these in the installable shared/static library — they
 * would be a dispatch-correctness footgun in production.
 *
 * Prototypes declared here (rather than in a public header) so the
 * symbols are visible only to the AMA_TESTING_MODE compilation unit
 * and to test C files that forward-declare them inline.
 * ============================================================================ */

void ama_test_force_argon2_g_scalar(void);
void ama_test_force_chacha20_block_x8_scalar(void);
void ama_test_restore_argon2_g_avx2(void);
void ama_test_restore_chacha20_block_x8_avx2(void);

void ama_test_force_argon2_g_scalar(void) {
    ama_dispatch_init();
    dispatch_table.argon2_g = NULL;
}

void ama_test_force_chacha20_block_x8_scalar(void) {
    ama_dispatch_init();
    dispatch_table.chacha20_block_x8 = NULL;
}

/* Restore the function pointer to its post-dispatch_init value (which
 * reflects: detected ISA support, AMA_DISPATCH_NO_*_AVX2 env opt-outs,
 * and the SHA-3 auto-tune verdict). This makes the test hooks
 * round-trip cleanly with the env opt-outs the production library
 * already exposes — a test that does:
 *
 *     setenv("AMA_DISPATCH_NO_ARGON2_AVX2", "1", 1);
 *     ama_argon2id(...);            // scalar (env opt-out)
 *     ama_test_force_argon2_g_scalar();
 *     ama_argon2id(...);            // scalar (test hook)
 *     ama_test_restore_argon2_g_avx2();
 *     ama_argon2id(...);            // STILL scalar (env opt-out
 *                                   // remembered from init snapshot)
 *
 * gets predictable behavior, which is what the reviewer asked for. */
void ama_test_restore_argon2_g_avx2(void) {
    ama_dispatch_init();
    dispatch_table.argon2_g = dispatch_table_post_init.argon2_g;
}

void ama_test_restore_chacha20_block_x8_avx2(void) {
    ama_dispatch_init();
    dispatch_table.chacha20_block_x8 = dispatch_table_post_init.chacha20_block_x8;
}
#endif /* AMA_TESTING_MODE */

/**
 * Prints dispatch info to stderr (for diagnostics / benchmark output).
 */
void ama_print_dispatch_info(void) {
    const ama_dispatch_info_t *info = ama_get_dispatch_info();

    fprintf(stderr, "\n");
    fprintf(stderr, "╔══════════════════════════════════════════════╗\n");
    fprintf(stderr, "║   AMA Cryptography SIMD Dispatch Info       ║\n");
    fprintf(stderr, "╠══════════════════════════════════════════════╣\n");
    fprintf(stderr, "║  Architecture:       %-24s║\n", info->arch_name);
    fprintf(stderr, "║  SHA-3/Keccak:       %-24s║\n", ama_impl_level_name(info->sha3));
    fprintf(stderr, "║  ML-KEM-1024:        %-24s║\n", ama_impl_level_name(info->kyber));
    fprintf(stderr, "║  ML-DSA-65:          %-24s║\n", ama_impl_level_name(info->dilithium));
    fprintf(stderr, "║  SPHINCS+-256f:      %-24s║\n", ama_impl_level_name(info->sphincs));
    fprintf(stderr, "║  AES-256-GCM:        %-24s║\n", ama_impl_level_name(info->aes_gcm));
    fprintf(stderr, "║  Ed25519:            %-24s║\n", ama_impl_level_name(info->ed25519));
    fprintf(stderr, "║  ChaCha20-Poly1305:  %-24s║\n", ama_impl_level_name(info->chacha20poly1305));
    fprintf(stderr, "║  Argon2:             %-24s║\n", ama_impl_level_name(info->argon2));
    fprintf(stderr, "╚══════════════════════════════════════════════╝\n");
    fprintf(stderr, "\n");
}
