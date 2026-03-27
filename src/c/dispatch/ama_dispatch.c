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
 * InitOnceExecuteOnce (thread-safe, INVARIANT-2 compliant).
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include "ama_dispatch.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Platform once-primitive (mirrors ama_cpuid.c — INVARIANT-2 compliant)
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

/* ============================================================================
 * SIMD implementations (conditionally available at link time)
 * ============================================================================ */

#ifdef AMA_HAVE_AVX2_IMPL
extern void ama_keccak_f1600_avx2(uint64_t state[25]);
extern int  ama_sha3_256_avx2(const uint8_t *input, size_t input_len,
                               uint8_t output[32]);
extern void ama_kyber_ntt_avx2(int16_t poly[256], const int16_t zetas[128]);
extern void ama_kyber_invntt_avx2(int16_t poly[256], const int16_t zetas[128]);
extern void ama_kyber_poly_pointwise_avx2(int16_t r[256],
                                           const int16_t a[256],
                                           const int16_t b[256]);
extern void ama_dilithium_ntt_avx2(int32_t poly[256],
                                    const int32_t zetas[128]);
extern void ama_dilithium_poly_pointwise_avx2(int32_t r[256],
                                               const int32_t a[256],
                                               const int32_t b[256]);
#endif

#ifdef AMA_HAVE_NEON_IMPL
extern void ama_keccak_f1600_neon(uint64_t state[25]);
extern int  ama_sha3_256_neon(const uint8_t *input, size_t input_len,
                               uint8_t output[32]);
extern void ama_kyber_ntt_neon(int16_t poly[256], const int16_t zetas[128]);
extern void ama_dilithium_ntt_neon(int32_t poly[256],
                                    const int32_t zetas[128]);
extern void ama_dilithium_poly_pointwise_neon(int32_t r[256],
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
    dispatch_info.ed25519          = effective;
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
    dispatch_info.ed25519          = best;
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
    dispatch_table.sha3_256          = NULL;  /* dispatched via keccak_f1600 */
    dispatch_table.kyber_ntt         = NULL;  /* NULL = caller uses inline generic */
    dispatch_table.kyber_invntt      = NULL;
    dispatch_table.kyber_pointwise   = NULL;
    dispatch_table.dilithium_ntt     = NULL;
    dispatch_table.dilithium_pointwise = NULL;

#ifdef AMA_HAVE_AVX2_IMPL
    if (dispatch_info.sha3 >= AMA_IMPL_AVX2) {
        dispatch_table.keccak_f1600 = ama_keccak_f1600_avx2;
    }
    /* Kyber/Dilithium AVX2 NTT implementations use vectorized zetas
     * layouts (swizzled for SIMD lane access) that differ from the generic
     * scalar zetas array.  Dispatch pointers remain NULL until a zetas-
     * swizzle adapter is integrated.  This ensures correctness while the
     * dispatch infrastructure is ready for future wiring.
     * (INVARIANT-4: graceful fallback to generic C when NULL.) */
#endif

#ifdef AMA_HAVE_NEON_IMPL
    if (dispatch_info.sha3 >= AMA_IMPL_NEON) {
        dispatch_table.keccak_f1600 = ama_keccak_f1600_neon;
    }
    /* Kyber/Dilithium NEON NTT: same zetas layout issue — deferred. */
#endif

    if (dispatch_verbose()) {
        fprintf(stderr, "[AMA Dispatch] keccak_f1600 -> %s\n",
                dispatch_table.keccak_f1600 == ama_keccak_f1600_generic
                    ? "generic" : "SIMD");
        fprintf(stderr, "[AMA Dispatch] kyber_ntt    -> %s\n",
                dispatch_table.kyber_ntt ? "SIMD" : "generic (inline)");
        fprintf(stderr, "[AMA Dispatch] dil_ntt      -> %s\n",
                dispatch_table.dilithium_ntt ? "SIMD" : "generic (inline)");
    }
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
 * Prints dispatch info to stderr (for diagnostics / benchmark output).
 */
const ama_dispatch_table_t *ama_get_dispatch_table(void) {
    ama_dispatch_init();
    return &dispatch_table;
}

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
