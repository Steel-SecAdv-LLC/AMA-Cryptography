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

/* Expose POSIX clock_gettime / CLOCK_MONOTONIC + C99 snprintf on every
 * libc.  Must precede all system headers.
 *
 * Bumped from 199309L (POSIX.1b) → 200809L (POSIX.1-2008) to align
 * with the rest of the project (tests/c/test_*.c and
 * benchmarks/benchmark_c_raw.c all use 200809L).  The previous value
 * was sufficient on glibc — POSIX.1b exposes clock_gettime, and
 * glibc separately exposes the C99 stdio surface (snprintf etc.)
 * regardless of _POSIX_C_SOURCE level — but on Apple's libc, defining
 * _POSIX_C_SOURCE at any level (including 199309L) switches
 * <stdio.h> into strict POSIX mode, which hides snprintf below
 * _POSIX_C_SOURCE = 200112L (the level POSIX.1-2001 incorporated the
 * C99 stdio additions).  Apple Clang's default
 * `-Werror=implicit-function-declaration` then fails the build at the
 * snprintf call in `print_dispatch_info` below.  200809L exposes both
 * clock_gettime and snprintf on every supported libc (glibc, musl,
 * Apple libc, BSD libc), and matches the version the rest of the C
 * test/benchmark surface already uses. */
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 200809L
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "ama_dispatch.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if !defined(_MSC_VER)
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

/* Scalar reference NTT entry points exposed by src/c/ama_kyber.c and
 * src/c/ama_dilithium.c.  The dispatch auto-tune below microbenches the
 * AVX2 / NEON / SVE2 NTT kernels against these baselines and reverts
 * the SIMD slot pointer when the SIMD path regresses past the 10 %
 * hysteresis band.  Signatures match ama_kyber_ntt_fn /
 * ama_dilithium_ntt_fn so the dispatched and reference forms are
 * interchangeable at the call site. */
extern void ama_kyber_ntt_generic_ref(int16_t poly[256], const int16_t zetas[128]);
extern void ama_kyber_invntt_generic_ref(int16_t poly[256], const int16_t zetas[128]);
extern void ama_dilithium_ntt_generic_ref(int32_t poly[256], const int32_t zetas[256]);
extern void ama_dilithium_invntt_generic_ref(int32_t poly[256], const int32_t zetas[256]);

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

/* AMA_DISPATCH_ONLY-resolved slot label (audit Issue 3 close-out).
 * Set to a string literal by apply_dispatch_only() when an AMA_DISPATCH_ONLY
 * request is honored; left at "all-default-dispatch" otherwise.  Read
 * by ama_dispatch_active_slot().  Storage duration is static; the
 * pointer always references a string literal in this TU. */
static const char *dispatch_active_slot_label = "all-default-dispatch";

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

/* CPU-feature detection is consolidated in ama_cpuid.c — that layer
 * carries the OSXSAVE + XCR0 AVX-state gate (x86-64) and the
 * getauxval / sysctl HWCAP probes (AArch64) that the dispatcher must
 * honour before selecting any architecture-specific kernel.  Forward
 * to it from a single header so there is one source of truth for the
 * runtime feature contract and no duplicated CPUID/HWCAP emission. */
#include "ama_cpuid.h"

#if defined(__x86_64__) || defined(_M_X64)

/* x86-64 stays under the legacy comment block above. */

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
#if defined(__x86_64__) || defined(_M_X64)
/* Single source of truth for the AVX2/VAES kernel prototypes.  This
 * header is private to src/c/avx2/ and this dispatch TU; it carries
 * the VAES/VPCLMULQDQ entry points (with the _MSC_VER guard), the
 * AES-NI reference, and every dispatch-registered SIMD helper.
 * Including it here — instead of re-declaring each extern inline —
 * eliminates signature-drift risk flagged in Copilot review
 * #3136110871.  The header pulls in <immintrin.h> transitively, so
 * it stays under the x86-64 guard even within AMA_HAVE_AVX2_IMPL. */
#include "../avx2/ama_avx2_internal.h"
#endif
#endif

/* AVX-512 4-way Keccak (PR C — 2026-04, opt-in via AMA_ENABLE_AVX512).
 *
 * Only the SHA3 slot is promoted past AMA_IMPL_AVX2 today: this is the
 * single in-house AVX-512 kernel.  The dispatcher gates the wiring on
 * ama_cpuid_has_avx512_keccak() (AVX-512F + AVX-512VL + XCR0 1+2+5+6+7)
 * AND on AMA_HAVE_AVX512_IMPL having been defined by CMake — the
 * AMA_ENABLE_AVX512 build option is the build-time half of that gate. */
#ifdef AMA_HAVE_AVX512_IMPL
#if defined(__x86_64__) || defined(_M_X64)
extern void ama_keccak_f1600_x4_avx512(uint64_t states[4][25]);
#endif
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
/* NEON AES-GCM, ChaCha20, Argon2 kernels (wired by this PR — 2026-05).
 * Each is gated at install-time on the ARM Crypto Extensions probe
 * `ama_has_arm_aes()` (AES + PMULL) for AES-GCM and unconditionally
 * for ChaCha20 / Argon2 (which only need baseline NEON, mandatory on
 * AArch64).  All four kernels scrub round-key / GHASH-key / mask
 * material on every return path — INVARIANT-12. */
extern void ama_aes256_gcm_encrypt_neon(const uint8_t *plaintext, size_t plaintext_len,
                                         const uint8_t *aad, size_t aad_len,
                                         const uint8_t key[32], const uint8_t nonce[12],
                                         uint8_t *ciphertext, uint8_t tag[16]);
extern ama_error_t ama_aes256_gcm_decrypt_neon(const uint8_t *ciphertext, size_t ciphertext_len,
                                                const uint8_t *aad, size_t aad_len,
                                                const uint8_t key[32], const uint8_t nonce[12],
                                                const uint8_t tag[16], uint8_t *plaintext);
extern void ama_chacha20_block_x8_neon(const uint8_t key[32],
                                        const uint8_t nonce[12],
                                        uint32_t counter,
                                        uint8_t out[512]);
extern void ama_argon2_g_neon(uint64_t out[128],
                               const uint64_t x[128],
                               const uint64_t y[128]);
#endif

#ifdef AMA_HAVE_SVE2_IMPL
extern void ama_keccak_f1600_sve2(uint64_t state[25]);
extern ama_error_t ama_sha3_256_sve2(const uint8_t *input, size_t input_len,
                                     uint8_t output[32]);
extern void ama_kyber_ntt_sve2(int16_t poly[256], const int16_t zetas[128]);
extern void ama_kyber_invntt_sve2(int16_t poly[256], const int16_t zetas[128]);
extern void ama_kyber_poly_pointwise_sve2(int16_t r[256],
                                           const int16_t a[256],
                                           const int16_t b[256],
                                           const int16_t zetas[128]);
extern void ama_kyber_poly_add_sve2(int16_t r[256],
                                     const int16_t a[256],
                                     const int16_t b[256]);
extern void ama_kyber_poly_sub_sve2(int16_t r[256],
                                     const int16_t a[256],
                                     const int16_t b[256]);
extern void ama_kyber_poly_reduce_sve2(int16_t poly[256]);
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
 * AMA_DISPATCH_ONLY filtering (audit Issue 3 close-out)
 *
 * apply_dispatch_only() runs AFTER dispatch_init_internal() has wired
 * every available SIMD kernel and the auto-tune verdict has settled.
 * It scrubs every kernel pointer back to its scalar fallback EXCEPT
 * the one(s) belonging to the requested slot.  This isolates one
 * SIMD kernel for the dudect per-slot timing sweep so the t-value is
 * attributable to that kernel alone (rather than to whichever AVX2
 * paths happened to fire under the same dispatch invocation).
 *
 * Recognition strategy: compare the wired function pointer in
 * `saved` against the architecture-specific kernel symbol.  A
 * mismatch (the wired pointer is generic, a different SIMD tier, or
 * NULL) means the host does not satisfy the requested slot — return
 * AMA_DISPATCH_ONLY_UNSUPPORTED so the caller emits a clear error
 * and leaves the dispatch_table at scalar fallback.  An unknown
 * slot name returns AMA_DISPATCH_ONLY_UNRECOGNISED.  Either way the
 * test harness in tests/c/test_dispatch_only_env.c surfaces that
 * state as a CTest skip (exit 77) via the `"all-default-dispatch"`
 * sentinel from ama_dispatch_active_slot().
 *
 * The function itself emits NO stderr — every diagnostic is the
 * caller's responsibility.  This is deliberate (Copilot review #323
 * follow-up): when apply_dispatch_only() ALSO printed a stderr line
 * for the unrecognised-slot branch, the caller's own diagnostic
 * doubled it for that case while leaving the unsupported-slot case
 * silent under the verbose gate.  The status-enum return restores
 * the "exactly one diagnostic per failure" contract the header
 * promises.
 *
 * INVARIANT-15 is preserved: this function runs inside the
 * pthread_once / InitOnceExecuteOnce body, on the same once-init
 * code path as the rest of dispatch_init_internal().
 * ============================================================================ */
typedef enum {
    AMA_DISPATCH_ONLY_HONORED      = 0,
    AMA_DISPATCH_ONLY_UNRECOGNISED = 1,  /* slot name not in the inventory */
    AMA_DISPATCH_ONLY_UNSUPPORTED  = 2,  /* slot name known, but the CPU /
                                          * build does not satisfy it */
} apply_dispatch_only_result_t;

static apply_dispatch_only_result_t apply_dispatch_only(
        const char *slot, const char **resolved_label_out) {
    /* Save the wired state so we can selectively restore the
     * requested slot's kernel pointer(s).  Then zero the table and
     * restore the two always-non-NULL slots (keccak_f1600 +
     * keccak_f1600_x4) to their generic fallbacks — those two are
     * the dispatch-table contract per include/ama_dispatch.h. */
    const ama_dispatch_table_t saved = dispatch_table;

    memset(&dispatch_table, 0, sizeof(dispatch_table));  // PUBLIC-DATA: dispatch_table — scrub dispatch state before AMA_DISPATCH_ONLY rewires it (PUBLIC global state — CPU feature info + function pointers, no secrets)
    dispatch_table.keccak_f1600    = ama_keccak_f1600_generic;
    dispatch_table.keccak_f1600_x4 = ama_keccak_f1600_x4_generic;

#ifdef AMA_HAVE_AVX512_IMPL
#if defined(__x86_64__) || defined(_M_X64)
    if (strcmp(slot, "sha3-avx512x4") == 0) {
        if (saved.keccak_f1600_x4 == ama_keccak_f1600_x4_avx512) {
            dispatch_table.keccak_f1600_x4 = saved.keccak_f1600_x4;
            *resolved_label_out = "sha3-avx512x4";
            return AMA_DISPATCH_ONLY_HONORED;
        }
        return AMA_DISPATCH_ONLY_UNSUPPORTED;
    }
#endif
#endif

#ifdef AMA_HAVE_AVX2_IMPL
    if (strcmp(slot, "kyber-ntt-avx2") == 0) {
        if (saved.kyber_ntt == ama_kyber_ntt_avx2) {
            dispatch_table.kyber_ntt       = saved.kyber_ntt;
            dispatch_table.kyber_invntt    = saved.kyber_invntt;
            dispatch_table.kyber_pointwise = saved.kyber_pointwise;
            dispatch_table.kyber_cbd2      = saved.kyber_cbd2;
            *resolved_label_out = "kyber-ntt-avx2";
            return AMA_DISPATCH_ONLY_HONORED;
        }
        return AMA_DISPATCH_ONLY_UNSUPPORTED;
    }
    if (strcmp(slot, "dilithium-ntt-avx2") == 0) {
        if (saved.dilithium_ntt == ama_dilithium_ntt_avx2) {
            dispatch_table.dilithium_ntt         = saved.dilithium_ntt;
            dispatch_table.dilithium_invntt      = saved.dilithium_invntt;
            dispatch_table.dilithium_pointwise   = saved.dilithium_pointwise;
            dispatch_table.dilithium_rej_uniform = saved.dilithium_rej_uniform;
            *resolved_label_out = "dilithium-ntt-avx2";
            return AMA_DISPATCH_ONLY_HONORED;
        }
        return AMA_DISPATCH_ONLY_UNSUPPORTED;
    }
    if (strcmp(slot, "chacha20-avx2x8") == 0) {
        if (saved.chacha20_block_x8 == ama_chacha20_block_x8_avx2) {
            dispatch_table.chacha20_block_x8 = saved.chacha20_block_x8;
            *resolved_label_out = "chacha20-avx2x8";
            return AMA_DISPATCH_ONLY_HONORED;
        }
        return AMA_DISPATCH_ONLY_UNSUPPORTED;
    }
    if (strcmp(slot, "argon2-g-avx2") == 0) {
        if (saved.argon2_g == ama_argon2_g_avx2) {
            dispatch_table.argon2_g = saved.argon2_g;
            *resolved_label_out = "argon2-g-avx2";
            return AMA_DISPATCH_ONLY_HONORED;
        }
        return AMA_DISPATCH_ONLY_UNSUPPORTED;
    }
    if (strcmp(slot, "x25519-avx2") == 0) {
        /* x25519_x4 is opt-in via AMA_DISPATCH_USE_X25519_AVX2=1.
         * If saved.x25519_x4 is NULL here, either the host lacks AVX2
         * OR the caller forgot the use-opt-in flag.  Either way the
         * slot is unsatisfied — surface that as a CTest skip. */
        if (saved.x25519_x4 == ama_x25519_scalarmult_x4_avx2) {
            dispatch_table.x25519_x4 = saved.x25519_x4;
            *resolved_label_out = "x25519-avx2";
            return AMA_DISPATCH_ONLY_HONORED;
        }
        return AMA_DISPATCH_ONLY_UNSUPPORTED;
    }
#endif

#ifdef AMA_HAVE_NEON_IMPL
    if (strcmp(slot, "aes-gcm-neon") == 0) {
        if (saved.aes_gcm_encrypt == ama_aes256_gcm_encrypt_neon) {
            dispatch_table.aes_gcm_encrypt = saved.aes_gcm_encrypt;
            dispatch_table.aes_gcm_decrypt = saved.aes_gcm_decrypt;
            *resolved_label_out = "aes-gcm-neon";
            return AMA_DISPATCH_ONLY_HONORED;
        }
        return AMA_DISPATCH_ONLY_UNSUPPORTED;
    }
    if (strcmp(slot, "chacha20-neon") == 0) {
        if (saved.chacha20_block_x8 == ama_chacha20_block_x8_neon) {
            dispatch_table.chacha20_block_x8 = saved.chacha20_block_x8;
            *resolved_label_out = "chacha20-neon";
            return AMA_DISPATCH_ONLY_HONORED;
        }
        return AMA_DISPATCH_ONLY_UNSUPPORTED;
    }
    if (strcmp(slot, "sha3-neon") == 0) {
        if (saved.keccak_f1600 == ama_keccak_f1600_neon) {
            dispatch_table.keccak_f1600 = saved.keccak_f1600;
            dispatch_table.sha3_256     = saved.sha3_256;
            *resolved_label_out = "sha3-neon";
            return AMA_DISPATCH_ONLY_HONORED;
        }
        return AMA_DISPATCH_ONLY_UNSUPPORTED;
    }
#endif

#ifdef AMA_HAVE_SVE2_IMPL
    if (strcmp(slot, "kyber-sve2") == 0) {
        if (saved.kyber_ntt == ama_kyber_ntt_sve2) {
            dispatch_table.kyber_ntt         = saved.kyber_ntt;
            dispatch_table.kyber_invntt      = saved.kyber_invntt;
            dispatch_table.kyber_pointwise   = saved.kyber_pointwise;
            dispatch_table.kyber_poly_add    = saved.kyber_poly_add;
            dispatch_table.kyber_poly_sub    = saved.kyber_poly_sub;
            dispatch_table.kyber_poly_reduce = saved.kyber_poly_reduce;
            *resolved_label_out = "kyber-sve2";
            return AMA_DISPATCH_ONLY_HONORED;
        }
        return AMA_DISPATCH_ONLY_UNSUPPORTED;
    }
    if (strcmp(slot, "sha3-sve2") == 0) {
        if (saved.keccak_f1600 == ama_keccak_f1600_sve2) {
            dispatch_table.keccak_f1600 = saved.keccak_f1600;
            dispatch_table.sha3_256     = saved.sha3_256;
            *resolved_label_out = "sha3-sve2";
            return AMA_DISPATCH_ONLY_HONORED;
        }
        return AMA_DISPATCH_ONLY_UNSUPPORTED;
    }
#endif

    /* Suppress unused-variable warnings on builds where every branch
     * above is compiled out (e.g., -DAMA_ENABLE_AVX2=OFF on x86-64,
     * or non-ARM hosts where AMA_HAVE_NEON_IMPL / AMA_HAVE_SVE2_IMPL
     * are undefined).  `saved` is read by every conditional branch,
     * so its address is observably used at the language level — but
     * if all branches are #ifdef'd out, the compiler can't see that. */
    (void)saved;

    /* Slot name doesn't match any of our recognised entries (the
     * inventory the slot inventory in include/ama_dispatch.h
     * documents).  No stderr here — the caller's diagnostic in
     * dispatch_init_internal() carries the inventory list for the
     * unrecognised case (single line of stderr, no duplication). */
    return AMA_DISPATCH_ONLY_UNRECOGNISED;
}

/* ============================================================================
 * Auto-tune verdict struct, bench helpers, and cross-process cache
 * (Phase 3 of dispatch_init_internal — see the long comment below
 * the kernel-wiring block for the design rationale).
 *
 * Verdict layout: one `<slot>_regressed` flag per benched slot plus
 * the raw best-of-N nanosecond readings (for verbose diagnostics and
 * cache-file round-trip).  Cache hit applies the flags; cache miss
 * populates them from the benches.
 * ============================================================================ */
typedef struct {
    int     keccak_regressed;
    int     keccak_x4_regressed;
    int     kyber_ntt_regressed;
    int     kyber_invntt_regressed;
    int     dilithium_ntt_regressed;
    int     dilithium_invntt_regressed;
    int64_t keccak_simd_ns,        keccak_generic_ns;
    int64_t keccak_x4_simd_ns,     keccak_x4_generic_ns;
    int64_t kyber_ntt_simd_ns,     kyber_ntt_generic_ns;
    int64_t kyber_invntt_simd_ns,  kyber_invntt_generic_ns;
    int64_t dilithium_ntt_simd_ns, dilithium_ntt_generic_ns;
    int64_t dilithium_invntt_simd_ns, dilithium_invntt_generic_ns;
} dispatch_autotune_verdicts_t;

/* 10 % hysteresis band — same threshold as the original keccak
 * auto-tune.  Within-band results keep the SIMD pointer (SIMD has
 * lower peak latency even when averages overlap on noisy hosts);
 * outside-band results revert to scalar.  Negative inputs (bench
 * never ran) yield "not regressed" so the surrounding code can leave
 * the dispatched pointer alone. */
static int bench_slot_regressed(int64_t simd_best_ns, int64_t generic_best_ns) {
    if (simd_best_ns < 0 || generic_best_ns < 0) return 0;
    return simd_best_ns > (generic_best_ns + generic_best_ns / 10);
}

#if !defined(_MSC_VER)
static int64_t timespec_delta_ns(struct timespec a, struct timespec b) {
    return (int64_t)(b.tv_sec - a.tv_sec) * INT64_C(1000000000)
         + (int64_t)(b.tv_nsec - a.tv_nsec);
}

/* Per-signature bench helpers.  Avoid the function-pointer-cast UB
 * (C11 §6.3.2.3 / §6.5.2.2 — calling a function through a pointer of
 * the wrong type is UB even when the ABIs match) by typing each
 * helper to the kernel signature it benches. */
static void dispatch_bench_keccak_single(ama_keccak_f1600_fn generic_fn,
                                          ama_keccak_f1600_fn simd_fn,
                                          uint64_t state[25],
                                          int warmup, int trials, int iters,
                                          int64_t *generic_best,
                                          int64_t *simd_best) {
    for (int w = 0; w < warmup; w++) generic_fn(state);
    for (int w = 0; w < warmup; w++) simd_fn(state);

    *generic_best = -1;
    *simd_best    = -1;
    for (int trial = 0; trial < trials; trial++) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < iters; i++) generic_fn(state);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        int64_t g = timespec_delta_ns(t0, t1);
        if (*generic_best < 0 || g < *generic_best) *generic_best = g;

        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < iters; i++) simd_fn(state);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        int64_t s = timespec_delta_ns(t0, t1);
        if (*simd_best < 0 || s < *simd_best) *simd_best = s;
    }
}

/* x4 bench helper.  The "generic 4-way" reference here is INLINED as
 * four sequential calls to the host's already-wired single-state
 * keccak kernel rather than the public `ama_keccak_f1600_x4_generic`
 * symbol.  The public symbol calls `ama_get_dispatch_table()` to
 * resolve `keccak_f1600`, which would deadlock the pthread_once
 * currently running this dispatch_init_internal — re-entering a
 * once-init under the same thread is implementation-defined on
 * POSIX and is undefined behaviour on Windows InitOnceExecuteOnce.
 * Inlining the 4× scalar fold here uses the kernel pointer the
 * dispatcher has already wired and stays inside the active once
 * call, removing the re-entrancy hazard while preserving the
 * apples-to-apples comparison (the public symbol does the same 4×
 * fold via the same kernel pointer once init completes). */
static void dispatch_bench_keccak_x4(ama_keccak_f1600_x4_fn simd_x4_fn,
                                      ama_keccak_f1600_fn single_state_fn,
                                      uint64_t states[4][25],
                                      int warmup, int trials, int iters,
                                      int64_t *generic_best,
                                      int64_t *simd_best) {
    for (int w = 0; w < warmup; w++) {
        single_state_fn(states[0]);
        single_state_fn(states[1]);
        single_state_fn(states[2]);
        single_state_fn(states[3]);
    }
    for (int w = 0; w < warmup; w++) simd_x4_fn(states);

    *generic_best = -1;
    *simd_best    = -1;
    for (int trial = 0; trial < trials; trial++) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < iters; i++) {
            single_state_fn(states[0]);
            single_state_fn(states[1]);
            single_state_fn(states[2]);
            single_state_fn(states[3]);
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        int64_t g = timespec_delta_ns(t0, t1);
        if (*generic_best < 0 || g < *generic_best) *generic_best = g;

        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < iters; i++) simd_x4_fn(states);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        int64_t s = timespec_delta_ns(t0, t1);
        if (*simd_best < 0 || s < *simd_best) *simd_best = s;
    }
}

static void dispatch_bench_kyber_ntt(ama_kyber_ntt_fn generic_fn,
                                      ama_kyber_ntt_fn simd_fn,
                                      int16_t poly[256],
                                      const int16_t zetas_bench[128],
                                      int64_t *generic_best,
                                      int64_t *simd_best) {
    /* Smaller workload than keccak — Kyber NTT is ~30× faster per
     * call (8 layers × 128 butterflies, all in L1), so we crank ITERS
     * up to keep the total runtime above the clock_gettime resolution
     * floor (~50 ns on modern Linux). */
    const int WARMUP = 100;
    const int TRIALS = 5;
    const int ITERS  = 2000;

    for (int w = 0; w < WARMUP; w++) generic_fn(poly, zetas_bench);
    for (int w = 0; w < WARMUP; w++) simd_fn(poly, zetas_bench);

    *generic_best = -1;
    *simd_best    = -1;
    for (int trial = 0; trial < TRIALS; trial++) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < ITERS; i++) generic_fn(poly, zetas_bench);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        int64_t g = timespec_delta_ns(t0, t1);
        if (*generic_best < 0 || g < *generic_best) *generic_best = g;

        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < ITERS; i++) simd_fn(poly, zetas_bench);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        int64_t s = timespec_delta_ns(t0, t1);
        if (*simd_best < 0 || s < *simd_best) *simd_best = s;
    }
}

static void dispatch_bench_dilithium_ntt(ama_dilithium_ntt_fn generic_fn,
                                          ama_dilithium_ntt_fn simd_fn,
                                          int32_t poly[256],
                                          const int32_t zetas_bench[256],
                                          int64_t *generic_best,
                                          int64_t *simd_best) {
    const int WARMUP = 100;
    const int TRIALS = 5;
    const int ITERS  = 2000;

    for (int w = 0; w < WARMUP; w++) generic_fn(poly, zetas_bench);
    for (int w = 0; w < WARMUP; w++) simd_fn(poly, zetas_bench);

    *generic_best = -1;
    *simd_best    = -1;
    for (int trial = 0; trial < TRIALS; trial++) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < ITERS; i++) generic_fn(poly, zetas_bench);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        int64_t g = timespec_delta_ns(t0, t1);
        if (*generic_best < 0 || g < *generic_best) *generic_best = g;

        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < ITERS; i++) simd_fn(poly, zetas_bench);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        int64_t s = timespec_delta_ns(t0, t1);
        if (*simd_best < 0 || s < *simd_best) *simd_best = s;
    }
}

/* ===== Cross-process auto-tune cache =====================================
 *
 * Opt-in via `AMA_DISPATCH_CACHE_FILE=<path>`.  When set:
 *   - Load:  if <path> exists and the cached `fingerprint=` line matches
 *            the current host's fingerprint, populate the verdict
 *            struct from the file and skip the microbench entirely.
 *   - Save:  after a successful microbench, write the verdict struct
 *            to <path> using a tmp-file + rename for atomicity.
 *
 * The fingerprint is a deterministic string built from the dispatch
 * info (arch_name + per-slot impl level) and the CPU feature probes
 * already exposed by ama_cpuid.h.  Any change to the host CPU's
 * detected features (kernel upgrade, microcode change, hypervisor
 * masking) invalidates the cache automatically — no manual flush.
 *
 * Format (text, one key=value per line, leading `#` are comments):
 *
 *     # AMA Cryptography dispatch auto-tune cache v1
 *     fingerprint=<deterministic-string>
 *     keccak_regressed=<0|1>
 *     keccak_x4_regressed=<0|1>
 *     kyber_ntt_regressed=<0|1>
 *     kyber_invntt_regressed=<0|1>
 *     dilithium_ntt_regressed=<0|1>
 *     dilithium_invntt_regressed=<0|1>
 *     keccak_simd_ns=<int64>
 *     keccak_generic_ns=<int64>
 *     ...
 *
 * The verdict timings are written for diagnostic value (a future
 * operator can `cat` the cache file and see WHY the dispatcher reverted
 * a slot); they are ignored on load — only the per-slot regressed
 * flags drive kernel revert decisions.  Unknown lines are skipped so
 * old binaries reading a newer cache file degrade gracefully.
 *
 * The fingerprint check is a strict string equality — if any feature
 * differs between the cached header and the current host, the cache
 * is treated as a miss and the bench runs.  This is the conservative
 * choice: a false-positive cache hit could install a regressed kernel
 * pointer that the bench would have caught.
 */
static void dispatch_cache_fingerprint(char *out, size_t outlen) {
    int avx2 = 0, avx512f = 0, avx512kc = 0, aesni = 0, pclmul = 0;
    int vaes = 0, arm_aes = 0, arm_pmull = 0;
#if defined(__x86_64__) || defined(_M_X64)
    avx2     = ama_has_avx2();
    avx512f  = ama_has_avx512f();
    avx512kc = ama_cpuid_has_avx512_keccak();
    aesni    = ama_has_aes_ni();
    pclmul   = ama_has_pclmulqdq();
#if !defined(_MSC_VER)
    vaes     = ama_cpuid_has_vaes_aesgcm();
#endif
#elif defined(__aarch64__) || defined(_M_ARM64)
    arm_aes   = ama_has_arm_aes();
    arm_pmull = ama_has_arm_pmull();
#endif
    /* `dispatch_info.arch_name` already set by the architecture
     * detection block above; this helper runs strictly after that. */
    snprintf(out, outlen,
        "v1|%s|avx2=%d|avx512f=%d|avx512kc=%d|aesni=%d|pclmul=%d|vaes=%d|"
        "arm_aes=%d|arm_pmull=%d",
        dispatch_info.arch_name ? dispatch_info.arch_name : "unknown",
        avx2, avx512f, avx512kc, aesni, pclmul, vaes,
        arm_aes, arm_pmull);
}

/* Strip trailing newline / CR.  No allocation. */
static void rstrip(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

/* Returns 0 on cache hit, non-zero on miss.  Verdict struct is left
 * untouched on miss so the surrounding code can populate it via
 * benches. */
static int dispatch_cache_load(const char *path, const char *fingerprint,
                                dispatch_autotune_verdicts_t *v) {
    FILE *fp = fopen(path, "re");
    if (!fp) return -1;

    char line[512];
    int  fp_matched = 0;
    dispatch_autotune_verdicts_t tmp;
    memset(&tmp, 0, sizeof(tmp));  // PUBLIC-DATA: tmp — zero-init cache parsing scratch (PUBLIC)

    while (fgets(line, sizeof(line), fp)) {
        rstrip(line);
        if (line[0] == '\0' || line[0] == '#') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *key = line;
        const char *val = eq + 1;

        if (strcmp(key, "fingerprint") == 0) {
            fp_matched = (strcmp(val, fingerprint) == 0);
        } else if (strcmp(key, "keccak_regressed") == 0) {
            tmp.keccak_regressed = atoi(val);
        } else if (strcmp(key, "keccak_x4_regressed") == 0) {
            tmp.keccak_x4_regressed = atoi(val);
        } else if (strcmp(key, "kyber_ntt_regressed") == 0) {
            tmp.kyber_ntt_regressed = atoi(val);
        } else if (strcmp(key, "kyber_invntt_regressed") == 0) {
            tmp.kyber_invntt_regressed = atoi(val);
        } else if (strcmp(key, "dilithium_ntt_regressed") == 0) {
            tmp.dilithium_ntt_regressed = atoi(val);
        } else if (strcmp(key, "dilithium_invntt_regressed") == 0) {
            tmp.dilithium_invntt_regressed = atoi(val);
        }
        /* timing fields are diagnostic; ignored on load.  Unknown keys
         * silently skipped for forward compatibility. */
    }
    fclose(fp);

    if (!fp_matched) return -2;
    *v = tmp;
    return 0;
}

static void dispatch_cache_save(const char *path, const char *fingerprint,
                                 const dispatch_autotune_verdicts_t *v) {
    /* tmp-file + rename for atomicity.  No fsync — this is best-effort
     * diagnostic state; a crash mid-write leaves the prior cache (if
     * any) intact and a future init just re-runs the bench. */
    size_t pathlen = strlen(path);
    if (pathlen == 0 || pathlen > 4000) return;
    char tmppath[4096];
    snprintf(tmppath, sizeof(tmppath), "%s.tmp.%ld", path, (long)getpid());

    FILE *fp = fopen(tmppath, "we");
    if (!fp) {
        if (dispatch_verbose())
            fprintf(stderr,
                "[AMA Dispatch] cache write FAILED (open '%s' errno=%d)\n",
                tmppath, errno);
        return;
    }
    fprintf(fp, "# AMA Cryptography dispatch auto-tune cache v1\n");
    fprintf(fp, "# Generated automatically; safe to delete (a future "
                "process will re-bench).\n");
    fprintf(fp, "fingerprint=%s\n", fingerprint);
    fprintf(fp, "keccak_regressed=%d\n",            v->keccak_regressed);
    fprintf(fp, "keccak_x4_regressed=%d\n",         v->keccak_x4_regressed);
    fprintf(fp, "kyber_ntt_regressed=%d\n",         v->kyber_ntt_regressed);
    fprintf(fp, "kyber_invntt_regressed=%d\n",      v->kyber_invntt_regressed);
    fprintf(fp, "dilithium_ntt_regressed=%d\n",     v->dilithium_ntt_regressed);
    fprintf(fp, "dilithium_invntt_regressed=%d\n",  v->dilithium_invntt_regressed);
    fprintf(fp, "keccak_simd_ns=%lld\n",            (long long)v->keccak_simd_ns);
    fprintf(fp, "keccak_generic_ns=%lld\n",         (long long)v->keccak_generic_ns);
    fprintf(fp, "keccak_x4_simd_ns=%lld\n",         (long long)v->keccak_x4_simd_ns);
    fprintf(fp, "keccak_x4_generic_ns=%lld\n",      (long long)v->keccak_x4_generic_ns);
    fprintf(fp, "kyber_ntt_simd_ns=%lld\n",         (long long)v->kyber_ntt_simd_ns);
    fprintf(fp, "kyber_ntt_generic_ns=%lld\n",      (long long)v->kyber_ntt_generic_ns);
    fprintf(fp, "kyber_invntt_simd_ns=%lld\n",      (long long)v->kyber_invntt_simd_ns);
    fprintf(fp, "kyber_invntt_generic_ns=%lld\n",   (long long)v->kyber_invntt_generic_ns);
    fprintf(fp, "dilithium_ntt_simd_ns=%lld\n",     (long long)v->dilithium_ntt_simd_ns);
    fprintf(fp, "dilithium_ntt_generic_ns=%lld\n",  (long long)v->dilithium_ntt_generic_ns);
    fprintf(fp, "dilithium_invntt_simd_ns=%lld\n",  (long long)v->dilithium_invntt_simd_ns);
    fprintf(fp, "dilithium_invntt_generic_ns=%lld\n", (long long)v->dilithium_invntt_generic_ns);
    fclose(fp);

    if (rename(tmppath, path) != 0) {
        if (dispatch_verbose())
            fprintf(stderr,
                "[AMA Dispatch] cache rename FAILED ('%s' -> '%s' errno=%d)\n",
                tmppath, path, errno);
        (void)unlink(tmppath);
        return;
    }

    if (dispatch_verbose())
        fprintf(stderr, "[AMA Dispatch] Auto-tune verdict cached to '%s'\n",
                path);
}
#else  /* _MSC_VER — no POSIX clock_gettime, no microbench, no cache. */
static void dispatch_cache_fingerprint(char *out, size_t outlen) {
    if (out && outlen) out[0] = '\0';
}
static int dispatch_cache_load(const char *path, const char *fingerprint,
                                dispatch_autotune_verdicts_t *v) {
    (void)path; (void)fingerprint; (void)v;
    return -1;
}
static void dispatch_cache_save(const char *path, const char *fingerprint,
                                 const dispatch_autotune_verdicts_t *v) {
    (void)path; (void)fingerprint; (void)v;
}
#endif

/* ============================================================================
 * Dispatch initialization
 *
 * Sets the implementation level for each algorithm based on detected
 * CPU features.  Called once via ama_dispatch_init().
 * ============================================================================ */
static void dispatch_init_internal(void) {
    memset(&dispatch_info, 0, sizeof(dispatch_info));  // PUBLIC-DATA: dispatch_info — init global dispatch_info (PUBLIC — CPU arch label + per-slot impl level)

#if defined(__x86_64__) || defined(_M_X64)
    dispatch_info.arch_name = "x86-64";

    int has_avx2 = ama_has_avx2();       /* CPUID + OSXSAVE + XCR0 AVX state */
    int has_avx512f = ama_has_avx512f(); /* CPUID + OSXSAVE AVX state; no ZMM XCR0 yet */

    ama_impl_level_t best = AMA_IMPL_GENERIC;
    if (has_avx2)   best = AMA_IMPL_AVX2;
    /* Belt-and-suspenders: AVX-512F is a strict superset of AVX2.
     * Never promote past AVX2 unless AVX2 itself passed its XCR0
     * gate, preventing the effective→AVX2 fallback below from
     * wiring VEX-encoded function pointers on a host whose OS has
     * not enabled AVX state (Devin Review #3136221784). */
    if (has_avx512f && has_avx2) best = AMA_IMPL_AVX512;

    /* Default per-slot effective level.  Until each non-SHA3 slot
     * grows its own ZMM/EVEX kernel, AMA_IMPL_AVX512 is downgraded
     * to AMA_IMPL_AVX2 here; PR C carved out the SHA3 slot only,
     * via the explicit promotion below. */
    ama_impl_level_t effective = (best == AMA_IMPL_AVX512)
                                 ? AMA_IMPL_AVX2
                                 : best;

    /* PR C — SHA3 slot promotion to AMA_IMPL_AVX512.
     *
     * The in-house AVX-512 4-way Keccak kernel
     * (src/c/avx512/ama_sha3_x4_avx512.c) is the only AVX-512 path
     * wired today.  Promote the SHA3 slot past the per-slot
     * effective→AVX2 downgrade if and only if:
     *   1. CMake compiled the kernel in (AMA_HAVE_AVX512_IMPL), and
     *   2. the runtime CPUID bundle gate
     *      (ama_cpuid_has_avx512_keccak() — AVX-512F + AVX-512VL
     *      + XCR0 1+2+5+6+7) passes on this host.
     * All other slots keep `effective` until they grow ZMM/EVEX
     * kernels of their own — explicit non-goal of PR C. */
    ama_impl_level_t effective_sha3 = effective;
#ifdef AMA_HAVE_AVX512_IMPL
    if (best == AMA_IMPL_AVX512 && ama_cpuid_has_avx512_keccak()) {
        effective_sha3 = AMA_IMPL_AVX512;
    }
#endif

    dispatch_info.sha3             = effective_sha3;
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
    dispatch_info.x25519           = effective;

    if (dispatch_verbose())
        fprintf(stderr,
            "[AMA Dispatch] x86-64: AVX2=%d AVX-512F=%d AVX-512-Keccak=%d "
            "=> level=%d (sha3=%d)\n",
            has_avx2, has_avx512f,
            ama_cpuid_has_avx512_keccak(),
            (int)effective, (int)effective_sha3);

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
    /* X25519 4-way ladder: AVX2-only kernel ships in this PR; NEON
     * and SVE2 tiers fall through to GENERIC and the public batch
     * API uses the scalar fe51 ladder per lane. */
    dispatch_info.x25519           = AMA_IMPL_GENERIC;

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
    dispatch_table.kyber_poly_add    = NULL;  /* NULL = caller uses inline scalar; today only the SVE2 init below wires this */
    dispatch_table.kyber_poly_sub    = NULL;
    dispatch_table.kyber_poly_reduce = NULL;
    dispatch_table.kyber_cbd2        = NULL;  /* NULL = caller uses inline generic */
    dispatch_table.dilithium_ntt     = NULL;
    dispatch_table.dilithium_invntt  = NULL;
    dispatch_table.dilithium_pointwise = NULL;
    dispatch_table.dilithium_rej_uniform = NULL;  /* NULL = caller uses 3-byte scalar loop */
    dispatch_table.aes_gcm_encrypt     = NULL;  /* NULL = caller uses schoolbook GHASH */
    dispatch_table.aes_gcm_decrypt     = NULL;
    dispatch_table.chacha20_block_x8   = NULL;  /* NULL = caller uses scalar 1-block loop */
    dispatch_table.argon2_g            = NULL;  /* NULL = caller uses scalar BlaMka G */
    dispatch_table.x25519_x4           = NULL;  /* NULL = caller uses 4 sequential scalar ladders */

#ifdef AMA_HAVE_AVX2_IMPL
    if (dispatch_info.sha3 >= AMA_IMPL_AVX2) {
        dispatch_table.keccak_f1600    = ama_keccak_f1600_avx2;
        dispatch_table.keccak_f1600_x4 = ama_keccak_f1600_x4_avx2;
        dispatch_table.sha3_256        = ama_sha3_256_avx2;
    }
#endif

    /* PR C — AVX-512 4-way Keccak upgrade.  Layered on top of the
     * AVX2 wiring so that:
     *   - When AMA_ENABLE_AVX512 is OFF (default), this block is
     *     compiled out entirely and the AVX2 4-way pointer stands.
     *   - When AMA_ENABLE_AVX512 is ON but the runtime gate fails
     *     (no AVX-512F/VL CPUID, or OS hasn't enabled the AVX-512
     *     save area in XCR0), dispatch_info.sha3 < AMA_IMPL_AVX512
     *     and this branch is skipped — AVX2 4-way remains.
     *   - When both the build flag and the runtime gate pass, the
     *     in-house AVX-512 kernel takes over the keccak_f1600_x4
     *     pointer.  The single-state keccak_f1600 pointer is left
     *     on the AVX2 path — this PR ships only the 4-way kernel.
     * The hand-written kernel preserves the same uint64_t[4][25]
     * ABI as the AVX2 4-way path, so the SHAKE128/SHAKE256 absorb +
     * squeeze wrappers in src/c/ama_sha3.c need no changes. */
#ifdef AMA_HAVE_AVX512_IMPL
#if defined(__x86_64__) || defined(_M_X64)
    if (dispatch_info.sha3 >= AMA_IMPL_AVX512) {
        dispatch_table.keccak_f1600_x4 = ama_keccak_f1600_x4_avx512;
        if (dispatch_verbose())
            fprintf(stderr,
                "[AMA Dispatch] keccak_f1600_x4: AVX-512 (vprolq + vpternlogq) selected\n");
    }
#endif
#endif

#ifdef AMA_HAVE_AVX2_IMPL
    if (dispatch_info.kyber >= AMA_IMPL_AVX2) {
        dispatch_table.kyber_ntt       = ama_kyber_ntt_avx2;
        dispatch_table.kyber_invntt    = ama_kyber_invntt_avx2;
        dispatch_table.kyber_pointwise = ama_kyber_poly_pointwise_avx2;
        dispatch_table.kyber_cbd2      = ama_kyber_cbd2_avx2;
    }
    if (dispatch_info.dilithium >= AMA_IMPL_AVX2) {
        dispatch_table.dilithium_ntt         = ama_dilithium_ntt_avx2;
        dispatch_table.dilithium_invntt      = ama_dilithium_invntt_avx2;
        dispatch_table.dilithium_pointwise   = ama_dilithium_poly_pointwise_avx2;
        dispatch_table.dilithium_rej_uniform = ama_dilithium_rej_uniform_avx2;
    }
    /* The AVX2 AES-GCM kernel emits AES-NI (AESENC / AESENCLAST /
     * AESKEYGENASSIST) and PCLMULQDQ (CLMUL) opcodes in addition to
     * VEX-encoded 128-bit loads/stores.  AVX2 alone is not a
     * sufficient gate: a hypervisor (or chicken-bit MSR) may advertise
     * CPUID.(EAX=7,ECX=0):EBX[5] while masking CPUID.(EAX=1):ECX[25]
     * (AES-NI) or CPUID.(EAX=1):ECX[1] (PCLMULQDQ).  Installing the
     * AVX2 AES-NI pointers on such a host would SIGILL on the first
     * AESENC — Copilot review #3140228457 / #3140228489.  Require
     * AVX2 + AES-NI + PCLMULQDQ explicitly here.  The VAES upgrade
     * inside this block is gated separately by
     * ama_cpuid_has_vaes_aesgcm(), which since Devin Review
     * #3140732664 also explicitly checks PCLMULQDQ (the kernel uses
     * _mm_clmulepi64_si128 on single-block edge paths;
     * baseline PCLMULQDQ — CPUID.(EAX=1):ECX[1] — is architecturally
     * independent of VPCLMULQDQ — CPUID.(EAX=7,ECX=0):ECX[10] — even
     * though every shipped CPU has both). */
    if (dispatch_info.aes_gcm >= AMA_IMPL_AVX2
        && ama_has_aes_ni()
        && ama_has_pclmulqdq()) {
        dispatch_table.aes_gcm_encrypt = ama_aes256_gcm_encrypt_avx2;
        dispatch_table.aes_gcm_decrypt = ama_aes256_gcm_decrypt_avx2;
        /* PR A — VAES + VPCLMULQDQ YMM upgrade.  CPUID-gated; falls
         * through to the AVX2 AES-NI pointers above when the bundle
         * (AVX2 + VAES + VPCLMULQDQ + AES-NI + AVX-OSXSAVE) is not
         * present.  No reordering of dispatch_init_internal() calls
         * — INVARIANT-15 unchanged. */
#if !defined(_MSC_VER)
        if (ama_cpuid_has_vaes_aesgcm()) {
            dispatch_table.aes_gcm_encrypt = ama_aes256_gcm_encrypt_vaes_avx2;
            dispatch_table.aes_gcm_decrypt = ama_aes256_gcm_decrypt_vaes_avx2;
            if (dispatch_verbose())
                fprintf(stderr, "[AMA Dispatch] AES-GCM: VAES+VPCLMULQDQ YMM path selected\n");
        }
#endif
    } else if (dispatch_verbose() && dispatch_info.aes_gcm >= AMA_IMPL_AVX2) {
        fprintf(stderr,
            "[AMA Dispatch] AES-GCM: AVX2 present but AES-NI=%d PCLMULQDQ=%d"
            " — falling back to generic C path\n",
            ama_has_aes_ni(), ama_has_pclmulqdq());
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
    if (dispatch_info.x25519 >= AMA_IMPL_AVX2) {
        /* X25519 4-way AVX2 kernel is **opt-in**, not opt-out.
         *
         * Rationale: on hosts where the scalar X25519 path is fe64
         * (radix-2^64, x86-64 GCC/Clang with MULX/ADX), four
         * sequential scalar ladders are *faster* than four lanes of
         * the AVX2 donna-32bit ladder.  The 4-way kernel uses 32-bit
         * limbs because AVX2 lacks a 64×64→128 lane-wise multiply
         * (that arrived with AVX-512 IFMA); donna-32bit's larger
         * cross-product count outpaces the 4× SIMD width on
         * Skylake-Cascade-class cores.  Measured locally:
         *   scalar fe64    : ~78 µs / op
         *   AVX2 4-way     : ~234 µs / op
         * — a ~3× regression per op.
         *
         * The kernel is still wired in for: (a) the `_x4` constant-
         * time test lane, (b) CI matrix coverage of the SIMD path,
         * (c) future hosts where the scalar path falls back to fe51
         * or gf16 and the 4-way may break even, (d) eventual port
         * to AVX-512 IFMA / VPMADD52 which closes the gap.  Opt in
         * with `AMA_DISPATCH_USE_X25519_AVX2=1` to exercise it. */
        const char *use_x25519 = getenv("AMA_DISPATCH_USE_X25519_AVX2");
        if (use_x25519 && use_x25519[0] == '1')
            dispatch_table.x25519_x4 = ama_x25519_scalarmult_x4_avx2;
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
    /* NEON AES-GCM, ChaCha20, Argon2 wiring (2026-05).
     *
     * AES-GCM is gated on `ama_cpuid_has_arm_aes()` — the AES + PMULL
     * bundle.  The kernel emits both vaeseq_u8/vaesmcq_u8 (FEAT_AES)
     * and vmull_p64/vmull_high_p64 (FEAT_PMULL) for GHASH; a host that
     * reports AES but masks PMULL would SIGILL on the first GHASH
     * multiply.  Gating on the bundle gate — rather than `ama_has_arm_aes()`
     * alone — closes that hazard (Copilot review #3249188230).
     *
     * The encrypt kernel existed before this PR; the decrypt kernel
     * and these wiring lines are new.  ChaCha20 and Argon2 only need
     * baseline NEON, which is mandatory on AArch64 (`detect_neon()`
     * always returns 1), so they wire unconditionally under
     * AMA_HAVE_NEON_IMPL.  Each kernel scrubs sensitive intermediate
     * state on every return path (INVARIANT-12). */
    if (dispatch_info.aes_gcm >= AMA_IMPL_NEON && ama_cpuid_has_arm_aes()) {
        dispatch_table.aes_gcm_encrypt = ama_aes256_gcm_encrypt_neon;
        dispatch_table.aes_gcm_decrypt = ama_aes256_gcm_decrypt_neon;
        if (dispatch_verbose())
            fprintf(stderr, "[AMA Dispatch] AES-GCM: NEON + ARMv8 Crypto Ext (AES + PMULL) selected\n");
    } else if (dispatch_verbose() && dispatch_info.aes_gcm >= AMA_IMPL_NEON) {
        fprintf(stderr,
            "[AMA Dispatch] AES-GCM: NEON present but ARM-AES=%d ARM-PMULL=%d"
            " — falling back to generic C path\n",
            ama_has_arm_aes(), ama_has_arm_pmull());
    }
    if (dispatch_info.chacha20poly1305 >= AMA_IMPL_NEON) {
        /* Match the AVX2 env opt-out for parity across architectures. */
        const char *no_chacha = getenv("AMA_DISPATCH_NO_CHACHA_AVX2");
        if (!(no_chacha && no_chacha[0] == '1'))
            dispatch_table.chacha20_block_x8 = ama_chacha20_block_x8_neon;
    }
    if (dispatch_info.argon2 >= AMA_IMPL_NEON) {
        const char *no_argon = getenv("AMA_DISPATCH_NO_ARGON2_AVX2");
        if (!(no_argon && no_argon[0] == '1'))
            dispatch_table.argon2_g = ama_argon2_g_neon;
    }
#endif

    /* Save the pre-SVE2 keccak pointer (could be NEON or generic) so
     * the auto-tuning fallback reverts to this rather than always
     * falling back to generic C — which would skip the NEON tier. */
    ama_keccak_f1600_fn pre_sve2_keccak = dispatch_table.keccak_f1600;
    /* Save the pre-SVE2 sha3_256 slot the same way so the auto-tune
     * revert below can keep the two slots in lockstep: the SVE2
     * `ama_sha3_256_sve2` wrapper calls `ama_keccak_f1600_sve2`
     * directly (not through the dispatch table), so if the auto-tune
     * decides SVE2 keccak regressed on this host, sha3_256 must revert
     * too — otherwise sha3_256 stays on the slow SVE2 path while
     * keccak_f1600 has already moved off it. */
    ama_sha3_256_fn pre_sve2_sha3_256 = dispatch_table.sha3_256;
    /* Save the pre-SVE2 kyber_poly_{add,sub,reduce} slots for the same
     * lockstep revert reason: today no other tier wires these (AVX2 /
     * NEON let the compiler auto-vectorise the trivial int16 add/sub
     * loop), so the pre-SVE2 values are NULL on every host.  Saving
     * them anyway keeps the revert path future-proof: if a NEON or
     * AVX2 helper is wired in a later release, the SVE2 auto-tune
     * fallback will demote to that tier instead of all the way to
     * scalar.  Mirrors the pre_sve2_keccak / pre_sve2_sha3_256
     * pattern above. */
    ama_kyber_poly_add_fn    pre_sve2_kyber_poly_add    = dispatch_table.kyber_poly_add;
    ama_kyber_poly_sub_fn    pre_sve2_kyber_poly_sub    = dispatch_table.kyber_poly_sub;
    ama_kyber_poly_reduce_fn pre_sve2_kyber_poly_reduce = dispatch_table.kyber_poly_reduce;

#ifdef AMA_HAVE_SVE2_IMPL
    if (dispatch_info.sha3 >= AMA_IMPL_SVE2) {
        dispatch_table.keccak_f1600 = ama_keccak_f1600_sve2;
        /* sha3_256 wrapper: reuses the SVE2 Keccak permutation above
         * and adds a lane-predicated rate-block absorb.  Promoted from
         * "compiled but unwired" to wired in this PR; pinned by the
         * existing FIPS 202 SHA3-256 KATs which flow through
         * `dispatch_table.sha3_256` on any host where this slot is
         * non-NULL. */
        dispatch_table.sha3_256     = ama_sha3_256_sve2;
    }
    if (dispatch_info.kyber >= AMA_IMPL_SVE2) {
        dispatch_table.kyber_ntt        = ama_kyber_ntt_sve2;
        dispatch_table.kyber_invntt     = ama_kyber_invntt_sve2;
        dispatch_table.kyber_pointwise  = ama_kyber_poly_pointwise_sve2;
        /* Promoted from compiled-but-unwired in this PR.  All three
         * are algorithmically straightforward (svadd_s16_x,
         * svsub_s16_x, and the Barrett reduction reused from the
         * wired SVE2 NTT path), reuse the same VL-agnostic predicated
         * loop scaffold as kyber_ntt_sve2, and are pinned by
         * test_kyber_poly_equiv.c.  See the file header in
         * src/c/sve2/ama_kyber_sve2.c for the historical wiring
         * checklist; every item is now resolved.
         *
         * NOTE on benchmarking: modern GCC/Clang already auto-vectorise
         * short int16 add/sub loops at -O3, so the SVE2 win over
         * scalar may be marginal on real ARMv9 hardware.  If a future
         * measurement on a real ARMv9 host shows SVE2 regressing past
         * the 10% hysteresis band, the auto-tune lockstep revert
         * below (the SVE2 keccak proxy) will demote these three slots
         * back to NULL — production code in src/c/ama_kyber.c then
         * falls through to its inline scalar loop, which the compiler
         * auto-vectorises on AArch64.  kyber_ntt / kyber_invntt /
         * kyber_pointwise are NOT reverted in lockstep today (their
         * arithmetic intensity is high enough that the auto-tune
         * proxy is a worse fit for them than the empirical reality
         * on real silicon); only the three thin int16 helpers ride
         * the keccak proxy.  qemu's SVE2 emulation is ~47x slower
         * than scalar and is not a real-hardware finding; benchmark
         * on an actual core. */
        dispatch_table.kyber_poly_add    = ama_kyber_poly_add_sve2;
        dispatch_table.kyber_poly_sub    = ama_kyber_poly_sub_sve2;
        dispatch_table.kyber_poly_reduce = ama_kyber_poly_reduce_sve2;
    }
    if (dispatch_info.dilithium >= AMA_IMPL_SVE2) {
        dispatch_table.dilithium_ntt       = ama_dilithium_ntt_sve2;
        dispatch_table.dilithium_invntt    = ama_dilithium_invntt_sve2;
        dispatch_table.dilithium_pointwise = ama_dilithium_poly_pointwise_sve2;
    }
    /* SVE2 wired surface (canonical as of this PR):
     *   - keccak_f1600  (single-state Keccak permutation)
     *   - sha3_256      (SHA3-256 sponge using the above permutation;
     *                    promoted from compiled-but-unwired in PR #312)
     *   - kyber_ntt / kyber_invntt / kyber_pointwise
     *   - kyber_poly_add / kyber_poly_sub / kyber_poly_reduce
     *                   (promoted from compiled-but-unwired in this
     *                    PR; pinned by test_kyber_poly_equiv.c)
     *   - dilithium_ntt / dilithium_invntt / dilithium_pointwise
     *
     * Every other SVE2 TU has been reduced to a documentation
     * placeholder (mirroring `ama_aes_gcm_sve2.c` from PR #308) for
     * one of three concrete reasons, all enumerated in the per-file
     * headers under `src/c/sve2/`:
     *
     *   - ChaCha20 (`ama_chacha20poly1305_sve2.c`): prior kernel had a
     *     VL-dependent block-count signature that could not match the
     *     fixed `ama_chacha20_block_x8_fn` dispatch contract, and no
     *     SVE-aware CI lane existed to KAT-validate it across
     *     VL=128/256/512.  AArch64 hosts continue to dispatch to the
     *     validated NEON kernel wired above.
     *   - Argon2 (`ama_argon2_sve2.c`): prior kernel implemented
     *     plain Blake2b G — not RFC 9106 §3.5 BlaMka G — and was
     *     missing the column-pass entirely.  Wiring it would have
     *     broken Argon2id KATs.  AArch64 hosts continue to dispatch
     *     to the validated NEON BlaMka kernel wired above.
     *   - SPHINCS+ / SLH-DSA (`ama_sphincs_sve2.c`): the dispatch
     *     table intentionally exposes no SPHINCS+ function-pointer
     *     slots; the SLH-DSA inner loop accelerates indirectly via
     *     the `keccak_f1600` slot above (which on SVE2 routes to the
     *     SVE2 Keccak kernel).  A standalone SLH-DSA SVE2 surface
     *     would be speculative API.
     *   - Ed25519 (`ama_ed25519_sve2.c`): the dispatcher reports
     *     `ed25519 = AMA_IMPL_GENERIC` on every AArch64 host (see
     *     lines 354-357 above).  A vector-wide Ed25519 path only
     *     pays off in a batched API which AMA Cryptography
     *     intentionally does not expose.
     *   - AES-GCM (`ama_aes_gcm_sve2.c`): PR #308 precedent.  AES-GCM
     *     on SVE2 dispatches through the NEON PMULL kernel above,
     *     which carries the ARMv8 Crypto Extensions.
     *
     * Each placeholder TU documents the preconditions (correct
     * algorithmic shape, byte-identity KAT lane under SVE-aware CI,
     * conforming dispatch signature, real production caller) that
     * a future SVE2 kernel must meet before wiring.  The current
     * wired tier is the strict superset of every previous release. */
#endif

    /* ====================================================================
     * Phase 3: per-slot SIMD auto-tune.
     *
     * Each SIMD slot is benched independently against its scalar
     * reference and reverted alone on a >10 % regression.  Only the
     * single-state `keccak_f1600` verdict carries a lockstep tie —
     * to `sha3_256` and `kyber_poly_{add,sub,reduce}` — because the
     * SVE2 `sha3_256` wrapper embeds `ama_keccak_f1600_sve2` directly
     * and the three `kyber_poly_*` slots share the SVE2 codegen tier
     * with no independent kernel.  Every other slot stands alone.
     *
     * `AMA_DISPATCH_CACHE_FILE=<path>` (opt-in): write the verdict
     * after a successful bench; subsequent processes with the same
     * env var and matching CPU-feature fingerprint load the verdict
     * and skip the bench.  Default does no file I/O.
     *
     * `AMA_DISPATCH_NO_AUTOTUNE=1` bypasses every bench AND the cache.
     * MSVC skips the whole phase (no POSIX clock_gettime).
     * ==================================================================== */
#if !defined(_MSC_VER)
    const char *no_autotune = getenv("AMA_DISPATCH_NO_AUTOTUNE");
    int autotune_disabled = (no_autotune && no_autotune[0] == '1');

    /* Per-slot regression verdicts.  Default = "SIMD kept".  Each bench
     * below sets its own field; the cache layer can also populate them
     * before the benches run, in which case the benches are skipped. */
    dispatch_autotune_verdicts_t v;
    memset(&v, 0, sizeof(v));  // PUBLIC-DATA: v — zero-init verdict struct (PUBLIC; no secret material)

    const char *cache_path = getenv("AMA_DISPATCH_CACHE_FILE");
    char fingerprint[256];
    dispatch_cache_fingerprint(fingerprint, sizeof(fingerprint));
    int cache_hit = 0;

    if (!autotune_disabled && cache_path && cache_path[0]) {
        if (dispatch_cache_load(cache_path, fingerprint, &v) == 0) {
            cache_hit = 1;
            if (dispatch_verbose())
                fprintf(stderr,
                    "[AMA Dispatch] Auto-tune: cache HIT from '%s' "
                    "(fingerprint=%s) — skipping microbench\n",
                    cache_path, fingerprint);
        } else if (dispatch_verbose()) {
            fprintf(stderr,
                "[AMA Dispatch] Auto-tune: cache MISS for '%s' "
                "(fingerprint=%s) — running microbench\n",
                cache_path, fingerprint);
        }
    }

    if (!autotune_disabled && !cache_hit) {
        /* ----- Slot 1: keccak_f1600 (single-state permutation) ------- */
        if (dispatch_table.keccak_f1600 != ama_keccak_f1600_generic) {
            uint64_t state[25];
            memset(state, 0x42, sizeof(state));  // PUBLIC-DATA: state — bench scratch buffer (PUBLIC; KAT-irrelevant 0x42 fill)

            int64_t generic_best = -1, simd_best = -1;
            dispatch_bench_keccak_single(
                ama_keccak_f1600_generic, dispatch_table.keccak_f1600,
                state,
                /*warmup=*/200, /*trials=*/5, /*iters=*/2000,
                &generic_best, &simd_best);
            v.keccak_regressed = bench_slot_regressed(simd_best, generic_best);
            v.keccak_simd_ns    = simd_best;
            v.keccak_generic_ns = generic_best;
        }

        /* ----- Slot 2: keccak_f1600_x4 (batched 4-way permutation) ----
         * Benched independently — the AVX-512 4-way kernel is a
         * fundamentally different implementation from the AVX2 single-
         * state kernel, so the slot-1 verdict cannot proxy for it.
         * The 4× scalar baseline uses `dispatch_table.keccak_f1600`
         * (the kernel slot 1 just settled on), matching what
         * `ama_keccak_f1600_x4_generic` does at runtime.  Fewer iters
         * than slot 1 because each call permutes 4× the state. */
        if (dispatch_table.keccak_f1600_x4 != ama_keccak_f1600_x4_generic) {
            uint64_t states[4][25];
            memset(states, 0x42, sizeof(states));  // PUBLIC-DATA: states — bench scratch (PUBLIC)

            int64_t generic_best = -1, simd_best = -1;
            dispatch_bench_keccak_x4(
                dispatch_table.keccak_f1600_x4,
                dispatch_table.keccak_f1600,
                states,
                /*warmup=*/100, /*trials=*/5, /*iters=*/500,
                &generic_best, &simd_best);
            v.keccak_x4_regressed = bench_slot_regressed(simd_best, generic_best);
            v.keccak_x4_simd_ns    = simd_best;
            v.keccak_x4_generic_ns = generic_best;
        }

        /* ----- Slot 3: kyber_ntt (forward NTT) ------------------------ */
        if (dispatch_table.kyber_ntt != NULL) {
            int16_t poly[256];
            int16_t zetas_bench[128];
            for (int i = 0; i < 256; i++) poly[i] = (int16_t)((i * 37) & 0x7FF);
            for (int i = 0; i < 128; i++) zetas_bench[i] = (int16_t)((i * 91) & 0x7FF);

            int64_t generic_best = -1, simd_best = -1;
            dispatch_bench_kyber_ntt(
                ama_kyber_ntt_generic_ref, dispatch_table.kyber_ntt,
                poly, zetas_bench, &generic_best, &simd_best);
            v.kyber_ntt_regressed = bench_slot_regressed(simd_best, generic_best);
            v.kyber_ntt_simd_ns    = simd_best;
            v.kyber_ntt_generic_ns = generic_best;
        }

        /* ----- Slot 4: kyber_invntt (inverse NTT) --------------------- */
        if (dispatch_table.kyber_invntt != NULL) {
            int16_t poly[256];
            int16_t zetas_bench[128];
            for (int i = 0; i < 256; i++) poly[i] = (int16_t)((i * 53) & 0x7FF);
            for (int i = 0; i < 128; i++) zetas_bench[i] = (int16_t)((i * 67) & 0x7FF);

            int64_t generic_best = -1, simd_best = -1;
            dispatch_bench_kyber_ntt(
                ama_kyber_invntt_generic_ref, dispatch_table.kyber_invntt,
                poly, zetas_bench, &generic_best, &simd_best);
            v.kyber_invntt_regressed = bench_slot_regressed(simd_best, generic_best);
            v.kyber_invntt_simd_ns    = simd_best;
            v.kyber_invntt_generic_ns = generic_best;
        }

        /* ----- Slot 5: dilithium_ntt (forward NTT) -------------------- */
        if (dispatch_table.dilithium_ntt != NULL) {
            int32_t poly[256];
            int32_t zetas_bench[256];
            for (int i = 0; i < 256; i++) {
                poly[i]        = (int32_t)((i * 1337) & 0x7FFFFF);
                zetas_bench[i] = (int32_t)((i * 4093) & 0x7FFFFF);
            }

            int64_t generic_best = -1, simd_best = -1;
            dispatch_bench_dilithium_ntt(
                ama_dilithium_ntt_generic_ref, dispatch_table.dilithium_ntt,
                poly, zetas_bench, &generic_best, &simd_best);
            v.dilithium_ntt_regressed = bench_slot_regressed(simd_best, generic_best);
            v.dilithium_ntt_simd_ns    = simd_best;
            v.dilithium_ntt_generic_ns = generic_best;
        }

        /* ----- Slot 6: dilithium_invntt (inverse NTT) ----------------- */
        if (dispatch_table.dilithium_invntt != NULL) {
            int32_t poly[256];
            int32_t zetas_bench[256];
            for (int i = 0; i < 256; i++) {
                poly[i]        = (int32_t)((i * 5119) & 0x7FFFFF);
                zetas_bench[i] = (int32_t)((i * 7919) & 0x7FFFFF);
            }

            int64_t generic_best = -1, simd_best = -1;
            dispatch_bench_dilithium_ntt(
                ama_dilithium_invntt_generic_ref, dispatch_table.dilithium_invntt,
                poly, zetas_bench, &generic_best, &simd_best);
            v.dilithium_invntt_regressed = bench_slot_regressed(simd_best, generic_best);
            v.dilithium_invntt_simd_ns    = simd_best;
            v.dilithium_invntt_generic_ns = generic_best;
        }
    } /* end of bench block (cache miss + autotune enabled) */

    if (!autotune_disabled) {
        /* Apply per-slot verdicts.  Each block reverts at most one slot
         * group; the keccak group carries the carved-out lockstep tie
         * for sha3_256 / kyber_poly_{add,sub,reduce} described above. */
        if (v.keccak_regressed) {
            if (pre_sve2_keccak != dispatch_table.keccak_f1600) {
                dispatch_table.keccak_f1600 = pre_sve2_keccak;
            } else {
                dispatch_table.keccak_f1600 = ama_keccak_f1600_generic;
            }
            /* sha3_256 — SVE2 wrapper calls ama_keccak_f1600_sve2 directly */
            if (pre_sve2_sha3_256 != dispatch_table.sha3_256) {
                dispatch_table.sha3_256 = pre_sve2_sha3_256;
            }
            /* kyber_poly_{add,sub,reduce} — share the SVE2 codegen tier */
            if (pre_sve2_kyber_poly_add != dispatch_table.kyber_poly_add) {
                dispatch_table.kyber_poly_add = pre_sve2_kyber_poly_add;
            }
            if (pre_sve2_kyber_poly_sub != dispatch_table.kyber_poly_sub) {
                dispatch_table.kyber_poly_sub = pre_sve2_kyber_poly_sub;
            }
            if (pre_sve2_kyber_poly_reduce != dispatch_table.kyber_poly_reduce) {
                dispatch_table.kyber_poly_reduce = pre_sve2_kyber_poly_reduce;
            }
        }

        if (v.keccak_x4_regressed) {
            dispatch_table.keccak_f1600_x4 = ama_keccak_f1600_x4_generic;
        }

        if (v.kyber_ntt_regressed)        dispatch_table.kyber_ntt        = NULL;
        if (v.kyber_invntt_regressed)     dispatch_table.kyber_invntt     = NULL;
        if (v.dilithium_ntt_regressed)    dispatch_table.dilithium_ntt    = NULL;
        if (v.dilithium_invntt_regressed) dispatch_table.dilithium_invntt = NULL;

        if (dispatch_verbose()) {
            fprintf(stderr,
                "[AMA Dispatch] Auto-tune verdicts (regressed=1 reverted): "
                "keccak=%d (simd=%lld ns vs generic=%lld ns), "
                "keccak_x4=%d (simd=%lld ns vs generic=%lld ns), "
                "kyber_ntt=%d (simd=%lld ns vs generic=%lld ns), "
                "kyber_invntt=%d (simd=%lld ns vs generic=%lld ns), "
                "dilithium_ntt=%d (simd=%lld ns vs generic=%lld ns), "
                "dilithium_invntt=%d (simd=%lld ns vs generic=%lld ns)%s\n",
                v.keccak_regressed,        (long long)v.keccak_simd_ns,        (long long)v.keccak_generic_ns,
                v.keccak_x4_regressed,     (long long)v.keccak_x4_simd_ns,     (long long)v.keccak_x4_generic_ns,
                v.kyber_ntt_regressed,     (long long)v.kyber_ntt_simd_ns,     (long long)v.kyber_ntt_generic_ns,
                v.kyber_invntt_regressed,  (long long)v.kyber_invntt_simd_ns,  (long long)v.kyber_invntt_generic_ns,
                v.dilithium_ntt_regressed, (long long)v.dilithium_ntt_simd_ns, (long long)v.dilithium_ntt_generic_ns,
                v.dilithium_invntt_regressed, (long long)v.dilithium_invntt_simd_ns, (long long)v.dilithium_invntt_generic_ns,
                cache_hit ? " (from cache)" : "");
        }

        /* Save the verdict to the cache file (opt-in, miss-only).  Skip
         * on cache hit so a re-init doesn't keep rewriting the same
         * bytes; skip if AMA_DISPATCH_CACHE_FILE is unset (default
         * deployment writes no files); skip if any slot bench
         * disagrees with the cached entry — which can't happen on a
         * cache hit because the verdict came straight from the file. */
        if (!cache_hit && cache_path && cache_path[0]) {
            dispatch_cache_save(cache_path, fingerprint, &v);
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
        fprintf(stderr, "[AMA Dispatch] kyber_poly_* -> %s\n",
                (dispatch_table.kyber_poly_add &&
                 dispatch_table.kyber_poly_sub &&
                 dispatch_table.kyber_poly_reduce)
                    ? "SIMD (add/sub/reduce)"
                    : "scalar (compiler auto-vectorised)");
        fprintf(stderr, "[AMA Dispatch] dil_ntt      -> %s\n",
                dispatch_table.dilithium_ntt ? "SIMD" : "generic (inline)");
        fprintf(stderr, "[AMA Dispatch] chacha20_x8 -> %s\n",
                dispatch_table.chacha20_block_x8 ? "SIMD" : "scalar");
        fprintf(stderr, "[AMA Dispatch] argon2_g     -> %s\n",
                dispatch_table.argon2_g ? "SIMD" : "scalar");
        fprintf(stderr, "[AMA Dispatch] x25519_x4    -> %s\n",
                dispatch_table.x25519_x4 ? "SIMD (AVX2 4-way)" : "scalar (4× sequential)");
        fprintf(stderr, "[AMA Dispatch] ed25519      -> scalar (no SIMD wired; backend chosen at build time)\n");
    }

    /* AMA_DISPATCH_ONLY filtering (audit Issue 3 close-out).  Runs
     * AFTER the auto-tune verdict and BEFORE the test snapshot, so:
     *   - dudect sees the requested slot in isolation (every other
     *     SIMD kernel is back at scalar fallback).
     *   - the test snapshot below captures the post-filter state, so
     *     ama_test_force_*_scalar / ama_test_restore_* round-trip
     *     to the actually-active slot rather than to a pre-filter
     *     state the test process never observed. */
    {
        const char *only = getenv("AMA_DISPATCH_ONLY");
        if (only && only[0]) {
            /* Status-enum return + out-parameter for the resolved
             * label.  Lets the caller emit exactly one diagnostic
             * per outcome (Copilot review #323 round 2 follow-up):
             * HONORED       — verbose-gated info line only.
             * UNRECOGNISED  — one stderr ERROR with the slot inventory.
             * UNSUPPORTED   — one stderr ERROR naming the slot.
             * No outcome produces two stderr lines, satisfying the
             * "single clear error" contract in
             * include/ama_dispatch.h. */
            const char *resolved = NULL;
            apply_dispatch_only_result_t r = apply_dispatch_only(only, &resolved);
            switch (r) {
            case AMA_DISPATCH_ONLY_HONORED:
                dispatch_active_slot_label = resolved;
                if (dispatch_verbose())
                    fprintf(stderr,
                        "[AMA Dispatch] AMA_DISPATCH_ONLY='%s' honored — "
                        "every other slot is scalar fallback.\n", resolved);
                break;
            case AMA_DISPATCH_ONLY_UNRECOGNISED:
                fprintf(stderr,
                    "[AMA Dispatch] ERROR: AMA_DISPATCH_ONLY='%s' is not a "
                    "recognised slot on this build.  Known slots: "
                    "sha3-avx512x4, kyber-ntt-avx2, dilithium-ntt-avx2, "
                    "chacha20-avx2x8, argon2-g-avx2, aes-gcm-neon, "
                    "chacha20-neon, sha3-neon, kyber-sve2, sha3-sve2, "
                    "x25519-avx2.  Dispatch left at scalar fallback; "
                    "ama_dispatch_active_slot() will report "
                    "\"all-default-dispatch\".\n", only);
                break;
            case AMA_DISPATCH_ONLY_UNSUPPORTED:
                fprintf(stderr,
                    "[AMA Dispatch] ERROR: AMA_DISPATCH_ONLY='%s' is "
                    "recognised, but the required CPU feature is not "
                    "present on this host (or the build did not compile "
                    "the kernel).  Dispatch left at scalar fallback; "
                    "ama_dispatch_active_slot() will report "
                    "\"all-default-dispatch\".\n", only);
                break;
            }
        }
    }

#ifdef AMA_TESTING_MODE
    /* Snapshot post-init dispatch state for ama_test_restore_*_avx2().
     * Captures the actual choices the dispatcher made — including any
     * env-var opt-outs (AMA_DISPATCH_NO_*_AVX2 / AMA_DISPATCH_ONLY)
     * and the auto-tune verdict — so that "restore" returns to that
     * state rather than blindly re-enabling AVX2. */
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
void ama_test_force_x25519_x4_scalar(void);
void ama_test_force_aes_gcm_scalar(void);
void ama_test_force_keccak_f1600_scalar(void);
void ama_test_force_kyber_ntt_scalar(void);
void ama_test_force_dilithium_ntt_scalar(void);
void ama_test_restore_argon2_g_avx2(void);
void ama_test_restore_chacha20_block_x8_avx2(void);
void ama_test_restore_x25519_x4_avx2(void);
void ama_test_restore_aes_gcm(void);
void ama_test_restore_keccak_f1600(void);
void ama_test_restore_kyber_ntt(void);
void ama_test_restore_dilithium_ntt(void);

void ama_test_force_argon2_g_scalar(void) {
    ama_dispatch_init();
    dispatch_table.argon2_g = NULL;
}

void ama_test_force_chacha20_block_x8_scalar(void) {
    ama_dispatch_init();
    dispatch_table.chacha20_block_x8 = NULL;
}

void ama_test_force_x25519_x4_scalar(void) {
    ama_dispatch_init();
    dispatch_table.x25519_x4 = NULL;
}

/* Force the generic-C AES-GCM scalar reference (src/c/ama_aes_gcm.c)
 * by NULLing the dispatch slot.  When the public
 * ama_aes256_gcm_encrypt / ama_aes256_gcm_decrypt are called with the
 * slot NULL, the generic implementation in ama_aes_gcm.c runs inline
 * instead of forwarding to the SIMD kernel.  Used by
 * test_aes_gcm_neon_equiv.c and the VAES/AVX2 equivalence tests to
 * obtain a NON-DISPATCHED scalar ground truth, which is what makes
 * the byte-identity comparison meaningful — Copilot review
 * #3249188280.  Restore via ama_test_restore_aes_gcm(). */
void ama_test_force_aes_gcm_scalar(void) {
    ama_dispatch_init();
    dispatch_table.aes_gcm_encrypt = NULL;
    dispatch_table.aes_gcm_decrypt = NULL;
}

/* Force the generic-C Keccak-f[1600] scalar reference by reverting the
 * single-state pointer to ama_keccak_f1600_generic.  The x4 pointer
 * is kept on the (typically faster) installed kernel because the x4
 * scalar fallback simply invokes the single-state pointer 4 times —
 * NULLing the single-state pointer already routes the x4 call to the
 * generic path via the dispatch contract documented in
 * include/ama_dispatch.h. */
void ama_test_force_keccak_f1600_scalar(void) {
    ama_dispatch_init();
    dispatch_table.keccak_f1600 = ama_keccak_f1600_generic;
}

/* Force the generic-C Kyber NTT path by NULLing the SIMD pointers.
 * ama_kyber.c's NULL-check then dispatches to its inline scalar
 * NTT/inverse-NTT/pointwise implementations.  Also NULLs the
 * kyber_poly_{add,sub,reduce} slots: after this hook fires, the
 * scalar inline fallbacks inside `poly_add` / `poly_sub` /
 * `poly_reduce` are exercised end-to-end by every Kyber test that
 * subsequently runs, which is the production behaviour on any host
 * that lacks an SVE2 wiring for these slots.  Paired with
 * `ama_test_restore_kyber_ntt()` below. */
void ama_test_force_kyber_ntt_scalar(void) {
    ama_dispatch_init();
    dispatch_table.kyber_ntt = NULL;
    dispatch_table.kyber_invntt = NULL;
    dispatch_table.kyber_pointwise = NULL;
    dispatch_table.kyber_poly_add = NULL;
    dispatch_table.kyber_poly_sub = NULL;
    dispatch_table.kyber_poly_reduce = NULL;
}

/* Force the generic-C Dilithium NTT path by NULLing the SIMD
 * pointers.  ama_dilithium.c's NULL-check then dispatches to its
 * inline scalar NTT/inverse-NTT/pointwise implementations. */
void ama_test_force_dilithium_ntt_scalar(void) {
    ama_dispatch_init();
    dispatch_table.dilithium_ntt = NULL;
    dispatch_table.dilithium_invntt = NULL;
    dispatch_table.dilithium_pointwise = NULL;
}

void ama_test_force_x25519_x4_avx2(void);
void ama_test_force_x25519_x4_avx2(void) {
    /* Test-only: wires the AVX2 4-way kernel into the dispatch table
     * unconditionally so tests can verify the SIMD path even when
     * `AMA_DISPATCH_USE_X25519_AVX2` is not set in the environment.
     * Safe to call only when the host actually supports AVX2 — which
     * is what `dispatch_info.x25519 >= AMA_IMPL_AVX2` gates on.  No-op
     * on hosts without AVX2 (the kernel symbol still exists but
     * `ama_x25519_scalarmult_x4_avx2` would crash on a non-AVX2 CPU,
     * so the dispatch level guard is mandatory).
     *
     * On builds without `AMA_HAVE_AVX2_IMPL` (non-x86-64 hosts,
     * `-DAMA_ENABLE_AVX2=OFF`, MSVC builds where the AVX2 sources
     * aren't compiled in), the symbol `ama_x25519_scalarmult_x4_avx2`
     * is neither declared nor defined, so referencing it would fail
     * to compile.  Keep this hook available on every build as a
     * compile-clean no-op — non-AVX2 test binaries can still call
     * `ama_test_force_x25519_x4_scalar()` / restore counterparts
     * without conditional compilation at the call site. */
    ama_dispatch_init();
#ifdef AMA_HAVE_AVX2_IMPL
    if (dispatch_info.x25519 >= AMA_IMPL_AVX2)
        dispatch_table.x25519_x4 = ama_x25519_scalarmult_x4_avx2;
#endif
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

void ama_test_restore_x25519_x4_avx2(void) {
    ama_dispatch_init();
    dispatch_table.x25519_x4 = dispatch_table_post_init.x25519_x4;
}

/* Restore the post-init dispatch state for the families forced to
 * scalar by the new test hooks above.  Snapshot semantics mirror the
 * argon2 / chacha20 / x25519 restores: returns to the choices the
 * dispatcher actually made at init (respecting env opt-outs and the
 * auto-tune verdict). */
void ama_test_restore_aes_gcm(void) {
    ama_dispatch_init();
    dispatch_table.aes_gcm_encrypt = dispatch_table_post_init.aes_gcm_encrypt;
    dispatch_table.aes_gcm_decrypt = dispatch_table_post_init.aes_gcm_decrypt;
}

void ama_test_restore_keccak_f1600(void) {
    ama_dispatch_init();
    dispatch_table.keccak_f1600 = dispatch_table_post_init.keccak_f1600;
}

void ama_test_restore_kyber_ntt(void) {
    ama_dispatch_init();
    dispatch_table.kyber_ntt = dispatch_table_post_init.kyber_ntt;
    dispatch_table.kyber_invntt = dispatch_table_post_init.kyber_invntt;
    dispatch_table.kyber_pointwise = dispatch_table_post_init.kyber_pointwise;
    dispatch_table.kyber_poly_add = dispatch_table_post_init.kyber_poly_add;
    dispatch_table.kyber_poly_sub = dispatch_table_post_init.kyber_poly_sub;
    dispatch_table.kyber_poly_reduce = dispatch_table_post_init.kyber_poly_reduce;
}

void ama_test_restore_dilithium_ntt(void) {
    ama_dispatch_init();
    dispatch_table.dilithium_ntt = dispatch_table_post_init.dilithium_ntt;
    dispatch_table.dilithium_invntt = dispatch_table_post_init.dilithium_invntt;
    dispatch_table.dilithium_pointwise = dispatch_table_post_init.dilithium_pointwise;
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
    /* Annotate the X25519 4-way row when capability is detected but the
     * kernel pointer is NULL — i.e., the dispatcher saw AVX2+ but the
     * `AMA_DISPATCH_USE_X25519_AVX2=1` opt-in wasn't tripped, so the
     * batch path falls back to four sequential scalar ladders.  Without
     * this annotation an external reader sees "AVX2" here and concludes
     * the SIMD kernel is on, which is the obvious confused-bug-report
     * source. */
    {
        const char *x25519_label;
        char x25519_buf[24];
#ifdef AMA_HAVE_AVX2_IMPL
        /* On builds where the AVX2 4-way kernel TU was actually
         * compiled in, the `(opt-in, off)` suffix is meaningful: the
         * symbol exists, the dispatcher can wire it via
         * `AMA_DISPATCH_USE_X25519_AVX2=1`, and the user has a
         * concrete path to enable the kernel.  Annotate the row so
         * external readers don't conclude the SIMD path is on by
         * default (Copilot Review 2026-04 — the obvious
         * confused-bug-report source).  On non-AMA_HAVE_AVX2_IMPL
         * builds (-DAMA_ENABLE_AVX2=OFF, non-x86-64 hosts, MSVC
         * without the AVX2 sources), `dispatch_table.x25519_x4` is
         * also NULL, but for a different reason — the kernel TU was
         * never compiled — so the opt-in is not actually available
         * and the annotation would mislead the reader into thinking
         * a build-time-decided absence is a runtime-toggleable one.
         * Drop the suffix in that case (the bare `AMA_IMPL_GENERIC`
         * label `info->x25519` will hold matches reality: there's no
         * AVX2 kernel for X25519 in this binary, period). */
        if (info->x25519 >= AMA_IMPL_AVX2 && dispatch_table.x25519_x4 == NULL) {
            snprintf(x25519_buf, sizeof(x25519_buf), "%s (opt-in, off)",
                     ama_impl_level_name(info->x25519));
            x25519_label = x25519_buf;
        } else {
            x25519_label = ama_impl_level_name(info->x25519);
        }
#else
        (void)x25519_buf;
        x25519_label = ama_impl_level_name(info->x25519);
#endif
        fprintf(stderr, "║  X25519 4-way:       %-24s║\n", x25519_label);
    }
    fprintf(stderr, "╚══════════════════════════════════════════════╝\n");
    fprintf(stderr, "\n");
}

/* ============================================================================
 * AES-GCM backend introspection (audit Issue 5 / INVARIANT-20)
 *
 * Identifies which AES-GCM kernel the runtime dispatcher actually
 * selected on the current host.  Recognition order matches the
 * dispatch_init_internal() selection order above:
 *
 *   1. VAES + VPCLMULQDQ YMM kernel  -> "vaes-avx2"
 *   2. AVX2 AES-NI + PCLMULQDQ       -> "aes-ni-pclmul"
 *   3. NEON + ARMv8 crypto AES+PMULL -> "arm-aes-pmull"
 *   4. compile-time bitsliced S-box  -> "bitsliced-software"
 *   5. compile-time table S-box      -> "table-insecure"
 *
 * 4 and 5 are mutually exclusive at compile time: AMA_AES_CONSTTIME
 * gates ama_aes_bitsliced.c into the build via CMakeLists.txt, and
 * the macro is checked in ama_aes_gcm.c::aes256_encrypt_block.  The
 * runtime check below derives the active path from the dispatcher's
 * function pointers when SIMD is wired in; otherwise it returns the
 * compile-time selection.
 *
 * The kernel pointer comparisons cross translation units, so the
 * compared symbol must have external linkage with the same name on
 * both sides — which it does (these are declared `extern` near the
 * top of this TU and defined as global functions in the AVX2 / NEON
 * source files).  No type-punning / dlsym is required. ============= */
const char *ama_aes_gcm_active_backend(void) {
    ama_dispatch_init();
#ifdef AMA_HAVE_AVX2_IMPL
#if !defined(_MSC_VER)
    if (dispatch_table.aes_gcm_encrypt == ama_aes256_gcm_encrypt_vaes_avx2)
        return "vaes-avx2";
#endif
    if (dispatch_table.aes_gcm_encrypt == ama_aes256_gcm_encrypt_avx2)
        return "aes-ni-pclmul";
#endif
#ifdef AMA_HAVE_NEON_IMPL
    if (dispatch_table.aes_gcm_encrypt == ama_aes256_gcm_encrypt_neon)
        return "arm-aes-pmull";
#endif
    /* Compile-time S-box selection — the SIMD dispatch table left
     * aes_gcm_encrypt at NULL because no hardware AES kernel was
     * detected, so the generic schoolbook GHASH + S-box path will
     * run.  Which S-box flavour that is, is fixed at compile time. */
#ifdef AMA_AES_CONSTTIME
    return "bitsliced-software";
#else
    /* INVARIANT-20: this path is only reachable when the build was
     * explicitly opted in via -DAMA_AES_TABLE_INSECURE=ON; the CMake
     * guardrail above fails configuration otherwise.  The returned
     * label is intentionally loud so an integration test that just
     * does `assert(strcmp(backend, "table-insecure") != 0)` will
     * catch a regression. */
    return "table-insecure";
#endif
}

/* ============================================================================
 * AMA_DISPATCH_ONLY introspection (audit Issue 3 close-out)
 *
 * Returns the slot label honored by `AMA_DISPATCH_ONLY=<slot>` at
 * init time, or `"all-default-dispatch"` if the env var was unset
 * OR set to a slot this host could not satisfy.  See the header
 * comment in include/ama_dispatch.h for the full slot inventory.
 * ============================================================================ */
const char *ama_dispatch_active_slot(void) {
    ama_dispatch_init();
    return dispatch_active_slot_label;
}
