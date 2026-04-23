/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 */

/**
 * @file ama_cpuid.c
 * @brief CPU feature detection and AEAD runtime dispatch
 * @author Andrew E. A., Steel Security Advisors LLC
 *
 * Implements CPU feature detection for selecting the optimal AEAD backend:
 * - x86: CPUID leaf 1 for AES-NI (ECX[25]) and PCLMULQDQ (ECX[1])
 * - ARM: getauxval(AT_HWCAP) on Linux, sysctlbyname on macOS
 *
 * Thread safety (INVARIANT-15):
 *   All one-time initialization is performed via a platform once-primitive
 *   (pthread_once on POSIX, InitOnceExecuteOnce on Windows).  No lockless
 *   flag + plain-variable patterns are used.  See .github/INVARIANTS.md.
 *
 * AI Co-Architects: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
 */

#include "../include/ama_cpuid.h"
#include <stdio.h>

/* ============================================================================
 * Platform once-primitive abstraction (INVARIANT-15)
 *
 * C11 <threads.h> (call_once) is NOT reliably available:
 *   - macOS: Apple SDK has never shipped <threads.h>
 *   - MSVC: <threads.h> was only partially shipped starting VS 17.8 and
 *           remains buggy in several versions
 *   - Linux glibc: available since glibc 2.28, but not universal
 *
 * Instead we use the platform-native once-primitives that are guaranteed
 * available on every CI target:
 *   - POSIX (Linux, macOS): pthread_once  (IEEE Std 1003.1)
 *   - Windows (MSVC):       InitOnceExecuteOnce  (Vista+, synchapi.h)
 * ============================================================================ */

#if defined(_MSC_VER)
    /* Windows: InitOnceExecuteOnce (available since Vista / Server 2008) */
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>

    #define AMA_ONCE_FLAG          INIT_ONCE
    #define AMA_ONCE_FLAG_INIT     INIT_ONCE_STATIC_INIT

    typedef void (*ama_once_fn)(void);

    static BOOL CALLBACK ama_once_trampoline(PINIT_ONCE once, PVOID param, PVOID *ctx) {
        (void)once; (void)ctx;
        ((ama_once_fn)param)();
        return TRUE;
    }

    #define AMA_CALL_ONCE(flag, fn) \
        InitOnceExecuteOnce(&(flag), ama_once_trampoline, (PVOID)(fn), NULL)

#else
    /* POSIX (Linux, macOS, BSDs): pthread_once */
    #include <pthread.h>

    #define AMA_ONCE_FLAG          pthread_once_t
    #define AMA_ONCE_FLAG_INIT     PTHREAD_ONCE_INIT

    #define AMA_CALL_ONCE(flag, fn) \
        pthread_once(&(flag), (fn))

#endif

/* ============================================================================
 * x86 CPUID Detection
 * ============================================================================ */

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif

static AMA_ONCE_FLAG cpuid_once = AMA_ONCE_FLAG_INIT;
static int has_aes_ni_cached = 0;
static int has_pclmulqdq_cached = 0;
static int has_avx2_cached = 0;
static int has_avx512f_cached = 0;
/* AVX-512 bundle cache (PR A — VAES / VPCLMULQDQ dispatch, 2026-04).
 * Each field is populated by detect_x86_features() behind the same
 * pthread_once / InitOnceExecuteOnce gate as the legacy fields above,
 * so INVARIANT-15 applies unchanged. */
static int has_avx512vl_cached = 0;
static int has_vaes_cached = 0;
static int has_vpclmulqdq_cached = 0;
static int has_avx512_osxsave_cached = 0;

/* Read XCR0 via XGETBV to confirm the OS has enabled SSE/AVX/AVX-512
 * save state.  Required before dispatching to any AVX-512 kernel: a
 * guest VM can legitimately expose the CPUID bits without enabling
 * XCR0 bits 5, 6, 7 (opmask, ZMM_Hi256, Hi16_ZMM), in which case any
 * ZMM / K-register instruction would raise #UD.  CPUID.(EAX=1):ECX[27]
 * gates whether XGETBV itself is safe to issue. */
static int xcr0_has_avx512_state(void) {
#ifdef _MSC_VER
    /* _xgetbv(0) returns XCR0 */
    unsigned long long xcr0 = _xgetbv(0);
#else
    unsigned int eax_xcr, edx_xcr;
    __asm__ volatile (".byte 0x0f, 0x01, 0xd0"
                      : "=a"(eax_xcr), "=d"(edx_xcr)
                      : "c"(0));
    unsigned long long xcr0 =
        ((unsigned long long)edx_xcr << 32) | (unsigned long long)eax_xcr;
#endif
    /* Bit 1 = SSE, bit 2 = AVX (YMM), bits 5/6/7 = AVX-512 opmask / ZMM_Hi256 / Hi16_ZMM. */
    const unsigned long long avx_bits    = (1ULL << 1) | (1ULL << 2);
    const unsigned long long avx512_bits = (1ULL << 5) | (1ULL << 6) | (1ULL << 7);
    return ((xcr0 & avx_bits) == avx_bits) && ((xcr0 & avx512_bits) == avx512_bits);
}

static void detect_x86_features(void) {
#ifdef _MSC_VER
    int info[4];
    __cpuid(info, 1);
    has_aes_ni_cached = (info[2] >> 25) & 1;
    has_pclmulqdq_cached = (info[2] >> 1) & 1;
    int osxsave = (info[2] >> 27) & 1;
    /* Leaf 7, sub-leaf 0: AVX2 (EBX[5]) and AVX-512F (EBX[16]) */
    __cpuidex(info, 7, 0);
    has_avx2_cached       = (info[1] >> 5)  & 1;
    has_avx512f_cached    = (info[1] >> 16) & 1;
    has_avx512vl_cached   = (info[1] >> 31) & 1;
    has_vaes_cached       = (info[2] >> 9)  & 1;
    has_vpclmulqdq_cached = (info[2] >> 10) & 1;
    has_avx512_osxsave_cached = osxsave ? xcr0_has_avx512_state() : 0;
#else
    unsigned int eax, ebx, ecx, edx;
    int osxsave = 0;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        has_aes_ni_cached    = (ecx >> 25) & 1;
        has_pclmulqdq_cached = (ecx >> 1)  & 1;
        osxsave              = (ecx >> 27) & 1;
    }
    /* CPUID leaf 7, sub-leaf 0:
     *   EBX bit 5  — AVX2
     *   EBX bit 16 — AVX-512F
     *   EBX bit 31 — AVX-512VL
     *   ECX bit 9  — VAES
     *   ECX bit 10 — VPCLMULQDQ
     * Only read XCR0 when OSXSAVE is set; otherwise XGETBV #UDs. */
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        has_avx2_cached       = (ebx >> 5)  & 1;
        has_avx512f_cached    = (ebx >> 16) & 1;
        has_avx512vl_cached   = (ebx >> 31) & 1;
        has_vaes_cached       = (ecx >> 9)  & 1;
        has_vpclmulqdq_cached = (ecx >> 10) & 1;
    }
    has_avx512_osxsave_cached = osxsave ? xcr0_has_avx512_state() : 0;
#endif
}

int ama_has_aes_ni(void) {
    AMA_CALL_ONCE(cpuid_once, detect_x86_features);
    return has_aes_ni_cached;
}

int ama_has_pclmulqdq(void) {
    AMA_CALL_ONCE(cpuid_once, detect_x86_features);
    return has_pclmulqdq_cached;
}

int ama_has_avx2(void) {
    AMA_CALL_ONCE(cpuid_once, detect_x86_features);
    return has_avx2_cached;
}

int ama_has_avx512f(void) {
    AMA_CALL_ONCE(cpuid_once, detect_x86_features);
    /* AVX-512F is only *usable* when XCR0 also enables the opmask and
     * ZMM state.  Returning the CPUID bit alone would let the
     * dispatcher select an AVX-512 kernel inside a VM that has the
     * bit but no OS save-area — the first AVX-512 instruction then
     * #UDs.  The XCR0 gate is the same guard the Linux kernel uses
     * (arch/x86/kernel/fpu/xstate.c). */
    return has_avx512f_cached && has_avx512_osxsave_cached;
}

int ama_has_avx512vl(void) {
    AMA_CALL_ONCE(cpuid_once, detect_x86_features);
    return has_avx512vl_cached && has_avx512_osxsave_cached;
}

int ama_has_vaes(void) {
    AMA_CALL_ONCE(cpuid_once, detect_x86_features);
    /* VAES on YMM is usable with just AVX-enabled XCR0, but every path
     * that currently calls VAES is entered via the AVX-512 bundle
     * below, which already gates on AVX-512 XCR0 state.  Keep the
     * check strict here to avoid a foot-gun: a caller that reads
     * ama_has_vaes() alone would otherwise get "yes" on an AVX2-only
     * host (there are none in the wild, but be defensive). */
    return has_vaes_cached && has_avx512_osxsave_cached;
}

int ama_has_vpclmulqdq(void) {
    AMA_CALL_ONCE(cpuid_once, detect_x86_features);
    return has_vpclmulqdq_cached && has_avx512_osxsave_cached;
}

int ama_cpuid_has_avx512_aesgcm_bundle(void) {
    /* Intentionally re-enters each cached getter: they all share
     * pthread_once so the probe runs exactly once, and the compiler
     * will fold the tail into a single AND. */
    return ama_has_avx512f()
        && ama_has_avx512vl()
        && ama_has_vaes()
        && ama_has_vpclmulqdq()
        && ama_has_aes_ni();
}

int ama_cpuid_has_avx512_keccak(void) {
    return ama_has_avx512f();
}

int ama_has_arm_aes(void) { return 0; }
int ama_has_arm_pmull(void) { return 0; }
int ama_has_arm_neon(void) { return 0; }
int ama_has_arm_sve2(void) { return 0; }

/* ============================================================================
 * ARM Crypto Extension Detection
 * ============================================================================ */

#elif defined(__aarch64__) || defined(_M_ARM64)

static AMA_ONCE_FLAG arm_once = AMA_ONCE_FLAG_INIT;
static int has_arm_aes_cached = 0;
static int has_arm_pmull_cached = 0;
static int has_arm_neon_cached = 0;
static int has_arm_sve2_cached = 0;

#if defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#ifndef HWCAP_PMULL
#define HWCAP_PMULL (1 << 4)
#endif
#ifndef AT_HWCAP2
#define AT_HWCAP2 26
#endif
#ifndef HWCAP2_SVE2
#define HWCAP2_SVE2 (1 << 1)
#endif

static void detect_arm_features(void) {
    unsigned long hwcap = getauxval(AT_HWCAP);
    has_arm_aes_cached = (hwcap & HWCAP_AES) ? 1 : 0;
    has_arm_pmull_cached = (hwcap & HWCAP_PMULL) ? 1 : 0;
    /* NEON is mandatory on AArch64 */
    has_arm_neon_cached = 1;
    /* SVE2 detection via AT_HWCAP2 */
    unsigned long hwcap2 = getauxval(AT_HWCAP2);
    has_arm_sve2_cached = (hwcap2 & HWCAP2_SVE2) ? 1 : 0;
}

#elif defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>

static void detect_arm_features(void) {
    /* Apple Silicon (M1+) always has AES, PMULL, and NEON */
    int val = 0;
    size_t len = sizeof(val);
    if (sysctlbyname("hw.optional.arm.FEAT_AES", &val, &len, NULL, 0) == 0) {
        has_arm_aes_cached = val;
    } else {
        has_arm_aes_cached = 1;
    }
    val = 0;
    len = sizeof(val);
    if (sysctlbyname("hw.optional.arm.FEAT_PMULL", &val, &len, NULL, 0) == 0) {
        has_arm_pmull_cached = val;
    } else {
        has_arm_pmull_cached = 1;
    }
    has_arm_neon_cached = 1;
    /* Apple Silicon does not support SVE2 as of M4 */
    has_arm_sve2_cached = 0;
}

#else
static void detect_arm_features(void) {
    has_arm_aes_cached = 0;
    has_arm_pmull_cached = 0;
    has_arm_neon_cached = 0;
    has_arm_sve2_cached = 0;
}
#endif

int ama_has_aes_ni(void) { return 0; }
int ama_has_pclmulqdq(void) { return 0; }
int ama_has_avx2(void) { return 0; }
int ama_has_avx512f(void) { return 0; }
int ama_has_avx512vl(void) { return 0; }
int ama_has_vaes(void) { return 0; }
int ama_has_vpclmulqdq(void) { return 0; }
int ama_cpuid_has_avx512_aesgcm_bundle(void) { return 0; }
int ama_cpuid_has_avx512_keccak(void) { return 0; }

int ama_has_arm_aes(void) {
    AMA_CALL_ONCE(arm_once, detect_arm_features);
    return has_arm_aes_cached;
}

int ama_has_arm_pmull(void) {
    AMA_CALL_ONCE(arm_once, detect_arm_features);
    return has_arm_pmull_cached;
}

int ama_has_arm_neon(void) {
    AMA_CALL_ONCE(arm_once, detect_arm_features);
    return has_arm_neon_cached;
}

int ama_has_arm_sve2(void) {
    AMA_CALL_ONCE(arm_once, detect_arm_features);
    return has_arm_sve2_cached;
}

/* ============================================================================
 * Unsupported architecture — no hardware crypto
 * ============================================================================ */

#else

int ama_has_aes_ni(void) { return 0; }
int ama_has_pclmulqdq(void) { return 0; }
int ama_has_avx2(void) { return 0; }
int ama_has_avx512f(void) { return 0; }
int ama_has_avx512vl(void) { return 0; }
int ama_has_vaes(void) { return 0; }
int ama_has_vpclmulqdq(void) { return 0; }
int ama_cpuid_has_avx512_aesgcm_bundle(void) { return 0; }
int ama_cpuid_has_avx512_keccak(void) { return 0; }
int ama_has_arm_aes(void) { return 0; }
int ama_has_arm_pmull(void) { return 0; }
int ama_has_arm_neon(void) { return 0; }
int ama_has_arm_sve2(void) { return 0; }

#endif

/* ============================================================================
 * AEAD Backend Selection (Runtime Dispatch)
 *
 * Thread safety: ama_select_aead_init() runs exactly once via the platform
 * once-primitive.  All shared state (selected_backend) is written inside the
 * init function and is fully visible to every thread after the once-call
 * returns — guaranteed by the memory ordering semantics of pthread_once /
 * InitOnceExecuteOnce.
 * ============================================================================ */

static AMA_ONCE_FLAG dispatch_once = AMA_ONCE_FLAG_INIT;
static ama_aead_backend_t selected_backend = AMA_AEAD_CHACHA20_POLY1305;

static void ama_select_aead_init(void) {
    if ((ama_has_aes_ni() && ama_has_pclmulqdq()) ||
        (ama_has_arm_aes() && ama_has_arm_pmull())) {
        selected_backend = AMA_AEAD_HW_AES_GCM;
    } else {
        /* No hardware AES — use ChaCha20-Poly1305 (constant-time by design).
         * Never use software table-based AES-GCM on secret data at runtime. */
        selected_backend = AMA_AEAD_CHACHA20_POLY1305;
    }

    /* Log selection once */
    fprintf(stderr, "[AMA Cryptography] AEAD backend selected: %s (AES-NI=%d, PCLMULQDQ=%d, ARM-AES=%d, ARM-PMULL=%d)\n",
            ama_aead_backend_name(selected_backend),
            ama_has_aes_ni(), ama_has_pclmulqdq(),
            ama_has_arm_aes(), ama_has_arm_pmull());
}

ama_aead_backend_t ama_select_aead(void) {
    AMA_CALL_ONCE(dispatch_once, ama_select_aead_init);
    return selected_backend;
}

const char *ama_aead_backend_name(ama_aead_backend_t backend) {
    switch (backend) {
        case AMA_AEAD_HW_AES_GCM:
            return "Hardware AES-256-GCM (AES-NI/ARMv8-CE)";
        case AMA_AEAD_CHACHA20_POLY1305:
            return "ChaCha20-Poly1305 (constant-time)";
        case AMA_AEAD_SW_AES_GCM:
            return "Software AES-256-GCM (bitsliced constant-time)";
        default:
            return "Unknown";
    }
}
