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
 * All detection results are cached after first invocation using atomic
 * flag variables to prevent data races in multithreaded use.
 * The dispatch function ama_select_aead() logs the selection once at init.
 *
 * AI Co-Architects: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
 */

#include "../include/ama_cpuid.h"
#include <stdio.h>

/*
 * Thread-safety: We use C11 stdatomic where available, falling back to
 * compiler intrinsics on MSVC. The cached values themselves are written
 * before the flag is set (release), and read after the flag is checked
 * (acquire), establishing a happens-before relationship.
 */
#if !defined(_MSC_VER) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L \
    && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#define AMA_ATOMIC_INT  _Atomic int
#define AMA_ATOMIC_LOAD(p) atomic_load_explicit(&(p), memory_order_acquire)
#define AMA_ATOMIC_STORE(p, v) atomic_store_explicit(&(p), (v), memory_order_release)
#elif defined(_MSC_VER)
#include <intrin.h>
#define AMA_ATOMIC_INT  volatile long
#define AMA_ATOMIC_LOAD(p) _InterlockedCompareExchange(&(p), 0, 0)
#define AMA_ATOMIC_STORE(p, v) _InterlockedExchange(&(p), (v))
#else
/* Best-effort fallback: volatile prevents caching in registers */
#define AMA_ATOMIC_INT  volatile int
#define AMA_ATOMIC_LOAD(p) (p)
#define AMA_ATOMIC_STORE(p, v) ((p) = (v))
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

static AMA_ATOMIC_INT cpuid_detected = 0;
static int has_aes_ni_cached = 0;
static int has_pclmulqdq_cached = 0;

static void detect_x86_features(void) {
    if (AMA_ATOMIC_LOAD(cpuid_detected)) return;

    /* Cached values are set before the flag — benign if two threads
     * both execute this block (idempotent CPUID reads). */
#ifdef _MSC_VER
    int info[4];
    __cpuid(info, 1);
    has_aes_ni_cached = (info[2] >> 25) & 1;
    has_pclmulqdq_cached = (info[2] >> 1) & 1;
#else
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        has_aes_ni_cached = (ecx >> 25) & 1;
        has_pclmulqdq_cached = (ecx >> 1) & 1;
    }
#endif
    AMA_ATOMIC_STORE(cpuid_detected, 1);
}

int ama_has_aes_ni(void) {
    detect_x86_features();
    return has_aes_ni_cached;
}

int ama_has_pclmulqdq(void) {
    detect_x86_features();
    return has_pclmulqdq_cached;
}

int ama_has_arm_aes(void) { return 0; }
int ama_has_arm_pmull(void) { return 0; }

/* ============================================================================
 * ARM Crypto Extension Detection
 * ============================================================================ */

#elif defined(__aarch64__) || defined(_M_ARM64)

static AMA_ATOMIC_INT arm_detected = 0;
static int has_arm_aes_cached = 0;
static int has_arm_pmull_cached = 0;

#if defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#ifndef HWCAP_PMULL
#define HWCAP_PMULL (1 << 4)
#endif

static void detect_arm_features(void) {
    if (AMA_ATOMIC_LOAD(arm_detected)) return;
    unsigned long hwcap = getauxval(AT_HWCAP);
    has_arm_aes_cached = (hwcap & HWCAP_AES) ? 1 : 0;
    has_arm_pmull_cached = (hwcap & HWCAP_PMULL) ? 1 : 0;
    AMA_ATOMIC_STORE(arm_detected, 1);
}

#elif defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>

static void detect_arm_features(void) {
    if (AMA_ATOMIC_LOAD(arm_detected)) return;
    /* Apple Silicon (M1+) always has AES and PMULL */
    int val = 0;
    size_t len = sizeof(val);
    if (sysctlbyname("hw.optional.arm.FEAT_AES", &val, &len, NULL, 0) == 0) {
        has_arm_aes_cached = val;
    } else {
        /* Apple Silicon fallback: assume available */
        has_arm_aes_cached = 1;
    }
    val = 0;
    len = sizeof(val);
    if (sysctlbyname("hw.optional.arm.FEAT_PMULL", &val, &len, NULL, 0) == 0) {
        has_arm_pmull_cached = val;
    } else {
        has_arm_pmull_cached = 1;
    }
    AMA_ATOMIC_STORE(arm_detected, 1);
}

#else
static void detect_arm_features(void) {
    if (AMA_ATOMIC_LOAD(arm_detected)) return;
    has_arm_aes_cached = 0;
    has_arm_pmull_cached = 0;
    AMA_ATOMIC_STORE(arm_detected, 1);
}
#endif

int ama_has_aes_ni(void) { return 0; }
int ama_has_pclmulqdq(void) { return 0; }

int ama_has_arm_aes(void) {
    detect_arm_features();
    return has_arm_aes_cached;
}

int ama_has_arm_pmull(void) {
    detect_arm_features();
    return has_arm_pmull_cached;
}

/* ============================================================================
 * Unsupported architecture — no hardware crypto
 * ============================================================================ */

#else

int ama_has_aes_ni(void) { return 0; }
int ama_has_pclmulqdq(void) { return 0; }
int ama_has_arm_aes(void) { return 0; }
int ama_has_arm_pmull(void) { return 0; }

#endif

/* ============================================================================
 * AEAD Backend Selection (Runtime Dispatch)
 * ============================================================================ */

static AMA_ATOMIC_INT dispatch_done = 0;
static AMA_ATOMIC_INT dispatch_running = 0;
static ama_aead_backend_t selected_backend = AMA_AEAD_CHACHA20_POLY1305;

ama_aead_backend_t ama_select_aead(void) {
    /* Fast path: already dispatched */
    if (AMA_ATOMIC_LOAD(dispatch_done)) return selected_backend;

    /* Acquire: only one thread performs detection.
     * Others spin on dispatch_done until the winner finishes. */
    while (1) {
        int expected = 0;
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
        if (atomic_compare_exchange_strong_explicit(
                &dispatch_running, &expected, 1,
                memory_order_acq_rel, memory_order_relaxed))
            break;  /* We won the race — proceed with detection */
#elif defined(_MSC_VER)
        if (_InterlockedCompareExchange(&dispatch_running, 1, 0) == 0)
            break;
#else
        /* Fallback: non-atomic — acceptable on single-threaded builds */
        if (!dispatch_running) { dispatch_running = 1; break; }
#endif
        /* Another thread is detecting — wait for it */
        if (AMA_ATOMIC_LOAD(dispatch_done)) return selected_backend;
    }

    /* Double-check after acquiring */
    if (AMA_ATOMIC_LOAD(dispatch_done)) return selected_backend;

    ama_aead_backend_t backend;
    if ((ama_has_aes_ni() && ama_has_pclmulqdq()) ||
        (ama_has_arm_aes() && ama_has_arm_pmull())) {
        backend = AMA_AEAD_HW_AES_GCM;
    } else {
        /* No hardware AES — use ChaCha20-Poly1305 (constant-time by design).
         * Never use software table-based AES-GCM on secret data at runtime. */
        backend = AMA_AEAD_CHACHA20_POLY1305;
    }

    /* Write to shared state BEFORE publishing dispatch_done */
    selected_backend = backend;

    /* Log selection once */
    fprintf(stderr, "[AMA Cryptography] AEAD backend selected: %s (AES-NI=%d, PCLMULQDQ=%d, ARM-AES=%d, ARM-PMULL=%d)\n",
            ama_aead_backend_name(backend),
            ama_has_aes_ni(), ama_has_pclmulqdq(),
            ama_has_arm_aes(), ama_has_arm_pmull());

    /* Release fence: all prior writes (selected_backend) visible before done=1 */
    AMA_ATOMIC_STORE(dispatch_done, 1);
    return backend;
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
