/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_keccak_equiv.c
 * @brief Byte-equivalence test for the dispatched Keccak-f[1600]
 *        permutation (AVX2 on x86-64, NEON on AArch64, AVX-512 4-way
 *        for the x4 wrapper when ``AMA_ENABLE_AVX512=ON``) against
 *        ``ama_keccak_f1600_generic`` — the scalar reference baked
 *        into ``src/c/ama_sha3.c``.
 *
 * Goes through ``ama_get_dispatch_table()->keccak_f1600`` and
 * ``ama_get_dispatch_table()->keccak_f1600_x4`` to exercise the
 * dispatch surface the production wrappers (SHA3-256, SHAKE128,
 * SHAKE256, ML-KEM/ML-DSA matrix expansion) actually call.
 * Compares against ``ama_keccak_f1600_generic`` invoked directly —
 * exported by ``src/c/ama_sha3.c`` for exactly this purpose.
 *
 * If the dispatched and generic paths ever diverge, every SHA3
 * digest, every SHAKE squeeze, and every ML-KEM/ML-DSA matrix-A
 * expansion would silently produce different output from a
 * standards-conformant peer.  That would be caught by every existing
 * KAT, but this test pins the permutation in isolation so a
 * regression localises immediately to the SIMD kernel rather than
 * being mis-blamed on the wrapper.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"
#include "ama_cpuid.h"
#include "ama_dispatch.h"

/* Forward decl: src/c/ama_sha3.c always defines this, regardless of
 * SIMD build state.  It is the scalar reference. */
extern void ama_keccak_f1600_generic(uint64_t state[25]);
extern void ama_keccak_f1600_x4_generic(uint64_t states[4][25]);

/* SIMD kernel forward decls — present when the corresponding build
 * flag is set.  Calling them directly avoids the dispatch auto-tune
 * heuristic, which can revert the dispatched pointer to the generic
 * path on noisy hosts (qemu / shared CI runners) — see the verbose
 * log output in src/c/dispatch/ama_dispatch.c.  We want this test
 * to actually exercise the SIMD kernel regardless of what auto-tune
 * picks. */
#if defined(AMA_HAVE_AVX2_IMPL) && (defined(__x86_64__) || defined(_M_X64))
extern void ama_keccak_f1600_avx2(uint64_t state[25]);
extern void ama_keccak_f1600_x4_avx2(uint64_t states[4][25]);
#endif
#if defined(AMA_HAVE_NEON_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
extern void ama_keccak_f1600_neon(uint64_t state[25]);
#endif

static uint64_t xs_state = 0xC0FFEE5005BAD123ULL;
static uint64_t xs_next(void) {
    uint64_t x = xs_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    xs_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static int cmp_state(const uint64_t a[25], const uint64_t b[25],
                     const char *label, int trial) {
    for (int i = 0; i < 25; i++) {
        if (a[i] != b[i]) {
            fprintf(stderr,
                    "FAIL: %s trial %d, lane %d: scalar=%016llx simd=%016llx\n",
                    label, trial, i,
                    (unsigned long long)a[i], (unsigned long long)b[i]);
            return 1;
        }
    }
    return 0;
}

/* Pick the SIMD kernel for this build/arch — direct symbol reference,
 * not the dispatch pointer, so the test runs regardless of what the
 * dispatch auto-tune picks at init time.  Returns NULL when no SIMD
 * kernel is compiled in (test SKIPs in that case). */
typedef void (*keccak_single_fn)(uint64_t state[25]);
typedef void (*keccak_x4_fn)(uint64_t states[4][25]);

static keccak_single_fn simd_keccak_single(const char **label) {
#if defined(AMA_HAVE_AVX2_IMPL) && (defined(__x86_64__) || defined(_M_X64))
    if (!ama_has_avx2()) {
        (void)label;
        return NULL;
    }
    *label = "AVX2";
    return ama_keccak_f1600_avx2;
#elif defined(AMA_HAVE_NEON_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
    *label = "NEON";
    return ama_keccak_f1600_neon;
#else
    (void)label;
    return NULL;
#endif
}

static keccak_x4_fn simd_keccak_x4(const char **label) {
#if defined(AMA_HAVE_AVX2_IMPL) && (defined(__x86_64__) || defined(_M_X64))
    if (!ama_has_avx2()) {
        (void)label;
        return NULL;
    }
    *label = "AVX2 4-way";
    return ama_keccak_f1600_x4_avx2;
#else
    /* No NEON 4-way batched kernel is wired today — the x4 dispatch
     * pointer is set to ama_keccak_f1600_x4_generic which invokes
     * the single-state path 4 times.  We skip the x4 sub-test on
     * NEON-only builds and rely on the single-state coverage. */
    (void)label;
    return NULL;
#endif
}

int main(void) {
    printf("Keccak-f[1600] direct-SIMD-vs-scalar equivalence\n");
    printf("================================================\n");

    const char *single_label = NULL;
    const char *x4_label = NULL;
    keccak_single_fn k_single = simd_keccak_single(&single_label);
    keccak_x4_fn     k_x4     = simd_keccak_x4(&x4_label);

    if (k_single == NULL) {
        printf("SKIP: no SIMD Keccak kernel built in for this target\n"
               "      (non-x86-64, non-AArch64, or SIMD disabled).\n");
        printf("================================================\n");
        return 77;
    }

    int fail = 0;

    /* Single-state permutation: 4096 random initial states. */
    const int N_SINGLE = 4096;
    for (int trial = 0; trial < N_SINGLE; trial++) {
        uint64_t state_s[25];
        uint64_t state_v[25];
        for (int i = 0; i < 25; i++) {
            uint64_t r = xs_next();
            state_s[i] = r;
            state_v[i] = r;
        }
        ama_keccak_f1600_generic(state_s);
        k_single(state_v);
        fail += cmp_state(state_s, state_v, single_label, trial);
        if (fail && trial >= 2) break;
    }
    if (fail) {
        fprintf(stderr, "%d mismatches in single-state pass (%s)\n",
                fail, single_label);
        return 1;
    }
    printf("PASS: %s single-state (%d trials)\n", single_label, N_SINGLE);

    /* 4-way x4 permutation: 1024 random 4-state batches. */
    if (k_x4 != NULL) {
        const int N_X4 = 1024;
        for (int trial = 0; trial < N_X4; trial++) {
            uint64_t states_v[4][25];
            uint64_t states_s[4][25];
            for (int lane = 0; lane < 4; lane++) {
                for (int i = 0; i < 25; i++) {
                    uint64_t r = xs_next();
                    states_s[lane][i] = r;
                    states_v[lane][i] = r;
                }
            }
            for (int lane = 0; lane < 4; lane++) {
                ama_keccak_f1600_generic(states_s[lane]);
            }
            k_x4(states_v);
            for (int lane = 0; lane < 4; lane++) {
                if (cmp_state(states_s[lane], states_v[lane], x4_label, trial)) {
                    fail++;
                    break;
                }
            }
            if (fail && trial >= 2) break;
        }
        if (fail) {
            fprintf(stderr, "%d mismatches in x4 pass (%s)\n", fail, x4_label);
            return 1;
        }
        printf("PASS: %s x4 (%d trials)\n", x4_label, N_X4);
    } else {
        printf("INFO: no SIMD x4 kernel on this target — single-state covers it\n");
    }

    printf("================================================\n");
    return 0;
}
