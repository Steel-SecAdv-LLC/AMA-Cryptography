/* POSIX feature test macro — must precede all #includes.
 * 200809L (POSIX.1-2008) covers clock_gettime, gmtime_r, ctime_r.
 * The earlier 199309L only guaranteed clock_gettime and caused
 * implicit-declaration errors on macOS/clang whose headers enforce
 * feature-test macros strictly. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

/*
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Raw C Benchmark Harness for AMA Cryptography
 * ==============================================
 *
 * Directly calls C library functions — no Python, no ctypes, no FFI overhead.
 * Uses clock_gettime(CLOCK_MONOTONIC) for high-resolution timing.
 *
 * Build:
 *   make -C benchmarks benchmark_c_raw
 *
 * Run:
 *   ./benchmarks/benchmark_c_raw [--csv] [--json]
 *
 * Output modes:
 *   (default)  Human-readable table
 *   --csv      Machine-parseable CSV to stdout
 *   --json     Machine-parseable JSON to stdout
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <float.h>

#include "ama_cryptography.h"
#include "ama_dispatch.h"

/* ============================================================================
 * TIMING HELPERS
 * ============================================================================ */

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* ============================================================================
 * STATISTICS
 * ============================================================================ */

typedef struct {
    const char *name;
    double mean_ns;
    double median_ns;
    double stddev_ns;
    double min_ns;
    double max_ns;
    double ops_per_sec;
    int iterations;
} bench_result_t;

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static bench_result_t compute_stats(const char *name, double *samples, int n) {
    bench_result_t r;
    memset(&r, 0, sizeof(r));
    r.name = name;
    r.iterations = n;

    if (n == 0) return r;

    /* Sort for median */
    qsort(samples, (size_t)n, sizeof(double), cmp_double);

    double sum = 0.0, mn = DBL_MAX, mx = 0.0;
    for (int i = 0; i < n; i++) {
        sum += samples[i];
        if (samples[i] < mn) mn = samples[i];
        if (samples[i] > mx) mx = samples[i];
    }

    r.mean_ns = sum / n;
    r.min_ns = mn;
    r.max_ns = mx;

    /* Median */
    if (n % 2 == 0)
        r.median_ns = (samples[n / 2 - 1] + samples[n / 2]) / 2.0;
    else
        r.median_ns = samples[n / 2];

    /* Stddev */
    double var = 0.0;
    for (int i = 0; i < n; i++) {
        double d = samples[i] - r.mean_ns;
        var += d * d;
    }
    r.stddev_ns = sqrt(var / n);

    r.ops_per_sec = (r.mean_ns > 0.0) ? 1e9 / r.mean_ns : 0.0;

    return r;
}

/* ============================================================================
 * RANDOM DATA HELPER (uses /dev/urandom on Linux)
 * ============================================================================ */

static void fill_random(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t got = fread(buf, 1, len, f);
        fclose(f);
        if (got == len) return;
    }
    /* Fallback: insecure but sufficient for benchmarking */
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(rand() & 0xFF);
}

/* ============================================================================
 * MAX BENCHMARK ITERATIONS
 * ============================================================================ */

#define MAX_SAMPLES 10000

static double g_samples[MAX_SAMPLES];

/* ============================================================================
 * INDIVIDUAL BENCHMARKS
 * ============================================================================ */

/* --- X25519 DH --- */
static bench_result_t bench_x25519_keygen(int iters, int warmup) {
    uint8_t pk[32], sk[32];
    for (int i = 0; i < warmup; i++)
        ama_x25519_keypair(pk, sk);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_x25519_keypair(pk, sk);
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("X25519 KeyGen", g_samples, iters);
}

static bench_result_t bench_x25519_dh(int iters, int warmup) {
    uint8_t pk_a[32], sk_a[32], pk_b[32], sk_b[32], shared[32];
    ama_x25519_keypair(pk_a, sk_a);
    ama_x25519_keypair(pk_b, sk_b);

    for (int i = 0; i < warmup; i++)
        ama_x25519_key_exchange(shared, sk_a, pk_b);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_x25519_key_exchange(shared, sk_a, pk_b);
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("X25519 DH Exchange", g_samples, iters);
}

/* Batch DH at a few representative N's.  N=1 measures the fast-path
 * pass-through (must be ≈ single-shot); N=4 measures one straight
 * AVX2 chunk (no tail); N=8 / N=16 measure two / four chunks.
 * Useful for callers who batch handshakes (e.g. server-side TLS
 * resumption clusters, mass key-derivation pipelines). */
static bench_result_t bench_x25519_dh_batch(size_t batch_n, int iters, int warmup) {
    uint8_t pk_a[32], sk_a[32];
    ama_x25519_keypair(pk_a, sk_a);

    uint8_t (*scs)[32]   = (uint8_t (*)[32])malloc(batch_n * 32);
    uint8_t (*pts)[32]   = (uint8_t (*)[32])malloc(batch_n * 32);
    uint8_t (*outs)[32]  = (uint8_t (*)[32])malloc(batch_n * 32);
    if (!scs || !pts || !outs) {
        free(scs); free(pts); free(outs);
        bench_result_t r = {0}; r.name = "(alloc failed)"; return r;
    }
    for (size_t k = 0; k < batch_n; k++) {
        uint8_t pk_k[32], sk_k[32];
        ama_x25519_keypair(pk_k, sk_k);
        memcpy(scs[k], sk_a, 32);
        memcpy(pts[k], pk_k, 32);
    }

    for (int i = 0; i < warmup; i++)
        ama_x25519_scalarmult_batch(outs,
                                     (const uint8_t (*)[32])scs,
                                     (const uint8_t (*)[32])pts,
                                     batch_n);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_x25519_scalarmult_batch(outs,
                                     (const uint8_t (*)[32])scs,
                                     (const uint8_t (*)[32])pts,
                                     batch_n);
        g_samples[i] = now_ns() - t0;
    }

    static char name_buf[8][64];  /* small static cache so labels live for the report */
    static int  name_idx = 0;
    char *name = name_buf[name_idx++ & 7];
    snprintf(name, 64, "X25519 DH Batch×%zu", batch_n);

    free(scs); free(pts); free(outs);
    return compute_stats(name, g_samples, iters);
}

/* --- AES-256-GCM --- */
static bench_result_t bench_aes_gcm_encrypt(size_t data_size, int iters, int warmup) {
    uint8_t key[32], nonce[12], tag[16];
    fill_random(key, 32);
    fill_random(nonce, 12);

    uint8_t *pt = (uint8_t *)malloc(data_size);
    uint8_t *ct = (uint8_t *)malloc(data_size);
    if (!pt || !ct) { free(pt); free(ct); bench_result_t r = {0}; r.name = "(alloc failed)"; return r; }
    fill_random(pt, data_size);

    for (int i = 0; i < warmup; i++)
        ama_aes256_gcm_encrypt(key, nonce, pt, data_size, NULL, 0, ct, tag);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_aes256_gcm_encrypt(key, nonce, pt, data_size, NULL, 0, ct, tag);
        g_samples[i] = now_ns() - t0;
    }

    char label[64];
    snprintf(label, sizeof(label), "AES-256-GCM Enc %zuKB", data_size / 1024);
    /* Static label storage — we keep a few around */
    static char labels[8][64];
    static int label_idx = 0;
    int li = label_idx++ % 8;
    strncpy(labels[li], label, 63);
    labels[li][63] = '\0';

    free(pt);
    free(ct);
    return compute_stats(labels[li], g_samples, iters);
}

static bench_result_t bench_aes_gcm_decrypt(size_t data_size, int iters, int warmup) {
    uint8_t key[32], nonce[12], tag[16];
    fill_random(key, 32);
    fill_random(nonce, 12);

    uint8_t *pt = (uint8_t *)malloc(data_size);
    uint8_t *ct = (uint8_t *)malloc(data_size);
    uint8_t *dec = (uint8_t *)malloc(data_size);
    if (!pt || !ct || !dec) { free(pt); free(ct); free(dec); bench_result_t r = {0}; r.name = "(alloc failed)"; return r; }
    fill_random(pt, data_size);

    ama_aes256_gcm_encrypt(key, nonce, pt, data_size, NULL, 0, ct, tag);

    for (int i = 0; i < warmup; i++)
        ama_aes256_gcm_decrypt(key, nonce, ct, data_size, NULL, 0, tag, dec);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_aes256_gcm_decrypt(key, nonce, ct, data_size, NULL, 0, tag, dec);
        g_samples[i] = now_ns() - t0;
    }

    char label[64];
    snprintf(label, sizeof(label), "AES-256-GCM Dec %zuKB", data_size / 1024);
    static char labels[8][64];
    static int label_idx = 0;
    int li = label_idx++ % 8;
    strncpy(labels[li], label, 63);
    labels[li][63] = '\0';

    free(pt);
    free(ct);
    free(dec);
    return compute_stats(labels[li], g_samples, iters);
}

/* --- Ed25519 --- */
static bench_result_t bench_ed25519_keygen(int iters, int warmup) {
    uint8_t pk[32], sk[64];

    for (int i = 0; i < warmup; i++) {
        fill_random(sk, 32);
        ama_ed25519_keypair(pk, sk);
    }

    for (int i = 0; i < iters; i++) {
        fill_random(sk, 32);
        double t0 = now_ns();
        ama_ed25519_keypair(pk, sk);
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("Ed25519 KeyGen", g_samples, iters);
}

static bench_result_t bench_ed25519_sign(int iters, int warmup) {
    uint8_t pk[32], sk[64], sig[64];
    const uint8_t msg[] = "Benchmark message for Ed25519 sign/verify test 0123456789ABCDEF";
    size_t msg_len = sizeof(msg) - 1;

    fill_random(sk, 32);
    ama_ed25519_keypair(pk, sk);

    for (int i = 0; i < warmup; i++)
        ama_ed25519_sign(sig, msg, msg_len, sk);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_ed25519_sign(sig, msg, msg_len, sk);
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("Ed25519 Sign", g_samples, iters);
}

/* Ed25519 verify, end-to-end: SHA-512(R||A||M), point decompression,
 * and the verify scalar-mult.  The reported number is what protocol
 * stacks (TLS cert chains, Noise handshakes, MLS Welcome/Commit) see
 * per signature check.
 *
 * Backend-dependent interpretation:
 *   - In-tree C backend (AMA_ED25519_ASSEMBLY=OFF): the scalar-mult
 *     path is selected by the compile-time gates AMA_ED25519_VERIFY_SHAMIR
 *     (default 1 — Shamir/Straus joint layout) and AMA_ED25519_VERIFY_WINDOW
 *     (default 5 — wNAF window width).
 *   - Donna shim backend (AMA_ED25519_ASSEMBLY=ON, auto-enabled on MSVC
 *     x64): those gates are ignored; the shim uses its own vendored
 *     scalar-mult and wNAF width.  Toggling the gates at CMake-time has
 *     no effect on this benchmark's numbers on shim builds. */
static bench_result_t bench_ed25519_verify(int iters, int warmup) {
    uint8_t pk[32], sk[64], sig[64];
    const uint8_t msg[] = "Benchmark message for Ed25519 sign/verify test 0123456789ABCDEF";
    size_t msg_len = sizeof(msg) - 1;

    fill_random(sk, 32);
    ama_ed25519_keypair(pk, sk);
    ama_ed25519_sign(sig, msg, msg_len, sk);

    for (int i = 0; i < warmup; i++)
        ama_ed25519_verify(sig, msg, msg_len, pk);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_ed25519_verify(sig, msg, msg_len, pk);
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("Ed25519 Verify", g_samples, iters);
}

/* Ed25519 double-scalarmult [s1]P1 + [s2]P2 in isolation.
 *
 * Times ama_ed25519_double_scalarmult_public() without the surrounding
 * verify overhead (no SHA-512 of (R||A||M), no extra decompressions).
 * Interpretation is backend-dependent:
 *
 *   - In-tree C backend (AMA_ED25519_ASSEMBLY=OFF): measures the
 *     Shamir/Straus joint pass that the verify path uses.  This is the
 *     relevant microbenchmark for AMA_ED25519_VERIFY_WINDOW tuning —
 *     comparing results across builds with W=4/5/6 isolates the pure
 *     scalar-mult cost from the SHA-512 noise that dominates whole-
 *     verify timings on short messages.
 *   - Donna shim backend (AMA_ED25519_ASSEMBLY=ON): the public API is
 *     implemented as two separate scalar multiplications plus one
 *     point add, so this bench does NOT isolate the in-tree Shamir
 *     path, and AMA_ED25519_VERIFY_WINDOW has no effect on the
 *     measured code.
 *
 * Setup uses two pseudo-random valid Ed25519 points (public keys from
 * two derived keypairs) and the s/h halves of a real signature for
 * scalars, so the input shape closely matches the verify call site. */
static bench_result_t bench_ed25519_double_scalarmult(int iters, int warmup) {
    uint8_t pk1[32], pk2[32], sk1[64], sk2[64], sig[64], h[64];
    const uint8_t msg[] = "Benchmark message for Ed25519 sign/verify test 0123456789ABCDEF";
    size_t msg_len = sizeof(msg) - 1;

    fill_random(sk1, 32);
    ama_ed25519_keypair(pk1, sk1);
    fill_random(sk2, 32);
    ama_ed25519_keypair(pk2, sk2);
    ama_ed25519_sign(sig, msg, msg_len, sk1);

    /* Build a verify-shaped second scalar: h = SHA-512(R || A || M)
     * reduced mod l, exactly what ama_ed25519_verify computes
     * internally.  This keeps the wNAF expansion realistic.  Size
     * hbuf from sizeof(msg) so editing the benchmark message cannot
     * silently overflow this buffer (sizeof includes the trailing
     * NUL, so we have one extra byte of headroom — harmless). */
    uint8_t hbuf[32 + 32 + sizeof(msg)];
    memcpy(hbuf, sig, 32);
    memcpy(hbuf + 32, pk1, 32);
    memcpy(hbuf + 64, msg, msg_len);
    ama_ed25519_sha512(hbuf, 64 + msg_len, h);
    /* sc_reduce works on a 64-byte buffer in place; result lives in h[0..31]. */
    ama_ed25519_sc_reduce(h);

    /* s1 = signature s-half (already < l); s2 = h (already reduced). */
    const uint8_t *s1 = sig + 32;
    const uint8_t *s2 = h;

    uint8_t out[32];
    for (int i = 0; i < warmup; i++)
        ama_ed25519_double_scalarmult_public(out, s1, pk1, s2, pk2);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_ed25519_double_scalarmult_public(out, s1, pk1, s2, pk2);
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("Ed25519 Double-ScalarMult", g_samples, iters);
}

/* --- ML-DSA-65 (Dilithium) --- */
static bench_result_t bench_dilithium_keygen(int iters, int warmup) {
    uint8_t pk[AMA_ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_ML_DSA_65_SECRET_KEY_BYTES];

    for (int i = 0; i < warmup; i++)
        ama_dilithium_keypair(pk, sk);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_dilithium_keypair(pk, sk);
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("ML-DSA-65 KeyGen", g_samples, iters);
}

static bench_result_t bench_dilithium_sign(int iters, int warmup) {
    uint8_t pk[AMA_ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t sig[AMA_ML_DSA_65_SIGNATURE_BYTES];
    size_t sig_len = sizeof(sig);
    const uint8_t msg[] = "ML-DSA-65 benchmark message for sign/verify operations";
    size_t msg_len = sizeof(msg) - 1;

    ama_dilithium_keypair(pk, sk);

    for (int i = 0; i < warmup; i++)
        ama_dilithium_sign(sig, &sig_len, msg, msg_len, sk);

    for (int i = 0; i < iters; i++) {
        sig_len = sizeof(sig);
        double t0 = now_ns();
        ama_dilithium_sign(sig, &sig_len, msg, msg_len, sk);
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("ML-DSA-65 Sign", g_samples, iters);
}

static bench_result_t bench_dilithium_verify(int iters, int warmup) {
    uint8_t pk[AMA_ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t sig[AMA_ML_DSA_65_SIGNATURE_BYTES];
    size_t sig_len = sizeof(sig);
    const uint8_t msg[] = "ML-DSA-65 benchmark message for sign/verify operations";
    size_t msg_len = sizeof(msg) - 1;

    ama_dilithium_keypair(pk, sk);
    ama_dilithium_sign(sig, &sig_len, msg, msg_len, sk);

    for (int i = 0; i < warmup; i++)
        ama_dilithium_verify(msg, msg_len, sig, sig_len, pk);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_dilithium_verify(msg, msg_len, sig, sig_len, pk);
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("ML-DSA-65 Verify", g_samples, iters);
}

/* --- ML-KEM-1024 (Kyber) --- */
static bench_result_t bench_kyber_keygen(int iters, int warmup) {
    uint8_t pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_KYBER_1024_SECRET_KEY_BYTES];

    for (int i = 0; i < warmup; i++)
        ama_kyber_keypair(pk, sizeof(pk), sk, sizeof(sk));

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_kyber_keypair(pk, sizeof(pk), sk, sizeof(sk));
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("ML-KEM-1024 KeyGen", g_samples, iters);
}

static bench_result_t bench_kyber_encaps(int iters, int warmup) {
    uint8_t pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_KYBER_1024_SECRET_KEY_BYTES];
    uint8_t ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
    uint8_t ss[AMA_KYBER_1024_SHARED_SECRET_BYTES];
    size_t ct_len = sizeof(ct);

    ama_kyber_keypair(pk, sizeof(pk), sk, sizeof(sk));

    for (int i = 0; i < warmup; i++) {
        ct_len = sizeof(ct);
        ama_kyber_encapsulate(pk, sizeof(pk), ct, &ct_len, ss, sizeof(ss));
    }

    for (int i = 0; i < iters; i++) {
        ct_len = sizeof(ct);
        double t0 = now_ns();
        ama_kyber_encapsulate(pk, sizeof(pk), ct, &ct_len, ss, sizeof(ss));
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("ML-KEM-1024 Encaps", g_samples, iters);
}

static bench_result_t bench_kyber_decaps(int iters, int warmup) {
    uint8_t pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_KYBER_1024_SECRET_KEY_BYTES];
    uint8_t ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
    uint8_t ss[AMA_KYBER_1024_SHARED_SECRET_BYTES];
    uint8_t ss2[AMA_KYBER_1024_SHARED_SECRET_BYTES];
    size_t ct_len = sizeof(ct);

    ama_kyber_keypair(pk, sizeof(pk), sk, sizeof(sk));
    ama_kyber_encapsulate(pk, sizeof(pk), ct, &ct_len, ss, sizeof(ss));

    for (int i = 0; i < warmup; i++)
        ama_kyber_decapsulate(ct, ct_len, sk, sizeof(sk), ss2, sizeof(ss2));

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_kyber_decapsulate(ct, ct_len, sk, sizeof(sk), ss2, sizeof(ss2));
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("ML-KEM-1024 Decaps", g_samples, iters);
}

/* --- ML-KEM-1024 poly helpers (poly_add / poly_sub / poly_reduce) ---
 *
 * Microbench for the SVE2 kyber_poly_{add,sub,reduce} dispatch slots.
 * Compares the dispatched helper against an explicit scalar loop —
 * NOT against the inline scalar in src/c/ama_kyber.c (which is what
 * the dispatcher itself falls back to when the slot is NULL), so the
 * two timings are directly comparable without re-entering the dispatch
 * indirection.
 *
 * Wired today only on SVE2; on AVX2/NEON hosts the slot is NULL and
 * the "(scalar)" and "(dispatch)" rows both measure the same compiler
 * auto-vectorised loop, which is intentional — it confirms the
 * autovectorizer is delivering on those tiers.
 *
 * IMPORTANT: a single poly_add over 256 int16_t is ~hundreds of
 * picoseconds on a modern core, so per-iteration `now_ns()` overhead
 * dominates.  Each iteration runs the helper in a tight 256-call
 * inner loop (g_samples[i] holds the per-call mean over those 256
 * calls) so the dispatch arithmetic is amortised across enough work
 * to land in the resolvable timing band.
 *
 * NOTE on real-hardware measurement: qemu's SVE2 emulation is ~47x
 * slower than scalar and is NOT representative.  Real ARMv9 hardware
 * is required for the SVE2 helper to clearly beat the auto-vectoriser
 * — see the rationale block at the SVE2 init in
 * src/c/dispatch/ama_dispatch.c. */
#define KYBER_POLY_N 256
#define KYBER_POLY_Q 3329
#define BENCH_INNER_LOOP 256

static void scalar_kyber_poly_add(int16_t r[KYBER_POLY_N],
                                   const int16_t a[KYBER_POLY_N],
                                   const int16_t b[KYBER_POLY_N]) {
    for (int i = 0; i < KYBER_POLY_N; i++) r[i] = (int16_t)(a[i] + b[i]);
}
static void scalar_kyber_poly_sub(int16_t r[KYBER_POLY_N],
                                   const int16_t a[KYBER_POLY_N],
                                   const int16_t b[KYBER_POLY_N]) {
    for (int i = 0; i < KYBER_POLY_N; i++) r[i] = (int16_t)(a[i] - b[i]);
}
static int16_t kyber_barrett_ref(int16_t a) {
    const int16_t v = ((1 << 26) + KYBER_POLY_Q / 2) / KYBER_POLY_Q;
    int16_t t = (int16_t)(((int32_t)v * a) >> 26);
    t *= KYBER_POLY_Q;
    return (int16_t)(a - t);
}
static void scalar_kyber_poly_reduce(int16_t r[KYBER_POLY_N]) {
    for (int i = 0; i < KYBER_POLY_N; i++) r[i] = kyber_barrett_ref(r[i]);
}

static void fill_random_poly(int16_t p[KYBER_POLY_N]) {
    for (int i = 0; i < KYBER_POLY_N; i++) {
        p[i] = (int16_t)(rand() % (2 * KYBER_POLY_Q - 1)) - (KYBER_POLY_Q - 1);
    }
}

static bench_result_t bench_kyber_poly_add(int iters, int warmup, int use_dispatch) {
    int16_t a[KYBER_POLY_N], b[KYBER_POLY_N], r[KYBER_POLY_N];
    fill_random_poly(a); fill_random_poly(b);

    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    ama_kyber_poly_add_fn fn = (use_dispatch && dt->kyber_poly_add)
                                 ? dt->kyber_poly_add
                                 : scalar_kyber_poly_add;

    for (int i = 0; i < warmup; i++) fn(r, a, b);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        for (int j = 0; j < BENCH_INNER_LOOP; j++) fn(r, a, b);
        g_samples[i] = (now_ns() - t0) / (double)BENCH_INNER_LOOP;
    }
    static char labels[2][48];
    snprintf(labels[use_dispatch ? 1 : 0], sizeof(labels[0]),
             "ML-KEM-1024 poly_add (%s)",
             use_dispatch ? "dispatch" : "scalar");
    return compute_stats(labels[use_dispatch ? 1 : 0], g_samples, iters);
}

static bench_result_t bench_kyber_poly_sub(int iters, int warmup, int use_dispatch) {
    int16_t a[KYBER_POLY_N], b[KYBER_POLY_N], r[KYBER_POLY_N];
    fill_random_poly(a); fill_random_poly(b);

    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    ama_kyber_poly_sub_fn fn = (use_dispatch && dt->kyber_poly_sub)
                                 ? dt->kyber_poly_sub
                                 : scalar_kyber_poly_sub;

    for (int i = 0; i < warmup; i++) fn(r, a, b);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        for (int j = 0; j < BENCH_INNER_LOOP; j++) fn(r, a, b);
        g_samples[i] = (now_ns() - t0) / (double)BENCH_INNER_LOOP;
    }
    static char labels[2][48];
    snprintf(labels[use_dispatch ? 1 : 0], sizeof(labels[0]),
             "ML-KEM-1024 poly_sub (%s)",
             use_dispatch ? "dispatch" : "scalar");
    return compute_stats(labels[use_dispatch ? 1 : 0], g_samples, iters);
}

static bench_result_t bench_kyber_poly_reduce(int iters, int warmup, int use_dispatch) {
    /* Pre-randomise a ring of BENCH_INNER_LOOP input polys so the
     * timed inner loop calls fn() on a fresh, distinct in-place
     * buffer every call.  This keeps the input distribution stable
     * across runs (no implicit re-randomisation cost in the timed
     * region) AND removes the memcpy-per-call that was previously
     * dominating the measurement and masking dispatch-vs-scalar
     * differences.  Re-seed the ring once per outer iteration; the
     * re-seed happens outside the clock-gettime fence. */
    static int16_t ring[BENCH_INNER_LOOP][KYBER_POLY_N];
    for (int j = 0; j < BENCH_INNER_LOOP; j++) fill_random_poly(ring[j]);

    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    ama_kyber_poly_reduce_fn fn = (use_dispatch && dt->kyber_poly_reduce)
                                    ? dt->kyber_poly_reduce
                                    : scalar_kyber_poly_reduce;

    /* Warmup: reduce the warmed buffers in place.  Subsequent
     * iterations re-seed the ring before timing so the input
     * distribution stays bounded in [-q+1, q-1]. */
    for (int i = 0; i < warmup; i++) {
        fn(ring[i % BENCH_INNER_LOOP]);
    }
    for (int j = 0; j < BENCH_INNER_LOOP; j++) fill_random_poly(ring[j]);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        for (int j = 0; j < BENCH_INNER_LOOP; j++) {
            fn(ring[j]);
        }
        g_samples[i] = (now_ns() - t0) / (double)BENCH_INNER_LOOP;
        /* Re-seed outside the timed region so the next outer iteration
         * sees the same input distribution as the first one.  Without
         * the re-seed, after one pass every coefficient is already
         * reduced — measuring "reduce of already-reduced poly" rather
         * than "reduce of a poly in the natural post-add range". */
        for (int j = 0; j < BENCH_INNER_LOOP; j++) fill_random_poly(ring[j]);
    }
    static char labels[2][48];
    snprintf(labels[use_dispatch ? 1 : 0], sizeof(labels[0]),
             "ML-KEM-1024 poly_reduce (%s)",
             use_dispatch ? "dispatch" : "scalar");
    return compute_stats(labels[use_dispatch ? 1 : 0], g_samples, iters);
}

/* --- SHA3-256 / SHA3-512 --- */
static bench_result_t bench_sha3_256(size_t data_size, int iters, int warmup) {
    uint8_t *data = (uint8_t *)malloc(data_size);
    uint8_t hash[32];
    if (!data) { bench_result_t r = {0}; r.name = "(alloc failed)"; return r; }
    fill_random(data, data_size);

    for (int i = 0; i < warmup; i++)
        ama_sha3_256(data, data_size, hash);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_sha3_256(data, data_size, hash);
        g_samples[i] = now_ns() - t0;
    }

    char label[64];
    snprintf(label, sizeof(label), "SHA3-256 (%zuB)", data_size);
    static char labels[4][64];
    static int label_idx = 0;
    int li = label_idx++ % 4;
    strncpy(labels[li], label, 63);
    labels[li][63] = '\0';

    free(data);
    return compute_stats(labels[li], g_samples, iters);
}

static bench_result_t bench_sha3_512(size_t data_size, int iters, int warmup) {
    uint8_t *data = (uint8_t *)malloc(data_size);
    uint8_t hash[64];
    if (!data) { bench_result_t r = {0}; r.name = "(alloc failed)"; return r; }
    fill_random(data, data_size);

    for (int i = 0; i < warmup; i++)
        ama_sha3_512(data, data_size, hash);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_sha3_512(data, data_size, hash);
        g_samples[i] = now_ns() - t0;
    }

    char label[64];
    snprintf(label, sizeof(label), "SHA3-512 (%zuB)", data_size);
    static char labels[4][64];
    static int label_idx = 0;
    int li = label_idx++ % 4;
    strncpy(labels[li], label, 63);
    labels[li][63] = '\0';

    free(data);
    return compute_stats(labels[li], g_samples, iters);
}

/* --- HMAC-SHA3-256 --- */
static bench_result_t bench_hmac_sha3(size_t msg_size, int iters, int warmup) {
    uint8_t key[32], out[32];
    fill_random(key, 32);
    uint8_t *msg = (uint8_t *)malloc(msg_size);
    if (!msg) { bench_result_t r = {0}; r.name = "(alloc failed)"; return r; }
    fill_random(msg, msg_size);

    for (int i = 0; i < warmup; i++)
        ama_hmac_sha3_256(key, 32, msg, msg_size, out);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_hmac_sha3_256(key, 32, msg, msg_size, out);
        g_samples[i] = now_ns() - t0;
    }

    char label[64];
    snprintf(label, sizeof(label), "HMAC-SHA3-256 (%zuB)", msg_size);
    static char labels[4][64];
    static int label_idx = 0;
    int li = label_idx++ % 4;
    strncpy(labels[li], label, 63);
    labels[li][63] = '\0';

    free(msg);
    return compute_stats(labels[li], g_samples, iters);
}

/* --- ChaCha20-Poly1305 AEAD (exercises AVX2 8-way for >= 512 B) --- */
static bench_result_t bench_chacha20poly1305_encrypt(size_t data_size, int iters, int warmup) {
    uint8_t key[32], nonce[12], tag[16];
    fill_random(key, 32);
    fill_random(nonce, 12);

    uint8_t *pt = (uint8_t *)malloc(data_size);
    uint8_t *ct = (uint8_t *)malloc(data_size);
    if (!pt || !ct) { free(pt); free(ct); bench_result_t r = {0}; r.name = "(alloc failed)"; return r; }
    fill_random(pt, data_size);

    for (int i = 0; i < warmup; i++)
        ama_chacha20poly1305_encrypt(key, nonce, pt, data_size, NULL, 0, ct, tag);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_chacha20poly1305_encrypt(key, nonce, pt, data_size, NULL, 0, ct, tag);
        g_samples[i] = now_ns() - t0;
    }

    char label[64];
    if (data_size >= 1024)
        snprintf(label, sizeof(label), "ChaCha20-Poly1305 Enc %zuKB", data_size / 1024);
    else
        snprintf(label, sizeof(label), "ChaCha20-Poly1305 Enc %zuB", data_size);
    static char labels[8][64];
    static int label_idx = 0;
    int li = label_idx++ % 8;
    strncpy(labels[li], label, 63);
    labels[li][63] = '\0';

    free(pt);
    free(ct);
    return compute_stats(labels[li], g_samples, iters);
}

/* --- Argon2id (exercises AVX2 BlaMka G) --- */
static bench_result_t bench_argon2id(uint32_t m_cost, int iters, int warmup) {
    const uint8_t password[] = "benchmark-password-argon2-avx2";
    /* Explicit 16-byte salt (no string literal → no dependence on the
     * "trailing NUL dropped when array size matches char count" corner
     * of C11 §6.7.9 ¶14, which some toolchains warn or error on). */
    const uint8_t salt[16]   = {
        'S','I','X','T','E','E','N','-','B','Y','T','E','-','S','L','T'
    };
    uint8_t tag[32];

    for (int i = 0; i < warmup; i++)
        ama_argon2id(password, sizeof(password) - 1, salt, 16,
                     1, m_cost, 1, tag, 32);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_argon2id(password, sizeof(password) - 1, salt, 16,
                     1, m_cost, 1, tag, 32);
        g_samples[i] = now_ns() - t0;
    }

    char label[64];
    if (m_cost >= 1024)
        snprintf(label, sizeof(label), "Argon2id (m=%uMiB,t=1)", m_cost / 1024);
    else
        snprintf(label, sizeof(label), "Argon2id (m=%uKiB,t=1)", m_cost);
    static char labels[4][64];
    static int label_idx = 0;
    int li = label_idx++ % 4;
    strncpy(labels[li], label, 63);
    labels[li][63] = '\0';

    return compute_stats(labels[li], g_samples, iters);
}

/* --- HKDF --- */
static bench_result_t bench_hkdf(int iters, int warmup) {
    uint8_t salt[32], ikm[32], info[] = "benchmark-hkdf";
    uint8_t okm[96]; /* 3 derived keys */
    fill_random(salt, 32);
    fill_random(ikm, 32);

    for (int i = 0; i < warmup; i++)
        ama_hkdf(salt, 32, ikm, 32, info, sizeof(info) - 1, okm, 96);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_hkdf(salt, 32, ikm, 32, info, sizeof(info) - 1, okm, 96);
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("HKDF-SHA3-256 (96B)", g_samples, iters);
}

/* ============================================================================
 * BENCHMARK ADDITIONS — explicit gap-list coverage (2026-05)
 *
 * Five benchmark families added to close the gaps called out in the brief:
 *   - MULX/ADX on-vs-off X25519 ratio
 *   - SLH-DSA (SHAKE-128s, FIPS 205 L1)
 *   - secp256k1 pubkey-from-privkey
 *   - FROST 2-of-3 round1 / round2 / aggregate (RFC 9591)
 *   - Dilithium NTT kernel isolation (forward + inverse, scalar vs dispatched)
 *
 * Provenance / design notes per family live above each function. The five
 * families together fill the "Benchmarks still missing" list in
 * `benchmarks/README.md` and feed `benchmarks/generate_charts.py` so the
 * SVG dashboards reflect coverage rather than only ML-DSA / ML-KEM /
 * Ed25519 / X25519 ops.
 * ============================================================================ */

/* --- X25519 DH (MULX/ADX) on / off ---
 *
 * Same Diffie-Hellman call as `bench_x25519_dh()`, but pins the runtime
 * selection of the in-house BMI2+ADX kernel via the benchmark/test-only
 * `ama_x25519_set_mulx_override()` API. Used to quantify the MULX+ADX
 * speedup quoted in `wiki/Performance-Benchmarks.md` (~1.46× on this
 * sandbox — 75.1 µs → 51.5 µs, 13.3k → 19.4k ops/s; literature 1.8-2.2×
 * on uncontended Skylake+ / Zen+) without rebuilding. The previous ~21%
 * figure referenced here was a copy from the ML-DSA-65 NTT row
 * (1.21× / 21%) and did not match the X25519 measurement.
 *
 * If the host CPUID lacks BMI2+ADX OR the MULX kernel TU was not linked
 * in (`AMA_HAVE_X25519_FE64_MULX_IMPL` undefined at build), the
 * "MULX on" override is a documented no-op and both rows time the
 * pure-C fe64 path — the equal numbers are themselves informative
 * ("no kernel on this host"). The override is restored to auto (-1)
 * at the end of each function so subsequent benchmarks see the
 * default production policy. */
static bench_result_t bench_x25519_dh_mulx_off(int iters, int warmup) {
    uint8_t pk_a[32], sk_a[32], pk_b[32], sk_b[32], shared[32];
    ama_x25519_keypair(pk_a, sk_a);
    ama_x25519_keypair(pk_b, sk_b);

    ama_x25519_set_mulx_override(0);    /* pin pure-C fe64 */

    for (int i = 0; i < warmup; i++)
        ama_x25519_key_exchange(shared, sk_a, pk_b);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_x25519_key_exchange(shared, sk_a, pk_b);
        g_samples[i] = now_ns() - t0;
    }

    ama_x25519_set_mulx_override(-1);   /* restore auto */
    return compute_stats("X25519 DH (MULX off)", g_samples, iters);
}

static bench_result_t bench_x25519_dh_mulx_on(int iters, int warmup) {
    uint8_t pk_a[32], sk_a[32], pk_b[32], sk_b[32], shared[32];
    ama_x25519_keypair(pk_a, sk_a);
    ama_x25519_keypair(pk_b, sk_b);

    ama_x25519_set_mulx_override(1);    /* pin MULX+ADX kernel (no-op
                                         * on hosts without BMI2+ADX
                                         * or without the kernel TU) */

    for (int i = 0; i < warmup; i++)
        ama_x25519_key_exchange(shared, sk_a, pk_b);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_x25519_key_exchange(shared, sk_a, pk_b);
        g_samples[i] = now_ns() - t0;
    }

    ama_x25519_set_mulx_override(-1);   /* restore auto */
    return compute_stats("X25519 DH (MULX on)", g_samples, iters);
}

/* --- Dilithium NTT kernel isolation ---
 *
 * Times the forward and inverse NTT in isolation from the surrounding
 * `bench_dilithium_sign` / `bench_dilithium_verify` flow (which sums
 * the NTT kernel cost into the end-to-end ML-DSA latency along with
 * sampling, rejection, and packing). The benchmark-only
 * `ama_dilithium_{ntt,invntt}_bench()` entry points route the same
 * `dil_{ntt,invntt}_cached` code, but bind the dispatch slot
 * explicitly so we can produce paired scalar-vs-dispatched rows.
 *
 * Per-sample inner loop is BENCH_INNER_LOOP iterations to push the
 * per-NTT cost above clock_gettime() resolution on modern hosts
 * (single NTT is a few hundred nanoseconds with SIMD wired up).
 * Each *outer* sample begins by refilling `g_dil_ntt_ring` with
 * BENCH_INNER_LOOP independent random polynomials (see
 * `fill_dil_ntt_ring()` and the `for (i = 0; i < iters; i++)` loops
 * below); the *inner* loop then indexes through that prefilled ring
 * one poly per call. Pre-filling outside the timed region keeps the
 * `fill_random_int32_poly()` work out of the measurement; indexing
 * a fresh ring slot per call still ensures every NTT operates on
 * independent inputs so the compiler cannot hoist the result and
 * successive in-place transforms do not compound across iterations.
 *
 * BENCH_INNER_LOOP itself is defined once earlier in this file
 * (next to KYBER_POLY_N) — that single define is the source of
 * truth for every microbench that needs a per-sample inner-loop
 * count. */

static void fill_random_int32_poly(int32_t a[256]) {
    /* Coefficients in [-q+1, q-1] for q = 8380417 — the natural input
     * range entering the NTT during ML-DSA signing. Lightweight,
     * non-cryptographic benchmark input generation via `rand()`,
     * seeded from `time(NULL)` in `main()` — the sequence varies from
     * run to run on the same host, which is intentional (the
     * benchmark cares about per-NTT throughput, not byte-for-byte
     * reproducibility of inputs; the bench harness already filters
     * timing noise via median + stddev across ≥50 samples per row). */
    for (int i = 0; i < 256; i++) {
        int32_t v = (int32_t)((unsigned)rand() % 8380417u);
        if (rand() & 1) v = -v;
        a[i] = v;
    }
}

/* Pre-randomised ring of BENCH_INNER_LOOP independent input polynomials.
 * Each inner-loop call below indexes into this ring so every NTT/invNTT
 * call operates on a fresh, in-range polynomial rather than the
 * compounding output of the previous (in-place) call. The ring is
 * static (256 polys × 256 int32 × 4 B = 256 KiB) to keep stack pressure
 * bounded and to mirror the kyber_poly_{add,sub,reduce} ring pattern
 * earlier in this file. */
static int32_t g_dil_ntt_ring[BENCH_INNER_LOOP][256];

static void fill_dil_ntt_ring(void) {
    for (int j = 0; j < BENCH_INNER_LOOP; j++)
        fill_random_int32_poly(g_dil_ntt_ring[j]);
}

static bench_result_t bench_dilithium_ntt(int iters, int warmup, int use_dispatch) {
    int32_t scratch[256];

    fill_dil_ntt_ring();
    for (int i = 0; i < warmup; i++) {
        memcpy(scratch, g_dil_ntt_ring[i % BENCH_INNER_LOOP], sizeof(scratch));
        ama_dilithium_ntt_bench(scratch, use_dispatch);
    }

    for (int i = 0; i < iters; i++) {
        /* Refresh the ring per outer iteration so the timed inner loop
         * always begins from independent, never-transformed inputs. */
        fill_dil_ntt_ring();
        double t0 = now_ns();
        for (int j = 0; j < BENCH_INNER_LOOP; j++) {
            ama_dilithium_ntt_bench(g_dil_ntt_ring[j], use_dispatch);
        }
        g_samples[i] = (now_ns() - t0) / (double)BENCH_INNER_LOOP;
    }

    static char labels[2][48];
    snprintf(labels[use_dispatch ? 1 : 0], sizeof(labels[0]),
             "ML-DSA-65 NTT (%s)",
             use_dispatch ? "dispatch" : "scalar");
    return compute_stats(labels[use_dispatch ? 1 : 0], g_samples, iters);
}

static bench_result_t bench_dilithium_invntt(int iters, int warmup, int use_dispatch) {
    int32_t scratch[256];

    fill_dil_ntt_ring();
    for (int i = 0; i < warmup; i++) {
        memcpy(scratch, g_dil_ntt_ring[i % BENCH_INNER_LOOP], sizeof(scratch));
        ama_dilithium_invntt_bench(scratch, use_dispatch);
    }

    for (int i = 0; i < iters; i++) {
        fill_dil_ntt_ring();
        double t0 = now_ns();
        for (int j = 0; j < BENCH_INNER_LOOP; j++) {
            ama_dilithium_invntt_bench(g_dil_ntt_ring[j], use_dispatch);
        }
        g_samples[i] = (now_ns() - t0) / (double)BENCH_INNER_LOOP;
    }

    static char labels[2][48];
    snprintf(labels[use_dispatch ? 1 : 0], sizeof(labels[0]),
             "ML-DSA-65 invNTT (%s)",
             use_dispatch ? "dispatch" : "scalar");
    return compute_stats(labels[use_dispatch ? 1 : 0], g_samples, iters);
}

/* --- SLH-DSA SHAKE-128s (FIPS 205, NIST L1) ---
 *
 * Times the practical L1 parameter set: smallest public key (32 B),
 * smallest signature (7,856 B) at the cost of the slowest sign of the
 * SLH-DSA family. Verify is the more common production hot path and
 * is significantly faster than sign on this parameter set.
 *
 * Per-op cost on the 2026-05 sandbox: KeyGen ~164 ms, Sign ~1.25 s
 * (seconds-scale — three to four orders of magnitude beyond the
 * `iters_vslow` 1 ms+ tier), Verify ~1.15 ms. Call sites therefore
 * use `iters_slh_sign` (5) for the sign row and `iters_slow` (200)
 * for keygen / verify so the family stays inside the ~60 s subprocess
 * timeout the downstream `benchmarks/comparative_benchmark.py` runner
 * enforces (see its `timeout=60` argument on the raw-C subprocess).
 *
 * Warmup is capped *locally* per call (see SLH_KEYGEN_WARMUP_MAX /
 * SLH_SIGN_WARMUP_MAX / SLH_VERIFY_WARMUP_MAX below) so that the
 * shared `--warmup N` flag (default 50) does not multiply against
 * multi-millisecond keygen and seconds-long sign. Without these caps,
 * 50 warmup signs alone burn ~60 s before measurement begins. */

#define SLH_KEYGEN_WARMUP_MAX 3   /* ~164 ms each -> ~0.5 s warmup */
#define SLH_SIGN_WARMUP_MAX   2   /* ~1.25 s each -> ~2.5 s warmup */
#define SLH_VERIFY_WARMUP_MAX 10  /* ~1.15 ms each -> ~12 ms warmup */
static bench_result_t bench_slhdsa_shake128s_keygen(int iters, int warmup) {
    uint8_t pk[AMA_SLHDSA_SHAKE_128S_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_SLHDSA_SHAKE_128S_SECRET_KEY_BYTES];

    if (warmup > SLH_KEYGEN_WARMUP_MAX) warmup = SLH_KEYGEN_WARMUP_MAX;
    for (int i = 0; i < warmup; i++)
        ama_slhdsa_keygen(AMA_SLHDSA_SHAKE_128S, pk, sk);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_slhdsa_keygen(AMA_SLHDSA_SHAKE_128S, pk, sk);
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("SLH-DSA-SHAKE-128s KeyGen", g_samples, iters);
}

static bench_result_t bench_slhdsa_shake128s_sign(int iters, int warmup) {
    uint8_t pk[AMA_SLHDSA_SHAKE_128S_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_SLHDSA_SHAKE_128S_SECRET_KEY_BYTES];
    uint8_t *sig = (uint8_t *)malloc(AMA_SLHDSA_SHAKE_128S_SIGNATURE_BYTES);
    if (!sig) { bench_result_t r = {0}; r.name = "(alloc failed)"; return r; }
    size_t sig_len = AMA_SLHDSA_SHAKE_128S_SIGNATURE_BYTES;
    const uint8_t msg[] = "SLH-DSA SHAKE-128s benchmark message";
    size_t msg_len = sizeof(msg) - 1;

    ama_slhdsa_keygen(AMA_SLHDSA_SHAKE_128S, pk, sk);

    if (warmup > SLH_SIGN_WARMUP_MAX) warmup = SLH_SIGN_WARMUP_MAX;
    for (int i = 0; i < warmup; i++) {
        sig_len = AMA_SLHDSA_SHAKE_128S_SIGNATURE_BYTES;
        ama_slhdsa_sign(AMA_SLHDSA_SHAKE_128S, sig, &sig_len,
                        msg, msg_len, NULL, 0, sk);
    }

    for (int i = 0; i < iters; i++) {
        sig_len = AMA_SLHDSA_SHAKE_128S_SIGNATURE_BYTES;
        double t0 = now_ns();
        ama_slhdsa_sign(AMA_SLHDSA_SHAKE_128S, sig, &sig_len,
                        msg, msg_len, NULL, 0, sk);
        g_samples[i] = now_ns() - t0;
    }

    free(sig);
    return compute_stats("SLH-DSA-SHAKE-128s Sign", g_samples, iters);
}

static bench_result_t bench_slhdsa_shake128s_verify(int iters, int warmup) {
    uint8_t pk[AMA_SLHDSA_SHAKE_128S_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_SLHDSA_SHAKE_128S_SECRET_KEY_BYTES];
    uint8_t *sig = (uint8_t *)malloc(AMA_SLHDSA_SHAKE_128S_SIGNATURE_BYTES);
    if (!sig) { bench_result_t r = {0}; r.name = "(alloc failed)"; return r; }
    size_t sig_len = AMA_SLHDSA_SHAKE_128S_SIGNATURE_BYTES;
    const uint8_t msg[] = "SLH-DSA SHAKE-128s benchmark message";
    size_t msg_len = sizeof(msg) - 1;

    ama_slhdsa_keygen(AMA_SLHDSA_SHAKE_128S, pk, sk);
    ama_slhdsa_sign(AMA_SLHDSA_SHAKE_128S, sig, &sig_len,
                    msg, msg_len, NULL, 0, sk);

    if (warmup > SLH_VERIFY_WARMUP_MAX) warmup = SLH_VERIFY_WARMUP_MAX;
    for (int i = 0; i < warmup; i++)
        ama_slhdsa_verify(AMA_SLHDSA_SHAKE_128S, sig, sig_len,
                          msg, msg_len, NULL, 0, pk);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_slhdsa_verify(AMA_SLHDSA_SHAKE_128S, sig, sig_len,
                          msg, msg_len, NULL, 0, pk);
        g_samples[i] = now_ns() - t0;
    }

    free(sig);
    return compute_stats("SLH-DSA-SHAKE-128s Verify", g_samples, iters);
}

/* --- secp256k1 pubkey-from-privkey ---
 *
 * Constant-time Montgomery-ladder scalar multiplication on secp256k1
 * (`ama_secp256k1_pubkey_from_privkey`, SEC1 compressed output). The
 * single-shot pubkey derivation is the dominant cost in BIP-340
 * Schnorr / ECDSA signing and is what production wallets call to
 * import a private key. */
static bench_result_t bench_secp256k1_pubkey(int iters, int warmup) {
    uint8_t privkey[32];
    uint8_t pubkey[33];

    /* Fill with a non-zero scalar in [1, N-1]. The library rejects 0
     * and values >= N; using 0x01..0x20 keeps the ladder on the same
     * code path every iteration. */
    for (int i = 0; i < 32; i++) privkey[i] = (uint8_t)(i + 1);

    for (int i = 0; i < warmup; i++)
        ama_secp256k1_pubkey_from_privkey(privkey, pubkey);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_secp256k1_pubkey_from_privkey(privkey, pubkey);
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("secp256k1 pubkey", g_samples, iters);
}

/* --- FROST 2-of-3 (RFC 9591) ---
 *
 * Three rows for the per-round per-signer cost in a 2-of-3 FROST
 * session: round1 nonce commitment, round2 signature share, and the
 * coordinator's final aggregate into a standard Ed25519 signature.
 * Keygen-trusted-dealer is run once at setup and is NOT in the timed
 * region (it is an offline / one-shot operation, not the hot path
 * any production deployment cares about). */
static bench_result_t bench_frost_round1_commit(int iters, int warmup) {
    uint8_t group_pk[32];
    uint8_t shares[3 * AMA_FROST_SHARE_BYTES];
    if (ama_frost_keygen_trusted_dealer(2, 3, group_pk, shares, NULL) != AMA_SUCCESS) {
        bench_result_t r = {0}; r.name = "(FROST keygen failed)"; return r;
    }

    uint8_t nonce_pair[AMA_FROST_NONCE_BYTES];
    uint8_t commitment[AMA_FROST_COMMITMENT_BYTES];
    const uint8_t *share1 = shares + 0 * AMA_FROST_SHARE_BYTES;

    for (int i = 0; i < warmup; i++)
        ama_frost_round1_commit(nonce_pair, commitment, share1);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_frost_round1_commit(nonce_pair, commitment, share1);
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("FROST round1 commit", g_samples, iters);
}

static bench_result_t bench_frost_round2_sign(int iters, int warmup) {
    uint8_t group_pk[32];
    uint8_t shares[3 * AMA_FROST_SHARE_BYTES];
    if (ama_frost_keygen_trusted_dealer(2, 3, group_pk, shares, NULL) != AMA_SUCCESS) {
        bench_result_t r = {0}; r.name = "(FROST keygen failed)"; return r;
    }

    /* Two signers (indices 1 and 2). Each generates its round1
     * commitment; round2 sign needs the concatenated commitments and
     * indices of the participating signer set. */
    uint8_t nonce_pairs[2][AMA_FROST_NONCE_BYTES];
    uint8_t commitments[2 * AMA_FROST_COMMITMENT_BYTES];
    uint8_t signer_indices[2] = { 1, 2 };
    for (int s = 0; s < 2; s++) {
        ama_frost_round1_commit(nonce_pairs[s],
                                commitments + s * AMA_FROST_COMMITMENT_BYTES,
                                shares + s * AMA_FROST_SHARE_BYTES);
    }

    const uint8_t msg[] = "FROST 2-of-3 benchmark message";
    size_t msg_len = sizeof(msg) - 1;
    uint8_t sig_share[AMA_FROST_SIG_SHARE_BYTES];

    for (int i = 0; i < warmup; i++)
        ama_frost_round2_sign(sig_share, msg, msg_len,
                              shares + 0 * AMA_FROST_SHARE_BYTES, 1,
                              nonce_pairs[0],
                              commitments, signer_indices, 2, group_pk);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_frost_round2_sign(sig_share, msg, msg_len,
                              shares + 0 * AMA_FROST_SHARE_BYTES, 1,
                              nonce_pairs[0],
                              commitments, signer_indices, 2, group_pk);
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("FROST round2 sign", g_samples, iters);
}

static bench_result_t bench_frost_aggregate(int iters, int warmup) {
    uint8_t group_pk[32];
    uint8_t shares[3 * AMA_FROST_SHARE_BYTES];
    if (ama_frost_keygen_trusted_dealer(2, 3, group_pk, shares, NULL) != AMA_SUCCESS) {
        bench_result_t r = {0}; r.name = "(FROST keygen failed)"; return r;
    }

    uint8_t nonce_pairs[2][AMA_FROST_NONCE_BYTES];
    uint8_t commitments[2 * AMA_FROST_COMMITMENT_BYTES];
    uint8_t signer_indices[2] = { 1, 2 };
    for (int s = 0; s < 2; s++) {
        ama_frost_round1_commit(nonce_pairs[s],
                                commitments + s * AMA_FROST_COMMITMENT_BYTES,
                                shares + s * AMA_FROST_SHARE_BYTES);
    }

    const uint8_t msg[] = "FROST 2-of-3 benchmark message";
    size_t msg_len = sizeof(msg) - 1;
    uint8_t sig_shares[2 * AMA_FROST_SIG_SHARE_BYTES];
    for (int s = 0; s < 2; s++) {
        ama_frost_round2_sign(sig_shares + s * AMA_FROST_SIG_SHARE_BYTES,
                              msg, msg_len,
                              shares + s * AMA_FROST_SHARE_BYTES,
                              signer_indices[s],
                              nonce_pairs[s],
                              commitments, signer_indices, 2, group_pk);
    }

    uint8_t signature[64];

    for (int i = 0; i < warmup; i++)
        ama_frost_aggregate(signature, sig_shares, commitments,
                            signer_indices, 2, msg, msg_len, group_pk);

    for (int i = 0; i < iters; i++) {
        double t0 = now_ns();
        ama_frost_aggregate(signature, sig_shares, commitments,
                            signer_indices, 2, msg, msg_len, group_pk);
        g_samples[i] = now_ns() - t0;
    }
    return compute_stats("FROST aggregate", g_samples, iters);
}

/* ============================================================================
 * OUTPUT FORMATTERS
 * ============================================================================ */

static void print_table_header(void) {
    printf("\n");
    printf("%-30s | %12s | %12s | %12s | %10s | %10s | %12s | %6s\n",
           "Operation", "Mean (us)", "Median (us)", "Stddev (us)",
           "Min (us)", "Max (us)", "Ops/sec", "Iters");
    printf("%-30s-|-%12s-|-%12s-|-%12s-|-%10s-|-%10s-|-%12s-|-%6s\n",
           "------------------------------", "------------", "------------",
           "------------", "----------", "----------", "------------", "------");
}

static void print_table_row(const bench_result_t *r) {
    printf("%-30s | %12.3f | %12.3f | %12.3f | %10.3f | %10.3f | %12.0f | %6d\n",
           r->name,
           r->mean_ns / 1000.0,
           r->median_ns / 1000.0,
           r->stddev_ns / 1000.0,
           r->min_ns / 1000.0,
           r->max_ns / 1000.0,
           r->ops_per_sec,
           r->iterations);
}

static void print_csv_header(void) {
    printf("operation,mean_us,median_us,stddev_us,min_us,max_us,ops_per_sec,iterations\n");
}

static void print_csv_row(const bench_result_t *r) {
    printf("%s,%.3f,%.3f,%.3f,%.3f,%.3f,%.0f,%d\n",
           r->name,
           r->mean_ns / 1000.0,
           r->median_ns / 1000.0,
           r->stddev_ns / 1000.0,
           r->min_ns / 1000.0,
           r->max_ns / 1000.0,
           r->ops_per_sec,
           r->iterations);
}

static void print_json_start(void) {
    printf("{\n  \"benchmark\": \"AMA Cryptography Raw C\",\n");
    printf("  \"version\": \"%d.%d.%d\",\n",
           AMA_CRYPTOGRAPHY_VERSION_MAJOR,
           AMA_CRYPTOGRAPHY_VERSION_MINOR,
           AMA_CRYPTOGRAPHY_VERSION_PATCH);

    time_t now = time(NULL);
    struct tm t;
    gmtime_r(&now, &t);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &t);
    printf("  \"timestamp\": \"%s\",\n", ts);
    printf("  \"results\": [\n");
}

static void print_json_row(const bench_result_t *r, int last) {
    printf("    {\n");
    printf("      \"operation\": \"%s\",\n", r->name);
    printf("      \"mean_us\": %.3f,\n", r->mean_ns / 1000.0);
    printf("      \"median_us\": %.3f,\n", r->median_ns / 1000.0);
    printf("      \"stddev_us\": %.3f,\n", r->stddev_ns / 1000.0);
    printf("      \"min_us\": %.3f,\n", r->min_ns / 1000.0);
    printf("      \"max_us\": %.3f,\n", r->max_ns / 1000.0);
    printf("      \"ops_per_sec\": %.0f,\n", r->ops_per_sec);
    printf("      \"iterations\": %d\n", r->iterations);
    printf("    }%s\n", last ? "" : ",");
}

/*
 * Emit a `peer_context` JSON section recording published ops/sec figures
 * for peer cryptographic libraries on comparable x86-64 hardware. These
 * are static reference numbers with citations — they provide a frame of
 * reference for readers when the peer libraries are not installed in the
 * environment (so `benchmarks/comparative_benchmark.py` skips them). They
 * are NOT live measurements. When comparative_benchmark.py runs with
 * pynacl / oqs / cryptography installed, those live numbers supersede
 * these references for that specific run.
 *
 * Ranges are intentionally used rather than point values: peer-library
 * throughput varies by CPU model, microcode, and build flags, and a
 * single number would misrepresent the distribution.
 */
static void print_json_peer_context(void) {
    printf("  \"peer_context\": {\n");
    printf("    \"description\": \"Published ops/sec ranges for peer libraries on x86-64. Reference only — not measured by this harness.\",\n");
    printf("    \"libsodium_ed25519_keygen\":  { \"ops_per_sec_range\": [40000, 60000], \"source\": \"libsodium 1.0.20 bench on Intel x86-64 with precomputed base-point table; https://doc.libsodium.org/advanced/ed25519\" },\n");
    printf("    \"libsodium_ed25519_sign\":    { \"ops_per_sec_range\": [50000, 80000], \"source\": \"SUPERCOP ed25519/ref10, amd64; https://bench.cr.yp.to/supercop.html\" },\n");
    printf("    \"libsodium_ed25519_verify\":  { \"ops_per_sec_range\": [15000, 30000], \"source\": \"libsodium 1.0.20 on x86-64 (vartime verify); https://bench.cr.yp.to/supercop.html\" },\n");
    printf("    \"liboqs_ml_dsa_65_sign\":     { \"ops_per_sec_range\": [500, 1500],   \"source\": \"liboqs 0.10 reference C implementation; https://openquantumsafe.org/benchmarking/\" },\n");
    printf("    \"liboqs_ml_dsa_65_verify\":   { \"ops_per_sec_range\": [4000, 9000],  \"source\": \"liboqs 0.10 reference C implementation; https://openquantumsafe.org/benchmarking/\" },\n");
    printf("    \"liboqs_ml_kem_1024_encap\":  { \"ops_per_sec_range\": [7000, 15000], \"source\": \"liboqs 0.10 reference C implementation; https://openquantumsafe.org/benchmarking/\" },\n");
    printf("    \"liboqs_ml_kem_1024_decap\":  { \"ops_per_sec_range\": [6000, 13000], \"source\": \"liboqs 0.10 reference C implementation; https://openquantumsafe.org/benchmarking/\" }\n");
    printf("  }\n");
}

static void print_json_end(void) {
    printf("  ],\n");
    print_json_peer_context();
    printf("}\n");
}

/* ============================================================================
 * COMPARISON OUTPUT — column-ready for BENCHMARKS.md
 * ============================================================================ */

static void print_comparison_table(bench_result_t *results, int count) {
    printf("\n--- Column-Ready Comparison Format ---\n\n");
    printf("%-30s | %14s | %14s\n", "Operation", "Raw C ops/sec", "Raw C latency");
    printf("%-30s-|-%14s-|-%14s\n",
           "------------------------------", "--------------", "--------------");
    for (int i = 0; i < count; i++) {
        char lat[32];
        double us = results[i].mean_ns / 1000.0;
        if (us < 1.0)
            snprintf(lat, sizeof(lat), "%.0f ns", results[i].mean_ns);
        else if (us < 1000.0)
            snprintf(lat, sizeof(lat), "%.2f us", us);
        else
            snprintf(lat, sizeof(lat), "%.2f ms", us / 1000.0);

        printf("%-30s | %14.0f | %14s\n",
               results[i].name, results[i].ops_per_sec, lat);
    }
    printf("\n");
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

int main(int argc, char **argv) {
    int csv_mode = 0, json_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--csv") == 0)   csv_mode = 1;
        if (strcmp(argv[i], "--json") == 0)  json_mode = 1;
    }

    /* Seed fallback RNG */
    srand((unsigned)time(NULL));

    /* Warmup and iteration counts */
    const int warmup = 50;
    const int iters_fast  = 5000;   /* < 1us ops */
    const int iters_med   = 1000;   /* 1-100us ops */
    const int iters_slow  = 200;    /* 100us+ ops */
    const int iters_vslow = 50;     /* 1ms+ ops */
    /* SLH-DSA-SHAKE-128s sign is ~1.25 s / op on a modern x86-64 core —
     * three to four orders of magnitude beyond `iters_vslow`'s intended
     * 1 ms+ band. Use a dedicated, much smaller iteration count so the
     * sign row stays inside the ~60 s wall-clock ceiling that downstream
     * runners enforce (see `benchmarks/comparative_benchmark.py` line
     * ~231: `timeout=60` on the raw-C harness subprocess). At 5 iters
     * the sign row is ~6 s — within budget, and the harness emits min
     * / median / max / stddev so a 5-sample median still surfaces a
     * gross regression even if it is not statistically tight. */
    const int iters_slh_sign = 5;   /* seconds-scale ops (SLH-DSA Sign only) */

    /* Collect all results */
    #define MAX_RESULTS 80
    bench_result_t results[MAX_RESULTS];
    int n = 0;

    if (!csv_mode && !json_mode) {
        printf("AMA Cryptography — Raw C Benchmark Harness\n");
        printf("============================================\n");
        printf("Library version: %s\n", ama_version_string());
        printf("Timer: clock_gettime(CLOCK_MONOTONIC)\n");

        time_t now = time(NULL);
        char datebuf[32];
        if (ctime_r(&now, datebuf) != NULL) {
            printf("Date: %s", datebuf);
        } else {
            printf("Date: (unavailable)\n");
        }
        printf("\nRunning benchmarks...\n");
    }

    /* --- Hash functions --- */
    results[n++] = bench_sha3_256(32, iters_fast, warmup);
    results[n++] = bench_sha3_256(1024, iters_fast, warmup);
    results[n++] = bench_sha3_512(32, iters_fast, warmup);
    results[n++] = bench_sha3_512(1024, iters_fast, warmup);

    /* --- HMAC --- */
    results[n++] = bench_hmac_sha3(32, iters_fast, warmup);
    results[n++] = bench_hmac_sha3(1024, iters_fast, warmup);

    /* --- HKDF --- */
    results[n++] = bench_hkdf(iters_fast, warmup);

    /* --- Ed25519 --- */
    results[n++] = bench_ed25519_keygen(iters_med, warmup);
    results[n++] = bench_ed25519_sign(iters_med, warmup);
    results[n++] = bench_ed25519_verify(iters_med, warmup);
    results[n++] = bench_ed25519_double_scalarmult(iters_med, warmup);

    /* --- X25519 --- */
    results[n++] = bench_x25519_keygen(iters_med, warmup);
    results[n++] = bench_x25519_dh(iters_med, warmup);
    results[n++] = bench_x25519_dh_batch(1,  iters_med, warmup);
    results[n++] = bench_x25519_dh_batch(4,  iters_med, warmup);
    results[n++] = bench_x25519_dh_batch(8,  iters_med, warmup);
    results[n++] = bench_x25519_dh_batch(16, iters_med, warmup);

    /* --- X25519 MULX/ADX kernel on-vs-off ---
     * Surfaces the BMI2+ADX speedup quoted in
     * `wiki/Performance-Benchmarks.md` directly in the harness output.
     * On hosts without the kernel (CPUID gate or build flag), the two
     * rows match — informative in its own right. */
    results[n++] = bench_x25519_dh_mulx_off(iters_med, warmup);
    results[n++] = bench_x25519_dh_mulx_on(iters_med, warmup);

    /* --- secp256k1 (constant-time Montgomery ladder) --- */
    results[n++] = bench_secp256k1_pubkey(iters_med, warmup);

    /* --- FROST 2-of-3 (RFC 9591) --- */
    results[n++] = bench_frost_round1_commit(iters_med, warmup);
    results[n++] = bench_frost_round2_sign(iters_med, warmup);
    results[n++] = bench_frost_aggregate(iters_med, warmup);

    /* --- AES-256-GCM ---
     * 1 KB / 4 KB / 16 KB / 64 KB rows.  PR A (2026-04) added the 16 KB
     * row to bracket the regime where the VAES + VPCLMULQDQ YMM kernel
     * starts to dominate the AVX2 AES-NI 8-way path: per-block setup
     * overhead is amortized, but the working set still fits in L1d, so
     * the throughput plateau here is the cleanest signal of the kernel
     * choice rather than memory-bandwidth saturation. */
    results[n++] = bench_aes_gcm_encrypt(1024, iters_med, warmup);
    results[n++] = bench_aes_gcm_decrypt(1024, iters_med, warmup);
    results[n++] = bench_aes_gcm_encrypt(4096, iters_slow, warmup);
    results[n++] = bench_aes_gcm_decrypt(4096, iters_slow, warmup);
    results[n++] = bench_aes_gcm_encrypt(16384, iters_slow, warmup);
    results[n++] = bench_aes_gcm_decrypt(16384, iters_slow, warmup);
    results[n++] = bench_aes_gcm_encrypt(65536, iters_vslow, warmup);
    results[n++] = bench_aes_gcm_decrypt(65536, iters_vslow, warmup);

    /* --- ChaCha20-Poly1305 (AVX2 8-way kicks in at >=512 B) --- */
    results[n++] = bench_chacha20poly1305_encrypt(256,   iters_med,   warmup);
    results[n++] = bench_chacha20poly1305_encrypt(1024,  iters_med,   warmup);
    results[n++] = bench_chacha20poly1305_encrypt(4096,  iters_slow,  warmup);
    results[n++] = bench_chacha20poly1305_encrypt(65536, iters_vslow, warmup);

    /* --- Argon2id (exercises AVX2 BlaMka G) --- */
    results[n++] = bench_argon2id(64,   iters_slow,  warmup);  /*  64 KiB */
    results[n++] = bench_argon2id(1024, iters_vslow, warmup);  /*   1 MiB */

    /* --- ML-DSA-65 --- */
    results[n++] = bench_dilithium_keygen(iters_slow, warmup);
    results[n++] = bench_dilithium_sign(iters_slow, warmup);
    results[n++] = bench_dilithium_verify(iters_slow, warmup);

    /* --- ML-DSA-65 NTT kernel isolation (scalar vs dispatched) ---
     * Isolates the NTT cost from the surrounding ML-DSA flow so a
     * future SIMD-NTT win shows up here as a scalar-vs-dispatch
     * delta even when end-to-end sign/verify is dominated by
     * sampling and rejection. */
    results[n++] = bench_dilithium_ntt(iters_fast,    warmup, 0);
    results[n++] = bench_dilithium_ntt(iters_fast,    warmup, 1);
    results[n++] = bench_dilithium_invntt(iters_fast, warmup, 0);
    results[n++] = bench_dilithium_invntt(iters_fast, warmup, 1);

    /* --- SLH-DSA SHAKE-128s (FIPS 205, NIST L1) ---
     * KeyGen ~164 ms, Sign ~1.25 s, Verify ~1.15 ms on this sandbox.
     * Sign uses the dedicated `iters_slh_sign` (5) tier so the row
     * lands at ~6 s and stays inside the 60 s subprocess timeout that
     * `benchmarks/comparative_benchmark.py` enforces on the harness. */
    results[n++] = bench_slhdsa_shake128s_keygen(iters_slow,     warmup);
    results[n++] = bench_slhdsa_shake128s_sign(iters_slh_sign,   warmup);
    results[n++] = bench_slhdsa_shake128s_verify(iters_slow,     warmup);

    /* --- ML-KEM-1024 --- */
    results[n++] = bench_kyber_keygen(iters_slow, warmup);
    results[n++] = bench_kyber_encaps(iters_slow, warmup);
    results[n++] = bench_kyber_decaps(iters_slow, warmup);

    /* --- ML-KEM-1024 poly helpers (scalar vs dispatched) ---
     * Surfaces the SVE2 kyber_poly_{add,sub,reduce} win (if any) on
     * ARMv9 hardware.  On AVX2/NEON hosts the dispatch slot is NULL
     * and both rows time the same compiler auto-vectorised loop —
     * the comparison is a no-op there.  Run as `iters_fast` because
     * each sample averages BENCH_INNER_LOOP=256 helper calls (the
     * single helper is sub-nanosecond on a modern core, well below
     * clock_gettime resolution). */
    results[n++] = bench_kyber_poly_add(iters_fast, warmup, 0);
    results[n++] = bench_kyber_poly_add(iters_fast, warmup, 1);
    results[n++] = bench_kyber_poly_sub(iters_fast, warmup, 0);
    results[n++] = bench_kyber_poly_sub(iters_fast, warmup, 1);
    results[n++] = bench_kyber_poly_reduce(iters_fast, warmup, 0);
    results[n++] = bench_kyber_poly_reduce(iters_fast, warmup, 1);

    /* --- Output --- */
    if (json_mode) {
        print_json_start();
        for (int i = 0; i < n; i++)
            print_json_row(&results[i], i == n - 1);
        print_json_end();
    } else if (csv_mode) {
        print_csv_header();
        for (int i = 0; i < n; i++)
            print_csv_row(&results[i]);
    } else {
        print_table_header();
        for (int i = 0; i < n; i++)
            print_table_row(&results[i]);

        print_comparison_table(results, n);

        printf("Done. %d benchmarks completed.\n", n);
    }

    return 0;
}
