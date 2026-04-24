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

    /* Collect all results */
    #define MAX_RESULTS 40
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

    /* --- AES-256-GCM --- */
    results[n++] = bench_aes_gcm_encrypt(1024, iters_med, warmup);
    results[n++] = bench_aes_gcm_decrypt(1024, iters_med, warmup);
    results[n++] = bench_aes_gcm_encrypt(4096, iters_slow, warmup);
    results[n++] = bench_aes_gcm_decrypt(4096, iters_slow, warmup);
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

    /* --- ML-KEM-1024 --- */
    results[n++] = bench_kyber_keygen(iters_slow, warmup);
    results[n++] = bench_kyber_encaps(iters_slow, warmup);
    results[n++] = bench_kyber_decaps(iters_slow, warmup);

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
