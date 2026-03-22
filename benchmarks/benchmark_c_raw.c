/* POSIX feature test macro — must precede all #includes */
#define _POSIX_C_SOURCE 199309L

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
    if (!pt || !ct) { free(pt); free(ct); bench_result_t r = {0}; return r; }
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
    if (!pt || !ct || !dec) { free(pt); free(ct); free(dec); bench_result_t r = {0}; return r; }
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
    if (!data) { bench_result_t r = {0}; return r; }
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
    if (!data) { bench_result_t r = {0}; return r; }
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
    if (!msg) { bench_result_t r = {0}; return r; }
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

static void print_json_end(void) {
    printf("  ]\n}\n");
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
    #define MAX_RESULTS 32
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
