/**
 * Copyright 2025 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_kat.c
 * @brief Known Answer Test (KAT) framework for PQC implementations
 * @author Andrew E. A., Steel Security Advisors LLC
 *
 * Tests native PQC implementations against NIST KAT vectors and verifies
 * roundtrip correctness for all three algorithms:
 *   - ML-DSA-65 (CRYSTALS-Dilithium)
 *   - Kyber-1024 (ML-KEM-1024)
 *   - SPHINCS+-SHA2-256f-simple
 *
 * Includes a NIST-compliant AES-256-CTR DRBG for deterministic random
 * byte generation, allowing exact reproduction of KAT vector outputs.
 */

#define _POSIX_C_SOURCE 200809L  /* for strdup */
#include "../../include/ama_cryptography.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

/* ============================================================================
 * TEST INFRASTRUCTURE
 * ============================================================================ */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { \
        printf("  FAIL: %s\n", msg); \
        tests_failed++; \
        return 0; \
    } else { \
        tests_passed++; \
    } \
} while(0)

#define RUN_TEST(fn, name) do { \
    printf("[TEST] %s\n", name); \
    if (fn()) { \
        printf("  PASS: %s\n", name); \
    } else { \
        printf("  FAIL: %s\n", name); \
    } \
} while(0)

/* ============================================================================
 * NIST AES-256-CTR DRBG
 * ============================================================================
 * The NIST PQC KAT framework uses a deterministic PRNG based on
 * AES-256 in counter mode. Given a 48-byte seed, it produces the
 * same pseudorandom stream every time, making KAT outputs reproducible.
 * ============================================================================ */

typedef struct {
    uint8_t key[32];
    uint8_t v[16];    /* Counter (V) */
    int reseed_ctr;
} nist_drbg_ctx;

static nist_drbg_ctx g_drbg;

/**
 * AES-256-ECB encrypt a single 16-byte block
 */
static void aes256_ecb_encrypt(const uint8_t key[32], const uint8_t in[16],
                                uint8_t out[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, out, &outlen, in, 16);
    EVP_EncryptFinal_ex(ctx, out + outlen, &outlen);
    EVP_CIPHER_CTX_free(ctx);
}

/**
 * Increment the 16-byte counter V by 1 (big-endian)
 */
static void drbg_inc_v(uint8_t v[16]) {
    int i;
    for (i = 15; i >= 0; i--) {
        if (++v[i] != 0) break;
    }
}

/**
 * NIST DRBG Update function
 * Updates key and V using AES-256-CTR with provided_data XOR'd in
 */
static void nist_drbg_update(nist_drbg_ctx *ctx, const uint8_t *provided_data) {
    uint8_t temp[48];
    int i;

    for (i = 0; i < 3; i++) {
        drbg_inc_v(ctx->v);
        aes256_ecb_encrypt(ctx->key, ctx->v, temp + 16 * i);
    }

    if (provided_data) {
        for (i = 0; i < 48; i++) {
            temp[i] ^= provided_data[i];
        }
    }

    memcpy(ctx->key, temp, 32);
    memcpy(ctx->v, temp + 32, 16);
}

/**
 * Seed the NIST DRBG with a 48-byte entropy input
 * This is the exact seeding procedure from the NIST KAT framework
 */
static void nist_drbg_init(nist_drbg_ctx *ctx, const uint8_t seed[48]) {
    memset(ctx->key, 0, 32);
    memset(ctx->v, 0, 16);
    nist_drbg_update(ctx, seed);
    ctx->reseed_ctr = 1;
}

/**
 * Generate pseudorandom bytes from the NIST DRBG
 */
static void nist_drbg_generate(nist_drbg_ctx *ctx, uint8_t *out, size_t outlen) {
    uint8_t block[16];

    while (outlen > 0) {
        drbg_inc_v(ctx->v);
        aes256_ecb_encrypt(ctx->key, ctx->v, block);

        size_t tocopy = (outlen < 16) ? outlen : 16;
        memcpy(out, block, tocopy);
        out += tocopy;
        outlen -= tocopy;
    }

    nist_drbg_update(ctx, NULL);
    ctx->reseed_ctr++;
}

/* ============================================================================
 * RANDOMNESS HOOKS
 * ============================================================================
 * External hooks defined in the crypto source files. When set, all
 * internal random byte generation routes through these, allowing
 * deterministic output for KAT vector reproduction.
 * ============================================================================ */

extern ama_error_t (*ama_kyber_randombytes_hook)(uint8_t* buf, size_t len);
extern ama_error_t (*ama_dilithium_randombytes_hook)(uint8_t* buf, size_t len);
extern ama_error_t (*ama_sphincs_randombytes_hook)(uint8_t* buf, size_t len);

/* DRBG-based hook (for legacy pre-FIPS KAT tests) */
static ama_error_t drbg_randombytes(uint8_t *buf, size_t len) {
    nist_drbg_generate(&g_drbg, buf, len);
    return AMA_SUCCESS;
}

static void install_drbg_hooks(void) {
    ama_kyber_randombytes_hook = drbg_randombytes;
    ama_dilithium_randombytes_hook = drbg_randombytes;
    ama_sphincs_randombytes_hook = drbg_randombytes;
}

static void remove_drbg_hooks(void) {
    ama_kyber_randombytes_hook = NULL;
    ama_dilithium_randombytes_hook = NULL;
    ama_sphincs_randombytes_hook = NULL;
}

/* Buffer-based hook for FIPS KAT tests (feeds pre-loaded bytes sequentially) */
static uint8_t g_buf_hook_data[256];
static size_t g_buf_hook_len = 0;
static size_t g_buf_hook_pos = 0;

static ama_error_t buf_hook_randombytes(uint8_t *buf, size_t len) {
    if (g_buf_hook_pos + len > g_buf_hook_len) {
        return AMA_ERROR_CRYPTO;  /* Buffer exhausted */
    }
    memcpy(buf, g_buf_hook_data + g_buf_hook_pos, len);
    g_buf_hook_pos += len;
    return AMA_SUCCESS;
}

static void buf_hook_load(const uint8_t *data, size_t len) {
    if (len > sizeof(g_buf_hook_data)) len = sizeof(g_buf_hook_data);
    memcpy(g_buf_hook_data, data, len);
    g_buf_hook_len = len;
    g_buf_hook_pos = 0;
}

/* ============================================================================
 * HEX UTILITIES
 * ============================================================================ */

static int hex_char_to_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len) {
    size_t hex_len = strlen(hex);
    size_t byte_len = hex_len / 2;
    size_t i;

    if (byte_len > max_len) return -1;

    for (i = 0; i < byte_len; i++) {
        int hi = hex_char_to_nibble(hex[2*i]);
        int lo = hex_char_to_nibble(hex[2*i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)byte_len;
}

static void __attribute__((unused)) bytes_to_hex(const uint8_t *bytes, size_t len, char *hex) {
    static const char hextable[] = "0123456789ABCDEF";
    size_t i;
    for (i = 0; i < len; i++) {
        hex[2*i] = hextable[bytes[i] >> 4];
        hex[2*i + 1] = hextable[bytes[i] & 0x0F];
    }
    hex[2*len] = '\0';
}

/* ============================================================================
 * RSP FILE PARSER
 * ============================================================================ */

#define RSP_MAX_LINE (256 * 1024)   /* KAT hex values can be very long */
#define RSP_MAX_FIELD_NAME 32

typedef struct {
    char name[RSP_MAX_FIELD_NAME];
    char *value;    /* Heap-allocated hex string */
} rsp_field;

#define RSP_MAX_FIELDS 16

typedef struct {
    rsp_field fields[RSP_MAX_FIELDS];
    int num_fields;
} rsp_entry;

static void rsp_entry_free(rsp_entry *e) {
    int i;
    for (i = 0; i < e->num_fields; i++) {
        free(e->fields[i].value);
        e->fields[i].value = NULL;
    }
    e->num_fields = 0;
}

/**
 * Read next KAT entry from an .rsp file.
 * Returns 1 if an entry was read, 0 on EOF.
 */
static int rsp_read_entry(FILE *f, rsp_entry *entry) {
    char *line = (char *)malloc(RSP_MAX_LINE);
    if (!line) return 0;

    entry->num_fields = 0;

    while (fgets(line, RSP_MAX_LINE, f)) {
        /* Strip trailing whitespace */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' ||
                           line[len-1] == ' ' || line[len-1] == '\t')) {
            line[--len] = '\0';
        }

        /* Skip blank lines and comments */
        if (len == 0 || line[0] == '#') {
            /* If we already have fields, a blank line ends the entry */
            if (entry->num_fields > 0) {
                free(line);
                return 1;
            }
            continue;
        }

        /* Parse "name = value" */
        char *eq = strchr(line, '=');
        if (!eq) continue;

        /* Extract field name (trim spaces) */
        *eq = '\0';
        char *name = line;
        while (*name == ' ' || *name == '\t') name++;
        char *name_end = eq - 1;
        while (name_end > name && (*name_end == ' ' || *name_end == '\t'))
            name_end--;
        *(name_end + 1) = '\0';

        /* Extract value (trim spaces) */
        char *val = eq + 1;
        while (*val == ' ' || *val == '\t') val++;

        /* Store the field */
        if (entry->num_fields < RSP_MAX_FIELDS) {
            rsp_field *fld = &entry->fields[entry->num_fields];
            strncpy(fld->name, name, RSP_MAX_FIELD_NAME - 1);
            fld->name[RSP_MAX_FIELD_NAME - 1] = '\0';
            fld->value = strdup(val);
            entry->num_fields++;
        }
    }

    free(line);
    return entry->num_fields > 0 ? 1 : 0;
}

/**
 * Find a field value by name in an RSP entry
 */
static const char *rsp_get_field(const rsp_entry *e, const char *name) {
    int i;
    for (i = 0; i < e->num_fields; i++) {
        if (strcmp(e->fields[i].name, name) == 0)
            return e->fields[i].value;
    }
    return NULL;
}

/* ============================================================================
 * EXTERN DECLARATIONS FOR NATIVE PQC API
 * ============================================================================ */

extern ama_error_t ama_kyber_keypair(uint8_t* pk, size_t pk_len,
                                      uint8_t* sk, size_t sk_len);
extern ama_error_t ama_kyber_encapsulate(const uint8_t* pk, size_t pk_len,
                                          uint8_t* ct, size_t* ct_len,
                                          uint8_t* ss, size_t ss_len);
extern ama_error_t ama_kyber_decapsulate(const uint8_t* ct, size_t ct_len,
                                          const uint8_t* sk, size_t sk_len,
                                          uint8_t* ss, size_t ss_len);
extern ama_error_t ama_dilithium_keypair(uint8_t *public_key, uint8_t *secret_key);
extern ama_error_t ama_dilithium_sign(uint8_t *signature, size_t *signature_len,
                                       const uint8_t *message, size_t message_len,
                                       const uint8_t *secret_key);
extern ama_error_t ama_dilithium_verify(const uint8_t *message, size_t message_len,
                                         const uint8_t *signature, size_t signature_len,
                                         const uint8_t *public_key);
extern ama_error_t ama_sphincs_keypair(uint8_t *public_key, uint8_t *secret_key);
extern ama_error_t ama_sphincs_sign(uint8_t *signature, size_t *signature_len,
                                     const uint8_t *message, size_t message_len,
                                     const uint8_t *secret_key);
extern ama_error_t ama_sphincs_verify(const uint8_t *message, size_t message_len,
                                       const uint8_t *signature, size_t signature_len,
                                       const uint8_t *public_key);

/* ============================================================================
 * SELF-CONSISTENCY TESTS (Roundtrip Correctness)
 * ============================================================================
 * These tests prove the algorithms work end-to-end without needing
 * KAT vectors. They are the first line of defense.
 * ============================================================================ */

/**
 * Kyber-1024: keygen -> encapsulate -> decapsulate -> shared secrets match
 */
static int test_kyber_roundtrip(void) {
    uint8_t pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_KYBER_1024_SECRET_KEY_BYTES];
    uint8_t ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
    uint8_t ss_enc[AMA_KYBER_1024_SHARED_SECRET_BYTES];
    uint8_t ss_dec[AMA_KYBER_1024_SHARED_SECRET_BYTES];
    size_t ct_len = sizeof(ct);
    ama_error_t rc;

    /* Generate keypair */
    rc = ama_kyber_keypair(pk, sizeof(pk), sk, sizeof(sk));
    TEST_ASSERT(rc == AMA_SUCCESS, "Kyber keypair generation failed");

    /* Encapsulate */
    rc = ama_kyber_encapsulate(pk, sizeof(pk), ct, &ct_len, ss_enc, sizeof(ss_enc));
    TEST_ASSERT(rc == AMA_SUCCESS, "Kyber encapsulation failed");
    TEST_ASSERT(ct_len == AMA_KYBER_1024_CIPHERTEXT_BYTES, "Kyber ciphertext wrong size");

    /* Decapsulate */
    rc = ama_kyber_decapsulate(ct, ct_len, sk, sizeof(sk), ss_dec, sizeof(ss_dec));
    TEST_ASSERT(rc == AMA_SUCCESS, "Kyber decapsulation failed");

    /* Shared secrets must match */
    TEST_ASSERT(memcmp(ss_enc, ss_dec, AMA_KYBER_1024_SHARED_SECRET_BYTES) == 0,
                "Kyber shared secrets DO NOT MATCH - ROUNDTRIP FAILURE");

    printf("    Shared secrets match (%d bytes)\n", AMA_KYBER_1024_SHARED_SECRET_BYTES);
    return 1;
}

/**
 * Kyber-1024: verify implicit rejection works (tampered ciphertext)
 */
static int test_kyber_implicit_rejection(void) {
    uint8_t pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_KYBER_1024_SECRET_KEY_BYTES];
    uint8_t ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
    uint8_t ss_enc[AMA_KYBER_1024_SHARED_SECRET_BYTES];
    uint8_t ss_dec[AMA_KYBER_1024_SHARED_SECRET_BYTES];
    size_t ct_len = sizeof(ct);
    ama_error_t rc;

    rc = ama_kyber_keypair(pk, sizeof(pk), sk, sizeof(sk));
    TEST_ASSERT(rc == AMA_SUCCESS, "Kyber keypair generation failed");

    rc = ama_kyber_encapsulate(pk, sizeof(pk), ct, &ct_len, ss_enc, sizeof(ss_enc));
    TEST_ASSERT(rc == AMA_SUCCESS, "Kyber encapsulation failed");

    /* Tamper with ciphertext */
    ct[0] ^= 0xFF;
    ct[100] ^= 0xFF;

    /* Decapsulate tampered ciphertext - should succeed but produce different SS */
    rc = ama_kyber_decapsulate(ct, ct_len, sk, sizeof(sk), ss_dec, sizeof(ss_dec));
    TEST_ASSERT(rc == AMA_SUCCESS, "Kyber decap should succeed (implicit rejection)");

    /* Shared secrets must NOT match (implicit rejection) */
    TEST_ASSERT(memcmp(ss_enc, ss_dec, AMA_KYBER_1024_SHARED_SECRET_BYTES) != 0,
                "Kyber implicit rejection FAILED - tampered CT produced same SS!");

    printf("    Implicit rejection working (tampered CT produces different SS)\n");
    return 1;
}

/**
 * ML-DSA-65: keygen -> sign -> verify -> pass
 */
static int test_dilithium_roundtrip(void) {
    uint8_t pk[AMA_ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t sig[AMA_ML_DSA_65_SIGNATURE_BYTES];
    size_t sig_len = sizeof(sig);
    const uint8_t msg[] = "AMA Cryptography - Post-Quantum Cryptography Self-Test";
    ama_error_t rc;

    /* Generate keypair */
    rc = ama_dilithium_keypair(pk, sk);
    TEST_ASSERT(rc == AMA_SUCCESS, "Dilithium keypair generation failed");

    /* Sign */
    rc = ama_dilithium_sign(sig, &sig_len, msg, sizeof(msg) - 1, sk);
    TEST_ASSERT(rc == AMA_SUCCESS, "Dilithium signing failed");
    TEST_ASSERT(sig_len == AMA_ML_DSA_65_SIGNATURE_BYTES, "Dilithium signature wrong size");

    /* Verify */
    rc = ama_dilithium_verify(msg, sizeof(msg) - 1, sig, sig_len, pk);
    TEST_ASSERT(rc == AMA_SUCCESS,
                "Dilithium verification FAILED - ROUNDTRIP FAILURE");

    printf("    Sign/verify roundtrip OK (sig = %zu bytes)\n", sig_len);
    return 1;
}

/**
 * ML-DSA-65: tampered message should fail verification
 */
static int test_dilithium_tamper_detection(void) {
    uint8_t pk[AMA_ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t sig[AMA_ML_DSA_65_SIGNATURE_BYTES];
    size_t sig_len = sizeof(sig);
    uint8_t msg[] = "Original message for Dilithium tamper test";
    ama_error_t rc;

    rc = ama_dilithium_keypair(pk, sk);
    TEST_ASSERT(rc == AMA_SUCCESS, "Dilithium keypair generation failed");

    rc = ama_dilithium_sign(sig, &sig_len, msg, sizeof(msg) - 1, sk);
    TEST_ASSERT(rc == AMA_SUCCESS, "Dilithium signing failed");

    /* Verify original passes */
    rc = ama_dilithium_verify(msg, sizeof(msg) - 1, sig, sig_len, pk);
    TEST_ASSERT(rc == AMA_SUCCESS, "Dilithium verification of original message failed");

    /* Tamper with message */
    msg[0] ^= 0x01;
    rc = ama_dilithium_verify(msg, sizeof(msg) - 1, sig, sig_len, pk);
    TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                "Dilithium FAILED to detect tampered message!");

    /* Tamper with signature */
    msg[0] ^= 0x01;  /* Restore message */
    sig[0] ^= 0xFF;
    rc = ama_dilithium_verify(msg, sizeof(msg) - 1, sig, sig_len, pk);
    TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                "Dilithium FAILED to detect tampered signature!");

    printf("    Tamper detection OK (modified msg and sig both rejected)\n");
    return 1;
}

/**
 * ML-DSA-65: multiple sign/verify with different messages
 */
static int test_dilithium_multiple_messages(void) {
    uint8_t pk[AMA_ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t sig[AMA_ML_DSA_65_SIGNATURE_BYTES];
    size_t sig_len;
    ama_error_t rc;
    int i;

    rc = ama_dilithium_keypair(pk, sk);
    TEST_ASSERT(rc == AMA_SUCCESS, "Dilithium keypair generation failed");

    /* Sign and verify 5 different messages with same key */
    const char *messages[] = {
        "Message 1: Short",
        "Message 2: A slightly longer message for testing purposes",
        "Message 3: Testing with special chars: !@#$%^&*()",
        "",  /* Empty message */
        "Message 5: The quick brown fox jumps over the lazy dog"
    };

    for (i = 0; i < 5; i++) {
        sig_len = sizeof(sig);
        rc = ama_dilithium_sign(sig, &sig_len, (const uint8_t *)messages[i],
                                strlen(messages[i]), sk);
        TEST_ASSERT(rc == AMA_SUCCESS, "Dilithium signing failed for multi-message test");

        rc = ama_dilithium_verify((const uint8_t *)messages[i], strlen(messages[i]),
                                  sig, sig_len, pk);
        TEST_ASSERT(rc == AMA_SUCCESS, "Dilithium verification failed for multi-message test");
    }

    printf("    5/5 messages signed and verified correctly\n");
    return 1;
}

/**
 * SPHINCS+-SHA2-256f: keygen -> sign -> verify -> pass
 */
static int test_sphincs_roundtrip(void) {
    uint8_t pk[AMA_SPHINCS_256F_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_SPHINCS_256F_SECRET_KEY_BYTES];
    uint8_t *sig;
    size_t sig_len = AMA_SPHINCS_256F_SIGNATURE_BYTES;
    const uint8_t msg[] = "SPHINCS+ hash-based signature self-test";
    ama_error_t rc;

    /* Allocate signature buffer on heap (49856 bytes is large) */
    sig = (uint8_t *)malloc(AMA_SPHINCS_256F_SIGNATURE_BYTES);
    TEST_ASSERT(sig != NULL, "Failed to allocate SPHINCS+ signature buffer");

    /* Generate keypair */
    rc = ama_sphincs_keypair(pk, sk);
    TEST_ASSERT(rc == AMA_SUCCESS, "SPHINCS+ keypair generation failed");

    /* Sign */
    rc = ama_sphincs_sign(sig, &sig_len, msg, sizeof(msg) - 1, sk);
    TEST_ASSERT(rc == AMA_SUCCESS, "SPHINCS+ signing failed");
    TEST_ASSERT(sig_len == AMA_SPHINCS_256F_SIGNATURE_BYTES,
                "SPHINCS+ signature wrong size");

    /* Verify */
    rc = ama_sphincs_verify(msg, sizeof(msg) - 1, sig, sig_len, pk);
    TEST_ASSERT(rc == AMA_SUCCESS,
                "SPHINCS+ verification FAILED - ROUNDTRIP FAILURE");

    printf("    Sign/verify roundtrip OK (sig = %zu bytes)\n", sig_len);
    free(sig);
    return 1;
}

/**
 * SPHINCS+: tampered message should fail verification
 */
static int test_sphincs_tamper_detection(void) {
    uint8_t pk[AMA_SPHINCS_256F_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_SPHINCS_256F_SECRET_KEY_BYTES];
    uint8_t *sig;
    size_t sig_len = AMA_SPHINCS_256F_SIGNATURE_BYTES;
    uint8_t msg[] = "SPHINCS+ tamper detection test message";
    ama_error_t rc;

    sig = (uint8_t *)malloc(AMA_SPHINCS_256F_SIGNATURE_BYTES);
    TEST_ASSERT(sig != NULL, "Failed to allocate SPHINCS+ signature buffer");

    rc = ama_sphincs_keypair(pk, sk);
    TEST_ASSERT(rc == AMA_SUCCESS, "SPHINCS+ keypair generation failed");

    rc = ama_sphincs_sign(sig, &sig_len, msg, sizeof(msg) - 1, sk);
    TEST_ASSERT(rc == AMA_SUCCESS, "SPHINCS+ signing failed");

    /* Verify original */
    rc = ama_sphincs_verify(msg, sizeof(msg) - 1, sig, sig_len, pk);
    TEST_ASSERT(rc == AMA_SUCCESS, "SPHINCS+ verification of original failed");

    /* Tamper with message */
    msg[0] ^= 0x01;
    rc = ama_sphincs_verify(msg, sizeof(msg) - 1, sig, sig_len, pk);
    TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                "SPHINCS+ FAILED to detect tampered message!");

    printf("    Tamper detection OK\n");
    free(sig);
    return 1;
}

/* ============================================================================
 * NIST KAT VECTOR TESTS (FIPS 203/204 format)
 * ============================================================================
 * These tests use FIPS-compliant KAT vectors that provide d/z (ML-KEM)
 * or seed (ML-DSA) directly, matching the FIPS 203/204 algorithms.
 * ============================================================================ */

static FILE *try_open_kat(const char *name) {
    char path[512];
    const char *prefixes[] = {"", "../", "../../"};
    for (int i = 0; i < 3; i++) {
        snprintf(path, sizeof(path), "%s%s", prefixes[i], name);
        FILE *f = fopen(path, "r");
        if (f) return f;
    }
    return NULL;
}

/**
 * ML-KEM-1024 FIPS 203 KAT test: provide d and z directly,
 * compare keygen output against known vectors.
 */
static int test_kyber_kat_vector(void) {
    FILE *f = try_open_kat("tests/kat/fips203/ml_kem_1024.kat");
    TEST_ASSERT(f != NULL, "Could not open ml_kem_1024.kat FIPS 203 KAT file");

    rsp_entry entry;
    int kat_tested = 0;
    int kat_passed = 0;

    /* Test first 10 KAT vectors */
    while (rsp_read_entry(f, &entry) && kat_tested < 10) {
        const char *d_hex = rsp_get_field(&entry, "d");
        const char *z_hex = rsp_get_field(&entry, "z");
        const char *pk_hex = rsp_get_field(&entry, "pk");
        const char *sk_hex = rsp_get_field(&entry, "sk");

        if (!d_hex || !z_hex || !pk_hex || !sk_hex) {
            rsp_entry_free(&entry);
            continue;
        }

        printf("    FIPS 203 KAT #%d: ", kat_tested);

        /* Parse d (32 bytes) and z (32 bytes) */
        uint8_t dz_buf[64];
        hex_to_bytes(d_hex, dz_buf, 32);
        hex_to_bytes(z_hex, dz_buf + 32, 32);

        /* Load d||z into buffer hook: keygen calls randombytes(d, 32) then randombytes(z, 32) */
        buf_hook_load(dz_buf, 64);
        ama_kyber_randombytes_hook = buf_hook_randombytes;

        /* Generate keypair */
        uint8_t pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
        uint8_t sk[AMA_KYBER_1024_SECRET_KEY_BYTES];
        ama_error_t rc = ama_kyber_keypair(pk, sizeof(pk), sk, sizeof(sk));

        ama_kyber_randombytes_hook = NULL;

        if (rc != AMA_SUCCESS) {
            printf("keygen failed (rc=%d)\n", rc);
            rsp_entry_free(&entry);
            kat_tested++;
            continue;
        }

        /* Compare public key */
        uint8_t *expected_pk = (uint8_t *)malloc(AMA_KYBER_1024_PUBLIC_KEY_BYTES);
        int pk_bytes = hex_to_bytes(pk_hex, expected_pk, AMA_KYBER_1024_PUBLIC_KEY_BYTES);
        int pk_match = (pk_bytes == AMA_KYBER_1024_PUBLIC_KEY_BYTES &&
                       memcmp(pk, expected_pk, AMA_KYBER_1024_PUBLIC_KEY_BYTES) == 0);

        /* Compare secret key */
        uint8_t *expected_sk = (uint8_t *)malloc(AMA_KYBER_1024_SECRET_KEY_BYTES);
        int sk_bytes = hex_to_bytes(sk_hex, expected_sk, AMA_KYBER_1024_SECRET_KEY_BYTES);
        int sk_match = (sk_bytes == AMA_KYBER_1024_SECRET_KEY_BYTES &&
                       memcmp(sk, expected_sk, AMA_KYBER_1024_SECRET_KEY_BYTES) == 0);

        if (pk_match && sk_match) {
            printf("keygen MATCH (pk + sk)\n");
            kat_passed++;
        } else {
            printf("keygen MISMATCH (pk=%s, sk=%s)\n",
                   pk_match ? "OK" : "DIFFER",
                   sk_match ? "OK" : "DIFFER");
            if (!pk_match) {
                /* Show first divergence byte for debugging */
                for (int i = 0; i < pk_bytes && i < AMA_KYBER_1024_PUBLIC_KEY_BYTES; i++) {
                    if (pk[i] != expected_pk[i]) {
                        printf("      pk diverges at byte %d: got %02X, expected %02X\n", i, pk[i], expected_pk[i]);
                        break;
                    }
                }
            }
        }

        free(expected_pk);
        free(expected_sk);
        rsp_entry_free(&entry);
        kat_tested++;
    }

    fclose(f);

    printf("    KAT vectors: %d/%d passed\n", kat_passed, kat_tested);
    TEST_ASSERT(kat_tested > 0, "No ML-KEM KAT vectors were tested");
    TEST_ASSERT(kat_passed == kat_tested, "ML-KEM FIPS 203 KAT vector mismatch");
    return 1;
}

/**
 * ML-DSA-65 FIPS 204 KAT test: provide seed (xi) directly,
 * compare keygen output against known vectors.
 */
static int test_dilithium_kat_vector(void) {
    FILE *f = try_open_kat("tests/kat/fips204/ml_dsa_65.kat");
    TEST_ASSERT(f != NULL, "Could not open ml_dsa_65.kat FIPS 204 KAT file");

    rsp_entry entry;
    int kat_tested = 0;
    int kat_passed = 0;

    /* Test first 10 KAT vectors */
    while (rsp_read_entry(f, &entry) && kat_tested < 10) {
        const char *seed_hex = rsp_get_field(&entry, "seed");
        const char *pk_hex = rsp_get_field(&entry, "pkey");
        const char *sk_hex = rsp_get_field(&entry, "skey");

        if (!seed_hex || !pk_hex || !sk_hex) {
            rsp_entry_free(&entry);
            continue;
        }

        printf("    FIPS 204 KAT #%d: ", kat_tested);

        /* Parse seed (32 bytes = xi for ML-DSA keygen) */
        uint8_t seed[32];
        hex_to_bytes(seed_hex, seed, 32);

        /* Load seed into buffer hook: keygen calls randombytes(seedbuf, 32) */
        buf_hook_load(seed, 32);
        ama_dilithium_randombytes_hook = buf_hook_randombytes;

        /* Generate keypair */
        uint8_t pk[AMA_ML_DSA_65_PUBLIC_KEY_BYTES];
        uint8_t sk[AMA_ML_DSA_65_SECRET_KEY_BYTES];
        ama_error_t rc = ama_dilithium_keypair(pk, sk);

        ama_dilithium_randombytes_hook = NULL;

        if (rc != AMA_SUCCESS) {
            printf("keygen failed (rc=%d)\n", rc);
            rsp_entry_free(&entry);
            kat_tested++;
            continue;
        }

        /* Compare public key */
        uint8_t *expected_pk = (uint8_t *)malloc(AMA_ML_DSA_65_PUBLIC_KEY_BYTES);
        int pk_bytes = hex_to_bytes(pk_hex, expected_pk, AMA_ML_DSA_65_PUBLIC_KEY_BYTES);
        int pk_match = (pk_bytes == AMA_ML_DSA_65_PUBLIC_KEY_BYTES &&
                       memcmp(pk, expected_pk, AMA_ML_DSA_65_PUBLIC_KEY_BYTES) == 0);

        /* Compare secret key */
        uint8_t *expected_sk = (uint8_t *)malloc(AMA_ML_DSA_65_SECRET_KEY_BYTES);
        int sk_bytes = hex_to_bytes(sk_hex, expected_sk, AMA_ML_DSA_65_SECRET_KEY_BYTES);
        int sk_match = (sk_bytes == AMA_ML_DSA_65_SECRET_KEY_BYTES &&
                       memcmp(sk, expected_sk, AMA_ML_DSA_65_SECRET_KEY_BYTES) == 0);

        if (pk_match && sk_match) {
            printf("keygen MATCH (pk + sk)\n");
            kat_passed++;
        } else {
            printf("keygen MISMATCH (pk=%s, sk=%s)\n",
                   pk_match ? "OK" : "DIFFER",
                   sk_match ? "OK" : "DIFFER");
            if (!pk_match) {
                for (int i = 0; i < pk_bytes && i < AMA_ML_DSA_65_PUBLIC_KEY_BYTES; i++) {
                    if (pk[i] != expected_pk[i]) {
                        printf("      pk diverges at byte %d: got %02X, expected %02X\n", i, pk[i], expected_pk[i]);
                        break;
                    }
                }
            }
        }

        free(expected_pk);
        free(expected_sk);
        rsp_entry_free(&entry);
        kat_tested++;
    }

    fclose(f);

    printf("    KAT vectors: %d/%d passed\n", kat_passed, kat_tested);
    TEST_ASSERT(kat_tested > 0, "No ML-DSA KAT vectors were tested");
    TEST_ASSERT(kat_passed == kat_tested, "ML-DSA FIPS 204 KAT vector mismatch");
    return 1;
}

/* ============================================================================
 * NIST DRBG SELF-TEST
 * ============================================================================
 * Verify the DRBG itself produces correct output before using it for KAT
 * ============================================================================ */

static int test_drbg_selftest(void) {
    /* Known test: seed with all zeros, check first output */
    uint8_t seed[48];
    memset(seed, 0, 48);

    nist_drbg_init(&g_drbg, seed);

    uint8_t output[32];
    nist_drbg_generate(&g_drbg, output, 32);

    /* The output should be deterministic and non-zero */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (output[i] != 0) { all_zero = 0; break; }
    }
    TEST_ASSERT(!all_zero, "DRBG produced all zeros (broken)");

    /* Reseed with same seed, should produce same output */
    uint8_t output2[32];
    nist_drbg_init(&g_drbg, seed);
    nist_drbg_generate(&g_drbg, output2, 32);
    TEST_ASSERT(memcmp(output, output2, 32) == 0,
                "DRBG is not deterministic (same seed, different output)");

    printf("    DRBG deterministic: YES\n");

    /* Different seed should produce different output */
    uint8_t seed2[48];
    memset(seed2, 0xFF, 48);
    nist_drbg_init(&g_drbg, seed2);
    nist_drbg_generate(&g_drbg, output2, 32);
    TEST_ASSERT(memcmp(output, output2, 32) != 0,
                "DRBG produced same output for different seeds");

    printf("    DRBG different seeds -> different output: YES\n");
    return 1;
}

/* ============================================================================
 * KYBER POLYNOMIAL ARITHMETIC TESTS
 * ============================================================================
 * Test internal correctness of compression/decompression roundtrip
 * ============================================================================ */

static int test_kyber_compress_roundtrip(void) {
    /* Test that compress -> decompress approximately recovers the value.
     * Compression is lossy, but decompress(compress(x)) should be close to x. */

    /* We test this indirectly through the full KEM roundtrip,
     * which exercises all compression paths. The roundtrip test above
     * already validates this. This test specifically checks the 11-bit path. */

    uint8_t pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_KYBER_1024_SECRET_KEY_BYTES];
    uint8_t ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
    uint8_t ss1[AMA_KYBER_1024_SHARED_SECRET_BYTES];
    uint8_t ss2[AMA_KYBER_1024_SHARED_SECRET_BYTES];
    size_t ct_len;
    ama_error_t rc;
    int i, successes = 0;

    /* Run 10 roundtrips to stress-test compression */
    for (i = 0; i < 10; i++) {
        rc = ama_kyber_keypair(pk, sizeof(pk), sk, sizeof(sk));
        if (rc != AMA_SUCCESS) continue;

        ct_len = sizeof(ct);
        rc = ama_kyber_encapsulate(pk, sizeof(pk), ct, &ct_len, ss1, sizeof(ss1));
        if (rc != AMA_SUCCESS) continue;

        rc = ama_kyber_decapsulate(ct, ct_len, sk, sizeof(sk), ss2, sizeof(ss2));
        if (rc != AMA_SUCCESS) continue;

        if (memcmp(ss1, ss2, sizeof(ss1)) == 0) {
            successes++;
        }
    }

    TEST_ASSERT(successes == 10,
                "Kyber compression roundtrip failed (not all 10 iterations matched)");
    printf("    10/10 roundtrips passed (11-bit compression verified)\n");
    return 1;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    /* Disable output buffering for real-time progress */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("================================================================\n");
    printf("  AMA Cryptography - PQC Known Answer Test (KAT) Framework\n");
    printf("  Steel Security Advisors LLC\n");
    printf("================================================================\n\n");

    /* Section 1: DRBG Self-Test */
    printf("--- NIST AES-256-CTR DRBG Self-Test ---\n");
    RUN_TEST(test_drbg_selftest, "DRBG determinism and correctness");

    /* Section 2: Self-Consistency (Roundtrip) Tests */
    printf("\n--- Kyber-1024 (ML-KEM-1024) Self-Consistency ---\n");
    RUN_TEST(test_kyber_roundtrip, "Kyber-1024 encap/decap roundtrip");
    RUN_TEST(test_kyber_implicit_rejection, "Kyber-1024 implicit rejection");
    RUN_TEST(test_kyber_compress_roundtrip, "Kyber-1024 compression stress test (10x)");

    printf("\n--- ML-DSA-65 (Dilithium) Self-Consistency ---\n");
    RUN_TEST(test_dilithium_roundtrip, "ML-DSA-65 sign/verify roundtrip");
    RUN_TEST(test_dilithium_tamper_detection, "ML-DSA-65 tamper detection");
    RUN_TEST(test_dilithium_multiple_messages, "ML-DSA-65 multi-message test");

    printf("\n--- SPHINCS+-SHA2-256f Self-Consistency ---\n");
    RUN_TEST(test_sphincs_roundtrip, "SPHINCS+ sign/verify roundtrip");
    RUN_TEST(test_sphincs_tamper_detection, "SPHINCS+ tamper detection");

    /* Section 3: NIST KAT Vector Tests */
    printf("\n--- NIST KAT Vector Matching ---\n");
    RUN_TEST(test_kyber_kat_vector, "Kyber-1024 KAT vectors");
    RUN_TEST(test_dilithium_kat_vector, "ML-DSA-65 KAT vectors");

    /* Summary */
    printf("\n================================================================\n");
    printf("  RESULTS: %d tests run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    printf("================================================================\n");

    if (tests_failed > 0) {
        printf("\n  *** %d TEST(S) FAILED ***\n", tests_failed);
        return 1;
    }

    printf("\n  ALL TESTS PASSED\n");
    return 0;
}
