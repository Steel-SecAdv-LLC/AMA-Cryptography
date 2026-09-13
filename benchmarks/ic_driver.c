/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Deterministic instruction-count driver.
 *
 * Why this exists
 * ---------------
 * `benchmarks/baseline.json` gates performance on `operations_per_second`
 * measured with `time.perf_counter()` on a shared CI runner.  That number is
 * not a property of this library.  `benchmarks/benchmark_runner.py` records
 * the proof in its own docstring: one UNCHANGED binary measured 917, 1845 and
 * 3086 ops/sec across three runs — a 3.4x spread with no code change.  The
 * tolerances were then widened to 45% to stop the gate flapping, which is the
 * same as switching it off: a 45% band cannot detect a 30% regression.
 *
 * Retired instruction count under callgrind is a property of the binary and
 * its input, not of the host.  Same build, same input, same number — on a
 * loaded runner, a quiet one, or a different CPU entirely.  That makes a 2%
 * threshold meaningful where 45% was decoration.
 *
 * How a measurement is taken
 * --------------------------
 * This driver runs ONE named operation exactly N times and does nothing else.
 * Per-operation cost is the DIFFERENCE
 *
 *     (Ir(2N) - Ir(N)) / N
 *
 * so process start-up, dynamic loading, key setup and the dispatcher's own
 * initialisation cancel exactly instead of being estimated and subtracted.
 *
 * Determinism requirements, each load-bearing
 * -------------------------------------------
 * 1. Every input is fixed.  No system RNG reaches a measured loop; key
 *    material is either a compile-time pattern or derived from a fixed seed
 *    through the `_from_seed` entry points.
 * 2. All setup happens BEFORE the loop, so it lands in both Ir(N) and Ir(2N)
 *    and cancels.
 * 3. The caller must set `AMA_DISPATCH_NO_AUTOTUNE=1`.  This is not optional
 *    and `measure_instruction_counts.py` enforces it.  The dispatcher's
 *    auto-tune microbenchmarks SIMD kernels against scalar at first use and
 *    demotes a slot that reads slower; the verdict depends on host load, so
 *    with auto-tune live the binary executes DIFFERENT code between runs and
 *    no count is reproducible.  Measured on an AVX-512 host: the auto-tune
 *    costs 2,600,710,540 instructions on the first SHA3 call, against 53,664
 *    for the call itself.
 * 4. A `volatile` sink consumes one output byte per iteration so the loop
 *    cannot be optimised away.
 *
 * Operations whose cost depends on secret or sampled data — ML-DSA signing
 * rejection-samples until a candidate passes — are not silently excluded
 * here.  The measurement tool runs every operation twice and refuses to
 * record a baseline for any that does not reproduce, so a non-deterministic
 * operation fails loudly rather than being baselined at whatever it happened
 * to cost.
 *
 * Dispatch fingerprint
 * --------------------
 * A count is only comparable against a baseline measured with the SAME
 * kernels wired.  An AVX-512 host and an AVX2 host run different code and
 * legitimately produce different counts, so ``--fingerprint`` emits the
 * active dispatch configuration and the gate keys its baseline on it,
 * refusing to compare across configurations rather than reporting a
 * regression that is really a different machine.
 *
 * With auto-tune disabled the wired kernels are a deterministic function of
 * the detected tiers and the build, which is what makes the detected tiers a
 * sound key.  With auto-tune live they are not, which is the other reason
 * the measurement tool pins it off.
 *
 * Usage: ic_driver <operation> <iterations>
 *        ic_driver --list
 *        ic_driver --fingerprint
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ama_cryptography.h"
#include "ama_dispatch.h"

/* ------------------------------------------------------------------
 * Per-primitive availability.
 *
 * The A/B comparison in ci-build-test.yml builds this ONE driver source
 * against two libraries: the head build and the merge-base build. A base
 * that predates a primitive does not export it, and the link fails --
 * measured: `main` at 2dcef5c has no `ama_sha512`, which this branch
 * added, so the base driver would not build at all and the whole A/B lane
 * would be dead on arrival.
 *
 * benchmarks/ic_symbol_flags.py reads the target library with `nm` and
 * emits -DAMA_IC_HAVE_<FEATURE>=0 for whatever is absent. Everything
 * defaults to present, so a normal build needs no flags and a missing
 * primitive is opted OUT explicitly rather than silently skipped.
 * ------------------------------------------------------------------ */
#ifndef AMA_IC_HAVE_AES_GCM
#define AMA_IC_HAVE_AES_GCM 1
#endif
#ifndef AMA_IC_HAVE_CHACHA
#define AMA_IC_HAVE_CHACHA 1
#endif
#ifndef AMA_IC_HAVE_DILITHIUM
#define AMA_IC_HAVE_DILITHIUM 1
#endif
#ifndef AMA_IC_HAVE_ED25519
#define AMA_IC_HAVE_ED25519 1
#endif
#ifndef AMA_IC_HAVE_HKDF
#define AMA_IC_HAVE_HKDF 1
#endif
#ifndef AMA_IC_HAVE_HMAC_SHA3_256
#define AMA_IC_HAVE_HMAC_SHA3_256 1
#endif
#ifndef AMA_IC_HAVE_KYBER
#define AMA_IC_HAVE_KYBER 1
#endif
#ifndef AMA_IC_HAVE_SECP256K1
#define AMA_IC_HAVE_SECP256K1 1
#endif
#ifndef AMA_IC_HAVE_SHA3_256
#define AMA_IC_HAVE_SHA3_256 1
#endif
#ifndef AMA_IC_HAVE_SHA3_512
#define AMA_IC_HAVE_SHA3_512 1
#endif
#ifndef AMA_IC_HAVE_SHA512
#define AMA_IC_HAVE_SHA512 1
#endif
#ifndef AMA_IC_HAVE_X25519
#define AMA_IC_HAVE_X25519 1
#endif


/* Deterministic filler: a fixed affine pattern, never a PRNG. */
#define FIXED_FILL(buf, tag)                                                  \
    do {                                                                      \
        for (size_t _i = 0; _i < sizeof(buf); _i++) {                         \
            (buf)[_i] = (uint8_t)((_i * 31u) + (unsigned)(tag));              \
        }                                                                     \
    } while (0)

/* 1 KiB, matching the message size benchmarks/baseline.json documents for
 * the hash and AEAD rows, so the two gates describe the same work. */
#define MSG_BYTES 1024

static const char *const OPERATIONS[] = {
#if AMA_IC_HAVE_SHA3_256
    "sha3_256",
#endif
#if AMA_IC_HAVE_SHA3_512
    "sha3_512",
#endif
#if AMA_IC_HAVE_SHA512
    "sha512",
#endif
#if AMA_IC_HAVE_HMAC_SHA3_256
    "hmac_sha3_256",
#endif
#if AMA_IC_HAVE_HKDF
    "hkdf_derive",
#endif
#if AMA_IC_HAVE_ED25519
    "ed25519_keygen",
#endif
#if AMA_IC_HAVE_ED25519
    "ed25519_sign",
#endif
#if AMA_IC_HAVE_ED25519
    "ed25519_verify",
#endif
#if AMA_IC_HAVE_X25519
    "x25519_scalarmult",
#endif
#if AMA_IC_HAVE_AES_GCM
    "aes_256_gcm_encrypt",
#endif
#if AMA_IC_HAVE_CHACHA
    "chacha20poly1305_encrypt",
#endif
#if AMA_IC_HAVE_SECP256K1
    "secp256k1_ecdsa_sign",
#endif
#if AMA_IC_HAVE_KYBER
    "kyber_keygen",
#endif
#if AMA_IC_HAVE_KYBER
    "kyber_encapsulate",
#endif
#if AMA_IC_HAVE_KYBER
    "kyber_decapsulate",
#endif
#if AMA_IC_HAVE_DILITHIUM
    "dilithium_keygen",
#endif
#if AMA_IC_HAVE_DILITHIUM
    "dilithium_sign",
#endif
#if AMA_IC_HAVE_DILITHIUM
    "dilithium_verify",
#endif
    NULL
};

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--fingerprint") == 0) {
        const ama_dispatch_info_t *info = ama_get_dispatch_info();
        if (!info) {
            fprintf(stderr, "dispatch info unavailable\n");
            return 2;
        }
        /* Field order is fixed here rather than taken from the struct so a
         * reordered struct cannot silently change the key and invalidate
         * every recorded baseline without anyone noticing. */
        printf("arch=%s sha3=%s kyber=%s dilithium=%s sphincs=%s aes_gcm=%s "
               "ed25519=%s chacha20poly1305=%s argon2=%s x25519=%s\n",
               info->arch_name ? info->arch_name : "unknown",
               ama_impl_level_name(info->sha3),
               ama_impl_level_name(info->kyber),
               ama_impl_level_name(info->dilithium),
               ama_impl_level_name(info->sphincs),
               ama_impl_level_name(info->aes_gcm),
               ama_impl_level_name(info->ed25519),
               ama_impl_level_name(info->chacha20poly1305),
               ama_impl_level_name(info->argon2),
               ama_impl_level_name(info->x25519));
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--list") == 0) {
        for (const char *const *op = OPERATIONS; *op; op++) {
            printf("%s\n", *op);
        }
        return 0;
    }
    if (argc != 3) {
        fprintf(stderr, "usage: %s <operation> <iterations>\n", argv[0]);
        fprintf(stderr, "       %s --list\n", argv[0]);
        fprintf(stderr, "       %s --fingerprint\n", argv[0]);
        return 2;
    }

    const char *op = argv[1];
    char *end = NULL;
    long iterations = strtol(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || iterations < 0) {
        fprintf(stderr, "iterations must be a non-negative integer\n");
        return 2;
    }

    /* ---- fixed inputs -------------------------------------------------- */
    static uint8_t message[MSG_BYTES];
    static uint8_t key32[32], nonce12[12], salt32[32], info16[16];
    FIXED_FILL(message, 0x11);
    FIXED_FILL(key32,   0x22);
    FIXED_FILL(nonce12, 0x33);
    FIXED_FILL(salt32,  0x44);
    FIXED_FILL(info16,  0x55);

    static uint8_t digest32[32], digest64[64], okm32[32], tag16[16];
    static uint8_t ciphertext[MSG_BYTES];

    static uint8_t ed_pk[32], ed_sk[64], ed_sig[64];
    static uint8_t x_ours[32], x_theirs[32], x_shared[32];
    FIXED_FILL(x_ours,   0x66);
    FIXED_FILL(x_theirs, 0x77);

    static uint8_t ec_sig[72];
    static uint8_t ec_priv[32], ec_hash[32];
    FIXED_FILL(ec_priv, 0x01);   /* in range for secp256k1 */
    FIXED_FILL(ec_hash, 0x88);

    static uint8_t seed_d[32], seed_z[32], seed_xi[32];
    FIXED_FILL(seed_d,  0x99);
    FIXED_FILL(seed_z,  0xAA);
    FIXED_FILL(seed_xi, 0xBB);

    static uint8_t k_pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
    static uint8_t k_sk[AMA_KYBER_1024_SECRET_KEY_BYTES];
    static uint8_t k_ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
    static uint8_t k_ss[AMA_KYBER_1024_SHARED_SECRET_BYTES];
    size_t k_ct_len = sizeof k_ct;

    static uint8_t d_pk[AMA_ML_DSA_87_PUBLIC_KEY_BYTES];
    static uint8_t d_sk[AMA_ML_DSA_87_SECRET_KEY_BYTES];
    static uint8_t d_sig[AMA_ML_DSA_87_SIGNATURE_BYTES];
    size_t d_sig_len = sizeof d_sig;

    /* ---- setup, outside the measured loop so it cancels in the difference */
#if AMA_IC_HAVE_ED25519
    if (ama_ed25519_keypair(ed_pk, ed_sk) != AMA_SUCCESS) return 1;
    if (ama_ed25519_sign(ed_sig, message, sizeof message, ed_sk) != AMA_SUCCESS) return 1;
#endif
#if AMA_IC_HAVE_KYBER
    if (ama_kyber_keypair_from_seed(seed_d, seed_z, k_pk, k_sk) != AMA_SUCCESS) return 1;
    if (ama_kyber_encapsulate(k_pk, sizeof k_pk, k_ct, &k_ct_len,
                              k_ss, sizeof k_ss) != AMA_SUCCESS) return 1;
#endif
#if AMA_IC_HAVE_DILITHIUM
    if (ama_dilithium_keypair_from_seed(seed_xi, d_pk, d_sk) != AMA_SUCCESS) return 1;
    if (ama_dilithium_sign(d_sig, &d_sig_len, message, sizeof message, d_sk) != AMA_SUCCESS) {
        return 1;
    }
#endif

    /* Resolve the operation once; a strcmp chain inside the loop would be
     * measured as part of the operation. */
    enum {
        OP_SHA3_256, OP_SHA3_512, OP_SHA512, OP_HMAC_SHA3_256, OP_HKDF,
        OP_ED_KEYGEN, OP_ED_SIGN, OP_ED_VERIFY, OP_X25519,
        OP_AES_GCM, OP_CHACHA, OP_ECDSA_SIGN,
        OP_KYBER_KEYGEN, OP_KYBER_ENCAP, OP_KYBER_DECAP,
        OP_DIL_KEYGEN, OP_DIL_SIGN, OP_DIL_VERIFY, OP_UNKNOWN
    } which = OP_UNKNOWN;

#if AMA_IC_HAVE_SHA3_256
    if (!strcmp(op, "sha3_256")) which = OP_SHA3_256;
#endif
#if AMA_IC_HAVE_SHA3_512
    if (!strcmp(op, "sha3_512")) which = OP_SHA3_512;
#endif
#if AMA_IC_HAVE_SHA512
    if (!strcmp(op, "sha512")) which = OP_SHA512;
#endif
#if AMA_IC_HAVE_HMAC_SHA3_256
    if (!strcmp(op, "hmac_sha3_256")) which = OP_HMAC_SHA3_256;
#endif
#if AMA_IC_HAVE_HKDF
    if (!strcmp(op, "hkdf_derive")) which = OP_HKDF;
#endif
#if AMA_IC_HAVE_ED25519
    if (!strcmp(op, "ed25519_keygen")) which = OP_ED_KEYGEN;
#endif
#if AMA_IC_HAVE_ED25519
    if (!strcmp(op, "ed25519_sign")) which = OP_ED_SIGN;
#endif
#if AMA_IC_HAVE_ED25519
    if (!strcmp(op, "ed25519_verify")) which = OP_ED_VERIFY;
#endif
#if AMA_IC_HAVE_X25519
    if (!strcmp(op, "x25519_scalarmult")) which = OP_X25519;
#endif
#if AMA_IC_HAVE_AES_GCM
    if (!strcmp(op, "aes_256_gcm_encrypt")) which = OP_AES_GCM;
#endif
#if AMA_IC_HAVE_CHACHA
    if (!strcmp(op, "chacha20poly1305_encrypt")) which = OP_CHACHA;
#endif
#if AMA_IC_HAVE_SECP256K1
    if (!strcmp(op, "secp256k1_ecdsa_sign")) which = OP_ECDSA_SIGN;
#endif
#if AMA_IC_HAVE_KYBER
    if (!strcmp(op, "kyber_keygen")) which = OP_KYBER_KEYGEN;
#endif
#if AMA_IC_HAVE_KYBER
    if (!strcmp(op, "kyber_encapsulate")) which = OP_KYBER_ENCAP;
#endif
#if AMA_IC_HAVE_KYBER
    if (!strcmp(op, "kyber_decapsulate")) which = OP_KYBER_DECAP;
#endif
#if AMA_IC_HAVE_DILITHIUM
    if (!strcmp(op, "dilithium_keygen")) which = OP_DIL_KEYGEN;
#endif
#if AMA_IC_HAVE_DILITHIUM
    if (!strcmp(op, "dilithium_sign")) which = OP_DIL_SIGN;
#endif
#if AMA_IC_HAVE_DILITHIUM
    if (!strcmp(op, "dilithium_verify")) which = OP_DIL_VERIFY;
#endif
    if (which == OP_UNKNOWN) {
        fprintf(stderr,
                "operation not available in this build: %s (try --list)\n", op);
        return 2;
    }

    volatile uint8_t sink = 0;

    for (long i = 0; i < iterations; i++) {
        size_t ct_len = sizeof k_ct;
        size_t sig_len = sizeof d_sig;
        size_t ecl = sizeof ec_sig;

        switch (which) {
#if AMA_IC_HAVE_SHA3_256
        case OP_SHA3_256:
            ama_sha3_256(message, sizeof message, digest32);
            sink ^= digest32[0]; break;
#endif
#if AMA_IC_HAVE_SHA3_512
        case OP_SHA3_512:
            ama_sha3_512(message, sizeof message, digest64);
            sink ^= digest64[0]; break;
#endif
#if AMA_IC_HAVE_SHA512
        case OP_SHA512:
            ama_sha512(message, sizeof message, digest64);
            sink ^= digest64[0]; break;
#endif
#if AMA_IC_HAVE_HMAC_SHA3_256
        case OP_HMAC_SHA3_256:
            ama_hmac_sha3_256(key32, sizeof key32, message, sizeof message, digest32);
            sink ^= digest32[0]; break;
#endif
#if AMA_IC_HAVE_HKDF
        case OP_HKDF:
            ama_hkdf(salt32, sizeof salt32, key32, sizeof key32,
                     info16, sizeof info16, okm32, sizeof okm32);
            sink ^= okm32[0]; break;
#endif
#if AMA_IC_HAVE_ED25519
        case OP_ED_KEYGEN:
            ama_ed25519_keypair(ed_pk, ed_sk);
            sink ^= ed_pk[0]; break;
#endif
#if AMA_IC_HAVE_ED25519
        case OP_ED_SIGN:
            ama_ed25519_sign(ed_sig, message, sizeof message, ed_sk);
            sink ^= ed_sig[0]; break;
#endif
#if AMA_IC_HAVE_ED25519
        case OP_ED_VERIFY:
            ama_ed25519_verify(ed_sig, message, sizeof message, ed_pk);
            sink ^= ed_sig[0]; break;
#endif
#if AMA_IC_HAVE_X25519
        case OP_X25519:
            ama_x25519_key_exchange(x_shared, x_ours, x_theirs);
            sink ^= x_shared[0]; break;
#endif
#if AMA_IC_HAVE_AES_GCM
        case OP_AES_GCM:
            ama_aes256_gcm_encrypt(key32, nonce12, message, sizeof message,
                                   NULL, 0, ciphertext, tag16);
            sink ^= tag16[0]; break;
#endif
#if AMA_IC_HAVE_CHACHA
        case OP_CHACHA:
            ama_chacha20poly1305_encrypt(key32, nonce12, message, sizeof message,
                                         NULL, 0, ciphertext, tag16);
            sink ^= tag16[0]; break;
#endif
#if AMA_IC_HAVE_SECP256K1
        case OP_ECDSA_SIGN:
            ama_secp256k1_ecdsa_sign(ec_sig, &ecl, ec_hash, ec_priv);
            sink ^= ec_sig[0]; break;
#endif
#if AMA_IC_HAVE_KYBER
        case OP_KYBER_KEYGEN:
            ama_kyber_keypair_from_seed(seed_d, seed_z, k_pk, k_sk);
            sink ^= k_pk[0]; break;
#endif
#if AMA_IC_HAVE_KYBER
        case OP_KYBER_ENCAP:
            ama_kyber_encapsulate(k_pk, sizeof k_pk, k_ct, &ct_len, k_ss, sizeof k_ss);
            sink ^= k_ss[0]; break;
#endif
#if AMA_IC_HAVE_KYBER
        case OP_KYBER_DECAP:
            ama_kyber_decapsulate(k_ct, sizeof k_ct, k_sk, sizeof k_sk,
                                  k_ss, sizeof k_ss);
            sink ^= k_ss[0]; break;
#endif
#if AMA_IC_HAVE_DILITHIUM
        case OP_DIL_KEYGEN:
            ama_dilithium_keypair_from_seed(seed_xi, d_pk, d_sk);
            sink ^= d_pk[0]; break;
#endif
#if AMA_IC_HAVE_DILITHIUM
        case OP_DIL_SIGN:
            ama_dilithium_sign(d_sig, &sig_len, message, sizeof message, d_sk);
            sink ^= d_sig[0]; break;
#endif
#if AMA_IC_HAVE_DILITHIUM
        case OP_DIL_VERIFY:
            ama_dilithium_verify(message, sizeof message, d_sig, d_sig_len, d_pk);
            sink ^= d_sig[0]; break;
#endif
        case OP_UNKNOWN:
        default:
            return 2;
        }
        (void)ct_len; (void)sig_len; (void)ecl;
    }

    /* Printed so the sink is observably used; callgrind measures the loop,
     * and this line is identical at N and 2N so it cancels. */
    printf("%s iterations=%ld sink=%02x\n", op, iterations, (unsigned)sink);
    return 0;
}
