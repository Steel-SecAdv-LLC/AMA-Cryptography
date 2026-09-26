/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_csprng_failure_residue.c
 * @brief A failed CSPRNG draw leaves none of its output on the stack
 *        (INVARIANT-6).
 *
 * `ama_randombytes` is not all-or-nothing.  Its getrandom(2) and
 * getentropy(3) paths loop, advancing an offset, and return an error after
 * earlier iterations have already written CSPRNG output into the caller's
 * buffer.  Output drawn for a seed, a message or a randomizer is secret the
 * moment it is written, so the exit that follows a failed draw must scrub
 * the buffer exactly as the normal exit does.
 *
 * Eight such exits did not, measured 2026-09-26 with this probe: the seed
 * buffers of `ama_slhdsa_keygen` and the legacy `ama_sphincs_keypair`, the
 * hedged randomizer of `ama_slhdsa_sign` and `ama_sphincs_sign`, ML-KEM key
 * generation's `d`, ML-KEM encapsulation's `m` (the value the shared secret
 * is derived from), ML-DSA key generation's `xi`, and `ama_x25519_keypair`,
 * which draws straight into the caller's `secret_key` and returned the error
 * with that buffer holding the draw.  `ama_nistp.c`'s hedged signer and
 * `ama_core.c`'s Ed25519 and hybrid key generation already scrubbed on this
 * exit; the others had not followed them.  Every other CSPRNG call in
 * `src/c` was read in the same sweep and already scrubs on failure.  Until 2026-09-26 the SLH-DSA FIPS 205 entry points could not
 * be driven down this exit at all, because only the legacy pair consulted
 * the test CSPRNG hook.
 *
 * THE PROBE.  Each test hook here writes a known needle into the buffer it
 * is handed and then reports failure -- the partial-draw shape at its worst,
 * with every octet written.  The entry point is called through
 * `residue_probe.h` (poison, call below a GAP at the same depth, scan the
 * poisoned bytes); a hit is the needle left in the dead frame of the entry
 * point that owned the buffer.  The hook writes the needle only into the
 * buffer it is given, so the hook's own frame is not a source: every
 * verdict below reads 0 on the fixed tree.
 *
 * WHY THE TEST ARCHIVE, not the shared library the other two probes link.
 * The hooks exist only under AMA_TESTING_MODE.  The concern recorded at
 * `add_ama_residue_probe` -- LTO re-optimising the primitive with the
 * harness until the probed frame is not the shipped one -- does not reach
 * this needle: the buffer's address is passed to an indirect call, so the
 * buffer must exist in memory and the hook's writes cannot be elided.
 *
 * X25519's buffer is the caller's, not a dead frame, so its verdict reads
 * that buffer after the refusal as well as scanning the stack.
 *
 * MUTATION RECORD (AGENTS.md section 6.2; gcc 13.3.0, Release, x86-64).
 * Deleting any one of the eight scrubs fails exactly its own verdict and no
 * other: 6 hits for each SLH-DSA seed buffer (3n = 96 octets), 2 for each
 * randomizer and for ML-KEM's `d` and `m` and ML-DSA's `xi` (32 octets), per
 * parameter set, and 2 in X25519's `secret_key`.  Each verdict is a PIN.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "ama_cryptography.h"

#include "residue_probe.h"

#if !AMA_PROBE_IS_INSTRUMENTED

extern ama_error_t (*ama_kyber_randombytes_hook)(uint8_t *buf, size_t len);
extern ama_error_t (*ama_dilithium_randombytes_hook)(uint8_t *buf, size_t len);
extern ama_error_t (*ama_sphincs_randombytes_hook)(uint8_t *buf, size_t len);
extern ama_error_t (*ama_x25519_randombytes_hook)(uint8_t *buf, size_t len);

static int checks = 0;
static int failures = 0;

#define CHECK(cond, msg) do {                                    \
    checks++;                                                    \
    if (!(cond)) {                                               \
        failures++;                                              \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); \
    }                                                            \
} while (0)

/* What each hook writes and each verdict searches for.  Sixteen octets, so
 * a 32-octet draw holds it twice and a 96-octet one six times. */
#define NEEDLE_BYTES 16u
static uint8_t g_needle[NEEDLE_BYTES];

/* What the control plants.  Never the needle: see THE SENTINEL in
 * residue_probe.h. */
static uint8_t g_sentinel[32];

/* Outputs live outside the probed stack. */
static uint8_t g_pk[4096], g_sk[8192], g_ct[2048], g_ss[32], g_sig[65536];
static const uint8_t g_msg[3] = {'m', 's', 'g'};

/* The partial draw at its worst: every octet written, then failure. */
static ama_error_t needle_then_fail(uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = g_needle[i % NEEDLE_BYTES];
    }
    return AMA_ERROR_CRYPTO;
}

RESIDUE_NOINLINE static int needle_residue_count(void) {
    return residue_count(g_needle, NEEDLE_BYTES);
}

RESIDUE_NOINLINE static ama_error_t probe_ml_kem_keypair(ama_ml_kem_param_set_t ps) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_ml_kem_keypair(ps, g_pk, ama_ml_kem_public_key_bytes(ps), g_sk,
                                     ama_ml_kem_secret_key_bytes(ps)));
    return rc;
}

RESIDUE_NOINLINE static ama_error_t probe_ml_kem_encapsulate(ama_ml_kem_param_set_t ps) {
    ama_error_t rc;
    size_t ct_len = ama_ml_kem_ciphertext_bytes(ps);
    RUN_BELOW_GAP(ama_ml_kem_encapsulate(ps, g_pk, ama_ml_kem_public_key_bytes(ps), g_ct,
                                         &ct_len, g_ss, sizeof g_ss));
    return rc;
}

RESIDUE_NOINLINE static ama_error_t probe_ml_dsa_keypair(ama_ml_dsa_param_set_t ps) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_ml_dsa_keypair(ps, g_pk, g_sk));
    return rc;
}

RESIDUE_NOINLINE static ama_error_t probe_slhdsa_keygen(void) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_slhdsa_keygen(AMA_SLHDSA_SHA2_256F, g_pk, g_sk));
    return rc;
}

RESIDUE_NOINLINE static ama_error_t probe_slhdsa_sign(void) {
    ama_error_t rc;
    size_t sig_len = sizeof g_sig;
    RUN_BELOW_GAP(ama_slhdsa_sign(AMA_SLHDSA_SHA2_256F, g_sig, &sig_len, g_msg,
                                  sizeof g_msg, NULL, 0, g_sk));
    return rc;
}

RESIDUE_NOINLINE static ama_error_t probe_sphincs_keypair(void) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_sphincs_keypair(g_pk, g_sk));
    return rc;
}

RESIDUE_NOINLINE static ama_error_t probe_sphincs_sign(void) {
    ama_error_t rc;
    size_t sig_len = sizeof g_sig;
    RUN_BELOW_GAP(ama_sphincs_sign(g_sig, &sig_len, g_msg, sizeof g_msg, g_sk));
    return rc;
}

RESIDUE_NOINLINE static ama_error_t probe_x25519_keypair(void) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_x25519_keypair(g_pk, g_sk));
    return rc;
}

/* Occurrences of the needle in a caller-owned buffer. */
static int needle_count_in(const uint8_t *buf, size_t len) {
    size_t i;
    int hits = 0;
    for (i = 0; i + NEEDLE_BYTES <= len; i++) {
        if (memcmp(buf + i, g_needle, NEEDLE_BYTES) == 0) {
            hits++;
        }
    }
    return hits;
}

/* One verdict: poison, run the probed exit, require the refusal, count the
 * needle once (ONE SCAN PER POISON, residue_probe.h). */
#define VERDICT(call, what) do {                                          \
    ama_error_t rc_;                                                      \
    int hits_;                                                            \
    poison_stack();                                                       \
    rc_ = (call);                                                         \
    hits_ = needle_residue_count();                                       \
    printf("  %-58s %d hit(s)\n", (what), hits_);                         \
    CHECK(rc_ == AMA_ERROR_CRYPTO, (what));                               \
    CHECK(hits_ == 0, (what));                                            \
} while (0)

#endif /* !AMA_PROBE_IS_INSTRUMENTED */

int main(void) {
#if AMA_PROBE_IS_INSTRUMENTED
    /* Skipped, not suppressed: the probe's read of dead stack below its own
     * frame is the measurement, and it is what ASan and MSan exist to object
     * to.  See the AMA_PROBE_IS_INSTRUMENTED block in residue_probe.h. */
    printf("SKIP: dead-stack residue cannot be measured under a sanitizer "
           "that relocates locals or instruments the read\n");
    return 77;
#else
    static const ama_ml_kem_param_set_t kem_sets[] = {
        AMA_ML_KEM_512, AMA_ML_KEM_768, AMA_ML_KEM_1024};
    static const char *const kem_names[] = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    static const ama_ml_dsa_param_set_t dsa_sets[] = {
        AMA_ML_DSA_44, AMA_ML_DSA_65, AMA_ML_DSA_87};
    static const char *const dsa_names[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    uint8_t seed[32];
    char what[96];
    unsigned i;
    int control_hits;

    for (i = 0; i < NEEDLE_BYTES; i++) {
        /* Distinct from the 0x5A poison and from the sentinel. */
        g_needle[i] = (uint8_t)(0x96u ^ (i * 29u + 5u));
    }
    for (i = 0; i < sizeof g_sentinel; i++) {
        g_sentinel[i] = (uint8_t)(0xA7u ^ (i * 13u + 3u));
    }

    printf("CSPRNG-failure dead-stack residue (INVARIANT-6)\n");
    printf("===============================================\n");

    /* --- control: the probe must see a value that IS left behind. */
    poison_stack();
    residue_probe_control(g_sentinel, sizeof g_sentinel);
    control_hits = residue_count(g_sentinel, sizeof g_sentinel);
    printf("  control (sentinel deliberately left): %d hit(s)\n", control_hits);
    CHECK(control_hits > 0,
          "probe control: a value left on the stack IS detected "
          "(a zero here makes every verdict below vacuous)");
    CHECK(residue_window_covers_poison(),
          "probe coverage: the bytes the scan reads are the bytes the poison wrote");

    /* --- baseline: the window holds no needle before any hook has run. */
    poison_stack();
    CHECK(needle_residue_count() == 0, "baseline: no needle before any probed call");

    /* --- ML-KEM: key generation's d, encapsulation's m. */
    memset(seed, 0x35, sizeof seed);
    for (i = 0; i < 3; i++) {
        if (ama_ml_kem_keypair_from_seed(kem_sets[i], seed, seed, g_pk,
                                         ama_ml_kem_public_key_bytes(kem_sets[i]), g_sk,
                                         ama_ml_kem_secret_key_bytes(kem_sets[i])) !=
            AMA_SUCCESS) {
            CHECK(0, "ML-KEM keypair from seed");
            continue;
        }
        ama_kyber_randombytes_hook = needle_then_fail;
        snprintf(what, sizeof what, "%s keypair: d after a failed draw", kem_names[i]);
        VERDICT(probe_ml_kem_keypair(kem_sets[i]), what);
        snprintf(what, sizeof what, "%s encapsulate: m after a failed draw", kem_names[i]);
        VERDICT(probe_ml_kem_encapsulate(kem_sets[i]), what);
        ama_kyber_randombytes_hook = NULL;
    }

    /* --- ML-DSA: key generation's xi. */
    ama_dilithium_randombytes_hook = needle_then_fail;
    for (i = 0; i < 3; i++) {
        snprintf(what, sizeof what, "%s keypair: xi after a failed draw", dsa_names[i]);
        VERDICT(probe_ml_dsa_keypair(dsa_sets[i]), what);
    }
    ama_dilithium_randombytes_hook = NULL;

    /* --- SLH-DSA: both key generators' seeds, both signers' randomizers. */
    memset(seed, 0x57, sizeof seed);
    if (ama_slhdsa_keygen_from_seed(AMA_SLHDSA_SHA2_256F, seed, seed, seed, g_pk, g_sk) !=
        AMA_SUCCESS) {
        CHECK(0, "SLH-DSA keygen from seed");
    } else {
        ama_sphincs_randombytes_hook = needle_then_fail;
        VERDICT(probe_slhdsa_sign(), "SLH-DSA sign: addrnd after a failed draw");
        VERDICT(probe_sphincs_sign(), "SPHINCS+ (legacy) sign: addrnd after a failed draw");
        VERDICT(probe_slhdsa_keygen(), "SLH-DSA keygen: seeds after a failed draw");
        VERDICT(probe_sphincs_keypair(), "SPHINCS+ (legacy) keypair: seeds after a failed draw");
        ama_sphincs_randombytes_hook = NULL;
    }

    /* --- X25519: the draw lands in the caller's secret_key. */
    ama_x25519_randombytes_hook = needle_then_fail;
    VERDICT(probe_x25519_keypair(), "X25519 keypair: stack after a failed draw");
    {
        int hits = needle_count_in(g_sk, 32);
        printf("  %-58s %d hit(s)\n", "X25519 keypair: caller's secret_key after a failed draw",
               hits);
        CHECK(hits == 0, "X25519 keypair: the refused call returns no partial secret key");
    }
    ama_x25519_randombytes_hook = NULL;

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
#endif
}
