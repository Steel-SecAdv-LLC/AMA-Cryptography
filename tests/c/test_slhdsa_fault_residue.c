/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_slhdsa_fault_residue.c
 * @brief SLH-DSA signing's hash-failure exits leave nothing secret behind
 *        (INVARIANT-6).
 *
 * `slh_sign_internal` returns an error when PRF_msg or H_msg fails, and the
 * SHAKE absorb helpers every SLH-DSA-SHAKE hash runs through return -1 when
 * a step of the sponge fails.  No input reaches those exits: every entry
 * point refuses a NULL segment with a nonzero length before any hashing
 * starts, and `ama_hmac_sha512_3` returns 0 only.  Each exit must still
 * scrub what it computed, because what it computed is secret until it is
 * published, and on these exits it never is:
 *
 *   - R = PRF_msg(SK.prf, opt_rand, M') is public only once it is the first
 *     n octets of a signature;
 *   - the H_msg digest is a function of R;
 *   - a SHAKE context that absorbed SK.prf (PRF_msg) or SK.seed (PRF) still
 *     holds it in its rate buffer after the squeeze, because the input was
 *     shorter than one block.
 *
 * THE FAULT.  `ama_slhdsa_hash_fault_hook` (AMA_TESTING_MODE only; the
 * shipped object is byte-identical without it) is consulted once per hash
 * call, AFTER that call has computed its output, and a nonzero return makes
 * the call report failure.  That is the worst case for what an exit leaves
 * behind: every value it could hold has been computed.  The calls that
 * consult it are PRF_msg and H_msg in both families and, in the SHAKE family
 * only, every F, H, T_l and PRF: once per SHAKE-256 hash, in shake_finish,
 * not once per absorbed segment (F, H, T_l and PRF absorb three each).  A
 * call whose sponge or HMAC step has already failed does not consult it, and
 * no input makes one fail.  Deterministic signing consults it for PRF_msg
 * first, H_msg second, then, in SHAKE-128s, for every F, H, T_l and PRF of
 * the FORS and hypertree signatures, whose failure the caller ignores; so
 * the consultation's 1-based position selects the exit.  Checks below hold
 * that rule, less the failed-step case no input reaches: two consultation
 * counts (SHAKE-128s key generation consults it once per hash of the top
 * XMSS tree, SHA2-256f signing twice); "a fault after the output leaves the
 * signature exact" for F, H, T_l and PRF; and, in each family, a position
 * control that finds R on the live stack at PRF_msg's consultation and the
 * H_msg digest at H_msg's, without which a hook consulted before the hash
 * would leave every verdict below passing with nothing to find.
 *
 * THE PROBE is `residue_probe.h` (poison, call below a GAP at the same depth,
 * scan the poisoned bytes once per poison).  Each needle is computed outside
 * the probed call: R from a reference signature over the same input, the
 * SHAKE digest with the public `ama_shake256`, SK.prf and SK.seed from the
 * seeds the key was generated from.
 *
 * THE FINDING.  The first run of this test on the tree it was written for
 * failed: one copy of SK.prf after a failed PRF_msg, one of R after a failed
 * H_msg.  Neither was in SLH-DSA.  `ama_shake256_inc_finalize` copies the
 * rate buffer into a local block to pad it, and did not scrub that block, so
 * the last partial block of every incremental SHAKE-256 absorb -- for a keyed
 * absorb, the key -- stayed in its dead frame; `ama_shake128_inc_finalize`
 * had the same omission.  Every other finalizer in ama_sha3.c scrubs its
 * block; these two now do, and the first two verdicts below probe them
 * directly through the public incremental API.
 *
 * THE BUILD MATTERS.  CI's unoptimised strict build (gcc 13.3.0,
 * CMAKE_BUILD_TYPE=None) then failed two verdicts the Release build passed:
 * one copy of R after a failed PRF_msg and one of the digest after a failed
 * H_msg, left in the dead frame of the Keccak permutation, whose lanes hold
 * the state both were squeezed from.  slh_sign_internal's two error exits
 * therefore also wipe the dead stack below their frame
 * (ama_stack_wipe_below), as the Ed25519 and AEAD entry points do.
 *
 * MUTATION RECORD (AGENTS.md section 6.2; gcc 13.3.0, x86-64, 2026-09-28,
 * both in Release and in the unoptimised build).  Each change was made, the
 * testing archive rebuilt and this test run.
 *   PIN in both builds, deleted alone:
 *   - ama_shake256_inc_finalize's block scrub: "ama_shake256_inc_finalize:
 *     the absorbed key";
 *   - ama_shake128_inc_finalize's block scrub: "ama_shake128_inc_finalize:
 *     the absorbed key";
 *   - each finalizer's clear of the context's rate buffer, which still held
 *     the key after the squeeze-only state took over: "... : the key in its
 *     context" for that finalizer (added after Copilot's overview on
 *     7223e36);
 *   - slh_sign_internal's R scrub on the PRF_msg exit: "SHAKE-128s PRF_msg
 *     fails: R";
 *   - its R scrub on the H_msg exit: "SHAKE-128s H_msg fails: R" and
 *     "SHA2-256f H_msg fails: R";
 *   - its digest scrub on the H_msg exit: "SHAKE-128s H_msg fails: digest";
 *   - R copied into the signature before H_msg, as it was until 2026-09-28:
 *     both "H_msg fails: no R in the signature" verdicts.
 *   PIN in the unoptimised build, deleted alone:
 *   - the stack wipe on the PRF_msg exit: "SHAKE-128s PRF_msg fails: R";
 *   - the stack wipe on the H_msg exit: "SHAKE-128s H_msg fails: digest".
 *   Redundant with the wipe (section 6.3): each of these guards a frame
 *   below slh_sign_internal, which the wipe also clears, so deleting it alone
 *   fails nothing in either build, and deleting it together with the wipe
 *   fails the verdicts named.  The test pins the property, that the failed
 *   hash's frames hold nothing, not either implementation:
 *   - the SHAKE helpers' context scrub on a failing path (shake_finish):
 *     "SHAKE-128s PRF_msg fails: SK.prf" and "... : R", "SHAKE-128s H_msg
 *     fails: R" and "... : digest";
 *   - sha2_PRF_msg's HMAC scrub on its failure branch: "SHA2-256f PRF_msg
 *     fails: R";
 *   - ama_shake256_inc_finalize's block scrub, for the SLH-DSA verdicts
 *     ("SHAKE-128s PRF_msg fails: SK.prf", "SHAKE-128s H_msg fails: R");
 *     its direct verdict above pins it alone.
 *
 * "SHAKE-128s every F, H and PRF fails: SK.seed" is SMOKE: deleting the
 * shared context scrub leaves it at 0 hits.  PRF absorbs SK.seed, but every
 * PRF call is followed at the same depth by further absorbs (the chain's F
 * calls, then the tree's H calls) whose contexts overwrite the dead one
 * before any caller returns, so no flow leaves that frame observable.  The
 * verdict is kept for the check beside it, that a fault after the output
 * leaves the signature exact.
 *
 * The consultation counts and position controls (added 2026-09-29, x86-64;
 * gcc 13.3.0 in both builds, clang 18.1.3 in Release, the same result in
 * each) pin the rule THE FAULT states, less the failed-step case:
 * shake_finish consulting the hook after a failed step fails nothing,
 * because no input makes a step fail.
 *   - "SHAKE-128s: key generation consults the hook once per hash" fails
 *     alone when F, H, T_l and PRF consult the hook again after their output
 *     (575,486 consultations) and when H and T_l stop consulting it
 *     (286,720).  When F, H, T_l and PRF consult it once per absorbed segment
 *     (863,229), it fails together with "SHAKE-128s: a fault after the
 *     output leaves the signature exact".  When every SHAKE hash does, it
 *     fails together with that check, "SHAKE-128s every F, H and PRF fails:
 *     SK.seed" and both SHAKE-128s position controls; when shake_finish
 *     consults it twice (575,486), with the same checks less the PRF_msg
 *     position control;
 *   - "SHA2-256f: PRF_msg and H_msg alone consult the hook" fails alone when
 *     sha2_PRF (37,320) or sha2_F (300,042) consults the hook.  sha2_H_msg
 *     not consulting it (1) fails it together with the "SHA2-256f H_msg
 *     fails" verdicts and "SHA2-256f: H_msg's consultation finds the digest";
 *   - each position control fails alone, at 0 hits, when its hash consults
 *     the hook before computing its output: sha2_PRF_msg before the HMAC,
 *     sha2_H_msg before its inner SHA-512, shake_absorb_four (PRF_msg) or
 *     shake_absorb_five (H_msg) before the finalize.  Without the controls,
 *     every check passes under each of those four;
 *   - shake_finish consulting the hook before the squeeze fails "SHAKE-128s:
 *     a fault after the output leaves the signature exact" alone.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "ama_cryptography.h"

#include "residue_probe.h"
#include "../../src/c/internal/ama_testing_exports.h"

#if !AMA_PROBE_IS_INSTRUMENTED

static int checks = 0;
static int failures = 0;

#define CHECK(cond, msg) do {                                    \
    checks++;                                                    \
    if (!(cond)) {                                               \
        failures++;                                              \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); \
    }                                                            \
} while (0)

/* Largest n and signature of the two parameter sets. */
#define N_MAX 32u
#define SIG_MAX AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES
/* SLH-DSA-SHAKE-128s: n = 16, m = 30, h' = 9, w = 16, len = 35 (FIPS 205
 * Table 2). */
#define SHAKE_128S_N 16u
#define SHAKE_128S_M 30u
#define SHAKE_128S_HP 9u
#define SHAKE_128S_W 16u
#define SHAKE_128S_LEN 35u
/* The SHAKE-256 hashes key generation computes for the top XMSS tree (FIPS
 * 205 Algorithms 6, 9 and 18): per leaf, len chains of one PRF and w - 1 F,
 * then one T_len; then 2^h' - 1 H.  287,743; they absorb three segments
 * each, 863,229 in all. */
#define SHAKE_128S_KEYGEN_HASHES                                        \
    ((1u << SHAKE_128S_HP) * (SHAKE_128S_LEN * SHAKE_128S_W + 1u) +     \
     (1u << SHAKE_128S_HP) - 1u)
/* What an untouched signature buffer holds. */
#define UNTOUCHED 0xEEu

/* What the control plants.  Never a needle: see THE SENTINEL in
 * residue_probe.h. */
static uint8_t g_sentinel[32];

/* Outputs and inputs live outside the probed stack. */
static uint8_t g_pk[2 * N_MAX], g_sk[4 * N_MAX];
static uint8_t g_sig[SIG_MAX], g_ref[SIG_MAX];
static const uint8_t g_msg[3] = {'m', 's', 'g'};
static ama_slhdsa_param_set_t g_ps;

/* The fault hook: counts the calls that consult it and fails those whose
 * 1-based position lies in [g_fail_from, g_fail_to]; arm(0, 0) counts and
 * fails none.  At position g_scan_at it also counts g_scan_needle on the
 * live stack (position_control). */
static unsigned g_calls, g_fail_from, g_fail_to, g_scan_at;
static const uint8_t *g_scan_needle;
static size_t g_scan_len;
static int g_scan_hits;

RESIDUE_NOINLINE static int live_count(const uint8_t *needle, size_t len);

static int count_and_fault(void) {
    g_calls++;
    if (g_calls == g_scan_at) {
        g_scan_hits = live_count(g_scan_needle, g_scan_len);
    }
    return g_calls >= g_fail_from && g_calls <= g_fail_to;
}

static void arm(unsigned from, unsigned to) {
    g_calls = 0;
    g_fail_from = from;
    g_fail_to = to;
    ama_slhdsa_hash_fault_hook = count_and_fault;
}

static void disarm(void) {
    ama_slhdsa_hash_fault_hook = NULL;
    g_scan_at = 0;
}

/* A context outside the probed stack: only the finalizer's own frame is in
 * the window. */
static ama_sha3_ctx g_ctx;

RESIDUE_NOINLINE static ama_error_t probe_shake256_finalize(void) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_shake256_inc_finalize(&g_ctx));
    return rc;
}

RESIDUE_NOINLINE static ama_error_t probe_shake128_finalize(void) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_shake128_inc_finalize(&g_ctx));
    return rc;
}

/* Occurrences of `needle` in a caller-owned object. */
static int count_in(const uint8_t *buf, size_t len, const uint8_t *needle, size_t n) {
    size_t i;
    int hits = 0;
    for (i = 0; i + n <= len; i++) {
        if (memcmp(buf + i, needle, n) == 0) {
            hits++;
        }
    }
    return hits;
}

/* Occurrences of `needle` on the stack from below this frame up to the top of
 * the last poison: the live frames of the probed call that consulted the
 * hook.  -1 when this frame lies outside the poison. */
RESIDUE_NOINLINE static int live_count(const uint8_t *needle, size_t len) {
    uintptr_t mark = 0;
    residue_stack_mark(&mark);
    if (mark < residue_poison_lo || mark >= residue_poison_hi) {
        return -1;
    }
    return count_in((const uint8_t *)mark, (size_t)(residue_poison_hi - mark), needle, len);
}

/* A keyed absorb shorter than one block, then the finalizer alone under the
 * probe: its local copy of the rate buffer is the only place on the stack
 * the key can be left.  The context is checked as well: the rate buffer the
 * key was absorbed into must not still hold it once the finalizer has run,
 * for a caller that does not scrub its context. */
static void finalizer_verdict(int shake128, const uint8_t *key, size_t len,
                              const char *what, const char *what_ctx) {
    ama_error_t rc;
    int hits, held;
    if (shake128) {
        (void)ama_shake128_inc_init(&g_ctx);
        (void)ama_shake128_inc_absorb(&g_ctx, key, len);
    } else {
        (void)ama_shake256_inc_init(&g_ctx);
        (void)ama_shake256_inc_absorb(&g_ctx, key, len);
    }
    poison_stack();
    rc = shake128 ? probe_shake128_finalize() : probe_shake256_finalize();
    hits = residue_count(key, len);
    held = count_in((const uint8_t *)&g_ctx, sizeof g_ctx, key, len);
    memset(&g_ctx, 0, sizeof g_ctx);
    printf("  %-58s %d hit(s)\n", what, hits);
    printf("  %-58s %d hit(s)\n", what_ctx, held);
    CHECK(rc == AMA_SUCCESS, what);
    CHECK(hits == 0, what);
    CHECK(held == 0, what_ctx);
}

RESIDUE_NOINLINE static ama_error_t probe_sign(void) {
    ama_error_t rc;
    size_t sig_len = sizeof g_sig;
    RUN_BELOW_GAP(ama_slhdsa_sign_deterministic(g_ps, g_sig, &sig_len, g_msg,
                                                sizeof g_msg, NULL, 0, g_sk));
    return rc;
}

/* One verdict: arm the fault, poison, sign, require the expected result, and
 * count one needle once (ONE SCAN PER POISON, residue_probe.h). */
static void verdict(unsigned from, unsigned to, ama_error_t expect,
                    const uint8_t *needle, size_t len, const char *what) {
    ama_error_t rc;
    int hits;
    memset(g_sig, UNTOUCHED, sizeof g_sig);
    arm(from, to);
    poison_stack();
    rc = probe_sign();
    hits = residue_count(needle, len);
    disarm();
    printf("  %-58s %d hit(s)\n", what, hits);
    CHECK(rc == expect, what);
    CHECK(hits == 0, what);
}

/* The fault falls after the output: at the consultation at position `at`,
 * with nothing failed, the value that hash computes is already on the live
 * stack.  The poison first clears the copies an earlier signature left. */
static void position_control(unsigned at, const uint8_t *needle, size_t len,
                             const char *what) {
    ama_error_t rc;
    arm(0, 0);
    g_scan_at = at;
    g_scan_needle = needle;
    g_scan_len = len;
    g_scan_hits = 0;
    poison_stack();
    rc = probe_sign();
    disarm();
    printf("  %-58s %d hit(s)\n", what, g_scan_hits);
    CHECK(rc == AMA_SUCCESS, what);
    CHECK(g_scan_hits > 0, what);
}

/* After a refused signature: the caller's buffer holds no R. */
static void no_r_in_signature(unsigned from, size_t n, const char *what) {
    ama_error_t rc;
    size_t i;
    int untouched = 1;
    memset(g_sig, UNTOUCHED, sizeof g_sig);
    arm(from, from);
    rc = probe_sign();
    disarm();
    for (i = 0; i < n; i++) {
        if (g_sig[i] != UNTOUCHED) {
            untouched = 0;
        }
    }
    printf("  %-58s %s\n", what, untouched ? "untouched" : "WRITTEN");
    CHECK(rc == AMA_ERROR_MEMORY, what);
    CHECK(untouched, what);
}

static int keygen(ama_slhdsa_param_set_t ps, size_t n, uint8_t *sk_seed,
                  uint8_t *sk_prf) {
    uint8_t pk_seed[N_MAX];
    size_t i;
    for (i = 0; i < n; i++) {
        /* Distinct from each other, from the 0x5A poison and from the
         * sentinel. */
        sk_seed[i] = (uint8_t)(0xC3u ^ (i * 37u + 11u));
        sk_prf[i] = (uint8_t)(0x3Cu ^ (i * 53u + 7u));
        pk_seed[i] = (uint8_t)(0x96u ^ (i * 29u + 5u));
    }
    return ama_slhdsa_keygen_from_seed(ps, sk_seed, sk_prf, pk_seed, g_pk, g_sk) ==
           AMA_SUCCESS;
}

static int reference_signature(void) {
    size_t sig_len = sizeof g_ref;
    return ama_slhdsa_sign_deterministic(g_ps, g_ref, &sig_len, g_msg, sizeof g_msg,
                                         NULL, 0, g_sk) == AMA_SUCCESS;
}

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
    uint8_t sk_seed[N_MAX], sk_prf[N_MAX], digest[SHAKE_128S_M];
    uint8_t h_msg_in[3 * SHAKE_128S_N + 2 + sizeof g_msg];
    uint8_t sha2_in[3 * N_MAX + 2 + sizeof g_msg], mgf_in[2 * N_MAX + 64 + 4];
    uint8_t sha2_digest[64];
    const uint8_t *r = g_ref;
    size_t i;
    int control_hits, keygen_ok;
    unsigned signing_calls, keygen_calls;

    for (i = 0; i < sizeof g_sentinel; i++) {
        g_sentinel[i] = (uint8_t)(0xA7u ^ (i * 13u + 3u));
    }

    printf("SLH-DSA hash-failure dead-stack residue (INVARIANT-6)\n");
    printf("=====================================================\n");

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

    /* --- the SHAKE incremental finalizers every keyed absorb ends in. */
    for (i = 0; i < SHAKE_128S_N; i++) {
        sk_prf[i] = (uint8_t)(0x69u ^ (i * 41u + 17u));
    }
    finalizer_verdict(0, sk_prf, SHAKE_128S_N, "ama_shake256_inc_finalize: the absorbed key",
                      "ama_shake256_inc_finalize: the key in its context");
    finalizer_verdict(1, sk_prf, SHAKE_128S_N, "ama_shake128_inc_finalize: the absorbed key",
                      "ama_shake128_inc_finalize: the key in its context");

    /* --- SLH-DSA-SHAKE-128s. */
    g_ps = AMA_SLHDSA_SHAKE_128S;
    /* The consultation rule the positions below rely on: once per hash, not
     * once per absorbed segment. */
    arm(0, 0);
    keygen_ok = keygen(g_ps, SHAKE_128S_N, sk_seed, sk_prf);
    keygen_calls = g_calls;
    disarm();
    printf("  %-58s %u\n", "SHAKE-128s: key generation's hook consultations",
           keygen_calls);
    CHECK(keygen_calls == SHAKE_128S_KEYGEN_HASHES,
          "SHAKE-128s: key generation consults the hook once per hash");
    if (!keygen_ok || !reference_signature()) {
        CHECK(0, "SLH-DSA-SHAKE-128s keygen and reference signature");
    } else {
        /* digest = H_msg(R, PK.seed, PK.root, M') = SHAKE-256(R || PK || M', 8m),
         * with M' = 0x00 || 0x00 || M for an empty context (FIPS 205 §10.2). */
        memcpy(h_msg_in, r, SHAKE_128S_N);
        memcpy(h_msg_in + SHAKE_128S_N, g_pk, 2 * SHAKE_128S_N);
        h_msg_in[3 * SHAKE_128S_N] = 0x00;
        h_msg_in[3 * SHAKE_128S_N + 1] = 0x00;
        memcpy(h_msg_in + 3 * SHAKE_128S_N + 2, g_msg, sizeof g_msg);
        CHECK(ama_shake256(h_msg_in, sizeof h_msg_in, digest, sizeof digest) ==
                  AMA_SUCCESS,
              "SHAKE-256 of the H_msg input");

        /* The hook is live, and the fault falls after the output: with every
         * call from the third on failing, the signature is the reference. */
        memset(g_sig, UNTOUCHED, sizeof g_sig);
        arm(3, ~0u);
        CHECK(probe_sign() == AMA_SUCCESS &&
                  memcmp(g_sig, g_ref, AMA_SLHDSA_SHAKE_128S_SIGNATURE_BYTES) == 0,
              "SHAKE-128s: a fault after the output leaves the signature exact");
        signing_calls = g_calls;
        disarm();
        printf("  %-58s %u\n", "SHAKE-128s: hash calls that consulted the hook",
               signing_calls);
        CHECK(signing_calls > 2, "SHAKE-128s: F, H and PRF consult the hook");
        position_control(1, r, SHAKE_128S_N, "SHAKE-128s: PRF_msg's consultation finds R");
        position_control(2, digest, SHAKE_128S_N,
                         "SHAKE-128s: H_msg's consultation finds the digest");

        verdict(1, 1, AMA_ERROR_MEMORY, sk_prf, SHAKE_128S_N,
                "SHAKE-128s PRF_msg fails: SK.prf");
        verdict(1, 1, AMA_ERROR_MEMORY, r, SHAKE_128S_N, "SHAKE-128s PRF_msg fails: R");
        verdict(2, 2, AMA_ERROR_MEMORY, r, SHAKE_128S_N, "SHAKE-128s H_msg fails: R");
        verdict(2, 2, AMA_ERROR_MEMORY, digest, SHAKE_128S_N,
                "SHAKE-128s H_msg fails: digest");
        no_r_in_signature(2, SHAKE_128S_N, "SHAKE-128s H_msg fails: no R in the signature");
        verdict(3, ~0u, AMA_SUCCESS, sk_seed, SHAKE_128S_N,
                "SHAKE-128s every F, H and PRF fails: SK.seed");
    }

    /* --- SLH-DSA-SHA2-256f: PRF_msg is HMAC-SHA-512, H_msg MGF1-SHA-512. */
    g_ps = AMA_SLHDSA_SHA2_256F;
    if (!keygen(g_ps, N_MAX, sk_seed, sk_prf) || !reference_signature()) {
        CHECK(0, "SLH-DSA-SHA2-256f keygen and reference signature");
    } else {
        /* sha2_F, sha2_HT and sha2_PRF have no failure path: only PRF_msg
         * and H_msg consult the hook. */
        arm(0, 0);
        CHECK(probe_sign() == AMA_SUCCESS &&
                  memcmp(g_sig, g_ref, AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES) == 0,
              "SHA2-256f: signing with the hook set is the reference");
        signing_calls = g_calls;
        disarm();
        printf("  %-58s %u\n", "SHA2-256f: hash calls that consulted the hook",
               signing_calls);
        CHECK(signing_calls == 2, "SHA2-256f: PRF_msg and H_msg alone consult the hook");
        /* digest = MGF1-SHA-512(R || PK.seed || SHA-512(R || PK || M'), m); its
         * first block, SHA-512(that seed || toByte(0, 4)), holds all m = 49
         * octets. */
        memcpy(sha2_in, r, N_MAX);
        memcpy(sha2_in + N_MAX, g_pk, 2 * N_MAX);
        sha2_in[3 * N_MAX] = 0x00;
        sha2_in[3 * N_MAX + 1] = 0x00;
        memcpy(sha2_in + 3 * N_MAX + 2, g_msg, sizeof g_msg);
        memcpy(mgf_in, r, N_MAX);
        memcpy(mgf_in + N_MAX, g_pk, N_MAX);
        memset(mgf_in + 2 * N_MAX + 64, 0, 4);
        CHECK(ama_sha512(sha2_in, sizeof sha2_in, mgf_in + 2 * N_MAX) == AMA_SUCCESS &&
                  ama_sha512(mgf_in, sizeof mgf_in, sha2_digest) == AMA_SUCCESS,
              "SHA-512 of the H_msg input");
        position_control(1, r, N_MAX, "SHA2-256f: PRF_msg's consultation finds R");
        position_control(2, sha2_digest, N_MAX,
                         "SHA2-256f: H_msg's consultation finds the digest");
        verdict(1, 1, AMA_ERROR_MEMORY, r, N_MAX, "SHA2-256f PRF_msg fails: R");
        verdict(2, 2, AMA_ERROR_MEMORY, r, N_MAX, "SHA2-256f H_msg fails: R");
        no_r_in_signature(2, N_MAX, "SHA2-256f H_msg fails: no R in the signature");
    }

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
#endif
}
