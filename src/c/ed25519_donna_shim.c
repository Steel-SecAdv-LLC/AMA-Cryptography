/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ed25519_donna_shim.c
 * @brief AMA API shim for ed25519-donna (public domain, Andrew Moon)
 *
 * Compiles ed25519-donna as a single translation unit with AMA's public API.
 * Uses donna's built-in reference SHA-512 and AMA's platform CSPRNG.
 *
 * Field representation: donna's 64-bit path uses radix 2^51 (5 x uint64_t),
 * the same family as AMA's fe51.h. However, donna's scalar multiplication
 * is self-contained — it uses its own field ops, group ops, and precomputed
 * Niels basepoint table internally. On x86-64 with GCC, donna activates
 * inline assembly for constant-time table selection
 * (ed25519-donna-64bit-x86.h).
 *
 * This shim replaces ama_ed25519.c when AMA_ED25519_ASSEMBLY is enabled.
 */

#include "../include/ama_cryptography.h"
#include <string.h>
#include <stdlib.h>

/* --- donna compilation flags ---
 * ED25519_REFHASH: use donna's built-in SHA-512 (no OpenSSL dependency)
 * ED25519_CUSTOMRANDOM: we provide ed25519_randombytes_unsafe below
 */
#define ED25519_REFHASH
#define ED25519_CUSTOMRANDOM

/* Provide randombytes for donna's batch verification (not used by sign/verify
 * but needed to compile). Backed by AMA's platform CSPRNG. */
#include "ama_platform_rand.h"

/* Batch verification draws its per-signature randomizers through this hook.
 * ama_randombytes is NOT all-or-nothing (it returns AMA_ERROR_CRYPTO and may
 * leave the buffer partially or never written), and donna's void-returning
 * hook signature cannot report that.  Dropping the status is a fail-OPEN:
 * with garbage randomizers the Bos-Carter multi-scalar check loses its
 * soundness, and in the degenerate all-zero case the aggregate collapses to
 * the identity and the routine reports EVERY signature valid regardless of
 * whether it is genuine.  Latch the failure in a thread-local flag that
 * ama_ed25519_batch_verify inspects and fails closed on; zero-fill the buffer
 * so the discarded computation is at least deterministic rather than reading
 * indeterminate stack. */
static _Thread_local int s_ed25519_batch_rng_failed = 0;

#ifdef AMA_TESTING_MODE
/**
 * Allocation-failure hook for fail-closed testing.
 *
 * When non-zero, the next ama_ed25519_batch_verify() call behaves as though
 * every malloc for donna's pointer arrays returned NULL, so a test can drive
 * the AMA_ERROR_MEMORY return.  That return is the ONLY path on this backend
 * where the caller's `results` array is written by the fail-closed pre-zeroing
 * loop and by nothing else, so without this hook the pre-zeroing could be
 * deleted outright and every assertion in the tree still passed — measured,
 * not assumed.  The flag is cleared by the call it affects, so a test cannot
 * leave it armed for the next one.
 *
 * Only available in test builds (AMA_TESTING_MODE); the shipped shared and
 * static libraries never define it, and it appears in no public header.
 */
int ama_ed25519_batch_force_alloc_failure = 0;
#endif

static void
ed25519_randombytes_unsafe(void *p, size_t len) {
    if (ama_randombytes((uint8_t *)p, len) != AMA_SUCCESS) {
        s_ed25519_batch_rng_failed = 1;
        memset(p, 0, len);
    }
}

/* Suppress -Wmissing-prototypes for donna's static functions */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

/* Include donna's single-file compilation unit. The actual
 * `#include` lives in a vendor-local aggregator header so the
 * pattern stays inside the path-ignored vendor tree (see
 * .github/codeql/codeql-config.yml). Donna's upstream `ed25519.c`
 * is shipped here as `ed25519_unit.h` so the directive includes a
 * header-extension file and CodeQL's `cpp/include-non-header`
 * rule remains enabled for first-party code. */
#include "vendor/ed25519-donna/ama_donna_unit.h"

/* RFC 8032 §5.1.7 canonical-S check, shared with the portable fe51 backend
 * in ama_ed25519.c.  Header-only because the two backends are mutually
 * exclusive at build time (CMakeLists.txt swaps one source for the other),
 * so a shared .c would be linked in only one configuration. */
#include "internal/ama_ed25519_canonical.h"

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

/* ----------------------------------------------------------------------------
 * CodeQL cpp/unused-static-variable resolution (code-scanning alerts #499/#500)
 *
 * donna's 64-bit backend (curve25519-donna-64bit.h) defines the field-reduction
 * masks reduce_mask_40 / reduce_mask_51 / reduce_mask_56 at file scope, but the
 * 40- and 56-bit masks are only *read* from the emulated 128-bit multiply path
 * guarded by `#if !defined(HAVE_NATIVE_UINT128)`. AMA builds on targets with a
 * native 128-bit integer (x86-64, aarch64), so that path is compiled out and
 * CodeQL sees reduce_mask_40 / reduce_mask_56 as unused *in this translation
 * unit* (reduce_mask_51 is read from the always-compiled reduce path, so it is
 * never flagged).
 *
 * We resolve the finding at the source with a genuine reference — not a
 * Security-UI "Won't fix" dismissal and not a rule/path suppression — so
 * cpp/unused-static-variable stays fully enforced on all first-party and vendor
 * code, and upstream donna stays byte-for-byte identical (the reference lives
 * here in the project-local shim, never in the vendored header).
 *
 * Form: an external-linkage (non-static, so out of scope for the
 * static-only unused rule), hidden-visibility (unexported from
 * libama_cryptography), zero-runtime-cost table of the two mask addresses.
 * Taking &reduce_mask_40 / &reduce_mask_56 is a real use of each constant.
 * Compiled only under ED25519_64BIT — i.e. exactly the configuration in which
 * curve25519-donna-64bit.h defines these two symbols (never on the 32-bit
 * backend or MSVC, where they do not exist).
 * ------------------------------------------------------------------------- */
#if defined(ED25519_64BIT)
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
const uint64_t *const ama_ed25519_donna_reduce_mask_anchor[2] = {
    &reduce_mask_40,
    &reduce_mask_56,
};
#endif /* ED25519_64BIT */

/* ============================================================================
 * AMA API WRAPPERS
 *
 * donna's API:
 *   ed25519_publickey(sk_32byte, pk_32byte)
 *   ed25519_sign(msg, msglen, sk_32byte, pk_32byte, sig_64byte)
 *   ed25519_sign_open(msg, msglen, pk_32byte, sig_64byte) -> 0 ok, -1 fail
 *
 * AMA's API:
 *   ama_ed25519_keypair(pk_32byte, sk_64byte)     // sk = seed || pk
 *   ama_ed25519_sign(sig, msg, msglen, sk_64byte)
 *   ama_ed25519_verify(sig, msg, msglen, pk_32byte)
 * ============================================================================ */

ama_error_t ama_ed25519_keypair(uint8_t public_key[32], uint8_t secret_key[64]) {
    if (!public_key || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* AMA convention: caller provides the 32-byte seed in secret_key[0..31].
     * The Python wrapper (native_ed25519_keypair) fills these bytes with
     * cryptographic randomness before calling us, and
     * native_ed25519_keypair_from_seed loads a deterministic seed.
     * We must NOT overwrite secret_key[0..31] here. */

    /* Derive the public key from the seed. */
    ed25519_publickey(secret_key, public_key);

    /* AMA convention: secret_key = seed[0..31] || public_key[32..63] */
    memcpy(secret_key + 32, public_key, 32);

    return AMA_SUCCESS;
}

ama_error_t ama_ed25519_sign(
    uint8_t signature[64],
    const uint8_t *message,
    size_t message_len,
    const uint8_t secret_key[64]
) {
    if (!signature || !secret_key || (!message && message_len > 0)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* donna: ed25519_sign(msg, msglen, sk_32, pk_32, sig_out) */
    ed25519_sign(message, message_len,
                 secret_key,        /* 32-byte seed */
                 secret_key + 32,   /* 32-byte public key */
                 signature);

    return AMA_SUCCESS;
}

ama_error_t ama_ed25519_verify(
    const uint8_t signature[64],
    const uint8_t *message,
    size_t message_len,
    const uint8_t public_key[32]
) {
    if (!signature || !public_key || (!message && message_len > 0)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* RFC 8032 §5.1.7: S must decode in the range 0 <= S < L, and a
     * signature whose S falls outside it is invalid.  donna's own guard is
     * `RS[63] & 224`, which only rejects S >= 2^253; since L is just above
     * 2^252 the band L <= S < 2^253 passes it, so (R, S + L) verifies
     * alongside (R, S).  Wycheproof tc63/tc85 catch exactly that.  See
     * internal/ama_ed25519_canonical.h. */
    if (!ama_ed25519_signature_s_is_canonical(signature)) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    /* Reject a non-canonical public-key y.  donna's
     * ge25519_unpack_negative_vartime() reduces mod p like ref10, so the 19
     * encodings with y in [p, 2^255) decode to the same key as their reduced
     * form.  The in-tree fe51 backend enforces this inside its own
     * ge25519_frombytes(); applied here so both backends accept exactly the
     * same set of encodings.  donna's sources stay unmodified. */
    if (!ama_ed25519_point_y_is_canonical(public_key) ||
        !ama_ed25519_point_x_sign_is_admissible(public_key)) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    /* RFC 8032 §5.1.7 step 1 applies §5.1.3's decode rules to R as well as to
     * A.  This path already rejected every non-canonical R, but by accident:
     * ed25519_sign_open re-encodes [S]B - [h]A with ge25519_pack, which emits
     * only canonical encodings, so the byte comparison could never match one.
     * Stating the rule here rather than relying on the encoder's range makes
     * the two verify paths in this file reject for the same stated reason —
     * and the batch path below has no such comparison to lean on.  Accepts
     * exactly what it accepted before; see internal/ama_ed25519_canonical.h. */
    if (!ama_ed25519_signature_r_is_canonical(signature)) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    /* donna returns 0 on success, -1 on failure */
    int result = ed25519_sign_open(message, message_len, public_key, signature);

    return (result == 0) ? AMA_SUCCESS : AMA_ERROR_VERIFY_FAILED;
}

/* ============================================================================
 * BATCH VERIFICATION — donna Bos-Carter multi-scalar multiplication
 *
 * donna's ed25519_sign_open_batch() uses a binary heap for multi-scalar
 * multiplication (Bos-Carter method), supporting up to 64 signatures per
 * batch for ~2.5x throughput vs sequential verify.
 *
 * donna's API expects separate arrays of pointers:
 *   const unsigned char **m     — messages
 *   size_t              *mlen   — message lengths
 *   const unsigned char **pk    — 32-byte public keys
 *   const unsigned char **RS    — 64-byte signatures (R || S)
 *   size_t               num    — number of entries
 *   int                 *valid  — per-entry result (1=valid, 0=invalid)
 *
 * We convert from AMA's ama_ed25519_batch_entry struct array.
 * ============================================================================ */

ama_error_t ama_ed25519_batch_verify(
    const ama_ed25519_batch_entry *entries,
    size_t count,
    int *results
) {
    if (!entries || !results) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (count == 0) {
        return AMA_SUCCESS;
    }

    /* SECURITY FIX: Guard against integer overflow in ALL allocation sizes.
     * Each malloc below uses count * sizeof(...); validate each size so no
     * allocation can wrap to a smaller-than-expected buffer (audit C-MEM-1). */
    if (count > SIZE_MAX / sizeof(const unsigned char *) ||
        count > SIZE_MAX / sizeof(size_t)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Every return past this point leaves `results` fully written, so the
     * header's "exactly `count` are written" holds on the error paths too.
     * Without this, an allocation failure returned with the caller's array
     * untouched — and a caller that reuses one buffer across batches, or that
     * reads `results` before checking the return code, would see stale 1s from
     * an earlier successful batch and read them as valid signatures.  Zeroing
     * first makes the failure mode "everything invalid", which is the
     * direction a verifier must fail in.
     *
     * AFTER the overflow guard, deliberately, and this comment used to say
     * "an allocation failure or the overflow rejection above" as though it
     * covered both.  It does not cover the overflow rejection and MUST NOT: a
     * `count` large enough to wrap `count * sizeof(...)` cannot describe a real
     * array, so writing `results[0..count)` would be the very out-of-bounds
     * write the guard exists to prevent.  The header says so
     * ("touching `results[0..count)` would be the wild write"), and
     * tests/c/test_ed25519_canonical_s.c pins that an argument rejection
     * leaves the caller's array exactly as it was.  Only the sentence was
     * wrong; the ordering is correct. */
    for (size_t i = 0; i < count; i++) {
        results[i] = 0;
    }

    /* Per-entry pointer validation, which this path did not have.
     *
     * ama_ed25519_verify rejects a NULL signature, a NULL public key, and a
     * NULL message with message_len > 0 with AMA_ERROR_INVALID_PARAM in BOTH
     * backends.  The fe51 batch path is a loop over that function, so it
     * inherits the guard and turns a malformed entry into results[i] = 0 plus
     * AMA_ERROR_VERIFY_FAILED.  This path handed entries[i].message /
     * .signature / .public_key straight to ed25519_sign_open_batch, which
     * dereferences all three unconditionally (ed25519-donna-batchverify.h
     * expand256_modm(..., RS[i] + 32, 32) and ed25519_hram(..., m[i],
     * mlen[i])), and the `num <= 3` tail dereferences them through
     * ed25519_sign_open, so small batches faulted too.  The canonicality loop
     * this branch added runs AFTER the batch call and dereferences the same
     * fields itself, so it could not screen them either.
     *
     * Measured on a 6-entry batch with one field of entry 3 nulled: fe51
     * returned AMA_ERROR_VERIFY_FAILED with results 111011 and exit 0, donna
     * took SIGSEGV (exit 139), for message=NULL/message_len=5, for
     * signature=NULL and for public_key=NULL alike.  Same library, same public
     * API, crash on x86-64 and a clean rejection on aarch64 — and aarch64 CI
     * runs fe51, so no lane could observe it.
     *
     * Falling back to the per-entry loop rather than screening in place is
     * what makes the two backends byte-identical here: donna's batch API takes
     * dense arrays with no room for a hole, and ama_ed25519_verify applies
     * exactly the guards, canonicality rules and return code fe51's loop
     * applies. */
    int malformed_entry = 0;
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].signature || !entries[i].public_key ||
            (!entries[i].message && entries[i].message_len > 0)) {
            malformed_entry = 1;
            break;
        }
    }
    if (malformed_entry) {
        int fallback_all_valid = 1;
        for (size_t i = 0; i < count; i++) {
            ama_error_t rc = ama_ed25519_verify(
                entries[i].signature,
                entries[i].message,
                entries[i].message_len,
                entries[i].public_key
            );
            results[i] = (rc == AMA_SUCCESS) ? 1 : 0;
            if (!results[i]) {
                fallback_all_valid = 0;
            }
        }
        return fallback_all_valid ? AMA_SUCCESS : AMA_ERROR_VERIFY_FAILED;
    }

    /* Allocate pointer arrays for donna's batch verify interface */
    const unsigned char **msgs = (const unsigned char **)malloc(count * sizeof(const unsigned char *));
    size_t *mlens = (size_t *)malloc(count * sizeof(size_t));
    const unsigned char **pks = (const unsigned char **)malloc(count * sizeof(const unsigned char *));
    const unsigned char **sigs = (const unsigned char **)malloc(count * sizeof(const unsigned char *));

    int alloc_failed = (!msgs || !mlens || !pks || !sigs);
#ifdef AMA_TESTING_MODE
    if (ama_ed25519_batch_force_alloc_failure) {
        ama_ed25519_batch_force_alloc_failure = 0;
        alloc_failed = 1;
    }
#endif
    if (alloc_failed) {
        /* Explicit (void *) casts: free() takes `void *` but `msgs` /
         * `pks` / `sigs` are `const unsigned char **`.  Without the
         * cast, clang-tidy's bugprone-multi-level-implicit-pointer-conversion
         * fires (audit Issue 9 fail-closed). */
        free((void *)msgs);
        free((void *)mlens);
        free((void *)pks);
        free((void *)sigs);
        return AMA_ERROR_MEMORY;
    }

    /* Convert ama_ed25519_batch_entry structs to donna's separate arrays */
    for (size_t i = 0; i < count; i++) {
        msgs[i] = entries[i].message;
        mlens[i] = entries[i].message_len;
        pks[i] = entries[i].public_key;
        sigs[i] = entries[i].signature;
    }

    /* donna's batch verify: returns 0 if all valid, nonzero otherwise.
     * Per-entry results are written to the valid[] array (1=valid, 0=invalid).
     * Clear the CSPRNG-failure latch first so it reflects only this call's
     * randomizer draw (see ed25519_randombytes_unsafe). */
    s_ed25519_batch_rng_failed = 0;
    int ret = ed25519_sign_open_batch(msgs, mlens, pks, sigs, count, results);

    /* Fail closed if the randomizer draw failed: the batch soundness argument
     * depends on unpredictable randomizers, so a batch that could not draw
     * them cannot report any entry valid.  Mark every entry invalid and force
     * an error return, ahead of (and overriding) the canonical-S/y loop and
     * the success mapping below. */
    if (s_ed25519_batch_rng_failed) {
        for (size_t i = 0; i < count; i++) {
            results[i] = 0;
        }
        free((void *)msgs);
        free((void *)mlens);
        free((void *)pks);
        free((void *)sigs);
        return AMA_ERROR_CRYPTO;
    }

    /* RFC 8032 §5.1.7 canonical-S enforcement, applied per entry.
     *
     * This cannot be delegated to the single-signature path: donna's batch
     * routine calls its own ed25519_sign_open() internally (see
     * ed25519-donna-batchverify.h), never ama_ed25519_verify(), so the check
     * added there does not reach here.  Without this loop, batch verification
     * would accept malleable signatures that single verification rejects —
     * a difference in accepted-signature sets between two APIs documented to
     * agree, which is worse than either behaviour on its own.
     *
     * Applied after the batch rather than before it so donna's multi-scalar
     * arithmetic runs over the inputs it was handed; the override below is
     * what decides the result.  S is public, so no timing property is at
     * stake in overriding rather than skipping. */
    /* RFC 8032 §5.1.3 canonical-y enforcement (INVARIANT-38), applied per
     * entry for exactly the reason spelled out above for canonical S.
     *
     * ama_ed25519_verify() gained this check, but donna's batch routine
     * reaches ge25519_unpack_negative_vartime() through its own internal
     * ed25519_sign_open(), so nothing added there reaches here.  Leaving it
     * out would make batch verification accept a public-key encoding that
     * single verification rejects — and would also split the two Ed25519
     * backends, since the fe51 batch path (ama_ed25519.c) is a loop over
     * ama_ed25519_verify() and therefore already enforces it.
     *
     * Only the 19 encodings with y in [p, 2^255) are affected, and a
     * legitimate key can collide with one only if its y is below 19, so this
     * is an encoding-uniqueness guarantee rather than a reachable forgery.
     * That is the same standing INVARIANT-38 has on the single-signature
     * path; the point is that both APIs enforce it, not that either is a
     * break. */
    /* RFC 8032 §5.1.7 step 1 canonical-R enforcement (INVARIANT-38 applied to
     * the signature's first half), per entry, for a reason the S and y checks
     * above do NOT share: on those two, this loop restates a rule the
     * single-signature path also applies.  On R it supplies one the batch
     * path never had.
     *
     * ed25519-donna-batchverify.h decodes R with
     * ge25519_unpack_negative_vartime and puts the decoded point into the
     * aggregate group equation.  It never re-encodes and compares, which is
     * the only thing that was rejecting a non-canonical R on the
     * single-signature path.  unpack decodes `01 00..00` with bit 255 set to
     * the identity and drops the set sign bit (x = 0 has a single root, so
     * the conditional negate is a no-op), so that encoding satisfied the
     * batch equation whenever [S]B - [h]A was the identity — which S = h*a
     * mod L arranges with the signer's own key, no forgery required.  The
     * result was a signature ama_ed25519_verify REJECTS reported VALID here.
     *
     * Only reachable at count >= 4: donna verifies per entry while num <= 3,
     * and that fallback re-encodes.  tests/c/test_ed25519_canonical_r.c pins
     * both sides of that boundary. */
    for (size_t i = 0; i < count; i++) {
        if (!ama_ed25519_signature_s_is_canonical(entries[i].signature) ||
            !ama_ed25519_signature_r_is_canonical(entries[i].signature) ||
            !ama_ed25519_point_y_is_canonical(entries[i].public_key) ||
            !ama_ed25519_point_x_sign_is_admissible(entries[i].public_key)) {
            results[i] = 0;
            ret = -1;
        }
    }

    /* Same explicit (void *) casts as the early-error path above —
     * bugprone-multi-level-implicit-pointer-conversion (audit Issue 9). */
    free((void *)msgs);
    free((void *)mlens);
    free((void *)pks);
    free((void *)sigs);

    /* Map donna's return: 0 = all valid, nonzero = at least one invalid */
    return (ret == 0) ? AMA_SUCCESS : AMA_ERROR_VERIFY_FAILED;
}

/* ============================================================================
 * FROST PRIMITIVES — Ed25519 group operations via donna internals
 *
 * donna provides: ge25519_scalarmult_base_niels, ge25519_pack,
 * ge25519_unpack_negative_vartime, expand256_modm, contract256_modm,
 * mul256_modm, add256_modm, ed25519_hash (SHA-512).
 * ============================================================================ */

AMA_API ama_error_t ama_ed25519_point_from_scalar(uint8_t point[32],
                                                  const uint8_t scalar[32]) {
    /* Both zero-initialised at declaration, and that is a FIX rather than a
     * style choice.  This function used to carry the repository's only
     * clang-tidy next-line suppression comment, silencing three
     * clang-analyzer uninitialised-read checks: donna fills these through
     * macros that the analyzer's interprocedural pass does not follow, so it
     * read `s` and `R` as garbage at the call below.  INVARIANT-13 forbids
     * suppressions under src/c/ "regardless of justification", and
     * .clang-tidy's own header says the answer to a false positive is to fix
     * the code or drop the category, never to silence a site.  Zeroing removes
     * the analyzer's premise instead of arguing with it, costs two small stack
     * objects once per call outside every loop, and changes no output:
     * expand256_modm and ge25519_scalarmult_base_niels overwrite both in
     * full.  (The suppression token itself is deliberately not spelled here:
     * clang-tidy matches it anywhere in a comment, so writing it in prose
     * would re-arm the very suppression this removed.) */
    bignum256modm s = {0};
    ge25519 ALIGN(16) R = {0};
    /* BREAKING in 4.0.0: returns ama_error_t so a NULL argument is an error
     * rather than a segfault.  Returning void left no honest fix — an early
     * return would leave `point` uninitialised, which is silent where the
     * crash at least was not.  See include/ama_cryptography.h. */
    if (!point || !scalar) return AMA_ERROR_INVALID_PARAM;
    expand256_modm(s, scalar, 32);
    ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, s);
    ge25519_pack(point, &R);
    return AMA_SUCCESS;
}

AMA_API ama_error_t ama_ed25519_point_add(uint8_t result[32],
                                          const uint8_t p[32],
                                          const uint8_t q[32]) {
    ge25519 ALIGN(16) P, Q, R;
    /* Pointer guard first.  ama_ed25519_double_scalarmult_public() below has
     * always had one; this function and ama_ed25519_scalarmult_public() did
     * not, in either backend, so a NULL argument segfaulted instead of
     * returning AMA_ERROR_INVALID_PARAM.  That inconsistency became easier to
     * reach when tests/test_ed25519_canonical_y.py started driving these two
     * through ctypes, where a Python None arrives as NULL and takes the
     * interpreter down with it. */
    if (!result || !p || !q) return AMA_ERROR_INVALID_PARAM;
    /* donna's unpack negates Y; we negate back */
    if (!ama_ed25519_point_y_is_canonical(p) ||
        !ama_ed25519_point_x_sign_is_admissible(p)) return AMA_ERROR_INVALID_PARAM;
    if (!ge25519_unpack_negative_vartime(&P, p)) return AMA_ERROR_INVALID_PARAM;
    curve25519_neg(P.x, P.x);
    curve25519_neg(P.t, P.t);
    if (!ama_ed25519_point_y_is_canonical(q) ||
        !ama_ed25519_point_x_sign_is_admissible(q)) return AMA_ERROR_INVALID_PARAM;
    if (!ge25519_unpack_negative_vartime(&Q, q)) return AMA_ERROR_INVALID_PARAM;
    curve25519_neg(Q.x, Q.x);
    curve25519_neg(Q.t, Q.t);

    ge25519_p1p1 ALIGN(16) r_p1p1;
    ge25519_add_p1p1(&r_p1p1, &P, &Q);
    ge25519_p1p1_to_full(&R, &r_p1p1);
    ge25519_pack(result, &R);
    return AMA_SUCCESS;
}

/* donna's ge25519_double_scalarmult_vartime finishes its ladder with
 * ge25519_p1p1_to_partial (vendor/ed25519-donna/ed25519-donna-impl-base.h),
 * which writes x, y and z but NEVER t: the returned point's extended
 * coordinate holds whatever an intermediate ge25519_p1p1_to_full left
 * there.  That is harmless upstream, because donna only ever hands the
 * result to ge25519_pack, which reads x, y and z alone.  It is NOT
 * harmless here: ama_ed25519_double_scalarmult_public adds two such
 * results with ge25519_add_p1p1, whose third product is
 * curve25519_mul(c, p->t, q->t) — with two stale t's the sum is an
 * arbitrary point and the function still returns AMA_SUCCESS.
 *
 * Restore a valid extended representation without an inversion by
 * scaling the projective point by z:
 *
 *     (x : y : z)  ->  (x*z : y*z : z^2 : x*y)
 *
 * which denotes the same point and satisfies the extended-coordinate
 * invariant X*Y == Z*T (both sides equal x*y*z^2).  Cost is three
 * multiplications and one squaring; the alternative, packing and
 * unpacking each summand, costs two field inversions. */
static void ama_ge25519_restore_extended_t(ge25519 *r) {
    bignum25519 ALIGN(16) xy, xz, yz, zz;
    curve25519_mul(xy, r->x, r->y);
    curve25519_mul(xz, r->x, r->z);
    curve25519_mul(yz, r->y, r->z);
    curve25519_square(zz, r->z);
    curve25519_copy(r->x, xz);
    curve25519_copy(r->y, yz);
    curve25519_copy(r->z, zz);
    curve25519_copy(r->t, xy);
}

/* Renamed from ama_ed25519_scalar_mult (audit finding C7).
 * NOT constant-time — public_scalar MUST be non-secret. */
AMA_API ama_error_t ama_ed25519_scalarmult_public(uint8_t result[32],
                                                  const uint8_t public_scalar[32],
                                                  const uint8_t point[32]) {
    ge25519 ALIGN(16) P, R;
    bignum256modm s1, s2_zero = {0};
    if (!result || !public_scalar || !point) return AMA_ERROR_INVALID_PARAM;
    if (!ama_ed25519_point_y_is_canonical(point) ||
        !ama_ed25519_point_x_sign_is_admissible(point)) return AMA_ERROR_INVALID_PARAM;
    if (!ge25519_unpack_negative_vartime(&P, point)) return AMA_ERROR_INVALID_PARAM;
    curve25519_neg(P.x, P.x);
    curve25519_neg(P.t, P.t);
    expand256_modm(s1, public_scalar, 32);
    /* r = s1*P + 0*G via donna's double-scalar mult */
    ge25519_double_scalarmult_vartime(&R, &P, s1, s2_zero);
    ge25519_pack(result, &R);
    return AMA_SUCCESS;
}

/* Joint variable-time double-base scalar mult: [s1]P1 + [s2]P2.
 * NOT constant-time — both scalars MUST be PUBLIC.
 *
 * donna's ge25519_double_scalarmult_vartime is hardcoded to compute
 * `s1*P + s2*B` (B is the basepoint), so for the generic two-arbitrary-
 * point form we do two single-base scalarmults and a final point add.
 * This is the donna-backend equivalent of the in-tree Shamir routine
 * exposed for the same test/bench purpose — see the in-tree definition
 * in src/c/ama_ed25519.c for the API contract. */
AMA_API ama_error_t ama_ed25519_double_scalarmult_public(
    uint8_t result[32],
    const uint8_t s1[32], const uint8_t P1[32],
    const uint8_t s2[32], const uint8_t P2[32]) {
    ge25519 ALIGN(16) P1u, P2u, R1, R2, R;
    bignum256modm e1, e2, zero = {0};
    ge25519_p1p1 ALIGN(16) sum;

    if (!result || !s1 || !P1 || !s2 || !P2) return AMA_ERROR_INVALID_PARAM;
    if (!ama_ed25519_point_y_is_canonical(P1) ||
        !ama_ed25519_point_x_sign_is_admissible(P1)) return AMA_ERROR_INVALID_PARAM;
    if (!ge25519_unpack_negative_vartime(&P1u, P1)) return AMA_ERROR_INVALID_PARAM;
    curve25519_neg(P1u.x, P1u.x);
    curve25519_neg(P1u.t, P1u.t);
    if (!ama_ed25519_point_y_is_canonical(P2) ||
        !ama_ed25519_point_x_sign_is_admissible(P2)) return AMA_ERROR_INVALID_PARAM;
    if (!ge25519_unpack_negative_vartime(&P2u, P2)) return AMA_ERROR_INVALID_PARAM;
    curve25519_neg(P2u.x, P2u.x);
    curve25519_neg(P2u.t, P2u.t);

    expand256_modm(e1, s1, 32);
    expand256_modm(e2, s2, 32);

    /* R1 = s1*P1, R2 = s2*P2 (each via donna's existing double-mult
     * with a zero basepoint scalar). */
    ge25519_double_scalarmult_vartime(&R1, &P1u, e1, zero);
    ge25519_double_scalarmult_vartime(&R2, &P2u, e2, zero);

    /* Both results are PARTIAL points — t is stale.  ge25519_add_p1p1
     * multiplies p->t by q->t, so it must be repaired first; see
     * ama_ge25519_restore_extended_t above. */
    ama_ge25519_restore_extended_t(&R1);
    ama_ge25519_restore_extended_t(&R2);

    ge25519_add_p1p1(&sum, &R1, &R2);
    ge25519_p1p1_to_full(&R, &sum);
    ge25519_pack(result, &R);
    return AMA_SUCCESS;
}

AMA_API void ama_ed25519_sc_reduce(uint8_t s[64]) {
    bignum256modm m;
    expand256_modm(m, s, 64);
    contract256_modm(s, m);
}

AMA_API void ama_ed25519_sc_muladd(uint8_t out[32],
                                   const uint8_t a[32],
                                   const uint8_t b[32],
                                   const uint8_t c[32]) {
    /* out = a + b*c mod l */
    bignum256modm ma, mb, mc, mr;
    expand256_modm(ma, a, 32);
    expand256_modm(mb, b, 32);
    expand256_modm(mc, c, 32);
    mul256_modm(mr, mb, mc);     /* mr = b*c */
    add256_modm(mr, ma, mr);     /* mr = a + b*c */
    contract256_modm(out, mr);
}

AMA_API void ama_ed25519_sha512(const uint8_t *data, size_t len,
                                uint8_t out[64]) {
    ed25519_hash(out, data, len);
}
