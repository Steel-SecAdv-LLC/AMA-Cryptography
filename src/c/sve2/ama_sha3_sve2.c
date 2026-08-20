/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_sha3_sve2.c
 * @brief ARM SVE2-optimized Keccak-f[1600] permutation + SHA3-256 wrapper
 *
 * SVE2 (Scalable Vector Extension 2) for ARMv9 processors.
 * Uses scalable vectors that adapt to hardware vector length.
 *
 * Wired surface (`src/c/dispatch/ama_dispatch.c`):
 *   - `ama_keccak_f1600_sve2` — single-state permutation (line ~589).
 *   - `ama_sha3_256_sve2`     — SHA3-256 wrapper (line ~590, this PR).
 *
 * The SHA3-256 wrapper reuses the wired Keccak permutation above; the
 * only SVE2-specific work is the rate-block absorb (predicated XOR via
 * `sveor_u64_x`).  Algorithmic correctness is straightforward (it is
 * literally FIPS 202's sponge construction at rate=136, padding 0x06)
 * and is pinned by every SHA3-256 KAT in the suite once the dispatch
 * pointer is set.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__ARM_FEATURE_SVE2)
#include <arm_sve.h>
#include "ama_sve2_internal.h"

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const int ROTC[25] = {
     0,  1, 62, 28, 27, 36, 44,  6, 55, 20,
     3, 10, 43, 25, 39, 41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
};

static const int PI[25] = {
     0, 10, 20,  5, 15, 16,  1, 11, 21,  6,
     7, 17,  2, 12, 22, 23,  8, 18,  3, 13,
    14, 24,  9, 19,  4,
};

/* ============================================================================
 * Keccak-f[1600] in the SVE2 translation unit — SCALAR, deliberately.
 *
 * This function contains no SVE intrinsics.  It once did: theta's five-element
 * column parity was strip-mined through one `svwhilelt_b64(0, 5)` predicate,
 * which activates at most `min(5, svcntd())` lanes and therefore left 3 of the
 * 5 parity words uninitialised at VL=128 and 1 at VL=256 — correct only at
 * VL >= 320, which is why QEMU's default 2048-bit `max` CPU was the one
 * environment where it was ever exercised.  The fix was to compute theta in
 * scalar C, and the measurement that settled it is in the comment on the loop
 * below: a vector-length-agnostic form of that five-element reduction is
 * 15.9x slower at VL=128, 10.0x at VL=256 and 5.6x at VL=512 than the 20
 * scalar XORs it would replace, because the time goes into predicate setup.
 * rho/pi/chi/iota were always scalar.
 *
 * The header said "Uses SVE2 scalable vectors for theta column-parity XOR and
 * chi step" and a comment on the chi loop said "use SVE2 for vectorized
 * bic-and-xor", after the vectors had been removed from both.  A file that
 * describes work it does not do is how a reader concludes the SVE2 tier is
 * earning something here that it is not.
 *
 * What the SVE2 tier does earn in this file is `ama_sha3_256_sve2`'s
 * lane-predicated rate-block absorb, which is genuinely vectorised.  The
 * permutation is kept in this TU so that wrapper can call it directly, and
 * because the dispatcher's Phase-3 auto-tune measures whatever pointer is
 * installed: if this kernel is slower than the scalar baseline on a given
 * host, the auto-tune now reverts to a tier it has ALSO measured.
 * ============================================================================ */
void ama_keccak_f1600_sve2(uint64_t state[25]) {
    uint64_t C[5], D[5], B[25];

    for (int round = 0; round < 24; round++) {
        /* Theta: column parity.
         *
         * Computed scalar, and that is a correctness requirement rather than a
         * missed optimisation.  The previous form built one predicate
         * `svwhilelt_b64(0, 5)` and issued five `svld1_u64` / `sveor` / one
         * `svst1_u64` against it — but a predicate can activate at most
         * `svcntd()` lanes, which is the HARDWARE vector length, not the 5 the
         * bound asks for.  At VL=128 (2 lanes) only C[0..1] were written and at
         * VL=256 (4 lanes) C[4] was not, so the D[] computation below consumed
         * uninitialised stack and mixed it into the state — wrong digests, and
         * undefined behaviour besides.  Every SVE2 part shipping today is
         * VL=128 (Neoverse N2/V2/V3, Cortex-X2..X4, A710/A715/A720, Graviton 4)
         * or VL=256, i.e. exactly the hardware where this dispatches.  It went
         * unseen because the only environment this path was ever exercised in
         * is QEMU's default `max` CPU, whose 2048-bit vectors activate all five
         * lanes and hide the bug.
         *
         * Whether to restore a vector form, written vector-length-agnostically,
         * was left open in review.  It is settled here by measurement rather
         * than preference: a correctly strip-mined VLA reduction is SLOWER
         * than the scalar form at every vector length, because a five-element
         * reduction cannot fill a vector.  aarch64-linux-gnu-gcc 13.3
         * -O2 -march=armv9-a+sve2, 2,000,000 calls under qemu-aarch64-static:
         *
         *   VL   scalar    VLA vector   ratio
         *   128  108.1 ms  1720.0 ms    15.9x slower  (3 strip-mine passes)
         *   256  114.7 ms  1144.7 ms    10.0x slower  (2 passes)
         *   512  108.6 ms   612.0 ms     5.6x slower  (1 pass + loop overhead)
         *
         * Static instruction counts agree on the direction: 16 for the scalar
         * form against a 20-instruction loop BODY for the vector one, executed
         * three times at VL=128 and twice at VL=256.  QEMU translates rather
         * than models a pipeline, so treat the ratios as indicative and the
         * ordering as sound — they agree at every VL and with the static count,
         * and the gap is an order of magnitude, not a margin.
         *
         * The same harness re-confirmed the defect this replaced: the
         * single-predicate form produces the wrong parity at VL=128 and VL=256
         * and the right one at VL=512, exactly as the lane analysis predicts.
         *
         * So the scalar form is kept — it is both correct at every VL and the
         * faster of the two on all shipping SVE2 silicon.  The permutation's
         * real vector work is elsewhere.  The absorb loop below is separately
         * strip-mined (it reduces over 17 lanes, which does fill a vector) and
         * is not affected. */
        for (int i = 0; i < 5; i++) {
            C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }

        /* D[i] = C[(i+4)%5] ^ ROT(C[(i+1)%5], 1) */
        for (int i = 0; i < 5; i++) {
            D[i] = C[(i + 4) % 5] ^ ((C[(i + 1) % 5] << 1) | (C[(i + 1) % 5] >> 63));
        }

        /* Apply D to state */
        for (int i = 0; i < 25; i++) {
            state[i] ^= D[i % 5];
        }

        /* Rho and Pi */
        for (int i = 0; i < 25; i++) {
            int r = ROTC[i];
            B[PI[i]] = (r == 0) ? state[i] : ((state[i] << r) | (state[i] >> (64 - r)));
        }

        /* Chi: scalar bic-and-xor.  (An earlier comment here said "use SVE2
         * for vectorized bic-and-xor"; there are no vectors in these five
         * lines and there never were in the shipped form.) */
        for (int y = 0; y < 25; y += 5) {
            state[y + 0] = B[y + 0] ^ (~B[y + 1] & B[y + 2]);
            state[y + 1] = B[y + 1] ^ (~B[y + 2] & B[y + 3]);
            state[y + 2] = B[y + 2] ^ (~B[y + 3] & B[y + 4]);
            state[y + 3] = B[y + 3] ^ (~B[y + 4] & B[y + 0]);
            state[y + 4] = B[y + 4] ^ (~B[y + 0] & B[y + 1]);
        }

        /* Iota */
        state[0] ^= RC[round];
    }
}

/* ============================================================================
 * SVE2 SHA3-256 — single-shot hash (no streaming API).
 *
 * FIPS 202 sponge: absorb `input` at rate=136 bytes, pad with 0x06 ||
 * 0* || 0x80, run f1600 over the final block, squeeze 32 output bytes.
 * The absorb XOR is the only SVE2-vectorised step (lane-predicated
 * `svld1_u64` / `sveor_u64_x` pair over the rate-block lanes); the
 * permutation reuses `ama_keccak_f1600_sve2` above.
 *
 * Signature matches `ama_sha3_256_fn` in `include/ama_dispatch.h`
 * (returns `ama_error_t`) so the dispatcher can wire this function
 * directly into `dispatch_table.sha3_256`.  Pinned by the existing
 * SHA3-256 KATs at every layer (the FIPS 202 vectors flow through
 * the dispatched `sha3_256` slot).
 * ============================================================================ */
ama_error_t ama_sha3_256_sve2(const uint8_t *input, size_t input_len, uint8_t output[32]) {
    if (!output) return AMA_ERROR_INVALID_PARAM;
    if (!input && input_len > 0) return AMA_ERROR_INVALID_PARAM;

    uint64_t state[25];
    memset(state, 0, sizeof(state));  // PUBLIC-DATA: state — SVE2 Keccak permutation buffer, pre-use init; post-use scrub via ama_secure_memzero at function exit
    const size_t rate = 136;
    size_t offset = 0;

    while (offset + rate <= input_len) {
        /* Absorb a full rate block using SVE2 lane-predicated XOR. */
        size_t lanes = rate / 8;
        size_t i = 0;
        while (i < lanes) {
            svbool_t pg = svwhilelt_b64((int64_t)i, (int64_t)lanes);
            svuint64_t vs = svld1_u64(pg, &state[i]);
            uint64_t temp[17];
            for (size_t j = i; j < lanes && j < i + svcntd(); j++) {
                memcpy(&temp[j - i], input + offset + j * 8, 8);
            }
            svuint64_t vi = svld1_u64(pg, temp);
            svst1_u64(pg, &state[i], sveor_u64_x(pg, vs, vi));
            i += svcntd();
        }
        ama_keccak_f1600_sve2(state);
        offset += rate;
    }

    /* Final block with SHA-3 padding (0x06 marker + 0x80 sentinel). */
    uint8_t block[200];
    memset(block, 0, sizeof(block));  // PUBLIC-DATA: block — SVE2 SHA3 rate-block padding buffer, pre-use init filled by memcpy + 0x06/0x80 padding
    size_t remaining = input_len - offset;
    if (remaining > 0)
        memcpy(block, input + offset, remaining);
    block[remaining] = 0x06;
    block[rate - 1] |= 0x80;

    for (size_t i = 0; i < rate / 8; i++) {
        uint64_t lane;
        memcpy(&lane, block + i * 8, 8);
        state[i] ^= lane;
    }
    ama_keccak_f1600_sve2(state);

    memcpy(output, state, 32);

    /* Scrub Keccak state and padding scratch buffer.  `ama_secure_memzero`
     * is guaranteed not to be optimised away (audit finding MEM-1). */
    ama_secure_memzero(state, sizeof(state));
    ama_secure_memzero(block, sizeof(block));

    return AMA_SUCCESS;
}

#else
typedef int ama_sha3_sve2_not_available;
#endif /* __ARM_FEATURE_SVE2 */
