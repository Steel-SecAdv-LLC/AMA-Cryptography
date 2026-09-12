/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
#ifndef AMA_DUDECT_STAGE_H
#define AMA_DUDECT_STAGE_H

/*
 * Shared class-input staging for every dudect harness in the tree
 * (tests/c/test_dudect.c and the two standalone harnesses under
 * tools/constant_time).  One implementation, so the discipline stated below
 * cannot hold in one harness and be missing from another — which is exactly
 * how it came to be missing from the newer lanes while the older ones had it.
 *
 * tools/check_dudect_class_staging.py enforces the rule this header states.
 */

#include <stddef.h>

/* --------------------------------------------------------------------------
 * Class staging
 * --------------------------------------------------------------------------
 * A lane compares two input classes, and the two classes must differ in the
 * property under test and in NOTHING ELSE.  Handing the timed call one of two
 * per-class buffers breaks that: the classes then differ in the input's
 * ADDRESS as well as its value, and a load's timing legitimately depends on
 * its address — which cache line it falls in, whether it spans two, which set
 * it maps to.  That difference is fixed for a given binary on a given host,
 * so it reproduces in every round with the same sign, which is exactly what a
 * real leak looks like and exactly what no threshold or number of rounds can
 * separate from one.
 *
 * Measured on this tree with the Ascon-AEAD128-encrypt lane's own cipher call
 * and IDENTICAL key data in both classes, so the true effect is exactly zero:
 * placing class 0's key across two cache lines while class 1's sits inside
 * one drives the cropped statistic to |t| = 13.5..30.9, over threshold in 10
 * of 10 runs, all one sign.  Staged through a single buffer the same
 * measurement reports 0 of 10.
 *
 * This became reachable when the harnesses adopted percentile cropping, which
 * resolves the BULK of the timing distribution: a lane measured here has a
 * cropped bulk standard deviation of about 4 ns over ~22,000 samples per
 * class, so the standard error is ~0.04 ns and the threshold is crossed by a
 * systematic difference of roughly 0.2 ns — under half a cycle at 2.1 GHz.
 * At that resolution the harness's own memory layout is a first-class
 * confounder.
 *
 * So a lane copies the selected class's input into ONE shared, cache-line-
 * aligned buffer and hands the timed call that.  Both classes then present
 * the same address and the same alignment, and only the DATA differs.  The
 * copy is identical work for both classes and happens outside the timed
 * region.  Sensitivity is untouched: a data-dependent leak follows the data.
 *
 * Staging the DESTINATION is not sufficient, and the first form of this
 * helper only did that
 * -----------------------------------------------------------------------
 * The earlier signature took one already-selected source pointer, so every
 * caller wrote
 *
 *     dudect_stage(buf, class_idx ? A : B, sizeof buf);
 *
 * and the selection itself stayed inside the loop, between the class draw
 * and the opening timer call.  That leaves two class-correlated effects in
 * exactly the window the measurement is most sensitive to:
 *
 *   1. the ternary compiles to a CONDITIONAL BRANCH whose direction is
 *      perfectly correlated with the class, so its misprediction penalty is
 *      paid immediately before the timer opens and, on an out-of-order core,
 *      retires inside the timed region; and
 *   2. `A` and `B` are two different objects, so the staging copy's own
 *      source address — line, set, alignment — is class-correlated too.
 *
 * Measured on this tree with the AES-GCM forgery-position lane's own decrypt
 * call and BYTE-IDENTICAL input in both classes, so the true effect is
 * exactly zero (500,000 measurements per run, 8 runs, |t| threshold 5.0):
 *
 *   construction                                        over threshold  worst |t|
 *   --------------------------------------------------  --------------  ---------
 *   two sources + ternary select (the old form)             4/8, 4/8, 1/8    7.85
 *   one aligned two-entry source, indexed (no branch)             0/8         2.79
 *   two sources, branch-free pointer select                       0/8         2.18
 *   one aligned two-entry source + ternary select                 0/8         4.47
 *   both sources merged under a mask (this helper)                0/8         3.01
 *
 * The branch is the dominant term — the two rows that keep it are the only
 * ones that trip or drift toward the threshold — and the source-address
 * asymmetry compounds it.  That is not a fault the multi-round majority rule
 * or the direction rule in dudect_rounds.h can absorb: like any layout bias
 * it is fixed for a given binary on a given host, so it reproduces every
 * round with one sign, which is the exact shape of a real leak.  It is why
 * the shipped AES-GCM forgery-position lane read |t| = 61..75 with a
 * consistent sign on two different CI hosts while the decrypt it measures
 * executes a bit-identical instruction stream for both classes (2,000 and
 * 20,000 repetitions under callgrind, scalar / AES-NI-AVX2 / VAES: the
 * per-call difference is zero in all three).
 *
 * So the selection is part of the staging.  This helper takes BOTH class
 * inputs, reads both on every iteration, and merges them under a
 * constant-time mask: no branch depends on the class, and the address stream
 * is identical whichever class was drawn — by construction, at any input
 * size, rather than by the coincidence that two small buffers landed in one
 * cache line.
 * -------------------------------------------------------------------------- */
static inline const void *dudect_stage_select(void *staging,
                                              const void *src0,
                                              const void *src1,
                                              size_t len, int cls) {
    unsigned char *dst = (unsigned char *)staging;
    const unsigned char *a = (const unsigned char *)src0;
    const unsigned char *b = (const unsigned char *)src1;
    /* The mask is read back through a volatile so the compiler cannot prove
     * it is one of {0x00, 0xFF} and unswitch the merge into the two-armed
     * copy this helper exists to remove.  One volatile byte per staged
     * input, outside the timed region; the merge loop itself is branchless.
     * tools/check_dudect_class_staging.py enforces that no lane reaches the
     * timer with a class-dependent branch still in front of it. */
    volatile unsigned char mask_cell = (unsigned char)(0u - (unsigned)(cls & 1));
    const unsigned char m = mask_cell;
    size_t i;
    for (i = 0; i < len; i++) {
        dst[i] = (unsigned char)((a[i] & (unsigned char)~m) | (b[i] & m));
    }
    return staging;
}

#endif /* AMA_DUDECT_STAGE_H */
