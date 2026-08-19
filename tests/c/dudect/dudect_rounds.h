/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file dudect_rounds.h
 * @brief Multi-round verdict rule shared by every dudect harness in the tree.
 *
 * ============================================================================
 * WHAT THIS REPLACES, AND WHY IT IS ONE FILE
 * ============================================================================
 *
 * Three harnesses ran the same multi-round loop and each got the same thing
 * wrong: `tests/c/test_dudect.c`, `tools/constant_time/dudect_crypto.c` and
 * `tools/constant_time/dudect_harness.c`.  All three printed "Retrying to rule
 * out noise" (or "environmental noise"), and none of them ruled out anything.
 *
 * The loop passed when *any single round* had no failing lane and failed
 * otherwise — without ever checking whether the **same** lane failed twice.
 * With ~24 lanes and ordinary scheduling jitter on a shared runner, a
 * different lane tripping in each of three rounds is a routine outcome, and
 * the harness then reported "Potential timing leakage detected across 3
 * rounds": a claim of consistency it had never tested.  A false alarm from
 * these gates is indistinguishable in the log from a real finding, which is
 * the property that makes a real finding get waved through.
 *
 * The rule here is the one those messages already promised, at the tighter of
 * the two readings: **a lane must exceed the threshold in a majority of rounds
 * to count as a failure.**  A leak reproduces — its t-statistic grows with
 * measurements and the same lane trips most or all of the time.  Noise moves.
 * The per-lane threshold is untouched, so this removes false alarms rather
 * than sensitivity.
 *
 * Two of the three harnesses also discarded their per-lane t-values between
 * rounds (`run_round` returned a bool), so the summary could not show whether
 * a finding reproduced — the single most useful fact about a timing result.
 * Evidence is accumulated here instead, and printed as a `failed/run` ratio
 * beside each lane.
 *
 * It lives in one header because three copies of a security-gate decision rule
 * is how the copies drift apart, and because the self-test below then covers
 * all three at once.
 *
 * ============================================================================
 * WHY MAJORITY AND NOT ALL
 * ============================================================================
 *
 * "Every round" and "most rounds" both rule out the one-off, and the choice
 * between them only matters for a lane sitting right at the threshold.  Under
 * an all-rounds rule such a lane — tripping two rounds in three — is reported
 * as noise and the run goes green.  That is the wrong way to be wrong: a
 * primitive drifting toward a real leak is exactly the finding this gate exists
 * to surface, and one within-threshold round is a thin reason to discard two
 * over-threshold ones.  A majority keeps the property that made the change
 * worth making (a single trip never fails the build) while refusing to sit on
 * repeated evidence.
 *
 * The summary still prints the ratio beside every lane, so a 1/3 is visible as
 * a `NOISE` row rather than vanishing.  Nothing is hidden; the difference is
 * only where the build stops.
 *
 * This interacts with the early exit, and the interaction is easy to get
 * wrong.  Under an all-rounds rule, stopping at the first clean round is
 * always safe.  Under a majority it is not: a lane that tripped round 1 and is
 * clean in round 2 sits at 1/2, but had round 3 run and tripped it would be
 * 2/3 — a failure the early exit would have skipped.  So the loop stops early
 * only while *nothing* has tripped at all (`dudect_rounds_any_failure`), which
 * keeps the one-round fast path for a healthy run and forces the full schedule
 * precisely when the extra evidence is what decides the verdict.
 *
 * A lane flagged `fatal` — a setup failure or a per-class return-code mismatch
 * — is exempt from the majority rule and from info-only suppression.  It is
 * not a timing measurement, so retrying it proves nothing and one occurrence
 * is conclusive: the lane never witnessed its invariant.
 */

#ifndef AMA_DUDECT_ROUNDS_H
#define AMA_DUDECT_ROUNDS_H

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Upper bound on lanes any one harness registers.  Overridable so a harness
 * with more lanes can raise it at its own include site rather than silently
 * truncating. */
#ifndef DUDECT_ROUNDS_MAX_LANES
#define DUDECT_ROUNDS_MAX_LANES 32
#endif

/* ============================================================================
 * THE EFFECT-SIZE FLOOR, AND WHY A t-VALUE ALONE CANNOT DECIDE
 * ============================================================================
 *
 * t = (m0 - m1) / se, and se falls as 1/sqrt(n).  So for ANY difference that
 * is not exactly zero, |t| grows without bound as measurements accumulate:
 * significance is a statement about how well a difference was RESOLVED, not
 * about how large it is.  A gate that reads only |t| therefore decides on
 * measurement precision, and at high measurement counts it decides on
 * differences far below anything a timing attack could use — or a CPU could
 * even produce from the source under test.
 *
 * That is not a theoretical worry here; it is what this harness did.  On one
 * CI run at 100,000 measurements, with the percentile-cropped statistic:
 *
 *     lane                                    |t|        difference
 *     --------------------------------------  ---------  ----------
 *     AES-GCM tag verify                        6.27       +0.199 ns   FAILED
 *     Ascon-AEAD128 encrypt                    21.88       +0.596 ns   FAILED
 *     agent binding check                      41.72       -1.141 ns   FAILED
 *     secp256k1 scalar multiplication           1.44      -35.200 ns   passed
 *     X25519 scalarmult batch x4                2.03      -78.135 ns   passed
 *     SLH-DSA-SHA2-256f sign                    2.14   +53932.078 ns   passed
 *
 * The lanes that failed are the ones measured most precisely, not the ones
 * with the largest difference — by five orders of magnitude in the other
 * direction.  Every failing difference is between a fraction of one CPU cycle
 * and about two cycles.
 *
 * And they are not properties of the code.  In the SAME workflow run, on a
 * second runner, the same binary read `Ascon-AEAD128 encrypt` at -2.87 (clean)
 * and `agent binding check` with its excursions pointing the other way.  A
 * difference that reverses between two machines running identical instructions
 * is a property of the machines.  This repository has already identified what
 * it is and recorded it in `.github/workflows/dudect.yml`: data-operand-
 * dependent execution — what Intel's DOITM and ARM's PSTATE.DIT exist to
 * control — measured there against retired-instruction counts that are
 * IDENTICAL across all eight input classes, cross-class delta 0, noise floor
 * 0.
 *
 * That is one candidate, and it is the one this repository named first.  The
 * candidate it has since MEASURED is closer to home: a class-correlated
 * branch or address in the harness itself, between the class draw and the
 * opening timer.  Run as a null experiment — byte-identical input in both
 * classes, so the true effect is exactly zero — the ternary class select the
 * lanes used to carry reads over threshold in 4 of 8 runs on the AES-GCM
 * decrypt lane and 3 of 5 on the Kyber decapsulation lane, every excursion
 * one sign, while the masked-merge staging that replaced it reads 0 of 8 and
 * 0 of 5.  Both explanations produce a difference that is fixed for a binary
 * on a host and reverses between hosts; the difference is that this one is
 * the harness's to remove, and it has been.  Anything a lane reports now is
 * measured with `dudect_stage_select` in front of it and
 * `tools/check_dudect_class_staging.py` enforcing that nothing else gets in.
 *
 * So the floor below is not a tolerance for leaks.  It is the resolution
 * limit of a wall-clock apparatus on shared hardware, stated instead of
 * ignored, and everything under it is delegated to the tool that can actually
 * decide it: the deterministic instruction-count gates
 * (`tools/check_ghash_constant_time.py --target ghash|consttime|ascon-hash`),
 * which measure retired instructions with a zero-instruction noise floor and
 * cannot flake.
 *
 * WHAT THE FLOOR MUST NOT DO is hide a leak, so it is set from measurement in
 * both directions:
 *
 *   above every artefact observed          largest was 1.141 ns
 *   below every real leak mechanism        a mispredicted branch is 7-10 ns,
 *                                          an L1 miss 30-50 ns, one extra AES
 *                                          round ~4 ns, and the early-exit
 *                                          memcmp this statistic was
 *                                          calibrated against moves the mean
 *                                          by hundreds of ns
 *
 * 2 ns clears the largest observed artefact by 1.8x and sits at least 3.5x
 * below the cheapest real mechanism.  Measured directly against the canary
 * this statistic was calibrated on — a textbook early-exit ``memcmp`` over 64
 * bytes, first-byte versus last-byte mismatch, 10 repetitions of 50,000
 * measurements on a quiet host:
 *
 *     leaky memcmp        |t| = 412..481, over threshold 10/10,  |diff| = 22.4 ns
 *     ama_consttime_memcmp |t| = 0.9..3.2, over threshold  0/10,  |diff| =  1.8 ns
 *
 * The leak clears the floor by 11x and would clear it at a tenth of the
 * measurements.  The constant-time function's own difference lands at 1.8 ns
 * on a QUIET machine, which is the apparatus's noise floor measured a second
 * way and independently puts the floor at the right order of magnitude.  For scale, this repository already
 * applies exactly this discipline to its Python POST timing oracle, where
 * `ama_cryptography/_self_test.py` sets `_TIMING_MIN_EFFECT_NS` to
 * `max(50, 4 x clock_resolution)` — 50 ns on Linux — for the same reason and
 * citing the same runner behaviour.  This floor is 25x stricter than that.
 *
 * A lane under the floor is NOT reported as a pass.  It gets its own verdict
 * (DUDECT_LANE_SUB_FLOOR), prints its difference, and says which gate owns
 * the claim it could not make.  Nothing is silent. */
#ifndef DUDECT_MIN_EFFECT_NS
#define DUDECT_MIN_EFFECT_NS 2.0
#endif

/**
 * What one lane measured: the statistic AND the effect size behind it.
 *
 * These travel together because a verdict needs both — see
 * DUDECT_MIN_EFFECT_NS.  Returning a bare `double` from a lane is what let
 * the effect size go unconsidered in the first place, so the harnesses return
 * this instead.
 */
typedef struct {
    double t;        /**< the percentile-cropped Welch statistic */
    double delta_ns; /**< per-class mean difference behind it, nanoseconds */
} dudect_measurement_t;

/** One lane's outcome for one round. */
typedef struct {
    const char *name;
    double      t_value;
    int         is_info_only; /**< 1 = report the t-value, never fail on it */
    int         is_fatal;     /**< 1 = harness fault; conclusive on one sighting */
    /** Per-class mean difference behind `t_value`, in nanoseconds.  The
     *  effect size; see DUDECT_MIN_EFFECT_NS above for why a verdict needs
     *  it.  A harness that cannot supply it leaves it 0.0, which reads as
     *  "below any floor" — so a lane whose effect size is unknown can report
     *  a measurement but can never, on its own, fail a build. */
    double      delta_ns;
} dudect_lane_result_t;

/** What a lane did across every round run so far. */
typedef struct {
    const char *name;
    int         is_info_only;
    int         rounds_failed; /**< rounds in which |t| >= threshold */
    int         trips_positive; /**< over-threshold rounds with t > 0 */
    int         trips_negative; /**< over-threshold rounds with t < 0 */
    int         fatal;         /**< saw a harness fault at least once */
    double      worst_t;       /**< signed t of the largest |t| observed */
    /** Effect size recorded with `worst_t`, and the largest |difference|
     *  seen in any OVER-THRESHOLD round.  The second is what the floor is
     *  applied to: a lane must have been both significant and large in the
     *  same rounds, and taking the largest over-threshold difference is the
     *  reading most favourable to calling it a finding. */
    double      worst_t_delta_ns;
    double      max_trip_delta_ns;
} dudect_lane_evidence_t;

/** Accumulated evidence for a whole run. */
typedef struct {
    dudect_lane_evidence_t lanes[DUDECT_ROUNDS_MAX_LANES];
    int    num_lanes;
    int    rounds_run;
    double threshold;
} dudect_rounds_t;

static inline void dudect_rounds_init(dudect_rounds_t *r, double threshold) {
    memset(r, 0, sizeof(*r));
    r->threshold = threshold;
}

/**
 * Fold one round's per-lane results into the running evidence.
 *
 * Lanes are expected in a fixed order across rounds; the name is compared as
 * well as the index so a future reordering aborts rather than silently
 * attributing one lane's measurement to another.
 */
static inline void dudect_rounds_add(dudect_rounds_t *r,
                                     const dudect_lane_result_t *results,
                                     int num_results) {
    if (num_results > DUDECT_ROUNDS_MAX_LANES) {
        fprintf(stderr, "  FATAL: %d lanes exceeds DUDECT_ROUNDS_MAX_LANES=%d\n",
                num_results, DUDECT_ROUNDS_MAX_LANES);
        abort();
    }

    if (r->num_lanes == 0) {
        for (int i = 0; i < num_results; i++) {
            r->lanes[i].name          = results[i].name;
            r->lanes[i].is_info_only  = results[i].is_info_only;
            r->lanes[i].rounds_failed  = 0;
            r->lanes[i].trips_positive = 0;
            r->lanes[i].trips_negative = 0;
            r->lanes[i].fatal          = 0;
            r->lanes[i].worst_t        = 0.0;
            r->lanes[i].worst_t_delta_ns = 0.0;
            r->lanes[i].max_trip_delta_ns = 0.0;
        }
        r->num_lanes = num_results;
    } else if (num_results != r->num_lanes) {
        fprintf(stderr, "  FATAL: lane count changed between rounds (%d -> %d)\n",
                r->num_lanes, num_results);
        abort();
    }

    for (int i = 0; i < num_results; i++) {
        if (strcmp(r->lanes[i].name, results[i].name) != 0) {
            fprintf(stderr,
                    "  FATAL: lane %d changed identity between rounds ('%s' -> '%s')\n",
                    i, r->lanes[i].name, results[i].name);
            abort();
        }
        if (results[i].is_fatal) {
            r->lanes[i].fatal = 1;
            r->lanes[i].rounds_failed++;
            continue;
        }
        if (fabs(results[i].t_value) >= r->threshold) {
            /* A tripped lane MUST carry an effect size.  The statistic IS
             * `delta / se`, so |t| at or over the threshold with `delta_ns`
             * exactly 0.0 is not a small effect — it is arithmetically
             * impossible from a real measurement, and can only mean the
             * harness never populated the field.  That matters because the
             * floor below adjudicates on `max_trip_delta_ns`: without this
             * check a lane whose harness omits the effect size would be
             * classified SUB-FLOOR and could never fail a build, which is
             * the silent-gate-erosion failure mode this whole rule exists to
             * avoid.  It is a harness fault, and it is fatal.
             *
             * Info-only lanes are exempt, and deliberately so: they cannot
             * reach the floor because dudect_lane_verdict() classifies them
             * NOISE before it ever looks at an effect size, so a missing
             * delta there erodes nothing.  The check is scoped to exactly the
             * lanes whose verdict the floor decides. */
            if (!results[i].is_info_only && results[i].delta_ns == 0.0) {
                fprintf(stderr,
                        "  FATAL: lane '%s' reports |t| = %.4f (>= %.4f) with no "
                        "effect size. t = delta/se, so this cannot be a "
                        "measurement; the harness did not set delta_ns.\n",
                        results[i].name, results[i].t_value, r->threshold);
                r->lanes[i].fatal = 1;
            }
            r->lanes[i].rounds_failed++;
            /* Which direction the excursion went. A leak has a direction: one
             * class is systematically the faster one, so its t keeps its sign
             * as measurements accumulate. Scheduler noise does not. */
            if (results[i].t_value > 0.0)
                r->lanes[i].trips_positive++;
            else if (results[i].t_value < 0.0)
                r->lanes[i].trips_negative++;
            /* Effect size of the excursions themselves.  The floor is applied
             * to this rather than to every round's difference, so a lane is
             * judged on the rounds in which it actually tripped. */
            if (fabs(results[i].delta_ns) > fabs(r->lanes[i].max_trip_delta_ns))
                r->lanes[i].max_trip_delta_ns = results[i].delta_ns;
        }
        if (fabs(results[i].t_value) > fabs(r->lanes[i].worst_t)) {
            r->lanes[i].worst_t = results[i].t_value;
            r->lanes[i].worst_t_delta_ns = results[i].delta_ns;
        }
    }
    r->rounds_run++;
}

/** What a lane's accumulated evidence amounts to. */
typedef enum {
    DUDECT_LANE_CLEAN = 0,   /**< never tripped */
    DUDECT_LANE_NOISE,       /**< tripped, but in a minority of rounds */
    DUDECT_LANE_LEAK,        /**< tripped a majority of rounds, one direction */
    DUDECT_LANE_UNUSABLE,    /**< tripped a majority of rounds, directions disagree */
    DUDECT_LANE_SUB_FLOOR,   /**< tripped a majority, but under DUDECT_MIN_EFFECT_NS */
    DUDECT_LANE_FAULT,       /**< harness fault; conclusive on one sighting */
} dudect_lane_verdict_t;

/**
 * Classify a lane.
 *
 * Majority: strictly more than half of the rounds must have tripped, so a
 * 3-round schedule reaches a verdict at 2/3 and 3/3 and reports noise at 1/3;
 * a single round counts at 1/1.  Integer arithmetic on both sides — no
 * floating-point midpoint to argue about.
 *
 * Direction: a timing leak means one class is systematically faster, so its
 * Welch t keeps a fixed sign — the statistic grows with measurements, it does
 * not oscillate.  An over-threshold excursion in the OPPOSITE direction would
 * require the slower class to become the faster one by more than the threshold,
 * which a deterministic timing difference cannot do.  So trips that disagree
 * about direction are not evidence of a leak; they are evidence that the host's
 * measurements are dominated by something other than the code under test.
 *
 * This is not hypothetical.  The `FROST scalar_negate (extremes)` lane tripped
 * |t| <= 13.3 in 3/3 rounds on one CI run with the sign flipping between
 * rounds, and the rule reported it as a timing leak.  Re-measured on a quiet
 * host at 2,000,000 operations per round x 5 rounds, at batch sizes 1, 8, 64
 * and 256, that lane reads |t| <= 1.62 with per-class means agreeing to within
 * 0.6% (106.9 ns vs 107.5 ns unbatched) — there is no timing difference to
 * find, and `scalar_negate`'s borrow loop plus `sc_reduce` are branchless on
 * inspection.  The excursion was the runner, and the gate said "leak".
 *
 * Both of the majority cases still FAIL the build.  Nothing is being waved
 * through: DUDECT_LANE_UNUSABLE is a red run, because a gate that cannot
 * measure has not cleared anything.  What changes is the diagnosis, and
 * therefore the operator's next action — re-run on a quiet host versus audit
 * the primitive.  Sensitivity is untouched: a real leak's trips share a sign,
 * so it classifies as DUDECT_LANE_LEAK exactly as before.
 */
static inline dudect_lane_verdict_t dudect_lane_verdict(
    const dudect_lane_evidence_t *lane, int rounds_run) {
    if (lane->fatal)
        return DUDECT_LANE_FAULT;
    if (rounds_run <= 0 || lane->rounds_failed == 0)
        return DUDECT_LANE_CLEAN;
    if (lane->is_info_only)
        return DUDECT_LANE_NOISE;
    if (lane->rounds_failed * 2 <= rounds_run)
        return DUDECT_LANE_NOISE;
    /* Defence in depth for callers that build evidence directly rather than
     * through dudect_rounds_add(): no effect size behind a majority of trips
     * is a harness fault, never a pass.  This is checked BEFORE the floor and
     * before the direction rule, because both of them read a number the
     * harness has to have supplied.  See the ingestion-side check for why
     * t != 0 implies delta != 0. */
    if (lane->max_trip_delta_ns == 0.0)
        return DUDECT_LANE_FAULT;

    /* The floor is a PRECONDITION for adjudication, not a tie-breaker, so it
     * is applied before the direction rule rather than after it.
     *
     * The direction rule's premise is that a real leak keeps a fixed sign
     * because the statistic grows with measurements rather than oscillating.
     * That premise presupposes the effect is RESOLVABLE.  Below
     * DUDECT_MIN_EFFECT_NS it is not, and the consequence is not theoretical:
     * `Ascon-AEAD128 encrypt` read 3/3 consistently signed at +0.596 ns on one
     * CI runner and 2+/1- at +0.607 ns on another — same binary, same
     * measurement count, same effect size to within 2%, opposite verdicts
     * (SUB_FLOOR vs UNUSABLE, green vs red).  A sign-consistency test applied
     * to a quantity whose sign is not reproducible is a coin flip, and a gate
     * that decides a build on a coin flip is worse than one that abstains.
     *
     * Ordering it this way costs no sensitivity to a real leak.  The floor is
     * set below every mechanism that can produce one — a mispredicted branch
     * is 7-10 ns, an L1 miss 30-50 ns, one extra AES round ~4 ns, an
     * early-exit memcmp hundreds — so at or above 2 ns direction disagreement
     * still yields DUDECT_LANE_UNUSABLE and still fails the build, exactly as
     * before.  What changes is confined to the range the floor already
     * declares unadjudicable, where the deterministic instruction-count gates
     * are the instrument: `ama_ascon_aead128_encrypt` retires 32,069,814
     * instructions identically across all eight key classes (cross-class delta
     * 0, noise floor 0), and `ama_agent_binding_check` 612,810,230 identically
     * whether it accepts or rejects. */
    if (fabs(lane->max_trip_delta_ns) < DUDECT_MIN_EFFECT_NS)
        return DUDECT_LANE_SUB_FLOOR;

    if (lane->trips_positive > 0 && lane->trips_negative > 0)
        return DUDECT_LANE_UNUSABLE;
    return DUDECT_LANE_LEAK;
}

/**
 * A lane fails the build unless it is clean, info-only, minority noise, or
 * an excursion smaller than this apparatus can adjudicate.
 *
 * DUDECT_LANE_UNUSABLE still fails: a majority of rounds over the threshold
 * with the direction reversing means the measurements are not usable, and a
 * gate that could not measure has cleared nothing.
 *
 * DUDECT_LANE_SUB_FLOOR does not, and that is a statement about which
 * instrument owns the claim rather than a tolerance.  Below
 * DUDECT_MIN_EFFECT_NS a wall-clock t-test on shared hardware cannot separate
 * a source-level leak from data-operand-dependent execution in the CPU; the
 * deterministic instruction-count gates measure that range exactly, with a
 * zero-instruction noise floor, and they are what a real regression there
 * trips.  The lane still prints its verdict, its t and its difference, so the
 * excursion is visible in the log rather than absorbed into a PASS.
 */
static inline int dudect_lane_failed(const dudect_lane_evidence_t *lane, int rounds_run) {
    switch (dudect_lane_verdict(lane, rounds_run)) {
        case DUDECT_LANE_FAULT:
        case DUDECT_LANE_LEAK:
        case DUDECT_LANE_UNUSABLE:
            return 1;
        default:
            return 0;
    }
}

/** 1 iff no lane failed under the rule above. */
static inline int dudect_rounds_passed(const dudect_rounds_t *r) {
    for (int i = 0; i < r->num_lanes; i++) {
        if (dudect_lane_failed(&r->lanes[i], r->rounds_run))
            return 0;
    }
    return 1;
}

/**
 * 1 iff any lane that *could* fail has tripped at least once so far.
 *
 * This is the early-exit predicate, and it is deliberately not "was the last
 * round clean".  Under a majority rule a clean round does not settle anything
 * once something has already tripped: a lane at 1/2 becomes a 2/3 failure if
 * the third round trips it, and stopping at two rounds would skip that.  While
 * this returns 0 nothing has tripped at all, so no further round can produce a
 * majority over the rounds already run and the loop may stop — which is the
 * common healthy case, still costing one round.
 */
static inline int dudect_rounds_any_failure(const dudect_rounds_t *r) {
    for (int i = 0; i < r->num_lanes; i++) {
        if (r->lanes[i].fatal)
            return 1;
        if (!r->lanes[i].is_info_only && r->lanes[i].rounds_failed > 0)
            return 1;
    }
    return 0;
}

/** Per-lane worst |t|, failed/run ratio, and status. */
static inline void dudect_rounds_print_summary(const dudect_rounds_t *r) {
    printf("\n  %-35s  %10s  %12s  %8s  %9s\n",
           "Function", "worst |t|", "diff (ns)", "rounds", "Status");
    printf("  %-35s  %10s  %12s  %8s  %9s\n",
           "-----------------------------------", "----------", "------------",
           "--------", "---------");

    for (int i = 0; i < r->num_lanes; i++) {
        const dudect_lane_evidence_t *lane = &r->lanes[i];
        const char *status;
        switch (dudect_lane_verdict(lane, r->rounds_run)) {
            case DUDECT_LANE_FAULT:    status = "FAULT";    break;
            case DUDECT_LANE_LEAK:     status = "FAIL";     break;
            /* Over the threshold in a majority of rounds, one direction, but
             * the difference is smaller than this apparatus can adjudicate.
             * Printed as its own state, never folded into PASS. */
            case DUDECT_LANE_SUB_FLOOR: status = "SUB-FLOOR"; break;
            /* A majority of rounds tripped, but they disagreed on direction —
             * one class faster in some rounds and slower in others.  A leak has
             * a direction; this does not.  Still a failing run (see
             * dudect_lane_verdict), labelled for what it is. */
            case DUDECT_LANE_UNUSABLE: status = "UNUSABLE"; break;
            /* Over the threshold in a minority of rounds, or an info-only lane.
             * Printed rather than hidden: a lane drifting toward the threshold
             * should be visible in the log before it becomes a failure. */
            case DUDECT_LANE_NOISE:
                status = lane->is_info_only ? "INFO" : "NOISE";
                break;
            default:                   status = "PASS";     break;
        }

        char rounds[24];
        if (lane->trips_positive && lane->trips_negative)
            snprintf(rounds, sizeof(rounds), "%d/%d %d+/%d-", lane->rounds_failed,
                     r->rounds_run, lane->trips_positive, lane->trips_negative);
        else
            snprintf(rounds, sizeof(rounds), "%d/%d", lane->rounds_failed, r->rounds_run);
        printf("  %-35s  %+10.4f  %+12.3f  %8s  %9s\n",
               lane->name, lane->worst_t, lane->worst_t_delta_ns, rounds, status);
    }
}

/**
 * Report every lane that was over the threshold in a majority of rounds but
 * whose difference is under the floor.
 *
 * These do not fail the build (see dudect_lane_failed), and printing them is
 * the reason that is not a silent exemption: the reader gets the lane, the
 * statistic, the size of the difference, and the gate that owns the range.
 */
static inline int dudect_rounds_print_sub_floor(const dudect_rounds_t *r) {
    int shown = 0;
    for (int i = 0; i < r->num_lanes; i++) {
        const dudect_lane_evidence_t *lane = &r->lanes[i];
        if (dudect_lane_verdict(lane, r->rounds_run) != DUDECT_LANE_SUB_FLOOR)
            continue;
        if (!shown) {
            printf("\nBelow the effect-size floor (%.1f ns) — reported, not failed:\n",
                   (double)DUDECT_MIN_EFFECT_NS);
        }
        shown++;
        printf("  - %s: |t| reached %.4f in %d of %d round(s), but the per-class\n"
               "    difference is %+.3f ns. A wall-clock t-test on shared hardware\n"
               "    cannot separate that from data-operand-dependent execution in the\n"
               "    CPU (Intel DOITM / ARM PSTATE.DIT). The deterministic\n"
               "    instruction-count gates own this range and measure it exactly.\n",
               lane->name, fabs(lane->worst_t), lane->rounds_failed, r->rounds_run,
               lane->max_trip_delta_ns);
        /* Say so when the excursions also disagreed on direction, rather than
         * printing it identically to a consistently-signed one.  Above the
         * floor that disagreement is DUDECT_LANE_UNUSABLE and fails the build;
         * here it is a second, independent indication that the measurement is
         * the host rather than the code, and the reader should see it. */
        if (lane->trips_positive > 0 && lane->trips_negative > 0) {
            printf("    The excursions also DISAGREED on direction (%d+/%d-), which\n"
                   "    at or above the floor would be a red run on its own.\n",
                   lane->trips_positive, lane->trips_negative);
        }
    }
    return shown;
}

/** Name every lane that actually failed, and why. */
static inline void dudect_rounds_print_failures(const dudect_rounds_t *r) {
    for (int i = 0; i < r->num_lanes; i++) {
        const dudect_lane_evidence_t *lane = &r->lanes[i];
        if (!dudect_lane_failed(lane, r->rounds_run))
            continue;
        switch (dudect_lane_verdict(lane, r->rounds_run)) {
            case DUDECT_LANE_FAULT:
                printf("  - %s: harness fault (setup failure or per-class rc mismatch)\n",
                       lane->name);
                break;
            case DUDECT_LANE_UNUSABLE:
                printf("  - %s: |t| reached %.4f (threshold %.1f) in %d of %d round(s), "
                       "but the excursions DISAGREED on direction (%d+/%d-). A timing "
                       "leak has a direction; this does not. The measurements on this "
                       "host are not usable — re-run on a quiet, unshared machine "
                       "before treating it as a finding.\n",
                       lane->name, fabs(lane->worst_t), r->threshold,
                       lane->rounds_failed, r->rounds_run,
                       lane->trips_positive, lane->trips_negative);
                break;
            default:
                printf("  - %s: |t| reached %.4f (threshold %.1f) in %d of %d round(s), "
                       "consistently signed (%d+/%d-), per-class difference %+.3f ns "
                       "(floor %.1f ns)\n",
                       lane->name, fabs(lane->worst_t), r->threshold,
                       lane->rounds_failed, r->rounds_run,
                       lane->trips_positive, lane->trips_negative,
                       lane->max_trip_delta_ns, (double)DUDECT_MIN_EFFECT_NS);
                break;
        }
    }
}

/* -------------------------------------------------------------------------
 * Self-test
 *
 * The rule above decides whether these gates can block a merge, and a
 * measurement pass cannot exercise it: reproducing "the same lane trips in
 * every round" on demand would require a real leak, and reproducing "a
 * different lane each round" would require controlling the scheduler.  So it
 * is driven with synthetic evidence, in both directions.  Deterministic, no
 * timing, milliseconds.
 * ------------------------------------------------------------------------- */

static inline int dudect_rounds_case(const char *what, dudect_lane_evidence_t lane,
                                     int rounds_run, int want) {
    int got = dudect_lane_failed(&lane, rounds_run);
    printf("  %-58s %s\n", what, got == want ? "ok" : "MISMATCH");
    return got == want;
}

/** Same, for the classification rather than the pass/fail collapse of it. */
static inline int dudect_rounds_verdict_case(const char *what,
                                             dudect_lane_evidence_t lane,
                                             int rounds_run,
                                             dudect_lane_verdict_t want) {
    dudect_lane_verdict_t got = dudect_lane_verdict(&lane, rounds_run);
    printf("  %-58s %s\n", what, got == want ? "ok" : "MISMATCH");
    return got == want;
}

static inline int dudect_rounds_self_test(void) {
    int ok = 1;
    printf("dudect verdict self-check\n\n");

    /* Designated initialisers throughout: this struct gained the per-direction
     * trip counters, and positional forms would have silently re-bound every
     * field after `rounds_failed` — the exact failure mode designated
     * initialisers exist to prevent in a table that decides a security gate.
     *
     * The majority boundary is the load-bearing part: 2/3 fails and 1/3 does
     * not.  Both sides of it are named so that moving the rule again means
     * editing a case that says what it decides, rather than watching a number
     * change.  Every case here gives its trips a consistent direction unless
     * it is specifically testing the direction rule. */
#define LANE(...) ((dudect_lane_evidence_t){__VA_ARGS__})
    ok &= dudect_rounds_case("strict lane over threshold in 3/3 rounds -> FAIL",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 3, .worst_t = 9.0,
                                  .max_trip_delta_ns = 40.0), 3, 1);
    ok &= dudect_rounds_case("strict lane over threshold in 2/3 rounds -> FAIL (majority)",
                             LANE(.name = "strict", .rounds_failed = 2,
                                  .trips_positive = 2, .worst_t = 9.0,
                                  .max_trip_delta_ns = 40.0), 3, 1);
    ok &= dudect_rounds_case("strict lane over threshold in 1/3 rounds -> pass (minority)",
                             LANE(.name = "strict", .rounds_failed = 1,
                                  .trips_positive = 1, .worst_t = 9.0), 3, 0);
    ok &= dudect_rounds_case("strict lane over threshold in 2/2 rounds -> FAIL",
                             LANE(.name = "strict", .rounds_failed = 2,
                                  .trips_positive = 2, .worst_t = 9.0,
                                  .max_trip_delta_ns = 40.0), 2, 1);
    ok &= dudect_rounds_case("strict lane over threshold in 1/2 rounds -> pass (tie, not majority)",
                             LANE(.name = "strict", .rounds_failed = 1,
                                  .trips_positive = 1, .worst_t = 9.0), 2, 0);
    ok &= dudect_rounds_case("strict lane over threshold in 2/4 rounds -> pass (tie, not majority)",
                             LANE(.name = "strict", .rounds_failed = 2,
                                  .trips_positive = 2, .worst_t = 9.0), 4, 0);
    ok &= dudect_rounds_case("strict lane over threshold in 3/4 rounds -> FAIL",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 3, .worst_t = 9.0,
                                  .max_trip_delta_ns = 40.0), 4, 1);
    ok &= dudect_rounds_case("strict lane within threshold every round -> pass",
                             LANE(.name = "strict", .worst_t = 1.2), 3, 0);
    ok &= dudect_rounds_case("info lane over threshold in 3/3 rounds -> pass",
                             LANE(.name = "info", .is_info_only = 1, .rounds_failed = 3,
                                  .trips_positive = 3, .worst_t = 3800.0), 3, 0);
    ok &= dudect_rounds_case("fatal harness fault seen once in 3 rounds -> FAIL",
                             LANE(.name = "strict", .rounds_failed = 1, .fatal = 1), 3, 1);
    ok &= dudect_rounds_case("fatal harness fault on an info lane -> FAIL",
                             LANE(.name = "info", .is_info_only = 1, .rounds_failed = 1,
                                  .fatal = 1), 3, 1);
    ok &= dudect_rounds_case("strict lane over threshold in 1/1 round -> FAIL",
                             LANE(.name = "strict", .rounds_failed = 1,
                                  .trips_positive = 1, .worst_t = 9.0,
                                  .max_trip_delta_ns = 40.0), 1, 1);
    ok &= dudect_rounds_case("no rounds run -> pass (nothing was measured)",
                             LANE(.name = "strict"), 0, 0);

    /* The direction rule.  A leak makes one class systematically faster, so
     * its Welch t keeps its sign; noise on a shared runner does not.  The
     * `FROST scalar_negate (extremes)` lane tripped 3/3 on one CI run with the
     * sign flipping between rounds — a shape no leak produces, and the
     * majority rule alone called it a finding. */
    ok &= dudect_rounds_verdict_case("3/3 trips, all + -> LEAK",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 3, .worst_t = 9.0,
                                  .max_trip_delta_ns = 40.0), 3,
                             DUDECT_LANE_LEAK);
    ok &= dudect_rounds_verdict_case("3/3 trips, all - -> LEAK",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_negative = 3, .worst_t = -9.0,
                                  .max_trip_delta_ns = -40.0), 3,
                             DUDECT_LANE_LEAK);
    ok &= dudect_rounds_verdict_case("3/3 trips, signs 2+/1- -> UNUSABLE (not a leak)",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 2, .trips_negative = 1,
                                  .worst_t = 13.3,
                                  .max_trip_delta_ns = 40.0), 3, DUDECT_LANE_UNUSABLE);
    ok &= dudect_rounds_verdict_case("3/3 trips, signs 1+/2- -> UNUSABLE (not a leak)",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 1, .trips_negative = 2,
                                  .worst_t = -9.0,
                                  .max_trip_delta_ns = -40.0), 3, DUDECT_LANE_UNUSABLE);
    ok &= dudect_rounds_verdict_case("4/4 trips, signs 2+/2- -> UNUSABLE",
                             LANE(.name = "strict", .rounds_failed = 4,
                                  .trips_positive = 2, .trips_negative = 2,
                                  .worst_t = 9.0,
                                  .max_trip_delta_ns = 40.0), 4, DUDECT_LANE_UNUSABLE);
    ok &= dudect_rounds_verdict_case("2/3 trips, signs 1+/1- -> UNUSABLE",
                             LANE(.name = "strict", .rounds_failed = 2,
                                  .trips_positive = 1, .trips_negative = 1,
                                  .worst_t = 9.0,
                                  .max_trip_delta_ns = 40.0), 3, DUDECT_LANE_UNUSABLE);
    ok &= dudect_rounds_verdict_case("1/3 trips -> NOISE regardless of sign",
                             LANE(.name = "strict", .rounds_failed = 1,
                                  .trips_negative = 1, .worst_t = -9.0), 3,
                             DUDECT_LANE_NOISE);
    /* UNUSABLE still fails the build — it is a diagnosis, not an exemption. */
    ok &= dudect_rounds_case("an UNUSABLE lane still fails the run",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 2, .trips_negative = 1,
                                  .worst_t = 13.3,
                                  .max_trip_delta_ns = 40.0), 3, 1);
    /* The effect-size floor.  It decides the same shape of evidence the
     * direction rule does — a majority of consistently-signed excursions —
     * and separates "large enough for this apparatus to adjudicate" from
     * "not".  The observed CI values are used verbatim so the boundary is
     * pinned to the measurements that set it. */
    ok &= dudect_rounds_verdict_case("3/3 trips, +0.596 ns (Ascon lane, observed) -> SUB_FLOOR",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 3, .worst_t = 21.8752,
                                  .max_trip_delta_ns = 0.596), 3,
                             DUDECT_LANE_SUB_FLOOR);
    ok &= dudect_rounds_verdict_case("3/3 trips, -1.141 ns (binding lane, observed) -> SUB_FLOOR",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_negative = 3, .worst_t = -41.7199,
                                  .max_trip_delta_ns = -1.141), 3,
                             DUDECT_LANE_SUB_FLOOR);
    ok &= dudect_rounds_case("a SUB_FLOOR lane does not fail the run",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 3, .worst_t = 21.8752,
                                  .max_trip_delta_ns = 0.596), 3, 0);
    /* ...and the floor is a floor, not a ceiling: the same evidence with a
     * difference an actual mechanism could produce is still a leak.  A
     * mispredicted branch is 7-10 ns; an early-exit memcmp, hundreds. */
    ok &= dudect_rounds_verdict_case("3/3 trips, +8.0 ns (a mispredicted branch) -> LEAK",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 3, .worst_t = 21.8752,
                                  .max_trip_delta_ns = 8.0), 3,
                             DUDECT_LANE_LEAK);
    ok &= dudect_rounds_case("...and that one DOES fail the run",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 3, .worst_t = 21.8752,
                                  .max_trip_delta_ns = 8.0), 3, 1);
    ok &= dudect_rounds_verdict_case("3/3 trips, +500 ns (early-exit memcmp) -> LEAK",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 3, .worst_t = 113.0,
                                  .max_trip_delta_ns = 500.0), 3,
                             DUDECT_LANE_LEAK);
    /* Exactly at the floor counts as adjudicable: the comparison is `<`. */
    ok &= dudect_rounds_verdict_case("3/3 trips, exactly at the floor -> LEAK",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 3, .worst_t = 9.0,
                                  .max_trip_delta_ns = DUDECT_MIN_EFFECT_NS), 3,
                             DUDECT_LANE_LEAK);
    /* The floor is a PRECONDITION, so it is reached before the direction rule.
     * Below it the sign is not reproducible — the same lane, same binary and
     * same measurement count read 3/3 one-signed at +0.596 ns on one CI runner
     * and 2+/1- at +0.607 ns on another — so a sign-consistency test there
     * decides nothing. */
    ok &= dudect_rounds_verdict_case("below the floor, direction disagreement is SUB_FLOOR",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 2, .trips_negative = 1,
                                  .worst_t = 41.7, .max_trip_delta_ns = 0.5), 3,
                             DUDECT_LANE_SUB_FLOOR);
    ok &= dudect_rounds_case("...and that does not fail the run",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 2, .trips_negative = 1,
                                  .worst_t = 41.7, .max_trip_delta_ns = 0.5), 3, 0);
    /* The observed shape that forced the ordering: 3/3 at +0.607 ns, 2+/1-. */
    ok &= dudect_rounds_verdict_case("3/3 2+/1- at +0.607 ns (Ascon lane, observed) -> SUB_FLOOR",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 2, .trips_negative = 1,
                                  .worst_t = 21.4230, .max_trip_delta_ns = 0.607), 3,
                             DUDECT_LANE_SUB_FLOOR);
    /* At and above the floor the direction rule is untouched: an excursion big
     * enough to be a mechanism is big enough for its sign to mean something. */
    ok &= dudect_rounds_verdict_case("at the floor, direction disagreement is UNUSABLE",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 2, .trips_negative = 1,
                                  .worst_t = 41.7,
                                  .max_trip_delta_ns = DUDECT_MIN_EFFECT_NS), 3,
                             DUDECT_LANE_UNUSABLE);
    ok &= dudect_rounds_case("...and that IS still a red run",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 2, .trips_negative = 1,
                                  .worst_t = 41.7,
                                  .max_trip_delta_ns = DUDECT_MIN_EFFECT_NS), 3, 1);
    ok &= dudect_rounds_verdict_case("well above the floor, disagreement is UNUSABLE",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 2, .trips_negative = 1,
                                  .worst_t = 41.7, .max_trip_delta_ns = 40.0), 3,
                             DUDECT_LANE_UNUSABLE);
    ok &= dudect_rounds_verdict_case("a harness fault outranks the floor",
                             LANE(.name = "strict", .rounds_failed = 1, .fatal = 1,
                                  .max_trip_delta_ns = 0.001), 3,
                             DUDECT_LANE_FAULT);
    /* A harness that trips the threshold without supplying an effect size is
     * a FAULT, not a pass.  t = delta/se, so |t| >= threshold with delta
     * exactly 0.0 cannot come from a measurement.  Classifying it SUB_FLOOR
     * would make a harness omission silently unfailable. */
    ok &= dudect_rounds_verdict_case("no effect size behind a majority -> FAULT",
                             LANE(.name = "strict", .rounds_failed = 3,
                                  .trips_positive = 3, .worst_t = 9.0), 3,
                             DUDECT_LANE_FAULT);

    ok &= dudect_rounds_verdict_case("fatal outranks the direction rule",
                             LANE(.name = "strict", .rounds_failed = 2, .fatal = 1,
                                  .trips_positive = 1, .trips_negative = 1), 2,
                             DUDECT_LANE_FAULT);
#undef LANE

    /* Folding: a different lane over threshold each round fails nothing. */
    dudect_rounds_t r;
    dudect_rounds_init(&r, 4.5);
    dudect_lane_result_t round1[2] = {{.name = "a", .t_value = 9.0, .delta_ns = 40.0},
                                      {.name = "b", .t_value = 0.5}};
    dudect_lane_result_t round2[2] = {{.name = "a", .t_value = 0.4},
                                      {.name = "b", .t_value = 7.0, .delta_ns = 40.0}};
    dudect_rounds_add(&r, round1, 2);
    dudect_rounds_add(&r, round2, 2);
    int folded = (r.num_lanes == 2 && r.rounds_run == 2 &&
                  r.lanes[0].rounds_failed == 1 && r.lanes[1].rounds_failed == 1 &&
                  dudect_rounds_passed(&r));
    printf("  %-58s %s\n", "a different lane over threshold each round -> neither fails",
           folded ? "ok" : "MISMATCH");
    ok &= folded;

    int worst = fabs(r.lanes[0].worst_t - 9.0) < 1e-9;
    printf("  %-58s %s\n", "worst |t| is kept across rounds", worst ? "ok" : "MISMATCH");
    ok &= worst;

    /* The same lane over threshold in both rounds does fail. */
    dudect_rounds_t s;
    dudect_rounds_init(&s, 4.5);
    dudect_lane_result_t both1[1] = {{.name = "a", .t_value = 9.0, .delta_ns = 40.0}};
    dudect_lane_result_t both2[1] = {{.name = "a", .t_value = 8.0, .delta_ns = 40.0}};
    dudect_rounds_add(&s, both1, 1);
    dudect_rounds_add(&s, both2, 1);
    int consistent = !dudect_rounds_passed(&s);
    printf("  %-58s %s\n", "the same lane over threshold in every round -> FAIL",
           consistent ? "ok" : "MISMATCH");
    ok &= consistent;

    /* The three-round case the majority rule exists for: a lane that trips
     * twice and is clean once. Under an all-rounds rule this went green. */
    dudect_rounds_t m;
    dudect_rounds_init(&m, 4.5);
    dudect_lane_result_t maj1[1] = {{.name = "a", .t_value = 9.0, .delta_ns = 40.0}};
    dudect_lane_result_t maj2[1] = {{.name = "a", .t_value = 1.0}};
    dudect_lane_result_t maj3[1] = {{.name = "a", .t_value = 8.0, .delta_ns = 40.0}};
    dudect_rounds_add(&m, maj1, 1);
    dudect_rounds_add(&m, maj2, 1);
    dudect_rounds_add(&m, maj3, 1);
    int majority = (m.lanes[0].rounds_failed == 2 && m.rounds_run == 3 &&
                    !dudect_rounds_passed(&m));
    printf("  %-58s %s\n", "one lane over threshold in 2 of 3 rounds -> FAIL",
           majority ? "ok" : "MISMATCH");
    ok &= majority;

    /* The FROST case, folded from results rather than hand-built evidence:
     * the same lane over threshold in all three rounds with the sign flipping
     * must NOT be reported as a finding. */
    dudect_rounds_t f;
    dudect_rounds_init(&f, 4.5);
    dudect_lane_result_t flip1[1] = {{.name = "frost", .t_value = 13.3, .delta_ns = 40.0}};
    dudect_lane_result_t flip2[1] = {{.name = "frost", .t_value = -9.1, .delta_ns = -40.0}};
    dudect_lane_result_t flip3[1] = {{.name = "frost", .t_value = 7.4, .delta_ns = 40.0}};
    dudect_rounds_add(&f, flip1, 1);
    dudect_rounds_add(&f, flip2, 1);
    dudect_rounds_add(&f, flip3, 1);
    int flipped = (f.lanes[0].rounds_failed == 3 &&
                   f.lanes[0].trips_positive == 2 && f.lanes[0].trips_negative == 1 &&
                   dudect_lane_verdict(&f.lanes[0], f.rounds_run) == DUDECT_LANE_UNUSABLE &&
                   !dudect_rounds_passed(&f));
    printf("  %-58s %s\n",
           "the observed FROST shape -> UNUSABLE, and still red",
           flipped ? "ok" : "MISMATCH");
    ok &= flipped;

    dudect_rounds_t g;
    dudect_rounds_init(&g, 4.5);
    dudect_lane_result_t alt1[1] = {{.name = "frost", .t_value = 13.3, .delta_ns = 40.0}};
    dudect_lane_result_t alt2[1] = {{.name = "frost", .t_value = -9.1, .delta_ns = -40.0}};
    dudect_lane_result_t alt3[1] = {{.name = "frost", .t_value = 7.4, .delta_ns = 40.0}};
    dudect_lane_result_t alt4[1] = {{.name = "frost", .t_value = -6.2, .delta_ns = -40.0}};
    dudect_rounds_add(&g, alt1, 1);
    dudect_rounds_add(&g, alt2, 1);
    dudect_rounds_add(&g, alt3, 1);
    dudect_rounds_add(&g, alt4, 1);
    int alternating = (g.lanes[0].rounds_failed == 4 &&
                       g.lanes[0].trips_positive == 2 &&
                       g.lanes[0].trips_negative == 2 &&
                       dudect_lane_verdict(&g.lanes[0], g.rounds_run) == DUDECT_LANE_UNUSABLE &&
                       !dudect_rounds_passed(&g));
    printf("  %-58s %s\n",
           "4/4 alternating-sign trips -> UNUSABLE, not a leak, still red",
           alternating ? "ok" : "MISMATCH");
    ok &= alternating;

    /* The early-exit predicate. It is load-bearing under a majority rule: the
     * loop may only stop while nothing has tripped, because a lane at 1/2
     * becomes a 2/3 failure if the third round trips it. */
    dudect_rounds_t e;
    dudect_rounds_init(&e, 4.5);
    dudect_lane_result_t clean[2] = {{.name = "a", .t_value = 1.0},
                                     {.name = "info", .t_value = 900.0, .is_info_only = 1}};
    dudect_rounds_add(&e, clean, 2);
    int quiet = !dudect_rounds_any_failure(&e);
    printf("  %-58s %s\n", "only an info lane tripped -> early exit still allowed",
           quiet ? "ok" : "MISMATCH");
    ok &= quiet;

    dudect_lane_result_t tripped[2] = {{.name = "a", .t_value = 9.0, .delta_ns = 40.0},
                                       {.name = "info", .t_value = 1.0, .is_info_only = 1}};
    dudect_rounds_add(&e, tripped, 2);
    int busy = dudect_rounds_any_failure(&e);
    printf("  %-58s %s\n", "a strict lane tripped -> early exit refused",
           busy ? "ok" : "MISMATCH");
    ok &= busy;

    /* Ingestion side of the effect-size requirement.  A lane that trips the
     * threshold and reports delta_ns == 0.0 has not measured anything —
     * t = delta/se — so dudect_rounds_add() marks it fatal on the spot rather
     * than letting the floor read it as a sub-floor pass.  Without this a
     * harness that forgot to populate delta_ns would be permanently unable to
     * fail a build, and would look green while measuring nothing. */
    dudect_rounds_t z;
    dudect_rounds_init(&z, 4.5);
    dudect_lane_result_t noeffect[1] = {{.name = "a", .t_value = 41.72}};
    dudect_rounds_add(&z, noeffect, 1);
    int flagged = (z.lanes[0].fatal == 1 &&
                   dudect_lane_verdict(&z.lanes[0], z.rounds_run) == DUDECT_LANE_FAULT &&
                   !dudect_rounds_passed(&z));
    printf("  %-58s %s\n", "a trip with no effect size is a fault, not a pass",
           flagged ? "ok" : "MISMATCH");
    ok &= flagged;

    /* ...and the exemption is real: an info-only lane may trip without one,
     * because it can never reach the floor in the first place. */
    dudect_rounds_t zi;
    dudect_rounds_init(&zi, 4.5);
    dudect_lane_result_t infotrip[1] = {{.name = "info", .t_value = 900.0,
                                         .is_info_only = 1}};
    dudect_rounds_add(&zi, infotrip, 1);
    int exempt = (zi.lanes[0].fatal == 0 &&
                  dudect_lane_verdict(&zi.lanes[0], zi.rounds_run) == DUDECT_LANE_NOISE &&
                  dudect_rounds_passed(&zi));
    printf("  %-58s %s\n", "an info-only lane may trip without an effect size",
           exempt ? "ok" : "MISMATCH");
    ok &= exempt;

    /* And a sub-threshold round with no effect size is untouched: only trips
     * carry the requirement, so a quiet lane is not conscripted into it. */
    dudect_rounds_t zq;
    dudect_rounds_init(&zq, 4.5);
    dudect_lane_result_t quietlane[1] = {{.name = "a", .t_value = 1.39}};
    dudect_rounds_add(&zq, quietlane, 1);
    int untouched = (zq.lanes[0].fatal == 0 &&
                     dudect_lane_verdict(&zq.lanes[0], zq.rounds_run) == DUDECT_LANE_CLEAN &&
                     dudect_rounds_passed(&zq));
    printf("  %-58s %s\n", "a quiet lane needs no effect size",
           untouched ? "ok" : "MISMATCH");
    ok &= untouched;

    printf("\n%s\n", ok ? "verdict self-check: PASS" : "verdict self-check: FAIL");
    return ok ? 0 : 1;
}

#endif /* AMA_DUDECT_ROUNDS_H */
