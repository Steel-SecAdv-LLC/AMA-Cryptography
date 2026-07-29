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

/** One lane's outcome for one round. */
typedef struct {
    const char *name;
    double      t_value;
    int         is_info_only; /**< 1 = report the t-value, never fail on it */
    int         is_fatal;     /**< 1 = harness fault; conclusive on one sighting */
} dudect_lane_result_t;

/** What a lane did across every round run so far. */
typedef struct {
    const char *name;
    int         is_info_only;
    int         rounds_failed; /**< rounds in which |t| >= threshold */
    int         fatal;         /**< saw a harness fault at least once */
    double      worst_t;       /**< signed t of the largest |t| observed */
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
            r->lanes[i].rounds_failed = 0;
            r->lanes[i].fatal         = 0;
            r->lanes[i].worst_t       = 0.0;
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
        if (fabs(results[i].t_value) >= r->threshold)
            r->lanes[i].rounds_failed++;
        if (fabs(results[i].t_value) > fabs(r->lanes[i].worst_t))
            r->lanes[i].worst_t = results[i].t_value;
    }
    r->rounds_run++;
}

/** A lane fails only if it is strict and tripped in a MAJORITY of rounds, or
 *  ever reported a harness fault.
 *
 *  Strictly more than half, so a 3-round schedule fails at 2/3 and 3/3 and
 *  passes at 1/3; a single round fails at 1/1.  Integer arithmetic on both
 *  sides — no floating-point midpoint to argue about. */
static inline int dudect_lane_failed(const dudect_lane_evidence_t *lane, int rounds_run) {
    if (lane->fatal)
        return 1;
    if (rounds_run <= 0)
        return 0;
    return !lane->is_info_only && (lane->rounds_failed * 2 > rounds_run);
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
    printf("\n  %-35s  %10s  %8s  %8s\n", "Function", "worst |t|", "rounds", "Status");
    printf("  %-35s  %10s  %8s  %8s\n",
           "-----------------------------------", "----------", "--------", "--------");

    for (int i = 0; i < r->num_lanes; i++) {
        const dudect_lane_evidence_t *lane = &r->lanes[i];
        const char *status;
        if (lane->fatal)
            status = "FAIL";
        else if (lane->rounds_failed == 0)
            status = "PASS";
        else if (lane->is_info_only)
            status = "INFO";
        else if (dudect_lane_failed(lane, r->rounds_run))
            status = "FAIL";
        else
            /* Over the threshold, but in a minority of rounds. Printed rather
             * than hidden: a lane drifting toward the threshold should be
             * visible in the log before it becomes a failure. */
            status = "NOISE";

        char rounds[16];
        snprintf(rounds, sizeof(rounds), "%d/%d", lane->rounds_failed, r->rounds_run);
        printf("  %-35s  %+10.4f  %8s  %8s\n", lane->name, lane->worst_t, rounds, status);
    }
}

/** Name every lane that actually failed, and why. */
static inline void dudect_rounds_print_failures(const dudect_rounds_t *r) {
    for (int i = 0; i < r->num_lanes; i++) {
        const dudect_lane_evidence_t *lane = &r->lanes[i];
        if (!dudect_lane_failed(lane, r->rounds_run))
            continue;
        if (lane->fatal)
            printf("  - %s: harness fault (setup failure or per-class rc mismatch)\n",
                   lane->name);
        else
            printf("  - %s: |t| reached %.4f (threshold %.1f) in %d of %d round(s)\n",
                   lane->name, fabs(lane->worst_t), r->threshold,
                   lane->rounds_failed, r->rounds_run);
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

static inline int dudect_rounds_self_test(void) {
    int ok = 1;
    printf("dudect verdict self-check\n\n");

    /* name, is_info_only, rounds_failed, fatal, worst_t
     *
     * The majority boundary is the load-bearing part: 2/3 fails and 1/3 does
     * not.  Both sides of it are named so that moving the rule again means
     * editing a case that says what it decides, rather than watching a number
     * change. */
    ok &= dudect_rounds_case("strict lane over threshold in 3/3 rounds -> FAIL",
                             (dudect_lane_evidence_t){"strict", 0, 3, 0, 9.0}, 3, 1);
    ok &= dudect_rounds_case("strict lane over threshold in 2/3 rounds -> FAIL (majority)",
                             (dudect_lane_evidence_t){"strict", 0, 2, 0, 9.0}, 3, 1);
    ok &= dudect_rounds_case("strict lane over threshold in 1/3 rounds -> pass (minority)",
                             (dudect_lane_evidence_t){"strict", 0, 1, 0, 9.0}, 3, 0);
    ok &= dudect_rounds_case("strict lane over threshold in 2/2 rounds -> FAIL",
                             (dudect_lane_evidence_t){"strict", 0, 2, 0, 9.0}, 2, 1);
    ok &= dudect_rounds_case("strict lane over threshold in 1/2 rounds -> pass (tie, not majority)",
                             (dudect_lane_evidence_t){"strict", 0, 1, 0, 9.0}, 2, 0);
    ok &= dudect_rounds_case("strict lane over threshold in 2/4 rounds -> pass (tie, not majority)",
                             (dudect_lane_evidence_t){"strict", 0, 2, 0, 9.0}, 4, 0);
    ok &= dudect_rounds_case("strict lane over threshold in 3/4 rounds -> FAIL",
                             (dudect_lane_evidence_t){"strict", 0, 3, 0, 9.0}, 4, 1);
    ok &= dudect_rounds_case("strict lane within threshold every round -> pass",
                             (dudect_lane_evidence_t){"strict", 0, 0, 0, 1.2}, 3, 0);
    ok &= dudect_rounds_case("info lane over threshold in 3/3 rounds -> pass",
                             (dudect_lane_evidence_t){"info", 1, 3, 0, 3800.0}, 3, 0);
    ok &= dudect_rounds_case("fatal harness fault seen once in 3 rounds -> FAIL",
                             (dudect_lane_evidence_t){"strict", 0, 1, 1, 0.0}, 3, 1);
    ok &= dudect_rounds_case("fatal harness fault on an info lane -> FAIL",
                             (dudect_lane_evidence_t){"info", 1, 1, 1, 0.0}, 3, 1);
    ok &= dudect_rounds_case("strict lane over threshold in 1/1 round -> FAIL",
                             (dudect_lane_evidence_t){"strict", 0, 1, 0, 9.0}, 1, 1);
    ok &= dudect_rounds_case("no rounds run -> pass (nothing was measured)",
                             (dudect_lane_evidence_t){"strict", 0, 0, 0, 0.0}, 0, 0);

    /* Folding: a different lane over threshold each round fails nothing. */
    dudect_rounds_t r;
    dudect_rounds_init(&r, 4.5);
    dudect_lane_result_t round1[2] = {{"a", 9.0, 0, 0}, {"b", 0.5, 0, 0}};
    dudect_lane_result_t round2[2] = {{"a", 0.4, 0, 0}, {"b", 7.0, 0, 0}};
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
    dudect_lane_result_t both1[1] = {{"a", 9.0, 0, 0}};
    dudect_lane_result_t both2[1] = {{"a", 8.0, 0, 0}};
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
    dudect_lane_result_t maj1[1] = {{"a", 9.0, 0, 0}};
    dudect_lane_result_t maj2[1] = {{"a", 1.0, 0, 0}};
    dudect_lane_result_t maj3[1] = {{"a", 8.0, 0, 0}};
    dudect_rounds_add(&m, maj1, 1);
    dudect_rounds_add(&m, maj2, 1);
    dudect_rounds_add(&m, maj3, 1);
    int majority = (m.lanes[0].rounds_failed == 2 && m.rounds_run == 3 &&
                    !dudect_rounds_passed(&m));
    printf("  %-58s %s\n", "one lane over threshold in 2 of 3 rounds -> FAIL",
           majority ? "ok" : "MISMATCH");
    ok &= majority;

    /* The early-exit predicate. It is load-bearing under a majority rule: the
     * loop may only stop while nothing has tripped, because a lane at 1/2
     * becomes a 2/3 failure if the third round trips it. */
    dudect_rounds_t e;
    dudect_rounds_init(&e, 4.5);
    dudect_lane_result_t clean[2] = {{"a", 1.0, 0, 0}, {"info", 900.0, 1, 0}};
    dudect_rounds_add(&e, clean, 2);
    int quiet = !dudect_rounds_any_failure(&e);
    printf("  %-58s %s\n", "only an info lane tripped -> early exit still allowed",
           quiet ? "ok" : "MISMATCH");
    ok &= quiet;

    dudect_lane_result_t tripped[2] = {{"a", 9.0, 0, 0}, {"info", 1.0, 1, 0}};
    dudect_rounds_add(&e, tripped, 2);
    int busy = dudect_rounds_any_failure(&e);
    printf("  %-58s %s\n", "a strict lane tripped -> early exit refused",
           busy ? "ok" : "MISMATCH");
    ok &= busy;

    printf("\n%s\n", ok ? "verdict self-check: PASS" : "verdict self-check: FAIL");
    return ok ? 0 : 1;
}

#endif /* AMA_DUDECT_ROUNDS_H */
