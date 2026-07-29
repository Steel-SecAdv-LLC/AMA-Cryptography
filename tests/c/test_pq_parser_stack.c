/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_pq_parser_stack.c
 * @brief Measure the stack high-water mark of the parser-reachable PQ
 *        validation entry points, and hold them under a stated budget.
 *
 * `ama_ml_dsa_pubkey_from_privkey` and `ama_ml_kem_pubkey_from_privkey` are
 * called by `ama_cryptography.key_formats.load_pkcs8` on every
 * `expandedKey`-only key it imports. Their frame size is therefore chosen by
 * whoever hands you a key file, which makes it a property that has to be
 * bounded and *measured*, not asserted in a comment.
 *
 * The ML-DSA one used to hold the whole k x l matrix A plus five length-k
 * vectors — about 110 KB at ML-DSA-87. That is more than the whole default
 * thread stack on musl (128 KB) and more than most embedded RTOS task stacks;
 * a parser that overflows the stack on a *well-formed* input is a denial of
 * service. It now expands A one row at a time; this test is what keeps that
 * true.
 *
 * Method
 * ------
 * Run the call on a pthread whose stack this test owns (`pthread_attr_setstack`
 * over an mmap'd region), pre-painted with a known 64-bit pattern. Afterwards,
 * scan from the low end for the first word the run disturbed: that is the
 * high-water mark. A baseline thread that does nothing measures the constant
 * the C library itself places on a caller-supplied stack (TCB, TLS, the thread
 * entry frame), and is subtracted, so the number reported is the call chain's
 * own consumption.
 *
 * The measurement covers the entire call chain — SHAKE, the NTT, the dispatch
 * layer — not just the one frame, which is the number that actually matters for
 * a parser.
 *
 * The same harness now also measures the three ML-DSA *operation* entry
 * points, under their own budget. Verification is at least as
 * attacker-reachable as key import — anyone who can present a signature
 * reaches it — and it, like keygen, held the whole k x l matrix A on the stack
 * for every parameter set, so ML-DSA-44 paid ML-DSA-87's 57 KB. Both now
 * expand A one row at a time. Signing keeps the whole matrix, because it uses
 * A once per rejection attempt and re-expanding it 4-5 times per signature is
 * a large constant cost on the one path where the parameter set is chosen by
 * the key holder rather than by an attacker; its frame is therefore *measured
 * and stated* rather than reduced, and AMA_ML_DSA_SIGN_STACK_BUDGET is what
 * stops it drifting further.
 *
 * POSIX only. Returns 77 (CTest SKIP) where the technique is unavailable
 * rather than passing tautologically.
 */

/* Feature-test macros, and they must precede every #include.
 *
 * `pthread_attr_setstack` is POSIX-2001 and `MAP_ANONYMOUS` is a BSD extension,
 * so glibc hides both behind these unless asked. This repository compiles with
 * a strict `-std=c11` rather than `-std=gnu11`, under which the implicit
 * feature-test defaults do not include them — the file built under one
 * toolchain's defaults and failed under clang's with "call to undeclared
 * function 'pthread_attr_setstack'". */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1

#include "ama_cryptography.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || !defined(__unix__)
int main(void) {
    printf("SKIP: caller-supplied thread stacks need POSIX pthreads\n");
    return 77;
}
#else

#include <pthread.h>
#include <sys/mman.h>

/* The stated ceiling for either parser-reachable validation entry point,
 * measured over the whole call chain. Chosen with headroom over the measured
 * figure so an unrelated inlining decision does not turn this into a flake,
 * but far enough below a small thread stack (musl's 128 KB default) that the
 * property it protects is real. */
#define AMA_PQ_PARSER_STACK_BUDGET (48u * 1024u)

/* Budget for ML-DSA keygen and verification. Both expand A row-wise, so they
 * sit well under musl's 128 KB default thread stack with room for a caller's
 * own frames below them. */
#define AMA_ML_DSA_OP_STACK_BUDGET (80u * 1024u)

/* Budget for ML-DSA signing, which holds the whole matrix A across the
 * rejection loop. Stated at the measured figure plus headroom rather than
 * pretended away: a caller running ML-DSA signing on a thread with a small
 * stack needs to size it accordingly, and `include/ama_cryptography.h` says so
 * beside the signing entry points. This number existing is the point — it is
 * what turns "it segfaults on musl" into a documented requirement with a
 * regression gate. */
#define AMA_ML_DSA_SIGN_STACK_BUDGET (176u * 1024u)

/* Stack region for the measured thread. Large enough that an unbounded
 * implementation does not fault before it can be measured — the point is to
 * report a number, not to crash. */
#define REGION_BYTES (4u * 1024u * 1024u)
#define PAINT UINT64_C(0xA5A5A5A5A5A5A5A5)

typedef struct {
    int kind;          /* 0 = baseline, 1 = ML-DSA parser, 2 = ML-KEM parser,
                        * 3 = ML-DSA keygen, 4 = ML-DSA sign, 5 = ML-DSA verify */
    int param_set;
    const uint8_t *sk;
    const uint8_t *pk;
    uint8_t *pk_out;
    size_t pk_len;
    uint8_t *sig;
    size_t sig_len;
    const uint8_t *msg;
    size_t msg_len;
    ama_error_t rc;
} job_t;

static void *run_job(void *arg) {
    job_t *job = (job_t *)arg;
    switch (job->kind) {
        case 1:
            job->rc = ama_ml_dsa_pubkey_from_privkey(
                (ama_ml_dsa_param_set_t)job->param_set, job->sk, job->pk_out);
            break;
        case 2:
            job->rc = ama_ml_kem_pubkey_from_privkey(
                (ama_ml_kem_param_set_t)job->param_set, job->sk,
                ama_ml_kem_secret_key_bytes((ama_ml_kem_param_set_t)job->param_set),
                job->pk_out, job->pk_len);
            break;
        case 3:
            job->rc = ama_ml_dsa_keypair((ama_ml_dsa_param_set_t)job->param_set,
                                         job->pk_out, (uint8_t *)job->sk);
            break;
        case 4:
            job->rc = ama_ml_dsa_sign((ama_ml_dsa_param_set_t)job->param_set,
                                      job->sig, &job->sig_len,
                                      job->msg, job->msg_len, job->sk);
            break;
        case 5:
            job->rc = ama_ml_dsa_verify((ama_ml_dsa_param_set_t)job->param_set,
                                        job->msg, job->msg_len,
                                        job->sig, job->sig_len, job->pk);
            break;
        default:
            job->rc = AMA_SUCCESS;
            break;
    }
    return NULL;
}

/* Returns the high-water mark in bytes, or SIZE_MAX on a harness failure. */
static size_t measure(job_t *job) {
    void *region;
    pthread_attr_t attr;
    pthread_t tid;
    uint64_t *words;
    size_t count, i;

    region = mmap(NULL, REGION_BYTES, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        return (size_t)-1;
    }
    words = (uint64_t *)region;
    count = REGION_BYTES / sizeof(uint64_t);
    for (i = 0; i < count; i++) {
        words[i] = PAINT;
    }

    if (pthread_attr_init(&attr) != 0) {
        munmap(region, REGION_BYTES);
        return (size_t)-1;
    }
    if (pthread_attr_setstack(&attr, region, REGION_BYTES) != 0 ||
        pthread_create(&tid, &attr, run_job, job) != 0) {
        pthread_attr_destroy(&attr);
        munmap(region, REGION_BYTES);
        return (size_t)-1;
    }
    pthread_join(tid, NULL);
    pthread_attr_destroy(&attr);

    /* The stack grows down from the top of the region on every platform this
     * builds for, so the first disturbed word from the bottom is the deepest
     * point reached. */
    for (i = 0; i < count; i++) {
        if (words[i] != PAINT) {
            break;
        }
    }
    munmap(region, REGION_BYTES);
    if (i == count) {
        return 0;
    }
    return REGION_BYTES - i * sizeof(uint64_t);
}

static int fail(const char *msg) {
    printf("FAIL: %s\n", msg);
    return 1;
}

int main(void) {
    static uint8_t dsa_pk[AMA_ML_DSA_MAX_PUBLIC_KEY_BYTES];
    static uint8_t dsa_sk[AMA_ML_DSA_MAX_SECRET_KEY_BYTES];
    static uint8_t kem_pk[AMA_ML_KEM_MAX_PUBLIC_KEY_BYTES];
    static uint8_t kem_sk[AMA_ML_KEM_MAX_SECRET_KEY_BYTES];
    static uint8_t out[AMA_ML_DSA_MAX_PUBLIC_KEY_BYTES];
    const ama_ml_dsa_param_set_t dsa_sets[] = {
        AMA_ML_DSA_44, AMA_ML_DSA_65, AMA_ML_DSA_87
    };
    const ama_ml_kem_param_set_t kem_sets[] = {
        AMA_ML_KEM_512, AMA_ML_KEM_768, AMA_ML_KEM_1024
    };
    uint8_t seed[32], z[32];
    job_t baseline_job;
    size_t baseline, worst = 0;
    unsigned int i;

    for (i = 0; i < 32; i++) {
        seed[i] = (uint8_t)(0x40 + i);
        z[i] = (uint8_t)(0x80 + i);
    }

    memset(&baseline_job, 0, sizeof(baseline_job));
    baseline = measure(&baseline_job);
    if (baseline == (size_t)-1) {
        printf("SKIP: could not create a thread on a caller-supplied stack\n");
        return 77;
    }
    printf("baseline (empty thread on a caller-supplied stack): %zu bytes\n", baseline);

    for (i = 0; i < sizeof(dsa_sets) / sizeof(dsa_sets[0]); i++) {
        job_t job;
        size_t used;
        if (ama_ml_dsa_keypair_from_seed(dsa_sets[i], seed, dsa_pk, dsa_sk)
                != AMA_SUCCESS) {
            return fail("ML-DSA keypair_from_seed");
        }
        memset(&job, 0, sizeof(job));
        job.kind = 1;
        job.param_set = (int)dsa_sets[i];
        job.sk = dsa_sk;
        job.pk_out = out;
        used = measure(&job);
        if (used == (size_t)-1) {
            return fail("measurement harness");
        }
        if (job.rc != AMA_SUCCESS) {
            return fail("ML-DSA pubkey_from_privkey did not succeed under measurement");
        }
        if (memcmp(out, dsa_pk, ama_ml_dsa_public_key_bytes(dsa_sets[i])) != 0) {
            return fail("ML-DSA pubkey_from_privkey returned the wrong public key");
        }
        used = used > baseline ? used - baseline : 0;
        printf("  %-12s ama_ml_dsa_pubkey_from_privkey: %6zu bytes of stack\n",
               ama_ml_dsa_param_set_name(dsa_sets[i]), used);
        if (used > worst) {
            worst = used;
        }
    }

    for (i = 0; i < sizeof(kem_sets) / sizeof(kem_sets[0]); i++) {
        job_t job;
        size_t used;
        size_t pk_len = ama_ml_kem_public_key_bytes(kem_sets[i]);
        size_t sk_len = ama_ml_kem_secret_key_bytes(kem_sets[i]);
        if (ama_ml_kem_keypair_from_seed(kem_sets[i], seed, z, kem_pk, pk_len,
                                         kem_sk, sk_len) != AMA_SUCCESS) {
            return fail("ML-KEM keypair_from_seed");
        }
        memset(&job, 0, sizeof(job));
        job.kind = 2;
        job.param_set = (int)kem_sets[i];
        job.sk = kem_sk;
        job.pk_out = out;
        job.pk_len = pk_len;
        used = measure(&job);
        if (used == (size_t)-1) {
            return fail("measurement harness");
        }
        if (job.rc != AMA_SUCCESS) {
            return fail("ML-KEM pubkey_from_privkey did not succeed under measurement");
        }
        if (memcmp(out, kem_pk, pk_len) != 0) {
            return fail("ML-KEM pubkey_from_privkey returned the wrong public key");
        }
        used = used > baseline ? used - baseline : 0;
        printf("  %-12s ama_ml_kem_pubkey_from_privkey: %6zu bytes of stack\n",
               ama_ml_kem_param_set_name(kem_sets[i]), used);
        if (used > worst) {
            worst = used;
        }
    }

    printf("worst case: %zu bytes; budget: %u bytes\n",
           worst, (unsigned)AMA_PQ_PARSER_STACK_BUDGET);

    /* ---------------------------------------------------------------------
     * The three ML-DSA operations, under their own budgets.
     * ------------------------------------------------------------------- */
    {
        static uint8_t sig[AMA_ML_DSA_MAX_SIGNATURE_BYTES];
        static const uint8_t msg[32] = {
            'A', 'M', 'A', ' ', 'M', 'L', '-', 'D', 'S', 'A', ' ', 's', 't', 'a',
            'c', 'k', ' ', 'b', 'u', 'd', 'g', 'e', 't', ' ', 'p', 'r', 'o', 'b',
            'e', '.', '.', '.'
        };
        size_t op_worst = 0, sign_worst = 0;

        for (i = 0; i < sizeof(dsa_sets) / sizeof(dsa_sets[0]); i++) {
            job_t job;
            size_t used;
            const char *name = ama_ml_dsa_param_set_name(dsa_sets[i]);

            /* keygen */
            memset(&job, 0, sizeof(job));
            job.kind = 3;
            job.param_set = (int)dsa_sets[i];
            job.sk = dsa_sk;
            job.pk_out = dsa_pk;
            used = measure(&job);
            if (used == (size_t)-1) {
                return fail("measurement harness");
            }
            if (job.rc != AMA_SUCCESS) {
                return fail("ML-DSA keygen did not succeed under measurement");
            }
            used = used > baseline ? used - baseline : 0;
            printf("  %-12s ama_ml_dsa_keypair:             %6zu bytes of stack\n",
                   name, used);
            if (used > op_worst) {
                op_worst = used;
            }

            /* sign */
            memset(&job, 0, sizeof(job));
            job.kind = 4;
            job.param_set = (int)dsa_sets[i];
            job.sk = dsa_sk;
            job.sig = sig;
            job.sig_len = sizeof(sig);
            job.msg = msg;
            job.msg_len = sizeof(msg);
            used = measure(&job);
            if (used == (size_t)-1) {
                return fail("measurement harness");
            }
            if (job.rc != AMA_SUCCESS) {
                return fail("ML-DSA sign did not succeed under measurement");
            }
            used = used > baseline ? used - baseline : 0;
            printf("  %-12s ama_ml_dsa_sign:                %6zu bytes of stack\n",
                   name, used);
            if (used > sign_worst) {
                sign_worst = used;
            }

            /* verify — the signature just produced, so a wrong answer here is
             * a failure and not merely a measurement. */
            {
                size_t produced = job.sig_len;
                memset(&job, 0, sizeof(job));
                job.kind = 5;
                job.param_set = (int)dsa_sets[i];
                job.pk = dsa_pk;
                job.sig = sig;
                job.sig_len = produced;
                job.msg = msg;
                job.msg_len = sizeof(msg);
                used = measure(&job);
            }
            if (used == (size_t)-1) {
                return fail("measurement harness");
            }
            if (job.rc != AMA_SUCCESS) {
                return fail("ML-DSA verify rejected a signature it had just produced");
            }
            used = used > baseline ? used - baseline : 0;
            printf("  %-12s ama_ml_dsa_verify:              %6zu bytes of stack\n",
                   name, used);
            if (used > op_worst) {
                op_worst = used;
            }
        }

        printf("ML-DSA keygen/verify worst: %zu bytes; budget: %u bytes\n",
               op_worst, (unsigned)AMA_ML_DSA_OP_STACK_BUDGET);
        printf("ML-DSA sign worst:          %zu bytes; budget: %u bytes\n",
               sign_worst, (unsigned)AMA_ML_DSA_SIGN_STACK_BUDGET);
        if (op_worst > AMA_ML_DSA_OP_STACK_BUDGET) {
            printf("FAIL: ML-DSA keygen or verification exceeds its stack budget. "
                   "Verification is driven by whoever supplies the signature, so "
                   "its frame has to fit a small thread stack.\n");
            return 1;
        }
        if (sign_worst > AMA_ML_DSA_SIGN_STACK_BUDGET) {
            printf("FAIL: ML-DSA signing exceeds its stated stack budget. If this "
                   "is a deliberate change, the figure in "
                   "include/ama_cryptography.h has to move with it.\n");
            return 1;
        }
        if (op_worst < 4096 || sign_worst < 4096) {
            printf("FAIL: an ML-DSA operation measured implausibly small — the "
                   "measurement is not measuring anything\n");
            return 1;
        }
        /* Signing genuinely is the largest of the three; if it ever stops
         * being, the budgets above have gone stale in the other direction. */
        if (sign_worst <= op_worst) {
            printf("FAIL: signing no longer dominates keygen/verify (%zu vs %zu) — "
                   "the budgets need revisiting\n", sign_worst, op_worst);
            return 1;
        }
    }

    if (worst > AMA_PQ_PARSER_STACK_BUDGET) {
        printf("FAIL: a parser-reachable PQ validation entry point exceeds the "
               "stated stack budget. This path is reached from load_pkcs8, so "
               "its frame is chosen by whoever supplies the key file.\n");
        return 1;
    }
    /* Non-vacuity: a measurement that reports ~0 means the painting or the
     * baseline subtraction is broken, and the budget check would pass for a
     * function of any size. */
    if (worst < 4096) {
        printf("FAIL: measured %zu bytes, which is implausibly small — the "
               "measurement is not measuring anything\n", worst);
        return 1;
    }
    printf("PASS\n");
    return 0;
}

#endif /* POSIX */
