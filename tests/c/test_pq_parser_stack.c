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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

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

/* Two mappings of ONE shared object: the thread runs on `stack_map`, and the
 * paint is read back through `read_map`.
 *
 * The obvious single-mapping arrangements are both unusable under a memory
 * checker, for the same underlying reason — Valgrind models a thread stack and
 * refuses reads it believes are out of bounds:
 *
 *   - scanning from the PARENT after pthread_join() reads a region Valgrind
 *     marks unaddressable the moment the thread exits (32 invalid reads across
 *     6 contexts), even though POSIX hands the region back to the caller;
 *   - scanning from inside the THREAD reads far below its own stack pointer,
 *     which Valgrind also refuses (32 invalid reads, 1 context).
 *
 * A second mapping of the same pages is neither: `read_map` is an ordinary
 * shared mapping that no thread has ever run on, so the checker has nothing to
 * object to, while the bytes it reads are the same bytes the thread wrote.  No
 * suppression file and no client-request annotation — the reads become
 * genuinely unremarkable rather than merely excused.
 *
 * shm_open + ftruncate + two mmaps is the POSIX spelling; the anonymous
 * mapping the previous version used cannot be aliased.  A harness that cannot
 * set this up returns SIZE_MAX, which main() reports as a SKIP.
 *
 * Returns the high-water mark in bytes, or SIZE_MAX on a harness failure. */
static size_t measure(job_t *job) {
    void *stack_map = MAP_FAILED, *read_map = MAP_FAILED;
    pthread_attr_t attr;
    pthread_t tid;
    uint64_t *words;
    const uint64_t *paint;
    size_t count, i;
    char shm_name[64];
    int fd;

    snprintf(shm_name, sizeof(shm_name), "/ama-pqstack-%ld-%u",
             (long)getpid(), (unsigned)job->kind);
    shm_unlink(shm_name); /* stale object from a crashed earlier run */
    fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        return (size_t)-1;
    }
    /* Unlink immediately: the two mappings keep the object alive, and nothing
     * is left behind if this process dies. */
    shm_unlink(shm_name);
    if (ftruncate(fd, (off_t)REGION_BYTES) != 0) {
        close(fd);
        return (size_t)-1;
    }
    stack_map = mmap(NULL, REGION_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    read_map = mmap(NULL, REGION_BYTES, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (stack_map == MAP_FAILED || read_map == MAP_FAILED) {
        if (stack_map != MAP_FAILED) munmap(stack_map, REGION_BYTES);
        if (read_map != MAP_FAILED) munmap(read_map, REGION_BYTES);
        return (size_t)-1;
    }

    words = (uint64_t *)stack_map;
    paint = (const uint64_t *)read_map;
    count = REGION_BYTES / sizeof(uint64_t);
    for (i = 0; i < count; i++) {
        words[i] = PAINT;
    }

    if (pthread_attr_init(&attr) != 0) {
        munmap(stack_map, REGION_BYTES);
        munmap(read_map, REGION_BYTES);
        return (size_t)-1;
    }
    if (pthread_attr_setstack(&attr, stack_map, REGION_BYTES) != 0 ||
        pthread_create(&tid, &attr, run_job, job) != 0) {
        pthread_attr_destroy(&attr);
        munmap(stack_map, REGION_BYTES);
        munmap(read_map, REGION_BYTES);
        return (size_t)-1;
    }
    pthread_join(tid, NULL);
    pthread_attr_destroy(&attr);

    /* The stack grows down from the top of the region on every platform this
     * builds for, so the first disturbed word from the bottom is the deepest
     * point reached.  Read through the alias, never through the stack. */
    for (i = 0; i < count; i++) {
        if (paint[i] != PAINT) {
            break;
        }
    }
    munmap(stack_map, REGION_BYTES);
    munmap(read_map, REGION_BYTES);
    if (i == count) {
        return 0;
    }
    return REGION_BYTES - i * sizeof(uint64_t);
}

static int fail(const char *msg) {
    printf("FAIL: %s\n", msg);
    return 1;
}

/* ASan's fake stack relocates the frames this test exists to measure
 * -------------------------------------------------------------------------
 * With `detect_stack_use_after_return=1` — which
 * `.github/workflows/static-analysis.yml` sets for the whole ASan ctest run —
 * AddressSanitizer moves function frames off the real stack into a heap
 * "fake stack" so it can detect a returned frame being used.  Frames larger
 * than the runtime's largest fake-stack size class (clang: kMaxStackMallocSize,
 * 1 << 16 = 64 KiB) stay on the real stack; everything smaller moves.
 *
 * That splits this test's subjects exactly in half.  Measured here under
 * gcc 13 ASan, which does not relocate them: ML-DSA keygen 60,336-61,904 B,
 * verify 57,264-58,832 B, the parser entry points at most 32,816 B — all
 * under 64 KiB — and ML-DSA sign 152,048-153,616 B, over it.  Under clang's
 * ASan in CI the first group reported 200-584 B while sign still reported
 * 149,640 B: the small frames had been moved to the heap and the painted
 * region never saw them, while the one frame too large to move measured
 * intact.  The non-vacuity guards below caught it, which is what they are
 * for, but the measurement was gone.
 *
 * So the test takes control of the one option that breaks its instrument and
 * re-executes itself once with it off.  Every other ASan and UBSan check is
 * untouched — this is not a sanitizer opt-out, it is the removal of a
 * relocation that makes a stack measurement measure a different stack.  The
 * use-after-return check itself is not lost to the suite: the other 62 tests
 * in the ctest run keep it, and they cover the same library code.
 *
 * If the re-exec cannot happen the test does NOT skip: it runs, and the
 * non-vacuity guards fail the run with the diagnosis, because a stack budget
 * that cannot be measured must not report as met.
 */
/* gcc defines __SANITIZE_ADDRESS__; clang answers __has_feature.  The two
 * cannot be tested in one expression: gcc has no __has_feature, and a
 * `defined(__has_feature) && __has_feature(...)` conjunction still expands
 * the second operand there, which is a preprocessor error rather than a
 * false. */
#if defined(__SANITIZE_ADDRESS__)
#define AMA_PQ_STACK_UNDER_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define AMA_PQ_STACK_UNDER_ASAN 1
#endif
#endif

#ifdef AMA_PQ_STACK_UNDER_ASAN
/* Returns 0 if no re-exec was needed or it already happened, non-zero if the
 * re-exec was attempted and failed. */
static int asan_reexec_without_fake_stack(int argc, char **argv) {
    const char *guard = getenv("AMA_PQ_STACK_ASAN_REEXEC");
    const char *existing;
    char opts[1024];
    char self[PATH_MAX];
    ssize_t n;
    const char *image;

    if (guard != NULL && guard[0] == '1') {
        return 0; /* already re-executed once; do not loop */
    }
    if (argc < 1 || argv == NULL || argv[0] == NULL) {
        return 1;
    }

    existing = getenv("ASAN_OPTIONS");
    /* Appended, not replaced: detect_leaks and anything else the caller set
     * must survive.  The last occurrence of a key is the one ASan honours. */
    if (existing != NULL && existing[0] != '\0') {
        if ((size_t)snprintf(opts, sizeof(opts),
                             "%s:detect_stack_use_after_return=0",
                             existing) >= sizeof(opts)) {
            return 1;
        }
    } else {
        snprintf(opts, sizeof(opts), "detect_stack_use_after_return=0");
    }
    if (setenv("ASAN_OPTIONS", opts, 1) != 0 ||
        setenv("AMA_PQ_STACK_ASAN_REEXEC", "1", 1) != 0) {
        return 1;
    }

    /* /proc/self/exe is exact where it exists; argv[0] is the portable
     * fallback and is a path (not a PATH lookup) under ctest. */
    image = argv[0];
    n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n > 0) {
        self[n] = '\0';
        image = self;
    }
    execv(image, argv);
    return 1; /* execv only returns on failure */
}
#endif /* AMA_PQ_STACK_UNDER_ASAN */

int main(int argc, char **argv) {
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
    int asan_fake_stack_may_be_active = 0;

#ifdef AMA_PQ_STACK_UNDER_ASAN
    /* Does not return when the re-exec succeeds. */
    asan_fake_stack_may_be_active = asan_reexec_without_fake_stack(argc, argv);
    if (asan_fake_stack_may_be_active) {
        printf("NOTE: running under AddressSanitizer and could not re-exec "
               "with detect_stack_use_after_return=0; if ASan's fake stack is "
               "active the measurements below are of the wrong stack and the "
               "non-vacuity guards will say so.\n");
    }
#else
    (void)argc;
    (void)argv;
#endif

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
            if (asan_fake_stack_may_be_active) {
                printf("       AddressSanitizer's fake stack is the known "
                       "cause: it relocates every frame under 64 KiB off the "
                       "real stack, which is where this test looks. Re-run "
                       "with ASAN_OPTIONS=detect_stack_use_after_return=0.\n");
            }
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
        if (asan_fake_stack_may_be_active) {
            printf("      AddressSanitizer's fake stack is the known cause: "
                   "it relocates every frame under 64 KiB off the real stack, "
                   "which is where this test looks. Re-run with "
                   "ASAN_OPTIONS=detect_stack_use_after_return=0.\n");
        }
        return 1;
    }
    printf("PASS\n");
    return 0;
}

#endif /* POSIX */
