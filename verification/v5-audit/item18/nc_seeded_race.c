/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/* * Item 18 NEGATIVE CONTROL: a deliberate, unsynchronised data race.
 * Both TSan and Helgrind MUST report it.  A detector that reports this
 * program clean is not instrumented, and any "clean" verdict it gives on
 * the real harness is worthless.  Run before the clean run counts.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define NTHREADS 64
#define ITERS 20000

static long g_shared;          /* deliberately unguarded */
static unsigned char g_buf[64];

static void *worker(void *arg) {
    long id = (long)arg;
    for (int i = 0; i < ITERS; i++) {
        g_shared += id;                        /* RACE: read-modify-write */
        g_buf[i % (int)sizeof(g_buf)] = (unsigned char)(id + i); /* RACE */
    }
    return NULL;
}

int main(void) {
    pthread_t t[NTHREADS];
    for (long i = 0; i < NTHREADS; i++) {
        if (pthread_create(&t[i], NULL, worker, (void *)i) != 0) {
            perror("pthread_create");
            return 2;
        }
    }
    for (int i = 0; i < NTHREADS; i++) pthread_join(t[i], NULL);
    printf("seeded-race harness finished, g_shared=%ld\n", g_shared);
    return 0;
}
