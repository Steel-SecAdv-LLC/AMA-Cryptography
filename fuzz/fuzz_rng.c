/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file fuzz_rng.c
 * @brief Fuzz-only deterministic PRNG that wraps ``ama_randombytes``.
 *
 * Purpose
 * -------
 * libFuzzer / AFL corpus minimization and crash reduction require byte-
 * exact reproducibility — a given input must always exercise the same
 * code path.  The core AMA FROST implementation deliberately calls
 * ``ama_randombytes`` from ``scalar_random`` inside ``ama_frost_round1_commit``
 * (RFC 9591 §2.1 mandates fresh per-round nonces; reuse is total key
 * compromise, so this cannot be relaxed in the core code).  That makes
 * any fuzz harness that exercises the full round1→round2→aggregate path
 * non-deterministic for a given input.
 *
 * Mechanism
 * ---------
 * This translation unit is linked **only** into fuzz targets that opt
 * in via the linker rule ``-Wl,--wrap=ama_randombytes`` (see
 * ``fuzz/CMakeLists.txt``).  That rule rewrites every call to
 * ``ama_randombytes`` inside the fuzz executable so it resolves to
 * ``__wrap_ama_randombytes`` below; the original OS CSPRNG
 * implementation is still reachable as ``__real_ama_randombytes``.
 *
 * The wrap is fuzz-target-only.  The production static library, the
 * Python extension, the ``libama_cryptography`` shared library, and
 * every installed consumer of the public API continue to bind to the
 * unmodified ``ama_randombytes`` and still receive OS-kernel CSPRNG
 * bytes.  There is no possible path by which the deterministic PRNG
 * below can leak into a production build.
 *
 * PRNG construction
 * -----------------
 * Output block i (32 bytes) = ``SHA3-256(seed || LE64(i))`` for
 * ``i = 0, 1, 2, …``.  SHA3-256 is used because it is already in the
 * library's public API (``ama_sha3_256``) and gives a well-spread,
 * collision-resistant stream; this is a debug aid, not a cryptographic
 * RNG, so the construction only needs to be deterministic and have
 * enough diffusion to exercise distinct code paths on distinct inputs.
 */

#include "fuzz_rng.h"
#include "../include/ama_cryptography.h"

#include <stdint.h>
#include <string.h>

/* ``__real_ama_randombytes`` is defined by the linker's --wrap rule.
 * Declared here so the "no seed yet" fall-through is well-typed. */
ama_error_t __real_ama_randombytes(uint8_t *buf, size_t len);

/* Prior prototype so -Wmissing-prototypes stays clean under the strict
 * clang warning build.  The symbol has external linkage because the
 * linker's --wrap rule has to find it; it is not intended to be called
 * from any other translation unit. */
ama_error_t __wrap_ama_randombytes(uint8_t *buf, size_t len);

/* ==========================================================================
 * PRNG state
 * ========================================================================== */

/* Key = 32-byte seed copied from the fuzz input (zero-padded if shorter). */
static uint8_t g_seed[32];
/* Monotonic 64-bit counter, little-endian when hashed. */
static uint64_t g_counter;
/* Whether the PRNG has been seeded since process start. */
static int g_seeded;

void fuzz_rng_seed(const uint8_t *seed, size_t seed_len) {
    memset(g_seed, 0, sizeof g_seed);
    if (seed != NULL && seed_len > 0) {
        size_t copy = seed_len > sizeof g_seed ? sizeof g_seed : seed_len;
        memcpy(g_seed, seed, copy);
    }
    g_counter = 0;
    /* A zero-length seed explicitly clears the PRNG — subsequent calls
     * will fall back to the real CSPRNG.  A non-empty seed (even all
     * zeros) activates the deterministic path: all-zero seeds are a
     * legitimate fuzz input and must still produce reproducible
     * transcripts. */
    g_seeded = (seed != NULL && seed_len > 0) ? 1 : 0;
}

/* Fill exactly 32 output bytes from block index ``idx``. */
static ama_error_t fuzz_rng_block(uint64_t idx, uint8_t out[32]) {
    uint8_t input[sizeof g_seed + 8];
    memcpy(input, g_seed, sizeof g_seed);
    for (int i = 0; i < 8; i++) {
        input[sizeof g_seed + i] = (uint8_t)((idx >> (8 * i)) & 0xFFU);
    }
    return ama_sha3_256(input, sizeof input, out);
}

/* ==========================================================================
 * __wrap_ama_randombytes — linker-installed override for fuzz targets
 * ========================================================================== */

ama_error_t __wrap_ama_randombytes(uint8_t *buf, size_t len) {
    if (!g_seeded) {
        /* Startup path (before the first LLVMFuzzerTestOneInput).  Fall
         * through to the real OS CSPRNG so any pre-harness initialization
         * that needs real entropy still gets it. */
        return __real_ama_randombytes(buf, len);
    }
    if (buf == NULL && len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (len == 0) {
        return AMA_SUCCESS;
    }

    size_t offset = 0;
    while (offset < len) {
        uint8_t block[32];
        ama_error_t rc = fuzz_rng_block(g_counter++, block);
        if (rc != AMA_SUCCESS) {
            return rc;
        }
        size_t take = len - offset;
        if (take > sizeof block) {
            take = sizeof block;
        }
        memcpy(buf + offset, block, take);
        offset += take;
    }
    return AMA_SUCCESS;
}
