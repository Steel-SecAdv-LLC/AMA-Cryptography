/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file fuzz_rng.h
 * @brief Fuzz-only deterministic PRNG header — fuzz-harness-only.
 *
 * This header is consumed **only** by fuzz targets that link against a
 * wrapped ``ama_randombytes`` (see ``fuzz/fuzz_rng.c``).  It is not
 * included anywhere in the production library and is not installed.
 *
 * Seed the per-input PRNG at the top of ``LLVMFuzzerTestOneInput`` with
 * ``fuzz_rng_seed(data, size)``.  Subsequent calls to ``ama_randombytes``
 * inside the fuzz target will be intercepted by the linker's
 * ``--wrap=ama_randombytes`` rule and serviced deterministically from
 * the SHA3-256 counter stream keyed by the seed, so a given fuzz input
 * always produces the same protocol transcript.  Calls that arrive
 * before the first seed (e.g. during libFuzzer warm-up) fall through to
 * the real OS CSPRNG via ``__real_ama_randombytes``.
 */

#ifndef AMA_FUZZ_RNG_H
#define AMA_FUZZ_RNG_H

#include <stddef.h>
#include <stdint.h>

#include "../include/ama_cryptography.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Seed the fuzz-harness PRNG from ``seed``/``seed_len`` bytes.  Copies up
 * to 32 bytes (zero-padded if shorter) into the internal key and resets
 * the counter.  Safe to call with ``seed == NULL && seed_len == 0``
 * (clears the PRNG — subsequent calls fall back to the real CSPRNG).
 */
void fuzz_rng_seed(const uint8_t *seed, size_t seed_len);

/**
 * Prototype for the RNG symbol whose calls are rewritten by
 * ``-Wl,--wrap=ama_randombytes`` on the fuzz target.  Declared here (and
 * not only in the private ``src/c/ama_platform_rand.h``) so fuzz
 * harnesses can call it directly — e.g. for the self-check in
 * ``fuzz_frost.c`` that verifies the wrap is actually in effect — without
 * pulling in a private library header.
 */
ama_error_t ama_randombytes(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* AMA_FUZZ_RNG_H */
