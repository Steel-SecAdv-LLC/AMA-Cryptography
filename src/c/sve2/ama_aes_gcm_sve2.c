/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_aes_gcm_sve2.c
 * @brief ARM SVE2 AES-GCM placeholder TU (no kernels currently wired)
 *
 * SVE2 GHASH acceleration is not yet implemented.  AES-GCM on
 * SVE2-capable ARM systems dispatches through the NEON path
 * (src/c/neon/ama_aes_gcm_neon.c), which uses vmull_p64 / vmull_high_p64
 * from the ARMv8 Crypto Extensions for the GHASH PMULL and the AES
 * instructions for the block cipher.  That kernel is byte-identical to
 * the generic-C reference (verified by tests/c/test_aes_gcm_neon_equiv.c)
 * and is the production path on every shipped AArch64 host.
 *
 * The previous content of this file was a scalar bit-loop stub
 * (ghash_mul_gf128, ama_ghash_precompute_sve2) that was compiled but
 * never reached by any dispatch table entry.  It has been removed: a
 * dead stub carries audit cost without operational benefit, and any
 * future SVE2 GHASH implementation will need a real PMULL/PMULL2 +
 * SVE2 vector design with a corresponding feature probe in
 * src/c/dispatch/ama_dispatch.c and an ARM SVE2 + crypto-extension CI
 * lane to validate against KAT.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>

typedef int ama_aes_gcm_sve2_not_available;
