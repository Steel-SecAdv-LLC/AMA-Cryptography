/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_ed25519_sve2.c
 * @brief ARM SVE2 Ed25519 placeholder TU (no kernels currently wired)
 *
 * SVE2 Ed25519 acceleration is not currently shipped.  As documented
 * at `src/c/dispatch/ama_dispatch.c` lines 354-357, the dispatcher
 * reports `dispatch_info.ed25519 = AMA_IMPL_GENERIC` on every AArch64
 * host: the concrete non-vector backend (scalar `fe51` radix-2^51, or
 * the donna shim when `AMA_ED25519_ASSEMBLY` is enabled) is selected
 * by the build configuration, not at runtime, because:
 *
 *   1. Ed25519 single-shot signatures are dominated by SHA-512 and a
 *      single-point scalar multiplication.  Vectorizing the field
 *      arithmetic does not help a single ladder — the ladder is
 *      sequential by construction.  A vector path is only useful for a
 *      batched API, and AMA Cryptography intentionally does not expose
 *      a batched Ed25519 sign / verify API today (per the project's
 *      "no speculative API surface" principle — see `THREAT_MODEL.md`).
 *   2. The AVX2 Ed25519 trampoline was removed in PR #238 after
 *      benchmarks showed the scalar `fe51` backend was already faster;
 *      that decision applies symmetrically to NEON and SVE2 absent a
 *      batched caller.
 *
 * The previous content of this file was scalar-driven
 * `ama_fe51_add_batch_sve2` / `ama_fe51_sub_batch_sve2` helpers that
 * exposed a `fe51_sve2 {uint64_t v[5];}` struct never referenced by
 * any other TU.  No dispatch table slot fed them, no public API
 * consumed them, and no KAT covered them — they were dead code, and
 * dead crypto code is pre-installed attack surface.  They have been
 * removed.
 *
 * A future SVE2 Ed25519 acceleration must (a) materialize through a
 * deliberately declared batched API (`include/ama_cryptography.h`
 * change required) with its own threat model, ethical gate, and PQC
 * companion path, and (b) land alongside an SVE-aware CI lane that
 * compares the batched output byte-for-byte against the scalar
 * single-shot reference per lane.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>

typedef int ama_ed25519_sve2_not_available;
