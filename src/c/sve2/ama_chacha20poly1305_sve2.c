/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_chacha20poly1305_sve2.c
 * @brief ARM SVE2 ChaCha20-Poly1305 placeholder TU (no kernels currently wired)
 *
 * SVE2 ChaCha20 acceleration is not currently shipped.  ChaCha20-Poly1305
 * on SVE2-capable ARM systems dispatches through the NEON path
 * (`src/c/neon/ama_chacha20poly1305_neon.c`), which is byte-identical to
 * the scalar reference (verified by `tests/c/test_chacha20poly1305.c` and
 * `tests/c/test_chacha20poly1305_neon_equiv.c`) and is the production path
 * on every shipped AArch64 host — including SVE2-capable ones.
 *
 * The previous content of this file was a `ama_chacha20_block_sve2`
 * kernel whose output shape (VL-dependent block count returned via an
 * `out_blocks` pointer) was structurally incompatible with the dispatch
 * table's fixed-shape `ama_chacha20_block_x8_fn` signature
 * (`uint8_t out[512]`, exactly 8 sequential blocks).  Wiring it would
 * have required an adapter plus byte-identity validation against
 * VL=128/256/512 — none of which can be exercised without an
 * SVE-aware CI lane.  Per the project's "no speculative API surface"
 * principle, that kernel has been removed:
 *
 *   - It carried audit cost (sensitive intermediate `tmp[64]` buffer
 *     was not scrubbed on return, in tension with INVARIANT-12).
 *   - It carried correctness risk (no KAT lane on real or emulated
 *     SVE2 hardware across the three relevant VLs).
 *   - It carried zero operational benefit because no caller could
 *     reach it through the dispatch table.
 *
 * A future SVE2 ChaCha20 kernel must (a) match
 * `ama_chacha20_block_x8_fn` exactly, (b) scrub every intermediate
 * state buffer on every return path, and (c) land alongside a
 * SVE-aware CI lane (qemu-aarch64 `--cpu max,sve2=on` with sweep over
 * `SVE_VECTOR_LENGTH=128/256/512`) that compares the kernel's output
 * byte-for-byte against the scalar reference.  Until those three
 * preconditions hold, SVE2 hosts continue dispatching to the validated
 * NEON kernel — a strict upgrade over the generic-C fallback.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>

typedef int ama_chacha20poly1305_sve2_not_available;
