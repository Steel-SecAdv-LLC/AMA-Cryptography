/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_argon2_sve2.c
 * @brief ARM SVE2 Argon2 placeholder TU (no kernels currently wired)
 *
 * SVE2 Argon2id acceleration is not currently shipped.  Argon2id on
 * SVE2-capable ARM systems dispatches through the NEON path
 * (`src/c/neon/ama_argon2_neon.c`), which implements the full RFC 9106
 * §3.5 BlaMka G permutation (row-pass + column-pass over the 1024-byte
 * block) and is byte-identical to the scalar reference on the Argon2id
 * KAT lane.
 *
 * The previous content of this file was an `ama_argon2_g_sve2` kernel
 * that — as the prior file header itself flagged — implemented **plain
 * Blake2b G, not RFC 9106 BlaMka G**, and was missing the column-pass
 * entirely.  Wiring it would have produced incorrect Argon2id tags and
 * broken every KAT.  The kernel was deferred for that reason; the
 * project's "no speculative API surface" principle forbids leaving a
 * known-broken acceleration TU compiled into the library because it
 * is pre-installed attack surface (any future contributor adding a
 * wiring line would silently corrupt password-derived keys).  The
 * kernel has therefore been removed.
 *
 * A future SVE2 Argon2 kernel must (a) reproduce
 * `src/c/avx2/ama_argon2_avx2.c` / `src/c/neon/ama_argon2_neon.c`
 * exactly — row-pass over each 16-qword row, then column-pass over
 * each stride-16 column group, with the BlaMka G round (`a = a + b +
 * 2*lower32(a)*lower32(b)` per RFC 9106 §3.5, not Blake2b's plain `a =
 * a + b + m`) — and (b) land alongside an SVE-aware CI lane that
 * compares its 1024-byte block output byte-for-byte against the scalar
 * reference under VL=128/256/512.  Until those preconditions hold,
 * SVE2 hosts continue dispatching to the validated NEON BlaMka kernel.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>

typedef int ama_argon2_sve2_not_available;
