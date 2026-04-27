/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Wrapper TU for the fe51 vs fe64 byte-equivalence test
 * (`tests/c/test_x25519_field_equiv.c`).
 *
 * Compiles ama_x25519.c with the fe51 field path forced and renames the
 * inner ladder symbol so the resulting object can be linked alongside
 * the fe64 wrapper into a single test executable.
 *
 *   AMA_X25519_FORCE_FE51       — pick the fe51 ladder regardless of host
 *   AMA_X25519_NO_PUBLIC_API    — skip duplicate ama_x25519_* definitions
 *   AMA_X25519_LADDER_LINKAGE   — empty (i.e. external linkage)
 *   x25519_scalarmult           — renamed via the macro override below
 */

#define AMA_X25519_FORCE_FE51       1
#define AMA_X25519_NO_PUBLIC_API    1
#define AMA_X25519_LADDER_LINKAGE   /* empty — external linkage */
#define x25519_scalarmult           x25519_scalarmult_fe51

#include "../../src/c/ama_x25519.c"
