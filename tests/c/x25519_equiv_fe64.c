/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Wrapper TU for the fe51 vs fe64 byte-equivalence test
 * (`tests/c/test_x25519_field_equiv.c`).
 *
 * Compiles ama_x25519.c with the fe64 field path forced and renames the
 * inner ladder symbol so the resulting object can be linked alongside
 * the fe51 wrapper into a single test executable.
 */

#define AMA_X25519_FORCE_FE64       1
#define AMA_X25519_NO_PUBLIC_API    1
#define AMA_X25519_LADDER_LINKAGE   /* empty — external linkage */
#define x25519_scalarmult           x25519_scalarmult_fe64

#include "../../src/c/ama_x25519.c"
