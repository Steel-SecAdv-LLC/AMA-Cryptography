/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file stack_scrub_build.c
 * @brief What the library's own compiler flags select in
 *        src/c/internal/ama_stack_wipe.h, for tests/c/test_stack_scrub.c.
 *
 * The depth a scrubbed entry point clears is chosen where the library is
 * compiled, by whether that compilation optimises.  test_stack_scrub.c
 * cannot ask its own preprocessor: a residue probe is always compiled -O2
 * (tests/c/CMakeLists.txt, add_ama_residue_probe), whatever the library was.
 * Measured 2026-11-10 with CMAKE_BUILD_TYPE=None: the probe named 2,048 bytes
 * for SHA-3 while the library cleared 8,192.  This file is compiled with the
 * directory's flags, which are the library's (the build gives optimisation
 * to no target of its own, only to the configuration), and holds the answers
 * as data.
 */
#include "stack_scrub_build.h"

#include "../../src/c/internal/ama_stack_wipe.h"

const int scrub_library_is_optimised = AMA_SCRUB_OPTIMISED_BUILD;

#define SCRUB_DEFINE_DEPTH(family) const size_t scrub_depth_##family = AMA_SCRUB_##family##_BYTES;
SCRUB_FAMILIES(SCRUB_DEFINE_DEPTH)
