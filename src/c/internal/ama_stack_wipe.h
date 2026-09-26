/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_stack_wipe.h
 * @brief Internal, depth-parameterised form of ama_secure_stack_wipe().
 *
 * `ama_secure_stack_wipe()` clears AMA_STACK_WIPE_BYTES (4 KiB) below its
 * caller, which covers the AEAD kernels.  The Ed25519 signing chain runs
 * deeper: under UBSan instrumentation limbs of the secret scalar were
 * measured 4,679-4,895 bytes below the probe anchor, out of that window
 * (tests/c/test_ed25519_stack_residue.c).  Both depths come from this one
 * routine rather than two copies of it.
 */
#ifndef AMA_STACK_WIPE_H
#define AMA_STACK_WIPE_H

#include <stddef.h>

/** Largest depth ama_stack_wipe_below() can clear. */
#define AMA_STACK_WIPE_MAX_BYTES 8192u

/** Depth the Ed25519 entry points clear (see the file comment). */
#define AMA_ED25519_STACK_WIPE_BYTES 8192u

/**
 * Zero the `bytes` bytes of dead stack immediately below the calling frame
 * (clamped to AMA_STACK_WIPE_MAX_BYTES).  Call it from the frame that called
 * the primitive, right after the primitive returns.
 */
void ama_stack_wipe_below(size_t bytes);

#endif /* AMA_STACK_WIPE_H */
