/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file x25519_equiv_ladders.h
 * @brief The two renamed X25519 ladders used by the fe51/fe64 differential.
 *
 * The `x25519_equiv_fe51` and `x25519_equiv_fe64` object libraries
 * (tests/c/CMakeLists.txt) each compile `src/c/ama_x25519.c` with one field
 * path forced and `x25519_scalarmult` renamed by a -D definition, and
 * force-include this header, so both objects link into one executable.  The
 * renamed symbols had no prototype at their definitions and were declared
 * with a local `extern` in `test_x25519_field_equiv.c` — so the signature the
 * test calls through and the signature the wrapper defines were two separate
 * transcriptions, on a differential whose entire purpose is to prove two
 * implementations agree byte for byte.
 *
 * One declaration, seen by all three, so the compiler checks what the
 * comment was asserting.
 */
#ifndef AMA_X25519_EQUIV_LADDERS_H
#define AMA_X25519_EQUIV_LADDERS_H

#include <stdint.h>

/** Montgomery ladder compiled against the 5x51-bit field representation. */
void x25519_scalarmult_fe51(uint8_t q[32], const uint8_t n[32], const uint8_t p[32]);

/** Montgomery ladder compiled against the 4x64-bit field representation. */
void x25519_scalarmult_fe64(uint8_t q[32], const uint8_t n[32], const uint8_t p[32]);

#endif /* AMA_X25519_EQUIV_LADDERS_H */
