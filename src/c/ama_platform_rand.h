/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_platform_rand.h
 * @brief Platform-native cryptographic random number generation
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * Provides OS-level CSPRNG access without OpenSSL dependency.
 * Supports Linux (getrandom), macOS (getentropy), Windows (BCryptGenRandom),
 * and BSD (/dev/urandom fallback).
 */

#ifndef AMA_PLATFORM_RAND_H
#define AMA_PLATFORM_RAND_H

#include <stddef.h>
#include <stdint.h>
#include "../include/ama_cryptography.h"

/**
 * @brief Fill buffer with cryptographically secure random bytes.
 *
 * Uses the operating system's CSPRNG:
 *   - Linux 3.17+: getrandom(2) with blocking semantics
 *   - macOS 10.12+: getentropy(3) in 256-byte chunks
 *   - Windows Vista+: BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG
 *   - BSD fallback: /dev/urandom
 *
 * @param buf   Output buffer
 * @param len   Number of random bytes to generate
 * @return AMA_SUCCESS on success, AMA_ERROR_CRYPTO on failure
 */
ama_error_t ama_randombytes(uint8_t *buf, size_t len);

#endif /* AMA_PLATFORM_RAND_H */
