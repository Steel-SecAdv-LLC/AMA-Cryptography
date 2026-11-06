/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file benchmark_c_raw_recorded.h
 * @brief Prototypes shared by test_benchmark_mldsa_sign_pool.c and the
 *        recorded build of benchmarks/benchmark_c_raw.c.
 *
 * tests/c/CMakeLists.txt compiles the harness as the object library
 * `benchmark_c_raw_recorded`, with ama_dilithium_sign, ama_dilithium_keypair
 * and main renamed by -D definitions and this header force-included.  The
 * recorders are defined by the test; benchmark_c_raw_main is the harness's
 * main under its new name.  One declaration of each, seen by both TUs, so the
 * compiler checks the signatures the rename joins.
 */
#ifndef AMA_BENCHMARK_C_RAW_RECORDED_H
#define AMA_BENCHMARK_C_RAW_RECORDED_H

#include <stddef.h>
#include <stdint.h>

#include "ama_cryptography.h"

ama_error_t recording_dilithium_sign(uint8_t *signature, size_t *signature_len,
                                     const uint8_t *message, size_t message_len,
                                     const uint8_t *secret_key);
ama_error_t recording_dilithium_keypair(uint8_t *public_key, uint8_t *secret_key);
int benchmark_c_raw_main(int argc, char **argv);

#endif /* AMA_BENCHMARK_C_RAW_RECORDED_H */
