/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_cpuid_assume_adx.c
 * @brief AMA_TESTING_ASSUME_ADX=1 selects the MULX+ADX kernels exactly when
 *        CPUID reports BMI2, and the answer is a pure function of CPUID.
 *
 * Valgrind 3.22 executes ADCX/ADOX but reports CPUID ADX clear, so no
 * Valgrind-based gate could select the X25519 MULX ladder or the P-curve
 * MULX Montgomery multiply that production runs on every ADX-capable CPU.
 * src/c/ama_cpuid.c honours AMA_TESTING_ASSUME_ADX=1 in the AMA_TESTING_MODE
 * archive only (tools/check_ct_operand.py --assume-adx).  This holds the two
 * halves of that contract:
 *
 *   - set: ama_has_adx() equals ama_has_bmi2(), and
 *     ama_cpuid_has_x25519_mulx() follows it;
 *   - and X25519 still agrees with RFC 7748's section 5.2 vector through
 *     whichever ladder that selects, so an assumption that selected a broken
 *     kernel cannot pass.
 *
 * The variable is set before the first CPUID read, which is when the library
 * caches its answer.  Fails if the override is removed on a BMI2 host (ADX
 * stays at CPUID's answer, which is 0 under Valgrind and 1 natively on an
 * ADX host, so the first check is the one that fails under Valgrind) and if
 * it is honoured without BMI2.
 */
#define _POSIX_C_SOURCE 200112L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ama_cryptography.h"
#include "ama_cpuid.h"

int main(void) {
    if (setenv("AMA_TESTING_ASSUME_ADX", "1", 1) != 0) {
        printf("FAIL: setenv\n");
        return 1;
    }
    int failures = 0;
    const int bmi2 = ama_has_bmi2();
    const int adx = ama_has_adx();
    if (adx != bmi2) {
        printf("FAIL: with AMA_TESTING_ASSUME_ADX=1, ama_has_adx()=%d but "
               "ama_has_bmi2()=%d\n", adx, bmi2);
        failures++;
    }
#if defined(__x86_64__) || defined(_M_X64)
    if (ama_cpuid_has_x25519_mulx() != bmi2) {
        printf("FAIL: ama_cpuid_has_x25519_mulx()=%d, expected %d\n",
               ama_cpuid_has_x25519_mulx(), bmi2);
        failures++;
    }
#endif

    /* RFC 7748 section 5.2, first X25519 test vector. */
    static const uint8_t scalar[32] = {
        0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15,
        0x4b, 0x82, 0x46, 0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc,
        0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4};
    static const uint8_t u_in[32] = {
        0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1,
        0xa4, 0x24, 0xb1, 0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3,
        0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c};
    static const uint8_t expect[32] = {
        0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea,
        0x4d, 0xf2, 0x8d, 0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c,
        0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52};
    uint8_t out[32];
    if (ama_x25519_key_exchange(out, scalar, u_in) != AMA_SUCCESS ||
        memcmp(out, expect, sizeof(out)) != 0) {
        printf("FAIL: X25519 RFC 7748 5.2 vector through the selected ladder\n");
        failures++;
    }

    if (failures == 0) {
        printf("PASS: AMA_TESTING_ASSUME_ADX follows BMI2 (bmi2=%d adx=%d); "
               "X25519 RFC 7748 vector holds\n", bmi2, adx);
        return 0;
    }
    return 1;
}
