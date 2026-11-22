/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ct_hw_mode.c
 * @brief ama_ct_hw_mode_status / _enable / _control report the hardware
 *        data-independent-timing mode truthfully (Intel DOITM, Arm DIT).
 *
 * The secret-operand gate (tools/check_ct_operand.py) admits an instruction
 * because a vendor lists it as data-independent; both vendors make that a
 * property of a MODE.  These three functions are how a deployment learns
 * whether the mode is in force, so a wrong answer is a false assurance.
 * Every assertion compares the library against an INDEPENDENT probe written
 * here, never against the library's own state:
 *
 *   x86-64  the CPUID vendor string and CPUID.(EAX=07H,ECX=0):EDX[29].  An
 *           Intel part with IA32_ARCH_CAPABILITIES must report UNKNOWN (the
 *           MSR is unreadable from user mode), any other part
 *           NOT_IMPLEMENTED, and enable() must change neither: the library
 *           cannot set DOITM and must never claim ENABLED.
 *   AArch64 getauxval(AT_HWCAP) & HWCAP_DIT and a direct MRS of DIT
 *           (S3_3_C4_C2_5, bit 24).  Without FEAT_DIT both calls report
 *           NOT_IMPLEMENTED.  With it, status() must match the register
 *           before and after, and enable() must leave bit 24 set and report
 *           ENABLED.
 *
 * Elsewhere the functions must answer UNKNOWN, and the test checks that.
 */

#include "ama_cryptography.h"
#include "ama_dispatch.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif
#if defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>
#endif

static int g_failures = 0;

#define CHECK(cond, ...)                                                                       \
    do {                                                                                       \
        if (cond) {                                                                            \
            printf("  [ OK ] ");                                                               \
        } else {                                                                               \
            printf("  [FAIL] ");                                                               \
            g_failures++;                                                                      \
        }                                                                                      \
        printf(__VA_ARGS__);                                                                   \
        printf("\n");                                                                          \
    } while (0)

static const char *mode_name(int m) {
    switch (m) {
        case AMA_CT_HW_MODE_ENABLED:
            return "ENABLED";
        case AMA_CT_HW_MODE_DISABLED:
            return "DISABLED";
        case AMA_CT_HW_MODE_NOT_IMPLEMENTED:
            return "NOT_IMPLEMENTED";
        case AMA_CT_HW_MODE_UNKNOWN:
            return "UNKNOWN";
        default:
            return "(not a defined value)";
    }
}

int main(void) {
    const int before = ama_ct_hw_mode_status();
    const char *control = ama_ct_hw_mode_control();
    printf("test_ct_hw_mode: control=%s status=%s\n", control ? control : "(null)",
           mode_name(before));
    CHECK(control != NULL, "the control name is never NULL");
    CHECK(before >= AMA_CT_HW_MODE_ENABLED && before <= AMA_CT_HW_MODE_UNKNOWN,
          "status() returns a defined AMA_CT_HW_MODE_* value (%d)", before);

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    {
        unsigned r0[4] = {0, 0, 0, 0}, r7[4] = {0, 0, 0, 0};
        char vendor[12];
#ifdef _MSC_VER
        int t[4];
        __cpuidex(t, 0, 0);
        for (int i = 0; i < 4; i++) r0[i] = (unsigned)t[i];
        if (r0[0] >= 7u) {
            __cpuidex(t, 7, 0);
            for (int i = 0; i < 4; i++) r7[i] = (unsigned)t[i];
        }
#else
        __cpuid_count(0, 0, r0[0], r0[1], r0[2], r0[3]);
        if (r0[0] >= 7u) {
            __cpuid_count(7, 0, r7[0], r7[1], r7[2], r7[3]);
        }
#endif
        memcpy(vendor + 0, &r0[1], 4);
        memcpy(vendor + 4, &r0[3], 4);
        memcpy(vendor + 8, &r0[2], 4);
        const int intel = memcmp(vendor, "GenuineIntel", sizeof vendor) == 0;
        const int arch_caps = intel && r0[0] >= 7u && ((r7[3] >> 29) & 1u);
        const int expected = arch_caps ? AMA_CT_HW_MODE_UNKNOWN : AMA_CT_HW_MODE_NOT_IMPLEMENTED;
        printf("  probe: vendor=%.12s IA32_ARCH_CAPABILITIES enumerated=%d\n", vendor, arch_caps);
        CHECK(before == expected, "status() is %s for this CPU (got %s)", mode_name(expected),
              mode_name(before));
        CHECK(strcmp(control, intel ? "intel-doitm" : "none") == 0,
              "control() names %s for this vendor (got %s)", intel ? "intel-doitm" : "none",
              control);
        const int after = ama_ct_hw_mode_enable();
        CHECK(after == before, "enable() changes nothing on x86-64 (got %s)", mode_name(after));
        CHECK(after != AMA_CT_HW_MODE_ENABLED && before != AMA_CT_HW_MODE_ENABLED,
              "the library never claims DOITM is ENABLED: it cannot read the control");
    }
#elif defined(__aarch64__) && defined(__linux__) && defined(HWCAP_DIT) && \
    (defined(__GNUC__) || defined(__clang__))
    {
        const int implemented = (getauxval(AT_HWCAP) & (unsigned long)HWCAP_DIT) != 0;
        printf("  probe: HWCAP_DIT=%d\n", implemented);
        CHECK(strcmp(control, "arm-pstate-dit") == 0, "control() is arm-pstate-dit");
        if (!implemented) {
            CHECK(before == AMA_CT_HW_MODE_NOT_IMPLEMENTED, "status() is NOT_IMPLEMENTED (got %s)",
                  mode_name(before));
            CHECK(ama_ct_hw_mode_enable() == AMA_CT_HW_MODE_NOT_IMPLEMENTED,
                  "enable() is NOT_IMPLEMENTED without FEAT_DIT");
        } else {
            uint64_t reg;
            __asm__ volatile("mrs %0, S3_3_C4_C2_5" : "=r"(reg));
            const int bit = (int)((reg >> 24) & 1u);
            CHECK(before == (bit ? AMA_CT_HW_MODE_ENABLED : AMA_CT_HW_MODE_DISABLED),
                  "status() matches DIT bit 24 = %d before enable (got %s)", bit,
                  mode_name(before));
            const int after = ama_ct_hw_mode_enable();
            __asm__ volatile("mrs %0, S3_3_C4_C2_5" : "=r"(reg));
            CHECK(((reg >> 24) & 1u) == 1u, "enable() leaves DIT bit 24 set in PSTATE");
            CHECK(after == AMA_CT_HW_MODE_ENABLED, "enable() reports ENABLED (got %s)",
                  mode_name(after));
            CHECK(ama_ct_hw_mode_status() == AMA_CT_HW_MODE_ENABLED,
                  "status() reports ENABLED after enable()");
        }
    }
#else
    CHECK(before == AMA_CT_HW_MODE_UNKNOWN,
          "status() is UNKNOWN where this build has no probe (got %s)", mode_name(before));
    CHECK(ama_ct_hw_mode_enable() == AMA_CT_HW_MODE_UNKNOWN,
          "enable() is UNKNOWN where this build has no probe");
#endif

    if (g_failures) {
        printf("test_ct_hw_mode: %d FAILED\n", g_failures);
        return 1;
    }
    printf("test_ct_hw_mode: all checks passed\n");
    return 0;
}
