/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_register_residue.c
 * @brief No secret a public entry point produces is left in a vector
 *        register, or in its dead stack, when the call returns (INVARIANT-6).
 *
 * WHY A REGISTER, AND WHY THIS IS A MEMORY DEFECT.  The System V x86-64 ABI
 * makes every vector register call-clobbered (AAPCS64 all but the low halves
 * of v8-v15), so a secret a callee leaves in
 * one is the caller's to overwrite, and nothing makes the caller do it soon.
 * The next save of the register file writes it to memory nobody scrubs: the
 * dynamic linker's lazy-binding trampoline (_dl_runtime_resolve_xsavec saves
 * every vector register onto the stack), a signal frame, a ucontext switch.
 * Measured 2026-11-08: once ama_sha3.c's store64_le became a whole-word
 * memcpy, gcc 13 -O2 merged ama_sha3_final's four digest stores into two
 * MOVDQU copies through %xmm8/%xmm9, and tools/measure_secret_residue.py
 * found one whole live copy of the HKDF-SHA3-256 output on [stack] under
 * CPython 3.12 (CI job 128658717231; reproduced locally, and gone under
 * LD_BIND_NOW=1, which binds every PLT slot before the call so that no
 * trampoline runs after it).
 *
 * That Python-level instrument sees such a copy only when a trampoline runs
 * before the interpreter overwrites the registers: under CPython 3.13 here it
 * did not, on the same library, and a signal raised from Python to force the
 * save came too late as well.  So it is no pin for the property.  This
 * harness is: it calls each entry point through the shared library and
 * stores %xmm0-%xmm15 (%ymm0-%ymm15 with AVX, and %zmm16-%zmm31 with
 * AVX-512F) in the instructions right after the call returns.  Nothing runs
 * in between that could clear them, and the compiler cannot keep a value of
 * its own in them across the call, because all of them are caller-saved.
 * Any 8-byte word of the secret found in the dump is a failure.
 *
 * WHAT HOLDS THE PROPERTY.  The measured surface leaked, before the
 * 2026-11-08 change, on main as well as on this branch: PBKDF2-SHA512,
 * Argon2id and the plaintext of all three AEADs (and two AES-256 key words
 * from AES-GCM decrypt on main); this branch added the SHA-3 digest and the
 * X25519 shared secret.  Every exported function is now compiled with
 * zero_call_used_regs("all") (AMA_API in include/ama_cryptography.h), so it
 * clears every call-clobbered register on return whatever its callees,
 * kernels and libc left there.  That attribute is the PIN for the PBKDF2,
 * Argon2id and AEAD rows: without it they fail.
 *
 * It cannot reach %zmm16-31 from a baseline x86-64 translation unit, and
 * glibc's EVEX memcpy copies through exactly those on every AVX-512 CPU:
 * under clang 18.1, which calls glibc for variable-length copies, the HKDF,
 * HKDF-SHA256, PBKDF2 and Argon2id rows failed with the output in %zmm16 and
 * %zmm17.  src/c/internal/ama_string_ops.h expands every library copy inline
 * instead (REP MOVSB under clang), and is the PIN for those rows on clang
 * (redundant on gcc, whose string-op pin already inlined them);
 * tests/test_no_libc_string_calls.py holds the import table.
 *
 * THE DEAD-STACK ROWS.  fe64_tobytes spilled the X25519 shared secret to its
 * own frame on the way to the MOVDQU copies, and nothing scrubs a returned
 * frame.  The register attribute cannot reach memory, so the value barrier
 * in fe64_store64_le / fe51_store64_le (each word stored from a general
 * register) is what keeps that copy from being made; the probe of
 * residue_probe.h pins it (poison, call below a gap, scan).
 *
 * CORRECTED 2026-11-10 (AGENTS.md section 6.6), twice over.  These two rows
 * look for the whole 32-byte value, which is the copy that was found and
 * all they can find: with one 8-byte word as the needle, the HKDF row's own
 * output had three of its four words in the dead stack of the shipped build
 * while this row read clean, and src/c/internal/ama_keccak_round.h cited the
 * row as evidence that there was nothing there.  The dead stack is now held
 * by tests/c/test_stack_scrub.c, which names no needle, and cleared by every
 * entry point (src/c/internal/ama_stack_wipe.h).  And the rows no longer pin
 * the value barrier: with it removed from fe64_store64_le, every row of this
 * file still passes (gcc 13.3 -O3, LTO), because whatever the compiler then
 * does with the words, the entry point clears the stack it does it in and
 * its return clears the registers.  The rows hold the property; the barrier
 * is one of two things that produce it.
 *
 * AARCH64 (added 2026-11-08, after review asked for it).  The same rows dump
 * x0-x18, q0-q31 and, where the kernel reports SVE, z0-z31 at the vector
 * length.  Measured there before the cures (gcc 13.3, qemu-aarch64 8.2):
 *   - As Neoverse N1/N2/V1 and Cortex-A72, glibc's memcpy left the HKDF,
 *     HKDF-SHA256 and PBKDF2 outputs in q0-q3 (z0-z3 in its SVE form).
 *     As "max", glibc picks its FEAT_MOPS memcpy, which uses no SIMD
 *     register, and the rows passed: run under one CPU model only, this
 *     harness would have missed it.
 *   - The NEON AEAD kernels left key words in q21/q28-q30 and plaintext in
 *     q4/q25.  AMA_API's attribute cannot reach them: the portable sources
 *     compile with -mgeneral-regs-only.
 *   - Under clang 18 with LTO, ama_kyber_encapsulate returned a word of the
 *     shared secret in x10.  It ended in a tail call to an internal
 *     function, so its own clearing return never ran.
 * The cures, each of which fails rows when removed: the AArch64 branch of
 * src/c/internal/ama_string_ops.h (5 rows on N2 and A72),
 * AMA_SIMD_CLEAR_REGS on every NEON/SVE2 kernel (4 rows on every model), and
 * -fno-optimize-sibling-calls (the ML-KEM row under clang).  The ML-KEM rows
 * are otherwise SMOKE: no other mutation fails them.
 * tests/test_public_exits_clear_registers.py reads every export for a tail
 * call, which these rows sample.
 *
 * CONTROLS: a word the harness itself loads into %xmm8 (v8) must be found in
 * the dump, and the stack probe's sentinel must be found in its window, or
 * the instrument is broken and every verdict is void.  The control clears the
 * register again: the low half of v8 is callee-saved, and a planted value
 * left there would be read back by a later row.
 *
 * x86-64 and AArch64 with GNU C inline assembly, not Windows; elsewhere, and
 * under a sanitizer that moves locals off the real frame, it skips (77).
 */
#include "ama_cryptography.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if (defined(__GNUC__) || defined(__clang__)) && !defined(_WIN32)
#if defined(__x86_64__)
#define RESIDUE_X86_64 1
#elif defined(__aarch64__)
#define RESIDUE_AARCH64 1
#if defined(__linux__)
#include <sys/auxv.h>
#if defined(HWCAP_SVE)
#define RESIDUE_SVE_DUMP 1 /* z0-z31 too, where the kernel reports SVE */
#endif
#endif
#endif
#endif

/* The probe header only where it is used: on any other target its helpers
 * would be compiled and never called (-Werror=unused-function). */
#if defined(RESIDUE_X86_64) || defined(RESIDUE_AARCH64)
#include "residue_probe.h"
#endif

/* AMA_REGISTER_RESIDUE_PQC_GROUP: set by tests/c/CMakeLists.txt when the
 * AMA_USE_NATIVE_PQC source group (X25519, Argon2id, ChaCha20-Poly1305) is
 * built; without it those rows are not compiled, and the rest still run. */

#if !(defined(RESIDUE_X86_64) || defined(RESIDUE_AARCH64)) || AMA_PROBE_IS_INSTRUMENTED
int main(void) {
    printf("SKIP: x86-64 or AArch64 with GNU C inline assembly, uninstrumented, only\n");
    return 77;
}
#else

static int g_failures;

#if defined(RESIDUE_X86_64)
#define REG_STRIDE 32
static uint8_t g_regs[16 * REG_STRIDE];
static uint8_t g_hi[16 * 64];
static int g_have_avx;
static int g_have_avx512;

/* Every register stored to its own slot; the YMM form also stores the upper
 * halves, which the trampoline's XSAVEC saves too. */
#define DUMP_XMM()                                                                \
    __asm__ volatile("movdqu %%xmm0,    0(%0)\n\tmovdqu %%xmm1,   32(%0)\n\t"     \
                     "movdqu %%xmm2,   64(%0)\n\tmovdqu %%xmm3,   96(%0)\n\t"     \
                     "movdqu %%xmm4,  128(%0)\n\tmovdqu %%xmm5,  160(%0)\n\t"     \
                     "movdqu %%xmm6,  192(%0)\n\tmovdqu %%xmm7,  224(%0)\n\t"     \
                     "movdqu %%xmm8,  256(%0)\n\tmovdqu %%xmm9,  288(%0)\n\t"     \
                     "movdqu %%xmm10, 320(%0)\n\tmovdqu %%xmm11, 352(%0)\n\t"     \
                     "movdqu %%xmm12, 384(%0)\n\tmovdqu %%xmm13, 416(%0)\n\t"     \
                     "movdqu %%xmm14, 448(%0)\n\tmovdqu %%xmm15, 480(%0)"         \
                     : : "r"(g_regs) : "memory")
#define DUMP_YMM()                                                                \
    __asm__ volatile("vmovdqu %%ymm0,    0(%0)\n\tvmovdqu %%ymm1,   32(%0)\n\t"   \
                     "vmovdqu %%ymm2,   64(%0)\n\tvmovdqu %%ymm3,   96(%0)\n\t"   \
                     "vmovdqu %%ymm4,  128(%0)\n\tvmovdqu %%ymm5,  160(%0)\n\t"   \
                     "vmovdqu %%ymm6,  192(%0)\n\tvmovdqu %%ymm7,  224(%0)\n\t"   \
                     "vmovdqu %%ymm8,  256(%0)\n\tvmovdqu %%ymm9,  288(%0)\n\t"   \
                     "vmovdqu %%ymm10, 320(%0)\n\tvmovdqu %%ymm11, 352(%0)\n\t"   \
                     "vmovdqu %%ymm12, 384(%0)\n\tvmovdqu %%ymm13, 416(%0)\n\t"   \
                     "vmovdqu %%ymm14, 448(%0)\n\tvmovdqu %%ymm15, 480(%0)"       \
                     : : "r"(g_regs) : "memory")
/* The registers AVX-512 adds, which neither VZEROUPPER nor a legacy-SSE
 * epilogue touches. */
#define DUMP_ZMM_HI()                                                             \
    __asm__ volatile("vmovdqu64 %%zmm16,   0(%0)\n\tvmovdqu64 %%zmm17,  64(%0)\n\t" \
                     "vmovdqu64 %%zmm18, 128(%0)\n\tvmovdqu64 %%zmm19, 192(%0)\n\t" \
                     "vmovdqu64 %%zmm20, 256(%0)\n\tvmovdqu64 %%zmm21, 320(%0)\n\t" \
                     "vmovdqu64 %%zmm22, 384(%0)\n\tvmovdqu64 %%zmm23, 448(%0)\n\t" \
                     "vmovdqu64 %%zmm24, 512(%0)\n\tvmovdqu64 %%zmm25, 576(%0)\n\t" \
                     "vmovdqu64 %%zmm26, 640(%0)\n\tvmovdqu64 %%zmm27, 704(%0)\n\t" \
                     "vmovdqu64 %%zmm28, 768(%0)\n\tvmovdqu64 %%zmm29, 832(%0)\n\t" \
                     "vmovdqu64 %%zmm30, 896(%0)\n\tvmovdqu64 %%zmm31, 960(%0)"     \
                     : : "r"(g_hi) : "memory")

/* The call, then the dump as the very next statements. */
#define CALL_THEN_DUMP(rc, call)                \
    do {                                        \
        memset(g_regs, 0, sizeof(g_regs));      \
        memset(g_hi, 0, sizeof(g_hi));          \
        if (g_have_avx512) {                    \
            (rc) = (call);                      \
            DUMP_YMM();                         \
            DUMP_ZMM_HI();                      \
        } else if (g_have_avx) {                \
            (rc) = (call);                      \
            DUMP_YMM();                         \
        } else {                                \
            (rc) = (call);                      \
            DUMP_XMM();                         \
        }                                       \
    } while (0)

/* The control: sixteen bytes of src loaded into %xmm8, then the dump, then
 * %xmm8 cleared again, so that the planted bytes cannot be read back by a
 * later row as the library's residue. */
static void plant_and_dump(const uint8_t *src) {
    memset(g_regs, 0, sizeof(g_regs));
    if (g_have_avx) {
        __asm__ volatile("vmovdqu (%0), %%xmm8" : : "r"(src) : "xmm8");
        DUMP_YMM();
    } else {
        __asm__ volatile("movdqu (%0), %%xmm8" : : "r"(src) : "xmm8");
        DUMP_XMM();
    }
    __asm__ volatile("pxor %%xmm8, %%xmm8" : : : "xmm8");
}
#define PLANTED_SLOT (g_regs + 8 * REG_STRIDE)
#define PLANTED_NAME "%xmm8"

/* The register that holds byte `off` of the dump (`hi`: of g_hi). */
static void slot_name(int hi, size_t off, char *buf, size_t len) {
    if (hi) {
        snprintf(buf, len, "zmm%u", (unsigned)(16 + off / 64));
    } else {
        snprintf(buf, len, "%s%u", g_have_avx ? "ymm" : "xmm", (unsigned)(off / REG_STRIDE));
    }
}

static void detect_registers(void) {
    __builtin_cpu_init();
    g_have_avx = __builtin_cpu_supports("avx");
    g_have_avx512 = __builtin_cpu_supports("avx512f");
    printf("register dump: %s\n", g_have_avx512 ? "ymm0-15, zmm16-31"
                                  : g_have_avx  ? "ymm0-15"
                                                : "xmm0-15");
}

#else /* RESIDUE_AARCH64 */

/* AAPCS64: x0-x18 and all of v0-v31 but the low 64 bits of v8-v15 are the
 * caller's to overwrite, and the full SVE z0-z31 beyond them.  Everything is
 * dumped: x0-x18, q0-q31 whole, and z0-z31 at the vector length where SVE is
 * present.  The base address lives in x19, which is callee-saved: the
 * compiler sets it before the call (or after it, into x19 itself), so no
 * dumped register is written between the return and the stores. */
#define A64_GPR_BYTES 160 /* x0-x18, 8 bytes each, padded to 16 */
#define A64_Z_OFFSET 672 /* A64_GPR_BYTES + 32 * 16: z0-z31 follow q31 */
static struct {
    uint8_t regs[A64_Z_OFFSET];
    uint8_t hi[32 * 256]; /* z0-z31 at up to VL = 2048 bits */
} g_a64;
#define g_regs g_a64.regs
#define g_hi g_a64.hi
static int g_have_sve;

#define A64_DUMP_GPR_Q                                                     \
    "stp x0, x1, [x19, #0]\n\tstp x2, x3, [x19, #16]\n\t"                   \
    "stp x4, x5, [x19, #32]\n\tstp x6, x7, [x19, #48]\n\t"                  \
    "stp x8, x9, [x19, #64]\n\tstp x10, x11, [x19, #80]\n\t"                \
    "stp x12, x13, [x19, #96]\n\tstp x14, x15, [x19, #112]\n\t"             \
    "stp x16, x17, [x19, #128]\n\tstr x18, [x19, #144]\n\t"                 \
    "stp q0, q1, [x19, #160]\n\tstp q2, q3, [x19, #192]\n\t"                \
    "stp q4, q5, [x19, #224]\n\tstp q6, q7, [x19, #256]\n\t"                \
    "stp q8, q9, [x19, #288]\n\tstp q10, q11, [x19, #320]\n\t"              \
    "stp q12, q13, [x19, #352]\n\tstp q14, q15, [x19, #384]\n\t"            \
    "stp q16, q17, [x19, #416]\n\tstp q18, q19, [x19, #448]\n\t"            \
    "stp q20, q21, [x19, #480]\n\tstp q22, q23, [x19, #512]\n\t"            \
    "stp q24, q25, [x19, #544]\n\tstp q26, q27, [x19, #576]\n\t"            \
    "stp q28, q29, [x19, #608]\n\tstp q30, q31, [x19, #640]\n\t"

#if defined(RESIDUE_SVE_DUMP)
#define A64_DUMP_Z                                                         \
    ".arch_extension sve\n\tadd x0, x19, #672\n\t"                                 \
    "str z0, [x0, #0, mul vl]\n\tstr z1, [x0, #1, mul vl]\n\t"              \
    "str z2, [x0, #2, mul vl]\n\tstr z3, [x0, #3, mul vl]\n\t"              \
    "str z4, [x0, #4, mul vl]\n\tstr z5, [x0, #5, mul vl]\n\t"              \
    "str z6, [x0, #6, mul vl]\n\tstr z7, [x0, #7, mul vl]\n\t"              \
    "str z8, [x0, #8, mul vl]\n\tstr z9, [x0, #9, mul vl]\n\t"              \
    "str z10, [x0, #10, mul vl]\n\tstr z11, [x0, #11, mul vl]\n\t"          \
    "str z12, [x0, #12, mul vl]\n\tstr z13, [x0, #13, mul vl]\n\t"          \
    "str z14, [x0, #14, mul vl]\n\tstr z15, [x0, #15, mul vl]\n\t"          \
    "str z16, [x0, #16, mul vl]\n\tstr z17, [x0, #17, mul vl]\n\t"          \
    "str z18, [x0, #18, mul vl]\n\tstr z19, [x0, #19, mul vl]\n\t"          \
    "str z20, [x0, #20, mul vl]\n\tstr z21, [x0, #21, mul vl]\n\t"          \
    "str z22, [x0, #22, mul vl]\n\tstr z23, [x0, #23, mul vl]\n\t"          \
    "str z24, [x0, #24, mul vl]\n\tstr z25, [x0, #25, mul vl]\n\t"          \
    "str z26, [x0, #26, mul vl]\n\tstr z27, [x0, #27, mul vl]\n\t"          \
    "str z28, [x0, #28, mul vl]\n\tstr z29, [x0, #29, mul vl]\n\t"          \
    "str z30, [x0, #30, mul vl]\n\tstr z31, [x0, #31, mul vl]\n\t"          \
    ".arch_extension nosve"

/* The call, then the dump as the very next instructions. */
#define CALL_THEN_DUMP(rc, call)                                                   \
    do {                                                                           \
        memset(g_regs, 0, sizeof(g_regs));                                         \
        memset(g_hi, 0, sizeof(g_hi));                                             \
        if (g_have_sve) {                                                          \
            register uint8_t *a64_base_ __asm__("x19") = g_regs;                   \
            (rc) = (call);                                                         \
            __asm__ volatile(A64_DUMP_GPR_Q A64_DUMP_Z                             \
                             : : "r"(a64_base_) : "x0", "memory");                 \
        } else {                                                                   \
            register uint8_t *a64_base_ __asm__("x19") = g_regs;                   \
            (rc) = (call);                                                         \
            __asm__ volatile(A64_DUMP_GPR_Q : : "r"(a64_base_) : "memory");        \
        }                                                                          \
    } while (0)
#else
#define CALL_THEN_DUMP(rc, call)                                                   \
    do {                                                                           \
        register uint8_t *a64_base_ __asm__("x19") = g_regs;                       \
        memset(g_regs, 0, sizeof(g_regs));                                         \
        (rc) = (call);                                                             \
        __asm__ volatile(A64_DUMP_GPR_Q : : "r"(a64_base_) : "memory");            \
    } while (0)
#endif /* RESIDUE_SVE_DUMP */

_Static_assert(sizeof(g_a64.regs) == A64_GPR_BYTES + 32 * 16, "q31 ends where z0 begins");

/* The control: sixteen bytes of src loaded into v8, then the dump, then v8
 * cleared in the same statement.  The low half of v8 is callee-saved, so
 * every later library call would preserve the planted bytes, and a later row
 * would read them as residue (measured under clang 18, which inlined this
 * into main: the AEAD plaintext rows reported plaintext word 0 in q8). */
static void plant_and_dump(const uint8_t *src) {
    register uint8_t *a64_base_ __asm__("x19") = g_regs;
    memset(g_regs, 0, sizeof(g_regs));
    memset(g_hi, 0, sizeof(g_hi));
    __asm__ volatile("ldr q8, [%1]\n\t" A64_DUMP_GPR_Q "movi v8.16b, #0"
                     : : "r"(a64_base_), "r"(src) : "v8", "memory");
}
#define PLANTED_SLOT (g_regs + A64_GPR_BYTES + 8 * 16)
#define PLANTED_NAME "v8"

static size_t g_sve_vl; /* bytes per z register */

/* The register that holds byte `off` of the dump (`hi`: of g_hi). */
static void slot_name(int hi, size_t off, char *buf, size_t len) {
    if (hi) {
        snprintf(buf, len, "z%u", (unsigned)(g_sve_vl ? off / g_sve_vl : 0));
    } else if (off < A64_GPR_BYTES) {
        snprintf(buf, len, "x%u", (unsigned)(off / 8));
    } else {
        snprintf(buf, len, "q%u", (unsigned)((off - A64_GPR_BYTES) / 16));
    }
}

static void detect_registers(void) {
#if defined(RESIDUE_SVE_DUMP)
    g_have_sve = (getauxval(AT_HWCAP) & HWCAP_SVE) != 0;
    if (g_have_sve) {
        uint64_t vl;
        __asm__ volatile(".arch_extension sve\n\trdvl %0, #1\n\t.arch_extension nosve"
                         : "=r"(vl));
        g_sve_vl = (size_t)vl;
        if (g_sve_vl == 0 || g_sve_vl > 256) {
            printf("FAIL SVE vector length %zu bytes is outside the dump\n", g_sve_vl);
            g_have_sve = 0;
            g_sve_vl = 0;
            g_failures++;
        }
    }
#endif
    printf("register dump: x0-x18, q0-q31%s", g_have_sve ? ", z0-z31" : "");
    if (g_have_sve) {
        printf(" (VL %zu bytes)", g_sve_vl);
    }
    printf("\n");
}

#endif /* RESIDUE_AARCH64 */

static int count_in(const uint8_t *dump, size_t dump_len, const uint8_t *s, size_t len) {
    int hits = 0;
    for (size_t w = 0; w + 8 <= len; w += 8) {
        for (size_t off = 0; off + 8 <= dump_len; off++) {
            if (memcmp(dump + off, s + w, 8) == 0) {
                hits++;
            }
        }
    }
    return hits;
}

/* Occurrences of any 8-byte word of s[0..len) at any offset of the dump. */
static int words_in_dump(const uint8_t *s, size_t len) {
    return count_in(g_regs, sizeof(g_regs), s, len) + count_in(g_hi, sizeof(g_hi), s, len);
}

/* Which registers hold a word of s, for the log. */
static void where(const uint8_t *s, size_t len) {
    char reg[16];
    for (int hi = 0; hi < 2; hi++) {
        const uint8_t *dump = hi ? g_hi : g_regs;
        size_t dump_len = hi ? sizeof(g_hi) : sizeof(g_regs);
        for (size_t w = 0; w + 8 <= len; w += 8) {
            for (size_t off = 0; off + 8 <= dump_len; off++) {
                if (memcmp(dump + off, s + w, 8) == 0) {
                    slot_name(hi, off, reg, sizeof(reg));
                    printf("       word %zu in %s\n", w / 8, reg);
                }
            }
        }
    }
}

static void verdict(const char *name, int rc, const uint8_t *s, size_t len) {
    int hits = words_in_dump(s, len);
    if (rc != AMA_SUCCESS) {
        printf("FAIL %-40s rc=%d\n", name, rc);
        g_failures++;
    } else if (hits != 0) {
        printf("FAIL %-40s %d secret word(s) left in registers\n", name, hits);
        where(s, len);
        g_failures++;
    } else {
        printf("ok   %-40s 0 secret words in registers\n", name);
    }
}

static const uint8_t g_key[32] = {
    0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x83, 0x94, 0xa5,
    0xb6, 0xc7, 0xd8, 0xe9, 0xfa, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
    0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0};
static const uint8_t g_salt[12] = {'s', 'a', 'l', 't', 's', 'a', 'l', 't', 's', 'a', 'l', 't'};
static const uint8_t g_info[7] = {'r', 'e', 's', 'i', 'd', 'u', 'e'};
static const uint8_t g_nonce[16] = {7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8};
static uint8_t g_pt[64], g_ct[64], g_tag[16], g_out[64];
#if defined(AMA_REGISTER_RESIDUE_PQC_GROUP)
static uint8_t g_pk1[32], g_sk1[32], g_pk2[32], g_sk2[32], g_ss[32];
static uint8_t g_kem_pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
static uint8_t g_kem_sk[AMA_KYBER_1024_SECRET_KEY_BYTES];
static uint8_t g_kem_ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
static uint8_t g_kem_ss[AMA_KYBER_1024_SHARED_SECRET_BYTES];
/* FIPS 203 dk = dk_PKE || ek || H(ek) || z: the secret parts are the first
 * 1536 bytes and the last 32. */
#define KEM_DK_PKE_BYTES 1536u
#define KEM_Z_OFFSET (AMA_KYBER_1024_SECRET_KEY_BYTES - 32u)
#endif

/* --- dead stack: the X25519 shared secret and the HKDF-SHA3-256 output. */

#if defined(AMA_REGISTER_RESIDUE_PQC_GROUP)
RESIDUE_NOINLINE static ama_error_t probe_x25519_key_exchange(void) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_x25519_key_exchange(g_ss, g_sk1, g_pk2));
    return rc;
}
#endif

RESIDUE_NOINLINE static ama_error_t probe_hkdf(void) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_hkdf(g_salt, 1, g_key, sizeof(g_key), g_info, sizeof(g_info), g_out, 32));
    return rc;
}

static void stack_verdict(const char *name, ama_error_t (*probe)(void), const uint8_t *secret,
                          size_t len) {
    uint8_t needle[32];
    ama_error_t rc;
    int hits;
    memcpy(needle, secret, len); /* the output of an identical earlier call */
    poison_stack();
    rc = probe();
    hits = residue_count(needle, len);
    if (rc != AMA_SUCCESS || hits != 0 || memcmp(needle, secret, len) != 0) {
        printf("FAIL %-40s rc=%d, %d copy(ies) in its dead stack\n", name, (int)rc, hits);
        g_failures++;
    } else {
        printf("ok   %-40s 0 copies in its dead stack\n", name);
    }
}

int main(void) {
    int rc;
    uint8_t sentinel[32];

    detect_registers();
    for (size_t i = 0; i < sizeof(g_pt); i++) {
        g_pt[i] = (uint8_t)(0x3cu ^ (i * 41u));
    }

    /* CONTROL (registers): sixteen bytes the harness loads into %xmm8 (v8 on
     * AArch64) are in that register's slot and are counted (the scan may
     * count more: the compiler is free to have built the array in another
     * register as well). */
    plant_and_dump(g_pt);
    if (memcmp(PLANTED_SLOT, g_pt, 16) != 0 || words_in_dump(g_pt, 16) < 2) {
        printf("FAIL control: the dump did not see a planted %s\n", PLANTED_NAME);
        return 1;
    }
    printf("ok   control: a planted %s is seen\n", PLANTED_NAME);

    /* CONTROL (stack): a sentinel left in a frame at the probed depth is
     * seen, and the window reads what the poison wrote. */
    for (size_t i = 0; i < sizeof(sentinel); i++) {
        sentinel[i] = (uint8_t)(0xA7u ^ (i * 13u + 3u));
    }
    poison_stack();
    residue_probe_control(sentinel, sizeof(sentinel));
    if (residue_count(sentinel, sizeof(sentinel)) <= 0 || !residue_window_covers_poison()) {
        printf("FAIL control: the stack probe did not see its sentinel\n");
        return 1;
    }
    printf("ok   control: a sentinel left on the stack is seen\n");

#if defined(AMA_REGISTER_RESIDUE_PQC_GROUP)
    if (ama_x25519_keypair(g_pk1, g_sk1) != AMA_SUCCESS ||
        ama_x25519_keypair(g_pk2, g_sk2) != AMA_SUCCESS) {
        printf("FAIL x25519 keypairs\n");
        return 1;
    }
#endif

    /* --- SHA-3 family: the row CI named, and what it is built from. */
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_hkdf(g_salt, 1, g_key, sizeof(g_key), g_info, sizeof(g_info),
                                g_out, 32));
    verdict("ama_hkdf (32)", rc, g_out, 32);
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_hkdf(g_salt, 1, g_key, sizeof(g_key), g_info, sizeof(g_info),
                                g_out, 64));
    verdict("ama_hkdf (64)", rc, g_out, 64);
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_hmac_sha3_256(g_key, sizeof(g_key), g_info, sizeof(g_info), g_out));
    verdict("ama_hmac_sha3_256", rc, g_out, 32);
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_sha3_256(g_key, sizeof(g_key), g_out));
    verdict("ama_sha3_256", rc, g_out, 32);
    {
        ama_sha3_ctx ctx;
        if (ama_sha3_init(&ctx) != AMA_SUCCESS ||
            ama_sha3_update(&ctx, g_key, sizeof(g_key)) != AMA_SUCCESS) {
            printf("FAIL ama_sha3_init/update\n");
            return 1;
        }
        memset(g_out, 0, sizeof(g_out));
        CALL_THEN_DUMP(rc, ama_sha3_final(&ctx, g_out));
        verdict("ama_sha3_final", rc, g_out, 32);
    }

#if defined(AMA_REGISTER_RESIDUE_PQC_GROUP)
    /* --- key agreement and key generation. */
    memset(g_ss, 0, sizeof(g_ss));
    CALL_THEN_DUMP(rc, ama_x25519_key_exchange(g_ss, g_sk1, g_pk2));
    verdict("ama_x25519_key_exchange", rc, g_ss, 32);
    CALL_THEN_DUMP(rc, ama_x25519_keypair(g_pk1, g_sk1));
    verdict("ama_x25519_keypair (secret key)", rc, g_sk1, 32);
    memset(g_ss, 0, sizeof(g_ss));
    if (ama_x25519_key_exchange(g_ss, g_sk1, g_pk2) != AMA_SUCCESS) {
        printf("FAIL x25519 key exchange\n");
        return 1;
    }

    /* --- ML-KEM-1024: the shared secret (SHA-3 kernels) and the secret key
     * (NTT kernels on the secret vector). */
    {
        size_t ct_len = sizeof(g_kem_ct);
        uint8_t ss_enc[AMA_KYBER_1024_SHARED_SECRET_BYTES];
        CALL_THEN_DUMP(rc, ama_kyber_keypair(g_kem_pk, sizeof(g_kem_pk), g_kem_sk,
                                             sizeof(g_kem_sk)));
        verdict("ama_kyber_keypair (dk_PKE)", rc, g_kem_sk, KEM_DK_PKE_BYTES);
        verdict("ama_kyber_keypair (z)", rc, g_kem_sk + KEM_Z_OFFSET, 32);
        CALL_THEN_DUMP(rc, ama_kyber_encapsulate(g_kem_pk, sizeof(g_kem_pk), g_kem_ct, &ct_len,
                                                 ss_enc, sizeof(ss_enc)));
        verdict("ama_kyber_encapsulate (shared secret)", rc, ss_enc, sizeof(ss_enc));
        memset(g_kem_ss, 0, sizeof(g_kem_ss));
        CALL_THEN_DUMP(rc, ama_kyber_decapsulate(g_kem_ct, ct_len, g_kem_sk, sizeof(g_kem_sk),
                                                 g_kem_ss, sizeof(g_kem_ss)));
        verdict("ama_kyber_decapsulate (shared secret)", rc, g_kem_ss, sizeof(g_kem_ss));
        if (memcmp(ss_enc, g_kem_ss, sizeof(ss_enc)) != 0) {
            printf("FAIL ML-KEM shared secrets differ\n");
            g_failures++;
        }
    }
#endif

    /* --- the other KDFs. */
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_hkdf_sha256(g_salt, 1, g_key, sizeof(g_key), g_info,
                                       sizeof(g_info), g_out, 32));
    verdict("ama_hkdf_sha256", rc, g_out, 32);
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_pbkdf2_hmac_sha512(g_key, 13, g_salt, 8, 2, g_out, 64));
    verdict("ama_pbkdf2_hmac_sha512", rc, g_out, 64);
    memset(g_out, 0, sizeof(g_out));
#if defined(AMA_REGISTER_RESIDUE_PQC_GROUP)
    CALL_THEN_DUMP(rc, ama_argon2id(g_key, 13, g_salt, sizeof(g_salt), 1, 64, 1, g_out, 32));
    verdict("ama_argon2id", rc, g_out, 32);
#endif

    /* --- AEAD decryption: the plaintext, and the key. */
    if (ama_aes256_gcm_encrypt(g_key, g_nonce, g_pt, sizeof(g_pt), NULL, 0, g_ct, g_tag) !=
        AMA_SUCCESS) {
        printf("FAIL ama_aes256_gcm_encrypt\n");
        return 1;
    }
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_aes256_gcm_decrypt(g_key, g_nonce, g_ct, sizeof(g_ct), NULL, 0,
                                              g_tag, g_out));
    verdict("ama_aes256_gcm_decrypt (plaintext)", rc, g_out, sizeof(g_pt));
    verdict("ama_aes256_gcm_decrypt (key)", rc, g_key, sizeof(g_key));
#if defined(AMA_REGISTER_RESIDUE_PQC_GROUP)
    if (ama_chacha20poly1305_encrypt(g_key, g_nonce, g_pt, sizeof(g_pt), NULL, 0, g_ct,
                                     g_tag) != AMA_SUCCESS) {
        printf("FAIL ama_chacha20poly1305_encrypt\n");
        return 1;
    }
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_chacha20poly1305_decrypt(g_key, g_nonce, g_ct, sizeof(g_ct), NULL,
                                                    0, g_tag, g_out));
    verdict("ama_chacha20poly1305_decrypt (plaintext)", rc, g_out, sizeof(g_pt));
    verdict("ama_chacha20poly1305_decrypt (key)", rc, g_key, sizeof(g_key));
#endif
    if (ama_ascon_aead128_encrypt(g_key, g_nonce, g_pt, sizeof(g_pt), NULL, 0, g_ct, g_tag) !=
        AMA_SUCCESS) {
        printf("FAIL ama_ascon_aead128_encrypt\n");
        return 1;
    }
    memset(g_out, 0, sizeof(g_out));
    CALL_THEN_DUMP(rc, ama_ascon_aead128_decrypt(g_key, g_nonce, g_ct, sizeof(g_ct), NULL, 0,
                                                 g_tag, g_out));
    verdict("ama_ascon_aead128_decrypt (plaintext)", rc, g_out, sizeof(g_pt));
    verdict("ama_ascon_aead128_decrypt (key)", rc, g_key, 16);

    /* --- dead stack. */
    memset(g_out, 0, sizeof(g_out));
    if (ama_hkdf(g_salt, 1, g_key, sizeof(g_key), g_info, sizeof(g_info), g_out, 32) !=
        AMA_SUCCESS) {
        printf("FAIL ama_hkdf\n");
        return 1;
    }
#if defined(AMA_REGISTER_RESIDUE_PQC_GROUP)
    stack_verdict("ama_x25519_key_exchange (dead stack)", probe_x25519_key_exchange, g_ss, 32);
#endif
    stack_verdict("ama_hkdf (dead stack)", probe_hkdf, g_out, 32);

    memset(g_regs, 0, sizeof(g_regs));
    memset(g_hi, 0, sizeof(g_hi));
    if (g_failures) {
        printf("%d verdict(s) failed\n", g_failures);
        return 1;
    }
    return 0;
}
#endif
