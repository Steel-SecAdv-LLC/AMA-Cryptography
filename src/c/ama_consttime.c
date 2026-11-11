/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_consttime.c
 * @brief Constant-time cryptographic operations
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * Timing-attack resistant implementations of critical cryptographic primitives.
 * All operations execute in constant time regardless of input values.
 */

#include "internal/ama_string_ops.h"  /* first: no vector register holds what memcpy/memset move */
#include "../include/ama_cryptography.h"
#include "internal/ama_testing_exports.h"
#include "internal/ama_stack_wipe.h"
#include "internal/ama_ct_barrier.h"
#include <string.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h>
#endif

/**
 * Constant-time memory comparison
 *
 * Compares two memory regions in constant time to prevent timing attacks.
 * Uses bitwise OR to accumulate differences without branching.
 *
 * @param a First buffer
 * @param b Second buffer
 * @param len Number of bytes to compare
 * @return 0 if equal, 1 if different (constant time)
 */
int ama_consttime_memcmp(const void* a, const void* b, size_t len) {
    const volatile uint8_t* va = (const volatile uint8_t*)a;
    const volatile uint8_t* vb = (const volatile uint8_t*)b;
    uint8_t diff = 0;
    size_t i;

    /* Accumulate differences without branching */
    for (i = 0; i < len; i++) {
        diff |= va[i] ^ vb[i];
    }

    /* Convert any non-zero to 1.  Stay in unsigned arithmetic the whole
     * way: right-shifting a negative signed value is implementation-
     * defined under C11 §6.5.7p5, which the original `(diff | -diff)
     * >> 7` form triggered after the usual integer promotion of diff
     * to int.  Two's-complement negation of an unsigned value is
     * ~x + 1; the result is 0 only when diff == 0, otherwise bit 7
     * (or higher) is set, so the >> 7 mask yields {0, 1}. */
    uint32_t d = diff;
    return (int)(((d | (~d + 1u)) >> 7) & 1u);
}

/**
 * Secure memory zeroing
 *
 * Scrubs memory to zero in a way that cannot be optimized away by the compiler:
 * every store goes through a volatile pointer, and a compiler barrier follows.
 *
 * Whole 64-bit words are stored when the buffer is 8-byte aligned, which every
 * caller's field element, hash state and key buffer is, then the byte tail.
 * The previous byte-at-a-time loop was correct but cost three instructions per
 * byte, and the callers scrub a lot: one SHA-512 compression scrubs its
 * 640-byte message schedule, so the loop was 40% of every hashed block and a
 * tenth of an Ed25519 signature.  A memset-plus-barrier rendering was measured
 * too and rejected: the X25519 ladder's dozen small scrubs became library
 * calls and its exchange slowed by 2-3%, while the word loop stays inline.
 *
 * @param ptr Memory to zero
 * @param len Number of bytes to zero
 */
/**
 * @brief Zero the stack the last call left behind (INVARIANT-6, dead frames).
 *
 * `ama_secure_memzero` scrubs the buffers a function NAMES.  It cannot reach
 * the copies an optimizing compiler makes of them.  Measured on the shipped
 * build (gcc 13 -O3, LTO): the AES-GCM AES-NI and VAES kernels expand the key
 * into a local `rk[15]`, scrub that array at exit as the source says — and
 * gcc has already hoisted the loop-invariant round keys into separate stack
 * slots that the AES rounds use as memory operands (`aesenc 0x10(%rsp)` …)
 * and that nothing scrubs.  A residue probe found all fifteen round keys
 * after every encrypt and decrypt, `rk[0]` and `rk[1]` among them — and for
 * AES-256 those two ARE the raw 32-byte key.  ChaCha20-Poly1305 left its key
 * likewise (that one was also a missing scrub, fixed at source).
 *
 * The compiler's copies have no names, so the only way to reach them is by
 * address: AMA_STACK_WIPE_BELOW() (internal/ama_stack_wipe.h, which says who
 * uses it and why from there) lays a frame over the region a just-returned
 * callee used and zeroes it.  Used right after the primitive returns, the
 * frame lands exactly where the primitive's frames were.
 *
 * `AMA_STACK_WIPE_BYTES` (4096), the depth of the exported
 * ama_secure_stack_wipe(), comfortably covers the deepest AEAD kernel frame
 * measured here (0x680 = 1664 bytes); the residue probe found nothing below
 * 2,167 bytes of the caller's own anchor.  The library's own entry points
 * each clear the depth measured for their family.
 *
 * NOTHING OF ITS OWN.  The wipe must leave nothing below what it clears, in
 * any build: tests/c/test_stack_scrub.c requires every byte under an entry
 * point's frame to be zero or never written, and a reader of that stack
 * cannot tell the routine's bookkeeping from a primitive's residue.  The form
 * this replaces was one helper holding `memset` and a barrier, called by
 * frame functions that took the depth as a parameter.  Measured 2026-11-10:
 * optimised, it left nothing; unoptimised, the helper was a real call and its
 * return address, frame pointer and three arguments stayed below the array
 * (36 non-zero bytes, gcc 13.3 -O0; 60, clang 18.1 -O0), and on AArch64 each
 * frame function homed its parameter under the array as well.  So a frame
 * function now takes no parameter, names no scalar, and makes no call:
 *   - x86-64 and AArch64, GNU C: the array is zeroed by inline assembly that
 *     touches call-clobbered registers and the array, and nothing else --
 *     `rep stosq` on x86-64, sixty-four bytes of `stp xzr, xzr` a turn on
 *     AArch64.  An asm statement that clobbers "memory" is never deleted,
 *     and taking the array's address as its operand keeps the frame
 *     allocated.
 *   - any other GNU C target: `memset` and an empty asm that takes the
 *     array's address and clobbers memory, so the compiler must assume the
 *     array is read.  Nothing measures such a build (the stack tests run on
 *     x86-64 and AArch64), and an unoptimised one leaves the helper's frame.
 *   - MSVC (x64 and ARM64 have no inline asm): until 2026-09-24 this branch
 *     was `memset` followed by `_ReadWriteBarrier()`.  That intrinsic orders
 *     memory accesses across the point of the call; it does not make the
 *     array's address escape, so nothing in it obliges the optimiser to keep
 *     a store to an array no one can read.  (clang in MSVC mode happens to
 *     keep it; cl.exe's behaviour is not documented and could not be measured
 *     here.)  The write goes through a `volatile` pointer to `memset`:
 *     reading a volatile object is an observable side effect whose value the
 *     compiler cannot know, so it cannot know which function it is calling,
 *     and an unknown callee handed `frame`'s address may read it.  This is
 *     the construction OpenSSL's OPENSSL_cleanse uses for the same reason,
 *     and it keeps `memset`'s wide-store path.
 * A wide store, in every branch: the volatile word loop `ama_secure_memzero`
 * uses was measured at 90-127 ns for the exported 4 KiB wipe against 29 ns
 * for `memset` and a barrier, on a 16-byte AEAD call the difference between
 * +50% and +17%.
 *
 * This is a backstop, not a substitute for scrubbing named buffers.
 */
_Static_assert(AMA_SCRUB_EXPORTED_WIPE_BYTES == AMA_STACK_WIPE_BYTES,
               "the pasteable depth of ama_secure_stack_wipe() is the public one");

#if defined(_MSC_VER)
static void *(*const volatile ama_stack_wipe_memset)(void *, int, size_t) = memset;
/* Opaque callee (see above): the call and the frame it is handed are both
 * live by construction. */
#define AMA_STACK_WIPE_ZERO(frame) (void)ama_stack_wipe_memset((frame), 0, sizeof(frame))
#elif defined(__x86_64__) && !defined(__ILP32__)
/* Under the System V ABI %rdi, %rcx and %rax are call-clobbered and named as
 * clobbers, so neither operand is given one of them and nothing is saved to
 * make room.  The Windows x64 convention keeps %rdi across a call, so a GNU
 * compiler targeting it pushes the caller's %rdi first (measured, MinGW gcc
 * 13.2: `push %rdi` directly under the return address); the cap, which runs
 * after, clears that word with the rest.  The direction flag is clear at
 * every function boundary under both conventions. */
#define AMA_STACK_WIPE_ZERO(frame)                                                \
    __asm__ __volatile__("mov %0, %%rdi\n\tmov %1, %%rcx\n\txor %%eax, %%eax\n\t" \
                         "rep stosq"                                              \
                         :                                                        \
                         : "r"((void *)(frame)), "r"((size_t)(sizeof(frame) / 8u)) \
                         : "rdi", "rcx", "rax", "cc", "memory")
#elif defined(__aarch64__) && !defined(__ILP32__)
/* x9 and x10 are call-clobbered temporaries on AAPCS64 and on Darwin. */
#define AMA_STACK_WIPE_ZERO(frame)                                             \
    __asm__ __volatile__("mov x9, %0\n\tmov x10, %1\n"                         \
                         "1:\tstp xzr, xzr, [x9]\n\tstp xzr, xzr, [x9, #16]\n" \
                         "\tstp xzr, xzr, [x9, #32]\n\tstp xzr, xzr, [x9, #48]\n" \
                         "\tadd x9, x9, #64\n\tsubs x10, x10, #64\n\tb.ne 1b" \
                         :                                                     \
                         : "r"((void *)(frame)), "r"((size_t)sizeof(frame))    \
                         : "x9", "x10", "cc", "memory")
#else
static inline void ama_stack_wipe_zero(unsigned char *frame, size_t size) {
    memset(frame, 0, size);  // SCRUB-BARRIER: frame — dead stack, possibly secret; the barrier below makes the write non-elidable, and memset keeps the wide-store path
    /* Make the write observable so it survives dead-store elimination, and
     * keep the array's address escaping so the frame is really allocated. */
    __asm__ __volatile__("" : : "r"(frame) : "memory");
}
#define AMA_STACK_WIPE_ZERO(frame) ama_stack_wipe_zero((frame), sizeof(frame))
#endif

/* One function per depth, its frame exactly as large as what it clears.
 *
 * Exactly, because a frame larger than the request reserves, and under
 * -fstack-clash-protection touches, stack the primitive itself never
 * needed.  One frame, not a chain of smaller ones, because every frame
 * begins with bytes its own function does not write: the padding beside the
 * return address and the stack protector's canary (measured, gcc 13.3
 * x86-64: `[ret][8 unwritten][canary][8 unwritten][array]`).  In a chain
 * those bytes recur at every link, deep inside the region being cleared,
 * holding whatever the primitive left there.  Every size is a multiple of
 * sixty-four, which is what the AArch64 loop counts in. */
#define AMA_STACK_WIPE_FRAME(BYTES)                              \
    AMA_SCRUBBED_BODY void ama_stack_wipe_frame_##BYTES(void) { \
        unsigned char frame[BYTES];                              \
        _Static_assert((BYTES) % 64 == 0, "a whole number of 64-byte turns"); \
        AMA_STACK_WIPE_ZERO(frame);                              \
    }

AMA_STACK_WIPE_FRAME(1024)
AMA_STACK_WIPE_FRAME(2048)
AMA_STACK_WIPE_FRAME(4096)
AMA_STACK_WIPE_FRAME(8192)
AMA_STACK_WIPE_FRAME(16384)
AMA_STACK_WIPE_FRAME(24576)
AMA_STACK_WIPE_FRAME(45056)
AMA_STACK_WIPE_FRAME(49152)
AMA_STACK_WIPE_FRAME(77824)
AMA_STACK_WIPE_FRAME(176128)
AMA_STACK_WIPE_FRAME(196608)

/* The bytes directly below the calling frame, cleared last.
 *
 * AMA_STACK_WIPE_BELOW() calls a frame function and then this.  The frame
 * function zeroes its array and nothing else in its frame, so what it leaves
 * at the top is its own: the padding beside its return address, which it
 * never wrote and which therefore still holds what the primitive left there,
 * and its stack-protector canary.  This function lies over those and writes
 * all of them.  It ran first until the Windows build was measured
 * (2026-11-10, below): first, it cannot clear what the frame function's own
 * prologue puts there afterwards.
 *
 * Scalars, not an array: an array is what makes -fstack-protector-strong add
 * a canary and its padding.  A function with no array has none, and its
 * scalars are laid out from its own return address down with nothing between
 * them.  Measured, gcc 13.3, gcc 14.2 and clang 18.1, optimised and not: on
 * x86-64 under the System V ABI thirteen 8-byte slots from -8(%rsp) to
 * -104(%rsp); on AArch64, which pushes no return address, thirteen slots
 * ending at the caller's stack pointer, the alignment word left at the low
 * end.  Thirteen, an odd count, is what puts that word at the low end on
 * both.
 *
 * WINDOWS x64 is a different function, for two things its convention does
 * that the others do not.  Measured 2026-11-10 on the MinGW build (gcc 13.2,
 * run under Wine 9.0), with the C function above and the cap first: 29 of
 * the 132 verdicts of tests/c/test_stack_scrub.c failed with up to eight
 * input-dependent bytes, and ama_secure_stack_wipe() left 32 bytes of its own
 * frame unwritten.
 *   - A frame of a page or more is probed by ___chkstk_ms before it is
 *     allocated, and that helper pushes %rcx and %rax.  %rcx is
 *     call-clobbered: it holds whatever the primitive last computed in it.
 *     The push lands in the frame function's padding, after a cap that ran
 *     first had zeroed it.
 *   - A caller reserves 32 bytes above every return address, the home area,
 *     which belongs to the callee.  The primitive may have written there, it
 *     is inside the frame that is clearing its stack, and no frame laid below
 *     that one reaches it.  A callee may write it, so this one does.
 * With a GNU compiler the function is assembly, so that its layout is not a
 * compiler's choice: it calls nothing and moves no stack pointer, and
 * writes the home area and the fifteen words under its own return address.
 * (The convention keeps no red zone, so those words may be overwritten at any
 * time; they are being cleared, not kept.)  Three of the fifteen reach all
 * the frame function leaves on this build, its saved %rdi, its canary and
 * the probe's %rcx; the rest are margin for a toolchain that lays its frame
 * out differently, and no test tells twelve from none.  MSVC has no inline
 * assembly on x64: there it is the scalars in C, fifteen of them, and the
 * home area through _AddressOfReturnAddress().  Nothing measures that build;
 * the stack tests need GNU C.
 */
#if defined(_WIN64) && defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#if defined(__CET__)
#define AMA_STACK_WIPE_CAP_ENDBR "\tendbr64\n"
#else
#define AMA_STACK_WIPE_CAP_ENDBR ""
#endif
__asm__("\t.text\n"
        "\t.p2align 4\n"
        "\t.globl\tama_stack_wipe_cap\n"
        "\t.def\tama_stack_wipe_cap;\t.scl\t2;\t.type\t32;\t.endef\n"
        "ama_stack_wipe_cap:\n"
        AMA_STACK_WIPE_CAP_ENDBR
        "\txorl\t%eax, %eax\n"
        "\tmovq\t%rax, 8(%rsp)\n"
        "\tmovq\t%rax, 16(%rsp)\n"
        "\tmovq\t%rax, 24(%rsp)\n"
        "\tmovq\t%rax, 32(%rsp)\n"
        "\tmovq\t%rax, -8(%rsp)\n"
        "\tmovq\t%rax, -16(%rsp)\n"
        "\tmovq\t%rax, -24(%rsp)\n"
        "\tmovq\t%rax, -32(%rsp)\n"
        "\tmovq\t%rax, -40(%rsp)\n"
        "\tmovq\t%rax, -48(%rsp)\n"
        "\tmovq\t%rax, -56(%rsp)\n"
        "\tmovq\t%rax, -64(%rsp)\n"
        "\tmovq\t%rax, -72(%rsp)\n"
        "\tmovq\t%rax, -80(%rsp)\n"
        "\tmovq\t%rax, -88(%rsp)\n"
        "\tmovq\t%rax, -96(%rsp)\n"
        "\tmovq\t%rax, -104(%rsp)\n"
        "\tmovq\t%rax, -112(%rsp)\n"
        "\tmovq\t%rax, -120(%rsp)\n"
        "\tret\n");
#elif defined(_MSC_VER) && defined(_M_X64)
#include <intrin.h>
AMA_SCRUBBED_BODY void ama_stack_wipe_cap(void) {
    volatile uint64_t w0 = 0, w1 = 0, w2 = 0, w3 = 0, w4 = 0, w5 = 0, w6 = 0, w7 = 0;
    volatile uint64_t w8 = 0, w9 = 0, w10 = 0, w11 = 0, w12 = 0, w13 = 0, w14 = 0;
    volatile uint64_t *home = (volatile uint64_t *)_AddressOfReturnAddress() + 1;
    home[0] = 0;
    home[1] = 0;
    home[2] = 0;
    home[3] = 0;
    (void)w0; (void)w1; (void)w2; (void)w3; (void)w4; (void)w5; (void)w6; (void)w7;
    (void)w8; (void)w9; (void)w10; (void)w11; (void)w12; (void)w13; (void)w14;
}
#else
AMA_SCRUBBED_BODY void ama_stack_wipe_cap(void) {
    volatile uint64_t w0 = 0, w1 = 0, w2 = 0, w3 = 0, w4 = 0, w5 = 0, w6 = 0;
    volatile uint64_t w7 = 0, w8 = 0, w9 = 0, w10 = 0, w11 = 0, w12 = 0;
    (void)w0; (void)w1; (void)w2; (void)w3; (void)w4; (void)w5; (void)w6;
    (void)w7; (void)w8; (void)w9; (void)w10; (void)w11; (void)w12;
}
#endif

AMA_API void ama_secure_stack_wipe(void) {
    /* This function's own frame lies between the caller and what is cleared,
     * where the first words of the caller's last callee were, so every byte
     * of it must be one this function writes.  It keeps no local.  What is
     * left is the return address and one more word: padding that realigns
     * the stack for the calls below, which nobody writes, or, in a function
     * that keeps a frame pointer, the saved frame pointer, which the prologue
     * does.  Taking the frame address is what makes gcc and clang keep one
     * here in every build.  Measured 2026-11-10 without it:
     *   - x86-64, on the form this replaces (a named `volatile` word in the
     *     padding's place): right when optimised ([ret][word]), eight
     *     unwritten bytes when not ([ret][rbp][word][padding], gcc 13.3 and
     *     clang 18.1 with no -O);
     *   - AArch64 under -fomit-frame-pointer, which the Release build sets:
     *     `str x30, [sp, #-16]!` and nothing else, the link register in a
     *     sixteen-byte slot whose other half is never written (gcc 13.3 and
     *     clang 18.1, -O0 to -O3 and -Os).  This comment said AArch64 saves a
     *     frame record in any function that calls and has no such word; that
     *     is true only of a build that keeps frame pointers.
     * tests/c/test_stack_wipe_coverage.c holds every build it runs in to
     * this, and failed the AArch64 Release build until the frame address was
     * taken there too.  Nothing measures MSVC, which keeps the named word. */
#if (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(__aarch64__))
    __asm__ __volatile__("" : : "r"(__builtin_frame_address(0)));
#elif defined(_M_X64)
    volatile uint64_t own = 0;
    (void)own;
#endif
    AMA_STACK_WIPE_BELOW(AMA_SCRUB_EXPORTED_WIPE_BYTES);
}

void ama_secure_memzero(void* ptr, size_t len) {
    volatile uint8_t* vptr = (volatile uint8_t*)ptr;
    size_t i = 0;

    if (((uintptr_t)ptr & 7u) == 0) {
        /* Type-puns the aligned buffer as volatile 64-bit words to scrub eight
         * bytes per store.  Formally a strict-aliasing deviation, but benign:
         * the stores are volatile (never elided or reordered away) and the
         * object is dead after this call.  The branch is on the public pointer
         * alignment and length only. */
        volatile uint64_t* vwords = (volatile uint64_t*)ptr;
        size_t words = len / 8;
        size_t w;
        for (w = 0; w < words; w++) {
            vwords[w] = 0;
        }
        i = words * 8;
    }
    for (; i < len; i++) {
        vptr[i] = 0;
    }

    /* Additional barrier to prevent optimization */
#ifdef _MSC_VER
    _ReadWriteBarrier();
#else
    __asm__ __volatile__("" ::: "memory");
#endif
}

/**
 * Constant-time conditional swap
 *
 * Swaps two buffers if condition is non-zero, in constant time.
 * Uses XOR swap to avoid branching.
 *
 * The mask goes through ama_ct_value_barrier_u64 (internal/ama_ct_barrier.h
 * lists "conditional swap" among the shapes it exists for).  Without it,
 * measured on 2026-09-24, clang 18.1.3 at -O3 proved the mask is 0x00 or 0xFF
 * and unswitched the loop: `test %edi,%edi; je` on `condition` at entry, then
 * two copies of the loop.  The only shipped caller is the Montgomery ladder of
 * ama_secp256k1_point_mul, where `condition` is a bit of the secret scalar,
 * and the Memcheck secret-taint gate (tools/check_ghash_constant_time.py
 * --target secp256k1-scalarmult --taint) failed on a clang build with 16
 * reports in this function.  gcc 13.3.0 does not unswitch it, which is why
 * the gcc-built CI lane never saw it.
 *
 * @param condition Swap if non-zero (constant time in condition value)
 * @param a First buffer
 * @param b Second buffer
 * @param len Number of bytes to swap
 */
void ama_consttime_swap(int condition, void* a, void* b, size_t len) {
    volatile uint8_t* va = (volatile uint8_t*)a;
    volatile uint8_t* vb = (volatile uint8_t*)b;
    size_t i;
    uint8_t mask;
    uint8_t tmp;

    /* Convert condition to mask: 0x00 or 0xFF, opaquely (see above). */
    mask = (uint8_t)ama_ct_value_barrier_u64((uint64_t)0 - (uint64_t)(condition != 0));

    /* XOR-based conditional swap */
    for (i = 0; i < len; i++) {
        tmp = mask & (va[i] ^ vb[i]);
        va[i] ^= tmp;
        vb[i] ^= tmp;
    }
}

/**
 * Constant-time equality check for size_t values
 *
 * Returns 1 if a == b, 0 otherwise, in constant time.
 * Uses the standard BoringSSL/libsodium pattern for branchless equality.
 *
 * @param a First value
 * @param b Second value
 * @return 1 if equal, 0 otherwise
 */
static inline int consttime_eq_size(size_t a, size_t b) {
    size_t diff = a ^ b;
    /* diff == 0  -> (diff | -diff) == 0, high bit 0, eq = 1
     * diff != 0  -> high bit of (diff | -diff) is 1, eq = 0 */
    diff |= (size_t)0 - diff;
    diff >>= (sizeof(size_t) * 8 - 1);
    return (int)(diff ^ 1);
}

/**
 * Constant-time array lookup
 *
 * Looks up an element in an array in constant time.
 * Always scans entire array to prevent timing leaks.
 *
 * SECURITY NOTE: This function uses constant-time comparison to avoid
 * timing side-channels. The equality check uses arithmetic operations
 * that do not branch on the secret index value. Volatile pointers prevent
 * compiler optimizations that could introduce timing variations.
 *
 * @param table Array to search
 * @param table_len Number of elements
 * @param elem_size Size of each element in bytes
 * @param index Index to retrieve (may be secret)
 * @param output Output buffer for element
 */
void ama_consttime_lookup(
    const void* table,
    size_t table_len,
    size_t elem_size,
    size_t index,
    void* output
) {
    const volatile uint8_t* tbl = (const volatile uint8_t*)table;
    volatile uint8_t* out = (volatile uint8_t*)output;
    size_t i, j;

    /* Initialize output to zero using volatile pointer */
    for (j = 0; j < elem_size; j++) {
        out[j] = 0;
    }

    /* Scan entire table using constant-time comparison */
    for (i = 0; i < table_len; i++) {
        /* Use constant-time equality check */
        int match = consttime_eq_size(i, index);
        /* Convert match (0 or 1) to full mask (0x00 or 0xFF) without casts */
        size_t full_mask = (size_t)0 - (size_t)match;

        /* Conditionally OR in this element */
        for (j = 0; j < elem_size; j++) {
            size_t v = tbl[i * elem_size + j];
            out[j] |= (uint8_t)(full_mask & v);
        }
    }
}

/**
 * Constant-time conditional copy
 *
 * Copies src to dst if condition is non-zero, in constant time.
 *
 * @param condition Copy if non-zero
 * @param dst Destination buffer
 * @param src Source buffer
 * @param len Number of bytes
 */
void ama_consttime_copy(int condition, void* dst, const void* src, size_t len) {
    volatile uint8_t* vdst = (volatile uint8_t*)dst;
    const volatile uint8_t* vsrc = (const volatile uint8_t*)src;
    size_t i;
    uint8_t mask;

    /* Convert condition to mask */
    mask = (uint8_t)(-(int8_t)(condition != 0));

    /* Conditional copy */
    for (i = 0; i < len; i++) {
        vdst[i] = (vdst[i] & ~mask) | (vsrc[i] & mask);
    }
}

#ifdef AMA_TESTING_MODE
/**
 * Whether THIS translation unit — and therefore the library it is part of —
 * was compiled with optimization enabled.
 *
 * See internal/ama_testing_exports.h for why this exists and what the return
 * values mean.  It is deliberately in ama_consttime.c: the caller is the
 * constant-time instruction-count gate, and this file is the one every such
 * build must contain.
 */
int ama_build_optimization_probe(void) {
#if defined(__GNUC__) || defined(__clang__)
    /* Defined by gcc and clang at -O1 and above; absent at -O0. */
#  if defined(__OPTIMIZE__)
    return 1;
#  else
    return 0;
#  endif
#else
    return -1;
#endif
}
#endif /* AMA_TESTING_MODE */
