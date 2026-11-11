/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_stack_wipe.h
 * @brief Scrubbed entry points: a secret-handling public function clears the
 *        stack it used before it returns (INVARIANT-6).
 *
 * THE SHAPE.  Every such function is two, the second of them the exported
 * one.  (Its export attribute is left off the sketch: cmake/generate_pe_def.cmake
 * reads every header line that carries it as a declaration, comments
 * included, and stops the Windows configure on a name nothing defines.)
 *
 *     static AMA_SCRUBBED_BODY ama_error_t ama_x_body(args);   // does the work
 *
 *     ama_error_t ama_x(args) {                                // is exported
 *         ama_error_t rc = ama_x_body(args);
 *         AMA_STACK_WIPE_BELOW(AMA_SCRUB_X_BYTES);
 *         return rc;
 *     }
 *
 * THE LIBRARY'S OWN CALLS.  Where the library itself calls the primitive (a
 * hash under HMAC, SHAKE under ML-KEM), the work is a third function,
 * `ama_x_inner`, which clears nothing; the implementation half is then one
 * call of it, and the library calls it directly.  Its caller runs under an
 * entry point that clears the whole depth, or is verification and holds
 * nothing to clear, and a wipe under either is paid for and buys nothing
 * (internal/ama_scrubbed_inner.h, with what it cost before the rule).
 *
 * WHY TWO.  `ama_secure_memzero` scrubs the buffers a function names.  It
 * cannot reach the copies an optimising compiler makes of them: a spilled
 * register, a hoisted round key, a scalar the compiler split out of an array
 * that the source does wipe.  Those have no names; they can only be cleared
 * by address, by laying a zeroed frame over the region once it is dead.  A
 * function cannot do that to its own frame, which is still live, nor
 * reliably to its callees': it may be holding a word of the secret in a
 * callee-saved register, and the next function it calls, the wipe routine
 * included, pushes that register into the very region being cleared.  The
 * exported function holds pointers and lengths and nothing else, so its own
 * frame and the registers it saves carry nothing of the secret, and when it
 * clears the stack below itself everything the implementation and its
 * callees wrote is under the wipe.  Ascon-AEAD128 was given this shape first,
 * for a key word gcc -O2 left in the entry point's own frame
 * (src/c/ama_ascon.c).
 *
 * WHAT WAS MEASURED, 2026-11-10, on the shipped build (gcc 13.3 -O3, LTO),
 * searching the dead stack for single 8-byte words of the secret where the
 * earlier residue rows searched for the whole of it:
 *   - three of the four words of the HKDF-SHA3-256 output, seven of eight of
 *     a SHA3-512 digest, three of four of a SHAKE256 output: lanes the Keccak
 *     kernels spill.  The scalar permutation leaves 8 of its 25 final lanes
 *     in its frame and the AVX2 four-way kernel 69 of 100;
 *   - two words of ML-KEM's implicit-rejection seed z, in a copy the compiler
 *     made beside a buffer the decapsulation does wipe;
 *   - sixteen bytes of a SHA-256 digest, spilled across the call that scrubs
 *     the hash context.
 * src/c/internal/ama_keccak_round.h had said an optimised build keeps the
 * lanes in registers, and tests/c/test_register_residue.c had read the rows
 * as clean; x86-64 has fifteen general registers for twenty-five lanes.
 *
 * DEPTHS.  Each family clears more than its entry points were measured to
 * use: half as much again at least, the four post-quantum families excepted
 * (below).  "Used" is the largest stack any entry point of the family
 * wrote, taken as the lowest byte written under a 512-byte gap with the wipe
 * compiled out, over seventeen optimised builds (gcc 13.3 and 14.2 and clang
 * 18.1 on x86-64; gcc 13.3 and clang 18.1 on AArch64 under qemu; -O1, -Og,
 * -O2, -O3 and -Os; with and without LTO, AVX-512, SVE2 and
 * -fsanitize=undefined) and five unoptimised ones.
 * tests/c/test_stack_scrub.c holds every entry point to its depth on every
 * lane that runs it, so a toolchain whose frames outgrow a figure fails
 * there instead of leaving the excess uncleared.
 *
 *                       optimised            unoptimised
 *   family            used    cleared      used    cleared
 *   BASE64             247      1,024       448      2,048
 *   ASCON              303      1,024       379      2,048
 *   HYBRID             166      2,048       310      2,048
 *   SHA256             855      2,048     5,055     16,384
 *   AES              1,007      2,048       504      2,048
 *   HMAC_SHA256      1,111      2,048     5,407     16,384
 *   SHA3             1,175      2,048     1,475      8,192
 *   AEAD             1,487      4,096     6,284     16,384
 *   SHA512           1,663      4,096     2,276      8,192
 *   HMAC             2,207      4,096     2,868      8,192
 *   X25519           2,222      4,096   109,087    196,608
 *   KDF              2,879      8,192     6,495     16,384
 *   SECP256K1        3,711      8,192     7,247     16,384
 *   FROST            4,692      8,192   120,583    196,608
 *   ED25519          6,711     16,384    25,695     49,152
 *   NISTP            8,376     16,384     9,343     24,576
 *   ARGON2           9,772     16,384    10,111     24,576
 *   SLH_DSA         11,991     24,576    10,463     24,576
 *   ML_DSA_CHECK    30,847     45,056    28,788     45,056
 *   ML_KEM          37,727     45,056    34,692     45,056
 *   ML_DSA_KEYGEN   65,471     77,824    63,988     77,824
 *   ML_DSA_SIGN    154,479    176,128   151,092    176,128
 *
 * The figures are of this shape of the code (2026-11-10, after the library's
 * own calls were moved to the inner functions): the first measurement, on
 * the shape before, differed from these by at most 249 bytes in any row.
 *
 * The four post-quantum families have less, because their depths are also
 * held from above: tests/c/test_pq_parser_stack.c budgets the stack of the
 * entry points a key file or a signature can reach (48 KiB for the two
 * pubkey_from_privkey parsers, 80 KiB for ML-DSA key generation, 176 KiB for
 * ML-DSA signing), so that a small thread stack fits them, and a wipe is
 * stack too.  First set at half as much again, these four failed that test
 * (2026-11-10: 63,688 bytes against 49,152, 96,456 against 81,920 and
 * 194,760 against 180,224).  They now clear 1.46 times what was measured
 * (ML-DSA's two checks), 1.19 (ML-KEM), 1.19 (ML-DSA key generation) and
 * 1.14 (ML-DSA signing).  That is enough here, where it would not be for a
 * hash: their frames are arrays whose sizes the source fixes (ML-DSA
 * signing spans 149,583 to 154,479 over the twenty-two builds, ML-KEM
 * 32,991 to 37,727), and test_stack_scrub.c fails the lane on which one
 * ever outgrows its depth.
 *
 * An unoptimised build is a different program (the X25519 batch entry point
 * and FROST's second round write over a hundred kilobytes there, where an
 * optimised build writes under five), so it has its own column, never the
 * shallower of the two.
 *
 * HYBRID is a depth of another kind.  ama_sign()'s hybrid branch calls two
 * entry points that clear their own stack, so its pair (src/c/ama_core.c,
 * hybrid_sign) clears only what is written outside them: the
 * implementation's frame and the allocator's.  Its figures are the run of
 * bytes that branch left below ama_sign() before it was a pair: 166
 * optimised (gcc 13.3 and 14.2, x86-64), 310 unoptimised (aarch64 gcc 13.3).
 *
 * A depth is also what the entry point asks of its caller: the wipe touches
 * that much stack below the entry point whether or not the implementation
 * did.  The depths above are therefore each family's stack requirement, to
 * within the entry point's own few words.
 *
 * NOT WRAPPED.  The constant-time helpers and ama_secure_memzero() make no
 * call and keep no frame in an optimised build; tests/c/test_stack_scrub.c
 * holds them to that, and says what an unoptimised build cannot give them.
 * The generic ama_keypair_generate(), ama_kem_encapsulate() and
 * ama_kem_decapsulate() hand their caller's pointers to an entry point above
 * and keep nothing; they have rows too.  So do the eleven exports that are
 * one call of such an entry point and nothing else: the ama_kyber_* names
 * for ML-KEM-1024, the ama_dilithium_* key-generation and signing names for
 * ML-DSA-65, and ama_nistp_ecdsa_sign(), _sign_raw() and _sign_hedged().
 * They cleared their stack as well at first, and the instruction counts
 * showed each call zeroing its depth twice.  The library's remaining
 * exports take no secret or leave none: verification, encodings of public
 * values, size and parameter queries, dispatch and diagnostics, the memory
 * utilities, and ama_random_bytes(), whose output the operating system
 * writes into the caller's buffer.  tests/test_stack_scrub_surface.py puts
 * every export in one of these places and fails on one that is in none.
 *
 * WHERE THIS IS MEASURED.  Linux on x86-64 and AArch64, macOS on arm64, and
 * Windows x64 built with a GNU compiler, which CI runs under Wine
 * (ci-build-test.yml).  The depths were measured on the first two; the macOS
 * and Windows builds are held to them by the same two tests.  MSVC, which
 * builds the Windows wheels, takes the same code and is measured by nothing:
 * the stack tests need GNU C inline assembly, which MSVC does not have on
 * x64.  What is known of that build is what its convention shares with
 * MinGW's and is handled the same way (src/c/ama_consttime.c,
 * ama_stack_wipe_cap); what it does with it is not.
 */
#ifndef AMA_STACK_WIPE_H
#define AMA_STACK_WIPE_H

/**
 * The implementation half of a scrubbed entry point: never inlined, so that
 * its frame and every frame below it are dead when the entry point clears
 * the stack.
 */
#if defined(__GNUC__) || defined(__clang__)
#  define AMA_SCRUBBED_BODY __attribute__((noinline))
#elif defined(_MSC_VER)
#  define AMA_SCRUBBED_BODY __declspec(noinline)
#else
#  define AMA_SCRUBBED_BODY
#endif

/* Which column of the table above this compilation takes.  MSVC defines no
 * __OPTIMIZE__; there _DEBUG marks the unoptimised configurations. */
#if defined(__OPTIMIZE__) || (defined(_MSC_VER) && !defined(_DEBUG))
#  define AMA_SCRUB_OPTIMISED_BUILD 1
#else
#  define AMA_SCRUB_OPTIMISED_BUILD 0
#endif

/* The table.  A depth is a plain decimal token and nothing else:
 * AMA_STACK_WIPE_BELOW() pastes it into the name of the function that clears
 * exactly that much. */
#if AMA_SCRUB_OPTIMISED_BUILD
#define AMA_SCRUB_BASE64_BYTES 1024
#define AMA_SCRUB_ASCON_BYTES 1024
#define AMA_SCRUB_HYBRID_BYTES 2048
#define AMA_SCRUB_SHA256_BYTES 2048
#define AMA_SCRUB_AES_BYTES 2048
#define AMA_SCRUB_HMAC_SHA256_BYTES 2048
#define AMA_SCRUB_SHA3_BYTES 2048
#define AMA_SCRUB_AEAD_BYTES 4096
#define AMA_SCRUB_SHA512_BYTES 4096
#define AMA_SCRUB_HMAC_BYTES 4096
#define AMA_SCRUB_X25519_BYTES 4096
#define AMA_SCRUB_KDF_BYTES 8192
#define AMA_SCRUB_SECP256K1_BYTES 8192
#define AMA_SCRUB_FROST_BYTES 8192
#define AMA_SCRUB_ED25519_BYTES 16384
#define AMA_SCRUB_NISTP_BYTES 16384
#define AMA_SCRUB_ARGON2_BYTES 16384
#define AMA_SCRUB_SLH_DSA_BYTES 24576
#define AMA_SCRUB_ML_DSA_CHECK_BYTES 45056
#define AMA_SCRUB_ML_KEM_BYTES 45056
#define AMA_SCRUB_ML_DSA_KEYGEN_BYTES 77824
#define AMA_SCRUB_ML_DSA_SIGN_BYTES 176128
#else
#define AMA_SCRUB_BASE64_BYTES 2048
#define AMA_SCRUB_ASCON_BYTES 2048
#define AMA_SCRUB_HYBRID_BYTES 2048
#define AMA_SCRUB_SHA256_BYTES 16384
#define AMA_SCRUB_AES_BYTES 2048
#define AMA_SCRUB_HMAC_SHA256_BYTES 16384
#define AMA_SCRUB_SHA3_BYTES 8192
#define AMA_SCRUB_AEAD_BYTES 16384
#define AMA_SCRUB_SHA512_BYTES 8192
#define AMA_SCRUB_HMAC_BYTES 8192
#define AMA_SCRUB_X25519_BYTES 196608
#define AMA_SCRUB_KDF_BYTES 16384
#define AMA_SCRUB_SECP256K1_BYTES 16384
#define AMA_SCRUB_FROST_BYTES 196608
#define AMA_SCRUB_ED25519_BYTES 49152
#define AMA_SCRUB_NISTP_BYTES 24576
#define AMA_SCRUB_ARGON2_BYTES 24576
#define AMA_SCRUB_SLH_DSA_BYTES 24576
#define AMA_SCRUB_ML_DSA_CHECK_BYTES 45056
#define AMA_SCRUB_ML_KEM_BYTES 45056
#define AMA_SCRUB_ML_DSA_KEYGEN_BYTES 77824
#define AMA_SCRUB_ML_DSA_SIGN_BYTES 176128
#endif

/* The depth of the exported ama_secure_stack_wipe(): AMA_STACK_WIPE_BYTES of
 * the public header, as a token that can be pasted.  src/c/ama_consttime.c
 * holds the two equal at compile time. */
#define AMA_SCRUB_EXPORTED_WIPE_BYTES 4096

/* What AMA_STACK_WIPE_BELOW() is made of (src/c/ama_consttime.c): one
 * function per depth that lays a frame of exactly that size over the dead
 * stack and zeroes all of its array, and the cap, which then clears what a
 * frame function leaves at the top of its own frame. */
void ama_stack_wipe_cap(void);
void ama_stack_wipe_frame_1024(void);
void ama_stack_wipe_frame_2048(void);
void ama_stack_wipe_frame_4096(void);
void ama_stack_wipe_frame_8192(void);
void ama_stack_wipe_frame_16384(void);
void ama_stack_wipe_frame_24576(void);
void ama_stack_wipe_frame_45056(void);
void ama_stack_wipe_frame_49152(void);
void ama_stack_wipe_frame_77824(void);
void ama_stack_wipe_frame_176128(void);
void ama_stack_wipe_frame_196608(void);

/**
 * Zero the `bytes` bytes of dead stack immediately below the calling frame.
 * Use it in the frame that called the primitive, right after the primitive
 * returns.  `bytes` is one of the depths above.
 *
 * A macro, and two calls: both must be made by the frame that is clearing
 * its stack.  A function in between, which is what an `inline` one is in a
 * build that does not inline, lays its own frame at the top of the region,
 * and the bytes of that frame it does not write keep what the primitive
 * left there.  Measured 2026-11-10, gcc 13.3 -O0, on the `static inline`
 * this replaces: four bytes of the AES-256 key schedule, in the alignment
 * word of the dispatcher's frame, after ama_aes256_key_expansion_consttime()
 * had returned.  A depth with no frame function does not link.
 *
 * The frame function first, the cap second: the cap clears the top of the
 * frame function's frame, and on Windows x64 what that function's stack
 * probe pushed there (src/c/ama_consttime.c, ama_stack_wipe_cap).
 */
#define AMA_STACK_WIPE_FRAME_NAME_(bytes) ama_stack_wipe_frame_##bytes
#define AMA_STACK_WIPE_FRAME_NAME(bytes) AMA_STACK_WIPE_FRAME_NAME_(bytes)
#define AMA_STACK_WIPE_BELOW(bytes)                \
    do {                                           \
        AMA_STACK_WIPE_FRAME_NAME(bytes)();        \
        ama_stack_wipe_cap();                      \
    } while (0)

#endif /* AMA_STACK_WIPE_H */
