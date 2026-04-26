/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file ama_x25519.c
 * @brief X25519 Diffie-Hellman key exchange (RFC 7748)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * Implements X25519 Diffie-Hellman key exchange per RFC 7748 using the
 * Montgomery curve Curve25519: y^2 = x^3 + 486662*x^2 + x over GF(2^255-19).
 *
 * Field arithmetic — three tiers, selected at compile time:
 *   - **fe64** (radix 2^64, 4 limbs of uint64_t with __uint128_t
 *     intermediates) on x86-64 GCC/Clang where the 64x64→128 native
 *     multiply is single-cycle and `__int128` is available. The fewest
 *     possible limbs on a 64-bit target — 16 cross-products per mul.
 *   - **fe51** (radix 2^51, 5 limbs) — the donna64 layout, 25 cross-
 *     products per mul. Used on non-x86-64 GCC/Clang 64-bit targets
 *     (e.g. aarch64, ppc64le) where `__int128` is available but the
 *     fe64 carry chain is less of a win or unverified at perf level.
 *   - **gf radix-2^16** (16 limbs of int64_t, TweetNaCl-style) — fully
 *     portable fallback for MSVC, clang-cl, 32-bit targets, and any
 *     other toolchain without `__int128`.
 *
 * The selection is *deterministic* at compile time — the build-time
 * guard `AMA_X25519_FIELD_FE64` is defined exactly when the fe64 path
 * is selected, and `ama_x25519_field_path()` returns a stable string
 * literal ("fe64" / "fe51" / "gf16") so a future build-flag change
 * cannot silently regress the path. See `tests/c/test_x25519_path.c`
 * for the compile-time pin.
 *
 * The Montgomery ladder operates on x-coordinates only, processing scalar
 * bits from bit 254 down to 0 with constant-time conditional swaps.
 *
 * Security properties:
 * - Constant-time Montgomery ladder (no secret-dependent branches)
 * - Constant-time field arithmetic
 * - Constant-time conditional swap
 * - Key clamping per RFC 7748 Section 5
 * - Low-order point rejection (all-zero shared secret check)
 * - Secure memory cleanup via ama_secure_memzero
 */

#include "../include/ama_cryptography.h"
#include "../include/ama_cpuid.h"
#include "ama_platform_rand.h"
#include <string.h>
#include <stdint.h>

#include "fe51.h"
#include "fe64.h"

/* PR D (2026-04) — MULX+ADX fe64 kernel runtime branch.
 *
 * The kernel lives in src/c/internal/ama_x25519_fe64_mulx.c and is
 * compiled with per-file -mbmi2 -madx flags. CMake defines
 * AMA_HAVE_X25519_FE64_MULX_IMPL on every target that links the
 * kernel TU.
 *
 * The forward declarations are *unconditional* on every TU that picks
 * up this header chain, matching the style used by the other dispatch
 * targets — but they're only invoked under the runtime CPUID gate
 * `ama_cpuid_has_x25519_mulx()` (BMI2 + ADX) AND the build-time
 * AMA_HAVE_X25519_FE64_MULX_IMPL macro AND the `AMA_X25519_FIELD_FE64`
 * compile-path. On every host that fails any of those gates the
 * pure-C fe64_mul / fe64_sq from fe64.h continues to drive the
 * Montgomery ladder. */
#if defined(AMA_HAVE_X25519_FE64_MULX_IMPL) && defined(AMA_FE64_AVAILABLE)
extern void ama_x25519_fe64_mul_mulx(uint64_t h[4], const uint64_t f[4],
                                     const uint64_t g[4]);
extern void ama_x25519_fe64_sq_mulx(uint64_t h[4], const uint64_t f[4]);
#endif

/* ----------------------------------------------------------------------
 * Build-time field-path selection (deterministic).
 *
 *   AMA_X25519_FIELD_FE64 — set when the fe64 (radix 2^64) ladder is
 *                           compiled in. Default: x86-64 GCC/Clang
 *                           with __int128.
 *   AMA_X25519_FIELD_FE51 — set when the fe51 (radix 2^51) ladder is
 *                           compiled in. Default: non-x86-64 GCC/Clang
 *                           with __int128.
 *   AMA_X25519_FIELD_GF   — set when the portable radix-2^16 ladder is
 *                           compiled in. Default: anything else.
 *
 * Override knobs (mostly for the byte-equivalence test that compiles
 * the fe51 path on an x86-64 host):
 *   AMA_X25519_FORCE_FE51 — force fe51 even when fe64 would otherwise
 *                           win (useful for bit-for-bit cross-checks).
 *   AMA_X25519_FORCE_FE64 — force fe64 (only takes effect if
 *                           AMA_FE64_AVAILABLE).
 * ---------------------------------------------------------------------- */
#if defined(AMA_X25519_FORCE_FE64) && defined(AMA_FE64_AVAILABLE)
#  define AMA_X25519_FIELD_FE64 1
#elif defined(AMA_X25519_FORCE_FE51) && defined(AMA_FE51_AVAILABLE)
#  define AMA_X25519_FIELD_FE51 1
#elif defined(AMA_FE64_AVAILABLE) && (defined(__x86_64__) || defined(_M_X64))
#  define AMA_X25519_FIELD_FE64 1
#elif defined(AMA_FE51_AVAILABLE)
#  define AMA_X25519_FIELD_FE51 1
#else
#  define AMA_X25519_FIELD_GF 1
#endif

/* Linkage of the inner ladder. Defaults to `static` so the production
 * library export surface is exactly `ama_x25519_keypair` /
 * `ama_x25519_key_exchange` / `ama_x25519_field_path`. The fe51-vs-fe64
 * byte-equivalence test (`tests/c/test_x25519_field_equiv.c`) overrides
 * this to nothing so it can compile two TUs from this file with
 * different rename macros and link the resulting non-static
 * `x25519_scalarmult_{fe51,fe64}` symbols into a single test binary. */
#ifndef AMA_X25519_LADDER_LINKAGE
#  define AMA_X25519_LADDER_LINKAGE static
#endif

#if defined(AMA_X25519_FIELD_FE64)

/* ============================================================================
 * X25519 SCALAR MULTIPLICATION  (radix-2^64, RFC 7748 Section 5 / Appendix A)
 *
 * Same RFC 7748 Appendix A ladder structure as the fe51 path — only the
 * field-element type and the per-step ops change. 4-limb representation
 * with __uint128_t intermediates: 16 cross-products per multiplication
 * (vs 25 for fe51) and the 64x64→128 native multiply on x86-64 maps
 * directly to a single MUL/MULX instruction.
 * ============================================================================ */

/* Per-call ladder driver: takes function pointers for the field
 * multiply and square so the runtime branch (pure-C fe64 vs MULX+ADX
 * kernel) happens *once* per scalar-mult instead of once per ladder
 * step. Marked `always_inline` so the compiler folds the function-
 * pointer indirection through the surrounding caller and re-inlines
 * the chosen multiply at every call site. */
typedef void (*fe64_mul_fn)(uint64_t h[4], const uint64_t f[4],
                            const uint64_t g[4]);
typedef void (*fe64_sq_fn) (uint64_t h[4], const uint64_t f[4]);

/* Templated 1/z over GF(2^255-19) — exact same straight-line schedule
 * as `fe64_invert` in src/c/fe64.h, but with the field multiply / square
 * provided as function-pointer arguments. Marked `always_inline` so the
 * runtime-selected mul/sq fold through every call site here, which lights
 * the MULX+ADX kernel up across the ~265 squares + ~11 multiplies inside
 * the inversion as well as inside the ladder body. */
static inline __attribute__((always_inline))
void fe64_invert_with_ops(uint64_t out[4], const uint64_t z[4],
                          fe64_mul_fn mul, fe64_sq_fn sq) {
    uint64_t t0[4], t1[4], t2[4], t3[4];
    int i;

    sq (t0, z);
    sq (t1, t0); sq(t1, t1);
    mul(t1, z, t1);
    mul(t0, t0, t1);
    sq (t2, t0);
    mul(t1, t1, t2);
    sq (t2, t1);
    for (i = 0; i < 4; i++)  sq(t2, t2);
    mul(t1, t2, t1);
    sq (t2, t1);
    for (i = 0; i < 9; i++)  sq(t2, t2);
    mul(t2, t2, t1);
    sq (t3, t2);
    for (i = 0; i < 19; i++) sq(t3, t3);
    mul(t2, t3, t2);
    sq (t2, t2);
    for (i = 0; i < 9; i++)  sq(t2, t2);
    mul(t1, t2, t1);
    sq (t2, t1);
    for (i = 0; i < 49; i++) sq(t2, t2);
    mul(t2, t2, t1);
    sq (t3, t2);
    for (i = 0; i < 99; i++) sq(t3, t3);
    mul(t2, t3, t2);
    sq (t2, t2);
    for (i = 0; i < 49; i++) sq(t2, t2);
    mul(t1, t2, t1);
    sq (t1, t1);
    for (i = 0; i < 4; i++)  sq(t1, t1);
    mul(out, t1, t0);

    ama_secure_memzero(t0, sizeof(t0));
    ama_secure_memzero(t1, sizeof(t1));
    ama_secure_memzero(t2, sizeof(t2));
    ama_secure_memzero(t3, sizeof(t3));
}

static inline __attribute__((always_inline))
void x25519_scalarmult_fe64_with_ops(uint8_t q[32],
                                     const uint8_t n[32],
                                     const uint8_t p[32],
                                     fe64_mul_fn mul,
                                     fe64_sq_fn  sq) {
    uint8_t z[32];
    fe64 x1, x2, z2, x3, z3;
    fe64 A, AA, B, BB, E, C, D, DA, CB, t0, t1;
    unsigned int swap = 0;
    int t;

    /* Copy and clamp scalar per RFC 7748 Section 5 */
    memcpy(z, n, 32);
    z[0]  &= 248;
    z[31] &= 127;
    z[31] |= 64;

    /* Decode u-coordinate of base point (clears bit 255 inside) */
    fe64_frombytes(x1, p);

    /* Ladder initial state */
    fe64_1(x2);
    fe64_0(z2);
    fe64_copy(x3, x1);
    fe64_1(z3);

    for (t = 254; t >= 0; t--) {
        unsigned int k_t = (z[t >> 3] >> (t & 7)) & 1;
        swap ^= k_t;
        fe64_cswap(x2, x3, (uint64_t)swap);
        fe64_cswap(z2, z3, (uint64_t)swap);
        swap = k_t;

        fe64_add(A, x2, z2);      /* A  = x2 + z2    */
        sq      (AA, A);          /* AA = A^2        */
        fe64_sub(B, x2, z2);      /* B  = x2 - z2    */
        sq      (BB, B);          /* BB = B^2        */
        fe64_sub(E, AA, BB);      /* E  = AA - BB    */
        fe64_add(C, x3, z3);      /* C  = x3 + z3    */
        fe64_sub(D, x3, z3);      /* D  = x3 - z3    */
        mul     (DA, D, A);       /* DA = D * A      */
        mul     (CB, C, B);       /* CB = C * B      */
        fe64_add(t0, DA, CB);     /* t0 = DA + CB    */
        sq      (x3, t0);         /* x3 = (DA+CB)^2  */
        fe64_sub(t0, DA, CB);     /* t0 = DA - CB    */
        sq      (t1, t0);         /* t1 = (DA-CB)^2  */
        mul     (z3, x1, t1);     /* z3 = x1 * (DA-CB)^2 */
        mul     (x2, AA, BB);     /* x2 = AA * BB    */
        fe64_mul_121665(t0, E);   /* t0 = a24 * E    */
        fe64_add(t1, AA, t0);     /* t1 = AA + a24*E */
        mul     (z2, E, t1);      /* z2 = E * (AA + a24*E) */
    }

    /* Final swap */
    fe64_cswap(x2, x3, (uint64_t)swap);
    fe64_cswap(z2, z3, (uint64_t)swap);

    /* Result = x2 / z2.
     *
     * Templated invert: ~265 squares + 11 multiplies, all routed
     * through the same runtime-selected `mul` / `sq` ops as the
     * ladder body. On hosts where the MULX+ADX kernel is selected
     * the inversion runs through it too (the squarings dominate the
     * count and benefit most from the dedicated sq kernel). */
    fe64_invert_with_ops(z2, z2, mul, sq);
    mul        (x2, x2, z2);
    fe64_tobytes(q, x2);

    /* Secure cleanup of all sensitive intermediates */
    ama_secure_memzero(z,  sizeof(z));
    ama_secure_memzero(x1, sizeof(fe64));
    ama_secure_memzero(x2, sizeof(fe64));
    ama_secure_memzero(z2, sizeof(fe64));
    ama_secure_memzero(x3, sizeof(fe64));
    ama_secure_memzero(z3, sizeof(fe64));
    ama_secure_memzero(A,  sizeof(fe64));
    ama_secure_memzero(AA, sizeof(fe64));
    ama_secure_memzero(B,  sizeof(fe64));
    ama_secure_memzero(BB, sizeof(fe64));
    ama_secure_memzero(E,  sizeof(fe64));
    ama_secure_memzero(C,  sizeof(fe64));
    ama_secure_memzero(D,  sizeof(fe64));
    ama_secure_memzero(DA, sizeof(fe64));
    ama_secure_memzero(CB, sizeof(fe64));
    ama_secure_memzero(t0, sizeof(fe64));
    ama_secure_memzero(t1, sizeof(fe64));
}

/* Pure-C fe64 multiply / square wrappers. Match the (uint64_t[4], …)
 * signature expected by `x25519_scalarmult_fe64_with_ops`. The
 * compiler inlines these through the function-pointer call site
 * because both are `always_inline` — no indirect-call cost in the
 * hot loop. */
static inline __attribute__((always_inline))
void fe64_mul_purec_wrapper(uint64_t h[4], const uint64_t f[4],
                            const uint64_t g[4]) {
    fe64_mul((uint64_t *)h, (const uint64_t *)f, (const uint64_t *)g);
}

static inline __attribute__((always_inline))
void fe64_sq_purec_wrapper(uint64_t h[4], const uint64_t f[4]) {
    fe64_sq((uint64_t *)h, (const uint64_t *)f);
}

AMA_X25519_LADDER_LINKAGE void x25519_scalarmult(uint8_t q[32],
                                                 const uint8_t n[32],
                                                 const uint8_t p[32]) {
#if defined(AMA_HAVE_X25519_FE64_MULX_IMPL)
    /* Runtime branch: BMI2 (MULX) + ADX (ADCX/ADOX) bundle gate. The
     * detection is cached after the first call by `cpuid_once` in
     * ama_cpuid.c, so the cost is one predictable load + branch per
     * scalarmult, amortised over ~2500 mults+squares in the ladder. */
    if (ama_cpuid_has_x25519_mulx()) {
        x25519_scalarmult_fe64_with_ops(q, n, p,
                                        ama_x25519_fe64_mul_mulx,
                                        ama_x25519_fe64_sq_mulx);
        return;
    }
#endif
    x25519_scalarmult_fe64_with_ops(q, n, p,
                                    fe64_mul_purec_wrapper,
                                    fe64_sq_purec_wrapper);
}

#elif defined(AMA_X25519_FIELD_FE51)

/* ============================================================================
 * X25519 SCALAR MULTIPLICATION  (radix-2^51, RFC 7748 Section 5 / Appendix A)
 *
 * Uses the reference ladder formulation from RFC 7748 Appendix A.  At each
 * iteration the working pair (x2:z2)/(x3:z3) is conditionally swapped so
 * the secret bit is folded into the cswap mask only — no branches depend
 * on the scalar.
 * ============================================================================ */

AMA_X25519_LADDER_LINKAGE void x25519_scalarmult(uint8_t q[32], const uint8_t n[32],
                              const uint8_t p[32]) {
    uint8_t z[32];
    fe51 x1, x2, z2, x3, z3;
    fe51 A, AA, B, BB, E, C, D, DA, CB, t0, t1;
    unsigned int swap = 0;
    int t;

    /* Copy and clamp scalar per RFC 7748 Section 5 */
    memcpy(z, n, 32);
    z[0]  &= 248;
    z[31] &= 127;
    z[31] |= 64;

    /* Decode u-coordinate of base point (clears bit 255 inside) */
    fe51_frombytes(x1, p);

    /* Ladder initial state */
    fe51_1(x2);
    fe51_0(z2);
    fe51_copy(x3, x1);
    fe51_1(z3);

    for (t = 254; t >= 0; t--) {
        unsigned int k_t = (z[t >> 3] >> (t & 7)) & 1;
        swap ^= k_t;
        fe51_cswap(x2, x3, (uint64_t)swap);
        fe51_cswap(z2, z3, (uint64_t)swap);
        swap = k_t;

        fe51_add(A, x2, z2);      /* A  = x2 + z2    */
        fe51_sq (AA, A);          /* AA = A^2        */
        fe51_sub(B, x2, z2);      /* B  = x2 - z2    */
        fe51_sq (BB, B);          /* BB = B^2        */
        fe51_sub(E, AA, BB);      /* E  = AA - BB    */
        fe51_add(C, x3, z3);      /* C  = x3 + z3    */
        fe51_sub(D, x3, z3);      /* D  = x3 - z3    */
        fe51_mul(DA, D, A);       /* DA = D * A      */
        fe51_mul(CB, C, B);       /* CB = C * B      */
        fe51_add(t0, DA, CB);     /* t0 = DA + CB    */
        fe51_sq (x3, t0);         /* x3 = (DA+CB)^2  */
        fe51_sub(t0, DA, CB);     /* t0 = DA - CB    */
        fe51_sq (t1, t0);         /* t1 = (DA-CB)^2  */
        fe51_mul(z3, x1, t1);     /* z3 = x1 * (DA-CB)^2 */
        fe51_mul(x2, AA, BB);     /* x2 = AA * BB    */
        fe51_mul_121665(t0, E);   /* t0 = a24 * E    */
        fe51_add(t1, AA, t0);     /* t1 = AA + a24*E */
        fe51_mul(z2, E, t1);      /* z2 = E * (AA + a24*E) */
    }

    /* Final swap */
    fe51_cswap(x2, x3, (uint64_t)swap);
    fe51_cswap(z2, z3, (uint64_t)swap);

    /* Result = x2 / z2 */
    fe51_invert(z2, z2);
    fe51_mul(x2, x2, z2);
    fe51_tobytes(q, x2);

    /* Secure cleanup of all sensitive intermediates */
    ama_secure_memzero(z,  sizeof(z));
    ama_secure_memzero(x1, sizeof(fe51));
    ama_secure_memzero(x2, sizeof(fe51));
    ama_secure_memzero(z2, sizeof(fe51));
    ama_secure_memzero(x3, sizeof(fe51));
    ama_secure_memzero(z3, sizeof(fe51));
    ama_secure_memzero(A,  sizeof(fe51));
    ama_secure_memzero(AA, sizeof(fe51));
    ama_secure_memzero(B,  sizeof(fe51));
    ama_secure_memzero(BB, sizeof(fe51));
    ama_secure_memzero(E,  sizeof(fe51));
    ama_secure_memzero(C,  sizeof(fe51));
    ama_secure_memzero(D,  sizeof(fe51));
    ama_secure_memzero(DA, sizeof(fe51));
    ama_secure_memzero(CB, sizeof(fe51));
    ama_secure_memzero(t0, sizeof(fe51));
    ama_secure_memzero(t1, sizeof(fe51));
}

#else  /* AMA_X25519_FIELD_GF — portable radix-2^16 fallback */

/* ============================================================================
 * FIELD ELEMENT TYPE: 16 limbs of ~16 bits each, stored in int64_t
 *
 * TweetNaCl-inspired radix-2^16 representation. Slower but portable
 * (no __uint128_t required). Selected whenever fe51.h is not available
 * — MSVC, clang-cl, 32-bit targets, and any other toolchain where
 * __SIZEOF_INT128__ is undefined.
 * ============================================================================ */

typedef int64_t gf[16];

static void gf_set(gf o, const gf a) {
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i];
}

static void gf_cswap(gf p, gf q, int64_t b) {
    int64_t t, mask = ~(b - 1);
    int i;
    for (i = 0; i < 16; i++) {
        t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void car25519(gf o) {
    int64_t c;
    int i;
    for (i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void gf_add(gf o, const gf a, const gf b) {
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void gf_sub(gf o, const gf a, const gf b) {
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void gf_mul(gf o, const gf a, const gf b) {
    int64_t t[31];
    int i, j;
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    for (i = 16; i < 31; i++)
        t[i - 16] += 38 * t[i];
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void gf_sqr(gf o, const gf a) {
    gf_mul(o, a, a);
}

static void gf_mul_scalar(gf o, const gf a, uint32_t s) {
    int64_t t[31];
    int i;
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++)
        t[i] = a[i] * (int64_t)s;
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void gf_inv(gf o, const gf a) {
    gf c;
    int i;
    gf_set(c, a);
    for (i = 253; i >= 0; i--) {
        gf_sqr(c, c);
        if (i != 2 && i != 4) {
            gf_mul(c, c, a);
        }
    }
    gf_set(o, c);
}

static void unpack25519(gf o, const uint8_t n[32]) {
    int i;
    for (i = 0; i < 16; i++)
        o[i] = (int64_t)n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void pack25519(uint8_t o[32], const gf n) {
    int i, j;
    gf m, t;
    gf_set(t, n);
    car25519(t);
    car25519(t);
    car25519(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int64_t b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        for (i = 0; i < 16; i++)
            t[i] = m[i] * (1 - b) + t[i] * b;
    }
    for (i = 0; i < 16; i++) {
        o[2 * i]     = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

AMA_X25519_LADDER_LINKAGE void x25519_scalarmult(uint8_t q[32], const uint8_t n[32],
                              const uint8_t p[32]) {
    uint8_t z[32];
    gf x, a, b, c, d, e, f;
    int64_t r;
    int i;

    memcpy(z, n, 32);
    z[0]  &= 248;
    z[31] &= 127;
    z[31] |= 64;

    unpack25519(x, p);

    for (i = 0; i < 16; i++) {
        b[i] = x[i];
        a[i] = d[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;

    for (i = 254; i >= 0; i--) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        gf_cswap(a, b, r);
        gf_cswap(c, d, r);

        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_add(c, b, d);
        gf_sub(b, b, d);
        gf_sqr(d, e);
        gf_sqr(f, a);
        gf_mul(a, c, a);
        gf_mul(c, b, e);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_sqr(b, a);
        gf_sub(c, d, f);
        gf_mul_scalar(a, c, 121665);
        gf_add(a, a, d);
        gf_mul(c, c, a);
        gf_mul(a, d, f);
        gf_mul(d, b, x);
        gf_sqr(b, e);

        gf_cswap(a, b, r);
        gf_cswap(c, d, r);
    }

    gf_inv(c, c);
    gf_mul(a, a, c);
    pack25519(q, a);

    ama_secure_memzero(z, sizeof(z));
    ama_secure_memzero(x, sizeof(gf));
    ama_secure_memzero(a, sizeof(gf));
    ama_secure_memzero(b, sizeof(gf));
    ama_secure_memzero(c, sizeof(gf));
    ama_secure_memzero(d, sizeof(gf));
    ama_secure_memzero(e, sizeof(gf));
    ama_secure_memzero(f, sizeof(gf));
}

#endif  /* AMA_X25519_FIELD_* */

/* ============================================================================
 * PUBLIC API
 *
 * The byte-equivalence test compiles this TU twice with different field-
 * path force flags to expose two non-static `x25519_scalarmult` symbols
 * (renamed via `-Dx25519_scalarmult=x25519_scalarmult_fe51` etc.). In
 * those builds, AMA_X25519_NO_PUBLIC_API is defined so the AMA_API
 * exports below are skipped — otherwise we'd get duplicate definitions
 * of `ama_x25519_keypair` etc. when the test executable links the two
 * wrapper TUs together with the production library.
 * ============================================================================ */

#ifndef AMA_X25519_NO_PUBLIC_API

/**
 * @brief Return the X25519 field-arithmetic path selected at compile time.
 *
 * Returns one of the string literals "fe64", "fe51", or "gf16". Used by
 * the path-pinning regression test (see `tests/c/test_x25519_path.c`)
 * to assert that a future build-flag change cannot silently regress the
 * compiled-in path.
 */
AMA_API const char *ama_x25519_field_path(void) {
#if defined(AMA_X25519_FIELD_FE64)
    return "fe64";
#elif defined(AMA_X25519_FIELD_FE51)
    return "fe51";
#else
    return "gf16";
#endif
}

/**
 * @brief Generate X25519 keypair.
 *
 * Fills secret_key with 32 random bytes (clamped per RFC 7748 Section 5).
 * Computes public_key = X25519(secret_key, 9) where 9 is the base point.
 *
 * @param public_key  Output: 32-byte public key (u-coordinate)
 * @param secret_key  Output: 32-byte secret key (clamped)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_x25519_keypair(
    uint8_t public_key[32],
    uint8_t secret_key[32]
) {
    ama_error_t err;

    if (!public_key || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    err = ama_randombytes(secret_key, 32);
    if (err != AMA_SUCCESS) {
        return err;
    }

    secret_key[0]  &= 248;
    secret_key[31] &= 127;
    secret_key[31] |= 64;

    uint8_t basepoint[32];
    memset(basepoint, 0, sizeof(basepoint));
    basepoint[0] = 9;

    x25519_scalarmult(public_key, secret_key, basepoint);

    return AMA_SUCCESS;
}

/**
 * @brief X25519 Diffie-Hellman key exchange.
 *
 * Computes shared_secret = X25519(our_secret_key, their_public_key).
 * Returns AMA_ERROR_CRYPTO if the result is all-zero (low-order point input).
 *
 * @param shared_secret    Output: 32-byte shared secret
 * @param our_secret_key   Our 32-byte secret key
 * @param their_public_key Their 32-byte public key
 * @return AMA_SUCCESS or AMA_ERROR_CRYPTO
 */
AMA_API ama_error_t ama_x25519_key_exchange(
    uint8_t shared_secret[32],
    const uint8_t our_secret_key[32],
    const uint8_t their_public_key[32]
) {
    if (!shared_secret || !our_secret_key || !their_public_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    x25519_scalarmult(shared_secret, our_secret_key, their_public_key);

    uint8_t zero_check = 0;
    int i;
    for (i = 0; i < 32; i++) {
        zero_check |= shared_secret[i];
    }

    if (zero_check == 0) {
        ama_secure_memzero(shared_secret, 32);
        return AMA_ERROR_CRYPTO;
    }

    return AMA_SUCCESS;
}

#endif /* AMA_X25519_NO_PUBLIC_API */
