/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_nistp.c
 * @brief NIST prime curves P-256 / P-384 / P-521 — ECDSA (FIPS 186-5) and ECDH
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-07-27
 *
 * Implemented from specification (SP 800-186 curve parameters, FIPS 186-5
 * ECDSA, SP 800-56A §5.7.1.2 ECC CDH, RFC 6979 deterministic nonces, SEC 1
 * point encoding).  Zero external crypto dependencies (INVARIANT-1): the only
 * primitives consumed are AMA's own HMAC-SHA-256/384/512 and the platform
 * CSPRNG.
 *
 * Why one file for three curves.  P-256, P-384 and P-521 are all short
 * Weierstrass curves `y^2 = x^3 - 3x + b` over a prime field with cofactor 1.
 * The *only* things that differ are the modulus, the group order, `b`, the
 * generator, and the operand width.  Writing three near-identical files would
 * triple the audit surface for zero capability; instead the arithmetic is
 * generic over a limb count (`nlimbs <= AMA_NISTP_MAX_LIMBS`) and the curve is
 * a `const` parameter block.  `ama_secp256k1.c` stays separate because it is a
 * different curve shape (`a = 0`, and a Solinas prime that admits a
 * curve-specific 5x52 reduction that a generic path cannot express).
 *
 * Arithmetic.  Montgomery form over 64-bit limbs with CIOS multiplication.
 * A generic Montgomery multiply is used rather than per-curve Solinas
 * reduction because the reduction chains for P-256/384/521 are three separate
 * bodies of subtle carry code; one generic, uniformly constant-time kernel is
 * the defensible engineering trade at this stage.  See the "Timing posture"
 * note below and `docs/NIST_PRIME_CURVES.md` for the measured cost.
 *
 * Security properties:
 * - Constant-time field and scalar arithmetic: no secret-dependent branch and
 *   no secret-dependent memory index anywhere on the signing / ECDH path.
 * - Scalar multiplication is a fixed 4-bit window whose table is read with a
 *   full constant-time linear scan (every entry is touched, every time).
 * - The point addition handles *all* exceptional cases (either operand at
 *   infinity, P == Q, P == -Q) branchlessly by computing the general result
 *   and the doubling and selecting between them with masks.
 * - Every secret intermediate is zeroed on every exit path (INVARIANT-6).
 * - Verification is variable time by design; every one of its inputs is
 *   public.  This matches `ama_secp256k1_ecdsa_verify` and
 *   `ama_ed25519_batch_verify`.
 *
 * Malleability posture (INVARIANT-34).  Low-`s` is a property of a
 * sign/verify *pair*, not of either half, and both halves are off by default
 * on these curves:
 *
 *   - Signing emits RFC 6979's `s` verbatim, so `ama_nistp_ecdsa_sign`
 *     reproduces the RFC's own Appendix A.2.5/A.2.6/A.2.7 vectors exactly.
 *     `AMA_NISTP_ECDSA_SIGN_LOW_S` opts in to normalisation.
 *   - Verification accepts either representative, because that is what
 *     X9.62 / FIPS 186-5 / TLS / JWS / WebAuthn / X.509 require and the entire
 *     point of these curves here is interoperating with them.
 *     `AMA_NISTP_ECDSA_REQUIRE_LOW_S` opts in to rejection.
 *
 * Normalising while verifying permissively — which this file did before —
 * prevents nothing: the twin of an AMA signature still verifies under AMA.
 * It only costs RFC 6979 conformance.  A caller who controls both ends sets
 * both flags and gets the real property.
 *
 * The checks that do *not* cost interop — minimal DER, `r, s` strictly in
 * `[1, n-1]` rather than reduced, and public-key coordinates strictly in
 * `[0, p)` — are unconditional in every mode, exactly as INVARIANT-28/29
 * require for secp256k1.
 */

#include "../include/ama_cryptography.h"
#include "../include/ama_cpuid.h"
#include "ama_hmac_sha256.h"
#include "ama_platform_rand.h"
#include "internal/ama_once.h"

#include <stdint.h>
#include <string.h>

/* ============================================================================
 * WIDE ARITHMETIC SUPPORT
 * ============================================================================ */

#ifdef __SIZEOF_INT128__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
typedef unsigned __int128 nistp_u128;
#pragma GCC diagnostic pop
#define NISTP_HAVE_U128 1
#endif

/**
 * lo:hi = a*b + c + d.
 *
 * The maximum value is (2^64-1)^2 + 2*(2^64-1) = 2^128 - 1, so this never
 * overflows 128 bits — which is exactly the accumulation shape CIOS needs.
 */
static inline void nistp_mul_add2(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                                  uint64_t *lo, uint64_t *hi) {
#ifdef NISTP_HAVE_U128
    nistp_u128 t = (nistp_u128)a * (nistp_u128)b + (nistp_u128)c + (nistp_u128)d;
    *lo = (uint64_t)t;
    *hi = (uint64_t)(t >> 64);
#else
    uint64_t a_lo = a & 0xFFFFFFFFULL, a_hi = a >> 32;
    uint64_t b_lo = b & 0xFFFFFFFFULL, b_hi = b >> 32;
    uint64_t ll = a_lo * b_lo;
    uint64_t lh = a_lo * b_hi;
    uint64_t hl = a_hi * b_lo;
    uint64_t hh = a_hi * b_hi;
    uint64_t mid = (ll >> 32) + (lh & 0xFFFFFFFFULL) + (hl & 0xFFFFFFFFULL);
    uint64_t rlo = (ll & 0xFFFFFFFFULL) | (mid << 32);
    uint64_t rhi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
    uint64_t s;

    s = rlo + c;
    rhi += (s < rlo) ? 1u : 0u;
    rlo = s;
    s = rlo + d;
    rhi += (s < rlo) ? 1u : 0u;
    rlo = s;

    *lo = rlo;
    *hi = rhi;
#endif
}

/* ============================================================================
 * CURVE PARAMETER BLOCKS
 *
 * Every value below was generated from the SP 800-186 / FIPS 186-5 decimal
 * and hex parameters rather than typed by hand, and every derived value
 * (rr_p, rr_n, p0inv, n0inv) is *re-derived from p and n at test time* by
 * tests/c/test_nistp.c — a transcription error fails a test rather than
 * silently producing a wrong-but-self-consistent curve.
 * ============================================================================ */

#define AMA_NISTP_MAX_LIMBS 9

typedef struct {
    const char *name;
    unsigned    nlimbs;   /**< 64-bit limbs needed to hold p (and n) */
    unsigned    nbytes;   /**< octet width of a field element / scalar */
    unsigned    pbits;    /**< bit length of p */
    unsigned    qbits;    /**< bit length of n (RFC 6979 `qlen`) */
    uint64_t    p[AMA_NISTP_MAX_LIMBS];
    uint64_t    n[AMA_NISTP_MAX_LIMBS];
    uint64_t    b[AMA_NISTP_MAX_LIMBS];   /**< standard (non-Montgomery) form */
    uint64_t    gx[AMA_NISTP_MAX_LIMBS];
    uint64_t    gy[AMA_NISTP_MAX_LIMBS];
    uint64_t    rr_p[AMA_NISTP_MAX_LIMBS]; /**< R^2 mod p, R = 2^(64*nlimbs) */
    uint64_t    rr_n[AMA_NISTP_MAX_LIMBS]; /**< R^2 mod n */
    uint64_t    p0inv;                     /**< -p^-1 mod 2^64 */
    uint64_t    n0inv;                     /**< -n^-1 mod 2^64 */
} nistp_curve;

static const nistp_curve NISTP_CURVES[3] = {
    /* ---------------------------------------------------------------- P-256 */
    {
        "P-256", 4, 32, 256, 256,
        { 0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL,
          0x0000000000000000ULL, 0xFFFFFFFF00000001ULL },
        { 0xF3B9CAC2FC632551ULL, 0xBCE6FAADA7179E84ULL,
          0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL },
        { 0x3BCE3C3E27D2604BULL, 0x651D06B0CC53B0F6ULL,
          0xB3EBBD55769886BCULL, 0x5AC635D8AA3A93E7ULL },
        { 0xF4A13945D898C296ULL, 0x77037D812DEB33A0ULL,
          0xF8BCE6E563A440F2ULL, 0x6B17D1F2E12C4247ULL },
        { 0xCBB6406837BF51F5ULL, 0x2BCE33576B315ECEULL,
          0x8EE7EB4A7C0F9E16ULL, 0x4FE342E2FE1A7F9BULL },
        { 0x0000000000000003ULL, 0xFFFFFFFBFFFFFFFFULL,
          0xFFFFFFFFFFFFFFFEULL, 0x00000004FFFFFFFDULL },
        { 0x83244C95BE79EEA2ULL, 0x4699799C49BD6FA6ULL,
          0x2845B2392B6BEC59ULL, 0x66E12D94F3D95620ULL },
        0x0000000000000001ULL,
        0xCCD1C8AAEE00BC4FULL
    },
    /* ---------------------------------------------------------------- P-384 */
    {
        "P-384", 6, 48, 384, 384,
        { 0x00000000FFFFFFFFULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFFFFFFFFFEULL,
          0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL },
        { 0xECEC196ACCC52973ULL, 0x581A0DB248B0A77AULL, 0xC7634D81F4372DDFULL,
          0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL },
        { 0x2A85C8EDD3EC2AEFULL, 0xC656398D8A2ED19DULL, 0x0314088F5013875AULL,
          0x181D9C6EFE814112ULL, 0x988E056BE3F82D19ULL, 0xB3312FA7E23EE7E4ULL },
        { 0x3A545E3872760AB7ULL, 0x5502F25DBF55296CULL, 0x59F741E082542A38ULL,
          0x6E1D3B628BA79B98ULL, 0x8EB1C71EF320AD74ULL, 0xAA87CA22BE8B0537ULL },
        { 0x7A431D7C90EA0E5FULL, 0x0A60B1CE1D7E819DULL, 0xE9DA3113B5F0B8C0ULL,
          0xF8F41DBD289A147CULL, 0x5D9E98BF9292DC29ULL, 0x3617DE4A96262C6FULL },
        { 0xFFFFFFFE00000001ULL, 0x0000000200000000ULL, 0xFFFFFFFE00000000ULL,
          0x0000000200000000ULL, 0x0000000000000001ULL, 0x0000000000000000ULL },
        { 0x2D319B2419B409A9ULL, 0xFF3D81E5DF1AA419ULL, 0xBC3E483AFCB82947ULL,
          0xD40D49174AAB1CC5ULL, 0x3FB05B7A28266895ULL, 0x0C84EE012B39BF21ULL },
        0x0000000100000001ULL,
        0x6ED46089E88FDC45ULL
    },
    /* ---------------------------------------------------------------- P-521 */
    {
        "P-521", 9, 66, 521, 521,
        { 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
          0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
          0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0x00000000000001FFULL },
        { 0xBB6FB71E91386409ULL, 0x3BB5C9B8899C47AEULL, 0x7FCC0148F709A5D0ULL,
          0x51868783BF2F966BULL, 0xFFFFFFFFFFFFFFFAULL, 0xFFFFFFFFFFFFFFFFULL,
          0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0x00000000000001FFULL },
        { 0xEF451FD46B503F00ULL, 0x3573DF883D2C34F1ULL, 0x1652C0BD3BB1BF07ULL,
          0x56193951EC7E937BULL, 0xB8B489918EF109E1ULL, 0xA2DA725B99B315F3ULL,
          0x929A21A0B68540EEULL, 0x953EB9618E1C9A1FULL, 0x0000000000000051ULL },
        { 0xF97E7E31C2E5BD66ULL, 0x3348B3C1856A429BULL, 0xFE1DC127A2FFA8DEULL,
          0xA14B5E77EFE75928ULL, 0xF828AF606B4D3DBAULL, 0x9C648139053FB521ULL,
          0x9E3ECB662395B442ULL, 0x858E06B70404E9CDULL, 0x00000000000000C6ULL },
        { 0x88BE94769FD16650ULL, 0x353C7086A272C240ULL, 0xC550B9013FAD0761ULL,
          0x97EE72995EF42640ULL, 0x17AFBD17273E662CULL, 0x98F54449579B4468ULL,
          0x5C8A5FB42C7D1BD9ULL, 0x39296A789A3BC004ULL, 0x0000000000000118ULL },
        { 0x0000000000000000ULL, 0x0000400000000000ULL, 0x0000000000000000ULL,
          0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
          0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL },
        { 0x137CD04DCF15DD04ULL, 0xF707BADCE5547EA3ULL, 0x12A78D38794573FFULL,
          0xD3721EF557F75E06ULL, 0xDD6E23D82E49C7DBULL, 0xCFF3D142B7756E3EULL,
          0x5BCC6D61A8E567BCULL, 0x2D8E03D1492D0D45ULL, 0x000000000000003DULL },
        0x0000000000000001ULL,
        0x1D2F5CCD79A995C7ULL
    }
};

static const nistp_curve *nistp_lookup(ama_nist_curve_t curve) {
    switch (curve) {
        case AMA_NIST_CURVE_P256: return &NISTP_CURVES[0];
        case AMA_NIST_CURVE_P384: return &NISTP_CURVES[1];
        case AMA_NIST_CURVE_P521: return &NISTP_CURVES[2];
        default:                  return NULL;
    }
}

/* ============================================================================
 * BIG-INTEGER PRIMITIVES (constant time)
 *
 * All operate on `nl` little-endian 64-bit limbs.  "ct" in a name means the
 * function's timing and memory-access pattern are independent of its operand
 * *values*; `nl` itself is a public curve parameter.
 * ============================================================================ */

/** Mask of all ones when `c != 0`, all zeros when `c == 0`. */
static inline uint64_t nistp_mask64(uint64_t c) {
    return (uint64_t)0 - (uint64_t)((c | (~c + 1u)) >> 63);
}

/** 1 when every limb is zero, else 0.  Constant time. */
static int nistp_is_zero(const uint64_t *a, unsigned nl) {
    uint64_t acc = 0;
    unsigned i;
    for (i = 0; i < nl; i++)
        acc |= a[i];
    return (int)((~nistp_mask64(acc)) & 1u);
}

/** 1 when a == b, else 0.  Constant time. */
static int nistp_equal(const uint64_t *a, const uint64_t *b, unsigned nl) {
    uint64_t acc = 0;
    unsigned i;
    for (i = 0; i < nl; i++)
        acc |= (a[i] ^ b[i]);
    return (int)((~nistp_mask64(acc)) & 1u);
}

/** r = a + b; returns the carry out (0 or 1).  Constant time. */
static uint64_t nistp_add(uint64_t *r, const uint64_t *a, const uint64_t *b, unsigned nl) {
    uint64_t carry = 0;
    unsigned i;
    for (i = 0; i < nl; i++) {
        uint64_t s = a[i] + carry;
        uint64_t c1 = (s < carry) ? 1u : 0u;
        uint64_t t = s + b[i];
        carry = c1 + ((t < s) ? 1u : 0u);
        r[i] = t;
    }
    return carry;
}

/** r = a - b; returns the borrow out (0 or 1).  Constant time. */
static uint64_t nistp_sub(uint64_t *r, const uint64_t *a, const uint64_t *b, unsigned nl) {
    uint64_t borrow = 0;
    unsigned i;
    for (i = 0; i < nl; i++) {
        uint64_t s = a[i] - borrow;
        uint64_t b1 = (a[i] < borrow) ? 1u : 0u;
        uint64_t t = s - b[i];
        borrow = b1 + ((s < b[i]) ? 1u : 0u);
        r[i] = t;
    }
    return borrow;
}

/** r = mask ? a : b, where mask is all-ones or all-zeros.  Constant time. */
static void nistp_select(uint64_t *r, const uint64_t *a, const uint64_t *b,
                         uint64_t mask, unsigned nl) {
    unsigned i;
    for (i = 0; i < nl; i++)
        r[i] = (a[i] & mask) | (b[i] & ~mask);
}

/** 1 when a < m, else 0.  Constant time — this is the canonicality gate. */
static int nistp_lt(const uint64_t *a, const uint64_t *m, unsigned nl) {
    uint64_t scratch[AMA_NISTP_MAX_LIMBS];
    return (int)nistp_sub(scratch, a, m, nl);
}

/**
 * r = a mod m, valid only when a < 2*m.  One conditional subtraction.
 * `carry` is the (0 or 1) limb above a[nl-1]; pass 0 when there is none.
 *
 * Deliberately does not zero its stack temporary.  This sits inside every
 * Montgomery multiply, so a `memzero` here would put a compiler barrier in
 * the innermost arithmetic loop; the difference it holds is a partial
 * reduction of a value the caller is about to zero anyway.  Secret material
 * is zeroed at the operation boundary instead — the same division of labour
 * as `ama_secp256k1.c`'s `sc_cond_sub_n`.
 */
static void nistp_cond_sub_mod(uint64_t *r, const uint64_t *a, uint64_t carry,
                               const uint64_t *m, unsigned nl) {
    uint64_t diff[AMA_NISTP_MAX_LIMBS];
    uint64_t borrow = nistp_sub(diff, a, m, nl);
    /* Take the difference when a >= m (borrow == 0) or when the extra high
     * limb is set (a is unconditionally >= m in that case). */
    uint64_t take = nistp_mask64(carry | (borrow ^ 1u));
    nistp_select(r, diff, a, take, nl);
}

/** Big-endian octets -> limbs.  `nbytes` must be a multiple-of-8 offset grid. */
static void nistp_from_bytes(uint64_t *r, const uint8_t *in, unsigned nbytes, unsigned nl) {
    unsigned i;
    memset(r, 0, sizeof(uint64_t) * AMA_NISTP_MAX_LIMBS);
    (void)nl;
    for (i = 0; i < nbytes; i++) {
        unsigned bitpos = (nbytes - 1u - i) * 8u;
        r[bitpos >> 6] |= (uint64_t)in[i] << (bitpos & 63u);
    }
}

/** limbs -> big-endian octets. */
static void nistp_to_bytes(uint8_t *out, const uint64_t *a, unsigned nbytes) {
    unsigned i;
    for (i = 0; i < nbytes; i++) {
        unsigned bitpos = (nbytes - 1u - i) * 8u;
        out[i] = (uint8_t)(a[bitpos >> 6] >> (bitpos & 63u));
    }
}

/* ============================================================================
 * MONTGOMERY ARITHMETIC (CIOS)
 * ============================================================================ */

/**
 * r = a * b * R^-1 mod m, with R = 2^(64*nl).
 *
 * Requires a < m and b < m.  Under that precondition the CIOS accumulator is
 * bounded by 2*m, so the single conditional subtraction at the end is
 * sufficient — this holds for every modulus in NISTP_CURVES because each has
 * either exactly 64*nl bits (P-256/P-384) or is far below R (P-521), and is
 * asserted directly by tests/c/test_nistp.c over boundary operands.
 *
 * Fully constant time: the inner loops are fixed-trip and the only data
 * dependence is arithmetic.
 */
#if defined(AMA_HAVE_NISTP_MONT_MULX_IMPL)
/* Four-limb MULX+ADCX/ADOX Montgomery multiply — src/c/x86/ama_nistp_mont_mulx.c.
 * Covers P-256's field and its scalar field, which between them account for
 * every Montgomery multiply a P-256 signature or verification performs. */
extern void ama_nistp_mont_mul4_mulx(uint64_t r[4], const uint64_t a[4],
                                     const uint64_t b[4], const uint64_t m[4],
                                     uint64_t m0inv);

/* CPUID gate, resolved once.
 *
 * `ama_has_bmi2()` and `ama_has_adx()` are each a load-and-branch after
 * their shared one-shot probe, but this predicate is consulted on the order
 * of ten thousand times per verification, so it is worth collapsing to a
 * single relaxed load.  The write is idempotent — every thread computes the
 * same value from the same cached CPUID result — and a torn read is not
 * possible for an aligned int, so no synchronisation is needed beyond the
 * once-guard already inside the CPUID getters. */
static int nistp_mulx_gate = -1;

static inline int nistp_use_mulx4(void) {
    int g = nistp_mulx_gate;
    if (g < 0) {
        g = (ama_has_bmi2() && ama_has_adx()) ? 1 : 0;
        nistp_mulx_gate = g;
    }
    return g;
}
#endif /* AMA_HAVE_NISTP_MONT_MULX_IMPL */

/* Portable "inline this even at -O0" marker.
 *
 * The point of `nistp_mont_mul_body` is that the 4-limb wrapper below
 * instantiates it with a *literal* limb count, so both loops unroll.  That
 * only happens if the body is actually inlined, which is a request no
 * standard C spelling can make — hence the per-compiler form.  MSVC spells
 * it `__forceinline` and rejects `__attribute__` outright; this file is in
 * the unconditional source list, so an unguarded GNU attribute here breaks
 * every MSVC build.  Same split as include/ama_uint128.h. */
#if defined(__GNUC__) || defined(__clang__)
#define AMA_NISTP_ALWAYS_INLINE static inline __attribute__((always_inline))
#elif defined(_MSC_VER)
#define AMA_NISTP_ALWAYS_INLINE static __forceinline
#else
#define AMA_NISTP_ALWAYS_INLINE static inline
#endif

/* Body of the CIOS multiply, always_inline so the two wrappers below can
 * instantiate it with the limb count as a literal.  The 4-limb wrapper is
 * what P-256 reaches on a host without ADX (and what every non-x86 host
 * reaches), and constant-folding `nl` there lets the compiler unroll both
 * loops: measured 102 cycles against 178 for the runtime-`nl` form. */
AMA_NISTP_ALWAYS_INLINE
void nistp_mont_mul_body(uint64_t *r, const uint64_t *a, const uint64_t *b,
                         const uint64_t *m, uint64_t m0inv, unsigned nl) {
    uint64_t t[AMA_NISTP_MAX_LIMBS + 2];
    unsigned i, j;

    memset(t, 0, sizeof(t));

    for (i = 0; i < nl; i++) {
        uint64_t carry = 0, lo, hi, mu, s;

        /* t = t + a * b[i] */
        for (j = 0; j < nl; j++) {
            nistp_mul_add2(a[j], b[i], t[j], carry, &lo, &hi);
            t[j] = lo;
            carry = hi;
        }
        s = t[nl] + carry;
        t[nl + 1] = (s < carry) ? 1u : 0u;
        t[nl] = s;

        /* t = (t + mu * m) / 2^64 */
        mu = t[0] * m0inv;
        nistp_mul_add2(mu, m[0], t[0], 0, &lo, &hi);
        carry = hi;                     /* lo is zero by construction of mu */
        (void)lo;
        for (j = 1; j < nl; j++) {
            nistp_mul_add2(mu, m[j], t[j], carry, &lo, &hi);
            t[j - 1] = lo;
            carry = hi;
        }
        s = t[nl] + carry;
        t[nl - 1] = s;
        t[nl] = t[nl + 1] + ((s < carry) ? 1u : 0u);
    }

    nistp_cond_sub_mod(r, t, t[nl], m, nl);
}

static void nistp_mont_mul(uint64_t *r, const uint64_t *a, const uint64_t *b,
                           const uint64_t *m, uint64_t m0inv, unsigned nl) {
    if (nl == 4) {
#if defined(AMA_HAVE_NISTP_MONT_MULX_IMPL)
        if (nistp_use_mulx4()) {
            ama_nistp_mont_mul4_mulx(r, a, b, m, m0inv);
            return;
        }
#endif
        nistp_mont_mul_body(r, a, b, m, m0inv, 4);
        return;
    }
    nistp_mont_mul_body(r, a, b, m, m0inv, nl);
}

static void nistp_mont_sqr(uint64_t *r, const uint64_t *a,
                           const uint64_t *m, uint64_t m0inv, unsigned nl) {
    nistp_mont_mul(r, a, a, m, m0inv, nl);
}

/** r = (a + b) mod m, for a, b < m. */
static void nistp_mod_add(uint64_t *r, const uint64_t *a, const uint64_t *b,
                          const uint64_t *m, unsigned nl) {
    uint64_t sum[AMA_NISTP_MAX_LIMBS];
    uint64_t carry = nistp_add(sum, a, b, nl);
    nistp_cond_sub_mod(r, sum, carry, m, nl);
}

/** r = (a - b) mod m, for a, b < m. */
static void nistp_mod_sub(uint64_t *r, const uint64_t *a, const uint64_t *b,
                          const uint64_t *m, unsigned nl) {
    uint64_t diff[AMA_NISTP_MAX_LIMBS], fixed[AMA_NISTP_MAX_LIMBS];
    uint64_t borrow = nistp_sub(diff, a, b, nl);
    (void)nistp_add(fixed, diff, m, nl);
    nistp_select(r, fixed, diff, nistp_mask64(borrow), nl);
}

/** Convert standard form -> Montgomery form. */
static void nistp_to_mont(uint64_t *r, const uint64_t *a, const uint64_t *rr,
                          const uint64_t *m, uint64_t m0inv, unsigned nl) {
    nistp_mont_mul(r, a, rr, m, m0inv, nl);
}

/** Convert Montgomery form -> standard form (multiply by 1). */
static void nistp_from_mont(uint64_t *r, const uint64_t *a,
                            const uint64_t *m, uint64_t m0inv, unsigned nl) {
    uint64_t one[AMA_NISTP_MAX_LIMBS];
    memset(one, 0, sizeof(one));
    one[0] = 1;
    nistp_mont_mul(r, a, one, m, m0inv, nl);
}

/** Montgomery-form representation of 1, i.e. R mod m. */
static void nistp_mont_one(uint64_t *r, const uint64_t *rr,
                           const uint64_t *m, uint64_t m0inv, unsigned nl) {
    uint64_t one[AMA_NISTP_MAX_LIMBS];
    memset(one, 0, sizeof(one));
    one[0] = 1;
    nistp_mont_mul(r, one, rr, m, m0inv, nl);
}

/**
 * r = a^e mod m in Montgomery form, left-to-right square-and-multiply.
 *
 * `e` is always a *public* constant here (p-2, n-2 or (p+1)/4), so branching
 * on its bits leaks nothing about the base.  The base — which may be secret —
 * is only ever fed to `nistp_mont_mul`/`nistp_mont_sqr`, both constant time.
 */
static void nistp_mont_pow(uint64_t *r, const uint64_t *a,
                           const uint64_t *e, unsigned ebits,
                           const uint64_t *rr, const uint64_t *m,
                           uint64_t m0inv, unsigned nl) {
    uint64_t acc[AMA_NISTP_MAX_LIMBS];
    int i;

    nistp_mont_one(acc, rr, m, m0inv, nl);
    for (i = (int)ebits - 1; i >= 0; i--) {
        nistp_mont_sqr(acc, acc, m, m0inv, nl);
        if ((e[(unsigned)i >> 6] >> ((unsigned)i & 63u)) & 1u)
            nistp_mont_mul(acc, acc, a, m, m0inv, nl);
    }
    memcpy(r, acc, sizeof(uint64_t) * nl);
    ama_secure_memzero(acc, sizeof(acc));
}

/** e = m - 2 (both m and the result are public curve data). */
static void nistp_exp_minus2(uint64_t *e, const uint64_t *m, unsigned nl) {
    uint64_t two[AMA_NISTP_MAX_LIMBS];
    memset(two, 0, sizeof(two));
    two[0] = 2;
    (void)nistp_sub(e, m, two, nl);
}

/** Modular inverse via Fermat: r = a^(m-2) mod m.  a must be nonzero. */
static void nistp_mont_inv(uint64_t *r, const uint64_t *a,
                           const uint64_t *rr, const uint64_t *m,
                           unsigned mbits, uint64_t m0inv, unsigned nl) {
    uint64_t e[AMA_NISTP_MAX_LIMBS];
    nistp_exp_minus2(e, m, nl);
    nistp_mont_pow(r, a, e, mbits, rr, m, m0inv, nl);
    ama_secure_memzero(e, sizeof(e));
}

/* ============================================================================
 * POINT ARITHMETIC — Jacobian coordinates, a = -3
 *
 * A point (X, Y, Z) represents the affine point (X/Z^2, Y/Z^3).  Z == 0 is the
 * point at infinity.  All coordinates are held in Montgomery form.
 * ============================================================================ */

typedef struct {
    uint64_t X[AMA_NISTP_MAX_LIMBS];
    uint64_t Y[AMA_NISTP_MAX_LIMBS];
    uint64_t Z[AMA_NISTP_MAX_LIMBS];
} nistp_jac;

static int nistp_jac_is_infinity(const nistp_jac *p, unsigned nl) {
    return nistp_is_zero(p->Z, nl);
}

/**
 * The point at infinity.
 *
 * Only Z == 0 carries meaning; X and Y are never read for their value on any
 * path (doubling an infinity point reproduces Z3 = 0 for any X, Y, and
 * `nistp_jac_to_affine` refuses to convert it at all).  They are set to a
 * small nonzero constant rather than to the Montgomery encoding of 1 purely
 * so this costs a `memset` instead of two Montgomery multiplications —
 * `nistp_jac_add` constructs an infinity on every single call.
 */
static void nistp_jac_set_infinity(nistp_jac *p) {
    memset(p, 0, sizeof(*p));
    p->X[0] = 1;
    p->Y[0] = 1;
}

/**
 * R = 2*P using the `dbl-2001-b` formula for a = -3 (Bernstein–Lange EFD).
 *
 *   delta = Z1^2 ; gamma = Y1^2 ; beta = X1*gamma
 *   alpha = 3*(X1-delta)*(X1+delta)          [ == 3*X1^2 - 3*Z1^4, i.e. a = -3 ]
 *   X3 = alpha^2 - 8*beta
 *   Z3 = (Y1+Z1)^2 - gamma - delta
 *   Y3 = alpha*(4*beta - X3) - 8*gamma^2
 *
 * Correct for P at infinity without a branch: Z1 = 0 gives delta = 0 and
 * Z3 = (Y1)^2 - gamma - 0 = 0, so infinity doubles to infinity.  Correct for
 * Y1 = 0 (a 2-torsion point) too: Z3 = 0.  Neither NIST prime curve has a
 * 2-torsion point in the prime-order group, but the formula does not care.
 */
static void nistp_jac_double(nistp_jac *r, const nistp_jac *p, const nistp_curve *c) {
    const uint64_t *m = c->p;
    uint64_t m0 = c->p0inv;
    unsigned nl = c->nlimbs;
    uint64_t delta[AMA_NISTP_MAX_LIMBS], gamma[AMA_NISTP_MAX_LIMBS];
    uint64_t beta[AMA_NISTP_MAX_LIMBS], alpha[AMA_NISTP_MAX_LIMBS];
    uint64_t t0[AMA_NISTP_MAX_LIMBS], t1[AMA_NISTP_MAX_LIMBS];
    nistp_jac out;

    nistp_mont_sqr(delta, p->Z, m, m0, nl);          /* delta = Z1^2 */
    nistp_mont_sqr(gamma, p->Y, m, m0, nl);          /* gamma = Y1^2 */
    nistp_mont_mul(beta, p->X, gamma, m, m0, nl);    /* beta  = X1*gamma */

    nistp_mod_sub(t0, p->X, delta, m, nl);           /* X1 - delta */
    nistp_mod_add(t1, p->X, delta, m, nl);           /* X1 + delta */
    nistp_mont_mul(alpha, t0, t1, m, m0, nl);
    nistp_mod_add(t0, alpha, alpha, m, nl);
    nistp_mod_add(alpha, t0, alpha, m, nl);          /* alpha = 3*(X1-d)(X1+d) */

    /* X3 = alpha^2 - 8*beta */
    nistp_mont_sqr(out.X, alpha, m, m0, nl);
    nistp_mod_add(t0, beta, beta, m, nl);            /* 2*beta */
    nistp_mod_add(t0, t0, t0, m, nl);                /* 4*beta */
    nistp_mod_add(t1, t0, t0, m, nl);                /* 8*beta */
    nistp_mod_sub(out.X, out.X, t1, m, nl);

    /* Z3 = (Y1+Z1)^2 - gamma - delta */
    nistp_mod_add(t1, p->Y, p->Z, m, nl);
    nistp_mont_sqr(out.Z, t1, m, m0, nl);
    nistp_mod_sub(out.Z, out.Z, gamma, m, nl);
    nistp_mod_sub(out.Z, out.Z, delta, m, nl);

    /* Y3 = alpha*(4*beta - X3) - 8*gamma^2   (t0 still holds 4*beta) */
    nistp_mod_sub(t1, t0, out.X, m, nl);
    nistp_mont_mul(out.Y, alpha, t1, m, m0, nl);
    nistp_mont_sqr(t1, gamma, m, m0, nl);            /* gamma^2 */
    nistp_mod_add(t1, t1, t1, m, nl);
    nistp_mod_add(t1, t1, t1, m, nl);
    nistp_mod_add(t1, t1, t1, m, nl);                /* 8*gamma^2 */
    nistp_mod_sub(out.Y, out.Y, t1, m, nl);

    *r = out;

}

/**
 * R = P + Q (`add-2007-bl`), with every exceptional case resolved branchlessly.
 *
 * The generic chain is wrong when H == 0 (P and Q share an x-coordinate) and
 * when either input is at infinity.  Rather than branch — which would leak the
 * scalar bit pattern on the signing path — all candidates are computed and
 * selected with masks, exactly as `ama_secp256k1.c` does:
 *
 *   H == 0 && R == 0 -> 2*P      (P == Q)
 *   H == 0 && R != 0 -> infinity (P == -Q)
 *   Z1 == 0          -> Q
 *   Z2 == 0          -> P
 *
 * The unconditional doubling this costs is what buys the fixed-window scalar
 * multiplication the right to keep `infinity` in its table slot 0 without any
 * scalar-dependent special-casing.
 */
static void nistp_jac_add(nistp_jac *r, const nistp_jac *p, const nistp_jac *q,
                          const nistp_curve *c) {
    const uint64_t *m = c->p;
    uint64_t m0 = c->p0inv;
    unsigned nl = c->nlimbs;
    uint64_t z1z1[AMA_NISTP_MAX_LIMBS], z2z2[AMA_NISTP_MAX_LIMBS];
    uint64_t u1[AMA_NISTP_MAX_LIMBS], u2[AMA_NISTP_MAX_LIMBS];
    uint64_t s1[AMA_NISTP_MAX_LIMBS], s2[AMA_NISTP_MAX_LIMBS];
    uint64_t h[AMA_NISTP_MAX_LIMBS], rr[AMA_NISTP_MAX_LIMBS];
    uint64_t ii[AMA_NISTP_MAX_LIMBS], jj[AMA_NISTP_MAX_LIMBS];
    uint64_t vv[AMA_NISTP_MAX_LIMBS], t0[AMA_NISTP_MAX_LIMBS];
    nistp_jac out, doubled, inf;
    uint64_t mask_h, mask_r, mask_p, mask_q;
    unsigned k;

    nistp_mont_sqr(z1z1, p->Z, m, m0, nl);
    nistp_mont_sqr(z2z2, q->Z, m, m0, nl);
    nistp_mont_mul(u1, p->X, z2z2, m, m0, nl);
    nistp_mont_mul(u2, q->X, z1z1, m, m0, nl);

    nistp_mont_mul(t0, z2z2, q->Z, m, m0, nl);
    nistp_mont_mul(s1, p->Y, t0, m, m0, nl);
    nistp_mont_mul(t0, z1z1, p->Z, m, m0, nl);
    nistp_mont_mul(s2, q->Y, t0, m, m0, nl);

    nistp_mod_sub(h, u2, u1, m, nl);                 /* H = U2 - U1 */
    nistp_mod_sub(rr, s2, s1, m, nl);
    nistp_mod_add(rr, rr, rr, m, nl);                /* r = 2*(S2 - S1) */

    nistp_mod_add(t0, h, h, m, nl);                  /* 2H */
    nistp_mont_sqr(ii, t0, m, m0, nl);               /* I = (2H)^2 */
    nistp_mont_mul(jj, h, ii, m, m0, nl);            /* J = H*I */
    nistp_mont_mul(vv, u1, ii, m, m0, nl);           /* V = U1*I */

    /* X3 = r^2 - J - 2*V */
    nistp_mont_sqr(out.X, rr, m, m0, nl);
    nistp_mod_sub(out.X, out.X, jj, m, nl);
    nistp_mod_sub(out.X, out.X, vv, m, nl);
    nistp_mod_sub(out.X, out.X, vv, m, nl);

    /* Y3 = r*(V - X3) - 2*S1*J */
    nistp_mod_sub(t0, vv, out.X, m, nl);
    nistp_mont_mul(out.Y, rr, t0, m, m0, nl);
    nistp_mont_mul(t0, s1, jj, m, m0, nl);
    nistp_mod_add(t0, t0, t0, m, nl);
    nistp_mod_sub(out.Y, out.Y, t0, m, nl);

    /* Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) * H */
    nistp_mod_add(t0, p->Z, q->Z, m, nl);
    nistp_mont_sqr(out.Z, t0, m, m0, nl);
    nistp_mod_sub(out.Z, out.Z, z1z1, m, nl);
    nistp_mod_sub(out.Z, out.Z, z2z2, m, nl);
    nistp_mont_mul(out.Z, out.Z, h, m, m0, nl);

    /* Exceptional-case resolution. */
    nistp_jac_double(&doubled, p, c);
    nistp_jac_set_infinity(&inf);

    mask_h = nistp_mask64((uint64_t)nistp_is_zero(h, nl));
    mask_r = nistp_mask64((uint64_t)nistp_is_zero(rr, nl));
    mask_p = nistp_mask64((uint64_t)nistp_jac_is_infinity(p, nl));
    mask_q = nistp_mask64((uint64_t)nistp_jac_is_infinity(q, nl));

    for (k = 0; k < nl; k++) {
        uint64_t selx = (doubled.X[k] & mask_r) | (inf.X[k] & ~mask_r);
        uint64_t sely = (doubled.Y[k] & mask_r) | (inf.Y[k] & ~mask_r);
        uint64_t selz = (doubled.Z[k] & mask_r) | (inf.Z[k] & ~mask_r);

        out.X[k] = (selx & mask_h) | (out.X[k] & ~mask_h);
        out.Y[k] = (sely & mask_h) | (out.Y[k] & ~mask_h);
        out.Z[k] = (selz & mask_h) | (out.Z[k] & ~mask_h);

        out.X[k] = (q->X[k] & mask_p) | (out.X[k] & ~mask_p);
        out.Y[k] = (q->Y[k] & mask_p) | (out.Y[k] & ~mask_p);
        out.Z[k] = (q->Z[k] & mask_p) | (out.Z[k] & ~mask_p);

        out.X[k] = (p->X[k] & mask_q) | (out.X[k] & ~mask_q);
        out.Y[k] = (p->Y[k] & mask_q) | (out.Y[k] & ~mask_q);
        out.Z[k] = (p->Z[k] & mask_q) | (out.Z[k] & ~mask_q);
    }

    *r = out;

}

/**
 * Jacobian -> affine (Montgomery form in, Montgomery form out).
 * Returns 0 when the input is the point at infinity (outputs untouched).
 */
static int nistp_jac_to_affine(uint64_t *x, uint64_t *y, const nistp_jac *p,
                               const nistp_curve *c) {
    uint64_t zi[AMA_NISTP_MAX_LIMBS], zi2[AMA_NISTP_MAX_LIMBS], zi3[AMA_NISTP_MAX_LIMBS];
    unsigned nl = c->nlimbs;

    if (nistp_jac_is_infinity(p, nl))
        return 0;

    nistp_mont_inv(zi, p->Z, c->rr_p, c->p, c->pbits, c->p0inv, nl);
    nistp_mont_sqr(zi2, zi, c->p, c->p0inv, nl);
    nistp_mont_mul(zi3, zi2, zi, c->p, c->p0inv, nl);
    nistp_mont_mul(x, p->X, zi2, c->p, c->p0inv, nl);
    nistp_mont_mul(y, p->Y, zi3, c->p, c->p0inv, nl);

    return 1;
}

/* ============================================================================
 * SCALAR MULTIPLICATION
 * ============================================================================ */

#define NISTP_WINDOW_BITS  4
#define NISTP_TABLE_SIZE   (1 << NISTP_WINDOW_BITS)

/**
 * Constant-time R = k * P.
 *
 * Fixed 4-bit window.  The precomputed table holds [0]P .. [15]P, and slot 0
 * really is the point at infinity — legal here only because `nistp_jac_add`
 * resolves an infinity operand branchlessly, so a zero window digit costs the
 * same time and takes the same memory path as any other digit.
 *
 * The table read is a full linear scan: every one of the 16 entries is loaded
 * and masked on every window, so the memory-access trace is independent of the
 * scalar.  `k` is consumed as `nbytes` big-endian octets and is *not* required
 * to be reduced; callers that pass a secret scalar are responsible for its
 * range, which every caller in this file checks before arriving here.
 */
static void nistp_scalar_mul(nistp_jac *out, const uint8_t *k,
                             const nistp_jac *base, const nistp_curve *c) {
    nistp_jac table[NISTP_TABLE_SIZE];
    nistp_jac acc, sel;
    unsigned nl = c->nlimbs;
    unsigned nwin = c->nbytes * (8u / NISTP_WINDOW_BITS);
    unsigned w, i, limb;

    nistp_jac_set_infinity(&table[0]);
    table[1] = *base;
    for (i = 2; i < NISTP_TABLE_SIZE; i++)
        nistp_jac_add(&table[i], &table[i - 1], base, c);

    nistp_jac_set_infinity(&acc);

    for (w = 0; w < nwin; w++) {
        unsigned byte_index = w >> 1;
        unsigned shift = (w & 1u) ? 0u : 4u;   /* high nibble first */
        uint64_t digit = (uint64_t)((k[byte_index] >> shift) & 0x0Fu);

        if (w != 0) {
            nistp_jac_double(&acc, &acc, c);
            nistp_jac_double(&acc, &acc, c);
            nistp_jac_double(&acc, &acc, c);
            nistp_jac_double(&acc, &acc, c);
        }

        memset(&sel, 0, sizeof(sel));
        for (i = 0; i < NISTP_TABLE_SIZE; i++) {
            uint64_t mask = nistp_mask64((uint64_t)i ^ digit);  /* 0 when equal */
            mask = ~mask;                                        /* all-ones when equal */
            for (limb = 0; limb < nl; limb++) {
                sel.X[limb] |= table[i].X[limb] & mask;
                sel.Y[limb] |= table[i].Y[limb] & mask;
                sel.Z[limb] |= table[i].Z[limb] & mask;
            }
        }
        nistp_jac_add(&acc, &acc, &sel, c);
    }

    *out = acc;

    ama_secure_memzero(table, sizeof(table));
    ama_secure_memzero(&acc, sizeof(acc));
    ama_secure_memzero(&sel, sizeof(sel));
}

/* ============================================================================
 * FIXED-BASE COMB FOR THE GENERATOR
 * ============================================================================ */

/**
 * The generator is a *public constant*, so the doublings its scalar
 * multiplication performs can be done once, at start-up, instead of on every
 * call.  That is the whole idea here, and it is where the time goes:
 * `nistp_scalar_mul` on P-521 runs 132 windows x 4 doublings = 528 doublings
 * plus 132 additions, and 528 doublings is most of a 2.1 ms operation.
 *
 * The comb splits the scalar into `NISTP_COMB_BLOCKS` equal blocks and
 * precomputes every subset sum of the block-aligned multiples
 * `2^(e*j) * G`.  Then one pass over `e` bit positions does *one* doubling and
 * *one* addition each:
 *
 *     acc = 0
 *     for t = e-1 down to 0:
 *         acc = 2*acc
 *         digit = bit(k, t) | bit(k, t+e)<<1 | ... | bit(k, t+3e)<<3
 *         acc = acc + T[digit]
 *
 * At P-521 that is 131 doublings and 131 additions against 528 and 132 — the
 * doubling count falls by 4x, which is the operation the profile is made of.
 *
 * **Four blocks, deliberately, and not eight.**  A comb's table has 2^blocks
 * entries, and the table must be read with a *full linear scan* to keep the
 * memory-access trace independent of the scalar (the same requirement, and the
 * same reason, as in `nistp_scalar_mul`).  Doubling the block count halves the
 * iterations and doubles the per-iteration scan, so the win flattens quickly
 * while the constant-time scan cost grows without bound.  Sixteen entries also
 * keeps the scan *identical in shape* to the one already reviewed for the
 * variable-base path, and the table at 3.5 KB per curve fits comfortably in
 * L1 — an 8-block table would be 56 KB per curve and would not.
 *
 * **Only the generator.**  ECDH multiplies a *peer-supplied* point and keeps
 * `nistp_scalar_mul`: precomputing for a base that changes every call buys
 * nothing, and a table built from attacker-supplied input is a surface this
 * does not need.
 *
 * **Initialised through the platform once-primitive, per curve.**  It used to
 * be a plain `int ready` flag with a comment calling the race benign because
 * "the table holds only public data, so two threads write identical bytes".
 * That reasoning was wrong twice over, and INVARIANT-15 prohibits the pattern
 * outright for exactly these reasons:
 *
 *   - `nistp_comb_build` does not only *write* the table, it *reads it back*:
 *     entry `i` is built by adding to entry `i & ~(1<<low)`.  So two threads
 *     racing produce read/write races on the table, not write/write races on
 *     identical bytes, and a partially written entry is not garbage — the
 *     table lives in BSS, and a Jacobian point whose `Z` limbs are still zero
 *     *is* the point at infinity.  A wrong-but-well-formed answer.
 *   - Even for genuinely identical bytes, a plain flag supplies no
 *     happens-before edge.  On a weakly-ordered target — AArch64 and POWER are
 *     both supported here — a third thread can observe `ready == 1` before the
 *     table stores are visible and multiply against an entry that reads as
 *     infinity, yielding a silently wrong public key or a wrong `r`.  Nothing
 *     reports it; the first thing to notice would be a peer.
 *
 * `pthread_once` / `InitOnceExecuteOnce` gives both exactly-once execution and
 * the visibility guarantee.  After the once-call returns, the table is
 * immutable for the life of the process, so the hot path is a plain read.
 */
#define NISTP_COMB_BLOCKS  4
#define NISTP_COMB_SIZE    (1u << NISTP_COMB_BLOCKS)

typedef struct {
    nistp_jac table[NISTP_COMB_SIZE];
    unsigned  block_bits;   /**< `e`: bits per block, ceil(qbits / blocks) */
} nistp_comb;

static nistp_comb NISTP_COMBS[3];

/* One flag per curve: a caller that only ever uses P-256 should not pay for
 * P-521's table, and a shared flag would force all three to be built together.
 * The trampolines exist because the once-primitive takes `void (*)(void)`. */
static AMA_ONCE_FLAG NISTP_COMB_ONCE[3] = {
    AMA_ONCE_FLAG_INIT, AMA_ONCE_FLAG_INIT, AMA_ONCE_FLAG_INIT
};

/** The generator in Jacobian/Montgomery form. */
static void nistp_generator(nistp_jac *g, const nistp_curve *c) {
    nistp_to_mont(g->X, c->gx, c->rr_p, c->p, c->p0inv, c->nlimbs);
    nistp_to_mont(g->Y, c->gy, c->rr_p, c->p, c->p0inv, c->nlimbs);
    nistp_mont_one(g->Z, c->rr_p, c->p, c->p0inv, c->nlimbs);
}

/**
 * Build the comb table: `T[i] = sum over set bits j of i` of `2^(e*j) * G`.
 *
 * Built from repeated doubling of the generator only — no scalar
 * multiplication, so this cannot depend on the very routine it accelerates.
 */
static void nistp_comb_build(nistp_comb *comb, const nistp_curve *c) {
    nistp_jac base[NISTP_COMB_BLOCKS];
    unsigned e, i, j, b;

    /* `e` covers the scalar's full width: a scalar is `nbytes` octets and the
     * caller is not required to have reduced it, so the comb must span every
     * bit those octets can hold, not just `qbits`. */
    e = (c->nbytes * 8u + NISTP_COMB_BLOCKS - 1u) / NISTP_COMB_BLOCKS;
    comb->block_bits = e;

    nistp_generator(&base[0], c);
    for (j = 1; j < NISTP_COMB_BLOCKS; j++) {
        base[j] = base[j - 1];
        for (b = 0; b < e; b++)
            nistp_jac_double(&base[j], &base[j], c);
    }

    nistp_jac_set_infinity(&comb->table[0]);
    for (i = 1; i < NISTP_COMB_SIZE; i++) {
        /* Lowest set bit of `i`, added to the entry for `i` without it. */
        unsigned low = 0;
        while (!((i >> low) & 1u))
            low++;
        nistp_jac_add(&comb->table[i], &comb->table[i & ~(1u << low)],
                      &base[low], c);
    }
}

/* Once-trampolines. `NISTP_CURVES` is indexed 0/1/2 for P-256/P-384/P-521 and
 * `NISTP_COMBS` is parallel to it, so each of these builds exactly one. */
static void nistp_comb_build_0(void) { nistp_comb_build(&NISTP_COMBS[0], &NISTP_CURVES[0]); }
static void nistp_comb_build_1(void) { nistp_comb_build(&NISTP_COMBS[1], &NISTP_CURVES[1]); }
static void nistp_comb_build_2(void) { nistp_comb_build(&NISTP_COMBS[2], &NISTP_CURVES[2]); }

static void (*const NISTP_COMB_BUILDERS[3])(void) = {
    nistp_comb_build_0, nistp_comb_build_1, nistp_comb_build_2
};

/**
 * Constant-time R = k * G using the comb.
 *
 * The scalar is read a bit at a time at fixed indices, so nothing about the
 * access pattern depends on its value; the table read is the same full linear
 * scan as the variable-base multiplier's.
 */
static void nistp_scalar_mul_generator(nistp_jac *out, const uint8_t *k,
                                       const nistp_curve *c) {
    unsigned idx = (unsigned)(c - &NISTP_CURVES[0]);
    nistp_comb *comb = &NISTP_COMBS[idx];
    nistp_jac acc, sel;
    unsigned nl = c->nlimbs;
    unsigned nbits = c->nbytes * 8u;
    unsigned e, i, limb;
    int t;

    AMA_CALL_ONCE(NISTP_COMB_ONCE[idx], NISTP_COMB_BUILDERS[idx]);
    e = comb->block_bits;

    nistp_jac_set_infinity(&acc);
    for (t = (int)e - 1; t >= 0; t--) {
        uint64_t digit = 0;

        nistp_jac_double(&acc, &acc, c);

        for (i = 0; i < NISTP_COMB_BLOCKS; i++) {
            unsigned bit_index = (unsigned)t + i * e;
            uint64_t bit = 0;
            if (bit_index < nbits) {
                /* `k` is big-endian: bit 0 is the low bit of the last octet. */
                unsigned byte_index = c->nbytes - 1u - (bit_index >> 3);
                bit = (uint64_t)((k[byte_index] >> (bit_index & 7u)) & 1u);
            }
            digit |= bit << i;
        }

        memset(&sel, 0, sizeof(sel));
        for (i = 0; i < NISTP_COMB_SIZE; i++) {
            uint64_t mask = nistp_mask64((uint64_t)i ^ digit);  /* 0 when equal */
            mask = ~mask;                                        /* all-ones when equal */
            for (limb = 0; limb < nl; limb++) {
                sel.X[limb] |= comb->table[i].X[limb] & mask;
                sel.Y[limb] |= comb->table[i].Y[limb] & mask;
                sel.Z[limb] |= comb->table[i].Z[limb] & mask;
            }
        }
        nistp_jac_add(&acc, &acc, &sel, c);
    }

    *out = acc;
    ama_secure_memzero(&acc, sizeof(acc));
    ama_secure_memzero(&sel, sizeof(sel));
}

/**
 * R = P + Q where Q is affine (`madd-2007-bl`), VARIABLE TIME.
 *
 * Restricted and unsafe relative to `nistp_jac_add` in two deliberate ways,
 * both of which are what make it cheaper:
 *
 *   - Q is affine, i.e. Z2 == 1.  Dropping Z2 removes Z2Z2, U1, S1 and the
 *     Z2 term of Z3 from the chain: 7M + 4S instead of 11M + 5S.
 *   - The exceptional cases branch instead of being computed and masked.
 *     `nistp_jac_add` evaluates a full doubling on every call so that its
 *     timing cannot depend on whether the inputs happened to coincide; here
 *     the doubling is taken only when it is needed.
 *
 * That branching is why this must never be reachable from signing.  Its only
 * caller is `nistp_shamir`, which ECDSA *verification* uses, where u1, u2, the
 * public key and the signature are all public by definition — the same posture
 * `ama_secp256k1.c` takes for its verify path.  Nothing secret reaches either
 * argument.
 *
 * Per addition this is 11 field multiplications against 24 for the
 * constant-time path (16 for add-2007-bl plus 8 for the unconditional
 * doubling), and a P-256 verification performs roughly 192 of them.
 */
static void nistp_jac_add_affine_vartime(nistp_jac *r, const nistp_jac *p,
                                         const uint64_t *qx, const uint64_t *qy,
                                         const nistp_curve *c) {
    const uint64_t *m = c->p;
    uint64_t m0 = c->p0inv;
    unsigned nl = c->nlimbs;
    uint64_t z1z1[AMA_NISTP_MAX_LIMBS], u2[AMA_NISTP_MAX_LIMBS];
    uint64_t s2[AMA_NISTP_MAX_LIMBS], h[AMA_NISTP_MAX_LIMBS];
    uint64_t hh[AMA_NISTP_MAX_LIMBS], ii[AMA_NISTP_MAX_LIMBS];
    uint64_t jj[AMA_NISTP_MAX_LIMBS], rr[AMA_NISTP_MAX_LIMBS];
    uint64_t vv[AMA_NISTP_MAX_LIMBS], t0[AMA_NISTP_MAX_LIMBS];
    nistp_jac out;

    /* P at infinity: the sum is Q, lifted back to Jacobian with Z = 1. */
    if (nistp_jac_is_infinity(p, nl)) {
        memcpy(r->X, qx, sizeof(uint64_t) * nl);
        memcpy(r->Y, qy, sizeof(uint64_t) * nl);
        nistp_mont_one(r->Z, c->rr_p, m, m0, nl);
        return;
    }

    nistp_mont_sqr(z1z1, p->Z, m, m0, nl);           /* Z1Z1 = Z1^2      */
    nistp_mont_mul(u2, qx, z1z1, m, m0, nl);         /* U2 = X2*Z1Z1     */
    nistp_mont_mul(t0, z1z1, p->Z, m, m0, nl);       /* Z1^3             */
    nistp_mont_mul(s2, qy, t0, m, m0, nl);           /* S2 = Y2*Z1^3     */

    nistp_mod_sub(h, u2, p->X, m, nl);               /* H = U2 - X1      */
    nistp_mod_sub(rr, s2, p->Y, m, nl);              /* S2 - Y1          */

    if (nistp_is_zero(h, nl)) {
        /* Same x-coordinate: either P == Q (double) or P == -Q (infinity). */
        if (nistp_is_zero(rr, nl))
            nistp_jac_double(r, p, c);
        else
            nistp_jac_set_infinity(r);
        return;
    }

    nistp_mod_add(rr, rr, rr, m, nl);                /* r = 2*(S2 - Y1)  */

    nistp_mont_sqr(hh, h, m, m0, nl);                /* HH = H^2         */
    nistp_mod_add(ii, hh, hh, m, nl);
    nistp_mod_add(ii, ii, ii, m, nl);                /* I = 4*HH         */
    nistp_mont_mul(jj, h, ii, m, m0, nl);            /* J = H*I          */
    nistp_mont_mul(vv, p->X, ii, m, m0, nl);         /* V = X1*I         */

    /* X3 = r^2 - J - 2*V */
    nistp_mont_sqr(out.X, rr, m, m0, nl);
    nistp_mod_sub(out.X, out.X, jj, m, nl);
    nistp_mod_sub(out.X, out.X, vv, m, nl);
    nistp_mod_sub(out.X, out.X, vv, m, nl);

    /* Y3 = r*(V - X3) - 2*Y1*J */
    nistp_mod_sub(t0, vv, out.X, m, nl);
    nistp_mont_mul(out.Y, rr, t0, m, m0, nl);
    nistp_mont_mul(t0, p->Y, jj, m, m0, nl);
    nistp_mod_add(t0, t0, t0, m, nl);
    nistp_mod_sub(out.Y, out.Y, t0, m, nl);

    /* Z3 = (Z1 + H)^2 - Z1Z1 - HH */
    nistp_mod_add(t0, p->Z, h, m, nl);
    nistp_mont_sqr(out.Z, t0, m, m0, nl);
    nistp_mod_sub(out.Z, out.Z, z1z1, m, nl);
    nistp_mod_sub(out.Z, out.Z, hh, m, nl);

    *r = out;
}

/**
 * Variable-time R = u1*A + u2*B (Shamir's trick), A and B affine.
 *
 * Used only by ECDSA verification, where every input is public — the same
 * posture, and the same 2-bit interleaved table, as
 * `secp256k1_point_mul_shamir`.
 *
 * A and B arrive as affine Montgomery coordinates rather than Jacobian
 * points.  That is not a convenience: it is the precondition that lets the
 * inner loop use `nistp_jac_add_affine_vartime` (11 field multiplications)
 * instead of the constant-time `nistp_jac_add` (24).  Taking them as
 * coordinate pairs puts the precondition in the signature, where a future
 * caller cannot quietly violate it by passing an unnormalised point.
 *
 * The third table entry A+B is computed once and normalised to affine so it
 * can be used the same way; the single inversion that costs is repaid many
 * times over across the ~192 additions the loop performs.  A+B is the one
 * entry that can be the point at infinity (exactly when B == -A, which a
 * crafted public key can arrange), so it carries a validity flag and its
 * digit is skipped when it is unavailable — adding infinity is a no-op, so
 * skipping is the correct result, not an approximation.
 */
static void nistp_shamir(nistp_jac *out,
                         const uint8_t *u1, const uint64_t *ax, const uint64_t *ay,
                         const uint8_t *u2, const uint64_t *bx, const uint64_t *by,
                         const nistp_curve *c) {
    unsigned nl = c->nlimbs;
    uint64_t tx[4][AMA_NISTP_MAX_LIMBS], ty[4][AMA_NISTP_MAX_LIMBS];
    int valid[4] = { 0, 1, 1, 0 };
    nistp_jac acc, ja, jb, sum;
    unsigned i;
    int j;

    memcpy(tx[1], ax, sizeof(uint64_t) * nl);
    memcpy(ty[1], ay, sizeof(uint64_t) * nl);
    memcpy(tx[2], bx, sizeof(uint64_t) * nl);
    memcpy(ty[2], by, sizeof(uint64_t) * nl);

    /* t[3] = A + B, normalised to affine.  Built through the constant-time
     * adder because it is a single operation whose cost does not matter and
     * whose exceptional-case handling is already proven. */
    memcpy(ja.X, ax, sizeof(uint64_t) * nl);
    memcpy(ja.Y, ay, sizeof(uint64_t) * nl);
    nistp_mont_one(ja.Z, c->rr_p, c->p, c->p0inv, nl);
    memcpy(jb.X, bx, sizeof(uint64_t) * nl);
    memcpy(jb.Y, by, sizeof(uint64_t) * nl);
    nistp_mont_one(jb.Z, c->rr_p, c->p, c->p0inv, nl);
    nistp_jac_add(&sum, &ja, &jb, c);
    valid[3] = nistp_jac_to_affine(tx[3], ty[3], &sum, c);

    nistp_jac_set_infinity(&acc);
    for (i = 0; i < c->nbytes; i++) {
        for (j = 7; j >= 0; j--) {
            int idx = ((u1[i] >> j) & 1) | (((u2[i] >> j) & 1) << 1);
            nistp_jac_double(&acc, &acc, c);
            if (idx && valid[idx])
                nistp_jac_add_affine_vartime(&acc, &acc, tx[idx], ty[idx], c);
        }
    }
    *out = acc;
}

/* ============================================================================
 * POINT VALIDATION AND (DE)SERIALIZATION
 * ============================================================================ */

/**
 * Load an affine public key from `2 * nbytes` big-endian octets (X || Y) and
 * validate it fully:
 *
 *   1. Both coordinates are canonical field elements in [0, p).  A coordinate
 *      >= p is rejected, never reduced — the INVARIANT-29 rule, applied here
 *      for the same reason: one signature must not verify under two distinct
 *      public-key byte strings.
 *   2. The point satisfies y^2 = x^3 - 3x + b.
 *   3. The point is not the identity.
 *
 * All three NIST prime curves have cofactor 1 and prime order, so on-curve
 * plus non-identity is exactly "in the prime-order group" — no separate
 * order check is needed, and none is silently skipped.
 *
 * Returns 1 on success, 0 on rejection.  Outputs are Montgomery form.
 */
static int nistp_load_point(uint64_t *x, uint64_t *y, const uint8_t *pub,
                            const nistp_curve *c) {
    uint64_t xs[AMA_NISTP_MAX_LIMBS], ys[AMA_NISTP_MAX_LIMBS];
    uint64_t lhs[AMA_NISTP_MAX_LIMBS], rhs[AMA_NISTP_MAX_LIMBS];
    uint64_t t[AMA_NISTP_MAX_LIMBS], bm[AMA_NISTP_MAX_LIMBS];
    unsigned nl = c->nlimbs;
    int ok = 0;

    nistp_from_bytes(xs, pub, c->nbytes, nl);
    nistp_from_bytes(ys, pub + c->nbytes, c->nbytes, nl);

    if (!nistp_lt(xs, c->p, nl) || !nistp_lt(ys, c->p, nl))
        goto done;
    if (nistp_is_zero(xs, nl) && nistp_is_zero(ys, nl))
        goto done;   /* the SEC 1 encoding of the identity is not a valid key */

    nistp_to_mont(x, xs, c->rr_p, c->p, c->p0inv, nl);
    nistp_to_mont(y, ys, c->rr_p, c->p, c->p0inv, nl);

    /* rhs = x^3 - 3x + b */
    nistp_mont_sqr(t, x, c->p, c->p0inv, nl);
    nistp_mont_mul(rhs, t, x, c->p, c->p0inv, nl);
    nistp_mod_add(t, x, x, c->p, nl);
    nistp_mod_add(t, t, x, c->p, nl);            /* 3x */
    nistp_mod_sub(rhs, rhs, t, c->p, nl);
    nistp_to_mont(bm, c->b, c->rr_p, c->p, c->p0inv, nl);
    nistp_mod_add(rhs, rhs, bm, c->p, nl);

    nistp_mont_sqr(lhs, y, c->p, c->p0inv, nl);
    ok = nistp_equal(lhs, rhs, nl);

done:
    ama_secure_memzero(xs, sizeof(xs));
    ama_secure_memzero(ys, sizeof(ys));
    ama_secure_memzero(lhs, sizeof(lhs));
    ama_secure_memzero(rhs, sizeof(rhs));
    ama_secure_memzero(t, sizeof(t));
    ama_secure_memzero(bm, sizeof(bm));
    return ok;
}

/* ============================================================================
 * SCALARS MOD n
 * ============================================================================ */

/** Load a scalar and report whether it was already canonical (< n). */
static int nistp_scalar_load(uint64_t *s, const uint8_t *in, const nistp_curve *c) {
    nistp_from_bytes(s, in, c->nbytes, c->nlimbs);
    return nistp_lt(s, c->n, c->nlimbs);
}

/**
 * RFC 6979 §2.3.2 `bits2int`.
 *
 * Keeps the leftmost min(8*inlen, qlen) bits — the FIPS 186-5 truncation rule
 * — so a digest wider than the group order is shifted right rather than
 * folded, and a narrower one is used whole.  No reduction is applied: the
 * RFC 6979 nonce loop must be able to *see* an out-of-range candidate in
 * order to reject it, which is a different behaviour from reducing it.
 */
static void nistp_bits2int(uint64_t *out, const uint8_t *in, size_t inlen,
                           const nistp_curve *c) {
    /* Widest input this is ever handed is a 2-block RFC 6979 `T` for P-521:
     * 128 octets = 16 limbs.  Round up generously; it is stack-only. */
    uint64_t wide[24];
    unsigned nl = c->nlimbs;
    size_t i;
    unsigned shift, wordshift, bitshift;

    memset(wide, 0, sizeof(wide));
    if (inlen > sizeof(wide))
        inlen = sizeof(wide);          /* unreachable for every caller here */
    for (i = 0; i < inlen; i++) {
        size_t bitpos = (inlen - 1u - i) * 8u;
        wide[bitpos >> 6] |= (uint64_t)in[i] << (bitpos & 63u);
    }

    shift = (8u * (unsigned)inlen > c->qbits) ? (8u * (unsigned)inlen - c->qbits) : 0u;
    wordshift = shift >> 6;
    bitshift = shift & 63u;
    for (i = 0; i < nl; i++) {
        size_t src = i + wordshift;
        uint64_t lo = (src < (sizeof(wide) / sizeof(wide[0]))) ? wide[src] : 0u;
        uint64_t hi = (src + 1 < (sizeof(wide) / sizeof(wide[0]))) ? wide[src + 1] : 0u;
        out[i] = bitshift ? ((lo >> bitshift) | (hi << (64u - bitshift))) : lo;
    }
    for (i = nl; i < AMA_NISTP_MAX_LIMBS; i++)
        out[i] = 0;

    ama_secure_memzero(wide, sizeof(wide));
}

/**
 * `bits2int` followed by one conditional subtraction of n.
 *
 * That single subtraction is a *complete* reduction here: `bits2int` returns
 * a value strictly below 2^qlen, and n has exactly qlen bits, so n >= 2^(qlen-1)
 * and therefore 2^qlen <= 2n.  This is the ECDSA message representative `e`
 * (FIPS 186-5 §6.4.1) and RFC 6979's `bits2octets`.
 */
static void nistp_bits2int_mod_n(uint64_t *out, const uint8_t *in, size_t inlen,
                                 const nistp_curve *c) {
    nistp_bits2int(out, in, inlen, c);
    nistp_cond_sub_mod(out, out, 0, c->n, c->nlimbs);
}

/** 1 when s > (n-1)/2 (the non-canonical "high" representative). */
static int nistp_scalar_is_high(const uint64_t *s, const nistp_curve *c) {
    uint64_t half[AMA_NISTP_MAX_LIMBS];
    unsigned nl = c->nlimbs, i;
    int high;

    /* half = (n-1)/2 = n >> 1, since n is odd. */
    for (i = 0; i < nl; i++) {
        uint64_t lo = c->n[i];
        uint64_t hi = (i + 1 < nl) ? c->n[i + 1] : 0u;
        half[i] = (lo >> 1) | (hi << 63);
    }
    high = !nistp_lt(s, half, nl) && !nistp_equal(s, half, nl);
    ama_secure_memzero(half, sizeof(half));
    return high;
}

/* ============================================================================
 * RFC 6979 — deterministic (and hedged) nonce generation
 * ============================================================================ */

static void nistp_hmac(unsigned hlen, const uint8_t *key, size_t klen,
                       const uint8_t *msg, size_t mlen, uint8_t *out) {
    switch (hlen) {
        case 32: ama_hmac_sha256(key, klen, msg, mlen, out); break;
        case 48: (void)ama_hmac_sha384(key, klen, msg, mlen, out); break;
        default: (void)ama_hmac_sha512(key, klen, msg, mlen, out); break;
    }
}

/**
 * RFC 6979 §3.2 HMAC_DRBG nonce, generalised over hash width and qlen, with
 * the §3.6 "additional data" hedge wired in as an optional `extra` block.
 *
 * The HMAC hash is chosen by the digest width the caller supplied — 32 -> SHA-256,
 * 48 -> SHA-384, 64 -> SHA-512 — which is what RFC 6979 prescribes (the same
 * hash that produced the message digest) and what every interoperating
 * implementation does.  Widths other than those three are rejected upstream.
 *
 * Returns 1 on success, 0 if no candidate landed in [1, n-1] (statistically
 * unreachable; the bound exists so the loop is provably finite).
 */
static int nistp_rfc6979_nonce(uint64_t *k_out, uint8_t *k_bytes,
                               const uint8_t *priv, const uint8_t *digest,
                               size_t digest_len, const uint8_t *extra,
                               size_t extra_len, const nistp_curve *c) {
    unsigned hlen = (unsigned)digest_len;
    unsigned nb = c->nbytes;
    uint8_t V[64], K[64];
    uint8_t seed[64 + 1 + 66 + 66 + 32];   /* V || sep || x || bits2octets(h) || extra */
    uint8_t T[128];
    uint64_t h1int[AMA_NISTP_MAX_LIMBS];
    uint8_t h1oct[66];
    size_t seedlen;
    int attempt, ok = 0;

    if (extra_len > 32)
        return 0;

    /* bits2octets(h1) = int2octets(bits2int(h1) mod n) */
    nistp_bits2int_mod_n(h1int, digest, digest_len, c);
    nistp_to_bytes(h1oct, h1int, nb);

    memset(V, 0x01, hlen);
    memset(K, 0x00, hlen);

    seedlen = (size_t)hlen + 1u + nb + nb + extra_len;
    memcpy(seed, V, hlen);
    seed[hlen] = 0x00;
    memcpy(seed + hlen + 1, priv, nb);
    memcpy(seed + hlen + 1 + nb, h1oct, nb);
    if (extra_len)
        memcpy(seed + hlen + 1 + nb + nb, extra, extra_len);
    nistp_hmac(hlen, K, hlen, seed, seedlen, K);
    nistp_hmac(hlen, K, hlen, V, hlen, V);

    memcpy(seed, V, hlen);
    seed[hlen] = 0x01;
    nistp_hmac(hlen, K, hlen, seed, seedlen, K);
    nistp_hmac(hlen, K, hlen, V, hlen, V);

    for (attempt = 0; attempt < 1024; attempt++) {
        size_t tlen = 0;
        while (tlen * 8u < c->qbits) {
            nistp_hmac(hlen, K, hlen, V, hlen, V);
            memcpy(T + tlen, V, hlen);
            tlen += hlen;
        }
        nistp_bits2int(k_out, T, tlen, c);
        /* RFC 6979 §3.2 step h.3 verbatim: a candidate outside [1, n-1] is
         * *rejected and regenerated*, never reduced.  Reducing would be a
         * silent divergence — it produces a nonce a conformant signer would
         * never choose, so the signature would not match any reference
         * implementation's.  The rejection branch is data-dependent, which
         * RFC 6979 accepts and every conformant signer shares: it fires with
         * probability below 2^-32 on these curves, and when it does the only
         * fact it exposes is that one discarded DRBG block landed above n. */
        if (nistp_lt(k_out, c->n, c->nlimbs) && !nistp_is_zero(k_out, c->nlimbs)) {
            nistp_to_bytes(k_bytes, k_out, nb);
            ok = 1;
            break;
        }
        memcpy(seed, V, hlen);
        seed[hlen] = 0x00;
        nistp_hmac(hlen, K, hlen, seed, (size_t)hlen + 1u, K);
        nistp_hmac(hlen, K, hlen, V, hlen, V);
    }

    ama_secure_memzero(V, sizeof(V));
    ama_secure_memzero(K, sizeof(K));
    ama_secure_memzero(seed, sizeof(seed));
    ama_secure_memzero(T, sizeof(T));
    ama_secure_memzero(h1int, sizeof(h1int));
    ama_secure_memzero(h1oct, sizeof(h1oct));
    return ok;
}

/* ============================================================================
 * STRICT DER (X9.62 / SEC 1)
 *
 * Accepts exactly `30 <len> 02 <rlen> <r> 02 <slen> <s>` with minimal
 * INTEGERs, no negative values, no superfluous leading zero, and no trailing
 * bytes.  Unlike the secp256k1 parser this must also accept the one-octet
 * long-form SEQUENCE length, because a P-521 signature body is up to 138
 * octets — but only when the length actually needs it, so `30 81 <len<0x80>`
 * (a non-minimal long form) is still rejected.
 * ============================================================================ */

/** Maximum DER length: 3 header octets + 2 * (2 + 1 + 66) for P-521. */
#define NISTP_DER_MAX 141

static int nistp_der_parse_int(const uint8_t *buf, size_t len, size_t *off,
                               uint8_t *out, unsigned nb) {
    size_t ilen, i;
    const uint8_t *p;

    if (*off + 2 > len) return 0;
    if (buf[*off] != 0x02) return 0;
    ilen = buf[*off + 1];
    if (ilen & 0x80u) return 0;              /* long form / indefinite */
    if (ilen == 0) return 0;
    *off += 2;
    if (*off + ilen > len) return 0;
    p = buf + *off;

    if (p[0] & 0x80u) return 0;              /* negative */
    if (p[0] == 0x00) {
        if (ilen == 1) {
            /* the value zero — legal DER, rejected later by the range check */
        } else if (!(p[1] & 0x80u)) {
            return 0;                        /* non-minimal leading zero */
        }
    }
    if (ilen > (size_t)nb + 1u) return 0;
    if (ilen == (size_t)nb + 1u && p[0] != 0x00) return 0;

    memset(out, 0, nb);
    if (ilen > nb) {
        for (i = 0; i < nb; i++)
            out[i] = p[1 + i];
    } else {
        for (i = 0; i < ilen; i++)
            out[nb - ilen + i] = p[i];
    }
    *off += ilen;
    return 1;
}

static int nistp_der_parse(const uint8_t *sig, size_t sig_len,
                           uint8_t *r, uint8_t *s, unsigned nb) {
    size_t off, seq_len, hdr;

    if (sig_len < 8) return 0;
    if (sig[0] != 0x30) return 0;

    if (sig[1] & 0x80u) {
        if (sig[1] != 0x81u) return 0;       /* only one long-form octet is ever needed */
        /* No `sig_len < 3` check: the `sig_len < 8` above already guarantees
         * three octets, so it was dead code — the shortest DER signature is
         * `30 06 02 01 xx 02 01 yy`, eight octets. */
        seq_len = sig[2];
        if (seq_len < 0x80u) return 0;       /* non-minimal long form */
        hdr = 3;
    } else {
        seq_len = sig[1];
        hdr = 2;
    }
    if (hdr + seq_len != sig_len) return 0;

    off = hdr;
    if (!nistp_der_parse_int(sig, sig_len, &off, r, nb)) return 0;
    if (!nistp_der_parse_int(sig, sig_len, &off, s, nb)) return 0;
    if (off != sig_len) return 0;
    return 1;
}

static size_t nistp_der_encode_int(uint8_t *out, const uint8_t *v, unsigned nb) {
    unsigned lead = 0;
    size_t len, i, n = 0;

    while (lead + 1u < nb && v[lead] == 0x00)
        lead++;
    len = (size_t)nb - lead;
    out[n++] = 0x02;
    if (v[lead] & 0x80u) {
        out[n++] = (uint8_t)(len + 1);
        out[n++] = 0x00;
    } else {
        out[n++] = (uint8_t)len;
    }
    for (i = 0; i < len; i++)
        out[n++] = v[lead + i];
    return n;
}

static size_t nistp_der_encode(uint8_t *out, const uint8_t *r, const uint8_t *s, unsigned nb) {
    uint8_t body[2 * (2 + 1 + 66)];
    size_t n = 0, total;

    n += nistp_der_encode_int(body + n, r, nb);
    n += nistp_der_encode_int(body + n, s, nb);

    out[0] = 0x30;
    if (n < 0x80u) {
        out[1] = (uint8_t)n;
        memcpy(out + 2, body, n);
        total = n + 2;
    } else {
        out[1] = 0x81;
        out[2] = (uint8_t)n;
        memcpy(out + 3, body, n);
        total = n + 3;
    }
    return total;
}

/* ============================================================================
 * PUBLIC API — metadata
 * ============================================================================ */

AMA_API size_t ama_nistp_field_bytes(ama_nist_curve_t curve) {
    const nistp_curve *c = nistp_lookup(curve);
    return c ? c->nbytes : 0u;
}

AMA_API size_t ama_nistp_pubkey_bytes(ama_nist_curve_t curve) {
    const nistp_curve *c = nistp_lookup(curve);
    return c ? (size_t)c->nbytes * 2u : 0u;
}

AMA_API size_t ama_nistp_sig_der_max_len(ama_nist_curve_t curve) {
    const nistp_curve *c = nistp_lookup(curve);
    if (!c) return 0u;
    /* SEQUENCE header (2 or 3) + 2 * INTEGER (2 + optional pad + nbytes) */
    return (c->nbytes > 48u ? 3u : 2u) + 2u * (2u + 1u + (size_t)c->nbytes);
}

AMA_API const char *ama_nistp_curve_name(ama_nist_curve_t curve) {
    const nistp_curve *c = nistp_lookup(curve);
    return c ? c->name : NULL;
}

/* ============================================================================
 * PUBLIC API — keys
 * ============================================================================ */

AMA_API ama_error_t ama_nistp_pubkey_from_privkey(ama_nist_curve_t curve,
                                                  const uint8_t *private_key,
                                                  uint8_t *public_key) {
    const nistp_curve *c = nistp_lookup(curve);
    uint64_t d[AMA_NISTP_MAX_LIMBS];
    uint64_t x[AMA_NISTP_MAX_LIMBS], y[AMA_NISTP_MAX_LIMBS];
    uint64_t xs[AMA_NISTP_MAX_LIMBS], ys[AMA_NISTP_MAX_LIMBS];
    nistp_jac Q;
    ama_error_t rc = AMA_ERROR_INVALID_PARAM;

    if (!c || !private_key || !public_key)
        return AMA_ERROR_INVALID_PARAM;
    if (!nistp_scalar_load(d, private_key, c) || nistp_is_zero(d, c->nlimbs))
        return AMA_ERROR_INVALID_PARAM;

    /* Fixed base: the comb skips the doublings entirely (see
     * nistp_scalar_mul_generator).  Same result, same constant-time posture. */
    nistp_scalar_mul_generator(&Q, private_key, c);
    if (!nistp_jac_to_affine(x, y, &Q, c)) {
        rc = AMA_ERROR_CRYPTO;
        goto done;
    }
    nistp_from_mont(xs, x, c->p, c->p0inv, c->nlimbs);
    nistp_from_mont(ys, y, c->p, c->p0inv, c->nlimbs);
    nistp_to_bytes(public_key, xs, c->nbytes);
    nistp_to_bytes(public_key + c->nbytes, ys, c->nbytes);
    rc = AMA_SUCCESS;

done:
    ama_secure_memzero(d, sizeof(d));
    ama_secure_memzero(x, sizeof(x));
    ama_secure_memzero(y, sizeof(y));
    ama_secure_memzero(xs, sizeof(xs));
    ama_secure_memzero(ys, sizeof(ys));
    ama_secure_memzero(&Q, sizeof(Q));
    return rc;
}

AMA_API ama_error_t ama_nistp_keypair(ama_nist_curve_t curve,
                                      uint8_t *private_key,
                                      uint8_t *public_key) {
    const nistp_curve *c = nistp_lookup(curve);
    uint64_t d[AMA_NISTP_MAX_LIMBS];
    uint8_t candidate[66];
    int attempt;
    ama_error_t rc = AMA_ERROR_CRYPTO;

    if (!c || !private_key || !public_key)
        return AMA_ERROR_INVALID_PARAM;

    /* Rejection sampling into [1, n-1].  Sampling `nbytes` octets and
     * rejecting out-of-range candidates (rather than reducing them) keeps the
     * distribution exactly uniform, which matters for P-521 where the top
     * octet carries only 9 significant bits and the rejection rate is high. */
    for (attempt = 0; attempt < 256; attempt++) {
        if (ama_randombytes(candidate, c->nbytes) != AMA_SUCCESS) {
            rc = AMA_ERROR_CRYPTO;
            goto done;
        }
        if (c->qbits % 8u)
            candidate[0] = (uint8_t)(candidate[0] & ((1u << (c->qbits % 8u)) - 1u));
        if (nistp_scalar_load(d, candidate, c) && !nistp_is_zero(d, c->nlimbs)) {
            memcpy(private_key, candidate, c->nbytes);
            rc = ama_nistp_pubkey_from_privkey(curve, private_key, public_key);
            goto done;
        }
    }

done:
    ama_secure_memzero(d, sizeof(d));
    ama_secure_memzero(candidate, sizeof(candidate));
    if (rc != AMA_SUCCESS)
        ama_secure_memzero(private_key, c->nbytes);
    return rc;
}

AMA_API ama_error_t ama_nistp_pubkey_validate(ama_nist_curve_t curve,
                                              const uint8_t *public_key) {
    const nistp_curve *c = nistp_lookup(curve);
    uint64_t x[AMA_NISTP_MAX_LIMBS], y[AMA_NISTP_MAX_LIMBS];
    int ok;

    if (!c || !public_key)
        return AMA_ERROR_INVALID_PARAM;
    ok = nistp_load_point(x, y, public_key, c);
    ama_secure_memzero(x, sizeof(x));
    ama_secure_memzero(y, sizeof(y));
    return ok ? AMA_SUCCESS : AMA_ERROR_VERIFY_FAILED;
}

/* ============================================================================
 * PUBLIC API — SEC 1 point encoding
 * ============================================================================ */

AMA_API ama_error_t ama_nistp_point_encode(ama_nist_curve_t curve,
                                           const uint8_t *public_key,
                                           int compressed,
                                           uint8_t *out, size_t *out_len) {
    const nistp_curve *c = nistp_lookup(curve);

    if (!c || !public_key || !out || !out_len)
        return AMA_ERROR_INVALID_PARAM;
    if (ama_nistp_pubkey_validate(curve, public_key) != AMA_SUCCESS)
        return AMA_ERROR_INVALID_PARAM;

    if (compressed) {
        out[0] = (uint8_t)(0x02u | (public_key[2u * c->nbytes - 1u] & 1u));
        memcpy(out + 1, public_key, c->nbytes);
        *out_len = (size_t)c->nbytes + 1u;
    } else {
        out[0] = 0x04;
        memcpy(out + 1, public_key, (size_t)c->nbytes * 2u);
        *out_len = (size_t)c->nbytes * 2u + 1u;
    }
    return AMA_SUCCESS;
}

AMA_API ama_error_t ama_nistp_point_decode(ama_nist_curve_t curve,
                                           const uint8_t *in, size_t in_len,
                                           uint8_t *public_key) {
    const nistp_curve *c = nistp_lookup(curve);
    uint64_t xs[AMA_NISTP_MAX_LIMBS], x[AMA_NISTP_MAX_LIMBS];
    uint64_t rhs[AMA_NISTP_MAX_LIMBS], t[AMA_NISTP_MAX_LIMBS];
    uint64_t bm[AMA_NISTP_MAX_LIMBS], yv[AMA_NISTP_MAX_LIMBS];
    uint64_t chk[AMA_NISTP_MAX_LIMBS], ys[AMA_NISTP_MAX_LIMBS];
    uint64_t e[AMA_NISTP_MAX_LIMBS], neg[AMA_NISTP_MAX_LIMBS];
    unsigned nl, i;
    ama_error_t rc = AMA_ERROR_INVALID_PARAM;

    if (!c || !in || !public_key)
        return AMA_ERROR_INVALID_PARAM;
    nl = c->nlimbs;

    if (in_len == (size_t)c->nbytes * 2u + 1u && in[0] == 0x04) {
        /* Route through `done:` rather than returning here.  The header
         * promises "the output buffer is zeroed" on rejection, and the
         * compressed branch below honours it via the shared exit — this branch
         * returned early and left the caller holding 2*field_bytes of
         * attacker-chosen octets that are not a point on the curve.  A caller
         * that treats an all-zero buffer as "not populated", or that logs the
         * buffer on the error path, was handed exactly what it was told it
         * would not be. */
        memcpy(public_key, in + 1, (size_t)c->nbytes * 2u);
        rc = ama_nistp_pubkey_validate(curve, public_key) == AMA_SUCCESS
                 ? AMA_SUCCESS : AMA_ERROR_INVALID_PARAM;
        goto done;
    }
    if (in_len != (size_t)c->nbytes + 1u || (in[0] != 0x02 && in[0] != 0x03))
        return AMA_ERROR_INVALID_PARAM;

    nistp_from_bytes(xs, in + 1, c->nbytes, nl);
    if (!nistp_lt(xs, c->p, nl))
        goto done;

    nistp_to_mont(x, xs, c->rr_p, c->p, c->p0inv, nl);

    /* rhs = x^3 - 3x + b */
    nistp_mont_sqr(t, x, c->p, c->p0inv, nl);
    nistp_mont_mul(rhs, t, x, c->p, c->p0inv, nl);
    nistp_mod_add(t, x, x, c->p, nl);
    nistp_mod_add(t, t, x, c->p, nl);
    nistp_mod_sub(rhs, rhs, t, c->p, nl);
    nistp_to_mont(bm, c->b, c->rr_p, c->p, c->p0inv, nl);
    nistp_mod_add(rhs, rhs, bm, c->p, nl);

    /* y = rhs^((p+1)/4).  Every NIST prime curve has p = 3 mod 4, so this is
     * the square root when one exists; squaring the result is what proves it
     * does — a non-residue x is rejected rather than yielding a bogus point. */
    {
        uint64_t one[AMA_NISTP_MAX_LIMBS];
        uint64_t carry;
        memset(one, 0, sizeof(one));
        one[0] = 1;
        carry = nistp_add(e, c->p, one, nl);
        (void)carry;   /* p+1 never overflows nl limbs for these curves */
        for (i = 0; i < nl; i++) {
            uint64_t lo = e[i];
            uint64_t hi = (i + 1u < nl) ? e[i + 1u] : 0u;
            one[i] = (lo >> 2) | (hi << 62);
        }
        memcpy(e, one, sizeof(uint64_t) * nl);
        ama_secure_memzero(one, sizeof(one));
    }
    nistp_mont_pow(yv, rhs, e, c->pbits, c->rr_p, c->p, c->p0inv, nl);
    nistp_mont_sqr(chk, yv, c->p, c->p0inv, nl);
    if (!nistp_equal(chk, rhs, nl))
        goto done;

    nistp_from_mont(ys, yv, c->p, c->p0inv, nl);
    /* Select the root whose least significant bit matches the sign octet. */
    if ((unsigned)(ys[0] & 1u) != (unsigned)(in[0] & 1u)) {
        memset(neg, 0, sizeof(neg));
        nistp_mod_sub(neg, neg, ys, c->p, nl);
        memcpy(ys, neg, sizeof(uint64_t) * nl);
    }

    nistp_to_bytes(public_key, xs, c->nbytes);
    nistp_to_bytes(public_key + c->nbytes, ys, c->nbytes);
    rc = ama_nistp_pubkey_validate(curve, public_key) == AMA_SUCCESS
             ? AMA_SUCCESS : AMA_ERROR_INVALID_PARAM;

done:
    ama_secure_memzero(xs, sizeof(xs));
    ama_secure_memzero(x, sizeof(x));
    ama_secure_memzero(rhs, sizeof(rhs));
    ama_secure_memzero(t, sizeof(t));
    ama_secure_memzero(bm, sizeof(bm));
    ama_secure_memzero(yv, sizeof(yv));
    ama_secure_memzero(chk, sizeof(chk));
    ama_secure_memzero(ys, sizeof(ys));
    ama_secure_memzero(e, sizeof(e));
    ama_secure_memzero(neg, sizeof(neg));
    if (rc != AMA_SUCCESS)
        ama_secure_memzero(public_key, (size_t)c->nbytes * 2u);
    return rc;
}

/* ============================================================================
 * PUBLIC API — ECDH (SP 800-56A §5.7.1.2, cofactor 1)
 * ============================================================================ */

AMA_API ama_error_t ama_nistp_ecdh(ama_nist_curve_t curve,
                                   const uint8_t *private_key,
                                   const uint8_t *peer_public_key,
                                   uint8_t *shared_secret) {
    const nistp_curve *c = nistp_lookup(curve);
    uint64_t d[AMA_NISTP_MAX_LIMBS];
    uint64_t px[AMA_NISTP_MAX_LIMBS], py[AMA_NISTP_MAX_LIMBS];
    uint64_t x[AMA_NISTP_MAX_LIMBS], y[AMA_NISTP_MAX_LIMBS];
    uint64_t xs[AMA_NISTP_MAX_LIMBS];
    nistp_jac P, S;
    ama_error_t rc = AMA_ERROR_INVALID_PARAM;

    if (!c || !private_key || !peer_public_key || !shared_secret)
        return AMA_ERROR_INVALID_PARAM;

    if (!nistp_scalar_load(d, private_key, c) || nistp_is_zero(d, c->nlimbs))
        goto done;

    /* Full public-key validation before any secret-scalar arithmetic touches
     * it.  This is the invalid-curve defence: without it, a peer that sends a
     * point on a different (weak-order) curve recovers the private key from a
     * handful of exchanges. */
    if (!nistp_load_point(px, py, peer_public_key, c))
        goto done;

    memcpy(P.X, px, sizeof(uint64_t) * c->nlimbs);
    memcpy(P.Y, py, sizeof(uint64_t) * c->nlimbs);
    nistp_mont_one(P.Z, c->rr_p, c->p, c->p0inv, c->nlimbs);

    nistp_scalar_mul(&S, private_key, &P, c);
    if (!nistp_jac_to_affine(x, y, &S, c)) {
        /* d*P == infinity is impossible for a validated prime-order point and
         * d in [1, n-1]; treat it as a hard failure rather than emitting a
         * predictable all-zero secret. */
        rc = AMA_ERROR_CRYPTO;
        goto done;
    }

    nistp_from_mont(xs, x, c->p, c->p0inv, c->nlimbs);
    nistp_to_bytes(shared_secret, xs, c->nbytes);
    rc = AMA_SUCCESS;

done:
    ama_secure_memzero(d, sizeof(d));
    ama_secure_memzero(px, sizeof(px));
    ama_secure_memzero(py, sizeof(py));
    ama_secure_memzero(x, sizeof(x));
    ama_secure_memzero(y, sizeof(y));
    ama_secure_memzero(xs, sizeof(xs));
    ama_secure_memzero(&P, sizeof(P));
    ama_secure_memzero(&S, sizeof(S));
    if (rc != AMA_SUCCESS)
        ama_secure_memzero(shared_secret, c->nbytes);
    return rc;
}

/* ============================================================================
 * PUBLIC API — ECDSA
 * ============================================================================ */

static int nistp_digest_len_ok(size_t digest_len) {
    return digest_len == 32u || digest_len == 48u || digest_len == 64u;
}

/**
 * Core signer.  Emits `r` and `s` as `nbytes` big-endian octets each.
 * `extra`/`extra_len` carry the RFC 6979 §3.6 hedge (NULL/0 for the pure
 * deterministic variant).
 */
static ama_error_t nistp_ecdsa_sign_core(const nistp_curve *c,
                                         const uint8_t *digest, size_t digest_len,
                                         const uint8_t *private_key,
                                         const uint8_t *extra, size_t extra_len,
                                         int low_s, uint8_t *r_out, uint8_t *s_out) {
    unsigned nl = c->nlimbs;
    uint64_t d[AMA_NISTP_MAX_LIMBS], k[AMA_NISTP_MAX_LIMBS], z[AMA_NISTP_MAX_LIMBS];
    uint64_t dm[AMA_NISTP_MAX_LIMBS], km[AMA_NISTP_MAX_LIMBS], zm[AMA_NISTP_MAX_LIMBS];
    uint64_t rm[AMA_NISTP_MAX_LIMBS], sm[AMA_NISTP_MAX_LIMBS], tm[AMA_NISTP_MAX_LIMBS];
    uint64_t rs[AMA_NISTP_MAX_LIMBS], ss[AMA_NISTP_MAX_LIMBS];
    uint64_t x[AMA_NISTP_MAX_LIMBS], y[AMA_NISTP_MAX_LIMBS], xs[AMA_NISTP_MAX_LIMBS];
    uint8_t k_bytes[66], x_bytes[66];
    nistp_jac R;
    ama_error_t rc = AMA_ERROR_INVALID_PARAM;

    if (!nistp_scalar_load(d, private_key, c) || nistp_is_zero(d, nl))
        goto done;

    nistp_bits2int_mod_n(z, digest, digest_len, c);

    if (!nistp_rfc6979_nonce(k, k_bytes, private_key, digest, digest_len,
                             extra, extra_len, c)) {
        rc = AMA_ERROR_CRYPTO;
        goto done;
    }

    /* R = k*G on the fixed generator — the comb path. */
    nistp_scalar_mul_generator(&R, k_bytes, c);
    if (!nistp_jac_to_affine(x, y, &R, c)) {
        rc = AMA_ERROR_CRYPTO;
        goto done;
    }
    nistp_from_mont(xs, x, c->p, c->p0inv, nl);
    nistp_to_bytes(x_bytes, xs, c->nbytes);

    /* r = R.x mod n.  R.x < p and p < 2n for all three curves, so this single
     * conditional subtraction is a complete reduction. */
    nistp_from_bytes(rs, x_bytes, c->nbytes, nl);
    nistp_cond_sub_mod(rs, rs, 0, c->n, nl);
    if (nistp_is_zero(rs, nl)) {
        rc = AMA_ERROR_CRYPTO;
        goto done;
    }

    /* s = k^-1 * (z + r*d) mod n, all in Montgomery form mod n. */
    nistp_to_mont(dm, d, c->rr_n, c->n, c->n0inv, nl);
    nistp_to_mont(km, k, c->rr_n, c->n, c->n0inv, nl);
    nistp_to_mont(zm, z, c->rr_n, c->n, c->n0inv, nl);
    nistp_to_mont(rm, rs, c->rr_n, c->n, c->n0inv, nl);

    nistp_mont_mul(tm, rm, dm, c->n, c->n0inv, nl);
    nistp_mod_add(tm, tm, zm, c->n, nl);
    nistp_mont_inv(sm, km, c->rr_n, c->n, c->qbits, c->n0inv, nl);
    nistp_mont_mul(sm, sm, tm, c->n, c->n0inv, nl);
    nistp_from_mont(ss, sm, c->n, c->n0inv, nl);

    if (nistp_is_zero(ss, nl)) {
        rc = AMA_ERROR_CRYPTO;
        goto done;
    }

    /* Low-`s` normalisation is OPT-IN (INVARIANT-34).
     *
     * The default emits RFC 6979's `s` verbatim, because that is what the RFC
     * specifies and what its own published vectors contain — normalising here
     * by default made this function fail RFC 6979 Appendix A.2.5/A.2.6/A.2.7
     * on every vector whose natural `s` happens to be high, roughly half of
     * them, while still calling itself "deterministic per RFC 6979".
     *
     * Normalising is only a *security* property when it is paired with a
     * verifier that rejects the high twin.  Paired with the X9.62-conformant
     * verifier that these curves need in order to interoperate, it prevents
     * nothing — the twin of an AMA signature still verifies under AMA — and
     * costs conformance.  So the caller asks for the pair or neither. */
    if (low_s && nistp_scalar_is_high(ss, c)) {
        uint64_t zero[AMA_NISTP_MAX_LIMBS];
        memset(zero, 0, sizeof(zero));
        nistp_mod_sub(ss, zero, ss, c->n, nl);
        ama_secure_memzero(zero, sizeof(zero));
    }

    nistp_to_bytes(r_out, rs, c->nbytes);
    nistp_to_bytes(s_out, ss, c->nbytes);
    rc = AMA_SUCCESS;

done:
    ama_secure_memzero(d, sizeof(d));
    ama_secure_memzero(k, sizeof(k));
    ama_secure_memzero(z, sizeof(z));
    ama_secure_memzero(dm, sizeof(dm));
    ama_secure_memzero(km, sizeof(km));
    ama_secure_memzero(zm, sizeof(zm));
    ama_secure_memzero(rm, sizeof(rm));
    ama_secure_memzero(sm, sizeof(sm));
    ama_secure_memzero(tm, sizeof(tm));
    ama_secure_memzero(ss, sizeof(ss));
    ama_secure_memzero(x, sizeof(x));
    ama_secure_memzero(y, sizeof(y));
    ama_secure_memzero(xs, sizeof(xs));
    ama_secure_memzero(k_bytes, sizeof(k_bytes));
    ama_secure_memzero(&R, sizeof(R));
    return rc;
}

/**
 * Shared signing body for every public entry point.
 *
 * `flags` is the single place the two independent choices live — hedged vs.
 * deterministic, and low-`s` vs. RFC 6979 verbatim.  Folding them into one
 * argument rather than a matrix of `_hedged` / `_low_s` / `_hedged_low_s`
 * entry points is what keeps every combination reachable; the previous shape
 * made hedged+raw unreachable purely because nobody had written the fourth
 * function.
 */
static ama_error_t nistp_sign_dispatch(const nistp_curve *c,
                                       const uint8_t *digest, size_t digest_len,
                                       const uint8_t *private_key,
                                       uint32_t flags,
                                       uint8_t *r_out, uint8_t *s_out) {
    uint8_t entropy[32];
    const uint8_t *extra = NULL;
    size_t extra_len = 0;
    ama_error_t rc;

    if (flags & ~(AMA_NISTP_ECDSA_SIGN_LOW_S | AMA_NISTP_ECDSA_SIGN_HEDGED))
        return AMA_ERROR_INVALID_PARAM;   /* unknown flag bits are rejected */

    if (flags & AMA_NISTP_ECDSA_SIGN_HEDGED) {
        if (ama_randombytes(entropy, sizeof(entropy)) != AMA_SUCCESS) {
            /* `ama_randombytes` is not all-or-nothing: the getrandom(2) and
             * getentropy(3) paths both loop, advancing the offset, and can
             * return an error after earlier iterations have already written
             * CSPRNG output into the buffer.  Returning without the scrub left
             * up to 31 live entropy octets in the frame — the one error return
             * in this path that missed the scrub the file header claims for
             * "every exit path". */
            ama_secure_memzero(entropy, sizeof(entropy));
            return AMA_ERROR_CRYPTO;
        }
        extra = entropy;
        extra_len = sizeof(entropy);
    }

    rc = nistp_ecdsa_sign_core(c, digest, digest_len, private_key,
                               extra, extra_len,
                               (flags & AMA_NISTP_ECDSA_SIGN_LOW_S) ? 1 : 0,
                               r_out, s_out);
    ama_secure_memzero(entropy, sizeof(entropy));
    return rc;
}

AMA_API ama_error_t ama_nistp_ecdsa_sign_raw_ex(ama_nist_curve_t curve,
                                                const uint8_t *digest, size_t digest_len,
                                                const uint8_t *private_key,
                                                uint8_t *signature, uint32_t flags) {
    const nistp_curve *c = nistp_lookup(curve);
    if (!c || !digest || !private_key || !signature)
        return AMA_ERROR_INVALID_PARAM;
    if (!nistp_digest_len_ok(digest_len))
        return AMA_ERROR_INVALID_PARAM;
    return nistp_sign_dispatch(c, digest, digest_len, private_key, flags,
                               signature, signature + c->nbytes);
}

AMA_API ama_error_t ama_nistp_ecdsa_sign_ex(ama_nist_curve_t curve,
                                            const uint8_t *digest, size_t digest_len,
                                            const uint8_t *private_key,
                                            uint8_t *signature, size_t *signature_len,
                                            uint32_t flags) {
    const nistp_curve *c = nistp_lookup(curve);
    uint8_t r[66], s[66];
    ama_error_t rc;

    if (!c || !digest || !private_key || !signature || !signature_len)
        return AMA_ERROR_INVALID_PARAM;
    if (!nistp_digest_len_ok(digest_len))
        return AMA_ERROR_INVALID_PARAM;

    rc = nistp_sign_dispatch(c, digest, digest_len, private_key, flags, r, s);
    if (rc == AMA_SUCCESS)
        *signature_len = nistp_der_encode(signature, r, s, c->nbytes);

    ama_secure_memzero(r, sizeof(r));
    ama_secure_memzero(s, sizeof(s));
    return rc;
}

AMA_API ama_error_t ama_nistp_ecdsa_sign_raw(ama_nist_curve_t curve,
                                             const uint8_t *digest, size_t digest_len,
                                             const uint8_t *private_key,
                                             uint8_t *signature) {
    return ama_nistp_ecdsa_sign_raw_ex(curve, digest, digest_len, private_key,
                                       signature, AMA_NISTP_ECDSA_SIGN_DEFAULT);
}

AMA_API ama_error_t ama_nistp_ecdsa_sign(ama_nist_curve_t curve,
                                         const uint8_t *digest, size_t digest_len,
                                         const uint8_t *private_key,
                                         uint8_t *signature, size_t *signature_len) {
    return ama_nistp_ecdsa_sign_ex(curve, digest, digest_len, private_key,
                                   signature, signature_len,
                                   AMA_NISTP_ECDSA_SIGN_DEFAULT);
}

AMA_API ama_error_t ama_nistp_ecdsa_sign_hedged(ama_nist_curve_t curve,
                                                const uint8_t *digest, size_t digest_len,
                                                const uint8_t *private_key,
                                                uint8_t *signature, size_t *signature_len) {
    return ama_nistp_ecdsa_sign_ex(curve, digest, digest_len, private_key,
                                   signature, signature_len,
                                   AMA_NISTP_ECDSA_SIGN_HEDGED);
}

/** Shared verification body over already-extracted fixed-width r and s. */
static ama_error_t nistp_ecdsa_verify_rs(const nistp_curve *c,
                                         const uint8_t *r_bytes, const uint8_t *s_bytes,
                                         const uint8_t *digest, size_t digest_len,
                                         const uint8_t *public_key, uint32_t flags) {
    unsigned nl = c->nlimbs;
    uint64_t rsc[AMA_NISTP_MAX_LIMBS], ssc[AMA_NISTP_MAX_LIMBS], z[AMA_NISTP_MAX_LIMBS];
    uint64_t rm[AMA_NISTP_MAX_LIMBS], sm[AMA_NISTP_MAX_LIMBS], zm[AMA_NISTP_MAX_LIMBS];
    uint64_t wm[AMA_NISTP_MAX_LIMBS], u1m[AMA_NISTP_MAX_LIMBS], u2m[AMA_NISTP_MAX_LIMBS];
    uint64_t u1[AMA_NISTP_MAX_LIMBS], u2[AMA_NISTP_MAX_LIMBS];
    uint64_t qx[AMA_NISTP_MAX_LIMBS], qy[AMA_NISTP_MAX_LIMBS];
    uint64_t x[AMA_NISTP_MAX_LIMBS], y[AMA_NISTP_MAX_LIMBS], xs[AMA_NISTP_MAX_LIMBS];
    uint64_t vx[AMA_NISTP_MAX_LIMBS];
    uint8_t u1b[66], u2b[66], x_bytes[66];
    nistp_jac G, Q, R;

    /* Unknown policy bits are rejected, symmetrically with the signer.
     *
     * `nistp_sign_dispatch` has always refused a flag word it does not
     * understand; the verifier silently discarded every bit but bit 0. So the
     * two halves of one documented policy pair behaved oppositely on the same
     * malformed input, and a caller that set a mistyped or future-version
     * strictness bit got AMA_SUCCESS from the *permissive* default while
     * believing it had asked for — and received — the strict one. That is
     * INVARIANT-35's failure applied to the policy word instead of the curve
     * selector: a selection nobody made, resolved silently to a neighbour.
     *
     * AMA_ERROR_INVALID_PARAM rather than AMA_ERROR_VERIFY_FAILED: the
     * signature has not been judged, the *request* is malformed. */
    if (flags & ~AMA_NISTP_ECDSA_REQUIRE_LOW_S)
        return AMA_ERROR_INVALID_PARAM;

    /* r and s must already be in [1, n-1] — never reduced into range: a value
     * >= n is a second byte string that would otherwise verify. */
    if (!nistp_scalar_load(rsc, r_bytes, c) || nistp_is_zero(rsc, nl))
        return AMA_ERROR_VERIFY_FAILED;
    if (!nistp_scalar_load(ssc, s_bytes, c) || nistp_is_zero(ssc, nl))
        return AMA_ERROR_VERIFY_FAILED;

    if ((flags & AMA_NISTP_ECDSA_REQUIRE_LOW_S) && nistp_scalar_is_high(ssc, c))
        return AMA_ERROR_VERIFY_FAILED;

    if (!nistp_load_point(qx, qy, public_key, c))
        return AMA_ERROR_VERIFY_FAILED;

    nistp_bits2int_mod_n(z, digest, digest_len, c);

    nistp_to_mont(rm, rsc, c->rr_n, c->n, c->n0inv, nl);
    nistp_to_mont(sm, ssc, c->rr_n, c->n, c->n0inv, nl);
    nistp_to_mont(zm, z, c->rr_n, c->n, c->n0inv, nl);
    nistp_mont_inv(wm, sm, c->rr_n, c->n, c->qbits, c->n0inv, nl);
    nistp_mont_mul(u1m, zm, wm, c->n, c->n0inv, nl);
    nistp_mont_mul(u2m, rm, wm, c->n, c->n0inv, nl);
    nistp_from_mont(u1, u1m, c->n, c->n0inv, nl);
    nistp_from_mont(u2, u2m, c->n, c->n0inv, nl);
    nistp_to_bytes(u1b, u1, c->nbytes);
    nistp_to_bytes(u2b, u2, c->nbytes);

    nistp_to_mont(G.X, c->gx, c->rr_p, c->p, c->p0inv, nl);
    nistp_to_mont(G.Y, c->gy, c->rr_p, c->p, c->p0inv, nl);
    nistp_mont_one(G.Z, c->rr_p, c->p, c->p0inv, nl);
    memcpy(Q.X, qx, sizeof(uint64_t) * nl);
    memcpy(Q.Y, qy, sizeof(uint64_t) * nl);
    nistp_mont_one(Q.Z, c->rr_p, c->p, c->p0inv, nl);

    nistp_shamir(&R, u1b, G.X, G.Y, u2b, Q.X, Q.Y, c);
    if (!nistp_jac_to_affine(x, y, &R, c))
        return AMA_ERROR_VERIFY_FAILED;

    nistp_from_mont(xs, x, c->p, c->p0inv, nl);
    nistp_to_bytes(x_bytes, xs, c->nbytes);
    nistp_from_bytes(vx, x_bytes, c->nbytes, nl);
    nistp_cond_sub_mod(vx, vx, 0, c->n, nl);

    return nistp_equal(vx, rsc, nl) ? AMA_SUCCESS : AMA_ERROR_VERIFY_FAILED;
}

AMA_API ama_error_t ama_nistp_ecdsa_verify_ex(ama_nist_curve_t curve,
                                              const uint8_t *digest, size_t digest_len,
                                              const uint8_t *public_key,
                                              const uint8_t *signature, size_t signature_len,
                                              uint32_t flags) {
    const nistp_curve *c = nistp_lookup(curve);
    uint8_t r[66], s[66];

    if (!c || !digest || !public_key || !signature)
        return AMA_ERROR_INVALID_PARAM;
    if (!nistp_digest_len_ok(digest_len))
        return AMA_ERROR_INVALID_PARAM;
    if (signature_len > NISTP_DER_MAX)
        return AMA_ERROR_VERIFY_FAILED;
    if (!nistp_der_parse(signature, signature_len, r, s, c->nbytes))
        return AMA_ERROR_VERIFY_FAILED;

    return nistp_ecdsa_verify_rs(c, r, s, digest, digest_len, public_key, flags);
}

AMA_API ama_error_t ama_nistp_ecdsa_verify(ama_nist_curve_t curve,
                                           const uint8_t *digest, size_t digest_len,
                                           const uint8_t *public_key,
                                           const uint8_t *signature, size_t signature_len) {
    return ama_nistp_ecdsa_verify_ex(curve, digest, digest_len, public_key,
                                     signature, signature_len,
                                     AMA_NISTP_ECDSA_VERIFY_DEFAULT);
}

AMA_API ama_error_t ama_nistp_ecdsa_verify_raw_ex(ama_nist_curve_t curve,
                                                  const uint8_t *digest, size_t digest_len,
                                                  const uint8_t *public_key,
                                                  const uint8_t *signature,
                                                  size_t signature_len,
                                                  uint32_t flags) {
    const nistp_curve *c = nistp_lookup(curve);

    if (!c || !digest || !public_key || !signature)
        return AMA_ERROR_INVALID_PARAM;
    if (!nistp_digest_len_ok(digest_len))
        return AMA_ERROR_INVALID_PARAM;
    if (signature_len != (size_t)c->nbytes * 2u)
        return AMA_ERROR_VERIFY_FAILED;

    return nistp_ecdsa_verify_rs(c, signature, signature + c->nbytes,
                                 digest, digest_len, public_key, flags);
}

AMA_API ama_error_t ama_nistp_ecdsa_verify_raw(ama_nist_curve_t curve,
                                               const uint8_t *digest, size_t digest_len,
                                               const uint8_t *public_key,
                                               const uint8_t *signature,
                                               size_t signature_len) {
    return ama_nistp_ecdsa_verify_raw_ex(curve, digest, digest_len, public_key,
                                         signature, signature_len,
                                         AMA_NISTP_ECDSA_VERIFY_DEFAULT);
}

/* ============================================================================
 * PUBLIC API — signature format conversion
 *
 * JWS (RFC 7515 §3.4), COSE (RFC 8152 §8.1) and WebAuthn's authenticator
 * assertions all use the fixed-width `r || s` form, while X.509, TLS and
 * PKCS#11 use DER.  Both directions are needed for the key-format layer, and
 * both re-validate the range of r and s so a conversion cannot launder an
 * out-of-range component into a well-formed encoding.
 * ============================================================================ */

AMA_API ama_error_t ama_nistp_sig_der_to_raw(ama_nist_curve_t curve,
                                             const uint8_t *der, size_t der_len,
                                             uint8_t *raw, size_t *raw_len) {
    const nistp_curve *c = nistp_lookup(curve);
    uint64_t v[AMA_NISTP_MAX_LIMBS];
    uint8_t r[66], s[66];
    ama_error_t rc = AMA_ERROR_INVALID_PARAM;

    if (!c || !der || !raw || !raw_len)
        return AMA_ERROR_INVALID_PARAM;
    if (der_len > NISTP_DER_MAX || !nistp_der_parse(der, der_len, r, s, c->nbytes))
        return AMA_ERROR_INVALID_PARAM;
    if (!nistp_scalar_load(v, r, c) || nistp_is_zero(v, c->nlimbs))
        goto done;
    if (!nistp_scalar_load(v, s, c) || nistp_is_zero(v, c->nlimbs))
        goto done;

    memcpy(raw, r, c->nbytes);
    memcpy(raw + c->nbytes, s, c->nbytes);
    *raw_len = (size_t)c->nbytes * 2u;
    rc = AMA_SUCCESS;

done:
    ama_secure_memzero(v, sizeof(v));
    ama_secure_memzero(r, sizeof(r));
    ama_secure_memzero(s, sizeof(s));
    return rc;
}

AMA_API ama_error_t ama_nistp_sig_raw_to_der(ama_nist_curve_t curve,
                                             const uint8_t *raw, size_t raw_len,
                                             uint8_t *der, size_t *der_len) {
    const nistp_curve *c = nistp_lookup(curve);
    uint64_t v[AMA_NISTP_MAX_LIMBS];
    ama_error_t rc = AMA_ERROR_INVALID_PARAM;

    if (!c || !raw || !der || !der_len)
        return AMA_ERROR_INVALID_PARAM;
    if (raw_len != (size_t)c->nbytes * 2u)
        return AMA_ERROR_INVALID_PARAM;
    if (!nistp_scalar_load(v, raw, c) || nistp_is_zero(v, c->nlimbs))
        goto done;
    if (!nistp_scalar_load(v, raw + c->nbytes, c) || nistp_is_zero(v, c->nlimbs))
        goto done;

    *der_len = nistp_der_encode(der, raw, raw + c->nbytes, c->nbytes);
    rc = AMA_SUCCESS;

done:
    ama_secure_memzero(v, sizeof(v));
    return rc;
}

/* ============================================================================
 * TEST-ONLY EXPORTS
 *
 * Not declared in any public header — visible only to AMA_TESTING_MODE builds
 * of the test static library.  They exist so tests/c/test_nistp.c can prove
 * the two things the public API cannot distinguish on its own: that the
 * hardcoded Montgomery constants really are derived from p and n, and that
 * the windowed scalar multiplication agrees with a naive double-and-add
 * reference over the boundary lattice.
 * ============================================================================ */

#ifdef AMA_TESTING_MODE

int ama_nistp_test_constants(int curve_index, uint64_t *rr_p_out, uint64_t *rr_n_out,
                             uint64_t *p0inv_out, uint64_t *n0inv_out, unsigned *nlimbs_out);
int ama_nistp_test_constants(int curve_index, uint64_t *rr_p_out, uint64_t *rr_n_out,
                             uint64_t *p0inv_out, uint64_t *n0inv_out, unsigned *nlimbs_out) {
    const nistp_curve *c;
    if (curve_index < 0 || curve_index > 2)
        return 0;
    c = &NISTP_CURVES[curve_index];
    memcpy(rr_p_out, c->rr_p, sizeof(uint64_t) * c->nlimbs);
    memcpy(rr_n_out, c->rr_n, sizeof(uint64_t) * c->nlimbs);
    *p0inv_out = c->p0inv;
    *n0inv_out = c->n0inv;
    *nlimbs_out = c->nlimbs;
    return 1;
}

int ama_nistp_test_modulus(int curve_index, uint64_t *p_out, uint64_t *n_out);
int ama_nistp_test_modulus(int curve_index, uint64_t *p_out, uint64_t *n_out) {
    const nistp_curve *c;
    if (curve_index < 0 || curve_index > 2)
        return 0;
    c = &NISTP_CURVES[curve_index];
    memcpy(p_out, c->p, sizeof(uint64_t) * c->nlimbs);
    memcpy(n_out, c->n, sizeof(uint64_t) * c->nlimbs);
    return 1;
}

/**
 * Reference Montgomery multiply for the MULX/ADX equivalence test.
 *
 * Deliberately routes through the *portable* CIOS body — not the
 * dispatching nistp_mont_mul, which on an ADX host would call the very
 * kernel under test and make the comparison tautological.  `use_n`
 * selects the scalar modulus n and its n0inv; otherwise the field
 * modulus p and p0inv.  Inputs and output are Montgomery-domain limb
 * arrays of length c->nlimbs.  Returns 1 on success, 0 on a bad index.
 */
int ama_nistp_test_mont_mul(int curve_index, int use_n,
                            const uint64_t a[], const uint64_t b[],
                            uint64_t out[]);
int ama_nistp_test_mont_mul(int curve_index, int use_n,
                            const uint64_t a[], const uint64_t b[],
                            uint64_t out[]) {
    const nistp_curve *c;
    if (curve_index < 0 || curve_index > 2)
        return 0;
    c = &NISTP_CURVES[curve_index];
    nistp_mont_mul_body(out, a, b,
                        use_n ? c->n : c->p,
                        use_n ? c->n0inv : c->p0inv,
                        c->nlimbs);
    return 1;
}

/**
 * Reference scalar multiplication: plain MSB-first double-and-add, no window,
 * no table.  Deliberately the most boring correct implementation there is, so
 * that agreeing with it is evidence about `nistp_scalar_mul` and not about a
 * shared bug.  Writes affine X || Y (big-endian, `nbytes` each); returns 0 if
 * the result is the point at infinity.
 */
int ama_nistp_test_scalar_mul_ref(ama_nist_curve_t curve, const uint8_t *scalar,
                                  const uint8_t *point, uint8_t *out);
int ama_nistp_test_scalar_mul_ref(ama_nist_curve_t curve, const uint8_t *scalar,
                                  const uint8_t *point, uint8_t *out) {
    const nistp_curve *c = nistp_lookup(curve);
    uint64_t px[AMA_NISTP_MAX_LIMBS], py[AMA_NISTP_MAX_LIMBS];
    uint64_t x[AMA_NISTP_MAX_LIMBS], y[AMA_NISTP_MAX_LIMBS];
    uint64_t xs[AMA_NISTP_MAX_LIMBS], ys[AMA_NISTP_MAX_LIMBS];
    nistp_jac P, acc;
    unsigned i;
    int j;

    if (!c || !nistp_load_point(px, py, point, c))
        return 0;
    memcpy(P.X, px, sizeof(uint64_t) * c->nlimbs);
    memcpy(P.Y, py, sizeof(uint64_t) * c->nlimbs);
    nistp_mont_one(P.Z, c->rr_p, c->p, c->p0inv, c->nlimbs);

    nistp_jac_set_infinity(&acc);
    for (i = 0; i < c->nbytes; i++) {
        for (j = 7; j >= 0; j--) {
            nistp_jac_double(&acc, &acc, c);
            if ((scalar[i] >> j) & 1)
                nistp_jac_add(&acc, &acc, &P, c);
        }
    }
    if (!nistp_jac_to_affine(x, y, &acc, c))
        return 0;
    nistp_from_mont(xs, x, c->p, c->p0inv, c->nlimbs);
    nistp_from_mont(ys, y, c->p, c->p0inv, c->nlimbs);
    nistp_to_bytes(out, xs, c->nbytes);
    nistp_to_bytes(out + c->nbytes, ys, c->nbytes);
    return 1;
}

/** Windowed scalar multiplication, same output contract as the reference. */
int ama_nistp_test_scalar_mul_win(ama_nist_curve_t curve, const uint8_t *scalar,
                                  const uint8_t *point, uint8_t *out);
int ama_nistp_test_scalar_mul_win(ama_nist_curve_t curve, const uint8_t *scalar,
                                  const uint8_t *point, uint8_t *out) {
    const nistp_curve *c = nistp_lookup(curve);
    uint64_t px[AMA_NISTP_MAX_LIMBS], py[AMA_NISTP_MAX_LIMBS];
    uint64_t x[AMA_NISTP_MAX_LIMBS], y[AMA_NISTP_MAX_LIMBS];
    uint64_t xs[AMA_NISTP_MAX_LIMBS], ys[AMA_NISTP_MAX_LIMBS];
    nistp_jac P, acc;

    if (!c || !nistp_load_point(px, py, point, c))
        return 0;
    memcpy(P.X, px, sizeof(uint64_t) * c->nlimbs);
    memcpy(P.Y, py, sizeof(uint64_t) * c->nlimbs);
    nistp_mont_one(P.Z, c->rr_p, c->p, c->p0inv, c->nlimbs);

    nistp_scalar_mul(&acc, scalar, &P, c);
    if (!nistp_jac_to_affine(x, y, &acc, c))
        return 0;
    nistp_from_mont(xs, x, c->p, c->p0inv, c->nlimbs);
    nistp_from_mont(ys, y, c->p, c->p0inv, c->nlimbs);
    nistp_to_bytes(out, xs, c->nbytes);
    nistp_to_bytes(out + c->nbytes, ys, c->nbytes);
    return 1;
}

/**
 * Fixed-base comb multiplication of the *generator*, same output contract.
 *
 * Exported separately from `..._scalar_mul_win` because the two take different
 * paths through the file and only this one uses the precomputed table. A
 * divergence between them would produce a public key that is internally
 * consistent and wrong — every self-round-trip would still pass, signatures
 * would verify against the wrong public key, and the first thing to notice
 * would be a peer.
 */
int ama_nistp_test_scalar_mul_comb(ama_nist_curve_t curve, const uint8_t *scalar,
                                   uint8_t *out);
int ama_nistp_test_scalar_mul_comb(ama_nist_curve_t curve, const uint8_t *scalar,
                                   uint8_t *out) {
    const nistp_curve *c = nistp_lookup(curve);
    uint64_t x[AMA_NISTP_MAX_LIMBS], y[AMA_NISTP_MAX_LIMBS];
    uint64_t xs[AMA_NISTP_MAX_LIMBS], ys[AMA_NISTP_MAX_LIMBS];
    nistp_jac acc;

    if (!c)
        return 0;
    nistp_scalar_mul_generator(&acc, scalar, c);
    if (!nistp_jac_to_affine(x, y, &acc, c))
        return 0;   /* k = 0 mod n: the identity has no affine form */
    nistp_from_mont(xs, x, c->p, c->p0inv, c->nlimbs);
    nistp_from_mont(ys, y, c->p, c->p0inv, c->nlimbs);
    nistp_to_bytes(out, xs, c->nbytes);
    nistp_to_bytes(out + c->nbytes, ys, c->nbytes);
    return 1;
}

/** Generator in affine X || Y form, so tests can drive the multipliers. */
int ama_nistp_test_generator(ama_nist_curve_t curve, uint8_t *out);
int ama_nistp_test_generator(ama_nist_curve_t curve, uint8_t *out) {
    const nistp_curve *c = nistp_lookup(curve);
    if (!c)
        return 0;
    nistp_to_bytes(out, c->gx, c->nbytes);
    nistp_to_bytes(out + c->nbytes, c->gy, c->nbytes);
    return 1;
}

#endif /* AMA_TESTING_MODE */
