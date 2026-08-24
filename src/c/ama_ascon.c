/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_ascon.c
 * @brief Ascon-AEAD128 and Ascon-Hash256 (NIST SP 800-232)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-07-27
 *
 * Native implementation of the two Ascon functions this project ships, as
 * standardized in NIST SP 800-232, *Ascon-Based Lightweight Cryptography
 * Standards for Constrained Devices* (final, 2025-08-13):
 *
 *   - Ascon-AEAD128  (Sec. 4, Algorithms 3 and 4) — 128-bit key, 128-bit
 *                     nonce, 128-bit tag, rate 128 bits, capacity 192 bits.
 *   - Ascon-Hash256  (Sec. 5, Algorithm 5)        — 256-bit digest,
 *                     rate 64 bits, capacity 256 bits.
 *
 * Ascon-XOF128 and Ascon-CXOF128 are specified in the same document but are
 * deliberately out of scope here; see docs/decisions/0001-adopt-ascon.md.
 *
 * Relationship to Ascon v1.2
 * --------------------------
 * SP 800-232 is NOT byte-compatible with the earlier Ascon v1.2 / CAESAR
 * submission, and code written against v1.2 produces wrong output here.  The
 * three differences that matter to an implementer, all handled below:
 *
 *   1. Rate.  Ascon-AEAD128 absorbs 128 bits per permutation call; v1.2's
 *      Ascon-128 absorbed 64.
 *   2. Initialization vector.  0x00001000808c0001, not v1.2's 0x80400c0600000000.
 *   3. Bit ordering.  SP 800-232 numbers a bitstring from its *least*
 *      significant bit (Appendix A.1), so the domain-separation constant
 *      0^319||1 is the integer 0x8000000000000000 (Appendix A.2), not 1.
 *      A v1.2-derived implementation writes `S4 ^= 1` and silently produces a
 *      non-standard tag on every message that has associated data.
 *
 * Security properties
 * -------------------
 * - No lookup tables anywhere.  The 5-bit S-box is evaluated bitsliced across
 *   the five 64-bit state words, so all 64 parallel applications are pure
 *   register logic.  There is no cache-timing surface to begin with — unlike
 *   table-driven AES, which needed ama_aes_bitsliced.c to acquire the same
 *   property.
 * - No secret-dependent branches or memory offsets.  Every branch below is on
 *   a *length*, which is public in an AEAD, never on key, nonce, plaintext or
 *   tag material.
 * - Tag verification uses ama_consttime_memcmp over all 16 bytes.
 * - Decryption is verify-then-decrypt.  Pass one absorbs the ciphertext and
 *   derives the tag while writing nothing; only a verified tag admits pass
 *   two, which emits plaintext.  On AMA_ERROR_VERIFY_FAILED the caller's
 *   buffer is untouched — not overwritten, not zeroed — the same contract
 *   ama_chacha20poly1305_decrypt and the scalar AES-GCM path provide.
 * - No dynamic allocation anywhere.  A heap scratch buffer would have made
 *   decryption single-pass, and was rejected: Ascon exists for constrained
 *   devices, where malloc is often unavailable, forbidden by coding standard,
 *   or a fragmentation hazard.  The cost is a second pass over the ciphertext
 *   on the success path only; a rejected forgery pays for one pass and stops,
 *   and encryption is unaffected.
 * - The permutation round count is a compile-time constant at every call site,
 *   so the loop bound never depends on secret data.
 *
 * INVARIANT-1 is preserved: this is original code written from the published
 * specification, and introduces no third-party cryptographic dependency.
 */

#include "../include/ama_cryptography.h"
#include <stdint.h>
#include <string.h>


/* ============================================================================
 * STATE AND PERMUTATION (SP 800-232 Sec. 3)
 * ============================================================================ */

/** The 320-bit Ascon state as five 64-bit words (Sec. 3.1, Eq. 2). */
typedef struct {
    uint64_t x[5];
} ama_ascon_state_t;

/**
 * Table 5: const_0 .. const_15, from which round constants are derived.
 *
 * The constant used in round i of Ascon-p[rnd] is const[16 - rnd + i]
 * (Eq. 3), so a 12-round permutation starts at index 4 and an 8-round
 * permutation at index 8.  Both run to index 15.
 */
static const uint64_t AMA_ASCON_RC[16] = {
    0x000000000000003CULL, 0x000000000000002DULL,
    0x000000000000001EULL, 0x000000000000000FULL,
    0x00000000000000F0ULL, 0x00000000000000E1ULL,
    0x00000000000000D2ULL, 0x00000000000000C3ULL,
    0x00000000000000B4ULL, 0x00000000000000A5ULL,
    0x0000000000000096ULL, 0x0000000000000087ULL,
    0x0000000000000078ULL, 0x0000000000000069ULL,
    0x000000000000005AULL, 0x000000000000004BULL
};

/** Ascon-AEAD128 initialization vector (Algorithm 3). */
#define AMA_ASCON_IV_AEAD128 0x00001000808C0001ULL

/** Ascon-Hash256 initialization vector (Algorithm 5, Eq. 54). */
#define AMA_ASCON_IV_HASH256 0x0000080100CC0002ULL

/**
 * Domain-separation constant, i.e. the bitstring 0^319 || 1 in integer form.
 *
 * Appendix A.2 states this explicitly: "The hexadecimal integer form of the
 * domain separation bit is 0x8000000000000000."  This is the single most
 * common porting error from Ascon v1.2 — see the file header.
 */
#define AMA_ASCON_DSEP 0x8000000000000000ULL

/** Rotate right, 64-bit.  n is always a nonzero compile-time constant here. */
static inline uint64_t ama_ascon_ror64(uint64_t v, unsigned n) {
    return (v >> n) | (v << (64 - n));
}

/**
 * One round of the Ascon permutation: p_L o p_S o p_C (Eq. 1).
 *
 * The substitution layer is the standard bitsliced evaluation of the 5-bit
 * S-box: it computes all 64 parallel S-box applications with 22 boolean
 * operations on the five words.  tests/c/test_ascon.c checks this against the
 * lookup-table representation in Table 6 for all 32 inputs, so the bitsliced
 * form is verified equivalent to the specification's own table rather than
 * merely asserted to be.
 */
static inline void ama_ascon_round(ama_ascon_state_t *s, uint64_t c) {
    uint64_t x0 = s->x[0], x1 = s->x[1], x2 = s->x[2];
    uint64_t x3 = s->x[3], x4 = s->x[4];
    uint64_t t0, t1, t2, t3, t4;

    /* p_C — constant addition into S2 (Eq. 4). */
    x2 ^= c;

    /* p_S — substitution layer (Sec. 3.3). */
    x0 ^= x4;  x4 ^= x3;  x2 ^= x1;
    t0 = ~x0 & x1;
    t1 = ~x1 & x2;
    t2 = ~x2 & x3;
    t3 = ~x3 & x4;
    t4 = ~x4 & x0;
    x0 ^= t1;  x1 ^= t2;  x2 ^= t3;  x3 ^= t4;  x4 ^= t0;
    x1 ^= x0;  x0 ^= x4;  x3 ^= x2;  x2 = ~x2;

    /* p_L — linear diffusion layer (Eqs. 8-12). */
    x0 ^= ama_ascon_ror64(x0, 19) ^ ama_ascon_ror64(x0, 28);
    x1 ^= ama_ascon_ror64(x1, 61) ^ ama_ascon_ror64(x1, 39);
    x2 ^= ama_ascon_ror64(x2,  1) ^ ama_ascon_ror64(x2,  6);
    x3 ^= ama_ascon_ror64(x3, 10) ^ ama_ascon_ror64(x3, 17);
    x4 ^= ama_ascon_ror64(x4,  7) ^ ama_ascon_ror64(x4, 41);

    s->x[0] = x0; s->x[1] = x1; s->x[2] = x2; s->x[3] = x3; s->x[4] = x4;
}

/** Ascon-p[12]. */
static void ama_ascon_p12(ama_ascon_state_t *s) {
    for (unsigned i = 0; i < 12u; ++i) {
        ama_ascon_round(s, AMA_ASCON_RC[4u + i]);
    }
}

/** Ascon-p[8]. */
static void ama_ascon_p8(ama_ascon_state_t *s) {
    for (unsigned i = 0; i < 8u; ++i) {
        ama_ascon_round(s, AMA_ASCON_RC[8u + i]);
    }
}

/* ============================================================================
 * WORD <-> BYTE CONVERSION (SP 800-232 Appendix A.1)
 * ============================================================================
 *
 * "the first eight bytes are mapped to the first 64-bit unsigned integer word
 * S0 in little-endian notation".  memcpy plus an explicit byte-swap on
 * big-endian hosts keeps this correct on both, and matches the load32_le /
 * store32_le idiom already used in ama_chacha20poly1305.c.
 */

static inline uint64_t ama_ascon_load64(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, sizeof(v));
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap64(v);
#endif
    return v;
}

static inline void ama_ascon_store64(uint8_t *p, uint64_t v) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap64(v);
#endif
    memcpy(p, &v, sizeof(v));
}

/**
 * Load fewer than eight bytes into the low end of a 64-bit word.
 *
 * Equivalent to loading the block little-endian after zero-extension, which
 * is what parse() plus the integer representation in Appendix A.2 requires.
 */
static inline uint64_t ama_ascon_load_partial(const uint8_t *p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        v |= (uint64_t)p[i] << (8u * i);
    }
    return v;
}

/** Store the low n bytes of a word (n < 8). */
static inline void ama_ascon_store_partial(uint8_t *p, uint64_t v, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        p[i] = (uint8_t)(v >> (8u * i));
    }
}

/*
 * Offset a caller buffer that the API permits to be NULL when its length is
 * zero.
 *
 * Adding to a null pointer is undefined even when the offset is zero
 * (C17 6.5.6p8), and hash256/encrypt/decrypt all accept (NULL, 0) for an
 * empty message, plaintext or ciphertext.  The final-partial-block step runs
 * unconditionally — it must, because pad() is absorbed even for an empty
 * input — so it forms base+i on exactly that path.  Routing those four call
 * sites through these helpers keeps the empty case defined.
 *
 * The branch is on pointer nullness, which is a public property of the call,
 * never on key material or a length derived from it, so the constant-time
 * argument for the tag and payload paths is unaffected.  The per-block loops
 * do not use these: a NULL base with a non-zero length is already rejected,
 * so a loop that executes at all has a non-NULL base and pays nothing.
 */
static inline const uint8_t *ama_ascon_at(const uint8_t *base, size_t off) {
    return (base == NULL) ? NULL : base + off;
}

static inline uint8_t *ama_ascon_at_mut(uint8_t *base, size_t off) {
    return (base == NULL) ? NULL : base + off;
}

/**
 * pad() for a partial block held in one word (Algorithm 2, Appendix A.2).
 *
 * "y <- x XOR (0x0000000000000001 << 8n)" for an n-byte x.  n < 8 always
 * holds at the call sites, so the shift is well defined.
 */
static inline uint64_t ama_ascon_pad(size_t n) {
    return 1ULL << (8u * n);
}

/**
 * Mask selecting the low n bytes of a word, for n < 8.
 *
 * Used by decryption to overwrite the rate with ciphertext.  n == 8 would
 * shift by 64 and is undefined; every call site is inside a branch that has
 * already established n < 8, which is why no runtime guard appears here.
 */
static inline uint64_t ama_ascon_low_mask(size_t n) {
    return (1ULL << (8u * n)) - 1ULL;
}

/* ============================================================================
 * ASCON-HASH256 (SP 800-232 Sec. 5.1, Algorithm 5)
 * ============================================================================ */

AMA_API ama_error_t ama_ascon_hash256(
    const uint8_t *message, size_t message_len,
    uint8_t digest[AMA_ASCON_HASH256_DIGEST_LEN]
) {
    ama_ascon_state_t s;
    size_t i;

    if (digest == NULL) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (message == NULL && message_len != 0) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Initialization: S <- Ascon-p[12](IV || 0^256).
     *
     * Computed rather than pasted from the precomputed table in Appendix A.3.
     * The precomputed words are used in the test suite as an independent check
     * of the permutation, which they can only be if the library does not
     * simply assume them. */
    s.x[0] = AMA_ASCON_IV_HASH256;
    s.x[1] = 0; s.x[2] = 0; s.x[3] = 0; s.x[4] = 0;
    ama_ascon_p12(&s);

    /* Absorbing, rate 64 bits. */
    for (i = 0; i + AMA_ASCON_HASH256_RATE <= message_len;
         i += AMA_ASCON_HASH256_RATE) {
        s.x[0] ^= ama_ascon_load64(message + i);
        ama_ascon_p12(&s);
    }
    {
        const size_t rem = message_len - i;
        s.x[0] ^= ama_ascon_load_partial(ama_ascon_at(message, i), rem);
        s.x[0] ^= ama_ascon_pad(rem);
    }

    /* Squeezing: four 64-bit blocks, a p12 before each subsequent one. */
    ama_ascon_p12(&s);
    ama_ascon_store64(digest, s.x[0]);
    for (i = 1; i < 4; ++i) {
        ama_ascon_p12(&s);
        ama_ascon_store64(digest + 8u * i, s.x[0]);
    }

    ama_secure_memzero(&s, sizeof(s));
    return AMA_SUCCESS;
}

/* ============================================================================
 * ASCON-AEAD128 (SP 800-232 Sec. 4.1, Algorithms 3 and 4)
 * ============================================================================ */

/** Initialization phase, shared by encrypt and decrypt. */
static void ama_ascon_aead_init(
    ama_ascon_state_t *s,
    const uint8_t key[AMA_ASCON_AEAD128_KEY_LEN],
    const uint8_t nonce[AMA_ASCON_AEAD128_NONCE_LEN]
) {
    const uint64_t k0 = ama_ascon_load64(key);
    const uint64_t k1 = ama_ascon_load64(key + 8);

    s->x[0] = AMA_ASCON_IV_AEAD128;
    s->x[1] = k0;
    s->x[2] = k1;
    s->x[3] = ama_ascon_load64(nonce);
    s->x[4] = ama_ascon_load64(nonce + 8);

    ama_ascon_p12(s);

    /* S <- S XOR (0^192 || K) */
    s->x[3] ^= k0;
    s->x[4] ^= k1;
}

/**
 * Associated-data phase plus the domain-separation bit.
 *
 * Note the asymmetry in Algorithm 3: the AD loop runs only when |A| > 0, but
 * the domain-separation XOR happens unconditionally.  Absorbing a padding
 * block for empty AD would change every tag, so the guard is load-bearing.
 */
static void ama_ascon_aead_absorb_ad(
    ama_ascon_state_t *s, const uint8_t *ad, size_t ad_len
) {
    size_t i = 0;

    if (ad_len > 0) {
        for (; i + AMA_ASCON_AEAD128_RATE <= ad_len;
             i += AMA_ASCON_AEAD128_RATE) {
            s->x[0] ^= ama_ascon_load64(ad + i);
            s->x[1] ^= ama_ascon_load64(ad + i + 8);
            ama_ascon_p8(s);
        }
        {
            const size_t rem = ad_len - i;
            if (rem < 8) {
                s->x[0] ^= ama_ascon_load_partial(ad + i, rem);
                s->x[0] ^= ama_ascon_pad(rem);
            } else {
                s->x[0] ^= ama_ascon_load64(ad + i);
                s->x[1] ^= ama_ascon_load_partial(ad + i + 8, rem - 8);
                s->x[1] ^= ama_ascon_pad(rem - 8);
            }
            ama_ascon_p8(s);
        }
    }

    s->x[4] ^= AMA_ASCON_DSEP;
}

/** Finalization: mix the key back in and emit the tag. */
static void ama_ascon_aead_final(
    ama_ascon_state_t *s,
    const uint8_t key[AMA_ASCON_AEAD128_KEY_LEN],
    uint8_t tag[AMA_ASCON_AEAD128_TAG_LEN]
) {
    const uint64_t k0 = ama_ascon_load64(key);
    const uint64_t k1 = ama_ascon_load64(key + 8);

    s->x[2] ^= k0;
    s->x[3] ^= k1;
    ama_ascon_p12(s);
    ama_ascon_store64(tag,     s->x[3] ^ k0);
    ama_ascon_store64(tag + 8, s->x[4] ^ k1);
}

AMA_API ama_error_t ama_ascon_aead128_encrypt(
    const uint8_t key[AMA_ASCON_AEAD128_KEY_LEN],
    const uint8_t nonce[AMA_ASCON_AEAD128_NONCE_LEN],
    const uint8_t *plaintext, size_t pt_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext,
    uint8_t tag[AMA_ASCON_AEAD128_TAG_LEN]
) {
    ama_ascon_state_t s;
    size_t i;

    if (key == NULL || nonce == NULL || tag == NULL) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if ((plaintext == NULL || ciphertext == NULL) && pt_len != 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (aad == NULL && aad_len != 0) {
        return AMA_ERROR_INVALID_PARAM;
    }

    ama_ascon_aead_init(&s, key, nonce);
    ama_ascon_aead_absorb_ad(&s, aad, aad_len);

    for (i = 0; i + AMA_ASCON_AEAD128_RATE <= pt_len;
         i += AMA_ASCON_AEAD128_RATE) {
        s.x[0] ^= ama_ascon_load64(plaintext + i);
        s.x[1] ^= ama_ascon_load64(plaintext + i + 8);
        ama_ascon_store64(ciphertext + i,     s.x[0]);
        ama_ascon_store64(ciphertext + i + 8, s.x[1]);
        ama_ascon_p8(&s);
    }
    {
        const size_t rem = pt_len - i;
        if (rem < 8) {
            s.x[0] ^= ama_ascon_load_partial(ama_ascon_at(plaintext, i), rem);
            s.x[0] ^= ama_ascon_pad(rem);
            ama_ascon_store_partial(ama_ascon_at_mut(ciphertext, i),
                                    s.x[0], rem);
        } else {
            s.x[0] ^= ama_ascon_load64(plaintext + i);
            s.x[1] ^= ama_ascon_load_partial(plaintext + i + 8, rem - 8);
            s.x[1] ^= ama_ascon_pad(rem - 8);
            ama_ascon_store64(ciphertext + i, s.x[0]);
            ama_ascon_store_partial(ciphertext + i + 8, s.x[1], rem - 8);
        }
    }

    ama_ascon_aead_final(&s, key, tag);
    ama_secure_memzero(&s, sizeof(s));
    return AMA_SUCCESS;
}

/**
 * Absorb ciphertext, optionally emitting plaintext (Algorithm 4).
 *
 * The state evolution during decryption depends only on the *ciphertext* —
 * each rate block is overwritten with C_i, not with P_i — so this function
 * advances the state identically whether or not @p plaintext is NULL.  That
 * is what makes the two-pass decrypt below exact: pass one passes NULL to
 * compute the tag without writing anything, pass two passes the caller's
 * buffer and reproduces the same states.
 *
 * @param plaintext Output buffer, or NULL to compute the tag only.
 */
static void ama_ascon_aead_absorb_ct(
    ama_ascon_state_t *s,
    const uint8_t *ciphertext, size_t ct_len,
    uint8_t *plaintext
) {
    size_t i;

    for (i = 0; i + AMA_ASCON_AEAD128_RATE <= ct_len;
         i += AMA_ASCON_AEAD128_RATE) {
        const uint64_t c0 = ama_ascon_load64(ciphertext + i);
        const uint64_t c1 = ama_ascon_load64(ciphertext + i + 8);
        if (plaintext != NULL) {
            ama_ascon_store64(plaintext + i,     s->x[0] ^ c0);
            ama_ascon_store64(plaintext + i + 8, s->x[1] ^ c1);
        }
        s->x[0] = c0;
        s->x[1] = c1;
        ama_ascon_p8(s);
    }
    {
        /* Final partial block (Algorithm 4):
         *   P~n      <- S[0:l-1] XOR C~n
         *   S[l:127] <- S[l:127] XOR (1 || 0^(127-l))
         *   S[0:l-1] <- C~n
         * In integer form: replace the low l bytes of the rate with the
         * ciphertext and XOR the padding bit in at byte offset l. */
        const size_t rem = ct_len - i;
        if (rem < 8) {
            const uint64_t c0 =
                ama_ascon_load_partial(ama_ascon_at(ciphertext, i), rem);
            if (plaintext != NULL) {
                ama_ascon_store_partial(plaintext + i, s->x[0] ^ c0, rem);
            }
            /* Clear the low rem bytes of x[0], then insert c0. */
            s->x[0] &= ~ama_ascon_low_mask(rem);
            s->x[0] |= c0;
            s->x[0] ^= ama_ascon_pad(rem);
        } else {
            const uint64_t c0 = ama_ascon_load64(ciphertext + i);
            const size_t rem1 = rem - 8;
            const uint64_t c1 = ama_ascon_load_partial(ciphertext + i + 8, rem1);
            if (plaintext != NULL) {
                ama_ascon_store64(plaintext + i, s->x[0] ^ c0);
                ama_ascon_store_partial(plaintext + i + 8, s->x[1] ^ c1, rem1);
            }
            s->x[0] = c0;
            s->x[1] &= ~ama_ascon_low_mask(rem1);
            s->x[1] |= c1;
            s->x[1] ^= ama_ascon_pad(rem1);
        }
    }
}

AMA_API ama_error_t ama_ascon_aead128_decrypt(
    const uint8_t key[AMA_ASCON_AEAD128_KEY_LEN],
    const uint8_t nonce[AMA_ASCON_AEAD128_NONCE_LEN],
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t tag[AMA_ASCON_AEAD128_TAG_LEN],
    uint8_t *plaintext
) {
    ama_ascon_state_t s;
    uint8_t computed_tag[AMA_ASCON_AEAD128_TAG_LEN];
    int mismatch;

    if (key == NULL || nonce == NULL || tag == NULL) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if ((ciphertext == NULL || plaintext == NULL) && ct_len != 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (aad == NULL && aad_len != 0) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Verify-then-decrypt, in two passes over the ciphertext.
     *
     * Pass one absorbs the ciphertext and derives the tag while writing
     * nothing.  Only if the tag verifies does pass two re-run the same state
     * machine and emit plaintext.  So on AMA_ERROR_VERIFY_FAILED the caller's
     * buffer is untouched — not overwritten and not zeroed — which is the
     * same contract ama_chacha20poly1305_decrypt and the scalar AES-GCM path
     * provide.  One uniform AEAD decrypt contract across the library beats
     * three subtly different ones.
     *
     * The cost is a second pass over the ciphertext on the SUCCESS path only;
     * a rejected forgery pays for one pass and stops.  Encryption is
     * unaffected.  The alternative — a heap scratch buffer holding plaintext
     * until the tag clears — was rejected deliberately: Ascon exists for
     * constrained devices, where malloc is frequently unavailable, forbidden
     * by coding standard, or a fragmentation hazard.  Trading 2x decrypt
     * throughput for zero dynamic allocation is the right trade for this
     * primitive specifically, and it removes AMA_ERROR_MEMORY from the
     * decrypt contract entirely.  Recorded in docs/decisions/0001-adopt-ascon.md.
     */
    ama_ascon_aead_init(&s, key, nonce);
    ama_ascon_aead_absorb_ad(&s, aad, aad_len);
    ama_ascon_aead_absorb_ct(&s, ciphertext, ct_len, NULL);
    ama_ascon_aead_final(&s, key, computed_tag);

    mismatch = ama_consttime_memcmp(computed_tag, tag,
                                    AMA_ASCON_AEAD128_TAG_LEN);

    ama_secure_memzero(computed_tag, sizeof(computed_tag));
    ama_secure_memzero(&s, sizeof(s));

    if (mismatch != 0) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    /* Authenticated.  Re-run and emit. */
    ama_ascon_aead_init(&s, key, nonce);
    ama_ascon_aead_absorb_ad(&s, aad, aad_len);
    ama_ascon_aead_absorb_ct(&s, ciphertext, ct_len, plaintext);
    ama_secure_memzero(&s, sizeof(s));

    return AMA_SUCCESS;
}

/* ============================================================================
 * TEST SUPPORT
 * ============================================================================ */

/**
 * Expose one permutation call for the known-answer tests.
 *
 * The test suite checks Ascon-p[12] against the precomputed Ascon-Hash256
 * initialization state published in SP 800-232 Appendix A.3, and the
 * bitsliced substitution layer against the Table 6 lookup representation.
 * Neither check is possible through the mode-level API alone, and a
 * permutation verified only indirectly through the modes would let a fault in
 * one cancel a fault in the other.
 */
/* No AMA_API: test-only, deliberately not exported from the shared library
 * (also localised in cmake/ama_exports.map).  The C KAT links it statically
 * via ama_cryptography_test.  Declared in internal/ama_testing_exports.h —
 * NOT in the installed public header, which would promise an ABI the export
 * map exists to withhold. */
#include "internal/ama_testing_exports.h"

void ama_ascon_permutation_for_test(uint64_t state[5], unsigned rounds) {
    ama_ascon_state_t s;
    unsigned i;

    if (state == NULL || rounds == 0u || rounds > 16u) {
        return;
    }
    for (i = 0; i < 5u; ++i) {
        s.x[i] = state[i];
    }
    for (i = 0; i < rounds; ++i) {
        ama_ascon_round(&s, AMA_ASCON_RC[16u - rounds + i]);
    }
    for (i = 0; i < 5u; ++i) {
        state[i] = s.x[i];
    }
}
