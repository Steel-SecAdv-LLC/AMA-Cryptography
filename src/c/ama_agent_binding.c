/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_agent_binding.c
 * @brief Agent-instance key/signature binding (see "AGENT-INSTANCE BINDING"
 *        in include/ama_cryptography.h for the construction and threat model)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-07-26
 *
 * No new algorithms.  This is a domain-separation and policy layer over the
 * primitives already in the tree: SHA3-256 (FIPS 202), HMAC-SHA3-256
 * (RFC 2104), HKDF (RFC 5869), and ama_consttime_memcmp.
 *
 * Constant-time discipline
 * ------------------------
 * ama_agent_binding_check() must not reveal, by timing, whether it refused or
 * which clause refused: an agent probing the boundary would otherwise learn
 * "the profile was accepted but the tag was wrong" and could search the tag
 * space one clause at a time.  So the policy is evaluated as arithmetic on
 * masks, every branch-free predicate runs unconditionally, and the HMAC over
 * the encoded record is computed even when the caller supplied no authority
 * key (a zero key is substituted).  The only data-dependent control flow left
 * is on NULL pointers and buffer capacities, which are caller-visible facts,
 * not secrets.
 */

#include "../include/ama_cryptography.h"
#include <string.h>
#include <stdint.h>

/* Label bytes.  Length-prefixed in the encoding so it cannot be confused with
 * a caller-supplied prefix (17 = 0x11). */
static const uint8_t AMA_AGENT_BIND_LABEL[17] = {
    'A', 'M', 'A', '-', 'A', 'G', 'E', 'N', 'T', '-',
    'B', 'I', 'N', 'D', '-', 'v', '1'
};

/* Sub-domain tags: distinct constants for the two things the encoded record
 * is fed into, so an authorization tag can never be replayed as a signature
 * context (and vice versa). */
#define AMA_AGENT_SUBDOMAIN_AUTH_TAG  0x01u
#define AMA_AGENT_SUBDOMAIN_SIG_CTX   0x02u

/* ========================================================================== */
/* Branch-free helpers                                                        */
/* ========================================================================== */

/**
 * 0xFF..FF when x == 0, else 0.  Operates on the full uint32_t width, so it
 * is correct for any byte-valued input.
 */
static uint32_t ct_is_zero_mask_u32(uint32_t x) {
    /* (x | -x) has its high bit set for every x != 0. */
    return (uint32_t)0 - (uint32_t)(((x | ((uint32_t)0 - x)) >> 31) ^ 1u);
}

/**
 * 0xFF..FF when the buffer is entirely zero, else 0.  Always reads all
 * @p len bytes.
 */
static uint32_t ct_buffer_is_zero_mask(const uint8_t* p, size_t len) {
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        acc = (uint8_t)(acc | p[i]);
    }
    return ct_is_zero_mask_u32((uint32_t)acc);
}

/* ========================================================================== */
/* Structural validation                                                      */
/* ========================================================================== */

/**
 * Is this record well-formed?  Returns 0xFF..FF for yes, 0 for no.
 *
 * "Well-formed" is a public property of a public record — it is checked
 * branch-free anyway so that ama_agent_binding_check() has exactly one exit
 * point and one timing profile.
 */
static uint32_t ct_record_is_wellformed_mask(const ama_agent_binding_t* b) {
    uint32_t bad = 0;

    /* Wrong version. */
    bad |= (uint32_t)b->version ^ (uint32_t)AMA_AGENT_BINDING_VERSION;

    /* reserved MUST be zero — a future field must not be smuggled through a
     * v1 verifier that ignores it. */
    bad |= (uint32_t)b->reserved;

    /* Capability bits this version does not define. */
    bad |= (uint32_t)b->capabilities & (uint32_t)(~(unsigned)AMA_AGENT_CAP_KNOWN_MASK & 0xFFu);

    /* Lifetime outside the defined enum.  Legal values are 0, 1 and 2, so the
     * test is lt > 2; computed branch-free as the borrow out of (2 - lt),
     * which sets the sign bit of the 32-bit difference exactly when lt > 2. */
    bad |= ((uint32_t)2u - (uint32_t)b->lifetime) >> 31;

    return ct_is_zero_mask_u32(bad);
}

/**
 * Does this record demand operator authorization?  Returns 0xFF..FF for yes.
 *
 * Two independent triggers: any restricted capability bit, or any lifetime
 * other than EPHEMERAL.  Either alone is enough.
 */
static uint32_t ct_requires_authorization_mask(const ama_agent_binding_t* b) {
    uint32_t restricted = (uint32_t)b->capabilities & (uint32_t)AMA_AGENT_CAP_RESTRICTED_MASK;
    uint32_t long_lived = (uint32_t)b->lifetime; /* EPHEMERAL == 0 */
    return ~ct_is_zero_mask_u32(restricted | long_lived);
}

/* ========================================================================== */
/* Canonical encoding                                                         */
/* ========================================================================== */

/* The encoding width is the sum of fixed-size components.  Assert it at
 * compile time rather than checking at runtime: a mismatch would silently
 * re-key every deployment, and there is no sensible thing to do about it once
 * the program is running. */
#define AMA_AGENT_ENC_COMPUTED_BYTES                                          \
    (1u + (unsigned)sizeof(AMA_AGENT_BIND_LABEL) + 4u                         \
     + 1u + AMA_AGENT_INSTANCE_ID_BYTES                                       \
     + 1u + AMA_ETHICAL_PROFILE_BYTES)

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(AMA_AGENT_ENC_COMPUTED_BYTES == AMA_AGENT_BINDING_ENCODED_BYTES,
               "AMA_AGENT_BINDING_ENCODED_BYTES disagrees with encode_unchecked()");
#else
typedef char ama_agent_encoding_width_check[
    (AMA_AGENT_ENC_COMPUTED_BYTES == AMA_AGENT_BINDING_ENCODED_BYTES) ? 1 : -1];
#endif

/**
 * Write enc(b) into @p out.  Caller guarantees capacity; structural validity
 * is the caller's business too (both public entry points check first).
 */
static void encode_unchecked(const ama_agent_binding_t* b, uint8_t* out) {
    size_t off = 0;

    out[off++] = (uint8_t)sizeof(AMA_AGENT_BIND_LABEL);   /* 0x11 */
    memcpy(out + off, AMA_AGENT_BIND_LABEL, sizeof(AMA_AGENT_BIND_LABEL));
    off += sizeof(AMA_AGENT_BIND_LABEL);

    out[off++] = b->version;
    out[off++] = b->lifetime;
    out[off++] = b->capabilities;
    out[off++] = b->reserved;

    out[off++] = (uint8_t)AMA_AGENT_INSTANCE_ID_BYTES;    /* 0x20 */
    memcpy(out + off, b->instance_id, AMA_AGENT_INSTANCE_ID_BYTES);
    off += AMA_AGENT_INSTANCE_ID_BYTES;

    out[off++] = (uint8_t)AMA_ETHICAL_PROFILE_BYTES;      /* 0x20 */
    memcpy(out + off, b->ethical_profile, AMA_ETHICAL_PROFILE_BYTES);
    off += AMA_ETHICAL_PROFILE_BYTES;

    /* Width is pinned by the _Static_assert above; `off` is only consumed
     * here so the arithmetic stays visible to a reader following the layout. */
    (void)off;
}

AMA_API ama_error_t ama_agent_binding_encode(
    const ama_agent_binding_t* b,
    uint8_t* out,
    size_t out_cap
) {
    if (!b || !out) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (out_cap < (size_t)AMA_AGENT_BINDING_ENCODED_BYTES) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (ct_record_is_wellformed_mask(b) == 0) {
        return AMA_ERROR_ETHICAL_BINDING;
    }
    encode_unchecked(b, out);
    return AMA_SUCCESS;
}

/* ========================================================================== */
/* Authorization tag                                                          */
/* ========================================================================== */

/**
 * tag = HMAC-SHA3-256(K, subdomain || enc(b))
 *
 * @p key may be NULL, in which case a 32-byte zero key is used.  That case
 * only arises inside ama_agent_binding_check() when the caller supplied no
 * authority key: the HMAC still runs (so the refusal costs the same as an
 * acceptance) and its output is discarded by the policy mask.
 */
static ama_error_t compute_binding_tag(
    const ama_agent_binding_t* b,
    uint8_t subdomain,
    const uint8_t* key,
    size_t key_len,
    uint8_t out_tag[AMA_AGENT_BINDING_TAG_BYTES]
) {
    uint8_t msg[1 + AMA_AGENT_BINDING_ENCODED_BYTES];
    uint8_t zero_key[32];
    ama_error_t rc;

    msg[0] = subdomain;
    encode_unchecked(b, msg + 1);

    if (key == NULL || key_len == 0) {
        ama_secure_memzero(zero_key, sizeof(zero_key));
        rc = ama_hmac_sha3_256(zero_key, sizeof(zero_key), msg, sizeof(msg), out_tag);
    } else {
        rc = ama_hmac_sha3_256(key, key_len, msg, sizeof(msg), out_tag);
    }

    ama_secure_memzero(msg, sizeof(msg));
    ama_secure_memzero(zero_key, sizeof(zero_key));
    return rc;
}

/* ========================================================================== */
/* Public API                                                                 */
/* ========================================================================== */

AMA_API ama_error_t ama_agent_binding_init(
    ama_agent_binding_t* b,
    ama_agent_lifetime_t lifetime,
    uint8_t capabilities,
    const uint8_t instance_id[AMA_AGENT_INSTANCE_ID_BYTES],
    const uint8_t* ethical_profile
) {
    if (!b || !instance_id) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (lifetime != AMA_AGENT_LIFETIME_EPHEMERAL &&
        lifetime != AMA_AGENT_LIFETIME_SESSION &&
        lifetime != AMA_AGENT_LIFETIME_PERSISTENT) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if ((capabilities & (uint8_t)~(unsigned)AMA_AGENT_CAP_KNOWN_MASK) != 0u) {
        return AMA_ERROR_INVALID_PARAM;
    }

    b->version = (uint8_t)AMA_AGENT_BINDING_VERSION;
    b->lifetime = (uint8_t)lifetime;
    b->capabilities = capabilities;
    b->reserved = 0u;
    memcpy(b->instance_id, instance_id, AMA_AGENT_INSTANCE_ID_BYTES);
    if (ethical_profile) {
        memcpy(b->ethical_profile, ethical_profile, AMA_ETHICAL_PROFILE_BYTES);
    } else {
        /* Absent profile is encoded as all-zero and is what the policy check
         * refuses for restricted bindings. */
        ama_secure_memzero(b->ethical_profile, AMA_ETHICAL_PROFILE_BYTES);
    }
    ama_secure_memzero(b->authorization, AMA_AGENT_BINDING_TAG_BYTES);
    return AMA_SUCCESS;
}

AMA_API ama_error_t ama_agent_binding_authorize(
    ama_agent_binding_t* b,
    const uint8_t* authority_key,
    size_t key_len
) {
    ama_error_t rc;

    if (!b || !authority_key) {
        return AMA_ERROR_INVALID_PARAM;
    }
    /* A short authority key would put the whole scheme below the 256-bit
     * security level it claims.  Refuse rather than silently accept. */
    if (key_len < 32) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (ct_record_is_wellformed_mask(b) == 0) {
        return AMA_ERROR_ETHICAL_BINDING;
    }
    /* Authorizing a restricted binding whose ethical profile is absent would
     * produce a tag that ama_agent_binding_check() must then refuse anyway.
     * Refuse at the point of issue so the operator sees the mistake. */
    if (ct_requires_authorization_mask(b) != 0 &&
        ct_buffer_is_zero_mask(b->ethical_profile, AMA_ETHICAL_PROFILE_BYTES) != 0) {
        return AMA_ERROR_ETHICAL_BINDING;
    }

    rc = compute_binding_tag(b, (uint8_t)AMA_AGENT_SUBDOMAIN_AUTH_TAG,
                             authority_key, key_len, b->authorization);
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(b->authorization, AMA_AGENT_BINDING_TAG_BYTES);
    }
    return rc;
}

AMA_API ama_error_t ama_agent_binding_check(
    const ama_agent_binding_t* b,
    const uint8_t* authority_key,
    size_t key_len
) {
    uint8_t expected[AMA_AGENT_BINDING_TAG_BYTES];
    uint32_t wellformed, requires_auth;
    uint32_t profile_absent, key_absent, tag_mismatch;
    uint32_t refuse;
    ama_error_t rc;

    if (!b) {
        return AMA_ERROR_ETHICAL_BINDING;
    }

    wellformed = ct_record_is_wellformed_mask(b);
    requires_auth = ct_requires_authorization_mask(b);

    /* The tag is always computed, for every input, so the refusal path and the
     * acceptance path cost the same.  A malformed record still encodes to
     * something (encode_unchecked is total over the struct); the `wellformed`
     * mask below discards the result. */
    rc = compute_binding_tag(b, (uint8_t)AMA_AGENT_SUBDOMAIN_AUTH_TAG,
                             authority_key, key_len, expected);
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(expected, sizeof(expected));
        return AMA_ERROR_ETHICAL_BINDING;
    }

    profile_absent = ct_buffer_is_zero_mask(b->ethical_profile, AMA_ETHICAL_PROFILE_BYTES);
    /* A NULL key and a key shorter than the 256-bit floor are the same answer:
     * no usable authority key was supplied. */
    key_absent = ct_is_zero_mask_u32((uint32_t)((authority_key != NULL) && (key_len >= 32)));
    /* ama_consttime_memcmp returns 1 on difference; widen to a full mask. */
    tag_mismatch = (uint32_t)0 - (uint32_t)ama_consttime_memcmp(
        b->authorization, expected, AMA_AGENT_BINDING_TAG_BYTES);

    /* Refuse if: the record is malformed, OR authorization is required and any
     * of {profile absent, key absent, tag mismatch} holds.  All three clauses
     * are evaluated; none short-circuits. */
    refuse = ~wellformed;
    refuse |= requires_auth & (profile_absent | key_absent | tag_mismatch);

    ama_secure_memzero(expected, sizeof(expected));

    /* Single exit, selected arithmetically.  AMA_SUCCESS is 0, so multiplying
     * the error code by the refusal bit yields AMA_ERROR_ETHICAL_BINDING or
     * AMA_SUCCESS without a branch and without relying on the
     * implementation-defined conversion of an out-of-range unsigned to int. */
    return (ama_error_t)(AMA_ERROR_ETHICAL_BINDING * (int)(refuse & 1u));
}

AMA_API ama_error_t ama_agent_binding_context(
    const ama_agent_binding_t* b,
    const uint8_t* authority_key,
    size_t key_len,
    uint8_t out_ctx[AMA_AGENT_BINDING_CONTEXT_BYTES]
) {
    uint8_t msg[1 + AMA_AGENT_BINDING_ENCODED_BYTES];
    ama_error_t rc;

    if (!b || !out_ctx) {
        return AMA_ERROR_INVALID_PARAM;
    }

    rc = ama_agent_binding_check(b, authority_key, key_len);
    if (rc != AMA_SUCCESS) {
        return rc;
    }

    msg[0] = (uint8_t)AMA_AGENT_SUBDOMAIN_SIG_CTX;
    encode_unchecked(b, msg + 1);
    rc = ama_sha3_256(msg, sizeof(msg), out_ctx);
    ama_secure_memzero(msg, sizeof(msg));
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(out_ctx, (size_t)AMA_AGENT_BINDING_CONTEXT_BYTES);
    }
    return rc;
}

AMA_API ama_error_t ama_hkdf_agent_bound(
    const ama_agent_binding_t* b,
    const uint8_t* authority_key,
    size_t key_len,
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* ikm,
    size_t ikm_len,
    const uint8_t* info,
    size_t info_len,
    uint8_t* okm,
    size_t okm_len
) {
    /* enc(b) || u32be(info_len) || info.  The 4-byte length prefix keeps the
     * concatenation injective: without it, a caller-chosen `info` could be
     * made to imitate a different binding's trailing bytes. */
    uint8_t prefix[AMA_AGENT_BINDING_ENCODED_BYTES + 4];
    uint8_t stack_info[256];
    uint8_t* joined = NULL;
    int joined_on_heap = 0;
    size_t joined_len;
    ama_error_t rc;

    if (!b || !okm) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!info && info_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    /* The u32be length prefix cannot represent an info longer than 2^32-1.
     * Guarded only where size_t can actually exceed that: on ILP32 the
     * comparison is tautologically false and -Wtype-limits says so. */
#if SIZE_MAX > 0xFFFFFFFFu
    if (info_len > 0xFFFFFFFFu) {
        return AMA_ERROR_OVERFLOW;
    }
#endif
    if (info_len > SIZE_MAX - sizeof(prefix)) {
        return AMA_ERROR_OVERFLOW;
    }

    rc = ama_agent_binding_check(b, authority_key, key_len);
    if (rc != AMA_SUCCESS) {
        return rc;
    }

    encode_unchecked(b, prefix);
    prefix[AMA_AGENT_BINDING_ENCODED_BYTES + 0] = (uint8_t)((info_len >> 24) & 0xFFu);
    prefix[AMA_AGENT_BINDING_ENCODED_BYTES + 1] = (uint8_t)((info_len >> 16) & 0xFFu);
    prefix[AMA_AGENT_BINDING_ENCODED_BYTES + 2] = (uint8_t)((info_len >> 8) & 0xFFu);
    prefix[AMA_AGENT_BINDING_ENCODED_BYTES + 3] = (uint8_t)(info_len & 0xFFu);

    joined_len = sizeof(prefix) + info_len;
    if (joined_len <= sizeof(stack_info)) {
        joined = stack_info;
    } else {
        /* ama_secure_alloc zeroes and (best-effort) locks; the joined info is
         * not secret, but it is adjacent to key derivation and the library
         * already routes such buffers through it. */
        joined = (uint8_t*)ama_secure_alloc(joined_len);
        if (!joined) {
            return AMA_ERROR_MEMORY;
        }
        joined_on_heap = 1;
    }

    memcpy(joined, prefix, sizeof(prefix));
    if (info_len > 0) {
        memcpy(joined + sizeof(prefix), info, info_len);
    }

    rc = ama_hkdf(salt, salt_len, ikm, ikm_len, joined, joined_len, okm, okm_len);

    ama_secure_memzero(prefix, sizeof(prefix));
    if (joined_on_heap) {
        ama_secure_free(joined, joined_len);
    } else {
        ama_secure_memzero(stack_info, sizeof(stack_info));
    }
    return rc;
}
