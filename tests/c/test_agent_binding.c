/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * Agent-instance binding tests
 * ============================
 *
 * Covers the four properties the binding claims:
 *
 *   1. The canonical encoding is byte-stable and injective over every field
 *      (a pinned KAT plus per-field perturbation).
 *   2. Restricted bindings fail closed — no authority key, no ethical profile,
 *      a tampered tag, or a tag minted under a different key all refuse, and
 *      refusal writes no output.
 *   3. Derived key material and signature contexts are separated by binding:
 *      flipping a single capability bit or the lifetime yields unrelated
 *      output.
 *   4. The unrestricted (ephemeral, non-restricted-capability) path needs no
 *      authority key at all, so the common case stays a plain HKDF call.
 *   5. Both derivations produce exactly the layouts the header documents
 *      under "Derivations" (byte KATs computed outside this library).
 */

#include <stdio.h>
#include <string.h>
#include "ama_cryptography.h"
#include "kat_slot_guard.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "✗ FAIL: %s\n", message); \
            return 1; \
        } else { \
            printf("✓ PASS: %s\n", message); \
        } \
    } while(0)

/* Deterministic fixtures — no RNG, so the KAT below is reproducible. */
static const uint8_t INSTANCE_ID[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const uint8_t PROFILE[32] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
};
static const uint8_t AUTHORITY_KEY[32] = {
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf
};
static const uint8_t OTHER_KEY[32] = {
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};
static const uint8_t IKM[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};

/*
 * Pinned canonical encoding of the ephemeral/DATA_SIGN binding over
 * INSTANCE_ID with an absent (all-zero) ethical profile.  This byte string is
 * folded into every derived key and signature context, so a change here
 * silently re-keys every deployment — that is exactly why it is pinned.
 *
 *   0x11 || "AMA-AGENT-BIND-v1" || 01 00 01 00
 *        || 0x20 || instance_id || 0x20 || 00*32
 */
static const uint8_t EXPECTED_ENCODING[AMA_AGENT_BINDING_ENCODED_BYTES] = {
    0x11,
    'A', 'M', 'A', '-', 'A', 'G', 'E', 'N', 'T', '-',
    'B', 'I', 'N', 'D', '-', 'v', '1',
    0x01, 0x00, 0x01, 0x00,
    0x20,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*
 * Derivation KATs (header, AGENT-INSTANCE BINDING, "Derivations"):
 *
 *   ctx   = SHA3-256(0x02 || enc(b) || binder_ctx)
 *   okm   = HKDF-SHA3-256(salt, ikm, enc(b) || binder_kdf || u32be(len) || info)
 *   binder_kdf = HMAC-SHA3-256(K_auth, 0x03 || enc(b))  } binding requires
 *   binder_ctx = HMAC-SHA3-256(K_auth, 0x04 || enc(b))  } authorization
 *   binder_kdf = binder_ctx = 0^32                         otherwise
 *
 * The expected bytes were computed OUTSIDE this library, from the formulas
 * above, with Python's hashlib.sha3_256 and hmac over the fixtures in this
 * file (salt absent; ikm = IKM).  They pin the published contract, not
 * whatever the implementation happens to do: until the 2026-09-24 review the
 * header still stated the 4.x layouts -- SHA3-256(0x02 || enc(b)) and
 * enc(b) || u32be(len) || info -- which no binding, restricted or not, has
 * produced since the binder landed (c-sym-core#0), and no test compared the
 * two.  For the record, the 4.x values for the ephemeral binding were
 * ctx 62becc27...6f77dc95 and okm("session") 46957769...e33a626f; 5.0.0
 * produces neither, which is the compatibility break the header now states.
 */
static const uint8_t KAT_EPH_CTX[32] = {
    0xa2, 0x55, 0x47, 0x24, 0xd0, 0x2a, 0xbd, 0x7b,
    0xa4, 0x54, 0xc0, 0xbd, 0x0f, 0x13, 0xec, 0x6d,
    0x5e, 0x5e, 0xfd, 0x74, 0x01, 0xe7, 0xc6, 0xd9,
    0xdf, 0xd2, 0x51, 0x5e, 0x57, 0x25, 0x81, 0xf2
};
/* ephemeral / DATA_SIGN, no key, info = "session" */
static const uint8_t KAT_EPH_OKM_SESSION[32] = {
    0xfb, 0x84, 0xeb, 0xaa, 0xfd, 0x48, 0xe0, 0xf4,
    0x0a, 0x70, 0x1e, 0x96, 0x9f, 0xf1, 0xd4, 0x51,
    0x81, 0x87, 0xe8, 0x11, 0xc1, 0xf7, 0xae, 0xef,
    0x9c, 0xe5, 0xce, 0xa6, 0x6a, 0xb6, 0xdf, 0x00
};
/* persistent / DATA_SIGN|PERSISTENCE|SELF_REPLICATE, PROFILE, AUTHORITY_KEY */
static const uint8_t KAT_PERS_CTX[32] = {
    0x12, 0x8f, 0x48, 0xd5, 0x4e, 0xd5, 0xc5, 0x6a,
    0x7a, 0x23, 0xca, 0xed, 0xc4, 0xde, 0x25, 0xda,
    0x75, 0x4b, 0xd7, 0x30, 0x33, 0xdc, 0x97, 0xac,
    0xb8, 0x8f, 0x36, 0x52, 0x4e, 0xea, 0x0b, 0x4e
};
/* same binding and key, info absent */
static const uint8_t KAT_PERS_OKM[32] = {
    0x7a, 0xc7, 0xd8, 0x82, 0xee, 0x50, 0xb6, 0x4c,
    0x31, 0x71, 0x77, 0xa2, 0x62, 0x02, 0x31, 0x28,
    0x12, 0x15, 0x40, 0xd3, 0x0f, 0xd5, 0xb2, 0xe5,
    0x55, 0xdd, 0xb9, 0xdc, 0x07, 0x80, 0x8e, 0xf5
};

static int buffer_is_zero(const uint8_t *p, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        if (p[i] != 0) return 0;
    }
    return 1;
}

/*
 * Property 5.  `eph` is the ephemeral/DATA_SIGN binding with no profile;
 * `pers` is the authorized persistent binding.  The byte KATs pin the
 * contract; the recomputation from the public primitives beside them names
 * which part of the layout moved when a KAT fails.
 */
static int check_derivation_layouts(const ama_agent_binding_t *eph,
                                    const ama_agent_binding_t *pers) {
    uint8_t enc[AMA_AGENT_BINDING_ENCODED_BYTES];
    uint8_t ctx_msg[1 + AMA_AGENT_BINDING_ENCODED_BYTES + 32];
    uint8_t bind_msg[1 + AMA_AGENT_BINDING_ENCODED_BYTES];
    uint8_t info[AMA_AGENT_BINDING_ENCODED_BYTES + 32 + 4 + 7];
    uint8_t got[32], want[32];
    ama_error_t rc;

    /* ---- unrestricted: a 32-byte ZERO binder, whatever key is passed ---- */
    rc = ama_agent_binding_context(eph, NULL, 0, got);
    TEST_ASSERT(rc == AMA_SUCCESS, "layout: ephemeral context derives");
    TEST_ASSERT(memcmp(got, KAT_EPH_CTX, sizeof(got)) == 0,
                "layout: ephemeral context matches the byte KAT");
    rc = ama_agent_binding_encode(eph, enc, sizeof(enc));
    TEST_ASSERT(rc == AMA_SUCCESS, "layout: ephemeral record encodes");
    ctx_msg[0] = 0x02;
    memcpy(ctx_msg + 1, enc, sizeof(enc));
    memset(ctx_msg + 1 + sizeof(enc), 0, 32);
    rc = ama_sha3_256(ctx_msg, sizeof(ctx_msg), want);
    TEST_ASSERT(rc == AMA_SUCCESS, "layout: SHA3-256(0x02 || enc(b) || 0^32) runs");
    TEST_ASSERT(memcmp(got, want, sizeof(got)) == 0,
                "layout: ephemeral context == SHA3-256(0x02 || enc(b) || 0^32)");

    rc = ama_hkdf_agent_bound(eph, NULL, 0, NULL, 0, IKM, sizeof(IKM),
                              (const uint8_t *)"session", 7, got, sizeof(got));
    TEST_ASSERT(rc == AMA_SUCCESS, "layout: ephemeral HKDF derives");
    TEST_ASSERT(memcmp(got, KAT_EPH_OKM_SESSION, sizeof(got)) == 0,
                "layout: ephemeral HKDF output matches the byte KAT");
    memcpy(info, enc, sizeof(enc));
    memset(info + sizeof(enc), 0, 32);
    info[sizeof(enc) + 32 + 0] = 0x00;
    info[sizeof(enc) + 32 + 1] = 0x00;
    info[sizeof(enc) + 32 + 2] = 0x00;
    info[sizeof(enc) + 32 + 3] = 0x07;
    memcpy(info + sizeof(enc) + 32 + 4, "session", 7);
    rc = ama_hkdf(NULL, 0, IKM, sizeof(IKM), info, sizeof(info), want, sizeof(want));
    TEST_ASSERT(rc == AMA_SUCCESS, "layout: HKDF over enc(b) || 0^32 || u32be(7) || info runs");
    TEST_ASSERT(memcmp(got, want, sizeof(got)) == 0,
                "layout: ephemeral HKDF info' == enc(b) || 0^32 || u32be(len) || info");

    /* ---- restricted: binder = HMAC-SHA3-256(K_auth, subdomain || enc(b)) ---- */
    rc = ama_agent_binding_context(pers, AUTHORITY_KEY, sizeof(AUTHORITY_KEY), got);
    TEST_ASSERT(rc == AMA_SUCCESS, "layout: persistent context derives");
    TEST_ASSERT(memcmp(got, KAT_PERS_CTX, sizeof(got)) == 0,
                "layout: persistent context matches the byte KAT");
    rc = ama_agent_binding_encode(pers, enc, sizeof(enc));
    TEST_ASSERT(rc == AMA_SUCCESS, "layout: persistent record encodes");
    bind_msg[0] = 0x04;
    memcpy(bind_msg + 1, enc, sizeof(enc));
    ctx_msg[0] = 0x02;
    memcpy(ctx_msg + 1, enc, sizeof(enc));
    rc = ama_hmac_sha3_256(AUTHORITY_KEY, sizeof(AUTHORITY_KEY), bind_msg,
                           sizeof(bind_msg), ctx_msg + 1 + sizeof(enc));
    TEST_ASSERT(rc == AMA_SUCCESS, "layout: context binder HMAC(K_auth, 0x04 || enc(b)) runs");
    rc = ama_sha3_256(ctx_msg, sizeof(ctx_msg), want);
    TEST_ASSERT(rc == AMA_SUCCESS, "layout: SHA3-256(0x02 || enc(b) || binder) runs");
    TEST_ASSERT(memcmp(got, want, sizeof(got)) == 0,
                "layout: persistent context == SHA3-256(0x02 || enc(b) || HMAC(K, 0x04 || enc(b)))");

    rc = ama_hkdf_agent_bound(pers, AUTHORITY_KEY, sizeof(AUTHORITY_KEY),
                              NULL, 0, IKM, sizeof(IKM), NULL, 0, got, sizeof(got));
    TEST_ASSERT(rc == AMA_SUCCESS, "layout: persistent HKDF derives");
    TEST_ASSERT(memcmp(got, KAT_PERS_OKM, sizeof(got)) == 0,
                "layout: persistent HKDF output matches the byte KAT");
    bind_msg[0] = 0x03;
    memcpy(info, enc, sizeof(enc));
    rc = ama_hmac_sha3_256(AUTHORITY_KEY, sizeof(AUTHORITY_KEY), bind_msg,
                           sizeof(bind_msg), info + sizeof(enc));
    TEST_ASSERT(rc == AMA_SUCCESS, "layout: HKDF binder HMAC(K_auth, 0x03 || enc(b)) runs");
    memset(info + sizeof(enc) + 32, 0, 4);   /* u32be(0): info absent */
    rc = ama_hkdf(NULL, 0, IKM, sizeof(IKM), info, sizeof(enc) + 32u + 4u,
                  want, sizeof(want));
    TEST_ASSERT(rc == AMA_SUCCESS, "layout: HKDF over enc(b) || binder || u32be(0) runs");
    TEST_ASSERT(memcmp(got, want, sizeof(got)) == 0,
                "layout: persistent HKDF info' == enc(b) || HMAC(K, 0x03 || enc(b)) || u32be(0)");
    return 0;
}

int main(void) {
    KAT_SLOT_GUARD_OR_EXIT();  /* per-slot KAT sweep: refuse a pin the host did not honour */
    ama_agent_binding_t eph, sess, pers, tampered;
    uint8_t enc[AMA_AGENT_BINDING_ENCODED_BYTES];
    uint8_t enc2[AMA_AGENT_BINDING_ENCODED_BYTES];
    uint8_t ctx_a[AMA_AGENT_BINDING_CONTEXT_BYTES];
    uint8_t ctx_b[AMA_AGENT_BINDING_CONTEXT_BYTES];
    uint8_t okm_a[32], okm_b[32], plain[32];
    ama_error_t rc;

    printf("===========================================\n");
    printf("Agent-Instance Binding Test Suite\n");
    printf("===========================================\n\n");

    /* ---------------------------------------------------------------- */
    /* 1. Construction and canonical encoding                            */
    /* ---------------------------------------------------------------- */

    rc = ama_agent_binding_init(&eph, AMA_AGENT_LIFETIME_EPHEMERAL,
                                AMA_AGENT_CAP_DATA_SIGN, INSTANCE_ID, NULL);
    TEST_ASSERT(rc == AMA_SUCCESS, "init: ephemeral / data-sign binding");
    TEST_ASSERT(buffer_is_zero(eph.authorization, AMA_AGENT_BINDING_TAG_BYTES),
                "init: authorization tag starts empty");
    TEST_ASSERT(buffer_is_zero(eph.ethical_profile, AMA_ETHICAL_PROFILE_BYTES),
                "init: NULL profile encodes as all-zero");

    rc = ama_agent_binding_encode(&eph, enc, sizeof(enc));
    TEST_ASSERT(rc == AMA_SUCCESS, "encode: succeeds for a well-formed record");
    TEST_ASSERT(memcmp(enc, EXPECTED_ENCODING, sizeof(enc)) == 0,
                "encode: matches the pinned canonical byte string (KAT)");

    rc = ama_agent_binding_encode(&eph, enc2, sizeof(enc2) - 1);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM, "encode: short buffer refused");

    rc = ama_agent_binding_encode(NULL, enc2, sizeof(enc2));
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM, "encode: NULL binding refused");

    /* Unknown capability bit / bad lifetime / dirty reserved byte are all
     * structural refusals, not silent acceptances. */
    memcpy(&tampered, &eph, sizeof(tampered));
    tampered.capabilities = 0x80;   /* undefined bit */
    rc = ama_agent_binding_encode(&tampered, enc2, sizeof(enc2));
    TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING, "encode: unknown capability bit refused");

    memcpy(&tampered, &eph, sizeof(tampered));
    tampered.lifetime = 3;          /* outside the enum */
    rc = ama_agent_binding_encode(&tampered, enc2, sizeof(enc2));
    TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING, "encode: undefined lifetime refused");

    memcpy(&tampered, &eph, sizeof(tampered));
    tampered.reserved = 1;
    rc = ama_agent_binding_encode(&tampered, enc2, sizeof(enc2));
    TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING, "encode: non-zero reserved byte refused");

    memcpy(&tampered, &eph, sizeof(tampered));
    tampered.version = 2;
    rc = ama_agent_binding_encode(&tampered, enc2, sizeof(enc2));
    TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING, "encode: wrong version refused");

    rc = ama_agent_binding_init(&eph, (ama_agent_lifetime_t)7,
                                AMA_AGENT_CAP_DATA_SIGN, INSTANCE_ID, NULL);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM, "init: undefined lifetime refused");
    rc = ama_agent_binding_init(&eph, AMA_AGENT_LIFETIME_EPHEMERAL,
                                0x40, INSTANCE_ID, NULL);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM, "init: undefined capability bit refused");
    rc = ama_agent_binding_init(&eph, AMA_AGENT_LIFETIME_EPHEMERAL,
                                AMA_AGENT_CAP_DATA_SIGN, NULL, NULL);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM, "init: NULL instance id refused");

    /* Rebuild the good ephemeral binding the later cases use. */
    rc = ama_agent_binding_init(&eph, AMA_AGENT_LIFETIME_EPHEMERAL,
                                AMA_AGENT_CAP_DATA_SIGN, INSTANCE_ID, NULL);
    TEST_ASSERT(rc == AMA_SUCCESS, "init: ephemeral binding rebuilt");

    /* ---------------------------------------------------------------- */
    /* 2. Unrestricted path needs no authority key                       */
    /* ---------------------------------------------------------------- */

    rc = ama_agent_binding_check(&eph, NULL, 0);
    TEST_ASSERT(rc == AMA_SUCCESS, "check: ephemeral + unrestricted caps passes keyless");

    rc = ama_hkdf_agent_bound(&eph, NULL, 0, NULL, 0, IKM, sizeof(IKM),
                              (const uint8_t *)"session", 7, okm_a, sizeof(okm_a));
    TEST_ASSERT(rc == AMA_SUCCESS, "derive: ephemeral derivation succeeds keyless");
    TEST_ASSERT(!buffer_is_zero(okm_a, sizeof(okm_a)), "derive: output is not all-zero");

    /* The binding really is folded into info — a plain ama_hkdf() over the
     * same salt/ikm/info must not collide with the bound derivation. */
    rc = ama_hkdf(NULL, 0, IKM, sizeof(IKM), (const uint8_t *)"session", 7,
                  plain, sizeof(plain));
    TEST_ASSERT(rc == AMA_SUCCESS, "derive: unbound reference derivation succeeds");
    TEST_ASSERT(memcmp(okm_a, plain, sizeof(plain)) != 0,
                "derive: bound output differs from unbound HKDF");

    rc = ama_agent_binding_context(&eph, NULL, 0, ctx_a);
    TEST_ASSERT(rc == AMA_SUCCESS, "context: ephemeral context derives keyless");

    /* ---------------------------------------------------------------- */
    /* 3. Restricted bindings fail closed                                */
    /* ---------------------------------------------------------------- */

    /* SESSION lifetime alone is enough to require authorization, even with
     * no restricted capability bit set. */
    rc = ama_agent_binding_init(&sess, AMA_AGENT_LIFETIME_SESSION,
                                AMA_AGENT_CAP_KEY_EXCHANGE, INSTANCE_ID, PROFILE);
    TEST_ASSERT(rc == AMA_SUCCESS, "init: session binding");
    rc = ama_agent_binding_check(&sess, NULL, 0);
    TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING,
                "check: session lifetime refused without authority key");

    /* PERSISTENT + SELF_REPLICATE — the July-2026 escape shape: key material
     * that outlives the instance plus a signature a successor would honour. */
    rc = ama_agent_binding_init(&pers, AMA_AGENT_LIFETIME_PERSISTENT,
                                (uint8_t)(AMA_AGENT_CAP_DATA_SIGN |
                                          AMA_AGENT_CAP_PERSISTENCE |
                                          AMA_AGENT_CAP_SELF_REPLICATE),
                                INSTANCE_ID, PROFILE);
    TEST_ASSERT(rc == AMA_SUCCESS, "init: persistent / self-replicating binding");

    rc = ama_agent_binding_check(&pers, NULL, 0);
    TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING,
                "check: persistence refused with no authority key");

    memset(okm_b, 0xAB, sizeof(okm_b));
    rc = ama_hkdf_agent_bound(&pers, NULL, 0, NULL, 0, IKM, sizeof(IKM),
                              NULL, 0, okm_b, sizeof(okm_b));
    TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING,
                "derive: unauthorized persistence derivation refused");
    {
        int untouched = 1;
        size_t i;
        for (i = 0; i < sizeof(okm_b); i++) {
            if (okm_b[i] != 0xAB) { untouched = 0; break; }
        }
        TEST_ASSERT(untouched, "derive: refusal writes no output bytes");
    }

    rc = ama_agent_binding_context(&pers, NULL, 0, ctx_b);
    TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING,
                "context: unauthorized persistence context refused");

    /* Authorize it properly, then re-check. */
    rc = ama_agent_binding_authorize(&pers, AUTHORITY_KEY, sizeof(AUTHORITY_KEY));
    TEST_ASSERT(rc == AMA_SUCCESS, "authorize: operator stamps the tag");
    TEST_ASSERT(!buffer_is_zero(pers.authorization, AMA_AGENT_BINDING_TAG_BYTES),
                "authorize: tag is populated");

    rc = ama_agent_binding_check(&pers, AUTHORITY_KEY, sizeof(AUTHORITY_KEY));
    TEST_ASSERT(rc == AMA_SUCCESS, "check: authorized persistence passes");

    rc = ama_hkdf_agent_bound(&pers, AUTHORITY_KEY, sizeof(AUTHORITY_KEY),
                              NULL, 0, IKM, sizeof(IKM), NULL, 0,
                              okm_b, sizeof(okm_b));
    TEST_ASSERT(rc == AMA_SUCCESS, "derive: authorized persistence derivation succeeds");

    /* ---------------------------------------------------------------- */
    /* The authority key is an INPUT, not only a gate (2026-09 audit A-6) */
    /* ---------------------------------------------------------------- */
    /* The gate above is sound, and both derivations call it.  Until the
     * audit, neither passed the key to the primitive underneath: the HKDF
     * info was `enc(b) || u32be(info_len) || info`, which is a function of
     * public values only.  `ama_agent_binding_encode` works on an
     * unauthorized record, and the adversary this file is about can call
     * `ama_hkdf` itself — so the derived bytes were obtainable without ever
     * holding the key, and the audit obtained them.
     *
     * The first two checks below are inequalities rather than pinned expected
     * values: a KAT would also pass if the derivation started returning a
     * constant.  They are not sufficient on their own, which the
     * reconstruction after them exists to close. */
    {
        uint8_t bypass_info[AMA_AGENT_BINDING_ENCODED_BYTES + 32 + 4];
        uint8_t bypass_okm[32];

        rc = ama_agent_binding_encode(&pers, enc2, sizeof(enc2));
        TEST_ASSERT(rc == AMA_SUCCESS, "binder: the record still encodes (it is public)");

        /* The pre-fix layout: enc(b) || u32be(0). */
        memcpy(bypass_info, enc2, sizeof(enc2));
        memset(bypass_info + sizeof(enc2), 0, 4);
        rc = ama_hkdf(NULL, 0, IKM, sizeof(IKM),
                      bypass_info, sizeof(enc2) + 4u, bypass_okm, sizeof(bypass_okm));
        TEST_ASSERT(rc == AMA_SUCCESS, "binder: the bypass derivation itself runs");
        TEST_ASSERT(memcmp(bypass_okm, okm_b, sizeof(okm_b)) != 0,
                    "binder: the audit's public-encoding bypass no longer reproduces the key");

        /* The current layout with a guessed all-zero binder. */
        memcpy(bypass_info, enc2, sizeof(enc2));
        memset(bypass_info + sizeof(enc2), 0, 32 + 4);
        rc = ama_hkdf(NULL, 0, IKM, sizeof(IKM),
                      bypass_info, sizeof(bypass_info), bypass_okm, sizeof(bypass_okm));
        TEST_ASSERT(rc == AMA_SUCCESS, "binder: the zero-binder derivation itself runs");
        TEST_ASSERT(memcmp(bypass_okm, okm_b, sizeof(okm_b)) != 0,
                    "binder: a guessed zero binder does not reproduce a restricted key");

        /* Neither inequality above can tell WHICH key the binder was taken
         * under.  A binder keyed by a public constant (the all-zero key that
         * compute_binding_tag substitutes for a NULL key, say) fails both of
         * them exactly as a real one does, and is recomputable by anyone who
         * holds enc(b), which is the audit's bypass again.  Measured: with
         * authority_binder() passing NULL/0 instead of the authority key,
         * every check in this block up to here passed.  So the layout is
         * rebuilt from its parts: HMAC-SHA3-256(K, subdomain || enc(b)) under
         * the authority key must reproduce both outputs, and the same
         * construction under the zero key or a foreign key must not.  A
         * reconstruction from K is not a constant KAT: it moves with K. */
        {
            static const uint8_t ZERO_KEY[32] = {0};
            static const char *const HKDF_LABELS[3] = {
                "binder: HMAC(K_auth, 0x03 || enc(b)) reproduces the restricted key",
                "binder: the same construction under the zero key does not",
                "binder: the same construction under a foreign key does not",
            };
            static const char *const CTX_LABELS[3] = {
                "binder: SHA3(0x02 || enc(b) || HMAC(K_auth, 0x04 || enc(b))) is the context",
                "binder: the context construction under the zero key does not match",
                "binder: the context construction under a foreign key does not match",
            };
            const uint8_t *const binder_keys[3] = {AUTHORITY_KEY, ZERO_KEY, OTHER_KEY};
            uint8_t binder_msg[1 + AMA_AGENT_BINDING_ENCODED_BYTES];
            uint8_t ctx_msg[1 + AMA_AGENT_BINDING_ENCODED_BYTES + 32];
            uint8_t ctx_real[AMA_AGENT_BINDING_CONTEXT_BYTES];
            uint8_t ctx_ref[AMA_AGENT_BINDING_CONTEXT_BYTES];
            size_t k;

            rc = ama_agent_binding_context(&pers, AUTHORITY_KEY, sizeof(AUTHORITY_KEY),
                                           ctx_real);
            TEST_ASSERT(rc == AMA_SUCCESS, "binder: the authorized context derives");

            memcpy(binder_msg + 1, enc2, sizeof(enc2));
            for (k = 0; k < 3; k++) {
                const int must_match = (k == 0);

                /* enc(b) || HMAC(K, 0x03 || enc(b)) || u32be(0) */
                binder_msg[0] = 0x03u;
                memcpy(bypass_info, enc2, sizeof(enc2));
                rc = ama_hmac_sha3_256(binder_keys[k], 32u, binder_msg, sizeof(binder_msg),
                                       bypass_info + sizeof(enc2));
                TEST_ASSERT(rc == AMA_SUCCESS, "binder: the reference HKDF binder computes");
                memset(bypass_info + sizeof(enc2) + 32u, 0, 4);
                rc = ama_hkdf(NULL, 0, IKM, sizeof(IKM),
                              bypass_info, sizeof(bypass_info), bypass_okm, sizeof(bypass_okm));
                TEST_ASSERT(rc == AMA_SUCCESS, "binder: the reference derivation runs");
                TEST_ASSERT((memcmp(bypass_okm, okm_b, sizeof(okm_b)) == 0) == must_match,
                            HKDF_LABELS[k]);

                /* SHA3-256(0x02 || enc(b) || HMAC(K, 0x04 || enc(b))) */
                binder_msg[0] = 0x04u;
                ctx_msg[0] = 0x02u;
                memcpy(ctx_msg + 1, enc2, sizeof(enc2));
                rc = ama_hmac_sha3_256(binder_keys[k], 32u, binder_msg, sizeof(binder_msg),
                                       ctx_msg + 1 + sizeof(enc2));
                TEST_ASSERT(rc == AMA_SUCCESS, "binder: the reference context binder computes");
                rc = ama_sha3_256(ctx_msg, sizeof(ctx_msg), ctx_ref);
                TEST_ASSERT(rc == AMA_SUCCESS, "binder: the reference context hashes");
                TEST_ASSERT((memcmp(ctx_ref, ctx_real, sizeof(ctx_real)) == 0) == must_match,
                            CTX_LABELS[k]);
            }
        }

        /* An UNRESTRICTED binding has no operator secret, so it takes a zero
         * binder by design.  Pinned positively: it is what proves the two
         * inequalities above fail because of a real binder rather than
         * because the layout moved under them. */
        rc = ama_agent_binding_encode(&eph, enc2, sizeof(enc2));
        TEST_ASSERT(rc == AMA_SUCCESS, "binder: the ephemeral record encodes");
        memcpy(bypass_info, enc2, sizeof(enc2));
        memset(bypass_info + sizeof(enc2), 0, 32 + 4);
        rc = ama_hkdf(NULL, 0, IKM, sizeof(IKM),
                      bypass_info, sizeof(bypass_info), bypass_okm, sizeof(bypass_okm));
        TEST_ASSERT(rc == AMA_SUCCESS, "binder: the unrestricted reference derivation runs");
        rc = ama_hkdf_agent_bound(&eph, NULL, 0, NULL, 0, IKM, sizeof(IKM), NULL, 0,
                                  okm_a, sizeof(okm_a));
        TEST_ASSERT(rc == AMA_SUCCESS, "binder: the unrestricted derivation runs");
        TEST_ASSERT(memcmp(bypass_okm, okm_a, sizeof(okm_a)) == 0,
                    "binder: an unrestricted binding uses the documented zero-binder layout");
    }

    /* ---------------------------------------------------------------- */
    /* 5. The derivations are the layouts the header documents           */
    /* ---------------------------------------------------------------- */
    if (check_derivation_layouts(&eph, &pers) != 0) {
        return 1;
    }

    /* A tag minted under a different authority key must not verify — this is
     * the property that an escaped agent cannot satisfy. */
    memcpy(&tampered, &pers, sizeof(tampered));
    rc = ama_agent_binding_authorize(&tampered, OTHER_KEY, sizeof(OTHER_KEY));
    TEST_ASSERT(rc == AMA_SUCCESS, "authorize: foreign key produces a tag");
    rc = ama_agent_binding_check(&tampered, AUTHORITY_KEY, sizeof(AUTHORITY_KEY));
    TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING,
                "check: tag from a foreign authority key refused");

    /* Single-bit tag tampering. */
    memcpy(&tampered, &pers, sizeof(tampered));
    tampered.authorization[17] ^= 0x08;
    rc = ama_agent_binding_check(&tampered, AUTHORITY_KEY, sizeof(AUTHORITY_KEY));
    TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING, "check: single-bit tag flip refused");

    /* Capability escalation after authorization: the tag covers the whole
     * record, so adding DELEGATE invalidates it. */
    memcpy(&tampered, &pers, sizeof(tampered));
    tampered.capabilities |= (uint8_t)AMA_AGENT_CAP_DELEGATE;
    rc = ama_agent_binding_check(&tampered, AUTHORITY_KEY, sizeof(AUTHORITY_KEY));
    TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING,
                "check: post-authorization capability escalation refused");

    /* Relabelling the lifetime downward does not launder restricted
     * capabilities: the capability bits still demand authorization and the
     * tag no longer covers the record. */
    memcpy(&tampered, &pers, sizeof(tampered));
    tampered.lifetime = (uint8_t)AMA_AGENT_LIFETIME_EPHEMERAL;
    rc = ama_agent_binding_check(&tampered, AUTHORITY_KEY, sizeof(AUTHORITY_KEY));
    TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING,
                "check: lifetime downgrade with restricted caps still refused");

    /* Stripping the restricted bits *does* satisfy the policy — an agent may
     * always ask for ordinary ephemeral material.  What it cannot do is reach
     * the persistent key that way: the derivation is a different domain. */
    memcpy(&tampered, &pers, sizeof(tampered));
    tampered.lifetime = (uint8_t)AMA_AGENT_LIFETIME_EPHEMERAL;
    tampered.capabilities = (uint8_t)AMA_AGENT_CAP_DATA_SIGN;
    rc = ama_agent_binding_check(&tampered, NULL, 0);
    TEST_ASSERT(rc == AMA_SUCCESS,
                "check: fully-downgraded record passes as an ordinary ephemeral binding");
    rc = ama_hkdf_agent_bound(&tampered, NULL, 0, NULL, 0, IKM, sizeof(IKM),
                              NULL, 0, okm_a, sizeof(okm_a));
    TEST_ASSERT(rc == AMA_SUCCESS, "derive: downgraded record derives");
    TEST_ASSERT(memcmp(okm_a, okm_b, sizeof(okm_a)) != 0,
                "derive: downgrading does not reproduce the persistent key material");

    /* Restricted capability with an absent ethical profile: refused at issue
     * time and at check time. */
    {
        ama_agent_binding_t no_profile;
        rc = ama_agent_binding_init(&no_profile, AMA_AGENT_LIFETIME_PERSISTENT,
                                    AMA_AGENT_CAP_PERSISTENCE, INSTANCE_ID, NULL);
        TEST_ASSERT(rc == AMA_SUCCESS, "init: persistent binding with no profile");
        rc = ama_agent_binding_authorize(&no_profile, AUTHORITY_KEY,
                                         sizeof(AUTHORITY_KEY));
        TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING,
                    "authorize: restricted binding with no ethical profile refused");
        rc = ama_agent_binding_check(&no_profile, AUTHORITY_KEY,
                                     sizeof(AUTHORITY_KEY));
        TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING,
                    "check: restricted binding with no ethical profile refused");
    }

    /* Short authority keys are below the claimed security level. */
    rc = ama_agent_binding_authorize(&pers, AUTHORITY_KEY, 31);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM, "authorize: sub-256-bit key refused");
    rc = ama_agent_binding_check(&pers, AUTHORITY_KEY, 31);
    TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING, "check: sub-256-bit key refused");

    rc = ama_agent_binding_check(NULL, AUTHORITY_KEY, sizeof(AUTHORITY_KEY));
    TEST_ASSERT(rc == AMA_ERROR_ETHICAL_BINDING, "check: NULL binding fails closed");

    /* ---------------------------------------------------------------- */
    /* 4. Domain separation across bindings                              */
    /* ---------------------------------------------------------------- */

    rc = ama_agent_binding_context(&pers, AUTHORITY_KEY, sizeof(AUTHORITY_KEY), ctx_b);
    TEST_ASSERT(rc == AMA_SUCCESS, "context: authorized persistence context derives");
    TEST_ASSERT(memcmp(ctx_a, ctx_b, sizeof(ctx_a)) != 0,
                "context: distinct bindings yield distinct signature contexts");

    /* The signature context must not equal the authorization tag — separate
     * sub-domain constants exist precisely to prevent that replay. */
    TEST_ASSERT(memcmp(ctx_b, pers.authorization, AMA_AGENT_BINDING_TAG_BYTES) != 0,
                "context: signature context is not the authorization tag");

    /* One capability bit apart => unrelated key material. */
    {
        ama_agent_binding_t cap_a, cap_b;
        uint8_t k1[32], k2[32];
        rc = ama_agent_binding_init(&cap_a, AMA_AGENT_LIFETIME_EPHEMERAL,
                                    AMA_AGENT_CAP_DATA_SIGN, INSTANCE_ID, NULL);
        TEST_ASSERT(rc == AMA_SUCCESS, "init: capability-separation binding A");
        rc = ama_agent_binding_init(&cap_b, AMA_AGENT_LIFETIME_EPHEMERAL,
                                    (uint8_t)(AMA_AGENT_CAP_DATA_SIGN |
                                              AMA_AGENT_CAP_KEY_EXCHANGE),
                                    INSTANCE_ID, NULL);
        TEST_ASSERT(rc == AMA_SUCCESS, "init: capability-separation binding B");
        rc = ama_hkdf_agent_bound(&cap_a, NULL, 0, NULL, 0, IKM, sizeof(IKM),
                                  NULL, 0, k1, sizeof(k1));
        TEST_ASSERT(rc == AMA_SUCCESS, "derive: capability-separation A");
        rc = ama_hkdf_agent_bound(&cap_b, NULL, 0, NULL, 0, IKM, sizeof(IKM),
                                  NULL, 0, k2, sizeof(k2));
        TEST_ASSERT(rc == AMA_SUCCESS, "derive: capability-separation B");
        TEST_ASSERT(memcmp(k1, k2, sizeof(k1)) != 0,
                    "derive: one capability bit apart => unrelated key material");
    }

    /* Different instance ids => unrelated key material. */
    {
        ama_agent_binding_t other_instance;
        uint8_t other_id[32];
        uint8_t k3[32];
        memcpy(other_id, INSTANCE_ID, sizeof(other_id));
        other_id[31] ^= 0x01;
        rc = ama_agent_binding_init(&other_instance, AMA_AGENT_LIFETIME_EPHEMERAL,
                                    AMA_AGENT_CAP_DATA_SIGN, other_id, NULL);
        TEST_ASSERT(rc == AMA_SUCCESS, "init: neighbouring instance id");
        rc = ama_hkdf_agent_bound(&other_instance, NULL, 0, NULL, 0,
                                  IKM, sizeof(IKM), (const uint8_t *)"session", 7,
                                  k3, sizeof(k3));
        TEST_ASSERT(rc == AMA_SUCCESS, "derive: neighbouring instance id");
        /* okm_a was overwritten above; re-derive the reference. */
        rc = ama_hkdf_agent_bound(&eph, NULL, 0, NULL, 0, IKM, sizeof(IKM),
                                  (const uint8_t *)"session", 7, okm_a, sizeof(okm_a));
        TEST_ASSERT(rc == AMA_SUCCESS, "derive: reference instance id");
        TEST_ASSERT(memcmp(k3, okm_a, sizeof(k3)) != 0,
                    "derive: one instance-id bit apart => unrelated key material");
    }

    /* Caller `info` is length-prefixed, so it cannot be split differently to
     * imitate another derivation. */
    {
        uint8_t k4[32], k5[32];
        rc = ama_hkdf_agent_bound(&eph, NULL, 0, NULL, 0, IKM, sizeof(IKM),
                                  (const uint8_t *)"ab", 2, k4, sizeof(k4));
        TEST_ASSERT(rc == AMA_SUCCESS, "derive: info = \"ab\"");
        rc = ama_hkdf_agent_bound(&eph, NULL, 0, NULL, 0, IKM, sizeof(IKM),
                                  (const uint8_t *)"a", 1, k5, sizeof(k5));
        TEST_ASSERT(rc == AMA_SUCCESS, "derive: info = \"a\"");
        TEST_ASSERT(memcmp(k4, k5, sizeof(k4)) != 0,
                    "derive: info length is bound into the derivation");
    }

    /* Long info takes the heap path in ama_hkdf_agent_bound; make sure it is
     * exercised and deterministic. */
    {
        uint8_t long_info[512];
        uint8_t k6[32], k7[32];
        size_t i;
        for (i = 0; i < sizeof(long_info); i++) {
            long_info[i] = (uint8_t)(i & 0xFF);
        }
        rc = ama_hkdf_agent_bound(&eph, NULL, 0, NULL, 0, IKM, sizeof(IKM),
                                  long_info, sizeof(long_info), k6, sizeof(k6));
        TEST_ASSERT(rc == AMA_SUCCESS, "derive: 512-byte info (heap path)");
        rc = ama_hkdf_agent_bound(&eph, NULL, 0, NULL, 0, IKM, sizeof(IKM),
                                  long_info, sizeof(long_info), k7, sizeof(k7));
        TEST_ASSERT(rc == AMA_SUCCESS, "derive: 512-byte info repeat");
        TEST_ASSERT(memcmp(k6, k7, sizeof(k6)) == 0, "derive: heap path is deterministic");
    }

    printf("\n===========================================\n");
    printf("All agent-binding tests passed\n");
    printf("===========================================\n");
    return 0;
}
