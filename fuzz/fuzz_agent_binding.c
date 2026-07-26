/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * libFuzzer harness for the agent-instance binding layer (INVARIANT-30).
 *
 * Why this target exists
 * ----------------------
 * ama_agent_binding.c is the one place in the tree where a *structured
 * record* — version, lifetime, capability bits, reserved byte, two 32-byte
 * hashes and a MAC tag — is parsed, canonically encoded, and then fed into
 * key derivation.  Every other primitive in fuzz/ has a harness; this surface
 * is the newest and the only one whose refusal is a *policy* decision rather
 * than an arithmetic one, so a fuzzer is the right instrument for it.
 *
 * What is asserted (beyond "does not crash under ASan/UBSan")
 * -----------------------------------------------------------
 *   1. FAIL-CLOSED.  This is the property the whole layer exists for: a
 *      record that demands operator authorization (any restricted capability
 *      bit, or any lifetime other than EPHEMERAL) must NEVER be accepted
 *      without a tag that verifies under a >=32-byte authority key.  The
 *      harness recomputes the predicate independently of the implementation
 *      and traps on any acceptance the policy does not permit.
 *   2. TOTALITY.  check() is called on records built from raw fuzz bytes —
 *      including out-of-range lifetimes, undefined capability bits and a
 *      non-zero reserved byte — so it must be total over arbitrary struct
 *      contents, never reading past a field or trapping.
 *   3. DETERMINISM.  encode(), context() and the bound HKDF are pure
 *      functions of their inputs; two identical calls must agree byte for
 *      byte.
 *   4. NO OUTPUT ON REFUSAL.  When the bound HKDF refuses, it must leave the
 *      caller's okm buffer untouched — a partially-written key would be worse
 *      than no key.
 *   5. ENCODING INJECTIVITY.  The canonical encoding must change whenever any
 *      covered field changes; if it did not, two different bindings would
 *      derive the same key material, collapsing the domain separation.
 *   6. HEAP/STACK SPLIT.  info_len is driven across the 256-byte boundary
 *      where ama_hkdf_agent_bound() switches from its stack buffer to
 *      ama_secure_alloc(), which is exactly where a length-handling bug would
 *      live.
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address,undefined -O1 -g -I../include \
 *         fuzz_agent_binding.c ../src/c/ama_agent_binding.c \
 *         ../src/c/ama_hkdf.c ../src/c/ama_hmac.c ../src/c/ama_sha3.c \
 *         ../src/c/ama_consttime.c ../src/c/ama_core.c -o fuzz_agent_binding
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Layout of the fuzz input:
 *   [0]      control: selects okm length, info length and key length
 *   [1]      lifetime byte      (deliberately unmasked — may be out of range)
 *   [2]      capabilities byte  (deliberately unmasked — may set unknown bits)
 *   [3]      reserved byte      (deliberately unmasked — may be non-zero)
 *   [4..35]  instance_id
 *   [36..67] ethical_profile
 *   [68..99] authorization tag
 *   [100..]  authority key material || info
 */
#define FUZZ_HEADER_BYTES 100

/* Mirrors the policy in ama_agent_binding.c, recomputed here from the record
 * so the assertion below is an INDEPENDENT check rather than a restatement of
 * the implementation. */
static int record_requires_authorization(const ama_agent_binding_t *b) {
    return (b->capabilities & (uint8_t)AMA_AGENT_CAP_RESTRICTED_MASK) != 0u ||
           b->lifetime != (uint8_t)AMA_AGENT_LIFETIME_EPHEMERAL;
}

static int record_is_wellformed(const ama_agent_binding_t *b) {
    return b->version == (uint8_t)AMA_AGENT_BINDING_VERSION &&
           b->reserved == 0u &&
           (b->capabilities & (uint8_t)~(unsigned)AMA_AGENT_CAP_KNOWN_MASK) == 0u &&
           b->lifetime <= (uint8_t)AMA_AGENT_LIFETIME_PERSISTENT;
}

static int buffer_is_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != 0u) return 0;
    }
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < FUZZ_HEADER_BYTES + 1) return 0;

    ama_agent_binding_t b;
    memset(&b, 0, sizeof(b));

    /* The version field is fixed to the supported value most of the time so
     * the fuzzer spends its budget on the policy surface rather than bouncing
     * off the version check; the low bit of the control byte still lets it
     * explore a wrong version. */
    const uint8_t control = data[0];
    b.version = (control & 0x01u) ? data[1] : (uint8_t)AMA_AGENT_BINDING_VERSION;
    b.lifetime = data[1];
    b.capabilities = data[2];
    b.reserved = data[3];
    memcpy(b.instance_id, data + 4, AMA_AGENT_INSTANCE_ID_BYTES);
    memcpy(b.ethical_profile, data + 36, AMA_ETHICAL_PROFILE_BYTES);
    memcpy(b.authorization, data + 68, AMA_AGENT_BINDING_TAG_BYTES);

    const uint8_t *tail = data + FUZZ_HEADER_BYTES;
    size_t tail_len = size - FUZZ_HEADER_BYTES;

    /* Split the tail into an authority key and an info block.  key_len is
     * driven across the 32-byte minimum so both "no usable key" and "usable
     * key" paths are reached. */
    size_t key_len = ((size_t)(control >> 1) * tail_len) / 128u;
    if (key_len > tail_len) key_len = tail_len;
    const uint8_t *key = key_len ? tail : NULL;
    const uint8_t *info = tail + key_len;
    size_t info_len = tail_len - key_len;

    /* ---- 2. TOTALITY: check() over an arbitrary record ------------------ */
    ama_error_t verdict = ama_agent_binding_check(&b, key, key_len);

    /* ---- 1. FAIL-CLOSED --------------------------------------------------
     * Acceptance is permitted ONLY when the record is well-formed and either
     * it needs no authorization, or it presents a non-zero profile and a
     * usable key.  (We cannot recompute the HMAC tag here without
     * reimplementing the construction, so the tag itself is checked by the
     * round-trip below; what this catches is the catastrophic class —
     * accepting a restricted record with no key, no profile, or a malformed
     * shape.) */
    if (verdict == AMA_SUCCESS) {
        if (!record_is_wellformed(&b)) {
            __builtin_trap(); /* accepted a malformed record */
        }
        if (record_requires_authorization(&b)) {
            if (key == NULL || key_len < 32u) {
                __builtin_trap(); /* accepted a restricted record with no usable key */
            }
            if (buffer_is_zero(b.ethical_profile, AMA_ETHICAL_PROFILE_BYTES)) {
                __builtin_trap(); /* accepted a restricted record with no ethical profile */
            }
        }
    }

    /* ---- 3. DETERMINISM of the verdict ---------------------------------- */
    if (ama_agent_binding_check(&b, key, key_len) != verdict) {
        __builtin_trap();
    }

    /* ---- 5. ENCODING INJECTIVITY ---------------------------------------- */
    uint8_t enc1[AMA_AGENT_BINDING_ENCODED_BYTES];
    uint8_t enc2[AMA_AGENT_BINDING_ENCODED_BYTES];
    if (ama_agent_binding_encode(&b, enc1, sizeof(enc1)) == AMA_SUCCESS) {
        if (ama_agent_binding_encode(&b, enc2, sizeof(enc2)) != AMA_SUCCESS ||
            memcmp(enc1, enc2, sizeof(enc1)) != 0) {
            __builtin_trap(); /* encoding is not deterministic */
        }

        /* Perturb one covered field; the encoding must follow. */
        ama_agent_binding_t perturbed = b;
        perturbed.instance_id[data[4] % AMA_AGENT_INSTANCE_ID_BYTES] ^= 0x01u;
        uint8_t enc3[AMA_AGENT_BINDING_ENCODED_BYTES];
        if (ama_agent_binding_encode(&perturbed, enc3, sizeof(enc3)) == AMA_SUCCESS) {
            if (memcmp(enc1, enc3, sizeof(enc1)) == 0) {
                __builtin_trap(); /* distinct bindings share an encoding */
            }
        }

        /* A short output buffer must be refused, never partially written. */
        uint8_t narrow[AMA_AGENT_BINDING_ENCODED_BYTES];
        memset(narrow, 0xA5, sizeof(narrow));
        if (ama_agent_binding_encode(&b, narrow, sizeof(narrow) - 1u) == AMA_SUCCESS) {
            __builtin_trap(); /* encoded into an undersized buffer */
        }
        for (size_t i = 0; i < sizeof(narrow); i++) {
            if (narrow[i] != 0xA5u) {
                __builtin_trap(); /* wrote through an undersized buffer */
            }
        }
    }

    /* ---- signature context: only on acceptance, and deterministic ------- */
    uint8_t ctx1[AMA_AGENT_BINDING_CONTEXT_BYTES];
    uint8_t ctx2[AMA_AGENT_BINDING_CONTEXT_BYTES];
    ama_error_t crc1 = ama_agent_binding_context(&b, key, key_len, ctx1);
    ama_error_t crc2 = ama_agent_binding_context(&b, key, key_len, ctx2);
    if (crc1 != crc2) {
        __builtin_trap();
    }
    if (crc1 == AMA_SUCCESS) {
        if (verdict != AMA_SUCCESS) {
            __builtin_trap(); /* context minted for a refused binding */
        }
        if (memcmp(ctx1, ctx2, sizeof(ctx1)) != 0) {
            __builtin_trap(); /* context is not deterministic */
        }
    }

    /* ---- 4 + 6. bound HKDF: refusal writes nothing; cross the 256-byte
     *             stack/heap split. ------------------------------------- */
    size_t okm_len = ((size_t)control % 64u) + 1u;
    uint8_t okm1[64];
    uint8_t okm2[64];
    memset(okm1, 0x5A, sizeof(okm1));
    memset(okm2, 0x5A, sizeof(okm2));

    /* Cap info so a single fuzz case stays fast, but keep enough range to sit
     * on both sides of the 256-byte stack buffer in ama_hkdf_agent_bound(). */
    size_t bound_info_len = info_len > 512u ? 512u : info_len;

    ama_error_t hrc1 = ama_hkdf_agent_bound(&b, key, key_len,
                                            NULL, 0,
                                            data + 4, AMA_AGENT_INSTANCE_ID_BYTES,
                                            bound_info_len ? info : NULL, bound_info_len,
                                            okm1, okm_len);
    ama_error_t hrc2 = ama_hkdf_agent_bound(&b, key, key_len,
                                            NULL, 0,
                                            data + 4, AMA_AGENT_INSTANCE_ID_BYTES,
                                            bound_info_len ? info : NULL, bound_info_len,
                                            okm2, okm_len);
    if (hrc1 != hrc2) {
        __builtin_trap();
    }
    if (hrc1 == AMA_SUCCESS) {
        if (verdict != AMA_SUCCESS) {
            __builtin_trap(); /* derived key material for a refused binding */
        }
        if (memcmp(okm1, okm2, okm_len) != 0) {
            __builtin_trap(); /* derivation is not deterministic */
        }
    } else {
        /* Refusal must leave the output buffer exactly as the caller left it. */
        for (size_t i = 0; i < sizeof(okm1); i++) {
            if (okm1[i] != 0x5A || okm2[i] != 0x5A) {
                __builtin_trap(); /* partial write on a refused derivation */
            }
        }
    }

    /* ---- authorize()/check() round trip on a well-formed record ---------
     * Uses the fuzzed bytes as the authority key, so the tag path is driven
     * with attacker-chosen keys rather than a fixed one. */
    if (key_len >= 32u) {
        ama_agent_binding_t issued;
        if (ama_agent_binding_init(&issued,
                                   AMA_AGENT_LIFETIME_PERSISTENT,
                                   (uint8_t)AMA_AGENT_CAP_PERSISTENCE,
                                   data + 4,
                                   data + 36) == AMA_SUCCESS) {
            /* Before authorization the policy must refuse. */
            if (ama_agent_binding_check(&issued, key, key_len) == AMA_SUCCESS) {
                __builtin_trap(); /* restricted binding accepted before authorize() */
            }
            if (ama_agent_binding_authorize(&issued, key, key_len) == AMA_SUCCESS) {
                /* ...and after authorization it must accept under that key. */
                if (ama_agent_binding_check(&issued, key, key_len) != AMA_SUCCESS) {
                    __builtin_trap(); /* valid tag rejected */
                }
                /* A single flipped tag bit must be refused. */
                issued.authorization[data[2] % AMA_AGENT_BINDING_TAG_BYTES] ^= 0x01u;
                if (ama_agent_binding_check(&issued, key, key_len) == AMA_SUCCESS) {
                    __builtin_trap(); /* tampered tag accepted */
                }
            }
        }
    }

    return 0;
}
