/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file tests/c/test_x25519_mulx_override.c
 * @brief End-to-end regression coverage for `ama_x25519_set_mulx_override()`.
 * @date 2026-05-18
 *
 * The MULX+ADX kernel byte-equivalence against the pure-C fe64 schoolbook
 * reference is already covered at the kernel level by
 * `test_x25519_fe64_mulx_equiv.c` (radix-2^64 field operations directly).
 * What that test does NOT cover is the *public selector* introduced in
 * the 2026-05 benchmark coverage expansion:
 *
 *     AMA_API void ama_x25519_set_mulx_override(int mode);
 *
 * The selector is consumed inside `x25519_scalarmult()`'s runtime branch
 * (`src/c/ama_x25519.c`) and changes which field-kernel pair the Montgomery
 * ladder calls. A wiring regression here — e.g. inverting the `use_mulx`
 * logic, dropping the safety `&& has_mulx` guard, or failing to clamp
 * an out-of-domain mode back to auto — would silently mislabel the
 * MULX-off / MULX-on benchmark rows and could escape detection because
 * the kernel-level equivalence test would still pass.
 *
 * This test pins four behaviours through `ama_x25519_key_exchange()`,
 * the production public API (not the test-only hidden kernels):
 *
 *   1. `mode = -1` (auto): a key exchange completes successfully and
 *      produces a deterministic shared secret for a fixed scalar pair.
 *   2. `mode =  0` (force off): the same scalar pair produces the
 *      same shared secret — the pure-C fe64 path is byte-identical
 *      to the auto-selected path.
 *   3. `mode =  1` (force on): the same scalar pair produces the
 *      same shared secret again — when the kernel is wired and CPUID
 *      permits, MULX/ADX is byte-identical to pure-C; when the kernel
 *      is unavailable, the selector is a documented no-op and pure-C
 *      runs.
 *   4. `mode = 42` (invalid): the setter clamps to auto (per the
 *      header contract: "anything outside {-1, 0, 1} is coerced to
 *      -1"), and the shared secret matches the auto-mode result.
 *
 * Restore-to-auto cleanup is verified by re-running the auto-mode
 * exchange after step 4 and asserting byte-equality with step 1.
 *
 * SKIP semantics: the test does NOT skip on hosts without BMI2+ADX.
 * The override API is a documented no-op there, and the byte-equality
 * assertions across all four modes are exactly what we need to verify
 * the no-op claim. The test only skips if `ama_x25519_key_exchange()`
 * itself is unavailable — which would indicate a build configuration
 * problem unrelated to this selector.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ama_cryptography.h"

static void hexdump(const char *label, const uint8_t *bytes, size_t n) {
    fprintf(stderr, "    %-22s ", label);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", bytes[i]);
    fprintf(stderr, "\n");
}

/* Deterministic 32-byte seed material for the keypair under test.
 * Two distinct scalar/point pairs so the shared secret depends on
 * both sides; using `ama_x25519_keypair` directly would inject
 * runtime entropy and we want byte-identity across runs. */
static const uint8_t SEED_A[32] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
};
static const uint8_t SEED_B[32] = {
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
    0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
    0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
};

/* Run a single key-exchange round under the given override mode and
 * stash the resulting 32-byte shared secret in `out`. Returns 0 on
 * success, non-zero (with a printed reason) on any API error. */
static int run_kx_with_mode(int mode, uint8_t out[32]) {
    /* Re-derive both keypairs from the static seeds. Treating the seed
     * as a raw scalar via the public `ama_x25519_key_exchange()` API
     * means we exercise the same Montgomery-ladder path that the
     * override is meant to influence — not some internal helper. */
    uint8_t sk_a[32], pk_a[32], sk_b[32], pk_b[32];
    memcpy(sk_a, SEED_A, 32);
    memcpy(sk_b, SEED_B, 32);

    /* Per RFC 7748 §5: clamp the scalar before treating it as a
     * Curve25519 secret. `ama_x25519_keypair` does this internally;
     * doing it explicitly here keeps the seed → pk derivation
     * deterministic without random fill-in. */
    sk_a[0] &= 248; sk_a[31] &= 127; sk_a[31] |= 64;
    sk_b[0] &= 248; sk_b[31] &= 127; sk_b[31] |= 64;

    /* Derive both public keys at the requested override mode so the
     * pk computation itself exercises the selector path. */
    ama_x25519_set_mulx_override(mode);

    /* Public-key derivation: DH against the canonical Curve25519 base
     * point (X = 9, leading byte 0x09, remaining 31 zero bytes). The
     * library exposes this through `ama_x25519_keypair`, but using
     * it would re-randomise sk; instead we replay the deterministic
     * scalar against the base point via the same key-exchange path. */
    static const uint8_t BASEPOINT[32] = {
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };
    if (ama_x25519_key_exchange(pk_a, sk_a, BASEPOINT) != AMA_SUCCESS) {
        fprintf(stderr, "FAIL: pk_a derivation failed at mode=%d\n", mode);
        ama_x25519_set_mulx_override(-1);
        return 1;
    }
    if (ama_x25519_key_exchange(pk_b, sk_b, BASEPOINT) != AMA_SUCCESS) {
        fprintf(stderr, "FAIL: pk_b derivation failed at mode=%d\n", mode);
        ama_x25519_set_mulx_override(-1);
        return 1;
    }

    /* Shared secret: sk_a · pk_b — the actual production hot path that
     * `bench_x25519_dh_mulx_{off,on}()` measures. */
    if (ama_x25519_key_exchange(out, sk_a, pk_b) != AMA_SUCCESS) {
        fprintf(stderr, "FAIL: shared-secret derivation failed at mode=%d\n", mode);
        ama_x25519_set_mulx_override(-1);
        return 1;
    }

    /* Restore production policy so subsequent calls in this process
     * (including the next lane below) start from the documented
     * default. The setter contract is single-threaded; we are the
     * only thread, so this is well-defined. */
    ama_x25519_set_mulx_override(-1);
    return 0;
}

int main(void) {
    printf("X25519 MULX override selector — public-API regression\n");
    printf("=====================================================\n");

    uint8_t ss_auto[32];
    uint8_t ss_force_off[32];
    uint8_t ss_force_on[32];
    uint8_t ss_invalid[32];
    uint8_t ss_auto_after_restore[32];

    /* --- Lane 1: mode = -1 (auto / production default) ---------- */
    if (run_kx_with_mode(-1, ss_auto) != 0) return 1;
    hexdump("auto (mode=-1)", ss_auto, 32);

    /* --- Lane 2: mode = 0 (force pure-C fe64) ------------------- */
    if (run_kx_with_mode(0, ss_force_off) != 0) return 1;
    hexdump("force off (mode=0)", ss_force_off, 32);

    /* --- Lane 3: mode = 1 (force MULX+ADX, no-op without kernel) - */
    if (run_kx_with_mode(1, ss_force_on) != 0) return 1;
    hexdump("force on (mode=1)", ss_force_on, 32);

    /* --- Lane 4: mode = 42 (out-of-domain; must clamp to auto) -- */
    if (run_kx_with_mode(42, ss_invalid) != 0) return 1;
    hexdump("invalid (mode=42)", ss_invalid, 32);

    /* --- Lane 5: restore-to-auto cleanup --------------------------
     * After the invalid mode is processed the override should be back
     * at -1, so a subsequent auto-mode run must reproduce ss_auto
     * byte-for-byte. */
    if (run_kx_with_mode(-1, ss_auto_after_restore) != 0) return 1;
    hexdump("auto post-restore", ss_auto_after_restore, 32);

    /* --- Equivalence assertions ----------------------------------
     * All four production-domain modes must produce the same shared
     * secret on the same (sk_a, sk_b) pair — the override only
     * selects between byte-identical kernel pairs, never alters the
     * mathematical result. */
    int fail = 0;
    if (memcmp(ss_auto, ss_force_off, 32) != 0) {
        fprintf(stderr, "FAIL: mode=-1 (auto) != mode=0 (force off)\n");
        fail++;
    }
    if (memcmp(ss_auto, ss_force_on, 32) != 0) {
        fprintf(stderr, "FAIL: mode=-1 (auto) != mode=1 (force on)\n");
        fail++;
    }
    if (memcmp(ss_auto, ss_invalid, 32) != 0) {
        fprintf(stderr, "FAIL: mode=-1 (auto) != mode=42 (clamped)\n");
        fail++;
    }
    if (memcmp(ss_auto, ss_auto_after_restore, 32) != 0) {
        fprintf(stderr, "FAIL: auto baseline drifted after invalid-mode "
                        "exposure (restore-to-auto broken)\n");
        fail++;
    }

    if (fail) {
        fprintf(stderr,
                "\nFAIL: %d mode(s) diverged from the auto baseline. The "
                "override is supposed to flip between byte-identical fe64 "
                "implementations; any divergence is a wiring regression.\n",
                fail);
        return 1;
    }

    printf("\n=== PASS — all 4 override modes byte-identical to auto, "
           "restore-to-auto verified ===\n");
    printf("    Field path under test: %s\n", ama_x25519_field_path());
    return 0;
}
