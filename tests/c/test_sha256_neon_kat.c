/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_sha256_neon_kat.c
 * @brief FIPS 180-4 KAT pinning `ama_sha256_compress_neon`.
 *
 * Background: PR #311 retired the speculative NEON `wots_chain`
 * byte-identity sub-lane (see `tests/c/test_sphincs_simd_equiv.c`
 * retirement comment).  In the same PR, a real correctness bug in
 * `ama_sha256_compress_neon` (rotation-based schedule passed the same
 * register to both `vsha256su0q_u32` arguments and indexed K-add on
 * a stale slot) was found and fixed.  After the retirement the helper
 * had no regression coverage on any host — the SLH-DSA SIMD-Keccak
 * parity lane that remains exercises SHAKE / Keccak, not SHA-256.
 *
 * This test plugs that gap.  It pins one block of SHA-256 compression
 * (FIPS 180-4 §5.3.3 initial-hash-value, applied to the canonical
 * "abc" message padded to a single 512-bit block per FIPS 180-4
 * §5.1.1) and compares against the known-good digest from FIPS 180-4
 * Appendix B.1 ("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD").
 *
 * CTest SKIP semantics (return 77):
 *   - Non-AArch64 builds (`__aarch64__` undefined): SKIP — the helper
 *     symbol is not built.
 *   - AArch64 build without `__ARM_FEATURE_SHA2`: still exercises the
 *     scalar fallback path (which is also pinned by this KAT — same
 *     bug class, different code path).
 *   - AArch64 with `__ARM_FEATURE_SHA2`: exercises the ARM Crypto
 *     Extensions path that was previously buggy.
 *
 * On all supported AArch64 hosts the test asserts byte-identity to
 * the FIPS 180-4 reference digest; any future regression in either
 * `ama_sha256_compress_neon` lane surfaces as a hard FAIL.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#if defined(__aarch64__) || defined(_M_ARM64)

/* Forward declaration of the helper under test.  The symbol has
 * external linkage (see src/c/neon/ama_sphincs_neon.c) but the
 * function is not exposed via include/ama_cryptography.h because it
 * is an internal SPHINCS+ building block. */
extern void ama_sha256_compress_neon(uint32_t state[8],
                                     const uint8_t block[64]);

/* FIPS 180-4 §5.3.3 SHA-256 initial hash value (H(0)). */
static const uint32_t H256_init[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

/* FIPS 180-4 §B.1 message "abc" padded into a single 512-bit block:
 *   - 'a'=0x61, 'b'=0x62, 'c'=0x63                               (3  B)
 *   - SHA-256 padding: 0x80 marker, then zero-pad through bit 447 (53 B)
 *   - big-endian 64-bit length field = 24 bits = 0x0000000000000018 (8 B)
 * Total = 64 B (one compression block). */
static const uint8_t MSG_ABC_BLOCK[64] = {
    0x61, 0x62, 0x63, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,
};

/* FIPS 180-4 §B.1 expected digest of "abc":
 * BA7816BF 8F01CFEA 414140DE 5DAE2223 B00361A3 96177A9C B410FF61 F20015AD */
static const uint32_t EXPECTED_ABC[8] = {
    0xba7816bfu, 0x8f01cfeau, 0x414140deu, 0x5dae2223u,
    0xb00361a3u, 0x96177a9cu, 0xb410ff61u, 0xf20015adu,
};

/* FIPS 180-4 §B.2 message "" (empty string) padded into one block:
 *   - 0x80 marker, then zero-pad through bit 447 (55 B)
 *   - big-endian 64-bit length field = 0 bits = 0x0000000000000000 (8 B)
 * Expected digest:
 *   e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855 */
static const uint8_t MSG_EMPTY_BLOCK[64] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint32_t EXPECTED_EMPTY[8] = {
    0xe3b0c442u, 0x98fc1c14u, 0x9afbf4c8u, 0x996fb924u,
    0x27ae41e4u, 0x649b934cu, 0xa495991bu, 0x7852b855u,
};

static int check_one(const char *label,
                     const uint8_t block[64],
                     const uint32_t expected[8]) {
    uint32_t state[8];
    memcpy(state, H256_init, sizeof(state));
    ama_sha256_compress_neon(state, block);
    if (memcmp(state, expected, sizeof(state)) != 0) {
        printf("  FAIL: %s digest mismatch\n", label);
        printf("    expected: ");
        for (int i = 0; i < 8; i++) printf("%08x ", expected[i]);
        printf("\n    got:      ");
        for (int i = 0; i < 8; i++) printf("%08x ", state[i]);
        printf("\n");
        return 1;
    }
    printf("  PASS: %s — byte-identical to FIPS 180-4 reference\n", label);
    return 0;
}

int main(void) {
    printf("===========================================\n");
    printf("ama_sha256_compress_neon FIPS 180-4 KAT\n");
    printf("===========================================\n\n");

#if defined(__ARM_FEATURE_SHA2)
    printf("  build: __ARM_FEATURE_SHA2 — ARM Crypto Extensions path\n\n");
#else
    printf("  build: no __ARM_FEATURE_SHA2 — scalar fallback path\n\n");
#endif

    int failed = 0;
    failed += check_one("\"abc\" (FIPS 180-4 §B.1)",
                        MSG_ABC_BLOCK, EXPECTED_ABC);
    failed += check_one("\"\" (FIPS 180-4 §B.2)",
                        MSG_EMPTY_BLOCK, EXPECTED_EMPTY);

    printf("\n===========================================\n");
    if (failed) {
        printf("FAIL: %d KAT mismatch(es)\n", failed);
        printf("===========================================\n");
        return 1;
    }
    printf("All NEON SHA-256 compression KATs passed!\n");
    printf("===========================================\n");
    return 0;
}

#else  /* non-AArch64 */
int main(void) {
    printf("SKIP: test_sha256_neon_kat — non-AArch64 host "
           "(ama_sha256_compress_neon not built)\n");
    return 77;
}
#endif
