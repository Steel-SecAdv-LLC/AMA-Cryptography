/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ed25519_frozen_oracle.c
 * @brief Replay tests/oracle/ed25519_frozen_oracle.txt against the linked
 *        Ed25519 backend.
 *
 * The fixture records the answers the since-removed vendored backend gave, at
 * the last commit that carried it, for a deterministic corpus that covers
 * keygen, signing, single and batch verification (honest, malleable, boundary,
 * bit-flipped, non-canonical-R and small-order-R signatures), the two
 * compressed-point decode rules, every group-arithmetic entry point on
 * unreduced scalars and small-order points, and the scalar arithmetic mod l.
 * See tools/freeze_ed25519_oracle.py for the format and the provenance header
 * at the top of the fixture.
 *
 * This is the C twin of tests/test_ed25519_frozen_oracle.py, so the replay
 * also runs where pytest does not: the AArch64/QEMU lanes, the sanitizer
 * lanes, the strict-warnings lanes.  It reads the fixture relative to the
 * source tree (WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} in tests/c/CMakeLists.txt,
 * the convention test_lms and test_kat use).
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ama_cryptography.h"

#define FIXTURE "tests/oracle/ed25519_frozen_oracle.txt"
#define MAX_LINE 2048
#define MAX_FIELDS 8
#define MAX_BYTES 512
#define EXPECTED_RECORDS 2022

static int failures = 0;
static int checked = 0;

static void fail(int line_no, const char *what) {
    failures++;
    if (failures <= 20) {
        fprintf(stderr, "  FAIL line %d: %s\n", line_no, what);
    }
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes a hex token into out; "-" decodes to zero bytes.  Returns the byte
 * count, or -1 on a malformed token. */
static int unhex(const char *tok, uint8_t *out, size_t cap) {
    size_t n = strlen(tok);
    size_t i;
    if (strcmp(tok, "-") == 0) return 0;
    if (n % 2 != 0 || n / 2 > cap) return -1;
    for (i = 0; i < n; i += 2) {
        int hi = hexval(tok[i]);
        int lo = hexval(tok[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(n / 2);
}

static void hexstr(const uint8_t *in, size_t n, char *out) {
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }
    out[2 * n] = '\0';
}

/* Compare a 32-byte output (or a refusal) against the recorded token. */
static void expect_out(int line_no, int rc, const uint8_t out[32], const char *want,
                       const char *what) {
    char got[65];
    if (rc != AMA_SUCCESS) {
        if (strcmp(want, "-") != 0) fail(line_no, what);
        return;
    }
    hexstr(out, 32, got);
    if (strcmp(got, want) != 0) fail(line_no, what);
}

int main(void) {
    FILE *f = fopen(FIXTURE, "rb");
    char line[MAX_LINE];
    int line_no = 0;
    /* Field buffers, one per token position. */
    static uint8_t b[MAX_FIELDS][MAX_BYTES];
    int len[MAX_FIELDS];
    char *tok[MAX_FIELDS];

    if (f == NULL) {
        fprintf(stderr, "cannot open %s (run from the source tree)\n", FIXTURE);
        return 1;
    }
    printf("Ed25519 frozen-oracle replay (%s)\n", FIXTURE);
    printf("  backend: %s\n", ama_ed25519_active_backend());

    while (fgets(line, sizeof line, f) != NULL) {
        int nf = 0;
        char *p = line;
        line_no++;
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r' || line[0] == '\0') continue;
        if (strchr(line, '\n') == NULL && !feof(f)) {
            fail(line_no, "line longer than MAX_LINE");
            fclose(f);
            return 1;
        }
        /* Split on blanks in place (no strtok_r: not in C11, not on MSVC). */
        while (*p != '\0' && nf < MAX_FIELDS) {
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
            if (*p == '\0') break;
            tok[nf++] = p;
            while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
            if (*p != '\0') *p++ = '\0';
        }
        if (nf == 0) continue;
        checked++;

        /* Decode every field after the kind that is not a small integer or an
         * op letter; the per-kind code below knows which are which. */
        {
            int i;
            for (i = 1; i < nf; i++) {
                len[i] = -2; /* not decoded */
            }
        }
#define HEX(i) (len[i] = unhex(tok[i], b[i], MAX_BYTES))
/* On a malformed record: report it and move to the next line.  A `continue`
 * here would bind to the do-while(0) of the macro itself (C11 6.8.6.2), not
 * to the fgets loop, and fall through into the per-kind body with undecoded
 * buffers; the goto leaves the record. */
#define NEED(cond) do { if (!(cond)) { fail(line_no, "malformed record"); goto next_record; } } while (0)

        if (strcmp(tok[0], "K") == 0) {
            uint8_t sk[64], pk[32], sig[64];
            NEED(nf == 5 && HEX(1) == 32 && HEX(2) == 32 && HEX(3) >= 0 && HEX(4) == 64);
            memcpy(sk, b[1], 32);
            if (ama_ed25519_keypair(pk, sk) != AMA_SUCCESS || memcmp(pk, b[2], 32) != 0) {
                fail(line_no, "keypair public key");
            }
            if (ama_ed25519_sign(sig, len[3] ? b[3] : NULL, (size_t)len[3], sk) != AMA_SUCCESS ||
                memcmp(sig, b[4], 64) != 0) {
                fail(line_no, "signature");
            }
        } else if (strcmp(tok[0], "V") == 0) {
            int want, got;
            NEED(nf == 5 && HEX(1) >= 0 && HEX(2) == 64 && HEX(3) == 32);
            want = atoi(tok[4]);
            got = ama_ed25519_verify(b[2], len[1] ? b[1] : NULL, (size_t)len[1], b[3]) == AMA_SUCCESS;
            if (got != want) fail(line_no, "verify verdict");
        } else if (strcmp(tok[0], "B") == 0) {
            int v0, count, i;
            ama_ed25519_batch_entry entries[80];
            int results[80];
            NEED(nf == 7 && HEX(3) >= 0 && HEX(4) == 64 && HEX(5) == 32 && HEX(6) == 64);
            v0 = atoi(tok[1]);
            count = atoi(tok[2]);
            NEED(count >= 1 && count <= 80);
            for (i = 0; i < count; i++) {
                entries[i].message = len[3] ? b[3] : NULL;
                entries[i].message_len = (size_t)len[3];
                entries[i].signature = (i == 0) ? b[4] : b[6];
                entries[i].public_key = b[5];
                results[i] = -1;
            }
            (void)ama_ed25519_batch_verify(entries, (size_t)count, results);
            if (results[0] != v0) fail(line_no, "batch verdict, entry 0");
            for (i = 1; i < count; i++) {
                if (results[i] != 1) {
                    fail(line_no, "batch verdict, honest entry");
                    break;
                }
            }
        } else if (strcmp(tok[0], "D") == 0) {
            static const uint8_t identity[32] = {1};
            static const uint8_t two[32] = {2};
            uint8_t out[32];
            int want, got;
            NEED(nf == 4 && HEX(2) == 32);
            want = atoi(tok[3]);
            if (strcmp(tok[1], "a") == 0) {
                got = ama_ed25519_point_add(out, b[2], identity) == AMA_SUCCESS;
            } else {
                got = ama_ed25519_scalarmult_public(out, two, b[2]) == AMA_SUCCESS;
            }
            if (got != want) fail(line_no, "decode verdict");
        } else if (strcmp(tok[0], "P") == 0) {
            uint8_t out[32];
            NEED(nf == 3 && HEX(1) == 32);
            expect_out(line_no, ama_ed25519_point_from_scalar(out, b[1]), out, tok[2],
                       "point_from_scalar");
        } else if (strcmp(tok[0], "M") == 0) {
            uint8_t out[32];
            NEED(nf == 4 && HEX(1) == 32 && HEX(2) == 32);
            expect_out(line_no, ama_ed25519_scalarmult_public(out, b[1], b[2]), out, tok[3],
                       "scalarmult_public");
        } else if (strcmp(tok[0], "A") == 0) {
            uint8_t out[32];
            NEED(nf == 4 && HEX(1) == 32 && HEX(2) == 32);
            expect_out(line_no, ama_ed25519_point_add(out, b[1], b[2]), out, tok[3], "point_add");
        } else if (strcmp(tok[0], "J") == 0) {
            uint8_t out[32];
            NEED(nf == 6 && HEX(1) == 32 && HEX(2) == 32 && HEX(3) == 32 && HEX(4) == 32);
            expect_out(line_no, ama_ed25519_double_scalarmult_public(out, b[1], b[2], b[3], b[4]),
                       out, tok[5], "double_scalarmult_public");
        } else if (strcmp(tok[0], "R") == 0) {
            uint8_t wide[64];
            NEED(nf == 3 && HEX(1) == 64 && HEX(2) == 32);
            memcpy(wide, b[1], 64);
            ama_ed25519_sc_reduce(wide);
            if (memcmp(wide, b[2], 32) != 0) fail(line_no, "sc_reduce");
        } else if (strcmp(tok[0], "S") == 0) {
            uint8_t out[32];
            NEED(nf == 5 && HEX(1) == 32 && HEX(2) == 32 && HEX(3) == 32 && HEX(4) == 32);
            ama_ed25519_sc_muladd(out, b[1], b[2], b[3]);
            if (memcmp(out, b[4], 32) != 0) fail(line_no, "sc_muladd");
        } else {
            fail(line_no, "unknown record kind");
        }
#undef HEX
#undef NEED
    next_record:;
    }
    fclose(f);

    printf("  records replayed: %d (expected %d)\n", checked, EXPECTED_RECORDS);
    if (checked != EXPECTED_RECORDS) {
        fprintf(stderr, "FAIL: fixture holds %d records, expected %d\n", checked, EXPECTED_RECORDS);
        return 1;
    }
    if (failures != 0) {
        fprintf(stderr, "FAIL: %d mismatch(es) against the frozen oracle\n", failures);
        return 1;
    }
    printf("PASS: the linked backend reproduces every frozen answer\n");
    return 0;
}
