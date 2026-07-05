/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_sha512_kat.c
 * @brief Standalone SHA-512 (FIPS 180-4) byte-exact known-answer test.
 *
 * Exercises the native SHA-512 core directly.  The one-shot SHA-512 primitive
 * is shipped in the shared library as ama_ed25519_sha512() (the Ed25519 /
 * FROST message hash), a thin public wrapper over the internal FIPS 180-4
 * SHA-512 compression in src/c/internal/ama_sha2.h — the same core that backs
 * ama_hmac_sha512, ama_hmac_sha384, HKDF-SHA-512, and SLH-DSA-SHA2 H_msg.
 * Testing it here pins byte-exactness of the actual linked kernel, independent
 * of those keyed constructions.
 *
 * Vectors:
 *   - Empty string and "abc": the canonical FIPS 180-4 published SHA-512
 *     digests (verbatim from the standard).
 *   - Padding-boundary lengths 111/112/113/127/128/129 and a 256-byte
 *     multi-block input: digests generated with the FIPS 180-4 reference
 *     (Python hashlib.sha512, the same reference nist_vectors/fetch_vectors.py
 *     uses to mint the SHA-256 ACVP set).  SHA-512 has a 128-byte block and a
 *     16-byte length field, so the interesting padding transitions sit at
 *     112 mod 128; these lengths straddle that boundary and the block edge.
 *
 * Always runs (no SKIP) — the SHA-512 core exists on every build.
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failed = 0;
static int passed = 0;

#define CHECK(cond, msg)                                    \
    do {                                                    \
        if (!(cond)) {                                      \
            printf("  FAIL: %s\n", (msg));                  \
            failed++;                                       \
        } else {                                            \
            passed++;                                       \
        }                                                   \
    } while (0)

/* Convert a hex string to bytes; returns byte length. */
static size_t hex2bin(const char *hex, uint8_t *out, size_t out_cap) {
    size_t n = strlen(hex) / 2;
    if (n > out_cap) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned int b = 0;
        sscanf(hex + 2 * i, "%2x", &b);
        out[i] = (uint8_t)b;
    }
    return n;
}

typedef struct {
    const char *name;
    const char *msg_hex; /* "" for the empty message */
    const char *md_hex;  /* expected 64-byte SHA-512 digest, hex */
} sha512_kat_t;

static const sha512_kat_t VECTORS[] = {
    {"empty (FIPS 180-4)", "",
     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
     "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
    {"abc (FIPS 180-4)", "616263",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
    {"len111 (pad boundary)",
     "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186"
     "abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc0126"
     "4b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6"
     "eb10355a7fa4c9ee13385d82a7ccf1",
     "4d1db900250c96436052fbca79c13acbf378aad9c35b87d94c3803264df61fd2"
     "2cbd327c8938d024db372abf4208934ee09367d571d6c670bf74ee07b83e7506"},
    {"len112 (pad boundary)",
     "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186"
     "abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc0126"
     "4b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6"
     "eb10355a7fa4c9ee13385d82a7ccf116",
     "dfb715ca3478a894302ace39c42d1d6646e1044f2247a6274d8b42d155d2fdbe"
     "7017195e85cfba96bedc51f84c44638978a540039ff09c64cef6c0c5ccc8f7b6"},
    {"len113 (pad boundary)",
     "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186"
     "abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc0126"
     "4b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6"
     "eb10355a7fa4c9ee13385d82a7ccf1163b",
     "604b00570a65f49111782330fd36bef680bcc58e13288cbec1b8554e81de17b0"
     "5f53e1293d33673872d0d48a57aba35f539643a3b8210d2bef35531f2b441451"},
    {"len127 (block edge)",
     "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186"
     "abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc0126"
     "4b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6"
     "eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c41",
     "f93a0e7465b294188e8aa2b1cc2e98bc8d5115d46f51c7a9ec599b9d9f96a80f"
     "ef6a4f226b648c89bd9eac23b3d64264898b568d915c66666c44cd0319e2ef56"},
    {"len128 (block edge)",
     "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186"
     "abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc0126"
     "4b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6"
     "eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c4166",
     "0b4815d35f9d07b1a30de2790e1be2a720234295cd7b4d9e9af51719ff90019f"
     "1fe6d4e402a7dcc4177085023dc460ab743dad9b2c1dda42662bda5d3b2e155b"},
    {"len129 (block edge +1)",
     "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186"
     "abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc0126"
     "4b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6"
     "eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c4166"
     "8b",
     "1809db04d02717483e04bc4333a14308bd2d0213ba7bf2c63f11eb1b8a0af825"
     "2e67fd104fd466fb95f945539824d8e4183155fa5ced0bee3dad46d9384a0bd5"},
    {"len256 (multi-block)",
     "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186"
     "abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc0126"
     "4b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6"
     "eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c4166"
     "8bb0d5fa1f44698eb3d8fd22476c91b6db00254a6f94b9de03284d7297bce106"
     "2b50759abfe4092e53789dc2e70c31567ba0c5ea0f34597ea3c8ed12375c81a6"
     "cbf0153a5f84a9cef3183d6287acd1f61b40658aafd4f91e43688db2d7fc2146"
     "6b90b5daff24496e93b8dd02274c7196bbe0052a4f7499bee3082d52779cc1e6",
     "00086aa6fcb4bb59f284fe8079038293aa2c430c4c635663cc04239e5c13d38d"
     "97eaf425edf0aab91cfaec9915a6e297efe64dbda38d3886862ab5232b1e7160"},
};

int main(void) {
    printf("=== SHA-512 (FIPS 180-4) byte-exact KAT ===\n");

    const size_t n_vectors = sizeof(VECTORS) / sizeof(VECTORS[0]);
    for (size_t i = 0; i < n_vectors; i++) {
        const sha512_kat_t *v = &VECTORS[i];
        uint8_t msg[512];
        uint8_t expected[64];
        uint8_t digest[64];

        size_t msg_len = 0;
        if (v->msg_hex[0] != '\0') {
            msg_len = hex2bin(v->msg_hex, msg, sizeof(msg));
            CHECK(msg_len > 0, "message hex decode");
        }
        size_t md_len = hex2bin(v->md_hex, expected, sizeof(expected));
        CHECK(md_len == 64, "expected digest is 64 bytes");

        /* ama_ed25519_sha512 argument order is (data, len, out[64]). */
        ama_ed25519_sha512(msg, msg_len, digest);

        if (memcmp(digest, expected, 64) == 0) {
            printf("  PASS: %s\n", v->name);
            passed++;
        } else {
            printf("  FAIL: %s (digest mismatch)\n", v->name);
            failed++;
        }
    }

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
