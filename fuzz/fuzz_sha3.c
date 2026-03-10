/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * libFuzzer harness for SHA3-256/512 and SHAKE XOF functions.
 *
 * Fuzz targets:
 * - ama_sha3_256: one-shot SHA3-256 hashing
 * - ama_sha3_512: one-shot SHA3-512 hashing
 * - streaming SHA3-256 (init/update/final) with chunked input
 * - SHAKE128/SHAKE256 incremental API
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address -O1 -g -I../include \
 *         fuzz_sha3.c ../src/c/ama_sha3.c ../src/c/ama_consttime.c \
 *         ../src/c/ama_core.c -o fuzz_sha3
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    /* Use first byte to select sub-target */
    uint8_t selector = data[0];
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    switch (selector % 5) {
    case 0: {
        /* SHA3-256 one-shot */
        uint8_t hash[32];
        ama_sha3_256(payload, payload_len, hash);
        break;
    }
    case 1: {
        /* SHA3-512 one-shot */
        uint8_t hash[64];
        ama_sha3_512(payload, payload_len, hash);
        break;
    }
    case 2: {
        /* SHA3-256 streaming: split payload into chunks */
        ama_sha3_ctx ctx;
        uint8_t hash_stream[32];
        uint8_t hash_oneshot[32];

        ama_sha3_init(&ctx);

        /* Feed in variable-sized chunks */
        size_t offset = 0;
        while (offset < payload_len) {
            size_t chunk = payload_len - offset;
            if (chunk > 137) chunk = 137; /* arbitrary chunk size */
            ama_sha3_update(&ctx, payload + offset, chunk);
            offset += chunk;
        }
        ama_sha3_final(&ctx, hash_stream);

        /* Cross-check: streaming must equal one-shot */
        ama_sha3_256(payload, payload_len, hash_oneshot);
        if (memcmp(hash_stream, hash_oneshot, 32) != 0) {
            __builtin_trap();
        }
        break;
    }
    case 3: {
        /* SHAKE256 incremental */
        if (payload_len < 1) break;
        ama_sha3_ctx ctx;
        uint8_t squeeze_buf[64];

        ama_shake256_inc_init(&ctx);
        ama_shake256_inc_absorb(&ctx, payload, payload_len);
        ama_shake256_inc_finalize(&ctx);
        ama_shake256_inc_squeeze(&ctx, squeeze_buf, sizeof(squeeze_buf));
        break;
    }
    case 4: {
        /* SHAKE128 incremental */
        if (payload_len < 1) break;
        ama_sha3_ctx ctx;
        uint8_t squeeze_buf[64];

        ama_shake128_inc_init(&ctx);
        ama_shake128_inc_absorb(&ctx, payload, payload_len);
        ama_shake128_inc_finalize(&ctx);
        ama_shake128_inc_squeeze(&ctx, squeeze_buf, sizeof(squeeze_buf));
        break;
    }
    }

    return 0;
}
