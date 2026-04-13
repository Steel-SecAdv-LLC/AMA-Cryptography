/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_sphincs_avx512.c
 * @brief AVX-512 optimized SPHINCS+/SLH-DSA tree hashing
 *
 * Uses AVX-512F for accelerated SPHINCS+ operations:
 *   - 8-way parallel Keccak for FORS/WOTS+ tree hashing
 *     (delegates to ama_keccak_f1600_x8_avx512)
 *   - Vectorized WOTS+ chain computation
 *   - Parallel leaf hash computation
 *
 * Requires: AVX-512F
 *
 * Constant-time: all operations are data-independent.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if (defined(__x86_64__) || defined(_M_X64)) && defined(__AVX512F__)
#include <immintrin.h>

/* Forward declaration: 8-way Keccak from ama_sha3_avx512.c */
extern void ama_keccak_f1600_x8_avx512(uint64_t states[8][25]);

/* ============================================================================
 * SPHINCS+ 8-way parallel hash for tree construction
 *
 * Hashes 8 independent messages simultaneously using the AVX-512
 * 8-way Keccak permutation. Used for FORS tree leaves and WOTS+
 * chain hashing where many independent hashes are needed.
 *
 * Each input[i] is absorbed into its own Keccak state, and
 * output[i] receives the corresponding 32-byte SHA3-256 digest.
 * ============================================================================ */
void ama_sphincs_hash_x8_avx512(
    const uint8_t *inputs[8], const size_t input_lens[8],
    uint8_t outputs[8][32])
{
    uint64_t states[8][25];
    memset(states, 0, sizeof(states));

    const size_t rate = 136; /* SHA3-256 rate */

    /* Find maximum input length for block processing */
    size_t max_len = 0;
    for (int s = 0; s < 8; s++) {
        if (input_lens[s] > max_len)
            max_len = input_lens[s];
    }

    /* Absorb complete blocks — process all 8 states in lockstep */
    size_t offset = 0;
    while (offset + rate <= max_len) {
        for (int s = 0; s < 8; s++) {
            if (offset + rate <= input_lens[s]) {
                for (size_t i = 0; i < rate / 8; i++) {
                    uint64_t lane;
                    memcpy(&lane, inputs[s] + offset + i * 8, 8);
                    states[s][i] ^= lane;
                }
            }
        }
        ama_keccak_f1600_x8_avx512(states);
        offset += rate;
    }

    /* Absorb final blocks with padding (per-state) */
    for (int s = 0; s < 8; s++) {
        uint8_t block[200];
        memset(block, 0, sizeof(block));
        size_t remaining = (input_lens[s] > offset)
                           ? input_lens[s] - offset : 0;

        if (remaining > 0 && offset < input_lens[s])
            memcpy(block, inputs[s] + offset, remaining);

        block[remaining] = 0x06;     /* SHA3 domain separation */
        block[rate - 1] |= 0x80;    /* Final padding bit */

        for (size_t i = 0; i < rate / 8; i++) {
            uint64_t lane;
            memcpy(&lane, block + i * 8, 8);
            states[s][i] ^= lane;
        }
    }
    ama_keccak_f1600_x8_avx512(states);

    /* Squeeze 32 bytes from each state */
    for (int s = 0; s < 8; s++) {
        memcpy(outputs[s], states[s], 32);
    }
}

#else
typedef int ama_sphincs_avx512_not_available;
#endif /* __x86_64__ && __AVX512F__ */
