/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Kyber-1024 debug test — isolates CPA encrypt/decrypt
 * to verify correctness of the native PQC backend.
 */
#define _POSIX_C_SOURCE 200809L
#include "../../include/ama_cryptography.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern ama_error_t ama_kyber_keypair(uint8_t* pk, size_t pk_len,
                                      uint8_t* sk, size_t sk_len);
extern ama_error_t ama_kyber_encapsulate(const uint8_t* pk, size_t pk_len,
                                          uint8_t* ct, size_t* ct_len,
                                          uint8_t* ss, size_t ss_len);
extern ama_error_t ama_kyber_decapsulate(const uint8_t* ct, size_t ct_len,
                                          const uint8_t* sk, size_t sk_len,
                                          uint8_t* ss, size_t ss_len);

int main(void) {
    setbuf(stdout, NULL);

    uint8_t pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_KYBER_1024_SECRET_KEY_BYTES];
    uint8_t ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
    uint8_t ss_enc[32], ss_dec[32];
    size_t ct_len = sizeof(ct);
    ama_error_t rc;

    printf("Kyber-1024 Debug Test\n");
    printf("=====================\n\n");

    printf("Step 1: Keypair generation...\n");
    rc = ama_kyber_keypair(pk, sizeof(pk), sk, sizeof(sk));
    printf("  keygen: %s (rc=%d)\n", rc == 0 ? "OK" : "FAIL", rc);
    if (rc != 0) return 1;

    /* Print first/last bytes of keys */
    printf("  pk[0..3]: %02X%02X%02X%02X  pk[-4..]: %02X%02X%02X%02X\n",
           pk[0], pk[1], pk[2], pk[3],
           pk[1564], pk[1565], pk[1566], pk[1567]);
    printf("  sk[0..3]: %02X%02X%02X%02X\n", sk[0], sk[1], sk[2], sk[3]);

    /* Check that sk contains pk */
    int pk_in_sk = (memcmp(sk + 4*384, pk, AMA_KYBER_1024_PUBLIC_KEY_BYTES) == 0);
    printf("  sk contains pk: %s\n", pk_in_sk ? "YES" : "NO");

    printf("\nStep 2: Encapsulation...\n");
    rc = ama_kyber_encapsulate(pk, sizeof(pk), ct, &ct_len, ss_enc, sizeof(ss_enc));
    printf("  encap: %s (rc=%d, ct_len=%zu)\n", rc == 0 ? "OK" : "FAIL", rc, ct_len);
    if (rc != 0) return 1;

    printf("  ss_enc[0..7]: %02X%02X%02X%02X%02X%02X%02X%02X\n",
           ss_enc[0], ss_enc[1], ss_enc[2], ss_enc[3],
           ss_enc[4], ss_enc[5], ss_enc[6], ss_enc[7]);

    printf("\nStep 3: Decapsulation...\n");
    rc = ama_kyber_decapsulate(ct, ct_len, sk, sizeof(sk), ss_dec, sizeof(ss_dec));
    printf("  decap: %s (rc=%d)\n", rc == 0 ? "OK" : "FAIL", rc);

    printf("  ss_dec[0..7]: %02X%02X%02X%02X%02X%02X%02X%02X\n",
           ss_dec[0], ss_dec[1], ss_dec[2], ss_dec[3],
           ss_dec[4], ss_dec[5], ss_dec[6], ss_dec[7]);

    int match = (memcmp(ss_enc, ss_dec, 32) == 0);
    printf("\nResult: shared secrets %s\n", match ? "MATCH" : "DO NOT MATCH");

    /* Count differing bytes */
    if (!match) {
        int diff_count = 0;
        for (int i = 0; i < 32; i++) {
            if (ss_enc[i] != ss_dec[i]) diff_count++;
        }
        printf("  %d/32 bytes differ\n", diff_count);
    }

    return match ? 0 : 1;
}
