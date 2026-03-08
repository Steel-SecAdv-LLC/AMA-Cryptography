/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Kyber-1024 CPA roundtrip test — exercises NTT and CPA encrypt/decrypt
 * in isolation to verify correctness of the native PQC backend.
 */
#include "../../include/ama_cryptography.h"
#include <stdio.h>
extern int ama_kyber_debug_ntt_roundtrip(void);
extern int ama_kyber_debug_cpa_roundtrip(void);
int main(void) {
    setbuf(stdout, NULL);
    printf("=== NTT Roundtrip Test ===\n");
    int ntt_rc = ama_kyber_debug_ntt_roundtrip();
    printf("NTT: %s\n\n", ntt_rc == 0 ? "PASS" : "FAIL");

    printf("=== CPA Encrypt/Decrypt Test ===\n");
    int cpa_rc = ama_kyber_debug_cpa_roundtrip();
    printf("CPA: %s\n", cpa_rc == 0 ? "PASS" : "FAIL");
    return ntt_rc || cpa_rc;
}
