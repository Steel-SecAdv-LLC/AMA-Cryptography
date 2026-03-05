#include "../../include/ava_guardian.h"
#include <stdio.h>
extern int ava_kyber_debug_ntt_roundtrip(void);
extern int ava_kyber_debug_cpa_roundtrip(void);
int main(void) {
    setbuf(stdout, NULL);
    printf("=== NTT Roundtrip Test ===\n");
    int ntt_rc = ava_kyber_debug_ntt_roundtrip();
    printf("NTT: %s\n\n", ntt_rc == 0 ? "PASS" : "FAIL");

    printf("=== CPA Encrypt/Decrypt Test ===\n");
    int cpa_rc = ava_kyber_debug_cpa_roundtrip();
    printf("CPA: %s\n", cpa_rc == 0 ? "PASS" : "FAIL");
    return ntt_rc || cpa_rc;
}
