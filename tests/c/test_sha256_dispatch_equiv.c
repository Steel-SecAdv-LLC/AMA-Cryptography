/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_sha256_dispatch_equiv.c
 * @brief Byte-identity KAT for the runtime-dispatched SHA-256 core.
 *
 * ama_sha256() (src/c/ama_sha256.c) selects, at runtime, the x86 SHA-NI kernel
 * (src/c/ama_sha256_ni.c), the AArch64 ARMv8 SHA2 kernel
 * (ama_sha256_compress_neon), or the scalar fallback.  This test asserts that
 * whatever backend the host CPU selects is byte-identical to:
 *   1. an independent in-test scalar SHA-256 reference, over a length sweep
 *      that straddles the 64-byte block boundary and spans multiple blocks; and
 *   2. the FIPS 180-4 Appendix B.1/B.2 published digests.
 *
 * The active backend is printed so the CI log proves the accelerated path was
 * actually exercised (on a SHA-NI/SHA2 host the hardware kernel runs; on a
 * host without the extension the scalar path is validated instead).  Any
 * divergence — a wrong SHA-NI shuffle constant, a bad round K, a NEON schedule
 * bug — fails hard.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Dispatched one-shot under test (out, in, inlen) — see src/c/ama_sha256.h. */
extern void ama_sha256(uint8_t *out, const uint8_t *in, size_t inlen);

/* CPU-feature probes — used only to report the selected backend. */
extern int ama_has_sha_ni(void);
extern int ama_has_arm_sha2(void);

/* ---- Independent reference SHA-256 (FIPS 180-4), deliberately NOT the
 *      library's implementation, so a shared bug cannot mask a divergence. --- */

static const uint32_t RK[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

#define RR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void ref_block(uint32_t st[8], const uint8_t p[64]) {
    uint32_t w[64], a,b,c,d,e,f,g,h,t1,t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4*i]<<24)|((uint32_t)p[4*i+1]<<16)|((uint32_t)p[4*i+2]<<8)|p[4*i+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = RR(w[i-15],7) ^ RR(w[i-15],18) ^ (w[i-15]>>3);
        uint32_t s1 = RR(w[i-2],17) ^ RR(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=st[0];b=st[1];c=st[2];d=st[3];e=st[4];f=st[5];g=st[6];h=st[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = RR(e,6)^RR(e,11)^RR(e,25);
        uint32_t ch = (e&f)^((~e)&g);
        t1 = h + S1 + ch + RK[i] + w[i];
        uint32_t S0 = RR(a,2)^RR(a,13)^RR(a,22);
        uint32_t mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    st[0]+=a;st[1]+=b;st[2]+=c;st[3]+=d;st[4]+=e;st[5]+=f;st[6]+=g;st[7]+=h;
}

static void ref_sha256(const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint32_t st[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                      0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    uint8_t blk[64];
    uint64_t bits = (uint64_t)len * 8;
    size_t i = 0;
    while (len - i >= 64) { ref_block(st, msg + i); i += 64; }
    size_t rem = len - i;
    memset(blk, 0, 64);
    memcpy(blk, msg + i, rem);
    blk[rem] = 0x80;
    if (rem >= 56) { ref_block(st, blk); memset(blk, 0, 64); }
    for (int k = 0; k < 8; k++) blk[56+k] = (uint8_t)(bits >> (56 - 8*k));
    ref_block(st, blk);
    for (int k = 0; k < 8; k++) {
        out[4*k]=(uint8_t)(st[k]>>24); out[4*k+1]=(uint8_t)(st[k]>>16);
        out[4*k+2]=(uint8_t)(st[k]>>8); out[4*k+3]=(uint8_t)st[k];
    }
}

static int hexeq(const uint8_t *d, const char *hex) {
    char buf[65];
    for (int i = 0; i < 32; i++) sprintf(buf + 2*i, "%02x", d[i]);
    return strcmp(buf, hex) == 0;
}

int main(void) {
    const char *backend =
        ama_has_sha_ni()  ? "x86 SHA-NI" :
        ama_has_arm_sha2() ? "ARMv8 SHA2" : "scalar";
    printf("SHA-256 dispatch backend under test: %s\n", backend);

    /* 1. FIPS 180-4 §B.1 ("abc") and §B.2 (448-bit message). */
    uint8_t d[32];
    ama_sha256(d, (const uint8_t *)"abc", 3);
    if (!hexeq(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")) {
        printf("FAIL: FIPS 180-4 B.1 'abc'\n"); return 1;
    }
    ama_sha256(d, (const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
    if (!hexeq(d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")) {
        printf("FAIL: FIPS 180-4 B.2 (448-bit)\n"); return 1;
    }

    /* 2. Differential sweep vs the independent reference across block
     *    boundaries and multi-block messages. */
    static const size_t lens[] = {0,1,2,3,55,56,57,63,64,65,119,120,127,128,129,
                                  191,192,255,256,257,1000,4096};
    uint8_t buf[4096];
    for (size_t j = 0; j < sizeof(lens)/sizeof(lens[0]); j++) {
        size_t n = lens[j];
        for (size_t k = 0; k < n; k++) buf[k] = (uint8_t)((k * 37u + 11u) & 0xff);
        uint8_t got[32], exp[32];
        ama_sha256(got, buf, n);
        ref_sha256(buf, n, exp);
        if (memcmp(got, exp, 32) != 0) {
            printf("FAIL: dispatch != reference at len=%zu (backend=%s)\n", n, backend);
            return 1;
        }
    }

    printf("PASS: dispatched SHA-256 (%s) byte-identical to reference + FIPS 180-4\n", backend);
    return 0;
}
