# Benchmark Regression Report

**Timestamp:** 2026-04-27T13:50:42.018676+00:00
**Results:** 17/17 passed, 0 failed, 0 warnings

## Results

| Primitive | Ops/sec | Baseline | Delta | Tolerance | Status |
|-----------|--------:|---------:|------:|----------:|--------|
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 230,244 | 31,000 | -642.7% | 35% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 148,565 | 19,500 | -661.9% | 40% | PASS |
| Ed25519 key pair generation (native C) | 48,134 | 10,560 | -355.8% | 35% | PASS |
| Ed25519 signature generation (native C, expanded key) | 51,046 | 10,430 | -389.4% | 35% | PASS |
| Ed25519 signature verification (native C) | 21,097 | 5,113 | -312.6% | 35% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 95,433 | 12,500 | -663.5% | 35% | PASS |
| Complete crypto package creation (with PQC) | 3,813 | 200 | -1806.5% | 70% | PASS |
| Complete crypto package verification (with PQC) | 4,055 | 700 | -479.3% | 50% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 3,331 | 1,943 | -71.4% | 40% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 1,104 | 130 | -749.0% | 50% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 7,216 | 900 | -701.7% | 40% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 5,346 | 2,200 | -143.0% | 40% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 11,687 | 2,400 | -387.0% | 40% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 276,778 | 150,000 | -84.5% | 40% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 215,256 | 32,000 | -572.7% | 40% | PASS |
| X25519 single-shot Diffie-Hellman scalar-mult (native C, default dispatch). Backed by fe64 (radix-2^64, MULX/ADX) on x86-64 hosts with BMI2+ADX, fe51 (radix-2^51) on 64-bit hosts without, and gf16 on 32-bit. The AVX2 4-way kernel is OPT-IN via AMA_DISPATCH_USE_X25519_AVX2=1 and is intentionally not faster than scalar fe64 on MULX/ADX hosts — see src/c/dispatch/ama_dispatch.c:478-502 and tests/test_x25519_dispatch_policy.py for the dispatch contract. Re-floored 5,000 → 13,000 (2026-04-27 audit) so the regression gate actually catches a >40% drop from canonical-host throughput rather than ignoring it. | 17,560 | 13,000 | -35.1% | 40% | PASS |
| X25519 batch-4 Diffie-Hellman under default dispatch — measures BATCHES/SEC, not per-op rate. On MULX/ADX hosts this is roughly x25519_scalarmult / 4 plus the wrapper's per-batch overhead (canonical-host run measured ~4,100 batches/sec vs ~17,000 single-shot ops/sec). A significantly slower batches/sec number typically means the AVX2 4-way kernel was accidentally selected as the default — that is a regression on every shipped Broadwell+/Zen+ part (see PR #273 design note and ama_dispatch.c:478-502). The runner calls native_x25519_scalarmult_batch with count=4 so this baseline genuinely exercises the batch wrapper, not four sequential native_x25519_key_exchange calls. | 4,112 | 2,600 | -58.2% | 40% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | █████████████████████████████████ 230,244
           hmac_sha3_256 | █████████████████████ 148,565
          ed25519_keygen | ██████ 48,134
            ed25519_sign | ███████ 51,046
          ed25519_verify | ███ 21,097
             hkdf_derive | █████████████ 95,433
     full_package_create |  3,813
     full_package_verify |  4,055
        dilithium_keygen |  3,331
          dilithium_sign |  1,104
        dilithium_verify | █ 7,216
            kyber_keygen |  5,346
       kyber_encapsulate | █ 11,687
     aes_256_gcm_encrypt | ████████████████████████████████████████ 276,778
chacha20poly1305_encrypt | ███████████████████████████████ 215,256
       x25519_scalarmult | ██ 17,560
x25519_scalarmult_batch4 |  4,112
```
