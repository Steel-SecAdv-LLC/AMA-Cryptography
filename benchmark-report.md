# Benchmark Regression Report

**Timestamp:** 2026-07-29T02:28:21.224562+00:00
**Results:** 19/19 passed, 0 failed, 0 warnings

## Results

| Primitive | Ops/sec | Baseline | Delta | Tolerance | Status |
|-----------|--------:|---------:|------:|----------:|--------|
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 261,781 | 140,000 | -87.0% | 35% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 183,642 | 96,000 | -91.3% | 40% | PASS |
| Ed25519 key pair generation (native C) | 55,943 | 31,000 | -80.5% | 35% | PASS |
| Ed25519 signature generation (native C, expanded key) | 65,571 | 33,000 | -98.7% | 35% | PASS |
| Ed25519 signature verification (native C) | 24,014 | 13,000 | -84.7% | 35% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 106,140 | 62,000 | -71.2% | 35% | PASS |
| Complete crypto package creation (with PQC) | 3,736 | 2,400 | -55.7% | 70% | PASS |
| Complete crypto package verification (with PQC) | 5,523 | 2,600 | -112.4% | 50% | PASS |
| secp256k1 ECDSA signing (native C, RFC 6979 deterministic nonce) | 2,887 | 1,900 | -51.9% | 40% | PASS |
| secp256k1 ECDSA verification (native C, Shamir's-trick joint multiply, low-s + canonical-pubkey policy) | 4,137 | 2,600 | -59.1% | 40% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 4,356 | 2,100 | -107.4% | 40% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 1,463 | 710 | -106.0% | 50% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 7,868 | 4,600 | -71.1% | 40% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 6,042 | 3,400 | -77.7% | 40% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 9,258 | 7,500 | -23.4% | 40% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 97,130 | 150,000 | +35.2% | 40% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 265,158 | 130,000 | -104.0% | 40% | PASS |
| X25519 single-shot Diffie-Hellman scalar-mult (native C, default dispatch). Backed by fe64 (radix-2^64, MULX/ADX) on x86-64 hosts with BMI2+ADX, fe51 (radix-2^51) on 64-bit hosts without, and gf16 on 32-bit. The AVX2 4-way kernel is OPT-IN via AMA_DISPATCH_USE_X25519_AVX2=1 and is intentionally not faster than scalar fe64 on MULX/ADX hosts — see src/c/dispatch/ama_dispatch.c:478-502 and tests/test_x25519_dispatch_policy.py for the dispatch contract. Re-floored 5,000 → 13,000 (2026-04-27 audit) so the regression gate actually catches a >40% drop from canonical-host throughput rather than ignoring it. | 19,429 | 13,000 | -49.5% | 40% | PASS |
| X25519 batch-4 Diffie-Hellman under default dispatch — measures BATCHES/SEC, not per-op rate. On MULX/ADX hosts this is roughly x25519_scalarmult / 4 plus the wrapper's per-batch overhead (canonical-host run measured ~4,100 batches/sec vs ~17,000 single-shot ops/sec). A significantly slower batches/sec number typically means the AVX2 4-way kernel was accidentally selected as the default — that is a regression on every shipped Broadwell+/Zen+ part (see PR #273 design note and ama_dispatch.c:478-502). The runner calls native_x25519_scalarmult_batch with count=4 so this baseline genuinely exercises the batch wrapper, not four sequential native_x25519_key_exchange calls. | 4,282 | 2,600 | -64.7% | 40% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | ███████████████████████████████████████ 261,781
           hmac_sha3_256 | ███████████████████████████ 183,642
          ed25519_keygen | ████████ 55,943
            ed25519_sign | █████████ 65,571
          ed25519_verify | ███ 24,014
             hkdf_derive | ████████████████ 106,140
     full_package_create |  3,736
     full_package_verify |  5,523
    secp256k1_ecdsa_sign |  2,887
  secp256k1_ecdsa_verify |  4,137
        dilithium_keygen |  4,356
          dilithium_sign |  1,463
        dilithium_verify | █ 7,868
            kyber_keygen |  6,042
       kyber_encapsulate | █ 9,258
     aes_256_gcm_encrypt | ██████████████ 97,130
chacha20poly1305_encrypt | ████████████████████████████████████████ 265,158
       x25519_scalarmult | ██ 19,429
x25519_scalarmult_batch4 |  4,282
```
