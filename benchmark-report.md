# Benchmark Regression Report

**Timestamp:** 2026-08-15T23:05:02.335379+00:00
**Results:** 19/19 passed, 0 failed, 0 warnings

## Provenance

| Property | Value |
|----------|-------|
| Commit | `d5007839c8ed7c5d2f7f950a721fa5b1bc036d23` (working tree DIRTY) |
| Version | `5.0.0` |
| Host | Linux-6.18.5-fc-v20-x86_64-with-glibc2.39 / x86_64 |
| CPU | 4 logical processor(s) |
| Python | 3.11.15 (CPython) |
| Command | `python benchmarks/benchmark_runner.py --baseline <file> --markdown <file>` |
| Sampling | batches sized to span >= 0.15s at the fastest rate observed; 3 full-window batches per call |
| Extra whole-run repeats | aes_256_gcm_encrypt x3, ama_sha3_256_hash x3, chacha20poly1305_encrypt x3, dilithium_keygen x3, dilithium_sign x3, dilithium_verify x3, ed25519_keygen x3, ed25519_sign x3, ed25519_verify x3, full_package_create x5, full_package_verify x5, hkdf_derive x3, hmac_sha3_256 x3 |
| Aggregation | fastest observation (throughput noise is one-sided: interference can only make an operation look slower) |
| Reading these numbers | the baseline column is a regression FLOOR measured on the named CI runner, not this host's expected throughput; a ratio below 1.0 on a developer machine is ordinary |

## Results

| Primitive | Ops/sec | Baseline | Delta | Tolerance | Status |
|-----------|--------:|---------:|------:|----------:|--------|
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 288,371 | 327,222 | +11.9% | 45% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 187,033 | 215,299 | +13.1% | 45% | PASS |
| Ed25519 key pair generation (native C) | 11,156 | 10,822 | -3.1% | 45% | PASS |
| Ed25519 signature generation (native C, expanded key) | 56,032 | 53,885 | -4.0% | 45% | PASS |
| Ed25519 signature verification (native C) | 20,227 | 19,181 | -5.5% | 45% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 108,276 | 131,341 | +17.6% | 45% | PASS |
| Complete crypto package creation (with PQC) | 1,440 | 1,983 | +27.4% | 45% | PASS |
| Complete crypto package verification (with PQC) | 2,133 | 3,442 | +38.0% | 45% | PASS |
| secp256k1 ECDSA signing (native C, RFC 6979 deterministic nonce) | 8,049 | 8,068 | +0.2% | 45% | PASS |
| secp256k1 ECDSA verification (native C, Shamir's-trick joint multiply, low-s + canonical-pubkey policy) | 3,618 | 3,302 | -9.6% | 45% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 980 | 1,312 | +25.3% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 1,826 | 2,636 | +30.7% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 6,950 | 8,897 | +21.9% | 45% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 1,924 | 2,726 | +29.4% | 45% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 8,305 | 11,994 | +30.8% | 45% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 244,131 | 224,406 | -8.8% | 45% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 211,098 | 227,521 | +7.2% | 45% | PASS |
| X25519 single-shot Diffie-Hellman scalar-mult (native C, default dispatch). Backed by fe64 (radix-2^64, MULX/ADX) on x86-64 hosts with BMI2+ADX, fe51 (radix-2^51) on 64-bit hosts without, and gf16 on 32-bit. The AVX2 4-way kernel is OPT-IN via AMA_DISPATCH_USE_X25519_AVX2=1 and is intentionally not faster than scalar fe64 on MULX/ADX hosts — see src/c/dispatch/ama_dispatch.c:478-502 and tests/test_x25519_dispatch_policy.py for the dispatch contract. Re-floored 5,000 → 13,000 (2026-04-27 audit) so the regression gate actually catches a >40% drop from canonical-host throughput rather than ignoring it. | 17,945 | 16,876 | -6.3% | 45% | PASS |
| X25519 batch-4 Diffie-Hellman under default dispatch — measures BATCHES/SEC, not per-op rate. On MULX/ADX hosts this is roughly x25519_scalarmult / 4 plus the wrapper's per-batch overhead (canonical-host run measured ~4,100 batches/sec vs ~17,000 single-shot ops/sec). A significantly slower batches/sec number typically means the AVX2 4-way kernel was accidentally selected as the default — that is a regression on every shipped Broadwell+/Zen+ part (see PR #273 design note and ama_dispatch.c:478-502). The runner calls native_x25519_scalarmult_batch with count=4 so this baseline genuinely exercises the batch wrapper, not four sequential native_x25519_key_exchange calls. | 4,334 | 4,074 | -6.4% | 45% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | ████████████████████████████████████████ 288,371
           hmac_sha3_256 | █████████████████████████ 187,033
          ed25519_keygen | █ 11,156
            ed25519_sign | ███████ 56,032
          ed25519_verify | ██ 20,227
             hkdf_derive | ███████████████ 108,276
     full_package_create |  1,440
     full_package_verify |  2,133
    secp256k1_ecdsa_sign | █ 8,049
  secp256k1_ecdsa_verify |  3,618
        dilithium_keygen |  980
          dilithium_sign |  1,826
        dilithium_verify |  6,950
            kyber_keygen |  1,924
       kyber_encapsulate | █ 8,305
     aes_256_gcm_encrypt | █████████████████████████████████ 244,131
chacha20poly1305_encrypt | █████████████████████████████ 211,098
       x25519_scalarmult | ██ 17,945
x25519_scalarmult_batch4 |  4,334
```
