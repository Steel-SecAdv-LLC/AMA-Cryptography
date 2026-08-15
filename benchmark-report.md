# Benchmark Regression Report

**Timestamp:** 2026-08-15T23:59:21.739814+00:00
**Results:** 19/19 passed, 0 failed, 0 warnings

## Provenance

| Property | Value |
|----------|-------|
| Commit | `0e97aefb09efa23672d5d0c5d651bdfe3b5a579c` |
| Version | `5.0.0` |
| Host | Linux-6.18.5-fc-v20-x86_64-with-glibc2.39 / x86_64 |
| CPU | 4 logical processor(s) |
| Python | 3.11.15 (CPython) |
| Command | `python benchmarks/benchmark_runner.py --baseline benchmarks/baseline.json --output benchmarks/benchmark-results.json --markdown benchmark-report.md` |
| Sampling | batches sized to span >= 0.15s at the fastest rate observed; 3 full-window batches per call |
| Extra whole-run repeats | aes_256_gcm_encrypt x3, ama_sha3_256_hash x3, chacha20poly1305_encrypt x3, dilithium_keygen x3, dilithium_sign x3, dilithium_verify x3, ed25519_keygen x3, ed25519_sign x3, ed25519_verify x3, full_package_create x5, full_package_verify x5, hkdf_derive x3, hmac_sha3_256 x3 |
| Aggregation | fastest observation (throughput noise is one-sided: interference can only make an operation look slower) |
| Reading these numbers | the baseline column is a regression FLOOR measured on the named CI runner, not this host's expected throughput; a ratio below 1.0 on a developer machine is ordinary |

## Results

| Primitive | Ops/sec | Baseline | Delta | Tolerance | Status |
|-----------|--------:|---------:|------:|----------:|--------|
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 289,692 | 327,222 | +11.5% | 45% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 187,325 | 215,299 | +13.0% | 45% | PASS |
| Ed25519 key pair generation (native C) | 11,268 | 10,822 | -4.1% | 45% | PASS |
| Ed25519 signature generation (native C, expanded key) | 56,299 | 53,885 | -4.5% | 45% | PASS |
| Ed25519 signature verification (native C) | 20,634 | 19,181 | -7.6% | 45% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 109,135 | 131,341 | +16.9% | 45% | PASS |
| Complete crypto package creation (with PQC) | 1,515 | 1,983 | +23.6% | 45% | PASS |
| Complete crypto package verification (with PQC) | 1,964 | 3,442 | +42.9% | 45% | PASS |
| secp256k1 ECDSA signing (native C, RFC 6979 deterministic nonce) | 8,352 | 8,068 | -3.5% | 45% | PASS |
| secp256k1 ECDSA verification (native C, Shamir's-trick joint multiply, low-s + canonical-pubkey policy) | 3,675 | 3,302 | -11.3% | 45% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 963 | 1,312 | +26.6% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 1,838 | 2,636 | +30.3% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 6,902 | 8,897 | +22.4% | 45% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 1,900 | 2,726 | +30.3% | 45% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 8,436 | 11,994 | +29.7% | 45% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 237,703 | 224,406 | -5.9% | 45% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 208,052 | 227,521 | +8.6% | 45% | PASS |
| X25519 single-shot Diffie-Hellman scalar-mult (native C, default dispatch). Backed by fe64 (radix-2^64, MULX/ADX) on x86-64 hosts with BMI2+ADX, fe51 (radix-2^51) on 64-bit hosts without, and gf16 on 32-bit. The AVX2 4-way kernel is OPT-IN via AMA_DISPATCH_USE_X25519_AVX2=1 and is intentionally not faster than scalar fe64 on MULX/ADX hosts — see src/c/dispatch/ama_dispatch.c:478-502 and tests/test_x25519_dispatch_policy.py for the dispatch contract. Re-floored 5,000 → 13,000 (2026-04-27 audit) so the regression gate actually catches a >40% drop from canonical-host throughput rather than ignoring it. | 18,201 | 16,876 | -7.9% | 45% | PASS |
| X25519 batch-4 Diffie-Hellman under default dispatch — measures BATCHES/SEC, not per-op rate. On MULX/ADX hosts this is roughly x25519_scalarmult / 4 plus the wrapper's per-batch overhead (canonical-host run measured ~4,100 batches/sec vs ~17,000 single-shot ops/sec). A significantly slower batches/sec number typically means the AVX2 4-way kernel was accidentally selected as the default — that is a regression on every shipped Broadwell+/Zen+ part (see PR #273 design note and ama_dispatch.c:478-502). The runner calls native_x25519_scalarmult_batch with count=4 so this baseline genuinely exercises the batch wrapper, not four sequential native_x25519_key_exchange calls. | 4,270 | 4,074 | -4.8% | 45% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | ████████████████████████████████████████ 289,692
           hmac_sha3_256 | █████████████████████████ 187,325
          ed25519_keygen | █ 11,268
            ed25519_sign | ███████ 56,299
          ed25519_verify | ██ 20,634
             hkdf_derive | ███████████████ 109,135
     full_package_create |  1,515
     full_package_verify |  1,964
    secp256k1_ecdsa_sign | █ 8,352
  secp256k1_ecdsa_verify |  3,675
        dilithium_keygen |  963
          dilithium_sign |  1,838
        dilithium_verify |  6,902
            kyber_keygen |  1,900
       kyber_encapsulate | █ 8,436
     aes_256_gcm_encrypt | ████████████████████████████████ 237,703
chacha20poly1305_encrypt | ████████████████████████████ 208,052
       x25519_scalarmult | ██ 18,201
x25519_scalarmult_batch4 |  4,270
```
