# Benchmark Regression Report

**Timestamp:** 2026-08-30T19:55:57.202496+00:00
**Results:** 19/19 passed, 0 failed, 0 warnings

## Provenance

| Property | Value |
|----------|-------|
| Commit | `611a41f54e132812343f96d677bf67bf63fa2004` |
| Tree | clean |
| Version | `5.0.0` |
| Host | Linux-6.18.44-fc-v22-x86_64-with-glibc2.39 / x86_64 |
| CPU | 4 logical processor(s) |
| Python | 3.11.15 (CPython) |
| Native backend | v5.0.0 · digest d59ee7cc1a323886… · /home/user/AMA-Cryptography/ama_cryptography/libama_cryptography.so |
| Command | `python benchmarks/benchmark_runner.py --baseline benchmarks/baseline.json --output benchmarks/benchmark-results.json --markdown benchmark-report.md` |
| Sampling | batches grown (sized to the fastest rate observed) until a timed batch spans >= 0.15s of measured wall-clock; 3 full-window batches per call |
| Extra whole-run repeats | aes_256_gcm_encrypt x3, ama_sha3_256_hash x3, chacha20poly1305_encrypt x3, dilithium_keygen x3, dilithium_sign x3, dilithium_verify x3, ed25519_keygen x3, ed25519_sign x3, ed25519_verify x3, full_package_create x5, full_package_verify x5, hkdf_derive x3, hmac_sha3_256 x3 |
| Aggregation | fastest observation (throughput noise is one-sided: interference can only make an operation look slower) |
| Reading these numbers | the baseline column is a regression FLOOR measured on the named CI runner, not this host's expected throughput; a ratio below 1.0 on a developer machine is ordinary |

## Results

*Regression is measured against the floor: **positive means SLOWER** than `baseline_value`, negative means faster. It is the same number as `regression_percent` in `benchmark-results.json`. The floor is a measured median on the runner class named in Provenance above, not a discount of this run, so the two hosts differ and a positive value within Tolerance is an ordinary result.*

| Primitive | Ops/sec | Baseline | Regression | Tolerance | Status |
|-----------|--------:|---------:|-----------:|----------:|--------|
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 372,509 | 327,222 | -13.8% | 45% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 243,639 | 215,299 | -13.2% | 45% | PASS |
| Ed25519 key pair generation (native C) | 12,182 | 10,822 | -12.6% | 45% | PASS |
| Ed25519 signature generation (native C, expanded key) | 59,554 | 53,885 | -10.5% | 45% | PASS |
| Ed25519 signature verification (native C) | 22,462 | 19,181 | -17.1% | 45% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 147,244 | 131,341 | -12.1% | 45% | PASS |
| Complete crypto package creation (with PQC) | 1,961 | 1,983 | +1.1% | 45% | PASS |
| Complete crypto package verification (with PQC) | 2,776 | 3,442 | +19.3% | 45% | PASS |
| secp256k1 ECDSA signing (native C, RFC 6979 deterministic nonce) | 9,209 | 8,068 | -14.1% | 45% | PASS |
| secp256k1 ECDSA verification (native C, Shamir's-trick joint multiply, low-s + canonical-pubkey policy) | 3,815 | 3,302 | -15.6% | 45% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 1,406 | 1,312 | -7.2% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 2,719 | 2,636 | -3.1% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 8,961 | 8,897 | -0.7% | 45% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 2,989 | 2,726 | -9.7% | 45% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 13,284 | 11,994 | -10.8% | 45% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 261,141 | 224,406 | -16.4% | 45% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 257,200 | 227,521 | -13.0% | 45% | PASS |
| X25519 single-shot Diffie-Hellman scalar-mult (native C, default dispatch). Backed by fe64 (radix-2^64, MULX/ADX) on x86-64 hosts with BMI2+ADX, fe51 (radix-2^51) on 64-bit hosts without, and gf16 on 32-bit. The AVX2 4-way kernel is OPT-IN via AMA_DISPATCH_USE_X25519_AVX2=1 and is intentionally not faster than scalar fe64 on MULX/ADX hosts — see src/c/dispatch/ama_dispatch.c:478-502 and tests/test_x25519_dispatch_policy.py for the dispatch contract. Re-floored 5,000 → 13,000 (2026-04-27 audit) so the regression gate actually catches a >40% drop from canonical-host throughput rather than ignoring it. | 19,587 | 16,876 | -16.1% | 45% | PASS |
| X25519 batch-4 Diffie-Hellman under default dispatch — measures BATCHES/SEC, not per-op rate. On MULX/ADX hosts this is roughly x25519_scalarmult / 4 plus the wrapper's per-batch overhead (canonical-host run measured ~4,100 batches/sec vs ~17,000 single-shot ops/sec). A significantly slower batches/sec number typically means the AVX2 4-way kernel was accidentally selected as the default — that is a regression on every shipped Broadwell+/Zen+ part (see PR #273 design note and ama_dispatch.c:478-502). The runner calls native_x25519_scalarmult_batch with count=4 so this baseline genuinely exercises the batch wrapper, not four sequential native_x25519_key_exchange calls. | 4,676 | 4,074 | -14.8% | 45% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | ████████████████████████████████████████ 372,509
           hmac_sha3_256 | ██████████████████████████ 243,639
          ed25519_keygen | █ 12,182
            ed25519_sign | ██████ 59,554
          ed25519_verify | ██ 22,462
             hkdf_derive | ███████████████ 147,244
     full_package_create |  1,961
     full_package_verify |  2,776
    secp256k1_ecdsa_sign |  9,209
  secp256k1_ecdsa_verify |  3,815
        dilithium_keygen |  1,406
          dilithium_sign |  2,719
        dilithium_verify |  8,961
            kyber_keygen |  2,989
       kyber_encapsulate | █ 13,284
     aes_256_gcm_encrypt | ████████████████████████████ 261,141
chacha20poly1305_encrypt | ███████████████████████████ 257,200
       x25519_scalarmult | ██ 19,587
x25519_scalarmult_batch4 |  4,676
```
