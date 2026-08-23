# Benchmark Regression Report

**Timestamp:** 2026-08-23T05:07:02.906349+00:00
**Results:** 19/19 passed, 0 failed, 0 warnings

## Provenance

| Property | Value |
|----------|-------|
| Commit | `1b9c0120d45bc6e61d534cbd1851a6c130eeea68` |
| Tree | DIRTY (uncommitted changes) |
| Version | `5.0.0` |
| Host | Linux-6.18.44-fc-v21-x86_64-with-glibc2.39 / x86_64 |
| CPU | 4 logical processor(s) |
| Python | 3.11.15 (CPython) |
| Command | `python benchmarks/benchmark_runner.py --baseline benchmarks/baseline.json --output benchmarks/benchmark-results.json --markdown benchmark-report.md` |
| Sampling | batches sized to span >= 0.15s at the fastest rate observed; 3 full-window batches per call |
| Extra whole-run repeats | aes_256_gcm_encrypt x3, ama_sha3_256_hash x3, chacha20poly1305_encrypt x3, dilithium_keygen x3, dilithium_sign x3, dilithium_verify x3, ed25519_keygen x3, ed25519_sign x3, ed25519_verify x3, full_package_create x5, full_package_verify x5, hkdf_derive x3, hmac_sha3_256 x3 |
| Aggregation | fastest observation (throughput noise is one-sided: interference can only make an operation look slower) |
| Reading these numbers | the baseline column is a regression FLOOR measured on the named CI runner, not this host's expected throughput; a ratio below 1.0 on a developer machine is ordinary |

## Results

*Regression is measured against the floor: **positive means SLOWER** than `baseline_value`, negative means faster. It is the same number as `regression_percent` in `benchmark-results.json`. The floor is a measured median on the runner class named in Provenance above, not a discount of this run, so the two hosts differ and a positive value within Tolerance is an ordinary result.*

| Primitive | Ops/sec | Baseline | Regression | Tolerance | Status |
|-----------|--------:|---------:|-----------:|----------:|--------|
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 358,479 | 327,222 | -9.6% | 45% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 211,979 | 215,299 | +1.5% | 45% | PASS |
| Ed25519 key pair generation (native C) | 13,558 | 10,822 | -25.3% | 45% | PASS |
| Ed25519 signature generation (native C, expanded key) | 63,875 | 53,885 | -18.5% | 45% | PASS |
| Ed25519 signature verification (native C) | 24,545 | 19,181 | -28.0% | 45% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 122,478 | 131,341 | +6.8% | 45% | PASS |
| Complete crypto package creation (with PQC) | 2,238 | 1,983 | -12.8% | 45% | PASS |
| Complete crypto package verification (with PQC) | 2,958 | 3,442 | +14.1% | 45% | PASS |
| secp256k1 ECDSA signing (native C, RFC 6979 deterministic nonce) | 10,215 | 8,068 | -26.6% | 45% | PASS |
| secp256k1 ECDSA verification (native C, Shamir's-trick joint multiply, low-s + canonical-pubkey policy) | 4,329 | 3,302 | -31.1% | 45% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 1,639 | 1,312 | -24.9% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 3,293 | 2,636 | -24.9% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 11,249 | 8,897 | -26.4% | 45% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 3,653 | 2,726 | -34.0% | 45% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 16,589 | 11,994 | -38.3% | 45% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 301,120 | 224,406 | -34.2% | 45% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 292,942 | 227,521 | -28.8% | 45% | PASS |
| X25519 single-shot Diffie-Hellman scalar-mult (native C, default dispatch). Backed by fe64 (radix-2^64, MULX/ADX) on x86-64 hosts with BMI2+ADX, fe51 (radix-2^51) on 64-bit hosts without, and gf16 on 32-bit. The AVX2 4-way kernel is OPT-IN via AMA_DISPATCH_USE_X25519_AVX2=1 and is intentionally not faster than scalar fe64 on MULX/ADX hosts — see src/c/dispatch/ama_dispatch.c:478-502 and tests/test_x25519_dispatch_policy.py for the dispatch contract. Re-floored 5,000 → 13,000 (2026-04-27 audit) so the regression gate actually catches a >40% drop from canonical-host throughput rather than ignoring it. | 22,085 | 16,876 | -30.9% | 45% | PASS |
| X25519 batch-4 Diffie-Hellman under default dispatch — measures BATCHES/SEC, not per-op rate. On MULX/ADX hosts this is roughly x25519_scalarmult / 4 plus the wrapper's per-batch overhead (canonical-host run measured ~4,100 batches/sec vs ~17,000 single-shot ops/sec). A significantly slower batches/sec number typically means the AVX2 4-way kernel was accidentally selected as the default — that is a regression on every shipped Broadwell+/Zen+ part (see PR #273 design note and ama_dispatch.c:478-502). The runner calls native_x25519_scalarmult_batch with count=4 so this baseline genuinely exercises the batch wrapper, not four sequential native_x25519_key_exchange calls. | 5,311 | 4,074 | -30.4% | 45% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | ████████████████████████████████████████ 358,479
           hmac_sha3_256 | ███████████████████████ 211,979
          ed25519_keygen | █ 13,558
            ed25519_sign | ███████ 63,875
          ed25519_verify | ██ 24,545
             hkdf_derive | █████████████ 122,478
     full_package_create |  2,238
     full_package_verify |  2,958
    secp256k1_ecdsa_sign | █ 10,215
  secp256k1_ecdsa_verify |  4,329
        dilithium_keygen |  1,639
          dilithium_sign |  3,293
        dilithium_verify | █ 11,249
            kyber_keygen |  3,653
       kyber_encapsulate | █ 16,589
     aes_256_gcm_encrypt | █████████████████████████████████ 301,120
chacha20poly1305_encrypt | ████████████████████████████████ 292,942
       x25519_scalarmult | ██ 22,085
x25519_scalarmult_batch4 |  5,311
```
