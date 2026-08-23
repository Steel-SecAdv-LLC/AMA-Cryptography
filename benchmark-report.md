# Benchmark Regression Report

**Timestamp:** 2026-08-23T05:50:47.624757+00:00
**Results:** 19/19 passed, 0 failed, 0 warnings

## Provenance

| Property | Value |
|----------|-------|
| Commit | `f8f2a35edaf80d0cde4de99e4f4aa58e5d31f1a0` |
| Tree | clean |
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
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 313,042 | 327,222 | +4.3% | 45% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 212,261 | 215,299 | +1.4% | 45% | PASS |
| Ed25519 key pair generation (native C) | 13,563 | 10,822 | -25.3% | 45% | PASS |
| Ed25519 signature generation (native C, expanded key) | 63,986 | 53,885 | -18.8% | 45% | PASS |
| Ed25519 signature verification (native C) | 24,929 | 19,181 | -30.0% | 45% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 123,441 | 131,341 | +6.0% | 45% | PASS |
| Complete crypto package creation (with PQC) | 2,352 | 1,983 | -18.6% | 45% | PASS |
| Complete crypto package verification (with PQC) | 3,421 | 3,442 | +0.6% | 45% | PASS |
| secp256k1 ECDSA signing (native C, RFC 6979 deterministic nonce) | 10,393 | 8,068 | -28.8% | 45% | PASS |
| secp256k1 ECDSA verification (native C, Shamir's-trick joint multiply, low-s + canonical-pubkey policy) | 4,347 | 3,302 | -31.6% | 45% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 1,687 | 1,312 | -28.6% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 3,209 | 2,636 | -21.7% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 11,372 | 8,897 | -27.8% | 45% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 3,755 | 2,726 | -37.8% | 45% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 17,210 | 11,994 | -43.5% | 45% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 307,206 | 224,406 | -36.9% | 45% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 295,589 | 227,521 | -29.9% | 45% | PASS |
| X25519 single-shot Diffie-Hellman scalar-mult (native C, default dispatch). Backed by fe64 (radix-2^64, MULX/ADX) on x86-64 hosts with BMI2+ADX, fe51 (radix-2^51) on 64-bit hosts without, and gf16 on 32-bit. The AVX2 4-way kernel is OPT-IN via AMA_DISPATCH_USE_X25519_AVX2=1 and is intentionally not faster than scalar fe64 on MULX/ADX hosts — see src/c/dispatch/ama_dispatch.c:478-502 and tests/test_x25519_dispatch_policy.py for the dispatch contract. Re-floored 5,000 → 13,000 (2026-04-27 audit) so the regression gate actually catches a >40% drop from canonical-host throughput rather than ignoring it. | 22,169 | 16,876 | -31.4% | 45% | PASS |
| X25519 batch-4 Diffie-Hellman under default dispatch — measures BATCHES/SEC, not per-op rate. On MULX/ADX hosts this is roughly x25519_scalarmult / 4 plus the wrapper's per-batch overhead (canonical-host run measured ~4,100 batches/sec vs ~17,000 single-shot ops/sec). A significantly slower batches/sec number typically means the AVX2 4-way kernel was accidentally selected as the default — that is a regression on every shipped Broadwell+/Zen+ part (see PR #273 design note and ama_dispatch.c:478-502). The runner calls native_x25519_scalarmult_batch with count=4 so this baseline genuinely exercises the batch wrapper, not four sequential native_x25519_key_exchange calls. | 5,345 | 4,074 | -31.2% | 45% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | ████████████████████████████████████████ 313,042
           hmac_sha3_256 | ███████████████████████████ 212,261
          ed25519_keygen | █ 13,563
            ed25519_sign | ████████ 63,986
          ed25519_verify | ███ 24,929
             hkdf_derive | ███████████████ 123,441
     full_package_create |  2,352
     full_package_verify |  3,421
    secp256k1_ecdsa_sign | █ 10,393
  secp256k1_ecdsa_verify |  4,347
        dilithium_keygen |  1,687
          dilithium_sign |  3,209
        dilithium_verify | █ 11,372
            kyber_keygen |  3,755
       kyber_encapsulate | ██ 17,210
     aes_256_gcm_encrypt | ███████████████████████████████████████ 307,206
chacha20poly1305_encrypt | █████████████████████████████████████ 295,589
       x25519_scalarmult | ██ 22,169
x25519_scalarmult_batch4 |  5,345
```
