# Benchmark Regression Report

**Timestamp:** 2026-09-08T01:34:49.172724+00:00
**Results:** 19/19 passed, 0 failed, 0 warnings

## Provenance

| Property | Value |
|----------|-------|
| Commit | `e8b9c8c106ddd13baeb3217d1fe405c0313aaae1` |
| Tree | DIRTY (uncommitted changes) |
| Version | `5.0.0` |
| Host | Linux-6.18.44-fc-v24-x86_64-with-glibc2.39 / x86_64 |
| CPU | 4 logical processor(s) |
| Python | 3.11.15 (CPython) |
| Native backend | v5.0.0 · digest 96d8f021ae29c3c8… · /home/user/AMA-Cryptography/ama_cryptography/libama_cryptography.so |
| Dispatch | x86-64: AVX2=1 AVX-512F=1 AVX-512-Keccak=1 => level=1 (sha3=1); AES-GCM: VAES+VPCLMULQDQ YMM path selected; Auto-tune verdicts (regressed=1 reverted): keccak=0 (simd=-1 ns vs generic=-1 ns), keccak_fallback=0 (tier=-1 ns vs generic=-1 ns; -1 = no distinct intermediate tier on this host), keccak_x4=1 (simd=756153 ns vs generic=485477 ns), kyber_ntt=0 (simd=1249208 ns vs generic=1495631 ns), kyber_invntt=0 (simd=1514375 ns vs generic=2367846 ns), dilithium_ntt=0 (simd=2197240 ns vs generic=3188243 ns), dilithium_invntt=0 (simd=2307717 ns vs generic=3329005 ns); keccak_f1600 -> scalar (BMI1/BMI2); kyber_ntt    -> SIMD; kyber_poly_* -> scalar (compiler auto-vectorised); dil_ntt      -> SIMD; chacha20_x8 -> SIMD; argon2_g     -> SIMD; x25519_x4    -> scalar (4× sequential); ed25519      -> fe51 field backend, avx2 niels-select fold |
| Command | `python benchmarks/benchmark_runner.py --baseline benchmarks/baseline.json --output benchmarks/benchmark-results.json --markdown benchmark-report.md` |
| Sampling | batches grown (sized to the fastest rate observed) until a timed batch spans >= 0.15s of measured wall-clock; 3 full-window batches per call |
| Extra whole-run repeats | aes_256_gcm_encrypt x3, ama_sha3_256_hash x3, chacha20poly1305_encrypt x3, dilithium_keygen x3, dilithium_sign x3, dilithium_verify x3, ed25519_keygen x3, ed25519_sign x3, ed25519_verify x3, full_package_create x5, full_package_verify x5, hkdf_derive x3, hmac_sha3_256 x3 |
| Aggregation | fastest observation (throughput noise is one-sided: interference can only make an operation look slower) |
| Reading these numbers | the baseline column is a regression FLOOR measured on the named CI runner, not this host's expected throughput; a ratio below 1.0 on a developer machine is ordinary |

## Results

*Regression is measured against the floor: **positive means SLOWER** than `baseline_value`, negative means faster. It is the same number as `regression_percent` in `benchmark-results.json`. The floor is a measured median on the runner class named in Provenance above, not a discount of this run, so the two hosts differ and a positive value within Tolerance is an ordinary result.*

| Primitive | Ops/sec | Baseline | Regression | Tolerance | Status |
|-----------|--------:|---------:|-----------:|----------:|--------|
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 423,439 | 327,222 | -29.4% | 45% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 293,001 | 215,299 | -36.1% | 45% | PASS |
| Ed25519 key pair generation through the Python API: one CSPRNG seed draw + native keygen + the FIPS 140-3 pairwise-consistency sign/verify that keypair() runs on every key (native keygen alone is about a sixth of the timed operation). Not comparable with the 4.x native-keygen-only row. | 16,814 | 15,370 | -9.4% | 45% | PASS |
| Ed25519 signature generation (native C, expanded key) | 76,279 | 70,496 | -8.2% | 45% | PASS |
| Ed25519 signature verification (native C) | 33,003 | 30,542 | -8.1% | 45% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 198,122 | 131,341 | -50.9% | 45% | PASS |
| Complete crypto package creation (with PQC) | 2,407 | 1,983 | -21.4% | 45% | PASS |
| Complete crypto package verification (with PQC) | 2,692 | 3,442 | +21.8% | 45% | PASS |
| secp256k1 ECDSA signing (native C, RFC 6979 deterministic nonce) | 9,966 | 8,068 | -23.5% | 45% | PASS |
| secp256k1 ECDSA verification (native C, Shamir's-trick joint multiply, low-s + canonical-pubkey policy) | 4,299 | 3,302 | -30.2% | 45% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 1,776 | 1,312 | -35.4% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 3,471 | 2,636 | -31.7% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 11,608 | 8,897 | -30.5% | 45% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 3,972 | 2,726 | -45.7% | 45% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 18,806 | 11,994 | -56.8% | 45% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 308,159 | 224,406 | -37.3% | 45% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 293,329 | 227,521 | -28.9% | 45% | PASS |
| X25519 single-shot Diffie-Hellman scalar-mult (native C, default dispatch). Backed by fe64 (radix-2^64, MULX/ADX) on x86-64 hosts with BMI2+ADX, fe51 (radix-2^51) on 64-bit hosts without, and gf16 on 32-bit. The AVX2 4-way kernel is OPT-IN via AMA_DISPATCH_USE_X25519_AVX2=1 and is intentionally not faster than scalar fe64 on MULX/ADX hosts — see src/c/dispatch/ama_dispatch.c:478-502 and tests/test_x25519_dispatch_policy.py for the dispatch contract. Re-floored 5,000 → 13,000 (2026-04-27 audit) so the regression gate actually catches a >40% drop from canonical-host throughput rather than ignoring it. | 22,050 | 16,876 | -30.7% | 45% | PASS |
| X25519 batch-4 Diffie-Hellman under default dispatch — measures BATCHES/SEC, not per-op rate. On MULX/ADX hosts this is roughly x25519_scalarmult / 4 plus the wrapper's per-batch overhead (canonical-host run measured ~4,100 batches/sec vs ~17,000 single-shot ops/sec). A significantly slower batches/sec number typically means the AVX2 4-way kernel was accidentally selected as the default — that is a regression on every shipped Broadwell+/Zen+ part (see PR #273 design note and ama_dispatch.c:478-502). The runner calls native_x25519_scalarmult_batch with count=4 so this baseline genuinely exercises the batch wrapper, not four sequential native_x25519_key_exchange calls. | 5,248 | 4,074 | -28.8% | 45% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | ████████████████████████████████████████ 423,439
           hmac_sha3_256 | ███████████████████████████ 293,001
          ed25519_keygen | █ 16,814
            ed25519_sign | ███████ 76,279
          ed25519_verify | ███ 33,003
             hkdf_derive | ██████████████████ 198,122
     full_package_create |  2,407
     full_package_verify |  2,692
    secp256k1_ecdsa_sign |  9,966
  secp256k1_ecdsa_verify |  4,299
        dilithium_keygen |  1,776
          dilithium_sign |  3,471
        dilithium_verify | █ 11,608
            kyber_keygen |  3,972
       kyber_encapsulate | █ 18,806
     aes_256_gcm_encrypt | █████████████████████████████ 308,159
chacha20poly1305_encrypt | ███████████████████████████ 293,329
       x25519_scalarmult | ██ 22,050
x25519_scalarmult_batch4 |  5,248
```
