# Benchmark Regression Report

**Timestamp:** 2026-09-16T20:49:54.992209+00:00
**Results:** 19/19 passed, 0 failed, 0 warnings

## Provenance

| Property | Value |
|----------|-------|
| Commit | `d198946034d075ad034fb8dd3e5c1b6fd7e94f48` |
| Tree | DIRTY (uncommitted changes) |
| Version | `5.0.0` |
| Host | Linux-6.18.44-fc-v33-x86_64-with-glibc2.39 / x86_64 |
| CPU | 4 logical processor(s) |
| Python | 3.11.15 (CPython) |
| Native backend | v5.0.0 · digest a086047c92ac4c7b… · /home/user/AMA-Cryptography/ama_cryptography/libama_cryptography.so |
| Dispatch | x86-64: AVX2=1 AVX-512F=1 AVX-512-Keccak=1 => level=1 (sha3=1); Auto-tune verdicts (regressed=1 reverted): keccak=0 (simd=-1 ns vs generic=-1 ns), keccak_fallback=0 (tier=-1 ns vs generic=-1 ns; -1 = no distinct intermediate tier on this host), keccak_x4=1 (simd=835728 ns vs generic=602074 ns), kyber_ntt=0 (simd=1545164 ns vs generic=1805915 ns), kyber_invntt=0 (simd=1921779 ns vs generic=2811061 ns), dilithium_ntt=0 (simd=2738103 ns vs generic=3905969 ns), dilithium_invntt=0 (simd=3027714 ns vs generic=4405703 ns); keccak_f1600 -> scalar (BMI1/BMI2); kyber_ntt    -> SIMD; kyber_poly_* -> scalar (compiler auto-vectorised); dil_ntt      -> SIMD; chacha20_x8 -> SIMD; argon2_g     -> SIMD; x25519_x4    -> scalar (4× sequential); ed25519      -> fe51 field backend, avx2 niels-select fold |
| Command | `python benchmarks/benchmark_runner.py --baseline benchmarks/baseline.json --output benchmarks/benchmark-results.json --markdown benchmark-report.md` |
| Sampling | batches grown (sized to the fastest rate observed) until a timed batch spans >= 0.15s of measured wall-clock; 3 full-window batches per call |
| Extra whole-run repeats | aes_256_gcm_encrypt x3, ama_sha3_256_hash x3, chacha20poly1305_encrypt x3, dilithium_keygen x3, dilithium_sign x3, dilithium_verify x3, ed25519_keygen x3, ed25519_sign x3, ed25519_verify x3, full_package_create x5, full_package_verify x5, hkdf_derive x3, hmac_sha3_256 x3 |
| Aggregation | fastest observation (throughput noise is one-sided: interference can only make an operation look slower) |
| Reading these numbers | the baseline column is a regression FLOOR measured on the named CI runner, not this host's expected throughput; a ratio below 1.0 on a developer machine is ordinary |

## Results

*Regression is measured against the floor: **positive means SLOWER** than `baseline_value`, negative means faster. It is the same number as `regression_percent` in `benchmark-results.json`. The floor is a measured median on the runner class named in Provenance above, not a discount of this run, so the two hosts differ and a positive value within Tolerance is an ordinary result.*

| Primitive | Ops/sec | Baseline | Regression | Tolerance | Status |
|-----------|--------:|---------:|-----------:|----------:|--------|
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 356,139 | 327,222 | -8.8% | 45% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 240,850 | 215,299 | -11.9% | 45% | PASS |
| Ed25519 key pair generation through the Python API: one CSPRNG seed draw + native keygen + the FIPS 140-3 pairwise-consistency sign/verify that keypair() runs on every key (native keygen alone is about a sixth of the timed operation). Not comparable with the 4.x native-keygen-only row. | 12,410 | 15,370 | +19.3% | 45% | PASS |
| Ed25519 signature generation (native C, expanded key) | 38,555 | 38,170 | -1.0% | 45% | PASS |
| Ed25519 signature verification (native C) | 28,347 | 30,542 | +7.2% | 45% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 162,904 | 131,341 | -24.0% | 45% | PASS |
| Complete crypto package creation (with PQC) | 1,791 | 1,983 | +9.7% | 45% | PASS |
| Complete crypto package verification (with PQC) | 2,212 | 3,442 | +35.7% | 45% | PASS |
| secp256k1 ECDSA signing (native C, RFC 6979 deterministic nonce) | 8,658 | 8,068 | -7.3% | 45% | PASS |
| secp256k1 ECDSA verification (native C, Shamir's-trick joint multiply, low-s + canonical-pubkey policy) | 3,666 | 3,302 | -11.0% | 45% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 1,439 | 1,312 | -9.7% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 2,935 | 2,636 | -11.3% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 9,892 | 8,897 | -11.2% | 45% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 3,404 | 2,726 | -24.9% | 45% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 16,013 | 11,994 | -33.5% | 45% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 284,597 | 224,406 | -26.8% | 45% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 243,814 | 227,521 | -7.2% | 45% | PASS |
| X25519 single-shot Diffie-Hellman scalar-mult (native C, default dispatch). Backed by fe64 (radix-2^64, MULX/ADX) on x86-64 hosts with BMI2+ADX, fe51 (radix-2^51) on 64-bit hosts without, and gf16 on 32-bit. The AVX2 4-way kernel is OPT-IN via AMA_DISPATCH_USE_X25519_AVX2=1 and is intentionally not faster than scalar fe64 on MULX/ADX hosts — see src/c/dispatch/ama_dispatch.c:478-502 and tests/test_x25519_dispatch_policy.py for the dispatch contract. Re-floored 5,000 → 13,000 (2026-04-27 audit) so the regression gate actually catches a >40% drop from canonical-host throughput rather than ignoring it. | 17,664 | 16,876 | -4.7% | 45% | PASS |
| X25519 batch-4 Diffie-Hellman under default dispatch — measures BATCHES/SEC, not per-op rate. On MULX/ADX hosts this is roughly x25519_scalarmult / 4 plus the wrapper's per-batch overhead (canonical-host run measured ~4,100 batches/sec vs ~17,000 single-shot ops/sec). A significantly slower batches/sec number typically means the AVX2 4-way kernel was accidentally selected as the default — that is a regression on every shipped Broadwell+/Zen+ part (see PR #273 design note and ama_dispatch.c:478-502). The runner calls native_x25519_scalarmult_batch with count=4 so this baseline genuinely exercises the batch wrapper, not four sequential native_x25519_key_exchange calls. | 4,231 | 4,074 | -3.8% | 45% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | ████████████████████████████████████████ 356,139
           hmac_sha3_256 | ███████████████████████████ 240,850
          ed25519_keygen | █ 12,410
            ed25519_sign | ████ 38,555
          ed25519_verify | ███ 28,347
             hkdf_derive | ██████████████████ 162,904
     full_package_create |  1,791
     full_package_verify |  2,212
    secp256k1_ecdsa_sign |  8,658
  secp256k1_ecdsa_verify |  3,666
        dilithium_keygen |  1,439
          dilithium_sign |  2,935
        dilithium_verify | █ 9,892
            kyber_keygen |  3,404
       kyber_encapsulate | █ 16,013
     aes_256_gcm_encrypt | ███████████████████████████████ 284,597
chacha20poly1305_encrypt | ███████████████████████████ 243,814
       x25519_scalarmult | █ 17,664
x25519_scalarmult_batch4 |  4,231
```
