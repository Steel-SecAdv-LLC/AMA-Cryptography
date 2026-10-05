# Benchmark Regression Report

**Timestamp:** 2026-09-28T08:46:52.199528+00:00
**Results:** 20/20 passed, 0 failed, 0 warnings

## Provenance

| Property | Value |
|----------|-------|
| Commit | `7836cc8957d5122e5feedbe551d8d7578de1f601` |
| Tree | clean |
| Version | `5.0.0` |
| Host | Linux-6.18.44-fc-v42-x86_64-with-glibc2.39 / x86_64 |
| CPU | 4 logical processor(s) |
| Python | 3.11.15 (CPython) |
| Native backend | v5.0.0 · digest 76a4afbba5a7308b… · /home/user/AMA-Cryptography/ama_cryptography/libama_cryptography.so |
| Build configuration | GNU 13.3.0; cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS= '-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG' -DAMA_AES_CONSTTIME=ON -DAMA_AES_TABLE_INSECURE=OFF -DAMA_ALLOW_UNVERIFIED_TOOLCHAIN=OFF -DAMA_BUILD_EXAMPLES=OFF -DAMA_BUILD_FUZZ=OFF -DAMA_BUILD_SHARED=ON -DAMA_BUILD_STATIC=ON -DAMA_BUILD_TESTS=OFF -DAMA_ENABLE_AVX2=ON -DAMA_ENABLE_AVX512=OFF -DAMA_ENABLE_DUDECT=OFF -DAMA_ENABLE_LTO=ON -DAMA_ENABLE_NATIVE_ARCH=OFF -DAMA_ENABLE_NEON=ON -DAMA_ENABLE_SANITIZERS=OFF -DAMA_ENABLE_SIMD=ON -DAMA_ENABLE_SVE2=OFF -DAMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX= -DAMA_KYBER_BUILD_DIAGNOSTICS=OFF -DAMA_USE_NATIVE_PQC=ON (from build/python-cmake) |
| Dispatch | x86-64: AVX2=1 AVX-512F=1 AVX-512-Keccak=1 => level=1 (sha3=1); AES-GCM: VAES+VPCLMULQDQ YMM path selected; Auto-tune verdicts (regressed=1 reverted): keccak=0 (simd=-1 ns vs generic=-1 ns), keccak_fallback=0 (tier=-1 ns vs generic=-1 ns; -1 = no distinct intermediate tier on this host), keccak_x4=1 (simd=789153 ns vs generic=546767 ns), kyber_ntt=0 (simd=1390339 ns vs generic=1592098 ns), kyber_invntt=0 (simd=1696711 ns vs generic=2598783 ns), dilithium_ntt=0 (simd=2502065 ns vs generic=3568762 ns), dilithium_invntt=0 (simd=2690469 ns vs generic=3743262 ns); keccak_f1600 -> scalar (BMI1/BMI2); kyber_ntt    -> SIMD; kyber_poly_* -> scalar (compiler auto-vectorised); dil_ntt      -> SIMD; chacha20_x8 -> SIMD; argon2_g     -> SIMD; x25519_x4    -> scalar (4× sequential); ed25519      -> fe51 field backend, avx2 niels-select fold |
| Python bindings | 6 of 6 compiled bindings imported: dilithium_binding, ed25519_binding, hkdf_binding, hmac_binding, math_engine, sha3_binding |
| Command | `python benchmarks/benchmark_runner.py --verbose --baseline benchmarks/baseline.json --require-runner-class x86_64 --require-populated-baseline --output benchmarks/benchmark-results.json --markdown benchmark-report.md` |
| Sampling | batches grown (sized to the fastest rate observed) until a timed batch spans >= 0.15s of measured wall-clock; 3 full-window batches per call |
| Extra whole-run repeats | aes_256_gcm_encrypt x3, ama_sha3_256_hash x3, chacha20poly1305_encrypt x3, dilithium_keygen x3, dilithium_sign x3, dilithium_verify x3, ed25519_keygen x3, ed25519_sign x3, ed25519_sign_expanded x3, ed25519_verify x3, full_package_create x5, full_package_verify x5, hkdf_derive x3, hmac_sha3_256 x3 |
| Aggregation | fastest observation (throughput noise is one-sided: interference can only make an operation look slower) |
| Reading these numbers | the baseline column is a regression FLOOR measured on the named CI runner, not this host's expected throughput; a ratio below 1.0 on a developer machine is ordinary |

## Results

*Regression is measured against the floor: **positive means SLOWER** than `baseline_value`, negative means faster. It is the same number as `regression_percent` in `benchmark-results.json`. The floor is a measured median on the CI runner class the baseline file names, not a discount of this run -- except on a row the baseline's change log records as DERIVED, whose floor is a placeholder taken from a measured sibling until that runner has measured the row -- so the two hosts differ and a positive value within Tolerance is an ordinary result.*

| Primitive | Ops/sec | Baseline | Regression | Tolerance | Status |
|-----------|--------:|---------:|-----------:|----------:|--------|
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 381,128 | 327,222 | -16.5% | 45% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 262,657 | 215,299 | -22.0% | 45% | PASS |
| Ed25519 key pair generation through the Python API: one CSPRNG seed draw + native keygen + the FIPS 140-3 pairwise-consistency sign/verify that keypair() runs on every key (native keygen alone is about a sixth of the timed operation). Not comparable with the 4.x native-keygen-only row. | 12,682 | 12,368 | -2.5% | 45% | PASS |
| Ed25519 signature generation through the Python API with the 64-byte seed \|\| A key (native C); INVARIANT-51 re-derives A = [a]B on every call. The once-at-load form is the ed25519_sign_expanded row. | 39,054 | 38,811 | -0.6% | 45% | PASS |
| Ed25519 signature generation through Ed25519SigningKey: the key is loaded once, outside the timed operation, with the INVARIANT-51 derivation of the public half done at load; each timed signature re-checks the expanded form's tag (ama_ed25519_sign_expanded) instead of re-deriving. Same 240-byte message and key source as ed25519_sign; the ratio between the two rows is the per-signature cost the derivation had. | 62,709 | 61,671 | -1.7% | 45% | PASS |
| Ed25519 signature verification (native C) | 30,127 | 27,934 | -7.8% | 45% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 172,643 | 131,341 | -31.4% | 45% | PASS |
| Complete crypto package creation (with PQC) | 1,857 | 1,856 | -0.1% | 45% | PASS |
| Complete crypto package verification (with PQC) | 2,430 | 2,807 | +13.4% | 45% | PASS |
| secp256k1 ECDSA signing (native C, RFC 6979 deterministic nonce) | 9,301 | 8,068 | -15.3% | 45% | PASS |
| secp256k1 ECDSA verification (native C, Shamir's-trick joint multiply, low-s + canonical-pubkey policy) | 3,815 | 3,302 | -15.5% | 45% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 1,519 | 1,312 | -15.8% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 3,187 | 2,636 | -20.9% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 10,495 | 8,897 | -18.0% | 45% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 3,519 | 2,726 | -29.1% | 45% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 17,020 | 11,994 | -41.9% | 45% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 279,062 | 224,406 | -24.4% | 45% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 263,653 | 227,521 | -15.9% | 45% | PASS |
| X25519 single-shot Diffie-Hellman scalar-mult (native C, default dispatch). Backed by fe64 (radix-2^64, MULX/ADX) on x86-64 hosts with BMI2+ADX, fe51 (radix-2^51) on 64-bit hosts without, and gf16 on 32-bit. The AVX2 4-way kernel is OPT-IN via AMA_DISPATCH_USE_X25519_AVX2=1 and is intentionally not faster than scalar fe64 on MULX/ADX hosts — see src/c/dispatch/ama_dispatch.c:478-502 and tests/test_x25519_dispatch_policy.py for the dispatch contract. Re-floored 5,000 → 13,000 (2026-04-27 audit) so the regression gate actually catches a >40% drop from canonical-host throughput rather than ignoring it. | 19,514 | 16,876 | -15.6% | 45% | PASS |
| X25519 batch-4 Diffie-Hellman under default dispatch — measures BATCHES/SEC, not per-op rate. On MULX/ADX hosts this is roughly x25519_scalarmult / 4 plus the wrapper's per-batch overhead (canonical-host run measured ~4,100 batches/sec vs ~17,000 single-shot ops/sec). A significantly slower batches/sec number typically means the AVX2 4-way kernel was accidentally selected as the default — that is a regression on every shipped Broadwell+/Zen+ part (see PR #273 design note and ama_dispatch.c:478-502). The runner calls native_x25519_scalarmult_batch with count=4 so this baseline genuinely exercises the batch wrapper, not four sequential native_x25519_key_exchange calls. | 4,673 | 4,074 | -14.7% | 45% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | ████████████████████████████████████████ 381,128
           hmac_sha3_256 | ███████████████████████████ 262,657
          ed25519_keygen | █ 12,682
            ed25519_sign | ████ 39,054
   ed25519_sign_expanded | ██████ 62,709
          ed25519_verify | ███ 30,127
             hkdf_derive | ██████████████████ 172,643
     full_package_create |  1,857
     full_package_verify |  2,430
    secp256k1_ecdsa_sign |  9,301
  secp256k1_ecdsa_verify |  3,815
        dilithium_keygen |  1,519
          dilithium_sign |  3,187
        dilithium_verify | █ 10,495
            kyber_keygen |  3,519
       kyber_encapsulate | █ 17,020
     aes_256_gcm_encrypt | █████████████████████████████ 279,062
chacha20poly1305_encrypt | ███████████████████████████ 263,653
       x25519_scalarmult | ██ 19,514
x25519_scalarmult_batch4 |  4,673
```
