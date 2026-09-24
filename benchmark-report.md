# Benchmark Regression Report

**Timestamp:** 2026-09-22T14:53:19.502656+00:00
**Results:** 20/20 passed, 0 failed, 0 warnings

## Provenance

| Property | Value |
|----------|-------|
| Commit | `4e4fa7fa7f25f9cf14adec240d4789fcf4123325` |
| Tree | DIRTY (uncommitted changes: ama_cryptography/_integrity_digest.txt, ama_cryptography/_integrity_signature.py) |
| Version | `5.0.0` |
| Host | Linux-6.18.44-fc-v37-x86_64-with-glibc2.39 / x86_64 |
| CPU | 4 logical processor(s) |
| Python | 3.11.15 (CPython) |
| Native backend | v5.0.0 · digest d95f5cc73e89c347… · /home/user/AMA-Cryptography/ama_cryptography/libama_cryptography.so |
| Dispatch | x86-64: AVX2=1 AVX-512F=1 AVX-512-Keccak=1 => level=1 (sha3=1); Auto-tune verdicts (regressed=1 reverted): keccak=0 (simd=-1 ns vs generic=-1 ns), keccak_fallback=0 (tier=-1 ns vs generic=-1 ns; -1 = no distinct intermediate tier on this host), keccak_x4=1 (simd=942757 ns vs generic=727863 ns), kyber_ntt=0 (simd=2198876 ns vs generic=2286563 ns), kyber_invntt=0 (simd=2635048 ns vs generic=3409021 ns), dilithium_ntt=0 (simd=3221020 ns vs generic=4345132 ns), dilithium_invntt=0 (simd=4082276 ns vs generic=5206757 ns); keccak_f1600 -> scalar (BMI1/BMI2); kyber_ntt    -> SIMD; kyber_poly_* -> scalar (compiler auto-vectorised); dil_ntt      -> SIMD; chacha20_x8 -> SIMD; argon2_g     -> SIMD; x25519_x4    -> scalar (4× sequential); ed25519      -> fe51 field backend, avx2 niels-select fold |
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
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 298,723 | 327,222 | +8.7% | 45% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 205,641 | 215,299 | +4.5% | 45% | PASS |
| Ed25519 key pair generation through the Python API: one CSPRNG seed draw + native keygen + the FIPS 140-3 pairwise-consistency sign/verify that keypair() runs on every key (native keygen alone is about a sixth of the timed operation). Not comparable with the 4.x native-keygen-only row. | 11,316 | 12,368 | +8.5% | 45% | PASS |
| Ed25519 signature generation through the Python API with the 64-byte seed \|\| A key (native C); INVARIANT-51 re-derives A = [a]B on every call. The once-at-load form is the ed25519_sign_expanded row. | 35,287 | 38,811 | +9.1% | 45% | PASS |
| Ed25519 signature generation through Ed25519SigningKey: the key is loaded once, outside the timed operation, with the INVARIANT-51 derivation of the public half done at load; each timed signature re-checks the expanded form's tag (ama_ed25519_sign_expanded) instead of re-deriving. Same 240-byte message and key source as ed25519_sign; the ratio between the two rows is the per-signature cost the derivation had. | 56,746 | 61,671 | +8.0% | 45% | PASS |
| Ed25519 signature verification (native C) | 25,181 | 27,934 | +9.8% | 45% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 136,549 | 131,341 | -4.0% | 45% | PASS |
| Complete crypto package creation (with PQC) | 1,387 | 1,856 | +25.3% | 45% | PASS |
| Complete crypto package verification (with PQC) | 2,444 | 2,807 | +12.9% | 45% | PASS |
| secp256k1 ECDSA signing (native C, RFC 6979 deterministic nonce) | 8,417 | 8,068 | -4.3% | 45% | PASS |
| secp256k1 ECDSA verification (native C, Shamir's-trick joint multiply, low-s + canonical-pubkey policy) | 3,642 | 3,302 | -10.3% | 45% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 1,142 | 1,312 | +12.9% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 2,172 | 2,636 | +17.6% | 45% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 7,837 | 8,897 | +11.9% | 45% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 2,126 | 2,726 | +22.0% | 45% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 10,091 | 11,994 | +15.9% | 45% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 267,103 | 224,406 | -19.0% | 45% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 219,335 | 227,521 | +3.6% | 45% | PASS |
| X25519 single-shot Diffie-Hellman scalar-mult (native C, default dispatch). Backed by fe64 (radix-2^64, MULX/ADX) on x86-64 hosts with BMI2+ADX, fe51 (radix-2^51) on 64-bit hosts without, and gf16 on 32-bit. The AVX2 4-way kernel is OPT-IN via AMA_DISPATCH_USE_X25519_AVX2=1 and is intentionally not faster than scalar fe64 on MULX/ADX hosts — see src/c/dispatch/ama_dispatch.c:478-502 and tests/test_x25519_dispatch_policy.py for the dispatch contract. Re-floored 5,000 → 13,000 (2026-04-27 audit) so the regression gate actually catches a >40% drop from canonical-host throughput rather than ignoring it. | 18,024 | 16,876 | -6.8% | 45% | PASS |
| X25519 batch-4 Diffie-Hellman under default dispatch — measures BATCHES/SEC, not per-op rate. On MULX/ADX hosts this is roughly x25519_scalarmult / 4 plus the wrapper's per-batch overhead (canonical-host run measured ~4,100 batches/sec vs ~17,000 single-shot ops/sec). A significantly slower batches/sec number typically means the AVX2 4-way kernel was accidentally selected as the default — that is a regression on every shipped Broadwell+/Zen+ part (see PR #273 design note and ama_dispatch.c:478-502). The runner calls native_x25519_scalarmult_batch with count=4 so this baseline genuinely exercises the batch wrapper, not four sequential native_x25519_key_exchange calls. | 4,268 | 4,074 | -4.8% | 45% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | ████████████████████████████████████████ 298,723
           hmac_sha3_256 | ███████████████████████████ 205,641
          ed25519_keygen | █ 11,316
            ed25519_sign | ████ 35,287
   ed25519_sign_expanded | ███████ 56,746
          ed25519_verify | ███ 25,181
             hkdf_derive | ██████████████████ 136,549
     full_package_create |  1,387
     full_package_verify |  2,444
    secp256k1_ecdsa_sign | █ 8,417
  secp256k1_ecdsa_verify |  3,642
        dilithium_keygen |  1,142
          dilithium_sign |  2,172
        dilithium_verify | █ 7,837
            kyber_keygen |  2,126
       kyber_encapsulate | █ 10,091
     aes_256_gcm_encrypt | ███████████████████████████████████ 267,103
chacha20poly1305_encrypt | █████████████████████████████ 219,335
       x25519_scalarmult | ██ 18,024
x25519_scalarmult_batch4 |  4,268
```
