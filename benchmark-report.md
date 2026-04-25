# Benchmark Regression Report

**Timestamp:** 2026-04-25T06:19:56.371446+00:00
**Results:** 16/16 passed, 0 failed, 0 warnings

## Results

| Primitive | Ops/sec | Baseline | Delta | Tolerance | Status |
|-----------|--------:|---------:|------:|----------:|--------|
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 48,134 | 31,000 | -55.3% | 35% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 30,817 | 19,500 | -58.0% | 40% | PASS |
| Ed25519 key pair generation (native C) | 16,656 | 10,560 | -57.7% | 35% | PASS |
| Ed25519 signature generation (native C, expanded key) | 17,543 | 10,430 | -68.2% | 35% | PASS |
| Ed25519 signature verification (native C) | 5,398 | 5,113 | -5.6% | 35% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 19,446 | 12,500 | -55.6% | 35% | PASS |
| Complete crypto package creation (with PQC) | 207 | 200 | -3.3% | 70% | PASS |
| Complete crypto package verification (with PQC) | 1,130 | 700 | -61.4% | 50% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 1,239 | 1,943 | +36.2% | 40% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 295 | 130 | -126.7% | 50% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 1,496 | 900 | -66.2% | 40% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 2,154 | 2,200 | +2.1% | 40% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 2,686 | 2,400 | -11.9% | 40% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 111,840 | 150,000 | +25.4% | 40% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 51,770 | 32,000 | -61.8% | 40% | PASS |
| X25519 key exchange scalar multiplication (native C) | 8,067 | 5,000 | -61.3% | 40% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | █████████████████ 48,134
           hmac_sha3_256 | ███████████ 30,817
          ed25519_keygen | █████ 16,656
            ed25519_sign | ██████ 17,543
          ed25519_verify | █ 5,398
             hkdf_derive | ██████ 19,446
     full_package_create |  207
     full_package_verify |  1,130
        dilithium_keygen |  1,239
          dilithium_sign |  295
        dilithium_verify |  1,496
            kyber_keygen |  2,154
       kyber_encapsulate |  2,686
     aes_256_gcm_encrypt | ████████████████████████████████████████ 111,840
chacha20poly1305_encrypt | ██████████████████ 51,770
       x25519_scalarmult | ██ 8,067
```
