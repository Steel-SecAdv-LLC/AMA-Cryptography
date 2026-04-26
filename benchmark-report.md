# Benchmark Regression Report

**Timestamp:** 2026-04-26T06:08:08.867009+00:00
**Results:** 16/16 passed, 0 failed, 0 warnings

## Results

| Primitive | Ops/sec | Baseline | Delta | Tolerance | Status |
|-----------|--------:|---------:|------:|----------:|--------|
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 184,112 | 31,000 | -493.9% | 35% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 115,408 | 19,500 | -491.8% | 40% | PASS |
| Ed25519 key pair generation (native C) | 55,716 | 10,560 | -427.6% | 35% | PASS |
| Ed25519 signature generation (native C, expanded key) | 51,488 | 10,430 | -393.7% | 35% | PASS |
| Ed25519 signature verification (native C) | 21,338 | 5,113 | -317.3% | 35% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 81,703 | 12,500 | -553.6% | 35% | PASS |
| Complete crypto package creation (with PQC) | 1,798 | 200 | -799.0% | 70% | PASS |
| Complete crypto package verification (with PQC) | 4,864 | 700 | -594.9% | 50% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 3,874 | 1,943 | -99.4% | 40% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 4,312 | 130 | -3216.9% | 50% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 7,413 | 900 | -723.7% | 40% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 5,999 | 2,200 | -172.7% | 40% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 12,365 | 2,400 | -415.2% | 40% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 293,143 | 150,000 | -95.4% | 40% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 256,249 | 32,000 | -700.8% | 40% | PASS |
| X25519 key exchange scalar multiplication (native C, MULX+ADX) | 13,168 | 5,000 | -163.4% | 40% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | █████████████████████████ 184,112
           hmac_sha3_256 | ███████████████ 115,408
          ed25519_keygen | ███████ 55,716
            ed25519_sign | ███████ 51,488
          ed25519_verify | ██ 21,338
             hkdf_derive | ███████████ 81,703
     full_package_create |  1,798
     full_package_verify |  4,864
        dilithium_keygen |  3,874
          dilithium_sign |  4,312
        dilithium_verify | █ 7,413
            kyber_keygen |  5,999
       kyber_encapsulate | █ 12,365
     aes_256_gcm_encrypt | ████████████████████████████████████████ 293,143
chacha20poly1305_encrypt | ██████████████████████████████████ 256,249
       x25519_scalarmult | █ 13,168
```
