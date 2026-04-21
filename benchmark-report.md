# Benchmark Regression Report

**Timestamp:** 2026-04-21T01:06:23.910038+00:00
**Results:** 15/16 passed, 0 failed, 1 warnings

## Results

| Primitive | Ops/sec | Baseline | Delta | Tolerance | Status |
|-----------|--------:|---------:|------:|----------:|--------|
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 170,834 | 113,388 | -50.7% | 35% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 129,999 | 76,215 | -70.6% | 40% | PASS |
| Ed25519 key pair generation (native C) | 9,162 | 10,560 | +13.2% | 35% | PASS |
| Ed25519 signature generation (native C, expanded key) | 10,569 | 10,430 | -1.3% | 35% | PASS |
| Ed25519 signature verification (native C) | 7,547 | 5,113 | -47.6% | 35% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 86,779 | 53,193 | -63.1% | 35% | PASS |
| Complete crypto package creation (with PQC) | 2,849 | 746 | -281.9% | 50% | PASS |
| Complete crypto package verification (with PQC) | 2,805 | 2,044 | -37.2% | 50% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 2,951 | 1,943 | -51.9% | 40% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 1,017 | 1,918 | +47.0% | 40% | WARN |
| ML-DSA-65 (Dilithium) signature verification (native C) | 6,322 | 4,303 | -46.9% | 40% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 4,850 | 2,200 | -120.4% | 40% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 9,138 | 2,400 | -280.8% | 40% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 278,298 | 150,000 | -85.5% | 40% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 271,362 | 130,000 | -108.7% | 40% | PASS |
| X25519 key exchange scalar multiplication (native C) | 22,918 | 25,000 | +8.3% | 40% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | ████████████████████████ 170,834
           hmac_sha3_256 | ██████████████████ 129,999
          ed25519_keygen | █ 9,162
            ed25519_sign | █ 10,569
          ed25519_verify | █ 7,547
             hkdf_derive | ████████████ 86,779
     full_package_create |  2,849
     full_package_verify |  2,805
        dilithium_keygen |  2,951
          dilithium_sign | ! 1,017
        dilithium_verify |  6,322
            kyber_keygen |  4,850
       kyber_encapsulate | █ 9,138
     aes_256_gcm_encrypt | ████████████████████████████████████████ 278,298
chacha20poly1305_encrypt | ███████████████████████████████████████ 271,362
       x25519_scalarmult | ███ 22,918
```
