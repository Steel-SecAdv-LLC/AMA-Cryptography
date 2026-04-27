# Benchmark Regression Report

**Timestamp:** 2026-04-27T05:29:08.547129+00:00
**Results:** 16/16 passed, 0 failed, 0 warnings

## Results

| Primitive | Ops/sec | Baseline | Delta | Tolerance | Status |
|-----------|--------:|---------:|------:|----------:|--------|
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 158,226 | 31,000 | -410.4% | 35% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 122,279 | 19,500 | -527.1% | 40% | PASS |
| Ed25519 key pair generation (native C) | 58,125 | 10,560 | -450.4% | 35% | PASS |
| Ed25519 signature generation (native C, expanded key) | 50,585 | 10,430 | -385.0% | 35% | PASS |
| Ed25519 signature verification (native C) | 20,574 | 5,113 | -302.4% | 35% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 78,708 | 12,500 | -529.7% | 35% | PASS |
| Complete crypto package creation (with PQC) | 3,728 | 200 | -1763.8% | 70% | PASS |
| Complete crypto package verification (with PQC) | 4,504 | 700 | -543.4% | 50% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 3,730 | 1,943 | -92.0% | 40% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 1,219 | 130 | -837.3% | 50% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 7,393 | 900 | -721.4% | 40% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 5,904 | 2,200 | -168.3% | 40% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 11,851 | 2,400 | -393.8% | 40% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 234,311 | 150,000 | -56.2% | 40% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 240,267 | 32,000 | -650.8% | 40% | PASS |
| X25519 key exchange scalar multiplication (native C) | 15,401 | 5,000 | -208.0% | 40% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | ██████████████████████████ 158,226
           hmac_sha3_256 | ████████████████████ 122,279
          ed25519_keygen | █████████ 58,125
            ed25519_sign | ████████ 50,585
          ed25519_verify | ███ 20,574
             hkdf_derive | █████████████ 78,708
     full_package_create |  3,728
     full_package_verify |  4,504
        dilithium_keygen |  3,730
          dilithium_sign |  1,219
        dilithium_verify | █ 7,393
            kyber_keygen |  5,904
       kyber_encapsulate | █ 11,851
     aes_256_gcm_encrypt | ███████████████████████████████████████ 234,311
chacha20poly1305_encrypt | ████████████████████████████████████████ 240,267
       x25519_scalarmult | ██ 15,401
```
