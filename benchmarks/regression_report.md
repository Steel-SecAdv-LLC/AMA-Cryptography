# Benchmark Regression Report

**Timestamp:** 2026-03-10T05:13:04.438023+00:00
**Results:** 11/11 passed, 0 failed, 0 warnings

## Results

| Primitive | Ops/sec | Baseline | Delta | Tolerance | Status |
|-----------|--------:|---------:|------:|----------:|--------|
| SHA3-256 hashing of 1KB data | 297,250 | 150,000 | -98.2% | 25% | PASS |
| HMAC-SHA3-256 authentication | 174,007 | 70,000 | -148.6% | 25% | PASS |
| Ed25519 key pair generation (native C) | 8,744 | 6,000 | -45.7% | 30% | PASS |
| Ed25519 signature generation (native C) | 4,146 | 3,000 | -38.2% | 30% | PASS |
| Ed25519 signature verification (native C) | 4,268 | 3,000 | -42.3% | 30% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 68,518 | 15,000 | -356.8% | 30% | PASS |
| Complete crypto package creation (with PQC) | 1,495 | 120 | -1145.7% | 50% | PASS |
| Complete crypto package verification (with PQC) | 2,073 | 800 | -159.1% | 50% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 4,877 | 3,500 | -39.3% | 35% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 2,806 | 1,000 | -180.6% | 35% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 5,129 | 3,500 | -46.5% | 35% | PASS |

## Throughput Comparison

```
      sha3_256_hash | ████████████████████████████████████████ 297,250
      hmac_sha3_256 | ███████████████████████ 174,007
     ed25519_keygen | █ 8,744
       ed25519_sign |  4,146
     ed25519_verify |  4,268
        hkdf_derive | █████████ 68,518
full_package_create |  1,495
full_package_verify |  2,073
   dilithium_keygen |  4,877
     dilithium_sign |  2,806
   dilithium_verify |  5,129
```
