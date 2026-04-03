# Benchmark Regression Report

**Timestamp:** 2026-04-03T00:02:24.882001+00:00
**Results:** 9/11 passed, 2 failed, 0 warnings

## Results

| Primitive | Ops/sec | Baseline | Delta | Tolerance | Status |
|-----------|--------:|---------:|------:|----------:|--------|
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 18,205 | 15,000 | -21.4% | 30% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 12,127 | 12,000 | -1.1% | 40% | PASS |
| Ed25519 key pair generation (native C) | 5,167 | 10,600 | +51.3% | 35% | **FAIL** |
| Ed25519 signature generation (native C, expanded key) | 5,069 | 8,527 | +40.6% | 35% | **FAIL** |
| Ed25519 signature verification (native C) | 2,796 | 3,416 | +18.2% | 35% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 8,509 | 6,500 | -30.9% | 35% | PASS |
| Complete crypto package creation (with PQC) | 184 | 280 | +34.2% | 50% | PASS |
| Complete crypto package verification (with PQC) | 561 | 380 | -47.5% | 50% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 595 | 500 | -18.9% | 40% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 567 | 140 | -304.8% | 40% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 697 | 530 | -31.4% | 40% | PASS |

## Throughput Comparison

```
  ama_sha3_256_hash | ████████████████████████████████████████ 18,205
      hmac_sha3_256 | ██████████████████████████ 12,127
     ed25519_keygen | !███████████ 5,167
       ed25519_sign | !███████████ 5,069
     ed25519_verify | ██████ 2,796
        hkdf_derive | ██████████████████ 8,509
full_package_create |  184
full_package_verify | █ 561
   dilithium_keygen | █ 595
     dilithium_sign | █ 567
   dilithium_verify | █ 697
```
