# Benchmark Regression Report

**Timestamp:** 2026-04-21T01:06:23.910038+00:00
**Results:** 16/16 passed, 0 failed, 0 warnings

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
| ML-DSA-65 (Dilithium) signature generation (native C) | 1,017 | 660 | -54.1% | 40% | PASS |
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
          dilithium_sign |  1,017
        dilithium_verify |  6,322
            kyber_keygen |  4,850
       kyber_encapsulate | █ 9,138
     aes_256_gcm_encrypt | ████████████████████████████████████████ 278,298
chacha20poly1305_encrypt | ███████████████████████████████████████ 271,362
       x25519_scalarmult | ███ 22,918
```

## Peer Comparison

Live numbers come from `benchmarks/comparative_benchmark.py`. When the
peer library is not installed in the benchmarking environment (the common
CI case), the cell reads `N/A (not installed)` and the reference range is
taken from `benchmarks/baseline.json::metadata.peer_references` — those
are published figures for the same hardware class (x86-64, generic C /
AVX2 path), not live measurements.

| Primitive | AMA ops/sec (measured) | libsodium ops/sec | liboqs ops/sec | Ratio (peer / AMA) |
|-----------|---------------------:|---------------------:|--------------------:|--------------------|
| Ed25519 KeyGen | 9,162 | 40,000–60,000 (ref) / N/A (not installed) | N/A (Ed25519 not in liboqs) | ~5.5x faster — libsodium has a precomputed base-point table |
| Ed25519 Sign | 10,569 | 50,000–80,000 (ref) / N/A (not installed) | N/A | ~6.1x faster — libsodium sign is the x86-64 ops/sec reference |
| Ed25519 Verify | 7,547 | 15,000–30,000 (ref) / N/A (not installed) | N/A | ~3.0x faster — vartime |
| ML-DSA-65 Sign | 1,017 | N/A (not in libsodium) | 500–1,500 (ref) / N/A (not installed) | within ~1x — AMA is inside the liboqs reference band |
| ML-DSA-65 Verify | 6,322 | N/A | 4,000–9,000 (ref) / N/A (not installed) | ~1.0x — within reference band |
| ML-KEM-1024 Encap | 9,138 | N/A | 7,000–15,000 (ref) / N/A (not installed) | ~1.0x — within reference band |
| ML-KEM-1024 Decap | N/A in this harness¹ | N/A | 6,000–13,000 (ref) | — |

¹ The regression harness measures ML-KEM-1024 encap only; the comparative
harness (`comparative_benchmark.py`) exercises decap separately when
liboqs-python is installed.

**Reading guidance.** A cell like "40,000–60,000 (ref) / N/A (not installed)"
means: the reference range for the peer library on comparable hardware is
40K–60K ops/sec (citation in `baseline.json::metadata.peer_references`),
and the peer library wasn't present in the environment this report was
generated on, so no live number was captured. When the peer libraries are
installed (e.g., running locally with `pip install pynacl oqs`) the
comparative benchmark prints a verdict like "libsodium Ed25519 sign:
6.3x faster than AMA" that supersedes the reference range for that run.
