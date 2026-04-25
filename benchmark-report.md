# Benchmark Regression Report

**Timestamp:** 2026-04-25T02:29:28.046050+00:00
**Results:** 16/16 passed, 0 failed, 0 warnings

## Results

| Primitive | Ops/sec | Baseline | Delta | Tolerance | Status |
|-----------|--------:|---------:|------:|----------:|--------|
| AMA native C SHA3-256 hashing of 1KB data (FIPS 202, ctypes) | 179,490 | 113,388 | -58.3% | 35% | PASS |
| HMAC-SHA3-256 authentication (native C via ctypes) | 126,098 | 76,215 | -65.5% | 40% | PASS |
| Ed25519 key pair generation (native C) | 35,946 | 10,560 | -240.4% | 35% | PASS |
| Ed25519 signature generation (native C, expanded key) | 51,206 | 10,430 | -390.9% | 35% | PASS |
| Ed25519 signature verification (native C) | 21,129 | 5,113 | -313.2% | 35% | PASS |
| HKDF-SHA3-256 key derivation (3 keys) | 86,154 | 53,193 | -62.0% | 35% | PASS |
| Complete crypto package creation (with PQC) | 2,853 | 746 | -282.4% | 50% | PASS |
| Complete crypto package verification (with PQC) | 4,973 | 2,044 | -143.3% | 50% | PASS |
| ML-DSA-65 (Dilithium) key pair generation (native C) | 3,626 | 1,943 | -86.6% | 40% | PASS |
| ML-DSA-65 (Dilithium) signature generation (native C) | 2,976 | 660 | -350.9% | 40% | PASS |
| ML-DSA-65 (Dilithium) signature verification (native C) | 7,576 | 4,303 | -76.1% | 40% | PASS |
| ML-KEM-1024 (Kyber) key pair generation (native C) | 4,965 | 2,200 | -125.7% | 40% | PASS |
| ML-KEM-1024 (Kyber) encapsulation (native C) | 10,253 | 2,400 | -327.2% | 40% | PASS |
| AES-256-GCM encryption of 1KB data (native C) | 271,449 | 150,000 | -81.0% | 40% | PASS |
| ChaCha20-Poly1305 encryption of 1KB data (native C) | 263,430 | 130,000 | -102.6% | 40% | PASS |
| X25519 key exchange scalar multiplication (native C) | 21,632 | 25,000 | +13.5% | 40% | PASS |

## Throughput Comparison

```
       ama_sha3_256_hash | ██████████████████████████ 179,490
           hmac_sha3_256 | ██████████████████ 126,098
          ed25519_keygen | █████ 35,946
            ed25519_sign | ███████ 51,206
          ed25519_verify | ███ 21,129
             hkdf_derive | ████████████ 86,154
     full_package_create |  2,853
     full_package_verify |  4,973
        dilithium_keygen |  3,626
          dilithium_sign |  2,976
        dilithium_verify | █ 7,576
            kyber_keygen |  4,965
       kyber_encapsulate | █ 10,253
     aes_256_gcm_encrypt | ████████████████████████████████████████ 271,449
chacha20poly1305_encrypt | ██████████████████████████████████████ 263,430
       x25519_scalarmult | ███ 21,632
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
| Ed25519 KeyGen | 35,946 | 40,000–60,000 (ref) / N/A (not installed) | N/A (Ed25519 not in liboqs) | ~1.4x faster — libsodium has a precomputed base-point table |
| Ed25519 Sign | 51,206 | 50,000–80,000 (ref) / N/A (not installed) | N/A | ~1.3x faster — libsodium sign is the x86-64 ops/sec reference |
| Ed25519 Verify | 21,129 | 15,000–30,000 (ref) / N/A (not installed) | N/A | within reference band — vartime verify with AVX2 primitives |
| ML-DSA-65 Sign | 2,976 | N/A (not in libsodium) | 500–1,500 (ref) / N/A (not installed) | AMA ~2x faster than the liboqs reference band |
| ML-DSA-65 Verify | 7,576 | N/A | 4,000–9,000 (ref) / N/A (not installed) | within reference band |
| ML-KEM-1024 Encap | 10,253 | N/A | 7,000–15,000 (ref) / N/A (not installed) | within reference band |
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
