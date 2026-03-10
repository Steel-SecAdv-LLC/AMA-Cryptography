# AMA Cryptography Benchmark Results

**Date:** 2026-03-10T05:13:12.969800+00:00
**Platform:** Linux-6.18.5-x86_64-with-glibc2.39
**CPU Cores:** 4
**Python:** 3.11.14
**Dilithium Backend:** native
**Total Duration:** 8.44s

## Dashboard Overview

![Performance Dashboard](assets/performance_dashboard.png)

![Benchmark Report](assets/benchmark_report.png)

## Key Generation

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| master_secret | 0.0005 | 0.0004 | 0.0005 | 2,117,408.61 | 10000 |
| hkdf_derivation | 0.0497 | 0.0465 | 0.0101 | 20,117.16 | 1000 |
| ed25519_keygen | 0.1197 | 0.1167 | 0.0127 | 8,354.03 | 1000 |
| dilithium_keygen | 0.2196 | 0.2212 | 0.0163 | 4,553.65 | 100 |
| kms_generation | 0.4030 | 0.4082 | 0.0279 | 2,481.25 | 100 |

## Cryptographic Operations

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| sha3_256 | 0.0010 | 0.0009 | 0.0005 | 1,046,449.81 | 10000 |
| hmac_auth | 0.0034 | 0.0033 | 0.0011 | 291,466.07 | 10000 |
| hmac_verify | 0.0036 | 0.0034 | 0.0013 | 278,528.16 | 10000 |
| ed25519_sign | 0.2354 | 0.2351 | 0.0108 | 4,247.70 | 1000 |
| ed25519_verify | 0.2457 | 0.2486 | 0.0163 | 4,069.75 | 1000 |
| dilithium_sign | 1.0190 | 1.0276 | 0.0556 | 981.36 | 100 |
| dilithium_verify | 0.2079 | 0.2061 | 0.0060 | 4,809.08 | 100 |

## Code Operations

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| canonical_encoding | 0.0013 | 0.0013 | 0.0006 | 747,422.25 | 10000 |
| code_hash | 0.0098 | 0.0093 | 0.0025 | 102,448.33 | 10000 |
| package_creation | 0.5904 | 0.6004 | 0.0417 | 1,693.83 | 100 |
| package_verification | 0.4494 | 0.4564 | 0.0267 | 2,224.98 | 100 |

## Ethical Integration

| Operation | Mean (ms) | Median (ms) | Std Dev (ms) | Ops/sec | Iterations |
|-----------|----------:|------------:|-------------:|--------:|-----------:|
| ethical_context | 0.0061 | 0.0060 | 0.0015 | 163,698.32 | 10000 |
| hkdf_standard | 0.0088 | 0.0085 | 0.0020 | 114,276.31 | 1000 |
| hkdf_ethical | 0.0169 | 0.0162 | 0.0029 | 59,138.94 | 1000 |

> **Ethical context overhead:** 0.0081 ms (92.05%)

## Scalability (Package Creation by Input Size)

| Input Scale | Mean (ms) | Ops/sec | Iterations |
|------------:|----------:|--------:|-----------:|
| 1x | 0.7380 | 1,355.04 | 50 |
| 10x | 0.9613 | 1,040.25 | 50 |
| 100x | 1.9756 | 506.18 | 50 |
| 1000x | 138.9809 | 7.20 | 50 |

## Performance Comparison (ops/sec)

```
       master_secret | ████████████████████████████████████████ 2,117,409
     hkdf_derivation |  20,117
      ed25519_keygen |  8,354
    dilithium_keygen |  4,554
      kms_generation |  2,481
            sha3_256 | ███████████████████ 1,046,450
           hmac_auth | █████ 291,466
         hmac_verify | █████ 278,528
        ed25519_sign |  4,248
      ed25519_verify |  4,070
      dilithium_sign |  981
    dilithium_verify |  4,809
  canonical_encoding | ██████████████ 747,422
           code_hash | █ 102,448
    package_creation |  1,694
package_verification |  2,225
```
