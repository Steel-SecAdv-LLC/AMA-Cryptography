# AMA Cryptography Benchmark Validation Report

## Summary

- **Date**: 2026-03-10T05:13:14.211741
- **Iterations**: 1000
- **Pass Rate**: 11/11 (100.0%)
- **Python Version**: 3.11.14
- **Platform**: Linux-6.18.5-x86_64-with-glibc2.39

## Results

| Claim | Documented | Measured | Status |
|-------|------------|----------|--------|
| master_secret_gen | 0.001ms | 0.0006ms | PASS |
| hkdf_derivation | 0.06ms | 0.0088ms | PASS |
| ed25519_keygen | 0.13ms | 0.1149ms | PASS |
| dilithium_keygen | 0.25ms | 0.2285ms | PASS |
| sha3_256_hash | 0.002ms | 0.0021ms | PASS |
| hmac_sha3_auth | 0.005ms | 0.0048ms | PASS |
| ed25519_sign | 0.26ms | 0.2344ms | PASS |
| ed25519_verify | 0.25ms | 0.2471ms | PASS |
| dilithium_sign | 0.55ms | 0.3844ms | PASS |
| dilithium_verify | 0.21ms | 0.2035ms | PASS |
| timing_monitor_overhead | 5.0% | 4.4600% | PASS |

## Detailed Results

### master_secret_gen

- **Status**: PASS
- **Documented**: 0.001ms
- **Measured**: 0.0006ms
- **Std Dev**: 0.0006ms
- **Tolerance**: 100.0%
- **Iterations**: 1000

### hkdf_derivation

- **Status**: PASS
- **Documented**: 0.06ms
- **Measured**: 0.0088ms
- **Std Dev**: 0.0034ms
- **Tolerance**: 100.0%
- **Iterations**: 1000

### ed25519_keygen

- **Status**: PASS
- **Documented**: 0.13ms
- **Measured**: 0.1149ms
- **Std Dev**: 0.0108ms
- **Tolerance**: 50.0%
- **Iterations**: 1000

### dilithium_keygen

- **Status**: PASS
- **Documented**: 0.25ms
- **Measured**: 0.2285ms
- **Std Dev**: 0.0254ms
- **Tolerance**: 100.0%
- **Iterations**: 1000

### sha3_256_hash

- **Status**: PASS
- **Documented**: 0.002ms
- **Measured**: 0.0021ms
- **Std Dev**: 0.0007ms
- **Tolerance**: 100.0%
- **Iterations**: 1000

### hmac_sha3_auth

- **Status**: PASS
- **Documented**: 0.005ms
- **Measured**: 0.0048ms
- **Std Dev**: 0.0033ms
- **Tolerance**: 100.0%
- **Iterations**: 1000

### ed25519_sign

- **Status**: PASS
- **Documented**: 0.26ms
- **Measured**: 0.2344ms
- **Std Dev**: 0.0138ms
- **Tolerance**: 50.0%
- **Iterations**: 1000

### ed25519_verify

- **Status**: PASS
- **Documented**: 0.25ms
- **Measured**: 0.2471ms
- **Std Dev**: 0.0120ms
- **Tolerance**: 50.0%
- **Iterations**: 1000

### dilithium_sign

- **Status**: PASS
- **Documented**: 0.55ms
- **Measured**: 0.3844ms
- **Std Dev**: 0.0247ms
- **Tolerance**: 100.0%
- **Iterations**: 1000

### dilithium_verify

- **Status**: PASS
- **Documented**: 0.21ms
- **Measured**: 0.2035ms
- **Std Dev**: 0.0127ms
- **Tolerance**: 100.0%
- **Iterations**: 1000

### timing_monitor_overhead

- **Status**: PASS
- **Documented**: 5.0%
- **Measured**: 4.4600%
- **Std Dev**: 0.0000%
- **Tolerance**: 100.0%
- **Iterations**: 1000
