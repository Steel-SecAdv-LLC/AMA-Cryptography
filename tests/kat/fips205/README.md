# FIPS 205 SLH-DSA (SPHINCS+) KAT Vectors

## Status: Pending

NIST FIPS 205 Known Answer Test vectors for SLH-DSA-SHA2-256f-simple have not yet been
added to this test suite.

### Current Test Coverage

The SPHINCS+ implementation in `src/c/ama_sphincs.c` is validated via:
- Self-consistency roundtrip tests (sign/verify) in `tests/c/test_kat.c`
- Tamper detection tests in `tests/c/test_kat.c`

### TODO

- Obtain official NIST FIPS 205 KAT vectors from NIST ACVP or CAVP
- Add Python-level KAT validation in `tests/test_nist_kat.py`
- Add C-level KAT matching in `tests/c/test_kat.c`

### Parameters (SLH-DSA-SHA2-256f-simple)

| Parameter | Value |
|-----------|-------|
| n | 32 |
| h | 68 |
| d | 17 |
| FORS trees | 35 |
| FORS height | 9 |
| w (Winternitz) | 16 |
| Public key | 64 bytes |
| Secret key | 128 bytes |
| Signature | 49,856 bytes |
