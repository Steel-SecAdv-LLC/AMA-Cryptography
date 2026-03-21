# FIPS 205 SLH-DSA (SPHINCS+) KAT Vectors

## Status: Available

NIST FIPS 205 Known Answer Test vectors for SLH-DSA-SHA2-256f-simple are sourced
from the NIST ACVP-Server repository (SLH-DSA-sigVer-FIPS205).

### Vector File

- `SLH-DSA-sigVer-FIPS205.json` — ACVP signature verification vectors
  covering SLH-DSA-SHA2-256f with internal (pure) mode

### Test Coverage

The SPHINCS+ implementation in `src/c/ama_sphincs.c` is validated via:
- NIST ACVP sigVer vectors in `tests/test_pqc_kat.py::TestSLHDSA_SHA2_256f_KAT`
- Self-consistency roundtrip tests (sign/verify) in `tests/c/test_kat.c`
- Tamper detection tests in `tests/c/test_kat.c`
- FIPS 140-3 POST KAT in `ama_cryptography/_self_test.py`

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
