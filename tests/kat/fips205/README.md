# FIPS 205 SLH-DSA (SPHINCS+) KAT Vectors

## Status: Available

NIST FIPS 205 Known Answer Test vectors for SLH-DSA-SHA2-256f-simple are sourced
from the NIST ACVP-Server repository (SLH-DSA-sigVer-FIPS205).

### Vector File

- `SLH-DSA-sigVer-FIPS205.json` — ACVP signature verification vectors
  covering SLH-DSA-SHA2-256f with internal (pure) mode
- `SLH-DSA-SHAKE-128s-sigGen-FIPS205.json` — 14 NIST ACVP signature
  generation vectors for SLH-DSA-SHAKE-128s (external/pure interface):
  7 deterministic (tcIds 214–220) and 7 hedged (tcIds 526–532, with
  `additionalRandomness`). Curated from the NIST ACVP-Server JSON
  prompt + expectedResults pair under
  `gen-val/json-files/SLH-DSA-sigGen-FIPS205/` so each vector is
  self-contained (sk, message, context, signature [, additionalRandomness]).

### Test Coverage

The SLH-DSA implementation is validated via:
- NIST ACVP sigVer vectors for SHA2-256f in
  `tests/test_pqc_kat.py::TestSLHDSA_SHA2_256f_KAT`
- NIST ACVP sigGen vectors for SHAKE-128s (byte-exact) in
  `tests/test_pqc_kat.py::TestSLHDSA_SHAKE_128s_ACVP`
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

### Parameters (SLH-DSA-SHAKE-128s)

| Parameter | Value |
|-----------|-------|
| n | 16 |
| h | 63 |
| d | 7 |
| FORS trees (k) | 14 |
| FORS height (a) | 12 |
| w (Winternitz) | 16 |
| Public key | 32 bytes |
| Secret key | 64 bytes |
| Signature | 7,856 bytes |
