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
- `SLH-DSA-SHA2-256f-sigGen-FIPS205.json` — 4 NIST ACVP signature
  generation vectors for the production **SLH-DSA-SHA2-256f** set
  (external/pure interface): 2 deterministic (tcIds 40, 43) and 2 hedged
  (tcIds 351, 356, with `additionalRandomness`). Curated from the same
  NIST ACVP-Server `v1.1.0.42` `SLH-DSA-sigGen-FIPS205/internalProjection.json`.

  The native SHA2-256f **signer** is byte-identical to the FIPS 205 / NIST ACVP
  reference for both the deterministic and hedged interfaces — signatures match
  the pinned vectors byte-for-byte and reproduce the NIST public-key root. This
  matches SLH-DSA-SHAKE-128s. Signing derives WOTS+/FORS secret values under the
  FIPS 205 §4.2 `WOTS_PRF=5` / `FORS_PRF=6` address types; an earlier divergence
  in the FORS/WOTS+/hypertree body (from reusing the chain/tree address types
  there) was corrected in the native `ama_slhdsa.c` signer.

### Test Coverage

The SLH-DSA implementation is validated via:
- NIST ACVP sigVer vectors for SHA2-256f in
  `tests/test_pqc_kat.py::TestSLHDSA_SHA2_256f_KAT`
- NIST ACVP sigGen vectors for SHAKE-128s (byte-exact) in
  `tests/test_pqc_kat.py::TestSLHDSA_SHAKE_128s_ACVP`
- NIST ACVP sigGen vectors for SHA2-256f (full byte-exact — deterministic and
  hedged — plus verifier interop and self-consistency) in
  `tests/test_pqc_kat.py::TestSLHDSA_SHA2_256f_ACVP_sigGen`
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
