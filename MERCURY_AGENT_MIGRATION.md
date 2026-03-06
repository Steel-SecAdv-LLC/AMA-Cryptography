# Mercury Agent Migration Guide: AMA Cryptography v2.0

This document describes the changes needed in Mercury Agent to work with
AMA Cryptography v2.0 (formerly Ava Guardian).

## Package Rename Summary

| Before (v1.x) | After (v2.0) |
|----------------|--------------|
| `ava-guardian` | `ama-cryptography` |
| `import ava_guardian` | `import ama_cryptography` |
| `AVA_GUARDIAN_*` env vars | `AMA_CRYPTO_*` env vars |
| `AvaGuardianCrypto` | `AmaCryptography` |

## Mercury Agent Files Requiring Updates

### 1. `pyproject.toml`

```diff
[project.optional-dependencies]
- pqc = ["ava-guardian>=1.1"]
+ pqc = ["ama-cryptography>=2.0"]
```

### 2. `security/pqc_backends.py`

```diff
- import ava_guardian
+ import ama_cryptography
```

Update the prioritized fallback chain:
AMA Cryptography (primary) -> liboqs (secondary) -> pqcrypto (tertiary) -> simulation (dev only)

### 3. `security/pqc_guards.py`

```diff
- if os.environ.get("AVA_REQUIRE_REAL_PQC"):
+ if os.environ.get("AMA_REQUIRE_REAL_PQC") or os.environ.get("AVA_REQUIRE_REAL_PQC"):
```

Note: Backward compatibility with `AVA_REQUIRE_REAL_PQC` is recommended during transition.

### 4. `integrations/mercury_guardian.py`

```diff
- from ava_guardian.crypto_api import AmaCryptography
+ from ama_cryptography.crypto_api import AmaCryptography
```

The `MercuryGuardianAdapter` class import paths need updating.

### 5. `security/crypto_api.py`

Provider pattern classes are unchanged:
- `Ed25519Provider`, `MLDSAProvider`, `KyberProvider`, `SphincsProvider`, `HybridSignatureProvider`
- `PQCStatus`, `DilithiumKeyPair`, `KyberKeyPair`, `SphincsKeyPair` dataclasses

## API Compatibility

### Algorithms Available

| Feature | v1.x Name | v2.0 Name | Status |
|---------|-----------|-----------|--------|
| ML-DSA-65 sign/verify | Same | Same | Compatible |
| Kyber-1024 encap/decap | Same | Same | Compatible |
| SPHINCS+-256f sign/verify | Same | Same | Compatible |
| Hybrid Ed25519+ML-DSA | Same | Same | Compatible |
| `get_pqc_capabilities()` | Same | Same | Compatible |
| Constant-time ops | `AVA_REQUIRE_CONSTANT_TIME` | `AMA_REQUIRE_CONSTANT_TIME` | Env var renamed |

### Kyber Parameter Note

Mercury Agent uses Kyber-768 references in some documentation, but AMA Cryptography
provides Kyber-1024 (ML-KEM-1024). Both parameter sets are supported in the C backend.
Verify Mercury's actual KEM parameter usage matches ML-KEM-1024.

## Environment Variables

| Old | New |
|-----|-----|
| `AVA_REQUIRE_REAL_PQC` | `AMA_REQUIRE_REAL_PQC` |
| `AVA_REQUIRE_CONSTANT_TIME` | `AMA_REQUIRE_CONSTANT_TIME` |
| `AVA_GUARDIAN_LOG_LEVEL` | `AMA_CRYPTO_LOG_LEVEL` |

## Shared Patterns

Both projects use identical patterns:
- Ethical governance: benevolence >= 0.99 threshold
- `SIGNATURE_DOMAIN_PREFIX`: now `AMA-PKG-v2` (was `AG-PKG-v2`)
- Omni-Codes / `HELIX_PARAMS` mathematical constants unchanged

## Python Version

AMA Cryptography v2.0 requires Python >= 3.9 (was >= 3.8).
Mercury Agent requires >= 3.11. No conflict.

## License

AMA Cryptography: Apache 2.0
Mercury Agent: GPL v3

Apache 2.0 is GPL-compatible. Mercury can depend on AMA Cryptography without issue.
