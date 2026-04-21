# Key Management

Comprehensive documentation for the AMA Cryptography key management system, including hierarchical deterministic (HD) key derivation, key lifecycle management, rotation, and HSM integration.

---

## Overview

The key management system provides enterprise-grade capabilities:

- **HD Key Derivation** — BIP32-compatible hierarchical deterministic keys
- **Key Lifecycle** — Active → Rotating → Deprecated → Revoked → Compromised
- **Zero-Downtime Rotation** — Seamless key rotation with versioned metadata
- **Secure Storage** — Encrypted key storage at rest
- **HSM Support** — FIPS 140-2 Level 3+ Hardware Security Module integration

---

## Core Classes

### `KeyStatus` Enum

```python
from ama_cryptography.key_management import KeyStatus

class KeyStatus(Enum):
    ACTIVE      # Key is active and in use
    ROTATING    # Key is being rotated (transitional state)
    DEPRECATED  # Key is deprecated; verify only, don't sign
    REVOKED     # Key is revoked; reject all operations
    COMPROMISED # Key is compromised; requires immediate action
```

### `KeyMetadata`

```python
from ama_cryptography.key_management import KeyMetadata

# Metadata attached to every managed key
meta = KeyMetadata(
    key_id="kid-abc123",
    created_at=datetime.now(timezone.utc),
    expires_at=datetime.now(timezone.utc) + timedelta(days=365),
    status=KeyStatus.ACTIVE,
    version=1,
    usage_count=0,
    max_usage=10000,
    derivation_path="m/44'/0'/0'/0'",
)
```

### `KeyRotationManager`

The policy-level class that tracks keys under rotation. It does **not**
hold key material itself — that stays with the application (or an HSM,
or `SecureKeyStorage` below); the manager tracks metadata (status,
version, expiry, usage counts) and exposes rotation hooks.

```python
from datetime import timedelta
from ama_cryptography.key_management import KeyRotationManager

mgr = KeyRotationManager(rotation_period=timedelta(days=90))

# Register a key under the rotation policy
meta = mgr.register_key(
    key_id="signing-key-v1",
    purpose="document-signatures",
    expires_in=timedelta(days=90),
    max_usage=100_000,
)

# Policy queries
should_rotate = mgr.should_rotate("signing-key-v1")     # bool
active_id     = mgr.get_active_key()                    # Optional[str]

# Rotation lifecycle: old key -> ROTATING -> DEPRECATED
mgr.initiate_rotation("signing-key-v1", "signing-key-v2")
# ... provision the new key material elsewhere ...
mgr.complete_rotation("signing-key-v1")

# Accounting
mgr.increment_usage("signing-key-v2")
mgr.revoke_key("signing-key-v1", reason="superseded")

# Audit snapshot
audit = mgr.export_metadata()    # or export_metadata(filepath=Path(...))
```

For seed-derived keys, construct an `HDKeyDerivation(seed=...)`
and call `derive_key(...)` — see the next section.

---

## Hierarchical Deterministic (HD) Key Derivation

### Overview

AMA Cryptography implements BIP32-compatible hierarchical deterministic
key derivation. The PRF is **HMAC-SHA-512** (BIP32-standard, delegated to
the native C backend via `ama_cryptography.pqc_backends.native_hmac_sha512`
to satisfy INVARIANT-1 — no stdlib `hmac`). Non-hardened child derivation
uses the native secp256k1 public-key computation.

**Path format:** `m/{purpose}'/{account}'/{change}'/{index}'` (BIP-44) or
any explicit BIP32 path.

- `HDKeyDerivation.derive_key(purpose, account, change, index)` is a
  convenience wrapper that always emits a **fully hardened** path — all
  four components are hardened by construction.
- `HDKeyDerivation.derive_path(path)` accepts an explicit BIP32-style
  path and **supports both hardened and non-hardened** components.
  Hardened indices are written with a trailing `'` (or equivalently
  passed as `index ≥ 2^31 = HARDENED_OFFSET`). Hardened derivation gives
  stronger branch isolation — compromise of a hardened child cannot be
  used to recover sibling or parent private keys — but non-hardened
  indices are supported for the cases where public-child derivation is
  required.

### `HDKeyDerivation`

```python
import os
from ama_cryptography.key_management import HDKeyDerivation

# Provide the seed (or a BIP-39-style seed_phrase) at construction. The
# instance holds the seed for subsequent derivations; the caller is
# responsible for seed lifetime — HDKeyDerivation does not currently
# perform secure wipe of self.master_seed on __del__.
seed = os.urandom(64)
hd   = HDKeyDerivation(seed=seed)

# Structured BIP-44-style derivation: always produces a FULLY hardened
# path m/{purpose}'/{account}'/{change}'/{index}'
key_material: bytes = hd.derive_key(purpose=44, account=0, change=0, index=0)

# Explicit-path derivation: returns (derived_key, chain_code).
# Accepts both hardened (with trailing ') and non-hardened components.
key, chain_code = hd.derive_path("m/44'/0'/0'/0'")
```

### Derivation Path Conventions

| Path | Purpose |
|------|---------|
| `m/44'/0'/0'/0'` | Standard account key (fully hardened) |
| `m/84'/0'/0'/0'` | Native segwit-style (fully hardened) |
| `m/0'/0'/0'/0'` | Custom derivation (fully hardened) |

**HARDENED_OFFSET = 2^31 = 2,147,483,648**

Hardened indices are written with a trailing `'` and correspond to
values ≥ 2^31.

- `HDKeyDerivation.derive_key(purpose, account, change, index)` always
  constructs a **fully hardened** BIP-44-style path — every component
  emitted by this convenience API is hardened.
- `HDKeyDerivation.derive_path(path)` accepts an explicit path and parses
  both hardened (`44'`) and non-hardened (`44`) components. Non-hardened
  derivation produces a public child from which sibling keys can be
  derived; use it only when public-child derivation is required, and
  prefer hardened components otherwise for stronger branch isolation.

---

## Key Lifecycle Management

### Lifecycle Transitions

```
ACTIVE
  │
  ├── rotate_key() ──► ROTATING ──► (old: DEPRECATED, new: ACTIVE)
  │
  └── revoke_key() ──► REVOKED
                        │
                        └── mark_compromised() ──► COMPROMISED
```

### Full Lifecycle Example

```python
from datetime import timedelta
from ama_cryptography.key_management import KeyRotationManager, KeyStatus

mgr = KeyRotationManager(rotation_period=timedelta(days=90))

# 1. Register the initial active key
old_meta = mgr.register_key(
    key_id="signing-key-v1",
    purpose="document-signatures",
    expires_in=timedelta(days=90),
    max_usage=100_000,
)
assert old_meta.status == KeyStatus.ACTIVE

# 2. Begin zero-downtime rotation: old key moves to ROTATING
#    (provision the new key material in your keystore before registering it)
mgr.register_key("signing-key-v2", purpose="document-signatures",
                 parent_id="signing-key-v1", expires_in=timedelta(days=90))
mgr.initiate_rotation("signing-key-v1", "signing-key-v2")

# 3. Finalize rotation: old key becomes DEPRECATED, new key is ACTIVE
mgr.complete_rotation("signing-key-v1")

# 4. DEPRECATED keys can verify but not sign — let them age out, then revoke
mgr.revoke_key("signing-key-v1", reason="superseded")
```

---

## Secure Key Storage

### `SecureKeyStorage`

For encrypted storage of key material at rest:

```python
import os
from pathlib import Path
from ama_cryptography.key_management import (
    SecureKeyStorage,
    KeyRotationManager,
)

# SecureKeyStorage takes a storage directory and an optional master
# password; it derives the at-rest encryption key internally.
storage = SecureKeyStorage(
    storage_path=Path("/var/lib/myapp/keys"),
    master_password=os.environ.get("AMA_KEY_PASSWORD"),   # None → uses default KDF
)
mgr = KeyRotationManager()

key_data = os.urandom(32)
meta     = mgr.register_key("my-key-id", purpose="doc-signing")

# store_key takes an optional plain dict of metadata; the KeyMetadata
# returned by register_key lives in the rotation manager, not the store.
storage.store_key("my-key-id", key_data, metadata={"purpose": "doc-signing"})

retrieved: bytes | None = storage.retrieve_key("my-key-id")
assert retrieved == key_data

# Metadata for active/deprecated/revoked status is maintained by the
# rotation manager:
active_meta = mgr.export_metadata()
```

### Key Storage Security

- **In-Memory:** Key material is stored as `bytearray` to allow in-place zeroing
- **At-Rest:** Keys are encrypted with AES-256-GCM before serialization
- **Memory Lock:** Uses `secure_mlock()` to prevent key swapping to disk
- **Zeroing:** Automatic multi-pass zeroing via `SecureBuffer` context manager

---

## Production Key Security

### Option 1: Hardware Security Module (HSM) — Recommended

For production deployments, store master secrets in FIPS 140-2 Level 3+ HSMs:

```python
# AWS CloudHSM Example
import boto3

def store_master_secret_hsm(master_secret: bytes, key_label: str) -> str:
    client = boto3.client('cloudhsmv2')
    response = client.import_key(
        KeyLabel=key_label,
        KeyMaterial=master_secret,
        KeySpec='AES_256'
    )
    # NEVER store master_secret on disk after this point
    # Zero out memory immediately
    master_secret_buf = bytearray(master_secret)
    for i in range(len(master_secret_buf)):
        master_secret_buf[i] = 0
    return response['KeyId']
```

### Option 2: Hardware Token (YubiKey, Nitrokey)

For personal/small-team use (FIPS 140-2 Level 2):

```python
from ykman.device import connect_to_device
from ykman.piv import PivController

def store_key_yubikey(master_secret: bytes, slot: int = 0x82):
    device, _ = connect_to_device()[0]
    piv = PivController(device.driver)
    piv.authenticate(management_key)
    piv.import_key(slot, master_secret)
```

### Option 3: Password-Encrypted Keystore (Software)

Minimum security for development. Use PBKDF2 with 600,000+ iterations (OWASP 2024):

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64, os

def encrypt_master_secret(master_secret: bytes, password: str, path: str):
    salt = os.urandom(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,  # OWASP 2024 recommendation
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    encrypted = Fernet(key).encrypt(master_secret)
    with open(path, 'wb') as f:
        f.write(salt + encrypted)
```

---

## Key Expiry and Rotation Policy

### Recommended Rotation Intervals

| Key Type | Recommended Rotation |
|----------|---------------------|
| Master Secret | Annually or on compromise |
| HMAC Key | 90 days |
| Ed25519 Signing Key | 1 year |
| ML-DSA-65 Signing Key | 2 years |
| Session Keys | Per session |

### Automated Rotation

```python
from ama_cryptography.key_management import KeyRotationManager

def check_and_rotate(
    mgr: KeyRotationManager,
    key_id: str,
    new_key_id: str,
) -> str:
    """Rotate `key_id` → `new_key_id` if policy says so; return the active id."""
    if mgr.should_rotate(key_id):
        mgr.initiate_rotation(key_id, new_key_id)
        # ... provision the new key material in the caller's keystore ...
        mgr.complete_rotation(key_id)
        return new_key_id
    return key_id
```

---

## Thread Safety

Key management operations use `datetime.now(timezone.utc)` for all timestamps (timezone-aware). The `KeyRotationManager` class is designed for concurrent use; however, critical operations around key rotation (`initiate_rotation` / `complete_rotation`) should be externally serialized in multi-threaded environments.

---

## Exception Handling

```python
from ama_cryptography.exceptions import (
    KeyManagementError,
    PQCUnavailableError,
    QuantumSignatureUnavailableError,
    SecurityWarning,
)
from ama_cryptography.pqc_backends import generate_dilithium_keypair

try:
    meta = mgr.register_key("my-key", purpose="doc-signing")
    # ... later ...
    mgr.revoke_key("my-key", reason="operator_action")
except KeyManagementError as e:
    print(f"Key management error: {e}")

try:
    kp = generate_dilithium_keypair()
except PQCUnavailableError as e:
    # INVARIANT-7: we do NOT silently fall back to a classical-only path.
    # The correct response is to surface the failure, not hide it.
    raise
```

---

*See [Secure Memory](Secure-Memory) for memory-safety details, or [Architecture](Architecture) for the full key management architecture diagram.*
