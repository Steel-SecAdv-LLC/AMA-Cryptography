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

### `KeyManager`

The primary key management class:

```python
from ama_cryptography.key_management import KeyManager
import os

# Initialize with a 256-bit master key
master_key = os.urandom(32)
manager = KeyManager(master_key)

# Generate and store a new key
key_id = manager.generate_master_key()

# Derive a key for a specific purpose
key_material = manager.derive_key("m/44'/0'/0'/0'")

# Rotate a key (zero-downtime)
new_key_id = manager.rotate_key(key_id)

# Get key material
key = manager.get_key(key_id)

# Get metadata
meta = manager.get_key_metadata(key_id)
print(f"Status: {meta.status}")
print(f"Version: {meta.version}")
print(f"Usage: {meta.usage_count}/{meta.max_usage}")
```

---

## Hierarchical Deterministic (HD) Key Derivation

### Overview

AMA Cryptography implements BIP32-compatible hierarchical deterministic key derivation using HKDF-SHA3-256 and secp256k1 elliptic curve operations.

**Key derivation path format:** `m/{purpose}'/{account}'/{change}'/{index}'`

All derivations use **hardened** child keys (index ≥ 2^31). Non-hardened derivation raises `NotImplementedError` because hardened derivation prevents child key exposure from compromising sibling or parent keys.

### `HDKeyDerivation`

```python
from ama_cryptography.key_management import HDKeyDerivation

hd = HDKeyDerivation()

# Derive key material from a seed
seed = os.urandom(64)
key_material = hd.derive_from_seed(seed, "m/44'/0'/0'/0'")

# Derive child from parent key
parent_key = os.urandom(32)
child_key = hd.derive_child(parent_key, "m/44'/0'/0'/0'")
```

### Derivation Path Conventions

| Path | Purpose |
|------|---------|
| `m/44'/0'/0'/0'` | Standard account key |
| `m/84'/0'/0'/0'` | Native segwit-style |
| `m/0'/0'/0'/0'` | Custom derivation |

**HARDENED_OFFSET = 2^31 = 2,147,483,648**

```python
from ama_cryptography.key_management import HDKeyDerivation

# Only hardened derivation is supported
# index >= 2^31 for hardened (denoted with ' in path)
child = hd.derive_child(parent_key, "m/44'/0'/0'/0'")
```

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
from ama_cryptography.key_management import KeyManager, KeyStatus
import os

manager = KeyManager(os.urandom(32))

# 1. Generate active key
key_id = manager.generate_master_key()
meta = manager.get_key_metadata(key_id)
assert meta.status == KeyStatus.ACTIVE

# 2. Rotate (zero-downtime: old key becomes DEPRECATED, new key is ACTIVE)
new_key_id = manager.rotate_key(key_id)

old_meta = manager.get_key_metadata(key_id)
new_meta = manager.get_key_metadata(new_key_id)
assert old_meta.status == KeyStatus.DEPRECATED
assert new_meta.status == KeyStatus.ACTIVE

# 3. Verify with old key still works during transition
# (DEPRECATED keys can verify but not sign)

# 4. Revoke old key when transition is complete
manager.revoke_key(key_id)
```

---

## Secure Key Storage

### `SecureKeyStorage`

For encrypted storage of key material at rest:

```python
from ama_cryptography.key_management import SecureKeyStorage
import os

# encryption_key is stored as bytearray (not bytes)
# to allow in-place zeroing when the context manager exits
encryption_key = bytearray(os.urandom(32))

with SecureKeyStorage(encryption_key) as storage:
    # Store key
    key_data = os.urandom(32)
    storage.store("my-key-id", key_data)
    
    # Retrieve key
    retrieved = storage.retrieve("my-key-id")
    assert retrieved == key_data

# encryption_key is automatically zeroed here
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
from ama_cryptography.key_management import KeyManager, KeyMetadata
from datetime import datetime, timezone, timedelta

def check_and_rotate(manager: KeyManager, key_id: str) -> str:
    meta = manager.get_key_metadata(key_id)
    now = datetime.now(timezone.utc)
    
    if meta.expires_at and now >= meta.expires_at:
        print(f"Key {key_id} expired, rotating...")
        return manager.rotate_key(key_id)
    
    if meta.usage_count >= meta.max_usage * 0.9:
        print(f"Key {key_id} approaching usage limit, rotating...")
        return manager.rotate_key(key_id)
    
    return key_id
```

---

## Thread Safety

Key management operations use `datetime.now(timezone.utc)` for all timestamps (timezone-aware). The `KeyManager` class is designed for concurrent use; however, critical operations around key rotation should be externally serialized in multi-threaded environments.

---

## Exception Handling

```python
from ama_cryptography.exceptions import (
    KeyManagementError,
    PQCUnavailableError,
    SecurityWarning,
)

try:
    key = manager.get_key("non-existent-key-id")
except KeyManagementError as e:
    print(f"Key management error: {e}")

try:
    pk, sk = generate_dilithium_keypair()
except PQCUnavailableError as e:
    print(f"PQC not available: {e}")
    # Fall back to classical-only
```

---

*See [Secure Memory](Secure-Memory) for memory-safety details, or [Architecture](Architecture) for the full key management architecture diagram.*
