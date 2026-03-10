# API Reference

Complete Python API reference for `ama_cryptography`. All modules, classes, functions, and their parameters.

---

## Module Index

| Module | Description |
|--------|-------------|
| [`crypto_api`](#crypto_api) | Algorithm-agnostic unified cryptographic interface |
| [`pqc_backends`](#pqc_backends) | Post-quantum cryptography backends |
| [`key_management`](#key_management) | Key management, HD derivation, lifecycle |
| [`secure_memory`](#secure_memory) | Secure memory operations |
| [`hybrid_combiner`](#hybrid_combiner) | Hybrid classical + PQC KEM |
| [`adaptive_posture`](#adaptive_posture) | Runtime threat response |
| [`rfc3161_timestamp`](#rfc3161_timestamp) | RFC 3161 trusted timestamps |
| [`exceptions`](#exceptions) | Exception hierarchy |

---

## `crypto_api`

### Enums

#### `CryptoMode`

```python
class CryptoMode(Enum):
    CLASSICAL          # Ed25519 only
    QUANTUM_RESISTANT  # ML-DSA-65 only
    HYBRID             # Ed25519 + ML-DSA-65 (recommended)
```

### Classes

#### `SymmetricCryptoAlgorithm`

AES-256-GCM authenticated encryption.

```python
algo = SymmetricCryptoAlgorithm()

# Encrypt plaintext with a 256-bit key
# Returns: ciphertext (includes IV and GCM tag)
ciphertext: bytes = algo.encrypt(plaintext: bytes, key: bytes) -> bytes

# Decrypt ciphertext
# Returns: plaintext
# Raises: ValueError if authentication fails
plaintext: bytes = algo.decrypt(ciphertext: bytes, key: bytes) -> bytes
```

#### `AsymmetricCryptoAlgorithm`

Ed25519 digital signatures.

```python
algo = AsymmetricCryptoAlgorithm()

# Generate Ed25519 key pair
# Returns: (public_key: 32 bytes, secret_key: 32 bytes)
pk, sk = algo.generate_keypair() -> tuple[bytes, bytes]

# Sign a message
# Returns: signature (64 bytes)
sig: bytes = algo.sign(message: bytes, secret_key: bytes) -> bytes

# Verify a signature
# Returns: True if valid, False otherwise
valid: bool = algo.verify(message: bytes, signature: bytes, public_key: bytes) -> bool
```

#### `PackageSigner`

High-level package signing with configurable mode.

```python
signer = PackageSigner(mode=CryptoMode.HYBRID)

# Sign a data package
# Returns: signed package dict with all applicable signatures
signed = signer.sign_package(package: dict, private_key: bytes) -> dict

# Verify a signed package
# Returns: True if all required signatures are valid
valid: bool = signer.verify_package(package: dict) -> bool
```

#### `HybridSigner`

Combined Ed25519 + ML-DSA-65 signing.

```python
signer = HybridSigner(mode=CryptoMode.HYBRID)

# Generate classical (Ed25519) key pair
pk_classical, sk_classical = signer.generate_classical_keypair()

# Generate PQC (ML-DSA-65) key pair
pk_pqc, sk_pqc = signer.generate_pqc_keypair()

# Sign with Ed25519
sig_ed: bytes = signer.sign_classical(message: bytes, secret_key: bytes) -> bytes

# Sign with ML-DSA-65
sig_pqc: bytes = signer.sign_pqc(message: bytes, secret_key: bytes) -> bytes

# Combine signatures into one structure
combined: bytes = signer.combine_signatures(
    ed25519_sig: bytes,
    ml_dsa_sig: bytes,
) -> bytes

# Verify hybrid signature (both must pass)
valid: bool = signer.verify_hybrid(
    message: bytes,
    combined_signature: bytes,
    pk_classical: bytes,
    pk_pqc: bytes,
) -> bool

# Switch cryptographic mode at runtime
signer.set_mode(mode: CryptoMode) -> None
```

---

## `pqc_backends`

### Constants

```python
DILITHIUM_AVAILABLE: bool  # True if ML-DSA-65 is available
KYBER_AVAILABLE: bool      # True if ML-KEM-1024 is available
SPHINCS_AVAILABLE: bool    # True if SPHINCS+ is available
```

### Functions

#### Status and Discovery

```python
# Get PQC status as a dict
get_pqc_status() -> dict
# Returns: {'ml_dsa_65': 'available', 'ml_kem_1024': 'available', ...}

# Get detailed backend information
get_pqc_backend_info() -> dict

# Get algorithm availability flags
get_pqc_capabilities() -> dict
```

#### ML-DSA-65 (Dilithium)

```python
# Generate ML-DSA-65 key pair
# Returns: (public_key: 1952 bytes, secret_key: 4032 bytes)
pk, sk = generate_dilithium_keypair() -> tuple[bytes, bytes]

# Sign a message
# Returns: signature (3309 bytes)
sig: bytes = dilithium_sign(message: bytes, secret_key: bytes) -> bytes

# Verify a signature
# Returns: True if valid, False otherwise
valid: bool = dilithium_verify(message: bytes, signature: bytes, public_key: bytes) -> bool
```

#### ML-KEM-1024 (Kyber)

```python
# Generate ML-KEM-1024 key pair
# Returns: (public_key: 1568 bytes, secret_key: 3168 bytes)
pk, sk = generate_kyber_keypair() -> tuple[bytes, bytes]

# Encapsulate (sender side)
# Returns: (ciphertext: 1568 bytes, shared_secret: 32 bytes)
ct, ss = kyber_encapsulate(public_key: bytes) -> tuple[bytes, bytes]

# Decapsulate (receiver side)
# Returns: shared_secret (32 bytes)
ss: bytes = kyber_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes
```

#### SPHINCS+-SHA2-256f

```python
# Generate SPHINCS+ key pair
# Returns: (public_key: 64 bytes, secret_key: 128 bytes)
pk, sk = generate_sphincs_keypair() -> tuple[bytes, bytes]

# Sign a message
# Returns: signature (49856 bytes)
sig: bytes = sphincs_sign(message: bytes, secret_key: bytes) -> bytes

# Verify a signature
# Returns: True if valid, False otherwise
valid: bool = sphincs_verify(message: bytes, signature: bytes, public_key: bytes) -> bool
```

---

## `key_management`

### Enums

#### `KeyStatus`

```python
class KeyStatus(Enum):
    ACTIVE
    ROTATING
    DEPRECATED
    REVOKED
    COMPROMISED
```

### Dataclasses

#### `KeyMetadata`

```python
@dataclass
class KeyMetadata:
    key_id: str
    created_at: datetime           # timezone-aware (UTC)
    expires_at: Optional[datetime] # timezone-aware (UTC), or None
    status: KeyStatus
    version: int
    usage_count: int
    max_usage: int
    derivation_path: Optional[str]
```

### Classes

#### `HDKeyDerivation`

BIP32-compatible hierarchical deterministic key derivation.

```python
hd = HDKeyDerivation()

# Derive key from seed using a path
# Only hardened derivation supported (indices ≥ 2^31)
key_material: bytes = hd.derive_from_seed(
    seed: bytes,            # 32-64 byte seed
    path: str,              # e.g., "m/44'/0'/0'/0'"
) -> bytes

# Derive child from parent key
child_key: bytes = hd.derive_child(
    parent_key: bytes,
    path: str,
) -> bytes

HARDENED_OFFSET: int = 2**31  # 2,147,483,648
```

#### `KeyManager`

```python
manager = KeyManager(master_key: bytes)

# Generate a new master key and store it
key_id: str = manager.generate_master_key() -> str

# Derive key material at a given path
key_material: bytes = manager.derive_key(derivation_path: str) -> bytes

# Rotate a key (returns new key_id; old key becomes DEPRECATED)
new_key_id: str = manager.rotate_key(old_key_id: str) -> str

# Get key material by ID
key: bytes = manager.get_key(key_id: str) -> bytes

# Get key metadata
meta: KeyMetadata = manager.get_key_metadata(key_id: str) -> KeyMetadata

# Revoke a key
manager.revoke_key(key_id: str) -> None
```

#### `SecureKeyStorage`

```python
# Context manager for encrypted key storage
# encryption_key must be bytearray (for in-place zeroing)
with SecureKeyStorage(encryption_key: bytearray) as storage:
    storage.store(key_id: str, key_material: bytes) -> None
    key: bytes = storage.retrieve(key_id: str) -> bytes
    storage.delete(key_id: str) -> None
    all_ids: list[str] = storage.list_keys() -> list[str]
```

---

## `secure_memory`

```python
# Context manager: auto-zero buffer on exit
with SecureBuffer(size: int) as buf:
    buf.data: bytearray  # size bytes, initially zeroed

# Multi-pass overwrite (must be bytearray)
secure_memzero(buffer: bytearray) -> None

# Lock memory into RAM (prevent swap)
# Returns True if successful
locked: bool = secure_mlock(buffer: bytearray) -> bool

# Unlock memory (allow swap)
secure_munlock(buffer: bytearray) -> None

# Constant-time byte comparison (timing-safe)
equal: bool = constant_time_compare(a: bytes, b: bytes) -> bool
```

---

## `hybrid_combiner`

```python
combiner = HybridCombiner()

# Sender: encapsulate using recipient's public keys
encapsulation: HybridEncapsulation = combiner.encapsulate(
    classical_pk: bytes,
    pqc_pk: bytes,
) -> HybridEncapsulation

# Receiver: decapsulate using secret keys
combined_secret: bytes = combiner.decapsulate(
    encapsulation: HybridEncapsulation,
    classical_sk: bytes,
    pqc_sk: bytes,
) -> bytes
```

#### `HybridEncapsulation`

```python
@dataclass
class HybridEncapsulation:
    combined_secret: bytes         # 32 bytes — HKDF output
    classical_ciphertext: bytes    # X25519 ephemeral public key (32 bytes)
    pqc_ciphertext: bytes          # ML-KEM-1024 ciphertext (1568 bytes)
    classical_shared_secret: bytes # X25519 shared secret (32 bytes)
    pqc_shared_secret: bytes       # Kyber shared secret (32 bytes)
```

---

## `adaptive_posture`

```python
evaluator = PostureEvaluator()

# Evaluate monitoring signals
evaluation: PostureEvaluation = evaluator.evaluate(
    monitor_signals: dict,
) -> PostureEvaluation

# PostureEvaluation fields:
# evaluation.threat_level: ThreatLevel
# evaluation.recommended_action: PostureAction
# evaluation.confidence: float  (0.0 – 1.0)
# evaluation.signals: dict

controller = CryptoPostureController()

# Execute recommended action
controller.execute_action(
    evaluation: PostureEvaluation,
    crypto_api: Any,
    key_manager: KeyManager,
) -> None
```

---

## `rfc3161_timestamp`

```python
from ama_cryptography.rfc3161_timestamp import get_timestamp, TimestampResult

# Request a trusted timestamp from a TSA
result: TimestampResult = get_timestamp(
    data_hash: bytes,               # SHA3-256 hash to timestamp
    tsa_url: str = "https://freetsa.org/tsr",  # TSA endpoint
) -> TimestampResult

# TimestampResult fields:
# result.token: bytes          — DER-encoded RFC 3161 token
# result.timestamp: datetime   — Signed timestamp (UTC)
# result.tsa_url: str          — TSA used
# result.success: bool
# result.error: Optional[str]
```

---

## `exceptions`

```python
from ama_cryptography.exceptions import (
    AMAError,              # Base exception
    PQCUnavailableError,   # PQC library not available
    KeyManagementError,    # Key management failures
    SecurityWarning,       # Non-fatal security warnings (Warning subclass)
    CryptoOperationError,  # Cryptographic operation failure
    TimestampError,        # RFC 3161 timestamp failure
)
```

### Exception Hierarchy

```
AMAError (Exception)
├── PQCUnavailableError   — raise when PQC backend missing
├── KeyManagementError    — raise on key lifecycle errors
├── CryptoOperationError  — raise on cryptographic failures
└── TimestampError        — raise on RFC 3161 errors

SecurityWarning (Warning)
└── Raised via warnings.warn() for non-fatal security issues
```

---

## Package-Level Imports

```python
import ama_cryptography

# Always available
ama_cryptography.crypto_api
ama_cryptography.pqc_backends
ama_cryptography.key_management
ama_cryptography.secure_memory
ama_cryptography.hybrid_combiner
ama_cryptography.adaptive_posture
ama_cryptography.rfc3161_timestamp
ama_cryptography.exceptions

# Conditionally available (requires NumPy)
# Loaded lazily via PEP 562 __getattr__ to avoid hard dependency
ama_cryptography.equations       # conditional import
ama_cryptography.double_helix_engine  # conditional import
```

---

*See [C API Reference](C-API-Reference) for the native C library, or [Quick Start](Quick-Start) for hands-on examples.*
