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

The algorithm-agnostic entry point is `AmaCryptography`, selected by an
`AlgorithmType`. Every concrete backend (Ed25519, ML-DSA-65, ML-KEM-1024,
SPHINCS+-256f, AES-256-GCM, hybrid signature, hybrid KEM) is a `CryptoProvider`
subclass that can also be used directly.

### Enums

#### `AlgorithmType`

```python
class AlgorithmType(Enum):
    ML_DSA_65      = 1   # NIST FIPS 204 signature (post-quantum)
    KYBER_1024     = 2   # NIST FIPS 203 KEM (post-quantum)
    SPHINCS_256F   = 3   # NIST FIPS 205 signature (hash-based)
    ED25519        = 4   # RFC 8032 signature (classical)
    AES_256_GCM    = 5   # NIST SP 800-38D AEAD
    HYBRID_SIG     = 6   # Ed25519 || ML-DSA-65  (recommended default)
    HYBRID_KEM     = 7   # X25519 || ML-KEM-1024
```

#### `CryptoBackend`

Defined in `ama_cryptography/crypto_api.py:215–220`.

```python
class CryptoBackend(Enum):
    """Available implementation backends."""
    C_LIBRARY   = auto()  # libama_cryptography.so (fastest, native PQC) — default
    CYTHON      = auto()  # Cython-optimized (fast)
    PURE_PYTHON = auto()  # Pure-Python fallback
```

> There is **no** `CryptoBackend.PYTHON` member; the pure-Python path is
> `CryptoBackend.PURE_PYTHON`.

### Dataclasses

Defined in `ama_cryptography/crypto_api.py:223–274`. Not `frozen=True`;
sensitive fields use `field(repr=False)` so `repr()` never surfaces key
material.

```python
@dataclass
class KeyPair:
    public_key: bytes
    secret_key: bytes = field(repr=False)   # SENSITIVE
    algorithm: AlgorithmType
    metadata: Dict[str, Any]

@dataclass
class Signature:
    signature: bytes
    algorithm: AlgorithmType
    message_hash: bytes
    metadata: Dict[str, Any]

@dataclass
class EncapsulatedSecret:
    ciphertext: bytes
    shared_secret: bytes = field(repr=False)  # SENSITIVE
    algorithm: AlgorithmType
    metadata: Dict[str, Any]
```

### Classes

#### `AmaCryptography`

High-level, algorithm-agnostic orchestrator. Used as-is for single-algorithm
workflows, or configured with `HYBRID_SIG` / `HYBRID_KEM` to transparently
drive the Ed25519+ML-DSA-65 or X25519+ML-KEM-1024 hybrid providers.

```python
from ama_cryptography.crypto_api import AmaCryptography, AlgorithmType, CryptoBackend

crypto = AmaCryptography(
    algorithm: AlgorithmType = AlgorithmType.HYBRID_SIG,
    backend: CryptoBackend = CryptoBackend.C_LIBRARY,
)

# Signature primitives (ED25519, ML_DSA_65, SPHINCS_256F, HYBRID_SIG)
kp: KeyPair      = crypto.generate_keypair()
sig: Signature   = crypto.sign(message: bytes, secret_key: bytes | bytearray)
valid: bool      = crypto.verify(message: bytes, signature: bytes | Signature, public_key: bytes)

# KEM primitives (KYBER_1024, HYBRID_KEM)
enc: EncapsulatedSecret = crypto.encapsulate(public_key: bytes)
shared: bytes           = crypto.decapsulate(ciphertext: bytes, secret_key: bytes | bytearray)

# Static helpers
digest: bytes   = AmaCryptography.hash_message(message: bytes, algorithm="sha3-256")
equal: bool     = AmaCryptography.constant_time_compare(a: bytes, b: bytes)
```

Invariants:
- `generate_keypair()` / `sign()` / `verify()` are valid only when the selected
  algorithm is a signature scheme; `encapsulate()` / `decapsulate()` only for
  KEM schemes. Calling the wrong family raises `ValueError`.
- INVARIANT-7 (no silent cryptographic fallback): if the native C library is
  unavailable, `__init__` raises rather than degrading to Python.

#### Direct providers

Each provider implements either `CryptoProvider` (sign/verify) or
`KEMProvider` (encapsulate/decapsulate) and shares the data shapes above.
Use them when you need to pin a single algorithm without going through the
dispatcher.

| Class | Algorithm | Family |
|-------|-----------|--------|
| `Ed25519Provider` | Ed25519 (RFC 8032) | signature |
| `MLDSAProvider` | ML-DSA-65 (FIPS 204) | signature |
| `SphincsProvider` | SPHINCS+-SHA2-256f (FIPS 205) | signature |
| `HybridSignatureProvider` | Ed25519 ∥ ML-DSA-65 | signature |
| `KyberProvider` | ML-KEM-1024 (FIPS 203) | KEM |
| `HybridKEMProvider` | X25519 ∥ ML-KEM-1024 | KEM |
| `AESGCMProvider` | AES-256-GCM (SP 800-38D) | AEAD (separate `encrypt` / `decrypt`) |

Each provider shares the same constructor signature as `AmaCryptography`
(no algorithm argument — the class itself pins the algorithm).

#### `KeypairCache`

```python
cache = KeypairCache(algorithm: AlgorithmType = AlgorithmType.HYBRID_SIG)
```

Fixed-size cache for hot-path keypair reuse. Constant-time-zeroed on eviction.

#### `AESGCMProvider` (AEAD)

```python
from ama_cryptography.crypto_api import AESGCMProvider
import os

aead = AESGCMProvider()
key  = os.urandom(32)                                              # 256-bit key

# Encrypt: nonce is auto-generated when omitted.
# Returns a dict with 'ciphertext', 'nonce', 'tag', 'aad', 'backend'.
result = aead.encrypt(plaintext: bytes, key: bytes,
                      nonce: bytes | None = None, aad: bytes = b"")

# Decrypt: caller passes the nonce and tag back in.
plaintext = aead.decrypt(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    tag: bytes,
    aad: bytes = b"",
)   # raises on tag mismatch
```

Nonces are 96-bit (NIST SP 800-38D); tags are 128-bit. Associated data
is authenticated but not encrypted. To reuse the same nonce/tag wire
layout across systems, the result dict fields can be concatenated as
`nonce || ciphertext || tag`; unpack them symmetrically on the
receive side.

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
# High-level rollup: returns PQCStatus.AVAILABLE if at least one PQC
# backend loaded, PQCStatus.UNAVAILABLE otherwise.
get_pqc_status() -> PQCStatus

# Detailed backend dict: per-algorithm availability + backend names,
# algorithm parameters (key/sig sizes), and hash/HMAC native-C status.
get_pqc_backend_info() -> dict
# Example keys: 'status', 'dilithium_available', 'dilithium_backend',
# 'kyber_available', 'sphincs_available', 'algorithms', 'SHA3-256',
# 'HMAC-SHA3-256'
```

#### ML-DSA-65 (Dilithium)

```python
# Generate ML-DSA-65 key pair.
# Returns a DilithiumKeyPair dataclass with .public_key (1952 bytes),
# .secret_key (4032 bytes), and .wipe() for constant-time zeroing.
kp = generate_dilithium_keypair()
pk, sk = kp.public_key, kp.secret_key

# Sign a message -> 3309-byte signature
sig: bytes = dilithium_sign(message: bytes, secret_key: bytes) -> bytes

# Verify a signature
valid: bool = dilithium_verify(message: bytes, signature: bytes, public_key: bytes) -> bool
```

#### ML-KEM-1024 (Kyber)

```python
# Generate ML-KEM-1024 key pair.
# Returns a KyberKeyPair dataclass with .public_key (1568 bytes),
# .secret_key (3168 bytes), and .wipe().
kp = generate_kyber_keypair()
pk, sk = kp.public_key, kp.secret_key

# Encapsulate (sender side).
# Returns a KyberEncapsulation dataclass with .ciphertext (1568 bytes)
# and .shared_secret (32 bytes).
enc = kyber_encapsulate(public_key: bytes)

# Decapsulate (receiver side) -> 32-byte shared secret
ss: bytes = kyber_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes
```

#### SPHINCS+-SHA2-256f

```python
# Generate SPHINCS+ key pair.
# Returns a SphincsKeyPair dataclass with .public_key (64 bytes),
# .secret_key (128 bytes), and .wipe().
kp = generate_sphincs_keypair()
pk, sk = kp.public_key, kp.secret_key

# Sign a message -> 49856-byte signature
sig: bytes = sphincs_sign(message: bytes, secret_key: bytes) -> bytes

# Verify a signature
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

BIP32-style hierarchical deterministic key derivation. AMA uses
HMAC-SHA3-256 (not HMAC-SHA-512) for derivation; only hardened indices
are permitted.

```python
from ama_cryptography.key_management import HDKeyDerivation

hd = HDKeyDerivation(seed: bytes | None = None, seed_phrase: str | None = None)   # 32–64 byte seed, or a BIP-39-style phrase

# Derive a key at a fixed BIP-44-style position
key_material: bytes = hd.derive_key(
    purpose: int,           # e.g., 44
    account: int = 0,
    change: int = 0,
    index: int = 0,
) -> bytes

# Derive from an explicit hardened path. Returns (key, chain_code)
key, chain_code = hd.derive_path(path: str)        # e.g. "m/44'/0'/0'/0'"
```

#### `KeyRotationManager`

```python
from datetime import timedelta
from ama_cryptography.key_management import KeyRotationManager, KeyMetadata

mgr = KeyRotationManager(rotation_period: timedelta = timedelta(days=90))

# Register a key with the rotation policy
meta: KeyMetadata = mgr.register_key(
    key_id: str,
    purpose: str,
    parent_id: str | None = None,
    derivation_path: str | None = None,
    expires_in: timedelta | None = None,
    max_usage: int | None = None,
)

# Policy hooks
should:    bool          = mgr.should_rotate(key_id: str)
active:    str | None    = mgr.get_active_key()
mgr.initiate_rotation(old_key_id: str, new_key_id: str)
mgr.complete_rotation(old_key_id: str)     # old key → DEPRECATED
mgr.increment_usage(key_id: str)
mgr.revoke_key(key_id: str, reason: str = "compromised")
metadata:  dict           = mgr.export_metadata(filepath: Path | None = None)
```

#### `SecureKeyStorage`

Defined in `ama_cryptography/key_management.py:537`. The constructor takes
a **storage directory** and an optional master password — not a raw
encryption key. `retrieve_key()` returns the ciphertext-decrypted key
material as `Optional[bytes]` (or `None` if the id is missing); metadata
is stored separately as a JSON-serializable `dict` and is typically
retrieved via `KeyRotationManager`.

```python
from pathlib import Path
from ama_cryptography.key_management import SecureKeyStorage

storage = SecureKeyStorage(
    storage_path: Path,
    master_password: Optional[str] = None,
)

# Store / retrieve / delete
storage.store_key(
    key_id: str,
    key_data: bytes,
    metadata: Optional[Dict[str, Any]] = None,
) -> None

key_bytes: Optional[bytes] = storage.retrieve_key(key_id: str)
storage.delete_key(key_id: str) -> None
all_ids:   list[str]       = storage.list_keys()
```

#### `HSMKeyStorage` (optional — PyKCS11)

Available when `PyKCS11 >= 1.5.18` is installed and `HSM_AVAILABLE` is
`True`. Raises `AmaHSMUnavailableError` (in `ama_cryptography.exceptions`)
when called without the dependency.

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

The combiner is KEM-agnostic: the caller supplies an `encapsulate` /
`decapsulate` callable for each half, letting the same class drive
X25519 ∥ ML-KEM-1024, ECDH ∥ Kyber, or any future pairing. Output is
derived with HKDF-SHA3-256 over a length-prefixed concatenation of both
shared secrets, both ciphertexts, and (optionally) both public keys —
length prefixing prevents the component-stripping attack fixed in
v2.1.5 (audit finding C6).

```python
from ama_cryptography.hybrid_combiner import HybridCombiner, HybridEncapsulation

combiner = HybridCombiner()

# Sender: encapsulate using recipient's public keys
enc: HybridEncapsulation = combiner.encapsulate_hybrid(
    classical_encapsulate: Callable,     # e.g. X25519 encapsulate
    pqc_encapsulate: Callable,           # e.g. ML-KEM-1024 encapsulate
    classical_pk: bytes,
    pqc_pk: bytes,
)

# Receiver: decapsulate using secret keys
combined: bytes = combiner.decapsulate_hybrid(
    classical_decapsulate: Callable,
    pqc_decapsulate: Callable,
    classical_ct: bytes,
    pqc_ct: bytes,
    classical_sk: bytes,
    pqc_sk: bytes,
    classical_pk: bytes = b"",
    pqc_pk: bytes = b"",
)

# Low-level combine(): use when you already hold both shared secrets
shared: bytes = combiner.combine(
    classical_ss: bytes,
    pqc_ss: bytes,
    classical_ct: bytes,
    pqc_ct: bytes,
    classical_pk: bytes = b"",
    pqc_pk: bytes = b"",
    output_len: int = 32,
)
```

#### `HybridEncapsulation`

```python
@dataclass
class HybridEncapsulation:
    combined_secret: bytes         # HKDF-SHA3-256 output (default 32 bytes)
    classical_ciphertext: bytes    # X25519 ephemeral public key (32 bytes)
    pqc_ciphertext: bytes          # ML-KEM-1024 ciphertext (1568 bytes)
    classical_shared_secret: bytes # X25519 shared secret (32 bytes)
    pqc_shared_secret: bytes       # ML-KEM-1024 shared secret (32 bytes)
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
    key_manager: KeyRotationManager,
) -> None
```

---

## `rfc3161_timestamp`

```python
from ama_cryptography.rfc3161_timestamp import (
    get_timestamp,
    verify_timestamp,
    TimestampResult,
    TimestampError,
    TimestampUnavailableError,
    RFC3161_AVAILABLE,
)

# Request a trusted timestamp.
# tsa_mode ∈ {"online", "mock", "disabled"}.
result: TimestampResult = get_timestamp(
    data: bytes,
    tsa_url: str | None = None,                 # defaults to FreeTSA in "online"
    hash_algorithm: str = "sha3-256",
    certificate_file: str | None = None,
    tsa_mode: str = "online",
)

# Verify a previously obtained timestamp token against the original data.
valid: bool = verify_timestamp(
    data: bytes,
    timestamp_result: TimestampResult,
    certificate_file: str | None = None,
)

# TimestampResult fields (frozen dataclass):
#   token:          bytes   — DER-encoded RFC 3161 token
#   tsa_url:        str     — TSA that produced the token
#   hash_algorithm: str     — hash used to imprint the message
#   data_hash:      bytes   — imprint actually sent to the TSA
```

Online mode requires the optional `rfc3161ng` package; mock and disabled
modes are always available for testing. `TimestampUnavailableError` is
raised if online mode is requested without the dependency.

---

## `exceptions`

```python
from ama_cryptography.exceptions import (
    CryptoModuleError,                # FIPS 140-3 error-state module lock (RuntimeError)
    CryptoConfigError,                # Configuration / environment problems (Exception)
    IntegrityError,                   # Integrity-check failure (Exception)
    SignatureVerificationError,       # Signature rejected (Exception)
    KeyManagementError,               # Key lifecycle errors (Exception)
    PQCUnavailableError,              # Native C PQC library not loaded (RuntimeError)
    QuantumSignatureUnavailableError, # PQC signer requested but unavailable (subclass of PQCUnavailableError)
    QuantumSignatureRequiredError,    # Policy requires PQC; classical-only refused (Exception)
    AmaHSMUnavailableError,           # HSM path requested without PyKCS11 (RuntimeError)
    SecurityWarning,                  # Non-fatal security warnings (UserWarning)
)
```

### Exception hierarchy

AMA's exceptions are **not** rooted under a single base class — most
derive directly from `Exception` or `RuntimeError`. Use the actual base
when writing `except` clauses; `except Exception` will catch all of them
but will over-catch.

```
RuntimeError (builtin)
├── CryptoModuleError             # FIPS 140-3 error-state module lock
├── PQCUnavailableError
│   └── QuantumSignatureUnavailableError
└── AmaHSMUnavailableError        # PyKCS11 missing

Exception (builtin)
├── CryptoConfigError
├── KeyManagementError
├── SignatureVerificationError
├── IntegrityError
└── QuantumSignatureRequiredError # note: NOT a PQCUnavailableError subclass

UserWarning (builtin)
└── SecurityWarning               # warnings.warn() for non-fatal security issues
```

> **There is no `RFC3161Error` class.** The RFC 3161 timestamp module
> raises `TimestampError` (request failure) and `TimestampUnavailableError`
> (optional `rfc3161ng` dependency missing), both defined in
> `ama_cryptography/rfc3161_timestamp.py:53–62`.

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
