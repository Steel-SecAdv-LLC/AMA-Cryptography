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
| [`rfc3161_timestamp`](#rfc3161_timestamp) | RFC 3161 timestamps — wire format + §2.4.2 message-imprint binding (not TSA attestation) |
| [`agent_binding`](#agent_binding) | Agent-instance key/signature binding (INVARIANT-30) |
| [`monitoring`](#monitoring) | 3R runtime monitoring + agentic-abuse detectors |
| [`exceptions`](#exceptions) | Exception hierarchy |

---

## `crypto_api`

The algorithm-agnostic entry point is `AmaCryptography`, selected by an
`AlgorithmType`. Every concrete backend (Ed25519, ML-DSA-65, ML-KEM-1024,
SLH-DSA-SHA2-256f, AES-256-GCM, hybrid signature, hybrid KEM) is a `CryptoProvider`
subclass that can also be used directly.

### Enums

#### `AlgorithmType`

Defined in `ama_cryptography/crypto_api.py:203–212`.

<!-- example: python-names module=ama_cryptography.crypto_api -->
```python
from enum import Enum, auto

class AlgorithmType(Enum):
    ML_DSA_65    = auto()  # NIST FIPS 204 signature (post-quantum)
    KYBER_1024   = auto()  # NIST FIPS 203 KEM (post-quantum)
    SPHINCS_256F = auto()  # NIST FIPS 205 signature (hash-based)
    ED25519      = auto()  # RFC 8032 signature (classical)
    AES_256_GCM  = auto()  # NIST SP 800-38D AEAD
    HYBRID_SIG   = auto()  # Ed25519 || ML-DSA-65  (recommended default)
    HYBRID_KEM   = auto()  # X25519 || ML-KEM-1024
```

> The underlying integer assigned to each member by `auto()` is an
> implementation detail — it depends on declaration order and is not
> part of the public API. Compare by member (e.g.,
> `alg == AlgorithmType.HYBRID_SIG`) or by name (`alg.name`), never by
> `.value`. The numeric values may change across releases without
> notice.

#### `CryptoBackend`

Defined in `ama_cryptography/crypto_api.py:215–220`.

<!-- example: python-names module=ama_cryptography.crypto_api -->
```python
class CryptoBackend(Enum):
    """Available implementation backends."""
    C_LIBRARY   = auto()  # libama_cryptography.so (fastest, native PQC) — default
    CYTHON      = auto()  # Cython-optimized (fast); provider-level overlay
    PURE_PYTHON = auto()  # RESERVED — not a usable runtime mode
```

> **INVARIANT-7 (revised):** The library refuses to operate without the
> native C constant-time backend. `ama_cryptography.crypto_api` raises
> `RuntimeError` at import time (see `crypto_api.py:105–114`) if the
> native HMAC/HKDF accelerators are missing. `CryptoBackend.PURE_PYTHON`
> is therefore a reserved enum slot only — passing it does **not** select
> a pure-Python fallback; the library has none. `CryptoBackend.CYTHON`
> remains a provider-level overlay on top of the C library.
>
> There is **no** `CryptoBackend.PYTHON` member.

### Dataclasses

Defined in `ama_cryptography/crypto_api.py:223–274`. Not `frozen=True`;
sensitive fields use `field(repr=False)` so `repr()` never surfaces key
material.

<!-- example: python-names module=ama_cryptography.crypto_api -->
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

<!-- example: python-signature module=ama_cryptography.crypto_api bind=crypto:AmaCryptography -->
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
- `generate_keypair()` / `sign()` / `verify()` are valid only when the
  selected algorithm is a signature scheme; `encapsulate()` /
  `decapsulate()` only for KEM schemes. Calling the wrong family raises
  **`TypeError`** (`"Current algorithm does not support signing"` /
  `"...verification"` / `"...KEM"` — see
  `ama_cryptography/crypto_api.py:1607-1645`). `AESGCMProvider` also
  raises `TypeError` from `generate_keypair()` because AEAD does not
  produce asymmetric keypairs.
- **INVARIANT-7 (no silent cryptographic fallback):** if the native C
  library is unavailable, the failure is raised **at module import
  time** (`crypto_api.py:105-114` hard-fails the
  `import ama_cryptography.crypto_api` with a `RuntimeError`) — not
  later in `AmaCryptography.__init__`. A `_enforce_invariant7()` call
  in each primitive (`crypto_api.py:149-168`) also re-checks at call
  time, so a runtime patch that unsets the native lib fails fast.

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

<!-- example: python-signature module=ama_cryptography.crypto_api -->
```python
cache = KeypairCache(algorithm: AlgorithmType = AlgorithmType.HYBRID_SIG)
```

Fixed-size cache for hot-path keypair reuse. Constant-time-zeroed on eviction.

#### `AESGCMProvider` (AEAD)

<!-- example: python-signature module=ama_cryptography.crypto_api bind=aead:AESGCMProvider -->
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

### MAC and KDF helpers

Two module-level convenience dispatchers wrap the native C MAC/KDF kernels
with a one-call surface. Both are native-only (INVARIANT-1 — no stdlib
`hmac`/`hashlib`): an unsupported `algorithm` raises **`ValueError`**, and a
missing native backend raises **`RuntimeError`**.

Signatures (`algorithm ∈ {"sha256", "sha384", "sha512", "sha3-256"}`; HMAC
digest length is 32 / 48 / 64 / 32 bytes respectively):

<!-- example: python-signature module=ama_cryptography.crypto_api -->
```python
def quick_hmac(key: bytes, message: bytes, algorithm: str = "sha256") -> bytes: ...

def quick_hkdf(
    ikm: bytes,
    length: int,
    salt: bytes | None = None,
    info: bytes = b"",
    algorithm: str = "sha256",
) -> bytes: ...
```

Usage:

<!-- example: python-run -->
```python
from ama_cryptography.crypto_api import quick_hmac, quick_hkdf

# HMAC (RFC 2104 / FIPS 198-1).
tag = quick_hmac(b"key", b"message", "sha256")

# HKDF (RFC 5869): sha256/384/512 = interoperable HKDF-SHA-2 (TLS 1.3 / HPKE);
# sha3-256 = AMA's default HMAC-SHA3-256 HKDF.
okm = quick_hkdf(b"input-key-material", 32, salt=b"salt", info=b"context")
```

These dispatch to the native `native_hmac_*` / `native_hkdf_*` interfaces in
[`pqc_backends`](#pqc_backends); use those directly when you want to pin one
algorithm without the string dispatch.

---

## `pqc_backends`

### Constants

<!-- example: python-names module=ama_cryptography.pqc_backends -->
```python
DILITHIUM_AVAILABLE: bool  # True if ML-DSA-65 is available
KYBER_AVAILABLE: bool      # True if ML-KEM-1024 is available
SPHINCS_AVAILABLE: bool    # True if SPHINCS+ is available
```

### Functions

#### Status and Discovery

<!-- example: python-signature module=ama_cryptography.pqc_backends -->
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

<!-- example: python-signature module=ama_cryptography.pqc_backends -->
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

<!-- example: python-signature module=ama_cryptography.pqc_backends -->
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

<!-- example: python-signature module=ama_cryptography.pqc_backends -->
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

#### Native hashes, HMAC, and HKDF

Direct one-call bindings to the native C kernels. All are INVARIANT-1
compliant (no stdlib `hashlib` / `hmac`) and raise **`RuntimeError`** when the
native backend is unavailable. The [`quick_hmac` / `quick_hkdf`](#crypto_api)
dispatchers in `crypto_api` are thin string-selectable wrappers over these.

<!-- example: python-run -->
```python
from ama_cryptography.pqc_backends import (
    native_sha256, native_sha3_256, native_sha3_512, native_shake128, native_shake256,
    native_hmac_sha256, native_hmac_sha384, native_hmac_sha512, native_hmac_sha3_256,
    native_hkdf, native_hkdf_sha256, native_hkdf_sha384, native_hkdf_sha512,
)

# Raw hashes (FIPS 180-4 / FIPS 202) — byte-identical to the hashlib equivalents.
d = native_sha256(b"data")           # 32-byte SHA-256
d = native_sha3_256(b"data")         # 32-byte SHA3-256
d = native_sha3_512(b"data")         # 64-byte SHA3-512
x = native_shake128(b"data", 32)     # SHAKE-128 XOF; second arg is output length in bytes
x = native_shake256(b"data", 64)     # SHAKE-256 XOF

# HMAC (RFC 2104 / FIPS 198-1) -> 32 / 48 / 64 / 32-byte tags.
t = native_hmac_sha256(b"key", b"msg")
t = native_hmac_sha384(b"key", b"msg")
t = native_hmac_sha512(b"key", b"msg")
t = native_hmac_sha3_256(b"key", b"msg")

# HKDF (RFC 5869): native_hkdf is the HMAC-SHA3-256 default; the _sha* variants
# are the interoperable HKDF-SHA-2 profiles. Signature (salt=None means a
# zero-length salt per RFC 5869; the _sha* variants share this signature):
#   native_hkdf(ikm: bytes, length: int, salt: bytes | None = None, info: bytes = b"") -> bytes
okm = native_hkdf(b"ikm", 32, salt=b"salt", info=b"context")
okm = native_hkdf_sha256(b"ikm", 32, salt=b"salt", info=b"context")
```

---

## `key_management`

### Enums

#### `KeyStatus`

<!-- example: python-names module=ama_cryptography.key_management -->
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

<!-- example: python-names module=ama_cryptography.key_management -->
```python
@dataclass
class KeyMetadata:
    # Eleven fields, none with a default: construct via
    # KeyRotationManager.register_key() rather than by hand.
    key_id: str
    created_at: datetime           # timezone-aware (UTC)
    expires_at: Optional[datetime] # timezone-aware (UTC), or None
    status: KeyStatus
    version: int
    parent_id: Optional[str]
    derivation_path: Optional[str]
    usage_count: int
    max_usage: Optional[int]
    purpose: str
    metadata: Dict[str, Any]
```

### Classes

#### `HDKeyDerivation`

BIP32-style hierarchical deterministic key derivation. AMA uses the
**BIP32-standard HMAC-SHA-512** PRF (delegated to the native C
accelerator via `ama_cryptography.pqc_backends.native_hmac_sha512` to
satisfy INVARIANT-1 — no stdlib `hmac`). Both hardened and non-hardened
derivation are supported:

- `derive_key(purpose, account, change, index)` is a convenience wrapper
  that always emits a **fully hardened** BIP-44 path.
- `derive_path(path)` accepts an explicit BIP32-style path and supports
  **both hardened (`44'` or index ≥ 2^31) and non-hardened** components.
  Non-hardened derivation uses the native secp256k1 public-key
  computation.

<!-- example: python-signature module=ama_cryptography.key_management bind=hd:HDKeyDerivation -->
```python
from ama_cryptography.key_management import HDKeyDerivation

hd = HDKeyDerivation(
    seed: bytes | None = None,           # 32–64 byte seed
    seed_phrase: str | None = None,      # BIP-39-style phrase (PBKDF2)
)

# Convenience: always fully-hardened BIP-44 path
key_material: bytes = hd.derive_key(
    purpose: int,           # e.g., 44
    account: int = 0,
    change: int = 0,
    index: int = 0,
)

# Explicit BIP32 path — accepts both hardened (44') and non-hardened (44)
key, chain_code = hd.derive_path(path: str)   # e.g. "m/44'/0'/0'/0'" or "m/44/0/0"
```

#### `KeyRotationManager`

<!-- example: python-signature module=ama_cryptography.key_management bind=mgr:KeyRotationManager -->
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

<!-- example: python-signature module=ama_cryptography.key_management bind=storage:SecureKeyStorage -->
```python
from pathlib import Path
from ama_cryptography.key_management import SecureKeyStorage

storage = SecureKeyStorage(
    storage_path: Path,
    master_password: Optional[str] = None,
    allow_legacy_kdf: bool = False,   # opt-in to reading pre-v5 KDF records
)

# Store / retrieve / delete
storage.store_key(
    key_id: str,
    key_data: bytes,
    metadata: Optional[Dict[str, Any]] = None,
) -> None

key_bytes: Optional[bytes] = storage.retrieve_key(key_id: str) -> Optional[bytes]
deleted:   bool            = storage.delete_key(key_id: str) -> bool
all_ids:   List[str]       = storage.list_keys() -> List[str]
```

#### `HSMKeyStorage` (optional — PyKCS11)

Available when `PyKCS11 >= 1.5.18` is installed and `HSM_AVAILABLE` is
`True`. Raises `AmaHSMUnavailableError` (in `ama_cryptography.exceptions`)
when called without the dependency.

---

## `secure_memory`

<!-- example: python-signature module=ama_cryptography.secure_memory -->
```python
# Construction.  `SecureBuffer.__enter__` yields the BYTEARRAY, not the
# wrapper — inside the `with`, the bound name IS the buffer (see the runnable
# example below).
SecureBuffer(size: int, lock: bool = True) -> None

# Functional form of the same thing; yields the bytearray directly.
secure_buffer(size: int, lock: bool = True) -> Generator[bytearray, None, None]

# Zero a buffer.  The native kernel writes zeros ONCE through volatile stores
# and then issues a compiler barrier; the barrier, not a repeat count, is what
# defeats dead-store elimination (src/c/ama_consttime.c).
secure_memzero(data: Union[bytearray, memoryview]) -> None

# Lock memory into RAM (prevent swap).
# Returns None and RAISES on failure — it does NOT return a boolean, so
# `if secure_mlock(buf):` takes the failure branch on every successful lock.
secure_mlock(data: Union[bytes, bytearray, memoryview]) -> None

# Unlock memory (allow swap).  Same contract: None, raises on failure.
secure_munlock(data: Union[bytes, bytearray, memoryview]) -> None

# Constant-time byte comparison (timing-safe)
constant_time_compare(a: Union[bytes, bytearray, memoryview], b: Union[bytes, bytearray, memoryview]) -> bool

# Backend introspection
is_available() -> bool
get_status() -> Dict[str, Union[bool, str]]
```

Runnable form — note that `buf` is the `bytearray`:

<!-- example: python-run -->
```python
import os

from ama_cryptography.secure_memory import (
    SecureBuffer,
    constant_time_compare,
    secure_memzero,
    secure_mlock,
    secure_munlock,
)

with SecureBuffer(32) as buf:
    assert isinstance(buf, bytearray) and len(buf) == 32
    buf[:] = os.urandom(32)

material = bytearray(os.urandom(32))
secure_mlock(material)          # returns None; raises SecureMemoryError on failure
try:
    assert constant_time_compare(bytes(material), bytes(material))
finally:
    secure_memzero(material)
    secure_munlock(material)
assert bytes(material) == bytes(32)
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

<!-- example: python-signature module=ama_cryptography.hybrid_combiner bind=combiner:HybridCombiner -->
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

<!-- example: python-names module=ama_cryptography.hybrid_combiner -->
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

<!-- example: python-run -->
```python
from ama_cryptography.adaptive_posture import (
    PostureEvaluator,
    CryptoPostureController,
    PostureEvaluation,
    PostureAction,
    ThreatLevel,
)
from ama_cryptography_monitor import AmaCryptographyMonitor

evaluator = PostureEvaluator()

# Evaluate a 3R-monitor report dict. `PostureEvaluator.evaluate()` takes
# a single positional `monitor_report: Dict[str, Any]` argument — NOT a
# keyword argument called `monitor_signals`.
monitor_report = AmaCryptographyMonitor(enabled=True).get_security_report()
evaluation: PostureEvaluation = evaluator.evaluate(monitor_report)

# The composite score is FOUR signals, weighted 0.45 / 0.25 / 0.15 / 0.15
# (adaptive_posture.py:265-268) — timing, pattern, resonance, Lyapunov:
print(sorted(k for k in evaluation.signals if k.endswith("_score")))
# ['lyapunov_score', 'pattern_score', 'raw_score', 'resonance_score', 'timing_score']

# PostureEvaluation fields (dataclass, see adaptive_posture.py:68):
#   evaluation.threat_level : ThreatLevel
#   evaluation.action       : PostureAction   # the recommended action
#   evaluation.confidence   : float (0.0 – 1.0)
#   evaluation.signals      : Dict[str, Any]  # contributing anomaly signals
#   evaluation.timestamp    : float
assert isinstance(evaluation.threat_level, ThreatLevel)
assert isinstance(evaluation.action, PostureAction)

# The controller's public entry point is `evaluate_and_respond()`, which
# internally calls the monitor, runs the evaluator, and dispatches the
# recommended action through its private `_execute_action(action)`
# machinery. There is NO public `execute_action(evaluation, ...)` method.
monitor    = AmaCryptographyMonitor(enabled=True)
controller = CryptoPostureController(monitor=monitor)

evaluation = controller.evaluate_and_respond()
if evaluation.action != PostureAction.NONE:
    # Application-level response (logging, paging, circuit-breaking, etc.).
    # The controller has already applied the cryptographic action by the
    # time evaluate_and_respond() returns.
    print("posture action applied:", evaluation.action)
```

---

## `rfc3161_timestamp`

> **What a passing check establishes.** AMA verifies the RFC 3161 §2.4.2
> *message-imprint binding* — that a token refers to this data — plus the
> `PKIStatusInfo` verdict and the TSA's nonce echo. It verifies **no** TSA
> signature and **no** certificate chain, so a token that binds your data is
> not evidence that a trusted authority issued it, and `TSTInfo.genTime` is
> unauthenticated. `RFC3161_CAPABILITIES` is the machine-readable statement of
> this boundary; [INVARIANT-37](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/INVARIANTS.md)
> enforces it against every document in the repository.

<!-- example: python-signature module=ama_cryptography.rfc3161_timestamp -->
```python
from ama_cryptography.rfc3161_timestamp import (
    allow_mock_tsa,
    describe_token_verification,
    get_timestamp,
    verify_timestamp_binding,
    RFC3161_CAPABILITIES,
    TokenVerification,
    TimestampResult,
    TimestampError,
    TimestampUnavailableError,
    RFC3161_AVAILABLE,
)

# Request a timestamp token.
# tsa_mode ∈ {"online", "mock", "disabled"}.
result: TimestampResult = get_timestamp(
    data: bytes,
    tsa_url: str | None = None,                 # defaults to FreeTSA in "online"
    hash_algorithm: str = "sha3-256",
    certificate_file: str | None = None,        # REFUSED — raises TimestampError
    tsa_mode: str = "online",
)

# Check that a previously obtained token binds the original data.
binds: bool = verify_timestamp_binding(
    data: bytes,
    timestamp_result: TimestampResult,
    allow_disabled: bool = False,   # True accepts a "disabled" tsa_mode result
)

# The same verdict as a record, for an audit trail or compliance profile.
# TokenVerification raises TypeError on bool(), so it cannot collapse into
# an "if" that silently reports an unverified token as verified.
record: TokenVerification = describe_token_verification(data: bytes, token: bytes)
record.binding_verified      # bool
record.signature_verified    # always False — not implemented
record.chain_verified        # always False — not implemented
record.not_verified          # frozenset: {"tsa_signature",
                             #             "tsa_certificate_chain", "gen_time"}

# Deprecated: same check, but the name claims attestation AMA does not perform.
# Emits DeprecationWarning; certificate_file raises.
valid: bool = verify_timestamp(
    data: bytes,
    timestamp_result: TimestampResult,
    certificate_file: str | None = None,   # REFUSED — raises TimestampError
    allow_disabled: bool = False,
)

# TimestampResult fields (frozen dataclass):
#   token:          bytes   — DER-encoded RFC 3161 token
#   tsa_url:        str     — TSA that produced the token
#   hash_algorithm: str     — hash used to imprint the message
#   data_hash:      bytes   — imprint actually sent to the TSA
```

RFC 3161 is implemented in-tree on AMA's own DER codec and requires no
third-party package: the `rfc3161ng` dependency was removed under INVARIANT-1
and `RFC3161_AVAILABLE` is unconditionally `True`. Mock tokens carry their own
HMAC key, so both creating and honouring one is gated to a testing context —
open it with `allow_mock_tsa()`.

`certificate_file` (here and on `verify_timestamp`) and
`legacy_compat.verify_rfc3161_timestamp`'s `tsa_cert_path` all **raise**. They
request X.509 chain validation of the TSA's signing certificate, which AMA does
not implement; refusing is the only honest answer, and returning the binding
check's verdict instead would answer a weaker question while appearing to
answer that one.

---

## `agent_binding`

Agent-instance key and signature binding (INVARIANT-30). A binding cryptographically
forbids long-lived persistence material and successor-authorizing signatures unless a
human-held operator key authorizes them. Domain separation and policy over the existing
SHA3-256 / HMAC-SHA3-256 / HKDF primitives — no new algorithm.

<!-- example: python-run -->
```python
import os
from ama_cryptography.agent_binding import (
    AgentBinding, AgentLifetime, AgentCapability, EthicalBindingError,
)
from ama_cryptography.pqc_backends import native_sha3_256

ikm = os.urandom(32)
iid = os.urandom(32)
authority_key = os.urandom(32)
profile_document = b"AMA ethical profile v1"

# Ordinary ephemeral use needs no operator key and no ethical profile.
b = AgentBinding(instance_id=os.urandom(32),
                 capabilities=AgentCapability.DATA_SIGN)
session_key = b.derive_key(ikm, 32, info=b"session")     # HKDF, binding folded into info
ctx = b.signing_context()                                # 32-byte ML-DSA / SLH-DSA ctx
assert len(session_key) == 32 and len(ctx) == 32

# Persistence / self-replication require the operator.
p = AgentBinding(instance_id=iid,
                 lifetime=AgentLifetime.PERSISTENT,
                 capabilities=AgentCapability.PERSISTENCE,
                 ethical_profile_hash=native_sha3_256(profile_document))

# Without authorize(), derive_key() raises EthicalBindingError and writes nothing.
try:
    p.derive_key(ikm, 32)
except EthicalBindingError as exc:
    print("unauthorized persistence refused:", exc)

p.authorize(authority_key)                               # operator-side; needs K_auth
root = p.derive_key(ikm, 32, authority_key=authority_key)
assert len(root) == 32
```

Refusal is fail-closed: no output bytes, a distinct error (`EthicalBindingError` /
`AMA_ERROR_ETHICAL_BINDING`), and no partial state. The policy check is constant-time
(verified by a strict dudect lane) and the native surface is fuzzed for its security
properties, not merely for memory safety.

---

## `monitoring`

The 3R runtime monitor (`AmaCryptographyMonitor`, `create_monitor()`) plus two optional
agentic-abuse detectors, on by default and advisory-only.

<!-- example: python-run -->
```python
from ama_cryptography.monitoring import (
    create_monitor, VolumeSpikeDetector, NoteArtifactDetector,
)

fp = b"\x01" * 8
payload = b"a signed payload"

m = create_monitor()                                     # both detectors active
m.record_operation_event("kyber_encaps", key_fingerprint=fp)   # feeds the volume detector
signal = m.inspect_signed_payload(payload, label="note")       # scores for note-like structure
print("note-artifact signal:", signal)
# Opt out entirely:
m = create_monitor(detect_volume_spikes=False, detect_note_artifacts=False)
```

- **`VolumeSpikeDetector`** — anomalous KEM/signature bursts, scored in the Anscombe
  variance-stabilising transform (a quiet baseline cannot manufacture false spikes).
  Three gates (warmup, an absolute floor, a 6-sigma residual) must all pass; an optional
  key fingerprint separates ephemeral-key churn from a hot loop over one key.
- **`NoteArtifactDetector`** — signed payloads shaped like instructions addressed to a
  later instance. Calibrated against the repository's own text as a hard-negative corpus;
  advisory (it never blocks a signature).

Both are backed by Cython kernels with exact pure-Python twins, so the compiled extension
is an optimisation and never a correctness dependency.

---

## `exceptions`

<!-- example: python-names module=ama_cryptography.exceptions -->
```python
from ama_cryptography.exceptions import (
    AmaCryptographyError,             # catch-all root of the exception hierarchy (Exception)
    CryptoModuleError,                # FIPS 140-3 error-state module lock (also RuntimeError)
    CryptoConfigError,                # Configuration / environment problems
    IntegrityError,                   # Integrity-check failure
    SignatureVerificationError,       # Signature rejected
    KeyManagementError,               # Key lifecycle errors
    PQCUnavailableError,              # Native C PQC library not loaded (also RuntimeError)
    QuantumSignatureUnavailableError, # PQC signer requested but unavailable (subclass of PQCUnavailableError)
    QuantumSignatureRequiredError,    # Policy requires PQC; classical-only refused
    AmaHSMUnavailableError,           # HSM path requested without PyKCS11 (also RuntimeError)
    SecurityWarning,                  # Non-fatal security warnings (UserWarning)
)
```

### Exception hierarchy

Every error raised by the library derives — directly or transitively — from
the single root **`AmaCryptographyError`**, so `except AmaCryptographyError`
catches all of them (including the module-specific `TimestampError`,
`SessionError`, `ChannelError`, and `SecureMemoryError` defined in their own
modules). The classes that historically subclass `RuntimeError`
(`PQCUnavailableError`, `CryptoModuleError`, `AmaHSMUnavailableError`)
*additionally* inherit from `RuntimeError`, so existing `except RuntimeError`
sites keep working. `SecurityWarning` is intentionally **not** an
`AmaCryptographyError` — it is a `UserWarning`, not an error.

```
Exception (builtin)
└── AmaCryptographyError               # catch-all root — every library error derives from this
    ├── PQCUnavailableError            # also inherits RuntimeError
    │   └── QuantumSignatureUnavailableError
    ├── QuantumSignatureRequiredError  # note: NOT a PQCUnavailableError subclass
    ├── CryptoConfigError
    ├── KeyManagementError
    ├── SignatureVerificationError
    ├── IntegrityError
    ├── CryptoModuleError              # FIPS 140-3 error-state module lock; also inherits RuntimeError
    └── AmaHSMUnavailableError         # PyKCS11 missing; also inherits RuntimeError

UserWarning (builtin)
└── SecurityWarning                    # warnings.warn() for non-fatal security issues
```

> **There is no `RFC3161Error` class.** The RFC 3161 timestamp module
> raises `TimestampError` (request failure) and `TimestampUnavailableError`
> (optional `rfc3161ng` dependency missing), both defined in
> `ama_cryptography/rfc3161_timestamp.py:53–62`.

---

## Package-Level Imports

`import ama_cryptography` binds **five** public submodules as attributes of the
package. Every other submodule needs its own `import` statement — the
package's PEP 562 `__getattr__` resolves *symbol* names (`AmaCryptography`,
`create_crypto_package`, the `key_formats` helpers) and raises `AttributeError`
for a submodule name it does not eagerly import.

(On a tree where the Cython extensions are built, the compiled FFI bindings —
`sha3_binding`, `hmac_binding`, `hkdf_binding`, `ed25519_binding`,
`dilithium_binding`, `math_engine` — also appear as attributes, because
`pqc_backends` imports whichever of them exist. They are an optimisation, not
public API: everything they accelerate has a pure-ctypes path.)

The example below is written for a **fresh interpreter**, which is the only
state in which the question has a stable answer: Python binds a submodule as an
attribute of its parent package the moment anything in the process imports it,
so once *your* program has done `import ama_cryptography.key_management`
anywhere, `ama_cryptography.key_management` resolves from then on. Do not rely
on that — write the import you need.

<!-- example: python-run -->
```python
import ama_cryptography

# Bound by a bare `import ama_cryptography` — these five and no others:
ama_cryptography.pqc_backends
ama_cryptography.secure_memory
ama_cryptography.exceptions
ama_cryptography.equations
ama_cryptography.double_helix_engine

# NOT bound by a bare import. `ama_cryptography.crypto_api` raises
# AttributeError; `import ama_cryptography.crypto_api` is the way in.
for name in (
    "crypto_api",
    "key_management",
    "hybrid_combiner",
    "adaptive_posture",
    "rfc3161_timestamp",
    "key_formats",
    "legacy_compat",
):
    try:
        getattr(ama_cryptography, name)
    except AttributeError:
        pass
    else:  # pragma: no cover - would mean the package changed
        raise AssertionError(f"{name} is now eagerly bound; update this page")

import ama_cryptography.crypto_api          # this works
from ama_cryptography.key_management import KeyRotationManager   # so does this

# Symbols, as opposed to submodules, ARE reachable from the package:
ama_cryptography.AmaCryptography
ama_cryptography.create_crypto_package
ama_cryptography.ETHICAL_VECTOR
```

`equations` and `double_helix_engine` are imported eagerly by
`ama_cryptography/__init__.py`, not lazily: they are bound whether or not
NumPy is present.

---

*See [C API Reference](C-API-Reference) for the native C library, or [Quick Start](Quick-Start) for hands-on examples.*
