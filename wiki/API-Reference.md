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

### MAC and KDF helpers

Two module-level convenience dispatchers wrap the native C MAC/KDF kernels
with a one-call surface. Both are native-only (INVARIANT-1 — no stdlib
`hmac`/`hashlib`): an unsupported `algorithm` raises **`ValueError`**, and a
missing native backend raises **`RuntimeError`**.

Signatures (`algorithm ∈ {"sha256", "sha384", "sha512", "sha3-256"}`; HMAC
digest length is 32 / 48 / 64 / 32 bytes respectively):

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

#### Native hashes, HMAC, and HKDF

Direct one-call bindings to the native C kernels. All are INVARIANT-1
compliant (no stdlib `hashlib` / `hmac`) and raise **`RuntimeError`** when the
native backend is unavailable. The [`quick_hmac` / `quick_hkdf`](#crypto_api)
dispatchers in `crypto_api` are thin string-selectable wrappers over these.

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
from ama_cryptography.adaptive_posture import (
    PostureEvaluator,
    CryptoPostureController,
    PostureEvaluation,
    PostureAction,
    ThreatLevel,
)

evaluator = PostureEvaluator()

# Evaluate a 3R-monitor report dict. `PostureEvaluator.evaluate()` takes
# a single positional `monitor_report: Dict[str, Any]` argument — NOT a
# keyword argument called `monitor_signals`.
evaluation: PostureEvaluation = evaluator.evaluate(monitor_report)

# PostureEvaluation fields (dataclass, see adaptive_posture.py:68):
#   evaluation.threat_level : ThreatLevel
#   evaluation.action       : PostureAction   # the recommended action
#   evaluation.confidence   : float (0.0 – 1.0)
#   evaluation.signals      : Dict[str, Any]  # contributing anomaly signals
#   evaluation.timestamp    : float

# The controller's public entry point is `evaluate_and_respond()`, which
# internally calls the monitor, runs the evaluator, and dispatches the
# recommended action through its private `_execute_action(action)`
# machinery. There is NO public `execute_action(evaluation, ...)` method.
from ama_cryptography_monitor import AmaCryptographyMonitor
monitor    = AmaCryptographyMonitor(enabled=True)
controller = CryptoPostureController(monitor=monitor)

evaluation = controller.evaluate_and_respond()
if evaluation.action != PostureAction.NONE:
    # Application-level response (logging, paging, circuit-breaking, etc.).
    # The controller has already applied the cryptographic action by the
    # time evaluate_and_respond() returns.
    ...
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
valid: bool = verify_timestamp(data, timestamp_result, certificate_file=None)

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

```python
import os
from ama_cryptography.agent_binding import (
    AgentBinding, AgentLifetime, AgentCapability, EthicalBindingError,
)

# Ordinary ephemeral use needs no operator key and no ethical profile.
b = AgentBinding(instance_id=os.urandom(32),
                 capabilities=AgentCapability.DATA_SIGN)
session_key = b.derive_key(ikm, 32, info=b"session")     # HKDF, binding folded into info
ctx = b.signing_context()                                # 32-byte ML-DSA / SLH-DSA ctx

# Persistence / self-replication require the operator.
p = AgentBinding(instance_id=iid,
                 lifetime=AgentLifetime.PERSISTENT,
                 capabilities=AgentCapability.PERSISTENCE,
                 ethical_profile_hash=sha3_256(profile_document))
p.authorize(authority_key)                               # operator-side; needs K_auth
root = p.derive_key(ikm, 32, authority_key=authority_key)
# Without authorize(), derive_key() raises EthicalBindingError and writes nothing.
```

Refusal is fail-closed: no output bytes, a distinct error (`EthicalBindingError` /
`AMA_ERROR_ETHICAL_BINDING`), and no partial state. The policy check is constant-time
(verified by a strict dudect lane) and the native surface is fuzzed for its security
properties, not merely for memory safety.

---

## `monitoring`

The 3R runtime monitor (`AmaCryptographyMonitor`, `create_monitor()`) plus two optional
agentic-abuse detectors, on by default and advisory-only.

```python
from ama_cryptography.monitoring import (
    create_monitor, VolumeSpikeDetector, NoteArtifactDetector,
)

m = create_monitor()                                     # both detectors active
m.record_operation_event("kyber_encaps", key_fingerprint=fp)   # feeds the volume detector
signal = m.inspect_signed_payload(payload, label="note")       # scores for note-like structure
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
