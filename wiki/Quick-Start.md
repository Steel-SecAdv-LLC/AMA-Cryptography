# Quick Start

Get up and running with AMA Cryptography in 5 minutes.

> **Prerequisites:** Complete [Installation](Installation) before proceeding.

---

## 1. Import the Package

<!-- example: python-run -->
```python
from ama_cryptography.pqc_backends import (
    generate_dilithium_keypair,
    dilithium_sign,
    dilithium_verify,
    get_pqc_status,
    get_pqc_backend_info,
)
from ama_cryptography.crypto_api import (
    AmaCryptography,
    AlgorithmType,
)
from ama_cryptography.key_management import KeyRotationManager
```

---

## 2. Verify PQC Availability

<!-- example: python-run -->
```python
from ama_cryptography.pqc_backends import get_pqc_status, get_pqc_backend_info

status = get_pqc_status()
print(status)
# PQCStatus.AVAILABLE  — at least one PQC backend loaded
#
# get_pqc_status() returns a PQCStatus ENUM, not a dict and not a string.
# Compare against the enum member, or read `.value` for the "AVAILABLE" /
# "UNAVAILABLE" string (ama_cryptography/pqc_backends.py::PQCStatus).
from ama_cryptography.pqc_backends import PQCStatus
assert status is PQCStatus.AVAILABLE
assert status.value == "AVAILABLE"

# Detailed backend info dict (see ama_cryptography/pqc_backends.py::get_pqc_backend_info).
# Top-level keys: status, <algo>_available, <algo>_backend, algorithms,
# SHA3-256, HMAC-SHA3-256 (+ legacy flat 'backend'/'algorithm' aliases).
info = get_pqc_backend_info()
print(info["status"])                 # "AVAILABLE" / "UNAVAILABLE"  (PQCStatus.value, uppercase — see pqc_backends.py:76-77)
print(info["dilithium_available"], info["dilithium_backend"])  # True, "native"
print(info["kyber_available"],     info["kyber_backend"])      # True, "native"
print(info["sphincs_available"],   info["sphincs_backend"])    # True, "native"

# Per-algorithm matrix lives under info["algorithms"].  The keys are the
# implementation's own spellings — "Kyber-1024" and "SPHINCS+-256f", not the
# FIPS names — see ama_cryptography/pqc_backends.py::get_pqc_backend_info.
for name, meta in info["algorithms"].items():
    print(name, meta["available"], meta["backend"], meta["security_level"])
# ML-DSA-65      True native 3
# Kyber-1024     True native 5
# SPHINCS+-256f  True native 5
```

---

## 3. Create and Verify a Crypto Package

The legacy multi-layer orchestrator lives in
`ama_cryptography.legacy_compat`; it drives the same codes + helix
pipeline used by historical AMA deployments. For new code prefer
`AmaCryptography` from section 4 below.

<!-- example: python-run -->
```python
from ama_cryptography.legacy_compat import (
    generate_key_management_system,
    create_crypto_package,
    verify_crypto_package,
    export_public_keys,
)
from pathlib import Path

# Step 1: Generate cryptographic keys
kms = generate_key_management_system("MyOrganization")

# Step 2: Define your Omni-Codes (data to protect)
codes = """
1. 👁20A07∞_XΔEΛX_ϵ19A89Ϙ
   Omni-Directional System
"""

helix_params = [(20.0, 0.7), (15.0, 1.0)]

# Step 3: Create the multi-layer crypto package.
# `author` is a REQUIRED fourth argument (legacy_compat.py::create_crypto_package);
# omitting it raises TypeError.
package = create_crypto_package(codes, helix_params, kms, author="MyOrganization")

# The result is a CryptoPackage DATACLASS, not a dict — there is no
# `package["..."]` and no `package_id` field.  Read its attributes:
print(f"Package by {package.author}, format v{package.signature_format_version}")

# Step 4: Verify the package
results = verify_crypto_package(codes, helix_params, package, kms.hmac_key)
# results keys: content_hash, hmac, ed25519, dilithium, timestamp,
#               rfc3161, rfc3161_binding, ethical_vector.
# The two rfc3161 entries are None when no RFC 3161 token was requested —
# None means "not checked", which is not the same as False.

# Step 5: Check all verification results
if all([
    results["content_hash"],
    results["hmac"],
    results["ed25519"],
    results["dilithium"] is True,
]):
    # ASCII only: a Windows console defaults to cp1252, which cannot encode
    # U+2713/U+2717, so a tick here would raise UnicodeEncodeError rather than
    # print (INVARIANT-43).
    print("ALL VERIFICATIONS PASSED")
else:
    print("Verification FAILED:", results)

# Step 6: Export public keys for distribution
export_public_keys(kms, Path("public_keys"))
```

---

## 4. Post-Quantum Signing (Direct API)

For direct use of the PQC signing API:

<!-- example: python-run -->
```python
from ama_cryptography.pqc_backends import (
    generate_dilithium_keypair,
    dilithium_sign,
    dilithium_verify,
)

# Generate ML-DSA-65 key pair (DilithiumKeyPair dataclass)
kp = generate_dilithium_keypair()
print(f"Public key: {len(kp.public_key)} bytes")   # 1952
print(f"Secret key: {len(kp.secret_key)} bytes")   # 4032

# Sign a message
message = b"Hello, quantum-resistant world!"
signature = dilithium_sign(message, kp.secret_key)
print(f"Signature: {len(signature)} bytes")        # 3309

# Verify the signature
valid = dilithium_verify(message, signature, kp.public_key)
print(f"Valid: {valid}")  # True
```

---

## 5. AES-256-GCM Encryption

<!-- example: python-run -->
```python
from ama_cryptography.crypto_api import AESGCMProvider
import os

aead = AESGCMProvider()

# Generate a 256-bit key
key = os.urandom(32)

# Encrypt — nonce is auto-generated when omitted.
# Returns a dict: {'ciphertext', 'nonce', 'tag', 'aad', 'backend'}
plaintext = b"Sensitive data to protect"
result    = aead.encrypt(plaintext, key, aad=b"header")

# Decrypt — caller passes nonce and tag back in; raises on tag mismatch
recovered = aead.decrypt(
    ciphertext=result["ciphertext"],
    key=key,
    nonce=result["nonce"],
    tag=result["tag"],
    aad=b"header",
)
assert recovered == plaintext
print("Encryption/decryption successful!")
```

---

## 6. Key Rotation

<!-- example: python-run -->
```python
from datetime import timedelta
from ama_cryptography.key_management import KeyRotationManager

# Create a rotation manager with a 90-day policy
mgr = KeyRotationManager(rotation_period=timedelta(days=90))

# Register a key under rotation policy (key material lives elsewhere;
# the manager tracks metadata, expiry, and usage counts)
meta = mgr.register_key(
    key_id="signing-key-v1",
    purpose="document-signatures",
    expires_in=timedelta(days=90),
    max_usage=100_000,
)
print(f"Status: {meta.status}, created: {meta.created_at}")

# Later: check whether it needs rotating. initiate_rotation() requires
# BOTH key ids to be registered first (KeyRotationManager.initiate_rotation raises
# ValueError otherwise), so register the replacement before rotating.
if mgr.should_rotate("signing-key-v1"):
    mgr.register_key(
        key_id="signing-key-v2",
        purpose="document-signatures",
        expires_in=timedelta(days=90),
        max_usage=100_000,
    )
    mgr.initiate_rotation("signing-key-v1", "signing-key-v2")
    # ... provision new key material ...
    mgr.complete_rotation("signing-key-v1")   # old key -> DEPRECATED
```

For HD seed derivation, use `HDKeyDerivation(seed=...)` from the
same module.

---

## 7. Hybrid KEM (Classical + PQC)

<!-- example: python-run -->
```python
from ama_cryptography.crypto_api import AmaCryptography, AlgorithmType

# One-liner hybrid KEM: drives X25519 + ML-KEM-1024 internally and
# length-prefix-binds both shared secrets through HKDF-SHA3-256.
hybrid = AmaCryptography(algorithm=AlgorithmType.HYBRID_KEM)

recipient = hybrid.generate_keypair()   # public = X25519_pk || ML-KEM_pk
enc = hybrid.encapsulate(recipient.public_key)
print(f"Combined secret: {enc.shared_secret.hex()[:16]}...")

# Receiver
recovered = hybrid.decapsulate(enc.ciphertext, recipient.secret_key)
assert recovered == enc.shared_secret
print("Hybrid KEM key agreement successful!")
```

See [Hybrid Cryptography](Hybrid-Cryptography) if you need to drive
the combiner with custom classical and PQC KEM callables.

---

## 8. Secure Memory

<!-- example: python-run -->
```python
from ama_cryptography.secure_memory import SecureBuffer, secure_memzero
import os

# Use the context manager for automatic zeroing on exit.
# __enter__ yields the BYTEARRAY itself, not the SecureBuffer wrapper —
# inside the `with`, `buf` IS the buffer and has no `.data` attribute.
with SecureBuffer(32) as buf:
    # buf is a bytearray of 32 zeroed bytes
    buf[:] = os.urandom(32)
    print(f"Using key: {buf.hex()[:8]}...")
# the buffer is zeroed here

# `.data` on the wrapper is valid only while the context is open — it
# raises RuntimeError otherwise, so keep a reference if you want both:
holder = SecureBuffer(32)
with holder as buf:
    assert holder.data is buf

# Manual zeroing.  The native kernel writes zeros ONCE through volatile
# stores and then issues a compiler barrier; the barrier, not a repeat
# count, is what defeats dead-store elimination (src/c/ama_consttime.c).
sensitive = bytearray(os.urandom(32))
# ... use sensitive ...
secure_memzero(sensitive)
print(f"After zeroing: {sensitive.hex()}")  # 000000...
```

---

## Security Profiles

Choose the verification profile appropriate for your deployment:

| Profile | Requirements | Use Case |
|---------|-------------|----------|
| `dev` | None | Local testing, prototyping |
| `classical` | Ed25519 only | Legacy environments |
| `hybrid` | Ed25519 + ML-DSA-65 | Typical production |
| `strict` | All layers + RFC 3161 binding | High-assurance, regulatory |

<!-- example: python-run -->
```python
from ama_cryptography.legacy_compat import (
    generate_key_management_system,
    create_crypto_package,
    verify_crypto_package,
)

kms = generate_key_management_system("MyOrganization")
codes = "1. test\n"
helix_params = [(20.0, 0.7)]
pkg = create_crypto_package(codes, helix_params, kms, author="MyOrganization")


def verify_strict(codes, helix_params, pkg, hmac_key):
    """Strict profile: every layer, including the RFC 3161 binding."""
    results = verify_crypto_package(codes, helix_params, pkg, hmac_key)
    if not (results["content_hash"] and results["hmac"]
            and results["ed25519"] and results["dilithium"] is True
            and results["rfc3161_binding"] is True):
        raise ValueError("Package failed strict verification profile")
    return results


# This package carries no RFC 3161 token, so `rfc3161_binding` is None —
# "not checked", which the strict profile must treat as a refusal, not a pass.
try:
    verify_strict(codes, helix_params, pkg, kms.hmac_key)
except ValueError as exc:
    print(f"strict profile correctly refused: {exc}")
```

`rfc3161_binding` establishes that the stored token refers to this package. It does **not** establish that a trusted authority issued it — AMA verifies no TSA signature and no certificate chain — so a `strict` profile must pair it with whatever control does establish the token's provenance. (The old key name `rfc3161` still returns the same value but emits a `DeprecationWarning` when read: the bare name read as attestation, which is the misreading it caused.)

---

## Next Steps

- [Architecture](Architecture) — Understand the multi-layer defense design
- [API Reference](API-Reference) — Complete Python API documentation
- [Key Management](Key-Management) — HD key derivation and lifecycle management
- [Post-Quantum Cryptography](Post-Quantum-Cryptography) — Deep dive into PQC algorithms
- [Security Model](Security-Model) — Threat model and security properties
