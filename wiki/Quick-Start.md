# Quick Start

Get up and running with AMA Cryptography in 5 minutes.

> **Prerequisites:** Complete [Installation](Installation) before proceeding.

---

## 1. Import the Package

```python
from ama_cryptography.pqc_backends import (
    generate_dilithium_keypair,
    dilithium_sign,
    dilithium_verify,
    get_pqc_status,
)
from ama_cryptography.crypto_api import (
    CryptoMode,
    PackageSigner,
)
from ama_cryptography.key_management import KeyManager
```

---

## 2. Verify PQC Availability

```python
status = get_pqc_status()
print(status)
# {'ml_dsa_65': 'available', 'ml_kem_1024': 'available', 'sphincs_sha2_256f': 'available'}
```

---

## 3. Create and Verify a Crypto Package

The main high-level API uses `code_guardian_secure.py` which orchestrates all 6 layers:

```python
# Run the complete demo
import subprocess
subprocess.run(["python3", "code_guardian_secure.py"])
```

Or use the Python API directly:

```python
from code_guardian_secure import (
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

# Step 3: Create the 6-layer crypto package
package = create_crypto_package(codes, helix_params, kms)
print(f"Package created: {package['package_id']}")

# Step 4: Verify the package
results = verify_crypto_package(codes, helix_params, package, kms.hmac_key)

# Step 5: Check all verification results
if all([
    results["content_hash"],
    results["hmac"],
    results["ed25519"],
    results["dilithium"] is True,
]):
    print("✓ ALL VERIFICATIONS PASSED")
else:
    print("✗ Verification failed:", results)

# Step 6: Export public keys for distribution
export_public_keys(kms, Path("public_keys"))
```

---

## 4. Post-Quantum Signing (Direct API)

For direct use of the PQC signing API:

```python
from ama_cryptography.pqc_backends import (
    generate_dilithium_keypair,
    dilithium_sign,
    dilithium_verify,
)

# Generate ML-DSA-65 key pair
public_key, secret_key = generate_dilithium_keypair()
print(f"Public key: {len(public_key)} bytes")   # 1952
print(f"Secret key: {len(secret_key)} bytes")   # 4032

# Sign a message
message = b"Hello, quantum-resistant world!"
signature = dilithium_sign(message, secret_key)
print(f"Signature: {len(signature)} bytes")      # 3309

# Verify the signature
valid = dilithium_verify(message, signature, public_key)
print(f"Valid: {valid}")  # True
```

---

## 5. AES-256-GCM Encryption

```python
from ama_cryptography.crypto_api import SymmetricCryptoAlgorithm
import os

algo = SymmetricCryptoAlgorithm()

# Generate a 256-bit key
key = os.urandom(32)

# Encrypt
plaintext = b"Sensitive data to protect"
ciphertext = algo.encrypt(plaintext, key)

# Decrypt
recovered = algo.decrypt(ciphertext, key)
assert recovered == plaintext
print("Encryption/decryption successful!")
```

---

## 6. Key Management

```python
from ama_cryptography.key_management import KeyManager
import os

# Initialize key manager with a master key
master_key = os.urandom(32)
manager = KeyManager(master_key)

# Generate and store a new key
key_id = manager.generate_master_key()
print(f"Key ID: {key_id}")

# Retrieve key metadata
meta = manager.get_key_metadata(key_id)
print(f"Status: {meta.status}")
print(f"Created: {meta.created_at}")

# Rotate the key
new_key_id = manager.rotate_key(key_id)
print(f"New key ID: {new_key_id}")
```

---

## 7. Hybrid KEM (Classical + PQC)

```python
from ama_cryptography.hybrid_combiner import HybridCombiner
from ama_cryptography.pqc_backends import generate_kyber_keypair
from ama_cryptography.crypto_api import AsymmetricCryptoAlgorithm

combiner = HybridCombiner()
classical_algo = AsymmetricCryptoAlgorithm()

# Generate key pairs
classical_pk, classical_sk = classical_algo.generate_keypair()
pqc_pk, pqc_sk = generate_kyber_keypair()

# Sender: encapsulate to derive shared secret
encapsulation = combiner.encapsulate(classical_pk, pqc_pk)
print(f"Combined secret: {encapsulation.combined_secret.hex()[:16]}...")

# Receiver: decapsulate using secret keys
recovered_secret = combiner.decapsulate(
    encapsulation,
    classical_sk,
    pqc_sk,
)
assert recovered_secret == encapsulation.combined_secret
print("Hybrid KEM key agreement successful!")
```

---

## 8. Secure Memory

```python
from ama_cryptography.secure_memory import SecureBuffer, secure_memzero
import os

# Use context manager for automatic zeroing on exit
with SecureBuffer(32) as buf:
    # buf.data is a bytearray of 32 zeroed bytes
    buf.data[:] = os.urandom(32)
    print(f"Using key: {buf.data.hex()[:8]}...")
# buf.data is automatically zeroed here

# Manual zeroing
sensitive = bytearray(os.urandom(32))
# ... use sensitive ...
secure_memzero(sensitive)  # Multi-pass overwrite
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
| `strict` | All layers + RFC 3161 | High-assurance, regulatory |

```python
# Strict profile: require all layers
results = verify_crypto_package(codes, helix_params, pkg, hmac_key)
if not (results["content_hash"] and results["hmac"]
        and results["ed25519"] and results["dilithium"] is True
        and results["rfc3161"] is True):
    raise ValueError("Package failed strict verification profile")
```

---

## Next Steps

- [Architecture](Architecture) — Understand the 6-layer defense design
- [API Reference](API-Reference) — Complete Python API documentation
- [Key Management](Key-Management) — HD key derivation and lifecycle management
- [Post-Quantum Cryptography](Post-Quantum-Cryptography) — Deep dive into PQC algorithms
- [Security Model](Security-Model) — Threat model and security properties
