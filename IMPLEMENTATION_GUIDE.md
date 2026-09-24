# AMA Cryptography: Implementation Guide
## Practical Guide to Deploying Cryptographic Protection

**Copyright (C) 2025-2026 Steel Security Advisors LLC**  
**Author/Inventor:** Andrew E. A.  
**Contact:** steel.sa.llc@gmail.com

**AI Co-Architects:**  
Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛

**Version:** 5.0.0
**Date:** 2026-07-25

---

## Security Profiles

Choose the appropriate verification profile for your use case:

| Profile | Dilithium Required | RFC 3161 Binding Required | Use Case |
|---------|-------------------|---------------------------|----------|
| **dev** | No | No | Local testing, prototyping |
| **classical** | No | Optional | Legacy environments, pre-quantum systems |
| **hybrid** | Yes | Optional | Typical production deployment |
| **strict** | Yes | Yes | High-assurance, regulatory compliance |

> The two "Required" columns are not comparable in strength. Dilithium's is signature verification. RFC 3161's is the §2.4.2 *message-imprint binding* — AMA verifies no TSA signature and no certificate chain, so an adversary who can supply a token satisfies it unaided ([INVARIANT-37](INVARIANTS.md#invariant-37--a-verification-api-must-not-claim-a-check-it-does-not-perform)). A `strict` profile therefore still requires the token's provenance to be established out of band.

**Example: Strict profile verification**
<!-- example: python-run -->
```python
from ama_cryptography.legacy_compat import (
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    create_crypto_package,
    generate_key_management_system,
    verify_crypto_package,
)

kms = generate_key_management_system("YourOrganization")
pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, author="YourOrganization")


def verify_strict(codes, helix_params, pkg, hmac_key):
    """Strict profile: require all checks, the RFC 3161 binding included."""
    results = verify_crypto_package(codes, helix_params, pkg, hmac_key)
    if not (results["content_hash"] and results["hmac"] and results["ed25519"]
            and results["dilithium"] is True and results["timestamp"]
            and results["rfc3161_binding"] is True):
        raise ValueError("Package failed strict verification profile")
    return results


# This package carries no RFC 3161 token, so `rfc3161_binding` is None --
# "not checked" -- which the strict profile refuses rather than passes.
try:
    verify_strict(MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key)
except ValueError as exc:
    print(f"strict profile correctly refused: {exc}")
```

`rfc3161_binding` establishes that the stored token refers to this package. It
does **not** establish that a trusted authority issued it, so a strict profile
must pair it with whatever control does. (The former key name `rfc3161` still
works and returns the same value, but reading it emits a `DeprecationWarning`:
the bare name read as attestation, which is exactly the misreading it caused.)

**Note:** The default behavior requires quantum signatures when Dilithium libraries are available (`require_quantum_signatures=None`). Set `require_quantum_signatures=False` only for compatibility testing.

---

## Quick Start (5 Minutes)

### 1. Install Dependencies

```bash
# Build native C library (all cryptographic primitives — zero external dependencies)
cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Install Python package
pip install -e .
```

**Note:** As of v2.0, all production cryptographic primitives (SHA3-256, HKDF-SHA3-256, Ed25519, AES-256-GCM, ML-DSA-65, ML-KEM-1024, SLH-DSA, X25519, ChaCha20-Poly1305, Argon2id, secp256k1, FROST) are implemented natively in C. No external cryptographic libraries are required.

### 2. Run Demo

```bash
python3 -m ama_cryptography
```

Expected output:
```
==================================================================
AMA Cryptography: SHA3-256 Security Hash
==================================================================

[1/5] Generating key management system...
  ✓ Master secret: 256 bits
  ✓ HMAC key: 256 bits
  ✓ Ed25519 keypair: 32 bytes
  ✓ Dilithium keypair: 1952 bytes

[2/5] Master Omni-Code Helix:
  1. 👁20A07∞_XΔEΛX_ϵ19A89Ϙ
     Omni-Directional System
     Helix: radius=20.0, pitch=0.7
  ...

[5/5] Exporting public keys...
  ✓ Package saved: CRYPTO_PACKAGE.json

==================================================================
✓ ALL VERIFICATIONS PASSED
==================================================================
```

### 3. Verify Generated Files

```bash
# Check files created
ls -lh CRYPTO_PACKAGE.json public_keys/

# View crypto package
cat CRYPTO_PACKAGE.json | python3 -m json.tool

# View public keys
ls -lh public_keys/
```

---

## Production Deployment

### Step 1: Build Native PQC Library (Quantum Resistance)

#### Build from Source (Recommended)

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential cmake

# macOS
brew install cmake

# Build native C library (all crypto primitives — zero external dependencies)
cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

All production cryptographic algorithms (SHA3-256, HKDF, Ed25519, AES-256-GCM, ML-DSA-65, ML-KEM-1024, SLH-DSA, X25519, ChaCha20-Poly1305, Argon2id, secp256k1, FROST) are implemented natively — no external cryptographic libraries required. Current self-attested NIST-vector scope is documented in `docs/compliance/CSRC_ALIGN_REPORT.md`.

#### Verify Installation

<!-- example: python-run -->
```python
from ama_cryptography.pqc_backends import PQCStatus, get_pqc_status, get_pqc_backend_info

# get_pqc_status() returns a PQCStatus ENUM (AVAILABLE / UNAVAILABLE), a
# single rollup verdict — not a per-algorithm report.
print("PQC status:", get_pqc_status())          # PQCStatus.AVAILABLE
assert get_pqc_status() is PQCStatus.AVAILABLE

# The per-algorithm report is get_pqc_backend_info()["algorithms"], keyed by
# the implementation's own spellings.
for name, meta in sorted(get_pqc_backend_info()["algorithms"].items()):
    print(f"  {name}: {meta['available']} ({meta['backend']})")
# ML-DSA-65, Kyber-1024 and SPHINCS+-256f should all report True / native.
```

### Step 2: Set Up Key Management

#### Generate Keys

<!-- example: python-run -->
```python
from pathlib import Path

from ama_cryptography.legacy_compat import export_public_keys, generate_key_management_system

# Generate key management system
kms = generate_key_management_system("YourOrganization")

# Export public keys for distribution
export_public_keys(kms, Path("public_keys"))
```

#### Secure Master Secret Storage

**Option 1: Hardware Security Module (HSM)**

Recommended for production. Supports FIPS 140-2 Level 3+.

<!-- example: pseudocode: needs a provisioned AWS CloudHSM cluster and boto3 credentials -->
```python
# Example: AWS CloudHSM
import boto3
from botocore.exceptions import ClientError

def store_master_secret_hsm(master_secret: bytes, key_label: str):
    """Store master secret in AWS CloudHSM."""
    client = boto3.client('cloudhsmv2')

    # Import key to HSM
    response = client.import_key(
        KeyLabel=key_label,
        KeyMaterial=master_secret,
        KeySpec='AES_256'
    )

    return response['KeyId']

# Store master secret
hsm_key_id = store_master_secret_hsm(
    kms.master_secret,
    "OMNI_GUARDIAN_MASTER_SECRET"
)
print(f"Master secret stored in HSM: {hsm_key_id}")

# NEVER store master_secret on disk after this point.  Rebinding the attribute
# drops this reference to the secret; it does NOT erase the bytes, which a
# Python `bytes` object cannot do.  Hold a secret you must wipe in a bytearray
# and pass it to ama_cryptography.secure_memory.secure_memzero().
kms.master_secret = b'\x00' * 32
```

**Option 2: Hardware Token (YubiKey, Nitrokey)**

For personal/small team use. FIPS 140-2 Level 2.

<!-- example: pseudocode: needs a physically attached YubiKey and the ykman package -->
```python
# Example: YubiKey PIV
from ykman.device import connect_to_device
from ykman.piv import PivController

def store_key_yubikey(master_secret: bytes, slot: int = 0x82):
    """Store key in YubiKey PIV slot."""
    device, _ = connect_to_device()[0]
    piv = PivController(device.driver)

    # Authenticate with management key
    piv.authenticate(bytes.fromhex('010203040506070801020304050607080102030405060708'))

    # Store key in slot
    piv.import_key(slot, master_secret)

    print(f"Key stored in YubiKey slot {hex(slot)}")

store_key_yubikey(kms.master_secret)
```

**Option 3: Encrypted Keystore (Software)**

Minimum security for testing. Use strong password.

The keystore below runs entirely on AMA's own primitives (INVARIANT-1):
PBKDF2-HMAC-SHA256 from `ama_cryptography.pqc_backends` derives the key and
AES-256-GCM from `ama_cryptography.crypto_api` seals the secret, so a wrong
password or a modified file fails the tag check instead of returning garbage.
An earlier revision used PyCA's Fernet with a `PBKDF2` class PyCA does not
have (the class is `PBKDF2HMAC`), never imported `base64`, and wrote a 32-byte
salt that the loader read back as 16 bytes, so it could not decrypt what it
had stored.

<!-- example: python-run -->
```python
import os

from ama_cryptography.crypto_api import AESGCMProvider
from ama_cryptography.legacy_compat import generate_key_management_system
from ama_cryptography.pqc_backends import native_pbkdf2_hmac_sha256

PBKDF2_ITERATIONS = 600_000  # OWASP recommendation (2024) for PBKDF2-HMAC-SHA256
SALT_LEN, NONCE_LEN, TAG_LEN = 32, 12, 16
AAD = b"ama-master-secret-v1"


def store_master_secret_encrypted(
    master_secret: bytes,
    password: str,
    keyfile: str = "master_secret.enc",
) -> None:
    """Store master secret encrypted under a password-derived AES-256-GCM key."""
    salt = os.urandom(SALT_LEN)  # 256-bit salt
    key = native_pbkdf2_hmac_sha256(password.encode(), salt, PBKDF2_ITERATIONS, 32)
    sealed = AESGCMProvider().encrypt(master_secret, key, aad=AAD)

    # Save salt || nonce || tag || ciphertext
    with open(keyfile, "wb") as f:
        f.write(salt + sealed["nonce"] + sealed["tag"] + sealed["ciphertext"])

    print(f"Master secret encrypted and saved to {keyfile}")
    print("WARNING: Password-protected encryption is weaker than HSM")
    print("         Use HSM for production deployments")


def load_master_secret_encrypted(password: str, keyfile: str = "master_secret.enc") -> bytes:
    """Load and decrypt master secret; raises if the password or the file is wrong."""
    with open(keyfile, "rb") as f:
        data = f.read()

    salt = data[:SALT_LEN]
    nonce = data[SALT_LEN:SALT_LEN + NONCE_LEN]
    tag = data[SALT_LEN + NONCE_LEN:SALT_LEN + NONCE_LEN + TAG_LEN]
    ciphertext = data[SALT_LEN + NONCE_LEN + TAG_LEN:]

    key = native_pbkdf2_hmac_sha256(password.encode(), salt, PBKDF2_ITERATIONS, 32)
    return AESGCMProvider().decrypt(ciphertext, key, nonce, tag, aad=AAD)


# Usage.  An interactive tool reads the password with getpass.getpass() and
# asks for it twice; it is a literal here so the example runs unattended.
kms = generate_key_management_system("YourOrganization")
password = "correct horse battery staple"
store_master_secret_encrypted(kms.master_secret, password)

# Later: Load master secret
master_secret = load_master_secret_encrypted(password)
assert master_secret == kms.master_secret
```

### Step 3: Configure RFC 3161 Timestamps

#### Option A: FreeTSA (Free, Rate-Limited)

<!-- example: pseudocode: contacts the FreeTSA server over the network, which a documentation check must not depend on -->
```python
def create_package_with_timestamp(
    codes: str,
    helix_params: List[Tuple[float, float]],
    kms: KeyManagementSystem
) -> CryptoPackage:
    """Create package with RFC 3161 timestamp."""

    return create_crypto_package(
        codes,
        helix_params,
        kms,
        author="Steel-SecAdv-LLC",
        use_rfc3161=True,  # Enable RFC 3161
        tsa_url="https://freetsa.org/tsr"  # FreeTSA
    )

# Usage
pkg = create_package_with_timestamp(
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    kms
)

if pkg.timestamp_token:
    print("OK: RFC 3161 timestamp obtained")
else:
    print("WARNING: RFC 3161 failed, using self-asserted timestamp")
```

#### Option B: Commercial TSA (Production)

<!-- example: pseudocode: contacts commercial TSA servers over the network, which a documentation check must not depend on -->
```python
# DigiCert Timestamp Server
pkg = create_crypto_package(
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    kms,
    author="Steel-SecAdv-LLC",
    use_rfc3161=True,
    tsa_url="http://timestamp.digicert.com"  # DigiCert
)

# GlobalSign Timestamp Server
pkg = create_crypto_package(
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    kms,
    author="Steel-SecAdv-LLC",
    use_rfc3161=True,
    tsa_url="http://timestamp.globalsign.com/tsa/r6advanced1"  # GlobalSign
)
```

#### Option C: OpenTimestamps (Bitcoin Blockchain)

```bash
# Install OpenTimestamps
pip install opentimestamps-client

# Create timestamp on Bitcoin blockchain
ots stamp CRYPTO_PACKAGE.json

# Wait for Bitcoin confirmation (6 blocks ≈ 1 hour)

# Verify timestamp
ots verify CRYPTO_PACKAGE.json.ots
```

### Step 4: Implement Key Rotation

<!-- example: python-run -->
```python
from datetime import datetime, timezone
from pathlib import Path

from ama_cryptography.legacy_compat import (
    KeyManagementSystem,
    export_public_keys,
    generate_key_management_system,
)

def should_rotate_keys(kms: KeyManagementSystem) -> bool:
    """Check if keys need rotation (quarterly schedule)."""
    creation = datetime.fromisoformat(kms.creation_date)
    now = datetime.now(timezone.utc)
    age = (now - creation).days

    if kms.rotation_schedule == "quarterly":
        return age >= 90
    elif kms.rotation_schedule == "monthly":
        return age >= 30
    elif kms.rotation_schedule == "annually":
        return age >= 365

    return False

def rotate_keys(old_kms: KeyManagementSystem, author: str) -> KeyManagementSystem:
    """Rotate keys while maintaining master secret."""

    print("Rotating keys...")

    # Generate new KMS with NEW master secret
    new_kms = generate_key_management_system(author)

    # Archive old public keys for verification.  (A compact UTC stamp: the
    # ":" in isoformat() is not a legal path character on Windows.)
    archive_dir = Path(f"public_keys_archive_{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}")
    export_public_keys(old_kms, archive_dir)
    print(f"Old public keys archived to: {archive_dir}")

    # Export new public keys
    export_public_keys(new_kms, Path("public_keys"))

    # Drop the old master secret.  Rebinding the attribute releases this
    # reference; it does not erase the bytes (a Python `bytes` object cannot
    # be erased in place).  See Step 2 for keeping secrets out of Python.
    old_kms.master_secret = b'\x00' * 32

    print("Key rotation complete")
    return new_kms

# Usage
kms = generate_key_management_system("Steel-SecAdv-LLC")
print("Rotation due:", should_rotate_keys(kms))  # False for a key created just now
if should_rotate_keys(kms):
    kms = rotate_keys(kms, "Steel-SecAdv-LLC")

# What the scheduled job runs once rotation is due:
kms = rotate_keys(kms, "Steel-SecAdv-LLC")
```

### Step 5: Sign Omni-Code Packages

<!-- example: python-run -->
```python
import json
from dataclasses import asdict
from typing import List, Tuple

from ama_cryptography.legacy_compat import (
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    CryptoPackage,
    KeyManagementSystem,
    create_crypto_package,
    generate_key_management_system,
)

def sign_codes(
    codes: str,
    helix_params: List[Tuple[float, float]],
    kms: KeyManagementSystem,
    output_file: str = "CRYPTO_PACKAGE.json"
) -> CryptoPackage:
    """Sign Omni-Codes and save package."""

    # Create cryptographic package.  Production should set use_rfc3161=True
    # with a TSA from Step 3; that contacts the TSA over the network.
    pkg = create_crypto_package(
        codes,
        helix_params,
        kms,
        author="Steel-SecAdv-LLC",
        use_rfc3161=False,
    )

    # Save to file
    with open(output_file, 'w') as f:
        json.dump(asdict(pkg), f, indent=2)

    print(f"Package signed and saved: {output_file}")
    return pkg

# Sign master Omni-Codes
kms = generate_key_management_system("Steel-SecAdv-LLC")
pkg = sign_codes(MASTER_CODES, MASTER_HELIX_PARAMS, kms)
```

### Step 6: Verify Omni-Code Packages

<!-- example: python-run continues -->
```python
from ama_cryptography.legacy_compat import verify_crypto_package

def verify_dna_package(
    package_file: str,
    codes: str,
    helix_params: List[Tuple[float, float]],
    hmac_key: bytes
) -> bool:
    """Verify Omni-Code package from file."""

    # Load package
    with open(package_file, 'r') as f:
        pkg_dict = json.load(f)

    pkg = CryptoPackage(**pkg_dict)

    # Verify all layers
    results = verify_crypto_package(
        codes,
        helix_params,
        pkg,
        hmac_key
    )

    # Print results.  A check that does not apply to this package (the
    # RFC 3161 ones, for a package with no token) reports None, not False.
    print(f"\nVerification Results for {package_file}:")
    print("-" * 50)
    for check, valid in results.items():
        verdict = "N/A" if valid is None else ("VALID" if valid else "INVALID")
        print(f"  {check}: {verdict}")

    all_valid = all(valid is not False for valid in results.values())
    print("-" * 50)
    if all_valid:
        print("ALL VERIFICATIONS PASSED")
    else:
        print("VERIFICATION FAILED")

    return all_valid

# Verify package
is_valid = verify_dna_package(
    "CRYPTO_PACKAGE.json",
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    kms.hmac_key
)
assert is_valid
```

---

## Advanced Usage

### Custom Omni-Codes

<!-- example: python-run continues -->
```python
# Define your own Omni-Codes
custom_codes = (
    "Ψ10B05α_YΩZΛY_β15C12Δ"
    "Δ12A08β_ΦΛNΩΦ_γ18D21Ε"
)

custom_helix_params = [
    (10.0, 0.5),  # First code
    (12.0, 0.8),  # Second code
]

# Sign custom codes
pkg = create_crypto_package(
    custom_codes,
    custom_helix_params,
    kms,
    author="Steel-SecAdv-LLC"
)

# Verify custom codes
results = verify_crypto_package(
    custom_codes,
    custom_helix_params,
    pkg,
    kms.hmac_key
)
```

### Multiple Signatures (Co-Signing)

<!-- example: python-run -->
```python
from typing import Any, Dict, List, Tuple

from ama_cryptography.legacy_compat import (
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    KeyManagementSystem,
    create_crypto_package,
    dilithium_sign,
    ed25519_sign,
    generate_key_management_system,
    hmac_authenticate,
)

def create_multi_signed_package(
    codes: str,
    helix_params: List[Tuple[float, float]],
    signers: List[Tuple[str, KeyManagementSystem]]
) -> Dict[str, Any]:
    """Create package signed by multiple parties."""

    # Create base package with first signer
    author1, kms1 = signers[0]
    pkg = create_crypto_package(codes, helix_params, kms1, author1)

    # Add additional signatures
    multi_pkg = {
        "content_hash": pkg.content_hash,
        "timestamp": pkg.timestamp,
        "signatures": []
    }

    for author, kms in signers:
        content_hash = bytes.fromhex(pkg.content_hash)

        sig = {
            "author": author,
            "hmac": hmac_authenticate(content_hash, kms.hmac_key).hex(),
            "ed25519_sig": ed25519_sign(content_hash, kms.ed25519_keypair.private_key).hex(),
            "dilithium_sig": dilithium_sign(content_hash, kms.dilithium_keypair.secret_key).hex(),
            "ed25519_pubkey": kms.ed25519_keypair.public_key.hex(),
            "dilithium_pubkey": kms.dilithium_keypair.public_key.hex()
        }
        multi_pkg["signatures"].append(sig)

    return multi_pkg

# Usage: Multiple organizations co-sign
kms_org1 = generate_key_management_system("Organization1")
kms_org2 = generate_key_management_system("Organization2")
kms_org3 = generate_key_management_system("Organization3")

multi_pkg = create_multi_signed_package(
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    [
        ("Organization1", kms_org1),
        ("Organization2", kms_org2),
        ("Organization3", kms_org3)
    ]
)

print(f"Package signed by {len(multi_pkg['signatures'])} parties")
```

### Git Integration (Signed Commits)

Git signs commits with an SSH key through `ssh-agent` or a key file, so the
private half has to be in OpenSSH form, which this library does not export.
What an AMA Ed25519 public key *can* do is **verify** those commits: it goes
into Git's allowed-signers file, in the SSH wire encoding
`base64(string "ssh-ed25519" || string key)` of RFC 4253 §6.6 / RFC 8709.
An earlier revision of this section wrote `base64(public_key)` — the raw 32
bytes, which no SSH tool parses — into `user.signingkey`, where Git expects a
signing key, not a verification key.

<!-- example: python-run -->
```python
import base64
import struct

from ama_cryptography.legacy_compat import generate_key_management_system

def ssh_ed25519_public_key(public_key: bytes, comment: str) -> str:
    """OpenSSH public-key line for a raw 32-byte Ed25519 key (RFC 8709)."""
    def ssh_string(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    blob = ssh_string(b"ssh-ed25519") + ssh_string(public_key)
    return f"ssh-ed25519 {base64.b64encode(blob).decode()} {comment}"

kms = generate_key_management_system("Steel-SecAdv-LLC")
line = ssh_ed25519_public_key(kms.ed25519_keypair.public_key, "Steel-SecAdv-LLC")

# Git's allowed-signers format: "<principal> <key type> <base64 key> [comment]"
with open("allowed_signers", "w") as f:
    f.write(f"security@example.org {line}\n")
print(line)
```

Then point Git at the file for verification:

```bash
git config gpg.format ssh
git config gpg.ssh.allowedSignersFile "$PWD/allowed_signers"
git log --show-signature
```

---

## Troubleshooting

### Issue: Dilithium Not Available

**Symptom:**
```
WARNING: Using INSECURE placeholder for Dilithium!
```

**Solution: Build the native C library**
```bash
# Install build dependencies
sudo apt-get install build-essential cmake  # Ubuntu/Debian
# brew install cmake  # macOS

# Build native C library (all crypto primitives)
cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

All cryptographic algorithms are implemented natively with NIST KAT validation — no external libraries needed.

### Issue: RFC 3161 Timestamp Fails

**Symptom:**
```
Warning: RFC 3161 timestamp failed: <error>
Falling back to self-asserted timestamp
```

**Possible Causes:**
1. No internet connection
2. TSA server unreachable
3. Rate limit exceeded (FreeTSA)
4. OpenSSL not installed

**Solutions:**

1. Check internet connection:
```bash
curl -I https://freetsa.org/tsr
```

2. Try different TSA:
<!-- example: pseudocode: an ellipsis sketch that shows only the tsa_url argument; contacts a TSA over the network -->
```python
pkg = create_crypto_package(
    ...,
    use_rfc3161=True,
    tsa_url="http://timestamp.digicert.com"  # Try DigiCert
)
```

3. Install OpenSSL:
```bash
# Ubuntu/Debian
sudo apt-get install openssl

# macOS
brew install openssl

# Windows
# Download from: https://slproweb.com/products/Win32OpenSSL.html
```

4. Use OpenTimestamps instead:
```bash
pip install opentimestamps-client
ots stamp CRYPTO_PACKAGE.json
```

### Issue: Key Import Errors

**Symptom:**
```
ValueError: Ed25519 private key must be 32 bytes
```

**Solution:**
Check key length before import:
<!-- example: pseudocode: a two-line guard on a private_key variable the reader already holds -->
```python
if len(private_key) != 32:
    raise ValueError(f"Expected 32 bytes, got {len(private_key)}")
```

### Issue: HMAC Verification Fails

**Symptom:**
```
✗ hmac: INVALID
```

**Possible Causes:**
1. Wrong HMAC key
2. Data modified
3. Key corrupted

**Solution:**
Regenerate package with correct key:
<!-- example: python-run -->
```python
import hashlib

from ama_cryptography.legacy_compat import (
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    create_crypto_package,
    generate_key_management_system,
)

kms = generate_key_management_system("Steel-SecAdv-LLC")

# Verify you're using the same KMS: compare a FINGERPRINT of the HMAC key,
# never the key bytes themselves -- a log line with 16 hex digits of the key
# discloses 64 bits of it.
print(f"HMAC key fingerprint: {hashlib.sha3_256(kms.hmac_key).hexdigest()[:16]}")

# Re-sign with correct key
pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, author="Steel-SecAdv-LLC")
```

---

## Performance Optimization

### Batch Processing

<!-- example: python-run -->
```python
import time
from typing import List, Tuple

from ama_cryptography.legacy_compat import (
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    CryptoPackage,
    KeyManagementSystem,
    create_crypto_package,
    generate_key_management_system,
)

def sign_multiple_codes(
    dna_list: List[Tuple[str, List[Tuple[float, float]]]],
    kms: KeyManagementSystem
) -> List[CryptoPackage]:
    """Sign multiple Omni-Codes efficiently."""

    packages = []

    for i, (codes, helix_params) in enumerate(dna_list):
        pkg = create_crypto_package(
            codes,
            helix_params,
            kms,
            author="Steel-SecAdv-LLC"
        )
        packages.append(pkg)

        if (i + 1) % 100 == 0:
            print(f"Signed {i + 1} packages...")

    print(f"Signed {len(packages)} packages total")
    return packages

# Usage: Sign 1000 Omni-Code sets
kms = generate_key_management_system("Steel-SecAdv-LLC")
dna_list = [(MASTER_CODES, MASTER_HELIX_PARAMS) for _ in range(1000)]
start = time.perf_counter()
packages = sign_multiple_codes(dna_list, kms)

# Throughput on this host (Ed25519 + ML-DSA-65 per package):
print(f"{len(packages) / (time.perf_counter() - start):,.0f} packages/second")
```

### Parallel Verification

<!-- example: python-run -->
```python
import time
from concurrent.futures import ProcessPoolExecutor
from typing import Dict, List, Optional, Tuple

from ama_cryptography.legacy_compat import (
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    CryptoPackage,
    create_crypto_package,
    generate_key_management_system,
    verify_crypto_package,
)

def verify_package_worker(args):
    """Worker function for parallel verification."""
    pkg, codes, helix_params, hmac_key = args
    return verify_crypto_package(codes, helix_params, pkg, hmac_key)

def verify_multiple_packages(
    packages: List[CryptoPackage],
    codes: str,
    helix_params: List[Tuple[float, float]],
    hmac_key: bytes,
    workers: int = 4
) -> List[Dict[str, Optional[bool]]]:
    """Verify multiple packages in parallel."""

    args_list = [
        (pkg, codes, helix_params, hmac_key)
        for pkg in packages
    ]

    with ProcessPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(verify_package_worker, args_list))

    return results

# The guard is required, not decoration: on Windows and macOS worker
# processes are spawned by re-importing this module, and without it each
# worker would start a pool of its own.
if __name__ == "__main__":
    kms = generate_key_management_system("Steel-SecAdv-LLC")
    packages = [
        create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, author="Steel-SecAdv-LLC")
        for _ in range(200)
    ]

    # Usage: Verify the packages with 4 workers
    start = time.perf_counter()
    results = verify_multiple_packages(packages, MASTER_CODES, MASTER_HELIX_PARAMS, kms.hmac_key)
    elapsed = time.perf_counter() - start

    assert all(v is not False for r in results for v in r.values())
    print(f"{len(results) / elapsed:,.0f} packages/second on 4 workers")
```

An earlier revision of these two sections printed fixed figures ("~1000
packages/second (with Dilithium)", "~4000 packages/second (4 cores)") with no
host or run behind them, and its parallel example had no `__main__` guard, so
it could not run where multiprocessing spawns rather than forks. Both examples
now measure and print the rate on the machine that runs them.

---

## Security Checklist

### Pre-Deployment

- [ ] Build native PQC C library (ML-DSA-65, ML-KEM-1024, SLH-DSA)
- [ ] Set up HSM or hardware token for master secret
- [ ] Configure RFC 3161 TSA (FreeTSA or commercial)
- [ ] Test key generation and signing
- [ ] Verify all cryptographic operations
- [ ] Run NIST KAT tests: `pytest tests/test_nist_kat.py tests/test_pqc_kat.py -v`
- [ ] Run constant-time verification harness on target hardware (see [CONSTANT_TIME_VERIFICATION.md](CONSTANT_TIME_VERIFICATION.md))
- [ ] Back up master secret (encrypted, offline)
- [ ] Document key rotation schedule

### Deployment

- [ ] Generate production keys
- [ ] Store master secret in HSM
- [ ] Export public keys for distribution
- [ ] Configure Git signing (optional)
- [ ] Set up monitoring and alerting
- [ ] Implement key rotation automation
- [ ] Create incident response plan

### Post-Deployment

- [ ] Rotate keys quarterly
- [ ] Audit key operations monthly
- [ ] Monitor for security updates
- [ ] Test disaster recovery
- [ ] Review access controls
- [ ] Update dependencies
- [ ] Archive old public keys

---

## Migration Guide: Ethical Integration (v1.0.0 → v2.0.0)

### Overview

Version 2.0.0 introduces ethical integration into the cryptographic framework, adding two new fields to the `CryptoPackage` dataclass. This is a **breaking change** that requires migration for existing packages.

### Breaking Changes

#### CryptoPackage Schema Changes

**v1.0.0 Schema:**
<!-- example: python-names module=ama_cryptography.legacy_compat -->
```python
@dataclass
class CryptoPackage:
    content_hash: str
    hmac_tag: str
    ed25519_signature: str
    dilithium_signature: str
    timestamp: str
    timestamp_token: Optional[str]
    author: str
    ed25519_pubkey: str
    dilithium_pubkey: str
    version: str
```

**v2.0.0 Schema (NEW):**
<!-- example: python-names module=ama_cryptography.legacy_compat -->
```python
@dataclass
class CryptoPackage:
    content_hash: str
    hmac_tag: str
    ed25519_signature: str
    dilithium_signature: str
    timestamp: str
    timestamp_token: Optional[str]
    author: str
    ed25519_pubkey: str
    dilithium_pubkey: str
    version: str
    ethical_vector: Dict[str, float]  # NEW: 4 Omni-Code Ethical Pillars
    ethical_hash: str                 # NEW: SHA3-256 hash of ethical vector
```

#### Impact

**Who is affected:**
- Applications deserializing `CRYPTO_PACKAGE.json` files
- Systems verifying packages created with v1.0.0
- Code that creates `CryptoPackage` instances directly

**What breaks:**
- Loading v1.0.0 packages into v2.0.0 code will fail with missing field errors
- Code that creates `CryptoPackage` without `ethical_vector` and `ethical_hash` will fail

### Migration Strategies

#### Strategy 1: Regenerate All Packages (Recommended)

**Best for:** New deployments, systems with few existing packages

<!-- example: python-run -->
```python
import json
from dataclasses import asdict

from ama_cryptography.legacy_compat import *

# Load your Omni-Codes and helix parameters (the shipped set stands in here)
codes = MASTER_CODES                # Your Omni-Codes
helix_params = MASTER_HELIX_PARAMS  # Your helix parameters

# Generate new KMS with ethical integration
kms = generate_key_management_system("YourOrganization")

# Create new package with ethical integration.  Production should set
# use_rfc3161=True with a TSA from Step 3, which contacts it over the network.
pkg = create_crypto_package(
    codes,
    helix_params,
    kms,
    author="YourOrganization",
    use_rfc3161=False,
)

# Save new package
with open("CRYPTO_PACKAGE.json", 'w') as f:
    json.dump(asdict(pkg), f, indent=2)

print("Package regenerated with ethical integration")
```

#### Strategy 2: Backward-Compatible Verification

**Best for:** Systems that must verify both v1.0.0 and v2.0.0 packages

<!-- example: python-run continues -->
```python
import hashlib
import json
from typing import Optional

def load_package_any_version(package_file: str) -> CryptoPackage:
    """Load package from any version, adding defaults for missing fields."""

    with open(package_file, 'r') as f:
        pkg_dict = json.load(f)

    # Check if ethical fields are present
    if 'ethical_vector' not in pkg_dict:
        # v1.0.0 package - add default ethical vector
        print("WARNING: loading v1.0.0 package without ethical integration")
        pkg_dict['ethical_vector'] = ETHICAL_VECTOR.copy()

        # Compute ethical hash for consistency
        ethical_json = json.dumps(pkg_dict['ethical_vector'], sort_keys=True)
        pkg_dict['ethical_hash'] = hashlib.sha3_256(ethical_json.encode()).hexdigest()

    return CryptoPackage(**pkg_dict)

# Usage
pkg = load_package_any_version("CRYPTO_PACKAGE.json")

# Verify with warning if no ethical binding
results = verify_crypto_package(codes, helix_params, pkg, kms.hmac_key)

if pkg.version == "1.0.0":
    print("WARNING: package verified but lacks ethical binding")
    print("  Consider regenerating with v2.0.0 for full security")
```

#### Strategy 3: Batch Migration Script

**Best for:** Systems with many existing packages

<!-- example: python-run -->
```python
import json
from dataclasses import asdict
from pathlib import Path
from typing import List, Tuple

from ama_cryptography.legacy_compat import (
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    KeyManagementSystem,
    create_crypto_package,
    generate_key_management_system,
)

def migrate_package_directory(
    input_dir: str,
    output_dir: str,
    kms: KeyManagementSystem,
    codes: str,
    helix_params: List[Tuple[float, float]]
):
    """Migrate all packages in directory to v2.0.0."""

    input_path = Path(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    # Find all JSON packages
    packages = list(input_path.glob("*.json"))

    print(f"Found {len(packages)} packages to migrate")

    for pkg_file in packages:
        print(f"Migrating {pkg_file.name}...")

        # Create new package with ethical integration (use_rfc3161=True in
        # production, as in Strategy 1)
        new_pkg = create_crypto_package(
            codes,
            helix_params,
            kms,
            author=kms.author if hasattr(kms, 'author') else "Unknown",
            use_rfc3161=False,
        )

        # Save to output directory
        output_file = output_path / pkg_file.name
        with open(output_file, 'w') as f:
            json.dump(asdict(new_pkg), f, indent=2)

        print(f"  Migrated to {output_file}")

    print(f"\nMigration complete: {len(packages)} packages")

# Usage
kms = generate_key_management_system("YourOrganization")
migrate_package_directory(
    input_dir="packages_v1",
    output_dir="packages_v2",
    kms=kms,
    codes=MASTER_CODES,
    helix_params=MASTER_HELIX_PARAMS
)
```

### Key Management Changes

#### Ethical Vector in KMS

**v2.0.0 adds ethical vector to KeyManagementSystem** (shown as it stands
today, with the fields added since):

<!-- example: python-names module=ama_cryptography.legacy_compat -->
```python
@dataclass
class KeyManagementSystem:
    master_secret: bytes
    hmac_key: bytes
    hkdf_salt: bytes
    ed25519_keypair: Ed25519KeyPair
    dilithium_keypair: Optional[DilithiumKeyPair]
    creation_date: str
    rotation_schedule: str
    version: str
    ethical_vector: Dict[str, float]  # NEW in v2.0.0
    quantum_signatures_enabled: bool = True
```

**Default Ethical Vector:**
<!-- example: python-run -->
```python
ETHICAL_VECTOR = {
    "omniscient": 3.0,        # Triad of Wisdom
    "omnipotent": 3.0,        # Triad of Agency
    "omnidirectional": 3.0,   # Triad of Geography
    "omnibenevolent": 3.0,    # Triad of Integrity
}
# Constraint: Σw = 12.0
assert sum(ETHICAL_VECTOR.values()) == 12.0

from ama_cryptography.legacy_compat import ETHICAL_VECTOR as DEFAULT_ETHICAL_VECTOR
assert ETHICAL_VECTOR == DEFAULT_ETHICAL_VECTOR
```

**Custom Ethical Vector (Advanced):**
<!-- example: python-run -->
```python
from ama_cryptography.legacy_compat import generate_key_management_system

# Define custom ethical vector for domain-specific use
custom_ethical_vector = {
    "omniscient": 4.0,        # Increased verification emphasis
    "omnipotent": 3.0,        # Standard strength
    "omnidirectional": 3.0,   # Standard coverage
    "omnibenevolent": 2.0,    # Reduced for specific use case
}

# Verify constraint
assert sum(custom_ethical_vector.values()) == 12.0

# Generate KMS with custom vector
kms = generate_key_management_system(
    author="YourOrganization",
    ethical_vector=custom_ethical_vector
)
```

### Verification Changes

#### Ethical Hash Verification

**v2.0.0 packages include ethical hash for verification:**

<!-- example: python-run -->
```python
import hashlib
import json

from ama_cryptography.legacy_compat import (
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    CryptoPackage,
    create_crypto_package,
    generate_key_management_system,
    verify_crypto_package,
)

def verify_ethical_binding(pkg: CryptoPackage) -> bool:
    """Verify ethical vector matches its hash."""

    # Recompute ethical hash
    ethical_json = json.dumps(pkg.ethical_vector, sort_keys=True)
    computed_hash = hashlib.sha3_256(ethical_json.encode()).hexdigest()

    # Compare with package hash
    if computed_hash != pkg.ethical_hash:
        print("FAILED: ethical hash mismatch - package may be tampered")
        return False

    # Verify constraint
    total_weight = sum(pkg.ethical_vector.values())
    if abs(total_weight - 12.0) > 1e-10:
        print(f"FAILED: ethical vector constraint violated: sum = {total_weight}, not 12.0")
        return False

    print("OK: ethical binding verified")
    return True

# Usage
kms = generate_key_management_system("YourOrganization")
pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, author="YourOrganization")
if verify_ethical_binding(pkg):
    print("Package has valid ethical integration")
```

### Testing Migration

<!-- example: python-run continues -->
```python
def test_migration():
    """Test migration from v1.0.0 to v2.0.0."""

    print("Testing migration...")

    # 1. Create v2.0.0 package
    kms = generate_key_management_system("TestOrg")
    pkg_v2 = create_crypto_package(
        MASTER_CODES,
        MASTER_HELIX_PARAMS,
        kms,
        author="TestOrg"
    )

    # 2. Verify all fields present
    assert hasattr(pkg_v2, 'ethical_vector')
    assert hasattr(pkg_v2, 'ethical_hash')
    # ETHICAL_VECTOR is FOUR pillars weighted 3.0 each: the sum is 12.0, the
    # length is 4 (ama_cryptography/equations.py:142-153, which raises at
    # import if either stops holding).
    assert len(pkg_v2.ethical_vector) == 4
    assert sum(pkg_v2.ethical_vector.values()) == 12.0

    # 3. Verify ethical hash
    assert verify_ethical_binding(pkg_v2)

    # 4. Verify cryptographic integrity
    results = verify_crypto_package(
        MASTER_CODES,
        MASTER_HELIX_PARAMS,
        pkg_v2,
        kms.hmac_key
    )
    # None means "not applicable" (the RFC 3161 checks, for a package with no
    # token); only False is a failed check.
    assert all(verdict is not False for verdict in results.values())

    print("Migration test passed")

test_migration()
```

### Rollback Plan

If you need to rollback to v1.0.0:

```bash
# 1. Checkout v1.0.0 tag
git checkout v1.0.0

# 2. Reinstall dependencies
pip install -r requirements.txt

# 3. Use archived v1.0.0 packages
# (v2.0.0 packages cannot be used with v1.0.0 code)
```

**Note:** v2.0.0 packages are **not backward compatible** with v1.0.0 code.

### Support

For migration assistance:
- Email: steel.sa.llc@gmail.com
- GitHub Issues: https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/issues

---

## Ongoing Development

AMA Cryptography is under continuous development with a focus on maintaining the highest security standards while expanding capabilities:

- **Mercury Agent Integration:** AMA Cryptography serves as the cryptographic protection layer for [Mercury Agent](https://github.com/Steel-SecAdv-LLC/Mercury-Agent), providing quantum-resistant security for Mercury Agent's services
- **Security Updates:** Continuous security updates and performance optimizations based on emerging cryptographic research and threat landscape changes
- **Phase 2 Primitives:** X25519 key exchange (RFC 7748), ChaCha20-Poly1305 AEAD (RFC 8439), Argon2id password hashing (RFC 9106), and secp256k1 HD key derivation are now available in the native C library
- **Community-Driven Features:** Feature development driven by real-world usage patterns and community feedback, ensuring the system evolves to meet practical security needs

For the latest development updates, see the project's GitHub repository and CHANGELOG.md.

---

## C API Build (Advanced)

For users who need direct C library integration for post-quantum cryptography:

### Prerequisites

The C API provides all cryptographic algorithms natively — no external libraries required.

```bash
# Ubuntu/Debian
sudo apt-get install -y cmake gcc build-essential

# macOS
brew install cmake
```

### Build C Library

```bash
# CMake Build (Recommended) — all crypto primitives native, zero external dependencies
cmake -B build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build
```

### Supported Algorithms (Native C)

| Algorithm | NIST Standard | Key Sizes | KAT Status |
|-----------|---------------|-----------|------------|
| ML-DSA-65 (Dilithium3) | FIPS 204 | PK: 1952, SK: 4032, Sig: 3309 | See `docs/compliance/CSRC_ALIGN_REPORT.md` |
| ML-KEM-1024 (Kyber lineage) | FIPS 203 | PK: 1568, SK: 3168, CT: 1568 | See `docs/compliance/CSRC_ALIGN_REPORT.md` |
| SPHINCS+-SHA2-256f | FIPS 205 | PK: 64, SK: 128, Sig: 49856 | Native |

**Note:** For most users, the Python API is recommended over the C library. All cryptographic algorithms are implemented natively — no external libraries required.

---

## Cross-Compilation (Advanced)

### For ARM64 (Raspberry Pi, AWS Graviton)

```bash
cmake .. \
    -DCMAKE_SYSTEM_NAME=Linux \
    -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
    -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
    -DAMA_ENABLE_AVX2=OFF
```

### CMake Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `AMA_BUILD_SHARED` | ON | Build shared library (.so/.dylib/.dll) |
| `AMA_BUILD_STATIC` | ON | Build static library (.a/.lib) |
| `AMA_ENABLE_SIMD` | ON | Enable SIMD optimizations |
| `AMA_ENABLE_AVX2` | ON | Enable AVX2 instructions |
| `AMA_ENABLE_LTO` | ON | Enable link-time optimization |
| `AMA_ENABLE_DUDECT` | OFF | Build the `test_dudect` empirical constant-time test binary (Welch's t-test on timing samples). Required to run the dudect CI workflow (`.github/workflows/dudect.yml`). |

### Environment Variables (Python Build)

| Variable | Effect |
|----------|--------|
| `AMA_NO_CYTHON=1` | Disable Cython (use pure Python) |
| `AMA_NO_C_EXTENSIONS=1` | Disable C extensions |
| `AMA_DEBUG=1` | Enable debug symbols |

---

## Disaster Recovery

### Key Compromise

1. Immediately rotate all keys using `rotate_keys()`
2. Revoke compromised key IDs
3. Re-sign all packages with new keys
4. Notify affected parties

### HSM Failure

1. Activate backup HSM
2. Restore keys from encrypted backup
3. Verify key integrity
4. Resume operations

### Performance Degradation

1. Disable 3R monitoring temporarily (see `MONITORING.md`)
2. Scale horizontally (add nodes)
3. Investigate bottleneck
4. Optimize or upgrade resources

---

## Support and Resources

### Documentation

- **Security Analysis:** See `SECURITY.md` for mathematical proofs
- **Architecture:** See `ARCHITECTURE.md` for system design
- **Monitoring:** See `MONITORING.md` for 3R security monitoring
- **README:** See `README.md` for overview

### External Resources

- **NIST PQC:** https://csrc.nist.gov/projects/post-quantum-cryptography
- **Open Quantum Safe:** https://openquantumsafe.org/
- **RFC 3161:** https://datatracker.ietf.org/doc/html/rfc3161
- **Ed25519:** https://ed25519.cr.yp.to/

### Self-Test Behavior (Aligned with FIPS 140-3 Level 1 Requirements)

AMA Cryptography implements technical controls aligned with FIPS 140-3 Security Level 1 requirements (pending future CMVP validation):

**Power-On Self-Tests (POST):** When `import ama_cryptography` runs, the module
automatically executes Known Answer Tests for all approved algorithms (SHA3-256,
HMAC-SHA3-256, AES-256-GCM, ML-KEM-1024, ML-DSA-65, SLH-DSA, Ed25519) plus
a module integrity check and RNG health test. This takes ~260ms.

**Module State:** After POST, the module is in one of three states:
- `OPERATIONAL` — all tests passed, crypto operations allowed
- `ERROR` — a test failed, all crypto operations raise `CryptoModuleError`
- `SELF_TEST` — tests in progress (transient)

Check state: `ama_cryptography.module_status()`

**Error Recovery:** Call `ama_cryptography.reset_module()` to re-run all
self-tests. If they pass, the module returns to OPERATIONAL.

**Integrity Digest:** The module's source files are hashed at startup and
compared to a stored digest. After legitimate code changes, regenerate
(build pipeline only):

```bash
AMA_BUILD_PIPELINE=1 python -m ama_cryptography.integrity --update --sign
```

A bare `--update` exits 2: the refresh is gated behind
`AMA_BUILD_PIPELINE=1` so a post-install user cannot silently re-bless
tampered sources, and `--sign` also regenerates the signed
`_integrity_signature.py` artefact, which takes precedence over the plain
digest at import. See `SECURITY.md` ("`--update` is build-pipeline-only").

Verify the module integrity digest (runs POST as part of normal import):

```bash
python -m ama_cryptography.integrity --verify
```

**Repeated-output CSPRNG check:** Use `ama_cryptography.secure_token_bytes(n)`
instead of `secrets.token_bytes(n)` for random byte generation with a
defence-in-depth sanity check. This wrapper detects consecutive identical
outputs from the OS CSPRNG and enters ERROR state. It is not the SP 800-90B
health-test suite (Repetition Count, Adaptive Proportion) FIPS 140-3 specifies,
nor an approved SP 800-90A DRBG — see `CSRC_STANDARDS.md` §3.1(e).

> **Note:** This implementation has NOT been submitted for CMVP validation and is NOT FIPS 140-3 certified. These controls represent design alignment with FIPS 140-3 Level 1 technical requirements.

**Pairwise Consistency Tests:** Functions `pairwise_test_signature()` and
`pairwise_test_kem()` in `ama_cryptography._self_test` can be called after
any key generation to verify the keypair is consistent.

### Contact

**Steel Security Advisors LLC**
Email: steel.sa.llc@gmail.com

**Author/Inventor:** Andrew E. A.

**AI Co-Architects:**  
Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛

---

**Document Version:** 5.0.0
**Last Updated:** 2026-08-24
**Copyright (C) 2025-2026 Steel Security Advisors LLC**
