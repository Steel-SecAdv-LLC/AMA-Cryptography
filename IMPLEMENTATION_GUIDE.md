# AMA Cryptography: Implementation Guide
## Practical Guide to Deploying Cryptographic Protection

**Copyright (C) 2025-2026 Steel Security Advisors LLC**  
**Author/Inventor:** Andrew E. A.  
**Contact:** steel.sa.llc@gmail.com

**AI Co-Architects:**  
Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛

**Version:** 2.1.5
**Date:** 2026-04-20

---

## Security Profiles

Choose the appropriate verification profile for your use case:

| Profile | Dilithium Required | RFC 3161 Required | Use Case |
|---------|-------------------|-------------------|----------|
| **dev** | No | No | Local testing, prototyping |
| **classical** | No | Optional | Legacy environments, pre-quantum systems |
| **hybrid** | Yes | Optional | Typical production deployment |
| **strict** | Yes | Yes | High-assurance, regulatory compliance |

**Example: Strict profile verification**
```python
results = verify_crypto_package(codes, helix_params, pkg, hmac_key)

# Strict profile: require all checks
if not (results["content_hash"] and results["hmac"] and results["ed25519"]
        and results["dilithium"] is True and results["timestamp"]
        and results["rfc3161"] is True):
    raise ValueError("Package failed strict verification profile")
```

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

**Note:** As of v2.0, all cryptographic primitives (SHA3-256, HKDF-SHA3-256, Ed25519, AES-256-GCM, ML-DSA-65, Kyber-1024, SPHINCS+) are implemented natively in C. No external cryptographic libraries are required.

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

All cryptographic algorithms (SHA3-256, HKDF, Ed25519, AES-256-GCM, ML-DSA-65, Kyber-1024, SPHINCS+-256f) are implemented natively — no external libraries required. PQC implementations pass NIST KAT validation (10/10 for ML-DSA-65 and ML-KEM-1024).

#### Verify Installation

```python
from ama_cryptography.pqc_backends import get_pqc_status
print("PQC status:")
print(get_pqc_status())
# Output should report ML-DSA-65, Kyber-1024, and SPHINCS+-256f as available
```

### Step 2: Set Up Key Management

#### Generate Keys

```python
from ama_cryptography.legacy_compat import *

# Generate key management system
kms = generate_key_management_system("YourOrganization")

# Export public keys for distribution
export_public_keys(kms, Path("public_keys"))
```

#### Secure Master Secret Storage

**Option 1: Hardware Security Module (HSM)**

Recommended for production. Supports FIPS 140-2 Level 3+.

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

# NEVER store master_secret on disk after this point
# Zero out memory
kms.master_secret = b'\x00' * 32
```

**Option 2: Hardware Token (YubiKey, Nitrokey)**

For personal/small team use. FIPS 140-2 Level 2.

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

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import getpass
import os

def store_master_secret_encrypted(
    master_secret: bytes,
    keyfile: str = "master_secret.enc"
):
    """Store master secret encrypted with password."""
    
    # Get password from user
    password = getpass.getpass("Enter encryption password: ")
    password_confirm = getpass.getpass("Confirm password: ")
    
    if password != password_confirm:
        raise ValueError("Passwords don't match")
    
    # Derive encryption key from password using PBKDF2
    salt = os.urandom(32)  # 256-bit salt
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000  # OWASP recommendation (2024)
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    # Encrypt master secret
    fernet = Fernet(key)
    encrypted = fernet.encrypt(master_secret)
    
    # Save salt + encrypted data
    with open(keyfile, 'wb') as f:
        f.write(salt + encrypted)
    
    print(f"Master secret encrypted and saved to {keyfile}")
    print("WARNING: Password-protected encryption is weaker than HSM")
    print("         Use HSM for production deployments")

def load_master_secret_encrypted(keyfile: str = "master_secret.enc") -> bytes:
    """Load and decrypt master secret."""
    
    # Read salt + encrypted data
    with open(keyfile, 'rb') as f:
        data = f.read()
    
    salt = data[:16]
    encrypted = data[16:]
    
    # Get password from user
    password = getpass.getpass("Enter encryption password: ")
    
    # Derive decryption key
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000  # Must match store iterations
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    # Decrypt master secret
    fernet = Fernet(key)
    master_secret = fernet.decrypt(encrypted)
    
    return master_secret

# Usage
store_master_secret_encrypted(kms.master_secret)

# Later: Load master secret
# master_secret = load_master_secret_encrypted()
```

### Step 3: Configure RFC 3161 Timestamps

#### Option A: FreeTSA (Free, Rate-Limited)

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
    MASTER_OMNI_CODES,
    MASTER_HELIX_PARAMS,
    kms
)

if pkg.timestamp_token:
    print("✓ RFC 3161 timestamp obtained")
else:
    print("⚠ RFC 3161 failed, using self-asserted timestamp")
```

#### Option B: Commercial TSA (Production)

```python
# DigiCert Timestamp Server
pkg = create_crypto_package(
    MASTER_OMNI_CODES,
    MASTER_HELIX_PARAMS,
    kms,
    author="Steel-SecAdv-LLC",
    use_rfc3161=True,
    tsa_url="http://timestamp.digicert.com"  # DigiCert
)

# GlobalSign Timestamp Server
pkg = create_crypto_package(
    MASTER_OMNI_CODES,
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

```python
from datetime import datetime, timedelta

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
    
    # Archive old public keys for verification
    archive_dir = Path(f"public_keys_archive_{datetime.now().isoformat()}")
    export_public_keys(old_kms, archive_dir)
    print(f"Old public keys archived to: {archive_dir}")
    
    # Export new public keys
    export_public_keys(new_kms, Path("public_keys"))
    
    # Securely delete old master secret
    old_kms.master_secret = b'\x00' * 32
    
    print("✓ Key rotation complete")
    return new_kms

# Usage
if should_rotate_keys(kms):
    kms = rotate_keys(kms, "Steel-SecAdv-LLC")
```

### Step 5: Sign Omni-Code Packages

```python
def sign_codes(
    codes: str,
    helix_params: List[Tuple[float, float]],
    kms: KeyManagementSystem,
    output_file: str = "CRYPTO_PACKAGE.json"
) -> CryptoPackage:
    """Sign Omni-Codes and save package."""
    
    # Create cryptographic package
    pkg = create_crypto_package(
        codes,
        helix_params,
        kms,
        author="Steel-SecAdv-LLC",
        use_rfc3161=True  # Production should use RFC 3161
    )
    
    # Save to file
    with open(output_file, 'w') as f:
        json.dump(asdict(pkg), f, indent=2)
    
    print(f"✓ Package signed and saved: {output_file}")
    return pkg

# Sign master Omni-Codes
pkg = sign_codes(MASTER_OMNI_CODES, MASTER_HELIX_PARAMS, kms)
```

### Step 6: Verify Omni-Code Packages

```python
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
    
    # Print results
    print(f"\nVerification Results for {package_file}:")
    print("-" * 50)
    for check, valid in results.items():
        status = "✓" if valid else "✗"
        print(f"  {status} {check}: {'VALID' if valid else 'INVALID'}")
    
    all_valid = all(results.values())
    print("-" * 50)
    if all_valid:
        print("✓ ALL VERIFICATIONS PASSED")
    else:
        print("✗ VERIFICATION FAILED")
    
    return all_valid

# Verify package
is_valid = verify_dna_package(
    "CRYPTO_PACKAGE.json",
    MASTER_OMNI_CODES,
    MASTER_HELIX_PARAMS,
    kms.hmac_key
)
```

---

## Advanced Usage

### Custom Omni-Codes

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

```python
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
            "dilithium_sig": dilithium_sign(content_hash, kms.dilithium_keypair.private_key).hex(),
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
    MASTER_OMNI_CODES,
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

```python
import subprocess

def setup_git_signing(kms: KeyManagementSystem):
    """Configure Git to sign commits with Ed25519."""
    
    # Export Ed25519 key in SSH format
    public_key_ssh = base64.b64encode(kms.ed25519_keypair.public_key).decode()
    
    with open("ed25519_git.key", "w") as f:
        f.write(f"ssh-ed25519 {public_key_ssh} Steel-SecAdv-LLC\n")
    
    # Configure Git
    subprocess.run(["git", "config", "user.signingkey", "ed25519_git.key"])
    subprocess.run(["git", "config", "commit.gpgsign", "true"])
    subprocess.run(["git", "config", "gpg.format", "ssh"])
    
    print("✓ Git configured for Ed25519 signing")
    print("Commit with: git commit -S -m 'Your message'")

setup_git_signing(kms)
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
```python
# Verify you're using the same KMS
print(f"HMAC key: {kms.hmac_key.hex()[:16]}...")

# Re-sign with correct key
pkg = create_crypto_package(MASTER_OMNI_CODES, MASTER_HELIX_PARAMS, kms, ...)
```

---

## Performance Optimization

### Batch Processing

```python
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
    
    print(f"✓ Signed {len(packages)} packages total")
    return packages

# Usage: Sign 1000 Omni-Code sets
dna_list = [(MASTER_OMNI_CODES, MASTER_HELIX_PARAMS) for _ in range(1000)]
packages = sign_multiple_codes(dna_list, kms)

# Performance: ~1000 packages/second (with Dilithium)
```

### Parallel Verification

```python
from concurrent.futures import ProcessPoolExecutor

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
) -> List[Dict[str, bool]]:
    """Verify multiple packages in parallel."""
    
    args_list = [
        (pkg, codes, helix_params, hmac_key)
        for pkg in packages
    ]
    
    with ProcessPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(verify_package_worker, args_list))
    
    return results

# Usage: Verify 1000 packages with 4 workers
results = verify_multiple_packages(packages, MASTER_OMNI_CODES, MASTER_HELIX_PARAMS, kms.hmac_key)

# Performance: ~4000 packages/second (4 cores)
```

---

## Security Checklist

### Pre-Deployment

- [ ] Build native PQC C library (ML-DSA-65, Kyber-1024, SPHINCS+-256f)
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

```python
from ama_cryptography.legacy_compat import *

# Load your Omni-Codes and helix parameters
codes = "..."  # Your Omni-Codes
helix_params = [...]  # Your helix parameters

# Generate new KMS with ethical integration
kms = generate_key_management_system("YourOrganization")

# Create new package with ethical integration
pkg = create_crypto_package(
    codes,
    helix_params,
    kms,
    author="YourOrganization",
    use_rfc3161=True
)

# Save new package
with open("CRYPTO_PACKAGE.json", 'w') as f:
    json.dump(asdict(pkg), f, indent=2)

print("✓ Package regenerated with ethical integration")
```

#### Strategy 2: Backward-Compatible Verification

**Best for:** Systems that must verify both v1.0.0 and v2.0.0 packages

```python
import json
from typing import Optional

def load_package_any_version(package_file: str) -> CryptoPackage:
    """Load package from any version, adding defaults for missing fields."""
    
    with open(package_file, 'r') as f:
        pkg_dict = json.load(f)
    
    # Check if ethical fields are present
    if 'ethical_vector' not in pkg_dict:
        # v1.0.0 package - add default ethical vector
        print("⚠ Loading v1.0.0 package without ethical integration")
        pkg_dict['ethical_vector'] = ETHICAL_VECTOR.copy()
        
        # Compute ethical hash for consistency
        ethical_json = json.dumps(pkg_dict['ethical_vector'], sort_keys=True)
        pkg_dict['ethical_hash'] = hashlib.sha3_256(ethical_json.encode()).hexdigest()
    
    return CryptoPackage(**pkg_dict)

# Usage
pkg = load_package_any_version("CRYPTO_PACKAGE.json")

# Verify with warning if no ethical binding
results = verify_crypto_package(codes, helix_params, pkg, hmac_key)

if pkg.version == "1.0.0":
    print("⚠ Package verified but lacks ethical binding")
    print("  Consider regenerating with v2.0.0 for full security")
```

#### Strategy 3: Batch Migration Script

**Best for:** Systems with many existing packages

```python
import os
from pathlib import Path

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
        
        # Create new package with ethical integration
        new_pkg = create_crypto_package(
            codes,
            helix_params,
            kms,
            author=kms.author if hasattr(kms, 'author') else "Unknown",
            use_rfc3161=True
        )
        
        # Save to output directory
        output_file = output_path / pkg_file.name
        with open(output_file, 'w') as f:
            json.dump(asdict(new_pkg), f, indent=2)
        
        print(f"  ✓ Migrated to {output_file}")
    
    print(f"\n✓ Migration complete: {len(packages)} packages")

# Usage
migrate_package_directory(
    input_dir="packages_v1",
    output_dir="packages_v2",
    kms=kms,
    codes=MASTER_OMNI_CODES,
    helix_params=MASTER_HELIX_PARAMS
)
```

### Key Management Changes

#### Ethical Vector in KMS

**v2.0.0 adds ethical vector to KeyManagementSystem:**

```python
@dataclass
class KeyManagementSystem:
    master_secret: bytes
    hmac_key: bytes
    ed25519_keypair: Ed25519KeyPair
    dilithium_keypair: DilithiumKeyPair
    creation_date: str
    rotation_schedule: str
    version: str
    ethical_vector: Dict[str, float]  # NEW in v2.0.0
```

**Default Ethical Vector:**
```python
ETHICAL_VECTOR = {
    "omniscient": 3.0,        # Triad of Wisdom
    "omnipotent": 3.0,        # Triad of Agency
    "omnidirectional": 3.0,   # Triad of Geography
    "omnibenevolent": 3.0,    # Triad of Integrity
}
# Constraint: Σw = 12.0
```

**Custom Ethical Vector (Advanced):**
```python
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

```python
def verify_ethical_binding(pkg: CryptoPackage) -> bool:
    """Verify ethical vector matches its hash."""
    
    # Recompute ethical hash
    ethical_json = json.dumps(pkg.ethical_vector, sort_keys=True)
    computed_hash = hashlib.sha3_256(ethical_json.encode()).hexdigest()
    
    # Compare with package hash
    if computed_hash != pkg.ethical_hash:
        print("✗ Ethical hash mismatch - package may be tampered")
        return False
    
    # Verify constraint
    total_weight = sum(pkg.ethical_vector.values())
    if abs(total_weight - 12.0) > 1e-10:
        print(f"✗ Ethical vector constraint violated: Σw = {total_weight} ≠ 12.0")
        return False
    
    print("✓ Ethical binding verified")
    return True

# Usage
if verify_ethical_binding(pkg):
    print("Package has valid ethical integration")
```

### Testing Migration

```python
def test_migration():
    """Test migration from v1.0.0 to v2.0.0."""
    
    print("Testing migration...")
    
    # 1. Create v2.0.0 package
    kms = generate_key_management_system("TestOrg")
    pkg_v2 = create_crypto_package(
        MASTER_OMNI_CODES,
        MASTER_HELIX_PARAMS,
        kms,
        author="TestOrg"
    )
    
    # 2. Verify all fields present
    assert hasattr(pkg_v2, 'ethical_vector')
    assert hasattr(pkg_v2, 'ethical_hash')
    assert len(pkg_v2.ethical_vector) == 12
    assert sum(pkg_v2.ethical_vector.values()) == 12.0
    
    # 3. Verify ethical hash
    assert verify_ethical_binding(pkg_v2)
    
    # 4. Verify cryptographic integrity
    results = verify_crypto_package(
        MASTER_OMNI_CODES,
        MASTER_HELIX_PARAMS,
        pkg_v2,
        kms.hmac_key
    )
    assert all(results.values())
    
    print("✓ Migration test passed")

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
| ML-DSA-65 (Dilithium3) | FIPS 204 | PK: 1952, SK: 4032, Sig: 3309 | **10/10 PASS** |
| ML-KEM-1024 (Kyber-1024) | FIPS 203 | PK: 1568, SK: 3168, CT: 1568 | **10/10 PASS** |
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
| `AMA_ED25519_VERIFY_SHAMIR` | ON | Ed25519 verify path (in-tree backend only; ignored by the donna shim). `ON` = Shamir/Straus joint scalar mult `[s]B + [h](-A)` in one interleaved pass (~30% fewer point doublings than the split layout). `OFF` = sequential layout (`[s]B` via comb + `[h](-A)` via wNAF + final point add). Both paths are byte-identical at the `R_check` level (verified by `tests/c/test_ed25519_verify_equiv.c` layer B). |
| `AMA_ED25519_VERIFY_WINDOW` | 5 | wNAF window width used by the variable-base scalar mults inside the Ed25519 verify path (both Shamir joint mult and the split mult; in-tree backend only). Accepted range: `[2, 6]`. Stack table size per point is `2^(W-1) * sizeof(ge25519_p3)` ≈ 160 B × `2^(W-1)` (Shamir instantiates two such tables). Practical sweet spot is `W=5` (≈18% fewer adds vs `W=4`); `W=6` is roughly par on Curve25519 with a doubled stack footprint. |
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
compared to a stored digest. After legitimate code changes, regenerate:

```bash
python -m ama_cryptography.integrity --update
```

Verify the module integrity digest (runs POST as part of normal import):

```bash
python -m ama_cryptography.integrity --verify
```

**Continuous RNG Test:** Use `ama_cryptography.secure_token_bytes(n)` instead
of `secrets.token_bytes(n)` for random byte generation with continuous health
testing. This wrapper detects consecutive identical outputs and enters ERROR
state if the RNG fails.

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

**Document Version:** 2.1.5
**Last Updated:** 2026-04-20
**Copyright (C) 2025-2026 Steel Security Advisors LLC**
