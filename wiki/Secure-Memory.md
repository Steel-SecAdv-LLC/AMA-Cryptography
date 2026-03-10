# Secure Memory

Documentation for the secure memory operations module (`ama_cryptography/secure_memory.py`), covering `SecureBuffer`, memory zeroing, memory locking, and constant-time comparisons.

---

## Overview

Cryptographic key material must be handled with care:
- **Zeroed** when no longer needed (prevent exposure via heap dumps, core files, swap)
- **Locked** in RAM (prevent exposure via swap/hibernate)
- **Compared** in constant time (prevent timing side-channel attacks)

The `secure_memory` module provides these capabilities with optional libsodium integration (via PyNaCl).

---

## `SecureBuffer`

A context manager for automatic, guaranteed memory zeroing:

```python
from ama_cryptography.secure_memory import SecureBuffer
import os

# Allocate a 32-byte secure buffer
with SecureBuffer(32) as buf:
    # buf.data is a bytearray, initially zeroed
    buf.data[:] = os.urandom(32)   # Load key material
    
    # Use buf.data for cryptographic operations...
    key = bytes(buf.data)
    
# On context manager __exit__, buf.data is automatically zeroed
# (multi-pass overwrite, ensuring the key cannot be recovered)
print(f"After context: {buf.data.hex()}")  # 0000...0000
```

### Internal Design

`SecureBuffer.data` is a `bytearray` (not `bytes`) because `bytearray` supports in-place modification, allowing the buffer to be zeroed without creating new memory allocations. `bytes` objects in Python are immutable and cannot be zeroed in place.

---

## `secure_memzero()`

Multi-pass memory overwrite for sensitive data:

```python
from ama_cryptography.secure_memory import secure_memzero

# Load sensitive data
secret_key = bytearray(os.urandom(32))

# Use the key...
signature = sign(message, bytes(secret_key))

# Zero immediately after use
secure_memzero(secret_key)
# secret_key is now all zeros
```

> **Important:** Always pass a `bytearray`, not `bytes`. `bytes` objects are immutable and cannot be zeroed.

### Implementation

`secure_memzero()` performs multiple overwrite passes:
1. Fill with `0x00`
2. Fill with `0xFF`
3. Fill with `0xAA` (alternating bits)
4. Final fill with `0x00`

This protects against "compiler optimization" attacks where a naive `memset()` call to zero is optimized away because the buffer is not subsequently read.

---

## `secure_mlock()` and `secure_munlock()`

Lock memory pages to prevent swapping to disk:

```python
from ama_cryptography.secure_memory import secure_mlock, secure_munlock

secret = bytearray(os.urandom(32))

# Lock the memory page containing `secret` into RAM
# Returns True if successful, False if insufficient privileges or not supported
locked = secure_mlock(secret)
if locked:
    print("Memory locked in RAM (will not swap)")

# ... use secret ...

# Unlock when done (allow the OS to swap it again)
secure_munlock(secret)

# Zero the memory
secure_memzero(secret)
```

### Platform Notes

| Platform | API | Notes |
|----------|-----|-------|
| Linux | `mlock()` | Requires `CAP_IPC_LOCK` or `ulimit -l` ≥ buffer size |
| macOS | `mlock()` | Requires entitlements in sandboxed environments |
| Windows | `VirtualLock()` | Standard user processes have limits |

> **libsodium:** If PyNaCl is installed (`pip install ".[secure-memory]"`), `secure_mlock()` delegates to `libsodium`'s `sodium_mlock()` which is more reliable across platforms.

---

## `constant_time_compare()`

Timing-safe byte comparison:

```python
from ama_cryptography.secure_memory import constant_time_compare

# Timing-safe comparison (always runs in O(n) time regardless of where mismatch occurs)
hmac_expected = compute_hmac(message, key)
hmac_received = package["hmac_tag"]

# Safe: does not leak position of first mismatch
if constant_time_compare(hmac_expected, hmac_received):
    print("HMAC valid")
else:
    print("HMAC invalid")
```

### Why Constant-Time Matters

A naive comparison (`expected == received`) returns `False` as soon as it finds the first differing byte. An attacker making many requests can measure small timing differences to determine byte-by-byte what the correct HMAC tag is (a timing oracle attack).

`constant_time_compare()` always processes all bytes in equal time, preventing this.

### Implementation

Uses `hmac.compare_digest()` from the Python standard library (which internally uses `_Py_bytes_cmp()`, a constant-time C implementation), with a fallback to a manual XOR-reduction approach.

---

## `SecureKeyStorage`

Encrypted storage with automatic memory management:

```python
from ama_cryptography.key_management import SecureKeyStorage

# encryption_key is bytearray to allow in-place zeroing
encryption_key = bytearray(os.urandom(32))

with SecureKeyStorage(encryption_key) as storage:
    # Store key material (encrypted with AES-256-GCM)
    storage.store("signing-key-v1", os.urandom(32))
    
    # Retrieve key material (decrypted on access)
    key = storage.retrieve("signing-key-v1")

# encryption_key is zeroed on context manager exit
```

---

## Best Practices

### Do: Use `bytearray` for Key Material

```python
# ✓ Correct: bytearray can be zeroed
key = bytearray(os.urandom(32))
# ... use key ...
secure_memzero(key)
```

```python
# ✗ Incorrect: bytes cannot be zeroed in-place
key = os.urandom(32)   # bytes object
# Cannot zero this after use
```

### Do: Use `SecureBuffer` Context Manager

```python
# ✓ Automatic zeroing even on exception
with SecureBuffer(32) as buf:
    buf.data[:] = get_key_from_hsm()
    result = encrypt(plaintext, bytes(buf.data))
# buf.data is zeroed here, even if encrypt() raised
```

### Do: Lock Sensitive Buffers in RAM

```python
# ✓ Prevent swap exposure for long-lived keys
master_key = bytearray(load_master_key())
secure_mlock(master_key)
# ... use master_key for the session ...
secure_munlock(master_key)
secure_memzero(master_key)
```

### Do: Use Constant-Time Comparisons for MACs and Secrets

```python
# ✓ Constant-time comparison for HMAC tags
if constant_time_compare(expected_mac, received_mac):
    proceed()
```

```python
# ✗ Timing-vulnerable comparison
if expected_mac == received_mac:   # DO NOT USE for secrets
    proceed()
```

---

## Optional: libsodium Integration

Install PyNaCl for enhanced secure memory operations:

```bash
pip install ".[secure-memory]"
# or
pip install PyNaCl>=1.5.0
```

When PyNaCl is available:
- `secure_mlock()` delegates to `libsodium`'s `sodium_mlock()`
- `secure_memzero()` delegates to `libsodium`'s `sodium_memzero()`
- `constant_time_compare()` delegates to `libsodium`'s `sodium_memcmp()`

These libsodium implementations provide stronger guarantees against compiler optimizations and are well-audited.

---

*See [Key Management](Key-Management) for how `SecureBuffer` is used in key storage, or [Architecture](Architecture) for the security architecture overview.*
